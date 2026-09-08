//! Bounded management HTTP server; untrusted strings never become metric labels.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Method, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    register_int_counter_with_registry, register_int_gauge_with_registry, Encoder, HistogramVec,
    IntCounter, IntCounterVec, IntGauge, Registry, TextEncoder,
};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::config::{MetricsConfig, Protocol, SensorConfig};

#[derive(Clone)]
pub struct Metrics {
    pub registry: Arc<Registry>,
    pub connections_total: IntCounterVec,
    pub rejected_total: IntCounterVec,
    pub active_sessions: IntGauge,
    pub bytes_received_total: IntCounterVec,
    pub session_duration_seconds: HistogramVec,
    pub closed_sessions_total: IntCounterVec,
    pub events_total: IntCounterVec,
    pub logger_written_total: IntCounter,
    pub logger_dropped_total: IntCounterVec,
    pub logger_errors_total: IntCounter,
    pub tracked_ips: IntGauge,
    pub ready: IntGauge,
    pub metrics_active_connections: IntGauge,
    pub metrics_rejected_total: IntCounter,
}

impl Metrics {
    pub fn new(sensor: &SensorConfig) -> Result<Self> {
        let labels = HashMap::from([
            ("sensor_id".into(), sensor.id.clone()),
            ("environment".into(), sensor.environment.clone()),
        ]);
        let registry = Arc::new(Registry::new_custom(Some("minotaur".into()), Some(labels))?);
        let connections_total = register_int_counter_vec_with_registry!(
            "connections_total",
            "Admitted honeypot TCP sessions.",
            &["protocol"],
            registry
        )?;
        let rejected_total = register_int_counter_vec_with_registry!(
            "rejected_total",
            "Rejected TCP connections.",
            &["protocol", "reason"],
            registry
        )?;
        let active_sessions = register_int_gauge_with_registry!(
            "active_sessions",
            "Currently active honeypot sessions.",
            registry
        )?;
        let bytes_received_total = register_int_counter_vec_with_registry!(
            "bytes_received_total",
            "Application bytes received, updated at session close.",
            &["protocol"],
            registry
        )?;
        let session_duration_seconds = register_histogram_vec_with_registry!(
            "session_duration_seconds",
            "Completed session lifetime in seconds.",
            &["protocol"],
            vec![0.01, 0.1, 0.5, 1.0, 5.0, 15.0, 60.0, 300.0, 3600.0],
            registry
        )?;
        let closed_sessions_total = register_int_counter_vec_with_registry!(
            "closed_sessions_total",
            "Session completion reasons.",
            &["protocol", "reason"],
            registry
        )?;
        let events_total = register_int_counter_vec_with_registry!(
            "events_total",
            "Parsed events, updated at session close.",
            &["protocol", "event"],
            registry
        )?;
        let logger_written_total = register_int_counter_with_registry!(
            "logger_written_total",
            "Records flushed to all configured sinks.",
            registry
        )?;
        let logger_dropped_total = register_int_counter_vec_with_registry!(
            "logger_dropped_total",
            "Records not delivered to all sinks.",
            &["reason"],
            registry
        )?;
        let logger_errors_total = register_int_counter_with_registry!(
            "logger_errors_total",
            "Fatal writer or serialization errors.",
            registry
        )?;
        let tracked_ips = register_int_gauge_with_registry!(
            "tracked_ips",
            "Rate-limit IP buckets currently allocated.",
            registry
        )?;
        let ready = register_int_gauge_with_registry!(
            "ready",
            "One when listeners are started and the writer is healthy.",
            registry
        )?;
        let metrics_active_connections = register_int_gauge_with_registry!(
            "metrics_active_connections",
            "Active management HTTP connections.",
            registry
        )?;
        let metrics_rejected_total = register_int_counter_with_registry!(
            "metrics_rejected_total",
            "Management connections rejected at capacity.",
            registry
        )?;
        for protocol in Protocol::ALL {
            connections_total.with_label_values(&[protocol.as_str()]);
            bytes_received_total.with_label_values(&[protocol.as_str()]);
            for reason in [
                "rate_limit",
                "rate_limit_capacity",
                "rate_limiter_unavailable",
                "max_sessions",
                "ignored_ip",
            ] {
                rejected_total.with_label_values(&[protocol.as_str(), reason]);
            }
        }
        for reason in ["queue_full", "channel_closed", "writer_error"] {
            logger_dropped_total.with_label_values(&[reason]);
        }
        Ok(Self {
            registry,
            connections_total,
            rejected_total,
            active_sessions,
            bytes_received_total,
            session_duration_seconds,
            closed_sessions_total,
            events_total,
            logger_written_total,
            logger_dropped_total,
            logger_errors_total,
            tracked_ips,
            ready,
            metrics_active_connections,
            metrics_rejected_total,
        })
    }

    pub fn render(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(8192);
        TextEncoder::new().encode(&self.registry.gather(), &mut buffer)?;
        Ok(buffer)
    }
}

/// Decrements its gauge even when a task panics or is aborted.
pub struct ActiveGuard(IntGauge);

impl ActiveGuard {
    pub fn new(gauge: &IntGauge) -> Self {
        gauge.inc();
        Self(gauge.clone())
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.dec();
    }
}

pub async fn serve(
    listener: TcpListener,
    config: MetricsConfig,
    metrics: Metrics,
    shutdown: CancellationToken,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    let mut failure = None;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = result {
                    failure = Some(anyhow::Error::from(error).context("management task failed"));
                    shutdown.cancel();
                    break;
                }
            }
            result = listener.accept() => {
                let (stream, _) = match result {
                    Ok(pair) => pair,
                    Err(error) => {
                        failure = Some(anyhow::Error::from(error).context("management accept failed"));
                        shutdown.cancel();
                        break;
                    }
                };
                if tasks.len() >= config.max_connections {
                    metrics.metrics_rejected_total.inc();
                    continue;
                }
                let metrics = metrics.clone();
                let token = shutdown.clone();
                let duration = Duration::from_secs(config.request_timeout_seconds);
                tasks.spawn(async move {
                    let _active = ActiveGuard::new(&metrics.metrics_active_connections);
                    let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                        let reply = handle(request.method(), request.uri().path(), &metrics);
                        async move { Ok::<_, Infallible>(reply) }
                    });
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    builder.keep_alive(false).max_buf_size(8192);
                    let connection = builder.serve_connection(TokioIo::new(stream), service);
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => {}
                        result = tokio::time::timeout(duration, connection) => {
                            match result {
                                Ok(Ok(())) => {}
                                Ok(Err(error)) => debug!(%error, "management connection closed"),
                                Err(_) => debug!("management connection deadline exceeded"),
                            }
                        }
                    }
                });
            }
        }
    }
    drop(listener);
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            failure.get_or_insert_with(|| anyhow::Error::from(error));
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn handle(method: &Method, path: &str, metrics: &Metrics) -> Response<Full<Bytes>> {
    if method != Method::GET {
        let mut response = reply(
            StatusCode::METHOD_NOT_ALLOWED,
            b"method not allowed\n".to_vec(),
            false,
        );
        response.headers_mut().insert(
            hyper::header::ALLOW,
            hyper::header::HeaderValue::from_static("GET"),
        );
        return response;
    }
    match path {
        "/metrics" => match metrics.render() {
            Ok(bytes) => reply(StatusCode::OK, bytes, true),
            Err(_) => reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                b"render failed\n".to_vec(),
                false,
            ),
        },
        "/healthz" => reply(StatusCode::OK, b"ok\n".to_vec(), false),
        "/readyz" if metrics.ready.get() == 1 && metrics.logger_errors_total.get() == 0 => {
            reply(StatusCode::OK, b"ready\n".to_vec(), false)
        }
        "/readyz" => reply(
            StatusCode::SERVICE_UNAVAILABLE,
            b"not ready\n".to_vec(),
            false,
        ),
        _ => reply(StatusCode::NOT_FOUND, b"not found\n".to_vec(), false),
    }
}

fn reply(status: StatusCode, body: Vec<u8>, prometheus: bool) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::from(Bytes::from(body)));
    *response.status_mut() = status;
    let content_type = if prometheus {
        "text/plain; version=0.0.4; charset=utf-8"
    } else {
        "text/plain; charset=utf-8"
    };
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static(content_type),
    );
    response.headers_mut().insert(
        hyper::header::CONNECTION,
        hyper::header::HeaderValue::from_static("close"),
    );
    response.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_sensor_labels_and_zero_counters() {
        let metrics = Metrics::new(&SensorConfig::default()).unwrap();
        let body = String::from_utf8(metrics.render().unwrap()).unwrap();
        assert!(body.contains("sensor_id=\"local-sensor\""));
        assert!(body.contains("minotaur_connections_total"));
        assert!(body.contains("protocol=\"ssh\""));
    }

    #[test]
    fn readiness_is_not_liveness() {
        let metrics = Metrics::new(&SensorConfig::default()).unwrap();
        assert_eq!(
            handle(&Method::GET, "/healthz", &metrics).status(),
            StatusCode::OK
        );
        assert_eq!(
            handle(&Method::GET, "/readyz", &metrics).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        metrics.ready.set(1);
        assert_eq!(
            handle(&Method::GET, "/readyz", &metrics).status(),
            StatusCode::OK
        );
        metrics.logger_errors_total.inc();
        assert_eq!(
            handle(&Method::GET, "/readyz", &metrics).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn unsupported_method_advertises_get() {
        let metrics = Metrics::new(&SensorConfig::default()).unwrap();
        let response = handle(&Method::POST, "/metrics", &metrics);
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[hyper::header::ALLOW], "GET");
    }

    #[test]
    fn active_gauge_is_raii_managed() {
        let metrics = Metrics::new(&SensorConfig::default()).unwrap();
        let guard = ActiveGuard::new(&metrics.active_sessions);
        assert_eq!(metrics.active_sessions.get(), 1);
        drop(guard);
        assert_eq!(metrics.active_sessions.get(), 0);
    }
}
