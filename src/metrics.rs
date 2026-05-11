//! Prometheus metrics registry and HTTP exporter.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    register_int_gauge_with_registry, Encoder, HistogramVec, IntCounterVec, IntGauge, Registry,
    TextEncoder,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

/// All metric handles. Cloneable; protocol handlers hold a clone.
#[derive(Clone)]
pub struct Metrics {
    pub registry: Arc<Registry>,
    pub connections_total: IntCounterVec,
    pub rejected_total: IntCounterVec,
    pub active_sessions: IntGauge,
    pub bytes_received_total: IntCounterVec,
    pub session_duration_seconds: HistogramVec,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        let registry = Arc::new(Registry::new_custom(Some("minotaur".into()), None)?);

        let connections_total = register_int_counter_vec_with_registry!(
            "connections_total",
            "Total accepted connections, labelled by protocol.",
            &["protocol"],
            registry
        )?;

        let rejected_total = register_int_counter_vec_with_registry!(
            "rejected_total",
            "Connections rejected, labelled by protocol and reason.",
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
            "Total bytes received from clients, labelled by protocol.",
            &["protocol"],
            registry
        )?;

        let session_duration_seconds = register_histogram_vec_with_registry!(
            "session_duration_seconds",
            "Distribution of session durations in seconds, labelled by protocol.",
            &["protocol"],
            vec![0.01, 0.1, 0.5, 1.0, 5.0, 15.0, 60.0, 300.0],
            registry
        )?;

        Ok(Self {
            registry,
            connections_total,
            rejected_total,
            active_sessions,
            bytes_received_total,
            session_duration_seconds,
        })
    }

    /// Render the current registry as a Prometheus text payload.
    pub fn render(&self) -> Result<Vec<u8>> {
        let mf = self.registry.gather();
        let encoder = TextEncoder::new();
        let mut buf = Vec::with_capacity(4096);
        encoder.encode(&mf, &mut buf)?;
        Ok(buf)
    }
}

/// Spawn the metrics HTTP server. Returns once the listener is bound; the
/// server runs in the background until `shutdown` is triggered.
pub async fn serve(bind: SocketAddr, metrics: Metrics, shutdown: CancellationToken) -> Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind metrics listener on {}", bind))?;
    info!(target: "minotaur::metrics", %bind, "metrics endpoint listening");

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!(target: "minotaur::metrics", "metrics server shutting down");
                    return;
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, peer)) => {
                            debug!(target: "minotaur::metrics", %peer, "metrics scrape");
                            let m = metrics.clone();
                            tokio::spawn(async move {
                                let io = TokioIo::new(stream);
                                let svc = service_fn(move |req| {
                                    let m = m.clone();
                                    async move { Ok::<_, Infallible>(handle(req, &m)) }
                                });
                                if let Err(e) = hyper::server::conn::http1::Builder::new()
                                    .serve_connection(io, svc)
                                    .await
                                {
                                    debug!(target: "minotaur::metrics", error = %e, "scrape conn closed");
                                }
                            });
                        }
                        Err(e) => {
                            error!(target: "minotaur::metrics", error = %e, "accept failed");
                        }
                    }
                }
            }
        }
    });
    Ok(())
}

fn handle(req: Request<hyper::body::Incoming>, metrics: &Metrics) -> Response<Full<Bytes>> {
    if req.method() != Method::GET {
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Full::from(Bytes::from_static(b"method not allowed")))
            .expect("static response");
    }
    match req.uri().path() {
        "/metrics" => match metrics.render() {
            Ok(body) => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/plain; version=0.0.4")
                .body(Full::from(Bytes::from(body)))
                .expect("response"),
            Err(e) => {
                error!(target: "minotaur::metrics", error = %e, "render failed");
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::from(Bytes::from_static(b"render failed")))
                    .expect("static response")
            }
        },
        "/healthz" => Response::builder()
            .status(StatusCode::OK)
            .body(Full::from(Bytes::from_static(b"ok")))
            .expect("static response"),
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::from(Bytes::from_static(b"not found")))
            .expect("static response"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_text_format() {
        let m = Metrics::new().unwrap();
        m.connections_total.with_label_values(&["ssh"]).inc();
        m.connections_total.with_label_values(&["http"]).inc_by(3);
        m.active_sessions.set(2);
        let body = m.render().unwrap();
        let s = String::from_utf8(body).unwrap();
        assert!(s.contains("minotaur_connections_total{protocol=\"ssh\"} 1"));
        assert!(s.contains("minotaur_connections_total{protocol=\"http\"} 3"));
        assert!(s.contains("minotaur_active_sessions 2"));
    }
}
