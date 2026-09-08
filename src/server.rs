//! Transactional listener binding, structured task ownership and bounded sessions.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::config::{canonical_ip, Config, EndpointConfig};
use crate::logger::Logger;
use crate::metrics::{self, ActiveGuard, Metrics};
use crate::protocols;
use crate::ratelimit::{Decision, RateLimiter};
use crate::session::{CloseReason, SessionState};

pub struct AppState {
    pub config: Config,
    pub logger: Logger,
    pub metrics: Metrics,
    pub rate_limiter: Arc<RateLimiter>,
    pub session_semaphore: Arc<Semaphore>,
    pub shutdown: CancellationToken,
    ignored_ips: HashSet<IpAddr>,
}

impl AppState {
    pub fn new(
        config: Config,
        logger: Logger,
        metrics: Metrics,
        shutdown: CancellationToken,
    ) -> Result<Self> {
        config.validate()?;
        let session_semaphore = Arc::new(Semaphore::new(config.server.max_concurrent_sessions));
        let rate_limiter = Arc::new(RateLimiter::new(
            config.server.rate_limit_per_ip_per_min,
            config.server.max_tracked_ips,
        ));
        let ignored_ips = config
            .server
            .ignore_source_ips
            .iter()
            .copied()
            .map(canonical_ip)
            .collect();
        Ok(Self {
            config,
            logger,
            metrics,
            rate_limiter,
            session_semaphore,
            shutdown,
            ignored_ips,
        })
    }
}

/// Binding creates no tasks. Any failure drops every previously bound socket.
/// This also supports race-free tests using real listeners on port zero.
pub struct BoundServer {
    endpoints: Vec<(TcpListener, EndpointConfig)>,
    management: Option<TcpListener>,
}

impl BoundServer {
    pub async fn bind(config: &Config) -> Result<Self> {
        config.validate()?;
        let mut endpoints = Vec::with_capacity(config.endpoints.len());
        for mut endpoint in config.endpoints.clone() {
            let listener = TcpListener::bind(endpoint.bind).await.with_context(|| {
                format!(
                    "cannot bind {} endpoint {}",
                    endpoint.protocol.as_str(),
                    endpoint.bind
                )
            })?;
            endpoint.bind = listener.local_addr()?;
            endpoints.push((listener, endpoint));
        }
        let management = if config.metrics.enabled {
            Some(
                TcpListener::bind(config.metrics.bind)
                    .await
                    .with_context(|| {
                        format!("cannot bind management endpoint {}", config.metrics.bind)
                    })?,
            )
        } else {
            None
        };
        Ok(Self {
            endpoints,
            management,
        })
    }

    pub fn endpoint_addresses(&self) -> Vec<SocketAddr> {
        self.endpoints.iter().map(|(_, ep)| ep.bind).collect()
    }

    pub fn metrics_address(&self) -> Result<Option<SocketAddr>> {
        self.management
            .as_ref()
            .map(TcpListener::local_addr)
            .transpose()
            .context("cannot inspect management socket")
    }

    pub async fn run(self, state: Arc<AppState>) -> Result<()> {
        let mut workers: JoinSet<Result<()>> = JoinSet::new();
        for (listener, endpoint) in self.endpoints {
            info!(protocol = endpoint.protocol.as_str(), bind = %endpoint.bind, name = %endpoint.label(), "endpoint listening");
            workers.spawn(run_endpoint(listener, endpoint, Arc::clone(&state)));
        }
        if let Some(listener) = self.management {
            info!(bind = %listener.local_addr()?, "management listening");
            workers.spawn(metrics::serve(
                listener,
                state.config.metrics.clone(),
                state.metrics.clone(),
                state.shutdown.clone(),
            ));
        }
        let limiter = Arc::clone(&state.rate_limiter);
        let metrics = state.metrics.clone();
        let token = state.shutdown.clone();
        workers.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => return Ok(()),
                    _ = tick.tick() => {
                        limiter.evict_idle();
                        metrics.tracked_ips.set(limiter.tracked_ips() as i64);
                    }
                }
            }
        });
        if !state.shutdown.is_cancelled() {
            state.metrics.ready.set(1);
        }
        let mut failure = None;
        tokio::select! {
            biased;
            _ = state.shutdown.cancelled() => {}
            result = workers.join_next() => {
                failure = Some(match result {
                    Some(Ok(Err(error))) => error,
                    Some(Err(error)) => anyhow::Error::from(error).context("server worker panicked"),
                    _ => anyhow!("server worker stopped unexpectedly"),
                });
            }
        }
        state.metrics.ready.set(0);
        state.shutdown.cancel();
        while let Some(result) = workers.join_next().await {
            match result {
                Ok(Err(error)) => {
                    failure.get_or_insert(error);
                }
                Err(error) => {
                    failure.get_or_insert_with(|| anyhow::Error::from(error));
                }
                Ok(Ok(())) => {}
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

/// Convenience API; prefer BoundServer when actual ephemeral addresses are needed.
pub async fn run(state: Arc<AppState>) -> Result<()> {
    BoundServer::bind(&state.config).await?.run(state).await
}

async fn run_endpoint(
    listener: TcpListener,
    endpoint: EndpointConfig,
    state: Arc<AppState>,
) -> Result<()> {
    let mut sessions = JoinSet::new();
    let mut failure = None;
    loop {
        tokio::select! {
            biased;
            _ = state.shutdown.cancelled() => break,
            result = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Err(error)) = result {
                    failure = Some(anyhow::Error::from(error).context("session task panicked"));
                    state.shutdown.cancel();
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(error) => {
                        failure = Some(anyhow::Error::from(error).context("honeypot accept failed"));
                        state.shutdown.cancel();
                        break;
                    }
                };
                let ip = canonical_ip(peer.ip());
                if state.ignored_ips.contains(&ip) {
                    reject(&state.metrics, &endpoint, "ignored_ip");
                    continue;
                }
                let decision = state.rate_limiter.check(ip);
                if decision != Decision::Allowed {
                    reject(&state.metrics, &endpoint, decision.reason());
                    continue;
                }
                let permit = match Arc::clone(&state.session_semaphore).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        reject(&state.metrics, &endpoint, "max_sessions");
                        continue;
                    }
                };
                let endpoint = endpoint.clone();
                let state = Arc::clone(&state);
                sessions.spawn(async move {
                    let _permit = permit;
                    handle_session(stream, peer, endpoint, state).await;
                });
            }
        }
    }
    drop(listener);
    // Each session's cancellation branch records Shutdown before returning.
    while let Some(result) = sessions.join_next().await {
        if let Err(error) = result {
            failure.get_or_insert_with(|| anyhow::Error::from(error));
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn reject(metrics: &Metrics, endpoint: &EndpointConfig, reason: &str) {
    metrics
        .rejected_total
        .with_label_values(&[endpoint.protocol.as_str(), reason])
        .inc();
    // Deliberately no warning per rejection: hostile traffic must not amplify logs.
}

async fn handle_session(
    stream: TcpStream,
    peer: SocketAddr,
    endpoint: EndpointConfig,
    state: Arc<AppState>,
) {
    if let Err(error) = stream.set_nodelay(true) {
        debug!(%error, "TCP_NODELAY unavailable");
    }
    let destination = stream.local_addr().unwrap_or(endpoint.bind);
    let protocol = endpoint.protocol.as_str();
    state
        .metrics
        .connections_total
        .with_label_values(&[protocol])
        .inc();
    let _active = ActiveGuard::new(&state.metrics.active_sessions);
    let mut session = SessionState::new(&endpoint, peer, destination, &state.config);
    let idle = Duration::from_secs(state.config.server.session_timeout_seconds);
    let lifetime = Duration::from_secs(state.config.server.max_session_duration_seconds);
    let reason = tokio::select! {
        biased;
        _ = state.shutdown.cancelled() => CloseReason::Shutdown,
        _ = tokio::time::sleep(lifetime) => CloseReason::LifetimeLimit,
        reason = protocols::handle(stream, &mut session, &endpoint, idle) => reason,
    };
    state
        .metrics
        .bytes_received_total
        .with_label_values(&[protocol])
        .inc_by(session.bytes_received);
    state
        .metrics
        .session_duration_seconds
        .with_label_values(&[protocol])
        .observe(session.started_at.elapsed().as_secs_f64());
    state
        .metrics
        .closed_sessions_total
        .with_label_values(&[protocol, reason.as_str()])
        .inc();
    for event in &session.events {
        state
            .metrics
            .events_total
            .with_label_values(&[protocol, event.kind()])
            .inc();
    }
    state.logger.log(session.finalize(reason));
}
