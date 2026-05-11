//! TCP listener per endpoint. Spawns one [`tokio::task`] per accepted
//! connection, gated by a global concurrency semaphore and a per-IP rate
//! limiter.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::{Config, EndpointConfig};
use crate::logger::Logger;
use crate::metrics::Metrics;
use crate::protocols;
use crate::ratelimit::RateLimiter;
use crate::session::{CloseReason, SessionState};

/// Shared runtime state passed to every endpoint task.
pub struct AppState {
    pub config: Config,
    pub logger: Logger,
    pub metrics: Metrics,
    pub rate_limiter: Arc<RateLimiter>,
    pub session_semaphore: Arc<Semaphore>,
    pub shutdown: CancellationToken,
}

impl AppState {
    pub fn new(
        config: Config,
        logger: Logger,
        metrics: Metrics,
        shutdown: CancellationToken,
    ) -> Self {
        let session_semaphore = Arc::new(Semaphore::new(config.server.max_concurrent_sessions));
        let rate_limiter = Arc::new(RateLimiter::new(config.server.rate_limit_per_ip_per_min));
        Self {
            config,
            logger,
            metrics,
            rate_limiter,
            session_semaphore,
            shutdown,
        }
    }
}

/// Bind and run every configured endpoint. Returns when all listeners have
/// shut down.
pub async fn run(state: Arc<AppState>) -> Result<()> {
    let mut handles = Vec::new();
    for ep in state.config.endpoints.clone() {
        let listener = TcpListener::bind(ep.bind)
            .await
            .with_context(|| format!("failed to bind endpoint {}", ep.bind))?;
        info!(
            target: "minotaur::server",
            protocol = ep.protocol.as_str(),
            bind = %ep.bind,
            "endpoint listening"
        );
        let state = Arc::clone(&state);
        handles.push(tokio::spawn(async move {
            run_endpoint(listener, ep, state).await;
        }));
    }
    // Periodic eviction of stale rate-limit buckets.
    let evictor_state = Arc::clone(&state);
    handles.push(tokio::spawn(async move {
        let token = evictor_state.shutdown.clone();
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = token.cancelled() => return,
                _ = ticker.tick() => evictor_state.rate_limiter.evict_idle(),
            }
        }
    }));

    for h in handles {
        if let Err(e) = h.await {
            warn!(target: "minotaur::server", error = %e, "endpoint task panicked");
        }
    }
    Ok(())
}

async fn run_endpoint(listener: TcpListener, ep: EndpointConfig, state: Arc<AppState>) {
    let bind = ep.bind;
    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => {
                info!(target: "minotaur::server", %bind, "endpoint shutting down");
                return;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let ip = peer.ip();
                        if !state.rate_limiter.check(ip) {
                            state.metrics.rejected_total
                                .with_label_values(&[ep.protocol.as_str(), "rate_limit"])
                                .inc();
                            debug!(target: "minotaur::server", %peer, "rate-limited");
                            drop(stream);
                            continue;
                        }

                        let permit = match Arc::clone(&state.session_semaphore).try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                state.metrics.rejected_total
                                    .with_label_values(&[ep.protocol.as_str(), "max_sessions"])
                                    .inc();
                                warn!(
                                    target: "minotaur::server",
                                    %peer,
                                    "max concurrent sessions reached, dropping"
                                );
                                drop(stream);
                                continue;
                            }
                        };

                        let ep_clone = ep.clone();
                        let state_clone = Arc::clone(&state);
                        tokio::spawn(async move {
                            handle_session(stream, peer, ep_clone, state_clone).await;
                            drop(permit);
                        });
                    }
                    Err(e) => {
                        error!(target: "minotaur::server", %bind, error = %e, "accept failed");
                        // Avoid a tight loop if the listener is misbehaving.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
}

async fn handle_session(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    ep: EndpointConfig,
    state: Arc<AppState>,
) {
    let _ = stream.set_nodelay(true);
    let proto = ep.protocol;
    state
        .metrics
        .connections_total
        .with_label_values(&[proto.as_str()])
        .inc();
    state.metrics.active_sessions.inc();

    let max_preview = state.config.server.max_bytes_per_session;
    let mut session_state = SessionState::new(proto, peer, ep.bind.port(), max_preview);
    let timeout = Duration::from_secs(state.config.server.session_timeout_seconds.max(1));

    let close_reason = tokio::select! {
        biased;
        _ = state.shutdown.cancelled() => CloseReason::Shutdown,
        reason = protocols::handle(stream, &mut session_state, &ep, timeout) => reason,
    };

    state
        .metrics
        .bytes_received_total
        .with_label_values(&[proto.as_str()])
        .inc_by(session_state.bytes_received as u64);
    state.metrics.active_sessions.dec();

    let elapsed = session_state.started_at.elapsed().as_secs_f64();
    state
        .metrics
        .session_duration_seconds
        .with_label_values(&[proto.as_str()])
        .observe(elapsed);

    let record = session_state.finalize(close_reason);
    if !state.logger.log(record) {
        debug!(target: "minotaur::server", "logger dropped record");
    }
}
