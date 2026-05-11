//! Generic raw-TCP capture: optional banner, then read bytes until close or
//! timeout. Used for ports where you don't want any protocol fidelity, just
//! want to see what scanners throw at it.

use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::config::EndpointConfig;
use crate::session::{CloseReason, SessionState};

use super::read_with_timeout;

pub async fn handle(
    mut stream: TcpStream,
    state: &mut SessionState,
    ep: &EndpointConfig,
    session_timeout: Duration,
) -> CloseReason {
    if let Some(banner) = ep.banner.as_deref() {
        if stream.write_all(banner.as_bytes()).await.is_err() {
            return CloseReason::Error;
        }
        let _ = stream.flush().await;
    }

    let mut buf = [0u8; 4096];
    loop {
        match read_with_timeout(&mut stream, &mut buf, session_timeout).await {
            Ok(None) => return CloseReason::ClientClosed,
            Ok(Some(n)) => state.record_bytes(&buf[..n]),
            Err(reason) => return reason,
        }
    }
}
