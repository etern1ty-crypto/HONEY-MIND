//! Protocol emulators.
//!
//! Each handler is an `async fn handle(...)` that consumes a TCP stream and
//! returns the close reason. Handlers update `SessionState` with the bytes
//! seen and any structured events parsed from the client.

pub mod http;
pub mod raw;
pub mod ssh;
pub mod telnet;

use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::{EndpointConfig, Protocol};
use crate::session::{CloseReason, SessionState};

/// Dispatch table.
pub async fn handle(
    stream: TcpStream,
    state: &mut SessionState,
    ep: &EndpointConfig,
    session_timeout: Duration,
) -> CloseReason {
    match ep.protocol {
        Protocol::Raw => raw::handle(stream, state, ep, session_timeout).await,
        Protocol::Ssh => ssh::handle(stream, state, ep, session_timeout).await,
        Protocol::Http => http::handle(stream, state, ep, session_timeout).await,
        Protocol::Telnet => telnet::handle(stream, state, ep, session_timeout).await,
    }
}

/// Read up to `buf.len()` bytes, applying a per-read timeout. Returns:
///   - `Ok(Some(n))`  — read `n` bytes (n > 0)
///   - `Ok(None)`     — client closed cleanly (EOF)
///   - `Err(reason)`  — timeout or IO error; caller should record reason.
pub async fn read_with_timeout(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Duration,
) -> Result<Option<usize>, CloseReason> {
    match timeout(deadline, stream.read(buf)).await {
        Ok(Ok(0)) => Ok(None),
        Ok(Ok(n)) => Ok(Some(n)),
        Ok(Err(_)) => Err(CloseReason::Error),
        Err(_) => Err(CloseReason::Timeout),
    }
}
