//! Low-interaction protocol dispatch and one bounded I/O implementation.

pub mod http;
pub mod raw;
pub mod ssh;
pub mod telnet;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use crate::config::{EndpointConfig, Protocol};
use crate::session::{CloseReason, SessionState};

pub async fn handle(
    stream: TcpStream,
    state: &mut SessionState,
    ep: &EndpointConfig,
    idle_timeout: Duration,
) -> CloseReason {
    let mut io = SessionIo {
        stream,
        idle_timeout,
    };
    match ep.protocol {
        Protocol::Raw => raw::handle(&mut io, state, ep).await,
        Protocol::Ssh => ssh::handle(&mut io, state, ep).await,
        Protocol::Http => http::handle(&mut io, state, ep).await,
        Protocol::Telnet => telnet::handle(&mut io, state, ep).await,
    }
}

/// The session supervisor adds cancellation and the absolute lifetime deadline.
/// No protocol handler performs unbounded direct socket I/O.
pub struct SessionIo {
    stream: TcpStream,
    idle_timeout: Duration,
}

impl SessionIo {
    pub async fn read(
        &mut self,
        state: &mut SessionState,
        buf: &mut [u8],
    ) -> Result<Option<usize>, CloseReason> {
        let available = state.remaining_input().min(buf.len());
        if available == 0 {
            return Err(CloseReason::ByteLimit);
        }
        match timeout(self.idle_timeout, self.stream.read(&mut buf[..available])).await {
            Ok(Ok(0)) => Ok(None),
            Ok(Ok(n)) => {
                state.record_bytes(&buf[..n]);
                Ok(Some(n))
            }
            Ok(Err(error)) => {
                debug!(kind = ?error.kind(), "TCP read failed");
                Err(CloseReason::Error)
            }
            Err(_) => Err(CloseReason::Timeout),
        }
    }

    pub async fn write(&mut self, bytes: &[u8]) -> Result<(), CloseReason> {
        match timeout(self.idle_timeout, self.stream.write_all(bytes)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                debug!(kind = ?error.kind(), "TCP write failed");
                Err(CloseReason::Error)
            }
            Err(_) => Err(CloseReason::Timeout),
        }
    }
}
