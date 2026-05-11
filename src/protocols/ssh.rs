//! Minimal SSH banner handler.
//!
//! We do NOT implement the SSH transport layer (no KEX, no encryption). The
//! handler sends a server identification string per RFC 4253 §4.2, then reads
//! the client's identification string and continues capturing raw bytes until
//! close/timeout. This is sufficient to:
//!   - log which clients connect (banner string is often unique per
//!     scanner/library: `libssh_0.9.6`, `paramiko-2.10`, `Go`, etc.)
//!   - count SSH-port scans
//!   - capture any post-banner payload (won't be valid SSH, but bytes are
//!     still interesting)

use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::config::EndpointConfig;
use crate::session::{CloseReason, SessionEvent, SessionState};

use super::read_with_timeout;

const DEFAULT_BANNER: &str = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3";
/// Per RFC 4253 §4.2, the identification string is at most 255 bytes
/// including the trailing CR LF.
const MAX_CLIENT_BANNER: usize = 255;

pub async fn handle(
    mut stream: TcpStream,
    state: &mut SessionState,
    ep: &EndpointConfig,
    session_timeout: Duration,
) -> CloseReason {
    let banner = ep.banner.as_deref().unwrap_or(DEFAULT_BANNER);
    if stream
        .write_all(format!("{}\r\n", banner.trim_end()).as_bytes())
        .await
        .is_err()
    {
        return CloseReason::Error;
    }
    if stream.flush().await.is_err() {
        return CloseReason::Error;
    }

    let mut buf = [0u8; 4096];
    let mut client_banner: Option<String> = None;
    let mut header = Vec::with_capacity(MAX_CLIENT_BANNER);

    loop {
        match read_with_timeout(&mut stream, &mut buf, session_timeout).await {
            Ok(None) => return CloseReason::ClientClosed,
            Ok(Some(n)) => {
                let chunk = &buf[..n];
                state.record_bytes(chunk);

                if client_banner.is_none() {
                    let want = MAX_CLIENT_BANNER
                        .saturating_sub(header.len())
                        .min(chunk.len());
                    header.extend_from_slice(&chunk[..want]);
                    if let Some(idx) = header.iter().position(|&b| b == b'\n') {
                        let line = &header[..idx];
                        let line = line.strip_suffix(b"\r").unwrap_or(line);
                        let banner_str = String::from_utf8_lossy(line).into_owned();
                        state.push_event(SessionEvent::SshClientBanner {
                            banner: banner_str.clone(),
                        });
                        client_banner = Some(banner_str);
                    } else if header.len() >= MAX_CLIENT_BANNER {
                        client_banner = Some(String::new());
                    }
                }
            }
            Err(reason) => return reason,
        }
    }
}
