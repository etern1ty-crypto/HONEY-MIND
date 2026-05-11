//! Telnet login-prompt honeypot.
//!
//! Sends an optional banner, then a `login:` prompt, captures the username
//! line, prompts for a password, captures it. Mirrors the classic
//! low-interaction telnet honeypot behaviour used in IoT-scanner research.
//!
//! Telnet IAC (`0xff`) negotiation bytes are stripped from captured input so
//! the logged username/password are clean.

use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::config::EndpointConfig;
use crate::session::{CloseReason, SessionEvent, SessionState};

use super::read_with_timeout;

/// Cap on bytes per line. Real scanners send short usernames.
const MAX_LINE: usize = 256;
/// Cap on attempts before we drop the connection.
const MAX_ATTEMPTS: u32 = 3;

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
        if !banner.ends_with('\n') {
            let _ = stream.write_all(b"\r\n").await;
        }
    }

    let prompt = ep.login_prompt.as_deref().unwrap_or("login: ");
    // Persistent buffer: a single recv() can deliver both username and password
    // (e.g. when a scanner sends them in one TCP segment), so we keep leftover
    // bytes between read_line calls instead of discarding them.
    let mut buffer: Vec<u8> = Vec::with_capacity(128);

    for _ in 0..MAX_ATTEMPTS {
        if stream.write_all(prompt.as_bytes()).await.is_err() {
            return CloseReason::Error;
        }
        let _ = stream.flush().await;

        let line = match read_line(&mut stream, state, &mut buffer, session_timeout).await {
            ReadLineResult::Line(l) => l,
            ReadLineResult::Closed => return CloseReason::ClientClosed,
            ReadLineResult::Reason(r) => return r,
        };
        let username = String::from_utf8_lossy(&strip_telnet(&line))
            .trim()
            .to_string();
        if username.is_empty() {
            continue;
        }

        if stream.write_all(b"Password: ").await.is_err() {
            return CloseReason::Error;
        }
        let _ = stream.flush().await;

        let password = match read_line(&mut stream, state, &mut buffer, session_timeout).await {
            ReadLineResult::Line(l) => {
                let s = String::from_utf8_lossy(&strip_telnet(&l))
                    .trim()
                    .to_string();
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            }
            ReadLineResult::Closed => None,
            ReadLineResult::Reason(r) => {
                state.push_event(SessionEvent::TelnetLogin {
                    username,
                    password: None,
                });
                return r;
            }
        };

        state.push_event(SessionEvent::TelnetLogin { username, password });

        let _ = stream.write_all(b"Login incorrect\r\n").await;
    }

    let _ = stream
        .write_all(b"Too many attempts. Disconnecting.\r\n")
        .await;
    CloseReason::ServerClosed
}

enum ReadLineResult {
    Line(Vec<u8>),
    Closed,
    Reason(CloseReason),
}

async fn read_line(
    stream: &mut TcpStream,
    state: &mut SessionState,
    buffer: &mut Vec<u8>,
    session_timeout: Duration,
) -> ReadLineResult {
    // If a previous call already buffered bytes past a newline, try to satisfy
    // this read entirely from the buffer first.
    if let Some(idx) = buffer.iter().position(|&b| b == b'\n') {
        let line = buffer.drain(..=idx).take(idx).collect::<Vec<u8>>();
        return ReadLineResult::Line(line);
    }
    let mut buf = [0u8; 256];
    loop {
        match read_with_timeout(stream, &mut buf, session_timeout).await {
            Ok(None) => return ReadLineResult::Closed,
            Ok(Some(n)) => {
                let chunk = &buf[..n];
                state.record_bytes(chunk);
                buffer.extend_from_slice(chunk);
                if let Some(idx) = buffer.iter().position(|&b| b == b'\n') {
                    let line = buffer.drain(..=idx).take(idx).collect::<Vec<u8>>();
                    return ReadLineResult::Line(line);
                }
                if buffer.len() >= MAX_LINE {
                    let line = std::mem::take(buffer);
                    return ReadLineResult::Line(line);
                }
            }
            Err(reason) => return ReadLineResult::Reason(reason),
        }
    }
}

/// Strip RFC 854 IAC sequences (`0xFF <cmd> [<opt>]`) and trailing CR.
fn strip_telnet(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if b == 0xff {
            // IAC <command>; commands 251–254 (WILL/WONT/DO/DONT) carry an
            // option byte. Skip 2 bytes for those; otherwise skip 2 bytes
            // (IAC + command).
            i += 2;
            if i <= input.len() && i >= 2 {
                let cmd = input.get(i - 1).copied().unwrap_or(0);
                if matches!(cmd, 0xfb..=0xfe) {
                    i += 1;
                }
            }
            continue;
        }
        if b == b'\r' {
            i += 1;
            continue;
        }
        out.push(b);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_telnet_removes_iac() {
        let input = b"\xff\xfb\x01admin\r\n";
        let cleaned = strip_telnet(input);
        assert_eq!(cleaned, b"admin\n");
    }

    #[test]
    fn strip_telnet_keeps_plain() {
        assert_eq!(strip_telnet(b"hello\n"), b"hello\n");
    }
}
