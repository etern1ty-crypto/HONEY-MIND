//! Session model: the structured record we emit per honeypot connection.

use std::net::SocketAddr;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::Protocol;

/// A single TCP session captured by the honeypot.
///
/// Fields are populated as the connection progresses; `finalize` produces the
/// serialized JSONL record at the end.
#[derive(Debug, Clone, Serialize)]
pub struct SessionRecord {
    /// ISO-8601 timestamp of connection acceptance (UTC).
    pub ts: DateTime<Utc>,
    pub session_id: Uuid,
    pub protocol: &'static str,
    pub src: SocketAddr,
    pub dst_port: u16,
    pub duration_ms: u64,
    pub bytes_received: usize,
    pub bytes_truncated: bool,
    /// First N bytes received, lowercase hex.
    pub data_preview_hex: String,
    /// First N bytes received, printable-ASCII representation (control chars
    /// replaced with `.`).
    pub data_preview_ascii: String,
    pub events: Vec<SessionEvent>,
    pub close_reason: CloseReason,
}

/// A structured event captured during the session. Protocol handlers append
/// these as they parse meaningful actions from the client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEvent {
    /// SSH banner exchange: client's banner string.
    SshClientBanner { banner: String },
    /// HTTP request line + first few headers.
    HttpRequest {
        method: String,
        path: String,
        version: String,
        host: Option<String>,
        user_agent: Option<String>,
    },
    /// Telnet captured a login attempt (username then password).
    TelnetLogin {
        username: String,
        password: Option<String>,
    },
    /// Generic notice (rate-limited, oversize, etc.).
    Notice { msg: String },
}

/// Reason a session ended.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    ClientClosed,
    Timeout,
    ServerClosed,
    Error,
    Shutdown,
}

/// Mutable session state used by protocol handlers.
pub struct SessionState {
    pub id: Uuid,
    pub protocol: Protocol,
    pub src: SocketAddr,
    pub dst_port: u16,
    pub started_at: Instant,
    pub ts: DateTime<Utc>,
    pub bytes_received: usize,
    /// Captured prefix, capped at `max_preview_bytes`.
    pub preview: Vec<u8>,
    pub max_preview_bytes: usize,
    pub bytes_truncated: bool,
    pub events: Vec<SessionEvent>,
}

impl SessionState {
    pub fn new(
        protocol: Protocol,
        src: SocketAddr,
        dst_port: u16,
        max_preview_bytes: usize,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            protocol,
            src,
            dst_port,
            started_at: Instant::now(),
            ts: Utc::now(),
            bytes_received: 0,
            preview: Vec::new(),
            max_preview_bytes,
            bytes_truncated: false,
            events: Vec::new(),
        }
    }

    /// Record a chunk of bytes received from the client. Appends to the preview
    /// buffer up to `max_preview_bytes`, then sets the truncated flag.
    pub fn record_bytes(&mut self, chunk: &[u8]) {
        self.bytes_received = self.bytes_received.saturating_add(chunk.len());
        if self.preview.len() < self.max_preview_bytes {
            let remaining = self.max_preview_bytes - self.preview.len();
            let take = remaining.min(chunk.len());
            self.preview.extend_from_slice(&chunk[..take]);
            if take < chunk.len() {
                self.bytes_truncated = true;
            }
        } else {
            self.bytes_truncated = true;
        }
    }

    pub fn push_event(&mut self, event: SessionEvent) {
        self.events.push(event);
    }

    pub fn finalize(self, close_reason: CloseReason) -> SessionRecord {
        let duration_ms = self.started_at.elapsed().as_millis() as u64;
        let data_preview_hex = hex::encode(&self.preview);
        let data_preview_ascii = ascii_preview(&self.preview);
        SessionRecord {
            ts: self.ts,
            session_id: self.id,
            protocol: self.protocol.as_str(),
            src: self.src,
            dst_port: self.dst_port,
            duration_ms,
            bytes_received: self.bytes_received,
            bytes_truncated: self.bytes_truncated,
            data_preview_hex,
            data_preview_ascii,
            events: self.events,
            close_reason,
        }
    }
}

/// Replace non-printable bytes with `.` and return as a UTF-8 string.
pub fn ascii_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_addr() -> SocketAddr {
        "127.0.0.1:1234".parse().unwrap()
    }

    #[test]
    fn record_bytes_caps_preview() {
        let mut s = SessionState::new(Protocol::Raw, dummy_addr(), 22, 4);
        s.record_bytes(b"hello world");
        assert_eq!(s.bytes_received, 11);
        assert_eq!(s.preview, b"hell");
        assert!(s.bytes_truncated);
    }

    #[test]
    fn record_bytes_below_cap_no_truncation() {
        let mut s = SessionState::new(Protocol::Raw, dummy_addr(), 22, 16);
        s.record_bytes(b"hi");
        s.record_bytes(b"!");
        assert_eq!(s.bytes_received, 3);
        assert_eq!(s.preview, b"hi!");
        assert!(!s.bytes_truncated);
    }

    #[test]
    fn ascii_preview_replaces_nonprintable() {
        assert_eq!(ascii_preview(b"ab\x01c\xff"), "ab.c.");
    }

    #[test]
    fn finalize_serializes_to_json() {
        let mut s = SessionState::new(Protocol::Ssh, dummy_addr(), 2222, 32);
        s.record_bytes(b"SSH-2.0-Client_1.0\r\n");
        s.push_event(SessionEvent::SshClientBanner {
            banner: "SSH-2.0-Client_1.0".into(),
        });
        let rec = s.finalize(CloseReason::ClientClosed);
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"protocol\":\"ssh\""));
        assert!(json.contains("\"close_reason\":\"client_closed\""));
        assert!(json.contains("ssh_client_banner"));
    }
}
