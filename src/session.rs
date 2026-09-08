//! Versioned JSONL records and privacy enforcement before events enter the queue.

use std::net::SocketAddr;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{Config, EndpointConfig, PrivacyConfig, PrivacyMode, Protocol, SensorConfig};

pub const SCHEMA_VERSION: u32 = 2;
const MAX_EVENTS: usize = 16;

#[derive(Debug, Clone, Serialize)]
pub struct SessionRecord {
    pub schema_version: u32,
    pub ts: DateTime<Utc>,
    pub session_id: Uuid,
    pub sensor: SensorConfig,
    pub endpoint: String,
    pub protocol: &'static str,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub dst_port: u16,
    pub duration_ms: u64,
    pub bytes_received: u64,
    pub payload_captured: bool,
    pub bytes_truncated: bool,
    pub data_preview_hex: String,
    pub data_preview_ascii: String,
    pub privacy_mode: PrivacyMode,
    pub events: Vec<SessionEvent>,
    pub events_truncated: bool,
    pub close_reason: CloseReason,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEvent {
    SshClientBanner {
        banner: String,
    },
    HttpRequest {
        method: String,
        path: String,
        version: String,
        host: Option<String>,
        user_agent: Option<String>,
    },
    TelnetLogin {
        username: String,
        password: Option<String>,
        credentials_redacted: bool,
    },
    Notice {
        msg: String,
    },
}

impl SessionEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::SshClientBanner { .. } => "ssh_client_banner",
            Self::HttpRequest { .. } => "http_request",
            Self::TelnetLogin { .. } => "telnet_login",
            Self::Notice { .. } => "notice",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    ClientClosed,
    Timeout,
    LifetimeLimit,
    ByteLimit,
    ProtocolError,
    ServerClosed,
    Error,
    Shutdown,
}

impl CloseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientClosed => "client_closed",
            Self::Timeout => "timeout",
            Self::LifetimeLimit => "lifetime_limit",
            Self::ByteLimit => "byte_limit",
            Self::ProtocolError => "protocol_error",
            Self::ServerClosed => "server_closed",
            Self::Error => "error",
            Self::Shutdown => "shutdown",
        }
    }
}

pub struct SessionState {
    pub id: Uuid,
    pub protocol: Protocol,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub started_at: Instant,
    pub ts: DateTime<Utc>,
    pub bytes_received: u64,
    pub events: Vec<SessionEvent>,
    preview: Vec<u8>,
    preview_limit: usize,
    input_limit: usize,
    events_truncated: bool,
    sensor: SensorConfig,
    endpoint: String,
    privacy: PrivacyConfig,
}

impl SessionState {
    pub fn new(ep: &EndpointConfig, src: SocketAddr, dst: SocketAddr, cfg: &Config) -> Self {
        Self {
            id: Uuid::new_v4(),
            protocol: ep.protocol,
            src,
            dst,
            started_at: Instant::now(),
            ts: Utc::now(),
            bytes_received: 0,
            events: Vec::new(),
            preview: Vec::new(),
            preview_limit: cfg.server.max_bytes_per_session,
            input_limit: cfg.server.max_read_bytes_per_session,
            events_truncated: false,
            sensor: cfg.sensor.clone(),
            endpoint: ep.label(),
            privacy: cfg.privacy.clone(),
        }
    }

    pub fn remaining_input(&self) -> usize {
        self.input_limit
            .saturating_sub(self.bytes_received.min(usize::MAX as u64) as usize)
    }

    /// Only SessionIo should call this for network input: it enforces input_limit.
    pub fn record_bytes(&mut self, bytes: &[u8]) {
        self.bytes_received = self.bytes_received.saturating_add(bytes.len() as u64);
        if self.privacy.mode == PrivacyMode::Full {
            let take = self
                .preview_limit
                .saturating_sub(self.preview.len())
                .min(bytes.len());
            self.preview.extend_from_slice(&bytes[..take]);
        }
    }

    pub fn push_event(&mut self, mut event: SessionEvent) {
        if self.events.len() >= MAX_EVENTS {
            self.events_truncated = true;
            return;
        }
        match &mut event {
            SessionEvent::HttpRequest {
                path,
                host,
                user_agent,
                ..
            } => {
                if !self.privacy.capture_http_path {
                    *path = "[redacted]".into();
                } else if self.privacy.mode == PrivacyMode::Metadata {
                    if let Some(index) = path.find(['?', '#']) {
                        path.truncate(index);
                    }
                }
                if self.privacy.mode == PrivacyMode::Metadata {
                    *host = None;
                    *user_agent = None;
                }
            }
            SessionEvent::TelnetLogin {
                username,
                password,
                credentials_redacted,
            } if self.privacy.mode == PrivacyMode::Metadata => {
                *username = "[redacted]".into();
                if password.is_some() {
                    *password = Some("[redacted]".into());
                }
                *credentials_redacted = true;
            }
            _ => {}
        }
        self.events.push(event);
    }

    pub fn notice(&mut self, msg: &str) {
        self.push_event(SessionEvent::Notice { msg: msg.into() });
    }

    pub fn finalize(self, close_reason: CloseReason) -> SessionRecord {
        let payload_captured = self.privacy.mode == PrivacyMode::Full && self.preview_limit > 0;
        let duration_ms = self.started_at.elapsed().as_millis().min(u64::MAX as u128) as u64;
        SessionRecord {
            schema_version: SCHEMA_VERSION,
            ts: self.ts,
            session_id: self.id,
            sensor: self.sensor,
            endpoint: self.endpoint,
            protocol: self.protocol.as_str(),
            src: self.src,
            dst: self.dst,
            dst_port: self.dst.port(),
            duration_ms,
            bytes_received: self.bytes_received,
            payload_captured,
            bytes_truncated: payload_captured && self.bytes_received > self.preview.len() as u64,
            data_preview_hex: hex::encode(&self.preview),
            data_preview_ascii: ascii_preview(&self.preview),
            privacy_mode: self.privacy.mode,
            events: self.events,
            events_truncated: self.events_truncated,
            close_reason,
        }
    }
}

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
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    fn state(full: bool) -> SessionState {
        let mut cfg = Config::default();
        cfg.server.max_bytes_per_session = 4;
        if full {
            cfg.privacy.mode = PrivacyMode::Full;
        }
        let addr = "127.0.0.1:1234".parse().unwrap();
        let ep = EndpointConfig::new(addr, Protocol::Telnet);
        SessionState::new(&ep, addr, addr, &cfg)
    }

    #[test]
    fn full_capture_is_bounded() {
        let mut s = state(true);
        s.record_bytes(b"hello world");
        s.record_bytes(b"");
        let r = s.finalize(CloseReason::ClientClosed);
        assert_eq!(r.bytes_received, 11);
        assert_eq!(r.data_preview_ascii, "hell");
        assert!(r.bytes_truncated);
    }

    #[test]
    fn exact_cap_and_empty_chunk_are_not_truncation() {
        let mut s = state(true);
        s.record_bytes(b"test");
        s.record_bytes(b"");
        assert!(!s.finalize(CloseReason::ClientClosed).bytes_truncated);
    }

    #[test]
    fn metadata_redacts_credentials_and_never_stores_payload() {
        let mut s = state(false);
        s.record_bytes(b"admin\r\nsecret\r\n");
        s.push_event(SessionEvent::TelnetLogin {
            username: "admin".into(),
            password: Some("secret".into()),
            credentials_redacted: false,
        });
        let json = serde_json::to_string(&s.finalize(CloseReason::ClientClosed)).unwrap();
        assert!(!json.contains("secret"));
        assert!(!json.contains("admin"));
        assert!(json.contains("[redacted]"));
        assert!(json.contains("\"payload_captured\":false"));
    }

    #[test]
    fn metadata_strips_query_and_headers() {
        let mut s = state(false);
        s.push_event(SessionEvent::HttpRequest {
            method: "GET".into(),
            path: "/admin?token=secret#secret".into(),
            version: "HTTP/1.1".into(),
            host: Some("private.example".into()),
            user_agent: Some("private-client".into()),
        });
        let json = serde_json::to_string(&s.finalize(CloseReason::ServerClosed)).unwrap();
        assert!(json.contains("/admin"));
        assert!(!json.contains("secret"));
        assert!(!json.contains("private"));
    }

    #[test]
    fn event_vector_is_bounded() {
        let mut s = state(false);
        for _ in 0..100 {
            s.notice("bounded");
        }
        let r = s.finalize(CloseReason::ServerClosed);
        assert_eq!(r.events.len(), MAX_EVENTS);
        assert!(r.events_truncated);
    }

    #[test]
    fn preview_is_printable() {
        assert_eq!(ascii_preview(b"ab\x00\xff"), "ab..");
    }
}
