//! Real TCP tests: listeners are pre-bound on port zero, never picked then freed.

#![allow(clippy::field_reassign_with_default)]

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde_json::Value;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use minotaur::config::{Config, EndpointConfig, PrivacyMode, Protocol};
use minotaur::logger::Logger;
use minotaur::metrics::Metrics;
use minotaur::server::{AppState, BoundServer};

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(6), future)
        .await
        .expect("operation exceeded test deadline")
}

struct Harness {
    dir: TempDir,
    address: SocketAddr,
    management: SocketAddr,
    state: Option<Arc<AppState>>,
    server: Option<JoinHandle<Result<()>>>,
    writer: Option<JoinHandle<Result<()>>>,
    token: CancellationToken,
    metrics: Metrics,
}

impl Harness {
    async fn new(protocol: Protocol, configure: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.logging.output = dir
            .path()
            .join("events.jsonl")
            .to_string_lossy()
            .into_owned();
        cfg.endpoints = vec![EndpointConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            protocol,
        )];
        cfg.metrics.enabled = true;
        cfg.metrics.bind = "127.0.0.1:0".parse().unwrap();
        cfg.server.rate_limit_per_ip_per_min = 0;
        cfg.server.session_timeout_seconds = 2;
        cfg.server.max_session_duration_seconds = 5;
        configure(&mut cfg);
        let bound = BoundServer::bind(&cfg).await.unwrap();
        let address = bound.endpoint_addresses()[0];
        let management = bound.metrics_address().unwrap().unwrap();
        let metrics = Metrics::new(&cfg.sensor).unwrap();
        let (logger, writer) = Logger::spawn(&cfg.logging, metrics.clone()).await.unwrap();
        let token = CancellationToken::new();
        let state = Arc::new(AppState::new(cfg, logger, metrics.clone(), token.clone()).unwrap());
        let server = tokio::spawn(bound.run(Arc::clone(&state)));
        Self {
            dir,
            address,
            management,
            state: Some(state),
            server: Some(server),
            writer: Some(writer),
            token,
            metrics,
        }
    }

    async fn client(&self) -> Client {
        Client::connect(self.address).await
    }

    async fn wait(&self, condition: impl Fn() -> bool) {
        bounded(async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
    }

    async fn records_written(&self, count: u64) {
        self.wait(|| self.metrics.logger_written_total.get() >= count)
            .await;
    }

    async fn shutdown(mut self) -> Vec<Value> {
        self.token.cancel();
        bounded(self.server.take().unwrap()).await.unwrap().unwrap();
        drop(self.state.take());
        bounded(self.writer.take().unwrap()).await.unwrap().unwrap();
        assert_eq!(self.metrics.active_sessions.get(), 0);
        assert_eq!(self.metrics.metrics_active_connections.get(), 0);
        let body = tokio::fs::read_to_string(self.dir.path().join("events.jsonl"))
            .await
            .unwrap();
        body.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.token.cancel();
        if let Some(handle) = &self.server {
            handle.abort();
        }
        if let Some(handle) = &self.writer {
            handle.abort();
        }
    }
}

struct Client {
    stream: TcpStream,
    pending: Vec<u8>,
}

impl Client {
    async fn connect(address: SocketAddr) -> Self {
        Self {
            stream: bounded(TcpStream::connect(address)).await.unwrap(),
            pending: Vec::new(),
        }
    }

    async fn send(&mut self, bytes: &[u8]) {
        bounded(self.stream.write_all(bytes)).await.unwrap();
    }

    async fn until(&mut self, marker: &[u8]) -> Vec<u8> {
        bounded(async {
            loop {
                if let Some(index) = self.pending.windows(marker.len()).position(|v| v == marker) {
                    return self.pending.drain(..index + marker.len()).collect();
                }
                assert!(self.pending.len() < 16384, "unexpectedly large response");
                let mut buffer = [0u8; 512];
                let n = self.stream.read(&mut buffer).await.unwrap();
                assert!(n > 0, "EOF before marker");
                self.pending.extend_from_slice(&buffer[..n]);
            }
        })
        .await
    }

    async fn eof(mut self) -> Vec<u8> {
        bounded(async {
            let result = self.stream.read_to_end(&mut self.pending).await;
            if let Err(error) = result {
                // A close with unread hostile input may be represented by a TCP RST.
                assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
            }
            self.pending
        })
        .await
    }
}

#[tokio::test]
async fn http_metadata_capture_strips_sensitive_fields() {
    let h = Harness::new(Protocol::Http, |_| {}).await;
    let mut c = h.client().await;
    c.send(b"GET /admin?token=secret HTTP/1.1\r\nHost: private.local\r\nAuthorization: Bearer secret\r\nUser-Agent: sensitive-agent\r\n\r\n").await;
    let response = String::from_utf8(c.eof().await).unwrap();
    assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(!response.contains("secret"));
    h.records_written(1).await;
    let records = h.shutdown().await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["events"][0]["path"], "/admin");
    assert_eq!(records[0]["data_preview_hex"], "");
    assert_eq!(records[0]["schema_version"], 2);
    assert!(!records[0].to_string().contains("secret"));
    assert!(!records[0].to_string().contains("private.local"));
}

#[tokio::test]
async fn http_full_capture_is_explicit_and_preserves_diagnostics() {
    let h = Harness::new(Protocol::Http, |cfg| cfg.privacy.mode = PrivacyMode::Full).await;
    let mut c = h.client().await;
    c.send(b"GET /probe?q=1 HTTP/1.1\r\nHost: test.local\r\nUser-Agent: test\r\n\r\n")
        .await;
    c.eof().await;
    h.records_written(1).await;
    let records = h.shutdown().await;
    assert_eq!(records[0]["events"][0]["path"], "/probe?q=1");
    assert_eq!(records[0]["events"][0]["host"], "test.local");
    assert_eq!(records[0]["payload_captured"], true);
}

#[tokio::test]
async fn head_response_has_no_body() {
    let h = Harness::new(Protocol::Http, |_| {}).await;
    let mut c = h.client().await;
    c.send(b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n").await;
    let response = c.eof().await;
    assert!(response.ends_with(b"\r\n\r\n"));
    h.records_written(1).await;
    h.shutdown().await;
}

#[tokio::test]
async fn oversized_http_headers_are_rejected_at_exact_cap() {
    let h = Harness::new(Protocol::Http, |_| {}).await;
    let mut c = h.client().await;
    let mut request = b"GET / HTTP/1.1\r\nHost: test\r\nX-Large: ".to_vec();
    request.extend(vec![b'a'; 9000]);
    c.send(&request).await;
    c.eof().await;
    h.records_written(1).await;
    let records = h.shutdown().await;
    assert_eq!(records[0]["bytes_received"], 8192);
    assert_eq!(records[0]["close_reason"], "protocol_error");
    assert_eq!(records[0]["events"][0]["msg"], "http_headers_too_large");
}

#[tokio::test]
async fn http_delimiter_across_read_buffer_boundary_is_detected() {
    let h = Harness::new(Protocol::Http, |_| {}).await;
    let mut c = h.client().await;
    let mut request = b"GET / HTTP/1.1\r\nHost: test\r\nX-Pad: ".to_vec();
    request.resize(2047, b'a');
    request.extend_from_slice(b"\r\n\r\n");
    c.send(&request).await;
    let response = c.eof().await;
    assert!(response.starts_with(b"HTTP/1.1 404"));
    h.records_written(1).await;
    h.shutdown().await;
}

#[tokio::test]
async fn ssh_records_valid_client_identification() {
    let h = Harness::new(Protocol::Ssh, |_| {}).await;
    let mut c = h.client().await;
    assert!(c.until(b"\r\n").await.starts_with(b"SSH-2.0-"));
    c.send(b"SSH-2.0-TestClient\r\n").await;
    c.stream.shutdown().await.unwrap();
    c.eof().await;
    h.records_written(1).await;
    let records = h.shutdown().await;
    assert_eq!(records[0]["events"][0]["banner"], "SSH-2.0-TestClient");
    assert_eq!(records[0]["close_reason"], "client_closed");
}

#[tokio::test]
async fn ssh_rejects_oversized_identification() {
    let h = Harness::new(Protocol::Ssh, |_| {}).await;
    let mut c = h.client().await;
    c.until(b"\r\n").await;
    c.send(&vec![b'a'; 256]).await;
    c.eof().await;
    h.records_written(1).await;
    let records = h.shutdown().await;
    assert_eq!(records[0]["close_reason"], "protocol_error");
}

#[tokio::test]
async fn telnet_pipeline_retains_every_attempt_and_redacts_credentials() {
    let h = Harness::new(Protocol::Telnet, |_| {}).await;
    let mut c = h.client().await;
    c.until(b"login: ").await;
    c.send(b"admin\r\nsecret\r\nroot\r\nsecret2\r\nuser\r\nsecret3\r\n")
        .await;
    let response = c.eof().await;
    assert!(String::from_utf8_lossy(&response).contains("Too many attempts"));
    h.records_written(1).await;
    let records = h.shutdown().await;
    assert_eq!(records[0]["events"].as_array().unwrap().len(), 3);
    assert!(!records[0].to_string().contains("secret"));
    assert_eq!(records[0]["events"][0]["credentials_redacted"], true);
}

#[tokio::test]
async fn telnet_full_mode_preserves_spaces_empty_password_and_iac_state() {
    let h = Harness::new(Protocol::Telnet, |cfg| cfg.privacy.mode = PrivacyMode::Full).await;
    let mut c = h.client().await;
    c.until(b"login: ").await;
    c.send(b"\xff\xfa\x18term\nvalue\xff\xf0 user \r\n\r\n")
        .await;
    c.until(b"Login incorrect\r\n").await;
    c.stream.shutdown().await.unwrap();
    c.eof().await;
    h.records_written(1).await;
    let records = h.shutdown().await;
    assert_eq!(records[0]["events"][0]["username"], " user ");
    assert_eq!(records[0]["events"][0]["password"], "");
}

#[tokio::test]
async fn telnet_eof_before_password_preserves_close_reason() {
    let h = Harness::new(Protocol::Telnet, |_| {}).await;
    let mut c = h.client().await;
    c.until(b"login: ").await;
    c.send(b"admin\r\n").await;
    c.until(b"Password: ").await;
    c.stream.shutdown().await.unwrap();
    c.eof().await;
    h.records_written(1).await;
    let records = h.shutdown().await;
    assert_eq!(records[0]["close_reason"], "client_closed");
    assert!(records[0]["events"][0]["password"].is_null());
}

#[tokio::test]
async fn telnet_oversized_line_is_not_reinterpreted_as_a_password() {
    let h = Harness::new(Protocol::Telnet, |_| {}).await;
    let mut c = h.client().await;
    c.until(b"login: ").await;
    c.send(&vec![b'a'; 257]).await;
    c.eof().await;
    h.records_written(1).await;
    let records = h.shutdown().await;
    assert_eq!(records[0]["close_reason"], "protocol_error");
    assert!(records[0]["events"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["type"] != "telnet_login"));
}

#[tokio::test]
async fn raw_preview_and_total_input_have_separate_limits() {
    let h = Harness::new(Protocol::Raw, |cfg| {
        cfg.privacy.mode = PrivacyMode::Full;
        cfg.server.max_bytes_per_session = 4;
        cfg.server.max_read_bytes_per_session = 8;
    })
    .await;
    let mut c = h.client().await;
    c.send(b"abcdefgh").await;
    c.eof().await;
    h.records_written(1).await;
    let records = h.shutdown().await;
    assert_eq!(records[0]["bytes_received"], 8);
    assert_eq!(records[0]["data_preview_ascii"], "abcd");
    assert_eq!(records[0]["bytes_truncated"], true);
    assert_eq!(records[0]["close_reason"], "byte_limit");
}

#[tokio::test]
async fn idle_connection_times_out() {
    let h = Harness::new(Protocol::Raw, |cfg| cfg.server.session_timeout_seconds = 1).await;
    h.client().await.eof().await;
    h.records_written(1).await;
    let records = h.shutdown().await;
    assert_eq!(records[0]["close_reason"], "timeout");
}

#[tokio::test]
async fn continuous_trickle_cannot_reset_absolute_lifetime() {
    let h = Harness::new(Protocol::Raw, |cfg| {
        cfg.server.session_timeout_seconds = 1;
        cfg.server.max_session_duration_seconds = 2;
    })
    .await;
    let mut c = h.client().await;
    let (mut read, mut write) = c.stream.split();
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    bounded(async {
        let mut byte = [0u8; 1];
        loop {
            tokio::select! {
                result = read.read(&mut byte) => {
                    match result {
                        Ok(0) => break,
                        Ok(_) => {},
                        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
                        Err(e) => panic!("unexpected read error: {e:?}"),
                    }
                }
                _ = tick.tick() => { if write.write_all(b"x").await.is_err() { break; } }
            }
        }
    })
    .await;
    h.records_written(1).await;
    let records = h.shutdown().await;
    assert_eq!(records[0]["close_reason"], "lifetime_limit");
}

#[tokio::test]
async fn rate_limit_rejections_are_observable() {
    let h = Harness::new(Protocol::Raw, |cfg| {
        cfg.server.rate_limit_per_ip_per_min = 1
    })
    .await;
    let _first = h.client().await;
    h.wait(|| {
        h.metrics
            .connections_total
            .with_label_values(&["raw"])
            .get()
            == 1
    })
    .await;
    assert!(h.client().await.eof().await.is_empty());
    assert_eq!(
        h.metrics
            .rejected_total
            .with_label_values(&["raw", "rate_limit"])
            .get(),
        1
    );
    let records = h.shutdown().await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["close_reason"], "shutdown");
}

#[tokio::test]
async fn global_session_capacity_rejects_and_shutdown_drains() {
    let h = Harness::new(Protocol::Raw, |cfg| cfg.server.max_concurrent_sessions = 1).await;
    let _first = h.client().await;
    h.wait(|| h.metrics.active_sessions.get() == 1).await;
    assert!(h.client().await.eof().await.is_empty());
    assert_eq!(
        h.metrics
            .rejected_total
            .with_label_values(&["raw", "max_sessions"])
            .get(),
        1
    );
    let records = h.shutdown().await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["close_reason"], "shutdown");
}

#[tokio::test]
async fn ignored_ip_does_not_create_a_session() {
    let h = Harness::new(Protocol::Raw, |cfg| {
        cfg.server
            .ignore_source_ips
            .push("127.0.0.1".parse().unwrap())
    })
    .await;
    assert!(h.client().await.eof().await.is_empty());
    assert_eq!(
        h.metrics
            .rejected_total
            .with_label_values(&["raw", "ignored_ip"])
            .get(),
        1
    );
    assert!(h.shutdown().await.is_empty());
}

#[tokio::test]
async fn management_probes_do_not_become_honeypot_events() {
    let h = Harness::new(Protocol::Http, |_| {}).await;
    h.wait(|| h.metrics.ready.get() == 1).await;
    let mut client = Client::connect(h.management).await;
    client
        .send(b"GET /readyz HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await;
    assert!(client.eof().await.starts_with(b"HTTP/1.1 200"));
    assert!(h.shutdown().await.is_empty());
}

#[tokio::test]
async fn management_slow_clients_are_bounded_and_expire() {
    let h = Harness::new(Protocol::Raw, |cfg| {
        cfg.metrics.max_connections = 1;
        cfg.metrics.request_timeout_seconds = 1;
    })
    .await;
    let first = Client::connect(h.management).await;
    h.wait(|| h.metrics.metrics_active_connections.get() == 1)
        .await;
    assert!(Client::connect(h.management).await.eof().await.is_empty());
    assert_eq!(h.metrics.metrics_rejected_total.get(), 1);
    assert!(first.eof().await.is_empty());
    assert!(h.shutdown().await.is_empty());
}

#[tokio::test]
async fn later_bind_failure_returns_without_starting_workers() {
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cfg = Config::default();
    cfg.endpoints = vec![EndpointConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        Protocol::Raw,
    )];
    cfg.metrics.enabled = true;
    cfg.metrics.bind = occupied.local_addr().unwrap();
    assert!(bounded(BoundServer::bind(&cfg)).await.is_err());
}
