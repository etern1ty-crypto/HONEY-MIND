//! End-to-end integration tests.
//!
//! Each test:
//!   1. Builds an [`AppState`] with a temp-file logger and an ephemeral
//!      endpoint bound to `127.0.0.1:0`.
//!   2. Spawns the server.
//!   3. Connects via [`tokio::net::TcpStream`] and exercises the protocol.
//!   4. Signals shutdown and waits for the writer to flush.
//!   5. Parses the resulting JSONL and asserts on the recorded fields.

use std::sync::Arc;
use std::time::Duration;

use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use minotaur::config::{
    Config, EndpointConfig, LoggingConfig, MetricsConfig, Protocol, ServerConfig,
};
use minotaur::logger::Logger;
use minotaur::metrics::Metrics;
use minotaur::server::{self, AppState};

async fn pick_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

struct Harness {
    log_path: std::path::PathBuf,
    state: Arc<AppState>,
    logger_handle: tokio::task::JoinHandle<()>,
    server_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    shutdown: CancellationToken,
    _log_file: NamedTempFile,
}

impl Harness {
    async fn new(ep: EndpointConfig) -> Self {
        let log_file = NamedTempFile::new().unwrap();
        let log_path = log_file.path().to_owned();

        let cfg = Config {
            logging: LoggingConfig {
                output: log_path.to_string_lossy().into_owned(),
                stdout: false,
                buffer_size: 256,
            },
            metrics: MetricsConfig {
                enabled: false,
                bind: "127.0.0.1:0".parse().unwrap(),
            },
            server: ServerConfig {
                max_concurrent_sessions: 16,
                session_timeout_seconds: 2,
                rate_limit_per_ip_per_min: 0,
                max_bytes_per_session: 4096,
            },
            endpoints: vec![ep],
        };
        cfg.validate().unwrap();

        let (logger, logger_handle) = Logger::spawn(Some(&log_path), false, 256).await.unwrap();
        let metrics = Metrics::new().unwrap();
        let shutdown = CancellationToken::new();
        let state = Arc::new(AppState::new(cfg, logger, metrics, shutdown.clone()));

        let state_clone = Arc::clone(&state);
        let server_handle = tokio::spawn(async move { server::run(state_clone).await });

        // Give the listener time to bind.
        sleep(Duration::from_millis(50)).await;

        Self {
            log_path,
            state,
            logger_handle,
            server_handle,
            shutdown,
            _log_file: log_file,
        }
    }

    fn endpoint_addr(&self) -> std::net::SocketAddr {
        self.state.config.endpoints[0].bind
    }

    async fn shutdown_and_read(self) -> Vec<serde_json::Value> {
        // Give in-flight sessions a moment to finalize, then cancel.
        sleep(Duration::from_millis(50)).await;
        self.shutdown.cancel();
        let _ = self.server_handle.await.unwrap();
        // Drop the state to release the Logger clones held in AppState.
        let log_path = self.log_path.clone();
        drop(self.state);
        let _ = self.logger_handle.await;
        let body = tokio::fs::read_to_string(&log_path).await.unwrap();
        body.lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("valid JSONL"))
            .collect()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_endpoint_records_client_banner() {
    let port = pick_port().await;
    let bind = format!("127.0.0.1:{port}").parse().unwrap();
    let h = Harness::new(EndpointConfig {
        bind,
        protocol: Protocol::Ssh,
        banner: Some("SSH-2.0-Honeypot_1.0".into()),
        server_header: None,
        http_status: None,
        login_prompt: None,
    })
    .await;

    let mut stream = TcpStream::connect(h.endpoint_addr()).await.unwrap();
    let mut server_banner = [0u8; 64];
    let n = stream.read(&mut server_banner).await.unwrap();
    let server_banner = String::from_utf8_lossy(&server_banner[..n]).into_owned();
    assert!(
        server_banner.starts_with("SSH-2.0-Honeypot_1.0"),
        "got banner: {server_banner:?}"
    );
    stream
        .write_all(b"SSH-2.0-IntegrationTest_42\r\n")
        .await
        .unwrap();
    stream.flush().await.unwrap();
    drop(stream);

    let records = h.shutdown_and_read().await;
    assert_eq!(records.len(), 1, "got: {records:?}");
    let r = &records[0];
    assert_eq!(r["protocol"], "ssh");
    let events = r["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["type"], "ssh_client_banner");
    assert_eq!(events[0]["banner"], "SSH-2.0-IntegrationTest_42");
    assert_eq!(r["close_reason"], "client_closed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_endpoint_parses_request_and_responds() {
    let port = pick_port().await;
    let bind = format!("127.0.0.1:{port}").parse().unwrap();
    let h = Harness::new(EndpointConfig {
        bind,
        protocol: Protocol::Http,
        banner: None,
        server_header: Some("nginx/1.21.0".into()),
        http_status: Some(404),
        login_prompt: None,
    })
    .await;

    let mut stream = TcpStream::connect(h.endpoint_addr()).await.unwrap();
    stream
        .write_all(b"GET /wp-admin HTTP/1.1\r\nHost: target.example\r\nUser-Agent: Mozilla/5.0 Scanner\r\n\r\n")
        .await
        .unwrap();
    stream.flush().await.unwrap();

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();
    let resp = String::from_utf8_lossy(&resp).into_owned();
    assert!(resp.starts_with("HTTP/1.1 404 Not Found\r\n"), "{resp}");
    assert!(resp.contains("Server: nginx/1.21.0"), "{resp}");

    let records = h.shutdown_and_read().await;
    assert_eq!(records.len(), 1, "got: {records:?}");
    let r = &records[0];
    assert_eq!(r["protocol"], "http");
    let events = r["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["type"], "http_request");
    assert_eq!(events[0]["method"], "GET");
    assert_eq!(events[0]["path"], "/wp-admin");
    assert_eq!(events[0]["host"], "target.example");
    assert_eq!(events[0]["user_agent"], "Mozilla/5.0 Scanner");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn telnet_captures_login_when_username_and_password_arrive_in_one_segment() {
    let port = pick_port().await;
    let bind = format!("127.0.0.1:{port}").parse().unwrap();
    let h = Harness::new(EndpointConfig {
        bind,
        protocol: Protocol::Telnet,
        banner: None,
        server_header: None,
        http_status: None,
        login_prompt: Some("login: ".into()),
    })
    .await;

    let mut stream = TcpStream::connect(h.endpoint_addr()).await.unwrap();
    let mut buf = [0u8; 128];
    let _ = stream.read(&mut buf).await.unwrap();
    // Send both lines in one write: a scanner pipelining credentials.
    stream.write_all(b"admin\r\nletmein\r\n").await.unwrap();
    // Read whatever the server sends (Password: prompt + Login incorrect).
    sleep(Duration::from_millis(200)).await;
    let _ = stream.read(&mut buf).await.unwrap();
    drop(stream);

    let records = h.shutdown_and_read().await;
    assert_eq!(records.len(), 1, "got: {records:?}");
    let events = records[0]["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["username"], "admin");
    assert_eq!(events[0]["password"], "letmein");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn telnet_endpoint_captures_login() {
    let port = pick_port().await;
    let bind = format!("127.0.0.1:{port}").parse().unwrap();
    let h = Harness::new(EndpointConfig {
        bind,
        protocol: Protocol::Telnet,
        banner: Some("Welcome".into()),
        server_header: None,
        http_status: None,
        login_prompt: Some("login: ".into()),
    })
    .await;

    let mut stream = TcpStream::connect(h.endpoint_addr()).await.unwrap();

    // Read banner + first login prompt.
    let mut buf = [0u8; 128];
    let n = stream.read(&mut buf).await.unwrap();
    let initial = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(initial.contains("Welcome"));
    assert!(initial.contains("login:"));

    stream.write_all(b"root\r\n").await.unwrap();
    // Read password prompt.
    let n = stream.read(&mut buf).await.unwrap();
    let pwd_prompt = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(pwd_prompt.contains("Password:"));
    stream.write_all(b"hunter2\r\n").await.unwrap();

    // Read "Login incorrect" then close from our side.
    let _ = stream.read(&mut buf).await.unwrap();
    drop(stream);

    let records = h.shutdown_and_read().await;
    assert_eq!(records.len(), 1, "got: {records:?}");
    let r = &records[0];
    assert_eq!(r["protocol"], "telnet");
    let events = r["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["type"], "telnet_login");
    assert_eq!(events[0]["username"], "root");
    assert_eq!(events[0]["password"], "hunter2");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_endpoint_sends_banner_and_logs_bytes() {
    let port = pick_port().await;
    let bind = format!("127.0.0.1:{port}").parse().unwrap();
    let h = Harness::new(EndpointConfig {
        bind,
        protocol: Protocol::Raw,
        banner: Some("+OK\r\n".into()),
        server_header: None,
        http_status: None,
        login_prompt: None,
    })
    .await;

    let mut stream = TcpStream::connect(h.endpoint_addr()).await.unwrap();
    let mut buf = [0u8; 32];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"+OK\r\n");

    stream.write_all(b"AUTH mypass\r\n").await.unwrap();
    stream.flush().await.unwrap();
    drop(stream);

    let records = h.shutdown_and_read().await;
    assert_eq!(records.len(), 1, "got: {records:?}");
    let r = &records[0];
    assert_eq!(r["protocol"], "raw");
    assert_eq!(r["bytes_received"], 13);
    let ascii = r["data_preview_ascii"].as_str().unwrap();
    assert!(ascii.starts_with("AUTH mypass"), "got: {ascii:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_timeout_closes_idle_connection() {
    let port = pick_port().await;
    let bind = format!("127.0.0.1:{port}").parse().unwrap();
    let h = Harness::new(EndpointConfig {
        bind,
        protocol: Protocol::Raw,
        banner: None,
        server_header: None,
        http_status: None,
        login_prompt: None,
    })
    .await;

    let _stream = TcpStream::connect(h.endpoint_addr()).await.unwrap();
    // Wait longer than the configured 2s session_timeout.
    sleep(Duration::from_millis(2500)).await;

    let records = h.shutdown_and_read().await;
    assert_eq!(records.len(), 1, "got: {records:?}");
    assert_eq!(records[0]["close_reason"], "timeout");
}
