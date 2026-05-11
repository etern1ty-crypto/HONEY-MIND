//! Configuration parsing and validation.
//!
//! The honeypot is configured through a single TOML file describing global
//! settings (logging, metrics, server limits) and one or more endpoints.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// Top-level configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default, rename = "endpoint")]
    pub endpoints: Vec<EndpointConfig>,
}

/// Where session logs are written.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Path to JSONL output file. `-` or empty means stdout only.
    #[serde(default = "default_log_output")]
    pub output: String,
    /// If true, also write each JSONL line to stdout in addition to the file.
    #[serde(default)]
    pub stdout: bool,
    /// Bounded channel buffer for log records. If exceeded, oldest records are dropped.
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            output: default_log_output(),
            stdout: false,
            buffer_size: default_buffer_size(),
        }
    }
}

impl LoggingConfig {
    /// Returns the resolved file path, or `None` if logging is stdout-only.
    pub fn file_path(&self) -> Option<PathBuf> {
        if self.output.is_empty() || self.output == "-" {
            None
        } else {
            Some(PathBuf::from(&self.output))
        }
    }
}

fn default_log_output() -> String {
    "honeypot.jsonl".to_string()
}

fn default_buffer_size() -> usize {
    1024
}

/// Prometheus metrics exporter configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_bind")]
    pub bind: SocketAddr,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_metrics_bind(),
        }
    }
}

fn default_metrics_bind() -> SocketAddr {
    "127.0.0.1:9090".parse().expect("valid default")
}

/// Global server limits applied across all endpoints.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Maximum number of concurrent sessions across all endpoints.
    #[serde(default = "default_max_sessions")]
    pub max_concurrent_sessions: usize,
    /// Per-session inactivity timeout in seconds. After this many seconds without
    /// new bytes, the session is closed and logged.
    #[serde(default = "default_session_timeout")]
    pub session_timeout_seconds: u64,
    /// Maximum number of new connections per source IP per 60-second window.
    /// 0 disables rate limiting.
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_ip_per_min: u32,
    /// Maximum bytes captured per session. Excess is counted but not stored.
    #[serde(default = "default_max_bytes_per_session")]
    pub max_bytes_per_session: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_sessions: default_max_sessions(),
            session_timeout_seconds: default_session_timeout(),
            rate_limit_per_ip_per_min: default_rate_limit(),
            max_bytes_per_session: default_max_bytes_per_session(),
        }
    }
}

fn default_max_sessions() -> usize {
    1024
}

fn default_session_timeout() -> u64 {
    60
}

fn default_rate_limit() -> u32 {
    120
}

fn default_max_bytes_per_session() -> usize {
    8 * 1024
}

/// A single listening endpoint.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointConfig {
    pub bind: SocketAddr,
    pub protocol: Protocol,
    /// Optional banner sent to the client immediately after connect (raw bytes;
    /// `\n` and `\r\n` work as expected).
    #[serde(default)]
    pub banner: Option<String>,
    /// HTTP-specific: value of the `Server:` header.
    #[serde(default)]
    pub server_header: Option<String>,
    /// HTTP-specific: status code for canned responses (default 404).
    #[serde(default)]
    pub http_status: Option<u16>,
    /// Telnet-specific: text shown as login prompt (default `login: `).
    #[serde(default)]
    pub login_prompt: Option<String>,
}

/// Supported protocol emulators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Raw,
    Ssh,
    Http,
    Telnet,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Raw => "raw",
            Protocol::Ssh => "ssh",
            Protocol::Http => "http",
            Protocol::Telnet => "telnet",
        }
    }
}

impl Config {
    /// Load configuration from a TOML file on disk.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config from {}", path.display()))?;
        let cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("failed to parse TOML config at {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse from a TOML string. Validates after parsing.
    pub fn from_toml(raw: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(raw).context("failed to parse TOML config")?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Check semantic constraints: at least one endpoint, no duplicate binds, etc.
    pub fn validate(&self) -> Result<()> {
        if self.endpoints.is_empty() {
            return Err(anyhow!("config must contain at least one [[endpoint]]"));
        }
        if self.server.max_concurrent_sessions == 0 {
            return Err(anyhow!("server.max_concurrent_sessions must be > 0"));
        }
        if self.logging.buffer_size == 0 {
            return Err(anyhow!("logging.buffer_size must be > 0"));
        }
        let mut seen = HashSet::new();
        for ep in &self.endpoints {
            if !seen.insert(ep.bind) {
                return Err(anyhow!("duplicate endpoint bind address: {}", ep.bind));
            }
            if let Some(code) = ep.http_status {
                if !(100..=599).contains(&code) {
                    return Err(anyhow!(
                        "endpoint {}: http_status {} is not a valid HTTP status code",
                        ep.bind,
                        code
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let raw = r#"
            [[endpoint]]
            bind = "127.0.0.1:2222"
            protocol = "ssh"
        "#;
        let cfg = Config::from_toml(raw).expect("valid");
        assert_eq!(cfg.endpoints.len(), 1);
        assert_eq!(cfg.endpoints[0].protocol, Protocol::Ssh);
        assert_eq!(cfg.logging.output, "honeypot.jsonl");
        assert_eq!(cfg.server.session_timeout_seconds, 60);
    }

    #[test]
    fn parses_full_config() {
        let raw = r#"
            [logging]
            output = "out.jsonl"
            stdout = true
            buffer_size = 2048

            [metrics]
            enabled = true
            bind = "127.0.0.1:9999"

            [server]
            max_concurrent_sessions = 200
            session_timeout_seconds = 30
            rate_limit_per_ip_per_min = 0
            max_bytes_per_session = 4096

            [[endpoint]]
            bind = "0.0.0.0:2222"
            protocol = "ssh"
            banner = "SSH-2.0-OpenSSH_8.4"

            [[endpoint]]
            bind = "0.0.0.0:8080"
            protocol = "http"
            server_header = "nginx/1.18.0"
            http_status = 404
        "#;
        let cfg = Config::from_toml(raw).expect("valid");
        assert_eq!(cfg.endpoints.len(), 2);
        assert!(cfg.metrics.enabled);
        assert_eq!(cfg.server.max_bytes_per_session, 4096);
        assert_eq!(cfg.endpoints[1].http_status, Some(404));
    }

    #[test]
    fn rejects_empty_endpoint_list() {
        let raw = "";
        let err = Config::from_toml(raw).unwrap_err();
        assert!(err.to_string().contains("at least one"));
    }

    #[test]
    fn rejects_duplicate_binds() {
        let raw = r#"
            [[endpoint]]
            bind = "0.0.0.0:2222"
            protocol = "ssh"

            [[endpoint]]
            bind = "0.0.0.0:2222"
            protocol = "telnet"
        "#;
        let err = Config::from_toml(raw).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn rejects_unknown_keys() {
        let raw = r#"
            [[endpoint]]
            bind = "0.0.0.0:2222"
            protocol = "ssh"
            wat = "no"
        "#;
        assert!(Config::from_toml(raw).is_err());
    }

    #[test]
    fn rejects_invalid_http_status() {
        let raw = r#"
            [[endpoint]]
            bind = "0.0.0.0:8080"
            protocol = "http"
            http_status = 1234
        "#;
        let err = Config::from_toml(raw).unwrap_err();
        assert!(err.to_string().contains("status"));
    }

    #[test]
    fn logging_output_dash_is_stdout_only() {
        let cfg = LoggingConfig {
            output: "-".into(),
            stdout: false,
            buffer_size: 16,
        };
        assert!(cfg.file_path().is_none());
    }
}
