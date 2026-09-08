//! Strict TOML configuration. Defaults favour local, metadata-only operation.

use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub sensor: SensorConfig,
    pub privacy: PrivacyConfig,
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
    pub server: ServerConfig,
    #[serde(rename = "endpoint")]
    pub endpoints: Vec<EndpointConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SensorConfig {
    pub id: String,
    pub environment: String,
    pub tags: BTreeMap<String, String>,
}

impl Default for SensorConfig {
    fn default() -> Self {
        Self {
            id: "local-sensor".into(),
            environment: "development".into(),
            tags: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivacyMode {
    #[default]
    Metadata,
    Full,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivacyConfig {
    pub mode: PrivacyMode,
    /// Even URL paths can contain secrets. Disable this for stricter minimisation.
    pub capture_http_path: bool,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            mode: PrivacyMode::Metadata,
            capture_http_path: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// Empty or "-" always selects stdout, regardless of `stdout`.
    pub output: String,
    pub stdout: bool,
    /// A full queue drops the NEW record; existing records are never displaced.
    pub buffer_size: usize,
    pub max_file_bytes: u64,
    /// Number of rotated archives, in addition to the active file.
    pub max_files: usize,
    pub write_timeout_seconds: u64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            output: "honeypot.jsonl".into(),
            stdout: false,
            buffer_size: 256,
            max_file_bytes: 10 * 1024 * 1024,
            max_files: 3,
            write_timeout_seconds: 3,
        }
    }
}

impl LoggingConfig {
    pub fn file_path(&self) -> Option<PathBuf> {
        match self.output.as_str() {
            "" | "-" => None,
            other => Some(PathBuf::from(other)),
        }
    }

    pub fn writes_stdout(&self) -> bool {
        self.stdout || self.file_path().is_none()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub bind: SocketAddr,
    /// Required opt-in for a non-loopback management listener; not authentication.
    pub allow_remote: bool,
    pub max_connections: usize,
    pub request_timeout_seconds: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 9090)),
            allow_remote: false,
            max_connections: 16,
            request_timeout_seconds: 3,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub max_concurrent_sessions: usize,
    /// Deadline for each read/write. The absolute deadline below cannot be reset.
    pub session_timeout_seconds: u64,
    pub max_session_duration_seconds: u64,
    pub shutdown_grace_seconds: u64,
    pub rate_limit_per_ip_per_min: u32,
    pub max_tracked_ips: usize,
    /// Captured prefix limit; capture itself requires privacy.mode = "full".
    pub max_bytes_per_session: usize,
    /// Total application bytes read before closing; independent of the preview.
    pub max_read_bytes_per_session: usize,
    /// Exact addresses only, not CIDRs. Ignored peers are immediately disconnected.
    pub ignore_source_ips: Vec<IpAddr>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_sessions: 256,
            session_timeout_seconds: 15,
            max_session_duration_seconds: 60,
            shutdown_grace_seconds: 10,
            rate_limit_per_ip_per_min: 30,
            max_tracked_ips: 4096,
            max_bytes_per_session: 1024,
            max_read_bytes_per_session: 65536,
            ignore_source_ips: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointConfig {
    #[serde(default)]
    pub name: String,
    pub bind: SocketAddr,
    pub protocol: Protocol,
    #[serde(default)]
    pub banner: Option<String>,
    #[serde(default)]
    pub server_header: Option<String>,
    #[serde(default)]
    pub http_status: Option<u16>,
    #[serde(default)]
    pub login_prompt: Option<String>,
}

impl EndpointConfig {
    pub fn new(bind: SocketAddr, protocol: Protocol) -> Self {
        Self {
            name: String::new(),
            bind,
            protocol,
            banner: None,
            server_header: None,
            http_status: None,
            login_prompt: None,
        }
    }

    pub fn label(&self) -> String {
        if self.name.is_empty() {
            format!("{}-{}", self.protocol.as_str(), self.bind.port())
        } else {
            self.name.clone()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Raw,
    Ssh,
    Http,
    Telnet,
}

impl Protocol {
    pub const ALL: [Self; 4] = [Self::Raw, Self::Ssh, Self::Http, Self::Telnet];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Ssh => "ssh",
            Self::Http => "http",
            Self::Telnet => "telnet",
        }
    }
}

impl Config {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("cannot inspect config {}", path.display()))?;
        ensure!(metadata.is_file(), "config must be a regular file");
        ensure!(metadata.len() <= 65536, "config exceeds 64 KiB");
        let mut raw = String::new();
        std::fs::File::open(path)
            .with_context(|| format!("cannot open config {}", path.display()))?
            .take(65537)
            .read_to_string(&mut raw)
            .with_context(|| format!("cannot read config {}", path.display()))?;
        let mut cfg = Self::from_toml(&raw)?;
        if let Some(output) = cfg.logging.file_path() {
            if output.is_relative() {
                let parent = path.parent().unwrap_or_else(|| Path::new("."));
                cfg.logging.output = parent.join(output).to_string_lossy().into_owned();
            }
        }
        Ok(cfg)
    }

    pub fn from_toml(raw: &str) -> Result<Self> {
        ensure!(raw.len() <= 65536, "config exceeds 64 KiB");
        let cfg: Self = toml::from_str(raw).context("invalid TOML configuration")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.endpoints.is_empty(),
            "at least one [[endpoint]] is required"
        );
        range("endpoint count", self.endpoints.len() as u64, 1, 32)?;
        identifier("sensor.id", &self.sensor.id)?;
        identifier("sensor.environment", &self.sensor.environment)?;
        ensure!(
            self.sensor.tags.len() <= 8,
            "sensor.tags allows at most 8 entries"
        );
        for (key, value) in &self.sensor.tags {
            identifier("sensor tag key", key)?;
            safe_text("sensor tag value", value, 128)?;
        }

        let s = &self.server;
        range(
            "server.max_concurrent_sessions",
            s.max_concurrent_sessions as u64,
            1,
            4096,
        )?;
        range(
            "server.session_timeout_seconds",
            s.session_timeout_seconds,
            1,
            300,
        )?;
        range(
            "server.max_session_duration_seconds",
            s.max_session_duration_seconds,
            1,
            3600,
        )?;
        range(
            "server.shutdown_grace_seconds",
            s.shutdown_grace_seconds,
            1,
            60,
        )?;
        range(
            "server.rate_limit_per_ip_per_min",
            s.rate_limit_per_ip_per_min as u64,
            0,
            10000,
        )?;
        range("server.max_tracked_ips", s.max_tracked_ips as u64, 1, 65536)?;
        range(
            "server.max_bytes_per_session",
            s.max_bytes_per_session as u64,
            0,
            65536,
        )?;
        range(
            "server.max_read_bytes_per_session",
            s.max_read_bytes_per_session as u64,
            1,
            16777216,
        )?;
        ensure!(
            s.max_bytes_per_session <= s.max_read_bytes_per_session,
            "preview limit must not exceed the total read limit"
        );
        ensure!(
            (s.max_tracked_ips as u64) * (s.rate_limit_per_ip_per_min as u64) <= 1_000_000,
            "rate-limit history budget exceeds 1,000,000 timestamps"
        );
        ensure!(
            s.ignore_source_ips.len() <= 256,
            "ignore_source_ips allows at most 256 addresses"
        );
        let mut ignored = HashSet::new();
        for ip in &s.ignore_source_ips {
            ensure!(
                ignored.insert(canonical_ip(*ip)),
                "duplicate ignored IP: {ip}"
            );
        }

        let l = &self.logging;
        ensure!(
            !l.output.contains('\0'),
            "logging.output contains a NUL byte"
        );
        range("logging.buffer_size", l.buffer_size as u64, 1, 4096)?;
        range(
            "logging.max_file_bytes",
            l.max_file_bytes,
            1048576,
            1073741824,
        )?;
        range("logging.max_files", l.max_files as u64, 1, 20)?;
        range(
            "logging.write_timeout_seconds",
            l.write_timeout_seconds,
            1,
            30,
        )?;
        let estimated_record_bytes = 65536 + 3 * s.max_bytes_per_session as u64;
        ensure!(
            estimated_record_bytes * l.buffer_size as u64 <= 268435456,
            "logging queue budget exceeds 256 MiB; reduce buffer_size or preview size"
        );

        let m = &self.metrics;
        range("metrics.max_connections", m.max_connections as u64, 1, 256)?;
        range(
            "metrics.request_timeout_seconds",
            m.request_timeout_seconds,
            1,
            30,
        )?;
        ensure!(
            !m.enabled || m.bind.ip().is_loopback() || m.allow_remote,
            "non-loopback metrics requires allow_remote = true and a management firewall"
        );

        let mut names = HashSet::new();
        for (index, ep) in self.endpoints.iter().enumerate() {
            if !ep.name.is_empty() {
                identifier("endpoint.name", &ep.name)?;
                ensure!(
                    names.insert(ep.name.as_str()),
                    "duplicate endpoint name: {}",
                    ep.name
                );
            }
            for previous in &self.endpoints[..index] {
                ensure!(
                    !binds_conflict(ep.bind, previous.bind),
                    "overlapping or duplicate endpoint binds: {} and {}",
                    ep.bind,
                    previous.bind
                );
            }
            ensure!(
                !m.enabled || !binds_conflict(ep.bind, m.bind),
                "endpoint {} overlaps the metrics bind",
                ep.bind
            );
            if let Some(banner) = &ep.banner {
                ensure!(banner.len() <= 4096, "endpoint banner exceeds 4096 bytes");
                ensure!(
                    ep.protocol != Protocol::Http,
                    "HTTP does not use endpoint.banner"
                );
                if ep.protocol == Protocol::Ssh {
                    ensure!(
                        banner.len() <= 253,
                        "SSH banner exceeds 253 bytes before CRLF"
                    );
                    ensure!(
                        banner.starts_with("SSH-2.0-") || banner.starts_with("SSH-1.99-"),
                        "SSH banner must start with SSH-2.0- or SSH-1.99-"
                    );
                    ensure!(
                        banner.bytes().all(|b| (0x20..=0x7e).contains(&b)),
                        "SSH banner must be printable ASCII without CR/LF"
                    );
                }
            }
            if let Some(header) = &ep.server_header {
                ensure!(ep.protocol == Protocol::Http, "server_header is HTTP-only");
                ensure!(
                    !header.is_empty()
                        && header.len() <= 256
                        && header.bytes().all(|b| (0x20..=0x7e).contains(&b)),
                    "server_header must be 1..256 printable ASCII bytes without CR/LF"
                );
            }
            if let Some(status) = ep.http_status {
                ensure!(ep.protocol == Protocol::Http, "http_status is HTTP-only");
                ensure!(
                    (200..=599).contains(&status),
                    "http_status must be a final status in 200..599"
                );
            }
            if let Some(prompt) = &ep.login_prompt {
                ensure!(
                    ep.protocol == Protocol::Telnet,
                    "login_prompt is Telnet-only"
                );
                safe_text("login_prompt", prompt, 128)?;
                ensure!(!prompt.is_empty(), "login_prompt must not be empty");
            }
        }
        Ok(())
    }
}

fn range(name: &str, value: u64, min: u64, max: u64) -> Result<()> {
    ensure!(
        (min..=max).contains(&value),
        "{name} must be in {min}..={max}"
    );
    Ok(())
}

fn identifier(name: &str, value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "{name} must be 1..64 ASCII letters, digits, '.', '_' or '-'"
    );
    Ok(())
}

fn safe_text(name: &str, value: &str, max: usize) -> Result<()> {
    if value.len() > max || value.chars().any(char::is_control) {
        bail!("{name} must be at most {max} bytes and contain no control characters");
    }
    Ok(())
}

/// IPv4-mapped IPv6 peers must not bypass exact-IP limits and exclusions.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

fn binds_conflict(a: SocketAddr, b: SocketAddr) -> bool {
    if a.port() == 0 || b.port() == 0 || a.port() != b.port() {
        return false;
    }
    let (a, b) = (canonical_ip(a.ip()), canonical_ip(b.ip()));
    if a == b {
        return true;
    }
    if a.is_ipv4() == b.is_ipv4() {
        return a.is_unspecified() || b.is_unspecified();
    }
    // Conservative cross-platform policy for dual-stack wildcard sockets.
    matches!(a, IpAddr::V6(ip) if ip.is_unspecified())
        || matches!(b, IpAddr::V6(ip) if ip.is_unspecified())
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    const ENDPOINT: &str = "[[endpoint]]\nbind='127.0.0.1:2222'\nprotocol='ssh'\n";

    #[test]
    fn minimal_is_metadata_only() {
        let cfg = Config::from_toml(ENDPOINT).unwrap();
        assert_eq!(cfg.privacy.mode, PrivacyMode::Metadata);
        assert_eq!(cfg.server.max_session_duration_seconds, 60);
    }

    #[test]
    fn stdout_aliases_are_unconditional() {
        for output in ["", "-"] {
            let cfg = LoggingConfig {
                output: output.into(),
                ..LoggingConfig::default()
            };
            assert!(cfg.file_path().is_none());
            assert!(cfg.writes_stdout());
        }
    }

    #[test]
    fn rejects_unknown_fields_and_zero_limits() {
        assert!(
            Config::from_toml(&format!("[server]\nmax_concurent_sessions=1\n{ENDPOINT}")).is_err()
        );
        for key in [
            "max_concurrent_sessions",
            "session_timeout_seconds",
            "max_session_duration_seconds",
            "max_read_bytes_per_session",
        ] {
            assert!(Config::from_toml(&format!("[server]\n{key}=0\n{ENDPOINT}")).is_err());
        }
    }

    #[test]
    fn rejects_header_injection_and_provisional_status() {
        for extra in ["server_header=\"nginx\\r\\nX-Fake: 1\"", "http_status=101"] {
            let raw = format!("[[endpoint]]\nbind='127.0.0.1:8080'\nprotocol='http'\n{extra}");
            assert!(Config::from_toml(&raw).is_err());
        }
    }

    #[test]
    fn rejects_wildcard_overlap_but_allows_ephemeral_ports() {
        let a = "0.0.0.0:8080".parse().unwrap();
        let b = "127.0.0.1:8080".parse().unwrap();
        assert!(binds_conflict(a, b));
        assert!(!binds_conflict(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap()
        ));
    }

    #[test]
    fn remote_management_requires_opt_in() {
        let raw = format!("[metrics]\nenabled=true\nbind='0.0.0.0:9090'\n{ENDPOINT}");
        assert!(Config::from_toml(&raw).is_err());
    }

    #[test]
    fn ignored_addresses_are_normalised() {
        assert_eq!(
            canonical_ip("::ffff:192.0.2.1".parse().unwrap()),
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn bundled_configs_validate() {
        for raw in [
            include_str!("../config.example.toml"),
            include_str!("../deploy/sensor.toml"),
            include_str!("../examples/e2e/minotaur.toml"),
        ] {
            Config::from_toml(raw).unwrap();
        }
    }

    #[test]
    fn file_paths_are_relative_to_config_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sensor.toml");
        std::fs::write(&file, ENDPOINT).unwrap();
        let cfg = Config::from_path(file).unwrap();
        assert_eq!(
            cfg.logging.file_path().unwrap(),
            dir.path().join("honeypot.jsonl")
        );
    }
}
