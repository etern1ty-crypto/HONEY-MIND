//! minotaur CLI and process-level supervision.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::{JoinError, JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use minotaur::config::{Config, PrivacyMode};
use minotaur::logger::Logger;
use minotaur::metrics::Metrics;
use minotaur::server::{AppState, BoundServer};

#[derive(Parser)]
#[command(
    version,
    about = "Bounded, privacy-first TCP deception sensor for authorised networks"
)]
struct Cli {
    /// TOML file. Relative log paths resolve against its containing directory.
    #[arg(
        long,
        short = 'c',
        default_value = "minotaur.toml",
        env = "MINOTAUR_CONFIG",
        global = true
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the sensor; this is the default command.
    Run,
    /// Check TOML and semantic constraints. Does not bind ports or create files.
    ValidateConfig {
        #[arg(long)]
        json: bool,
    },
    /// Print a complete config to stdout, without opening the configured file.
    PrintConfig {
        #[arg(long, value_enum, default_value = "local")]
        profile: Profile,
    },
    /// GET /readyz with a hard deadline; no honeypot session is created.
    Healthcheck {
        /// Overrides the configured management address; no config is needed then.
        #[arg(long)]
        address: Option<SocketAddr>,
        #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u64).range(1..=30))]
        timeout_seconds: u64,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Profile {
    Local,
    Sensor,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("warn,minotaur=info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    let cli = Cli::parse();
    let workers = std::thread::available_parallelism()
        .map(|n| n.get().min(8))
        .unwrap_or(2);
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(8)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: cannot start async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(dispatch(cli));
    // Tokio file/stdout operations may use blocking workers. Never wait forever
    // for a stalled OS write during runtime destruction.
    runtime.shutdown_timeout(Duration::from_secs(2));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn dispatch(cli: Cli) -> Result<()> {
    match cli.command.unwrap_or(Command::Run) {
        Command::Run => run(&cli.config).await,
        Command::PrintConfig { profile } => {
            let text = match profile {
                Profile::Local => include_str!("../config.example.toml"),
                Profile::Sensor => include_str!("../deploy/sensor.toml"),
            };
            let mut stdout = tokio::io::stdout();
            stdout
                .write_all(text.as_bytes())
                .await
                .context("cannot print config")?;
            stdout.flush().await.context("cannot flush config")
        }
        Command::ValidateConfig { json } => {
            let cfg = Config::from_path(&cli.config)?;
            let message = if json {
                serde_json::to_string(&serde_json::json!({
                    "valid": true, "sensor_id": cfg.sensor.id,
                    "endpoint_count": cfg.endpoints.len(), "privacy_mode": cfg.privacy.mode,
                }))?
            } else {
                format!(
                    "OK: {} endpoint(s); sensor={}; privacy={:?}",
                    cfg.endpoints.len(),
                    cfg.sensor.id,
                    cfg.privacy.mode
                )
            };
            let mut stdout = tokio::io::stdout();
            stdout.write_all(format!("{message}\n").as_bytes()).await?;
            stdout.flush().await?;
            Ok(())
        }
        Command::Healthcheck {
            address,
            timeout_seconds,
        } => {
            let address = match address {
                Some(address) => address,
                None => {
                    let config = Config::from_path(&cli.config)?;
                    if !config.metrics.enabled {
                        bail!("management HTTP is disabled");
                    }
                    config.metrics.bind
                }
            };
            healthcheck(address, Duration::from_secs(timeout_seconds)).await
        }
    }
}

async fn run(path: &Path) -> Result<()> {
    let config = Config::from_path(path)?;
    if config.privacy.mode == PrivacyMode::Full {
        warn!("full capture enabled: JSONL can contain passwords, tokens and personal data");
    }
    if config.metrics.enabled && !config.metrics.bind.ip().is_loopback() {
        warn!("management HTTP is not authenticated; restrict it to the monitoring network");
    }
    let metrics = Metrics::new(&config.sensor)?;
    // Bind EVERYTHING before starting any task or accepting any traffic.
    let bound = BoundServer::bind(&config).await?;
    let (logger, mut logger_handle) = Logger::spawn(&config.logging, metrics.clone()).await?;
    let grace = Duration::from_secs(config.server.shutdown_grace_seconds);
    let shutdown = CancellationToken::new();
    let state = Arc::new(AppState::new(config, logger, metrics, shutdown.clone())?);
    let mut server_handle = tokio::spawn(bound.run(Arc::clone(&state)));
    let (mut outcome, server_finished, logger_finished) = tokio::select! {
        result = wait_for_signal() => (result, false, false),
        result = &mut server_handle => (joined(result, "server"), true, false),
        result = &mut logger_handle => {
            let error = joined(result, "logger").err().unwrap_or_else(|| anyhow!("logger stopped while producers were alive"));
            (Err(error), false, true)
        }
    };
    shutdown.cancel();
    state.metrics.ready.set(0);
    if !server_finished {
        merge(
            &mut outcome,
            finish(&mut server_handle, grace, "server").await,
        );
    }
    drop(state);
    if !logger_finished {
        merge(
            &mut outcome,
            finish(&mut logger_handle, grace, "logger").await,
        );
    }
    if outcome.is_ok() {
        info!("shutdown complete; queued records flushed");
    }
    outcome
}

fn joined(result: std::result::Result<Result<()>, JoinError>, name: &str) -> Result<()> {
    result.with_context(|| format!("{name} task failed"))?
}

async fn finish(handle: &mut JoinHandle<Result<()>>, grace: Duration, name: &str) -> Result<()> {
    match tokio::time::timeout(grace, &mut *handle).await {
        Ok(result) => joined(result, name),
        Err(_) => {
            handle.abort();
            // Observe abortion so no detached top-level task remains.
            if let Err(error) = (&mut *handle).await {
                if !error.is_cancelled() {
                    warn!(%error, "task failed during forced shutdown");
                }
            }
            bail!("{name} exceeded shutdown grace; unfinished records may be lost")
        }
    }
}

fn merge(outcome: &mut Result<()>, next: Result<()>) {
    if let Err(error) = next {
        if outcome.is_ok() {
            *outcome = Err(error);
        } else {
            warn!(%error, "additional shutdown error");
        }
    }
}

async fn wait_for_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("cannot install SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("SIGINT handler failed")?,
            signal = terminate.recv() => { signal.context("SIGTERM stream closed")?; }
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .context("Ctrl+C handler failed")?;
    info!("shutdown signal received");
    Ok(())
}

async fn healthcheck(mut address: SocketAddr, duration: Duration) -> Result<()> {
    if address.ip().is_unspecified() {
        address.set_ip(if address.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        });
    }
    let probe = async {
        let mut stream = TcpStream::connect(address)
            .await
            .context("cannot connect to management endpoint")?;
        let request =
            format!("GET /readyz HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        stream.take(4096).read_to_end(&mut response).await?;
        let response = std::str::from_utf8(&response).context("invalid health response")?;
        let status = response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1));
        if status != Some("200") {
            bail!("sensor is not ready");
        }
        Ok(())
    };
    tokio::time::timeout(duration, probe)
        .await
        .context("healthcheck deadline exceeded")?
}
