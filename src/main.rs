//! `minotaur` — low-interaction honeypot CLI.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use minotaur::config::Config;
use minotaur::logger::Logger;
use minotaur::metrics::Metrics;
use minotaur::server::{self, AppState};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the TOML config file.
    #[arg(long, short = 'c', default_value = "minotaur.toml", global = true)]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the honeypot (default).
    Run,
    /// Parse and validate the config file, then exit.
    ValidateConfig,
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    let cli = Cli::parse();
    let result = match cli.command.unwrap_or(Command::Run) {
        Command::Run => run(&cli.config).await,
        Command::ValidateConfig => validate(&cli.config).await,
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("minotaur=info,warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_writer(std::io::stderr)
        .init();
}

async fn validate(path: &std::path::Path) -> Result<()> {
    let cfg = Config::from_path(path)?;
    println!("OK: {} endpoint(s)", cfg.endpoints.len());
    for ep in &cfg.endpoints {
        println!("  - {} on {}", ep.protocol.as_str(), ep.bind);
    }
    Ok(())
}

async fn run(path: &std::path::Path) -> Result<()> {
    let cfg = Config::from_path(path)
        .with_context(|| format!("failed to load config from {}", path.display()))?;
    info!(target: "minotaur", endpoints = cfg.endpoints.len(), "loaded config");

    let (logger, logger_handle) = Logger::spawn(
        cfg.logging.file_path().as_deref(),
        cfg.logging.stdout,
        cfg.logging.buffer_size,
    )
    .await?;

    let metrics = Metrics::new()?;
    let shutdown = CancellationToken::new();

    if cfg.metrics.enabled {
        let bind = cfg.metrics.bind;
        minotaur::metrics::serve(bind, metrics.clone(), shutdown.clone()).await?;
    }

    let state = Arc::new(AppState::new(cfg, logger, metrics, shutdown.clone()));

    let server_state = Arc::clone(&state);
    let server_handle = tokio::spawn(async move { server::run(server_state).await });

    install_signal_handler(shutdown.clone());

    if let Err(e) = server_handle.await.context("server task join")? {
        warn!(target: "minotaur", error = %e, "server returned error");
    }

    // Drop the AppState so all Logger clones in protocol handlers are released;
    // this lets the logger task observe channel closure and flush.
    drop(state);
    if let Err(e) = logger_handle.await {
        warn!(target: "minotaur", error = %e, "logger task join failed");
    }
    info!(target: "minotaur", "shutdown complete");
    Ok(())
}

fn install_signal_handler(shutdown: CancellationToken) {
    tokio::spawn(async move {
        let ctrl_c = async {
            if let Err(e) = tokio::signal::ctrl_c().await {
                warn!(target: "minotaur", error = %e, "ctrl_c handler error");
            }
        };

        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    warn!(target: "minotaur", error = %e, "SIGTERM handler unavailable");
                    ctrl_c.await;
                    shutdown.cancel();
                    return;
                }
            };
            tokio::select! {
                _ = ctrl_c => {},
                _ = term.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await;
        }

        info!(target: "minotaur", "shutdown signal received");
        shutdown.cancel();
    });
}
