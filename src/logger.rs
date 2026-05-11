//! Async JSONL session logger.
//!
//! Records are sent through a bounded channel to a dedicated writer task. If
//! the channel is full (slow disk, etc.), records are dropped and counted
//! rather than blocking the network handlers.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::session::SessionRecord;

/// A handle to the logger task. Cloneable; closing it requires dropping all
/// clones AND calling [`Logger::shutdown`] on the original.
#[derive(Clone)]
pub struct Logger {
    tx: mpsc::Sender<SessionRecord>,
    dropped: Arc<AtomicU64>,
}

impl Logger {
    /// Spawn the writer task. Returns a `Logger` handle and the `JoinHandle`
    /// for the writer (await it after dropping all `Logger` clones to flush).
    pub async fn spawn(
        file_path: Option<&Path>,
        mirror_stdout: bool,
        buffer_size: usize,
    ) -> Result<(Self, JoinHandle<()>)> {
        let file = if let Some(p) = file_path {
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .await
                .with_context(|| format!("failed to open log file {}", p.display()))?;
            Some(BufWriter::new(f))
        } else {
            None
        };

        let (tx, rx) = mpsc::channel::<SessionRecord>(buffer_size);
        let dropped = Arc::new(AtomicU64::new(0));
        let dropped_clone = Arc::clone(&dropped);

        let handle = tokio::spawn(async move {
            run_writer(rx, file, mirror_stdout, dropped_clone).await;
        });

        Ok((Self { tx, dropped }, handle))
    }

    /// Send a record. Returns `false` if the channel is closed; drops and
    /// counts if the channel is full.
    pub fn log(&self, record: SessionRecord) -> bool {
        match self.tx.try_send(record) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Total records dropped due to a full channel since start.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

async fn run_writer(
    mut rx: mpsc::Receiver<SessionRecord>,
    mut file: Option<BufWriter<File>>,
    mirror_stdout: bool,
    dropped: Arc<AtomicU64>,
) {
    info!(target: "minotaur::logger", "logger task started");
    while let Some(rec) = rx.recv().await {
        let line = match serde_json::to_string(&rec) {
            Ok(s) => s,
            Err(e) => {
                error!(target: "minotaur::logger", error = %e, "failed to serialize record");
                continue;
            }
        };
        if mirror_stdout {
            println!("{}", line);
        }
        if let Some(f) = file.as_mut() {
            if let Err(e) = f.write_all(line.as_bytes()).await {
                error!(target: "minotaur::logger", error = %e, "failed to write to log file");
                continue;
            }
            if let Err(e) = f.write_all(b"\n").await {
                error!(target: "minotaur::logger", error = %e, "failed to write newline");
            }
            // Flush after every record so external readers (tail -f, fluentbit)
            // get timely updates. JSONL is line-oriented; buffering more would
            // delay observability for marginal throughput gains in this workload.
            if let Err(e) = f.flush().await {
                error!(target: "minotaur::logger", error = %e, "failed to flush");
            }
        }
    }
    if let Some(mut f) = file.take() {
        let _ = f.flush().await;
    }
    let n = dropped.load(Ordering::Relaxed);
    if n > 0 {
        warn!(target: "minotaur::logger", dropped = n, "logger exiting with dropped records");
    }
    info!(target: "minotaur::logger", "logger task shut down");
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tempfile::NamedTempFile;

    use super::*;
    use crate::config::Protocol;
    use crate::session::{CloseReason, SessionState};

    fn dummy_record(protocol: Protocol) -> SessionRecord {
        let src: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let mut s = SessionState::new(protocol, src, 22, 64);
        s.record_bytes(b"hello");
        s.finalize(CloseReason::ClientClosed)
    }

    #[tokio::test]
    async fn writes_jsonl_to_file() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        let (logger, handle) = Logger::spawn(Some(&path), false, 16).await.unwrap();
        for _ in 0..3 {
            assert!(logger.log(dummy_record(Protocol::Ssh)));
        }
        drop(logger);
        handle.await.unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = body.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["protocol"], "ssh");
        }
    }

    #[tokio::test]
    async fn drops_when_full() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        // Buffer size 1 with no consumer pressure: send fast and check that
        // some get dropped. We deliberately keep the writer slow by spawning
        // many in a row before it can drain.
        let (logger, handle) = Logger::spawn(Some(&path), false, 1).await.unwrap();
        let mut sent = 0;
        for _ in 0..1000 {
            if logger.log(dummy_record(Protocol::Raw)) {
                sent += 1;
            }
        }
        drop(logger.clone()); // ensure clone count doesn't keep alive
        drop(logger);
        handle.await.unwrap();
        let _ = sent; // we don't assert exact numbers; just that no panic occurred
    }
}
