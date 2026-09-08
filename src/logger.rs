//! Bounded JSONL queue and supervised rotating writer with explicit failures.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::LoggingConfig;
use crate::metrics::Metrics;
use crate::session::SessionRecord;

#[derive(Clone)]
pub struct Logger {
    tx: mpsc::Sender<SessionRecord>,
    metrics: Metrics,
}

impl Logger {
    /// Drop all producers, then await the writer. An I/O failure is fatal.
    pub async fn spawn(
        config: &LoggingConfig,
        metrics: Metrics,
    ) -> Result<(Self, JoinHandle<Result<()>>)> {
        ensure!(config.buffer_size > 0, "logger buffer must be positive");
        let duration = Duration::from_secs(config.write_timeout_seconds.max(1));
        let sink = if let Some(path) = config.file_path() {
            Some(
                tokio::time::timeout(
                    duration,
                    FileSink::open(path, config.max_file_bytes, config.max_files),
                )
                .await
                .context("opening log sink timed out")??,
            )
        } else {
            None
        };
        let (tx, rx) = mpsc::channel(config.buffer_size);
        let handle = tokio::spawn(run_writer(
            rx,
            sink,
            config.writes_stdout(),
            duration,
            metrics.clone(),
        ));
        Ok((Self { tx, metrics }, handle))
    }

    /// Drop-newest on overflow; network handlers never wait for the log sink.
    pub fn log(&self, record: SessionRecord) -> bool {
        match self.tx.try_send(record) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.metrics
                    .logger_dropped_total
                    .with_label_values(&["queue_full"])
                    .inc();
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.metrics
                    .logger_dropped_total
                    .with_label_values(&["channel_closed"])
                    .inc();
                false
            }
        }
    }
}

async fn run_writer(
    mut rx: mpsc::Receiver<SessionRecord>,
    mut file: Option<FileSink>,
    stdout_enabled: bool,
    write_timeout: Duration,
    metrics: Metrics,
) -> Result<()> {
    let mut stdout = if stdout_enabled {
        Some(BufWriter::new(tokio::io::stdout()))
    } else {
        None
    };
    while let Some(record) = rx.recv().await {
        let write = async {
            let mut line = serde_json::to_vec(&record).context("cannot serialize session")?;
            line.push(b'\n');
            if let Some(sink) = &mut file {
                sink.write(&line).await?;
            }
            if let Some(out) = &mut stdout {
                out.write_all(&line)
                    .await
                    .context("cannot write JSONL stdout")?;
                out.flush().await.context("cannot flush JSONL stdout")?;
            }
            Ok::<(), anyhow::Error>(())
        };
        let result = match tokio::time::timeout(write_timeout, write).await {
            Ok(result) => result,
            Err(error) => Err(anyhow::Error::from(error).context("log write deadline exceeded")),
        };
        if let Err(error) = result {
            rx.close();
            metrics.ready.set(0);
            metrics.logger_errors_total.inc();
            metrics
                .logger_dropped_total
                .with_label_values(&["writer_error"])
                .inc_by(1 + rx.len() as u64);
            return Err(error);
        }
        metrics.logger_written_total.inc();
    }
    // Every successful record was flushed. Dropping the sink also releases its lock.
    Ok(())
}

struct FileSink {
    path: PathBuf,
    file: Option<BufWriter<File>>,
    size: u64,
    max_bytes: u64,
    max_files: usize,
    _lock: std::fs::File,
}

impl FileSink {
    async fn open(path: PathBuf, max_bytes: u64, max_files: usize) -> Result<Self> {
        ensure!(
            max_bytes > 0 && max_files > 0,
            "rotation limits must be positive"
        );
        let lock_path = suffixed(&path, ".lock");
        let lock = tokio::task::spawn_blocking(move || acquire_lock(&lock_path))
            .await
            .context("log lock task failed")??;
        let (file, size) = open_log(&path).await?;
        Ok(Self {
            path,
            file: Some(BufWriter::new(file)),
            size,
            max_bytes,
            max_files,
            _lock: lock,
        })
    }

    async fn write(&mut self, line: &[u8]) -> Result<()> {
        ensure!(
            line.len() as u64 <= self.max_bytes,
            "one JSONL record exceeds max_file_bytes"
        );
        if self.size.saturating_add(line.len() as u64) > self.max_bytes {
            self.rotate().await?;
        }
        let file = self
            .file
            .as_mut()
            .context("log file unavailable after rotation")?;
        file.write_all(line)
            .await
            .context("cannot write JSONL file")?;
        file.flush().await.context("cannot flush JSONL file")?;
        self.size += line.len() as u64;
        Ok(())
    }

    async fn rotate(&mut self) -> Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush().await?;
        }
        let oldest = suffixed(&self.path, &format!(".{}", self.max_files));
        if regular_exists(&oldest).await? {
            fs::remove_file(&oldest).await?;
        }
        for index in (1..self.max_files).rev() {
            let source = suffixed(&self.path, &format!(".{index}"));
            let destination = suffixed(&self.path, &format!(".{}", index + 1));
            if regular_exists(&source).await? {
                fs::rename(source, destination).await?;
            }
        }
        ensure!(
            regular_exists(&self.path).await?,
            "active log disappeared before rotation"
        );
        fs::rename(&self.path, suffixed(&self.path, ".1"))
            .await
            .context("cannot rotate active log")?;
        let (file, size) = open_log(&self.path).await?;
        self.file = Some(BufWriter::new(file));
        self.size = size;
        Ok(())
    }
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn acquire_lock(path: &Path) -> Result<std::fs::File> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "log lock must not be a symlink or special file"
        ),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("cannot inspect log lock"),
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .with_context(|| format!("cannot open log lock {}", path.display()))?;
    ensure!(
        file.metadata()?.is_file(),
        "log lock must be a regular file"
    );
    file.try_lock()
        .context("cannot lock log output; another writer may be running")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

async fn open_log(path: &Path) -> Result<(File, u64)> {
    regular_exists(path).await?;
    let mut options = OpenOptions::new();
    options.create(true).append(true).read(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .await
        .with_context(|| format!("cannot open log {}", path.display()))?;
    let metadata = file.metadata().await?;
    ensure!(metadata.is_file(), "log output must be a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .await?;
    }
    let size = metadata.len();
    if size > 0 {
        file.seek(std::io::SeekFrom::End(-1)).await?;
        let mut last = [0u8; 1];
        file.read_exact(&mut last).await?;
        ensure!(
            last[0] == b'\n',
            "log ends with an incomplete line; isolate or repair it before restarting"
        );
    }
    Ok((file, size))
}

async fn regular_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path).await {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                bail!("refusing non-regular log path {}", path.display());
            }
            Ok(true)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("cannot inspect log path {}", path.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, EndpointConfig, Protocol, SensorConfig};
    use crate::session::{CloseReason, SessionState};

    fn record() -> SessionRecord {
        let addr = "127.0.0.1:1234".parse().unwrap();
        let ep = EndpointConfig::new(addr, Protocol::Raw);
        SessionState::new(&ep, addr, addr, &Config::default()).finalize(CloseReason::ClientClosed)
    }

    #[tokio::test]
    async fn writes_complete_jsonl_and_releases_lock() {
        let dir = tempfile::tempdir().unwrap();
        let config = LoggingConfig {
            output: dir.path().join("events.jsonl").to_string_lossy().into(),
            ..LoggingConfig::default()
        };
        let metrics = Metrics::new(&SensorConfig::default()).unwrap();
        let (logger, handle) = Logger::spawn(&config, metrics.clone()).await.unwrap();
        for _ in 0..3 {
            assert!(logger.log(record()));
        }
        assert!(Logger::spawn(&config, metrics.clone()).await.is_err());
        drop(logger);
        handle.await.unwrap().unwrap();
        let body = fs::read_to_string(config.file_path().unwrap())
            .await
            .unwrap();
        assert_eq!(body.lines().count(), 3);
        for line in body.lines() {
            serde_json::from_str::<serde_json::Value>(line).unwrap();
        }
        assert_eq!(metrics.logger_written_total.get(), 3);
        let (logger, handle) = Logger::spawn(&config, metrics).await.unwrap();
        drop(logger);
        handle.await.unwrap().unwrap();
    }

    #[test]
    fn overflow_and_closed_channel_are_counted_exactly() {
        let metrics = Metrics::new(&SensorConfig::default()).unwrap();
        let (tx, rx) = mpsc::channel(1);
        let logger = Logger {
            tx,
            metrics: metrics.clone(),
        };
        assert!(logger.log(record()));
        assert!(!logger.log(record()));
        assert_eq!(
            metrics
                .logger_dropped_total
                .with_label_values(&["queue_full"])
                .get(),
            1
        );
        drop(rx);
        assert!(!logger.log(record()));
        assert_eq!(
            metrics
                .logger_dropped_total
                .with_label_values(&["channel_closed"])
                .get(),
            1
        );
    }

    #[tokio::test]
    async fn rotation_bounds_retention_and_preserves_line_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut sink = FileSink::open(path.clone(), 32, 2).await.unwrap();
        for _ in 0..30 {
            sink.write(b"{\"x\":1}\n").await.unwrap();
        }
        drop(sink);
        for suffix in ["", ".1", ".2"] {
            let body = fs::read(suffixed(&path, suffix)).await.unwrap();
            assert!(body.len() <= 32);
            assert!(body.ends_with(b"\n"));
            for line in String::from_utf8(body).unwrap().lines() {
                serde_json::from_str::<serde_json::Value>(line).unwrap();
            }
        }
        assert!(!suffixed(&path, ".3").exists());
    }

    #[tokio::test]
    async fn incomplete_tail_is_not_silently_concatenated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        fs::write(&path, b"{\"partial\":").await.unwrap();
        assert!(FileSink::open(path, 1024, 1).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn refuses_symlinks_and_uses_private_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let sink = FileSink::open(path.clone(), 1024, 1).await.unwrap();
        assert_eq!(
            fs::metadata(&path).await.unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(sink);
        let link = dir.path().join("link.jsonl");
        symlink(&path, &link).unwrap();
        assert!(FileSink::open(link, 1024, 1).await.is_err());
    }
}
