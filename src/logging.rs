//! Centralized file-backed logging for `nonce-cracker`.
//!
//! This module owns the application logging backend and the path policy
//! for report files written by the search pipeline.
//!
//! ## Responsibilities
//!
//! - Load log configuration from environment variables.
//! - Create the log directory before any file I/O occurs.
//! - Install a single global logger backend for all modules.
//! - Write structured, machine-readable log lines to a rotating file.
//! - Resolve relative report paths into the configured log directory.
//!
//! ## Configuration
//!
//! - `NONCE_CRACKER_LOG_DIR`: directory for application logs and reports.
//! - `NONCE_CRACKER_LOG_LEVEL`: minimum enabled level for backend logging.
//! - `NONCE_CRACKER_LOG_MAX_BYTES`: rotate the active application log after
//!   this many bytes.
//! - `NONCE_CRACKER_LOG_RETENTION`: number of rotated log files to retain.
//!
//! ## Invariants
//!
//! - The configured directory exists before the logger is installed.
//! - The active log file is opened in append mode.
//! - Rotation is serialized by a mutex and cannot interleave writes.
//! - Report paths resolve to the configured directory unless the caller
//!   provides an absolute path explicitly.

use log::{Level, LevelFilter, Log, Metadata, Record};
use parking_lot::Mutex;
use std::{
    env,
    ffi::OsString,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

const DEFAULT_LOG_DIR: &str = "logs";
const DEFAULT_LOG_FILE: &str = "nonce-cracker.log";
const DEFAULT_LOG_LEVEL: LevelFilter = LevelFilter::Info;
const DEFAULT_MAX_BYTES: u64 = 1_048_576;
const DEFAULT_RETENTION: usize = 5;

static LOG_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Errors produced while configuring or using the logging subsystem.
///
/// The variants separate the failure domains that matter for release-grade
/// observability:
///
/// - directory creation
/// - invalid configuration values
/// - rotation and file I/O
/// - backend registration
/// - invalid report paths
#[derive(Debug)]
pub enum LoggingError {
    Directory(String),
    Level(String),
    Rotation(String),
    Logger(String),
    Path(String),
}

impl fmt::Display for LoggingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directory(msg) => write!(f, "log directory error: {msg}"),
            Self::Level(msg) => write!(f, "log level error: {msg}"),
            Self::Rotation(msg) => write!(f, "log rotation error: {msg}"),
            Self::Logger(msg) => write!(f, "logger initialization error: {msg}"),
            Self::Path(msg) => write!(f, "log path error: {msg}"),
        }
    }
}

impl std::error::Error for LoggingError {}

#[derive(Clone)]
/// Resolved logger configuration derived from environment variables.
///
/// `directory` is guaranteed to exist after construction.
///
/// `level` is the backend filter passed to the global logger.
///
/// `max_bytes` and `retention` bound log growth and archive count.
pub struct LoggingConfig {
    /// Directory containing the active application log and archived rotations.
    pub directory: PathBuf,
    /// Minimum level emitted by the backend logger.
    pub level: LevelFilter,
    /// Maximum size of the active log file before rotation.
    pub max_bytes: u64,
    /// Number of archived rotated logs to retain.
    pub retention: usize,
}

impl LoggingConfig {
    /// Builds the logging configuration from environment variables.
    ///
    /// If no overrides are present, the defaults are:
    ///
    /// - directory: `logs/`
    /// - level: `info`
    /// - max_bytes: `1_048_576`
    /// - retention: `5`
    ///
    /// The directory is created before the configuration is returned.
    ///
    /// # Errors
    ///
    /// Returns a `LoggingError` if any environment value is malformed,
    /// a numeric bound is zero, or the directory cannot be created.
    pub fn from_env() -> Result<Self, LoggingError> {
        let directory = env::var_os("NONCE_CRACKER_LOG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_LOG_DIR));

        let level = match env::var("NONCE_CRACKER_LOG_LEVEL") {
            Ok(value) => parse_level_filter(&value)?,
            Err(env::VarError::NotPresent) => DEFAULT_LOG_LEVEL,
            Err(err) => return Err(LoggingError::Level(err.to_string())),
        };

        let max_bytes = match env::var("NONCE_CRACKER_LOG_MAX_BYTES") {
            Ok(value) => value
                .parse::<u64>()
                .map_err(|err| LoggingError::Rotation(err.to_string()))?,
            Err(env::VarError::NotPresent) => DEFAULT_MAX_BYTES,
            Err(err) => return Err(LoggingError::Rotation(err.to_string())),
        };
        if max_bytes == 0 {
            return Err(LoggingError::Rotation(
                "NONCE_CRACKER_LOG_MAX_BYTES must be greater than zero".into(),
            ));
        }

        let retention = match env::var("NONCE_CRACKER_LOG_RETENTION") {
            Ok(value) => value
                .parse::<usize>()
                .map_err(|err| LoggingError::Rotation(err.to_string()))?,
            Err(env::VarError::NotPresent) => DEFAULT_RETENTION,
            Err(err) => return Err(LoggingError::Rotation(err.to_string())),
        };
        if retention == 0 {
            return Err(LoggingError::Rotation(
                "NONCE_CRACKER_LOG_RETENTION must be greater than zero".into(),
            ));
        }

        fs::create_dir_all(&directory).map_err(|err| LoggingError::Directory(err.to_string()))?;

        Ok(Self {
            directory,
            level,
            max_bytes,
            retention,
        })
    }
}

/// Initializes the global logging backend from environment variables.
///
/// This function installs the file-backed logger once per process and sets the
/// global level filter used by the `log` facade.
///
/// # Errors
///
/// Returns a `LoggingError` if configuration loading fails, the logger cannot
/// be registered, or the active log file cannot be opened.
pub fn init_from_env() -> Result<(), LoggingError> {
    let config = LoggingConfig::from_env()?;
    let logger = RollingLogger::new(config.clone())?;
    let logger: &'static RollingLogger = Box::leak(Box::new(logger));
    log::set_logger(logger).map_err(|err| LoggingError::Logger(err.to_string()))?;
    log::set_max_level(config.level);
    let _ = LOG_DIR.set(config.directory);
    Ok(())
}

/// Returns the currently configured log directory.
///
/// This value is initialized from `NONCE_CRACKER_LOG_DIR` or defaults to
/// `logs/` before logger initialization completes.
pub fn log_directory() -> PathBuf {
    LOG_DIR.get().cloned().unwrap_or_else(|| {
        PathBuf::from(
            env::var_os("NONCE_CRACKER_LOG_DIR").unwrap_or_else(|| OsString::from(DEFAULT_LOG_DIR)),
        )
    })
}

/// Resolves a report path relative to the active log directory.
///
/// Relative paths are never written into the current working directory; they
/// are anchored beneath the configured logging directory. Absolute paths are
/// preserved to allow explicit caller overrides.
///
/// # Errors
///
/// Returns `LoggingError::Path` when the input is empty after trimming.
pub fn resolve_report_path(requested: &str) -> Result<PathBuf, LoggingError> {
    let requested = requested.trim();
    if requested.is_empty() {
        return Err(LoggingError::Path("report path must not be empty".into()));
    }

    let path = Path::new(requested);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    let log_dir = log_directory();
    Ok(log_dir.join(path))
}

/// Emits a structured summary line through the logging backend and, if
/// requested, mirrors the same line to stdout.
///
/// The line is formatted as human-readable `key=value` pairs so that log
/// aggregation tools can parse it without needing a custom schema.
pub fn emit_summary(level: Level, message: impl fmt::Display, console: bool) {
    let line = message.to_string();
    log::log!(level, "{line}");

    if console {
        let mut stdout = io::stdout().lock();
        let _ = writeln!(stdout, "{line}");
    }
}

struct RollingLogger {
    config: LoggingConfig,
    state: Mutex<LoggerState>,
}

struct LoggerState {
    /// Handle to the active log file.
    file: File,
    /// Current size of the active file in bytes.
    size: u64,
    /// Monotonic sequence used to avoid archive-name collisions.
    sequence: u64,
}

impl RollingLogger {
    /// Creates a new file-backed logger for the supplied configuration.
    ///
    /// The active log file is opened in append mode so concurrent restarts do
    /// not truncate existing logs.
    fn new(config: LoggingConfig) -> Result<Self, LoggingError> {
        let active_path = config.directory.join(DEFAULT_LOG_FILE);
        if let Some(parent) = active_path.parent() {
            fs::create_dir_all(parent).map_err(|err| LoggingError::Directory(err.to_string()))?;
        }
        let file = open_append(&active_path)?;
        let size = file
            .metadata()
            .map_err(|err| LoggingError::Rotation(err.to_string()))?
            .len();

        Ok(Self {
            config,
            state: Mutex::new(LoggerState {
                file,
                size,
                sequence: 0,
            }),
        })
    }

    /// Returns the path of the active application log.
    fn active_path(&self) -> PathBuf {
        self.config.directory.join(DEFAULT_LOG_FILE)
    }

    /// Computes the archive name for the next rotated log file.
    ///
    /// The timestamp, process id, and per-process sequence number collectively
    /// provide uniqueness without relying on global coordination.
    fn next_archive_path(&self, sequence: u64) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        self.config.directory.join(format!(
            "nonce-cracker-{:020}_{:09}_{}_{}.log",
            now.as_secs(),
            now.subsec_nanos(),
            std::process::id(),
            sequence
        ))
    }

    /// Rotates the active log file and opens a fresh append target.
    ///
    /// Rotation is size-triggered and archive retention is enforced
    /// immediately after the rename succeeds.
    fn rotate(&self, state: &mut LoggerState) -> Result<(), LoggingError> {
        state
            .file
            .flush()
            .map_err(|err| LoggingError::Rotation(err.to_string()))?;
        let active = self.active_path();
        if active.exists() {
            let archive = self.next_archive_path(state.sequence);
            state.sequence = state.sequence.saturating_add(1);
            fs::rename(&active, &archive).map_err(|err| LoggingError::Rotation(err.to_string()))?;
            self.prune_archives()?;
        }

        state.file = open_append(&active)?;
        state.size = 0;
        Ok(())
    }

    /// Removes archive files beyond the configured retention window.
    ///
    /// Archives are sorted lexicographically, which is valid because the file
    /// names include zero-padded timestamps.
    fn prune_archives(&self) -> Result<(), LoggingError> {
        let mut archives: Vec<PathBuf> = fs::read_dir(&self.config.directory)
            .map_err(|err| LoggingError::Rotation(err.to_string()))?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.starts_with("nonce-cracker-") && name.ends_with(".log"))
                    .unwrap_or(false)
            })
            .collect();

        archives.sort();

        if archives.len() > self.config.retention {
            let excess = archives.len() - self.config.retention;
            for path in archives.into_iter().take(excess) {
                let _ = fs::remove_file(path);
            }
        }

        Ok(())
    }

    /// Formats a log record into a structured `key=value` line.
    ///
    /// The record payload is quoted so newline and delimiter characters do not
    /// break downstream log parsing.
    fn format_record(&self, record: &Record<'_>) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        format!(
            "ts={}.{:09} level={} target={} message={}",
            timestamp.as_secs(),
            timestamp.subsec_nanos(),
            record.level(),
            record.target(),
            quote_value(&record.args().to_string()),
        )
    }
}

impl Log for RollingLogger {
    /// Returns whether a record should be written to the active backend.
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= self.config.level
    }

    /// Writes a record to the current log file, rotating first if required.
    ///
    /// The write path is synchronized with a mutex so the logger remains safe
    /// under concurrent use from multiple worker threads.
    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let line = self.format_record(record);
        let bytes = line.as_bytes();
        let mut state = self.state.lock();

        if state.size > 0
            && state.size.saturating_add(bytes.len() as u64 + 1) > self.config.max_bytes
        {
            if let Err(err) = self.rotate(&mut state) {
                eprintln!("{err}");
                return;
            }
        }

        if let Err(err) = writeln!(state.file, "{line}") {
            eprintln!("failed to write log line: {err}");
            return;
        }
        state.size = state.size.saturating_add(bytes.len() as u64 + 1);
    }

    /// Flushes the active log file handle.
    fn flush(&self) {
        let _ = self.state.lock().file.flush();
    }
}

/// Opens a log file in append mode, creating it if necessary.
fn open_append(path: &Path) -> Result<File, LoggingError> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| LoggingError::Rotation(err.to_string()))
}

/// Parses a `LevelFilter` from a case-insensitive string.
fn parse_level_filter(value: &str) -> Result<LevelFilter, LoggingError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Ok(LevelFilter::Off),
        "error" => Ok(LevelFilter::Error),
        "warn" | "warning" => Ok(LevelFilter::Warn),
        "info" => Ok(LevelFilter::Info),
        "debug" => Ok(LevelFilter::Debug),
        "trace" => Ok(LevelFilter::Trace),
        other => Err(LoggingError::Level(format!("invalid log level '{other}'"))),
    }
}

/// Quotes a value for structured logging output.
///
/// The output remains ASCII-friendly and escapes control characters so the
/// file can be parsed line-by-line without ambiguity.
fn quote_value(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}
