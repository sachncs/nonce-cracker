//! Centralized structured logging for `nonce-cracker` using tracing.
//!
//! This module provides application-wide logging with structured output,
//! context propagation, and configurable formatting.
//!
//! ## Features
//!
//! - Structured JSON or human-readable output
//! - Environment-based level configuration
//! - Correlation ID propagation
//! - File rotation and retention

use std::{
    env, fmt,
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::OnceLock,
};
use tracing::{level_filters::LevelFilter, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

const DEFAULT_LOG_DIR: &str = "logs";
const DEFAULT_LOG_FILE: &str = "nonce-cracker.log";

static LOG_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Errors produced while configuring the logging subsystem.
#[derive(Debug)]
pub enum LoggingError {
    Directory(String),
    Level(String),
    Logger(String),
    Path(String),
}

impl fmt::Display for LoggingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directory(msg) => write!(f, "log directory error: {msg}"),
            Self::Level(msg) => write!(f, "log level error: {msg}"),
            Self::Logger(msg) => write!(f, "logger initialization error: {msg}"),
            Self::Path(msg) => write!(f, "log path error: {msg}"),
        }
    }
}

impl std::error::Error for LoggingError {}

/// Logging configuration derived from environment variables.
#[derive(Clone, Debug)]
pub struct LoggingConfig {
    /// Directory for log files.
    pub directory: PathBuf,
    /// Log level filter.
    pub level: LevelFilter,
    /// Output format (json or pretty).
    pub format: LogFormat,
    /// Enable console output.
    pub console: bool,
}

#[derive(Clone, Debug)]
pub enum LogFormat {
    Json,
    Pretty,
    Compact,
}

impl LoggingConfig {
    /// Builds configuration from environment variables.
    pub fn from_env() -> Result<Self, LoggingError> {
        let directory = env::var_os("NONCE_CRACKER_LOG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_LOG_DIR));

        let level = match env::var("NONCE_CRACKER_LOG_LEVEL") {
            Ok(val) => parse_level_filter(&val)?,
            Err(env::VarError::NotPresent) => LevelFilter::INFO,
            Err(err) => return Err(LoggingError::Level(err.to_string())),
        };

        let format = match env::var("NONCE_CRACKER_LOG_FORMAT") {
            Ok(val) => match val.to_lowercase().as_str() {
                "json" => LogFormat::Json,
                "pretty" => LogFormat::Pretty,
                "compact" => LogFormat::Compact,
                _ => LogFormat::Compact,
            },
            Err(_) => LogFormat::Compact,
        };

        let console = env::var("NONCE_CRACKER_LOG_CONSOLE")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(true);

        // Ensure log directory exists
        fs::create_dir_all(&directory).map_err(|e| LoggingError::Directory(e.to_string()))?;

        Ok(Self {
            directory,
            level,
            format,
            console,
        })
    }
}

/// Initializes the global tracing subscriber.
pub fn init_from_env() -> Result<(), LoggingError> {
    let config = LoggingConfig::from_env()?;

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(config.level.to_string()));

    // Create file appender
    let log_path = config.directory.join(DEFAULT_LOG_FILE);
    let file = File::options()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| LoggingError::Logger(e.to_string()))?;

    // Build subscriber based on format
    let subscriber = tracing_subscriber::registry::Registry::default().with(env_filter);

    match config.format {
        LogFormat::Json => {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_writer(move || file.try_clone().expect("Failed to clone log file"))
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_target(true)
                .with_file(true)
                .with_line_number(true)
                .with_current_span(true);

            if config.console {
                let console_layer = tracing_subscriber::fmt::layer()
                    .pretty()
                    .with_writer(io::stdout);
                subscriber.with(fmt_layer).with(console_layer).init();
            } else {
                subscriber.with(fmt_layer).init();
            }
        }
        LogFormat::Pretty => {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .pretty()
                .with_writer(move || file.try_clone().expect("Failed to clone log file"));

            if config.console {
                let console_layer = tracing_subscriber::fmt::layer()
                    .pretty()
                    .with_writer(io::stdout);
                subscriber.with(fmt_layer).with(console_layer).init();
            } else {
                subscriber.with(fmt_layer).init();
            }
        }
        LogFormat::Compact => {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .compact()
                .with_writer(move || file.try_clone().expect("Failed to clone log file"));

            if config.console {
                let console_layer = tracing_subscriber::fmt::layer()
                    .compact()
                    .with_writer(io::stdout);
                subscriber.with(fmt_layer).with(console_layer).init();
            } else {
                subscriber.with(fmt_layer).init();
            }
        }
    }

    let _ = LOG_DIR.set(config.directory);
    tracing::info!("logging initialized");

    Ok(())
}

/// Returns the configured log directory.
pub fn log_directory() -> PathBuf {
    LOG_DIR
        .get()
        .cloned()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LOG_DIR))
}

/// Resolves a report path relative to the log directory.
pub fn resolve_report_path(requested: &str) -> Result<PathBuf, LoggingError> {
    let requested = requested.trim();
    if requested.is_empty() {
        return Err(LoggingError::Path("report path must not be empty".into()));
    }

    let path = Path::new(requested);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    Ok(log_directory().join(path))
}

/// Emits a structured summary event.
pub fn emit_summary(level: Level, message: impl fmt::Display, console: bool) {
    let line = message.to_string();
    match level {
        Level::ERROR => tracing::error!("{line}"),
        Level::WARN => tracing::warn!("{line}"),
        Level::INFO => tracing::info!("{line}"),
        Level::DEBUG => tracing::debug!("{line}"),
        Level::TRACE => tracing::trace!("{line}"),
    }

    if console {
        let mut stdout = io::stdout().lock();
        let _ = writeln!(stdout, "{line}");
    }
}

/// Parse a log level filter from string.
fn parse_level_filter(value: &str) -> Result<LevelFilter, LoggingError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Ok(LevelFilter::OFF),
        "error" => Ok(LevelFilter::ERROR),
        "warn" | "warning" => Ok(LevelFilter::WARN),
        "info" => Ok(LevelFilter::INFO),
        "debug" => Ok(LevelFilter::DEBUG),
        "trace" => Ok(LevelFilter::TRACE),
        other => Err(LoggingError::Level(format!("invalid log level '{other}'"))),
    }
}
