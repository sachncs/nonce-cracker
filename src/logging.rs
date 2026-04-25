//! Structured logging backend using `tracing`.
//!
//! `init` sets up a compact-format subscriber that writes to both a rolling
//! log file and optionally stdout.  The log directory and level are controlled
//! via environment variables.
//!
//! # Environment variables
//!
//! | Variable | Description | Default |
//! |----------|-------------|---------|
//! | `NONCE_CRACKER_LOG_LEVEL` | Minimum level (`error`..`trace`) | `info` |
//! | `NONCE_CRACKER_LOG_CONSOLE` | Mirror logs to stdout (`1`/`true`) | `true` |

use std::{
    fmt,
    fs::File,
    io::{self, Write},
    path::Path,
};
use tracing::Level;
use tracing_subscriber::{
    filter::LevelFilter, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

const DEFAULT_LOG_FILE: &str = "nonce-cracker.log";

/// Errors that can occur while setting up the logging subsystem.
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    /// The supplied level string was not recognised.
    #[error("invalid log level: {0}")]
    InvalidLevel(String),
    /// The log file could not be opened or cloned.
    #[error("logger initialization failed: {0}")]
    Logger(String),
}

/// Initialise the global tracing subscriber.
///
/// The subscriber writes a rolling compact-format log to
/// `<log_dir>/nonce-cracker.log`.  Optionally mirrors output to stdout.
///
/// # Errors
///
/// Returns [`LoggingError::InvalidLevel`] if `NONCE_CRACKER_LOG_LEVEL` is set to
/// an unrecognised value, or [`LoggingError::Logger`] if the log file cannot be
/// opened or cloned.
///
/// # Panics
///
/// Panics if the log file handle cannot be cloned for the tracing layer
/// writer.  This only occurs for invalid file descriptors.
pub fn init(log_dir: &Path, console: bool) -> Result<(), LoggingError> {
    let level = match std::env::var("NONCE_CRACKER_LOG_LEVEL") {
        Ok(v) => parse_level(&v)?,
        Err(_) => LevelFilter::INFO,
    };

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.to_string()));

    let log_path = log_dir.join(DEFAULT_LOG_FILE);
    let file = File::options()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| LoggingError::Logger(e.to_string()))?;

    let _ = file
        .try_clone()
        .map_err(|e| LoggingError::Logger(format!("clone log file: {e}")))?;

    let subscriber = tracing_subscriber::registry::Registry::default().with(env_filter);

    let fmt_layer = tracing_subscriber::fmt::layer()
        .compact()
        .with_writer(move || file.try_clone().expect("clone log file"));

    if console {
        let console_layer = tracing_subscriber::fmt::layer()
            .compact()
            .with_writer(io::stdout);
        subscriber.with(fmt_layer).with(console_layer).init();
    } else {
        subscriber.with(fmt_layer).init();
    }

    tracing::info!("logging initialized");
    Ok(())
}

/// Emit a single summary line at the given level, and optionally write it to
/// stdout regardless of whether the tracing subscriber is configured.
///
/// This is used to report the final search result so it is visible even when
/// console logging is disabled.
pub fn emit_summary(level: Level, message: impl fmt::Display, console: bool) {
    match level {
        Level::ERROR => tracing::error!("{message}"),
        Level::WARN => tracing::warn!("{message}"),
        Level::INFO => tracing::info!("{message}"),
        Level::DEBUG => tracing::debug!("{message}"),
        Level::TRACE => tracing::trace!("{message}"),
    }
    if console {
        let _ = writeln!(io::stdout().lock(), "{message}");
    }
}

/// Parse a level string into a [`LevelFilter`].
///
/// Accepts `off`, `error`, `warn`/`warning`, `info`, `debug`, `trace` (case
/// insensitive, leading and trailing whitespace ignored).
///
/// # Errors
///
/// Returns [`LoggingError::InvalidLevel`] if the string does not match a known
/// level.
pub fn parse_level(value: &str) -> Result<LevelFilter, LoggingError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Ok(LevelFilter::OFF),
        "error" => Ok(LevelFilter::ERROR),
        "warn" | "warning" => Ok(LevelFilter::WARN),
        "info" => Ok(LevelFilter::INFO),
        "debug" => Ok(LevelFilter::DEBUG),
        "trace" => Ok(LevelFilter::TRACE),
        other => Err(LoggingError::InvalidLevel(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::Level;

    #[test]
    fn test_parse_level_all_variants() {
        assert_eq!(parse_level("off").unwrap(), LevelFilter::OFF);
        assert_eq!(parse_level("error").unwrap(), LevelFilter::ERROR);
        assert_eq!(parse_level("warn").unwrap(), LevelFilter::WARN);
        assert_eq!(parse_level("warning").unwrap(), LevelFilter::WARN);
        assert_eq!(parse_level("info").unwrap(), LevelFilter::INFO);
        assert_eq!(parse_level("debug").unwrap(), LevelFilter::DEBUG);
        assert_eq!(parse_level("trace").unwrap(), LevelFilter::TRACE);
        assert_eq!(parse_level("  INFO  ").unwrap(), LevelFilter::INFO);
    }

    #[test]
    fn test_parse_level_invalid() {
        let err = parse_level("invalid").unwrap_err();
        assert!(err.to_string().contains("invalid"));
    }

    #[test]
    fn test_emit_summary_all_levels() {
        emit_summary(Level::ERROR, "error msg", false);
        emit_summary(Level::WARN, "warn msg", false);
        emit_summary(Level::INFO, "info msg", false);
        emit_summary(Level::DEBUG, "debug msg", false);
        emit_summary(Level::TRACE, "trace msg", false);
    }
}
