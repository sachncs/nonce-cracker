use std::{
    fmt,
    fs::File,
    io::{self, Write},
    path::PathBuf,
    sync::OnceLock,
};
use tracing::{level_filters::LevelFilter, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

const DEFAULT_LOG_FILE: &str = "nonce-cracker.log";

static LOG_DIR: OnceLock<PathBuf> = OnceLock::new();

#[derive(Debug)]
pub enum LoggingError {
    Level(String),
    Logger(String),
}

impl fmt::Display for LoggingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Level(s) => write!(f, "log level: {s}"),
            Self::Logger(s) => write!(f, "logger: {s}"),
        }
    }
}
impl std::error::Error for LoggingError {}

pub fn init() -> Result<(), LoggingError> {
    let dir = crate::config::Config::get().log_dir.clone();

    let level = match std::env::var("NONCE_CRACKER_LOG_LEVEL") {
        Ok(v) => parse_level(&v)?,
        Err(_) => LevelFilter::INFO,
    };

    let console = std::env::var("NONCE_CRACKER_LOG_CONSOLE")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(true);

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.to_string()));

    let log_path = dir.join(DEFAULT_LOG_FILE);
    let file = File::options()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| LoggingError::Logger(e.to_string()))?;

    // Pre-validate that the file handle can be cloned; subsequent clones
    // inside the tracing closure should not fail in practice.
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

    let _ = LOG_DIR.set(dir);
    tracing::info!("logging initialized");
    Ok(())
}

pub fn log_dir() -> PathBuf {
    LOG_DIR
        .get()
        .cloned()
        .unwrap_or_else(|| crate::config::Config::get().log_dir.clone())
}

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
        let _ = writeln!(io::stdout().lock(), "{line}");
    }
}

fn parse_level(value: &str) -> Result<LevelFilter, LoggingError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Ok(LevelFilter::OFF),
        "error" => Ok(LevelFilter::ERROR),
        "warn" | "warning" => Ok(LevelFilter::WARN),
        "info" => Ok(LevelFilter::INFO),
        "debug" => Ok(LevelFilter::DEBUG),
        "trace" => Ok(LevelFilter::TRACE),
        other => Err(LoggingError::Level(format!("invalid '{other}'"))),
    }
}
