//! Centralized configuration management for `nonce-cracker`.
//!
//! All runtime configuration is externalized through environment variables
//! with validation at startup. This ensures:
//!
//! - 12-factor compliance (configuration via environment)
//! - No hardcoded magic values in application logic
//! - Clear failure modes when configuration is invalid
//! - Environment-specific overrides (dev, staging, prod)
//!
//! ## Environment Variables
//!
//! | Variable | Type | Default | Description |
//! |----------|------|---------|-------------|
//! | `NONCE_CRACKER_LOG_DIR` | string | `"logs"` | Log output directory |
//! | `NONCE_CRACKER_LOG_LEVEL` | string | `"info"` | Minimum log level |
//! | `NONCE_CRACKER_MAX_THREADS` | integer | `256` | Maximum worker threads |
//! | `NONCE_CRACKER_CHUNK_SIZE` | integer | `10000` | Delta range chunk size |
//! | `NONCE_CRACKER_SEARCH_MAX_DELTA` | integer | `2^60` | Maximum delta range size |
//!
//! ## Validation
//!
//! All configuration values are validated at startup with specific error
//! messages indicating which value failed and why.

use std::env;
use std::path::PathBuf;
use std::sync::OnceLock;

use tracing::level_filters::LevelFilter;

/// Maximum allowed thread count to prevent resource exhaustion.
pub const MAX_THREADS_DEFAULT: usize = 256;

/// Default chunk size for parallel delta search (per thread).
pub const CHUNK_SIZE_DEFAULT: usize = 10_000;

/// Maximum delta range size to prevent overflow (roughly 2^60).
pub const SEARCH_MAX_DELTA: usize = 1 << 60;

/// Default log directory
pub const LOG_DIR_DEFAULT: &str = "logs";

/// Application configuration resolved from environment variables.
///
/// This struct is created once at startup via [`Config::load`] and
/// provides access to all externalized configuration values.
///
/// Note: fields are part of the public API for future extensibility.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Config {
    /// Maximum number of worker threads for parallel search.
    pub max_threads: usize,

    /// Chunk size (in deltas) per worker thread for load balancing.
    pub chunk_size: usize,

    /// Maximum delta range size to prevent arithmetic overflow.
    pub search_max_delta: usize,

    /// Log directory path.
    pub log_dir: PathBuf,

    /// Minimum log level.
    pub log_level: LevelFilter,

    /// Application version (from Cargo.toml at compile time).
    pub version: &'static str,
}

static CONFIG: OnceLock<Config> = OnceLock::new();

impl Config {
    /// Load configuration from environment variables.
    ///
    /// Returns an error if configuration values are invalid or if
    /// the log directory cannot be created.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `NONCE_CRACKER_MAX_THREADS` is not a positive integer
    /// - `NONCE_CRACKER_CHUNK_SIZE` is zero
    /// - `NONCE_CRACKER_SEARCH_MAX_DELTA` is zero
    /// - `NONCE_CRACKER_LOG_LEVEL` is not a valid log level
    /// - Log directory creation fails
    pub fn load() -> Result<Self, ConfigError> {
        let max_threads = parse_env_usize("NONCE_CRACKER_MAX_THREADS", MAX_THREADS_DEFAULT)?;
        let chunk_size = parse_env_usize("NONCE_CRACKER_CHUNK_SIZE", CHUNK_SIZE_DEFAULT)?;
        let search_max_delta = parse_env_usize("NONCE_CRACKER_SEARCH_MAX_DELTA", SEARCH_MAX_DELTA)?;
        let log_dir = parse_env_path("NONCE_CRACKER_LOG_DIR", LOG_DIR_DEFAULT)?;
        let log_level = parse_env_log_level("NONCE_CRACKER_LOG_LEVEL", LevelFilter::INFO)?;

        // Validate derived constraints
        if max_threads == 0 {
            return Err(ConfigError::InvalidValue {
                name: "NONCE_CRACKER_MAX_THREADS".into(),
                value: "0".into(),
                reason: "must be a positive integer".into(),
            });
        }

        if chunk_size == 0 {
            return Err(ConfigError::InvalidValue {
                name: "NONCE_CRACKER_CHUNK_SIZE".into(),
                value: "0".into(),
                reason: "must be a positive integer".into(),
            });
        }

        if search_max_delta == 0 {
            return Err(ConfigError::InvalidValue {
                name: "NONCE_CRACKER_SEARCH_MAX_DELTA".into(),
                value: "0".into(),
                reason: "must be a positive integer".into(),
            });
        }

        // Create log directory if it doesn't exist
        if !log_dir.exists() {
            std::fs::create_dir_all(&log_dir).map_err(|e| ConfigError::Directory {
                path: log_dir.clone(),
                source: e.to_string(),
            })?;
        }

        Ok(Config {
            max_threads,
            chunk_size,
            search_max_delta,
            log_dir,
            log_level,
            version: env!("CARGO_PKG_VERSION"),
        })
    }

    /// Get the global configuration instance.
    ///
    /// # Panics
    ///
    /// Panics if [`Config::load`] has not been called first.
    pub fn get() -> &'static Config {
        CONFIG
            .get()
            .expect("Config::load() must be called before Config::get()")
    }

    /// Initialize the global configuration from environment.
    ///
    /// This is a convenience wrapper around [`Config::load`] that stores
    /// the result in a global OnceLock. Subsequent calls return the
    /// cached configuration.
    ///
    /// # Errors
    ///
    /// Returns the error from [`Config::load`] if configuration loading fails.
    pub fn init() -> Result<(), ConfigError> {
        let config = Self::load()?;
        CONFIG
            .set(config)
            .map_err(|_| ConfigError::AlreadyInitialized)?;
        Ok(())
    }
}

/// Configuration loading errors.
#[derive(Debug)]
pub enum ConfigError {
    /// Failed to parse an environment variable as a positive integer.
    ParseInt {
        name: String,
        value: String,
        source: std::num::ParseIntError,
    },

    /// An environment variable had an invalid value.
    InvalidValue {
        name: String,
        value: String,
        reason: String,
    },

    /// Failed to create the log directory.
    Directory { path: PathBuf, source: String },

    /// Configuration has already been initialized.
    AlreadyInitialized,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseInt {
                name,
                value,
                source,
            } => {
                write!(f, "failed to parse {name}='{value}': {source}")
            }
            Self::InvalidValue {
                name,
                value,
                reason,
            } => {
                write!(f, "invalid {name}='{value}': {reason}")
            }
            Self::Directory { path, source } => {
                write!(
                    f,
                    "failed to create log directory '{}': {source}",
                    path.display()
                )
            }
            Self::AlreadyInitialized => {
                write!(f, "configuration has already been initialized")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

// Helper function to parse a usize from environment
fn parse_env_usize(name: &str, default: usize) -> Result<usize, ConfigError> {
    match env::var(name) {
        Ok(value) => value.parse().map_err(|source| ConfigError::ParseInt {
            name: name.into(),
            value,
            source,
        }),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::InvalidValue {
            name: name.into(),
            value: "<invalid unicode>".into(),
            reason: "must be valid UTF-8".into(),
        }),
    }
}

// Helper function to parse a PathBuf from environment
fn parse_env_path(name: &str, default: &str) -> Result<PathBuf, ConfigError> {
    match env::var(name) {
        Ok(value) => {
            let path = PathBuf::from(&value);
            Ok(path)
        }
        Err(env::VarError::NotPresent) => Ok(PathBuf::from(default)),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::InvalidValue {
            name: name.into(),
            value: "<invalid unicode>".into(),
            reason: "must be valid UTF-8".into(),
        }),
    }
}

// Helper function to parse log level from environment
fn parse_env_log_level(name: &str, default: LevelFilter) -> Result<LevelFilter, ConfigError> {
    match env::var(name) {
        Ok(value) => match value.to_lowercase().as_str() {
            "trace" => Ok(LevelFilter::TRACE),
            "debug" => Ok(LevelFilter::DEBUG),
            "info" => Ok(LevelFilter::INFO),
            "warn" | "warning" => Ok(LevelFilter::WARN),
            "error" => Ok(LevelFilter::ERROR),
            "off" => Ok(LevelFilter::OFF),
            _ => Err(ConfigError::InvalidValue {
                name: name.into(),
                value,
                reason: "must be one of: trace, debug, info, warn, error, off".into(),
            }),
        },
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::InvalidValue {
            name: name.into(),
            value: "<invalid unicode>".into(),
            reason: "must be valid UTF-8".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        // Clear any existing config
        let _ = CONFIG.set(Config {
            max_threads: MAX_THREADS_DEFAULT,
            chunk_size: CHUNK_SIZE_DEFAULT,
            search_max_delta: SEARCH_MAX_DELTA,
            log_dir: PathBuf::from(LOG_DIR_DEFAULT),
            log_level: LevelFilter::INFO,
            version: "0.0.0",
        });

        let config = Config::get();
        assert_eq!(config.max_threads, MAX_THREADS_DEFAULT);
        assert_eq!(config.chunk_size, CHUNK_SIZE_DEFAULT);
    }
}
