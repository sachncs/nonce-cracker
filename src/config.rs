//! Environment-driven configuration.
//!
//! `Config` is loaded from environment variables by the caller and passed
//! explicitly through the program.  There is no global singleton.
//!
//! # Environment variables
//!
//! | Variable | Description | Default |
//! |----------|-------------|---------|
//! | `NONCE_CRACKER_MAX_THREADS` | Upper bound on worker threads | `256` |
//! | `NONCE_CRACKER_LOG_DIR` | Directory for application logs | `logs` |

use std::env;
use std::path::PathBuf;

/// Default upper bound for worker threads.
pub const MAX_THREADS_DEFAULT: usize = 256;
/// Default log output directory.
pub const LOG_DIR_DEFAULT: &str = "logs";

/// Configuration loaded from environment variables.
///
/// Construct via [`Config::from_env`]; there is no global instance.
#[derive(Debug, Clone)]
pub struct Config {
    /// Maximum number of Rayon worker threads the search will ever spawn.
    pub max_threads: usize,
    /// Directory where log files and search reports are written.
    pub log_dir: PathBuf,
    /// Crate version (from `CARGO_PKG_VERSION`).
    pub version: &'static str,
}

/// Error type returned when configuration loading fails.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// `NONCE_CRACKER_MAX_THREADS` was zero.
    #[error("NONCE_CRACKER_MAX_THREADS must be > 0")]
    MaxThreadsZero,
    /// The log directory could not be created.
    #[error("failed to create log directory: {0}")]
    LogDirCreate(#[source] std::io::Error),
    /// An environment variable had an invalid value.
    #[error("invalid value for {name}: {value}")]
    InvalidEnvVar { name: String, value: String },
    /// An environment variable contained invalid unicode.
    #[error("environment variable {0} contains invalid unicode")]
    InvalidUnicode(String),
}

impl Config {
    /// Load configuration from the environment.
    ///
    /// Reads `NONCE_CRACKER_MAX_THREADS` and `NONCE_CRACKER_LOG_DIR`.  The log
    /// directory is created if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] if an environment variable is malformed,
    /// `NONCE_CRACKER_MAX_THREADS` is zero, or the log directory cannot be created.
    pub fn from_env() -> Result<Self, ConfigError> {
        let max_threads = parse_env_usize("NONCE_CRACKER_MAX_THREADS", MAX_THREADS_DEFAULT)?;
        let log_dir = parse_env_path("NONCE_CRACKER_LOG_DIR", LOG_DIR_DEFAULT)?;

        if max_threads == 0 {
            return Err(ConfigError::MaxThreadsZero);
        }
        if !log_dir.exists() {
            std::fs::create_dir_all(&log_dir).map_err(ConfigError::LogDirCreate)?;
        }

        Ok(Self {
            max_threads,
            log_dir,
            version: env!("CARGO_PKG_VERSION"),
        })
    }
}

/// Parse a `usize` environment variable.
///
/// Returns `Ok(default)` if the variable is unset.  Returns an error if the
/// variable is set but cannot be parsed as `usize`.
pub fn parse_env_usize(name: &str, default: usize) -> Result<usize, ConfigError> {
    match env::var(name) {
        Ok(v) => v.parse().map_err(|_| ConfigError::InvalidEnvVar {
            name: name.to_string(),
            value: v,
        }),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::InvalidUnicode(name.to_string())),
    }
}

/// Parse a path environment variable.
///
/// Returns `Ok(PathBuf::from(default))` if the variable is unset.
pub fn parse_env_path(name: &str, default: &str) -> Result<PathBuf, ConfigError> {
    match env::var(name) {
        Ok(v) => Ok(PathBuf::from(v)),
        Err(env::VarError::NotPresent) => Ok(PathBuf::from(default)),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::InvalidUnicode(name.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = Config {
            max_threads: MAX_THREADS_DEFAULT,
            log_dir: PathBuf::from(LOG_DIR_DEFAULT),
            version: "0.0.0",
        };
        assert_eq!(cfg.max_threads, MAX_THREADS_DEFAULT);
    }

    #[test]
    fn test_parse_env_usize_invalid() {
        std::env::set_var("TEST_VAR_INVALID", "abc");
        let err = parse_env_usize("TEST_VAR_INVALID", 256).unwrap_err();
        assert!(err.to_string().contains("TEST_VAR_INVALID"));
        std::env::remove_var("TEST_VAR_INVALID");
    }

    #[test]
    fn test_parse_env_usize_default() {
        std::env::remove_var("TEST_VAR_MISSING");
        let val = parse_env_usize("TEST_VAR_MISSING", 256).unwrap();
        assert_eq!(val, 256);
    }

    #[test]
    fn test_config_max_threads_zero() {
        std::env::set_var("NONCE_CRACKER_MAX_THREADS", "0");
        let err = Config::from_env().unwrap_err();
        assert!(err.to_string().contains("must be > 0"));
        std::env::remove_var("NONCE_CRACKER_MAX_THREADS");
    }
}
