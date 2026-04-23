use std::env;
use std::path::PathBuf;
use std::sync::OnceLock;

pub const MAX_THREADS_DEFAULT: usize = 256;
pub const LOG_DIR_DEFAULT: &str = "logs";

#[derive(Debug, Clone)]
pub struct Config {
    pub max_threads: usize,
    pub log_dir: PathBuf,
    pub version: &'static str,
}

static CONFIG: OnceLock<Config> = OnceLock::new();

#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ConfigError {}

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        let max_threads = parse_env_usize("NONCE_CRACKER_MAX_THREADS", MAX_THREADS_DEFAULT)?;
        let log_dir = parse_env_path("NONCE_CRACKER_LOG_DIR", LOG_DIR_DEFAULT)?;

        if max_threads == 0 {
            return Err(ConfigError("NONCE_CRACKER_MAX_THREADS must be > 0".into()));
        }
        if !log_dir.exists() {
            std::fs::create_dir_all(&log_dir)
                .map_err(|e| ConfigError(format!("failed to create log dir: {e}")))?;
        }

        Ok(Config {
            max_threads,
            log_dir,
            version: env!("CARGO_PKG_VERSION"),
        })
    }

    pub fn get() -> &'static Config {
        CONFIG.get().expect("Config::init() must be called first")
    }

    pub fn init() -> Result<(), ConfigError> {
        CONFIG
            .set(Self::load()?)
            .map_err(|_| ConfigError("already initialized".into()))?;
        Ok(())
    }
}

fn parse_env_usize(name: &str, default: usize) -> Result<usize, ConfigError> {
    match env::var(name) {
        Ok(v) => v
            .parse()
            .map_err(|e| ConfigError(format!("{name}={v}: {e}"))),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(_) => Err(ConfigError(format!("{name}: invalid unicode"))),
    }
}

fn parse_env_path(name: &str, default: &str) -> Result<PathBuf, ConfigError> {
    match env::var(name) {
        Ok(v) => Ok(PathBuf::from(v)),
        Err(env::VarError::NotPresent) => Ok(PathBuf::from(default)),
        Err(_) => Err(ConfigError(format!("{name}: invalid unicode"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let _ = CONFIG.set(Config {
            max_threads: MAX_THREADS_DEFAULT,
            log_dir: PathBuf::from(LOG_DIR_DEFAULT),
            version: "0.0.0",
        });
        assert_eq!(Config::get().max_threads, MAX_THREADS_DEFAULT);
    }
}
