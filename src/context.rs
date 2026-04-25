//! Application context that owns global resources.
//!
//! [`AppContext`] is constructed once in `main` and passed down.
//! It holds configuration and a [`ShutdownToken`] that replaces the old
//! global `SHUTDOWN` static.

use crate::config::Config;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Token that can be signalled to request graceful shutdown.
///
/// Clones share the same underlying flag so that a signal handler
/// can signal shutdown and worker threads can observe it.
///
/// All operations use sequential consistency ([`Ordering::SeqCst`]) to ensure
/// that a signal delivered on one thread is immediately visible to all workers.
#[derive(Debug, Clone)]
pub struct ShutdownToken {
    inner: Arc<AtomicBool>,
}

impl ShutdownToken {
    /// Create a new unsignalled token.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Signal shutdown.  Safe to call from any thread (e.g. a signal handler).
    ///
    /// Uses [`Ordering::SeqCst`] to ensure the signal is immediately visible
    /// to all worker threads on any platform.
    pub fn signal(&self) {
        self.inner.store(true, Ordering::SeqCst);
    }

    /// Check whether shutdown has been requested.
    ///
    /// Uses [`Ordering::SeqCst`]; paired with [`signal`](Self::signal) this
    /// guarantees that any signal set before this call is observed.
    #[must_use]
    pub fn is_signalled(&self) -> bool {
        self.inner.load(Ordering::SeqCst)
    }
}

impl Default for ShutdownToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Top-level context that owns all process-wide resources.
///
/// Construct once in `main` and pass `&ctx` (or cheap clone handles) to
/// subsystems.  The contained [`ShutdownToken`] can be cloned and passed
/// to a signal handler so workers can observe shutdown requests.
pub struct AppContext {
    /// Loaded configuration.
    pub config: Config,
    /// Shutdown coordination token.
    pub shutdown: ShutdownToken,
}

impl AppContext {
    /// Create a new context from the given configuration.
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self {
            config,
            shutdown: ShutdownToken::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shutdown_token_signal() {
        let token = ShutdownToken::new();
        assert!(!token.is_signalled());
        token.signal();
        assert!(token.is_signalled());
    }

    #[test]
    fn test_shutdown_token_default() {
        let token = ShutdownToken::default();
        assert!(!token.is_signalled());
    }

    #[test]
    fn test_app_context_new() {
        let config = Config {
            max_threads: 4,
            log_dir: std::path::PathBuf::from("/tmp"),
            version: "test",
        };
        let ctx = AppContext::new(config);
        assert_eq!(ctx.config.max_threads, 4);
        assert!(!ctx.shutdown.is_signalled());
    }
}
