//! Cooperative shutdown coordination.
//!
//! [`ShutdownToken`] is a clonable handle to a shared `AtomicBool`.  It is
//! constructed once in `main` and cloned into the search engine; the signal
//! handler mutates the underlying flag while workers observe it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Token that can be signalled to request graceful shutdown.
///
/// Clones share the same underlying flag so that a signal handler
/// can signal shutdown and worker threads can observe it.
///
/// `signal` uses [`Ordering::Release`] and `is_signalled` uses [`Ordering::Acquire`],
/// guaranteeing that a signal set before a load is observed.
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

    /// Signal shutdown. Safe to call from any thread (e.g. a signal handler).
    pub fn signal(&self) {
        self.inner.store(true, Ordering::Release);
    }

    /// Check whether shutdown has been requested.
    #[must_use]
    pub fn is_signalled(&self) -> bool {
        self.inner.load(Ordering::Acquire)
    }
}

impl Default for ShutdownToken {
    fn default() -> Self {
        Self::new()
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
}
