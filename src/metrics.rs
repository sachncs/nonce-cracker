//! Search performance metrics.
//!
//! The module defines a [`SearchReport`] event type and a [`MetricsSink`]
//! trait.  Callers decide how reports are handled; the default
//! [`TracingMetricsSink`] emits structured `tracing` lines.

use std::time::Duration;

/// A completed search report with all measurable data.
///
/// `Copy` so that implementations that do not need to retain the report
/// incur no allocation cost.
#[derive(Debug, Clone, Copy)]
pub struct SearchReport {
    /// Wall-clock elapsed time.
    pub elapsed: Duration,
    /// Whether a match was found.
    pub found: bool,
    /// The discovered nonce, if any.
    pub nonce: Option<i128>,
    /// Number of threads used.
    pub threads: usize,
}

/// Trait for receiving [`SearchReport`] events.
///
/// Implementors can write to a tracing subscriber, a metrics backend, a
/// database, or any other sink.  The trait is object-safe and all methods
/// are sync.
///
/// `emit` receives a borrowed reference so implementations may process
/// the data immediately or clone it for later batch delivery.
pub trait MetricsSink: Send + Sync {
    /// Emit a search report.
    fn emit(&self, report: &SearchReport);
}

/// Default sink that emits `search_complete` events via [`tracing::info!`](tracing).
pub struct TracingMetricsSink;

impl MetricsSink for TracingMetricsSink {
    fn emit(&self, report: &SearchReport) {
        tracing::info!(
            target: "nonce-cracker::metrics",
            event = "search_complete",
            found = report.found,
            nonce = report.nonce,
            elapsed_sec = format!("{:.3}", report.elapsed.as_secs_f64()),
            threads = report.threads,
        );
    }
}
