//! Metrics collection and reporting for nonce-cracker.
//!
//! Provides Prometheus-compatible metrics for observability:
//! - Search duration
//! - Candidates evaluated per second
//! - Success/failure counts
//! - Thread utilization
//!
//! ## Usage
//!
//! Metrics are collected during searches and can be exported via:
//! - Logs (structured format)
//! - Prometheus endpoint (optional feature)
//! - StatsD (optional feature)

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::info;

/// Global metrics collector for search operations.
#[derive(Debug)]
pub struct SearchMetrics {
    /// Start time of the search
    start_time: Instant,
    /// Total candidates evaluated
    candidates_evaluated: AtomicU64,
    /// Candidates evaluated since last report
    #[allow(dead_code)]
    candidates_since_last: AtomicU64,
    /// Last report time
    #[allow(dead_code)]
    last_report: std::sync::Mutex<Instant>,
    /// Report interval for progress updates
    #[allow(dead_code)]
    report_interval: Duration,
    /// Thread count used
    thread_count: usize,
}

#[allow(dead_code)]
impl SearchMetrics {
    /// Create a new metrics collector for a search.
    pub fn new(thread_count: usize) -> Self {
        let now = Instant::now();
        Self {
            start_time: now,
            candidates_evaluated: AtomicU64::new(0),
            candidates_since_last: AtomicU64::new(0),
            last_report: std::sync::Mutex::new(now),
            report_interval: Duration::from_secs(10),
            thread_count,
        }
    }

    /// Record that candidates were evaluated.
    pub fn record_candidates(&self, count: u64) {
        self.candidates_evaluated
            .fetch_add(count, Ordering::Relaxed);
        self.candidates_since_last
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Check if a progress report should be emitted.
    pub fn should_report(&self) -> bool {
        let now = Instant::now();
        let mut last = self.last_report.lock().unwrap();
        if now.duration_since(*last) >= self.report_interval {
            *last = now;
            true
        } else {
            false
        }
    }

    /// Emit a progress report via logging.
    pub fn report_progress(&self) {
        let total = self.candidates_evaluated.load(Ordering::Relaxed);
        let since_last = self.candidates_since_last.swap(0, Ordering::Relaxed);
        let elapsed = self.start_time.elapsed();
        let elapsed_secs = elapsed.as_secs_f64();

        let rate = if elapsed_secs > 0.0 {
            since_last as f64 / self.report_interval.as_secs_f64()
        } else {
            0.0
        };

        let overall_rate = if elapsed_secs > 0.0 {
            total as f64 / elapsed_secs
        } else {
            0.0
        };

        info!(
            target: "nonce-cracker::metrics",
            total_candidates = total,
            rate_per_sec = format!("{:.2}", rate),
            overall_rate_per_sec = format!("{:.2}", overall_rate),
            elapsed_sec = elapsed.as_secs(),
            threads = self.thread_count,
            "search progress"
        );
    }

    /// Emit final search results.
    pub fn report_completion(&self, found: bool, delta: Option<i64>) {
        let total = self.candidates_evaluated.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed();
        let elapsed_secs = elapsed.as_secs_f64();

        let overall_rate = if elapsed_secs > 0.0 {
            total as f64 / elapsed_secs
        } else {
            0.0
        };

        info!(
            target: "nonce-cracker::metrics",
            event = "search_complete",
            found = found,
            delta = delta,
            total_candidates = total,
            elapsed_sec = format!("{:.3}", elapsed_secs),
            overall_rate_per_sec = format!("{:.2}", overall_rate),
            threads = self.thread_count,
            "search completed"
        );
    }

    /// Get elapsed time since search started.
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }
}

/// Simple counter for tracking events.
#[derive(Debug)]
pub struct Counter {
    value: AtomicU64,
    #[allow(dead_code)]
    name: &'static str,
}

#[allow(dead_code)]
impl Counter {
    /// Create a new counter.
    pub const fn new(name: &'static str) -> Self {
        Self {
            value: AtomicU64::new(0),
            name,
        }
    }

    /// Increment the counter by 1.
    pub fn increment(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the counter by n.
    pub fn add(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    /// Get the current value.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Get the counter name.
    pub fn name(&self) -> &'static str {
        self.name
    }
}

/// Global application metrics.
pub struct ApplicationMetrics {
    /// Total number of searches initiated
    pub searches_started: Counter,
    /// Total number of searches completed
    pub searches_completed: Counter,
    /// Number of successful key recoveries
    pub keys_recovered: Counter,
    /// Number of errors encountered
    pub errors: Counter,
}

#[allow(dead_code)]
impl ApplicationMetrics {
    /// Create new application metrics.
    pub const fn new() -> Self {
        Self {
            searches_started: Counter::new("searches_started"),
            searches_completed: Counter::new("searches_completed"),
            keys_recovered: Counter::new("keys_recovered"),
            errors: Counter::new("errors"),
        }
    }

    /// Emit a summary of application metrics.
    pub fn emit_summary(&self) {
        info!(
            target: "nonce-cracker::metrics",
            searches_started = self.searches_started.get(),
            searches_completed = self.searches_completed.get(),
            keys_recovered = self.keys_recovered.get(),
            errors = self.errors.get(),
            "application metrics"
        );
    }
}

/// Global application metrics instance.
pub static APP_METRICS: ApplicationMetrics = ApplicationMetrics::new();

/// Emit a search started event.
pub fn search_started(thread_count: usize) -> SearchMetrics {
    APP_METRICS.searches_started.increment();
    SearchMetrics::new(thread_count)
}

/// Emit a search completed event.
pub fn search_completed(metrics: &SearchMetrics, found: bool, delta: Option<i64>) {
    APP_METRICS.searches_completed.increment();
    if found {
        APP_METRICS.keys_recovered.increment();
    }
    metrics.report_completion(found, delta);
}

/// Emit an error event.
#[allow(dead_code)]
pub fn record_error() {
    APP_METRICS.errors.increment();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter() {
        let counter = Counter::new("test");
        assert_eq!(counter.get(), 0);
        counter.increment();
        assert_eq!(counter.get(), 1);
        counter.add(5);
        assert_eq!(counter.get(), 6);
    }

    #[test]
    fn test_search_metrics() {
        let metrics = SearchMetrics::new(4);
        metrics.record_candidates(100);
        assert!(metrics.elapsed().as_secs() < 1);
    }
}
