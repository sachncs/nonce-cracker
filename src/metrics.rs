use std::time::Instant;
use tracing::info;

#[derive(Debug)]
pub struct SearchMetrics {
    start: Instant,
    threads: usize,
}

impl SearchMetrics {
    pub fn new(threads: usize) -> Self {
        Self {
            start: Instant::now(),
            threads,
        }
    }

    pub fn report(&self, found: bool, delta: Option<i128>) {
        let elapsed = self.start.elapsed().as_secs_f64();
        info!(
            target: "nonce-cracker::metrics",
            event = "search_complete",
            found = found,
            delta = delta,
            elapsed_sec = format!("{:.3}", elapsed),
            threads = self.threads,
        );
    }
}

pub fn search_started(threads: usize) -> SearchMetrics {
    SearchMetrics::new(threads)
}

pub fn search_completed(m: &SearchMetrics, found: bool, delta: Option<i128>) {
    m.report(found, delta);
}
