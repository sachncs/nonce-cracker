//! Parallel search algorithms: parallel scan and Baby-Step Giant-Step (BSGS).
//!
//! The public API is [`SearchEngine`], which owns a long-lived Rayon thread
//! pool and dispatches to the internal algorithms.  Raw algorithm functions
//! (`parallel_scan`, `bsgs`) are crate-private.

mod bsgs;
mod kangaroo;
/// Open-addressing hash map for storing distinguished points.
pub mod openmap;
mod parallel;
mod params;

pub use params::{KangarooParams, ScanParams};

use crate::{
    config::Config,
    context::ShutdownToken,
    crypto::{derive_affine_constants, derive_private_key},
    domain::{SearchOutcome, SearchSpec, Signature},
    error::{EngineError, Result},
    metrics::{MetricsSink, SearchReport},
};
use k256::{AffinePoint, ProjectivePoint, PublicKey, Scalar};
use rayon::ThreadPool;
use std::sync::Arc;
use std::time::Instant;

/// Maximum candidate count for which the parallel scan is used.
///
/// Above this threshold the BSGS algorithm is selected automatically.
pub const BSGS_THRESHOLD: u128 = 1 << 32;

/// Maximum candidate count for which BSGS is used.
/// Above this threshold Pollard's kangaroo is selected automatically.
pub const KANGAROO_THRESHOLD: u128 = 1 << 48;

/// Owned search engine that holds a reusable Rayon thread pool.
///
/// Construct once and call [`SearchEngine::search`] for each query.
pub struct SearchEngine {
    pool: ThreadPool,
    thread_count: usize,
    shutdown: ShutdownToken,
    metrics: Arc<dyn MetricsSink + Send + Sync>,
    bsgs_max_m: u64,
}

impl std::fmt::Debug for SearchEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchEngine")
            .field("thread_count", &self.thread_count)
            .field("shutdown", &self.shutdown)
            .finish_non_exhaustive()
    }
}

impl SearchEngine {
    /// Create a new engine.
    ///
    /// `threads` overrides the auto-detected thread count; `None` lets the
    /// engine pick `available_parallelism` capped by `config.max_threads`.
    ///
    /// # Errors
    ///
    /// Returns an error if the Rayon thread pool cannot be built.
    pub fn new(
        config: &Config,
        threads: Option<usize>,
        shutdown: ShutdownToken,
        metrics: Arc<dyn MetricsSink + Send + Sync>,
    ) -> Result<Self> {
        let max_threads = config.max_threads;
        let thread_count = match threads {
            Some(0) => return Err(EngineError::ThreadCountZero.into()),
            Some(t) if t > max_threads => {
                tracing::warn!(requested = t, max = max_threads, "capping threads");
                max_threads
            }
            Some(t) => t,
            None => std::thread::available_parallelism()
                .map(std::num::NonZero::get)
                .unwrap_or(1)
                .min(max_threads),
        };

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .build()
            .map_err(|e| EngineError::ThreadPoolInit(e.to_string()))?;

        Ok(Self {
            pool,
            thread_count,
            shutdown,
            metrics,
            bsgs_max_m: bsgs::BSGS_MAX_M,
        })
    }

    /// Return the shutdown token held by this engine.
    #[must_use]
    pub const fn shutdown_token(&self) -> &ShutdownToken {
        &self.shutdown
    }

    /// Search for the nonce `k` that makes the derived private key match
    /// `target`.
    ///
    /// Returns [`SearchOutcome`] containing the nonce (if found) and the
    /// affine constants.
    ///
    /// # Errors
    ///
    /// Returns a crypto error if the affine constants cannot be derived, or a
    /// range error if the search specification total overflows.
    pub fn search(
        &self,
        spec: &SearchSpec,
        sig: &Signature,
        target: &PublicKey,
    ) -> Result<SearchOutcome> {
        let start_time = Instant::now();
        let (alpha, beta) = derive_affine_constants(sig)?;

        let target_affine: AffinePoint = *target.as_affine();
        let d0_scalar = derive_private_key(spec.start, alpha, beta);
        let d0_point = ProjectivePoint::GENERATOR * d0_scalar;
        if d0_point == target_affine {
            let outcome = SearchOutcome::new(Some(spec.start), alpha, beta);
            self.emit_metrics(start_time, &outcome);
            return Ok(outcome);
        }

        let step_scalar = alpha * Scalar::from(spec.step.cast_unsigned());
        let step_point = ProjectivePoint::GENERATOR * step_scalar;
        let total = spec.total()?;

        if step_scalar == Scalar::ZERO {
            let outcome = SearchOutcome::new(None, alpha, beta);
            self.emit_metrics(start_time, &outcome);
            return Ok(outcome);
        }

        let scan = ScanParams {
            target: *target,
            start: spec.start,
            step: spec.step,
            total,
            alpha,
            beta,
            step_point,
        };

        let found = if total <= BSGS_THRESHOLD {
            parallel::scan(&self.pool, self.thread_count, &self.shutdown, &scan)
        } else if total > KANGAROO_THRESHOLD {
            let kangaroo_params = crate::search::params::KangarooParams {
                g: ProjectivePoint::GENERATOR,
                h: scan.target.into(),
                alpha: scan.alpha,
                beta: scan.beta,
                start: scan.start,
                step: scan.step,
                total,
                d: 16,
                max_iterations: 10 * (total as f64).sqrt() as u64,
            };
            kangaroo::search(
                &self.pool,
                self.thread_count,
                &self.shutdown,
                &kangaroo_params,
            )?
        } else {
            bsgs::search(
                &self.pool,
                self.thread_count,
                &self.shutdown,
                self.bsgs_max_m,
                &scan,
            )?
        };

        let outcome = SearchOutcome::new(found, alpha, beta);
        self.emit_metrics(start_time, &outcome);
        Ok(outcome)
    }

    fn emit_metrics(&self, start: Instant, outcome: &SearchOutcome) {
        self.metrics.emit(&SearchReport {
            elapsed: start.elapsed(),
            found: outcome.nonce.is_some(),
            nonce: outcome.nonce,
            threads: self.thread_count,
        });
    }
}

#[cfg(test)]
impl SearchEngine {
    /// Test-only constructor that allows overriding BSGS parameters.
    pub fn with_params(
        pool: ThreadPool,
        thread_count: usize,
        shutdown: ShutdownToken,
        metrics: Arc<dyn MetricsSink + Send + Sync>,
        bsgs_max_m: u64,
    ) -> Self {
        Self {
            pool,
            thread_count,
            shutdown,
            metrics,
            bsgs_max_m,
        }
    }

    /// Test-only access to the BSGS algorithm.
    pub fn bsgs(&self, scan: &ScanParams) -> Result<Option<i128>> {
        bsgs::search(
            &self.pool,
            self.thread_count,
            &self.shutdown,
            self.bsgs_max_m,
            scan,
        )
    }

    /// Test-only access to the parallel scan algorithm.
    pub fn parallel_scan(&self, scan: &ScanParams) -> Option<i128> {
        parallel::scan(&self.pool, self.thread_count, &self.shutdown, scan)
    }
}

/// Benchmark- and test-only access to the Pollard's kangaroo algorithm.
#[doc(hidden)]
impl SearchEngine {
    pub fn kangaroo(
        &self,
        kangaroo_params: &crate::search::params::KangarooParams,
    ) -> crate::error::Result<Option<i128>> {
        kangaroo::search(
            &self.pool,
            self.thread_count,
            &self.shutdown,
            kangaroo_params,
        )
    }
}

#[cfg(test)]
mod tests;
