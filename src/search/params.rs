//! Parameter structs consumed by the search algorithms.

use k256::{ProjectivePoint, PublicKey, Scalar};
/// Parameters shared by [`parallel_scan`](crate::search::parallel::scan) and
/// [`bsgs::search`](crate::search::bsgs::search).
pub struct ScanParams {
    /// Target public key to match.
    pub target: PublicKey,
    /// First nonce candidate in the search range.
    pub start: i128,
    /// Increment between successive nonce candidates.
    pub step: i128,
    /// Total number of candidates to evaluate.
    pub total: u128,
    /// Affine slope `alpha` from the signature.
    pub alpha: Scalar,
    /// Affine intercept `beta` from the signature.
    pub beta: Scalar,
    /// Precomputed `G * (alpha * step)` to avoid repeated scalar multiplies.
    pub step_point: ProjectivePoint,
}

/// Parameters for the giant-step phase shared by standard and segmented BSGS.
pub struct GiantStepParams<'a> {
    /// Target offset point: `T = Q - d0 * G`.
    pub t: ProjectivePoint,
    /// Baby-step count (and giant-step stride).
    pub m: u64,
    /// Precomputed `m * step_point`.
    pub m_step: ProjectivePoint,
    /// Total candidates in the full search range.
    pub total: u128,
    /// Number of worker threads.
    pub thread_count: usize,
    /// Precomputed `G * (alpha * step)`.
    pub step_point: ProjectivePoint,
    /// First delta candidate.
    pub start: i128,
    /// Step between candidates.
    pub step: i128,
    /// Baby-step tables (sharded by build thread) mapping compressed point to
    /// step index.  Lookups must scan all shards.
    pub baby_maps: &'a [crate::search::openmap::OpenMap],
    /// Rayon thread pool for parallel giant-step evaluation.
    pub pool: &'a rayon::ThreadPool,
    /// Cooperative shutdown token.
    pub shutdown: &'a crate::context::ShutdownToken,
}

/// Parameters for the Pollard's kangaroo bounded discrete-log search.
///
/// Fields are `pub(crate)` to enforce construction via the validated
/// [`KangarooParams::new`] constructor.
#[derive(Debug)]
pub struct KangarooParams {
    /// Generator point `G`.
    pub(crate) g: ProjectivePoint,
    /// Target point `h = target`.
    pub(crate) h: ProjectivePoint,
    /// Affine slope `alpha` from the signature.
    pub(crate) alpha: Scalar,
    /// Affine intercept `beta` from the signature.
    pub(crate) beta: Scalar,
    /// First nonce candidate in the search range.
    pub(crate) start: i128,
    /// Step between candidates.
    pub(crate) step: i128,
    /// Total number of candidates.
    pub(crate) total: u128,
    /// Number of bits that must be zero for a distinguished point (default 16).
    pub(crate) d: u32,
    /// Maximum iterations per thread before giving up.
    pub(crate) max_iterations: u64,
}

impl KangarooParams {
    /// Create a new `KangarooParams` with validation.
    ///
    /// `max_iterations` defaults to `10 * sqrt(total)` if `None` is provided.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::KangarooParamsInvalid`] if `d == 0`, `d > 264`, or
    /// `max_iterations == 0`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        g: ProjectivePoint,
        h: ProjectivePoint,
        alpha: Scalar,
        beta: Scalar,
        start: i128,
        step: i128,
        total: u128,
        d: u32,
        max_iterations: Option<u64>,
    ) -> crate::error::Result<Self> {
        if d == 0 || d > 264 {
            return Err(crate::error::EngineError::KangarooParamsInvalid(format!(
                "d={d} out of range [1, 264]"
            ))
            .into());
        }
        let max_iterations = max_iterations.unwrap_or_else(|| {
            let total_f64 = total as f64;
            (10.0 * total_f64.sqrt()).max(1.0) as u64
        });
        if max_iterations == 0 {
            return Err(crate::error::EngineError::KangarooParamsInvalid(
                "max_iterations must be > 0".into(),
            )
            .into());
        }
        let n = (total - 1) as i128;
        let _ = start
            .checked_add(
                n.checked_mul(step)
                    .ok_or(crate::error::RangeError::RangeOverflow)?,
            )
            .ok_or(crate::error::RangeError::RangeOverflow)?;
        Ok(Self {
            g,
            h,
            alpha,
            beta,
            start,
            step,
            total,
            d,
            max_iterations,
        })
    }
}
