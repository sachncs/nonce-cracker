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
    /// Baby-step table mapping compressed point to step index.
    pub baby_map: &'a crate::search::openmap::OpenMap,
    /// Rayon thread pool for parallel giant-step evaluation.
    pub pool: &'a rayon::ThreadPool,
    /// Cooperative shutdown token.
    pub shutdown: &'a crate::context::ShutdownToken,
}

/// Parameters for the Pollard's kangaroo bounded discrete-log search.
pub struct KangarooParams {
    /// Generator point `G`.
    pub g: ProjectivePoint,
    /// Target point `h = target`.
    pub h: ProjectivePoint,
    /// Affine slope `alpha` from the signature.
    pub alpha: Scalar,
    /// Affine intercept `beta` from the signature.
    pub beta: Scalar,
    /// First nonce candidate in the search range.
    pub start: i128,
    /// Step between candidates.
    pub step: i128,
    /// Total number of candidates.
    pub total: u128,
    /// Number of bits that must be zero for a distinguished point (default 16).
    pub d: u32,
    /// Maximum iterations per thread before giving up.
    pub max_iterations: u64,
}
