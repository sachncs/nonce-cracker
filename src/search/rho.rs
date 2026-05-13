//! Pollard's rho with van Oorschot-Wiener parallel collision search.
//!
//! Uses the negation map (Bernstein-Lange-Schwabe 2011) for sqrt(2) speedup,
//! branchless iteration, and Brent-style fruitless cycle detection.

use crate::{
    context::ShutdownToken,
    error::{EngineError, Result},
    search::params::RhoParams,
};
use k256::{elliptic_curve::BatchNormalize, AffinePoint, ProjectivePoint, Scalar};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::info;

/// Number of regions for the pseudorandom walk.
const R_REGIONS: usize = 20;
/// Check for fruitless cycles every this many iterations.
const CYCLE_CHECK_INTERVAL: u64 = 32;
/// Sentinel for "not found" in the atomic result.
const NOT_FOUND: u64 = u64::MAX;

/// A precomputed region defines the step multipliers for one partition of the walk.
struct WalkRegion {
    a: Scalar, // exponent of g
    b: Scalar, // exponent of h
}

/// A distinguished point found during a trail.
struct DistinguishedPoint {
    x: AffinePoint,
    a: Scalar,
    b: Scalar,
}
