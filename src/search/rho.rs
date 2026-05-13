//! Pollard's rho with van Oorschot-Wiener parallel collision search.
//!
//! Uses the negation map (Bernstein-Lange-Schwabe 2011) for sqrt(2) speedup,
//! branchless iteration, and Brent-style fruitless cycle detection.

use crate::{
    context::ShutdownToken,
    error::{EngineError, Result},
    search::params::RhoParams,
};
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, BatchNormalize},
    AffinePoint, ProjectivePoint, Scalar,
};
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

/// Apply the negation map: return |P|, the canonical representative of {P, -P}.
/// For secp256k1, -P = (x, -y). We choose the one with even y (0x02 prefix).
fn canonicalize(point: ProjectivePoint) -> ProjectivePoint {
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    // For compressed SEC1, byte 0 is 0x02 (even y) or 0x03 (odd y).
    // We want even y, i.e., 0x02 prefix.
    if bytes[0] == 0x03 {
        -point
    } else {
        point
    }
}

fn init_regions(_g: ProjectivePoint, _h: ProjectivePoint) -> Vec<WalkRegion> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..R_REGIONS)
        .map(|_| {
            let a = Scalar::from(rng.gen::<u64>());
            let b = Scalar::from(rng.gen::<u64>());
            WalkRegion { a, b }
        })
        .collect()
}

fn walk_step(x: ProjectivePoint, regions: &[WalkRegion], g: ProjectivePoint, h: ProjectivePoint) -> ProjectivePoint {
    let affine = x.to_affine();
    let encoded = affine.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    // Use first 8 bytes of x-coordinate as a hash to select region
    let hash = u64::from_le_bytes([
        bytes[1], bytes[2], bytes[3], bytes[4],
        bytes[5], bytes[6], bytes[7], bytes[8],
    ]);
    let region_idx = (hash as usize) % regions.len();
    let region = &regions[region_idx];
    // x = |x * g^a * h^b|
    let step = g * region.a + h * region.b;
    canonicalize(x + step)
}
