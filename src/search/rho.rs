//! Pollard's rho with van Oorschot-Wiener parallel collision search.
//!
//! Uses the negation map (Bernstein-Lange-Schwabe 2011) for sqrt(2) speedup,
//! branchless iteration, and Brent-style fruitless cycle detection.

use crate::{
    context::ShutdownToken,
    error::Result,
    search::params::RhoParams,
};
use k256::{
    elliptic_curve::sec1::ToEncodedPoint,
    AffinePoint, ProjectivePoint, Scalar,
};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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

/// Apply the negation map: return |P|, the canonical representative of {P, -P}.
/// For secp256k1, -P = (x, -y). We choose the one with even y (0x02 prefix).
/// Returns the canonical point and whether the point was negated.
fn canonicalize(point: ProjectivePoint) -> (ProjectivePoint, bool) {
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    // For compressed SEC1, byte 0 is 0x02 (even y) or 0x03 (odd y).
    // We want even y, i.e., 0x02 prefix.
    if bytes[0] == 0x03 {
        (-point, true)
    } else {
        (point, false)
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

fn walk_step(
    x: ProjectivePoint,
    a: Scalar,
    b: Scalar,
    regions: &[WalkRegion],
    g: ProjectivePoint,
    h: ProjectivePoint,
) -> (ProjectivePoint, Scalar, Scalar) {
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
    let mut new_a = a + region.a;
    let mut new_b = b + region.b;
    let (new_x, negated) = canonicalize(x + step);
    if negated {
        new_a = -new_a;
        new_b = -new_b;
    }
    (new_x, new_a, new_b)
}

fn is_distinguished(point: &AffinePoint, d: u32) -> bool {
    let encoded = point.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    let full_bytes = (d / 8) as usize;
    let rem_bits = (d % 8) as usize;

    // Check full bytes
    for i in 0..full_bytes {
        if bytes[1 + i] != 0 {
            return false;
        }
    }

    // Check partial byte (top rem_bits bits must be zero)
    if rem_bits > 0 {
        let mask = 0xFFu8 << (8 - rem_bits);
        if (bytes[1 + full_bytes] & mask) != 0 {
            return false;
        }
    }

    true
}

struct CollisionTable {
    shards: Vec<FxHashMap<[u8; 33], (Scalar, Scalar)>>,
}

impl CollisionTable {
    fn new(thread_count: usize) -> Self {
        let mut shards = Vec::with_capacity(thread_count);
        for _ in 0..thread_count {
            shards.push(FxHashMap::default());
        }
        Self { shards }
    }

    fn insert(&mut self, shard_id: usize, key: [u8; 33], a: Scalar, b: Scalar) {
        self.shards[shard_id].insert(key, (a, b));
    }

    fn find_collision(
        &self,
        key: &[u8; 33],
    ) -> Option<((Scalar, Scalar), (Scalar, Scalar))> {
        let mut first = None;
        for shard in &self.shards {
            if let Some(&(a, b)) = shard.get(key) {
                if let Some((a1, b1)) = first {
                    return Some(((a1, b1), (a, b)));
                }
                first = Some((a, b));
            }
        }
        None
    }
}

/// Convert a small `Scalar` (mod curve order) into an `i128`.
///
/// Handles both positive and negative values whose absolute value fits in `i128`.
fn scalar_to_i128(s: &Scalar) -> Option<i128> {
    let bytes = s.to_bytes();
    let arr: [u8; 32] = bytes.into();
    if arr[..16].iter().all(|&b| b == 0) {
        let low = u128::from_be_bytes([
            arr[16], arr[17], arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23],
            arr[24], arr[25], arr[26], arr[27],
            arr[28], arr[29], arr[30], arr[31],
        ]);
        if low <= i128::MAX as u128 {
            return Some(low as i128);
        }
    }
    let neg_s = Scalar::ZERO - s;
    let neg_arr: [u8; 32] = neg_s.to_bytes().into();
    if neg_arr[..16].iter().all(|&b| b == 0) {
        let low = u128::from_be_bytes([
            neg_arr[16], neg_arr[17], neg_arr[18], neg_arr[19],
            neg_arr[20], neg_arr[21], neg_arr[22], neg_arr[23],
            neg_arr[24], neg_arr[25], neg_arr[26], neg_arr[27],
            neg_arr[28], neg_arr[29], neg_arr[30], neg_arr[31],
        ]);
        if low <= i128::MAX as u128 {
            return Some(-(low as i128));
        }
    }
    None
}

/// Run parallel Pollard's rho trails.
///
/// Each thread runs independent trails starting from a unique seed point.
/// Distinguished points are stored in a sharded collision table; when two
/// trails collide, the discrete log is solved and converted back to a nonce.
pub fn search(
    pool: &rayon::ThreadPool,
    thread_count: usize,
    shutdown: &ShutdownToken,
    params: &RhoParams,
) -> Result<Option<i128>> {
    // Degenerate case: alpha == 0 means the private key is beta for all nonces.
    if params.alpha == Scalar::ZERO {
        let expected = params.g * params.beta;
        if expected == params.h {
            return Ok(Some(params.start));
        } else {
            return Ok(None);
        }
    }

    let regions = init_regions(params.g, params.h);
    let table = Arc::new(std::sync::Mutex::new(CollisionTable::new(thread_count)));
    let found_flag = Arc::new(AtomicU64::new(NOT_FOUND));
    let found_log = Arc::new(std::sync::Mutex::new(None::<Scalar>));
    let iterations = Arc::new(AtomicU64::new(0));

    pool.install(|| {
        (0..thread_count).into_par_iter().for_each(|tid| {
            let seed = tid as u64 + 1;
            let seed_scalar = Scalar::from(seed);
            let (mut x, negated) = canonicalize(params.g * seed_scalar);
            let mut local_a = if negated { -seed_scalar } else { seed_scalar };
            let mut local_b = Scalar::ZERO;

            let mut _trail_start_a = local_a;
            let mut _trail_start_b = local_b;
            let mut trail_start_x = x;
            let mut steps_since_check = 0u64;

            loop {
                if shutdown.is_signalled() {
                    break;
                }
                if found_flag.load(Ordering::Relaxed) != NOT_FOUND {
                    break;
                }

                let iter = iterations.fetch_add(1, Ordering::Relaxed);
                if iter >= params.max_iterations {
                    break;
                }

                // Walk step with exponent tracking and negation-map handling.
                let (new_x, new_a, new_b) =
                    walk_step(x, local_a, local_b, &regions, params.g, params.h);
                x = new_x;
                local_a = new_a;
                local_b = new_b;

                steps_since_check += 1;

                // Brent-style cycle detection
                if steps_since_check >= CYCLE_CHECK_INTERVAL {
                    steps_since_check = 0;
                    if x == trail_start_x {
                        // Fruitless cycle — restart with a new random seed.
                        let new_seed = iter.wrapping_mul(0x9e3779b97f4a7c15) + tid as u64;
                        let new_seed_scalar = Scalar::from(new_seed);
                        let (new_x, negated) = canonicalize(params.g * new_seed_scalar);
                        x = new_x;
                        local_a = if negated { -new_seed_scalar } else { new_seed_scalar };
                        local_b = Scalar::ZERO;
                        _trail_start_a = local_a;
                        _trail_start_b = local_b;
                        trail_start_x = x;
                        continue;
                    }
                }

                let affine = x.to_affine();
                if is_distinguished(&affine, params.d) {
                    let key = crate::crypto::affine_key(&affine);
                    let mut table_guard = table.lock().unwrap();
                    if let Some(((a1, b1), (a2, b2))) = table_guard.find_collision(&key) {
                        let delta_a = a1 - a2;
                        let delta_b = b2 - b1;
                        if delta_b != Scalar::ZERO {
                            let log = delta_a * delta_b.invert().unwrap();
                            let mut log_guard = found_log.lock().unwrap();
                            if log_guard.is_none() {
                                *log_guard = Some(log);
                                found_flag.store(1, Ordering::SeqCst);
                            }
                            drop(log_guard);
                            drop(table_guard);
                            break;
                        }
                    }
                    table_guard.insert(tid, key, local_a, local_b);
                    drop(table_guard);

                    // Start a new trail segment from this distinguished point.
                    _trail_start_a = local_a;
                    _trail_start_b = local_b;
                    trail_start_x = x;
                }
            }
        });
    });

    if let Some(log) = found_log.lock().unwrap().take() {
        let k_scalar = (log - params.beta) * params.alpha.invert().unwrap();
        if let Some(nonce) = scalar_to_i128(&k_scalar) {
            return Ok(Some(nonce));
        }
    }

    Ok(None)
}
