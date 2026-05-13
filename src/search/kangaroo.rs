//! Pollard's kangaroo (lambda) method for bounded-range discrete-log search.
//!
//! Designed for ranges where the discrete log is known to lie in a bounded
//! interval [a, a + N]. Expected runtime: O(sqrt(N)) group operations.

use crate::{
    context::ShutdownToken,
    error::Result,
    search::params::KangarooParams,
};
use k256::{
    elliptic_curve::sec1::ToEncodedPoint,
    AffinePoint, ProjectivePoint, Scalar,
};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Number of jump sizes for the pseudorandom walk.
const JUMP_COUNT: usize = 20;
/// Sentinel for "not found" in the atomic result.
const NOT_FOUND: u64 = u64::MAX;

/// A precomputed jump size for one partition of the walk.
struct JumpSize {
    distance: u64,
}

/// Parameters for a single kangaroo walk.
struct WalkParams {
    jump_sizes: Vec<JumpSize>,
    /// Precomputed `g * (alpha * step * distance)` for each jump size.
    jump_points: Vec<ProjectivePoint>,
    d: u32,
}

/// Run the Pollard's kangaroo search over the given [`KangarooParams`].
///
/// Returns the nonce index if found, or `None` if the target is not in range.
pub fn search(
    pool: &rayon::ThreadPool,
    thread_count: usize,
    shutdown: &ShutdownToken,
    params: &KangarooParams,
) -> Result<Option<i128>> {
    // Degenerate case: alpha == 0 means all candidates have the same discrete log.
    if params.alpha == Scalar::ZERO {
        let d0_scalar = crate::crypto::derive_private_key(params.start, params.alpha, params.beta);
        let d0_point = ProjectivePoint::GENERATOR * d0_scalar;
        if d0_point == params.h {
            return Ok(Some(params.start));
        }
        return Ok(None);
    }

    let total_f64 = params.total as f64;
    let avg_jump = (total_f64.sqrt() / 2.0).max(1.0);

    // Generate random jump sizes uniformly in [1, sqrt(total)]
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let jump_sizes: Vec<JumpSize> = (0..JUMP_COUNT)
        .map(|_| JumpSize {
            distance: (avg_jump * 2.0 * rng.gen::<f64>()).max(1.0) as u64,
        })
        .collect();

    let step_scalar = params.alpha * Scalar::from(params.step.cast_unsigned());
    let jump_points: Vec<ProjectivePoint> = jump_sizes
        .iter()
        .map(|js| {
            let scalar = step_scalar * Scalar::from(js.distance);
            params.g * scalar
        })
        .collect();

    let walk = WalkParams {
        jump_sizes,
        jump_points,
        d: params.d,
    };

    // Tame distinguished point table: sharded by thread, each shard protected by RwLock
    let table: Arc<Vec<std::sync::RwLock<FxHashMap<[u8; 33], u64>>>> =
        Arc::new((0..thread_count).map(|_| std::sync::RwLock::new(FxHashMap::default())).collect());

    let result = Arc::new(AtomicU64::new(NOT_FOUND));
    let dp_count = Arc::new(AtomicU64::new(0));

    pool.install(|| {
        (0..thread_count).into_par_iter().for_each(|tid| {
            // Each thread runs one tame and one wild walk
            let mut tame_dist = 0u64;
            let mut tame = ProjectivePoint::GENERATOR
                * crate::crypto::derive_private_key(params.start, params.alpha, params.beta);

            let mut wild_dist = 0u64;
            let mut wild = params.h;

            let mut iterations = 0u64;
            let max_iter = params.max_iterations;

            'walk: loop {
                if shutdown.is_signalled()
                    || result.load(Ordering::SeqCst) != NOT_FOUND
                {
                    break;
                }

                if iterations >= max_iter {
                    break;
                }
                iterations += 1;

                // Advance tame kangaroo
                let (new_tame, jump) = kangaroo_step(tame, &walk);
                tame = new_tame;
                match tame_dist.checked_add(jump) {
                    Some(v) => tame_dist = v,
                    None => break 'walk,
                }

                // Store tame distinguished point
                let tame_affine = tame.to_affine();
                if is_distinguished(&tame_affine, walk.d) {
                    let key = crate::crypto::affine_key(&tame_affine);
                    {
                        let mut guard = table[tid].write().unwrap();
                        guard.insert(key, tame_dist);
                    }
                    let c = dp_count.fetch_add(1, Ordering::Relaxed);
                    if c > 0 && c % 10_000 == 9999 {
                        tracing::info!("Kangaroo progress: {} distinguished points", c + 1);
                    }
                }

                // Advance wild kangaroo
                let (new_wild, jump) = kangaroo_step(wild, &walk);
                wild = new_wild;
                match wild_dist.checked_add(jump) {
                    Some(v) => wild_dist = v,
                    None => break 'walk,
                }

                // Check wild distinguished point against tame table
                let wild_affine = wild.to_affine();
                if is_distinguished(&wild_affine, walk.d) {
                    let key = crate::crypto::affine_key(&wild_affine);
                    for shard in table.iter() {
                        let guard = shard.read().unwrap();
                        if let Some(&tame_d) = guard.get(&key) {
                            // Collision found: k = start + step * (tame_dist - wild_dist)
                            let delta = if tame_d >= wild_dist {
                                tame_d - wild_dist
                            } else {
                                // This shouldn't happen for a valid collision, but handle gracefully
                                continue;
                            };
                            let candidate = params.start + params.step * delta as i128;
                            // Verify candidate is in range
                            let idx = (candidate - params.start) / params.step;
                            if idx >= 0 && (idx as u128) < params.total {
                                let _ = result.compare_exchange(
                                    NOT_FOUND,
                                    delta,
                                    Ordering::SeqCst,
                                    Ordering::Relaxed,
                                );
                                break 'walk;
                            }
                        }
                    }
                    let c = dp_count.fetch_add(1, Ordering::Relaxed);
                    if c > 0 && c % 10_000 == 9999 {
                        tracing::info!("Kangaroo progress: {} distinguished points", c + 1);
                    }
                }
            }
        });
    });

    let val = result.load(Ordering::SeqCst);
    if val == NOT_FOUND {
        Ok(None)
    } else {
        let candidate = params.start + params.step * (val as i128);
        Ok(Some(candidate))
    }
}

fn kangaroo_step(point: ProjectivePoint, walk: &WalkParams) -> (ProjectivePoint, u64) {
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    let hash = u64::from_le_bytes([
        bytes[1], bytes[2], bytes[3], bytes[4],
        bytes[5], bytes[6], bytes[7], bytes[8],
    ]);
    let idx = (hash as usize) % walk.jump_sizes.len();
    let jump = walk.jump_sizes[idx].distance;
    (point + walk.jump_points[idx], jump)
}

fn is_distinguished(point: &AffinePoint, d: u32) -> bool {
    let encoded = point.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    let full_bytes = (d / 8) as usize;
    let rem_bits = (d % 8) as usize;

    for i in 0..full_bytes {
        if bytes[1 + i] != 0 {
            return false;
        }
    }

    if rem_bits > 0 {
        let mask = 0xFFu8 << (8 - rem_bits);
        if (bytes[1 + full_bytes] & mask) != 0 {
            return false;
        }
    }

    true
}
