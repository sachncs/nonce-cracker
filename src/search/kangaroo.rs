//! Pollard's kangaroo (lambda) method for bounded-range discrete-log search.
//!
//! Designed for ranges where the discrete log is known to lie in a bounded
//! interval [a, a + N]. Expected runtime: O(sqrt(N)) group operations.

use crate::{context::ShutdownToken, error::Result, search::params::KangarooParams};
use k256::{ProjectivePoint, Scalar};
use rand::{Rng, SeedableRng};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Sharded distinguished-point table: one RwLock-protected FxHashMap per thread.
type DpTable = Arc<Vec<std::sync::RwLock<FxHashMap<[u8; 33], u64>>>>;

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
    params.validate()?;

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

    // Deterministic seed derived from search parameters so walks are reproducible.
    let seed = {
        let mut s = [0u8; 32];
        let alpha_bytes = params.alpha.to_bytes();
        let beta_bytes = params.beta.to_bytes();
        for i in 0..32 {
            s[i] = alpha_bytes[i] ^ beta_bytes[i];
        }
        let start_bytes = params.start.to_le_bytes();
        let step_bytes = params.step.to_le_bytes();
        for (i, b) in start_bytes.iter().enumerate() {
            s[i % 32] ^= *b;
        }
        for (i, b) in step_bytes.iter().enumerate() {
            s[(i + 8) % 32] ^= *b;
        }
        s
    };
    let mut rng = rand::rngs::StdRng::from_seed(seed);
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
    let table: DpTable = Arc::new(
        (0..thread_count)
            .map(|_| std::sync::RwLock::new(FxHashMap::default()))
            .collect(),
    );

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
                if shutdown.is_signalled() || result.load(Ordering::SeqCst) != NOT_FOUND {
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
                    None => {
                        tracing::warn!("tame kangaroo distance overflow; aborting thread");
                        break 'walk;
                    }
                }

                // Store tame distinguished point (only convert to affine here)
                if is_distinguished(&tame, walk.d) {
                    let tame_key = crate::crypto::affine_key(&tame.to_affine());
                    {
                        let mut guard = table[tid]
                            .write()
                            .unwrap_or_else(|e| e.into_inner());
                        guard.insert(tame_key, tame_dist);
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
                    None => {
                        tracing::warn!("wild kangaroo distance overflow; aborting thread");
                        break 'walk;
                    }
                }

                // Check wild distinguished point against tame table
                if is_distinguished(&wild, walk.d) {
                    let wild_key = crate::crypto::affine_key(&wild.to_affine());
                    for shard in table.iter() {
                        let guard = shard.read().unwrap_or_else(|e| e.into_inner());
                        if let Some(&tame_d) = guard.get(&wild_key) {
                            // Collision found: compute candidate and verify it
                            let delta = tame_d.abs_diff(wild_dist);
                            let delta_i128 = delta as i128;
                            let Some(step_delta) = params.step.checked_mul(delta_i128) else {
                                tracing::warn!("kangaroo step*delta overflow; skipping collision");
                                continue;
                            };
                            let Some(candidate) = params.start.checked_add(step_delta) else {
                                tracing::warn!("kangaroo start+step_delta overflow; skipping collision");
                                continue;
                            };
                            // Verify candidate is in range
                            let idx = (candidate - params.start) / params.step;
                            if idx >= 0 && (idx as u128) < params.total {
                                let verify_point = ProjectivePoint::GENERATOR
                                    * crate::crypto::derive_private_key(
                                        candidate, params.alpha, params.beta,
                                    );
                                if verify_point == params.h {
                                    if result
                                        .compare_exchange(
                                            NOT_FOUND,
                                            delta,
                                            Ordering::SeqCst,
                                            Ordering::Relaxed,
                                        )
                                        .is_ok()
                                    {
                                        break 'walk;
                                    }
                                    // Another thread already found a result; stop anyway.
                                    break 'walk;
                                }
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
        let delta_i128 = val as i128;
        let candidate = params
            .start
            .checked_add(
                params
                    .step
                    .checked_mul(delta_i128)
                    .ok_or(crate::error::RangeError::RangeOverflow)?,
            )
            .ok_or(crate::error::RangeError::RangeOverflow)?;
        Ok(Some(candidate))
    }
}

fn kangaroo_step(point: ProjectivePoint, walk: &WalkParams) -> (ProjectivePoint, u64) {
    let idx = projective_partition_index(&point) % walk.jump_sizes.len();
    let jump = walk.jump_sizes[idx].distance;
    (point + walk.jump_points[idx], jump)
}

/// Derive a partition index from projective coordinates without affine conversion.
///
/// Uses the X/Z ratio: if Z == 0 (identity), returns 0.  Otherwise XORs the
/// first 8 bytes of X and Z.  This is statistically uniform enough for the
/// kangaroo jump partitioning.
fn projective_partition_index(point: &ProjectivePoint) -> usize {
    let x_bytes = point.projective_x().to_bytes();
    let z_bytes = point.projective_z().to_bytes();
    if z_bytes.iter().all(|b| *b == 0) {
        return 0;
    }
    let hash = u64::from_le_bytes([
        x_bytes[0] ^ z_bytes[0],
        x_bytes[1] ^ z_bytes[1],
        x_bytes[2] ^ z_bytes[2],
        x_bytes[3] ^ z_bytes[3],
        x_bytes[4] ^ z_bytes[4],
        x_bytes[5] ^ z_bytes[5],
        x_bytes[6] ^ z_bytes[6],
        x_bytes[7] ^ z_bytes[7],
    ]);
    hash as usize
}

fn is_distinguished(point: &ProjectivePoint, d: u32) -> bool {
    let key = crate::crypto::affine_key(&point.to_affine());
    is_distinguished_from_key(&key, d)
}

fn is_distinguished_from_key(key: &[u8; 33], d: u32) -> bool {
    let full_bytes = (d / 8) as usize;
    let rem_bits = (d % 8) as usize;

    for i in 0..full_bytes {
        if key[1 + i] != 0 {
            return false;
        }
    }

    if rem_bits > 0 {
        let mask = 0xFFu8 << (8 - rem_bits);
        if (key[1 + full_bytes] & mask) != 0 {
            return false;
        }
    }

    true
}
