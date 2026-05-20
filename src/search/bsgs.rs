//! Baby-Step Giant-Step (BSGS) discrete-log search.
//!
//! Implements the classic BSGS algorithm with batched point normalization
//! and parallel giant-step evaluation.

use crate::{
    context::ShutdownToken,
    crypto::affine_key_prefix,
    error::{EngineError, Result},
    search::openmap::OpenMap,
    search::params::{GiantStepParams, ScanParams},
};
use k256::{elliptic_curve::BatchNormalize, AffinePoint, ProjectivePoint, Scalar};
use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Maximum baby-step table size (in entries) to prevent unbounded memory use.
///
/// At `2^28` entries the compact OpenMap consumes roughly 6 GB.
pub const BSGS_MAX_M: u64 = 1 << 28;
/// 128-bit prefix of the identity point encoding, used as a sentinel key.
///
/// On secp256k1 (prime order), the identity point encodes as `0x02` + 32 zero
/// bytes.  The first 16 bytes are `0x02` followed by 15 zero bytes.
///
/// # Safety invariant
///
/// This sentinel is only correct because secp256k1 has prime order, so the
/// identity point has a unique compressed encoding.  On a curve with a cofactor
/// the identity could have multiple representations and this assumption would
/// break.
const IDENTITY_KEY: u128 = 0x02000000000000000000000000000000u128;
/// Number of giant-step points processed in one batch-normalize call.
const BATCH: u64 = 8192;
/// Approximate size of one compact OpenMap entry in bytes (key + value + state + padding).
const OPENMAP_ENTRY_BYTES: u64 = 24;

/// Run the Baby-Step Giant-Step search over the given [`ScanParams`].
///
/// Returns the nonce index if found, or `None` if the target is not in range.
/// Returns an error if the required baby-step table would exceed the
/// configured memory guard.
pub fn search(
    pool: &rayon::ThreadPool,
    thread_count: usize,
    shutdown: &ShutdownToken,
    scan: &ScanParams,
) -> Result<Option<i128>> {
    debug_assert_eq!(affine_key_prefix(&AffinePoint::IDENTITY), IDENTITY_KEY,
        "IDENTITY_KEY sentinel must match AffinePoint::IDENTITY encoding");

    let target_affine: AffinePoint = *scan.target.as_affine();
    let d0_scalar = crate::crypto::derive_private_key(scan.start, scan.alpha, scan.beta);
    let d0_point = ProjectivePoint::GENERATOR * d0_scalar;

    if d0_point == target_affine {
        return Ok(Some(scan.start));
    }

    let mut t: ProjectivePoint = target_affine.into();
    t -= d0_point;

    let mut m = scan.total.isqrt();
    if m * m < scan.total {
        m += 1;
    }
    if m == 0 {
        m = 1;
    }

    if m > u128::from(BSGS_MAX_M) {
        return Err(EngineError::BsgsMemoryLimit.into());
    }

    let m_u64 = u64::try_from(m).map_err(|_| EngineError::BsgsMOverflow)?;

    // Expected peak memory: per-thread OpenMaps at 0.7 load factor.
    // Entry size is ~24 bytes.  Cap at ~8 GB to prevent OOM on typical machines.
    const BSGS_MEMORY_LIMIT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
    let per_thread_cap = ((m_u64 as f64 / thread_count as f64 / 0.7).ceil() as u64)
        .next_power_of_two();
    let expected_bytes = thread_count as u64 * per_thread_cap * OPENMAP_ENTRY_BYTES;
    if expected_bytes > BSGS_MEMORY_LIMIT_BYTES {
        return Err(EngineError::BsgsMemoryLimit.into());
    }

    let baby_maps = pool.install(|| build_baby_steps(0, m_u64, scan.step_point, thread_count));
    let m_step = scan.step_point * Scalar::from(m_u64);
    let params = GiantStepParams {
        t,
        m: m_u64,
        m_step,
        total: scan.total,
        thread_count,
        step_point: scan.step_point,
        start: scan.start,
        step: scan.step,
        baby_maps: &baby_maps,
        pool,
        shutdown,
    };
    Ok(run_giant_steps(&params).and_then(|k| reconstruct_nonce(&params, k)))
}

fn run_giant_steps(p: &GiantStepParams<'_>) -> Option<u64> {
    let result = Arc::new(AtomicU64::new(u64::MAX));

    p.pool.install(|| {
        (0..p.thread_count).into_par_iter().for_each(|tid| {
            if p.shutdown.is_signalled() || result.load(Ordering::SeqCst) != u64::MAX {
                return;
            }
            let chunk_start = tid as u128 * u128::from(p.m) / p.thread_count as u128;
            let chunk_end =
                ((tid + 1) as u128 * u128::from(p.m) / p.thread_count as u128).min(u128::from(p.m));
            if chunk_start >= chunk_end {
                return;
            }

            let Ok(chunk_start_u64) = u64::try_from(chunk_start) else {
                tracing::warn!("BSGS chunk_start overflow; skipping thread");
                return;
            };
            let Ok(chunk_end_u64) = u64::try_from(chunk_end) else {
                tracing::warn!("BSGS chunk_end overflow; skipping thread");
                return;
            };
            // Compute step_point * m * chunk_start via two scalar muls to avoid
            // u128/u64 overflow of the intermediate product.
            let offset = p.m_step * Scalar::from(chunk_start_u64);
            let mut giant = p.t - offset;

            let mut i = chunk_start_u64;
            while i < chunk_end_u64 {
                if p.shutdown.is_signalled() || result.load(Ordering::SeqCst) != u64::MAX {
                    break;
                }
                let batch_end = (i + BATCH).min(chunk_end_u64);
                let batch_size = usize::try_from(batch_end - i).expect("BATCH fits in usize");
                let mut points: Vec<ProjectivePoint> = Vec::with_capacity(batch_size);
                let mut indices: Vec<u64> = Vec::with_capacity(batch_size);
                let mut current = giant;
                for idx in 0..(batch_end - i) {
                    if current == ProjectivePoint::IDENTITY {
                        if let Some(j) = lookup_in_shards(p.baby_maps, IDENTITY_KEY) {
                            let k = (u128::from(i) + u128::from(idx)) * u128::from(p.m) + u128::from(j);
                            if k < p.total {
                                let _ = result.compare_exchange(
                                    u64::MAX,
                                    i + idx,
                                    Ordering::SeqCst,
                                    Ordering::Relaxed,
                                );
                                // Another thread may have already stored a result.
                                return;
                            }
                        }
                        current -= p.m_step;
                        continue;
                    }
                    points.push(current);
                    indices.push(idx);
                    current -= p.m_step;
                }

                if !points.is_empty() {
                    let affines: Vec<AffinePoint> =
                        ProjectivePoint::batch_normalize(points.as_slice());
                    for (affine_idx, affine) in affines.iter().enumerate() {
                        let idx = indices[affine_idx];
                        let key = affine_key_prefix(affine);
                        if let Some(j) = lookup_in_shards(p.baby_maps, key) {
                            let k = (u128::from(i) + u128::from(idx)) * u128::from(p.m) + u128::from(j);
                            if k < p.total {
                                let _ = result.compare_exchange(
                                    u64::MAX,
                                    i + idx,
                                    Ordering::SeqCst,
                                    Ordering::Relaxed,
                                );
                                // Another thread may have already stored a result.
                                return;
                            }
                        }
                    }
                }

                giant = current;
                i = batch_end;
            }
        });
    });

    let val = result.load(Ordering::SeqCst);
    if val == u64::MAX {
        None
    } else {
        Some(val)
    }
}

fn reconstruct_nonce(p: &GiantStepParams<'_>, k_giant: u64) -> Option<i128> {
    let km = u128::from(k_giant) * u128::from(p.m);
    let point = p.t - p.step_point * Scalar::from(km);
    let key = if point == ProjectivePoint::IDENTITY {
        IDENTITY_KEY
    } else {
        affine_key_prefix(&point.to_affine())
    };
    if let Some(j) = lookup_in_shards(p.baby_maps, key) {
        let candidate = km + u128::from(j);
        if candidate < p.total {
            let Ok(candidate_i128) = i128::try_from(candidate) else {
                tracing::warn!("BSGS candidate exceeds i128 range; skipping valid match");
                return None;
            };
            return p.start.checked_add(candidate_i128.checked_mul(p.step)?);
        }
    }
    None
}

/// Look up a key across all sharded baby-step tables.
#[inline]
fn lookup_in_shards(baby_maps: &[OpenMap], key: u128) -> Option<u64> {
    for map in baby_maps {
        if let Some(&value) = map.get(key) {
            return Some(value);
        }
    }
    None
}

fn build_baby_steps(
    start: u128,
    len: u64,
    step_point: ProjectivePoint,
    thread_count: usize,
) -> Vec<OpenMap> {
    let maps: Vec<OpenMap> = (0..thread_count)
        .into_par_iter()
        .map(|tid| {
            let start_j = tid as u128 * u128::from(len) / thread_count as u128;
            let end_j =
                ((tid + 1) as u128 * u128::from(len) / thread_count as u128).min(u128::from(len));
            if start_j >= end_j {
                return OpenMap::with_capacity(0);
            }
            let map_len = usize::try_from(end_j - start_j).expect("batch fits in usize");
            let mut map = OpenMap::with_capacity(map_len);

            let abs_start = start + start_j;
            let abs_end = start + end_j;

            if abs_start == 0 {
                map.insert(IDENTITY_KEY, 0);
            }

            let mut j = if abs_start == 0 { 1 } else { abs_start };
            let mut current = step_point * Scalar::from(j);
            let mut points =
                Vec::with_capacity(usize::try_from(BATCH).expect("BATCH fits in usize"));

            while j < abs_end {
                let batch_end = (j + u128::from(BATCH)).min(abs_end);
                let batch_size = usize::try_from(batch_end - j).expect("batch fits in usize");
                points.clear();

                for _ in 0..batch_size {
                    if current == ProjectivePoint::IDENTITY {
                        points.push(ProjectivePoint::IDENTITY);
                    } else {
                        points.push(current);
                    }
                    current += step_point;
                }

                let affines: Vec<AffinePoint> = ProjectivePoint::batch_normalize(points.as_slice());

                for (idx, affine) in affines.iter().enumerate() {
                    let key = affine_key_prefix(affine);
                    let inserted = u64::try_from(j + u128::try_from(idx).expect("idx fits in u128"))
                        .expect("inserted fits in u64");
                    map.insert(key, inserted);
                }

                j = batch_end;
            }
            map
        })
        .collect();

    maps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_key_matches_affine_identity() {
        // Verify the sentinel key matches k256's actual identity encoding.
        // This assumption relies on secp256k1 being prime-order.
        assert_eq!(affine_key_prefix(&AffinePoint::IDENTITY), IDENTITY_KEY);
    }
}
