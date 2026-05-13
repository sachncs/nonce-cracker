//! Baby-Step Giant-Step (BSGS) discrete-log search.
//!
//! Implements the classic BSGS algorithm with batched point normalization,
//! parallel giant-step evaluation, and segmented operation for ranges that
//! would otherwise require excessive memory for the baby-step table.

use crate::{
    context::ShutdownToken,
    crypto::affine_key,
    error::{EngineError, Result},
    search::openmap::OpenMap,
    search::params::{GiantStepParams, ScanParams},
};
use k256::{elliptic_curve::BatchNormalize, AffinePoint, ProjectivePoint, Scalar};
use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::info;

/// Maximum baby-step table size (in entries) to prevent unbounded memory use.
///
/// At `2^27` entries the OpenMap consumes roughly 10 GB.
pub const BSGS_MAX_M: u64 = 1 << 27;
/// Compressed encoding of the identity point, used as a sentinel key.
const IDENTITY_KEY: [u8; 33] = [0u8; 33];
/// Number of giant-step points processed in one batch-normalize call.
const BATCH: u64 = 8192;

/// Run the Baby-Step Giant-Step search over the given [`ScanParams`].
///
/// Automatically selects the standard in-memory BSGS when `m <= bsgs_max_m`,
/// or falls back to a segmented (disk-friendly) approach for larger ranges.
///
/// Returns the nonce index if found, or `None` if the target is not in range.
pub fn search(
    pool: &rayon::ThreadPool,
    thread_count: usize,
    shutdown: &ShutdownToken,
    bsgs_max_m: u64,
    scan: &ScanParams,
) -> Result<Option<i128>> {
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

    if m <= u128::from(bsgs_max_m) {
        let m_u64 = u64::try_from(m).map_err(|_| EngineError::BsgsMOverflow)?;
        let baby_map = pool.install(|| build_baby_steps(0, m_u64, scan.step_point, thread_count));
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
            baby_map: &baby_map,
            pool,
            shutdown,
        };
        Ok(run_giant_steps(&params).and_then(|k| reconstruct_nonce(&params, k)))
    } else {
        let segment_size = u128::from(bsgs_max_m);
        let num_segments = m.div_ceil(segment_size);
        info!(
            bsgs_mode = "segmented",
            m = m,
            segments = num_segments,
            segment_size = segment_size,
            "starting segmented BSGS"
        );

        let result = Arc::new(AtomicU64::new(u64::MAX));

        for seg in 0..num_segments {
            if shutdown.is_signalled() || result.load(Ordering::SeqCst) != u64::MAX {
                break;
            }

            let seg_start = seg * segment_size;
            let seg_end = ((seg + 1) * segment_size).min(m);
            let seg_len =
                u64::try_from(seg_end - seg_start).map_err(|_| EngineError::BsgsSegmentOverflow)?;

            if seg_len == 0 {
                continue;
            }

            let baby_map = pool
                .install(|| build_baby_steps(seg_start, seg_len, scan.step_point, thread_count));

            let m_u64 = u64::try_from(m).map_err(|_| EngineError::BsgsMOverflow)?;
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
                baby_map: &baby_map,
                pool,
                shutdown,
            };
            let found = run_giant_steps(&params);

            if let Some(k) = found {
                return Ok(reconstruct_nonce(&params, k));
            }

            let pct_whole = (seg + 1) * 100 / num_segments;
            let pct_frac = ((seg + 1) * 1000 / num_segments) % 10;
            if seg % 4 == 3 || seg + 1 == num_segments {
                info!(
                    segment = seg + 1,
                    total_segments = num_segments,
                    pct = format!("{pct_whole}.{pct_frac}"),
                    "BSGS progress"
                );
            }
        }

        Ok(None)
    }
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

            let chunk_start_u64 = u64::try_from(chunk_start).expect("chunk_start fits in u64");
            let chunk_end_u64 = u64::try_from(chunk_end).expect("chunk_end fits in u64");
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
                        if let Some(&j) = p.baby_map.get(&IDENTITY_KEY) {
                            let k = (u128::from(i) + u128::from(idx)) * u128::from(p.m) + j;
                            if k < p.total {
                                let _ = result.compare_exchange(
                                    u64::MAX,
                                    i + idx,
                                    Ordering::SeqCst,
                                    Ordering::Relaxed,
                                );
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
                        let key = affine_key(affine);
                        if let Some(&j) = p.baby_map.get(&key) {
                            let k = (u128::from(i) + u128::from(idx)) * u128::from(p.m) + j;
                            if k < p.total {
                                let _ = result.compare_exchange(
                                    u64::MAX,
                                    i + idx,
                                    Ordering::SeqCst,
                                    Ordering::Relaxed,
                                );
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
    let lookup = if point == ProjectivePoint::IDENTITY {
        p.baby_map.get(&IDENTITY_KEY)
    } else {
        p.baby_map.get(&affine_key(&point.to_affine()))
    };
    if let Some(&j) = lookup {
        let candidate = km + j;
        if candidate < p.total {
            let Ok(candidate_i128) = i128::try_from(candidate) else {
                return None;
            };
            return Some(p.start + candidate_i128 * p.step);
        }
    }
    None
}

fn build_baby_steps(
    start: u128,
    len: u64,
    step_point: ProjectivePoint,
    thread_count: usize,
) -> OpenMap {
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
                    let key = affine_key(affine);
                    let inserted = j + u128::try_from(idx).expect("idx fits in u128");
                    map.insert(key, inserted);
                }

                j = batch_end;
            }
            map
        })
        .collect();

    let mut merged = OpenMap::with_capacity(usize::try_from(len).expect("len fits in usize"));
    for map in maps {
        for (key, value) in map {
            merged.insert(key, value);
        }
    }
    merged
}
