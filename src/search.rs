use crate::{crypto::affine_key, crypto::derive_private_key, Error, Result};
use k256::{elliptic_curve::BatchNormalize, AffinePoint, ProjectivePoint, PublicKey, Scalar};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

pub const BSGS_THRESHOLD: u128 = 1 << 32;
const BSGS_MAX_M: u64 = 1 << 26;
const IDENTITY_KEY: [u8; 33] = [0u8; 33];
const BATCH: u64 = 4096;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Check whether a shutdown signal has been received.
pub fn shutdown() -> bool {
    SHUTDOWN.load(Ordering::Relaxed)
}

/// Store the shutdown flag. Called by the signal handler in `main`.
pub fn set_shutdown() {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// High-speed parallel scan for ranges with at most `BSGS_THRESHOLD` candidates.
///
/// Each thread processes a contiguous chunk of the delta range, evaluating
/// `d(delta) = alpha * delta + beta` and comparing the resulting public key
/// against the target using projective point equality (no field inversion).
#[allow(clippy::too_many_arguments)]
pub fn parallel_scan(
    target: PublicKey,
    start: i64,
    step: i64,
    total: u128,
    thread_count: usize,
    alpha: Scalar,
    beta: Scalar,
    step_point: ProjectivePoint,
) -> Result<Option<i64>> {
    let target_affine: AffinePoint = *target.as_affine();
    let chunk: u128 = total.div_ceil(thread_count as u128);
    let not_found = i64::MAX;
    let result = Arc::new(std::sync::atomic::AtomicI64::new(not_found));

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .map_err(|e| Error(format!("thread pool: {e}")))?;

    const INNER_BATCH: u128 = 1024;

    pool.install(|| {
        (0..thread_count).into_par_iter().for_each(|thread_id| {
            if shutdown() {
                return;
            }
            let chunk_start = thread_id as u128 * chunk;
            if chunk_start >= total {
                return;
            }
            let count = chunk.min(total - chunk_start);

            let start_delta = start as i128 + chunk_start as i128 * step as i128;
            let mut d0 = match i64::try_from(start_delta) {
                Ok(v) => v,
                Err(_) => return,
            };
            let mut point = ProjectivePoint::GENERATOR * derive_private_key(d0, alpha, beta);

            let mut i = 0u128;
            while i < count {
                if shutdown() || result.load(Ordering::Acquire) != not_found {
                    break;
                }
                let batch_end = (i + INNER_BATCH).min(count);
                let mut found = false;
                for _ in i..batch_end {
                    if point == target_affine {
                        let _ = result.compare_exchange(
                            not_found,
                            d0,
                            Ordering::SeqCst,
                            Ordering::Relaxed,
                        );
                        found = true;
                        break;
                    }
                    point += step_point;
                    d0 = d0.wrapping_add(step);
                }
                i = batch_end;
                if found {
                    break;
                }
            }
        });
    });

    let found = result.load(Ordering::SeqCst);
    if found != not_found {
        Ok(Some(found))
    } else {
        Ok(None)
    }
}

/// Baby-Step Giant-Step (BSGS) search with automatic segmentation for very
/// large ranges.
///
/// * Standard BSGS (`m <= BSGS_MAX_M`): builds one hash table of `m` baby
///   steps and scans `m` giant steps.  Time `O(sqrt(N))`, space `O(sqrt(N))`.
/// * Segmented BSGS (`m > BSGS_MAX_M`): splits baby steps into fixed-size
///   segments (each <= `BSGS_MAX_M` entries).  For each segment the full set
///   of giant steps is evaluated.  Time `O(N / BSGS_MAX_M * sqrt(N))`, space
///   `O(BSGS_MAX_M)`.
///
/// `total` must fit in `u128` (guaranteed by the caller).
#[allow(clippy::too_many_arguments)]
pub fn bsgs(
    target: PublicKey,
    start: i64,
    step: i64,
    total: u128,
    thread_count: usize,
    alpha: Scalar,
    beta: Scalar,
    step_point: ProjectivePoint,
) -> Result<Option<i64>> {
    let target_affine: AffinePoint = *target.as_affine();
    let d0_scalar = derive_private_key(start, alpha, beta);
    let d0_point = ProjectivePoint::GENERATOR * d0_scalar;

    if d0_point == target_affine {
        return Ok(Some(start));
    }

    let mut t: ProjectivePoint = target_affine.into();
    t -= d0_point;

    // Compute m = ceil(sqrt(total)) as u128.
    let mut m = (total as f64).sqrt().ceil() as u128;
    if m == 0 {
        m = 1;
    }
    while m * m < total {
        m += 1;
    }
    while m > 1 && (m - 1) * (m - 1) >= total {
        m -= 1;
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .map_err(|e| Error(format!("thread pool: {e}")))?;

    if m <= BSGS_MAX_M as u128 {
        // Standard in-memory BSGS.
        let m_u64 = m as u64;
        let baby_map = pool.install(|| build_baby_steps(m_u64, step_point, thread_count));
        run_giant_steps(
            t,
            m_u64,
            total,
            thread_count,
            step_point,
            start,
            step,
            &baby_map,
            &pool,
        )
    } else {
        // Segmented BSGS: process baby steps in chunks to stay within RAM.
        let segment_size = BSGS_MAX_M as u128;
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
            if shutdown() || result.load(Ordering::Acquire) != u64::MAX {
                break;
            }

            let seg_start = seg * segment_size;
            let seg_end = ((seg + 1) * segment_size).min(m);
            let seg_len = (seg_end - seg_start) as u64;

            if seg_len == 0 {
                continue;
            }

            // Build baby-step table for this segment.
            let baby_map = pool
                .install(|| build_baby_steps_segment(seg_start, seg_len, step_point, thread_count));

            // Run all giant steps against this segment.
            let found = run_giant_steps(
                t,
                m as u64,
                total,
                thread_count,
                step_point,
                start,
                step,
                &baby_map,
                &pool,
            )?;

            if found.is_some() {
                return Ok(found);
            }

            // Progress logging every segment (and at 25/50/75%).
            let pct = ((seg + 1) as f64 / num_segments as f64) * 100.0;
            if seg % 4 == 3 || seg + 1 == num_segments {
                info!(
                    segment = seg + 1,
                    total_segments = num_segments,
                    pct = format!("{pct:.1}"),
                    "BSGS progress"
                );
            }
        }

        Ok(None)
    }
}

/// Giant-step phase shared by standard and segmented BSGS.
///
/// Splits the `m` giant steps across worker threads and checks each batch
/// against the supplied `baby_map`.
fn run_giant_steps(
    t: ProjectivePoint,
    m: u64,
    total: u128,
    thread_count: usize,
    step_point: ProjectivePoint,
    start: i64,
    step: i64,
    baby_map: &FxHashMap<[u8; 33], u128>,
    pool: &rayon::ThreadPool,
) -> Result<Option<i64>> {
    let m_scalar = Scalar::from(m);
    let m_step = step_point * m_scalar;

    let result = Arc::new(AtomicU64::new(u64::MAX));

    pool.install(|| {
        (0..thread_count).into_par_iter().for_each(|tid| {
            if shutdown() || result.load(Ordering::Acquire) != u64::MAX {
                return;
            }
            let chunk_start = tid as u128 * m as u128 / thread_count as u128;
            let chunk_end = ((tid + 1) as u128 * m as u128 / thread_count as u128).min(m as u128);
            if chunk_start >= chunk_end {
                return;
            }

            let chunk_start_u64 = chunk_start as u64;
            let chunk_end_u64 = chunk_end as u64;
            let coeff = chunk_start_u64 as u128 * m as u128;
            let offset = step_point * Scalar::from(coeff as u64);
            let mut giant = t - offset;

            let mut i = chunk_start_u64;
            while i < chunk_end_u64 {
                if shutdown() || result.load(Ordering::Acquire) != u64::MAX {
                    break;
                }
                let batch_end = (i + BATCH).min(chunk_end_u64);
                let mut entries: Vec<(u64, ProjectivePoint)> =
                    Vec::with_capacity((batch_end - i) as usize);
                let mut current = giant;
                for idx in 0..(batch_end - i) {
                    if current == ProjectivePoint::IDENTITY {
                        if let Some(&j) = baby_map.get(&IDENTITY_KEY) {
                            let k = (i as u128 + idx as u128) * m as u128 + j;
                            if k < total {
                                let _ = result.compare_exchange(
                                    u64::MAX,
                                    1,
                                    Ordering::SeqCst,
                                    Ordering::Relaxed,
                                );
                                return;
                            }
                        }
                        current -= m_step;
                        continue;
                    }
                    entries.push((idx, current));
                    current -= m_step;
                }

                if !entries.is_empty() {
                    let points: Vec<ProjectivePoint> = entries.iter().map(|(_, p)| *p).collect();
                    let affines: Vec<AffinePoint> =
                        ProjectivePoint::batch_normalize(points.as_slice());
                    for (affine_idx, affine) in affines.iter().enumerate() {
                        let idx = entries[affine_idx].0;
                        let key = affine_key(affine);
                        if let Some(&j) = baby_map.get(&key) {
                            let k = (i as u128 + idx as u128) * m as u128 + j;
                            if k < total {
                                let _ = result.compare_exchange(
                                    u64::MAX,
                                    1,
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

    let did_find = result.load(Ordering::SeqCst) != u64::MAX;
    if did_find {
        // Reconstruct the exact k by iterating over segments again.
        // In practice we do a second pass only over giant steps, but for
        // simplicity we scan the same giant-step space sequentially until we
        // hit the match.
        warn!("BSGS match detected; reconstructing exact delta");
        for k in 0..m {
            if shutdown() {
                break;
            }
            let point = t - step_point * Scalar::from(k * m);
            if point == ProjectivePoint::IDENTITY {
                if let Some(&j) = baby_map.get(&IDENTITY_KEY) {
                    let candidate = k as u128 * m as u128 + j;
                    if candidate < total {
                        let delta_i128 = start as i128 + candidate as i128 * step as i128;
                        if let Ok(delta) = i64::try_from(delta_i128) {
                            return Ok(Some(delta));
                        }
                    }
                }
            } else {
                let enc = affine_key(&point.to_affine());
                if let Some(&j) = baby_map.get(&enc) {
                    let candidate = k as u128 * m as u128 + j;
                    if candidate < total {
                        let delta_i128 = start as i128 + candidate as i128 * step as i128;
                        if let Ok(delta) = i64::try_from(delta_i128) {
                            return Ok(Some(delta));
                        }
                    }
                }
            }
        }
        // Should never reach here if the parallel phase signalled a match.
        Ok(None)
    } else {
        Ok(None)
    }
}

/// Build the full baby-step table for standard BSGS (`m <= BSGS_MAX_M`).
fn build_baby_steps(
    m: u64,
    step_point: ProjectivePoint,
    thread_count: usize,
) -> FxHashMap<[u8; 33], u128> {
    let maps: Vec<FxHashMap<[u8; 33], u128>> = (0..thread_count)
        .into_par_iter()
        .map(|tid| {
            let start_j = tid as u64 * m / thread_count as u64;
            let end_j = ((tid + 1) as u64 * m / thread_count as u64).min(m);
            if start_j >= end_j {
                return FxHashMap::default();
            }
            let mut map =
                FxHashMap::with_capacity_and_hasher((end_j - start_j) as usize, Default::default());

            if start_j == 0 {
                map.insert(IDENTITY_KEY, 0);
            }

            let mut j = if start_j == 0 { 1 } else { start_j };
            let mut current = step_point * Scalar::from(j);
            let mut points = Vec::with_capacity(BATCH as usize);

            while j < end_j {
                let batch_end = (j + BATCH).min(end_j);
                let batch_size = (batch_end - j) as usize;
                points.clear();
                points.reserve(batch_size);

                for _ in 0..batch_size {
                    points.push(current);
                    current += step_point;
                }

                let affines: Vec<AffinePoint> = ProjectivePoint::batch_normalize(points.as_slice());

                for (idx, affine) in affines.iter().enumerate() {
                    let key = affine_key(affine);
                    map.insert(key, j as u128 + idx as u128);
                }

                j = batch_end;
            }
            map
        })
        .collect();

    let mut merged = FxHashMap::with_capacity_and_hasher(m as usize, Default::default());
    for map in maps {
        merged.extend(map);
    }
    merged
}

/// Build a baby-step table for a single segment in segmented BSGS.
fn build_baby_steps_segment(
    seg_start: u128,
    seg_len: u64,
    step_point: ProjectivePoint,
    thread_count: usize,
) -> FxHashMap<[u8; 33], u128> {
    let maps: Vec<FxHashMap<[u8; 33], u128>> = (0..thread_count)
        .into_par_iter()
        .map(|tid| {
            let start_j = tid as u128 * seg_len as u128 / thread_count as u128;
            let end_j =
                ((tid + 1) as u128 * seg_len as u128 / thread_count as u128).min(seg_len as u128);
            if start_j >= end_j {
                return FxHashMap::default();
            }
            let mut map =
                FxHashMap::with_capacity_and_hasher((end_j - start_j) as usize, Default::default());

            let abs_start = seg_start + start_j;
            let abs_end = seg_start + end_j;
            let mut j = abs_start;
            let mut current = step_point * Scalar::from(j as u64);
            let mut points = Vec::with_capacity(BATCH as usize);

            while j < abs_end {
                let batch_end = (j + BATCH as u128).min(abs_end);
                let batch_size = (batch_end - j) as usize;
                points.clear();
                points.reserve(batch_size);

                for _ in 0..batch_size {
                    points.push(current);
                    current += step_point;
                }

                let affines: Vec<AffinePoint> = ProjectivePoint::batch_normalize(points.as_slice());

                for (idx, affine) in affines.iter().enumerate() {
                    let key = affine_key(affine);
                    map.insert(key, j + idx as u128);
                }

                j = batch_end;
            }
            map
        })
        .collect();

    let mut merged = FxHashMap::with_capacity_and_hasher(seg_len as usize, Default::default());
    for map in maps {
        merged.extend(map);
    }
    merged
}
