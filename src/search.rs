use crate::{crypto::affine_key, crypto::derive_private_key, Error, Result};
use k256::{elliptic_curve::BatchNormalize, AffinePoint, ProjectivePoint, PublicKey, Scalar};
use rayon::prelude::*;
use rustc_hash::{FxBuildHasher, FxHashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

pub const BSGS_THRESHOLD: u128 = 1 << 32;
const BSGS_MAX_M: u64 = 1 << 26;
const IDENTITY_KEY: [u8; 33] = [0u8; 33];
const BATCH: u64 = 4096;
const PARALLEL_BATCH: u128 = 1024;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Check whether a shutdown signal has been received.
pub fn shutdown() -> bool {
    SHUTDOWN.load(Ordering::Relaxed)
}

/// Store the shutdown flag. Called by the signal handler in `main`.
pub fn set_shutdown() {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Parameters shared by `parallel_scan` and `bsgs`.
pub struct ScanParams {
    pub target: PublicKey,
    pub start: i64,
    pub step: i64,
    pub total: u128,
    pub thread_count: usize,
    pub alpha: Scalar,
    pub beta: Scalar,
    pub step_point: ProjectivePoint,
}

/// High-speed parallel scan for ranges with at most `BSGS_THRESHOLD` candidates.
///
/// Each thread processes a contiguous chunk of the delta range, evaluating
/// `d(delta) = alpha * delta + beta` and comparing the resulting public key
/// against the target using projective point equality (no field inversion).
pub fn parallel_scan(scan: &ScanParams) -> Result<Option<i64>> {
    let target_affine: AffinePoint = *scan.target.as_affine();
    let chunk: u128 = scan.total.div_ceil(scan.thread_count as u128);
    let not_found = i64::MAX;
    let result = Arc::new(std::sync::atomic::AtomicI64::new(not_found));

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(scan.thread_count)
        .build()
        .map_err(|e| Error(format!("thread pool: {e}")))?;

    pool.install(|| {
        (0..scan.thread_count)
            .into_par_iter()
            .for_each(|thread_id| {
                if shutdown() {
                    return;
                }
                let chunk_start = thread_id as u128 * chunk;
                if chunk_start >= scan.total {
                    return;
                }
                let count = chunk.min(scan.total - chunk_start);

                let Ok(chunk_start_i128) = i128::try_from(chunk_start) else {
                    return;
                };
                let start_delta = i128::from(scan.start) + chunk_start_i128 * i128::from(scan.step);
                let Ok(mut d0) = i64::try_from(start_delta) else {
                    return;
                };
                let mut point =
                    ProjectivePoint::GENERATOR * derive_private_key(d0, scan.alpha, scan.beta);

                let mut i = 0u128;
                while i < count {
                    if shutdown() || result.load(Ordering::Acquire) != not_found {
                        break;
                    }
                    let batch_end = (i + PARALLEL_BATCH).min(count);
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
                        point += scan.step_point;
                        d0 = d0.wrapping_add(scan.step);
                    }
                    i = batch_end;
                    if found {
                        break;
                    }
                }
            });
    });

    let found = result.load(Ordering::SeqCst);
    if found == not_found {
        Ok(None)
    } else {
        Ok(Some(found))
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
pub fn bsgs(scan: &ScanParams) -> Result<Option<i64>> {
    let target_affine: AffinePoint = *scan.target.as_affine();
    let d0_scalar = derive_private_key(scan.start, scan.alpha, scan.beta);
    let d0_point = ProjectivePoint::GENERATOR * d0_scalar;

    if d0_point == target_affine {
        return Ok(Some(scan.start));
    }

    let mut t: ProjectivePoint = target_affine.into();
    t -= d0_point;

    // Compute m = ceil(sqrt(total)) as u128.
    let mut m = scan.total.isqrt();
    if m * m < scan.total {
        m += 1;
    }
    if m == 0 {
        m = 1;
    }
    while m > 1 && (m - 1) * (m - 1) >= scan.total {
        m -= 1;
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(scan.thread_count)
        .build()
        .map_err(|e| Error(format!("thread pool: {e}")))?;

    if m <= u128::from(BSGS_MAX_M) {
        // Standard in-memory BSGS.
        let m_u64 = u64::try_from(m).map_err(|_| Error("BSGS m overflow".into()))?;
        let baby_map = pool.install(|| build_baby_steps(m_u64, scan.step_point, scan.thread_count));
        let params = GiantStepParams {
            t,
            m: m_u64,
            total: scan.total,
            thread_count: scan.thread_count,
            step_point: scan.step_point,
            start: scan.start,
            step: scan.step,
            baby_map: &baby_map,
            pool: &pool,
        };
        Ok(run_giant_steps(&params))
    } else {
        // Segmented BSGS: process baby steps in chunks to stay within RAM.
        let segment_size = u128::from(BSGS_MAX_M);
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
            let seg_len = u64::try_from(seg_end - seg_start)
                .map_err(|_| Error("BSGS segment length overflow".into()))?;

            if seg_len == 0 {
                continue;
            }

            // Build baby-step table for this segment.
            let baby_map = pool.install(|| {
                build_baby_steps_segment(seg_start, seg_len, scan.step_point, scan.thread_count)
            });

            // Run all giant steps against this segment.
            let m_u64 = u64::try_from(m).map_err(|_| Error("BSGS m overflow".into()))?;
            let params = GiantStepParams {
                t,
                m: m_u64,
                total: scan.total,
                thread_count: scan.thread_count,
                step_point: scan.step_point,
                start: scan.start,
                step: scan.step,
                baby_map: &baby_map,
                pool: &pool,
            };
            let found = run_giant_steps(&params);

            if found.is_some() {
                return Ok(found);
            }

            // Progress logging every segment (and at 25/50/75%).
            let seg_f = u64::try_from(seg + 1).expect("segment index fits in u64") as f64;
            let total_f = u64::try_from(num_segments).expect("segment count fits in u64") as f64;
            let pct = seg_f / total_f * 100.0;
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

/// Parameters for the giant-step phase shared by standard and segmented BSGS.
struct GiantStepParams<'a> {
    t: ProjectivePoint,
    m: u64,
    total: u128,
    thread_count: usize,
    step_point: ProjectivePoint,
    start: i64,
    step: i64,
    baby_map: &'a FxHashMap<[u8; 33], u128>,
    pool: &'a rayon::ThreadPool,
}

/// Giant-step phase shared by standard and segmented BSGS.
///
/// Splits the `m` giant steps across worker threads and checks each batch
/// against the supplied `baby_map`.
fn run_giant_steps(p: &GiantStepParams<'_>) -> Option<i64> {
    let m_scalar = Scalar::from(p.m);
    let m_step = p.step_point * m_scalar;

    let result = Arc::new(AtomicU64::new(u64::MAX));

    p.pool.install(|| {
        (0..p.thread_count).into_par_iter().for_each(|tid| {
            if shutdown() || result.load(Ordering::Acquire) != u64::MAX {
                return;
            }
            let chunk_start = tid as u128 * u128::from(p.m) / p.thread_count as u128;
            let chunk_end =
                ((tid + 1) as u128 * u128::from(p.m) / p.thread_count as u128).min(u128::from(p.m));
            if chunk_start >= chunk_end {
                return;
            }

            let chunk_start_u64 =
                u64::try_from(chunk_start).expect("chunk_start < p.m fits in u64");
            let chunk_end_u64 = u64::try_from(chunk_end).expect("chunk_end <= p.m fits in u64");
            let coeff = u128::from(chunk_start_u64) * u128::from(p.m);
            let offset =
                p.step_point * Scalar::from(u64::try_from(coeff).expect("coeff fits in u64"));
            let mut giant = p.t - offset;

            let mut i = chunk_start_u64;
            while i < chunk_end_u64 {
                if shutdown() || result.load(Ordering::Acquire) != u64::MAX {
                    break;
                }
                let batch_end = (i + BATCH).min(chunk_end_u64);
                let batch_size = usize::try_from(batch_end - i).expect("BATCH fits in usize");
                let mut entries: Vec<(u64, ProjectivePoint)> = Vec::with_capacity(batch_size);
                let mut current = giant;
                for idx in 0..(batch_end - i) {
                    if current == ProjectivePoint::IDENTITY {
                        if let Some(&j) = p.baby_map.get(&IDENTITY_KEY) {
                            let k = (u128::from(i) + u128::from(idx)) * u128::from(p.m) + j;
                            if k < p.total {
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
                        if let Some(&j) = p.baby_map.get(&key) {
                            let k = (u128::from(i) + u128::from(idx)) * u128::from(p.m) + j;
                            if k < p.total {
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

    if result.load(Ordering::SeqCst) == u64::MAX {
        return None;
    }
    reconstruct_delta(p)
}

/// Reconstruct the exact delta after the parallel giant-step phase signals a
/// match.
fn reconstruct_delta(p: &GiantStepParams<'_>) -> Option<i64> {
    warn!("BSGS match detected; reconstructing exact delta");
    for k in 0..p.m {
        if shutdown() {
            break;
        }
        let km = u128::from(k) * u128::from(p.m);
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
                    continue;
                };
                let delta_i128 = i128::from(p.start) + candidate_i128 * i128::from(p.step);
                if let Ok(delta) = i64::try_from(delta_i128) {
                    return Some(delta);
                }
            }
        }
    }
    None
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
            let mut map = FxHashMap::with_capacity_and_hasher(
                usize::try_from(end_j - start_j).expect("batch fits in usize"),
                FxBuildHasher,
            );

            if start_j == 0 {
                map.insert(IDENTITY_KEY, 0);
            }

            let mut j = if start_j == 0 { 1 } else { start_j };
            let mut current = step_point * Scalar::from(j);
            let mut points =
                Vec::with_capacity(usize::try_from(BATCH).expect("BATCH fits in usize"));

            while j < end_j {
                let batch_end = (j + BATCH).min(end_j);
                let batch_size = usize::try_from(batch_end - j).expect("batch fits in usize");
                points.clear();
                points.reserve(batch_size);

                for _ in 0..batch_size {
                    points.push(current);
                    current += step_point;
                }

                let affines: Vec<AffinePoint> = ProjectivePoint::batch_normalize(points.as_slice());

                for (idx, affine) in affines.iter().enumerate() {
                    let key = affine_key(affine);
                    map.insert(
                        key,
                        u128::from(j) + u128::try_from(idx).expect("idx fits in u128"),
                    );
                }

                j = batch_end;
            }
            map
        })
        .collect();

    let mut merged = FxHashMap::with_capacity_and_hasher(
        usize::try_from(m).expect("m fits in usize"),
        FxBuildHasher,
    );
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
            let start_j = tid as u128 * u128::from(seg_len) / thread_count as u128;
            let end_j = ((tid + 1) as u128 * u128::from(seg_len) / thread_count as u128)
                .min(u128::from(seg_len));
            if start_j >= end_j {
                return FxHashMap::default();
            }
            let mut map = FxHashMap::with_capacity_and_hasher(
                usize::try_from(end_j - start_j).expect("batch fits in usize"),
                FxBuildHasher,
            );

            let abs_start = seg_start + start_j;
            let abs_end = seg_start + end_j;
            let mut j = abs_start;
            let mut current = step_point * Scalar::from(u64::try_from(j).expect("j fits in u64"));
            let mut points =
                Vec::with_capacity(usize::try_from(BATCH).expect("BATCH fits in usize"));

            while j < abs_end {
                let batch_end = (j + u128::from(BATCH)).min(abs_end);
                let batch_size = usize::try_from(batch_end - j).expect("batch fits in usize");
                points.clear();
                points.reserve(batch_size);

                for _ in 0..batch_size {
                    points.push(current);
                    current += step_point;
                }

                let affines: Vec<AffinePoint> = ProjectivePoint::batch_normalize(points.as_slice());

                for (idx, affine) in affines.iter().enumerate() {
                    let key = affine_key(affine);
                    map.insert(key, j + u128::try_from(idx).expect("idx fits in u128"));
                }

                j = batch_end;
            }
            map
        })
        .collect();

    let mut merged = FxHashMap::with_capacity_and_hasher(
        usize::try_from(seg_len).expect("seg_len fits in usize"),
        FxBuildHasher,
    );
    for map in maps {
        merged.extend(map);
    }
    merged
}
