//! Parallel search algorithms: parallel scan and Baby-Step Giant-Step (BSGS).
//!
//! The public API is [`SearchEngine`], which owns a long-lived Rayon thread
//! pool and dispatches to the internal algorithms.  Raw algorithm functions
//! (`parallel_scan`, `bsgs`) are crate-private.

use crate::{
    config::Config,
    context::ShutdownToken,
    crypto::{affine_key, derive_affine_constants, derive_private_key},
    domain::{SearchOutcome, SearchSpec, SignaturePair},
    error::{EngineError, Result},
    metrics::{MetricsSink, SearchReport},
};
use k256::{elliptic_curve::BatchNormalize, AffinePoint, ProjectivePoint, PublicKey, Scalar};
use rayon::prelude::*;
use rustc_hash::{FxBuildHasher, FxHashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::info;

/// Maximum candidate count for which the parallel scan is used.
///
/// Above this threshold the BSGS algorithm is selected automatically.
pub const BSGS_THRESHOLD: u128 = 1 << 32;
/// Maximum baby-step table size (in entries) to prevent unbounded memory use.
///
/// At `2^26` entries the hash map consumes roughly 5 GB.
const BSGS_MAX_M: u64 = 1 << 26;
/// Compressed encoding of the identity point, used as a sentinel key.
const IDENTITY_KEY: [u8; 33] = [0u8; 33];
/// Number of giant-step points processed in one batch-normalize call.
const BATCH: u64 = 4096;
/// Number of scan candidates evaluated between atomic shutdown checks.
const PARALLEL_BATCH: u128 = 1024;

/// Owned search engine that holds a reusable Rayon thread pool.
///
/// Construct once and call [`SearchEngine::search`] for each query.
pub struct SearchEngine {
    pool: rayon::ThreadPool,
    thread_count: usize,
    shutdown: ShutdownToken,
    metrics: Arc<dyn MetricsSink + Send + Sync>,
    bsgs_max_m: u64,
}

impl std::fmt::Debug for SearchEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchEngine")
            .field("thread_count", &self.thread_count)
            .field("shutdown", &self.shutdown)
            .finish_non_exhaustive()
    }
}

impl SearchEngine {
    /// Create a new engine.
    ///
    /// `threads` overrides the auto-detected thread count; `None` lets the
    /// engine pick `available_parallelism` capped by `config.max_threads`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Engine`] if the Rayon thread pool cannot be built.
    pub fn new(
        config: &Config,
        threads: Option<usize>,
        shutdown: ShutdownToken,
        metrics: Arc<dyn MetricsSink + Send + Sync>,
    ) -> Result<Self> {
        let max_threads = config.max_threads;
        let thread_count = match threads {
            Some(t) if t > max_threads => {
                tracing::warn!(requested = t, max = max_threads, "capping threads");
                max_threads
            }
            Some(t) => t,
            None => std::thread::available_parallelism()
                .map(std::num::NonZero::get)
                .unwrap_or(1)
                .min(max_threads),
        };

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .build()
            .map_err(|e| EngineError::ThreadPoolInit(e.to_string()))?;

        Ok(Self {
            pool,
            thread_count,
            shutdown,
            metrics,
            bsgs_max_m: BSGS_MAX_M,
        })
    }

    /// Return the shutdown token held by this engine.
    #[must_use]
    pub const fn shutdown_token(&self) -> &ShutdownToken {
        &self.shutdown
    }

    /// Search for the nonce delta that makes the derived private key match
    /// `target`.
    ///
    /// Returns [`SearchOutcome`] containing the delta (if found) and the
    /// affine constants.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if the affine constants cannot be derived, or
    /// [`Error::Range`] if the search specification total overflows.
    pub fn search(
        &self,
        spec: &SearchSpec,
        pair: &SignaturePair,
        target: &PublicKey,
    ) -> Result<SearchOutcome> {
        let start_time = Instant::now();
        let (alpha, beta) = derive_affine_constants(pair)?;

        let target_affine: AffinePoint = *target.as_affine();
        let d0_scalar = derive_private_key(spec.start, alpha, beta);
        let d0_point = ProjectivePoint::GENERATOR * d0_scalar;
        if d0_point == target_affine {
            let outcome = SearchOutcome::new(Some(spec.start), alpha, beta);
            self.emit_metrics(start_time, &outcome);
            return Ok(outcome);
        }

        let step_scalar = alpha * Scalar::from(spec.step.cast_unsigned());
        let step_point = ProjectivePoint::GENERATOR * step_scalar;
        let total = spec.total()?;

        if step_scalar == Scalar::ZERO {
            let outcome = SearchOutcome::new(None, alpha, beta);
            self.emit_metrics(start_time, &outcome);
            return Ok(outcome);
        }

        let scan = ScanParams {
            target: *target,
            start: spec.start,
            step: spec.step,
            total,
            alpha,
            beta,
            step_point,
        };

        let found = if total <= BSGS_THRESHOLD {
            self.parallel_scan(&scan)
        } else {
            self.bsgs(&scan)?
        };

        let outcome = SearchOutcome::new(found, alpha, beta);
        self.emit_metrics(start_time, &outcome);
        Ok(outcome)
    }

    fn emit_metrics(&self, start: Instant, outcome: &SearchOutcome) {
        self.metrics.emit(&SearchReport {
            elapsed: start.elapsed(),
            found: outcome.delta.is_some(),
            delta: outcome.delta,
            threads: self.thread_count,
        });
    }

    fn parallel_scan(&self, scan: &ScanParams) -> Option<i128> {
        let target_affine: AffinePoint = *scan.target.as_affine();
        let chunk: u128 = scan.total.div_ceil(self.thread_count as u128);
        let found_flag = Arc::new(AtomicBool::new(false));
        let result = Arc::new(std::sync::Mutex::new(None::<i128>));

        self.pool.install(|| {
            (0..self.thread_count)
                .into_par_iter()
                .for_each(|thread_id| {
                    if self.shutdown.is_signalled() || found_flag.load(Ordering::SeqCst) {
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
                    let mut d0 = scan.start + chunk_start_i128 * scan.step;
                    let mut point =
                        ProjectivePoint::GENERATOR * derive_private_key(d0, scan.alpha, scan.beta);

                    let mut i = 0u128;
                    while i < count {
                        if self.shutdown.is_signalled() || found_flag.load(Ordering::SeqCst) {
                            break;
                        }
                        let batch_end = (i + PARALLEL_BATCH).min(count);
                        let mut found = false;
                        for _ in i..batch_end {
                            if point == target_affine {
                                found_flag.store(true, Ordering::SeqCst);
                                *result.lock().unwrap() = Some(d0);
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

        let lock = result.lock().unwrap();
        *lock
    }

    fn bsgs(&self, scan: &ScanParams) -> Result<Option<i128>> {
        let target_affine: AffinePoint = *scan.target.as_affine();
        let d0_scalar = derive_private_key(scan.start, scan.alpha, scan.beta);
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

        if m <= u128::from(self.bsgs_max_m) {
            let m_u64 = u64::try_from(m).map_err(|_| EngineError::BsgsMOverflow)?;
            let baby_map = self
                .pool
                .install(|| build_baby_steps(0, m_u64, scan.step_point, self.thread_count));
            let m_step = scan.step_point * Scalar::from(m_u64);
            let params = GiantStepParams {
                t,
                m: m_u64,
                m_step,
                total: scan.total,
                thread_count: self.thread_count,
                step_point: scan.step_point,
                start: scan.start,
                step: scan.step,
                baby_map: &baby_map,
                pool: &self.pool,
                shutdown: &self.shutdown,
            };
            Ok(run_giant_steps(&params).and_then(|k| reconstruct_delta(&params, k)))
        } else {
            let segment_size = u128::from(self.bsgs_max_m);
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
                if self.shutdown.is_signalled() || result.load(Ordering::SeqCst) != u64::MAX {
                    break;
                }

                let seg_start = seg * segment_size;
                let seg_end = ((seg + 1) * segment_size).min(m);
                let seg_len = u64::try_from(seg_end - seg_start)
                    .map_err(|_| EngineError::BsgsSegmentOverflow)?;

                if seg_len == 0 {
                    continue;
                }

                let baby_map = self.pool.install(|| {
                    build_baby_steps(seg_start, seg_len, scan.step_point, self.thread_count)
                });

                let m_u64 = u64::try_from(m).map_err(|_| EngineError::BsgsMOverflow)?;
                let m_step = scan.step_point * Scalar::from(m_u64);
                let params = GiantStepParams {
                    t,
                    m: m_u64,
                    m_step,
                    total: scan.total,
                    thread_count: self.thread_count,
                    step_point: scan.step_point,
                    start: scan.start,
                    step: scan.step,
                    baby_map: &baby_map,
                    pool: &self.pool,
                    shutdown: &self.shutdown,
                };
                let found = run_giant_steps(&params);

                if let Some(k) = found {
                    return Ok(reconstruct_delta(&params, k));
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
}

#[cfg(test)]
impl SearchEngine {
    /// Test-only constructor that allows overriding BSGS parameters.
    #[cfg(test)]
    pub fn with_params(
        pool: rayon::ThreadPool,
        thread_count: usize,
        shutdown: ShutdownToken,
        metrics: Arc<dyn MetricsSink + Send + Sync>,
        bsgs_max_m: u64,
    ) -> Self {
        Self {
            pool,
            thread_count,
            shutdown,
            metrics,
            bsgs_max_m,
        }
    }
}

/// Parameters shared by `parallel_scan` and `bsgs`.
struct ScanParams {
    target: PublicKey,
    start: i128,
    step: i128,
    total: u128,
    alpha: Scalar,
    beta: Scalar,
    step_point: ProjectivePoint,
}

/// Parameters for the giant-step phase shared by standard and segmented BSGS.
struct GiantStepParams<'a> {
    t: ProjectivePoint,
    m: u64,
    m_step: ProjectivePoint,
    total: u128,
    thread_count: usize,
    step_point: ProjectivePoint,
    start: i128,
    step: i128,
    baby_map: &'a FxHashMap<[u8; 33], u128>,
    pool: &'a rayon::ThreadPool,
    shutdown: &'a ShutdownToken,
}

/// Giant-step phase shared by standard and segmented BSGS.
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
            let coeff = u128::from(chunk_start_u64) * u128::from(p.m);
            let offset_scalar = u64::try_from(coeff).expect("coeff fits in u64");
            let offset = p.step_point * Scalar::from(offset_scalar);
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

/// Reconstruct the exact delta given the matching giant-step index.
fn reconstruct_delta(p: &GiantStepParams<'_>, k_giant: u64) -> Option<i128> {
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

/// Build a baby-step table.
///
/// * `start` — absolute index of the first entry (0 for standard BSGS,
///   segment offset for segmented BSGS).
/// * `len` — number of entries to build.
fn build_baby_steps(
    start: u128,
    len: u64,
    step_point: ProjectivePoint,
    thread_count: usize,
) -> FxHashMap<[u8; 33], u128> {
    let maps: Vec<FxHashMap<[u8; 33], u128>> = (0..thread_count)
        .into_par_iter()
        .map(|tid| {
            let start_j = tid as u128 * u128::from(len) / thread_count as u128;
            let end_j =
                ((tid + 1) as u128 * u128::from(len) / thread_count as u128).min(u128::from(len));
            if start_j >= end_j {
                return FxHashMap::default();
            }
            let map_len = usize::try_from(end_j - start_j).expect("batch fits in usize");
            let mut map = FxHashMap::with_capacity_and_hasher(map_len, FxBuildHasher);

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

    let mut merged = FxHashMap::with_capacity_and_hasher(
        usize::try_from(len).expect("len fits in usize"),
        FxBuildHasher,
    );
    for map in maps {
        merged.extend(map);
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        context::ShutdownToken,
        crypto::derive_affine_constants,
        domain::{Signature, SignaturePair},
        metrics::TracingMetricsSink,
    };
    use k256::{
        elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
        ProjectivePoint, Scalar,
    };
    use std::sync::Arc;

    #[test]
    fn test_bsgs_small_range() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let (pair, pk) = fixture();
        let (alpha, beta) = derive_affine_constants(&pair).unwrap();
        let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
        let engine = SearchEngine::new(
            &config,
            Some(4),
            ShutdownToken::new(),
            Arc::new(TracingMetricsSink),
        )
        .unwrap();
        let scan = ScanParams {
            target: pk,
            start: -10,
            step: 1,
            total: 21,
            alpha,
            beta,
            step_point,
        };
        let found = engine.bsgs(&scan).unwrap();
        assert_eq!(found, Some(-1));
    }

    #[test]
    fn test_bsgs_medium_range() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let (pair, pk) = fixture();
        let (alpha, beta) = derive_affine_constants(&pair).unwrap();
        let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
        let engine = SearchEngine::new(
            &config,
            Some(4),
            ShutdownToken::new(),
            Arc::new(TracingMetricsSink),
        )
        .unwrap();
        let scan = ScanParams {
            target: pk,
            start: -100,
            step: 1,
            total: 201,
            alpha,
            beta,
            step_point,
        };
        let found = engine.bsgs(&scan).unwrap();
        assert_eq!(found, Some(-1));
    }

    fn fixture() -> (SignaturePair, k256::PublicKey) {
        let d = Scalar::from(0x3039u64);
        let nonce = 0x1234u64;
        let next = nonce - 1;

        let r1 = r_from_nonce(nonce);
        let r2 = r_from_nonce(next);
        let z1 = Scalar::from(1u64);
        let z2 = Scalar::from(2u64);
        let s1 = sig_s(1, r1, d, nonce);
        let s2 = sig_s(2, r2, d, next);

        let pk = k256::PublicKey::from_sec1_bytes(
            (ProjectivePoint::GENERATOR * d)
                .to_affine()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .unwrap();

        let sig1 = Signature::new(r1, s1, z1);
        let sig2 = Signature::new(r2, s2, z2);
        (SignaturePair::new(sig1, sig2), pk)
    }

    fn r_from_nonce(n: u64) -> Scalar {
        let enc = (ProjectivePoint::GENERATOR * Scalar::from(n))
            .to_affine()
            .to_encoded_point(true);
        let mut b = [0u8; 32];
        b.copy_from_slice(&enc.as_bytes()[1..33]);
        Scalar::from_repr(b.into()).unwrap()
    }

    fn sig_s(z: u64, r: Scalar, d: Scalar, nonce: u64) -> Scalar {
        (Scalar::from(z) + r * d) * Scalar::from(nonce).invert().unwrap()
    }

    #[test]
    fn test_segmented_bsgs() {
        let _config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let (pair, pk) = fixture();
        let (alpha, beta) = derive_affine_constants(&pair).unwrap();
        let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        let engine = SearchEngine::with_params(
            pool,
            4,
            ShutdownToken::new(),
            Arc::new(TracingMetricsSink),
            50,
        );
        let scan = ScanParams {
            target: pk,
            start: -10,
            step: 1,
            total: 10_000,
            alpha,
            beta,
            step_point,
        };
        let found = engine.bsgs(&scan).unwrap();
        assert_eq!(found, Some(-1));
    }

    #[test]
    fn test_engine_debug() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let engine = SearchEngine::new(
            &config,
            Some(2),
            ShutdownToken::new(),
            Arc::new(TracingMetricsSink),
        )
        .unwrap();
        let s = format!("{engine:?}");
        assert!(s.contains("SearchEngine"));
        assert!(s.contains("thread_count"));
    }

    #[test]
    fn test_shutdown_token() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let engine = SearchEngine::new(
            &config,
            Some(2),
            ShutdownToken::new(),
            Arc::new(TracingMetricsSink),
        )
        .unwrap();
        assert!(!engine.shutdown_token().is_signalled());
    }

    #[test]
    fn test_thread_cap_warning() {
        let config = Config {
            max_threads: 2,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let engine = SearchEngine::new(
            &config,
            Some(100),
            ShutdownToken::new(),
            Arc::new(TracingMetricsSink),
        )
        .unwrap();
        assert_eq!(engine.thread_count, 2);
    }

    #[test]
    fn test_parallel_scan_empty_chunk() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let (pair, pk) = fixture();
        let (alpha, beta) = derive_affine_constants(&pair).unwrap();
        let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
        let engine = SearchEngine::new(
            &config,
            Some(4),
            ShutdownToken::new(),
            Arc::new(TracingMetricsSink),
        )
        .unwrap();
        let scan = ScanParams {
            target: pk,
            start: 0,
            step: 1,
            total: 2,
            alpha,
            beta,
            step_point,
        };
        let found = engine.parallel_scan(&scan);
        assert_eq!(found, None);
    }

    #[test]
    fn test_bsgs_match_at_start() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let (pair, pk) = fixture();
        let (alpha, beta) = derive_affine_constants(&pair).unwrap();
        let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
        let engine = SearchEngine::new(
            &config,
            Some(4),
            ShutdownToken::new(),
            Arc::new(TracingMetricsSink),
        )
        .unwrap();
        let scan = ScanParams {
            target: pk,
            start: -1,
            step: 1,
            total: 21,
            alpha,
            beta,
            step_point,
        };
        let found = engine.bsgs(&scan).unwrap();
        assert_eq!(found, Some(-1));
    }

    #[test]
    fn test_reconstruct_delta_out_of_range() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let (pair, pk) = fixture();
        let (alpha, beta) = derive_affine_constants(&pair).unwrap();
        let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
        let engine = SearchEngine::new(
            &config,
            Some(4),
            ShutdownToken::new(),
            Arc::new(TracingMetricsSink),
        )
        .unwrap();
        let scan = ScanParams {
            target: pk,
            start: 0,
            step: 1,
            total: 10,
            alpha,
            beta,
            step_point,
        };
        let found = engine.bsgs(&scan).unwrap();
        assert_eq!(found, None);
    }

    #[test]
    fn test_giant_steps_empty_chunk() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let (pair, pk) = fixture();
        let (alpha, beta) = derive_affine_constants(&pair).unwrap();
        let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
        let engine = SearchEngine::new(
            &config,
            Some(4),
            ShutdownToken::new(),
            Arc::new(TracingMetricsSink),
        )
        .unwrap();
        let scan = ScanParams {
            target: pk,
            start: -1,
            step: 1,
            total: 3,
            alpha,
            beta,
            step_point,
        };
        let found = engine.bsgs(&scan).unwrap();
        assert_eq!(found, Some(-1));
    }

    #[test]
    fn test_search_alpha_zero() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let r1 = Scalar::from(1u64);
        let r2 = Scalar::from(2u64);
        let s1 = Scalar::from(1u64);
        let s2 = Scalar::from(0u64);
        let z1 = Scalar::from(1u64);
        let z2 = Scalar::from(2u64);
        let sig1 = Signature::new(r1, s1, z1);
        let sig2 = Signature::new(r2, s2, z2);
        let pair = SignaturePair::new(sig1, sig2);
        let (_, _beta) = derive_affine_constants(&pair).unwrap();
        assert_eq!(derive_affine_constants(&pair).unwrap().0, Scalar::ZERO);

        let target = k256::PublicKey::from_sec1_bytes(
            (ProjectivePoint::GENERATOR * Scalar::from(42u64))
                .to_affine()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .unwrap();

        let engine = SearchEngine::new(
            &config,
            Some(4),
            ShutdownToken::new(),
            Arc::new(TracingMetricsSink),
        )
        .unwrap();
        let spec = SearchSpec::new(0, 10, 1).unwrap();
        let outcome = engine.search(&spec, &pair, &target).unwrap();
        assert_eq!(outcome.delta, None);
    }

    #[test]
    fn test_search_dispatches_to_bsgs() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let (pair, pk) = fixture();
        let engine = SearchEngine::new(
            &config,
            Some(4),
            ShutdownToken::new(),
            Arc::new(TracingMetricsSink),
        )
        .unwrap();
        let spec = SearchSpec::new(0, 1i128 << 32, 1).unwrap();
        let outcome = engine.search(&spec, &pair, &pk).unwrap();
        assert_eq!(outcome.delta, None);
    }

    #[test]
    fn test_parallel_scan_shutdown() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let (pair, pk) = fixture();
        let (alpha, beta) = derive_affine_constants(&pair).unwrap();
        let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
        let shutdown = ShutdownToken::new();
        shutdown.signal();
        let engine =
            SearchEngine::new(&config, Some(4), shutdown, Arc::new(TracingMetricsSink)).unwrap();
        let scan = ScanParams {
            target: pk,
            start: 0,
            step: 1,
            total: 100,
            alpha,
            beta,
            step_point,
        };
        let found = engine.parallel_scan(&scan);
        assert_eq!(found, None);
    }

    #[test]
    fn test_segmented_bsgs_no_match() {
        let (pair, pk) = fixture();
        let (alpha, beta) = derive_affine_constants(&pair).unwrap();
        let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        let engine = SearchEngine::with_params(
            pool,
            4,
            ShutdownToken::new(),
            Arc::new(TracingMetricsSink),
            50,
        );
        let scan = ScanParams {
            target: pk,
            start: 0,
            step: 1,
            total: 10_000,
            alpha,
            beta,
            step_point,
        };
        let found = engine.bsgs(&scan).unwrap();
        assert_eq!(found, None);
    }

    #[test]
    fn test_segmented_bsgs_shutdown() {
        let (pair, pk) = fixture();
        let (alpha, beta) = derive_affine_constants(&pair).unwrap();
        let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        let shutdown = ShutdownToken::new();
        shutdown.signal();
        let engine = SearchEngine::with_params(pool, 4, shutdown, Arc::new(TracingMetricsSink), 50);
        let scan = ScanParams {
            target: pk,
            start: 0,
            step: 1,
            total: 10_000,
            alpha,
            beta,
            step_point,
        };
        let found = engine.bsgs(&scan).unwrap();
        assert_eq!(found, None);
    }

    #[test]
    fn test_giant_steps_shutdown() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let (pair, pk) = fixture();
        let (alpha, beta) = derive_affine_constants(&pair).unwrap();
        let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
        let shutdown = ShutdownToken::new();
        shutdown.signal();
        let engine =
            SearchEngine::new(&config, Some(4), shutdown, Arc::new(TracingMetricsSink)).unwrap();
        let scan = ScanParams {
            target: pk,
            start: 0,
            step: 1,
            total: 100,
            alpha,
            beta,
            step_point,
        };
        let found = engine.bsgs(&scan).unwrap();
        assert_eq!(found, None);
    }

    #[test]
    fn test_bsgs_identity_match() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let (pair, pk) = fixture();
        let (alpha, beta) = derive_affine_constants(&pair).unwrap();
        let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
        let engine = SearchEngine::new(
            &config,
            Some(4),
            ShutdownToken::new(),
            Arc::new(TracingMetricsSink),
        )
        .unwrap();
        let scan = ScanParams {
            target: pk,
            start: -4,
            step: 1,
            total: 5,
            alpha,
            beta,
            step_point,
        };
        let found = engine.bsgs(&scan).unwrap();
        assert_eq!(found, Some(-1));
    }

    #[test]
    fn test_build_baby_steps_and_giant_empty() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let (pair, pk) = fixture();
        let (alpha, beta) = derive_affine_constants(&pair).unwrap();
        let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
        let engine = SearchEngine::new(
            &config,
            Some(4),
            ShutdownToken::new(),
            Arc::new(TracingMetricsSink),
        )
        .unwrap();
        let scan = ScanParams {
            target: pk,
            start: 0,
            step: 1,
            total: 3,
            alpha,
            beta,
            step_point,
        };
        let found = engine.bsgs(&scan).unwrap();
        assert_eq!(found, None);
    }
}
