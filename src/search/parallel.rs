//! Parallel brute-force scan for small search ranges.
//!
//! Splits the candidate space into per-thread chunks and evaluates each
//! candidate sequentially until a match is found or the range is exhausted.

use crate::{context::ShutdownToken, crypto::derive_private_key, search::params::ScanParams};
use k256::{AffinePoint, ProjectivePoint, Scalar};
use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Sentinel value for "not found" in the atomic result.
const NOT_FOUND: u64 = u64::MAX;
/// Number of scan candidates evaluated between atomic shutdown checks.
const PARALLEL_BATCH: u64 = 1024;

/// Run a parallel brute-force scan over the given [`ScanParams`].
///
/// Splits the range into per-thread chunks and evaluates candidates
/// sequentially. Best for small ranges where BSGS overhead is not worthwhile.
///
/// Returns the nonce value if found, or `None`.
pub fn scan(
    pool: &rayon::ThreadPool,
    thread_count: usize,
    shutdown: &ShutdownToken,
    scan: &ScanParams,
) -> Option<i128> {
    let target_affine: AffinePoint = *scan.target.as_affine();
    let chunk: u128 = scan.total.div_ceil(thread_count as u128);
    let found = Arc::new(AtomicU64::new(NOT_FOUND));

    // Precompute the base point for start to avoid per-chunk scalar mults.
    let base_point =
        ProjectivePoint::GENERATOR * derive_private_key(scan.start, scan.alpha, scan.beta);

    pool.install(|| {
        (0..thread_count).into_par_iter().for_each(|thread_id| {
            if shutdown.is_signalled() {
                return;
            }
            let chunk_start = thread_id as u128 * chunk;
            if chunk_start >= scan.total {
                return;
            }
            let count = chunk.min(scan.total - chunk_start);
            let chunk_start_u64 = u64::try_from(chunk_start).expect("total fits in u64 for scan");
            let _chunk_start_i128 = i128::try_from(chunk_start).expect("total fits in i128");

            // Compute chunk start point via point addition instead of scalar mult.
            let offset = scan.step_point * Scalar::from(chunk_start_u64);
            let mut point = base_point + offset;

            let count_u64 = u64::try_from(count).expect("chunk fits in u64");
            let mut i = 0u64;
            while i < count_u64 {
                if shutdown.is_signalled() || found.load(Ordering::Relaxed) != NOT_FOUND {
                    break;
                }
                let batch_end = (i + PARALLEL_BATCH).min(count_u64);
                let mut local_found = false;
                for batch_offset in 0..(batch_end - i) {
                    if point == target_affine {
                        let abs_index = chunk_start_u64 + i + batch_offset;
                        let _ = found.compare_exchange(
                            NOT_FOUND,
                            abs_index,
                            Ordering::SeqCst,
                            Ordering::Relaxed,
                        );
                        local_found = true;
                        break;
                    }
                    point += scan.step_point;
                }
                i = batch_end;
                if local_found {
                    break;
                }
            }
        });
    });

    let val = found.load(Ordering::SeqCst);
    if val == NOT_FOUND {
        None
    } else {
        let index = val as i128;
        Some(
            scan.start
                .checked_add(index.checked_mul(scan.step).expect("index*step overflow despite SearchSpec validation"))
                .expect("start+index*step overflow despite SearchSpec validation"),
        )
    }
}
