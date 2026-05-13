use super::*;
use crate::{
    config::Config,
    context::ShutdownToken,
    crypto::derive_affine_constants,
    domain::{SearchSpec, Signature},
    fixtures::{fixture, make_engine},
    metrics::TracingMetricsSink,
};
use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, Scalar};
use std::sync::Arc;

#[test]
fn test_bsgs_small_range() {
    let engine = make_engine(4);
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
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
    assert_eq!(found, Some(5));
}

#[test]
fn test_bsgs_medium_range() {
    let engine = make_engine(4);
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
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
    assert_eq!(found, Some(5));
}

#[test]
fn test_segmented_bsgs() {
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
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
    assert_eq!(found, Some(5));
}

#[test]
fn test_engine_debug() {
    let engine = make_engine(2);
    let s = format!("{engine:?}");
    assert!(s.contains("SearchEngine"));
    assert!(s.contains("thread_count"));
}

#[test]
fn test_shutdown_token() {
    let engine = make_engine(2);
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
    let engine = make_engine(4);
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
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
    let engine = make_engine(4);
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
    let scan = ScanParams {
        target: pk,
        start: 5,
        step: 1,
        total: 21,
        alpha,
        beta,
        step_point,
    };
    let found = engine.bsgs(&scan).unwrap();
    assert_eq!(found, Some(5));
}

#[test]
fn test_reconstruct_nonce_out_of_range() {
    let engine = make_engine(4);
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
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

#[test]
fn test_giant_steps_empty_chunk() {
    let engine = make_engine(4);
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
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

#[test]
fn test_search_alpha_zero() {
    let engine = make_engine(4);
    let r = Scalar::from(1u64);
    let s = Scalar::from(0u64);
    let z = Scalar::from(1u64);
    let sig = Signature::new(r, s, z);
    assert_eq!(derive_affine_constants(&sig).unwrap().0, Scalar::ZERO);

    let target = k256::PublicKey::from_sec1_bytes(
        (ProjectivePoint::GENERATOR * Scalar::from(42u64))
            .to_affine()
            .to_encoded_point(true)
            .as_bytes(),
    )
    .unwrap();

    let spec = SearchSpec::new(0, 10, 1).unwrap();
    let outcome = engine.search(&spec, &sig, &target).unwrap();
    assert_eq!(outcome.nonce, None);
}

#[test]
fn test_search_dispatches_to_bsgs() {
    let engine = make_engine(4);
    let (sig, pk) = fixture();
    let spec = SearchSpec::new(0, 1i128 << 32, 1).unwrap();
    let outcome = engine.search(&spec, &sig, &pk).unwrap();
    assert_eq!(outcome.nonce, Some(5));
}

#[test]
fn test_parallel_scan_shutdown() {
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
    let shutdown = ShutdownToken::new();
    shutdown.signal();
    let config = Config {
        max_threads: 4,
        log_dir: std::env::temp_dir(),
        version: "test",
    };
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
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
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
        start: 10,
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
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
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
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
    let shutdown = ShutdownToken::new();
    shutdown.signal();
    let config = Config {
        max_threads: 4,
        log_dir: std::env::temp_dir(),
        version: "test",
    };
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
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
    let scan = ScanParams {
        target: pk,
        start: 5,
        step: 1,
        total: 5,
        alpha,
        beta,
        step_point,
    };
    let found = make_engine(4).bsgs(&scan).unwrap();
    assert_eq!(found, Some(5));
}

#[test]
fn test_build_baby_steps_and_giant_empty() {
    let engine = make_engine(4);
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
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

#[test]
fn test_kangaroo_small_range() {
    let engine = make_engine(4);
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let kangaroo_params = crate::search::params::KangarooParams {
        g: ProjectivePoint::GENERATOR,
        h: pk.into(),
        alpha,
        beta,
        start: 0,
        step: 1,
        total: 1000,
        d: 8, // lower d for small test
        max_iterations: 1_000_000,
        thread_count: 4,
        pool: &engine.pool,
        shutdown: &engine.shutdown,
    };
    let found = engine.kangaroo(&kangaroo_params).unwrap();
    assert_eq!(found, Some(5));
}

#[test]
fn test_kangaroo_shutdown() {
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let pool = rayon::ThreadPoolBuilder::new().num_threads(4).build().unwrap();
    let shutdown = ShutdownToken::new();
    shutdown.signal();
    let engine = SearchEngine::with_params(
        pool,
        4,
        shutdown,
        Arc::new(TracingMetricsSink),
        50,
    );
    let kangaroo_params = crate::search::params::KangarooParams {
        g: ProjectivePoint::GENERATOR,
        h: pk.into(),
        alpha,
        beta,
        start: 0,
        step: 1,
        total: 1000,
        d: 8,
        max_iterations: 1_000_000,
        thread_count: 4,
        pool: &engine.pool,
        shutdown: &engine.shutdown,
    };
    let found = engine.kangaroo(&kangaroo_params).unwrap();
    assert_eq!(found, None);
}
