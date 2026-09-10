use super::*;
use crate::{
    config::Config,
    context::ShutdownToken,
    crypto::derive_affine_constants,
    domain::{SearchSpec, Signature},
    fixtures::{fixture, fixture_with_nonce, make_engine},
};
use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, Scalar};

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
        checkpoint_dir: std::env::temp_dir().join("checkpoints"),
        version: "test",
    };
    let engine = SearchEngine::new(&config, Some(100), ShutdownToken::new()).unwrap();
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
        checkpoint_dir: std::env::temp_dir().join("checkpoints"),
        version: "test",
    };
    let engine = SearchEngine::new(&config, Some(4), shutdown).unwrap();
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
fn test_giant_steps_shutdown() {
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
    let shutdown = ShutdownToken::new();
    shutdown.signal();
    let config = Config {
        max_threads: 4,
        log_dir: std::env::temp_dir(),
        checkpoint_dir: std::env::temp_dir().join("checkpoints"),
        version: "test",
    };
    let engine = SearchEngine::new(&config, Some(4), shutdown).unwrap();
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
    };
    let found = engine.kangaroo(&kangaroo_params).unwrap();
    assert_eq!(found, Some(5));
}

#[test]
fn test_kangaroo_shutdown() {
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap();
    let shutdown = ShutdownToken::new();
    shutdown.signal();
    let engine = SearchEngine::with_params(pool, 4, shutdown);
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
    };
    let found = engine.kangaroo(&kangaroo_params).unwrap();
    assert_eq!(found, None);
}

#[test]
fn test_kangaroo_total_one() {
    let engine = make_engine(4);
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let kangaroo_params = crate::search::params::KangarooParams {
        g: ProjectivePoint::GENERATOR,
        h: pk.into(),
        alpha,
        beta,
        start: 5,
        step: 1,
        total: 1,
        d: 8,
        max_iterations: 1_000_000,
    };
    let found = engine.kangaroo(&kangaroo_params).unwrap();
    assert_eq!(found, Some(5));
}

#[test]
fn test_kangaroo_step_not_one() {
    let engine = make_engine(4);
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let kangaroo_params = crate::search::params::KangarooParams {
        g: ProjectivePoint::GENERATOR,
        h: pk.into(),
        alpha,
        beta,
        start: 0,
        step: 2,
        total: 10,
        d: 8,
        max_iterations: 10_000,
    };
    let found = engine.kangaroo(&kangaroo_params).unwrap();
    assert_eq!(found, None);
}

#[test]
fn test_kangaroo_alpha_zero() {
    let engine = make_engine(4);
    let r = Scalar::from(1u64);
    let s = Scalar::from(0u64);
    let z = Scalar::from(1u64);
    let sig = Signature::new(r, s, z);
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    assert_eq!(alpha, Scalar::ZERO);

    let target = k256::PublicKey::from_sec1_bytes(
        (ProjectivePoint::GENERATOR * (Scalar::ZERO - beta))
            .to_affine()
            .to_encoded_point(true)
            .as_bytes(),
    )
    .unwrap();

    let kangaroo_params = crate::search::params::KangarooParams {
        g: ProjectivePoint::GENERATOR,
        h: target.into(),
        alpha,
        beta,
        start: 0,
        step: 1,
        total: 100,
        d: 8,
        max_iterations: 1_000_000,
    };
    let found = engine.kangaroo(&kangaroo_params).unwrap();
    assert_eq!(found, Some(0));
}

#[test]
fn test_kangaroo_no_match() {
    let engine = make_engine(4);
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let kangaroo_params = crate::search::params::KangarooParams {
        g: ProjectivePoint::GENERATOR,
        h: pk.into(),
        alpha,
        beta,
        start: 10,
        step: 1,
        total: 10,
        d: 8,
        max_iterations: 10_000,
    };
    let found = engine.kangaroo(&kangaroo_params).unwrap();
    assert_eq!(found, None);
}

#[test]
fn test_kangaroo_stress() {
    let engine = make_engine(4);
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    for _ in 0..10 {
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
        };
        let found = engine.kangaroo(&kangaroo_params).unwrap();
        assert_eq!(found, Some(5));
    }
}

#[test]
fn test_kangaroo_step_not_one_match() {
    let engine = make_engine(4);
    let (sig, pk) = fixture_with_nonce(9);
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let kangaroo_params = crate::search::params::KangarooParams {
        g: ProjectivePoint::GENERATOR,
        h: pk.into(),
        alpha,
        beta,
        start: 0,
        step: 3,
        total: 10,
        d: 8,
        max_iterations: 1_000_000,
    };
    let found = engine.kangaroo(&kangaroo_params).unwrap();
    assert_eq!(found, Some(9));
}

#[test]
fn test_bsgs_step_not_one() {
    let engine = make_engine(4);
    let (sig, pk) = fixture_with_nonce(5);
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(5u64));
    let scan = ScanParams {
        target: pk,
        start: 0,
        step: 5,
        total: 2,
        alpha,
        beta,
        step_point,
    };
    let found = engine.bsgs(&scan).unwrap();
    assert_eq!(found, Some(5));
}

#[test]
fn test_parallel_scan_step_not_one() {
    let engine = make_engine(4);
    let (sig, pk) = fixture_with_nonce(5);
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(5u64));
    let scan = ScanParams {
        target: pk,
        start: 0,
        step: 5,
        total: 2,
        alpha,
        beta,
        step_point,
    };
    let found = engine.parallel_scan(&scan);
    assert_eq!(found, Some(5));
}

#[test]
fn test_kangaroo_params_invalid_d() {
    let (sig, pk) = fixture();
    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let params = crate::search::params::KangarooParams::new(
        ProjectivePoint::GENERATOR,
        pk.into(),
        alpha,
        beta,
        0,
        1,
        1000,
        300,
        None,
    );
    assert!(params.is_err());
    let err = params.unwrap_err().to_string();
    assert!(err.contains("d=300 out of range"));
}
