//! Shared test fixtures and helpers used by unit tests across the crate.

use crate::{
    config::Config, context::ShutdownToken, domain::Signature, metrics::TracingMetricsSink,
    search::SearchEngine,
};
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    ProjectivePoint, PublicKey, Scalar,
};
use std::sync::Arc;

/// A pre-built valid `(Signature, PublicKey)` using a known private key.
///
/// Private key `d = 0x3039`, nonce `k = 5`, message hash `z = 1`.
pub fn fixture() -> (Signature, PublicKey) {
    let d = Scalar::from(0x3039u64);
    let nonce = 5u64;
    let z = Scalar::from(1u64);

    let r = r_from_nonce(nonce);
    let s = sig_s(1, r, d, nonce);

    let pk = PublicKey::from_sec1_bytes(
        (ProjectivePoint::GENERATOR * d)
            .to_affine()
            .to_encoded_point(true)
            .as_bytes(),
    )
    .unwrap();

    (Signature::new(r, s, z), pk)
}

/// Compute the `r` scalar from a nonce `n`.
///
/// This mirrors the ECDSA nonce-to-r derivation: `r = x(k * G)`.
pub fn r_from_nonce(n: u64) -> Scalar {
    let enc = (ProjectivePoint::GENERATOR * Scalar::from(n))
        .to_affine()
        .to_encoded_point(true);
    let mut b = [0u8; 32];
    b.copy_from_slice(&enc.as_bytes()[1..33]);
    Scalar::from_repr(b.into()).unwrap()
}

/// Compute the `s` component of an ECDSA signature.
///
/// Formula: `s = (z + r * d) / nonce`.
pub fn sig_s(z: u64, r: Scalar, d: Scalar, nonce: u64) -> Scalar {
    (Scalar::from(z) + r * d) * Scalar::from(nonce).invert().unwrap()
}

/// A pre-built valid `(Signature, PublicKey)` with a custom nonce.
pub fn fixture_with_nonce(nonce: u64) -> (Signature, PublicKey) {
    let d = Scalar::from(0x3039u64);
    let z = Scalar::from(1u64);
    let r = r_from_nonce(nonce);
    let s = sig_s(1, r, d, nonce);
    let pk = PublicKey::from_sec1_bytes(
        (ProjectivePoint::GENERATOR * d)
            .to_affine()
            .to_encoded_point(true)
            .as_bytes(),
    )
    .unwrap();
    (Signature::new(r, s, z), pk)
}

/// Create a [`SearchEngine`] with the given thread count for testing.
pub fn make_engine(threads: usize) -> SearchEngine {
    let config = Config {
        max_threads: threads,
        log_dir: std::env::temp_dir(),
        version: "test",
    };
    SearchEngine::new(
        &config,
        Some(threads),
        ShutdownToken::new(),
        Arc::new(TracingMetricsSink),
    )
    .unwrap()
}
