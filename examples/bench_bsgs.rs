//! Benchmark BSGS search speed for large nonce ranges.
//!
//! Generates a random private key and nonce, constructs a valid signature,
//! then measures wall-clock time to recover the nonce via BSGS.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --example bench_bsgs --release -- [BITS]
//! ```
//!
//! Default range is `2^48`. For `2^52`:
//! ```bash
//! cargo run --example bench_bsgs --release -- 52
//! ```

use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    ProjectivePoint, PublicKey, Scalar,
};
use nonce_cracker::{
    derive_affine_constants, derive_private_key, verify_ecdsa_signature, Config, SearchEngine,
    SearchSpec, ShutdownToken, Signature,
};
use rand::RngExt;

fn main() {
    let bits: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(48);

    if !(20..=64).contains(&bits) {
        eprintln!("Usage: bench_bsgs [BITS]  (range 20..=64, default 48)");
        std::process::exit(1);
    }

    let end = 1u128 << bits;
    println!("BSGS benchmark: searching nonce in [0, 2^{bits})  ({end} candidates)");

    let mut rng = rand::rng();

    let nonce: u64 = rng.random_range(0..(end as u64));
    let d_bytes: [u8; 32] = rng.random();
    let d = Scalar::from_repr(d_bytes.into()).unwrap_or_else(|| Scalar::from(1u64));

    // Compute public key.
    let pk = PublicKey::from_sec1_bytes(
        (ProjectivePoint::GENERATOR * d)
            .to_affine()
            .to_encoded_point(true)
            .as_bytes(),
    )
    .unwrap();

    // Build a valid signature: s = (z + r * d) / nonce, with z = 1.
    let z = Scalar::from(1u64);
    let r = {
        let enc = (ProjectivePoint::GENERATOR * Scalar::from(nonce))
            .to_affine()
            .to_encoded_point(true);
        let mut b = [0u8; 32];
        b.copy_from_slice(&enc.as_bytes()[1..33]);
        Scalar::from_repr(b.into()).unwrap()
    };
    let s = (z + r * d) * Scalar::from(nonce).invert().unwrap();

    let sig = Signature::new(r, s, z);
    verify_ecdsa_signature(&pk, &sig.r, &sig.s, &sig.z).unwrap();

    let (alpha, beta) = derive_affine_constants(&sig).unwrap();
    let expected_d = derive_private_key(nonce as u128, alpha, beta);
    assert_eq!(expected_d, d, "derived private key mismatch");

    println!("nonce = {nonce}  (0x{nonce:x})");
    println!("d     = 0x{}", hex::encode(d.to_bytes()));
    println!("r     = 0x{}", hex::encode(r.to_bytes()));
    println!("s     = 0x{}", hex::encode(s.to_bytes()));
    println!(
        "pubkey= {}",
        hex::encode(pk.to_encoded_point(true).as_bytes())
    );

    let config = Config {
        max_threads: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4),
        log_dir: std::env::temp_dir(),
        checkpoint_dir: std::env::temp_dir().join("checkpoints"),
        version: "bench",
    };
    let shutdown = ShutdownToken::new();
    let spec = SearchSpec::new(0, end as i128, 1).unwrap();

    let engine = SearchEngine::new(&config, None, shutdown).unwrap();

    let start = std::time::Instant::now();
    let outcome = engine.search(&spec, &sig, &pk).unwrap();
    let elapsed = start.elapsed();

    match outcome.nonce {
        Some(found) => {
            let sqrt_n = (end as f64).sqrt();
            let point_ops = 2.0 * sqrt_n; // baby steps + giant steps (approximate)
            println!("\n✓ Found nonce = {found}  (expected {nonce})");
            println!("  elapsed    : {elapsed:.3?}");
            println!(
                "  point ops  : {:.2e} ops/sec  ({point_ops:.2e} total)",
                point_ops / elapsed.as_secs_f64()
            );
            println!("  sqrt(N)    : {sqrt_n:.2e}");
        }
        None => {
            eprintln!("\n✗ Search completed without finding the nonce.");
            std::process::exit(1);
        }
    }
}
