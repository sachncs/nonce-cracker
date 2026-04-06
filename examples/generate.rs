//! Generates valid ECDSA test data for the nonce-cracker example.
//!
//! This generates signatures such that the nonce-cracker will recover
//! d = alpha * delta + beta for a known delta.
//!
//! Run: cargo run --example generate

use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    ProjectivePoint, Scalar,
};
use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};

const CURVE_ORDER_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

fn normalize(x: &BigInt, n: &BigInt) -> BigInt {
    let r = x % n;
    if r.sign() == Sign::Minus {
        r + n
    } else {
        r
    }
}

fn mod_inverse(a: &BigInt, n: &BigInt) -> Option<BigInt> {
    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = n.clone();
    let mut new_r = normalize(a, n);

    while !new_r.is_zero() {
        let quotient = &r / &new_r;
        let temp_t = &t - &quotient * &new_t;
        t = new_t;
        new_t = temp_t;
        let temp_r = &r - &quotient * &new_r;
        r = new_r;
        new_r = temp_r;
    }

    if r > BigInt::one() {
        return None;
    }
    if t.sign() == Sign::Minus {
        t += n;
    }
    Some(t)
}

fn main() {
    let n_bytes = hex::decode(CURVE_ORDER_HEX).unwrap();
    let n = BigInt::from_bytes_be(Sign::Plus, &n_bytes);

    // We want to find d such that d = alpha * delta + beta
    // with delta small enough to search.
    //
    // Setup: Choose k and k' = k + delta
    // Signatures: s = k^-1 * (z + r*d)
    //
    // The affine relation attack gives us alpha, beta from precompute,
    // and the search finds delta.
    //
    // Strategy: Choose d, delta, and k, then derive z values
    // such that the signatures are valid and the attack recovers d.

    // Private key we want to recover
    let d = 0x3039u64;
    let d_scalar = Scalar::from(d);

    // Choose delta (what we search for)
    let delta = 1u64;

    // Choose k such that k' = k + delta
    let k = 0x1234u64;
    let k_scalar = Scalar::from(k);
    let k_prime = k + delta;
    let k_prime_scalar = Scalar::from(k_prime);

    // Compute r1, r2 from k and k'
    let r1_point = ProjectivePoint::GENERATOR * k_scalar;
    let r1_enc = r1_point.to_affine().to_encoded_point(true);
    let r1_bytes = &r1_enc.as_bytes()[1..33];
    let mut r1_arr = [0u8; 32];
    r1_arr.copy_from_slice(r1_bytes);
    let r1_scalar = Scalar::from_repr(r1_arr.into()).unwrap();

    let r2_point = ProjectivePoint::GENERATOR * k_prime_scalar;
    let r2_enc = r2_point.to_affine().to_encoded_point(true);
    let r2_bytes = &r2_enc.as_bytes()[1..33];
    let mut r2_arr = [0u8; 32];
    r2_arr.copy_from_slice(r2_bytes);
    let r2_scalar = Scalar::from_repr(r2_arr.into()).unwrap();

    // Choose z1 and z2 to make the math work out
    // We want: d = alpha * delta + beta
    // where alpha and beta come from precompute(s1, s2, r1, r2, z1, z2)
    //
    // For simplicity, let's use z1 = 1, z2 = 2 and derive what d would be
    // Actually no, d is fixed. Let me use the signature formulas directly:
    // s1 = (z1 + r1*d) / k  => z1 = s1*k - r1*d
    // s2 = (z2 + r2*d) / k' => z2 = s2*k' - r2*d
    //
    // I'll choose z1 and z2 small and see what d we get.
    // Actually, the tool derives d from the signatures, so I need to
    // verify what d the tool will compute.
    //
    // Let me compute alpha, beta from the precompute formula using
    // the derived s1, s2 values, then see what d we get.

    // For simplicity, use z1 = 1, z2 = 2
    let z1_scalar = Scalar::from(1u64);
    let z2_scalar = Scalar::from(2u64);

    // Compute s1 = (z1 + r1*d) / k
    let s1_scalar = (z1_scalar + r1_scalar * d_scalar) * k_scalar.invert().unwrap();

    // Compute s2 = (z2 + r2*d) / k'
    let s2_scalar = (z2_scalar + r2_scalar * d_scalar) * k_prime_scalar.invert().unwrap();

    // Now compute alpha, beta using the precompute formula
    // This is what the tool does internally
    let r1_bn = BigInt::from_bytes_be(Sign::Plus, r1_bytes);
    let r2_bn = BigInt::from_bytes_be(Sign::Plus, r2_bytes);
    let s1_bn = BigInt::from_bytes_be(Sign::Plus, &s1_scalar.to_bytes());
    let s2_bn = BigInt::from_bytes_be(Sign::Plus, &s2_scalar.to_bytes());
    let z1_bn = BigInt::from(1u64);
    let z2_bn = BigInt::from(2u64);

    // precompute formula from main.rs:
    // u = s1^-1 mod n
    // a = (s2 * r1 * u - r2) mod n
    // b = (z2 - s2 * z1 * u) mod n
    // c = s2 mod n
    // a_inv = a^-1 mod n
    // alpha = (-c * a_inv) mod n
    // beta = (b * a_inv) mod n

    let u = mod_inverse(&s1_bn, &n).unwrap();
    let a = normalize(&(s2_bn.clone() * &r1_bn * &u - &r2_bn), &n);
    let b = normalize(&(z2_bn.clone() - s2_bn.clone() * &z1_bn * &u), &n);
    let c = normalize(&s2_bn, &n);
    let a_inv = mod_inverse(&a, &n).unwrap();
    let alpha_bn = normalize(&(-&c * &a_inv), &n);
    let beta_bn = normalize(&(b * &a_inv), &n);

    // The tool searches for delta and computes d = alpha * delta + beta
    let delta_bn = BigInt::from(delta);
    let computed_d = normalize(&(&alpha_bn * &delta_bn + &beta_bn), &n);

    println!("// Generated test data for nonce-cracker");
    println!("// Private key d = 0x{:x}", d);
    println!("// k = 0x{:x}, k' = k + {} = 0x{:x}", k, delta, k_prime);
    println!();
    println!("// Signature 1 (k = 0x{:x}, z1 = 1):", k);
    println!("let r1 = 0x{};", hex::encode(r1_bytes));
    println!("let s1 = 0x{};", hex::encode(s1_scalar.to_bytes()));
    println!("let z1 = 0x0000000000000000000000000000000000000000000000000000000000000001;");
    println!();
    println!("// Signature 2 (k' = 0x{:x}, z2 = 2):", k_prime);
    println!("let r2 = 0x{};", hex::encode(r2_bytes));
    println!("let s2 = 0x{};", hex::encode(s2_scalar.to_bytes()));
    println!("let z2 = 0x0000000000000000000000000000000000000000000000000000000000000002;");
    println!();

    // Public key
    let pk_point = ProjectivePoint::GENERATOR * d_scalar;
    let pk_enc = pk_point.to_affine().to_encoded_point(true);
    let pk_hex = hex::encode(pk_enc.as_bytes());
    println!("let pubkey = \"{}\";", pk_hex);
    println!();

    // Computed alpha and beta
    let (_, alpha_bytes) = alpha_bn.to_bytes_be();
    let (_, beta_bytes) = beta_bn.to_bytes_be();
    println!("// Precomputed values:");
    println!("// alpha = 0x{}", hex::encode(&alpha_bytes));
    println!("// beta = 0x{}", hex::encode(&beta_bytes));
    println!("// delta = {}", delta);
    println!();

    // What the tool will find
    let (_, d_bytes) = computed_d.to_bytes_be();
    println!("// Tool output:");
    println!("// delta = {} (search result)", delta);
    println!(
        "// d = alpha * {} + beta = 0x{}",
        delta,
        hex::encode(&d_bytes)
    );
    println!();

    // Check if it matches
    if computed_d == BigInt::from(d) {
        println!("// SUCCESS: d matches expected value 0x{:x}", d);
    } else {
        println!(
            "// NOTE: computed d = 0x{} != expected d = 0x{:x}",
            hex::encode(&d_bytes),
            d
        );
        println!(
            "// The tool will find delta = {} and recover d = 0x{}",
            delta,
            hex::encode(&d_bytes)
        );
    }

    // Print Rust code
    println!("\n// === Rust code for src/main.rs ===");
    println!("let r1 = parse_hex(\"0x{}\")?;", hex::encode(r1_bytes));
    println!(
        "let s1 = parse_hex(\"0x{}\")?;",
        hex::encode(s1_scalar.to_bytes())
    );
    println!("let z1 = parse_hex(\"0x0000000000000000000000000000000000000000000000000000000000000001\")?;");
    println!("let r2 = parse_hex(\"0x{}\")?;", hex::encode(r2_bytes));
    println!(
        "let s2 = parse_hex(\"0x{}\")?;",
        hex::encode(s2_scalar.to_bytes())
    );
    println!("let z2 = parse_hex(\"0x0000000000000000000000000000000000000000000000000000000000000002\")?;");
    println!("let pk = parse_pubkey(\"{}\")?;", pk_hex);
    println!(
        "let alpha = parse_hex(\"0x{}\")?;",
        hex::encode(&alpha_bytes)
    );
    println!("let beta = parse_hex(\"0x{}\")?;", hex::encode(&beta_bytes));
    println!("search(r1, r2, s1, s2, z1, z2, pk, 0, {}, 1, Some(4), false, \"example.log\", &curve_order)?", delta + 1);
}
