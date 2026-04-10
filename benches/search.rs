//! Benchmark for the nonce-cracker search algorithm.
//!
//! Run with: `cargo bench`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar};
use num_bigint::{BigInt, Sign};
use num_traits::{One, Signed, Zero};

const CURVE_ORDER_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

// Minimal function implementations for benchmark isolation

fn parse_bigint_hex(s: &str) -> BigInt {
    let raw = s.trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(raw).expect("valid hex");
    BigInt::from_bytes_be(Sign::Plus, &bytes)
}

fn normalize_modulo(x: &BigInt, n: &BigInt) -> BigInt {
    let r = x % n;
    if r.is_negative() {
        r + n
    } else {
        r
    }
}

fn modular_inverse(a: &BigInt, n: &BigInt) -> Option<BigInt> {
    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = n.clone();
    let mut new_r = normalize_modulo(a, n);

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
    if t.is_negative() {
        t += n;
    }
    Some(t)
}

fn derive_affine_constants(
    r1: &BigInt,
    r2: &BigInt,
    s1: &BigInt,
    s2: &BigInt,
    z1: &BigInt,
    z2: &BigInt,
    n: &BigInt,
) -> Option<(BigInt, BigInt)> {
    let u = modular_inverse(s1, n)?;
    let a = normalize_modulo(&(s2 * r1 * &u - r2), n);
    let b = normalize_modulo(&(z2 - s2 * z1 * &u), n);
    let c = normalize_modulo(s2, n);
    let a_inv = modular_inverse(&a, n)?;
    let alpha = normalize_modulo(&(-&c * &a_inv), n);
    let beta = normalize_modulo(&(b * &a_inv), n);
    Some((alpha, beta))
}

fn bigint_to_scalar_opt(d: &BigInt) -> Option<Scalar> {
    if d.is_negative() {
        return None;
    }
    let (_, bytes) = d.to_bytes_be();
    if bytes.len() > 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr[32 - bytes.len()..].copy_from_slice(&bytes);
    Scalar::from_repr_vartime(arr.into())
}

#[inline(always)]
fn derive_private_key(delta: i64, alpha: Scalar, beta: Scalar) -> Scalar {
    let delta_scalar = Scalar::from(delta.unsigned_abs());
    if delta.is_negative() {
        beta - alpha * delta_scalar
    } else {
        alpha * delta_scalar + beta
    }
}

fn bench_mod_inverse(c: &mut Criterion) {
    let n = parse_bigint_hex(CURVE_ORDER_HEX);
    let a = BigInt::from(7u64);

    c.bench_function("modular_inverse", |b| {
        b.iter(|| modular_inverse(black_box(&a), black_box(&n)).unwrap());
    });
}

fn bench_precompute(c: &mut Criterion) {
    let n = parse_bigint_hex(CURVE_ORDER_HEX);
    let r1 = BigInt::from(1u8);
    let r2 = BigInt::from(2u8);
    let s1 = BigInt::from(3u8);
    let s2 = BigInt::from(4u8);
    let z1 = BigInt::from(5u8);
    let z2 = BigInt::from(6u8);

    c.bench_function("derive_affine_constants", |b| {
        b.iter(|| {
            derive_affine_constants(
                black_box(&r1),
                black_box(&r2),
                black_box(&s1),
                black_box(&s2),
                black_box(&z1),
                black_box(&z2),
                black_box(&n),
            )
            .unwrap()
        });
    });
}

fn bench_scalar_operations(c: &mut Criterion) {
    let alpha = bigint_to_scalar_opt(&parse_bigint_hex(
        "0xa7fa8b4a2944338eee5180dbee8e763334c9c09c5f6450c8e08150714e3bd81b",
    ))
    .unwrap();
    let beta = bigint_to_scalar_opt(&parse_bigint_hex(
        "0x585e5a8c07383473109d225e68d210b5bc791f870357bf1c61fb5dbf6578740e",
    ))
    .unwrap();

    c.bench_function("derive_private_key", |b| {
        b.iter(|| derive_private_key(black_box(42i64), black_box(alpha), black_box(beta)));
    });
}

fn bench_point_multiplication(c: &mut Criterion) {
    let scalar = Scalar::from(1234567890u64);

    c.bench_function("point_multiplication", |b| {
        b.iter(|| ProjectivePoint::GENERATOR * black_box(scalar));
    });
}

fn bench_bigint_to_scalar(c: &mut Criterion) {
    let values: Vec<BigInt> = (0..100).map(|i| BigInt::from(i * 12345)).collect();

    c.bench_function("bigint_to_scalar_opt", |b| {
        b.iter(|| {
            for v in &values {
                black_box(bigint_to_scalar_opt(v));
            }
        });
    });
}

fn bench_search_chunk(c: &mut Criterion) {
    let mut group = c.benchmark_group("search_chunk");

    for size in [1000u64, 10000, 100000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let alpha = bigint_to_scalar_opt(&parse_bigint_hex(
                "0xa7fa8b4a2944338eee5180dbee8e763334c9c09c5f6450c8e08150714e3bd81b",
            ))
            .unwrap();
            let beta = bigint_to_scalar_opt(&parse_bigint_hex(
                "0x585e5a8c07383473109d225e68d210b5bc791f870357bf1c61fb5dbf6578740e",
            ))
            .unwrap();
            let step_scalar = alpha * Scalar::from(1u64);
            let step_point = ProjectivePoint::GENERATOR * step_scalar;

            let mut cur_scalar = derive_private_key(0, alpha, beta);
            let mut point = ProjectivePoint::GENERATOR * cur_scalar;

            b.iter(|| {
                for _ in 0..black_box(size) {
                    point += step_point;
                    cur_scalar += step_scalar;
                }
                black_box((point, cur_scalar))
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_mod_inverse,
    bench_precompute,
    bench_scalar_operations,
    bench_point_multiplication,
    bench_bigint_to_scalar,
    bench_search_chunk,
);

criterion_main!(benches);
