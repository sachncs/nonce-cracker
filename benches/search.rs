//! Criterion benchmarks for core cryptographic and search operations.
//!
//! Covers scalar inversion, affine-constant derivation, candidate-key
//! computation, point multiplication, and chunked search throughput.
//!
//! ## Running
//!
//! ```bash
//! cargo bench
//! ```
//!
//! Results are written to `target/criterion/` and can be viewed by opening
//! `target/criterion/report/index.html`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use k256::{ProjectivePoint, Scalar};
use nonce_cracker::{derive_affine_constants, derive_private_key};
use nonce_cracker::search::openmap::OpenMap;

fn bench_scalar_invert(c: &mut Criterion) {
    let scalar = Scalar::from(123_456_789_u64);
    c.bench_function("scalar_invert", |b| {
        b.iter(|| black_box(&scalar).invert());
    });
}

fn bench_derive_affine_constants(c: &mut Criterion) {
    let r = Scalar::from(1u64);
    let s = Scalar::from(3u64);
    let z = Scalar::from(5u64);
    let sig = nonce_cracker::Signature::new(r, s, z);

    c.bench_function("derive_affine_constants", |b| {
        b.iter(|| derive_affine_constants(black_box(&sig)).unwrap());
    });
}

fn bench_derive_private_key(c: &mut Criterion) {
    let alpha = Scalar::from(3u64);
    let beta = Scalar::from(7u64);

    c.bench_function("derive_private_key", |b| {
        b.iter(|| derive_private_key(black_box(42i128), black_box(alpha), black_box(beta)));
    });
}

fn bench_point_multiplication(c: &mut Criterion) {
    let scalar = Scalar::from(1_234_567_890_u64);
    c.bench_function("point_multiplication", |b| {
        b.iter(|| ProjectivePoint::GENERATOR * black_box(scalar));
    });
}

fn bench_search_chunk(c: &mut Criterion) {
    let mut group = c.benchmark_group("search_chunk");

    for size in &[1_000_u64, 10_000, 100_000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let alpha = Scalar::from(3u64);
            let beta = Scalar::from(7u64);
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

fn bench_openmap(c: &mut Criterion) {
    let mut group = c.benchmark_group("openmap");
    for size in [1000, 10_000, 100_000, 1_000_000].iter() {
        group.bench_with_input(BenchmarkId::new("insert_get", size), size, |b, &size| {
            let mut map = OpenMap::with_capacity(size);
            for i in 0..size {
                let mut key = [0u8; 33];
                key[..8].copy_from_slice(&(i as u64).to_le_bytes());
                map.insert(key, i as u128);
            }
            b.iter(|| {
                let mut key = [0u8; 33];
                key[..8].copy_from_slice(&(42u64).to_le_bytes());
                map.get(&key)
            });
        });
    }
    group.finish();
}

// TODO: Add kangaroo vs BSGS benchmark. This requires setting up a SearchEngine
// and ScanParams, which is complex enough to defer to a follow-up task.

criterion_group!(
    benches,
    bench_scalar_invert,
    bench_derive_affine_constants,
    bench_derive_private_key,
    bench_point_multiplication,
    bench_search_chunk,
    bench_openmap,
);
criterion_main!(benches);
