use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use k256::{elliptic_curve::PrimeField, ProjectivePoint, Scalar};

fn derive_affine_constants(
    r1: Scalar,
    r2: Scalar,
    s1: Scalar,
    s2: Scalar,
    z1: Scalar,
    z2: Scalar,
) -> Option<(Scalar, Scalar)> {
    let u: Scalar = Option::<Scalar>::from(s1.invert())?;
    let a: Scalar = s2 * r1 * u - r2;
    let b: Scalar = z2 - s2 * z1 * u;
    let c: Scalar = s2;
    let a_inv: Scalar = Option::<Scalar>::from(a.invert())?;
    let alpha: Scalar = -(c * a_inv);
    let beta: Scalar = b * a_inv;
    Some((alpha, beta))
}

#[inline(always)]
fn derive_private_key(delta: i64, alpha: Scalar, beta: Scalar) -> Scalar {
    let delta_scalar = Scalar::from(delta.unsigned_abs());
    if delta < 0 {
        beta - alpha * delta_scalar
    } else {
        alpha * delta_scalar + beta
    }
}

fn bench_scalar_invert(c: &mut Criterion) {
    let scalar = Scalar::from(123456789u64);
    c.bench_function("scalar_invert", |b| {
        b.iter(|| black_box(&scalar).invert());
    });
}

fn bench_precompute(c: &mut Criterion) {
    let r1 = Scalar::from(1u64);
    let r2 = Scalar::from(2u64);
    let s1 = Scalar::from(3u64);
    let s2 = Scalar::from(4u64);
    let z1 = Scalar::from(5u64);
    let z2 = Scalar::from(6u64);

    c.bench_function("derive_affine_constants", |b| {
        b.iter(|| {
            derive_affine_constants(
                black_box(r1),
                black_box(r2),
                black_box(s1),
                black_box(s2),
                black_box(z1),
                black_box(z2),
            )
        });
    });
}

fn parse_scalar_hex(s: &str) -> Scalar {
    let bytes: [u8; 32] = hex::decode(s).unwrap().try_into().unwrap();
    Scalar::from_repr(bytes.into()).unwrap()
}

fn bench_scalar_operations(c: &mut Criterion) {
    let alpha =
        parse_scalar_hex("a7fa8b4a2944338eee5180dbee8e763334c9c09c5f6450c8e08150714e3bd81b");
    let beta = parse_scalar_hex("585e5a8c07383473109d225e68d210b5bc791f870357bf1c61fb5dbf6578740e");

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

fn bench_search_chunk(c: &mut Criterion) {
    let mut group = c.benchmark_group("search_chunk");

    for size in [1000u64, 10000, 100000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let alpha = parse_scalar_hex(
                "a7fa8b4a2944338eee5180dbee8e763334c9c09c5f6450c8e08150714e3bd81b",
            );
            let beta = parse_scalar_hex(
                "585e5a8c07383473109d225e68d210b5bc791f870357bf1c61fb5dbf6578740e",
            );
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
    bench_scalar_invert,
    bench_precompute,
    bench_scalar_operations,
    bench_point_multiplication,
    bench_search_chunk,
);
criterion_main!(benches);
