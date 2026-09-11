# Patched k256 fork

This is a vendored copy of [`k256` v0.13.4](https://crates.io/crates/k256/0.13.4)
with a single local addition: two accessor methods on
`k256::ProjectivePoint` so the kangaroo hot path can partition its walk
without paying for a projective-to-affine conversion per iteration.

The added methods are:

```rust
impl ProjectivePoint {
    pub fn projective_x(&self) -> FieldElement { ... }
    pub fn projective_z(&self) -> FieldElement { ... }
}
```

Both are defined in `src/arithmetic/projective.rs`.

## Surface vs upstream

We have trimmed the vendored source to the minimum required by
nonce-cracker. Compared to upstream `k256` v0.13.4, this directory does
NOT contain:

- `src/ecdh.rs`, `src/schnorr.rs`, `src/schnorr/` — gated by features
  (`ecdh`, `schnorr`) that nonce-cracker does not enable.
- `src/test_vectors.rs`, `src/test_vectors/` — only compiled with the
  `test-vectors` feature or under `cfg(test)` for k256 itself.
- `src/arithmetic/hash2curve.rs` — gated by the `hash2curve` feature.
- `src/arithmetic/dev.rs` — dev-only helper used by k256's own tests.
- `benches/` — k256's Criterion benchmarks, not used by nonce-cracker.
- `Cargo.toml.orig` — upstream's pre-normalization Cargo.toml.

The patched crate is wired in via `Cargo.toml`:

```toml
[patch.crates-io]
k256 = { path = "patches/k256" }
```

## Upstreaming

The intended long-term fix is to upstream the `projective_x` /
`projective_z` accessors to `k256` proper. Until that lands, the patch
surface is intentionally small (~3.5K LOC trimmed from the upstream copy
to the arithmetic/ecdsa subset we use).
