# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Pollard's kangaroo (lambda) method for bounded-range discrete-log search for ranges > 2^48.
- `OpenMap`: custom open-addressing hash map reducing BSGS memory by ~25%.
- Algorithm dispatch heuristic: parallel scan / BSGS / kangaroo based on range size.
- `CryptoError::RNotInvertible` for single-signature derivation when `r` has no inverse.
- ECDSA signature verification (`verify_ecdsa_signature`) before search to prevent wasted computation.
- `EngineError::ThreadCountZero` guard against `threads=0`.
- `EngineError::KangarooTimeout` for iteration limit exceeded in kangaroo search.
- Support for decimal input in `parse_scalar` (previously hex-only).
- `examples/bench_bsgs.rs`: End-to-end BSGS benchmark for random nonces in configurable ranges (2^32 to 2^52).

### Changed
- BSGS_MAX_M increased from 2^26 to 2^27 (~10 GB).
- Migrated BSGS baby-step table from `FxHashMap` to `OpenMap`.
- **Algorithm**: Replaced two-signature affine-relation attack with a single-signature nonce search.
  - Derivation now uses one signature: `alpha = r^(-1) * s`, `beta = -r^(-1) * z`, so `d = alpha * k + beta  (mod n)`.
  - The search finds the nonce `k` directly instead of the inter-signature delta.
  - All core search infrastructure (parallel scan, BSGS) is unchanged; only the parameter setup changed.
- **CLI**: `run` command now accepts `--r`, `--s`, `--z` (single signature) instead of `--r1`, `--r2`, `--s1`, `--s2`, `--z1`, `--z2`.
- **API**: Removed `SignaturePair`; `derive_affine_constants` now takes `&Signature`. Renamed `SearchOutcome.delta` to `nonce`.

### Removed
- `SignaturePair` domain type and two-signature fixture helpers.
- `CryptoError::S1NotInvertible` and `CryptoError::DenominatorNotInvertible` (replaced by `RNotInvertible`).

### Fixed
- Division-by-zero in `parallel::scan` when `thread_count == 0`.
- `u64` overflow in BSGS offset computation by using two scalar multiplications instead of `chunk_start * m`.
- `ConfigError` visibility issue in public re-exports.

### Optimized
- **Lock-free parallel scan**: Replaced `AtomicBool` + `Mutex<Option<i128>>` with a single `AtomicU64` sentinel, eliminating mutex contention.
- **Per-chunk scalar-mult elimination**: Precompute `base_point = G * derive_private_key(start, alpha, beta)` once, then compute chunk start points via point addition (`base_point + chunk_start * step_point`) instead of per-chunk scalar multiplication.
- **BSGS batch size tuning**: Increased giant-step batch size from 4096 to 8192, better amortizing Montgomery's trick in `batch_normalize`.

## [0.2.0] - 2026-04-10

### Added
- Hybrid search algorithm: automatically dispatches to parallel scan for N <= 2^32 candidates or parallel Baby-Step Giant-Step (BSGS) for 2^32 < N < 2^64 candidates.
- Parallel BSGS implementation with thread-local baby-step hash maps, merged into a single lookup table.
- Batched projective-to-affine normalization via `ProjectivePoint::batch_normalize` to amortize field inversion cost in BSGS.
- Identity point handling in BSGS to avoid division-by-zero during batch normalization.
- BSGS memory guard: `BSGS_MAX_M = 2^26` (~5 GB max), preventing unbounded memory usage.
- Edge-case handling for `step_scalar == 0` (all candidates identical), short-circuiting without search.
- Unit test `test_bsgs_small_range` verifying BSGS correctness directly.
- Signed bounded-delta search support, including negative CLI bounds and matching unit/integration coverage.
- Deterministic default log-file naming with collision-resistant uniqueness within a process.
- Formal derivation notes for the affine relation used by the recovery algorithm.
- CLI integration coverage for `run`, `recover`, and the bundled example workflow.
- Benchmark and sample-data consistency updates to keep generated ECDSA fixtures mathematically valid.

### Changed
- Replaced arbitrary-precision BigInt arithmetic with native secp256k1 `Scalar` operations via `k256`, eliminating conversion overhead.
- Replaced per-iteration `to_affine().to_encoded_point()` (field inversion, ~20us) with direct projective point equality comparison (~67ns), a ~300x hot-loop speedup.
- Extracted scan logic into `parallel_scan()` function and search dispatch into `search()` for clarity.
- Simplified logging to compact format only; removed JSON and pretty format branches.
- Streamlined `Config` to `max_threads`, `log_dir`, and `version` only.
- Streamlined `SearchMetrics` to `start` and `threads` only.
- Replaced `i128` arithmetic in inner loop with `i64::wrapping_add` for performance.
- Reduced atomic polling frequency to once per 1024 iterations to eliminate cache-line bouncing.
- Unified CLI to single `run` command; removed `recover` subcommand.
- Consolidated CLI parsing and search execution into a shared validation path.
- Clarified public Rustdoc for the command surface and the core search helpers.
- Standardized search output formatting to use signed delta reporting.
- Aligned benchmark helpers with the production signed-delta model.

### Fixed
- Corrected import of `BatchNormalize` trait to resolve `batch_normalize` usage.
- Handled identity point explicitly in BSGS to prevent `batch_normalize` panic on zero-Z coordinates.
- Fixed `resolve_path` to recognize Unix-style absolute paths (`/path`) on Windows via `p.starts_with('/')` check.
- Rejected invalid empty output paths before file creation.
- Accepted negative numeric CLI bounds as literal values instead of treating them as options.
- Corrected public-key validation to enforce full SEC1 decoding for uncompressed keys.
- Removed the possibility of default log-file collisions within one process.

### Breaking Changes
- The default demo command is now `example` instead of the previous `demo` naming used in earlier revisions.
- Search range arguments now accept signed values explicitly; callers relying on unsigned-only assumptions must update their invocation patterns.

## [0.1.0] - 2024-01-01

### Added
- Initial release
- Parallel ECDSA key search using affine relation attack
- Support for secp256k1 signatures
- Parallel processing with Rayon
- CLI interface with clap
- Unit tests for core cryptographic functions
- Example mode for quick demonstration
