# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- `Signature` no longer implements `Copy`; it implements `Zeroize` + `Drop` to clear sensitive scalars from memory on drop.
- `SearchOutcome` no longer implements `Clone`; it implements `Zeroize` + `Drop` to prevent duplicated secrets.
- Zeroize temporary `r_inv` and nonce scalars in `derive_affine_constants` and `derive_private_key`.
- Zeroize the recovered private key `d` in `write_outcome` after logging.

### Added
- Deterministic seeded RNG for Pollard's kangaroo: seed derived from `alpha ^ beta ^ start ^ step` ensures reproducible walks.
- `KangarooParams::new` constructor validates `d` range `[1, 264]` and `max_iterations > 0`.
- BSGS automatic fallback to kangaroo when the expected baby-step memory exceeds 8 GB.
- Cross-platform signal handling via `ctrlc` crate replaces Unix-only `signal_hook`.
- `debug_assert!` verifying `IDENTITY_KEY` matches `AffinePoint::IDENTITY` encoding.
- Explicit prime-order assumption documentation in BSGS identity-point sentinel.
- Expected memory check in BSGS before table allocation.
- Minimal checkpoint/resume scaffolding: `Checkpoint` struct with text serialization, `NONCE_CRACKER_CHECKPOINT_DIR` config, and write/remove around `SearchEngine::search`.
- Property-based tests (`proptest`) for `OpenMap` round-trip, `parse_int`, and `derive_private_key` invariants.
- `cargo-fuzz` harness under `fuzz/` with targets for `parse_scalar`, `parse_pubkey`, `parse_int`, and `openmap`.
- Local `patches/k256/` fork exposing `ProjectivePoint::projective_x()` and `projective_z()` accessors to enable projective-coordinate hashing in the kangaroo hot path.

### Changed
- **BSGS baby-step table is now sharded**: per-thread `OpenMap`s are kept separate; giant-step lookups scan all shards. Eliminates the 2× memory peak from sequential merging.
- `SearchOutcome` no longer implements `Copy` (implements `Zeroize` + `Drop` instead).
- `GiantStepParams.baby_map` renamed to `baby_maps` and changed to `&[OpenMap]`.
- **Pollard's kangaroo no longer converts to affine on every step**: `kangaroo_step` now hashes the projective `(X, Z)` pair via a minimal k256 patch (`projective_x` / `projective_z` accessors) to select the jump size.  Affine conversion only happens when storing or checking a distinguished point.  Eliminates ~2 field inversions per loop iteration (~100× speedup on the hot path).
- **Affine relation updated to positive-beta formulation**: `beta = r^-1 * z` (positive), `d = alpha * k - beta`.  `derive_affine_constants` and `derive_private_key` updated accordingly.  Documentation (`README.md`, `docs/affine-relation-derivation.md`) aligned.
- **Compact `OpenMap` keys**: BSGS baby-step table now stores 128-bit key prefixes instead of full 33-byte compressed points, reducing entry size from ~72 bytes to ~24 bytes (~3× memory reduction).  Collision probability is `m² / 2¹²⁹` (negligible); any false positive is caught by cryptographic verification.
- **Auto-tuned kangaroo `d` parameter**: distinguished-point bit density is now computed as `log2(threads * sqrt(N) / 1000)` and clamped to `[8, 24]`, balancing memory and collision probability per range size instead of using a fixed `d=16`.

### Fixed
- `file.try_clone().expect()` panic in logging replaced with `LogWriter` enum and `io::Sink` fallback.
- Removed dead `bsgs_max_m` test-only field from production `SearchEngine` struct.
- Removed dead segmented BSGS code path (quadratic blowup).
- `OpenMap::insert` auto-grows table at 0.7 load factor instead of panicking on saturation.
- **Checkpoint I/O no longer silently swallowed**: `write` failures are logged with `warn!`; `remove` returns `io::Result<()>` and failures are logged.
- **Hardened checkpoint deserialization**: `Checkpoint::read_from` now rejects malformed lines, unknown keys, and missing required fields instead of silently substituting defaults.
- **Signal-handler failure is fatal**: `ctrlc::set_handler` error now exits the process instead of logging and continuing without graceful shutdown.
- **Logging Sink fallback is visible**: emits a one-time `eprintln!` warning when the log file descriptor cannot be cloned.
- **Stdout write failures are visible**: `emit_summary` now logs a `warn!` when `writeln!` to stdout fails (e.g. broken pipe).
- **RwLock poisoning no longer aborts**: kangaroo DP table locks use `unwrap_or_else(|e| e.into_inner())` to recover from poisoned locks instead of panicking.
- **Rayon thread panics eliminated**: `.expect()` calls inside BSGS and parallel-scan closures replaced with `let else` early returns that log a warning and skip the thread.
- **Kangaroo overflow paths are visible**: `tame_dist` and `wild_dist` `u64` overflows, and `step * delta` `i128` overflows, are logged with `warn!` instead of silently breaking the walk.
- **BSGS reconstruct_nonce overflow is visible**: `i128::try_from(candidate)` failure is logged with `warn!` instead of silently returning `None`.
- **Atomic report-file writes**: `run_search` and `run_example` write to a temp file and `rename` atomically on success, preventing empty/corrupted report files on crash.
- **Explicit CAS race documentation**: all `compare_exchange` return-value discards in scan, BSGS, and kangaroo are annotated with comments explaining the benign race.

## [0.6.0] - 2026-05-15

### Added
- Pollard's kangaroo (lambda) method for bounded-range discrete-log search for ranges > 2^48.
- `OpenMap`: custom open-addressing hash map reducing BSGS memory by ~25%.
- Algorithm dispatch heuristic: parallel scan / BSGS / kangaroo based on range size.
- `CryptoError::RNotInvertible` for single-signature derivation when `r` has no inverse.
- ECDSA signature verification (`verify_ecdsa_signature`) before search to prevent wasted computation.
- `EngineError::ThreadCountZero` guard against `threads=0`.
- `EngineError::KangarooTimeout` for iteration limit exceeded in kangaroo search.
- Support for decimal input in `parse_scalar` (previously hex-only).
- `examples/bench_bsgs.rs`: end-to-end BSGS benchmark for random nonces in configurable ranges (2^32 to 2^52).

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
