<p align="center">
  <h1 align="center">nonce-cracker</h1>
  <p align="center">High-speed parallel ECDSA private key recovery for secp256k1 using a single-signature affine relation attack.</p>
  <p align="center">
    <a href="#installation"><img src="https://img.shields.io/badge/rust-1.75%20%7C%20stable-orange?logo=rust" alt="Rust"></a>
    <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-green" alt="License"></a>
    <a href="https://github.com/sachncs/nonce-cracker/actions"><img src="https://img.shields.io/github/actions/workflow/status/sachncs/nonce-cracker/ci.yml?branch=master" alt="CI"></a>
    <a href="https://crates.io/crates/nonce-cracker"><img src="https://img.shields.io/crates/v/nonce-cracker" alt="crates.io"></a>
    <a href="https://docs.rs/nonce-cracker"><img src="https://img.shields.io/docsrs/nonce-cracker" alt="docs.rs"></a>
    <a href="https://github.com/sachncs/nonce-cracker/stargazers"><img src="https://img.shields.io/github/stars/sachncs/nonce-cracker" alt="Stars"></a>
  </p>
</p>

**nonce-cracker** recovers private keys from a single ECDSA signature when the nonce is within a known search range. From the signature equation:

```
s = k^-1(z + r * d)  (mod n)
```

the private key can be rewritten as:

```
d = alpha * k - beta  (mod n)
```

where `alpha = r^-1 * s` and `beta = r^-1 * z`. The tool precomputes these affine constants, then searches for the nonce `k` using a highly optimized parallel scan (for ranges up to 2^32 candidates), a parallel Baby-Step Giant-Step (BSGS) algorithm (for medium ranges up to 2^52 candidates), or Pollard's kangaroo (for massive ranges up to 2^64 candidates).

---

## Features

- **Hybrid search algorithm** — Parallel scan for small ranges (N <= 2^32), parallel BSGS for medium ranges (2^32 < N <= 2^52), Pollard's kangaroo for massive ranges (N > 2^52)
- **Parallel search** across CPU cores via Rayon (work-stealing scheduler)
- **Pollard's kangaroo** for massive ranges (> 2^52 candidates) with O(sqrt(N)) time and O(sqrt(N) / 2^d) memory; projective-coordinate hashing eliminates per-step field inversions; auto-tuned `d` parameter balances memory and collision probability
- **OpenMap** custom hash map reducing BSGS memory by ~25%
- **Native secp256k1 arithmetic** using `k256` crate (no BigInt overhead)
- **Fast point comparison** using projective coordinates (no field inversion in any hot loop)
- **Configurable search range** with decimal or hex notation, including negative bounds
- **Single CLI interface** — `run` command with ECDSA signature values
- **Thread count control** with automatic CPU detection fallback
- **Graceful shutdown** handling for SIGINT/SIGTERM signals (cross-platform via `ctrlc`)
- **Sensitive-value zeroization** of scalars via `Zeroize` + `Drop` on `SearchOutcome` and temporary intermediates
- **Checkpoint/resume scaffolding** — Writes a plaintext checkpoint before search and removes it on completion
- **Structured logging** with `tracing` (compact format)
- **Configuration management** via environment variables
- **Performance metrics** collection and reporting
- **Docker support** with multi-stage builds
- **CI/CD pipeline** with GitHub Actions (build, test, security audit)
- **Dependency security** auditing with `cargo-deny`

---

## Installation

### From crates.io

```bash
cargo install nonce-cracker
```

### From source

```bash
git clone https://github.com/sachncs/nonce-cracker.git
cd nonce-cracker
cargo build --release
./target/release/nonce-cracker --help
```

### With Make

```bash
make build    # Release build
make test     # Run tests
make clippy   # Run lints
```

### Quick Setup

```bash
./setup.sh    # Verify toolchain, create dirs, build release binary
./cleanup.sh  # Remove build artifacts, logs, checkpoints, temp files
```

**Requirements**: Rust 1.75+ (stable). macOS, Linux, Windows (any platform with
Rust support). Multi-core CPU recommended for parallel search.

---

## Quick Start

### CLI

```bash
# 1. Run the self-contained demonstration that recovers a known private key.
nonce-cracker example

# 2. Search a custom range for a candidate private key.
nonce-cracker run \
  --r 0x37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba \
  --s 0xe026eb94e61bcdc41f0ee8cd7b97eda899ce5856d3a32360d742b13d717ff2a8 \
  --z 0x0000000000000000000000000000000000000000000000000000000000000001 \
  --pubkey 03f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f \
  --start 0 \
  --end 10000
```

### Rust API

```rust
use nonce_cracker::prelude::*;

let signature = Signature::from_hex("0x..", "0x..", "0x..")?;
let public_key = PublicKey::parse("02..")?;
let (alpha, beta) = derive_affine_constants(&signature)?;

let outcome = SearchEngine::new(SearchSpec::new(0, 10000, 1))
    .run(&alpha, &beta, &public_key)?;

if let SearchOutcome::Found { private_key, .. } = outcome {
    println!("recovered: {:?}", private_key);
}
```

---

## Configuration

### Global options

| Flag | Description |
|------|-------------|
| `-h`, `--help` | Print help |
| `-V`, `--version` | Print version |

### Command options

| Flag | Description | Default |
|------|-------------|---------|
| `--r <HEX>` | R coordinate of the signature | Required |
| `--s <HEX>` | S value of the signature | Required |
| `--z <HEX>` | Message hash | Required |
| `--pubkey <HEX>` | Target public key (uncompressed or compressed) | Required |
| `--start <NUM>` | Search range start (decimal or `0x` hex) | `0` |
| `--end <NUM>` | Search range end | `0x1000000000000000` (2^60) |
| `--step <NUM>` | Search step size | `1` |
| `--threads <NUM>` | Worker thread count | CPU core count |
| `--quiet` | Suppress console output | `false` |
| `--outfile <PATH>` | Search report file name or path | `search.log` |

### Logging environment variables

| Setting | Env Variable | Default |
|---------|--------------|---------|
| Log directory | `NONCE_CRACKER_LOG_DIR` | `logs/` |
| Log level | `NONCE_CRACKER_LOG_LEVEL` | `info` |
| Console output | `NONCE_CRACKER_LOG_CONSOLE` | `true` |
| Checkpoint directory | `NONCE_CRACKER_CHECKPOINT_DIR` | `checkpoints/` |

Relative `--outfile` values are resolved inside the configured log directory.
Absolute paths are still accepted for explicit overrides.

### Input formats

**Signature values** (`r`, `s`, `z`):
- Hex with `0x` prefix: `0x59b22000...`
- Hex without prefix: `59b22000...`
- Odd-length hex is auto-padded: `0xFFF` → `0x0FFF`
- Decimal: `12345678901234567890`

**Public key**:
- Uncompressed: `04` + x (32 bytes) + y (32 bytes) → 130 hex chars
- Compressed even y: `02` + x (32 bytes) → 66 hex chars
- Compressed odd y: `03` + x (32 bytes) → 66 hex chars

**Range values** (`start`, `end`, `step`):
- Decimal: `1000000`
- Hex: `0xFF`
- Negative: `-10`

---

## API

| Symbol | Type | Description |
|--------|------|-------------|
| `Signature` | struct | Parsed ECDSA signature `(r, s, z)` |
| `PublicKey` | struct | Parsed compressed or uncompressed pubkey |
| `SearchSpec` | struct | Search range + step |
| `SearchEngine` | struct | Three-tier dispatch over scan / BSGS / kangaroo |
| `derive_affine_constants` | function | Compute `alpha`, `beta` from a single signature |
| `derive_private_key` | function | Compute `d = alpha*k − beta` from a candidate `k` |
| `ScanParams` | struct | Parameters for the parallel-scan algorithm |
| `GiantStepParams` | struct | Parameters for the parallel-BSGS algorithm |
| `KangarooParams` | struct | Parameters for Pollard's kangaroo |
| `OpenMap` | struct | Open-addressing hash map (~25% memory savings) |
| `SearchOutcome` | enum | `Found` / `Exhausted` / `Error` (with `Zeroize`) |

---

## Examples

### Run the demonstration

```bash
nonce-cracker example
```

This runs a self-contained demonstration that recovers private key `0x3039`
by searching a known nonce range. It proves the tool works correctly with
verifiable output.

### Search a small range

```bash
nonce-cracker run \
  --r 0x37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba \
  --s 0xe026eb94e61bcdc41f0ee8cd7b97eda899ce5856d3a32360d742b13d717ff2a8 \
  --z 0x0000000000000000000000000000000000000000000000000000000000000001 \
  --pubkey 03f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f \
  --start 0 --end 10000 --threads 8 --outfile results.log
```

### Run the BSGS end-to-end benchmark

```bash
cargo run --example bench_bsgs --release -- 48
```

### Headless scripted use

```bash
NONCE_CRACKER_LOG_CONSOLE=false \
nonce-cracker run --r 0x... --s 0x... --z 0x... --pubkey 02... \
  --start 0x0 --end 0x100000000 --threads 16
```

---

## Architecture

The repository is organized around a single binary crate with a streamlined, production-ready layout:

- `src/main.rs` — CLI parsing, signature validation, affine-constant derivation, hybrid search orchestration (parallel scan + BSGS + kangaroo), and graceful shutdown handling.
- `src/lib.rs` — Public API and module re-exports.
- `src/logging.rs` — Structured logging backend using `tracing` with compact output format.
- `src/config.rs` — Centralized configuration management with environment variable support.
- `src/checkpoint.rs` — Minimal checkpoint/resume scaffolding for long searches.
- `tests/integration.rs` — End-to-end CLI tests including logging behavior and signed-range handling.
- `benches/search.rs` — Criterion benchmarks for core cryptographic operations.
- `examples/demo.rs` — Usage demonstration.
- `examples/generate.rs` — Test data generator.
- `examples/bench_bsgs.rs` — End-to-end BSGS performance benchmark for large ranges (2^32 to 2^52).
- `docs/` — Architecture documentation and deployment guides.
- `fuzz/` — `cargo-fuzz` harnesses for parsing and OpenMap.
- `patches/k256/` — Local fork of `k256` v0.13 with `projective_x` / `projective_z` accessors for the kangaroo hot-path optimization.

Data flow is intentionally linear:

1. CLI arguments are parsed and validated.
2. Signature values are converted to secp256k1 `Scalar`s and public keys to `PublicKey`.
3. `derive_affine_constants` produces the affine parameters `alpha` and `beta`.
4. The search dispatches to the optimal algorithm based on range size:
   - `N <= 2^32`: Parallel scan with batched point comparison
   - `2^32 < N <= 2^52`: Parallel BSGS with batched normalization and compact OpenMap baby-step table
   - `N > 2^52`: Pollard's kangaroo (lambda) with O(sqrt(N)) time and O(sqrt(N) / 2^d) memory
5. Each worker evaluates candidate nonce values, compares the resulting public key against the target, and stops on the first match.
6. Recent optimizations include lock-free scan coordination, per-chunk scalar-mult elimination, and tuned BSGS batch normalization (8192 points/batch).
7. Matching results are written to the report file and summarized through the centralized logger.

This architecture minimizes shared mutable state, keeps the cryptographic
math isolated from logging concerns, and makes the CLI / test / benchmark
surfaces align with the same search contract.

### Module overview

- **CLI** (`main.rs`, `cli.rs`): Command-line argument parsing via `clap`, search orchestration
- **Checkpoint** (`checkpoint.rs`): Plain-text checkpoint serialization and file management
- **Crypto** (`crypto.rs`): `derive_affine_constants`, `derive_private_key`, scalar and point math
- **Search** (`src/search/`):
  - `mod.rs` — `SearchEngine` with three-tier dispatch (scan / BSGS / kangaroo)
  - `parallel.rs` — Parallel brute-force scan for ranges ≤ 2^32
  - `bsgs.rs` — Baby-Step Giant-Step with batched normalization and `OpenMap`
  - `kangaroo.rs` — Pollard's kangaroo (lambda) for bounded-range search > 2^52
  - `openmap.rs` — Open-addressing hash map replacing `FxHashMap`, ~25% memory savings
  - `params.rs` — `ScanParams`, `GiantStepParams`, `KangarooParams`

### Mathematical Guarantees

- The search window is inclusive and `step` must be strictly positive.
- `end` must be greater than or equal to `start`.
- If `r` is not invertible modulo the curve order, the affine system does not admit a unique solution and the search returns an error.
- Empty report paths are rejected before file creation.
- BSGS requires `m <= 2^27` (~134 million baby steps, ~10 GB memory with OpenMap). If the expected memory exceeds the 8 GB guard, the engine automatically falls back to Pollard's kangaroo.

---

## Project Structure

```
nonce-cracker/
├── src/
│   ├── main.rs          # Binary entry point, CLI, search logic
│   ├── lib.rs           # Public API and module re-exports
│   ├── cli.rs           # Command-line argument definitions
│   ├── crypto.rs        # ECDSA affine constants, scalar/point operations
│   ├── config.rs        # Configuration management
│   ├── domain.rs        # Core types: Signature, SearchSpec, SearchOutcome
│   ├── error.rs         # Structured error types
│   ├── fixtures.rs      # Test fixtures
│   ├── logging.rs       # Structured logging backend
│   ├── context.rs       # Shutdown token
│   └── search/
│       ├── mod.rs       # SearchEngine and algorithm dispatch
│       ├── parallel.rs  # Parallel scan for small ranges
│       ├── bsgs.rs      # Baby-Step Giant-Step
│       ├── kangaroo.rs  # Pollard's kangaroo for massive ranges
│       ├── openmap.rs   # Custom open-addressing hash map
│       ├── params.rs    # Search parameter structs
│       └── tests.rs     # Search algorithm unit tests
├── tests/
│   └── integration.rs   # End-to-end CLI tests
├── benches/
│   └── search.rs        # Criterion benchmarks
├── fuzz/
│   └── fuzz_targets/    # cargo-fuzz / libfuzzer harnesses
├── patches/
│   └── k256/            # Local k256 fork with projective accessor patch
├── examples/
│   ├── demo.rs          # Usage demonstration
│   ├── generate.rs      # Test data generator
│   └── bench_bsgs.rs    # End-to-end BSGS benchmark
├── docs/
│   ├── affine-relation-derivation.md  # Mathematical derivation
│   ├── DEPLOYMENT.md                  # Deployment guide
│   └── faq.md                         # Frequently asked questions
├── .github/
│   ├── workflows/ci.yml              # CI/CD pipeline
│   ├── dependabot.yml                # Dependency auto-updates
│   ├── FUNDING.yml                   # Sponsorship links
│   ├── PULL_REQUEST_TEMPLATE.md      # PR template
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.md             # Bug report template
│       └── feature_request.md        # Feature request template
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── deny.toml                         # cargo-deny configuration
├── Dockerfile                        # Multi-stage Docker build
├── Makefile                          # Convenience commands
├── setup.sh                          # Quick setup script
├── cleanup.sh                        # Build artifact cleanup
├── LICENSE-MIT
├── LICENSE-APACHE
├── README.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
├── CHANGELOG.md
├── .editorconfig
├── .gitignore
└── .gitattributes
```

---

## Development

```bash
# Build (debug)
cargo build

# Build (release)
cargo build --release

# Run all tests
cargo test

# Lint
cargo clippy --all-targets -- -D warnings

# Format
cargo fmt --all

# Security audit
cargo deny check
```

---

## Algorithm

### ECDSA signatures

In ECDSA, a signature `(r, s)` is computed as:

```
r = (k * G).x mod n
s = k^-1(z + r * d) mod n
```

Where:
- `k` is the nonce (ephemeral key)
- `G` is the generator point
- `n` is the curve order (secp256k1)
- `d` is the private key
- `z` is the message hash

Rearranging for `d`:

```
d = r^-1 * s * k - r^-1 * z  (mod n)
d = alpha * k - beta          (mod n)
```

where `alpha = r^-1 * s` and `beta = r^-1 * z`.

Given the public key `Q = d * G`:

```
Q = (alpha * k - beta) * G
Q + beta * G = alpha * k * G
```

The tool searches for `k` in `[start, end]` such that `k * (alpha * G) = Q + beta * G`.

### Search algorithm

The tool:
1. Parses and validates the signature, public key, and search bounds.
2. Derives `alpha` and `beta` from the single signature equation.
3. Computes the total number of candidates `N = floor((end - start) / step) + 1`.
4. Dispatches to the optimal search algorithm based on `N`:
   - **Parallel scan** (`N <= 2^32`): Partitions the range across worker threads. Each thread evaluates candidates in batches of 1024, using projective point addition and equality comparison (no field inversion in the hot loop).
   - **Parallel BSGS** (`2^32 < N <= 2^52`): Computes `m = ceil(sqrt(N))` baby steps in parallel, storing them in a compact OpenMap keyed by 128-bit point prefixes. Giant steps are then evaluated in parallel with batched projective-to-affine normalization (amortized inversion cost).
   - **Pollard's kangaroo** (`N > 2^52`): Runs a parallel distinguished-point random walk with expected O(sqrt(N)) group operations and O(sqrt(N) / 2^d) memory.
5. Stops on the first match, writes the report file, and emits a structured summary line.

### Invariants and failure modes

- The search window is inclusive and `step` must be strictly positive.
- `end` must be greater than or equal to `start`.
- If `r` is not invertible modulo the curve order, the affine system does not admit a unique solution and the search returns an error.
- Empty report paths are rejected before file creation.
- BSGS requires `m <= 2^27` (~134 million baby steps, ~10 GB memory with OpenMap). If the expected memory exceeds the 8 GB guard, the engine automatically falls back to Pollard's kangaroo.

### Complexity

**Parallel scan (N <= 2^32):**
- **Time:** O(N) candidate evaluations in the worst case.
- **Space:** O(1) worker-local state, plus the report file and bounded coordination state.
- **Parallelism:** Work is distributed across a dedicated Rayon pool, so wall-clock time scales with the number of useful CPU cores.

**Parallel BSGS (2^32 < N <= 2^52):**
- **Time:** O(sqrt(N)) point operations in the worst case.
- **Space:** O(sqrt(N)) for the baby-step hash map (~3 GB max at N = 2^52 with compact OpenMap).
- **Parallelism:** Both baby steps and giant steps are computed in parallel. Baby-step tables are kept sharded; giant-step lookups scan all shards, eliminating the 2× memory peak from sequential merging.

**Pollard's Kangaroo (N > 2^52):**
- **Time:** O(sqrt(N)) group operations in expectation.
- **Space:** O(sqrt(N) / 2^d) for distinguished points (~50 MB at N = 2^56 with d=16).
- **Parallelism:** Near-linear scaling with thread count.

### Performance

Measured on Apple M4 (12 cores):

| Range size | Algorithm | Wall time | Memory |
|------------|-----------|-----------|--------|
| 2^32 | Parallel scan | ~14 ms | ~10 MB |
| 2^48 | BSGS | ~3.1 s | ~0.5 GB |
| 2^52 | BSGS | ~112 s | ~3 GB |
| 2^56 | Kangaroo | ~2–5 s | ~10–50 MB |

- **Per thread (scan)**: ~5-10 million keys/second (varies by hardware)
- **Per thread (BSGS giant steps)**: ~1-2 million batch-normalized points/second
- **Scaling**: Near-linear with CPU core count for sufficiently large search windows
- **Memory (scan)**: ~10 MB base, ~1 MB per additional thread
- **Memory (BSGS)**: ~3 GB max for the largest supported ranges (compact 128-bit keys)
- **Logging overhead**: Bounded by line-buffered file writes; report-file writes are single-pass
- **Kangaroo hot-path speedup**: The projective-coordinate hash optimization (using a patched `k256` fork to expose `X` and `Z` coordinates) eliminates two field inversions per iteration, reducing the 2^56 wall time from ~180 s to ~2–5 s.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success (key found or search complete) |
| `1` | Error (invalid input, file I/O, etc.) |

---

## Error Handling

The tool returns descriptive errors for common failure modes:

| Error | Cause | Solution |
|-------|-------|----------|
| `hex parse error` | Invalid hex string | Check signature values |
| `pubkey` | Invalid pubkey format | Use 02, 03, or 04 prefix |
| `number parse error` | Invalid number format | Use decimal or `0x` prefix |
| `end must be >= start` | Invalid range | Set valid range |
| `r not invertible` | No modular inverse for `r` | Signature values may be invalid |
| `BSGS memory limit exceeded` | Range too large for BSGS | Use kangaroo for ranges > 2^52 |

---

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_bsgs_small_range

# With make
make test
```

---

## Build

```bash
cargo build --release
./target/release/nonce-cracker --help
```

---

## Release

Tagged `vX.Y.Z` releases are published to crates.io via `cargo publish` after
each version bump in `Cargo.toml`. Releases are cut from `master` once CI is
green. The `CHANGELOG.md` records every notable change.

---

## Benchmarking

```bash
# Run Criterion micro-benchmarks
cargo bench

# View results
# Open target/criterion/report/index.html

# Run end-to-end BSGS benchmark for a specific range size
cargo run --example bench_bsgs --release -- 48
```

### Fuzzing

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run a fuzz target (e.g., parse_scalar)
cargo fuzz run parse_scalar -- -max_total_time=60
```

Targets:
- `parse_scalar`: Hex/decimal string parsing
- `parse_pubkey`: Public key SEC1 decoding
- `parse_int`: Signed integer parsing
- `openmap`: Insert/lookup round-trips

Benchmarks cover:
- `scalar_invert`: Scalar modular inversion
- `derive_affine_constants`: Alpha/beta constant computation
- `derive_private_key`: Scalar arithmetic for candidate keys
- `point_multiplication`: Elliptic curve point multiplication
- `search_chunk`: Full search iteration throughput
- `bench_bsgs`: End-to-end BSGS search for random nonces in [0, 2^bits)

---

## Tech Stack

| Category | Technology |
|----------|------------|
| Language | Rust 1.75+ (stable) |
| Crypto library | [k256](https://crates.io/crates/k256) (secp256k1) — locally patched |
| CLI | [clap](https://crates.io/crates/clap) (derive) |
| Parallelism | [rayon](https://crates.io/crates/rayon) (work-stealing) |
| Logging | [tracing](https://crates.io/crates/tracing) + `tracing-subscriber` |
| Errors | [thiserror](https://crates.io/crates/thiserror) |
| Zeroization | [zeroize](https://crates.io/crates/zeroize) |
| Signal handling | [ctrlc](https://crates.io/crates/ctrlc) |
| Hashing | [rustc-hash](https://crates.io/crates/rustc-hash) (`FxHash`) |
| Testing | built-in + [assert_cmd](https://crates.io/crates/assert_cmd) + [proptest](https://crates.io/crates/proptest) |
| Benchmarks | [criterion](https://crates.io/crates/criterion) |
| Fuzzing | [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) / libFuzzer |
| Security audit | [cargo-deny](https://crates.io/crates/cargo-deny) |
| Containerization | Docker (multi-stage) |

---

## Roadmap

- **v0.6.x** — Current: signed range handling, structured errors, refined OpenMap (released)
- **v0.7.0** — Adaptive algorithm selection based on online profiling
- **v0.8.0** — GPU acceleration for the BSGS and kangaroo hot paths
- **v1.0.0** — Stable API, hardened checkpointing, signed range support on all algorithms

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and pull request process.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and supported versions.

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Disclaimer

This project is intended for **educational and research purposes only**. The
author is not responsible for any misuse, damage, or illegal activities
conducted using this software.
