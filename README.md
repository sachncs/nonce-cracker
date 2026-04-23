# nonce-cracker

[![Build](https://img.shields.io/github/actions/workflow/status/sachn-cs/nonce-cracker/ci.yml?style=flat-square)](https://github.com/sachn-cs/nonce-cracker/actions)
[![crate](https://img.shields.io/crates/v/nonce-cracker?style=flat-square)](https://crates.io/crates/nonce-cracker)
[![docs](https://img.shields.io/docsrs/nonce-cracker?style=flat-square)](https://docs.rs/nonce-cracker)

High-speed parallel ECDSA private key recovery for secp256k1 using an affine relation attack.

## Overview

`nonce-cracker` recovers private keys from two ECDSA signatures that share a nonce with a known affine relation `k' = k + delta`. When the nonce relation is linear, the private key can be expressed as:

```
d = alpha * delta + beta  (mod n)
```

The tool precomputes `alpha` and `beta` from the two signatures, then searches over delta values using either a highly optimized parallel scan (for ranges up to 2^32 candidates) or a parallel Baby-Step Giant-Step (BSGS) algorithm (for medium ranges up to 2^64 candidates).

## Architecture

The repository is organized around a single binary crate with a streamlined, production-ready layout:

- `src/main.rs` - CLI parsing, signature validation, affine-constant derivation, hybrid search orchestration (parallel scan + BSGS), and graceful shutdown handling.
- `src/logging.rs` - Structured logging backend using `tracing` with compact output format.
- `src/config.rs` - Centralized configuration management with environment variable support.
- `src/metrics.rs` - Search performance metrics collection.
- `tests/integration.rs` - End-to-end CLI tests including logging behavior and signed-range handling.
- `benches/search.rs` - Criterion benchmarks for core cryptographic operations.
- `examples/demo.rs` - Usage demonstration.
- `examples/generate.rs` - Test data generator.
- `docs/` - Architecture documentation and deployment guides.

Data flow is intentionally linear:

1. CLI arguments are parsed and validated.
2. Signature values are converted to secp256k1 `Scalar`s and public keys to `PublicKey`.
3. `derive_affine_constants` produces the affine parameters `alpha` and `beta`.
4. The search dispatches to the optimal algorithm based on range size:
   - `N <= 2^32`: Parallel scan with batched point comparison
   - `2^32 < N < 2^64`: Parallel BSGS with batched normalization
5. Each worker evaluates candidate delta values, compares the resulting public key against the target, and stops on the first match.
6. Matching results are written to the report file and summarized through the centralized logger.

This architecture minimizes shared mutable state, keeps the cryptographic math isolated from logging concerns, and makes the CLI/test/benchmark surfaces align with the same search contract.

## Features

### Core Functionality

- **Hybrid search algorithm**: Parallel scan for small ranges (N <= 2^32), parallel BSGS for medium ranges (2^32 < N < 2^64)
- **Parallel search** across CPU cores via Rayon (work-stealing scheduler)
- **Native secp256k1 arithmetic** using `k256` crate (no BigInt overhead)
- **Fast point comparison** using projective coordinates (no field inversion in hot loop)
- **Configurable search range** with decimal or hex notation, including negative bounds
- **Single CLI interface**: `run` command with ECDSA signature order
- **Thread count control** with automatic CPU detection fallback
- **Graceful shutdown** handling for SIGINT/SIGTERM signals

### Production Features

- **Structured logging** with tracing (compact format)
- **Configuration management** via environment variables
- **Performance metrics** collection and reporting
- **Docker support** with multi-stage builds
- **CI/CD pipeline** with GitHub Actions (build, test, security audit)
- **Dependency security** auditing with cargo-deny

## Requirements

- **Rust**: 1.75+ (stable)
- **OS**: macOS, Linux, Windows (any platform with Rust support)
- **CPU**: Multi-core recommended for parallel search

## Installation

### From crates.io

```bash
cargo install nonce-cracker
```

### From source

```bash
git clone https://github.com/sachn-cs/nonce-cracker.git
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

## Quick Start

### Run the demonstration

```bash
nonce-cracker example
```

This runs a self-contained demonstration that recovers private key `0x3039` by searching a 3-value range. It proves the tool works correctly with verifiable output.

### Search for a private key

```bash
nonce-cracker run \
  --r1 0x37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba \
  --r2 0xba5aec8a54a3a56fcd1bf17bceba9c4fad7103abf06669748b66578d03e0de12 \
  --s1 0xe026eb94e61bcdc41f0ee8cd7b97eda899ce5856d3a32360d742b13d717ff2a8 \
  --s2 0x31bc5dd7d522300c1a3fa117322581571329a2af3ba0d1a9b72d3c36eeac3ec7 \
  --z1 0x0000000000000000000000000000000000000000000000000000000000000001 \
  --z2 0x0000000000000000000000000000000000000000000000000000000000000002 \
  --pubkey 03f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f \
  --start 0 \
  --end 10
```

## Usage

### Global options

| Flag | Description |
|------|-------------|
| `-h`, `--help` | Print help |
| `-V`, `--version` | Print version |

### Subcommands

#### `run`

Search with signature values in ECDSA order (r1, r2, s1, s2, z1, z2).

```bash
nonce-cracker run [OPTIONS]
```

#### `example`

Run a self-contained demonstration with verifiable output.

```bash
nonce-cracker example
```

### Command options

| Flag | Description | Default |
|------|-------------|---------|
| `--r1 <HEX>` | R coordinate of first signature | Required |
| `--r2 <HEX>` | R coordinate of second signature | Required |
| `--s1 <HEX>` | S value of first signature | Required |
| `--s2 <HEX>` | S value of second signature | Required |
| `--z1 <HEX>` | Message hash of first signature | Required |
| `--z2 <HEX>` | Message hash of second signature | Required |
| `--pubkey <HEX>` | Target public key (uncompressed or compressed) | Required |
| `--start <NUM>` | Search range start (decimal or `0x` hex) | `0` |
| `--end <NUM>` | Search range end | `0x1000000000000000` (2^60) |
| `--step <NUM>` | Search step size | `1` |
| `--threads <NUM>` | Worker thread count | CPU core count |
| `--quiet` | Suppress console output | `false` |
| `--outfile <PATH>` | Search report file name or path | `search.log` |

### Logging

Application logs are written to a dedicated directory:

- `NONCE_CRACKER_LOG_DIR` - Directory for application logs and search reports. Default: `logs/`
- `NONCE_CRACKER_LOG_LEVEL` - Log level for the backend logger (`error`, `warn`, `info`, `debug`, `trace`). Default: `info`
- `NONCE_CRACKER_LOG_CONSOLE` - Enable console output (`1`/`true` to enable). Default: `true`

Relative `--outfile` values are resolved inside the configured log directory. Absolute paths are still accepted for explicit overrides.

### Input formats

**Signature values** (r1, r2, s1, s2, z1, z2):
- Hex with `0x` prefix: `0x59b22000...`
- Hex without prefix: `59b22000...`
- Odd-length hex is auto-padded: `0xFFF` -> `0x0FFF`

**Public key**:
- Uncompressed: `04` + x (32 bytes) + y (32 bytes) -> 130 hex chars
- Compressed even y: `02` + x (32 bytes) -> 66 hex chars
- Compressed odd y: `03` + x (32 bytes) -> 66 hex chars

**Range values** (start, end, step):
- Decimal: `1000000`
- Hex: `0xFF`
- Negative: `-10`

## Project Structure

```
nonce-cracker/
├── src/
│   ├── main.rs          # Binary entry point, CLI, search logic
│   ├── logging.rs       # Centralized file logger
│   ├── config.rs        # Configuration management
│   └── metrics.rs       # Performance metrics
├── tests/
│   └── integration.rs   # CLI integration tests
├── benches/
│   └── search.rs        # Criterion benchmarks
├── examples/
│   ├── demo.rs          # Usage demonstration
│   └── generate.rs      # Test data generator
├── docs/
│   ├── affine-relation-derivation.md  # Mathematical derivation
│   └── DEPLOYMENT.md                  # Deployment guide
├── Cargo.toml
├── rust-toolchain.toml
├── Makefile
└── README.md
```

### Module overview

- **CLI** (`main.rs`): Command-line argument parsing via `clap`
- **Crypto** (`main.rs`): `derive_affine_constants`, `derive_private_key`, `search` with hybrid scan/BSGS dispatch
- **Search** (`main.rs`): Parallel scan and parallel BSGS orchestration via Rayon

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

### Affine relation attack

When two signatures share a nonce with relation `k2 = k1 + delta`, the private key can be recovered via:

```
d = alpha * delta + beta  (mod n)
```

The tool:
1. Parses and validates the two signatures, public key, and signed search bounds.
2. Derives the linear coefficients from the two signature equations, then reduces them to `alpha` and `beta` using modular arithmetic in the secp256k1 scalar field.
3. Computes the total number of candidates `N = floor((end - start) / step) + 1`.
4. Dispatches to the optimal search algorithm based on `N`:
   - **Parallel scan** (`N <= 2^32`): Partitions the range across worker threads. Each thread evaluates candidates in batches of 1024, using projective point addition and equality comparison (no field inversion in the hot loop).
   - **Parallel BSGS** (`2^32 < N < 2^64`): Computes `m = ceil(sqrt(N))` baby steps in parallel, storing them in a hash map keyed by compressed public key bytes. Giant steps are then evaluated in parallel with batched projective-to-affine normalization (amortized inversion cost).
5. Stops on the first match, writes the report file, and emits a structured summary line.

### Invariants and failure modes

- The search window is inclusive and `step` must be strictly positive.
- `end` must be greater than or equal to `start`.
- If the linear coefficient `a` is not invertible modulo the curve order, the affine system does not admit a unique solution and the search returns an error.
- Empty report paths are rejected before file creation.
- BSGS requires `m <= 2^26` (~67 million baby steps, ~5 GB memory). If the range would exceed this, the search returns an error.

### Complexity

**Parallel scan (N <= 2^32):**
- **Time:** O(N) candidate evaluations in the worst case.
- **Space:** O(1) worker-local state, plus the report file and bounded coordination state.
- **Parallelism:** Work is distributed across a dedicated Rayon pool, so wall-clock time scales with the number of useful CPU cores.

**Parallel BSGS (2^32 < N < 2^64):**
- **Time:** O(sqrt(N)) point operations in the worst case.
- **Space:** O(sqrt(N)) for the baby-step hash map (~5 GB max at N = 2^52).
- **Parallelism:** Both baby steps and giant steps are computed in parallel. Baby-step tables are merged sequentially after parallel construction.

### Performance

- **Per thread (scan)**: ~5-10 million keys/second (varies by hardware)
- **Per thread (BSGS giant steps)**: ~1-2 million batch-normalized points/second
- **Scaling**: Near-linear with CPU core count for sufficiently large search windows
- **Memory (scan)**: ~10 MB base, ~1 MB per additional thread
- **Memory (BSGS)**: ~5 GB max for the largest supported ranges
- **Logging overhead**: Bounded by line-buffered file writes; report-file writes are single-pass

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success (key found or search complete) |
| `1` | Error (invalid input, file I/O, etc.) |

## Error Handling

The tool returns descriptive errors for common failure modes:

| Error | Cause | Solution |
|-------|-------|----------|
| `hex parse error` | Invalid hex string | Check signature values |
| `pubkey` | Invalid pubkey format | Use 02, 03, or 04 prefix |
| `number parse error` | Invalid number format | Use decimal or `0x` prefix |
| `end must be >= start` | Invalid range | Set valid range |
| `denominator not invertible` | No modular inverse exists | Signature values may be invalid |
| `BSGS memory limit exceeded` | Range too large for BSGS | Reduce search range |

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

## Benchmarking

```bash
# Run benchmarks
cargo bench

# View results
# Open target/criterion/report/index.html
```

Benchmarks cover:
- `scalar_invert`: Scalar modular inversion
- `derive_affine_constants`: Alpha/beta constant computation
- `derive_private_key`: Scalar arithmetic for candidate keys
- `point_multiplication`: Elliptic curve point multiplication
- `search_chunk`: Full search iteration throughput

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup
- Coding standards
- Testing guidelines
- Pull request process

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Disclaimer

This project is intended for **educational and research purposes only**. The author is not responsible for any misuse, damage, or illegal activities conducted using this software.
