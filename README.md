# nonce-cracker

[![Build](https://img.shields.io/github/actions/workflow/status/sachn-cs/nonce-cracker/ci.yml?style=flat-square)](https://github.com/sachn-cs/nonce-cracker/actions)
[![crate](https://img.shields.io/crates/v/nonce-cracker?style=flat-square)](https://crates.io/crates/nonce-cracker)
[![docs](https://img.shields.io/docsrs/nonce-cracker?style=flat-square)](https://docs.rs/nonce-cracker)

High-speed parallel ECDSA private key recovery for secp256k1 using an affine relation attack.

## Overview

`nonce-cracker` recovers private keys from two ECDSA signatures that share a nonce (`k`). When two secp256k1 signatures reuse a nonce with a linear relationship `k' = α·k + β`, a mathematical relationship emerges that allows computation of the private key via:

```
d = α·δ + β (mod n)
```

The tool precomputes α and β using arbitrary-precision integers, then searches over δ values in parallel across CPU cores.

## Architecture

The repository is organized around a single binary crate with a small number of clearly separated responsibilities:

- `src/main.rs` owns CLI parsing, signature validation, affine-constant derivation, bounded search orchestration, and report generation.
- `src/logging.rs` owns the global logging backend, environment-based configuration, file rotation, and log-directory enforcement.
- `tests/integration.rs` exercises the CLI end-to-end, including logging behavior and signed-range handling.
- `benches/search.rs` mirrors the production arithmetic for performance regression tracking.
- `docs/affine-relation-derivation.md` formalizes the algebra used by the recovery algorithm.

Data flow is intentionally linear:

1. CLI arguments are parsed and validated.
2. Signature values are converted to `BigInt` and public keys to SEC1 `PublicKey` values.
3. `derive_affine_constants` produces the affine parameters `alpha` and `beta`.
4. The search partitions the signed delta interval across a dedicated Rayon pool.
5. Each worker evaluates `d = alpha * delta + beta mod n`, reconstructs the corresponding public key, and compares it against the target.
6. Matching results are written to the report file and summarized through the centralized logger.

This architecture minimizes shared mutable state, keeps the cryptographic math isolated from logging concerns, and makes the CLI/test/benchmark surfaces align with the same search contract.

## Features

- **Parallel search** across CPU cores via Rayon (work-stealing scheduler)
- **x-only pubkey precheck** for fast filtering before full verification
- **BigInt precision** for cryptographic calculations (no overflow risk)
- **Configurable search range** with decimal or hex notation
- **Two CLI interfaces**: `run` (ECDSA order: r1, r2, s1, s2, z1, z2) and `recover` (user-specified order: r1, s1, z1, r2, s2, z2)
- **Thread count control** with automatic CPU detection fallback

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

### Recover a private key

```bash
nonce-cracker recover \
  --r1 0x37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba \
  --s1 0xe026eb94e61bcdc41f0ee8cd7b97eda899ce5856d3a32360d742b13d717ff2a8 \
  --z1 0x0000000000000000000000000000000000000000000000000000000000000001 \
  --r2 0xba5aec8a54a3a56fcd1bf17bceba9c4fad7103abf06669748b66578d03e0de12 \
  --s2 0x31bc5dd7d522300c1a3fa117322581571329a2af3ba0d1a9b72d3c36eeac3ec7 \
  --z2 0x0000000000000000000000000000000000000000000000000000000000000002 \
  --pubkey 03f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f
```

### Or use the `run` command (ECDSA signature order)

```bash
nonce-cracker run \
  --r1 <hex> --r2 <hex> --s1 <hex> --s2 <hex> --z1 <hex> --z2 <hex> \
  --pubkey <hex>
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

#### `recover`

Search with signature values in user-specified order (r1, s1, z1, r2, s2, z2).

```bash
nonce-cracker recover [OPTIONS]
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

Application logs are written to a dedicated directory and rotated automatically:

- `NONCE_CRACKER_LOG_DIR` - Directory for application logs and search reports. Default: `logs/`
- `NONCE_CRACKER_LOG_LEVEL` - Log level for the backend logger (`error`, `warn`, `info`, `debug`, `trace`). Default: `info`
- `NONCE_CRACKER_LOG_MAX_BYTES` - Rotate the active application log after this many bytes. Default: `1048576`
- `NONCE_CRACKER_LOG_RETENTION` - Number of rotated application logs to keep. Default: `5`

Relative `--outfile` values are resolved inside the configured log directory. Absolute paths are still accepted for explicit overrides.

### Input formats

**Signature values** (r1, r2, s1, s2, z1, z2):
- Hex with `0x` prefix: `0x59b22000...`
- Hex without prefix: `59b22000...`
- Odd-length hex is auto-padded: `0xFFF` → `0x0FFF`

**Public key**:
- Uncompressed: `04` + x (32 bytes) + y (32 bytes) → 130 hex chars
- Compressed even y: `02` + x (32 bytes) → 66 hex chars
- Compressed odd y: `03` + x (32 bytes) → 66 hex chars

**Range values** (start, end, step):
- Decimal: `1000000`
- Hex: `0xFF`

## Project Structure

```
nonce-cracker/
├── src/
│   ├── logging.rs       # Centralized file logger, rotation, path resolution
│   └── main.rs          # Binary entry point, CLI, search logic
├── tests/
│   └── integration.rs   # CLI integration tests
├── benches/
│   └── search.rs        # Criterion benchmarks
├── examples/
│   ├── demo.rs         # Usage demonstration
│   └── generate.rs     # Test data generator
├── Cargo.toml
├── rust-toolchain.toml
├── Makefile
└── README.md
```

### Module overview

- **CLI** (`main.rs`): Command-line argument parsing via `clap`
- **Crypto** (`main.rs`): `mod_inverse`, `precompute`, `normalize` for affine relation math
- **Search** (`main.rs`): Parallel search orchestration via Rayon

## Algorithm

### ECDSA signatures

In ECDSA, a signature `(r, s)` is computed as:

```
r = (k·G).x mod n
s = k⁻¹(z + r·d) mod n
```

Where:
- `k` is the nonce (ephemeral key)
- `G` is the generator point
- `n` is the curve order (secp256k1)
- `d` is the private key
- `z` is the message hash

### Affine relation attack

When two signatures share a nonce with linear relation `k' = α·k + β`, the private key can be recovered via:

```
d = α·δ + β (mod n)
```

The tool:
1. Parses and validates the two signatures, public key, and signed search bounds.
2. Derives the linear coefficients `a`, `b`, and `c` used to solve the affine relation, then reduces them to `alpha` and `beta`.
3. Converts `alpha` and `beta` to secp256k1 scalars when they fit in-field.
4. Partitions the inclusive delta range `[start, end]` into fixed-size chunks and assigns them to worker threads.
5. Evaluates `d(delta) = alpha * delta + beta mod n` for each candidate.
6. Reconstructs the public key from each candidate and compares it first by x-coordinate, then by full SEC1 encoding.
7. Stops on the first match, writes the report file, and emits a structured summary line.

### Invariants and failure modes

- The search window is inclusive and `step` must be strictly positive.
- `end` must be greater than or equal to `start`.
- `alpha` and `beta` must fit into 32-byte secp256k1 scalars before the fast path is used.
- If the linear coefficient `a` is not invertible modulo the curve order, the affine system does not admit a unique solution and the search returns an error.
- Empty report paths are rejected before file creation.

### Complexity

- **Time:** `O(N)` candidate evaluations in the worst case, where `N = floor((end - start) / step) + 1`.
- **Space:** `O(1)` worker-local state, plus the report file and bounded coordination state.
- **Parallelism:** Work is distributed across a dedicated Rayon pool, so wall-clock time scales with the number of useful CPU cores and the selectivity of the public-key precheck.

### Performance

- **Per thread**: ~1–5 million keys/second (varies by hardware)
- **Scaling**: Near-linear with CPU core count for sufficiently large search windows
- **Memory**: ~10 MB base, ~1 MB per additional thread
- **Logging overhead**: Bounded by line-buffered file writes and size-based rotation; report-file writes are single-pass and do not allocate per candidate

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
| `public key parse error` | Invalid pubkey format | Use 02, 03, or 04 prefix |
| `number parse error` | Invalid number format | Use decimal or `0x` prefix |
| `out of range` | `end < start` or alpha/beta overflow | Set valid range |
| `calculation error` | No modular inverse exists | Signature values may be invalid |

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_mod_inverse

# Run doc tests
cargo test --doc

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
- `mod_inverse`: Extended Euclidean algorithm
- `precompute`: Alpha/beta constant computation
- `compute_d`: Scalar arithmetic for candidate keys
- `point_multiplication`: Elliptic curve point multiplication
- `scalar_from_bigint`: BigInt to scalar conversion
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
- MIT license ([LICENSE-MIT])

at your option.

## Disclaimer

This project is intended for **educational and research purposes only**. The author is not responsible for any misuse, damage, or illegal activities conducted using this software.
