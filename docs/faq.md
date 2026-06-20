# Frequently Asked Questions

## General

### What is nonce-cracker?

nonce-cracker is a high-speed parallel ECDSA private key recovery tool for the secp256k1 curve. It recovers private keys from a single ECDSA signature when the nonce (ephemeral key) is within a known search range.

### Is this tool legal to use?

This tool is intended for **educational and research purposes only**, as well as authorized security testing. Users are responsible for ensuring they have proper authorization before attempting to recover private keys. The authors are not responsible for any misuse.

### What curves are supported?

Currently, only **secp256k1** is supported (the curve used in Bitcoin and Ethereum).

## Installation

### What Rust version is required?

Rust **1.75+** (stable) is required. The project includes a `rust-toolchain.toml` that pins to stable with `rustfmt` and `clippy` components.

### Can I install without Rust?

Yes, you can use the Docker image:

```bash
docker build -t nonce-cracker .
docker run nonce-cracker example
```

Or install from crates.io if you already have a Rust toolchain:

```bash
cargo install nonce-cracker
```

## Usage

### What signature values do I need?

You need three values from the ECDSA signature:
- **r**: The R coordinate of the signature
- **s**: The S value of the signature
- **z**: The message hash (typically SHA-256 of the message)

Plus the target **public key** and the expected **search range** for the nonce.

### What is the nonce search range?

The nonce `k` is a random number used during ECDSA signing. If you know the range where `k` was generated (e.g., a weak RNG that produces small values), you can search that range to recover the private key.

### Which search algorithm is used?

The tool automatically selects the optimal algorithm based on range size:

| Range Size | Algorithm | Time Complexity |
|------------|-----------|-----------------|
| N <= 2^32 | Parallel scan | O(N) |
| 2^32 < N <= 2^52 | Baby-Step Giant-Step (BSGS) | O(sqrt(N)) |
| N > 2^52 | Pollard's kangaroo | O(sqrt(N)) |

### How fast is the search?

Performance depends on hardware and range size:

| Range | Algorithm | Apple M4 (12 cores) |
|-------|-----------|---------------------|
| 2^32 | Parallel scan | ~14 ms |
| 2^48 | BSGS | ~3.1 s |
| 2^52 | BSGS | ~112 s |
| 2^56 | Kangaroo | ~2-5 s |

### Can I use this with Bitcoin transactions?

Yes, if you have the ECDSA signature components (r, s, z) and the public key, and you know the nonce was generated within a searchable range.

## Configuration

### What environment variables are available?

| Variable | Description | Default |
|----------|-------------|---------|
| `NONCE_CRACKER_LOG_DIR` | Directory for logs and reports | `logs/` |
| `NONCE_CRACKER_LOG_LEVEL` | Log level (error/warn/info/debug/trace) | `info` |
| `NONCE_CRACKER_LOG_CONSOLE` | Enable console output (1/true) | `true` |
| `NONCE_CRACKER_CHECKPOINT_DIR` | Checkpoint file directory | `checkpoints/` |

### How do I run in quiet mode?

Use the `--quiet` flag to suppress console output:

```bash
nonce-cracker run --quiet --r 0x... --s 0x... --z 0x... --pubkey 0x...
```

## Troubleshooting

### "r not invertible" error

The signature's `r` value has no modular inverse modulo the curve order. This typically means the signature values are invalid or corrupted.

### "BSGS memory limit exceeded" error

The search range is too large for the BSGS algorithm. The tool will automatically fall back to Pollard's kangaroo for ranges > 2^52. If you still see this error, try narrowing the search range.

### Search takes too long

- Verify your search range is correct (smaller is better)
- Use `--threads` to set the number of CPU cores
- For very large ranges (> 2^52), the kangaroo algorithm is used automatically

### No output or report file

Check the log directory (default: `logs/`) for the report file. The `--outfile` flag controls the report filename.

## Development

### How do I run tests?

```bash
cargo test
# or
make test
```

### How do I run benchmarks?

```bash
cargo bench
# or for a specific range size
cargo run --example bench_bsgs --release -- 48
```

### How do I contribute?

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## Security

### How do I report a vulnerability?

Please see [SECURITY.md](../SECURITY.md) for instructions on reporting security vulnerabilities responsibly.
