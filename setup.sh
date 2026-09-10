#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "=== nonce-cracker setup ==="

# Verify Rust toolchain
if ! command -v rustc &>/dev/null; then
    echo "error: Rust not found. Install from https://rustup.rs"
    exit 1
fi

if ! command -v cargo &>/dev/null; then
    echo "error: Cargo not found. Install from https://rustup.rs"
    exit 1
fi

echo "Rust version: $(rustc --version)"
echo "Cargo version: $(cargo --version)"

# Create runtime directories
mkdir -p logs checkpoints

# Build in release mode to verify everything compiles
echo "Building release binary..."
cargo build --release

echo ""
echo "=== Setup complete ==="
echo "Run tests:    cargo test"
echo "Run example:  ./target/release/nonce-cracker example"
echo "Run search:   ./target/release/nonce-cracker run --help"
