#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "=== nonce-cracker cleanup ==="

# Rust build artifacts
if [ -d target ]; then
    echo "Removing target/ ..."
    rm -rf target
fi

# Runtime directories
echo "Removing logs/ ..."
rm -rf logs

echo "Removing checkpoints/ ..."
rm -rf checkpoints

# Proptest regression seeds
if [ -d proptest-regressions ]; then
    echo "Removing proptest-regressions/ ..."
    rm -rf proptest-regressions
fi

# Temporary atomic-write files
if ls *.tmp.* >/dev/null 2>&1; then
    echo "Removing *.tmp.* files ..."
    rm -f *.tmp.*
fi

# Cargo cache (optional, kept commented out by default)
# echo "Cleaning cargo cache..."
# cargo clean

echo "=== Cleanup complete ==="
