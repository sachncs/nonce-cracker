# Pollard's Rho and Custom Hash Map Design

## Problem Statement

The current BSGS implementation is memory-bound at `m = 2^26` (~5 GB). For ranges above `2^48`, segmented BSGS becomes impractical (too many segments, each rebuilt from scratch). We need:

1. A memory-efficient alternative for `total > 2^48`: Pollard's rho with van Oorschot-Wiener parallel collision search.
2. A memory-optimized baby-step table for `m <= 2^27`: custom open-addressing hash map.

## Algorithm Selection Heuristic

`SearchEngine::search` selects algorithms in this priority order:

1. If `total <= BSGS_THRESHOLD` (2^32): use parallel scan.
2. If `total > RHO_THRESHOLD` (2^48): use Pollard's rho.
3. Otherwise (`2^32 < total <= 2^48`): use BSGS (in-memory or segmented).

This preserves deterministic output for all ranges up to 2^48, and only uses the probabilistic algorithm for genuinely massive ranges.

## Component: Custom Open-Addressing Hash Map (`OpenMap`)

### Motivation

`FxHashMap<[u8; 33], u128>` at 2^26 entries uses ~5 GB. With open addressing and inline keys, we can reduce overhead by ~25%, enabling 2^27 entries (~10 GB) without swap.

### Design

- `OpenMap` struct backed by `Vec<Entry>` where `Entry` is `([u8; 33], u128, state: u8)`.
- State values: `EMPTY`, `OCCUPIED`, `TOMBSTONE`.
- Quadratic probing for cache locality: `probe(i) = (hash + i * i) & mask`.
- Capacity is always a power of two for fast modulo via bitmask.
- Load factor capped at 0.7. No resizing — capacity is fixed at construction time.
- Uses `FxBuildHasher` from `rustc-hash` for the hash function.
- API: `new(capacity)`, `insert(key, value)`, `get(key) -> Option<&u128>`.

### Integration

- Replace `FxHashMap` in `build_baby_steps` and `run_giant_steps`.
- `build_baby_steps` returns `OpenMap` instead of `FxHashMap`.
- No public API change — internal implementation only.

## Component: Pollard's Rho with van Oorschot-Wiener

### Algorithm Overview

Parallel collision search for discrete logarithm. This design incorporates the **negation map optimization** from Bernstein-Lange-Schwabe (2011) and **branchless iteration** techniques from modern GPU implementations.

**Core idea:**
1. Define pseudorandom walk `f(x) = x * g^a * h^b` where `g = G`, `h = target`.
2. Exponents `a`, `b` are small scalars derived from a hash of `x`.
3. Exploit the negation map: on secp256k1, if `P = (x, y)` then `-P = (x, -y)`. The discrete log of `-P` is `n - dlog(P)` where `n` is the curve order. This gives an effective **sqrt(2) speedup** (~1.414x).
4. A point is "distinguished" if its compressed encoding has `d` leading zero bits.
5. Each thread runs independent trails. When a trail hits a distinguished point, it stores `(x, a, b)` in a sharded table.
6. If two trails hit the same distinguished point `x`, we have `x = g^a1 * h^b1 = g^a2 * h^b2`.
7. Solving: `h = g^((a1 - a2) / (b2 - b1))`, giving the discrete log.

**Expected runtime with negation map:**
- Without negation: `E[T] ≈ sqrt(πn / 2)` group operations
- With negation: `E[T] ≈ sqrt(πn / 4)` group operations

**Sources:**
- [Bernstein, Lange, Schwabe — "On the correct use of the negation map in the Pollard rho method"](https://eprint.iacr.org/2011/003)
- [SafeCurves rho security analysis for secp256k1](https://safecurves.cr.yp.to/rho.html)

### Data Structures

```rust
struct DistinguishedPoint {
    x: AffinePoint,
    a: Scalar,  // exponent of g
    b: Scalar,  // exponent of h
}

struct RhoParams {
    g: ProjectivePoint,        // generator
    h: ProjectivePoint,        // target
    d: u32,                    // distinguishing bit count (default: 16)
    max_trails: u64,           // safety cap
    thread_count: usize,
    pool: &rayon::ThreadPool,
    shutdown: &ShutdownToken,
}
```

### Negation Map and Branchless Iteration

**Negation map application:**
- After each step, compute `|x|` as the point with the lexicographically smaller y-coordinate: if `y > p/2`, replace with `-y`.
- This is implemented branchlessly using masking: `y = y + (y_msb) * (p - 2*y)` where `y_msb` is 1 if `y > p/2`.
- The iteration function always operates on `|x|`, effectively halving the search space.

**Branchless iteration function:**
- Partition into `r = 20` regions.
- Precompute `(a_i, b_i)` pairs for each region.
- Hash `|x|` to select region `i`.
- Step: `x = |x| * g^a_i * h^b_i`.
- All operations are straight-line (no conditional branches in the hot loop).

**Sources:**
- [Bernstein, Lange, Schwabe — branchless negation map](https://eprint.iacr.org/2011/003)

### Fruitless Cycle Detection and Escape

The negation map can cause walks to enter **2-cycles** and **4-cycles** (fruitless cycles that never hit a distinguished point).

**Detection:**
- Every `C` iterations (e.g., `C = 48`), store the current point and compare to a point `C/2` iterations ago.
- Check for 2-cycles: `x_i == x_{i+1}` (modulo negation).
- Check for 4-cycles: `x_i == x_{i+2}` (modulo negation).
- These checks are done with minimal branching using masking.

**Escape:**
- If a cycle is detected, escape by doubling the lexicographically minimal point encountered: `x = 2 * |x_min|`.
- This is also done branchlessly.

**Cycle check frequency:** Tunable parameter based on `r`. For `r = 2048`, check every 48 iterations. For our implementation with `r = 20`, a check every 32 iterations is sufficient.

**Sources:**
- [Bernstein, Lange, Schwabe — cycle handling](https://eprint.iacr.org/2011/003)

### Distinguished Point Table

**Sharded design:**
- `Vec<FxHashMap<[u8; 33], (Scalar, Scalar)>>` — one map per thread.
- Each thread only writes to its own shard, reads from all shards.
- Lock-free reads: shards are immutable after the current batch, or use `RwLock` per shard.

**Parameter selection:**
- Time-space tradeoff: `storage ≈ 2^(n/2 - d)`, `time ≈ (2^(n/2)/m + 2.5·2^d)·t`.
- For CPU implementation with shared memory (not GPU with slow global DRAM), we can afford lower `d`.
- For `n = 48`, `sqrt(n) = 2^24`:
  - `d = 16`: ~256 distinguished points in memory, fast collision detection.
  - `d = 20`: ~16 distinguished points, lower memory but slower.
- **Default: `d = 16`** for CPU. This gives negligible memory usage (~few KB) while keeping collision detection fast.

**Sources:**
- [Richard — ecdl implementation notes](https://github.com/brichard19/ecdl)
- [Boss — "Solving prime-field ECDLPs on GPUs with OpenCL"](https://www.cs.ru.nl/masters-theses/2015/E_Boss___Solving_prime-field_ECDLPs_on_Gpus_with_OpenCL.pdf)

### Pseudorandom Walk

- Partition the point space into `r = 20` regions (following Rudolph 2025 finding that `k = 1` is optimal).
- For each region `i`, precompute `(a_i, b_i)` pairs where `a_i` and `b_i` are small random scalars.
- Given point `|x|`, hash `|x|` to select region `i`, then step: `x = |x| * g^a_i * h^b_i`.
- The hash function can be a simple 64-bit hash of the compressed point encoding, modulo `r`.

**Sources:**
- [Rudolph — "Choosing iteration maps for the parallel Pollard rho method"](https://arxiv.org/abs/2506.12844)

### Collision Detection and Solving

- When a distinguished point is found, check all shards for the same key.
- If found, compute the discrete log: `log = (a1 - a2) * (b2 - b1)^(-1) mod n`.
- If not found, insert into the current thread's shard and continue.
- Montgomery batch inversion can be used within a single thread to amortize inversion cost when processing multiple distinguished points in a batch.

### Safety Limits

- `max_trails`: maximum number of trails per thread before giving up.
- `max_iterations`: total iterations across all threads (e.g., `10 * sqrt(n)` as a generous upper bound).
- If limits exceeded, return `None` (failure, not an error).
- The probability of failure with `max_iterations = 10 * sqrt(n)` is astronomically low.

## Component: Metrics and Observability

### New Metrics (Rho)

- `rho_trails`: total trails started
- `rho_distinguished_points`: distinguished points found
- `rho_collisions`: distinguished point collisions
- `rho_iterations`: total iterations
- `rho_time`: elapsed time for rho search
- `rho_fruitless_cycles`: fruitless cycles detected and escaped

### New Metrics (OpenMap)

- `openmap_capacity`: table capacity
- `openmap_load_factor`: current load factor
- `openmap_probe_length_avg`: average probe length

### Logging

- Rho: periodic progress logs every 10,000 distinguished points.
- OpenMap: none (silent implementation detail).

## Error Handling

- Rho is probabilistic. `None` result means "not found within limits", not an error.
- If rho fails, the caller can retry with different random seeds (future enhancement).
- No new error variants needed — rho uses existing `EngineError` or returns `Ok(None)`.

## Testing Strategy

### OpenMap

- Unit tests: insert/get with known keys, collision handling, tombstone reuse.
- Property test: random keys, compare against `FxHashMap`.

### Pollard's Rho

- Unit tests: mock `RhoParams` with known discrete logs (small ranges).
- Integration tests: run rho on a 48-bit range, assert it finds the answer.
- Property tests: random small scalars, compare rho result against BSGS.
- Stress test: run rho 100 times on the same problem, assert all succeed.
- Cycle test: verify fruitless cycle detection works by constructing a known 2-cycle.

### Benchmarks

- Criterion bench comparing BSGS vs rho on 2^32 and 2^40 ranges.
- Memory benchmark: measure peak RSS for BSGS with `FxHashMap` vs `OpenMap`.
- Rho scaling benchmark: measure speedup from 1 to N threads on a fixed problem.

## File Layout

```
src/search/
  mod.rs              # SearchEngine, algorithm dispatch
  bsgs.rs             # BSGS algorithm (uses OpenMap)
  rho.rs              # Pollard's rho algorithm
  parallel.rs         # Parallel scan (unchanged)
  params.rs           # ScanParams, GiantStepParams, RhoParams
  openmap.rs          # OpenMap implementation
  tests.rs            # Unit and integration tests
```

## Public API Changes

- No breaking changes to public API.
- `SearchEngine::search` remains the entry point.
- `bsgs_max_m` can be increased from `2^26` to `2^27` once `OpenMap` is validated.

## Rollout Plan

1. Implement `OpenMap` and integrate into BSGS.
2. Validate with tests and benchmarks.
3. Implement Pollard's rho with negation map and branchless iteration.
4. Integrate into `SearchEngine` with selection heuristic.
5. Validate with integration tests and benchmarks.
6. Update documentation and changelog.
