# Pollard's Rho and Custom Hash Map Design

## Problem Statement

The current BSGS implementation is memory-bound at `m = 2^26` (~5 GB). For ranges above `2^48`, segmented BSGS becomes impractical (too many segments, each rebuilt from scratch). We need:

1. A memory-efficient alternative for `total > 2^48`: Pollard's kangaroo (lambda) method for bounded-range discrete logarithm search.
2. A memory-optimized baby-step table for `m <= 2^27`: custom open-addressing hash map.

## Algorithm Selection Heuristic

`SearchEngine::search` selects algorithms in this priority order:

1. If `total <= BSGS_THRESHOLD` (2^32): use parallel scan.
2. If `total > KANGAROO_THRESHOLD` (2^48): use Pollard's kangaroo.
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

## Component: Pollard's Kangaroo (Lambda Method)

### Algorithm Overview

Pollard's kangaroo is a memory-efficient algorithm for **bounded-range** discrete logarithm search. Unlike Pollard's rho (which searches the full group), kangaroo is designed for cases where the discrete log is known to lie in a bounded interval `[a, a + N]`. Expected runtime is `O(sqrt(N))` group operations with `O(sqrt(N) / 2^d)` memory.

**Why kangaroo instead of rho:**
- Rho searches the full group order (~2^256 for secp256k1), requiring ~2^128 iterations in expectation.
- Kangaroo searches only the known range `total`, requiring ~sqrt(total) iterations.
- For `total = 2^48`, kangaroo needs ~2^24 iterations vs rho's ~2^128.

**Core idea:**
1. Two walks on the elliptic curve group: **tame** and **wild**.
2. **Tame kangaroo** starts at `T_0 = g^(alpha*start + beta)` (the lower bound of the discrete log range).
3. **Wild kangaroo** starts at `W_0 = h = target` (the unknown discrete log we want to find).
4. Both make pseudorandom jumps of deterministic sizes determined by a hash of the current point.
5. Tame kangaroos store distinguished points in a shared table along with accumulated jump distances.
6. When a wild kangaroo hits the same distinguished point as a tame one:
   - `T_m = W_n` means `g^(a + d_t) = g^(x + d_w)` where `a = alpha*start + beta`, `x = alpha*k + beta`
   - Therefore: `k = start + step * (d_t - d_w)`
7. Verify the candidate by checking if it's in range and if it produces the target.

**Expected runtime:**
- `E[T] ≈ 2 * sqrt(N)` group operations per kangaroo pair (tame + wild)
- With `p` parallel threads: near-linear speedup

### Data Structures

```rust
/// Precomputed jump size for one partition of the walk.
struct JumpSize {
    distance: u64,  // jump distance in candidate-index units
}

/// A distinguished point found during a trail, with accumulated distance.
struct DistinguishedPoint {
    x: AffinePoint,
    distance: u64,  // sum of all jump distances to reach this point
}

struct KangarooParams {
    g: ProjectivePoint,        // generator G
    h: ProjectivePoint,        // target = Q
    alpha: Scalar,             // affine slope
    beta: Scalar,              // affine intercept
    start: i128,               // first candidate
    step: i128,                // candidate increment
    total: u128,               // number of candidates
    d: u32,                    // distinguishing bit count (default: 16)
    max_iterations: u64,         // safety cap
    thread_count: usize,
    pool: &rayon::ThreadPool,
    shutdown: &ShutdownToken,
}
```

### Jump Size Selection

- Number of jump sizes: `JUMP_COUNT = 20`
- Average jump size: `avg = sqrt(total) / 2` (in candidate-index units)
- Jump sizes are random values uniformly distributed in `[1, sqrt(total)]`
- The actual scalar multiplication is by `alpha * step * jump_distance`
- For `alpha == 0` (degenerate case): all candidates have discrete log `beta`, so check if `h == g^beta` and return immediately.

### Pseudorandom Walk

```rust
fn kangaroo_step(
    point: ProjectivePoint,
    jump_sizes: &[JumpSize],
    step_scalar: Scalar,
) -> (ProjectivePoint, u64) {
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    // Hash first 8 bytes of x-coordinate to select jump
    let hash = u64::from_le_bytes([
        bytes[1], bytes[2], bytes[3], bytes[4],
        bytes[5], bytes[6], bytes[7], bytes[8],
    ]);
    let idx = (hash as usize) % jump_sizes.len();
    let jump = jump_sizes[idx].distance;
    let step = step_scalar * Scalar::from(jump);
    (point + step, jump)
}
```

### Distinguished Point Detection

Same as rho: a point is distinguished if the first `d` bits of its compressed x-coordinate are zero.

For CPU: default `d = 16`. Expected distinguished points per kangaroo: `sqrt(total) / 2^d`.
For `total = 2^48`: ~256 points per kangaroo pair.

### Parallel Collision Table

**Sharded design:**
- `Vec<FxHashMap<[u8; 33], u64>>` — one map per thread, storing `(key, distance)`.
- Tame threads write to their shard.
- Wild threads read all shards to check for collisions.
- When a wild thread finds a collision: compute candidate `k = start + step * (d_tame - d_wild)`.

**Collision verification:**
After computing `k`, verify:
1. `k` is in range `[start, start + total)`
2. `derive_private_key(k, alpha, beta) * G == target`

This prevents false positives from hash collisions or edge cases.

### Parallelization Strategy

- Each thread runs **one tame** and **one wild** walk concurrently.
- Or: half the threads run tame walks, half run wild walks.
- With `p` threads, expected speedup is near-linear: `O(sqrt(N) / p)`.
- Atomic result variable for early termination when any thread finds the answer.

### Safety Limits

- `max_iterations = 10 * sqrt(total)` per kangaroo (generous upper bound).
- If limit exceeded, return `None`.
- Probability of failure with this cap is astronomically low.

## Component: Metrics and Observability

### New Metrics (Kangaroo)

- `kangaroo_tame_points`: tame distinguished points stored
- `kangaroo_wild_points`: wild distinguished points checked
- `kangaroo_collisions`: distinguished point collisions found
- `kangaroo_iterations`: total iterations
- `kangaroo_time`: elapsed time

### New Metrics (OpenMap)

- `openmap_capacity`: table capacity
- `openmap_load_factor`: current load factor
- `openmap_probe_length_avg`: average probe length

### Logging

- Kangaroo: periodic progress logs every 10,000 distinguished points.
- OpenMap: none (silent implementation detail).

## Error Handling

- Kangaroo is probabilistic. `None` result means "not found within limits", not an error.
- If kangaroo fails, the caller can retry with different random seeds.
- `RhoTimeout` error variant (already added) is reused as `KangarooTimeout`.

## Testing Strategy

### OpenMap

- Unit tests: insert/get with known keys, collision handling, tombstone reuse.
- Property test: random keys, compare against `FxHashMap`.

### Pollard's Kangaroo

- Unit tests: mock `KangarooParams` with known discrete logs (small ranges, e.g., 2^16).
- Integration tests: run kangaroo on a 48-bit range, assert it finds the answer.
- Property tests: random small scalars, compare kangaroo result against BSGS.
- Stress test: run kangaroo 100 times on the same problem, assert all succeed.

### Benchmarks

- Criterion bench comparing BSGS vs kangaroo on 2^32 and 2^40 ranges.
- Memory benchmark: measure peak RSS for BSGS with `FxHashMap` vs `OpenMap`.
- Kangaroo scaling benchmark: measure speedup from 1 to N threads on a fixed problem.

## File Layout

```
src/search/
  mod.rs              # SearchEngine, algorithm dispatch
  bsgs.rs             # BSGS algorithm (uses OpenMap)
  kangaroo.rs         # Pollard's kangaroo algorithm
  parallel.rs         # Parallel scan (unchanged)
  params.rs           # ScanParams, GiantStepParams, KangarooParams
  openmap.rs          # OpenMap implementation
  tests.rs            # Unit and integration tests
```

## Public API Changes

- No breaking changes to public API.
- `SearchEngine::search` remains the entry point.
- `bsgs_max_m` increased from `2^26` to `2^27`.

## Rollout Plan

1. Implement `OpenMap` and integrate into BSGS.
2. Validate with tests and benchmarks.
3. Implement Pollard's kangaroo (replacing the incorrect rho design).
4. Integrate into `SearchEngine` with selection heuristic.
5. Validate with integration tests and benchmarks.
6. Update documentation and changelog.
