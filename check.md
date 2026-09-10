Cryptographic Audit Report: nonce-cracker

  Executive Summary

  nonce-cracker is a well-structured Rust CLI/library for ECDSA private-key recovery via an affine-relation attack on secp256k1. It delegates field and curve arithmetic to the audited
  k256 crate, which is sound. The project has three search tiers (parallel scan, BSGS, Pollard's kangaroo), good CLI ergonomics, structured logging, CI, and benchmarks. Tests pass and
  clippy is clean.

  However, there are critical correctness and safety defects that must be addressed before the codebase can be considered production-grade for demanding research or operational
  environments:

  1. Pollard's kangaroo uses unseeded, nondeterministic random walks (rand::thread_rng()), making results irreproducible, untestable, and impossible to debug or replay.
  2. Kangaroo converts projective points to affine on every single step (two expensive field inversions per iteration), a catastrophic performance cliff that likely makes the kangaroo
  path orders of magnitude slower than claimed.
  3. Segmented BSGS has quadratic time blowup if the baby-step table is smaller than sqrt(N). In the current dispatch this path is unreachable, but it is a latent integrity bomb if
  thresholds or parameters change.
  4. No zeroization of sensitive scalars — private keys, nonces, and affine constants (alpha, beta) remain in memory as plain bytes with no explicit clearing.
  5. The custom OpenMap hash map panics on saturation instead of growing, and its load-factor calculation doesn't account for the actual quadratic-probing clustering behavior.

  The codebase shows strong engineering discipline in module boundaries, error types, and test coverage for the happy path, but it lacks invariant enforcement for overflow in the search
  hot loop, property-based testing, checkpoint/resume capability, and side-channel awareness.

  Highest-Risk Findings

  ┌──────┬────────────────────────────────────────────────────────────────────────┬──────────┬─────────────────────────────────────────────────────┐
  │ Rank │                                 Issue                                  │ Severity │                    Blast Radius                     │
  ├──────┼────────────────────────────────────────────────────────────────────────┼──────────┼─────────────────────────────────────────────────────┤
  │ 1    │ Kangaroo unseeded RNG → irreproducible, untestable walks               │ Critical │ Entire kangaroo path (N > 2^48)                     │
  ├──────┼────────────────────────────────────────────────────────────────────────┼──────────┼─────────────────────────────────────────────────────┤
  │ 2    │ Kangaroo to_affine() on every step → ~2 field inversions per iteration │ Critical │ Performance, wall-clock correctness on timeout      │
  ├──────┼────────────────────────────────────────────────────────────────────────┼──────────┼─────────────────────────────────────────────────────┤
  │ 3    │ No zeroization of Scalar secrets in SearchOutcome, Signature, logs     │ High     │ Security / secret exposure                          │
  ├──────┼────────────────────────────────────────────────────────────────────────┼──────────┼─────────────────────────────────────────────────────┤
  │ 4    │ Segmented BSGS quadratic blowup (O(S·m) instead of O(m))               │ High     │ Latent correctness/performance if thresholds change │
  ├──────┼────────────────────────────────────────────────────────────────────────┼──────────┼─────────────────────────────────────────────────────┤
  │ 5    │ OpenMap::insert panics at saturation; no resize path                   │ High     │ Crash under load or adversarial input               │
  ├──────┼────────────────────────────────────────────────────────────────────────┼──────────┼─────────────────────────────────────────────────────┤
  │ 6    │ i128 wrapping addition in parallel scan hot loop (parallel.rs:76)      │ High     │ Incorrect candidate index for large negative starts │
  ├──────┼────────────────────────────────────────────────────────────────────────┼──────────┼─────────────────────────────────────────────────────┤
  │ 7    │ file.try_clone().expect() in logging init can panic in production      │ Medium   │ Startup failure under fd exhaustion                 │
  └──────┴────────────────────────────────────────────────────────────────────────┴──────────┴─────────────────────────────────────────────────────┘

  ---
  Correctness Issues

  C-1: Pollard's Kangaroo Uses Unseeded Thread RNG

  - Location: src/search/kangaroo.rs:58
  - Root cause: rand::thread_rng() is called fresh on every search() invocation without a seed. Jump sizes are drawn from avg_jump * 2.0 * rng.gen::<f64>().
  - Why it matters: Every run produces a different random walk. This makes the algorithm:
    - Impossible to reproduce for debugging,
    - Impossible to validate against known test vectors,
    - Non-deterministic in CI (a slow test could randomly exceed the iteration limit),
    - Unsuitable for cryptographic research where reproducibility is mandatory.
  - Severity: Critical
  - Fix: Accept a SeedableRng parameter (e.g., ChaCha8Rng) in KangarooParams, or at minimum use SeedableRng::from_seed([fixed_seed; 32]) derived from the input signature hash.
  - Tradeoff: Slightly more parameter plumbing; reproducibility is worth it.
  - Affects: Correctness, operability, testability

  C-2: Kangaroo Performs Projective-to-Affine Conversion on Every Step

  - Location: src/search/kangaroo.rs:189-198
  - Root cause: kangaroo_step calls point.to_affine() and to_encoded_point(true) to extract 8 bytes for partitioning. This is done twice per loop iteration (tame + wild).
  - Why it matters: A projective-to-affine conversion requires a modular field inversion, which is ~100× more expensive than projective point addition. The kangaroo's hot path is
  dominated by inversion cost rather than group operations, likely making it 1–2 orders of magnitude slower than claimed and causing false negatives on the iteration timeout.
  - Severity: Critical
  - Fix: Derive the partition index directly from projective coordinates. For secp256k1, you can use the X/Z (or a hash of the projective triple) to derive the jump index without
  inversion. Only convert to affine when storing or checking a distinguished point.
  - Tradeoff: Requires custom projective hashing, but this is standard in optimized kangaroo implementations.
  - Affects: Speed, correctness (timeout false-negatives)

  C-3: Segmented BSGS Has Quadratic Runtime

  - Location: src/search/bsgs.rs:80-143
  - Root cause: For each baby-step segment, the code rebuilds the baby map and then runs all giant steps against that segment. If m = sqrt(N) and the segment size is S, the number of
  segments is ceil(m/S), and total giant-step evaluations are ceil(m/S) * m = O(m²/S).
  - Why it matters: If N = 2^56 were ever dispatched to BSGS (it isn't today, but could be if thresholds change or the API is called directly), m = 2^28 and S = 2^27, giving 2 * 2^28 =
  2^29 evaluations instead of 2^28 — a 2× penalty. If S were smaller, the blowup becomes catastrophic (e.g., 32× for m = 2^32). In the current dispatch this path is dead code, but it is a
   correctness trap.
  - Severity: High
  - Fix: Segment the giant steps, not the baby steps. Build the full baby-step table once (in memory or on disk), then stream giant steps in segments. Alternatively, remove segmented BSGS
   entirely and dispatch everything above 2^48 to kangaroo with a deterministic seed.
  - Tradeoff: Simpler code if you remove the segmented path; more engineering if you fix it properly.
  - Affects: Speed, correctness under parameter changes

  C-4: derive_private_key Does Not Defend Against i128::MIN Overflow in unsigned_abs

  - Location: src/crypto.rs:40-47
  - Root cause: nonce.unsigned_abs() for i128::MIN returns 2^127 as u128. Scalar::from(u128) in k256 reduces modulo the curve order. The subtraction beta - alpha * s is algebraically
  correct in the field, but the code path is only smoke-tested (test_derive_private_key_i128_min has no assertion).
  - Why it matters: If a caller searches near i128::MIN and the test is misleadingly passing, a mathematician might assume correctness is verified when it is not.
  - Severity: Medium
  - Fix: Add a property assertion in the test: derive_private_key(i128::MIN, alpha, beta) == beta - alpha * Scalar::from(1u128 << 127).
  - Tradeoff: None.
  - Affects: Test correctness

  C-5: Parallel Scan Uses Wrapping Addition for Candidate Index Tracking

  - Location: src/search/parallel.rs:76
  - Root cause: d0 = d0.wrapping_add(scan.step) tracks the candidate nonce as an i128. If start is near i128::MAX and step is positive, this silently wraps around.
  - Why it matters: The search will silently evaluate the wrong nonce values without error. SearchSpec::new does not validate that start + total*step fits in i128.
  - Severity: High
  - Fix: Replace wrapping_add with checked_add and break/return error on overflow, or validate the full span in SearchSpec::new.
  - Tradeoff: One extra branch per batch (amortized cost is negligible).
  - Affects: Correctness

  C-6: Identity Point Encoding Assumption in BSGS

  - Location: src/search/bsgs.rs:25 (IDENTITY_KEY), build_baby_steps, run_giant_steps
  - Root cause: The code assumes the identity point's compressed encoding is [0u8; 33]. On secp256k1 (prime order), step_point will not return to identity for j < n, so this is
  theoretically unreachable in the current dispatch. However, if alpha * step == 0 (handled upstream), or if the code is reused on a curve with cofactor, this assumption breaks.
  - Why it matters: Fragile invariant that is not documented or enforced. The sentinel key is coupled to an implementation detail of k256.
  - Severity: Medium
  - Fix: Document the prime-order assumption explicitly in bsgs.rs, and add a debug_assert! that affine_key(&AffinePoint::IDENTITY) == IDENTITY_KEY in a test.
  - Tradeoff: None.
  - Affects: Maintainability, safety

  C-7: Kangaroo Collision Logic for step != 1 Is Untested for Matches

  - Location: src/search/kangaroo.rs:151-167, search/tests.rs:429-447
  - Root cause: test_kangaroo_step_not_one asserts found == None because the fixture nonce 5 is not in the {0,2,4,6,8} set. There is no test where the target nonce IS present with step !=
   1.
  - Why it matters: The collision reconstruction formula candidate = params.start + params.step * delta may be correct for step=1 but could have an off-by-one or scaling bug for step != 1
   that is never caught.
  - Severity: High
  - Fix: Add a test: start=0, step=3, total=10 with a fixture whose nonce is 9 (the third step), and assert found == Some(9).
  - Tradeoff: None.
  - Affects: Correctness

  ---
  Rust Safety and Code Quality Issues

  R-1: OpenMap Panics on Saturation

  - Location: src/search/openmap.rs:56
  - Root cause: insert panics with "OpenMap is full" when self.len >= self.entries.len(). There is no resize or growth path.
  - Why it matters: Quadratic probing on a power-of-two table can cluster more aggressively than the 0.7 load factor assumes. A carefully crafted or unlucky input set can hit this panic.
  In BSGS, the caller knows the exact size, but the panic path is still a DoS vector if the API is ever exposed to dynamic input.
  - Severity: High
  - Fix: Return Result<(), OpenMapError> from insert, or implement automatic growth (double + rehash) when load exceeds a threshold.
  - Tradeoff: API change from infallible to fallible; BSGS would need to propagate the error.
  - Affects: Safety, reliability

  R-2: Dead TOMBSTONE State in OpenMap

  - Location: src/search/openmap.rs:6, insert:64, get:90-92
  - Root cause: TOMBSTONE is defined and checked in insert/get, but no code ever transitions an entry to TOMBSTONE. It is unreachable code.
  - Why it matters: Dead code increases cognitive load and suggests incomplete design. The iterator also doesn't need to skip tombstones.
  - Severity: Low
  - Fix: Remove the TOMBSTONE variant and all related branches, or implement remove if deletion is needed.
  - Tradeoff: Minor code simplification.
  - Affects: Maintainability

  R-3: file.try_clone().expect() Can Panic in Production

  - Location: src/logging.rs:77
  - Root cause: The tracing layer writer closure calls file.try_clone().expect("clone log file"). If the process is near its file descriptor limit (ulimit -n), this will panic and abort
  the process (release profile uses panic = "abort").
  - Why it matters: A production process under resource pressure will crash during logging initialization rather than returning a clean error.
  - Severity: Medium
  - Fix: Pre-clone the file handle once and share an Arc<File> or use a channel-based writer. If cloning is unavoidable, return an error instead of panicking.
  - Tradeoff: Slightly more complex logging setup; eliminates a panic path.
  - Affects: Safety, operability

  R-4: ShutdownToken Uses SeqCst Unnecessarily

  - Location: src/context.rs:37,46
  - Root cause: A single AtomicBool for shutdown signaling uses Ordering::SeqCst. For a simple "set once, read many" flag, Acquire/Release or even Relaxed would be sufficient and faster
  on weakly ordered architectures.
  - Why it matters: Not a bug, but wastes memory barriers in the hot loop of every search worker. At high thread counts and low work per check, this is measurable.
  - Severity: Low
  - Fix: Change to self.inner.store(true, Ordering::Release) and self.inner.load(Ordering::Acquire).
  - Tradeoff: Negligible risk; better performance.
  - Affects: Speed

  R-5: main.rs Panic on Signal Handler Setup

  - Location: src/main.rs:36
  - Root cause: signal_hook::iterator::Signals::new(...).expect("signals") panics if signal registration fails (e.g., on systems that restrict signal handlers).
  - Why it matters: Startup crash on restricted environments.
  - Severity: Low
  - Fix: Convert to a proper error message and exit code.
  - Tradeoff: None.
  - Affects: Safety, operability

  R-6: SearchEngine Carries Test-Only Field in Production

  - Location: src/search/mod.rs:47,92-98,203-216
  - Root cause: bsgs_max_m: u64 is stored in every SearchEngine instance, but is only meaningful for #[cfg(test)] paths. The with_params constructor is test-gated, yet the field lives in
  release builds.
  - Why it matters: Minor bloat and blurred abstraction boundaries. The public bsgs_max_m is hardcoded in production.
  - Severity: Low
  - Fix: Remove the field from the production struct; use a test-only wrapper or type parameter.
  - Tradeoff: Requires more test scaffolding.
  - Affects: Maintainability

  ---
  Modular Design Issues

  M-1: CLI Module Mixes Parsing, Business Logic, and I/O

  - Location: src/cli.rs
  - Root cause: cli.rs contains clap derive macros, run_search, run_example, write_outcome, resolve_path, and private test helpers. This violates single responsibility.
  - Why it matters: Testing run_search requires constructing CLI args. The log-file path resolution logic is tangled with the search orchestration.
  - Severity: Medium
  - Fix: Split into cli/args.rs (parsing), cli/run.rs (orchestration), and output.rs (report formatting).
  - Tradeoff: More files, but cleaner boundaries.
  - Affects: Maintainability, testability

  M-2: KangarooParams Exposes Internal Tuning Knobs Without Validation

  - Location: src/search/params.rs:49-69, src/search/mod.rs:156-168
  - Root cause: d and max_iterations are public fields with no invariant checks. d=0 would mark every point as distinguished, causing memory explosion. max_iterations=0 causes immediate
  failure.
  - Why it matters: Public API footguns for library consumers.
  - Severity: Medium
  - Fix: Add a KangarooParams::new constructor that validates d > 0, max_iterations > 0, and computes max_iterations from total with a sensible multiplier rather than exposing it
  directly.
  - Tradeoff: Less flexibility for power users, safer defaults.
  - Affects: Safety, maintainability

  ---
  Reliability and Resilience Issues

  REL-1: No Checkpoint / Resume for Long Searches

  - Location: All search algorithms
  - Root cause: A BSGS search over N = 2^52 takes ~112 seconds and 10 GB of RAM. If a machine reboots or the process is killed at 111 seconds, all work is lost. There is no state
  serialization.
  - Why it matters: In production research or cloud environments, spot instances and maintenance windows are common. A long search should be resumable.
  - Severity: High
  - Fix: For BSGS, write the baby-step table to a mmap'd file or disk buffer and record the last-processed giant-step segment. On restart, load the table and resume giant steps. For
  kangaroo, write distinguished points to disk periodically.
  - Tradeoff: Significant engineering effort; requires a state file format and versioning.
  - Affects: Operability

  REL-2: No Memory Limit Enforcement

  - Location: src/search/bsgs.rs:21-23, src/search/openmap.rs:30-45
  - Root cause: BSGS allocates memory based on m = sqrt(N) with no upper bound other than BSGS_MAX_M. There is no check against available system memory. A user who accidentally passes a
  range near 2^54 to BSGS (if dispatch logic changes) could cause an OOM kill.
  - Why it matters: Unbounded memory growth is a denial-of-service vector.
  - Severity: Medium
  - Fix: Before allocating the OpenMap, check sysinfo or at least compute the expected bytes (len * sizeof(Entry)) and refuse if it exceeds a configurable memory cap.
  - Tradeoff: Requires a new dependency or syscall.
  - Affects: Reliability

  REL-3: Windows Has No Graceful Shutdown

  - Location: src/main.rs:28-45
  - Root cause: Signal handling is wrapped in #[cfg(unix)]. On Windows, Ctrl+C or Ctrl+Break terminates the process immediately without giving workers a chance to stop.
  - Why it matters: Windows users running large BSGS searches lose progress and leave corrupted/empty log files.
  - Severity: Medium
  - Fix: Use ctrlc crate or windows_sys SetConsoleCtrlHandler for cross-platform shutdown.
  - Tradeoff: Extra dependency.
  - Affects: Operability

  REL-4: Log Directory Creation Failure Not Distinguishable

  - Location: src/config.rs:73-75
  - Root cause: Config::from_env creates the log directory. If this fails (permissions, disk full, read-only FS), the error is propagated but the binary exits before any logging is
  initialized, so the user sees only a stderr message.
  - Why it matters: In containerized environments with misconfigured volumes, this is a common failure mode.
  - Severity: Low
  - Fix: Already handled via ConfigError::LogDirCreate. The error message is adequate.
  - Tradeoff: None.
  - Affects: Operability

  ---
  Performance Bottlenecks

  P-1: Kangaroo Hot-Path Field Inversions (Reiteration)

  - Location: src/search/kangaroo.rs:189-199
  - Impact: Each kangaroo step calls to_affine(), which is an inversion. Two steps per iteration (tame + wild) = ~2 inversions per loop. A kangaroo walk on N = 2^56 does ~`2^28 group
  operations per thread. At 2 inversions per step, this is ~2^29 inversions. An inversion on secp256k1 is ~250 multiplications. Total equivalent multiplications: ~2^29 * 250 ≈ 1.3e11`. A
  modern CPU does ~1e8 field ops/sec. Estimated wall time: ~20 minutes per thread just for inversions, not counting additions or distinguished-point checks. The README claims 180s total
  for kangaroo — this is only achievable if the inversion cost is eliminated.
  - Fix: Work in projective coordinates for step partitioning. Only convert to affine for DP storage.
  - Severity: Critical

  P-2: BSGS Baby-Step Merge Copies All Data

  - Location: src/search/bsgs.rs:261-320
  - Root cause: Per-thread OpenMaps are built in parallel, then merged sequentially into a single OpenMap. Peak memory is ~2× the final table size.
  - Impact: For m = 2^27, peak memory is ~20 GB instead of ~10 GB.
  - Fix: Build directly into a single pre-allocated OpenMap using atomic insert slots or lock-free chaining. Alternatively, keep the maps sharded and do a sharded lookup in
  run_giant_steps (like the kangaroo DP table does).
  - Severity: Medium
  - Tradeoff: Sharded lookup adds some overhead but saves 2× memory.

  P-3: OpenMap Hash Function Only Hashes First 8 Bytes

  - Location: src/search/openmap.rs:48
  - Root cause: (self.hasher.hash_one(&key[..8]) as usize) & self.mask. The first byte of a compressed key is always 0x02 or 0x03, so only 7 bytes of entropy are used.
  - Impact: For m = 2^27 entries, 7 bytes (56 bits) of entropy is below the birthday bound of 2^27.5, increasing collision rate and probing depth. Not catastrophic, but suboptimal.
  - Fix: Hash the full 33-byte key, or at least a 16-byte prefix using FxHash on two chunks.
  - Severity: Low
  - Tradeoff: Negligible latency increase for much better distribution.

  P-4: run_giant_steps Reconstructs the Batch Vec on Every Inner Loop

  - Location: src/search/bsgs.rs:175-198
  - Root cause: Vec::with_capacity(batch_size) is created fresh for every batch. The allocation is small (8192 * size_of::()), but in a tight loop it adds allocator pressure.
  - Impact: Minor but measurable in microbenchmarks.
  - Fix: Reuse a thread_local! or pool-local buffer with clear().
  - Severity: Low

  ---
  Test and Verification Gaps

  T-1: No Property-Based Tests

  - Gap: No proptest or quickcheck coverage for OpenMap, parse_scalar, parse_int, or search invariants.
  - Why it matters: Edge cases like overflow, hash collisions, and boundary values are poorly explored.
  - Fix: Add proptest tests for OpenMap with random keys, parse_scalar with hex/dec strings, and round-trip derive_private_key + derive_affine_constants.

  T-2: Kangaroo Stress Test Is Ignored

  - Location: src/search/tests.rs:503-523
  - Gap: test_kangaroo_stress is #[ignore]. It should run in CI to catch nondeterministic failures.
  - Fix: Remove #[ignore] and run it in CI, or add a dedicated CI job for slow tests.

  T-3: No Test for BSGS with step != 1 or Negative Start

  - Gap: BSGS tests only use step=1, start >= 0. The segmented and standard paths are not validated with asymmetric ranges.
  - Fix: Add tests: start=-1000, step=7, total=500 with a known fixture nonce in the sequence.

  T-4: test_derive_private_key_i128_min Has No Assertion

  - Location: src/crypto.rs:308-312
  - Gap: It calls the function but does not assert the result.
  - Fix: Add an equality assertion against a known-correct computation.

  T-5: No Fuzzing Harness

  - Gap: No cargo-fuzz or libfuzzer targets for parse_scalar, parse_pubkey, parse_int, or OpenMap.
  - Fix: Add a simple fuzz target for parse_scalar that feeds random strings and checks it either returns Ok or a known error variant.

  T-6: No Benchmark for Segmented BSGS

  - Gap: The benchmark file has a TODO for BSGS with OpenMap vs FxHashMap. Segmented BSGS is not benchmarked at all.
  - Fix: Add a parameterized benchmark for BSGS across range sizes 2^32 to 2^48.

  ---
  Production-Readiness Gaps

  PR-1: No Zeroization of Sensitive Values

  - Location: src/crypto.rs, src/domain.rs, src/cli.rs
  - Gap: Scalars (alpha, beta, nonce, d) are held in k256::Scalar and written to BufWriter/tracing logs. There is no use of the zeroize crate to clear stack or heap copies.
  - Fix: Add zeroize as a dependency. Implement ZeroizeOnDrop for a wrapper around Scalar, or at minimum call zeroize() on local Scalar variables before function exit. For the log file,
  warn users that recovered keys are written in plaintext.

  PR-2: No Checkpoint / Resume (Reiteration)

  - Gap: All algorithms are stateless and ephemeral. Long-running processes cannot survive interruption.
  - Fix: Design a simple JSON or binary checkpoint format storing algorithm state, last evaluated index, and baby-step table path.

  PR-3: Missing #[forbid(unsafe_code)]

  - Location: src/lib.rs
  - Gap: The crate contains no unsafe, but there is no compile-time guarantee it won't be introduced later.
  - Fix: Add #![forbid(unsafe_code)] to lib.rs.

  PR-4: Metrics Are Logging-Only

  - Location: src/metrics.rs
  - Gap: TracingMetricsSink emits human-readable tracing lines. There is no structured export (Prometheus, StatsD, JSON) for production monitoring.
  - Fix: Add a JsonMetricsSink or PrometheusMetricsSink behind a feature flag.

  PR-5: Release Profile Strips Symbols

  - Location: Cargo.toml:43
  - Gap: strip = "symbols" makes production crashes (e.g., from OpenMap panic or OOM) impossible to debug with backtraces.
  - Fix: Move strip = "symbols" to a separate [profile.dist] or remove it. Keep strip = "debuginfo" if binary size matters.

  PR-6: No Rate Limiting or Input Size Warnings

  - Gap: A user can pass --end 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF and --start 0, creating a total that overflows u128 or consumes absurd memory. The dispatch will send it to kangaroo with
   max_iterations = 10 * sqrt(total), which is still huge.
  - Fix: Add a total cap or warning in SearchSpec::new or the CLI layer.

  ---
  Recommended Refactors

  RF-1: Extract Projective Partition Function for Kangaroo

  Create a k256::ProjectivePoint → u64 hash that does not require inversion. Use this for kangaroo_step and only call to_affine() inside is_distinguished when storing a DP. This is the
  single highest-impact performance refactor.

  RF-2: Deterministic Kangaroo with Seeded RNG

  Replace rand::thread_rng() with ChaCha8Rng::from_seed(hash_of(signature || target || range)). This guarantees reproducibility, enables replay debugging, and makes CI deterministic.

  RF-3: Shard BSGS Baby-Step Lookup

  Instead of merging per-thread OpenMaps into a monolithic table, keep them sharded by the high bits of the hash key (or by thread ID). run_giant_steps then queries the appropriate
  shard(s) via a read lock or lock-free table. This eliminates the 2× memory peak and removes the serial merge bottleneck.

  RF-4: Add checked_add in Parallel Scan

  Replace wrapping_add with checked_add in parallel.rs and propagate the error. This eliminates silent overflow.

  RF-5: Split cli.rs into Parser / Runner / Output modules

  Separate clap structs, search orchestration, and report formatting into distinct modules for better testability.

  ---
  Quick Wins

  ┌───────────────────────────────────────────────────────────────┬────────┬────────────────────────────┐
  │                            Action                             │ Effort │           Impact           │
  ├───────────────────────────────────────────────────────────────┼────────┼────────────────────────────┤
  │ Add #[forbid(unsafe_code)] to lib.rs                          │ 1 min  │ Safety guarantee           │
  ├───────────────────────────────────────────────────────────────┼────────┼────────────────────────────┤
  │ Replace wrapping_add with checked_add in parallel.rs          │ 5 min  │ Eliminates silent overflow │
  ├───────────────────────────────────────────────────────────────┼────────┼────────────────────────────┤
  │ Hash full 33-byte key in OpenMap                              │ 5 min  │ Better distribution        │
  ├───────────────────────────────────────────────────────────────┼────────┼────────────────────────────┤
  │ Remove dead TOMBSTONE code                                    │ 5 min  │ Cleaner code               │
  ├───────────────────────────────────────────────────────────────┼────────┼────────────────────────────┤
  │ Add assertion to test_derive_private_key_i128_min             │ 5 min  │ Test integrity             │
  ├───────────────────────────────────────────────────────────────┼────────┼────────────────────────────┤
  │ Add kangaroo step != 1 match test                             │ 10 min │ Coverage gap               │
  ├───────────────────────────────────────────────────────────────┼────────┼────────────────────────────┤
  │ Change ShutdownToken to Acquire/Release                       │ 5 min  │ Performance                │
  ├───────────────────────────────────────────────────────────────┼────────┼────────────────────────────┤
  │ Replace file.try_clone().expect() with fallible clone + error │ 15 min │ Eliminates panic path      │
  ├───────────────────────────────────────────────────────────────┼────────┼────────────────────────────┤
  │ Remove strip = "symbols" from release profile                 │ 1 min  │ Debuggability              │
  └───────────────────────────────────────────────────────────────┴────────┴────────────────────────────┘

  ---
  Long-Term Improvements

  1. Checkpoint/resume system for BSGS and kangaroo with a versioned state file format.
  2. Projective-coordinate kangaroo (no per-step affine conversion) for 10–100× speedup.
  3. Property-based test suite (proptest) covering parse_scalar, OpenMap, and round-trip crypto derivations.
  4. Fuzzing harness for all parsing functions.
  5. Zeroization integration (zeroize + ZeroizeOnDrop) for all secret-bearing types.
  6. Cross-platform signal handling for Windows graceful shutdown.
  7. Memory-bounded BSGS with automatic fallback to kangaroo if RAM is insufficient.
  8. Distributed search protocol for multi-node kangaroo DP sharing.

  ---
  Overall Readiness Score: 6 / 10

  Rationale: The codebase is well-organized, idiomatic, and has good happy-path coverage. It correctly delegates hard cryptography to k256. However, the kangaroo implementation has
  critical defects (unseeded RNG, per-step affine conversion) that make it unsuitable for research or production use in its current state. The absence of zeroization, quadratic segmented
  BSGS, and silent integer overflow in the scan loop are blockers for environments where correctness and security are paramount. With focused fixes on the kangaroo path and overflow
  handling, this could reach 8–9/10 within a week.

  Confidence Level: High

  Basis: All source files were read in full. Tests pass (cargo test --all-features --all-targets). Clippy passes. The repository is small enough (~2,500 lines of non-test code) to allow
  exhaustive manual review. No hidden dependencies or build scripts. Assumptions are explicitly stated below.

  Explicit assumptions:
  - k256 v0.13.4 is assumed correct for field arithmetic, point operations, and batch normalization. This audit did not review k256 internals.
  - The secp256k1 curve is assumed to have prime order, making small-order point assumptions safe.
  - Performance claims in the README were not independently benchmarked; the kangaroo slowdown analysis is based on operation-count estimates.

  Concrete Next Actions

  1. Immediate (today): Open an issue/PR to seed the kangaroo RNG and replace to_affine() in kangaroo_step with a projective partition function. These are the highest-impact fixes.
  2. This week: Add checked_add in parallel.rs, remove TOMBSTONE dead code, fix OpenMap to hash the full key, and add the missing step != 1 kangaroo test.
  3. This sprint: Integrate zeroize for Scalar secrets, add #[forbid(unsafe_code)], and remove strip = "symbols" from release.
  4. Next sprint: Implement BSGS sharded lookup to eliminate the 2× memory peak, and add checkpoint/resume scaffolding.
  5. Ongoing: Add proptest and fuzz targets to CI, and run the ignored test_kangaroo_stress nightly.
