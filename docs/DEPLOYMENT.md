# Deployment & Production Hardening Checklist

This document is a production-hardening checklist for operators who already
know how to run a Rust CLI binary. It does not prescribe a specific
orchestration system: the binary is stateless, runs once per search, and
exits. Prometheus, Kubernetes, and friends are out of scope for this
project; the tool emits structured tracing logs only.

## Production hardening checklist

- [ ] Run the binary with a non-root user (UID ≥ 1000).
- [ ] Set explicit CPU and memory limits appropriate to the search range.
- [ ] Mount a writable log directory (default `logs/`) and checkpoint
      directory (default `checkpoints/`).
- [ ] Forward the log directory to your log aggregator; the binary writes
      compact-format `tracing` lines, one per event.
- [ ] Set `NONCE_CRACKER_LOG_LEVEL` to `warn` (or higher) for unattended
      jobs to keep log volume bounded.
- [ ] Set `NONCE_CRACKER_LOG_CONSOLE=false` when stdout is captured by a
      log shipper, to avoid duplicate lines.
- [ ] Verify `--outfile` resolves to a writable path (or set it to an
      absolute path under the mounted log directory).
- [ ] Decide on the signal-handling posture: the binary installs a
      `ctrlc` handler so `SIGINT`/`SIGTERM` triggers a graceful
      shutdown. Allow `terminationGracePeriodSeconds` accordingly.
- [ ] Cap `--threads` to the orchestrator's CPU budget via
      `NONCE_CRACKER_MAX_THREADS`.
- [ ] Choose `--start` and `--end` such that
      `floor((end - start) / step) + 1 ≤ 2^64` (the internal guard in
      `SearchSpec::new`).
- [ ] Pin the tool version in your build artifact and update it
      deliberately; `cargo deny check` is the project's gating supply-chain
      check, but you should also revalidate against the RustSec advisory
      database before upgrading.

## Local development

For local runs and CI, the project provides a Makefile with the usual
targets (`make build`, `make test`, `make clippy`, `make fmt-check`,
`make install-hooks`).

## Troubleshooting

If a search does not appear to make progress:

1. Verify the signature verifies against the public key with
   `verify_ecdsa_signature` (the binary already does this and exits with
   `InvalidSignature` on failure).
2. Check that `--start ≤ nonce ≤ --end` and that `nonce mod step == start mod step`.
3. Reduce the search range. BSGS uses O(sqrt(N)) time and memory; kangaroo
   uses O(sqrt(N)) time and O(sqrt(N) / 2^d) memory.
4. Inspect the structured log: the `event="search_complete"` line reports
   `found`, `nonce`, `elapsed_sec`, and `threads`.

## Support

- File an issue: <https://github.com/sachncs/nonce-cracker/issues>
- Security disclosures: <https://github.com/sachncs/nonce-cracker/security/advisories/new>
