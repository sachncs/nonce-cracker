# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.6.x   | :white_check_mark: |
| 0.5.x   | :white_check_mark: |
| < 0.5   | :x:                |

## Security Features

This project includes several security-focused features for production deployments:

### Input Validation

- All hex inputs are validated before processing
- Public keys must conform to SEC1 format
- Search bounds are checked for overflow
- Thread counts are capped to prevent resource exhaustion

### Cryptographic Security

- Uses `k256` crate (audited by Trail of Bits)
- No unsafe Rust code in cryptographic paths
- Constant-time scalar operations where applicable
- Modular arithmetic uses verified algorithms

### Container Security

- Non-root container execution
- Minimal attack surface (no shell, minimal dependencies)
- Read-only filesystem where possible
- Resource limits enforced

### Dependency Security

- `cargo-deny` configuration for license/audit checks
- CI runs `cargo deny check` (license and ban checks) on every PR
- Dependencies pinned in Cargo.lock
- Minimal dependency tree

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue
2. Use [GitHub Security Advisories](https://github.com/sachncs/nonce-cracker/security/advisories/new) (preferred), or email `security@sachn.dev`
3. Include detailed reproduction steps
4. Allow time for response before public disclosure

We typically respond within 48 hours and aim to resolve critical issues within 7 days.

## Security Hardening Checklist

When deploying in production:

- [ ] Use container image with non-root user
- [ ] Set resource limits (CPU/memory)
- [ ] Store signature data as secrets, not ConfigMaps
- [ ] Enable structured logging (JSON format)
- [ ] Set appropriate log levels (avoid DEBUG in production)
- [ ] Configure graceful shutdown handling
- [ ] Use network policies to restrict egress
- [ ] Enable Pod Security Standards
- [ ] Regularly update dependencies
- [ ] Monitor for security advisories

## Known Limitations

1. **Side-channel attacks**: The current implementation does not implement constant-time defense against all side-channel attacks. This is acceptable for offline key recovery but not for online signing.

2. **Memory clearing**: Cryptographic values are zeroized via `Zeroize` + `Drop` on `Signature`, `SearchOutcome`, and temporary intermediates. However, the Rust allocator may retain freed memory temporarily.

3. **Error messages**: Error messages may contain sensitive information in debug builds. Use release builds for production.

4. **Checkpoint file sensitivity**: The plaintext checkpoint file under `NONCE_CRACKER_CHECKPOINT_DIR` contains the signature `(r, s, z)`, the target public key, and the search range. On Unix systems it is created with `0600` permissions and removed on successful completion; if the process is killed mid-search the file may be left on disk. Mount the checkpoint directory on a filesystem with strict permissions (e.g. `tmpfs` with `mode=0700`) and add it to your incident-response sweep.

## Security Testing

Regular security measures include:

- `cargo audit` runs in CI
- Clippy lints for unsafe code
- Dependency scanning via Dependabot
- Static analysis with cargo-deny

## Disclosure Policy

We follow responsible disclosure:

1. Reporter submits vulnerability privately
2. We acknowledge receipt within 48 hours
3. We investigate and develop fix
4. We coordinate disclosure timeline with reporter
5. Public disclosure after fix is available

## Acknowledgments

Security improvements in this release:
- Structured logging with sanitization
- Environment-based configuration (no hardcoded secrets)
- Signal handling for graceful shutdown
- Resource limits and rate limiting

## License

Security-related code is licensed under the MIT License.
