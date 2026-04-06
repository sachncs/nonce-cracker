# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `recover` command with user-specified argument order (r1, s1, z1, r2, s2, z2)
- Comprehensive documentation (README, CONTRIBUTING, inline rustdoc)
- Criterion benchmarks for performance regression tracking
- Integration tests for CLI commands
- Pre-commit hooks for local CI validation

### Changed
- Improved error handling with descriptive error types
- CLI help text with detailed descriptions
- `run` command now accepts arguments in fixed order (r1, r2, s1, s2, z1, z2)

## [0.1.0] - 2024-01-01

### Added
- Initial release
- Parallel ECDSA key search using affine relation attack
- Support for secp256k1 signatures
- Parallel processing with Rayon
- CLI interface with clap
- Unit tests for core cryptographic functions
- Example mode for quick demonstration

### Fixed
- None

### Deprecated
- None

### Security
- None reported
