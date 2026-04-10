# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Future changes will be listed here after the 0.2.0 release.

## [0.2.0] - 2026-04-10

### Added
- Signed bounded-delta search support, including negative CLI bounds and matching unit/integration coverage.
- Deterministic default log-file naming with collision-resistant uniqueness within a process.
- Formal derivation notes for the affine relation used by the recovery algorithm.
- CLI integration coverage for `run`, `recover`, and the bundled example workflow.
- Benchmark and sample-data consistency updates to keep generated ECDSA fixtures mathematically valid.

### Changed
- Consolidated CLI parsing and search execution into a shared validation path.
- Clarified public Rustdoc for the command surface and the core search helpers.
- Standardized search output formatting to use signed delta reporting.
- Aligned benchmark helpers with the production signed-delta model.

### Fixed
- Rejected invalid empty output paths before file creation.
- Accepted negative numeric CLI bounds as literal values instead of treating them as options.
- Corrected public-key validation to enforce full SEC1 decoding for uncompressed keys.
- Removed the possibility of default log-file collisions within one process.

### Breaking Changes
- The default demo command is now `example` instead of the previous `demo` naming used in earlier revisions.
- Search range arguments now accept signed values explicitly; callers relying on unsigned-only assumptions must update their invocation patterns.

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
