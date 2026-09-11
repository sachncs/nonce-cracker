# Contributing to nonce-cracker

Thank you for your interest in contributing to nonce-cracker!

## Getting Started

### Prerequisites

- Rust 1.87+
- Git
- make (optional, for convenience commands)

### Setup

```bash
# Clone your fork
git clone https://github.com/sachncs/nonce-cracker.git
cd nonce-cracker

# Add upstream remote
git remote add upstream https://github.com/sachncs/nonce-cracker.git

# Install pre-commit hooks (runs cargo fmt --check and cargo clippy)
make install-hooks
```

The pre-commit hook lives at `.githooks/pre-commit` and is copied into
`.git/hooks/` by `make install-hooks`.

## Development Workflow

### 1. Create a Branch

```bash
# Create a feature branch
git checkout -b feature/your-feature-name

# Or a bugfix branch
git checkout -b fix/issue-description
```

### 2. Make Changes

```bash
# Make your changes to the code
# ...

# Run tests
cargo test

# Run lints
cargo clippy --all-targets --all-features -- -D warnings

# Format code
cargo fmt --all
```

### 3. Commit

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**

```bash
git commit -m "feat(run): add new CLI flag for offset search"
git commit -m "fix(hex): handle uppercase 0X prefix in range parsing"
git commit -m "docs: update README with new CLI examples"
```

### 4. Push and Create PR

```bash
# Push your branch
git push origin feature/your-feature-name

# Create pull request via GitHub
```

## Coding Standards

### Rust Style Guide

We follow the [Rust Style Guide](https://doc.rust-lang.org/style-guide/):

- **Indentation**: 4 spaces
- **Line width**: 100 characters (soft limit)
- **Trailing commas**: In multiline constructs
- **Naming**:
  - Types: `UpperCamelCase`
  - Functions/variables: `snake_case`
  - Constants: `SCREAMING_SNAKE_CASE`

### Code Documentation

Document all public items with rustdoc:

```rust
/// Compute the affine constants `alpha` and `beta` from a single ECDSA signature.
///
/// # Arguments
///
/// * `sig` - The signature triplet `(r, s, z)`.
///
/// # Returns
///
/// `(alpha, beta)` such that `d = alpha * k - beta (mod n)` for the nonce `k`
/// that produced the signature, or [`CryptoError::RNotInvertible`] if `r` has
/// no inverse modulo the curve order.
///
/// # Example
///
/// ```
/// use nonce_cracker::{derive_affine_constants, parse_scalar, Signature};
///
/// let sig = Signature::new(
///     parse_scalar("0x1").unwrap(),
///     parse_scalar("0x3").unwrap(),
///     parse_scalar("0x5").unwrap(),
/// );
/// let (alpha, beta) = derive_affine_constants(&sig).unwrap();
/// ```
pub fn derive_affine_constants(sig: &Signature) -> Result<(Scalar, Scalar)> {
    // ...
}
```

### Error Handling

- Use `Result` types with custom `Error` enum
- Prefer `?` operator over `unwrap()` in non-test code
- Provide actionable error messages

### Testing

- Unit tests in `#[cfg(test)]` modules
- Integration tests in `tests/` directory
- All tests must pass: `cargo test`

## Testing Guidelines

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_mod_inverse

# Run with output
cargo test -- --nocapture

# Run doc tests
cargo test --doc
```

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that `derive_private_key(0, alpha, beta) == -beta`.
    #[test]
    fn test_derive_private_key_identity() {
        use k256::elliptic_curve::PrimeField;
        use k256::Scalar;

        let alpha = Scalar::from(3u64);
        let beta = Scalar::from(7u64);
        assert_eq!(derive_private_key(0, alpha, beta), Scalar::ZERO - beta);
    }
}
```

## Pre-commit Checklist

Before pushing:

- [ ] Code is formatted: `cargo fmt --all`
- [ ] No clippy warnings: `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] All tests pass: `cargo test`
- [ ] Documentation updated (if applicable)
- [ ] Commit message follows conventional format

## Pull Request Guidelines

### PR Title

Follow conventional commits:
- `feat(run): add new CLI command`
- `fix(crypto): correct modular inverse calculation`
- `docs: update installation instructions`

### PR Description

Include:
- **What**: Brief description of changes
- **Why**: Motivation and context
- **How**: Technical approach (if non-obvious)
- **Testing**: How the changes were tested

### Review Process

1. Automated checks must pass (CI)
2. At least one review approval required
3. Address reviewer feedback

## Reporting Issues

### Bug Reports

Include:
- Rust version: `rustc --version`
- nonce-cracker version: `nonce-cracker --version`
- OS and architecture
- Minimal reproducible example
- Expected vs actual behavior

### Feature Requests

Include:
- Clear use case
- Proposed solution (if any)
- Alternative solutions considered

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior via [GitHub Security Advisories](https://github.com/sachncs/nonce-cracker/security/advisories/new) or by emailing `security@sachn.dev`.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
