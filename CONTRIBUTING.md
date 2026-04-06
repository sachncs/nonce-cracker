# Contributing to nonce-cracker

Thank you for your interest in contributing to nonce-cracker!

## Getting Started

### Prerequisites

- Rust 1.75+
- Git
- make (optional, for convenience commands)

### Setup

```bash
# Clone your fork
git clone https://github.com/sachn-cs/nonce-cracker.git
cd nonce-cracker

# Add upstream remote
git remote add upstream https://github.com/sachn-cs/nonce-cracker.git

# Install pre-commit hooks
make install-hooks
```

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
git commit -m "feat(recover): add recover command with user-specified argument order"
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
/// Computes the modular inverse using extended Euclidean algorithm.
///
/// # Arguments
///
/// * `a` - The value to invert
/// * `n` - The modulus
///
/// # Returns
///
/// The value a⁻¹ mod n, or `Error::Calculation` if no inverse exists.
///
/// # Example
///
/// ```
/// let n = parse_hex(CURVE_ORDER_HEX).unwrap();
/// let inv = mod_inverse(&7, &n)?;
/// ```
pub fn mod_inverse(a: &BigInt, n: &BigInt) -> Result<BigInt> {
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

    /// Tests that modular inverse of a number equals 1 when multiplied.
    #[test]
    fn test_mod_inverse() {
        let n = parse_hex(CURVE_ORDER_HEX).unwrap();
        let a = BigInt::from(7u64);
        let inv = mod_inverse(&a, &n).unwrap();
        let prod = (a * inv) % &n;
        assert_eq!(prod, BigInt::one());
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
- `feat(recover): add new CLI command`
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

- Be respectful and inclusive
- Focus on constructive feedback
- Follow Rust's community guidelines

## License

By contributing, you agree that your contributions will be licensed under the same licenses as the project (MIT or Apache 2.0).
