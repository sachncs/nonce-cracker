.PHONY: all build test lint clean fmt fmt-check clippy doc check bench install-hooks

# Default target
all: build

## Build commands
build:
	cargo build --release

build-debug:
	cargo build

## Test commands
test:
	cargo test --all-features --all-targets

test-verbose:
	cargo test --all-features --all-targets -- --nocapture

test-doc:
	cargo test --doc

## Format commands
fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

## Lint commands
clippy:
	cargo clippy --all-targets --all-features -- -D warnings

clippy-fix:
	cargo clippy --all-targets --all-features --fix --allow-dirty

## Documentation
doc:
	cargo doc --no-deps --document-private-items

doc-open: doc
	@case "$$OSTYPE" in \
		darwin*) open target/doc/nonce_crate/index.html ;; \
		linux*) xdg-open target/doc/nonce_crate/index.html ;; \
		*) echo "Open target/doc/nonce_crate/index.html manually" ;; \
	esac

## Benchmarking
bench:
	cargo bench --no-terminal

bench-html:
	cargo bench
	@echo "Open target/criterion/report/index.html for results"

## Clean
clean:
	cargo clean

## Full check (format + lint + test)
check: fmt-check clippy test

## Install git hooks
install-hooks:
	@if [ ! -d .git ]; then echo "Not a git repository"; exit 1; fi
	@mkdir -p .git/hooks
	cp .githooks/pre-commit .git/hooks/
	chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed"

## Run example
run-example:
	cargo run --example

## Help
help:
	@echo "Available targets:"
	@echo "  build        - Build release binary (default)"
	@echo "  build-debug  - Build debug binary"
	@echo "  test         - Run all tests"
	@echo "  test-verbose - Run tests with output"
	@echo "  fmt          - Format code"
	@echo "  fmt-check    - Check formatting"
	@echo "  clippy       - Run clippy lints"
	@echo "  clippy-fix   - Auto-fix clippy issues"
	@echo "  doc          - Generate documentation"
	@echo "  bench        - Run benchmarks"
	@echo "  check        - Full check (fmt + clippy + test)"
	@echo "  clean        - Remove build artifacts"
	@echo "  install-hooks - Install pre-commit hooks"
	@echo "  run-example  - Run example"
	@echo "  help         - Show this help"
