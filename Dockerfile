# Multi-stage build for production-grade container
# Stage 1: Build environment
FROM rust:1.78.0-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency manifests first for better layer caching
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./

# Copy source code
COPY src/ ./src/

# Build release binary
RUN cargo build --release

# Stage 2: Production image
FROM debian:bookworm-slim AS production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r appuser && useradd -r -g appuser appuser

# Create log directory with proper permissions
RUN mkdir -p /app/logs && chown appuser:appuser /app/logs

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/nonce-cracker /app/nonce-cracker

# Set ownership
RUN chown appuser:appuser /app/nonce-cracker

# Switch to non-root user
USER appuser

# Set environment defaults
ENV NONCE_CRACKER_LOG_DIR=/app/logs \
    NONCE_CRACKER_LOG_LEVEL=info \
    NONCE_CRACKER_MAX_THREADS=256 \
    RUST_BACKTRACE=1

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD /app/nonce-cracker --help > /dev/null || exit 1

ENTRYPOINT ["/app/nonce-cracker"]
CMD ["example"]

# Stage 3: Development image (includes build tools)
FROM builder AS development

RUN apt-get update && apt-get install -y \
    gdb \
    valgrind \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
CMD ["/bin/bash"]
