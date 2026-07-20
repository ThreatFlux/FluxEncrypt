# FluxEncrypt Docker Image
# Multi-stage build for optimized production image

# Build stage
FROM rust:1.95.0-bookworm AS builder

# Install build dependencies from the Bookworm repositories
# Track security updates from Bookworm; release artifacts pin the built image digest.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /usr/src/fluxencrypt

# Copy workspace configuration
COPY Cargo.toml Cargo.lock ./
COPY fluxencrypt/Cargo.toml ./fluxencrypt/
COPY fluxencrypt-cli/Cargo.toml ./fluxencrypt-cli/
COPY fluxencrypt-async/Cargo.toml ./fluxencrypt-async/

# Create dummy source files to cache dependencies
RUN mkdir -p fluxencrypt/src fluxencrypt/examples fluxencrypt/benches fluxencrypt-cli/src fluxencrypt-async/src \
    && echo "fn main() {}" > fluxencrypt-cli/src/main.rs \
    && echo "fn main() {}" > fluxencrypt/src/lib.rs \
    && echo "fn main() {}" > fluxencrypt/examples/basic_encryption.rs \
    && echo "fn main() {}" > fluxencrypt/examples/file_encryption.rs \
    && echo "fn main() {}" > fluxencrypt/examples/key_management.rs \
    && echo "fn main() {}" > fluxencrypt/examples/environment_config.rs \
    && echo "fn main() {}" > fluxencrypt/benches/encryption_benchmarks.rs \
    && echo "fn main() {}" > fluxencrypt-async/src/lib.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release --workspace
RUN rm -rf fluxencrypt/src fluxencrypt/examples fluxencrypt/benches \
    fluxencrypt-cli/src fluxencrypt-async/src

# Copy actual source code
COPY . .

# Build the application
RUN touch fluxencrypt/src/lib.rs fluxencrypt-cli/src/main.rs fluxencrypt-async/src/lib.rs && \
    cargo build --release --bin fluxencrypt-cli

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies from the Bookworm repositories
# Track security updates from Bookworm; release artifacts pin the built image digest.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && useradd -r -s /bin/false fluxencrypt

# Copy the binary from builder stage
COPY --from=builder /usr/src/fluxencrypt/target/release/fluxencrypt-cli /usr/local/bin/fluxencrypt-cli

# Set proper permissions
RUN chmod +x /usr/local/bin/fluxencrypt-cli

# Create data directory
RUN mkdir -p /data && chown fluxencrypt:fluxencrypt /data

# Switch to non-root user
USER fluxencrypt

# Set working directory
WORKDIR /data

# Default command
ENTRYPOINT ["fluxencrypt-cli"]
CMD ["--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD fluxencrypt-cli --version || exit 1

# Labels for metadata
LABEL org.opencontainers.image.title="FluxEncrypt"
LABEL org.opencontainers.image.description="Secure encryption SDK and CLI"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.authors="Wyatt Roersma, Claude Code, Codex"
LABEL org.opencontainers.image.vendor="ThreatFlux Organization"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.documentation="https://github.com/ThreatFlux/fluxencrypt"
LABEL org.opencontainers.image.source="https://github.com/ThreatFlux/fluxencrypt"
