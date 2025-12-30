# Multi-stage build for FluxEncrypt
# Stage 1: Build the application
FROM rust:1.89-slim AS builder

# Install required dependencies (versions managed by base image)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkgconf \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY fluxencrypt/Cargo.toml ./fluxencrypt/
COPY fluxencrypt-cli/Cargo.toml ./fluxencrypt-cli/
COPY fluxencrypt-async/Cargo.toml ./fluxencrypt-async/

# Create dummy main files to cache dependencies
RUN mkdir -p fluxencrypt/src fluxencrypt/examples fluxencrypt/benches fluxencrypt-cli/src fluxencrypt-async/src && \
    echo "fn main() {}" > fluxencrypt/src/lib.rs && \
    echo "fn main() {}" > fluxencrypt/examples/basic_encryption.rs && \
    echo "fn main() {}" > fluxencrypt/examples/file_encryption.rs && \
    echo "fn main() {}" > fluxencrypt/examples/key_management.rs && \
    echo "fn main() {}" > fluxencrypt/examples/environment_config.rs && \
    echo "fn main() {}" > fluxencrypt/benches/encryption_benchmarks.rs && \
    echo "fn main() {}" > fluxencrypt-cli/src/main.rs && \
    echo "fn main() {}" > fluxencrypt-async/src/lib.rs

# Build dependencies
RUN cargo build --release --package fluxencrypt-cli

# Remove dummy files
RUN rm -rf fluxencrypt/src fluxencrypt/examples fluxencrypt/benches fluxencrypt-cli/src fluxencrypt-async/src

# Copy actual source code
COPY fluxencrypt/src ./fluxencrypt/src
COPY fluxencrypt/examples ./fluxencrypt/examples
COPY fluxencrypt/benches ./fluxencrypt/benches
COPY fluxencrypt-cli/src ./fluxencrypt-cli/src
COPY fluxencrypt-async/src ./fluxencrypt-async/src

# Build the application
RUN touch fluxencrypt/src/lib.rs fluxencrypt-cli/src/main.rs fluxencrypt-async/src/lib.rs && \
    cargo build --release --package fluxencrypt-cli

# Stage 2: Create minimal runtime image
FROM debian:trixie-slim

# Install runtime dependencies (versions managed by base image)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3t64 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash fluxencrypt

# Copy binary from builder
COPY --from=builder /app/target/release/fluxencrypt-cli /usr/local/bin/fluxencrypt

# Set ownership and permissions
RUN chown fluxencrypt:fluxencrypt /usr/local/bin/fluxencrypt && \
    chmod 755 /usr/local/bin/fluxencrypt

# Switch to non-root user
USER fluxencrypt
WORKDIR /home/fluxencrypt

# Set version label
ARG VERSION=latest
LABEL version="${VERSION}"
LABEL description="FluxEncrypt - High-performance Rust encryption SDK"
LABEL maintainer="ThreatFlux"

# Default command
ENTRYPOINT ["/usr/local/bin/fluxencrypt"]
CMD ["--help"]