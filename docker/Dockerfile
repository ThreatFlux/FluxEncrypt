# FluxEncrypt Docker Image
# Multi-stage build for optimized production image

# Build stage
FROM rust:1.89-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkgconf \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /usr/src/fluxencrypt

# Copy workspace configuration
COPY Cargo.toml Cargo.lock ./
COPY fluxencrypt/Cargo.toml ./fluxencrypt/
COPY fluxencrypt-cli/Cargo.toml ./fluxencrypt-cli/
COPY fluxencrypt-async/Cargo.toml ./fluxencrypt-async/

# Create dummy source files to cache dependencies
RUN mkdir -p fluxencrypt/src fluxencrypt-cli/src fluxencrypt-async/src \
    && echo "fn main() {}" > fluxencrypt-cli/src/main.rs \
    && echo "fn main() {}" > fluxencrypt/src/lib.rs \
    && echo "fn main() {}" > fluxencrypt-async/src/lib.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release --workspace
RUN rm -rf fluxencrypt/src fluxencrypt-cli/src fluxencrypt-async/src

# Copy actual source code
COPY . .

# Build the application
RUN cargo build --release --bin fluxencrypt-cli

# Runtime stage (distroless eliminates OS-level CVEs)
FROM gcr.io/distroless/cc-debian12:nonroot

# Copy the binary from builder stage
COPY --from=builder /usr/src/fluxencrypt/target/release/fluxencrypt-cli /usr/local/bin/fluxencrypt-cli

# Default command (nonroot tag runs as uid 65534 by default)
ENTRYPOINT ["fluxencrypt-cli"]
CMD ["--help"]

# Labels for metadata
LABEL org.opencontainers.image.title="FluxEncrypt"
LABEL org.opencontainers.image.description="Secure encryption SDK and CLI"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.authors="Wyatt Roersma, Claude Code, Codex"
LABEL org.opencontainers.image.vendor="ThreatFlux Organization"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.documentation="https://github.com/ThreatFlux/fluxencrypt"
LABEL org.opencontainers.image.source="https://github.com/ThreatFlux/fluxencrypt"
