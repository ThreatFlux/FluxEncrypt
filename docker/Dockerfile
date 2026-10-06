# Stable upstream images are pinned to their multi-platform manifest digests.
# Refresh a digest with:
#   docker buildx imagetools inspect <image> | awk '/^Digest:/{print $2}'
# Dependabot refreshes the Rust builder; refresh the runtime digest with the
# command above when it is updated.

# rust 1.99.0 on Debian 13 (trixie)
FROM rust:1.99.0-slim-trixie@sha256:24e632c09342c20abf8312cf4f61430a911c01ed3a5e4c02b87292b1c39c5273 AS builder
# tini is installed here so the runtime stage can copy it out: distroless ships
# no init, and PID 1 must reap zombies and forward signals. Package revisions
# follow the pinned base image's Debian 13 repositories.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends tini && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
ARG CARGO_BUILD_JOBS=4
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
# The CLI uses ring, not OpenSSL, so it needs only glibc and libgcc at runtime.
# The distroless runtime has no shell to mkdir with, so the writable /data
# directory is staged here and its ownership applied by COPY --chown.
RUN cargo build --locked --release --package fluxencrypt-cli --all-features && \
    mkdir -p /out/bin /out/data && \
    cp target/release/fluxencrypt-cli /out/bin/fluxencrypt-cli

# distroless cc on Debian 13, nonroot tag (uid/gid 65532)
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2
ARG VERSION=latest
LABEL org.opencontainers.image.title="FluxEncrypt" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/ThreatFlux/FluxEncrypt" \
      org.opencontainers.image.licenses="MIT"
COPY --from=builder /usr/bin/tini /usr/bin/tini
# The binary stays root-owned so the runtime user cannot modify it; only the
# working directory belongs to the nonroot user.
COPY --from=builder --chown=0:0 /out/bin/fluxencrypt-cli /usr/local/bin/fluxencrypt-cli
COPY --from=builder --chown=65532:65532 /out/data /data
USER 65532:65532
WORKDIR /data
# Exec form (there is no shell in distroless); a nonzero exit means unhealthy.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/fluxencrypt-cli", "--version"]
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/fluxencrypt-cli"]
CMD ["--help"]
