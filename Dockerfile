# Stable upstream images are pinned to their multi-platform manifest digests.
FROM rust:1.99.0-slim-trixie@sha256:0952c7a429d2f53c7f1f5e0796190690e7d8db367ec4a66ce0419763b9e5e0d0 AS builder
# Distribution packages receive security updates during builds.
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
ARG CARGO_BUILD_JOBS=4
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
RUN cargo build --locked --release --package fluxencrypt-cli --all-features

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3t64 && rm -rf /var/lib/apt/lists/* && useradd -r -s /bin/false fluxencrypt
COPY --from=builder /app/target/release/fluxencrypt-cli /usr/local/bin/fluxencrypt
RUN mkdir -p /data && chown fluxencrypt:fluxencrypt /data
USER fluxencrypt
WORKDIR /data
ARG VERSION=latest
LABEL org.opencontainers.image.title="FluxEncrypt" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/ThreatFlux/FluxEncrypt" \
      org.opencontainers.image.licenses="MIT"
ENTRYPOINT ["/usr/local/bin/fluxencrypt"]
CMD ["--help"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD /usr/local/bin/fluxencrypt --version || exit 1
