# FluxEncrypt has no system TLS/DNS dependency: ring and Rust RSA are linked
# into a static PIE. Use Alpine's maintained musl archive, not Rust's bundled
# CRT, and prove the selected libc from the linker map on every architecture.
FROM rust:1.99.1-alpine3.24@sha256:557a94c82b485a14b569120e00867267108c734efe33f10cc31ca0cd5dd1eca9 AS builder
RUN apk add --no-cache build-base binutils cmake perl tini-static
WORKDIR /app
# Copy build inputs explicitly: security reports and workflow edits do not
# invalidate native compilation, and no generated credentials enter this stage.
COPY Cargo.toml Cargo.lock rust-toolchain.toml README.md LICENSE ./
COPY fluxencrypt/ fluxencrypt/
COPY fluxencrypt-cli/ fluxencrypt-cli/
COPY fluxencrypt-async/ fluxencrypt-async/
COPY tests/ tests/
ARG CARGO_BUILD_JOBS=4
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
RUN build_target="$(rustc -vV | sed -n 's/^host: //p')" && \
    mkdir -p /native-unwind /out/bin /out/data /out/etc /out/doc && \
    cp "$(rustc --print sysroot)/lib/rustlib/${build_target}/lib/self-contained/libunwind.a" /native-unwind/ && \
    RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=no -C linker=cc -C relocation-model=pic -C link-arg=-static-pie -L native=/native-unwind -C link-arg=-Wl,-Map=/native-link.map" \
      cargo build --locked --release --target "${build_target}" --package fluxencrypt-cli --all-features && \
    musl_archive="$(grep -oE '/[^[:space:](]+/libc\.a' /native-link.map | sort -u)" && \
    test "$(readlink -f "${musl_archive}")" = /usr/lib/libc.a && \
    cp "target/${build_target}/release/fluxencrypt-cli" /out/bin/fluxencrypt-cli && \
    readelf -h /out/bin/fluxencrypt-cli | grep -q 'Type:.*DYN' && \
    for executable in /out/bin/fluxencrypt-cli /sbin/tini-static; do \
      if readelf -l "${executable}" | grep -q INTERP || readelf -d "${executable}" | grep -q NEEDED; then \
        echo "Dynamic dependency in ${executable}" >&2; exit 1; \
      fi; \
    done && \
    printf 'nonroot:x:65532:65532:nonroot:/data:/sbin/nologin\n' > /out/etc/passwd && \
    printf 'nonroot:x:65532:nonroot\n' > /out/etc/group && \
    { rustc -vV; cargo tree --locked -p aws-lc-sys --depth 0; apk list --installed musl musl-dev tini-static; \
      sha256sum /usr/lib/libc.a /sbin/tini-static /native-unwind/libunwind.a; \
      grep -oE '/[^[:space:](]+/libc\.a' /native-link.map | sort -u; \
    } > /out/doc/native-build.txt

# The encryption CLI is deliberately offline. No dynamic libc, GCC libraries,
# zlib, shell, package manager or unused trust store is needed at runtime.
FROM scratch
ARG VERSION=latest
LABEL org.opencontainers.image.title="FluxEncrypt" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/ThreatFlux/FluxEncrypt" \
      org.opencontainers.image.licenses="MIT"
COPY --from=builder /sbin/tini-static /usr/bin/tini
COPY --from=builder --chown=0:0 /out/bin/fluxencrypt-cli /usr/local/bin/fluxencrypt-cli
COPY --from=builder --chown=0:0 /out/etc/ /etc/
COPY --from=builder --chown=0:0 /out/doc/ /usr/share/doc/fluxencrypt/
COPY --from=builder --chown=65532:65532 /out/data /data
USER 65532:65532
WORKDIR /data
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/fluxencrypt-cli", "--version"]
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/fluxencrypt-cli"]
CMD ["--help"]
