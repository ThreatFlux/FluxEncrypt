# Stable modernization — 2026-10-05

This change starts from main `33174c3e92f481654313daf084d58a98dfb005ef` (0.7.6). It preserves the workspace version, public cryptographic types, ciphertext formats, feature names and implications, and existing release ownership. The original checkout and its hooks are unchanged; development uses a sibling worktree.

## Versions and compatibility

The development toolchain is **Rust 1.99.0**, released October 1, verified against the [official distribution manifest](https://static.rust-lang.org/dist/channel-rust-stable.toml) and [release announcement](https://blog.rust-lang.org/2026/10/01/Rust-1.99.0/). The supported MSRV remains **1.97.1**, checked with that compiler against the locked workspace and all targets. CI explicitly overrides the repository toolchain for its MSRV, beta and nightly lanes.

Direct dependencies use the latest non-yanked stable versions except the three public RSA compatibility dependencies below. The lockfile also refreshes compatible transitive releases. In particular, `dirs` moves from 6.0.0 to 7.0.0; configuration-path behavior remains covered by CLI tests.

| Dependency | Selected stable version | Latest stable major | Reason |
| --- | --- | --- | --- |
| rsa | 0.9.10 | 0.9 | Latest stable; 0.10 remains a release candidate |
| rand | 0.8.8 | 0.10 | RSA 0.9 requires `rand_core` 0.6 RNG traits |
| sha2 | 0.10.9 | 0.11 | RSA's OAEP digest API uses `digest` 0.10 |
| pkcs8 | 0.10.2 | 0.11 | The exposed RSA key types implement PKCS#8 0.10 traits |

Sources: [RSA crate metadata](https://crates.io/api/v1/crates/rsa), [RSA 0.9.10 manifest](https://docs.rs/crate/rsa/0.9.10/source/Cargo.toml), and crates.io metadata for [rand](https://crates.io/api/v1/crates/rand), [sha2](https://crates.io/api/v1/crates/sha2) and [pkcs8](https://crates.io/api/v1/crates/pkcs8). Using their newer major versions would require a separate cryptographic API migration; prereleases are not introduced here. The outdated-dependency gate retains checks for the other direct dependencies and excludes only these three documented compatibility lines.

All six GitHub workflows use full commit SHA references verified against upstream stable releases and their input schemas. The channel-based `dtolnay/rust-toolchain` action has no release series; its current upstream commit is pinned. CodeQL remains native Rust with both existing query suites. The ThreatFlux reusable auto-release workflow remains the release owner; it runs as the threatflux-automation GitHub App, so the tag it pushes starts `release.yml` through its `push: tags` trigger. `release.yml` builds the CLI for six targets, attaches CycloneDX SBOMs for the three crates, and publishes `fluxencrypt`, `fluxencrypt-async` and `fluxencrypt-cli` to crates.io in that order through trusted publishing (a short-lived OIDC token in the `crates-io` environment; no registry secret), skipping any version that is already published. Both workflows take a `dry_run` input: `gh workflow run release.yml -f version=X.Y.Z -f dry_run=true` builds, packages and runs `cargo publish --dry-run` without tagging or publishing.

Pinned tooling: cargo-audit 0.22.2, cargo-deny 0.20.2, cargo-hack 0.6.45, cargo-llvm-cov 0.9.1, cargo-geiger 0.13.0, cargo-outdated 0.19.0, cross 0.2.5, mdBook 0.5.4 and Trivy 0.75.0 and Codecov CLI 11.3.1. Cross uses its latest stable release rather than mutable Git HEAD for the Linux ARM targets. Cross-target builds remain hosted checks; the stable cross tool defaults to an x86_64 host toolchain and cannot run the native ARM64 local lane without a separate emulated toolchain. mdBook deployment runs only when a real `docs/book.toml` produces a book.

The stable cross Windows image could not link Rust 1.99's `GetHostNameW` reference. The same `x86_64-pc-windows-gnu` target now builds on the official Windows 2025 runner with its current MinGW compiler, then executes the CLI version command. The lane names the compiler and linker paths explicitly and logs their versions alongside Rust's. This keeps the GNU target without depending on an unreleased cross image. The [official runner setup](https://github.com/actions/runner-images/blob/b50bb646e0a98aa27143b639a7a12d67f557768a/images/windows/scripts/build/Install-Mingw64.ps1) installs MinGW at `C:\mingw64\bin`; [Rust's target documentation](https://doc.rust-lang.org/rustc/platform-support/windows-gnu.html) specifies the supported C toolchain requirements.

The three Dockerfiles use Rust 1.99.0 and Debian 13 Trixie or Alpine 3.24.2. `Dockerfile` and `docker/Dockerfile` run the CLI on `gcr.io/distroless/cc-debian13:nonroot` (no shell or package manager; the CLI uses ring, so glibc and libgcc are its only runtime libraries) with `tini` as PID 1; `docker/Dockerfile.alpine` keeps an Alpine 3.24.2 runtime. Every base is pinned to an upstream multi-platform manifest digest. Build-time distribution package installs continue receiving repository security fixes. Runtime users remain non-root (uid 65532 on distroless), with the existing root-image `fluxencrypt` alias and alternate-image `fluxencrypt-cli` executable. Builds use the lockfile and include registered test paths; the old dummy-source dependency cache could not represent those paths. Container contexts exclude generated private keys and environment files.

## RSA advisory remains unresolved

**RUSTSEC-2023-0071 is still applicable.** This library actually performs RSA private-key decryption. The prior exception is retained in cargo-audit and cargo-deny; no additional vulnerability exceptions are added. It is not a claim that RSA is constant-time or that the advisory requires local access.

The [current RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) says no patched release exists, including the latest stable RSA 0.9.10. Attackers who can observe timing over a network may recover private-key information. Avoid exposing these private-key operations through endpoints where attackers can measure timing. An uncompromised local use case is the upstream workaround. Updating dependencies alone does not resolve this risk; changing the RSA backend or public API needs separate review.

Configured security checks must pass for every other advisory and for existing license/source policies. An additional audit without the exception is recorded separately to show the one unresolved RSA finding. Trivy's existing informational findings policy and unfixed-vulnerability filter are unchanged; tooling failures still fail its job. Unsafe-code inventory uses Geiger's native informational JSON mode: valid reports with the expected workspace package metrics and full stderr diagnostics are retained. Build/tooling failures propagate. Current upstream inventory limitations include unscanned generated/non-Rust inputs and a dependency syntax parser warning; this does not establish an absence of unsafe code. Geiger uses a separate target directory because the upstream tool cleans its analysis target before rebuilding.

## Existing tests and failure handling

The CLI E2E suite moves into the CLI package, obtains the actual binary through Cargo's `CARGO_BIN_EXE_fluxencrypt-cli`, and runs its thirteen formerly ignored tests. It no longer launches a recursive build or accepts failed commands as a passing test. Batch roundtrips use the current default output naming: decryption appends another `.enc` suffix, so the test verifies identical bytes under `.enc.enc` names rather than changing that existing behavior. Fixtures now use the shipped `--key`, `stream-encrypt`, `batch-encrypt`, configuration, info and benchmark commands and the actual package version. Raw/base64 roundtrips replace assertions about nonexistent CLI cipher-selection flags; both cipher suites remain tested through the core API.

The existing Go-format and full crypto integration suites are registered as Cargo tests. Their stale module import, encryption-storage constructor and byte-count assumptions are corrected to the shipped APIs. Tests retain invalid/truncated/wrong-key rejection, encrypted private-key storage with a wrong-password check, and the original one-second performance thresholds. Blob tests cover the actual 512 KiB boundary and reject the existing 1 MiB fixture; streaming tests still exercise larger file operations. These are Rust format tests, not execution of a Go implementation.

CI and local checks preserve eight property cases and ten shrink iterations. Example commands now fail on errors and execute in isolated temporary directories. Benchmark pipes preserve Cargo failures and require real bencher-format output; no fallback results are generated. Coverage retains a local artifact before its Codecov upload, which authenticates with GitHub OIDC instead of a stored token. Cache keys separate architecture, compiler, job and cross target.

## Local commands

Install Rust 1.99.0 with clippy, rustfmt and llvm-tools-preview, the tools above, actionlint 1.7.12 and yamllint 1.38.0. `make hooks-install` configures only the current Git worktree. `make ci-local` checks formatting, strict Clippy, release build/tests, strict rustdoc, all runnable examples, 25 feature configurations, featureless core tests, MSRV, configured audit/deny, workflow validators and every benchmark in Criterion test mode. `make all` retains the original full benchmark run, and `make bench` runs it explicitly.

For a separate Cargo target use `CARGO_TARGET_DIR=/absolute/path`; four build jobs and four test threads are defaults. Override `ACTIONLINT` and `YAMLLINT` if pinned executables are not in PATH. Container validation (the CI `Docker` job) builds each Dockerfile and uses `scripts/docker-smoke.sh IMAGE` to generate keys as the image's non-root user and verify an actual encrypt/decrypt roundtrip through the CLI entrypoint, without needing a shell in the image.

Cargo package verification checks all three crates; Cargo omits the existing workspace-external integration test paths from registry archives. Those suites run in checkout CI rather than being shipped as package tests.

Hosted platform, cross-target, CodeQL, dependency-review and reporting results are validated on the pushed head. Local native checks do not establish results for macOS, Windows, beta or nightly runners, nor for an external Codecov upload.
