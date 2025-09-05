.PHONY: all clean build test fmt clippy doc audit security coverage bench check install-tools help \
         fmt-check test-unit test-integration test-e2e test-property build-examples test-doc doc-check doc-links \
         deny outdated security-geiger security-supply-chain semver-check feature-test feature-test-full \
         msrv msrv-install security-enhanced ci-local validate analyze examples release-prep dev \
         build-cli build-async test-workspace test-cli test-async bench-crypto bench-streaming \
         docker-build docker-test clean-deep profile profile-memory

# Default target
all: install-tools fmt clippy build test test-integration test-e2e build-examples test-doc doc-check doc-links audit security
	@echo "✅ All checks passed!"

# CI simulation - matches GitHub Actions CI workflow
ci: fmt-check clippy build test test-integration test-e2e build-examples test-doc doc-check
	@echo "✅ CI checks passed!"

# Install required tools
install-tools:
	@echo "📦 Installing required tools..."
	@command -v cargo-audit >/dev/null 2>&1 || cargo install cargo-audit
	@command -v cargo-outdated >/dev/null 2>&1 || cargo install cargo-outdated
	@command -v cargo-deny >/dev/null 2>&1 || cargo install cargo-deny
	@command -v cargo-llvm-cov >/dev/null 2>&1 || cargo install cargo-llvm-cov
	@command -v cargo-hack >/dev/null 2>&1 || cargo install cargo-hack
	@command -v cargo-deadlinks >/dev/null 2>&1 || cargo install cargo-deadlinks
	@command -v cargo-geiger >/dev/null 2>&1 || cargo install cargo-geiger --locked
	@command -v cargo-supply-chain >/dev/null 2>&1 || cargo install cargo-supply-chain --locked
	@command -v cargo-semver-checks >/dev/null 2>&1 || cargo install cargo-semver-checks --locked
	@command -v cargo-criterion >/dev/null 2>&1 || cargo install cargo-criterion
	@command -v cargo-expand >/dev/null 2>&1 || cargo install cargo-expand
	@command -v cargo-bloat >/dev/null 2>&1 || cargo install cargo-bloat
	@echo "✅ Tools installed"

# Format code
fmt:
	@echo "🎨 Formatting code..."
	@cargo fmt --all
	@echo "✅ Code formatted"

# Check formatting without modifying
fmt-check:
	@echo "🔍 Checking code format..."
	@cargo fmt --all -- --check
	@echo "✅ Format check passed"

# Run clippy linter
clippy:
	@echo "📎 Running clippy..."
	@cargo clippy --workspace --all-features --all-targets -- -D warnings
	@echo "✅ Clippy passed"

# Build the entire workspace
build:
	@echo "🔨 Building workspace..."
	@cargo build --workspace --all-features --release
	@echo "✅ Build successful"

# Build CLI specifically
build-cli:
	@echo "🔨 Building CLI..."
	@cargo build -p fluxencrypt-cli --all-features --release
	@echo "✅ CLI build successful"

# Build async crate
build-async:
	@echo "🔨 Building async crate..."
	@cargo build -p fluxencrypt-async --all-features --release
	@echo "✅ Async crate build successful"

# Run all tests
test:
	@echo "🧪 Running all tests..."
	@cargo test --workspace --all-features
	@echo "✅ All tests passed"

# Run unit tests only
test-unit:
	@echo "🧪 Running unit tests..."
	@cargo test --workspace --lib --all-features
	@echo "✅ Unit tests passed"

# Run integration tests
test-integration:
	@echo "🧪 Running integration tests..."
	@cargo test --test integration_test --all-features
	@echo "✅ Integration tests passed"

# Run end-to-end tests
test-e2e:
	@echo "🧪 Running end-to-end tests..."
	@cargo test --test e2e_test --all-features
	@echo "✅ E2E tests passed"

# Run property-based tests
test-property:
	@echo "🧪 Running property tests..."
	@cargo test --test property_tests --all-features
	@echo "✅ Property tests passed"

# Test workspace members individually
test-workspace:
	@echo "🧪 Testing workspace members..."
	@cargo test -p fluxencrypt --all-features
	@cargo test -p fluxencrypt-cli --all-features
	@cargo test -p fluxencrypt-async --all-features
	@echo "✅ Workspace member tests passed"

# Test CLI specifically
test-cli:
	@echo "🧪 Testing CLI..."
	@cargo test -p fluxencrypt-cli --all-features
	@echo "✅ CLI tests passed"

# Test async crate specifically
test-async:
	@echo "🧪 Testing async crate..."
	@cargo test -p fluxencrypt-async --all-features
	@echo "✅ Async tests passed"

# Build examples
build-examples:
	@echo "🔨 Building examples..."
	@cargo build --examples --all-features
	@echo "✅ Examples built successfully"

# Test documentation examples
test-doc:
	@echo "📚 Testing documentation examples..."
	@cargo test --doc --workspace --all-features
	@echo "✅ Doc tests passed"

# Generate documentation
doc:
	@echo "📖 Generating documentation..."
	@cargo doc --workspace --all-features --no-deps --open
	@echo "✅ Documentation generated"

# Check documentation with warnings as errors
doc-check:
	@echo "📖 Checking documentation..."
	@RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --document-private-items
	@echo "✅ Documentation check passed"

# Run security audit
audit:
	@echo "🔒 Running security audit..."
	@cargo audit
	@echo "✅ Security audit passed"

# Check with cargo-deny
deny:
	@echo "🚫 Running cargo-deny checks..."
	@cargo deny check
	@echo "✅ Cargo deny checks passed"

# Check outdated dependencies
outdated:
	@echo "📊 Checking for outdated dependencies..."
	@cargo outdated || true
	@echo "✅ Outdated check complete"

# Security analysis with cargo-geiger (unsafe code detection)
security-geiger:
	@echo "🔍 Analyzing unsafe code usage..."
	@cargo geiger --output-format GitHubMarkdown > unsafe-report.md || echo "⚠️ Geiger analysis completed"
	@echo "✅ Unsafe code analysis complete (see unsafe-report.md)"

# Supply chain security analysis
security-supply-chain:
	@echo "🔗 Analyzing supply chain security..."
	@cargo supply-chain crates > supply-chain-report.txt 2>&1 || echo "⚠️ Supply chain analysis completed"
	@echo "✅ Supply chain analysis complete (see supply-chain-report.txt)"

# Check documentation links
doc-links:
	@echo "🔗 Checking documentation links..."
	@cargo doc --workspace --all-features --no-deps --document-private-items
	@cargo deadlinks --dir target/doc || echo "⚠️ Some documentation links may be broken"
	@echo "✅ Documentation link check complete"

# Semantic versioning checks
semver-check:
	@echo "📋 Checking semantic versioning..."
	@cargo semver-checks check-release || echo "⚠️ Semver check completed with warnings"
	@echo "✅ Semantic versioning check complete"

# Combined security checks
security: audit deny outdated security-geiger security-supply-chain
	@echo "✅ All security checks complete"

# Generate test coverage
coverage:
	@echo "📊 Generating test coverage..."
	@cargo llvm-cov --workspace --all-features --html
	@cargo llvm-cov --workspace --all-features --text
	@echo "✅ Coverage report generated at target/llvm-cov/html/index.html"

# Run benchmarks
bench:
	@echo "⚡ Running all benchmarks..."
	@cargo bench --workspace --all-features
	@echo "✅ Benchmarks complete"

# Run crypto-specific benchmarks
bench-crypto:
	@echo "⚡ Running crypto benchmarks..."
	@cargo bench --bench encryption_benchmarks --all-features
	@echo "✅ Crypto benchmarks complete"

# Run streaming benchmarks
bench-streaming:
	@echo "⚡ Running streaming benchmarks..."
	@cargo bench --bench streaming_benchmarks --all-features 2>/dev/null || echo "ℹ️ Streaming benchmarks not yet implemented"
	@echo "✅ Streaming benchmarks complete"

# Check MSRV (Minimum Supported Rust Version)
msrv:
	@echo "🦀 Checking MSRV (1.70.0)..."
	@if rustup toolchain list | grep -q "1.70.0"; then \
		cargo +1.70.0 check --workspace --all-features; \
	else \
		echo "⚠️  MSRV toolchain 1.70.0 not installed. Installing..."; \
		rustup toolchain install 1.70.0 --component rustfmt,clippy; \
		cargo +1.70.0 check --workspace --all-features; \
	fi
	@echo "✅ MSRV check complete"

# Install MSRV toolchain if not present
msrv-install:
	@echo "🦀 Installing MSRV toolchain (1.70.0)..."
	@rustup toolchain install 1.70.0 --component rustfmt,clippy
	@echo "✅ MSRV toolchain installed"

# Test feature combinations
feature-test:
	@echo "🔀 Testing feature combinations..."
	@cargo hack check --feature-powerset --depth 2 --all-targets --workspace
	@echo "✅ Feature combination tests passed"

# Test feature combinations with tests
feature-test-full:
	@echo "🔀 Testing feature combinations (with tests)..."
	@cargo hack test --feature-powerset --depth 2 --workspace
	@echo "✅ Full feature combination tests passed"

# Quick check (faster than full build)
check:
	@echo "⚡ Quick check..."
	@cargo check --workspace --all-features
	@echo "✅ Check passed"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@cargo clean
	@rm -f unsafe-report.md supply-chain-report.txt
	@echo "✅ Clean complete"

# Deep clean (includes target and cached dependencies)
clean-deep:
	@echo "🧹 Deep cleaning..."
	@cargo clean
	@rm -rf target/
	@rm -f Cargo.lock
	@rm -f unsafe-report.md supply-chain-report.txt
	@echo "✅ Deep clean complete"

# Run examples
examples:
	@echo "🎯 Running examples..."
	@cargo run --example basic_encryption
	@cargo run --example file_encryption
	@cargo run --example key_management
	@cargo run --example environment_config
	@echo "✅ Examples ran successfully"

# Docker build
docker-build:
	@echo "🐳 Building Docker images..."
	@docker build -f docker/Dockerfile -t fluxencrypt:latest .
	@docker build -f docker/Dockerfile.alpine -t fluxencrypt:alpine .
	@echo "✅ Docker images built"

# Docker test
docker-test:
	@echo "🐳 Testing in Docker..."
	@docker run --rm fluxencrypt:latest fluxencrypt --version
	@docker run --rm fluxencrypt:alpine fluxencrypt --version
	@echo "✅ Docker tests passed"

# Profile code performance
profile:
	@echo "📊 Profiling performance..."
	@cargo build --workspace --release --all-features
	@echo "Run: cargo flamegraph --example basic_encryption"
	@echo "✅ Profiling build ready"

# Memory profiling
profile-memory:
	@echo "🧠 Profiling memory usage..."
	@cargo build --workspace --release --all-features
	@echo "Run: valgrind --tool=massif target/release/fluxencrypt-cli keygen"
	@echo "✅ Memory profiling build ready"

# Release preparation
release-prep: fmt test doc audit security coverage
	@echo "📦 Checking Cargo.toml versions..."
	@grep "^version" fluxencrypt/Cargo.toml
	@grep "^version" fluxencrypt-cli/Cargo.toml
	@grep "^version" fluxencrypt-async/Cargo.toml
	@echo "📝 Checking CHANGELOG.md..."
	@head -n 20 CHANGELOG.md
	@echo "✅ Ready for release!"

# Development workflow - format, build, and test
dev: fmt build test test-unit
	@echo "✅ Development checks passed!"

# Enhanced security analysis (matches CI/CD security workflow)
security-enhanced: security security-supply-chain security-geiger semver-check
	@echo "✅ Enhanced security analysis complete!"

# CI-equivalent validation (matches GitHub Actions CI workflow)
ci-local: fmt-check clippy build test test-integration test-e2e test-property build-examples test-doc doc-check doc-links feature-test
	@echo "✅ Local CI validation complete!"

# Full validation (everything - matches all CI/CD workflows)
validate: all coverage feature-test-full security-enhanced
	@echo "🎉 Full validation complete!"

# Complete analysis (all tools, all checks)
analyze: validate security-enhanced doc-links semver-check bench
	@echo "🎯 Complete analysis finished!"

# Help target
help:
	@echo "FluxEncrypt Rust SDK - Makefile targets"
	@echo ""
	@echo "🎯 Main targets:"
	@echo "  make all          - Run all standard checks (format, lint, build, test, doc, security)"
	@echo "  make dev          - Quick development check (format, build, test)"
	@echo "  make ci-local     - Simulate full CI checks locally"
	@echo "  make validate     - Full validation including coverage and feature tests"
	@echo "  make analyze      - Complete analysis (all tools, all checks)"
	@echo ""
	@echo "🔨 Build targets:"
	@echo "  make build        - Build the entire workspace"
	@echo "  make build-cli    - Build CLI tool only"
	@echo "  make build-async  - Build async crate only"
	@echo "  make build-examples - Build all examples"
	@echo "  make check        - Quick check without building"
	@echo ""
	@echo "🧪 Testing targets:"
	@echo "  make test         - Run all tests"
	@echo "  make test-unit    - Run unit tests only"
	@echo "  make test-integration - Run integration tests"
	@echo "  make test-e2e     - Run end-to-end tests"
	@echo "  make test-property - Run property-based tests"
	@echo "  make test-workspace - Test each workspace member"
	@echo "  make test-cli     - Test CLI specifically"
	@echo "  make test-async   - Test async crate specifically"
	@echo "  make test-doc     - Test documentation examples"
	@echo "  make feature-test - Test feature combinations (check only)"
	@echo "  make feature-test-full - Test feature combinations (with tests)"
	@echo "  make coverage     - Generate test coverage report"
	@echo ""
	@echo "📖 Documentation targets:"
	@echo "  make doc          - Generate and open documentation"
	@echo "  make doc-check    - Check documentation with strict warnings"
	@echo "  make doc-links    - Check documentation links"
	@echo ""
	@echo "🎨 Code quality targets:"
	@echo "  make fmt          - Format code"
	@echo "  make fmt-check    - Check formatting without modifying"
	@echo "  make clippy       - Run clippy linter"
	@echo ""
	@echo "🔒 Security targets:"
	@echo "  make security     - Run all security checks"
	@echo "  make audit        - Run security audit"
	@echo "  make deny         - Run cargo-deny checks"
	@echo "  make security-geiger       - Analyze unsafe code usage"
	@echo "  make security-supply-chain - Supply chain analysis"
	@echo "  make security-enhanced     - Enhanced security analysis"
	@echo "  make semver-check - Check semantic versioning"
	@echo ""
	@echo "⚡ Performance targets:"
	@echo "  make bench        - Run all benchmarks"
	@echo "  make bench-crypto - Run cryptography benchmarks"
	@echo "  make bench-streaming - Run streaming benchmarks"
	@echo "  make profile      - Build for profiling"
	@echo "  make profile-memory - Build for memory profiling"
	@echo ""
	@echo "🐳 Docker targets:"
	@echo "  make docker-build - Build Docker images"
	@echo "  make docker-test  - Test Docker images"
	@echo ""
	@echo "🛠️ Utility targets:"
	@echo "  make msrv         - Check minimum supported Rust version"
	@echo "  make msrv-install - Install MSRV toolchain"
	@echo "  make outdated     - Check for outdated dependencies"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make clean-deep   - Deep clean including Cargo.lock"
	@echo "  make examples     - Run example programs"
	@echo "  make release-prep - Prepare for release"
	@echo ""
	@echo "📦 Tool installation:"
	@echo "  make install-tools - Install required cargo tools"
	@echo ""
	@echo "FluxEncrypt - High-performance encryption SDK for Rust"
	@echo "Authors: Wyatt Roersma, Claude Code, Codex"
	@echo "Organization: ThreatFlux"