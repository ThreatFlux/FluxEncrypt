.PHONY: all fmt clippy build test bench clean

# Default target - run all checks
all: fmt clippy build test bench
	@echo "All checks passed!"

# Format code
fmt:
	@echo "Formatting code..."
	@cargo fmt --all

# Run clippy linter
clippy:
	@echo "Running clippy..."
	@cargo clippy --workspace --all-features --all-targets -- -D warnings

# Build the project
build:
	@echo "Building workspace..."
	@cargo build --workspace --all-features --release

# Run tests
test:
	@echo "Running tests..."
	@PROPTEST_CASES=8 cargo test --workspace --all-features --release

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	@cargo bench --bench encryption_benchmarks

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@cargo clean
