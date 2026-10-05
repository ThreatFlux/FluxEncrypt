SHELL := /bin/bash
CARGO_BUILD_JOBS ?= 4
RUST_TEST_THREADS ?= 4
PROPTEST_CASES ?= 8
PROPTEST_MAX_SHRINK_ITERS ?= 10
export PROPTEST_CASES PROPTEST_MAX_SHRINK_ITERS
export RUST_TEST_THREADS
export CARGO_BUILD_JOBS
ACTIONLINT ?= actionlint
YAMLLINT ?= yamllint
MSRV ?= 1.97.1

.PHONY: all ci-local fmt fmt-check clippy build test bench bench-check docs examples-check features msrv security workflow-check hooks-install clean

# Keep the original full benchmark gate available.
all: fmt-check clippy build test bench

ci-local: fmt-check clippy build test docs examples-check features msrv security workflow-check bench-check

fmt:
	cargo fmt --all
fmt-check:
	cargo fmt --all -- --check
clippy:
	cargo clippy --locked --workspace --all-features --all-targets -- -D warnings
build:
	cargo build --locked --workspace --all-features --release
test:
	PROPTEST_CASES=8 PROPTEST_MAX_SHRINK_ITERS=10 cargo test --locked --workspace --all-features --release
bench:
	cargo bench --locked --bench encryption_benchmarks
bench-check:
	cargo bench --locked --bench encryption_benchmarks -- --test
docs:
	RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps
examples-check:
	./scripts/run-examples.sh
features:
	cargo hack check --locked --workspace --feature-powerset --all-targets
	cargo test --locked -p fluxencrypt --no-default-features --lib --release
msrv:
	cargo +$(MSRV) --version
	rustc +$(MSRV) --version --verbose
	cargo +$(MSRV) check --locked --workspace --all-features --all-targets
security:
	cargo audit --ignore RUSTSEC-2023-0071
	cargo deny check
workflow-check:
	python3 scripts/check-action-pins.py
	python3 scripts/test_set_version.py
	python3 scripts/test_geiger_report.py
	$(ACTIONLINT)
	$(YAMLLINT) -c .yamllint.yml .github/workflows
hooks-install:
	./scripts/install-hooks.sh
clean:
	cargo clean
