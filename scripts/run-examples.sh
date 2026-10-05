#!/usr/bin/env bash
set -euo pipefail
repo_root="$(git rev-parse --show-toplevel)"
cargo build --locked --release --all-features --workspace --examples
example_target="${CARGO_TARGET_DIR:-$repo_root/target}"
example_target="$(realpath "$example_target")"
example_work="$(mktemp -d)"
trap 'rm -rf "$example_work"' EXIT
for example in basic_encryption file_encryption key_management environment_config; do
    mkdir "$example_work/$example"
    (cd "$example_work/$example" && timeout 180 "$example_target/release/examples/$example")
done
