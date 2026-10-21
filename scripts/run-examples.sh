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
    # Python is already required by workflow validation; its timeout also works
    # on macOS, where GNU coreutils timeout is not installed by default.
    (cd "$example_work/$example" && python3 - "$example_target/release/examples/$example" <<'PYTHON'
import subprocess
import sys

subprocess.run(sys.argv[1:], check=True, timeout=180)
PYTHON
    )
done
