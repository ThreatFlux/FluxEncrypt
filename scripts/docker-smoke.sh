#!/usr/bin/env bash
set -euo pipefail
image="$1"
cli="$2"
# Docker uses the image's existing non-root user and an isolated temporary folder.
docker run --rm --entrypoint sh "$image" -ec '
    work="$(mktemp -d)"
    cd "$work"
    "$1" keygen --output-dir . --name smoke --key-size 2048
    printf "%s" "FluxEncrypt container roundtrip" > expected
    "$1" encrypt --key smoke.pub --input expected --output encrypted
    "$1" decrypt --key smoke.pem --input encrypted --output actual
    cmp expected actual
' sh "$cli"
