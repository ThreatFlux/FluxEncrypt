#!/usr/bin/env bash
# Smoke-test a FluxEncrypt image: scripts/docker-smoke.sh IMAGE
#
# The image's entrypoint is the CLI and the runtime may have no shell
# (distroless), so every step runs the CLI directly. Keys and files live in a
# host temporary directory mounted at /work, owned by the invoking user.
set -euo pipefail

image="$1"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

run() {
    docker run --rm --network none --user "$(id -u):$(id -g)" \
        --volume "$work:/work" --workdir /work "$image" "$@"
}

# The image's own non-root user can write to its working directory.
docker run --rm --network none "$image" keygen --name default-user --key-size 2048 >/dev/null

docker run --rm --network none "$image" --version
run keygen --output-dir . --name smoke --key-size 2048
printf '%s' "FluxEncrypt container roundtrip" > "$work/expected"
run encrypt --key smoke.pub --input expected --output encrypted
run decrypt --key smoke.pem --input encrypted --output actual
cmp "$work/expected" "$work/actual"
echo "Container roundtrip succeeded for $image"
