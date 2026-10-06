#!/usr/bin/env bash
# Smoke-test a FluxEncrypt image: scripts/docker-smoke.sh IMAGE
#
# The image's entrypoint is the CLI and the runtime may have no shell
# (distroless), so every step runs the CLI directly. Keys and files live in a
# host temporary directory mounted at /work, owned by the invoking user.
#
# Set SMOKE_PLATFORM (for example linux/arm64) to test one platform of a
# multi-platform image; non-native platforms need QEMU binfmt handlers.
set -euo pipefail

image="$1"
# ${array[@]+...} keeps an empty array safe under set -u in bash 3.2 (macOS).
platform_args=()
if [[ -n "${SMOKE_PLATFORM:-}" ]]; then
    platform_args=(--platform "$SMOKE_PLATFORM")
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# run ARGS...
#   Runs the image's CLI with ARGS as the invoking user, with the host work
#   directory mounted at /work as the working directory, no network, and the
#   SMOKE_PLATFORM platform when it is set.
run() {
    docker run --rm ${platform_args[@]+"${platform_args[@]}"} --network none --user "$(id -u):$(id -g)" \
        --volume "$work:/work" --workdir /work "$image" "$@"
}

# The image's own non-root user can write to its working directory.
docker run --rm ${platform_args[@]+"${platform_args[@]}"} --network none "$image" keygen --name default-user --key-size 2048 >/dev/null

docker run --rm ${platform_args[@]+"${platform_args[@]}"} --network none "$image" --version
run keygen --output-dir . --name smoke --key-size 2048
printf '%s' "FluxEncrypt container roundtrip" > "$work/expected"
run encrypt --key smoke.pub --input expected --output encrypted
run decrypt --key smoke.pem --input encrypted --output actual
cmp "$work/expected" "$work/actual"
echo "Container roundtrip succeeded for $image${SMOKE_PLATFORM:+ ($SMOKE_PLATFORM)}"
