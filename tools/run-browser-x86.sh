#!/bin/sh

set -eu

image=localhost/ngx-powgate-dev:trixie

case "${1-}" in
    test-browser-feasibility | test-browser-e2e | benchmark-browser \
        | check-browser-x86)
        target=$1
        ;;
    *)
        echo "error: run-browser-x86 requires exactly one approved browser target" >&2
        exit 2
        ;;
esac

if [ "$#" -ne 1 ]; then
    echo "error: run-browser-x86 requires exactly one approved browser target" >&2
    exit 2
fi

if [ -n "${POW_GATE_BROWSER_WS_ENDPOINT-}" ] \
    || [ -n "${PUPPETEER_BROWSER_WS_ENDPOINT-}" ] \
    || [ -n "${PUPPETEER_EXECUTABLE_PATH-}" ] \
    || [ -n "${CHROME_PATH-}" ]; then
    echo "error: browser endpoint or executable overrides are forbidden" >&2
    exit 2
fi

root=$(git rev-parse --show-toplevel)
root=$(cd "$root" && pwd -P)
current=$(pwd -P)

if [ "$current" != "$root" ]; then
    echo "error: run-browser-x86 must run from the physical repository root" >&2
    exit 2
fi

python3 tools/golden-image-lock.py check
lock=$(awk -F= '$1 == "GOLDEN_IMAGE_LOCK_SHA256" { print $2 }' \
    build/versions.env)

rootless=$(podman info --format json | python3 -c '
import json
import sys

value = json.load(sys.stdin).get("host", {}).get("security", {}).get("rootless")
print("true" if value is True else "false")
')

if [ "$rootless" != true ]; then
    echo "error: run-browser-x86 requires rootless Podman" >&2
    exit 2
fi

inspection=$(podman image inspect --format json "$image" | python3 -c '
import json
import sys

value = json.load(sys.stdin)
if not isinstance(value, list) or len(value) != 1:
    raise SystemExit("invalid image inspection result")
item = value[0]
labels = item.get("Labels") or item.get("Config", {}).get("Labels") or {}
digests = item.get("RepoDigests") or []
print(item.get("Architecture", ""))
print(item.get("Id", ""))
print(digests[0] if digests else "-")
print(labels.get("org.ngx-powgate.golden-image-lock", ""))
')

if [ "$(printf '%s\n' "$inspection" | wc -l)" -ne 4 ]; then
    echo "error: Podman image inspection returned invalid identity" >&2
    exit 2
fi

architecture=$(printf '%s\n' "$inspection" | sed -n '1p')
image_id=$(printf '%s\n' "$inspection" | sed -n '2p')
image_digest=$(printf '%s\n' "$inspection" | sed -n '3p')
image_lock=$(printf '%s\n' "$inspection" | sed -n '4p')

if [ "$architecture" != amd64 ]; then
    echo "error: browser image must be native amd64; detected $architecture" >&2
    exit 2
fi

if [ -z "$image_id" ] || [ "$image_lock" != "$lock" ]; then
    echo "error: browser image identity or golden-image lock mismatch" >&2
    exit 2
fi

if [ "$image_digest" = - ]; then
    image_digest=
fi

podman_version=$(podman version --format '{{.Client.Version}}')
if [ -z "$podman_version" ]; then
    echo "error: Podman client version is unavailable" >&2
    exit 2
fi

exec podman run --rm \
    --userns=keep-id \
    -v "$root:/work:Z" \
    -w /work \
    -e "POWGATE_HOST_UID=$(id -u)" \
    -e "POWGATE_HOST_GID=$(id -g)" \
    -e "POWGATE_IMAGE_ID=$image_id" \
    -e "POWGATE_IMAGE_DIGEST=$image_digest" \
    -e "POWGATE_IMAGE_LOCK=$image_lock" \
    -e "POWGATE_PODMAN_VERSION=$podman_version" \
    "$image" \
    make "$target"
