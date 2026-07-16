#!/bin/sh

set -eu

case "${1-}" in
    test-browser-feasibility | test-browser-e2e | benchmark-browser \
        | check-browser-x86)
        target=$1
        ;;
    *)
        echo "error: require-browser-x86 requires one public browser target" >&2
        exit 2
        ;;
esac

if [ "$#" -ne 1 ]; then
    echo "error: require-browser-x86 requires one public browser target" >&2
    exit 2
fi

fail() {
    echo "error: $target $1" >&2
    exit 2
}

if [ -n "${POW_GATE_BROWSER_WS_ENDPOINT-}" ] \
    || [ -n "${PUPPETEER_BROWSER_WS_ENDPOINT-}" ] \
    || [ -n "${PUPPETEER_EXECUTABLE_PATH-}" ] \
    || [ -n "${CHROME_PATH-}" ]; then
    fail "forbids browser endpoint or executable overrides"
fi

if [ "${POWGATE_HOST_UID+x}" != x ] \
    || [ "${POWGATE_HOST_GID+x}" != x ] \
    || [ "${POWGATE_IMAGE_ID+x}" != x ] \
    || [ "${POWGATE_IMAGE_DIGEST+x}" != x ] \
    || [ "${POWGATE_IMAGE_LOCK+x}" != x ] \
    || [ "${POWGATE_PODMAN_VERSION+x}" != x ] \
    || [ "${POWGATE_SOURCE_COMMIT+x}" != x ] \
    || [ "${POWGATE_SOURCE_WORKTREE_CLEAN+x}" != x ] \
    || [ "${POWGATE_TRACKED_TREE_SHA256+x}" != x ]; then
    fail "requires complete wrapper-provided metadata"
fi
if ! printf '%s\n' "$POWGATE_SOURCE_COMMIT" \
    | grep -Eq '^[0-9a-f]{40}$'; then
    fail "source commit identity is invalid"
fi
case "$POWGATE_SOURCE_WORKTREE_CLEAN" in
    true | false) ;;
    *) fail "source worktree identity is invalid" ;;
esac
if ! printf '%s\n' "$POWGATE_TRACKED_TREE_SHA256" \
    | grep -Eq '^[0-9a-f]{64}$'; then
    fail "tracked-tree identity is invalid"
fi

architecture=$(uname -m)
if [ "$architecture" != x86_64 ]; then
    fail "requires native x86_64; detected $architecture"
fi

if [ "$(id -u)" -eq 0 ]; then
    fail "requires non-root controller"
fi
if [ "$(id -u)" != "$POWGATE_HOST_UID" ]; then
    fail "UID mapping mismatch"
fi
if [ "$(id -g)" != "$POWGATE_HOST_GID" ]; then
    fail "GID mapping mismatch"
fi
if [ "$(awk '/^Seccomp:/ { print $2 }' /proc/self/status)" != 2 ]; then
    fail "seccomp is not filtering"
fi
if [ "$(awk '/^CapEff:/ { print $2 }' /proc/self/status)" \
    != 0000000000000000 ]; then
    fail "controller capabilities are not zero"
fi

# shellcheck disable=SC1091
. ./build/versions.env
python3 tools/golden-image-lock.py check || fail "repository image lock is stale"

if [ "$POWGATE_GOLDEN_IMAGE_LOCK" != "$GOLDEN_IMAGE_LOCK_SHA256" ] \
    || [ "$POWGATE_IMAGE_LOCK" != "$GOLDEN_IMAGE_LOCK_SHA256" ]; then
    fail "embedded image lock mismatch"
fi
if [ -z "$POWGATE_IMAGE_ID" ] || [ -z "$POWGATE_PODMAN_VERSION" ]; then
    fail "wrapper image identity is incomplete"
fi

chromium_path=$(command -v chromium || true)
if [ "$chromium_path" != /usr/bin/chromium ] \
    || [ "$(readlink -f "$chromium_path")" != /usr/bin/chromium ]; then
    fail "Chromium does not resolve exactly to /usr/bin/chromium"
fi

check_package() {
    installed=$(dpkg-query -W -f='${Version}' "$1" 2>/dev/null) \
        || fail "$1 is not installed"
    if [ "$installed" != "$2" ]; then
        fail "$1 version mismatch"
    fi
}

check_package chromium "$CHROMIUM_VERSION"
check_package chromium-sandbox "$CHROMIUM_SANDBOX_VERSION"
check_package nodejs "$NODEJS_VERSION"
check_package npm "$NPM_VERSION"

node - "$PUPPETEER_CORE_VERSION" "$AJV_VERSION" <<'NODE' \
    || fail "browser npm dependency version mismatch"
const { createRequire } = require("node:module");
const requireFromImage = createRequire("/opt/ngx-powgate/browser/package.json");
const expectedPuppeteer = process.argv[2];
const expectedAjv = process.argv[3];

if (requireFromImage("puppeteer-core/package.json").version !== expectedPuppeteer
    || requireFromImage("ajv/package.json").version !== expectedAjv) {
    process.exitCode = 1;
}
NODE

browser_version=${CHROMIUM_VERSION%%-*}
case "$(chromium --version)" in
    "Chromium $browser_version "*)
        ;;
    *)
        fail "Chromium reported version mismatch"
        ;;
esac
