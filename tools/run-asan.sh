#!/bin/sh

set -eu

cd "$(dirname "$0")/.."
root=$(pwd)

: "${NGX_SOURCE_DIR:?NGX_SOURCE_DIR must name the pinned NGINX source tree}"
test -f "$NGX_SOURCE_DIR/src/core/nginx.h"
NGX_RUNTIME_BINARY=${NGX_RUNTIME_BINARY:-/usr/sbin/nginx} \
    ./tools/check-test-env.sh
make challenge-page

work=$(mktemp -d /tmp/ngx-powgate-asan.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir "$work/sanitizer"

asan_unit='abort_on_error=1:detect_leaks=1'
# Dynamic modules intentionally export their own ngx_modules array. ASan's
# C++ ODR heuristic treats that NGINX loader contract as a duplicate global.
ubsan='halt_on_error=1:print_stacktrace=1'
sanitizers='-fsanitize=address,undefined -fno-omit-frame-pointer'

ASAN_OPTIONS="$asan_unit" \
UBSAN_OPTIONS="$ubsan" \
make test-unit \
    BUILD_DIR="$work/unit" \
    CC=clang \
    PURE_CFLAGS="-std=c99 -Wall -Wextra -Wpedantic -Wconversion \
        -Wshadow -Werror -Isrc $sanitizers" \
    PURE_LDLIBS="-lcrypto -fsanitize=address,undefined"

make module
./tools/prepare-browser-sanitized.sh "$work/server"
sanitized_nginx=$(node -e '
const manifest = require(process.argv[1]);
process.stdout.write(manifest.nginx.path);
' "$work/server/manifest.json")
sanitized_module=$(node -e '
const manifest = require(process.argv[1]);
process.stdout.write(manifest.module.path);
' "$work/server/manifest.json")
asan_nginx="abort_on_error=1:detect_leaks=0:detect_odr_violation=0\
:log_path=$work/sanitizer/asan"
ubsan_nginx="$ubsan:suppressions=$root/tools/ubsan-nginx.supp\
:log_path=$work/sanitizer/ubsan"

CC=clang \
POW_BUILD_CC_OPT="$sanitizers" \
POW_BUILD_LD_OPT='-fsanitize=address,undefined' \
./tools/build-pow-module.sh fault-first \
    "$work/fault-first/ngx_http_pow_module_fault_first.so"
CC=clang \
POW_BUILD_CC_OPT="$sanitizers" \
POW_BUILD_LD_OPT='-fsanitize=address,undefined' \
./tools/build-pow-module.sh fault-second \
    "$work/fault-second/ngx_http_pow_module_fault_second.so"

integration_status=0
env \
    ASAN_OPTIONS="$asan_nginx" \
    UBSAN_OPTIONS="$ubsan_nginx" \
    TEST_NGINX_BINARY="$sanitized_nginx" \
    TEST_NGINX_SERVROOT="$work/servroot" \
    POW_MODULE_PATH="$sanitized_module" \
    POW_FAULT_FIRST_MODULE_PATH=\
"$work/fault-first/ngx_http_pow_module_fault_first.so" \
    POW_FAULT_SECOND_MODULE_PATH=\
"$work/fault-second/ngx_http_pow_module_fault_second.so" \
    prove -Itests/integration/lib -v tests/integration/*.t \
    || integration_status=$?

sanitizer_status=0
for log in "$work"/sanitizer/*; do
    test -f "$log" || continue
    sanitizer_status=1
    echo "sanitizer finding: $log" >&2
    sed -n '1,240p' "$log" >&2
done

if test "$integration_status" -ne 0 \
   || test "$sanitizer_status" -ne 0;
then
    if test -f "$work/servroot/logs/error.log"; then
        sed -n '1,240p' "$work/servroot/logs/error.log" >&2
    fi
    exit 1
fi
