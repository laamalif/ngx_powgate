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
asan_nginx="abort_on_error=1:detect_leaks=0:detect_odr_violation=0\
:log_path=$work/sanitizer/asan"
ubsan='halt_on_error=1:print_stacktrace=1'
ubsan_nginx="$ubsan:suppressions=$root/tools/ubsan-nginx.supp\
:log_path=$work/sanitizer/ubsan"
sanitizers='-fsanitize=address,undefined -fno-omit-frame-pointer'
nginx_jobs=2

case "$(uname -m)" in
    amd64 | x86_64)
        nginx_jobs=8
    ;;
esac

echo "sanitizer nginx build jobs: $nginx_jobs"

ASAN_OPTIONS="$asan_unit" \
UBSAN_OPTIONS="$ubsan" \
make test-unit \
    BUILD_DIR="$work/unit" \
    CC=clang \
    PURE_CFLAGS="-std=c99 -Wall -Wextra -Wpedantic -Wconversion \
        -Wshadow -Werror -Isrc $sanitizers" \
    PURE_LDLIBS="-lcrypto -fsanitize=address,undefined"

cp -a "$NGX_SOURCE_DIR/." "$work/nginx"

cd "$work/nginx"
CC=clang ./configure \
    --with-compat \
    --with-debug \
    --with-http_realip_module \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-cc-opt="$sanitizers" \
    --with-ld-opt='-fsanitize=address,undefined' \
    --add-dynamic-module="$root"
make -s -j"$nginx_jobs"

test -x objs/nginx
test -f objs/ngx_http_pow_module.so

cd "$root"
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
    TEST_NGINX_BINARY="$work/nginx/objs/nginx" \
    TEST_NGINX_SERVROOT="$work/servroot" \
    POW_MODULE_PATH="$work/nginx/objs/ngx_http_pow_module.so" \
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
