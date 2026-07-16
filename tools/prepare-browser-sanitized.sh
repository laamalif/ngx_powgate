#!/bin/sh

set -eu

cd "$(dirname "$0")/.."
root=$(pwd)

if test "$#" -ne 1; then
    echo "usage: $0 OUTPUT_DIR" >&2
    exit 2
fi

case "$1" in
    build/*)
        output=$root/$1
        ;;
    "$root"/build/*)
        output=$1
        ;;
    /tmp/ngx-powgate-asan.*/*)
        output=$1
        ;;
    *)
        echo "sanitized browser output must be under build/" >&2
        exit 2
        ;;
esac

: "${NGX_SOURCE_DIR:?NGX_SOURCE_DIR must name the pinned NGINX source tree}"
test -f "$NGX_SOURCE_DIR/src/core/nginx.h"
test -x /usr/sbin/nginx
test -f out/ngx_http_pow_module.so

flags='-fsanitize=address,undefined -fno-omit-frame-pointer'
link_flags='-fsanitize=address,undefined'
nginx_jobs=2
case "$(uname -m)" in
    amd64 | x86_64)
        nginx_jobs=8
        ;;
esac
build=$(mktemp -d /tmp/ngx-powgate-browser-sanitized.XXXXXX)
trap 'rm -rf "$build"' EXIT HUP INT TERM

rm -rf "$output"
mkdir -p "$output/nginx" "$output/negative-control"
cp -a "$NGX_SOURCE_DIR/." "$build/nginx"

cd "$build/nginx"
CC=clang ./configure \
    --with-compat \
    --with-debug \
    --with-http_realip_module \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-cc-opt="$flags" \
    --with-ld-opt="$link_flags" \
    --add-dynamic-module="$root"
make -s -j"$nginx_jobs"

install -m 0755 objs/nginx "$output/nginx/nginx"
install -m 0755 objs/ngx_http_pow_module.so \
    "$output/nginx/ngx_http_pow_module.so"

cd "$root"
clang -std=c99 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror \
    $flags tests/sanitizer/alignment_negative_control.c \
    -o "$output/negative-control/alignment-negative-control" \
    $link_flags

negative_status=0
ASAN_OPTIONS="abort_on_error=1:detect_leaks=0\
:log_path=$output/negative-control/asan" \
UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1\
:log_path=$output/negative-control/ubsan" \
    "$output/negative-control/alignment-negative-control" \
    || negative_status=$?
if test "$negative_status" -eq 0; then
    echo "sanitizer negative control unexpectedly passed" >&2
    exit 1
fi

negative_reports=$(find "$output/negative-control" -type f \
    \( -name 'asan.*' -o -name 'ubsan.*' \) -print)
if test "$(printf '%s\n' "$negative_reports" | sed '/^$/d' | wc -l)" -ne 1;
then
    echo "sanitizer negative control report count mismatch" >&2
    exit 1
fi
negative_report=$(printf '%s\n' "$negative_reports")
grep -F 'runtime error: load of misaligned address' "$negative_report" \
    >/dev/null

grep -a '__asan' "$output/nginx/nginx" >/dev/null
grep -a '__ubsan' "$output/nginx/nginx" >/dev/null
grep -a '__asan' "$output/nginx/ngx_http_pow_module.so" >/dev/null
grep -a '__ubsan' "$output/nginx/ngx_http_pow_module.so" >/dev/null

node tools/write-sanitizer-manifest.mjs \
    "$output/manifest.json" \
    "$output/nginx/nginx" \
    "$output/nginx/ngx_http_pow_module.so" \
    /usr/sbin/nginx \
    out/ngx_http_pow_module.so \
    "$negative_report"

echo "sanitized browser server prepared: $output/manifest.json"
