#!/bin/sh

set -eu

cd "$(dirname "$0")/.."
root=$(pwd)

if test "$#" -ne 2; then
    echo "usage: $0 normal|fault-first|fault-second OUTPUT" >&2
    exit 2
fi

mode=$1
output=$2
define=

case "$mode" in
    normal)
        ;;
    fault-first)
        define=-DPOW_TEST_FAIL_FIRST_SET_COOKIE
        ;;
    fault-second)
        define=-DPOW_TEST_FAIL_SECOND_SET_COOKIE
        ;;
    *)
        echo "unsupported PowGate module build mode: $mode" >&2
        exit 2
        ;;
esac

case "$output" in
    /*) ;;
    *) output="$root/$output" ;;
esac

case "$mode:$output" in
    fault-*:"$root"/out/*)
        echo "fault modules must not be written under out/" >&2
        exit 2
        ;;
esac

: "${NGX_SOURCE_DIR:?NGX_SOURCE_DIR must name the pinned NGINX source tree}"
test -f "$NGX_SOURCE_DIR/src/core/nginx.h"

cc_opt=${POW_BUILD_CC_OPT:--D_FORTIFY_SOURCE=2 -fstack-protector-strong}
ld_opt=${POW_BUILD_LD_OPT:-}

if test -n "$define"; then
    cc_opt="$cc_opt $define"
fi

build=$(mktemp -d /tmp/ngx-powgate-module.XXXXXX)
trap 'rm -rf "$build"' EXIT HUP INT TERM
cp -a "$NGX_SOURCE_DIR/." "$build"

cd "$build"
set -- --with-compat "--with-cc-opt=$cc_opt"

if test -n "$ld_opt"; then
    set -- "$@" "--with-ld-opt=$ld_opt"
fi

set -- "$@" "--add-dynamic-module=$root"
./configure "$@"
make modules

mkdir -p "$(dirname "$output")"
install -m 0755 objs/ngx_http_pow_module.so "$output"
