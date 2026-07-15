#!/bin/sh

set -eu

nginx=${NGX_RUNTIME_BINARY:-/usr/sbin/nginx}

: "${NGX_SOURCE_DIR:?NGX_SOURCE_DIR must name the pinned NGINX source tree}"

command -v openssl >/dev/null
command -v curl >/dev/null
test -x "$nginx"
test -f "$NGX_SOURCE_DIR/src/core/nginx.h"

curl --version | grep -Eq '^Features:.*(^|[[:space:]])HTTP2([[:space:]]|$)'

nginx_version=$($nginx -v 2>&1)
test "$nginx_version" = 'nginx version: nginx/1.30.3'

nginx_build=$($nginx -V 2>&1)
case "$nginx_build" in
    *--with-http_ssl_module*) ;;
    *) echo "test environment: nginx lacks HTTP SSL" >&2; exit 1 ;;
esac
case "$nginx_build" in
    *--with-http_v2_module*) ;;
    *) echo "test environment: nginx lacks HTTP/2" >&2; exit 1 ;;
esac

echo "test environment: OK"
