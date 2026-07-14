SHELL := /bin/sh

NGX_SOURCE_DIR ?= /opt/ngx-powgate/nginx-source
MODULE := out/ngx_http_pow_module.so
BUILD_DIR ?= build
PURE_CFLAGS := -std=c99 -Wall -Wextra -Wpedantic -Wconversion \
	-Wshadow -Werror -Isrc
PURE_LDLIBS := -lcrypto

.PHONY: check-policy module test-unit test-integration test-e2e

check-policy:
	./tools/check-policy.sh

$(BUILD_DIR)/tests/test_parse: tests/unit/test_parse.c src/pow_parse.c \
		src/pow_parse.h src/pow_protocol.h tests/unit/test.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(PURE_CFLAGS) tests/unit/test_parse.c \
		src/pow_parse.c -o $@

test-unit: $(BUILD_DIR)/tests/test_parse
	./$(BUILD_DIR)/tests/test_parse

module:
	@set -eu; \
	test -f "$(NGX_SOURCE_DIR)/src/core/nginx.h"; \
	mkdir -p out; \
	build_dir=$$(mktemp -d /tmp/ngx-powgate.XXXXXX); \
	trap 'rm -rf "$$build_dir"' EXIT HUP INT TERM; \
	cp -a "$(NGX_SOURCE_DIR)/." "$$build_dir"; \
	cd "$$build_dir"; \
	./configure --with-compat \
	    --with-cc-opt='-D_FORTIFY_SOURCE=2 -fstack-protector-strong' \
	    --add-dynamic-module=/work; \
	$(MAKE) modules; \
	install -m 0755 objs/ngx_http_pow_module.so /work/$(MODULE)

test-integration: module
	TEST_NGINX_BINARY=/usr/sbin/nginx \
	TEST_NGINX_SERVROOT=/tmp/ngx-powgate-test prove -v tests/integration/pow_module.t

test-e2e: module
	node tests/e2e/smoke.mjs
