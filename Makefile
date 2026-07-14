SHELL := /bin/sh

NGX_SOURCE_DIR ?= /opt/ngx-powgate/nginx-source
MODULE := out/ngx_http_pow_module.so
BUILD_DIR ?= build
PURE_CFLAGS := -std=c99 -Wall -Wextra -Wpedantic -Wconversion \
	-Wshadow -Werror -Isrc
PURE_LDLIBS := -lcrypto

.PHONY: check-policy module test-unit test-vector-python test-integration \
	test-e2e

check-policy:
	./tools/check-policy.sh

$(BUILD_DIR)/tests/vector-v1.verified: tools/refsolve.py \
		tests/vectors/v1.json
	@mkdir -p $(@D)
	python3 tools/refsolve.py verify tests/vectors/v1.json
	@touch $@

test-vector-python: $(BUILD_DIR)/tests/vector-v1.verified

$(BUILD_DIR)/tests/test_parse: tests/unit/test_parse.c src/pow_parse.c \
		src/pow_parse.h src/pow_protocol.h tests/unit/test.h \
		| $(BUILD_DIR)/tests/vector-v1.verified
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(PURE_CFLAGS) tests/unit/test_parse.c \
		src/pow_parse.c -o $@

$(BUILD_DIR)/tests/test_crypto: tests/unit/test_crypto.c src/pow_crypto.c \
		src/pow_crypto.h src/pow_protocol.h tests/unit/test.h \
		| $(BUILD_DIR)/tests/vector-v1.verified
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(PURE_CFLAGS) tests/unit/test_crypto.c \
		src/pow_crypto.c -o $@ $(PURE_LDLIBS)

$(BUILD_DIR)/tests/test_challenge: tests/unit/test_challenge.c \
		src/pow_challenge.c src/pow_challenge.h src/pow_crypto.c \
		src/pow_crypto.h src/pow_parse.c src/pow_parse.h \
		src/pow_protocol.h tests/unit/test.h \
		| $(BUILD_DIR)/tests/vector-v1.verified
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(PURE_CFLAGS) tests/unit/test_challenge.c \
		src/pow_challenge.c src/pow_crypto.c src/pow_parse.c \
		-o $@ $(PURE_LDLIBS)

$(BUILD_DIR)/tests/test_cookie: tests/unit/test_cookie.c src/pow_cookie.c \
		src/pow_cookie.h src/pow_challenge.c src/pow_challenge.h \
		src/pow_crypto.c src/pow_crypto.h src/pow_parse.c src/pow_parse.h \
		src/pow_protocol.h tests/unit/test.h \
		| $(BUILD_DIR)/tests/vector-v1.verified
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(PURE_CFLAGS) tests/unit/test_cookie.c \
		src/pow_cookie.c src/pow_challenge.c src/pow_crypto.c \
		src/pow_parse.c -o $@ $(PURE_LDLIBS)

$(BUILD_DIR)/tests/vector_v1.h: tests/vectors/v1.json tools/vector-to-c.py \
		$(BUILD_DIR)/tests/vector-v1.verified
	python3 tools/vector-to-c.py tests/vectors/v1.json $@

$(BUILD_DIR)/tests/test_vector: tests/unit/test_vector.c \
		$(BUILD_DIR)/tests/vector_v1.h src/pow_cookie.c src/pow_cookie.h \
		src/pow_challenge.c src/pow_challenge.h src/pow_crypto.c \
		src/pow_crypto.h src/pow_parse.c src/pow_parse.h \
		src/pow_protocol.h tests/unit/test.h
	$(CC) $(CPPFLAGS) $(PURE_CFLAGS) -I$(BUILD_DIR)/tests \
		tests/unit/test_vector.c src/pow_cookie.c src/pow_challenge.c \
		src/pow_crypto.c src/pow_parse.c -o $@ $(PURE_LDLIBS)

test-unit: $(BUILD_DIR)/tests/test_parse $(BUILD_DIR)/tests/test_crypto \
		$(BUILD_DIR)/tests/test_challenge $(BUILD_DIR)/tests/test_cookie \
		$(BUILD_DIR)/tests/test_vector
	./$(BUILD_DIR)/tests/test_parse
	./$(BUILD_DIR)/tests/test_crypto
	./$(BUILD_DIR)/tests/test_challenge
	./$(BUILD_DIR)/tests/test_cookie
	./$(BUILD_DIR)/tests/test_vector

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
