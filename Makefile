SHELL := /bin/sh

NGX_SOURCE_DIR ?= /opt/ngx-powgate/nginx-source
MODULE := out/ngx_http_pow_module.so
BUILD_DIR ?= build
GENERATED_DIR := build/generated
CHALLENGE_HEADER := $(GENERATED_DIR)/pow_challenge_page.h
PURE_CFLAGS := -std=c99 -Wall -Wextra -Wpedantic -Wconversion \
	-Wshadow -Werror -Isrc
PURE_LDLIBS := -lcrypto
FUZZ_CFLAGS := $(PURE_CFLAGS) -fsanitize=fuzzer,address,undefined \
	-fno-omit-frame-pointer
COVERAGE_CFLAGS := $(PURE_CFLAGS) -O0 --coverage
COVERAGE_LDFLAGS := --coverage

.PHONY: check-policy challenge-page module test-tools test-unit \
	test-vector-python test-fuzz test-fuzz-long test-coverage \
	test-integration test-e2e asan check clean

check-policy:
	./tools/check-policy.sh

$(CHALLENGE_HEADER): html/challenge.html tools/build_pow_challenge.py
	@mkdir -p $(@D)
	python3 tools/build_pow_challenge.py $< $@

challenge-page: $(CHALLENGE_HEADER)

test-tools:
	python3 -m unittest -v tests.tools.test_build_pow_challenge

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
	$(BUILD_DIR)/tests/test_parse
	$(BUILD_DIR)/tests/test_crypto
	$(BUILD_DIR)/tests/test_challenge
	$(BUILD_DIR)/tests/test_cookie
	$(BUILD_DIR)/tests/test_vector

$(BUILD_DIR)/fuzz/fuzz_cookie: tests/fuzz/fuzz_cookie.c src/pow_cookie.c \
		src/pow_challenge.c src/pow_crypto.c src/pow_parse.c
	@mkdir -p $(@D) $(BUILD_DIR)/fuzz/artifacts \
		$(BUILD_DIR)/fuzz/corpus-cookie
	clang $(CPPFLAGS) $(FUZZ_CFLAGS) tests/fuzz/fuzz_cookie.c \
		src/pow_cookie.c src/pow_challenge.c src/pow_crypto.c \
		src/pow_parse.c -o $@ $(PURE_LDLIBS)

$(BUILD_DIR)/fuzz/fuzz_proof: tests/fuzz/fuzz_proof.c \
		src/pow_challenge.c src/pow_crypto.c src/pow_parse.c
	@mkdir -p $(@D) $(BUILD_DIR)/fuzz/artifacts \
		$(BUILD_DIR)/fuzz/corpus-proof
	clang $(CPPFLAGS) $(FUZZ_CFLAGS) tests/fuzz/fuzz_proof.c \
		src/pow_challenge.c src/pow_crypto.c src/pow_parse.c \
		-o $@ $(PURE_LDLIBS)

test-fuzz: $(BUILD_DIR)/fuzz/fuzz_cookie $(BUILD_DIR)/fuzz/fuzz_proof
	@mkdir -p $(BUILD_DIR)/fuzz/corpus-cookie \
		$(BUILD_DIR)/fuzz/corpus-proof $(BUILD_DIR)/fuzz/artifacts
	$(BUILD_DIR)/fuzz/fuzz_cookie -max_total_time=60 -timeout=5 \
		-max_len=257 \
		-artifact_prefix=$(BUILD_DIR)/fuzz/artifacts/cookie- \
		$(BUILD_DIR)/fuzz/corpus-cookie tests/fuzz/corpus/cookie
	$(BUILD_DIR)/fuzz/fuzz_proof -max_total_time=60 -timeout=5 \
		-max_len=65 \
		-artifact_prefix=$(BUILD_DIR)/fuzz/artifacts/proof- \
		$(BUILD_DIR)/fuzz/corpus-proof tests/fuzz/corpus/proof

test-fuzz-long: $(BUILD_DIR)/fuzz/fuzz_cookie $(BUILD_DIR)/fuzz/fuzz_proof
	@mkdir -p $(BUILD_DIR)/fuzz/corpus-cookie \
		$(BUILD_DIR)/fuzz/corpus-proof $(BUILD_DIR)/fuzz/artifacts
	$(BUILD_DIR)/fuzz/fuzz_cookie -max_total_time=600 -timeout=5 \
		-max_len=257 \
		-artifact_prefix=$(BUILD_DIR)/fuzz/artifacts/cookie- \
		$(BUILD_DIR)/fuzz/corpus-cookie tests/fuzz/corpus/cookie
	$(BUILD_DIR)/fuzz/fuzz_proof -max_total_time=600 -timeout=5 \
		-max_len=65 \
		-artifact_prefix=$(BUILD_DIR)/fuzz/artifacts/proof- \
		$(BUILD_DIR)/fuzz/corpus-proof tests/fuzz/corpus/proof

$(BUILD_DIR)/coverage/test_parse: tests/unit/test_parse.c src/pow_parse.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(COVERAGE_CFLAGS) tests/unit/test_parse.c \
		src/pow_parse.c -o $@ $(COVERAGE_LDFLAGS)

$(BUILD_DIR)/coverage/test_challenge: tests/unit/test_challenge.c \
		src/pow_challenge.c src/pow_crypto.c src/pow_parse.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(COVERAGE_CFLAGS) tests/unit/test_challenge.c \
		src/pow_challenge.c src/pow_crypto.c src/pow_parse.c \
		-o $@ $(PURE_LDLIBS) $(COVERAGE_LDFLAGS)

$(BUILD_DIR)/coverage/test_cookie: tests/unit/test_cookie.c \
		src/pow_cookie.c src/pow_challenge.c src/pow_crypto.c src/pow_parse.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(COVERAGE_CFLAGS) tests/unit/test_cookie.c \
		src/pow_cookie.c src/pow_challenge.c src/pow_crypto.c \
		src/pow_parse.c -o $@ $(PURE_LDLIBS) $(COVERAGE_LDFLAGS)

test-coverage: $(BUILD_DIR)/coverage/test_parse \
		$(BUILD_DIR)/coverage/test_challenge \
		$(BUILD_DIR)/coverage/test_cookie
	@rm -f $(BUILD_DIR)/coverage/*.gcda
	$(BUILD_DIR)/coverage/test_parse
	$(BUILD_DIR)/coverage/test_challenge
	$(BUILD_DIR)/coverage/test_cookie
	./tools/check-parser-coverage.sh $(BUILD_DIR)/coverage

module: $(CHALLENGE_HEADER)
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
	POW_MODULE_PATH=/work/out/ngx_http_pow_module.so \
	TEST_NGINX_SERVROOT=/tmp/ngx-powgate-test \
	prove -Itests/integration/lib -v tests/integration/*.t

test-e2e: module
	node tests/e2e/smoke.mjs

asan: check-policy
	./tools/run-asan.sh

check: check-policy test-tools test-unit test-coverage module test-integration \
		test-e2e test-fuzz asan

clean:
	rm -rf $(BUILD_DIR)/coverage $(BUILD_DIR)/fuzz $(BUILD_DIR)/tests \
		$(GENERATED_DIR) out
