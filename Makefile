SHELL := /bin/sh

NGX_SOURCE_DIR ?= /opt/ngx-powgate/nginx-source
MODULE := out/ngx_http_pow_module.so
FAULT_FIRST_MODULE := build/fault-first/ngx_http_pow_module_fault_first.so
FAULT_SECOND_MODULE := build/fault-second/ngx_http_pow_module_fault_second.so
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

.PHONY: check-policy check-test-env challenge-page module fault-modules \
	test-tools test-browser-evidence test-unit browser-tools \
	test-vector-python test-fuzz test-fuzz-long test-coverage \
	test-integration test-js test-e2e asan check clean \
	test-browser-feasibility test-browser-e2e \
	test-browser-partitioned-observer-equivalence \
	benchmark-browser \
	check-browser-x86

check-policy:
	./tools/check-policy.sh

check-test-env:
	./tools/check-test-env.sh

$(CHALLENGE_HEADER): html/challenge.html tools/build_pow_challenge.py
	@mkdir -p $(@D)
	python3 tools/build_pow_challenge.py $< $@

challenge-page: $(CHALLENGE_HEADER)

test-tools: test-browser-evidence
	python3 -m unittest -v tests.tools.test_build_pow_challenge \
		tests.tools.test_refsolve tests.tools.test_check_policy

test-browser-evidence:
	node --test tests/browser/evidence.test.mjs

$(BUILD_DIR)/browser-tools/cookie-occurrences: \
		tests/browser/cookie_occurrences.c src/pow_cookie_scan.c \
		src/pow_cookie_scan.h src/pow_protocol.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(PURE_CFLAGS) tests/browser/cookie_occurrences.c \
		src/pow_cookie_scan.c -o $@

browser-tools: $(BUILD_DIR)/browser-tools/cookie-occurrences

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

$(BUILD_DIR)/tests/test_cookie_scan: tests/unit/test_cookie_scan.c \
		src/pow_cookie_scan.c src/pow_cookie_scan.h tests/unit/test.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(PURE_CFLAGS) tests/unit/test_cookie_scan.c \
		src/pow_cookie_scan.c -o $@

$(BUILD_DIR)/tests/test_verify_errors: tests/unit/test_verify_errors.c \
		tests/unit/pow_crypto_fail.c src/pow_cookie.c src/pow_challenge.c \
		src/pow_parse.c src/pow_verify.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(PURE_CFLAGS) tests/unit/test_verify_errors.c \
		tests/unit/pow_crypto_fail.c src/pow_cookie.c \
		src/pow_challenge.c src/pow_parse.c -o $@

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
		$(BUILD_DIR)/tests/test_cookie_scan \
		$(BUILD_DIR)/tests/test_verify_errors $(BUILD_DIR)/tests/test_vector
	$(BUILD_DIR)/tests/test_parse
	$(BUILD_DIR)/tests/test_crypto
	$(BUILD_DIR)/tests/test_challenge
	$(BUILD_DIR)/tests/test_cookie
	$(BUILD_DIR)/tests/test_cookie_scan
	$(BUILD_DIR)/tests/test_verify_errors
	$(BUILD_DIR)/tests/test_vector

$(BUILD_DIR)/fuzz/fuzz_auth_cookie: tests/fuzz/fuzz_auth_cookie.c \
		src/pow_cookie.c \
		src/pow_challenge.c src/pow_crypto.c src/pow_parse.c
	@mkdir -p $(@D) $(BUILD_DIR)/fuzz/artifacts \
		$(BUILD_DIR)/fuzz/corpus-auth-cookie
	clang $(CPPFLAGS) $(FUZZ_CFLAGS) tests/fuzz/fuzz_auth_cookie.c \
		src/pow_cookie.c src/pow_challenge.c src/pow_crypto.c \
		src/pow_parse.c -o $@ $(PURE_LDLIBS)

$(BUILD_DIR)/fuzz/fuzz_proof_cookie: tests/fuzz/fuzz_proof_cookie.c \
		src/pow_challenge.c src/pow_crypto.c src/pow_parse.c
	@mkdir -p $(@D) $(BUILD_DIR)/fuzz/artifacts \
		$(BUILD_DIR)/fuzz/corpus-proof-cookie
	clang $(CPPFLAGS) $(FUZZ_CFLAGS) tests/fuzz/fuzz_proof_cookie.c \
		src/pow_challenge.c src/pow_crypto.c src/pow_parse.c \
		-o $@ $(PURE_LDLIBS)

$(BUILD_DIR)/fuzz/fuzz_cookie_scan: tests/fuzz/fuzz_cookie_scan.c \
		src/pow_cookie_scan.c src/pow_cookie_scan.h
	@mkdir -p $(@D) $(BUILD_DIR)/fuzz/artifacts \
		$(BUILD_DIR)/fuzz/corpus-cookie-scan
	clang $(CPPFLAGS) $(FUZZ_CFLAGS) tests/fuzz/fuzz_cookie_scan.c \
		src/pow_cookie_scan.c -o $@

test-fuzz: $(BUILD_DIR)/fuzz/fuzz_cookie_scan \
		$(BUILD_DIR)/fuzz/fuzz_auth_cookie \
		$(BUILD_DIR)/fuzz/fuzz_proof_cookie
	@mkdir -p $(BUILD_DIR)/fuzz/corpus-cookie-scan \
		$(BUILD_DIR)/fuzz/corpus-auth-cookie \
		$(BUILD_DIR)/fuzz/corpus-proof-cookie \
		$(BUILD_DIR)/fuzz/artifacts
	$(BUILD_DIR)/fuzz/fuzz_cookie_scan -max_total_time=60 -timeout=5 \
		-max_len=8192 \
		-artifact_prefix=$(BUILD_DIR)/fuzz/artifacts/cookie-scan- \
		$(BUILD_DIR)/fuzz/corpus-cookie-scan \
		tests/fuzz/corpus/cookie-scan
	$(BUILD_DIR)/fuzz/fuzz_auth_cookie -max_total_time=60 -timeout=5 \
		-max_len=257 \
		-artifact_prefix=$(BUILD_DIR)/fuzz/artifacts/auth-cookie- \
		$(BUILD_DIR)/fuzz/corpus-auth-cookie tests/fuzz/corpus/cookie
	$(BUILD_DIR)/fuzz/fuzz_proof_cookie -max_total_time=60 -timeout=5 \
		-max_len=65 \
		-artifact_prefix=$(BUILD_DIR)/fuzz/artifacts/proof-cookie- \
		$(BUILD_DIR)/fuzz/corpus-proof-cookie tests/fuzz/corpus/proof

test-fuzz-long: $(BUILD_DIR)/fuzz/fuzz_cookie_scan \
		$(BUILD_DIR)/fuzz/fuzz_auth_cookie \
		$(BUILD_DIR)/fuzz/fuzz_proof_cookie
	@mkdir -p $(BUILD_DIR)/fuzz/corpus-cookie-scan \
		$(BUILD_DIR)/fuzz/corpus-auth-cookie \
		$(BUILD_DIR)/fuzz/corpus-proof-cookie \
		$(BUILD_DIR)/fuzz/artifacts
	$(BUILD_DIR)/fuzz/fuzz_cookie_scan -max_total_time=600 -timeout=5 \
		-max_len=8192 \
		-artifact_prefix=$(BUILD_DIR)/fuzz/artifacts/cookie-scan- \
		$(BUILD_DIR)/fuzz/corpus-cookie-scan \
		tests/fuzz/corpus/cookie-scan
	$(BUILD_DIR)/fuzz/fuzz_auth_cookie -max_total_time=600 -timeout=5 \
		-max_len=257 \
		-artifact_prefix=$(BUILD_DIR)/fuzz/artifacts/auth-cookie- \
		$(BUILD_DIR)/fuzz/corpus-auth-cookie tests/fuzz/corpus/cookie
	$(BUILD_DIR)/fuzz/fuzz_proof_cookie -max_total_time=600 -timeout=5 \
		-max_len=65 \
		-artifact_prefix=$(BUILD_DIR)/fuzz/artifacts/proof-cookie- \
		$(BUILD_DIR)/fuzz/corpus-proof-cookie tests/fuzz/corpus/proof

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

$(BUILD_DIR)/coverage/test_cookie_scan: tests/unit/test_cookie_scan.c \
		src/pow_cookie_scan.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(COVERAGE_CFLAGS) tests/unit/test_cookie_scan.c \
		src/pow_cookie_scan.c -o $@ $(COVERAGE_LDFLAGS)

test-coverage: $(BUILD_DIR)/coverage/test_parse \
		$(BUILD_DIR)/coverage/test_challenge \
		$(BUILD_DIR)/coverage/test_cookie \
		$(BUILD_DIR)/coverage/test_cookie_scan
	@rm -f $(BUILD_DIR)/coverage/*.gcda
	$(BUILD_DIR)/coverage/test_parse
	$(BUILD_DIR)/coverage/test_challenge
	$(BUILD_DIR)/coverage/test_cookie
	$(BUILD_DIR)/coverage/test_cookie_scan
	./tools/check-parser-coverage.sh $(BUILD_DIR)/coverage

module: $(CHALLENGE_HEADER)
	./tools/build-pow-module.sh normal $(MODULE)

fault-modules: $(CHALLENGE_HEADER)
	./tools/build-pow-module.sh fault-first $(FAULT_FIRST_MODULE)
	./tools/build-pow-module.sh fault-second $(FAULT_SECOND_MODULE)
	@test -z "$$(find out -type f -name '*fault*' -print)"

test-integration: check-test-env module fault-modules
	TEST_NGINX_BINARY=/usr/sbin/nginx \
	POW_MODULE_PATH=/work/out/ngx_http_pow_module.so \
	POW_FAULT_FIRST_MODULE_PATH=/work/$(FAULT_FIRST_MODULE) \
	POW_FAULT_SECOND_MODULE_PATH=/work/$(FAULT_SECOND_MODULE) \
	TEST_NGINX_SERVROOT=/tmp/ngx-powgate-test \
	prove -Itests/integration/lib -v tests/integration/*.t

test-js:
	node --test tests/e2e/solver.test.mjs tests/e2e/controller.test.mjs

test-e2e: check-test-env module test-js
	node tests/e2e/smoke.mjs

test-browser-feasibility:
	./tools/require-browser-x86.sh test-browser-feasibility
	timeout --signal=TERM --kill-after=20s 160s \
		node tests/browser/feasibility.mjs

test-browser-partitioned-observer-equivalence: browser-tools module
	./tools/require-browser-x86.sh test-browser-e2e
	timeout --signal=TERM --kill-after=20s 160s \
		node tests/browser/partitioned-observer-equivalence.mjs

test-browser-e2e: test-browser-partitioned-observer-equivalence browser-tools
	./tools/require-browser-x86.sh test-browser-e2e
	$(MAKE) module
	node --test tests/browser/sanitizer.test.mjs
	./tools/prepare-browser-sanitized.sh build/browser-sanitized
	timeout --signal=TERM --kill-after=20s 580s \
		node tests/browser/e2e.mjs --sanitizer-manifest \
		build/browser-sanitized/manifest.json

benchmark-browser:
	./tools/require-browser-x86.sh benchmark-browser
	$(MAKE) challenge-page
	timeout --signal=TERM --kill-after=20s 340s \
		node tests/browser/benchmark.mjs

check-browser-x86:
	./tools/require-browser-x86.sh check-browser-x86
	timeout --signal=TERM --kill-after=20s 1280s sh -eu -c \
	  '$(MAKE) test-browser-feasibility && $(MAKE) test-browser-e2e && $(MAKE) benchmark-browser'

asan: check-policy check-test-env
	./tools/run-asan.sh

check: check-policy test-tools test-unit test-coverage module test-integration \
		test-e2e test-fuzz asan

clean:
	rm -rf $(BUILD_DIR)/coverage $(BUILD_DIR)/fuzz $(BUILD_DIR)/tests \
		$(BUILD_DIR)/browser-sanitized $(GENERATED_DIR) out
