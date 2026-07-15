# Phase 4A server verification implementation plan

> **For Codex:** REQUIRED SUB-SKILL: use `superpowers:executing-plans` to
> execute this plan task-by-task. Use `superpowers:test-driven-development`
> for every behavior change and `superpowers:verification-before-completion`
> before any completion claim. Create an isolated feature worktree with
> `superpowers:using-git-worktrees` before editing.

**Goal:** Complete the server-side PowGate loop: deterministically extract and
verify auth/proof cookies, issue an auth cookie after valid work, support
current/previous secrets, and fail atomically under internal errors.

**Architecture:** Keep request lifecycle and challenge rendering in
`ngx_http_pow_module.c`; add a thin NGINX adapter in
`ngx_http_pow_verify.c`; add an allocation-free pure Cookie-field scanner;
retain all value parsing, masking, and crypto in the pure core. The approved
design is
[`2026-07-15-phase4a-server-verification-design.md`](../specs/2026-07-15-phase4a-server-verification-design.md).

**Toolchain:** C99, NGINX 1.30.3 dynamic-module API, OpenSSL 3.x, Perl test
orchestration, Python reference solver, libFuzzer, ASan/UBSan, Podman image
`localhost/ngx-powgate-dev:trixie`.

---

## Execution rules

- Run every compile, test, fuzzer, sanitizer, and NGINX source inspection
  inside the canonical Podman image. Never compile on the host.
- Use this command shape throughout:

  ```sh
  podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie <command>
  ```

- Before each new NGINX API use, inspect its 1.30.3 precedent under
  `$NGX_SOURCE_DIR` inside that container and record the precedent in the
  implementation comment only when the reason is not obvious from code.
- Preserve unrelated work. Start every task with `git status --short` and
  end it with `git diff --check`.
- Tests go red before production code changes. Never weaken or skip a gate.
- Commit only after the focused tests and `make check-policy` pass. Use the
  exact short commit messages listed below.

## Preflight: isolate work and prove the baseline

Create a feature worktree/branch named `feat/phase4a-verification`. In that
worktree, confirm the approved design commit is present and the tree is clean:

```sh
git log -1 --oneline
git status --short
```

Inside the canonical container, verify the pinned environment and run the
pre-change gate:

```sh
make check-test-env
make clean
make check
```

Expected: NGINX source 1.30.3/checksum and runtime compatibility checks pass;
the complete Phase 3 gate is green. Stop and diagnose any baseline failure
before editing.

## Task 1: Make the normative documents unambiguous

**Files:**

- Modify: `docs/protocol.md`
- Modify: `PLAN.md`

### Step 1: Add a documentation consistency check

Run the current searches in the container:

```sh
grep -R -n "default 17\|pow_cookie_name.*__pow_p\|Cookie header carries" \
  docs PLAN.md src/pow_protocol.h README.md
```

Expected: no authoritative default-17 result; the current docs still lack the
full reserved-name, scanner, one-clock, current-proof-policy, and
invalid-versus-error contracts.

### Step 2: Update `docs/protocol.md`

Add the approved normative rules without copying implementation details:

- `__pow_p` is reserved and cannot be the configured auth name;
- exact case-sensitive semicolon-segment scanner grammar;
- first four auth occurrences and independent first-proof scan;
- one `now` sample for every time-dependent decision;
- proof verification uses current effective difficulty and prefix;
- current-secret error does not try previous secret;
- client invalidity challenges; provider/invariant failure returns `500`;
- auth value is exactly 39 bytes;
- exact Set-Cookie attribute bytes and fixed proof-clear `Path=/`;
- construction order is not a transport-order promise.

Correct the stale phrase saying the auth value is “~41 chars” to the exact
39-byte v1 length.

### Step 3: Update `PLAN.md`

Replace Phase 4A’s compact notes with references to the frozen rules. Move
`pow_log_level` implementation ownership into Phase 4A; leave Phase 5 owning
audit, documentation hardening, and regression-policy review. Name the three
fuzzers exactly:

```text
fuzz_cookie_scan
fuzz_auth_cookie
fuzz_proof_cookie
```

### Step 4: Verify and commit

```sh
git diff --check
grep -R -n "default 17" docs/protocol.md PLAN.md README.md \
  src/pow_protocol.h
```

Expected: clean diff; no result from the second command.

```sh
git add docs/protocol.md PLAN.md
git commit -m "docs: freeze server verification semantics"
```

## Task 2: Reserve the proof-cookie name in configuration

**Files:**

- Modify: `tests/integration/pow_config.t`
- Modify: `src/pow_config.c`
- Modify: `docs/configuration.md`

### Step 1: Write the failing configuration test

Add a rejected cookie-name row for exact `__pow_p` and a positive row for
`__POW_P`. Assert the rejected diagnostic by semantic substring:

```perl
qr/pow_cookie_name "__pow_p" is reserved for the proof cookie/
```

### Step 2: Run the focused test and confirm red

```sh
make module
TEST_NGINX_BINARY=/usr/sbin/nginx \
POW_MODULE_PATH=/work/out/ngx_http_pow_module.so \
TEST_NGINX_SERVROOT=/tmp/ngx-powgate-config \
prove -Itests/integration/lib -v tests/integration/pow_config.t
```

Expected: `__pow_p` is currently accepted, so the new rejection fails.

### Step 3: Implement exact reservation

In `ngx_http_pow_valid_cookie_name()`, after normal token validation, compare
length and bytes exactly against `POW_PROOF_COOKIE_NAME`. Do not use a
case-insensitive helper. Emit the approved safe diagnostic. Keep the default
and every other token rule unchanged.

### Step 4: Document and verify

Update the directive table and Cookie settings section. State that only the
exact protocol name is reserved in v1.

```sh
make check-policy
make module
TEST_NGINX_BINARY=/usr/sbin/nginx \
POW_MODULE_PATH=/work/out/ngx_http_pow_module.so \
TEST_NGINX_SERVROOT=/tmp/ngx-powgate-config \
prove -Itests/integration/lib -v tests/integration/pow_config.t
```

Expected: PASS.

```sh
git diff --check
git add src/pow_config.c tests/integration/pow_config.t \
  docs/configuration.md
git commit -m "fix: reserve proof cookie name"
```

## Task 3: Add the pure Cookie-field scanner and third fuzzer

**Files:**

- Create: `src/pow_cookie_scan.h`
- Create: `src/pow_cookie_scan.c`
- Create: `tests/unit/test_cookie_scan.c`
- Create: `tests/fuzz/fuzz_cookie_scan.c`
- Create: `tests/fuzz/corpus/cookie-scan/*`
- Rename: `tests/fuzz/fuzz_cookie.c` to
  `tests/fuzz/fuzz_auth_cookie.c`
- Rename: `tests/fuzz/fuzz_proof.c` to
  `tests/fuzz/fuzz_proof_cookie.c`
- Modify: `Makefile`
- Modify: `tools/check-parser-coverage.sh`
- Modify: `tools/check-policy.sh`
- Modify: `AGENTS.md`

### Step 1: Define the failing table

Create the public span/result types and declaration from the design. Write a
table-driven unit executable covering:

- start/end matches and multiple matches;
- empty segments and empty values;
- SP/HTAB before a pair only;
- whitespace before/after `=`;
- case variants and prefix names;
- quotes, commas, embedded NUL, malformed segments;
- invalid NULL arguments, zero name length, and cursor beyond input;
- unchanged cursor/output on error;
- strict cursor advance, exhaustion at `field_len`, contained non-overlapping
  spans.

Wire the new unit target before creating `pow_cookie_scan.c`.

### Step 2: Confirm compile failure

```sh
make test-unit
```

Expected: FAIL because the scanner implementation is absent.

### Step 3: Implement one-pass scanning

Implement a single forward state machine. Do not find a delimiter and then
rescan the segment. Each independent scan examines each byte at most once.
Return `ERROR` without output mutation for invalid arguments, `DONE` with
cursor at the end, and `FOUND` with strict progress.

### Step 4: Add coverage and fuzzing

Create `fuzz_cookie_scan` with invariants for progress, bounds, span
containment, non-overlap, and termination. Seed every scanner rule. Rename the
existing fuzzer sources and Make targets to the three frozen names. Use
`-max_len=8192` for the field scanner and retain value-parser caps for the two
existing fuzzers.

Add `pow_cookie_scan` explicitly to the policy gate’s pure-file expression and
add 100% branch checking for `pow_cookie_scan_next()`.

### Step 5: Update enduring instructions

Add the scanner family to the pure-core lists in `AGENTS.md`; change “both
fuzzers” to the exact three target names. Do not add temporary implementation
notes.

### Step 6: Verify and commit

```sh
make check-policy
make test-unit
make test-coverage
make test-fuzz
```

Expected: all PASS; three libFuzzer smoke runs execute.

```sh
git diff --check
git add src/pow_cookie_scan.c src/pow_cookie_scan.h \
  tests/unit/test_cookie_scan.c tests/fuzz Makefile \
  tools/check-parser-coverage.sh tools/check-policy.sh AGENTS.md
git commit -m "feat: add deterministic cookie field scanner"
```

## Task 4: Separate invalid artifacts from crypto failures

**Files:**

- Create: `src/pow_verify.h`
- Create: `tests/unit/pow_crypto_fail.c`
- Create: `tests/unit/test_verify_errors.c`
- Modify: `src/pow_cookie.h`
- Modify: `src/pow_cookie.c`
- Modify: `src/pow_challenge.h`
- Modify: `src/pow_challenge.c`
- Modify: `tests/unit/test_cookie.c`
- Modify: `tests/unit/test_challenge.c`
- Modify: `tests/fuzz/fuzz_auth_cookie.c`
- Modify: `tests/fuzz/fuzz_proof_cookie.c`
- Modify: `Makefile`
- Modify: `AGENTS.md`

### Step 1: Add failing tri-state assertions

Define `pow_verify_result_t` only in `pow_verify.h`. Update tests to require:

- valid artifact -> `POW_VERIFY_VALID`;
- MAC/work/expiry/policy rejection -> `POW_VERIFY_INVALID`;
- invalid verifier arguments/impossible parsed structure ->
  `POW_VERIFY_ERROR`.

Add `test_verify_errors.c`, linked against `pow_cookie.c`,
`pow_challenge.c`, parsers, and a test-only `pow_crypto_fail.c` implementing
the public crypto signatures with deterministic call counters and selectable
failure on call N. Prove cookie and proof verification return
`POW_VERIFY_ERROR`. Also assert the auth MAC attempt shape: current match is
one call; current mismatch with previous or dummy is exactly two; first-call
error stops at one; second-call error stops at two; no case makes a third
call.

### Step 2: Confirm red

```sh
make test-unit
```

Expected: compile/assertion failures because the APIs still return `int`
valid/invalid only.

### Step 3: Propagate tri-state results

Change only `pow_cookie_verify()` and `pow_proof_check()` return types.
Preserve parser `1/0` contracts. Ensure:

- current HMAC error returns ERROR immediately;
- current mismatch performs exactly one previous/dummy HMAC;
- second HMAC error returns ERROR;
- semantic auth checks happen only after MAC success;
- SHA failure returns ERROR;
- insufficient proof work returns INVALID.

Do not add detailed failure categories.

### Step 4: Update callers and policy

Update unit tests and fuzzers to consume the enum. Add `pow_verify.h` to the
NGINX-free policy/AGENTS lists. Do not place the enum in `pow_protocol.h`.

### Step 5: Verify and commit

```sh
make check-policy
make test-unit
make test-coverage
make test-fuzz
```

Expected: PASS, including deterministic crypto-failure coverage.

```sh
git diff --check
git add src/pow_verify.h src/pow_cookie.c src/pow_cookie.h \
  src/pow_challenge.c src/pow_challenge.h tests/unit \
  tests/fuzz Makefile AGENTS.md tools/check-policy.sh
git commit -m "fix: distinguish verification errors"
```

## Task 5: Extend the independent reference solver

**Files:**

- Modify: `tools/refsolve.py`
- Create: `tests/tools/test_refsolve.py`
- Modify: `Makefile`

### Step 1: Write failing CLI/tool tests

Cover:

- mixed-case CLI secret hex;
- `mine --start-counter` returning the first valid counter at/after start;
- complete `proof_cookie` JSON field;
- `proof-check` valid and invalid verdicts for an explicit counter;
- `auth` exact value for the immutable v1 vector;
- malformed/range errors and JSON field types;
- vector verification remains canonical and unchanged.

### Step 2: Confirm red

```sh
python3 -m unittest -v tests.tools.test_refsolve
```

Expected: FAIL because the subcommands/options do not exist.

### Step 3: Implement narrow subcommands

Split CLI hex decoding from canonical vector decoding so mixed-case CLI input
does not weaken immutable-vector validation. Add no implicit difficulty or
time defaults. Keep all inputs explicit. Keep output bounded JSON and reuse
the existing independent functions rather than shelling out.

### Step 4: Wire and verify

Add the new test module to `test-tools`.

```sh
make test-tools
make test-vector-python
```

Expected: PASS; `tests/vectors/v1.json` has no diff.

```sh
git diff --check
git add tools/refsolve.py tests/tools/test_refsolve.py Makefile
git commit -m "test: extend reference solver"
```

## Task 6: Add the NGINX adapter and auth-cookie path

**Files:**

- Create: `src/ngx_http_pow_verify.h`
- Create: `src/ngx_http_pow_verify.c`
- Create: `tests/integration/lib/PowGate/TestReference.pm`
- Create: `tests/integration/pow_verification_auth.t`
- Modify: `src/ngx_http_pow_module.c`
- Modify: `src/ngx_http_pow_module.h`
- Modify: `config`

### Step 1: Reinspect the pinned precedents

Inside the container, read—not recall—these 1.30.3 implementations:

```sh
sed -n '1810,1845p' "$NGX_SOURCE_DIR/src/http/ngx_http_request.c"
sed -n '1980,2070p' "$NGX_SOURCE_DIR/src/http/ngx_http_parse.c"
sed -n '3620,3730p' "$NGX_SOURCE_DIR/src/http/v2/ngx_http_v2.c"
sed -n '1100,1160p' "$NGX_SOURCE_DIR/src/http/ngx_http_core_module.c"
```

Confirm linked Cookie order, HTTP/2 reconstruction, and access-phase return
semantics before coding.

### Step 2: Create the narrow Perl reference helper

`TestReference.pm` may only:

- validate/parse one PowGate challenge field;
- execute `tools/refsolve.py` with an argument array and timeout;
- decode bounded JSON;
- extract exact Set-Cookie values.

It must not implement HMAC/SHA, duplicate protocol math, or become an HTTP
client.

### Step 3: Write failing auth integration tests

Over forced HTTPS H1 and H2, cover:

- independently generated valid auth passes to a marker content handler;
- a configured mixed-case auth name matches exactly, while the default name
  and case variants are unrelated;
- no target cookie still challenges;
- malformed, oversized, tampered, expired, wrong-IP, low-difficulty, and
  low-prefix cookies challenge;
- valid occurrences at positions two and four pass; valid fifth does not;
- exact case/prefix/whitespace/empty-segment scanner shapes;
- duplicate H1 fields and NGINX-reconstructed H2 order;
- valid auth stops before an invalid proof and emits no proof log;
- failed auth produces one fixed summary with occurrence count and no
  sentinel disclosure.

Use trusted RealIP configuration for controlled IP identities. Configure
difficulty 1 explicitly; never alter the production default.

### Step 4: Confirm red

```sh
make module
TEST_NGINX_BINARY=/usr/sbin/nginx \
POW_MODULE_PATH=/work/out/ngx_http_pow_module.so \
TEST_NGINX_SERVROOT=/tmp/ngx-powgate-auth \
prove -Itests/integration/lib -v \
  tests/integration/pow_verification_auth.t
```

Expected: valid auth still receives the Phase 3 challenge.

### Step 5: Refactor address ownership

Change the module helper to return canonical unmasked `ip16` plus effective
`plen`. For existing challenge issuance, copy then call `pow_ip16_mask()`
before `pow_challenge_derive()`. Run existing Phase 3 tests immediately to
prove challenge bytes do not change.

### Step 6: Implement adapter auth orchestration

Add the fully prefixed result enum and this responsibility boundary:

```c
ngx_http_pow_verify_result_t ngx_http_pow_verify_request(
    ngx_http_request_t *r, ngx_http_pow_main_conf_t *pmcf,
    ngx_http_pow_loc_conf_t *plcf, const uint8_t ip16[POW_IP_LEN],
    uint8_t plen, uint64_t now);
```

Walk auth fields with `pow_cookie_scan_next()`, stop after four exact
occurrences, length-gate before parsing, call `pow_cookie_verify()`, log one
summary only after final invalidity using the fixed form
`pow_gate: operation=auth verdict=invalid occurrences=<1..4>`, and return
ERROR without a client-invalid log for scanner/crypto invariants. Leave proof
absent/unimplemented as NONE in this incremental commit; do not add a
placeholder target or fake success.

Add `pow_cookie_scan.c` and `ngx_http_pow_verify.c` to `config`. In the main
handler, sample `now` once after supported/exempt gates, call the
adapter, map OK to `NGX_DECLINED`, ERROR to 500, and NONE to the unchanged
challenge path. Use the same sampled `now` for fallback challenge bucket.

### Step 7: Verify and commit

```sh
make check-policy
make test-unit
make module
make test-integration
make asan
```

Expected: all existing and auth integration tests PASS under normal and
sanitized NGINX.

```sh
git diff --check
git add src/ngx_http_pow_verify.c src/ngx_http_pow_verify.h \
  src/ngx_http_pow_module.c src/ngx_http_pow_module.h config \
  tests/integration/lib/PowGate/TestReference.pm \
  tests/integration/pow_verification_auth.t
git commit -m "feat: verify authentication cookies"
```

## Task 7: Implement proof verification and transactional issuance

**Files:**

- Modify: `src/pow_protocol.h`
- Modify: `src/ngx_http_pow_verify.c`
- Create: `tests/integration/lib/PowGate/TestBackend.pm`
- Create: `tests/integration/pow_verification_proof.t`
- Modify: `tests/integration/lib/PowGate/TestReference.pm`

### Step 1: Reinspect Set-Cookie/list precedents

```sh
sed -n '390,515p' \
  "$NGX_SOURCE_DIR/src/http/modules/ngx_http_userid_filter_module.c"
sed -n '380,460p' \
  "$NGX_SOURCE_DIR/src/http/modules/ngx_http_headers_filter_module.c"
```

Confirm `ngx_list_push`, `hash`, `next`, and rollback behavior.

### Step 2: Add a narrow backend fixture

Implement a test-only Perl loopback backend that does exactly two things:

- records whether it was reached;
- reads a bounded Content-Length body and returns its exact bytes/length.

It must have deterministic startup/timeout/cleanup, accept no arbitrary
handlers, and remain Perl-owned. This proves valid proof requests retain their
body and fault paths never reach downstream.

### Step 3: Write failing proof tests

For H1 and H2, cover:

- current-secret valid proof passes, preserves exact request body, creates
  exactly two Set-Cookie fields, and follow-up auth passes;
- exact 39-byte auth value and exact attributes;
- configured auth name is used for issuance while proof clearing remains
  fixed at `__pow_p`;
- default Secure and explicit opt-out;
- fixed proof clear `__pow_p=; Max-Age=0; Path=/`;
- no Domain or Expires attribute and no unexpected PowGate cookie field;
- malformed/oversized proof, deterministic failing counter, wrong IP,
  `current-2`, and `current+2` challenge;
- deterministic valid `current-1`, current, and `current+1` proofs;
- invalid first proof shadows valid second;
- four failed auth occurrences do not hide the first proof;
- auth-fail/proof-success emits one auth summary and no success summary;
- proof invalid emits exactly one proof summary with length only.

For wrong-context cases, loop with `mine --start-counter` and `proof-check`
until the counter is proven valid in the issuing context and invalid in the
alternate context. Bound the loop and fail rather than skip.

For bucket-window cases, reobserve the current challenge bucket before
submission and regenerate on rollover with a bounded retry.

### Step 4: Confirm red

```sh
make module
TEST_NGINX_BINARY=/usr/sbin/nginx \
POW_MODULE_PATH=/work/out/ngx_http_pow_module.so \
TEST_NGINX_SERVROOT=/tmp/ngx-powgate-proof \
prove -Itests/integration/lib -v \
  tests/integration/pow_verification_proof.t
```

Expected: valid proof still challenges.

### Step 5: Add fixed protocol literals

Define every fixed Set-Cookie header/attribute/proof-clear literal once in
`pow_protocol.h`. Do not encode the configurable auth name as a constant.
Use the existing `POW_AUTH_COOKIE_WIRE_LEN` assertion for 39 bytes.

### Step 6: Implement bounded proof verification

Only after auth completes without success:

- independently find the first proof occurrence;
- length-gate and parse;
- reject skew before HMAC;
- mask a local address copy with current `plen`;
- derive/check current;
- on INVALID only, derive/check previous when configured;
- on ERROR, return adapter ERROR without fallback;
- never inspect a later proof occurrence.

After final client invalidity, emit exactly
`pow_gate: operation=proof verdict=invalid value_len=<length>` at the
effective `pow_log_level`. Success and absence do not log.

### Step 7: Implement the Set-Cookie transaction

After valid proof:

1. checked `uint64_t` expiry addition;
2. exact length computation;
3. allocate and fully construct both values;
4. validate builder length and end pointers;
5. reserve both list slots through a local wrapper;
6. immediately initialize `hash = 0`, `next = NULL`;
7. populate both while inert;
8. perform adjacent final `hash = 1` assignments;
9. return OK.

Do not send headers, set status, discard the body, or finalize. Every failure
returns ERROR and logs fixed internal metadata only.

### Step 8: Verify and commit

```sh
make check-policy
make test-unit
make module
make test-integration
make asan
```

Expected: complete non-reload auth/proof loop passes under H1/H2 and
ASan/UBSan.

```sh
git diff --check
git add src/pow_protocol.h src/ngx_http_pow_verify.c \
  tests/integration/lib/PowGate/TestBackend.pm \
  tests/integration/lib/PowGate/TestReference.pm \
  tests/integration/pow_verification_proof.t
git commit -m "feat: accept proof cookies"
```

## Task 8: Prove reload, policy, binding, and rotation semantics

**Files:**

- Create: `tests/integration/pow_verification_reload.t`
- Modify: `tests/integration/lib/PowGate/TestNginx.pm`
- Modify: `tests/integration/lib/PowGate/TestReference.pm`

### Step 1: Add a bounded worker-generation helper

Build on `nginx_child_pids()` and existing `wait_until()`. The helper must
observe at least one new child and then verify every old PID has disappeared
before returning. It takes an explicit bounded deadline and never signals
workers itself.

### Step 2: Write transition tests first

Over H1 and H2, test:

- proof issued at lower difficulty is accepted/rejected strictly by current
  difficulty after reload, using a counter proven invalid at the new level;
- proof uses current prefix after reload, with alternate-context invalidity
  proven independently;
- auth cookie difficulty and prefix floors tighten on reload;
- IPv4 `/32` versus same-subnet `/24` behavior;
- equivalent IPv6 policy behavior;
- old-secret auth passes with old as previous and fails after removal;
- pre-rotation proof is valid under old, proven invalid under new current,
  then passes only through previous-secret fallback.

### Step 3: Enforce real worker retirement

For each reload:

- atomically rewrite the secret/config file with mode 0600;
- signal HUP;
- observe a new worker;
- wait for all prior workers to exit;
- use a fresh client connection.

The test must fail if file permission/type revalidation rejects the reload or
if old workers do not retire within the deadline.

### Step 4: Run focused and full tests

```sh
make module
TEST_NGINX_BINARY=/usr/sbin/nginx \
POW_MODULE_PATH=/work/out/ngx_http_pow_module.so \
TEST_NGINX_SERVROOT=/tmp/ngx-powgate-reload \
prove -Itests/integration/lib -v \
  tests/integration/pow_verification_reload.t
make test-integration
make asan
```

Expected: PASS without retries hidden as skips.

```sh
git diff --check
git add tests/integration/pow_verification_reload.t \
  tests/integration/lib/PowGate/TestNginx.pm \
  tests/integration/lib/PowGate/TestReference.pm
git commit -m "test: prove verification reload semantics"
```

## Task 9: Build and exercise narrow Set-Cookie fault modules

**Files:**

- Modify: `src/ngx_http_pow_verify.c`
- Create: `tools/build-pow-module.sh`
- Create: `tests/integration/pow_verification_fault.t`
- Modify: `Makefile`
- Modify: `tools/run-asan.sh`

### Step 1: Write the failing fault integration test

Require these environment paths; absence is a hard environment failure:

```text
POW_FAULT_FIRST_MODULE_PATH
POW_FAULT_SECOND_MODULE_PATH
```

For each module and protocol, submit an otherwise valid proof/body and assert:

- 500;
- no Set-Cookie;
- backend not reached;
- no client-invalid record;
- fixed internal error without request sentinels;
- a second request reuses the connection where NGINX permits and fails
  independently.

Run it now. Expected: FAIL because paths/artifacts do not exist.

### Step 2: Add the narrow compile-time wrapper

At only the two PowGate reservation calls, recognize:

```text
POW_TEST_FAIL_FIRST_SET_COOKIE
POW_TEST_FAIL_SECOND_SET_COOKIE
```

Make both defined a preprocessor error. Do not wrap global allocation, add a
directive, read environment variables, or inspect request data.

### Step 3: Refactor reproducible module building

`tools/build-pow-module.sh` accepts a closed mode set:

```text
normal
fault-first
fault-second
```

It copies the pinned source to a temporary directory, configures with
`--with-compat`, preserves hardening/sanitizer flags supplied by the caller,
builds only modules, and installs to the explicit output. Reject every other
mode.

Wire:

- normal -> `out/ngx_http_pow_module.so`;
- first -> `build/fault-first/ngx_http_pow_module_fault_first.so`;
- second -> `build/fault-second/ngx_http_pow_module_fault_second.so`.

`test-integration` depends on all three and exports all paths. `clean` removes
test artifacts. Add a Make assertion that no fault-named file exists under
`out/`.

### Step 4: Extend sanitizer execution

Build both fault modules with the same ASan/UBSan compiler/linker
instrumentation as the sanitized NGINX/module source. Export their paths to
the complete integration run. Do not create sanitizer-specific functional
branches.

### Step 5: Verify and commit

```sh
make check-policy
make module
make fault-modules
make test-integration
make asan
find out -type f -name '*fault*' -print
```

Expected: all tests PASS; final `find` prints nothing.

```sh
git diff --check
git add src/ngx_http_pow_verify.c tools/build-pow-module.sh \
  tests/integration/pow_verification_fault.t Makefile tools/run-asan.sh
git commit -m "test: exercise cookie allocation failures"
```

## Task 10: Finish public documentation and run release-shaped gates

**Files:**

- Modify: `docs/configuration.md`
- Modify: `docs/security.md`
- Modify: `README.md`
- Modify: `AGENTS.md`
- Modify: `PLAN.md`

### Step 1: Make implementation status honest

Document only now-working behavior:

- auth/proof processing order and exact-name scanning;
- current policy for proofs and policy floors for auth;
- rotation roles and worker-generation test;
- `pow_log_level` fixed summaries and nondisclosure;
- Secure opt-out and permanent proof-clear path;
- client invalidity versus provider/invariant errors;
- bounded maximum verification work.

Update README’s flow and requirements without claiming browser solver work
from Phase 4B. Prepare the PLAN Phase 4A completion edit, but do not mark it
complete until Step 3 succeeds. Keep only enduring rules in AGENTS.

### Step 2: Run static consistency checks

```sh
grep -R -n "default 17\|~41\|two fuzzers\|verification arrive" \
  README.md PLAN.md AGENTS.md docs/protocol.md docs/configuration.md \
  docs/security.md src tests/integration tools
grep -R -n "ngx_http_parse_cookie_lines" src
git diff --check
```

Expected: no stale default/length/fuzzer/status claims; production adapter
does not use the generic NGINX cookie helper.

### Step 3: Run the full canonical gate from clean state

```sh
make clean
make check
```

Expected: policy, tools, unit, 100% parser/scanner branch coverage, module,
all HTTPS integration, e2e smoke, all three fuzzers, and ASan/UBSan PASS with
no skip/TODO.

### Step 4: Inspect artifacts and logs

```sh
find out build -maxdepth 4 -type f -print
find out -type f -name '*fault*' -print
grep -R -n "cookie-sentinel\|secret-sentinel\|nonce-sentinel" \
  /tmp/ngx-powgate-* 2>/dev/null || true
```

Expected: only the production module under `out/`; fault modules only in
their test build directories; no disclosure sentinel in retained logs.

### Step 5: Request code review and resolve findings

Use `superpowers:requesting-code-review`. Review specifically:

- exact protocol bytes and bounds;
- scanner forward progress and independent scans;
- raw versus masked address ownership;
- auth current/previous/dummy attempt count;
- proof ERROR versus INVALID fallback;
- header hash-zero transaction;
- log nondisclosure;
- fault artifact isolation;
- NGINX 1.30.3 API precedents.

Apply valid findings test-first and rerun `make check` after any code change.
Commit code/test corrections separately before the documentation commit:

```sh
git add <reviewed-code-and-test-files>
git commit -m "fix: address verification review"
```

Omit this commit only when review produces no code or test changes.

### Step 6: Commit documentation

After Step 3 and any review fixes are green, mark Phase 4A complete in PLAN.

```sh
git diff --check
git add README.md PLAN.md AGENTS.md docs/configuration.md docs/security.md
git commit -m "docs: document server verification"
```

### Step 7: Final verification evidence

Use `superpowers:verification-before-completion`, then run again from the
committed tree:

```sh
git status --short
make clean
make check
git status --short
```

Expected: both status outputs contain no source/document changes; generated
ignored artifacts are allowed; `make check` exits zero. Record the exact
command result, sanitizer status, three fuzzer completions, and final commit
IDs in the handoff. Do not merge or push without an explicit user request.
