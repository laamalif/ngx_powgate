# Phase 1 Pure Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the allocation-free, NGINX-independent version 1 protocol core
with independent vectors, exhaustive parser tests, fuzzing, sanitizers, and
real-module compatibility gates.

**Architecture:** Four focused C99 units separate cryptographic primitives,
shared wire parsing, challenge/proof semantics, and authentication-cookie
semantics. A Python standard-library implementation verifies one immutable
JSON protocol vector; deterministic test tooling exposes that same vector to C
without implementing JSON or cryptography in the test converter.

**Tech Stack:** C99, OpenSSL 3.x, Python 3 standard library, clang 19,
libFuzzer, ASan/UBSan, GCC/gcov, GNU make, NGINX 1.30.3, Test::Nginx, Node.js,
Podman, and `localhost/ngx-powgate-dev:trixie`.

## Global Constraints

- Read `docs/protocol.md` and `docs/nginx-style.md` before changing C.
- Run every compile, unit test, fuzzer, sanitizer, module build, integration
  test, and e2e test inside `localhost/ngx-powgate-dev:trixie`.
- The host may invoke Podman and inspect artifacts only.
- Pure-core code uses C99 `stdint.h`/`stddef.h` types, fixed caller-owned
  buffers, and zero allocation. It includes no NGINX headers.
- Production cryptography uses OpenSSL only. Do not vendor crypto or add RNG.
- Compile pure-core unit and fuzz builds with `-std=c99 -Wall -Wextra
  -Wpedantic -Wconversion -Wshadow -Werror`.
- Parsing and verification return `1` or `0`; builders return encoded length
  or `0`. On parser failure, output structures are uninitialized.
- Authenticate retained wire bytes. Do not reparse or reserialize them during
  verification.
- Every production C protocol constant and wire-format literal comes from
  `src/pow_protocol.h`.
- Auth-cookie input over 256 bytes and proof-cookie input over 64 bytes is
  rejected before any field is inspected.
- All MAC and digest comparisons use `pow_ct_eq`, backed by `CRYPTO_memcmp`.
- After a current-secret auth-cookie MAC failure, calculate exactly one second
  HMAC: previous secret if present, otherwise a discarded current-secret HMAC.
- Proof verification tries current secret, then previous only when configured.
- Every parser rule or parser bug fix adds a unit-table row and fuzz seed.
- Keep C in upstream NGINX style: return type on its own line, declarations at
  function top, explicit comparisons, 80 columns, `/* */` comments, two blank
  lines between functions.
- Use concise commits in `type: imperative summary` form.

## File map

**Create:**

- `src/pow_parse.h`, `src/pow_parse.c` — spans, exact dot splitting,
  canonical decimal parsing, strict unpadded base64url codec.
- `src/pow_crypto.h`, `src/pow_crypto.c` — SHA-256, HMAC-SHA256,
  constant-time equality, leading-zero-bit count.
- `src/pow_challenge.h`, `src/pow_challenge.c` — IP conversion/masking,
  bucket skew, challenge nonce, proof parse/check.
- `src/pow_cookie.h`, `src/pow_cookie.c` — auth-cookie build, parse, verify.
- `tests/unit/test.h` — minimal allocation-free assertion helpers.
- `tests/unit/test_parse.c`, `test_crypto.c`, `test_challenge.c`,
  `test_cookie.c`, `test_vector.c` — table-driven unit executables.
- `tools/refsolve.py` — independent protocol implementation and vector checker.
- `tools/vector-to-c.py` — deterministic JSON-to-C data converter with no
  cryptographic operations.
- `tests/vectors/v1.json` — immutable versioned protocol vector.
- `tests/fuzz/fuzz_cookie.c`, `tests/fuzz/fuzz_proof.c` — bounded libFuzzer
  entry points.
- `tests/fuzz/corpus/cookie/*`, `tests/fuzz/corpus/proof/*` — valid and
  malformed parser seeds.
- `tools/check-parser-coverage.sh` — function-level gcov branch gate.
- `tools/run-asan.sh` — isolated unit and instrumented-NGINX sanitizer gate.

**Modify:**

- `AGENTS.md` — remove the residual `ngx_config.h` pure-core exception.
- `PLAN.md` — align Phase 1 ownership, APIs, vector immutability, fuzzing, and
  coverage with the approved design.
- `docs/protocol.md` — define canonical base64url tail bits and the no-previous
  dummy auth HMAC.
- `docs/nginx-style.md` — include `pow_parse` in the pure-core list.
- `src/pow_protocol.h` — single definitions for version fields, separators,
  lengths, offsets, and encoded widths.
- `tools/check-policy.sh` — enforce all four pure-core file families and reject
  NGINX headers or heap allocation there.
- `.gitignore` — exclude the generated `build/` tree used by units, vectors,
  coverage, fuzzers, and sanitizer artifacts.
- `Makefile` — strict core builds, unit/vector/fuzz/coverage/sanitizer targets,
  and the real `check` aggregate.
- `config` — compile all pure-core sources into the dynamic module and link
  `libcrypto` using the NGINX 1.30.3 `auto/module` precedent.
- `tests/integration/pow_module.t` — accept an explicit module path for the
  sanitizer build.
- `tests/e2e/smoke.mjs` — accept explicit NGINX binary/module paths while
  preserving current defaults.

---

### Task 1: Align the frozen contract and enforcement

**Files:**

- Modify: `AGENTS.md`
- Modify: `PLAN.md`
- Modify: `docs/protocol.md`
- Modify: `docs/nginx-style.md`
- Modify: `src/pow_protocol.h`
- Modify: `tools/check-policy.sh`

**Interfaces:**

- Produces: named constants and written invariants used by every later task.
- Consumes: approved design in
  `docs/superpowers/specs/2026-07-14-phase1-pure-core-design.md`.

- [ ] **Step 1: Add protocol-level canonical-encoding language**

In `docs/protocol.md`, extend the encoding primitive to say that unused bits in
the last base64url character must be zero. Extend auth-cookie verification step
2 to state exactly:

```text
MAC with the current secret; on failure, always calculate one second HMAC.
Use the previous secret when configured; otherwise calculate and discard a
second HMAC with the current secret. Never calculate a third HMAC.
```

Do not apply the dummy-HMAC rule to proof verification.

- [ ] **Step 2: Correct and complete the project rules**

In `AGENTS.md`, replace the `ngx_config.h` exception with:

```text
pow_parse.c, pow_cookie.c, pow_challenge.c, and pow_crypto.c include no NGINX
headers. Their public APIs use C99 stdint.h/stddef.h types, caller-provided
fixed buffers, and zero allocation.
```

Add `pow_parse.c` to every pure-core list in `docs/nginx-style.md`. Update Phase
1 in `PLAN.md` to match the approved four-unit ownership and exact verification
rules. Replace `pow_ip16_from_sockaddr_bytes` with the three byte-oriented IP
functions. State that `v1.json` is never regenerated by normal builds/tests,
the converter performs no crypto, fuzz durations apply per fuzzer, and parser
conditional branches must all execute.

- [ ] **Step 3: Define wire constants once**

Add these definitions to `src/pow_protocol.h`, retaining the existing labels,
caps, and sizes:

```c
#define POW_VERSION_TEXT                "1"
#define POW_VERSION_TEXT_LEN            1
#define POW_FIELD_SEPARATOR             '.'

#define POW_PROOF_FIELD_COUNT           3
#define POW_AUTH_FIELD_COUNT            3
#define POW_BUCKET_DECIMAL_MAX_LEN      20
#define POW_COUNTER_DECIMAL_MAX_LEN     16

#define POW_AUTH_PAYLOAD_B64_LEN        14
#define POW_AUTH_MAC_B64_LEN            22
#define POW_AUTH_COOKIE_WIRE_LEN        39

#define POW_AUTH_EXPIRY_OFFSET          0
#define POW_AUTH_DIFFICULTY_OFFSET      8
#define POW_AUTH_PLEN_OFFSET            9

#define POW_IPV4_MAPPED_FF_OFFSET       10
#define POW_IPV4_MAPPED_ADDR_OFFSET     12
```

Keep the existing `POW_*_LABEL`, sizes, cookie names, caps, difficulty bounds,
and counter maximum. Use the constants rather than repeating any value in
later production C.

- [ ] **Step 4: Tighten the mechanical policy gate**

Keep the existing `pure_files` matcher but make its comment list all four file
families. Add a public-header include check that permits only standard integer
and size headers plus project headers; OpenSSL includes belong in
`pow_crypto.c`, not public headers. Use this shape after deriving
`pure_headers` from `pure_files`:

```sh
hits=$(grep -En '#[[:space:]]*include' $pure_headers \
    | grep -Ev '<(stddef|stdint)\.h>|"pow_[a-z_]+\.h"')
[ -n "$hits" ] \
    && violation "non-C99 or external include in pure-core header" "$hits"
```

Guard the pipeline when `pure_headers` is empty. Retain the existing
NGINX-header, heap, bare-`memcmp`, banned-string, and RNG checks without
weakening any expression.

- [ ] **Step 5: Run documentation and policy checks**

Run:

```bash
podman run --rm --userns=keep-id \
  -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  make check-policy
git diff --check
```

Expected: `check-policy: OK`, no `git diff --check` output, exit 0.

- [ ] **Step 6: Commit the contract alignment**

```bash
git add AGENTS.md PLAN.md docs/protocol.md docs/nginx-style.md \
  src/pow_protocol.h tools/check-policy.sh
git commit -m "docs: lock phase one core contract"
```

---

### Task 2: Implement shared parsing and base64url

**Files:**

- Create: `src/pow_parse.h`
- Create: `src/pow_parse.c`
- Create: `tests/unit/test.h`
- Create: `tests/unit/test_parse.c`
- Modify: `.gitignore`
- Modify: `Makefile`
- Delete: `tests/unit/.gitkeep`

**Interfaces:**

- Produces:

```c
typedef struct {
    const uint8_t  *data;
    size_t          len;
} pow_span_t;

int pow_split_dot_fields(const uint8_t *buf, size_t len,
    pow_span_t *fields, size_t field_count);
int pow_parse_u64(const uint8_t *buf, size_t len, size_t max_digits,
    uint64_t max_value, uint64_t *out);
size_t pow_b64url_encoded_len(size_t input_len);
size_t pow_b64url_encode(const uint8_t *src, size_t src_len,
    uint8_t *dst, size_t dst_cap);
int pow_b64url_decode_exact(const uint8_t *src, size_t src_len,
    uint8_t *dst, size_t expected_len);
```

- Consumes: constants from `src/pow_protocol.h`.

- [ ] **Step 1: Add the strict unit-build skeleton and failing parse tables**

Add `build/` under the native build/test artifact section of `.gitignore`.
Confirm it with `git check-ignore build/example.o` before compiling.

Add to `Makefile`:

```make
BUILD_DIR ?= build
PURE_CFLAGS := -std=c99 -Wall -Wextra -Wpedantic -Wconversion \
	-Wshadow -Werror -Isrc
PURE_LDLIBS := -lcrypto

.PHONY: test-unit

$(BUILD_DIR)/tests/test_parse: tests/unit/test_parse.c src/pow_parse.c \
		src/pow_parse.h src/pow_protocol.h tests/unit/test.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(PURE_CFLAGS) tests/unit/test_parse.c \
		src/pow_parse.c -o $@

test-unit: $(BUILD_DIR)/tests/test_parse
	./$(BUILD_DIR)/tests/test_parse
```

Create `tests/unit/test.h` with a `TEST_ASSERT(expression)` macro that prints
`file:line: expression` to stderr and returns `1` from the current test
function. It must not allocate.

Create failing table tests with these exact classes:

```text
split valid:       "1.a.b" -> ["1", "a", "b"]
split reject:      "", ".a.b", "1..b", "1.a.", "1.a", "1.a.b.c"
decimal valid:     "0", "1", "9", "10", "18446744073709551615"
decimal reject:    "", "00", "01", "+1", "-1", " 1", "1 ", "1a",
                   "18446744073709551616", and any value above max_value
base64 valid:      1-, 2-, 3-, 10-, 16-, and 32-byte inputs
base64 reject:     "=", "AA=", "AA+", "AA/", length remainder 1,
                   wrong decoded length, and non-zero unused tail bits
round trips:       zero-filled lengths 1,2,3,10,16,32 and bytes 0..255
```

- [ ] **Step 2: Run the parse test and verify the red state**

Run inside the golden image:

```bash
make build/tests/test_parse
```

Expected: compilation fails because `src/pow_parse.h` and its functions do not
exist yet.

- [ ] **Step 3: Implement exact forward parsing**

Create `src/pow_parse.h` with the interfaces above and standard include guards.
Implement `pow_split_dot_fields` as one index-based pass. Reject `NULL`
arguments, zero input, zero field count, empty fields, too few fields, and too
many fields.

Implement `pow_parse_u64` with canonical grammar
`"0" | [1-9][0-9]*`. Before `value = value * 10 + digit`, reject overflow with:

```c
if (value > (max_value - digit) / 10) {
    return 0;
}
```

Implement unpadded base64url directly over bytes. Do not use OpenSSL's
newline-oriented base64 helpers. Reject empty codec input, size arithmetic
overflow, foreign characters, remainder 1, wrong exact output length, and
non-zero unused bits:

```c
if (remainder == 2 && (values[1] & 0x0fU) != 0) {
    return 0;
}

if (remainder == 3 && (values[2] & 0x03U) != 0) {
    return 0;
}
```

Keep the alphabet as a private encoder table derived from a single
`POW_B64URL_ALPHABET` definition added to `pow_protocol.h`; the decoder maps
ASCII ranges arithmetically so it does not duplicate the alphabet string.

- [ ] **Step 4: Run the parse unit and policy gates**

Run:

```bash
make test-unit
make check-policy
```

Expected: all parse tables pass and `check-policy: OK`.

- [ ] **Step 5: Commit parsing**

```bash
git add .gitignore Makefile src/pow_protocol.h src/pow_parse.c src/pow_parse.h \
  tests/unit/test.h tests/unit/test_parse.c tests/unit/.gitkeep
git commit -m "feat: add strict wire parsing"
```

---

### Task 3: Implement cryptographic primitives

**Files:**

- Create: `src/pow_crypto.h`
- Create: `src/pow_crypto.c`
- Create: `tests/unit/test_crypto.c`
- Modify: `Makefile`

**Interfaces:**

- Produces:

```c
int pow_sha256(const uint8_t *msg, size_t msg_len,
    uint8_t out[POW_DIGEST_LEN]);
int pow_hmac_sha256(const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t out[POW_DIGEST_LEN]);
int pow_ct_eq(const uint8_t *a, const uint8_t *b, size_t len);
uint16_t pow_leading_zero_bits(
    const uint8_t digest[POW_DIGEST_LEN]);
```

- Consumes: OpenSSL `SHA256`, `HMAC(EVP_sha256())`, and `CRYPTO_memcmp`.

- [ ] **Step 1: Add failing crypto known-answer tests**

Add `build/tests/test_crypto` to `test-unit`. Test SHA-256 of empty input and
`"abc"`. Test RFC 4231 HMAC-SHA256 cases 1 and 2 using byte arrays, including
the full expected 32-byte digests. Add equality tables for equal, first-byte
different, last-byte different, and zero length. Add leading-zero tables:

```text
ff... -> 0, 7f... -> 1, 01... -> 7, 00ff... -> 8,
007f... -> 9, 0000ff... -> 16, 000000ff... -> 24,
00000000ff... -> 32, all-zero digest -> 256
```

- [ ] **Step 2: Verify the crypto test is red**

Run `make build/tests/test_crypto` inside the golden image.

Expected: compilation fails because `pow_crypto` is absent.

- [ ] **Step 3: Implement thin OpenSSL wrappers**

Create the header without OpenSSL includes. In `pow_crypto.c`, include
`<limits.h>`, `<openssl/crypto.h>`, `<openssl/evp.h>`, `<openssl/hmac.h>`, and
`<openssl/sha.h>`.

Reject `NULL` pointers and a HMAC key length greater than `INT_MAX`. Verify that
`HMAC()` returns non-NULL and writes exactly `POW_DIGEST_LEN`. Wrap
`CRYPTO_memcmp` in `pow_ct_eq`; no other production file may call comparison
primitives directly. Count leading bits byte-by-byte without data-dependent
memory access outside the fixed digest.

- [ ] **Step 4: Run focused and aggregate tests**

Run:

```bash
make build/tests/test_crypto && ./build/tests/test_crypto
make test-unit
make check-policy
```

Expected: all crypto and parse tables pass; policy passes.

- [ ] **Step 5: Commit crypto primitives**

```bash
git add Makefile src/pow_crypto.c src/pow_crypto.h tests/unit/test_crypto.c
git commit -m "feat: add crypto primitives"
```

---

### Task 4: Implement challenge and proof semantics

**Files:**

- Create: `src/pow_challenge.h`
- Create: `src/pow_challenge.c`
- Create: `tests/unit/test_challenge.c`
- Modify: `Makefile`

**Interfaces:**

- Produces:

```c
typedef struct {
    uint64_t bucket;
    uint64_t counter;
    uint8_t  counter_ascii[POW_COUNTER_DECIMAL_MAX_LEN];
    size_t   counter_len;
} pow_proof_t;

void pow_ip16_from_ipv4(const uint8_t ipv4[4], uint8_t out[POW_IP_LEN]);
void pow_ip16_from_ipv6(const uint8_t ipv6[POW_IP_LEN],
    uint8_t out[POW_IP_LEN]);
int pow_ip16_mask(uint8_t ip16[POW_IP_LEN], uint8_t plen);
int pow_bucket_within_skew(uint64_t claimed, uint64_t current);
int pow_challenge_derive(const uint8_t secret[POW_SECRET_LEN],
    const uint8_t ip16[POW_IP_LEN], uint8_t plen, uint64_t bucket,
    uint8_t nonce[POW_NONCE_LEN]);
int pow_proof_check(const uint8_t nonce[POW_NONCE_LEN],
    const uint8_t *counter_ascii, size_t counter_len, uint8_t difficulty);
int pow_proof_cookie_parse(const uint8_t *buf, size_t len,
    pow_proof_t *out);
```

- Consumes: `pow_split_dot_fields`, `pow_parse_u64`, `pow_hmac_sha256`,
  `pow_sha256`, and `pow_leading_zero_bits`.

- [ ] **Step 1: Add failing IP, bucket, nonce, proof, and parser tables**

Add `build/tests/test_challenge` to `test-unit`. Include:

- IPv4 `192.0.2.129` mapped to
  `00000000000000000000ffffc0000281`;
- mapped IPv4 `/120` and `/128` masks, corresponding to configured `/24` and
  `/32`;
- IPv6 `/0`, `/56`, `/64`, `/127`, `/128`, and rejected `/129` attempts;
- bucket cases `(0,0)`, `(1,0)`, `(0,1)`, `(2,0)`, `(0,2)`, ordinary ±1/±2,
  `(UINT64_MAX, UINT64_MAX)`, `(UINT64_MAX-1, UINT64_MAX)`, and
  `(0, UINT64_MAX)`;
- nonce known answer using secret
  `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`,
  IP `2001:db8:1234:5678:9abc:def0:1234:5678`, plen 56, bucket 29333333,
  masked IP `20010db8123456000000000000000000`, and expected nonce
  `c382cd45c32e81f6f5bdcc5fb29497876a3d4364b688245668ab1b578ff7184f`;
- proof digest at difficulty 8 for counter ASCII `"34"`;
- proof cookies `1.0.0`, `1.29333333.34`, and maximum allowed counter;
- rejection of over-64-byte input, wrong version, empty/extra fields, bucket
  over 20 digits, counter over 16 digits, leading zeros, counter overflow, and
  counter above `POW_PROOF_COUNTER_MAX`;
- an assertion that parsed counter bytes and length equal the exact input
  field.

- [ ] **Step 2: Verify the challenge test is red**

Run `make build/tests/test_challenge` inside the golden image.

Expected: compilation fails because `pow_challenge` is absent.

- [ ] **Step 3: Implement IP and bucket helpers**

Implement IPv4 mapping by clearing 16 bytes, writing `0xff` at the named
mapped-prefix offsets, and copying the four address bytes. Implement IPv6 with
a fixed 16-byte loop, not `memcpy`. Mask in place: retain full bytes, mask the
boundary byte, and clear remaining bytes. Accept plen 0 through 128 and reject
larger values.

Implement bucket skew only as:

```c
if (claimed <= current) {
    return current - claimed <= 1 ? 1 : 0;
}

return claimed - current <= 1 ? 1 : 0;
```

- [ ] **Step 4: Implement nonce and proof operations**

Build the challenge MAC message in a fixed stack buffer sized from protocol
constants. Copy the 9-byte label, 16-byte IP, one-byte plen, and eight-byte
big-endian bucket by pointer walking. Require `plen <= 128`.

Build the proof hash input in a fixed
`POW_NONCE_LEN + POW_COUNTER_DECIMAL_MAX_LEN` stack buffer. Reject difficulty
outside `[1,32]` and counter length outside `1..16`. Parse proof cookies only
after the 64-byte gate, retain the exact counter bytes, and never append NUL.

- [ ] **Step 5: Run focused and aggregate tests**

Run:

```bash
make build/tests/test_challenge && ./build/tests/test_challenge
make test-unit
make check-policy
```

Expected: all challenge, crypto, and parse tests pass.

- [ ] **Step 6: Commit challenge semantics**

```bash
git add Makefile src/pow_challenge.c src/pow_challenge.h \
  tests/unit/test_challenge.c
git commit -m "feat: add challenge protocol core"
```

---

### Task 5: Implement authentication cookies

**Files:**

- Create: `src/pow_cookie.h`
- Create: `src/pow_cookie.c`
- Create: `tests/unit/test_cookie.c`
- Modify: `Makefile`

**Interfaces:**

- Produces:

```c
typedef struct {
    uint64_t expiry;
    uint8_t  difficulty;
    uint8_t  plen;
    uint8_t  payload[POW_AUTH_PAYLOAD_LEN];
    uint8_t  mac[POW_AUTH_MAC_LEN];
} pow_cookie_t;

size_t pow_cookie_build(const uint8_t secret[POW_SECRET_LEN],
    uint64_t expiry, uint8_t difficulty, uint8_t plen,
    const uint8_t ip16[POW_IP_LEN], uint8_t *buf, size_t buflen);
int pow_cookie_parse(const uint8_t *buf, size_t len, pow_cookie_t *out);
int pow_cookie_verify(const uint8_t secret[POW_SECRET_LEN],
    const uint8_t *previous_secret, const pow_cookie_t *parsed,
    const uint8_t ip16[POW_IP_LEN], uint64_t now,
    uint8_t min_difficulty, uint8_t min_plen);
```

- Consumes: strict base64url, HMAC, constant-time equality, and IP masking.

- [ ] **Step 1: Add failing cookie tables**

Add `build/tests/test_cookie` to `test-unit`. Use secret
`000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`,
masked IP `20010db8123456000000000000000000`, expiry `1800000000`,
difficulty 8, and plen 56. Assert byte-exact output:

```text
1.AAAAAGtJ0gAIOA.GfPZjHRTfYY8nuiwWBi_Rg
```

Add parse rejection rows for length 257, wrong field count/version, padding,
foreign alphabet, non-canonical tail bits, payload length not 10, MAC length
not 16, difficulty 0/33, and plen 31/129. Assert successful parse retains the
exact 10 payload bytes.

Add verification tables for current-secret success, previous-secret success,
wrong current with no previous, wrong both, `expiry == now`, expired, lower
difficulty, lower effective prefix length, tighter-than-minimum values, wrong
live IP, and every single-byte mutation of the valid wire cookie. Each mutation
must fail parse or verify.

- [ ] **Step 2: Verify the cookie test is red**

Run `make build/tests/test_cookie` inside the golden image.

Expected: compilation fails because `pow_cookie` is absent.

- [ ] **Step 3: Implement canonical build and strict parse**

Build the 10-byte payload with expiry in big-endian order followed by
difficulty and plen. Copy and mask the supplied IP before constructing
`PGv1-cook || payload || ip16`. Truncate the HMAC to 16 bytes. Emit exactly:

```text
version '.' payload-base64url '.' mac-base64url
```

Require `buflen >= POW_AUTH_COOKIE_WIRE_LEN`; return exactly
`POW_AUTH_COOKIE_WIRE_LEN` or `0`. Reject build inputs with difficulty outside
`[1,32]` or plen outside `[32,128]` before masking or signing.

Parse only after the 256-byte gate. Decode exactly 10 and 16 bytes, retain the
payload, decode expiry without alignment casts, and validate difficulty/plen
safety bounds before returning success.

- [ ] **Step 4: Implement dual-secret verification and policy floors**

Copy and mask live IP using parsed plen. Calculate current MAC and compare with
`pow_ct_eq`. On current failure, select `previous_secret` when non-NULL or the
current secret otherwise, calculate exactly one second HMAC, and compare it.
Accept the second match only when `previous_secret != NULL`.

After MAC success, enforce:

```c
if (parsed->expiry <= now
    || parsed->difficulty < min_difficulty
    || parsed->plen < min_plen)
{
    return 0;
}
```

Defensively reject minimum difficulty outside `[1,32]` and minimum plen
outside `[32,128]` before verification.

- [ ] **Step 5: Run focused and aggregate tests**

Run:

```bash
make build/tests/test_cookie && ./build/tests/test_cookie
make test-unit
make check-policy
```

Expected: all cookie cases and prior units pass.

- [ ] **Step 6: Commit auth cookies**

```bash
git add Makefile src/pow_cookie.c src/pow_cookie.h tests/unit/test_cookie.c
git commit -m "feat: add auth cookie core"
```

---

### Task 6: Add the independent reference vector

**Files:**

- Create: `tools/refsolve.py`
- Create: `tools/vector-to-c.py`
- Create: `tests/vectors/v1.json`
- Create: `tests/unit/test_vector.c`
- Modify: `Makefile`

**Interfaces:**

- Produces:

```text
python3 tools/refsolve.py verify tests/vectors/v1.json
python3 tools/vector-to-c.py tests/vectors/v1.json build/tests/vector_v1.h
```

- Consumes: all four pure-core units and the frozen protocol specification.

- [ ] **Step 1: Check in the immutable vector before its consumers**

Create `tests/vectors/v1.json` with a top-level `version: 1` and one canonical
case containing exactly these values:

```json
{
  "version": 1,
  "cases": [
    {
      "name": "ipv6-baseline",
      "secret_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "ip": "2001:db8:1234:5678:9abc:def0:1234:5678",
      "plen": 56,
      "masked_ip16_hex": "20010db8123456000000000000000000",
      "bucket": 29333333,
      "difficulty": 8,
      "nonce_hex": "c382cd45c32e81f6f5bdcc5fb29497876a3d4364b688245668ab1b578ff7184f",
      "nonce_b64url": "w4LNRcMugfb1vcxfspSXh2o9Q2S2iCRWaKsbV4_3GE8",
      "counter": 34,
      "counter_ascii": "34",
      "proof_digest_hex": "0028df459a18ed1973ccbfb54439b98bef2e3988fb5072e2fd3b8a1368d275f5",
      "expiry": 1800000000,
      "auth_payload_hex": "000000006b49d2000838",
      "auth_mac_hex": "19f3d98c74537d863c9ee8b05818bf46",
      "auth_cookie": "1.AAAAAGtJ0gAIOA.GfPZjHRTfYY8nuiwWBi_Rg"
    }
  ]
}
```

- [ ] **Step 2: Write failing Python verification tests**

Implement `refsolve.py verify PATH` so it independently:

- parses IPv4/IPv6 with `ipaddress.ip_address`;
- maps IPv4 to `00..00ffff || ipv4`;
- masks by plen;
- uses `hmac.new(..., hashlib.sha256)` for both labels;
- mines/checks `SHA256(nonce || counter_ascii)`;
- uses `base64.urlsafe_b64encode(...).rstrip(b'=')`;
- compares every stored expected field and exits nonzero with
  `case-name: field-name mismatch` on drift.

First wire the Make target:

```make
$(BUILD_DIR)/tests/vector-v1.verified: tools/refsolve.py \
		tests/vectors/v1.json
	@mkdir -p $(@D)
	python3 tools/refsolve.py verify tests/vectors/v1.json
	@touch $@

.PHONY: test-vector-python
test-vector-python: $(BUILD_DIR)/tests/vector-v1.verified
```

Run it before implementing the calculations.

Expected: exit nonzero because verification behavior is absent.

- [ ] **Step 3: Complete the independent solver and verify the vector**

Keep the implementation independent of C and OpenSSL. Add checked arithmetic
for bucket, difficulty, plen, expiry, and counter ranges. Provide a `mine`
subcommand requiring explicit secret, IP, plen, bucket, and difficulty; print
JSON to stdout and never rewrite a vector file.

Run `make test-vector-python`.

Expected: exit 0 with `v1.json: 1 case verified`.

- [ ] **Step 4: Implement the non-cryptographic JSON-to-C converter**

`vector-to-c.py INPUT OUTPUT` must parse JSON, require exactly version 1 and at
least one case, validate only JSON types and hex lengths, and emit fixed byte
arrays/string literals. It must not import `hashlib`, `hmac`, or `cryptography`.
Write to a temporary sibling path and replace the output only after complete
serialization.

Generate `build/tests/vector_v1.h` and run the converter twice, then compare
the two outputs with `cmp`.

Expected: identical files.

- [ ] **Step 5: Add the C end-to-end vector test**

Create `tests/unit/test_vector.c` using only generated array identifiers. It
must execute:

```text
ip conversion -> mask -> byte match
challenge derive -> nonce byte match
proof check -> success at difficulty 8
cookie build -> exact wire-byte match
cookie parse -> payload/mac byte match
cookie verify -> success
```

Add Make dependencies so the generated header depends on checked-in JSON, the
verification stamp, and `tools/vector-to-c.py`:

```make
$(BUILD_DIR)/tests/vector_v1.h: tests/vectors/v1.json \
		tools/vector-to-c.py $(BUILD_DIR)/tests/vector-v1.verified
	python3 tools/vector-to-c.py tests/vectors/v1.json $@
```

Give every C unit binary an order-only dependency on
`$(BUILD_DIR)/tests/vector-v1.verified`; this guarantees independent Python
verification occurs before C execution even under parallel make.

- [ ] **Step 6: Run all vector and unit gates**

Run:

```bash
make test-unit
make check-policy
git diff --check
```

Expected: Python reports one verified case; all five C unit executables pass;
policy and whitespace checks pass.

- [ ] **Step 7: Commit vectors and cross-implementation tests**

```bash
git add Makefile tools/refsolve.py tools/vector-to-c.py \
  tests/vectors/v1.json tests/unit/test_vector.c
git commit -m "test: add version one protocol vector"
```

---

### Task 7: Add parser fuzzing and branch coverage

**Files:**

- Create: `tests/fuzz/fuzz_cookie.c`
- Create: `tests/fuzz/fuzz_proof.c`
- Create: `tests/fuzz/corpus/cookie/*`
- Create: `tests/fuzz/corpus/proof/*`
- Create: `tools/check-parser-coverage.sh`
- Modify: `Makefile`
- Delete: `tests/fuzz/.gitkeep`

**Interfaces:**

- Produces: `make test-fuzz`, `make test-fuzz-long`, and
  `make test-coverage`.
- Consumes: all pure-core source files and parser regression tables.

- [ ] **Step 1: Add bounded fuzz harnesses**

Each harness exports only:

```c
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
```

The cookie harness parses `data`; on success it verifies with fixed 32-byte
secrets, fixed ip16, fixed `now`, difficulty 1, and plen 32. The proof harness
parses `data`; on success it checks bucket skew against a fixed bucket, derives
one fixed-secret nonce, and checks the retained counter. Neither harness calls
`malloc`, copies `size` bytes, or loops according to an unbounded parsed value.

- [ ] **Step 2: Add one seed per parser rule**

Cookie corpus names must include `valid`, `too-long`, `wrong-version`,
`missing-field`, `extra-field`, `empty-field`, `padding`, `foreign-alphabet`,
`tail-bits`, `payload-length`, `mac-length`, `difficulty-low`,
`difficulty-high`, `plen-low`, and `plen-high`.

Proof corpus names must include `valid`, `too-long`, `wrong-version`,
`missing-field`, `extra-field`, `empty-field`, `bucket-leading-zero`,
`bucket-overflow`, `counter-leading-zero`, `counter-too-long`, and
`counter-overflow`.

Use literal seed contents matching unit rows. The `too-long` seeds are exactly
257 and 65 bytes. Do not generate corpora at test runtime.

- [ ] **Step 3: Add clang/libFuzzer Make targets**

Compile both harnesses with:

```text
clang -std=c99 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror
-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -Isrc
```

Link all required core sources and `-lcrypto`. `test-fuzz` runs each binary
sequentially with `-max_total_time=60`, `-timeout=5`, and a separate artifact
prefix. `test-fuzz-long` uses the same binaries and options with
`-max_total_time=600` per fuzzer.

- [ ] **Step 4: Verify the fuzz smoke gate**

Run `make test-fuzz` inside the golden image.

Expected: both fuzzers run their full 60-second budgets with no crash,
sanitizer finding, timeout, or artifact.

- [ ] **Step 5: Add function-level parser branch coverage**

Build unit binaries into `build/coverage` with GCC `--coverage -O0`. Run every
unit. Implement `tools/check-parser-coverage.sh` to invoke `gcov -b -c -f` and
require `Branches executed:100.00%` for:

```text
pow_split_dot_fields
pow_parse_u64
pow_b64url_decode_exact
pow_proof_cookie_parse
pow_cookie_parse
```

The script exits nonzero and names the deficient function when any conditional
branch is missed. It does not enforce a project-wide percentage.

- [ ] **Step 6: Close missing coverage with regression rows and seeds**

Run `make test-coverage` inside the golden image.

Expected initially: the coverage script may name missed parser branches. For
each named branch, add a behavior assertion to the relevant table and a
matching fuzz seed, rerun until every listed function reports 100% branch
execution.

- [ ] **Step 7: Commit fuzzing and coverage**

```bash
git add Makefile tools/check-parser-coverage.sh tests/fuzz tests/unit
git commit -m "test: fuzz protocol parsers"
```

---

### Task 8: Integrate the core with NGINX and complete all gates

**Files:**

- Modify: `config`
- Modify: `Makefile`
- Modify: `tests/integration/pow_module.t`
- Modify: `tests/e2e/smoke.mjs`
- Create: `tools/run-asan.sh`

**Interfaces:**

- Produces: a dynamic module containing all pure-core objects and linked to
  `libcrypto`; environment-selectable test binaries; `make asan`; final
  `make check`.
- Consumes: all Phase 1 source and tests.

- [ ] **Step 1: Make integration fixtures path-selectable**

In `tests/integration/pow_module.t`, replace the static main config with:

```text
--- main_config eval
"load_module "
    . ($ENV{POW_MODULE_PATH} // "/work/out/ngx_http_pow_module.so")
    . ";"
```

In `tests/e2e/smoke.mjs`, define:

```js
const nginxBinary = process.env.NGX_BINARY ?? '/usr/sbin/nginx';
const modulePath = process.env.POW_MODULE_PATH
    ?? '/work/out/ngx_http_pow_module.so';
```

Use those values in `load_module` and `spawn`; preserve all existing behavior
when the variables are absent.

- [ ] **Step 2: Verify normal integration behavior is unchanged**

Run:

```bash
make test-integration
make test-e2e
```

Expected: the existing two Test::Nginx assertions pass and Node exits 0.

- [ ] **Step 3: Add the pure core to the NGINX dynamic module**

Following NGINX 1.30.3 `auto/module`, set:

```sh
ngx_module_srcs="$ngx_addon_dir/src/ngx_http_pow_module.c \
                 $ngx_addon_dir/src/pow_parse.c \
                 $ngx_addon_dir/src/pow_crypto.c \
                 $ngx_addon_dir/src/pow_challenge.c \
                 $ngx_addon_dir/src/pow_cookie.c"
ngx_module_libs="-lcrypto"
```

Do not enable NGINX's bundled OpenSSL build or use distribution source for
compilation. Run `make module` and inspect the resulting module with
`ldd out/ngx_http_pow_module.so`; it must resolve `libcrypto.so.3`.

- [ ] **Step 4: Add the isolated sanitizer runner**

`tools/run-asan.sh` must:

1. require `NGX_SOURCE_DIR` and create a trapped temporary build directory;
2. compile and run all C units with clang, strict warnings,
   `-fsanitize=address,undefined`, and `-fno-omit-frame-pointer`;
3. copy the pinned NGINX source into the temporary directory;
4. configure with `CC=clang`, `--with-compat --with-debug`, the same sanitizer
   flags in `--with-cc-opt` and `--with-ld-opt`, and
   `--add-dynamic-module=/work`;
5. build the instrumented nginx binary and dynamic module;
6. run Test::Nginx with `TEST_NGINX_BINARY` and `POW_MODULE_PATH` pointing at
   those temporary artifacts;
7. set `ASAN_OPTIONS=abort_on_error=1:detect_leaks=1` for unit binaries and
   `detect_leaks=0` for NGINX because its process-lifetime pools are not leak
   ownership bugs;
8. set `UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1` throughout.

Any compile warning, sanitizer report, test failure, or shell error must fail
the target.

- [ ] **Step 5: Wire and run the sanitizer gate**

Add:

```make
.PHONY: asan
asan:
	./tools/run-asan.sh
```

Run `make asan` inside the golden image.

Expected: all unit binaries and the real Test::Nginx suite pass under
ASan/UBSan with no report.

- [ ] **Step 6: Define the real pre-commit aggregate**

Define `check` to run, in dependency order:

```text
check-policy
test-unit
test-coverage
module
test-integration
test-e2e
test-fuzz
asan
```

Do not include `test-fuzz-long` in `check`; it remains the explicit Phase 1 and
pre-release long gate.

Add a `clean` target that removes only generated `build/` and `out/`
directories:

```make
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) out
```

- [ ] **Step 7: Run fresh Phase 1 completion verification**

From a clean `build/` and `out/`, run inside
`localhost/ngx-powgate-dev:trixie`:

```bash
make clean
make test-unit
make test-fuzz-long
make asan
make check
```

Expected:

- Python verifies the immutable v1 vector;
- all C unit tables pass;
- every listed parser function reports 100% conditional-branch execution;
- both fuzzers complete 10 minutes each without artifacts;
- sanitizer unit and instrumented-NGINX integration runs are clean;
- the NGINX 1.30.3 module builds and links `libcrypto.so.3`;
- nginx.org 1.30.3 integration and Node e2e tests pass;
- final `make check` exits 0 with no skipped target.

- [ ] **Step 8: Commit the completed Phase 1 gates**

```bash
git add Makefile config tests/integration/pow_module.t \
  tests/e2e/smoke.mjs tools/run-asan.sh
git commit -m "build: complete phase one gates"
```

- [ ] **Step 9: Review the complete branch**

Run:

```bash
git status --short
git log --oneline master..HEAD
git diff --check master...HEAD
git diff --stat master...HEAD
```

Expected: clean status; eight concise logical commits after the design commit;
no whitespace errors; changes limited to Phase 1 documentation, core, tests,
and build enforcement.
