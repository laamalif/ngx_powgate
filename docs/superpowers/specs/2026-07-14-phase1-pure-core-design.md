# Phase 1 Pure Core Design

**Date:** 2026-07-14

**Status:** Approved design

**Scope:** Phase 1 crypto, parsing, challenge, cookie, reference-vector,
unit-test, fuzzing, sanitizer, and coverage foundations

## Objective

Implement every security-critical byte operation as a small, allocation-free,
NGINX-independent C99 function before connecting protocol behavior to an NGINX
request. The core must reproduce the version 1 wire format in
`docs/protocol.md` byte for byte, compile under the project's strict warning
set, and be independently checked by Python reference vectors, table-driven
unit tests, fuzzing, and sanitizers.

Phase 1 adds no directives, request handling, secret-file loading, challenge
HTML, browser solver, or CI workflow.

## Core invariants

- All hostile inputs pass through a length gate, one forward parse, and only
  then cryptographic verification.
- Core code uses caller-provided fixed buffers and structures. It performs no
  allocation.
- Core public headers use only C99 `stdint.h` and `stddef.h` plus project
  headers. Cryptographic implementation files include OpenSSL where required.
  Core files use no NGINX header or type.
- Parsing and verification return `1` for success and `0` for failure. They do
  not expose detailed hostile-input error categories.
- Builders return the encoded length or `0` on failure.
- On failure, callers must treat parser output structures as uninitialized.
  Implementations need not erase partially written output.
- Verification never reparses or reserializes retained authenticated wire
  bytes after the initial successful parse.
- OpenSSL is the sole cryptographic implementation used by production code.
  The independent Python reference implementation uses Python's standard
  library.
- Production C implementation code takes every protocol constant and
  wire-format literal from `src/pow_protocol.h`. Normative documentation and
  checked-in protocol vectors necessarily spell their wire values explicitly.

## Component architecture

### `pow_crypto`

`src/pow_crypto.c` and `src/pow_crypto.h` own cryptographic primitives only:

- one-shot HMAC-SHA256 over explicit byte spans;
- SHA-256 over explicit byte spans;
- constant-time equality through `CRYPTO_memcmp`;
- leading-zero-bit counting and validation for a 32-byte digest.

This component does not parse protocol fields or serialize MAC inputs.

### `pow_parse`

`src/pow_parse.c` and `src/pow_parse.h` own shared wire-decoding mechanics:

- `pow_span_t`, containing an explicit byte pointer and length;
- splitting into an exact caller-requested count of non-empty dot-separated
  fields;
- canonical unsigned decimal parsing with caller-supplied digit and value
  limits;
- strict, unpadded base64url encoding;
- strict base64url decoding that requires an exact decoded length.

Strict base64url decoding accepts only `A-Z`, `a-z`, `0-9`, `-`, and `_`. It
rejects padding, foreign characters, impossible encoded lengths, wrong decoded
lengths, and non-zero unused tail bits. Builders receive an explicit output
capacity, precompute the required size, and never report partial output as
success.

### `pow_challenge`

`src/pow_challenge.c` and `src/pow_challenge.h` own challenge and proof
semantics. Their pure IP interface is:

```c
void pow_ip16_from_ipv4(const uint8_t ipv4[4], uint8_t out[16]);
void pow_ip16_from_ipv6(const uint8_t ipv6[16], uint8_t out[16]);
int pow_ip16_mask(uint8_t ip16[16], uint8_t plen);
```

The module will later extract address bytes from NGINX structures before
calling this interface. IPv4 conversion emits the protocol-defined
IPv4-mapped IPv6 form. Masking is in place and rejects `plen > 128`.

Bucket acceptance is isolated as:

```c
int pow_bucket_within_skew(uint64_t claimed, uint64_t current);
```

It uses ordered subtraction:

```text
claimed <= current ? current - claimed <= 1 : claimed - current <= 1
```

It never evaluates a bare `current - 1` or `current + 1`, so its behavior is
total at both `uint64_t` extremes.

Nonce derivation constructs the exact fixed-width `PGv1-chal` HMAC input.
Proof checking hashes the raw 32-byte nonce followed by the retained canonical
counter bytes and enforces difficulty in `[1, 32]` defensively.

The parsed proof structure is:

```c
typedef struct {
    uint64_t bucket;
    uint64_t counter;
    uint8_t  counter_ascii[16];
    size_t   counter_len;
} pow_proof_t;
```

Retaining the counter's exact canonical ASCII avoids a hidden reserialization
step during proof verification.

### `pow_cookie`

`src/pow_cookie.c` and `src/pow_cookie.h` own authentication-cookie parsing,
building, and verification. The parsed structure is:

```c
typedef struct {
    uint64_t expiry;
    uint8_t  difficulty;
    uint8_t  plen;
    uint8_t  payload[POW_AUTH_PAYLOAD_LEN];
    uint8_t  mac[POW_AUTH_MAC_LEN];
} pow_cookie_t;
```

The exact decoded payload is retained. MAC verification authenticates these
bytes directly rather than reconstructing them from interpreted fields.

`pow_cookie_verify` accepts the current secret, an optional previous secret,
the parsed cookie, live `ip16`, current time, minimum difficulty, and effective
minimum prefix length. The effective prefix floor is `pow_bind_ipv6` for IPv6
or `96 + pow_bind_ipv4` for IPv4.

## Validation and verification flow

### Proof cookie

1. Reject a value longer than 64 bytes before inspecting a field.
2. Require exactly `1.<bucket>.<counter>`.
3. Accept canonical decimal only: no signs, whitespace, empty fields, or
   leading zeros.
4. Enforce a 1-20 digit bucket and a 1-16 digit counter not exceeding
   `2^53-1`.
5. Check the claimed bucket with `pow_bucket_within_skew` before deriving a
   nonce.
6. Derive the current-secret nonce and check the retained counter bytes.
7. On failure, repeat with the previous secret only when one is configured.
8. Never try a third secret or alternate representation.

Proof verification without a configured previous secret performs no dummy
second proof verification.

### Authentication cookie

1. Reject a value longer than 256 bytes before inspecting a field.
2. Require exactly three non-empty fields and literal version `1`.
3. Decode strict canonical base64url.
4. Require decoded payload and MAC lengths of exactly 10 and 16 bytes.
5. Decode big-endian expiry and validate the parser safety bounds:
   difficulty in `[1, 32]` and prefix length in `[32, 128]`.
6. Copy the live `ip16`, mask the copy with the cookie's already bounded
   prefix length, and construct the fixed MAC input.
7. Compare the current-secret MAC in constant time.
8. If it fails, always calculate a second HMAC: use the previous secret when
   configured; otherwise calculate and discard a second HMAC with the current
   secret.
9. After a MAC succeeds, require `expiry > now`,
   `difficulty >= min_difficulty`, and `plen >= min_plen`. The last two checks
   are authenticated deployment-policy floors, distinct from parser safety
   bounds.

If the current-secret MAC succeeds, no second HMAC is calculated. If it fails,
exactly one second HMAC is calculated and no third secret is tried.

## Reference vector

`tests/vectors/v1.json` is the canonical, versioned protocol artifact. It
contains fixed inputs and byte-exact expected results for IP masking, nonce
derivation, proof checking, and authentication-cookie construction.

Existing byte-exact expected values cannot change without an explicit
protocol-spec change. New cases may be added without altering existing values.
Normal builds and tests never regenerate or rewrite the file.

`tools/refsolve.py` is an independent implementation written from
`docs/protocol.md`. It uses only Python's standard library and:

- derives nonces;
- mines the canonical low-difficulty proof;
- constructs expected cookie values;
- verifies every expected value already stored in `v1.json`.

It does not call, generate, or bind to the C core.

C tests consume the checked-in JSON through a deterministic test-build
converter. The converter reads only `v1.json`, performs no cryptographic
calculation, and emits a C header beneath `build/`. The generated header is not
committed. This keeps one vector source without adding a JSON parser to the C
test executable.

## Unit testing

Tests in `tests/unit/` are table-driven and split by component. They cover:

- RFC 4231 HMAC-SHA256 known-answer cases and SHA-256 known-answer cases;
- constant-time equality results;
- leading-zero-bit boundaries;
- canonical decimal acceptance, limits, overflow, and malformed forms;
- strict base64url acceptance and rejection, including unused tail bits;
- encode/decode round trips at boundary lengths, with zero bytes, and with a
  buffer containing every byte value from 0 through 255;
- IPv4 mapping and IPv4/IPv6 prefix-masking boundaries;
- bucket skew at zero, one, ordinary values, and `UINT64_MAX`;
- proof parsing, retained counter bytes, nonce derivation, and proof checking;
- cookie build, parse, and verification with current and previous secrets;
- no-previous-secret rejection, expiry, difficulty floor, and effective
  prefix floor;
- rejection by parsing or verification of every single-byte mutation of a
  valid cookie;
- byte-exact end-to-end reproduction of `tests/vectors/v1.json`.

Parser unit tests must execute every conditional branch in every parser.
Coverage is evidence used to verify this requirement, not a substitute for
behavioral assertions.

## Fuzzing and sanitizers

Two clang/libFuzzer targets run with ASan and UBSan:

- the authentication-cookie target parses arbitrary input and, after a
  successful parse, verifies it with fixed bounded inputs;
- the proof-cookie target parses arbitrary input and, after a successful
  parse, exercises bounded bucket and proof checks.

The fuzz harnesses and core code allocate no memory based on fuzzer input.
libFuzzer owns the supplied input buffer.

Each corpus contains at least one valid input and a seed for every malformed
input class represented by the unit tables. Every parser bug fixed or parser
rule added must introduce both a regression unit-test row and a corresponding
fuzz corpus seed.

`make test-fuzz` runs each fuzzer for 60 seconds. `make test-fuzz-long` runs
each fuzzer for 10 minutes.

## Build and completion gates

The pure core compiles warning-free with:

```text
-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror
```

All compilation and verification run inside
`localhost/ngx-powgate-dev:trixie`. Phase 1 is complete only when these fresh
commands all pass there:

```text
make test-unit
make test-fuzz-long
make asan
make check
```

## Documentation and policy alignment

Before implementation, the execution plan must include these documentation
updates:

- `PLAN.md` assigns base64url mechanics to `pow_parse`, replaces the old
  sockaddr helper with the approved byte-oriented APIs, records the exact
  parsed structures and verification behavior, and adopts the vector, fuzz,
  and coverage invariants in this design.
- `docs/protocol.md` specifies rejection of non-canonical base64url unused tail
  bits and makes the no-previous-secret dummy HMAC behavior explicit for auth
  cookies.
- Proof verification remains current-secret first and previous-secret only
  when configured.
- `AGENTS.md` removes the residual `ngx_config.h` exception. Pure-core files
  use no NGINX headers.
- `tools/check-policy.sh` is extended as needed to enforce pure-core include
  boundaries and prohibited allocation and string patterns.

Phase 1 introduces no runtime state, randomness, production network access, or
new production dependency.
