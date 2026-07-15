# Phase 4A server verification design

## Status and scope

Phase 4A completes the server-side PowGate loop against the independent
Python reference implementation. It accepts authentication cookies and proof
cookies, applies the frozen v1 protocol, issues authentication cookies after
valid proofs, and lets authenticated requests continue through NGINX.

This phase includes:

- deterministic Cookie-field extraction;
- authentication-cookie and proof-cookie verification;
- current/previous secret handling;
- transactional authentication-cookie issuance and proof-cookie clearing;
- bounded verification-failure logging;
- deterministic crypto and NGINX allocation-failure tests;
- HTTPS HTTP/1.1 and HTTP/2 integration coverage.

It excludes:

- browser solver changes;
- header-based proof submission;
- metrics and NGINX variables;
- long-lived keepalive continuity across reloads;
- performance benchmarking;
- protocol version changes;
- new dependencies, external calls, or server-side state.

The production difficulty default remains 20. The protocol, configuration,
README, implementation constant, and Phase 2 tests already agree on that
value. Integration mining uses an explicitly configured low difficulty.

## Enduring invariants

- Only client-facing requests are processed:
  `r == r->main && !r->internal`.
- The canonical client address is IPv4 or IPv6 after RealIP processing.
  Other address families fail closed as already specified.
- One nonnegative `now` value is sampled for each enabled, supported,
  non-exempt request before any time-dependent work. Bucket calculation,
  bucket skew checks, cookie expiry verification, issued expiry, and fallback
  challenge generation all use that value.
- The module extracts canonical unmasked `ip16`. Protocol-defined masking is
  performed by the pure core using an explicit prefix length.
- Authentication is attempted before proof verification. Authentication
  success stops all cookie scanning.
- Verification work is bounded: at most four auth occurrences, two MACs per
  failing auth occurrence, one proof occurrence, two nonce derivations, and
  two proof checks.
- A client-invalid artifact leads to the normal challenge. An internal
  inability to perform verification leads to `500`.
- A valid proof is not accepted until both required response cookies are
  completely and transactionally committed.
- The adapter does not discard request bodies, render challenges, send
  headers, or finalize requests.
- Each request has exactly one terminal outcome: `NGX_DECLINED`, `NGX_DONE`,
  or an NGINX error-response path.

## Architecture

The request flow is:

```text
enabled client-facing request
        |
        v
validate IPv4/IPv6 connection family
        |
        v
IP exemption -> path exemption
        |
        v
extract canonical unmasked ip16 + effective plen
        |
        v
sample now once
        |
        v
ngx_http_pow_verify_request(...)
        +-- OK ----> NGX_DECLINED
        +-- NONE --> existing Phase 3 challenge path
        `-- ERROR -> 500
```

### `ngx_http_pow_module.c`

The main module owns:

- phase-handler flow;
- subrequest/internal/disabled gates;
- connection-family handling and exemptions;
- canonical address extraction;
- current effective prefix selection;
- the single clock sample;
- mapping adapter results to allow, challenge, or error;
- existing HTML/bare challenge generation and request-body discard.

The Phase 3 identity helper is refactored so it no longer irreversibly masks
the only address copy. For IPv4 the current effective protocol prefix is
`96 + pow_bind_ipv4`; for IPv6 it is `pow_bind_ipv6`.

### `ngx_http_pow_verify.c/.h`

The NGINX verification adapter owns:

- walking NGINX Cookie fields in request order;
- invoking the pure scanner, value parsers, and verification functions;
- applying the request's current effective verification policy;
- bounded verification logging;
- transactional construction of both Set-Cookie fields;
- the narrow test-only Set-Cookie slot wrapper.

The adapter has no knowledge of HTML, 403/503 selection, challenge bodies,
or response finalization.

Its result type is:

```c
typedef enum {
    NGX_HTTP_POW_VERIFY_OK,
    NGX_HTTP_POW_VERIFY_NONE,
    NGX_HTTP_POW_VERIFY_ERROR
} ngx_http_pow_verify_result_t;
```

- `OK` means a valid auth cookie was found, or a valid proof was followed by
  successful commitment of both response cookies.
- `NONE` means no valid artifact exists and the caller must issue the normal
  challenge.
- `ERROR` means an internal operation failed; no PowGate Set-Cookie field is
  visible and the caller returns `500`.

Valid auth and proof requests leave the request body untouched for downstream
processing. Invalid or absent artifacts enter the existing challenge path,
which discards the body with NGINX's API.

### Pure core

`pow_cookie_scan.c/.h` is a new NGINX-free, zero-allocation pure module for
Cookie request-field syntax. It is separate from `pow_cookie.c`, which owns
the auth-cookie value format.

The dependency direction is:

```text
Cookie request field
        |
        v
pow_cookie_scan
        |
        v
cookie value span
        |
        +--> pow_cookie_parse --> pow_cookie_verify
        `--> pow_proof_cookie_parse --> proof verification
```

The existing challenge, cookie, parser, and crypto modules remain
NGINX-free. No historical configuration or request state enters the core.

## Reserved cookie name

The proof-cookie name `__pow_p` is protocol-reserved. Configuration rejects
the exact directive:

```nginx
pow_cookie_name __pow_p;
```

with a semantic diagnostic equivalent to:

```text
pow_cookie_name "__pow_p" is reserved for the proof cookie
```

The comparison is byte-exact and case-sensitive. A case variant such as
`__POW_P` remains eligible only if it satisfies the normal cookie-name token
grammar and does not collide with another explicitly reserved protocol name.
The v1 design reserves no `__Host-*` namespace; future internal names require
an explicit protocol reservation when introduced.

## Cookie request-field scanner

The scanner operates on one field value at a time:

```c
typedef struct {
    const uint8_t  *data;
    size_t          len;
} pow_cookie_value_t;

typedef enum {
    POW_COOKIE_SCAN_ERROR = -1,
    POW_COOKIE_SCAN_DONE = 0,
    POW_COOKIE_SCAN_FOUND = 1
} pow_cookie_scan_result_t;

pow_cookie_scan_result_t pow_cookie_scan_next(
    const uint8_t *field, size_t field_len,
    const uint8_t *name, size_t name_len,
    size_t *cursor, pow_cookie_value_t *out);
```

The contract is:

- `*cursor` is zero for the first call.
- Invalid arguments return `POW_COOKIE_SCAN_ERROR` without changing the
  cursor or output.
- Every successful call returns the next exact-name value span and makes the
  cursor strictly greater than its entry value.
- Exhaustion returns `POW_COOKIE_SCAN_DONE` with `cursor == field_len`.
- Output is usable only after `POW_COOKIE_SCAN_FOUND`.
- Successive returned spans do not overlap.
- Each input byte is examined at most once per independent scan.
- The scan is forward-only, linear, allocation-free, and length-delimited.

The field is a sequence of semicolon-delimited segments. Empty segments are
permitted and ignored. For every segment the scanner:

1. starts at the field beginning or immediately after the preceding `;`;
2. skips only SP (`0x20`) and HTAB (`0x09`) before the pair;
3. compares the requested name byte-for-byte and case-sensitively;
4. requires the following byte to be exactly `=`;
5. returns all bytes after `=` through, but excluding, the next `;` or field
   end;
6. performs no trimming, quote processing, escaping, decoding, or NUL-based
   operation;
7. skips malformed and unrelated segments without terminating the scan.

Consequences include:

- `__pow=` is an occurrence with an empty value and fails value parsing.
- `__pow= abc` is an occurrence whose value begins with SP.
- `__pow =abc` is not an occurrence.
- `__pow_extra=abc` is not an occurrence.
- `__POW=abc` does not match `__pow`.
- Embedded NUL bytes are ordinary bytes.
- Empty, oversized, and malformed exact-name values still count as
  occurrences.

For HTTP/1.x, the adapter walks every linked `r->headers_in.cookie` field in
receipt order and scans each left-to-right. NGINX 1.30.3 reconstructs HTTP/2
Cookie fields as one `"; "`-joined field while preserving the effective
receipt order used by the adapter.

Authentication and proof extraction are independent:

1. Auth verification scans exact configured-name occurrences in order.
2. Auth failure continues through at most four occurrences.
3. Auth success stops all scanning; proof is not inspected or logged.
4. Only after auth is absent or all attempted occurrences fail does a fresh
   proof scan begin.
5. Proof extraction stops after the first exact `__pow_p` occurrence.
6. No later proof occurrence is evaluated, even when the first is malformed,
   oversized, or invalid.
7. The auth bound cannot prevent the independent proof scan from locating
   its first occurrence.

## Verification result correction

The Phase 1 verification API is corrected to distinguish client invalidity
from cryptographic-provider failure:

```c
typedef enum {
    POW_VERIFY_ERROR   = -1,
    POW_VERIFY_INVALID = 0,
    POW_VERIFY_VALID   = 1
} pow_verify_result_t;
```

This type is used only by `pow_cookie_verify()` and `pow_proof_check()`.
Parsers retain strict `1`/`0` contracts. Builders and derivation functions
retain their existing success/zero contracts because their adapter inputs are
already validated and zero therefore represents an internal error.

Any OpenSSL failure, including allocation/context, initialization, update,
or finalization failure, propagates as `POW_VERIFY_ERROR`. A verifier never
maps an internal cryptographic failure to `POW_VERIFY_INVALID`.

For these verification APIs, invalid function arguments or an impossible
post-parse structure are caller/invariant errors and also return
`POW_VERIFY_ERROR`. `POW_VERIFY_INVALID` is reserved for a well-formed
verification attempt whose MAC, work, expiry, or policy verdict fails.

A test-only linked crypto shim deterministically fails HMAC and SHA-256 for
unit coverage. It is not compiled into production or fault-variant modules
and introduces no production switch.

## Authentication-cookie path

Auth verification precedes proof extraction. For each of at most four exact
occurrences:

1. Count the occurrence.
2. Reject a value over 256 bytes before value parsing.
3. Strictly parse version, field count, base64url lengths, decoded lengths,
   and payload sanity bounds.
4. Pass the canonical unmasked address, sampled `now`, current difficulty,
   and current family-specific minimum prefix to `pow_cookie_verify()`.
5. The pure core masks the address with the parsed, sanity-checked cookie
   prefix before computing the MAC.
6. MAC verification is attempted with the current secret. If and only if the
   comparison fails, compute exactly one additional MAC: previous secret
   when configured, otherwise a discarded dummy computation using the current
   secret.
7. A successful current-secret comparison does not evaluate the previous
   secret.
8. Only after a MAC succeeds, apply `expiry > now`, cookie difficulty at
   least current difficulty, and cookie prefix at least the current
   family-specific minimum.
9. `POW_VERIFY_VALID` stops all scanning and returns adapter `OK`.
10. `POW_VERIFY_INVALID` advances to the next occurrence.
11. `POW_VERIFY_ERROR` stops immediately and returns adapter `ERROR`.

After one through four auth occurrences all fail, emit one bounded auth
invalid summary and begin proof extraction. With no auth occurrence, emit no
auth log. `POW_VERIFY_ERROR` never contributes to client-failure summaries;
it produces only the fixed internal-error log.

## Proof-cookie path

Only after authentication is absent or completely fails:

1. Locate the first exact `__pow_p` occurrence.
2. Reject a value over 64 bytes before value parsing.
3. Strictly parse version, bucket, and counter.
4. Apply the total ordered-difference bucket rule against the bucket computed
   from the sampled `now`.
5. Bucket rejection occurs before HMAC derivation or any secret-dependent
   operation.
6. Copy canonical `ip16` and mask it with the request's current effective
   prefix.
7. Derive the current-secret nonce and check the proof at the request's
   current effective difficulty.
8. Only when that check is `POW_VERIFY_INVALID` and a previous secret exists,
   derive once with the previous secret and perform exactly one second proof
   check.
9. A current-secret `POW_VERIFY_ERROR` does not fall back to the previous
   secret. Any derivation failure or proof-check error returns adapter
   `ERROR` immediately.
10. No previous prefix, previous difficulty, third secret, or historical
    configuration is tried.
11. A final invalid result emits one proof-invalid summary and returns adapter
    `NONE`.
12. A valid result proceeds to transactional cookie issuance. Adapter `OK`
    is impossible until every required response mutation succeeds.

With no previous secret, proof verification performs one nonce derivation and
one proof check. It performs no dummy second proof check.

Proof verification always uses the request's current effective difficulty. A
proof satisfying that difficulty is accepted regardless of the difficulty in
effect when the challenge was issued. Nonce derivation always uses the
request's current effective binding prefix; no previous prefix is considered.
A reload may therefore invalidate an in-flight proof.

Configuration changes are not protocol events. Proofs are transient and tied
to current policy. Auth cookies are self-describing and survive only when
their embedded values satisfy the auth verification rules and current policy
floors. No configuration history is retained.

Current then previous secret is the sole proof fallback. New challenges and
new auth cookies always use the current secret.

## Issued expiry

The checked operation is:

```c
expiry = (uint64_t) now + (uint64_t) cookie_ttl;
```

The adapter checks the addition against `UINT64_MAX` before executing it.
Overflow is an internal invariant failure: fixed error log, no visible
Set-Cookie field, adapter `ERROR`. Saturation and wrapping are forbidden.
The check should be unreachable on supported platforms but makes the contract
total.

## Exact Set-Cookie construction

After a valid proof, the module creates exactly two Set-Cookie fields in this
construction order before NGINX serialization:

```text
Set-Cookie: <configured-name>=<auth-value>; Max-Age=<ttl>; Path=/; Secure; HttpOnly; SameSite=Lax
Set-Cookie: __pow_p=; Max-Age=0; Path=/
```

The v1 auth value length is fixed at 39 bytes:

```text
"1." + b64url(payload 10 bytes) + "." + b64url(mac 16 bytes)
  2  +              14 bytes +  1  +              22 bytes = 39
```

The length does not depend on TTL, difficulty, or prefix. `Max-Age` is the
configured TTL in canonical unsigned decimal seconds. No `Domain` or
`Expires` attribute is emitted.

`pow_cookie_secure off` omits only `; Secure` from the auth field. Cookie
security is never inferred from the request scheme. The proof-clear path is
always `/` and is not configurable; proof clearing has no Secure, HttpOnly,
or SameSite attribute.

All fixed Set-Cookie header-name, cookie-name, attribute, and proof-clear
literals are defined once in `pow_protocol.h`; the effective configured auth
name comes from location configuration. Their spelling, capitalization,
spacing, and construction order are protocol bytes. Transport intermediaries
are not promised an application-visible header ordering contract.

## Transactional response mutation

Cookie issuance follows this sequence:

1. Check expiry addition.
2. Precompute both exact field-value lengths.
3. Allocate both exact value buffers from `r->pool`.
4. Build both complete values by pointer walking.
5. Require the auth builder's exact 39-byte result and both final pointers to
   equal their buffer ends.
6. Reserve the first PowGate header slot through the narrow wrapper.
7. Immediately set `hash = 0` and `next = NULL`.
8. Reserve and initialize the second slot identically.
9. Populate both keys and values while both hashes remain zero.
10. Commit by setting both hashes to one.
11. Only then return adapter `OK`.

No header-list-visible field is committed until its `hash` is set. Reserved
but uncommitted entries are request-pool objects only and NGINX does not send
them. They require no manual free and disappear with the request pool.
The two hash assignments are adjacent, non-failing final mutations with no
call between them; NGINX cannot serialize the response concurrently while
the access handler is executing.

The adapter changes no response status, content length, body, or header-send
state. It does not call `ngx_http_send_header()` or finalize the request.

Any construction, reservation, arithmetic, crypto, or invariant failure:

- returns adapter `ERROR`;
- logs one fixed internal error at `NGX_LOG_ERR`;
- never uses `pow_log_level`;
- leaves any reserved slot at `hash = 0`;
- exposes no PowGate Set-Cookie field;
- never passes the request through.

Adapter `OK` means all required response mutations completed successfully. It
is never returned after partial header commitment.

## Verification logging

Client-invalid summaries use `r->connection->log` at the request's effective
`pow_log_level`. Each verification path contributes at most one record:

```text
no auth occurrence                  -> no auth log
auth succeeds                       -> no auth log; proof untouched
one to four auth occurrences fail   -> one auth-invalid summary
no proof occurrence                 -> no proof log
proof fails                         -> one proof-invalid summary
auth fails, proof succeeds          -> one auth summary only
auth fails, proof fails             -> one auth + one proof summary
proof succeeds                      -> no proof-success log
```

The fixed ASCII operation and verdict tokens form a stable observability
contract:

```text
pow_gate: operation=auth verdict=invalid occurrences=<1..4>
pow_gate: operation=proof verdict=invalid value_len=<length>
```

The summaries deliberately do not distinguish malformed, MAC, expiry,
difficulty, or prefix failures. They never include cookie bytes, decoded
payload, MAC, nonce, counter, secret-derived values, client address, URI,
arguments, headers, or request body.

Scanner contract errors, impossible arithmetic, allocation or construction
failures, and `POW_VERIFY_ERROR` produce only fixed internal records at
`NGX_LOG_ERR`. They never contribute to client-invalid summaries.

Phase 4A includes focused behavior, severity, count, and nondisclosure tests.
Phase 5 owns the broader logging audit and permanent regression-policy review,
not first implementation.

## Set-Cookie fault variants

The adapter reserves its two header slots through a tiny wrapper local to the
PowGate verification adapter. It does not replace `ngx_list_push()` globally.

Two mutually exclusive test macros are supported only in test builds:

```text
POW_TEST_FAIL_FIRST_SET_COOKIE
POW_TEST_FAIL_SECOND_SET_COOKIE
```

Defining both is a compile-time error. Each creates a separately named test
artifact:

```text
build/fault-first/ngx_http_pow_module_fault_first.so
build/fault-second/ngx_http_pow_module_fault_second.so
```

Normal production and normal sanitizer modules define neither macro. Fault
artifacts never enter `out/`, packaging inputs, or release artifacts and are
never loaded together.

For each variant, forced HTTPS HTTP/1.1 and HTTP/2 integration tests prove:

- a valid proof reaches the selected reservation site;
- the response is `500`;
- no Set-Cookie field is visible;
- backend/content handling is not reached, even when request headers and body
  are otherwise acceptable;
- no client-invalid summary is emitted;
- the internal failure record contains no request data;
- a second request reuses the connection where NGINX permits and fails
  independently through the same controlled site.

ASan/UBSan builds and exercises sanitized fault variants as test fixtures.
The functional request source remains the production source; only the narrow
slot wrapper differs at compile time.

## Reference implementation

`tools/refsolve.py` remains cryptographically independent of production C.
It gains three explicit, deterministic interfaces:

- `mine`: secret, IP, prefix, bucket, difficulty, and optional starting
  counter in; the first valid counter at or after that start and the complete
  `__pow_p` value out as bounded JSON;
- `proof-check`: the same context plus an explicit counter in; digest and
  valid/invalid verdict out as bounded JSON;
- `auth`: secret, IP, expiry, difficulty, and prefix in; complete auth value
  out as bounded JSON.

CLI secret hex accepts mixed case. Difficulty has no implicit refsolve
default; tests pass it explicitly. The tool does not consume generated C
headers or production binaries.

`tests/vectors/v1.json` remains immutable unless the protocol changes and is
never regenerated by normal builds or tests.

Perl retains NGINX lifecycle ownership. A narrow helper may parse the fixed
challenge field, execute refsolve with explicit arguments, decode bounded
JSON, and extract Set-Cookie values. It must not become a general HTTP or
cryptography framework.

Negative and transition tests never assume that a counter valid in one
context fails in another. They use `proof-check` to prove the alternate
context is invalid. If it is valid, they resume `mine` at the next counter
and repeat with a strict iteration bound. This applies to wrong-IP,
raised-difficulty, changed-prefix, and rotated-secret cases. Low test
difficulty therefore affects runtime, not determinism.

## Pure-core validation

The exact fuzz target names are:

```text
fuzz_cookie_scan
fuzz_auth_cookie
fuzz_proof_cookie
```

The scanner has a dedicated table test, corpus, fuzzer, and 100% branch
coverage requirement. Tables include every grammar rule, empty segments,
embedded NUL, exact-name boundaries, whitespace behavior, repeated
occurrences, invalid arguments, and cursor/output contracts. Fuzz invariants
include bounded monotonic cursors, contained and non-overlapping spans,
forward progress, and bounded termination.

Existing auth and proof tables are updated for tri-state verification. A
test-only linked crypto shim proves cookie HMAC failure and proof SHA failure
become `POW_VERIFY_ERROR`. Production OpenSSL success paths retain their
existing unit/vector coverage.

`make test-fuzz` and `make test-fuzz-long` run all three fuzzers. The coverage
gate enforces every scanner branch. `tools/check-policy.sh` and `AGENTS.md`
add `pow_cookie_scan.c/.h` to the NGINX-free, zero-allocation, strict-warning
pure core. Every future scanner rule or fixed scanner bug requires a unit
table row and corpus seed.

## HTTPS integration matrix

Every Phase 4A request-path case runs over forced HTTPS HTTP/1.1 and forced
HTTPS HTTP/2, with the negotiated protocol asserted.

### Baseline and success

- no target cookie challenges and emits no verification log;
- a valid current-secret proof reaches content, creates both exact cookies,
  and its issued auth cookie passes on a follow-up request;
- a valid proof carried on a request body leaves the exact body available to
  downstream content;
- a valid independently generated auth cookie passes without issuing another
  cookie;
- default auth issuance contains Secure;
- `pow_cookie_secure off` omits only Secure.

### Invalid proof and bucket behavior

- malformed and oversized proof values;
- a deterministically failing counter;
- stale `current - 2` and future `current + 2` buckets;
- wrong-IP proof;
- properly mined `current - 1`, current, and `current + 1` buckets;
- invalid or oversized first proof shadowing a valid second proof, with no
  attempt to evaluate the later occurrence;
- four failed auth occurrences followed by a valid proof, proving independent
  extraction.

Bucket-boundary tests observe a fresh challenge bucket immediately before
submission. If the observed bucket rolled while a counter was being mined,
the case is regenerated and retried with a strict bound; it is never silently
skipped. This prevents the `current - 1` acceptance case from becoming a
wall-clock race.

### Current proof policy

- proof verification uses current difficulty after reload;
- proof derivation uses current binding prefix after reload;
- no historical difficulty or prefix is tried.

For each policy-transition case, the selected counter is proven valid under
the issuing context and invalid under the new context before submission.

### Auth verification

- malformed, oversized, tampered, expired, wrong-IP, insufficient-difficulty,
  and insufficient-prefix auth values challenge;
- a second address fails at IPv4 `/32` and succeeds in the same `/24` when
  policy permits;
- equivalent IPv6 binding coverage;
- valid auth occurrences at positions two and four pass;
- a valid fifth occurrence is ignored;
- auth success prevents proof extraction and proof logging;
- auth failure followed by proof success produces only the auth-invalid
  summary.

### Scanner and header representation

- exact case, name prefixes, empty values, leading SP/HTAB, whitespace around
  `=`, empty segments, and malformed intervening segments;
- duplicate HTTP/1.1 Cookie fields preserve request order;
- NGINX's HTTP/2 Cookie reconstruction preserves the effective receipt order
  used by the adapter.

### Logging and fault behavior

- no, one-path, and two-path log outcomes;
- effective configured severity;
- fixed operation/verdict tokens and bounded count/length fields;
- no cookie, request, address, secret, nonce, MAC, or counter sentinel in
  logs;
- both Set-Cookie slot-failure variants return `500`, expose no cookie, and do
  not reach content;
- successful pass-through and fault responses retain connection reuse where
  NGINX permits.

Distinct test client identities use trusted RealIP configuration only. A
forwarding header is never authoritative without an explicitly trusted test
proxy.

## Rotation proof

The rotation test must identify worker generations rather than allowing a
draining worker to create false success:

1. Start with the old current secret only.
2. Obtain and mine a challenge, then close that client connection.
3. Atomically install new current plus old previous. The secret target's
   regular-file type and permission policy are revalidated during reload.
4. Reload NGINX.
5. Observe a new worker and wait until every pre-reload worker exits.
6. Before submission, use the independent reference implementation to prove
   the selected counter is valid for the old secret and invalid for the new
   current secret.
7. Submit the pre-rotation proof over a fresh connection; it passes only
   through previous-secret fallback.
8. Independently confirm the old-secret auth MAC differs from the new-current
   MAC for the fixed fixture, then verify that cookie passes in the new worker
   generation through previous-secret fallback.
9. Atomically remove the previous secret and reload again, again revalidating
   the secret file.
10. Wait for the next worker generation and retirement of the prior one.
11. Verify the old-secret auth cookie now challenges.

Long-lived keepalive continuity across reload remains Phase 5 scope.

## Build and sanitizer gates

All build, test, fuzz, sanitizer, and integration gates run inside
`localhost/ngx-powgate-dev:trixie`. Host compilation is unsupported.

Normal integration produces the release-shaped module only under `out/` and
the two fault modules only under their `build/` test directories. ASan/UBSan
builds and exercises:

- normal production source;
- both NGINX slot-fault variants;
- all pure unit tests, including the linked crypto-failure shim;
- the complete HTTPS HTTP/1.1 and HTTP/2 integration matrix;
- all three fuzz targets through the existing sanitizer-backed fuzz gates.

`make check` is the completion gate. No required case is skipped or marked
TODO. In the canonical image, missing required HTTP/2, OpenSSL, sanitizer, or
test support is an environment-gate failure rather than a skip.

## Documentation changes during implementation

Phase 4A updates:

- `docs/protocol.md`: reserved name, scanner semantics, clock snapshot,
  current proof policy, tri-state verification behavior, and exact cookie
  construction;
- `docs/configuration.md`: reserved-name rule, active verification/logging,
  reload effects, and Secure opt-out;
- `docs/security.md`: bounded verification, provider failures, secret roles,
  and rotation evidence;
- `README.md`: only behavior that is now implemented;
- `PLAN.md`: the frozen Phase 4A decisions and Phase 5's audit-only logging
  ownership;
- `AGENTS.md`: the scanner pure-core family, exact three-fuzzer gate, and the
  enduring invalid-versus-internal-error distinction.

No dependency or version-lock change is required.
