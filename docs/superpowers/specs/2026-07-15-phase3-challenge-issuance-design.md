# Phase 3 Challenge Issuance Design

## Status

Design decisions approved section by section on 2026-07-15. This written
specification is pending final review before implementation planning.

Phase 3 implements challenge delivery only. It does not verify authentication
cookies, accept proof cookies, issue authentication cookies, or solve proof of
work in the browser.

## Goal

When PowGate is enabled for a main, externally initiated request that is not
explicitly exempt, derive a deterministic challenge from the current secret
and return one of two complete responses:

- an HTML `503` for a `GET` or `HEAD` navigation whose `Accept` headers contain
  `text/html` using the protocol's case-insensitive substring rule; or
- a bodyless `403` with `PowGate-Challenge` for every other method/header
  combination.

Every request-behavior scenario is exercised over HTTPS with explicitly
negotiated HTTP/1.1 and HTTP/2.

## Non-goals

Phase 3 does not add:

- authentication-cookie parsing or verification;
- proof-cookie parsing or verification on the request path;
- authentication-cookie issuance;
- a working browser proof-of-work solver;
- header-based proof submission;
- custom challenge templates or NGINX variables;
- request state, challenge storage, randomness, network calls, or external
  services;
- Unix-domain client identity binding; or
- per-challenge request logging.

Cookies are deliberately ignored in this phase. Until Phase 4A, a non-exempt
protected request is challenged even if it carries a cookie named `__pow` or
`__pow_p`.

## NGINX 1.30.3 precedents

The pinned tree at `NGX_SOURCE_DIR` remains authoritative. Phase 3 follows
these specific precedents rather than inventing module conventions:

- access-phase registration and `NGX_DECLINED` composition:
  `src/http/modules/ngx_http_access_module.c`;
- access-phase return handling, `satisfy`, and handler order:
  `ngx_http_core_access_phase()` and `ngx_http_init_phase_handlers()`;
- post-RealIP address availability:
  `ngx_http_realip_init()`, which registers in post-read and pre-access before
  PowGate's access handler;
- CIDR matching, including IPv4-mapped IPv6:
  `ngx_cidr_match()` in `src/core/ngx_inet.c`;
- normalized, percent-decoded `r->uri`, dot-segment removal, and the
  `merge_slashes` switch: `ngx_http_parse_complex_uri()`;
- request-body disposal: `ngx_http_discard_request_body()`;
- content response construction: `ngx_http_send_response()`, static,
  autoindex, and stub-status handlers;
- embedded immutable HTML bytes and response cleanup:
  `ngx_http_special_response.c`;
- request finalization and `NGX_DONE`: `ngx_http_finalize_request()` and
  `ngx_http_core_access_phase()`;
- repeated `Accept` header representation: `ngx_http_process_header_line()`,
  which links occurrences through `ngx_table_elt_t.next`;
- post-1.25 HTTP/2 enablement: the `http2 on;` directive in
  `src/http/v2/ngx_http_v2_module.c`; and
- `add_header` status behavior: `ngx_http_headers_filter()`, where a `503`
  receives operator headers only when configured with `always`.

Before implementation introduces another NGINX API, the implementer must add
the exact pinned-source precedent to the task work log.

## Request state machine

The access handler evaluates one terminal path in this order:

1. If `r != r->main`, return `NGX_DECLINED`.
2. If `r->internal` is set, return `NGX_DECLINED`.
3. Load the merged location configuration. If `pow` is off, return
   `NGX_DECLINED`.
4. Classify `r->connection->sockaddr->sa_family`:
   - `AF_INET` is IPv4;
   - `AF_INET6` with `IN6_IS_ADDR_V4MAPPED` is IPv4;
   - other `AF_INET6` addresses are IPv6;
   - every other family logs the numeric family and fails closed with `500`.
5. If `pow_exempt_ip` exists and `ngx_cidr_match()` returns `NGX_OK`, return
   `NGX_DECLINED`. `NGX_DECLINED` continues. Any unexpected result fails with
   `500`.
6. Evaluate configured exempt paths in array order against `r->uri`:
   - `/` matches every URI;
   - another path matches an exact URI; or
   - it matches when the next URI byte is `/`.
   A query is never inspected because it resides in `r->args`.
7. Convert the post-RealIP address to canonical `ip16` and effective `plen`:
   - IPv4 uses IPv4-mapped IPv6 plus `96 + pow_bind_ipv4`;
   - IPv6 uses its 16 address bytes plus `pow_bind_ipv6`.
8. Mask `ip16` with the existing pure helper. Failure returns `500`.
9. Read wall-clock Unix time with `ngx_time()`. A negative value returns
   `500`. Divide by the validated positive challenge window to produce the
   `uint64_t` bucket.
10. Derive the nonce with the current secret. Failure returns `500`.
11. Serialize the challenge once. Failure returns `500`.
12. Call `ngx_http_discard_request_body(r)` before committing response
    headers. A non-`NGX_OK` result is returned unchanged so NGINX handles it.
13. Apply the navigation rule across every linked `Accept` occurrence.
14. Allocate, validate, commit, send, and finalize the selected response.
15. Return `NGX_DONE` after explicit finalization.

This order makes unsupported connection families fail closed even when a path
would otherwise be exempt. PowGate v1 supports identity binding only for IPv4
and IPv6 connections; an unsupported transport never becomes an implicit
trusted identity.

A request has exactly one terminal outcome:

- `NGX_DECLINED` for a request PowGate allows another handler to process;
- `NGX_DONE` after PowGate has explicitly finalized a challenge; or
- an NGINX error-response path before PowGate has made a challenge visible.

## Navigation detection

A request is navigational only when both conditions hold:

- `r->method` is `NGX_HTTP_GET` or `NGX_HTTP_HEAD`; and
- at least one linked `Accept` value contains the exact byte substring
  `text/html`, compared case-insensitively.

No media-type parsing, quality-factor interpretation, or wildcard inference
is added. This intentionally preserves the protocol's substring rule. An
absent `Accept`, `*/*`, or an `Accept` without that substring is
non-navigational. Repeated header lines are scanned in received linked-list
order, although the result is only whether any occurrence matches.

## Canonical challenge formatting

`pow_challenge.c` gains one pure formatter. The intended public shape is:

```c
typedef struct {
    size_t  len;
    size_t  difficulty_offset;
    size_t  difficulty_len;
    size_t  bucket_offset;
    size_t  bucket_len;
    size_t  nonce_offset;
    size_t  nonce_len;
} pow_challenge_text_t;

int pow_challenge_serialize(uint8_t difficulty, uint64_t bucket,
    const uint8_t nonce[POW_NONCE_LEN], uint8_t *buf, size_t buf_cap,
    pow_challenge_text_t *out);
```

On success, `buf[0..out->len)` is exactly:

```text
v=1; d=<difficulty>; b=<bucket>; n=<nonce-base64url>
```

The offsets identify the already-formatted difficulty, bucket, and nonce
inside that buffer. The HTML wrapper copies those spans into JSON, so decimal
and base64url encoding exist in exactly one implementation while the header
and JSON retain their distinct wire formats.

The formatter:

- accepts difficulty only in `[1, 32]`;
- accepts every `uint64_t` bucket;
- consumes a raw 32-byte nonce;
- emits canonical unpadded base64url through `pow_b64url_encode()`;
- writes into a caller-provided fixed buffer;
- allocates nothing;
- performs a complete capacity check before writing; and
- leaves `out` unusable on failure.

Protocol constants define the header literals, field separators, nonce text
length, and maximum serialized length once in `src/pow_protocol.h`.

## Response construction invariant

No externally visible challenge response exists until every required piece
has succeeded.

Both branches follow this sequence:

1. derive and format all values;
2. discard the request body through NGINX;
3. allocate every dynamic buffer and reserve every required header slot;
4. initialize each reserved `ngx_table_elt_t` with `hash = 0`;
5. populate body buffers, response metadata, and header values;
6. commit all module headers by filling their fields and setting `hash = 1`;
7. call `ngx_http_send_header(r)`;
8. call `ngx_http_output_filter(r, ...)` only when a body is permitted;
9. call `ngx_http_finalize_request(r, rc)` exactly once; and
10. return `NGX_DONE`.

If a list push fails after earlier slots were reserved, those earlier slots
remain disabled with `hash = 0`. If output fails after headers have begun,
PowGate finalizes the error and never attempts a second response.

## Non-navigation response

The response contract is:

```text
status: 403
Content-Length: 0
PowGate-Challenge: v=1; d=<int>; b=<bucket>; n=<nonce-b64url>
body: empty
```

PowGate sends this response itself instead of returning `403` to the phase
engine. Consequently, core special-response HTML and configured
`error_page 403` handling cannot replace it.

Header-based proof submission remains a v0.2 feature. Phase 3 only publishes
the challenge header.

## Navigation response

The response contract is:

```text
status: 503
Content-Type: text/html; charset=utf-8
Cache-Control: no-store
X-Robots-Tag: noindex
Content-Security-Policy: <fixed PowGate policy with generated script hash>
Content-Length: <exact assembled body length>
```

The module disables ranges and clears or suppresses `Accept-Ranges`, ETag, and
Last-Modified metadata. A `Range` or conditional request cannot turn the
challenge into `206` or `304`.

`HEAD` performs the same challenge derivation and publishes the same status,
headers, and content length as `GET`, but `r->header_only` prevents a body
from reaching the output filter.

Because PowGate sends and finalizes the response, `error_page 503` cannot
replace the challenge page.

## CSP protocol contract

The fixed policy becomes a named protocol template constant with exactly one
`<H>` marker:

```text
default-src 'none'; base-uri 'none'; form-action 'none';
frame-ancestors 'none'; script-src 'sha256-<H>';
style-src 'unsafe-inline'
```

The actual header is a single line with one ASCII space after each semicolon.
The module replaces `<H>` with the 44-byte padded standard-base64 SHA-256
digest emitted by the page build tool. The policy is never assembled from
unrelated literals in multiple files.

The CSP is part of the versioned challenge-page protocol contract. Weakening
or otherwise changing it requires an explicit protocol revision. Inline style
remains allowed in v1; Phase 3 does not add a second style-hashing pipeline.

An operator CSP added with:

```nginx
add_header Content-Security-Policy "..." always;
```

appears as an additional header and intersects with PowGate's policy in the
browser. Without `always`, NGINX does not add it to a `503`. PowGate never
merges, replaces, or weakens an operator policy.

## Challenge page build contract

`html/challenge.html` is UTF-8, contains no BOM or NUL, remains below the
project's 15 KiB page budget, and contains:

- exactly one literal `<!-- POW:PARAMS -->` marker;
- exactly one literal executable `<script>` opening tag;
- exactly one matching `</script>` closing tag; and
- no external script.

The Phase 3 script body is non-empty and inert:

```js
/* PowGate placeholder script v1 */
void 0;
```

It performs no proof work, DOM changes, timer scheduling, network access,
randomness, storage, analytics, or tracking. It exists only to validate the
production extraction, embedding, and CSP-hash pipeline. Phase 4B replaces
the script body without changing the surrounding delivery model.

`tools/build_pow_challenge.py` reads the input and writes the generated header
as bytes. It:

1. validates the file constraints above;
2. rejects zero or multiple parameter markers;
3. rejects zero, multiple, attributed, or case-variant executable script
   opening tags;
4. splits the template at the marker without reserialization;
5. extracts the exact bytes strictly between `<script>` and `</script>`;
6. computes SHA-256 and padded standard base64 over those exact bytes;
7. emits deterministic prefix/suffix arrays, lengths, and digest bytes; and
8. writes this warning at the top:

```c
/*
 * Generated by tools/build_pow_challenge.py.
 * Do not edit manually.
 */
```

The generated header lives under `build/`, is not committed, and is an input
to both normal and sanitized NGINX builds. Running the generator twice over
the same input must produce byte-identical output.

At runtime the body is exactly:

```text
generated prefix
+ <script type="application/json" id="pow-params"> JSON object </script>
+ generated suffix
```

The JSON object is fixed as:

```json
{"v":1,"d":<difficulty>,"b":"<bucket>","n":"<nonce>"}
```

Every inserted span is restricted to ASCII digits or base64url. No inserted
value contains a quote or `<`, so no escaping or serializer is required and
`</script` cannot be introduced.

## Body-discard behavior

PowGate calls `ngx_http_discard_request_body()` before sending headers for
both response branches. It never loops over socket bytes or blocks waiting
for a body itself.

NGINX may consume already buffered bytes immediately or install its normal
asynchronous discarded-body handler and adjust request reference counts.
PowGate then sends the challenge normally. This preserves keepalive and HTTP/2
stream behavior for fixed-length, chunked, and `Expect: 100-continue`
requests.

## Logging and failures

Normal challenge issuance is never logged.

The following failures produce `500` before any PowGate header is committed:

- unsupported connection address family;
- impossible runtime configuration state;
- negative wall-clock time;
- canonical-address conversion or mask failure;
- nonce derivation failure;
- challenge serialization failure; and
- pool or header-list allocation failure.

The unsupported-family diagnostic is equivalent to:

```text
pow_gate: unsupported connection address family <number>, request rejected
```

Other diagnostics identify only a fixed operation and verdict. Logs never
include URI, arguments, request headers, cookies, client-provided bytes,
nonce, MAC, secret, or response body. `pow_log_level` remains unused until
Phase 4 verification failures exist.

## HTTPS integration architecture

Perl remains the NGINX lifecycle owner. The existing
`PowGate::TestNginx` helper continues to own runtime prefixes, port
reservation, fork/exec handshakes, process groups, bounded startup, shutdown,
and cleanup.

A separate narrow test helper owns only HTTPS client operations needed by
Phase 3. It is not a general HTTP framework. Its request surface accepts the
small fixed set of fields used by the matrix: protocol, method, path, request
headers/body, and expected response properties.

Each isolated runtime generates its own test certificate and key under its
prefix through pinned OpenSSL:

- ECDSA P-256 key;
- SHA-256 self-signed certificate;
- SANs for `localhost`, `127.0.0.1`, and `::1`;
- key mode `0600` and certificate mode `0644`;
- no machine trust-store modification; and
- deletion with the runtime prefix.

Certificate generation is test infrastructure. It is the sole sanctioned
exception to the no-randomness principle and never supplies a PowGate secret,
nonce, challenge field, or production input.

The curl wrapper:

- uses safe argument-vector execution with bounded stdout/stderr and time;
- always requests an `https://` URL;
- always disables verification with `--insecure` because the certificate is
  intentionally ephemeral;
- forces `--http1.1` or `--http2`;
- records curl's negotiated `%{http_version}`;
- fails unless it is exactly `1.1` or `2` as requested;
- uses `--path-as-is` for raw normalization tests; and
- supports only the narrow multi-transfer sequence required to prove
  connection reuse.

The server uses `listen ... ssl;` and `http2 on;`. The instrumented NGINX
build adds `--with-http_ssl_module` and `--with-http_v2_module`; otherwise
the sanitizer job would not execute the production TLS/H2 path.

The Node e2e smoke moves from HTTP to HTTPS/HTTP/1.1 and uses
`rejectUnauthorized: false` only in test client code. Node remains reserved
for browser, DOM, script, and future solver behavior.

## Request integration matrix

Every applicable scenario runs once over negotiated HTTPS/HTTP/1.1 and once
over negotiated HTTPS/HTTP/2.

### Delivery and formatting

- `GET` with `Accept: text/html` returns the exact HTML `503`.
- Case variants and a match in a later repeated `Accept` occurrence navigate.
- Absent, wildcard-only, and nonmatching `Accept` values return bare `403`.
- `POST` with `Accept: text/html` remains non-navigational and returns `403`.
- Header and JSON fields are identical spans from the one formatter.
- The header grammar, field order, separators, and lengths are exact.
- The body equals generated prefix, runtime JSON, and generated suffix.
- The CSP digest independently recomputed from served script bytes matches the
  response header.

### Determinism and identity

- A known test secret, observed wall-clock bucket, canonical loopback IP, and
  prefix independently reproduce the server nonce.
- Repeated requests in the same bucket receive the same challenge.
- HTTP/1.1 and HTTP/2 receive the same challenge for the same identity and
  bucket.
- IPv4 uses mapped `ip16` and `96 + pow_bind_ipv4`.
- Native IPv6 uses `pow_bind_ipv6`.
- IPv4-mapped IPv6 is classified as IPv4.
- trusted RealIP rewriting changes the identity before derivation and
  exemption matching.
- Unix-domain TLS requests over both protocols fail closed with `500`.

### Exemptions and URI normalization

- IPv4 and IPv6 CIDR matches decline to the content handler.
- a nonmatching CIDR continues to challenge;
- `/` exempts all supported-family requests;
- `/api` exempts `/api` and `/api/v1`, not `/apiv2`;
- query strings never affect the match;
- `/%73tatic` matches a configured `/static` exemption;
- `/static/../admin` is evaluated as `/admin` and is not exempt;
- raw-path tests use `--path-as-is` so curl cannot normalize first; and
- duplicate-slash behavior is tested with both `merge_slashes on` and `off`.

### Request-body and lifecycle behavior

- fixed-length `POST` bodies are discarded;
- chunked HTTP/1.1 and HTTP/2 data bodies are discarded;
- `Expect: 100-continue` cannot hang the request;
- a second transfer reuses the same TLS connection after a challenged body;
- HTTP/2 proves a second stream succeeds on the same session; and
- teardown leaves no owned NGINX process or TLS fixture.

### NGINX composition

- `HEAD` returns the GET content length with no body;
- `Range` never produces `206`;
- conditional headers never produce `304`;
- SSI subrequests are not challenged;
- internal `error_page` redirects are not challenged;
- `error_page 403` and `error_page 503` cannot replace completed PowGate
  responses;
- exemption returns `NGX_DECLINED`, allowing the normal content handler;
- cookies do not bypass Phase 3; and
- an operator CSP configured with `always` appears as a second intersecting
  CSP, while one without `always` does not appear on `503`.

### Public header surface

Tests normalize response headers into a multimap and enforce an allowlist.
Transport headers generated by NGINX, including `Server`, `Date`, and
`Content-Length`, are allowed. Only response-appropriate protocol headers are
allowed in addition.

Tests reject:

- the known hexadecimal test secret in any header name or value;
- internal or debug headers;
- unknown `PowGate-*` headers;
- duplicate module-owned protocol headers; and
- any non-allowlisted generated header.

The deliberate second CSP in the `add_header ... always` scenario is the only
duplicate-policy exception.

## Build and test gates

Phase 3 extends the existing gates rather than adding placeholders:

- pure-core unit tables cover serializer success, exact offsets, boundary
  lengths, insufficient capacity, invalid difficulty, and null inputs;
- generator tests cover marker/script count failures, attributed/case-variant
  scripts, exact byte preservation, digest correctness, deterministic output,
  page-size/encoding constraints, and generated warning text;
- module builds consume the generated header and fail when it is absent or
  stale;
- normal integration runs the full HTTPS H1/H2 matrix against nginx.org
  NGINX 1.30.3;
- ASan/UBSan integration runs that same matrix against the pinned instrumented
  NGINX 1.30.3 build with SSL and HTTP/2 enabled;
- e2e smoke runs through HTTPS; and
- `make check` remains the completion gate.

No request test may silently skip TLS or HTTP/2 because a dependency or
feature is absent. Missing OpenSSL, curl HTTP/2, SSL module, or HTTP/2 module
support is a test failure in the golden environment.

## Documentation and enduring policy

Implementation updates:

- `docs/protocol.md` for the strengthened versioned CSP and unsupported
  families;
- `PLAN.md` for the corrected formatter, HTTPS matrix, response transaction,
  and Phase 3 boundaries;
- `docs/configuration.md` for runtime exemptions, HTTPS operation,
  `add_header ... always`, CSP intersection, and unsupported listeners;
- `docs/security.md` for fail-closed identity and challenge-response exposure;
- `README.md` for accurate Phase 3 status; and
- `docs/nginx-style.md` only if a response helper convention needs a concrete
  example beyond the enduring rules.

`AGENTS.md` records only long-lived rules:

- request integration uses HTTPS over asserted HTTP/1.1 and HTTP/2;
- self-signed TLS generation and disabled verification are test-only;
- unsupported connection families fail closed;
- response construction is allocate, validate, then commit;
- each request has exactly one terminal outcome;
- CIDR matching uses `ngx_cidr_match()`; and
- new response/finalization APIs require pinned-source precedent inspection.

## Completion criteria

Phase 3 is complete only when:

- all non-exempt protected requests receive the protocol-correct branch;
- every allowed request returns `NGX_DECLINED`;
- every completed challenge is finalized exactly once and returns `NGX_DONE`;
- unsupported address families fail closed without exposing request data;
- challenge values independently reproduce from secret, canonical identity,
  and bucket;
- served template and CSP script bytes match generated artifacts exactly;
- no partial response becomes visible on pre-send failure;
- request bodies do not poison persistent HTTP/1.1 or HTTP/2 connections;
- the response header allowlist remains exact and secret-free;
- every request scenario passes through HTTPS on both asserted protocols;
- the same request categories pass under ASan and UBSan; and
- a clean containerized `make check` succeeds.
