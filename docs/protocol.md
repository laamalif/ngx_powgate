# ngx_powgate — Protocol v1 Specification

STATUS: PROVISIONAL — freezes at v0.1 release (Phase 7)

## Primitives

- Hash: SHA-256. MAC: HMAC-SHA-256 via OpenSSL's one-shot `HMAC()` —
  decided; `EVP_MAC` is not used (no added value here, more surface).
- Encoding: base64url, **no padding**, alphabet `A–Z a–z 0–9 - _` only.
  Unused bits in the final character must be zero; decoders reject alternate,
  non-canonical encodings of the same bytes.
- Integers on the wire inside MAC inputs: fixed-width big-endian binary.
- Integers in cookie/JS-visible fields: ASCII decimal, no sign, no
  leading zeros — grammar `"0" | [1-9][0-9]*`, within each field's stated
  length cap.
- Domain labels `"PGv1-chal"` / `"PGv1-cook"` are 9-byte ASCII strings;
  a terminating NUL is never part of any MAC input.
- All comparisons of MACs/digests: constant time. Parsing is *not*
  constant-time and must not be made so — cookie contents are not secret,
  only the MAC verdict is, and CT parsing buys nothing.

## Secret

The file contains one or two lines, each exactly 64 bytes of ASCII
hexadecimal (32 bytes decoded). Hexadecimal digits are case-insensitive and
may be mixed case. Let `HEX64` denote one such 64-byte sequence. Exactly these
four byte layouts are accepted:

```
HEX64
HEX64 LF
HEX64 LF HEX64
HEX64 LF HEX64 LF
```

`LF` is the single byte `0x0A`. CRLF, other whitespace, byte-order marks,
blank lines, and any extra bytes are rejected.

Line 1 is the current secret: it derives every new challenge nonce and signs
every new authentication cookie. Line 2, when present, is the previous secret
and is verification-only. Both secrets are accepted when verifying
authentication cookies and submitted proofs.

The opened target may have no group or other permission bits
(`mode & 0077 == 0`). Ownership and owner permission bits are unrestricted.
The configured path is opened following symlinks; validation is performed
through the resulting file descriptor against the opened target.

## Canonical IP (ip16, plen)

- IPv6 address → its 16 bytes; `plen` = configured `pow_bind_ipv6`
  (default 56).
- IPv4 address `a.b.c.d` → IPv4-mapped IPv6
  `00…00 FF FF a b c d` (bytes 0–9 zero, 10–11 = 0xFF); `plen` = 96 +
  configured `pow_bind_ipv4` (default 96+32 = 128).
- `ip16` is masked to `plen` bits before any use: bits beyond `plen` are
  zero. Masking is byte-wise: full bytes zeroed, boundary byte ANDed with
  `0xFF << (8 - (plen % 8))`.

## Time bucket

`bucket = floor(unix_time / window)` with `window` =
`pow_challenge_window` (default 60 s), as uint64. `window` is a positive
integer number of seconds; zero is a configuration error, refused at
config validation (it is a divisor).
Time source is **wall-clock Unix time** (`ngx_time()`), never a monotonic
clock — buckets must agree across worker restarts, reloads, and unrelated
machines sharing a secret. Do not "improve" this later.
For each enabled, supported, non-exempt request, the server samples `now`
exactly once. Bucket calculation, bucket-window checks, auth-cookie expiry,
issued expiry, and any fallback challenge generation for that request use
that one value.
Acceptance at verification time: `bucket ∈ {current, current−1, current+1}`
(one bucket of clock skew in each direction; nothing else). The comparison is
evaluated in uint64 using an ordered difference:
`claimed <= current ? current - claimed <= 1 : claimed - current <= 1`.
Never evaluate it via bare `current - 1` or `current + 1`; this makes the
rule total even at uint64 extremes.

## Challenge nonce (derived, never stored)

```
nonce = HMAC(secret_current,
             "PGv1-chal" || ip16(16) || plen(1) || bucket(8, BE))
```
32 bytes. Sent to the client base64url-encoded (43 chars).
Verification re-derives with the client's *connection* ip16/plen and the
*claimed* bucket, trying the current secret first and the previous secret
only when configured and the current-secret proof check is invalid. An
internal derivation or proof-check error stops verification immediately; it
never triggers previous-secret fallback. New challenges and auth cookies are
always produced with the current secret.

## Client work

Find ASCII-decimal `counter` (1–16 digits, value ≤ 2^53−1) such that:

```
leading_zero_bits( SHA256( nonce_raw(32) || counter_ascii ) ) >= difficulty
```

`difficulty` ∈ [1, 32], default 20. Operators are advised to use 20–22
unless deployment measurements justify another value.

## Challenge delivery

Navigational request — `GET`/`HEAD` with `Accept` containing `text/html`
(case-insensitive substring match; an absent `Accept` header is
non-navigational). Repeated `Accept` fields are scanned in received order;
the request is navigational when any field contains the substring:

```
HTTP/1.1 503 Service Unavailable
Content-Type: text/html; charset=utf-8
Cache-Control: no-store
X-Robots-Tag: noindex
Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; script-src 'sha256-<H>'; style-src 'unsafe-inline'
```
The CSP is a versioned PowGate protocol constant. `<H>` is replaced by the
44-byte padded standard-base64 SHA-256 digest of the exact executable script
body. Any policy change requires an explicit protocol revision.

Body: challenge parameters inserted at the template marker as a
**non-executable JSON data block**
(`<script type="application/json" id="pow-params">{"v":1,"d":<int>,
"b":"<bucket decimal>","n":"<nonce b64url>"}</script>`). Every other byte
comes from the static challenge page, whose single executable `<script>`
never varies.
Every value inserted into the JSON block matches `[0-9A-Za-z_-]+` — no
quotes, no `<` — so `</script` can never appear inside the block and no
escaping is applied; any future field must preserve this property or the
block format changes with the version. CSP data blocks are not executable
scripts, so the solver script's SHA-256 hash `<H>` — the base64 encoding
of the digest of the exact script bytes as embedded, whitespace included —
is computed once at build time and served in ngx_powgate's own CSP.
Operators running strict site-wide CSP via `add_header` should know
policies intersect (all must pass); the published hash lets them allowlist
the solver explicitly. This is documented, not worked around.

Non-navigational request:

```
HTTP/1.1 403 Forbidden
Content-Length: 0
PowGate-Challenge: v=1; d=<int>; b=<bucket>; n=<nonce b64url>
```
(Header emitted in v0.1; header-based proof acceptance is v0.2.)
Header serialization is fixed: exactly these four keys, in this order,
separated by `"; "` (semicolon, one space); duplicate keys never occur.

PowGate v1 derives client identity only from IPv4 and IPv6 connection
addresses after RealIP processing. Requests on any other address family are
rejected with `500`; they are never treated as exempt and no synthetic
address is used.

## Cookie request-field extraction

Cookie names are matched byte-for-byte and case-sensitively within
semicolon-delimited segments. A segment begins at the field start or just
after `;`; empty segments are permitted and ignored. The scanner skips only
SP (`0x20`) and HTAB (`0x09`) before a pair, then requires the exact name
immediately followed by `=`. Its value is every byte after `=` up to, but not
including, the next `;` or field end. It performs no trimming, quoting,
escaping, decoding, or NUL-terminated operation. Malformed and unrelated
segments are skipped.

Consequently, `__pow=` is an occurrence with an empty value, `__pow= abc`
has a value beginning with SP, and `__pow =abc`, `__pow_extra=abc`, and
`__POW=abc` are not `__pow` occurrences. Oversized, empty, and malformed
exact-name values still count toward occurrence limits.

All received Cookie fields are processed in request order and each field is
scanned left-to-right. NGINX's HTTP/2 Cookie reconstruction preserves the
effective receipt order used by the module. Auth extraction and proof
extraction are independent: the first four exact configured auth-name
occurrences are tried in order; auth success stops all scanning; otherwise a
fresh scan selects only the first exact `__pow_p` occurrence. No later proof
occurrence is evaluated, even if the first is oversized, malformed, or
invalid. The auth-occurrence bound cannot prevent this independent proof
scan.

## Proof submission — proof cookie `__pow_p`

The solver sets a short-lived cookie and reloads. The challenge page is
only ever served on `GET`/`HEAD` navigations (above), so the reload
re-issues the same `GET` — path and query preserved by the browser, no
redirect endpoint, no open-redirect surface. Non-idempotent browser
requests (e.g. a form POST from a cookieless browser) receive the bare
403 and are **not transparently completed in v0.1** — a documented
limitation, addressed by the v0.2 header-based flow; the v0.1 operator
remedy is exempting such endpoints.

Cookie format:

```
__pow_p = 1.<bucket decimal>.<counter decimal>
```
Value cap: 64 bytes. Exactly 3 dot-separated fields. Field 1 must be the
literal `1`. Bucket 1–20 digits; counter 1–16 digits, ≤ 2^53−1.
If the Cookie header carries multiple `__pow_p` occurrences, only the
first is considered — a proof either verifies or the client re-solves;
iterating occurrences (unlike for `__pow`, where stale path-scoped
cookies persist) buys nothing and adds attacker-controlled work.

Server on seeing `__pow_p` (and no valid `__pow`): check the claimed bucket
against the window above before any secret-dependent operation, then
re-derive the nonce for (connection ip16, plen, claimed bucket) and check the
proof with the current secret first. Only an invalid check falls back to the
previous secret when configured. An internal error returns `500` without
fallback. This permits a proof mined immediately before a secret rotation to
verify immediately after it.

Proof verification always uses the request's current effective difficulty
and address-binding prefix. A proof satisfying the current difficulty is
accepted regardless of the difficulty in effect when its challenge was
issued. No previous difficulty, prefix, or other configuration history is
considered; a reload may invalidate an in-flight proof.

Valid → issue auth cookie + expire `__pow_p` (both `Set-Cookie` on the same
response) and let the request through. Invalid → normal challenge flow.

**Replay note (accepted by design):** a (bucket, counter) pair replays only
from the same masked IP within ≤ 2 windows, and yields only a cookie that
IP had already earned. No state is spent preventing this.

**Determinism note (intentional, reviewers will ask):** the same masked IP
in the same bucket always receives the same nonce. There is no per-request
randomness anywhere in the protocol. A page refresh mid-solve serves the
identical challenge, so already-computed work is not wasted — a feature,
not a leak: nonce unpredictability holds against anyone without the secret,
which is the only property the design needs.

## Auth cookie `__pow`

```
value   = "1" "." b64url(payload) "." b64url(mac)
payload = expiry(8, BE unix seconds) || difficulty(1) || plen(1)     (10 bytes)
mac     = HMAC(secret, "PGv1-cook" || payload || ip16(16))[0..15]    (16 bytes)
```
- MAC truncated to 16 bytes (128-bit). Frozen. Rationale, for future
  reviewers who will ask: forging requires ~2^128 online attempts against
  a cookie whose value expires in ≤ TTL; HMAC-SHA-256 truncation is
  explicitly sanctioned (RFC 2104 §5) and 128 bits is beyond any online
  budget by dozens of orders of magnitude. The 16 saved bytes shrink every
  request's Cookie header.
- `ip16` is bound inside the MAC but **not stored** in the cookie; it is
  taken from the live connection at verification and masked with the
  cookie's `plen`.
- Value cap: 256 bytes (well above the exact 39-byte v1 value; cap is the
  parser gate). Its fixed length is
  `"1." + b64url(payload 10 bytes) + "." + b64url(mac 16 bytes)` =
  `2 + 14 + 1 + 22` = 39 bytes. Exactly 3 dot-separated fields; field 1
  literal `1`; decoded
  payload exactly 10 bytes; decoded mac exactly 16 bytes. Payload sanity
  bounds, checked at parse before any use: difficulty ∈ [1, 32],
  plen ∈ [32, 128]. plen especially: it masks the connection address
  *before* the MAC verdict exists, so it is attacker-controlled at the
  moment it is used and must be bounded first.
- Attributes: `Max-Age=<ttl>; Path=/; Secure; HttpOnly; SameSite=Lax`.
  No `Domain` attribute — the cookie is host-only by design.
- `Secure` is emitted unless `pow_cookie_secure off` is explicitly
  configured. This non-default setting is for development and test
  environments only. Cookie security must never be inferred from the request
  scheme.
- `__pow` is the default name and is renameable per deployment with
  `pow_cookie_name`; the name is not a MAC input. The proof-cookie name
  `__pow_p` is fixed by this protocol: the solver sets it and it has no
  configuration channel. The exact name `__pow_p` is reserved and cannot be
  configured as the auth-cookie name. Matching is case-sensitive; other
  names remain subject to the normal cookie-token grammar and any explicitly
  reserved protocol names.

## Auth cookie verification order

If the Cookie header carries multiple occurrences of the auth cookie name
(path-scoped duplicates, stale cookies from earlier deployments — browsers
send the most-specific-path cookie first), occurrences are tried **in
order until one verifies**, bounded to the first 4 — an occurrence after
the fourth is never tried, even if it would verify. Without this, one
stale shadowing cookie at `Path=/app` would cause a permanent challenge
loop for that subtree, since a fresh solve sets `Path=/` and never
displaces it. Occurrence order is request order: Cookie header lines in the
order received, scanned left to right within each line. This also selects the
first `__pow_p` occurrence. Per occurrence:

1. Length ≤ 256, strict parse (field count, literals, decoded lengths,
   payload sanity bounds)
2. MAC with the current secret; on failure, always calculate one second HMAC.
   Use the previous secret when configured; otherwise calculate and discard a
   second HMAC with the current secret. A successful current-secret MAC does
   not evaluate the previous secret. Never calculate a third HMAC.
3. `expiry > now`
4. `difficulty(cookie) >= difficulty(config)` — difficulty floor
5. `plen(cookie) >= plen(config)` for the connection's address family —
   binding floor, same rationale as the difficulty floor: tightening
   `pow_bind_*` invalidates cookies bound at the old, wider mask, while a
   cookie bound tighter than the current config always passes
6. Pass → `NGX_DECLINED`. All occurrences failing → treat as absent cookie.

Configuration changes are not protocol events. Proofs use current policy,
while auth cookies are self-describing and remain valid only while their
signed difficulty and prefix satisfy the current policy floors.

## Verification outcomes and cookie issuance

A well-formed verification attempt that fails its MAC, proof-of-work, expiry,
bucket, or current policy is client-invalid and follows the normal challenge
flow. A cryptographic-provider failure, impossible arithmetic, invalid
internal argument, allocation failure, or construction invariant failure is
an internal error and returns `500`; it is never treated as client invalid.

After a valid proof, issued expiry is the checked uint64 operation
`expiry = now + pow_cookie_ttl`. Overflow returns `500`; wrapping and
saturation are forbidden. Before NGINX serialization the module constructs
exactly these two Set-Cookie fields, in this construction order:

```
Set-Cookie: <configured-name>=<39-byte-auth-value>; Max-Age=<ttl>; Path=/; Secure; HttpOnly; SameSite=Lax
Set-Cookie: __pow_p=; Max-Age=0; Path=/
```

`pow_cookie_secure off` omits only `; Secure` from the auth field. `Max-Age`
is canonical unsigned decimal seconds. Neither field contains `Domain` or
`Expires`; the proof-clear path is always `/` and is not configurable. The
construction order does not promise application-visible ordering after
transport serialization.

Both fields are committed transactionally. If arithmetic, construction,
allocation, or reservation fails, no PowGate Set-Cookie field is visible,
the protected content is not reached, and the request returns `500`.

## Version field

The leading literal `1` in both cookies and `v=1` in challenges names this
protocol. Any change to labels, widths, hash, MAC truncation, or masking
rules requires bumping it. HTTP header names (`PowGate-Challenge`, and
v0.2's `PowGate-Proof`) are deliberately implementation-neutral — a port
to another server keeps them — and are part of the protocol surface,
versioned alongside the cookie formats: renaming a header is a breaking
wire change. Version 1 reserves no other extension points — future
memory-hard PoW may arrive as version 2 (for example, Argon2id),
negotiated by the server simply issuing v2 challenges.
