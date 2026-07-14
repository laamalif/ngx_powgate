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

File of 1–2 lines, each exactly 64 lowercase hex chars (32 bytes decoded).
Line 1 = current (signs everything new), line 2 = previous (verify only).
Minimum file permissions: not readable by group/other, else refuse to start.

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
*claimed* bucket, trying current then previous secret.

## Client work

Find ASCII-decimal `counter` (1–16 digits, value ≤ 2^53−1) such that:

```
leading_zero_bits( SHA256( nonce_raw(32) || counter_ascii ) ) >= difficulty
```

`difficulty` ∈ [1, 32], default 17.

## Challenge delivery

Navigational request — `GET`/`HEAD` with `Accept` containing `text/html`
(case-insensitive substring match; an absent `Accept` header is
non-navigational):

```
HTTP/1.1 503 Service Unavailable
Content-Type: text/html; charset=utf-8
Cache-Control: no-store
X-Robots-Tag: noindex
Content-Security-Policy: default-src 'none'; script-src 'sha256-<H>';
                         style-src 'unsafe-inline'
```
Body: challenge parameters in a **non-executable JSON data block**
(`<script type="application/json" id="pow-params">{"v":1,"d":<int>,
"b":"<bucket decimal>","n":"<nonce b64url>"}</script>`) followed by the
static challenge page, whose single executable `<script>` never varies.
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
against the window above, then re-derive the nonce for (connection ip16,
plen, claimed bucket) and check the proof with the current secret first and
the previous secret on failure. This permits a proof mined immediately before
a secret rotation to verify immediately after it.
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
- Value cap: 256 bytes (well above the ~41 chars actual; cap is the parser
  gate). Exactly 3 dot-separated fields; field 1 literal `1`; decoded
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
  configuration channel.

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
   second HMAC with the current secret. Never calculate a third HMAC.
3. `expiry > now`
4. `difficulty(cookie) >= difficulty(config)` — difficulty floor
5. `plen(cookie) >= plen(config)` for the connection's address family —
   binding floor, same rationale as the difficulty floor: tightening
   `pow_bind_*` invalidates cookies bound at the old, wider mask, while a
   cookie bound tighter than the current config always passes
6. Pass → `NGX_DECLINED`. All occurrences failing → treat as absent cookie.

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
