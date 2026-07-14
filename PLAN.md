# ngx_powgate — Codex Execution Plan

How to use: place `AGENTS.md` at the repo root, then feed Codex one
phase at a time ("implement Phase 1 of PLAN.md"). Every phase ends with a
**Gate** — concrete commands that must pass before starting the next phase.
Do not parallelize phases; each builds on frozen output of the previous one.

Total scope: v0.1 MVP as defined in README.md. Estimated final size:
1500–2500 lines of C, ~200 lines of challenge-page JS, ~600 lines of tests.

## Required execution environment

Every compilation, build, test, fuzz, sanitizer, and integration command in
this plan runs inside the project-managed Podman golden image. The host only
builds or invokes that container and inspects its artifacts; it never installs
project dependencies or runs a bare `make` target.

Phase 0 establishes this canonical form (substitute the requested make target):

```
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie make <target>
```

Accordingly, every later Gate that says `make <target>` means this Podman
invocation, never host execution. CI builds the same image from the committed
Containerfile and runs all jobs inside it; workflows must not install build or
test dependencies independently.

---

## Phase 0 — Repository scaffold & build system

**Goal:** an empty module that compiles, loads into NGINX, and does nothing,
with all test plumbing runnable.

Tasks:

1. Create the repo layout:
   ```
   ngx_powgate/
   ├── src/            (empty .c/.h stubs created in later phases)
   ├── html/
   ├── tests/unit/  tests/fuzz/  tests/integration/  tests/e2e/
   ├── build/        (committed version/checksum lock files)
   ├── docs/
   ├── Containerfile    (Debian Trixie golden development image)
   ├── config          (NGINX dynamic-module build script)
   ├── AGENTS.md  README.md  PLAN.md  LICENSE  Makefile
   ```
2. Write `config` using the modern module form (`ngx_module_type=HTTP`,
   `. auto/module`) — not legacy `HTTP_MODULES=`.
3. `Makefile` exposes targets exactly as named in AGENTS.md when their real
   work exists. Phase 0 implements `check-policy`, `module`,
   `test-integration`, and `test-e2e`; the pure-core targets (`test-unit`,
   `test-fuzz`, `test-fuzz-long`, `asan`, and aggregate `check`) arrive in
   Phase 1 with useful work, never passing placeholders. Before the first image
   build is accepted, a committed `build/versions.env` records the immutable
   Debian base-image digest and repository snapshot, nginx.org package
   version/checksum, `NGX_VERSION`, and `NGX_SOURCE_SHA256`; the official
   source archive's PGP signature is also verified when that digest is
   recorded. Both the Makefile and
   Containerfile consume this lock. The Containerfile verifies the official
   NGINX 1.30.3 source archive and exposes its extracted reference tree as
   `NGX_SOURCE_DIR`. The cache is environment-owned and is never committed.
   `make module` creates a disposable build tree from that verified source,
   runs
   `./configure --with-compat --add-dynamic-module=../..`, builds the `.so`.
   Compiler flags are whatever nginx's `auto/cc` selects (includes
   `-Werror`); hardening flags (`-D_FORTIFY_SOURCE=2`,
   `-fstack-protector-strong`) are passed via `--with-cc-opt`. Do not
   inject `-Wconversion` or `-Wextra` — the module must compile clean
   inside an unmodified nginx build.
4. Create the reproducible Debian Trixie `Containerfile` for the golden
   `localhost/ngx-powgate-dev:trixie` image. It installs every normal-development and
   CI dependency: gcc and clang, make/build utilities, OpenSSL headers, nginx
   build dependencies, Perl/Test::Nginx, Node.js, LLVM/libFuzzer,
   ASan/UBSan runtimes, debugging tools, and the nginx.org 1.30.3 stable
   runtime package. It also provides the checksum-verified 1.30.3 NGINX
   source reference at `NGX_SOURCE_DIR`; no build may fetch or use an
   unverified source tree. The Debian base/repository snapshot and every
   nginx.org package input are locked to `build/versions.env`. Build it only
   with Podman:
   `podman build -t localhost/ngx-powgate-dev:trixie -f Containerfile .`.
   Missing dependencies require a Containerfile change and image rebuild;
   they are never installed ad hoc on the host or in a running container.
5. Verify `docs/nginx-style.md` is in place (pre-created). It is the
   style authority for all C in the project. Likewise verify
   `tools/check-policy.sh` (pre-created, self-tested): wire it as
   `make check-policy` and a Phase 0 CI step; make it a dependency of
   `make check` when that target is introduced in Phase 1 —
   every line of C in this project is born under that gate.
6. Minimal `src/ngx_http_pow_module.c`: module boilerplate written
   strictly to `docs/nginx-style.md` (this first file sets the pattern
   every later file imitates), an empty location conf with a single
   `pow on|off` flag via `ngx_conf_set_flag_slot`, postconfiguration
   that registers an access-phase handler which immediately returns
   `NGX_DECLINED`.
7. Create (or verify) `docs/protocol.md` by copying the **Protocol v1
   Specification**
   section at the bottom of this plan, verbatim, with one added header
   line: `STATUS: PROVISIONAL — freezes at v0.1 release (Phase 7)`. It is
   the single source of truth from this moment on, but not yet frozen:
   implementation (especially Phases 1 and 4A) may surface edge cases.
   The change discipline is spec-first — any change lands in protocol.md
   in its own commit before the code changes, and after the Phase 4A gate
   the bar for changes rises to "implementation is impossible otherwise."
8. Create `src/pow_protocol.h` defining every protocol constant from the
   spec: labels `"PGv1-chal"` / `"PGv1-cook"`, field widths, caps, cookie
   names, defaults. Constants use the `POW_*` prefix (pure-core side);
   module-only constants live in the module file as `NGX_HTTP_POW_*`.
9. Integration harness: `tests/integration/` using Test::Nginx
   (perl `nginx-tests` style) with one test: module loads, `pow on`,
   request passes through to a stub backend.
10. Bootstrap `tests/e2e/` and `make test-e2e` in this phase with a real
   Node HTTP smoke test against the containerized nginx fixture: with `pow
   on`, a request passes through and receives the backend's 200 response.
   This target is never skipped or a no-op. Phase 4C extends the same test
   target with the served solver and cookie loop.
11. Create `README.md` as the normative v0.1 scope statement referenced by
   this plan. It records the one-job stateless design, OpenSSL 3.x support,
   Podman-only development requirement, quickstart prerequisites, and the
   documented JavaScript/SEO/non-idempotent-request limitations. Later docs
   and release wording must cite this checked-in text, not an assumed README.
12. CI is deferred until the project has its complete test surface. The
   initial skeleton has no GitHub workflow. When CI is introduced after the
   Phase 1 pure core, it builds the committed
   `localhost/ngx-powgate-dev:trixie` image and runs all project commands
   inside it; no CI job installs project dependencies outside the image. Use
   the compiler/runtime matrix and the `make test-unit`, `make asan`
   (ASan+UBSan), and `make test-fuzz` (60s smoke; clang, since libFuzzer
   requires it) jobs then. OpenSSL: 3.x only — 1.1 is EOL and explicitly
   unsupported; state this in the README.

**Gate:**
```
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie make module
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie make test-integration
```
passes inside the golden image; its nginx.org 1.30.3 runtime accepts a config
with `pow on;`.

---

## Phase 1 — Pure core: crypto, parsing, protocol (no NGINX)

**Goal:** every security-critical byte operation exists as a pure, fuzzed,
table-tested function before any of it touches NGINX.

Files: `src/pow_crypto.c/.h`, `src/pow_parse.c/.h`,
`src/pow_challenge.c/.h`, `src/pow_cookie.c/.h` — all NGINX-free per
AGENTS.md's pure-core rule, enforced by `tools/check-policy.sh`.
`pow_parse` holds the shared low-level helpers both
parsers need — split-on-dot with exact field count, bounded ASCII-decimal
parser, strict b64url field decoder — so cookie and proof parsing never
duplicate them and the fuzzers exercise one implementation.

Tasks:

1. `pow_crypto`:
   - `pow_hmac_sha256(key, keylen, msg, msglen, out32)` — thin OpenSSL
     one-shot `HMAC()` wrapper.
   - `pow_ct_eq(a, b, len)` — wraps `CRYPTO_memcmp`, returns 1/0.
   - `pow_leading_zero_bits(digest32)` — bit count on raw bytes.
2. `pow_parse`:
   - `pow_split_dot_fields(...)`, canonical bounded `pow_parse_u64(...)`, and
     strict base64url encode/decode. Decoding rejects padding, wrong lengths,
     foreign characters, and non-zero unused tail bits.
3. `pow_challenge`:
   - `pow_ip16_from_ipv4(ipv4, out)`, `pow_ip16_from_ipv6(ipv6, out)`, and
     `pow_ip16_mask(ip16, plen)` use only byte arrays; masking rejects plen
     above 128.
   - `pow_bucket_within_skew(claimed, current)` uses the ordered-difference
     rule from protocol.md and is total at both uint64 extremes.
   - `pow_challenge_derive(secret, ip16, plen, bucket, nonce_out32)` —
     builds the exact `"PGv1-chal"` message per protocol.md.
   - `pow_proof_check(nonce32, counter_ascii, counter_len, difficulty)` —
     SHA256(nonce || counter), leading-zero-bits comparison.
   - `pow_proof_cookie_parse(buf, len, out)` — parses `__pow_p` value:
     strict 3-field decimal format, caps per spec.
4. `pow_cookie`:
   - `pow_cookie_build(secret, expiry, difficulty, plen, ip16, buf, buflen)`
     → writes the full `__pow` value, returns length.
   - `pow_cookie_parse(buf, len, out)` — strict parse only (no MAC check;
     MAC check is a separate step so the parser stays byte-pure).
   - `pow_cookie_verify(secret, secret2_or_null, parsed, ip16, now,
     min_difficulty, min_plen)` —
     MAC (after current failure, previous or a discarded current-secret dummy
     HMAC is always evaluated exactly once), expiry,
     difficulty and plen floors (config values passed by the caller),
     per protocol.md §Verification.
5. Reference solver `tools/refsolve.py`: given
   (secret, ip, plen, bucket, difficulty), independently derives the nonce
   and mines a counter using only Python stdlib hashlib/hmac — written
   from `docs/protocol.md` alone, deliberately without looking at the C.
   It is an executable second opinion on the spec, and any disagreement
   with the C found here or later is resolved in the doc first, code
   second.
6. Canonical end-to-end test vector, initially generated by `refsolve` at
   difficulty 8 and checked in as `tests/vectors/v1.json`: fixed secret, IP,
   plen, bucket → expected nonce (hex) → mined counter → proof digest (hex) →
   exact auth-cookie string. Consumed by the C unit tests now, by the JS
   solver unit test in Phase 4B. It is a versioned protocol artifact: normal
   builds and tests never regenerate it. A deterministic test-build converter
   emits a C header under `build/` from the JSON only and performs no crypto.
7. Unit tests (table-driven) in `tests/unit/`:
   - The canonical vector reproduced end-to-end: derive → check proof →
     build cookie → byte-exact match with `v1.json`.
   - Leading-zero-bit vectors at difficulty 0,1,7,8,9,16,17,24,32.
   - Known-answer HMAC vectors (compute once with `openssl dgst`, embed).
   - IPv6 /56 and /64 masking tables; IPv4-mapped /24 and /32 tables.
   - Round-trip cookie build→parse→verify; every single-byte tamper of a
     valid cookie fails verify.
   - Time-bucket edges: current, previous, +1 future (accepted per skew
     rule), +2 future and −2 past rejected; include current 0, 1, and
     `UINT64_MAX` to prove the ordered-difference comparison never wraps.
   - b64url: padding chars rejected, `+`/`/` rejected, wrong decoded lengths
     and non-canonical tail bits rejected; encode/decode round trips cover
     representative binary inputs including zero bytes and bytes 0–255.
8. Fuzz harnesses in `tests/fuzz/` (libFuzzer + ASan/UBSan, clang):
   - `fuzz_cookie.c` → `pow_cookie_parse` (+ verify with a fixed secret).
   - `fuzz_proof.c` → `pow_proof_cookie_parse`.
   - Seed corpora: one valid input plus the malformed set from the
     implementation checklist §6. Harnesses allocate nothing proportional to
     fuzzer input. Every parser rule or bug fix adds a regression table row and
     matching corpus seed.

**Gate:**
```
make test-unit && make test-fuzz-long && make asan
```
Each fuzzer runs 10 minutes clean under ASan; unit tests 100% pass. Parser unit
tests execute every conditional branch in every parser; `gcov` verifies this
requirement rather than substituting for behavioral assertions.

---

## Phase 2 — Module configuration & secret handling

**Goal:** all directives parse, merge, validate; secret loads with rotation
support. Handler still allows everything.

Tasks:

1. Directives in `src/pow_config.c`, using the standard slot handlers
   wherever one exists (custom handlers only for CIDR lists and the secret
   file, per the style guide):
   `pow on|off;` (flag slot)
   `pow_difficulty N;` (num slot + post validation 1–32, default 17)
   `pow_challenge_window Ns;` (sec slot, default 60s)
   `pow_cookie_name token;` (str slot + RFC 6265 token validation,
   length ≤ 64; additionally reject a leading `$` — a valid token char,
   but a legacy RFC 2109 attribute prefix)
   `pow_cookie_ttl time;` (sec slot, default 1h)
   `pow_cookie_secure on|off;` (flag slot, default on; `off` is for
   plain-HTTP development only)
   `pow_secret_file path;` (custom handler, `NGX_HTTP_MAIN_CONF` only —
   `NGX_HTTP_MAIN_CONF_OFFSET`; one secret pair per instance, stored in main
   conf from `cf->pool`; a second directive returns "is duplicate")
   `pow_bind_ipv4 N;` (num slot, 8–32, default 32)
   `pow_bind_ipv6 N;` (num slot, 32–128, default 56)
   `pow_exempt_ip CIDR;` (custom handler, repeatable, `ngx_ptocidr`)
   `pow_exempt_path prefix;` (custom handler, repeatable)
   `pow_log_level info|notice|warn|error;` (enum slot, modeled
   directly on `limit_req_log_level` — same values, same mechanism)
2. `create_main_conf` creates `ngx_http_pow_main_conf_t` containing
   `u_char secret[32]`, `u_char secret_prev[32]`, `ngx_flag_t has_prev`, and
   `ngx_flag_t secret_set` (all-zero secrets are valid, so presence needs its
   own flag). `init_main_conf` rejects an absent `pow_secret_file`; main conf
   has no merge function.
   `create_loc_conf`/`merge_loc_conf` use `NGX_CONF_UNSET*` sentinels and
   the matching `ngx_conf_merge_*` calls; cross-field validation (window
   vs TTL, difficulty range) after merge, errors via
   `ngx_conf_log_error(NGX_LOG_EMERG, ...)`. Inheritance from `http{}` →
   `server{}` → `location{}`.
3. Config-time validation failing `nginx -t`: absent or duplicate
   `pow_secret_file`, cookie TTL < challenge window, zero challenge window,
   difficulty out of range, missing/short/world-readable secret file, secret
   file with >2 lines or non-hex content. The file is opened following
   symlinks, then `fstat()` is applied to the opened descriptor: it must be a
   regular file and have no group/other read bits. Symlink targets are allowed;
   owner is intentionally not constrained.
4. Secret loading at config parse (master, pre-fork): file format is 1–2
   lines of 64 lowercase hex chars each (32 bytes decoded); line 1 =
   current, line 2 = previous. Stored in main conf allocated from `cf->pool`
   (cycle lifetime). The temporary
   hex-decode buffer is wiped (`ngx_explicit_memzero`/`OPENSSL_cleanse`)
   after copying; old-cycle secrets are released with the cycle and no
   further zeroization is attempted, because nginx pools do not guarantee
   it — stated in `docs/security.md` so reviewers don't rediscover it.
5. Integration tests: inheritance matrix (global on, location off; global
   difficulty, location override), every invalid config rejected by
   `nginx -t` with a clear error message. Cover a duplicate secret directive,
   an allowed symlink to a regular secret, and rejected directory, FIFO, and
   group-readable targets.

**Gate:** `make check` passes; a reload after editing the secret file picks
up the new secret (integration test proves old-cookie validity via dual
secrets — stubbed at handler level for now, fully exercised in Phase 4).

---

## Phase 3 — Challenge issuance path

**Goal:** requests without a valid cookie receive the correct response:
HTML challenge for navigations, bare 403 otherwise. No verification yet.

Tasks:

1. Access handler (`ngx_http_pow_module.c`) real skeleton:
   - Bail `NGX_DECLINED` if: module off, `r != r->main`, `r->internal`,
     exempt path, exempt CIDR
     (`r->connection->sockaddr`, post-realip).
     Matching uses nginx's normalized, percent-decoded `r->uri`; `r->args` is
     never considered. An exempt path must start with `/` and may not end in
     `/` except `/`. It matches `/` universally; otherwise it matches only an
     exact URI or a URI beginning with `path + "/"` (so `/api` never exempts
     `/apiv2`). Consequently `/static/../admin` is evaluated as `/admin`,
     while `/%73tatic` is evaluated as `/static`.
   - Extract canonical ip16 + prefix_len from sockaddr (AF_INET →
     IPv4-mapped, AF_INET6 direct), mask per config.
2. Navigation detection: `GET`/`HEAD` **and** `Accept` header contains
   `text/html` (case-insensitive scan; absent header = non-navigation).
3. Both challenge branches emit parameters through **one** pure helper —
   `pow_challenge_serialize(diff, bucket, nonce, buf)` producing the
   canonical `v=1; d=<diff>; b=<bucket>; n=<nonce_b64u>` field string. The
   403 header and the HTML preamble are thin wrappers around it; no field
   format string exists twice in the codebase. (The JS parser is the one
   unavoidable second implementation; the Phase 4 e2e test is what pins it
   to the C side.)
4. Non-navigation branch: `ngx_http_discard_request_body`, respond `403`,
   `Content-Length: 0`, header
   `PowGate-Challenge: <serialized fields>`,
   finalize, return `NGX_DONE`.
5. Navigation branch: derive challenge via `pow_challenge_derive`, emit
   `503` with `Cache-Control: no-store`, `X-Robots-Tag: noindex`,
   `Content-Type: text/html; charset=utf-8`, and ngx_powgate's own
   `Content-Security-Policy` per protocol.md. `html/challenge.html` contains
   exactly one `<!-- POW:PARAMS -->` marker. The build tool rejects zero or
   multiple markers, splits the file into immutable prefix/suffix byte arrays,
   and extracts the contents of its one executable script. At runtime the
   body is `prefix || generated JSON data block || suffix`; no other template
   substitution exists. The CSP hash is the SHA-256 of exactly the extracted
   script bytes (without `<script>` tags), computed by that same build tool
   and emitted as a generated C constant. Tests compare served body and CSP
   hash with the generated artifacts.
   `r->allow_ranges = 0`, no etag/last-modified. Pattern A from the
   implementation checklist (send_header → output_filter → finalize →
   `NGX_DONE`). Document in `configuration.md`: operator `add_header`
   CSP applies to module responses too and policies intersect — publish
   the solver hash so strict-CSP sites can allowlist it.
6. Embed `html/challenge.html` at build time (Makefile step converts it to
   a static `u_char` array header via a script checked into `tools/`).
   This follows nginx's own precedent — built-in error pages are embedded
   byte arrays in `ngx_http_special_response.c`. Placeholder page for now:
   static text and the required unique marker, no solver yet. (Operator
   customization of the page is
   deliberately deferred: the nginx-idiomatic route is exposing challenge
   params as `$pow_*` variables usable from a custom `error_page`
   location — that is the v0.2 "NGINX variables" feature. Do not invent a
   template mechanism in v0.1.)
7. Integration tests: no cookie + browser Accept → 503 with exact headers
   and preamble fields present; curl (no Accept: text/html) → 403 with
   challenge header; POST with body → 403, connection reusable afterwards
   (body discarded); exempt `/api` → 200 while `/apiv2` challenges; query
   strings do not affect exemption; normalized `/static/../admin` is not
   exempt while `/%73tatic` is; exempt path/CIDR → 200; HEAD → 503 headers, empty
   body; subrequest via SSI does not challenge; `error_page` hop does not
   challenge; H2 equivalents of all of the above.

**Gate:** `make check` green including all new integration tests, run over
HTTP/1.1 and HTTP/2. ASan job green.

---

## Phase 4A — Server-side verification path

**Goal:** the full server loop verified end-to-end using a *reference
solver script* — no browser JS yet. This deliberately proves the C side
against an independent implementation first.

Tasks:

1. `tools/refsolve.py` (from Phase 1) drives all integration tests in this
   phase: proofs and cookies the C code did not produce, exercised against
   the C code.
2. Handler order (final):
   Secrets come from `ngx_http_get_module_main_conf(r, ngx_http_pow_module)`;
   location conf supplies every other policy value.
   a. Parse `__pow` auth cookie if present (post-1.23 cookie API) →
      `pow_cookie_parse` + `pow_cookie_verify` (dual secret, expiry,
      difficulty floor vs current config, MAC over connection ip16) →
      valid: `NGX_DECLINED`.
   b. Else parse `__pow_p` proof cookie if present →
      `pow_proof_cookie_parse` → verify claimed bucket using the protocol's
      ordered-difference rule → re-derive nonce for (ip16, plen, claimed
      bucket) with current secret, then previous on failure →
      `pow_proof_check` →
      valid: build auth cookie (`pow_cookie_build`, expiry = now + TTL),
      push `Set-Cookie: __pow=…; Max-Age=…; Path=/; Secure; HttpOnly;
      SameSite=Lax` **and** `Set-Cookie: __pow_p=; Max-Age=0; Path=/`,
      then `NGX_DECLINED` — the original request proceeds immediately, no
      redirect.
   c. Else → Phase 3 challenge branches.
   If allocation of either `Set-Cookie` header fails after proof validation,
   return `NGX_HTTP_INTERNAL_SERVER_ERROR`; never pass the request through
   cookieless. A test-only allocator-fault hook, compiled only in test builds,
   forces each allocation site to fail independently and asserts 500; it has
   no directive or production request path and is excluded from release
   artifacts. A retry with the same proof remains valid within the accepted
   bucket window.
3. `Secure` attribute emitted per `pow_cookie_secure`, which is declared,
   merged, and validated with the other Phase 2 directives; default on.
4. Integration tests (proofs produced by `refsolve`): valid proof →
   Set-Cookie + pass-through; tampered proof (wrong counter) → challenge
   again; stale bucket (window + 2) → challenge; proof solved for IP A
   submitted from IP B (two client addrs in test harness) → challenge;
   auth cookie from IP A used from IP B at /32 binding → challenge, but
   passes when `pow_bind_ipv4 24` and B is in A's /24; difficulty
   raised in config → previously issued cookie rejected; binding
   tightened in config (`pow_bind_ipv4 24` → `32`) → cookie bound at the
   wider /24 mask rejected (plen floor); expired auth
   cookie → challenge; secret rotation: cookie signed with old secret
   still valid when old secret is line 2, invalid once removed; a proof mined
   against a pre-rotation challenge verifies after rotation; duplicate
   auth-cookie occurrences: garbage `__pow` before a valid one → passes
   (occurrence iteration per protocol.md), four garbage occurrences
   followed by a *valid* fifth → challenge (bound of 4 enforced; the
   valid fifth is never tried); duplicates split across Cookie header lines
   preserve request order, and only the first `__pow_p` occurrence is tried.

**Gate:** `make check` green — the whole protocol works server-side with
proofs the C code did not produce. Any spec ambiguity `refsolve`
exposed has been resolved in `docs/protocol.md` first, code second.

---

## Phase 4B — The real challenge page

**Goal:** a browser can solve what `refsolve` can solve.

Tasks:

1. Real challenge page (`html/challenge.html`, single file, no external
   resources). Structure: one non-executable JSON params block (populated
   by the server), one static executable `<script>` (hashed at build time
   for the CSP header) that reads the params via
   `JSON.parse(document.getElementById('pow-params').textContent)`.
   Solver requirements:
   - Solver yields on a **time budget, not a counter batch**: hash until
     ~10 ms have elapsed, yield to the event loop, continue. Device
     throughput varies by orders of magnitude; a hardcoded batch size is
     wrong on both ends.
   - Measure both solver backends once (in the Phase 4C harness):
     per-call `crypto.subtle.digest` has real async overhead that can
     dominate at 2^17 hashes; a compact pure-JS SHA-256 may be faster.
     Keep whichever wins, keep the other as fallback, stay a single file
     with no external WASM toolchain.
   - Progress bar keyed to expected 2^d work.
   - Counter as ASCII decimal appended to raw nonce bytes, per protocol.
   - On success: `document.cookie = "__pow_p=1.<bucket>.<counter>; Path=/;
     SameSite=Lax" (+ "; Secure" when on https)`, then `location.reload()`.
   - `<noscript>` block stating JavaScript is required.
   - Total page budget: < 15 KB, zero network fetches.
2. Standalone JS unit test (node): the solver function reproduces the
   canonical test vector exactly — same nonce in, same digest out, finds
   the vector's counter at its difficulty.

**Gate:** JS unit test green against the canonical vector; page renders
with no console errors.

---

## Phase 4C — End-to-end loop

**Goal:** browser engine → solve → proof cookie → verified → auth cookie →
pass-through, against a real nginx.

Tasks:

1. E2E test (`tests/e2e/`): node script (or headless chromium if available
   in CI) loads the 503 page from a real nginx, executes the served
   solver against the served parameters, reloads, asserts 200 + `__pow`
   cookie present + `__pow_p` cleared. This is the only test that catches
   server/JS encoding drift — it is mandatory, not optional.
2. Fuzz corpora expanded with real cookie/proof shapes captured from the
   e2e run.
3. Solver backend measurement (from 4B) recorded; loser wired as fallback.

**Gate:** `make check && make test-e2e` green; fuzz-long re-run clean.

---

## Phase 5 — Composition & operational correctness

**Goal:** ngx_powgate behaves predictably next to the rest of NGINX.

Tasks:

1. `satisfy any` decision implemented and documented: handler returns
   `NGX_DECLINED` on allow (already true) — add the integration test
   proving that under `satisfy any` + `allow all`, ngx_powgate is bypassed,
   and under `satisfy all` it is not; document this loudly in
   `docs/configuration.md`.
2. `docs/deployment-behind-proxies.md`: realip configuration, exact
   `set_real_ip_from` guidance, the two failure modes (shared LB IP vs
   spoofable XFF), and a copy-paste config for the common CDN cases.
3. Logging per README: challenge issuance at `info`, verification failures
   at the severity configured via `pow_log_level` (enum directive,
   `limit_req_log_level` mechanism) with verdict + lengths only, config
   errors via `ngx_conf_log_error`. Debug tracing through
   `ngx_log_debug*(NGX_LOG_DEBUG_HTTP, ...)` so `--with-debug` builds show
   the decision path. Grep-test: no log line ever contains a cookie value,
   nonce, or secret.
   `docs/configuration.md` documents normalized `pow_exempt_path` matching,
   duplicate-secret rejection, and the explicit secret-file policy; the
   security guide explains why descriptor-based checks permit symlinks but
   reject non-regular and group/other-readable targets.
4. **Request-path matrix** (genuinely overlooked until now): integration
   tests asserting the challenge fires exactly once, on the client-facing
   request only, across nginx's internal routing machinery — `rewrite`
   (`last` and `break`), `try_files` fallback, `index` internal redirect,
   `alias`, named-location fallback (`error_page ... @named`),
   `auth_request` subrequest, `mirror` subrequest, and
   `X-Accel-Redirect` from a backend. The `r != r->main || r->internal`
   bail should make these all pass; the tests exist because each of these
   re-enters phase processing in a slightly different way and this is
   exactly where nginx modules break in the field.
5. Reload continuity: extend the secret-rotation integration test with a
   keepalive connection opened before `nginx -s reload` and reused after —
   cookie issued by the old worker verifies in the new one (dual-secret),
   no reset, no challenge loop.
6. Performance sanity: `wrk` (or vendored equivalent) micro-benchmark in
   `tests/perf/` — cookie-valid path overhead target < 10µs per request on
   CI hardware vs `pow off`. Record the number in docs; do not
   optimize further in v0.1.

**Gate:** `make check` green; perf number recorded; both new docs exist and
are referenced from README.

---

## Phase 6 — Hardening audit

**Goal:** systematically close the security checklist before calling it 0.1.

Tasks — walk each item and either point to the test that proves it or add
that test:

1. Audit `tools/check-policy.sh` (created before Phase 0, wired into
   `make check` since then): every hard rule points at the script check
   or the test that proves it; anything found unenforced gets a new
   check or test row in the same commit. Constant-time comparison and
   banned-function coverage live in that script, not in prose.
2. Length caps enforced pre-parse (unit tests at cap, cap+1).
3. Integer overflow: expiry/bucket arithmetic in 64-bit, counter cap 2^53,
   difficulty cap 32, payload sanity bounds (difficulty 1–32,
   plen 32–128) — unit table rows for each boundary, including plen 31,
   129, and 255 (masking must never run on an out-of-range plen).
4. Rejection of future buckets beyond +1 skew.
5. Dual-secret verify walks both secrets on failure (timing-shape test:
   code inspection + comment, no timing measurement needed).
6. Allocation audit: no allocation proportional to attacker input; every
   pool return checked (grep + review).
7. Fuzz corpora expanded with Phase 4C real-traffic shapes; 1-hour fuzz run
   of both harnesses under ASan+UBSan clean.
8. Manual pass with checklist file (`docs/security.md` = finalized
   checklist with per-item "proven by: <test name>" annotations).
9. `docs/security.md` opens with a **Security Properties table** — the
   contract future changes are reviewed against:

   | Property | Guaranteed | Notes |
   |---|---|---|
   | Stateless operation | yes | no challenge/session storage anywhere |
   | Offline cookie forgery resistance | yes | requires the HMAC secret |
   | Challenge unpredictability (w/o secret) | yes | HMAC-derived nonce |
   | Constant-time MAC verification | yes | dual-secret, both evaluated |
   | Cookie theft resistance | partial | bound to masked IP prefix only |
   | Replay resistance | partial | same masked IP, ≤2 buckets; accepted |
   | Timing-leak resistance | partial | MAC compare CT; parsing is not, deliberately |
   | Transport security | delegated | requires HTTPS; `Secure` cookie |
   | GPU/ASIC cost asymmetry | no | known limit; v2 reserved for memory-hard PoW |

   Followed by a short **Documented non-mitigations** section: HTML
   challenge amplification (an anonymous browser-shaped GET costs one
   ~15 KB static in-memory response — cheaper than any backend hit it
   replaces, and non-browser-shaped requests get an empty 403; measured,
   accepted, not mitigated), deterministic challenges (same IP + same
   bucket = same nonce by design; a mid-solve refresh reuses the same
   challenge, which is a feature — no work is wasted), and the replay
   window (per protocol.md).

**Gate:** `docs/security.md` complete with every item annotated;
1-hour fuzz clean; `make asan` green.

---

## Phase 7 — Release v0.1

Tasks:

1. **Freeze the protocol**: flip `docs/protocol.md` STATUS to
   `FROZEN — version 1`, reconciling it against the shipped code and the
   canonical vector one final time. From this commit on, any wire change
   is version 2.
2. Final docs: `docs/protocol.md` (now frozen), `configuration.md`
   (every directive, defaults, examples), `security.md`, proxies doc,
   README updated with actual install steps (`load_module`, one-directive
   quickstart) and the SEO caveat verbatim from the plan README.
3. LOC audit: `cloc src/` reported in release notes; if > 2500, open issues
   to shrink, do not gate the release on it.
4. Tag `v0.1.0`; release artifact = source tarball + build instructions
   (no prebuilt binaries in 0.1).
5. Post-release backlog file (`docs/roadmap-v0.2.md`): header-based PoW
   flow (the `PowGate-Challenge` header from Phase 3 is already emitted —
   v0.2 adds accepting a `PowGate-Proof` request header), metrics,
   NGINX variables, custom challenge page, UA exemptions (disabled by
   default, documented as zero security value).

**Gate:** clean-machine build from the tarball following only the README
succeeds; full `make check && make test-e2e && make test-fuzz-long` green
on the tag.

---
---

# Protocol v1 Specification (copy verbatim to docs/protocol.md — PROVISIONAL until the Phase 7 freeze; spec-first changes only)

> Copied to docs/protocol.md — that copy is authoritative; changes land there
> first and are mirrored here only to keep the plan self-contained (the two
> must stay byte-identical below this note).

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
