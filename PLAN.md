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
   - `fuzz_auth_cookie` → auth-cookie parse and verification.
   - `fuzz_proof_cookie` → proof-cookie parse and verification.
   - Phase 4A adds `fuzz_cookie_scan` for Cookie-field extraction.
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
support. The handler still allows everything and is registered only when a
fully merged configuration enables PowGate.

Tasks:

1. Directives in `src/pow_config.c`, using the standard slot handlers
   wherever one exists (custom handlers only for CIDR lists and the secret
   file, per the style guide):
   `pow on|off;` (flag slot)
   `pow_difficulty N;` (num slot + post validation 1–32, default 20;
   operators are advised to use 20–22 unless measurements justify otherwise)
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
   `pow_exempt_path prefix;` (str-array slot + post validation, repeatable)
   `pow_log_level info|notice|warn|error;` (enum slot, modeled
   directly on `limit_req_log_level` — same values, same mechanism)
2. `create_main_conf` creates `ngx_http_pow_main_conf_t` containing
   `u_char secret[32]`, `u_char secret_prev[32]`, `ngx_flag_t has_prev`, and
   `ngx_flag_t secret_set` (all-zero secrets are valid, so presence needs its
   own flag), plus `ngx_flag_t effective_pow_enabled`. Main conf has no merge
   function and no `init_main_conf` secret requirement.
   `create_loc_conf`/`merge_loc_conf` use `NGX_CONF_UNSET*` sentinels and
   the matching `ngx_conf_merge_*` calls; cross-field validation (window
   vs TTL, difficulty range) after merge, errors via
   `ngx_conf_log_error(NGX_LOG_EMERG, ...)`. Inheritance from `http{}` →
   `server{}` → `location{}`. Each completed location merge that produces
   effective `pow on` sets `effective_pow_enabled`; this records merged
   behavior, not mere directive presence. During postconfiguration, inactive
   configuration returns `NGX_OK` without requiring a secret or registering
   the access handler. Active configuration requires `secret_set` and then
   registers the handler. An explicitly configured secret file is always
   validated, even when the module remains inactive.
3. Exemption arrays use standard replacement inheritance: a child inherits
   its parent array only when it declares no entries; otherwise its entries
   replace the inherited list. Repeated entries at one level append, and
   duplicates are accepted. `pow_exempt_ip` follows the
   `ngx_http_access_module` CIDR precedent. Configured exempt paths are stored
   byte-for-byte. Phase 3 matches them against normalized, percent-decoded
   `r->uri`; duplicate-slash compression follows the core `merge_slashes`
   setting and is not unconditional.
4. Secret loading at config parse (master, pre-fork) accepts exactly four
   byte layouts: `HEX64`, `HEX64 LF`, `HEX64 LF HEX64`, and
   `HEX64 LF HEX64 LF`. Each `HEX64` is 64 ASCII hexadecimal bytes;
   uppercase, lowercase, and mixed case are accepted. Reject CRLF, all other
   whitespace, BOMs, blank lines, malformed hex, and every extra byte. Line 1
   is current and signs new cookies and derives new challenges. Optional line
   2 is previous and verification-only; both are accepted for cookie and
   proof verification.
5. Resolve the configured path through `ngx_conf_full_name(..., 1)`, then
   open it following symlinks with
   `NGX_FILE_RDONLY | NGX_FILE_NONBLOCK`. Apply `ngx_fd_info`/`fstat()` to
   the opened descriptor and require a regular file with
   `(mode & 0077) == 0`; ownership and owner bits are unrestricted. Use a
   fixed buffer, validate the metadata and actual byte count, detect growth
   or shrinkage, and follow parse → validate → commit. Wipe raw and
   decoded temporary buffers on every path. Long-lived decoded secrets reside
   in cycle configuration memory, whose destruction NGINX does not guarantee
   to zeroize.
6. Rotation is operator-managed: atomically replace the file with new current
   followed by old current, test, and reload. After this first successful
   reload, wait until all workers from the old cycle have exited. From that
   exit point, retain previous for at least
   `max(maximum effective auth-cookie TTL in the old cycle, 2 × maximum
   effective challenge window in the old cycle)`, then atomically replace the
   file with current alone, test, and reload a second time. The two-window
   bound covers the protocol's ±1-bucket acceptance when an old worker issues
   a challenge at bucket start. Failed test or reload leaves the old cycle
   serving. Phase 2 proves that reload rereads the file and preserves the old
   cycle on failure; current-secret nonce derivation is deferred to Phase 3,
   and previous-secret verification and cryptographic rotation are deferred
   to Phase 4A. No temporary diagnostic directive, response header, or request
   behavior is introduced.
7. Organize integration coverage into five enduring categories:
   **Configuration** (directives, validation, contexts, merge construction),
   **Filesystem** (secret grammar, permissions, types, paths, symlinks),
   **Reload** (cycle lifecycle and worker replacement), **Request** (runtime
   behavior, activation, exemptions), and **Cryptography** (challenges,
   proofs, cookies, rotation). A category begins when its production behavior
   exists. Phase 2 exercises configuration, filesystem, reload, and the
   existing request smoke behavior. Observable inheritance moves to Phase 3;
   cryptographic rotation moves to Phase 4A.
8. Sanitizer policy, project-wide: every implemented integration category
   runs under ASan and UBSan before release; every finding blocks release.
   Sanitizer-specific functional or alternate implementation paths are
   prohibited. Sanitized tests use production NGINX and module source with
   compiler/linker instrumentation as the only difference. Test fixtures and
   fault injection add no production directive, request path, or release
   artifact. Once implemented, a category remains in the sanitizer gate.

**Gate:** `make check` passes. Reload tests prove file re-reading, successful
worker replacement, and continued old-cycle service after a failed reload.
They make no old-cookie-validity claim; dual-secret behavior is fully
exercised in Phase 4A.

---

## Phase 3 — Challenge issuance path

**Goal:** requests without a valid cookie receive the correct response:
HTML challenge for navigations, bare 403 otherwise. No verification yet.

Tasks:

1. Request evaluation follows one fixed order: skip subrequests and internal
   redirects; decline if disabled; classify the post-RealIP connection
   address; reject unsupported families with `500`; match IP exemptions with
   nginx's `ngx_cidr_match()`; then match path exemptions against normalized,
   percent-decoded `r->uri`. `/` matches all; another configured path requires
   an exact match or a `/` segment boundary. Queries never participate and
   duplicate-slash behavior follows `merge_slashes`.
2. Canonical identity uses IPv4-mapped `ip16` plus
   `96 + pow_bind_ipv4` for IPv4 and mapped IPv6, or native 16-byte `ip16`
   plus `pow_bind_ipv6` for IPv6. Mask before deriving anything. Use
   `ngx_time()` and the positive effective window for the bucket, then derive
   with the current secret only.
3. One pure allocation-free serializer emits
   `v=1; d=<difficulty>; b=<bucket>; n=<nonce-base64url>` and returns the
   offsets/lengths of the already-formatted difficulty, bucket, and nonce.
   The bare header uses the complete string; HTML JSON copies those spans.
   No other decimal/base64 formatter exists on the response path.
4. Navigation is `GET` or `HEAD` plus a case-insensitive `text/html`
   substring in any received `Accept` occurrence. All other method/header
   combinations are non-navigation. Both branches discard request bodies
   through `ngx_http_discard_request_body()` before response commitment.
5. A non-navigation response is an exact bodyless `403` with one
   `PowGate-Challenge`. PowGate sends it directly so core special responses
   and `error_page 403` cannot replace it.
6. A navigation response is an exact HTML `503` with `Cache-Control:
   no-store`, `X-Robots-Tag: noindex`, `Content-Type: text/html;
   charset=utf-8`, and PowGate's named versioned CSP. Ranges, ETag, and
   Last-Modified are disabled. `HEAD` publishes the GET content length but no
   body; `error_page 503` cannot replace the completed response.
7. Phase 3's `html/challenge.html` contains exactly one literal
   `<!-- POW:PARAMS -->` marker and one inert executable script. The build
   tool rejects malformed templates, splits exact prefix/suffix bytes,
   extracts the exact script body, and emits its padded standard-base64
   SHA-256 digest into the same deterministic generated header. Phase 4B
   later replaces only the inert script body with the solver.
8. Build responses transactionally: derive and validate values; allocate all
   buffers; reserve every header with `hash = 0`; populate metadata; enable
   headers only when complete; send; finalize exactly once; return
   `NGX_DONE`. Before commitment, any runtime/format/allocation error follows
   the NGINX error path. Allowed requests return `NGX_DECLINED`.
9. Every request-behavior scenario runs over HTTPS with both forced HTTP/1.1
   and HTTP/2 and asserts the negotiated protocol. Each isolated runtime owns
   an ephemeral self-signed P-256 certificate; only test clients disable
   verification. Tests cover exact body/header/CSP bytes, deterministic
   identity and RealIP, IPv4/IPv6/mapped IPv6, Unix fail-closed behavior,
   normalized paths, reusable connections after bodies, subrequests/internal
   redirects, error-page resistance, operator CSP intersection, and a strict
   public-header allowlist.
10. Normal and ASan/UBSan module builds consume the same generated page.
    Instrumented NGINX enables `--with-http_ssl_module` and
    `--with-http_v2_module` and runs the complete production H1/H2 matrix.
    Normal challenge issuance is not logged; `pow_log_level` remains reserved
    for Phase 4 verification failures.

**Gate:** `make check` green including all new integration tests, run over
HTTP/1.1 and HTTP/2. ASan job green.

---

## Phase 4A — Server-side verification path

**Status:** Complete (2026-07-15).

**Goal:** the full server loop verified end-to-end using a *reference
solver script* — no browser JS yet. This deliberately proves the C side
against an independent implementation first.

Tasks:

1. `tools/refsolve.py` (from Phase 1) drives all integration tests in this
   phase: proofs and cookies the C code did not produce, exercised against
   the C code. Mining always receives an explicit test difficulty.
2. Implement the adapter layering and exact handler order frozen in
   `docs/protocol.md` and the approved Phase 4A design: auth before proof;
   first four exact auth occurrences; an independent first-proof scan; one
   request clock sample; current verification policy; current/previous secret
   bounds; and distinct client-invalid versus internal-error outcomes.
   Secrets come from module main conf; location conf supplies all request
   policy.
3. Add the NGINX-free, allocation-free Cookie-field scanner and freeze the
   three fuzz targets as `fuzz_cookie_scan`, `fuzz_auth_cookie`, and
   `fuzz_proof_cookie`. Scanner tables and coverage execute every branch.
4. After a valid proof, build the exact auth and proof-clear fields and commit
   both transactionally. `pow_cookie_secure` controls only the auth field's
   `Secure` attribute. Either reservation failure returns `500`, exposes no
   PowGate Set-Cookie field, and never reaches protected content. The two
   compile-time fault variants remain test-only and outside `out/`.
5. Implement bounded verification summaries at effective `pow_log_level`:
   at most one auth-invalid and one proof-invalid record per request, with
   fixed operation/verdict tokens and no attacker-controlled bytes. Internal
   failures always use a fixed `NGX_LOG_ERR` record and never contribute to
   client-invalid summaries. These records use the cycle log so NGINX does
   not append request-line context.
6. Exercise the complete forced-HTTPS HTTP/1.1 and HTTP/2 matrix from the
   approved Phase 4A design: success, malformed and policy-invalid artifacts,
   clock window, IPv4/IPv6/RealIP binding, occurrence bounds and ordering,
   current-policy reloads, worker-generation-proven secret rotation, logging,
   response atomicity, body preservation, and both allocation-fault sites.

**Gate:** `make check` green — the whole protocol works server-side with
proofs the C code did not produce. Any spec ambiguity `refsolve`
exposed has been resolved in `docs/protocol.md` first, code second.

---

## Phase 4B — The real challenge page

**Status:** Complete (2026-07-15).

**Goal:** a browser can solve what `refsolve` can solve.

Tasks:

1. `html/challenge.html` is the only browser implementation: one accessible
   `<main>`, one non-executable JSON parameter block at the literal marker,
   and one build-hashed executable script. It has no external resource,
   storage, worker, randomness, tracking, console, or unrelated browser-state
   dependency. Generated prefix, suffix, and digest data remain build outputs.
2. The exact script installs only a frozen `globalThis.PowGateSolver` with
   synchronous pure-JavaScript `sha256` and an always-Promise bounded `solve`.
   Both `js` and sequential `subtle` backends examine the same contiguous
   safe-integer counter sequence and resolve the frozen five-field result:
   `found`, `exhausted`, `counter`, `nextCounter`, and `attempts`. Success,
   safe-integer exhaustion, and resumable attempt-limit outcomes are distinct;
   no counter wraps or constructs `Number.MAX_SAFE_INTEGER + 1`.
3. A private single-start controller strictly parses exactly `v`, `d`, `b`,
   and `n`; validates canonical uint64 bucket text and canonical 32-byte
   base64url nonce bytes; removes visible path-scoped `__pow_p` cookies; and
   runs one production-shaped known-answer self-test. Pure JavaScript is the
   fixed primary backend. WebCrypto is attempted once only after primary
   initialization or self-test failure.
4. Foreground mining uses adaptive bounded kernels inside approximately 10 ms
   controller slices. Hidden documents schedule no work and resume at the
   first untested counter. Progress is
   `min(0.99, 1 - exp(-attempts / 2^difficulty))` until success. Terminal
   failure is a static, non-diagnostic retry UI with no automatic reload.
5. Success writes exactly
   `__pow_p=1.<bucket>.<counter>; Path=/; SameSite=Lax`, appending `Secure`
   only for HTTPS. Reload occurs only after exact-name read-back finds one
   visible proof cookie. The controller never recursively restarts itself.
6. NGINX checks the actual assembled prefix + JSON + suffix length before
   response commitment; it must be strictly below 15 KiB. Node executes the
   exact production script, verifies SHA-256 padding boundaries, both backend
   contracts, canonical vectors, controller states, cookie behavior, and byte
   identity from template through generator and CSP digest. The HTTPS smoke
   executes the exact served bytes against NGINX 1.30.3. `node:vm` supplies a
   deterministic harness, not a security boundary.
7. The pure-JavaScript mining path uses one invocation-local, fixed-shape
   single-block workspace and shares one SHA-256 compression primitive with
   public `sha256()`. The pure-JavaScript kernel creates no explicit typed
   array, message buffer, or digest object per candidate. Both backends use
   one direct canonical-decimal encoder. The sequential SubtleCrypto backend
   reuses one invocation-local backing buffer and passes one exact-length view
   per awaited provider call. Cleanup always attempts `/`, skips only unsafe
   complete derived Path candidates, and still requires zero visible
   `__pow_p` occurrences before mining. Literal semicolons are skipped;
   percent-encoded `%3B` is preserved.

**Gate:** `make check` green with no skipped, TODO, placeholder, or test-only
production behavior. Phase 4C retains real-browser CSP enforcement, native
cookie/reload behavior, authenticated pass-through, and backend measurement.

---

## Phase 4C — End-to-end loop

**Goal:** browser engine → solve → proof cookie → verified → auth cookie →
pass-through, against a real nginx.

Tasks:

1. The pinned native x86_64 Chromium matrix executes the exact generated
   production solver over explicitly asserted HTTP/1.1 and HTTP/2. Each
   server build runs eight complete challenge/proof/auth/backend loops and two
   browser-native partitioned-cookie fail-closed cases. The same ten cases run
   against the normal and ASan+UBSan NGINX/module builds.
2. The controller-observer equivalence contract proves that the narrow
   negative-case call counter does not alter cookie, navigation, scheduling,
   or network behavior. Positive cases execute the untouched production
   namespace.
3. The reproducible browser benchmark runs seven alternating matched pairs
   for the existing JavaScript and sequential SubtleCrypto backends, enforces
   correctness and responsiveness per repetition, and writes schema-validated
   raw evidence under `build/`. Throughput may select only the fixed pre-search
   backend order; there is no runtime benchmark, dynamic selection, or
   mid-search fallback.
4. Canonical evidence is promoted only after the clean final source passes
   the project gate, native browser aggregate, and long fuzz gate. The
   evidence-only commit then runs the lightweight schema, relational,
   source-identity, policy, and documentation-link gate.

**Gate:** inside the golden image, `make check` and `make test-fuzz-long`
pass; on the canonical native x86_64 worker,
`tools/run-browser-x86.sh check-browser-x86` passes. A later standalone clean
benchmark agrees with the fixed production order and is promoted under
`docs/benchmarks/phase4c-v1/` before Phase 4C is complete.

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
3. Audit and harden the Phase 4A logging contract: normal challenge issuance
   remains silent; verification summaries retain their configured severity,
   fixed tokens, bounded counts/lengths, and nondisclosure guarantees. Add
   debug-only decision tracing where operationally useful and broaden the
   permanent regression-policy review; Phase 5 does not introduce the first
   runtime implementation of `pow_log_level`.
   `docs/configuration.md` documents normalized `pow_exempt_path` matching,
   duplicate-secret rejection, and the explicit secret-file policy; the
   security guide explains why descriptor-based checks permit symlinks but
   reject non-regular targets and targets with any group or other permission
   bits.
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
