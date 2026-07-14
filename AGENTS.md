# AGENTS.md — ngx_powgate

ngx_powgate ("PowGate") is a stateless proof-of-work gateway implemented
as a native NGINX dynamic module in C.
The module binary is `ngx_http_pow_module.so`; directives use the `pow_`
prefix. Read `docs/protocol.md` before touching any code that
creates or verifies challenges, cookies, or MACs — the wire format is frozen
and every byte matters.

## What this project is

- One job: make anonymous automation pay a small SHA-256 cost; server
  verifies with two HMACs. Never more than that.
- Stateless: no Redis, no DB, no sessions, no challenge storage, no
  per-request randomness. If a change requires storing anything, the change
  is wrong.
- Target: 1500–2500 lines of C total. Prefer deleting code to adding it.


## Development Environment (Mandatory)

All compilation, building, testing, fuzzing, sanitizers, and integration
tests MUST run inside the project Podman container environment.

The host machine MUST NOT be used for:
- compiling the module
- building nginx
- running unit tests
- running integration tests
- running fuzzers
- running ASan/UBSan jobs
- installing project build dependencies

The host machine is only used to invoke Podman commands and inspect
artifacts.

The canonical development environment is a project-managed golden image
built with Podman from Debian Trixie. Its canonical local name is
`localhost/ngx-powgate-dev:trixie`; use that fully qualified local tag for
every `podman run` and `podman build -t` invocation.

## Golden Development Image

The repository MUST provide a reproducible Containerfile for the golden
development image.

The image MUST contain all dependencies required for normal development,
building, testing, fuzzing, and CI, including:

- gcc and clang toolchains
- make and standard build utilities
- OpenSSL development headers
- nginx build dependencies
- Perl and Test::Nginx dependencies
- Node.js tooling required by browser/e2e tests
- LLVM/libFuzzer tooling
- ASan and UBSan runtime support
- debugging and analysis utilities used by the project

Do not install missing dependencies manually during development.
If a dependency is required, update the Containerfile and rebuild the
golden image.

All developers and CI jobs MUST use the same golden image.
The image base and Debian repository snapshot must be pinned; nginx.org
package inputs and the pinned NGINX source SHA-256 must be recorded in a
committed version lock.

## NGINX Build and Runtime Rules

The golden image MUST use Debian Trixie as the userspace base.

Integration tests MUST run against the latest stable nginx package from
nginx.org installed inside the container.

Dynamic module compilation MUST use the pinned nginx source version
defined by the project build system.

Do not use distribution-provided nginx packages for dynamic module builds.

The project intentionally separates:
- pinned nginx source → reproducible module compilation
- nginx.org stable package → runtime compatibility testing

## NGINX source reference

A checksum-pinned NGINX 1.30.3 source tree MUST be available inside the
development container at `NGX_SOURCE_DIR`; it is the authoritative reference
for coding style, module patterns, directive handling, configuration merging,
request phases, header/cookie processing, and API compatibility.

Before introducing a new NGINX API or helper pattern, inspect an equivalent
example in that pinned tree. Do not invent an NGINX-style helper or pattern
when an existing NGINX precedent exists.

The source may live in an environment-owned build cache and need not be
committed. Its exact version and SHA-256 MUST be pinned and verified before
extraction or use.

Test-only fault injection has no production directive or request path and is
excluded from release artifacts.


## Build & test commands

```
make check-policy    # source-policy gate, introduced in Phase 0
make module          # builds ngx_http_pow_module.so against pinned NGINX source
make test-integration# Test::Nginx suite against a real nginx binary
make test-e2e        # node-based solver runs the real challenge JS end-to-end

# Introduced in Phase 1 with the real pure core; never placeholder targets.
make test-unit       # pure-function unit tests (no NGINX needed)
make test-fuzz       # 60s smoke run of both fuzzers (libFuzzer, ASan)
make test-fuzz-long  # 10min run, required before any release tag
make asan            # full rebuild + unit + integration under ASan/UBSan
make check           # everything above except fuzz-long; the pre-commit gate
```

The Phase 0 gate is `make check-policy`, `make module`,
`make test-integration`, and `make test-e2e`. Phase 1 introduces the
pure-core targets and `make check`; from then on `make check` must pass before
any task is considered done. Never mark a phase complete with a skipped,
commented-out, or placeholder test.

## Enforcement

`tools/check-policy.sh` is the authoritative list of banned constructs
(libc string functions, bare `memcmp`, heap allocation, nginx headers in
the pure core, RNG). It runs as a Phase 0 gate, then in `make check`, in CI,
and on every source edit via the Codex hook. Never bypass or weaken it; extend it in
the same commit that introduces any new rule.

1. **No NUL-terminated string functions on request data.** Everything off
   the wire is `ngx_str_t` (len + data). Banned in request paths: `strlen`,
   `strcpy`, `strcmp`, `sprintf`, `sscanf`, `strtol`, `atoi`. Use
   `ngx_atoi`, `ngx_strncmp`, `ngx_snprintf` with explicit lengths.
2. **`CRYPTO_memcmp` for every MAC/signature comparison.** Plain `memcmp`
   in a verification path fails review; `make check` greps `src/` for it
   and for banned libc string functions (`strcpy`, `strcat`, `gets`, bare
   `sprintf`/`strlen`/`strtol` without the `ngx_` prefix) and fails on
   any hit.
3. **No `malloc`/`free` in request context.** `ngx_pnalloc`/`ngx_pcalloc`
   from `r->pool`; config-time allocations from `cf->pool`. Check every
   allocation for NULL.
4. **Parsers are pure functions.** `pow_cookie.c`, `pow_challenge.c`,
   `pow_crypto.c` include no NGINX headers except `ngx_config.h` basics for
   integer types — signature style:
   `int pow_cookie_parse(const uint8_t *buf, size_t len, pow_cookie_t *out)`.
   Output into caller-provided fixed structs. Zero allocation. This is what
   keeps the fuzz harnesses at 20 lines.
5. **Length gate before parsing.** Cookie value > 256 bytes or proof
   cookie > 64 bytes → reject before reading a single field. Exact field
   counts, strict base64url (no padding), exact decoded lengths, reject on
   first violation, single forward pass.
6. **HMAC inputs use domain labels and fixed-width binary fields** exactly
   as specified in `docs/protocol.md`. Never build a MAC input by
   concatenating variable-length strings.
7. **No crypto is vendored.** SHA-256 and HMAC come from the OpenSSL that
   NGINX links. No RNG anywhere (the design needs none); if one is ever
   added it is `RAND_bytes`.
8. **Access handler returns `NGX_DECLINED` for allowed requests**, never
   `NGX_OK` (composes with `satisfy`/`allow`/`deny`). Challenge responses
   finalize the request and return `NGX_DONE`.
9. **Skip subrequests and internal redirects**: bail out immediately when
   `r != r->main || r->internal`.
10. **Never log attacker-controlled bytes verbatim.** Log lengths and
    verdicts. Never log the secret, a MAC, or a full cookie value at any
    level.
11. **Out of scope, permanently** — do not implement even if asked by a
    TODO or an old comment: CAPTCHA, fingerprinting of any kind, TLS/JA3,
    ML scoring, reputation feeds, external API calls, crawler allowlists,
    JS obfuscation, challenge/session storage.

## Code conventions

- **`docs/nginx-style.md` is the style authority** — read it before writing
  any C. Code must read as if it were an upstream nginx module; when the
  guide is silent, imitate `ngx_http_limit_req_module.c` from
  `$NGX_SOURCE_DIR`, not personal taste.
- Non-negotiable style points (details and examples in the guide): return
  type on its own line above the function name; all variables declared at
  the top of the function, names column-aligned; explicit comparisons
  (`p == NULL`, `rc != NGX_OK`); `/* */` comments only; `ngx_str_t` +
  `sizeof("lit") - 1`; buffers built by pointer-walking with `ngx_cpymem`
  into exact precomputed sizes; standard `ngx_conf_set_*_slot` handlers
  over custom directive parsers wherever possible; 80 columns, 4 spaces,
  two blank lines between functions.
- Compiler flags are nginx's own (`-W -Wall -Wpointer-arith
  -Wno-unused-parameter -Werror` via auto/cc) for module-side code. Never
  add `-Wconversion` there (nginx headers don't compile under it) and
  never weaken `-Werror`. Hardening flags go through `--with-cc-opt` only.
  The **pure core is held to a stricter bar**: `pow_crypto.c`,
  `pow_cookie.c`, `pow_challenge.c` include no nginx headers, so the
  unit/fuzz builds compile them with
  `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror` — warning-free
  under the full set, no exceptions.
- Naming: module-side identifiers are fully prefixed
  (`ngx_http_pow_*`, `NGX_HTTP_POW_*`); pure-core identifiers
  are `pow_*` / `POW_*`. The pure core is the single sanctioned deviation
  from nginx's one-file module tradition, and it exists only for
  fuzzability — see the deviation section of the style guide.
- Pinned NGINX version: 1.30.3 for module builds and runtime tests. Use the
  post-1.23 cookie API
  (`r->headers_in.cookie` linked list); no legacy `#if` shims.
- Every constant that appears in the protocol (label strings, field widths,
  caps) is defined once in `src/pow_protocol.h` and used everywhere else by
  name.
- Tests are table-driven. New parser behavior = new table rows + new fuzz
  corpus seeds in the same commit.

## Git commits

- Format: `type: imperative summary` (72 characters or fewer).
- Types: `build`, `docs`, `feat`, `fix`, `test`, `chore`.
- One logical change per commit.

## Judgment rules (what no grep can catch)

- Everything off the wire is `ngx_str_t` (len + data); never assume NUL.
- Length gate before parsing: auth cookie > 256 or proof cookie > 64
  bytes → reject before reading a single field. Exact field counts,
  strict b64url, exact decoded lengths, single forward pass.
- MAC inputs are a domain label plus fixed-width binary fields exactly
  per `docs/protocol.md` — never concatenated variable-length strings.
- Allocate from `r->pool`/`cf->pool` only, never proportionally to
  attacker input; check every allocation for NULL.
- Log verdicts and lengths — never a cookie value, nonce, MAC, or secret.
- Access handler returns `NGX_DECLINED` for allowed requests, never
  `NGX_OK`; challenge responses finalize and return `NGX_DONE`.
- Bail immediately when `r != r->main || r->internal`.
- `pow_secret_file` is `http{}`/main-conf-only; a duplicate directive is an
  error. Follow symlinks, then `fstat()` the opened descriptor before reading:
  it must be a regular file with no group/other read bits. The owner is
  intentionally unrestricted.
- Exempt paths match normalized, percent-decoded `r->uri`, never `r->args`;
  `/` matches all, otherwise require an exact match or a `/` segment boundary.
- If either `Set-Cookie` allocation after a valid proof fails, return
  `NGX_HTTP_INTERNAL_SERVER_ERROR`; never pass the request through cookieless.
- The pure core (`pow_*.c/.h`) is NGINX-free: C99 `stdint.h`/`stddef.h`
  types only, zero allocation, caller-provided fixed structs.
- New parser behavior = new table rows + new fuzz corpus seeds in the
  same commit.

## When unsure

- Wire format question → `docs/protocol.md` is the single source of truth;
  if it is ambiguous, fix the doc first, then the code.
- Style question → `docs/nginx-style.md`, then imitate a core module in
  `$NGX_SOURCE_DIR/src/http/modules/`.
- NGINX API question → read the pinned source in `$NGX_SOURCE_DIR`, not
  memory; APIs drift between versions.
- Scope question → if it adds state, network calls, or a new dependency,
  the answer is no.
