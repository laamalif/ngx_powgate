# Phase 3 Challenge Issuance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver deterministic PowGate challenge responses over HTTPS, with a bare `403` for non-navigation requests and an exact generated HTML `503` for browser navigations.

**Architecture:** Extend the allocation-free pure core with one canonical challenge serializer, compile an immutable HTML template and exact script digest into a generated header, and keep all NGINX request mechanics in `ngx_http_pow_module.c`. A narrow Perl/curl HTTPS harness owns protocol assertions while the existing Perl runtime helper remains responsible for isolated NGINX lifecycle.

**Tech Stack:** C99, NGINX 1.30.3 dynamic-module APIs, OpenSSL 3.x, Python 3 standard library, Perl 5/Test::More, curl with HTTP/2, Node.js 20, GNU Make, Podman, ASan, and UBSan.

## Global Constraints

- Run every build, test, generator, sanitizer, and NGINX command inside `localhost/ngx-powgate-dev:trixie`; the host only invokes Podman and inspects files.
- Use only the checksum-pinned NGINX 1.30.3 tree at `$NGX_SOURCE_DIR` for module builds and API/style precedent; runtime compatibility uses nginx.org NGINX 1.30.3.
- Read `docs/protocol.md`, `docs/nginx-style.md`, and the approved Phase 3 design before changing C or protocol-visible bytes.
- Preserve statelessness: no request storage, challenge storage, per-request randomness, external service, or network lookup.
- The pure core remains NGINX-free, allocation-free C99 and compiles with `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror`.
- Protocol constants and wire-format literals live once in `src/pow_protocol.h`; generated template bytes live once in the generated header.
- Request integration is HTTPS-only and every implemented behavior runs with explicitly asserted HTTP/1.1 and HTTP/2 negotiation.
- Self-signed certificate generation and `--insecure`/`rejectUnauthorized: false` are test-only; do not add production TLS bypasses.
- Unsupported connection families fail closed with `500`; never synthesize an identity or convert the request into an exemption.
- Build responses transactionally: derive, validate, allocate, reserve disabled headers, populate, commit, send, and finalize exactly once.
- Each request ends in exactly one of `NGX_DECLINED`, explicitly finalized `NGX_DONE`, or an NGINX error-response path.
- Never log request bytes, URI, arguments, cookies, nonce, MAC, secret, or body; normal challenge issuance is not logged.
- Do not introduce `pow_log_level` behavior, cookie/proof verification, authentication-cookie issuance, a working solver, or header-based proof acceptance in Phase 3.
- Every source edit must pass `make check-policy`; the completed phase must pass containerized `make check` without skips.

## File Map

- `src/pow_protocol.h` — sole owner of challenge wire literals, maximum lengths, JSON wrapper literals, and versioned CSP template.
- `src/pow_challenge.h`, `src/pow_challenge.c` — pure canonical serializer plus existing identity, nonce, and proof helpers.
- `src/ngx_http_pow_module.h` — module-private response and identity declarations only when shared with `pow_config.c`; keep request-local helpers private in the module C file.
- `src/ngx_http_pow_module.c` — request evaluation, post-RealIP identity, exemptions, navigation detection, response transaction, output, and finalization.
- `html/challenge.html` — immutable Phase 3 page with one parameter marker and one inert executable script.
- `tools/build_pow_challenge.py` — byte-oriented validator/compiler for the page and its CSP digest.
- `build/generated/pow_challenge_page.h` — deterministic generated build artifact; never committed.
- `config`, `Makefile`, `tools/run-asan.sh` — generated-header dependency and equivalent normal/sanitized SSL+HTTP/2 builds.
- `tests/unit/test_challenge.c` — serializer tables and exact offset/capacity tests.
- `tests/tools/test_build_pow_challenge.py` — generator validation, exact-byte, digest, and determinism tests.
- `tests/integration/lib/PowGate/TestHTTPS.pm` — narrow TLS fixture and curl protocol helper.
- `tests/integration/lib/PowGate/TestNginx.pm` — existing lifecycle helper, extended only with Unix-listener cleanup/metadata needed by the matrix.
- `tests/integration/pow_challenge.t` — core delivery, determinism, identity, and exemption matrix.
- `tests/integration/pow_challenge_composition.t` — request-body lifecycle, internal/subrequest behavior, response override resistance, and header allowlist.
- `tests/integration/pow_reload.t` — existing reload lifecycle moved from plaintext probes to the shared HTTPS helper.
- `tests/integration/pow_module.t` — remove the obsolete Test::Nginx plaintext pass-through smoke after equivalent HTTPS coverage exists.
- `tests/e2e/smoke.mjs` — HTTPS/HTTP/1.1 smoke using its isolated ephemeral certificate.
- `docs/protocol.md`, `PLAN.md`, `docs/configuration.md`, `docs/security.md`, `README.md` — protocol, implementation phase, operator behavior, threat boundary, and honest status.

---

### Task 1: Freeze Phase 3 Protocol and Plan Wording

**Files:**
- Modify: `docs/protocol.md`
- Modify: `PLAN.md`
- Modify: `docs/superpowers/specs/2026-07-15-phase3-challenge-issuance-design.md`

**Interfaces:**
- Consumes: approved Phase 3 design and existing protocol v1 challenge grammar.
- Produces: exact normative wording that all code and tests in later tasks implement.

- [ ] **Step 1: Update the protocol challenge-delivery contract**

Replace the CSP in `docs/protocol.md` with this one-line semantic value:

```text
default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; script-src 'sha256-<H>'; style-src 'unsafe-inline'
```

State immediately below it:

```text
The CSP is a versioned PowGate protocol constant. `<H>` is replaced by the
44-byte padded standard-base64 SHA-256 digest of the exact executable script
body. Any policy change requires an explicit protocol revision.
```

Add the v1 address-family rule:

```text
PowGate v1 derives client identity only from IPv4 and IPv6 connection
addresses after RealIP processing. Requests on any other address family are
rejected with 500; they are never treated as exempt and no synthetic address
is used.
```

Clarify that repeated `Accept` fields are scanned in received order and that
the result is true if any value contains `text/html` case-insensitively.

- [ ] **Step 2: Replace the Phase 3 section in `PLAN.md`**

Make the roadmap agree with the approved design on all of these exact points:

```text
- unsupported address family -> 500 before exemptions
- IP exemption through ngx_cidr_match() after RealIP
- path exemption against normalized r->uri
- one canonical pure serializer with returned spans
- request body discarded through ngx_http_discard_request_body()
- bare 403 and exact HTML 503 constructed and finalized by PowGate
- allocate -> validate -> reserve hash=0 -> populate -> commit -> send -> finalize
- literal <!-- POW:PARAMS --> template marker and inert Phase 3 script
- named versioned CSP template with generated exact-script digest
- HTTPS-only H1/H2 matrix with explicit negotiated-version assertions
- ephemeral test certificates and test-only verification bypass
- SSL+HTTP/2 enabled in sanitized NGINX
- header allowlist and exactly-one-terminal-outcome invariant
```

Remove the stale Phase 3 statement that normal challenge issuance logs at
`info`; leave `pow_log_level` reserved for Phase 4 verification failures.

- [ ] **Step 3: Verify wording consistency**

Run inside the golden image:

```bash
rg -n "default-src|unsupported.*address|POW:PARAMS|challenge issuance.*info|HTTP/1.1|HTTP/2" \
  docs/protocol.md PLAN.md \
  docs/superpowers/specs/2026-07-15-phase3-challenge-issuance-design.md
make check-policy
```

Expected: the CSP has all six directives, the marker is always colon-form,
unsupported families fail closed, no per-challenge info logging remains, and
`check-policy: OK` is printed.

- [ ] **Step 4: Commit the normative alignment**

```bash
git add docs/protocol.md PLAN.md \
  docs/superpowers/specs/2026-07-15-phase3-challenge-issuance-design.md
git commit -m "docs: freeze phase three challenge contract"
```

---

### Task 2: Add the Canonical Pure Challenge Serializer

**Files:**
- Modify: `src/pow_protocol.h`
- Modify: `src/pow_challenge.h`
- Modify: `src/pow_challenge.c`
- Modify: `tests/unit/test_challenge.c`

**Interfaces:**
- Consumes: `pow_b64url_encode()` from `src/pow_parse.h` and raw 32-byte nonce.
- Produces:

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

- [ ] **Step 1: Add failing table-driven serializer tests**

Add `test_challenge_serialize()` to `tests/unit/test_challenge.c`. Its table
must contain these exact cases:

```c
static const struct {
    uint8_t      difficulty;
    uint64_t     bucket;
    const char  *wire;
    size_t       difficulty_offset;
    size_t       difficulty_len;
    size_t       bucket_offset;
    size_t       bucket_len;
    size_t       nonce_offset;
} cases[] = {
    { 1, UINT64_C(0),
      "v=1; d=1; b=0; n=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      7, 1, 12, 1, 17 },
    { 20, UINT64_C(29333333),
      "v=1; d=20; b=29333333; n=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      7, 2, 13, 8, 25 },
    { 32, UINT64_MAX,
      "v=1; d=32; b=18446744073709551615; n=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      7, 2, 13, 20, 37 }
};
```

For every row, use an all-zero nonce, assert exact bytes and length, assert
all returned offsets/lengths, and assert `nonce_len == 43`. Add rejection
rows for difficulty `0`, difficulty `33`, each null argument, and capacities
from zero through one byte below the required size. Pre-fill `out` with
nonzero bytes and document in the test that it is unusable after a `0` result
rather than requiring zeroization.

- [ ] **Step 2: Run the focused test and observe the missing interface**

```bash
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  make build/tests/test_challenge
```

Expected: compilation fails because `pow_challenge_text_t` and
`pow_challenge_serialize()` do not exist.

- [ ] **Step 3: Define the protocol constants and public type**

Add named literals and size formulas to `src/pow_protocol.h`; use these names
instead of spelling any separator in the serializer or module:

```c
#define POW_CHALLENGE_HEADER_NAME          "PowGate-Challenge"
#define POW_CHALLENGE_VERSION_PREFIX       "v=" POW_VERSION_TEXT "; d="
#define POW_CHALLENGE_VERSION_PREFIX_LEN   7
#define POW_CHALLENGE_BUCKET_PREFIX        "; b="
#define POW_CHALLENGE_BUCKET_PREFIX_LEN    4
#define POW_CHALLENGE_NONCE_PREFIX         "; n="
#define POW_CHALLENGE_NONCE_PREFIX_LEN     4
#define POW_NONCE_B64URL_LEN               43
#define POW_DIFFICULTY_DECIMAL_MAX_LEN     2
#define POW_CHALLENGE_WIRE_MAX_LEN         80
```

Put the exact public type and declaration from the Interfaces block in
`src/pow_challenge.h`.

- [ ] **Step 4: Implement a capacity-first serializer**

In `src/pow_challenge.c`, add a private decimal-length helper and writer that
operate on `uint64_t`. The serializer must:

```c
if (difficulty < POW_DIFFICULTY_MIN
    || difficulty > POW_DIFFICULTY_MAX
    || nonce == NULL || buf == NULL || out == NULL)
{
    return 0;
}

difficulty_len = pow_u64_decimal_len(difficulty);
bucket_len = pow_u64_decimal_len(bucket);
required = POW_CHALLENGE_VERSION_PREFIX_LEN + difficulty_len
    + POW_CHALLENGE_BUCKET_PREFIX_LEN + bucket_len
    + POW_CHALLENGE_NONCE_PREFIX_LEN + POW_NONCE_B64URL_LEN;

if (buf_cap < required) {
    return 0;
}
```

Only after the full capacity check, pointer-walk the fixed prefixes, decimal
fields, and `pow_b64url_encode(nonce, POW_NONCE_LEN, ...)`. Fill a local
`pow_challenge_text_t result`, assign `*out = result` only after the encoder
returns exactly `POW_NONCE_B64URL_LEN`, and return `1`. Do not use `snprintf`,
division on signed values, allocation, or NGINX headers.

- [ ] **Step 5: Run focused unit and coverage checks**

```bash
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie sh -lc \
  'make test-unit && make test-coverage && make check-policy'
```

Expected: every unit binary prints `PASS`, parser coverage remains complete,
and policy prints `OK`.

- [ ] **Step 6: Commit the serializer**

```bash
git add src/pow_protocol.h src/pow_challenge.h src/pow_challenge.c \
  tests/unit/test_challenge.c
git commit -m "feat: serialize canonical challenges"
```

---

### Task 3: Compile the Immutable Challenge Page

**Files:**
- Create: `html/challenge.html`
- Create: `tools/build_pow_challenge.py`
- Create: `tests/tools/test_build_pow_challenge.py`
- Modify: `src/pow_protocol.h`
- Modify: `config`
- Modify: `Makefile`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: literal `<!-- POW:PARAMS -->` and exact `<script>...</script>` bytes.
- Produces: `build/generated/pow_challenge_page.h` defining
  `ngx_http_pow_challenge_prefix`, `ngx_http_pow_challenge_prefix_len`,
  `ngx_http_pow_challenge_suffix`, `ngx_http_pow_challenge_suffix_len`,
  `ngx_http_pow_script_sha256_base64`, and its 44-byte length.

- [ ] **Step 1: Write generator tests before the generator**

Use `unittest`, `tempfile`, `hashlib`, `base64`, and `subprocess` only. The
success fixture must be byte-exact:

```python
VALID = (
    b"<!doctype html>\n<!-- POW:PARAMS -->\n"
    b"<script>/* PowGate placeholder script v1 */\nvoid 0;\n</script>\n"
)
SCRIPT = b"/* PowGate placeholder script v1 */\nvoid 0;\n"
```

Assert that generated arrays reconstruct `VALID` with only the marker
removed, that the emitted digest equals
`base64.b64encode(hashlib.sha256(SCRIPT).digest())`, that it ends in `=`,
that the generated warning is first, and that two runs are byte-identical.
Add named rejection tests for empty input, BOM, NUL, invalid UTF-8, 15 KiB or
larger input, zero/two markers, zero/two scripts, `<SCRIPT>`, `<script >`,
`<script src="x">`, missing close tag, and an empty script body.

- [ ] **Step 2: Run the generator tests and observe the missing program**

```bash
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  python3 -m unittest -v tests.tools.test_build_pow_challenge
```

Expected: failures report that `tools/build_pow_challenge.py` is absent.

- [ ] **Step 3: Add the exact Phase 3 HTML template**

Create a small semantic page with this mandatory shape:

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Checking your connection</title>
<style>
:root { color-scheme: light dark; font-family: system-ui, sans-serif; }
body { display: grid; min-height: 100vh; margin: 0; place-items: center; }
main { max-width: 32rem; padding: 2rem; text-align: center; }
</style>
</head>
<body>
<main><h1>Checking your connection</h1><p>Please wait.</p></main>
<!-- POW:PARAMS -->
<script>/* PowGate placeholder script v1 */
void 0;
</script>
</body>
</html>
```

Keep one exact marker, one exact unattributed lowercase `<script>`, one close
tag, no external resource, and the exact inert script bytes shown in the
test. The CSS may style only the listed static elements and must keep the
whole file below 15 KiB.

- [ ] **Step 4: Implement the byte-oriented compiler**

`tools/build_pow_challenge.py INPUT OUTPUT` must read with `Path.read_bytes()`,
validate all constraints before writing, split once at
`b"<!-- POW:PARAMS -->"`, locate exact script delimiters, hash only the bytes
between them, and emit C arrays using deterministic lowercase `0xNN` bytes.
Start output exactly with:

```c
/*
 * Generated by tools/build_pow_challenge.py.
 * Do not edit manually.
 */
```

Write to a sibling temporary file and `os.replace()` it only after complete
generation. On validation failure, print one fixed diagnostic to stderr,
exit nonzero, and leave an existing output unchanged.

- [ ] **Step 5: Add the versioned CSP template**

Define it once in `src/pow_protocol.h` with one marker:

```c
#define POW_CSP_HASH_MARKER             "<H>"
#define POW_CSP_HASH_MARKER_LEN         3
#define POW_CSP_SCRIPT_HASH_LEN         44
#define POW_CSP_POLICY_TEMPLATE         \
    "default-src 'none'; base-uri 'none'; form-action 'none'; " \
    "frame-ancestors 'none'; script-src 'sha256-" \
    POW_CSP_HASH_MARKER "'; " \
    "style-src 'unsafe-inline'"
```

Also define exact JSON wrapper literals, maximum JSON length, content type,
and the three HTML response header names/values in this file. Build the JSON
version literal from `POW_VERSION_TEXT`; do not duplicate the byte `"1"`.
The module will copy the serializer's digit/base64 spans between these fixed
literals; Python must not duplicate challenge-field formatting.

- [ ] **Step 6: Wire deterministic generation into every build**

Add a `challenge-page` phony target and this dependency shape to `Makefile`:

```make
GENERATED_DIR := build/generated
CHALLENGE_HEADER := $(GENERATED_DIR)/pow_challenge_page.h

$(CHALLENGE_HEADER): html/challenge.html tools/build_pow_challenge.py
	@mkdir -p $(@D)
	python3 tools/build_pow_challenge.py $< $@

challenge-page: $(CHALLENGE_HEADER)
module: $(CHALLENGE_HEADER)
test-tools:
	python3 -m unittest -v tests.tools.test_build_pow_challenge
```

Make `check` depend on `test-tools`. Add
`ngx_module_incs="$ngx_addon_dir/build/generated"` to `config`. The generated
module input always lives at this one fixed repository-relative location;
`BUILD_DIR` continues to select disposable unit/fuzz outputs only. Extend
`clean` to remove `build/generated`, and keep `build/` ignored.

- [ ] **Step 7: Verify success, rejection, and reproducibility**

```bash
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie sh -lc '
    make clean
    make test-tools challenge-page
    cp build/generated/pow_challenge_page.h /tmp/page.h
    rm build/generated/pow_challenge_page.h
    make challenge-page
    cmp /tmp/page.h build/generated/pow_challenge_page.h
    make module
    make check-policy
  '
```

Expected: tests pass, `cmp` is silent, the generated warning is present, the
module builds, and policy is OK.

- [ ] **Step 8: Commit the page pipeline**

```bash
git add html/challenge.html tools/build_pow_challenge.py \
  tests/tools/test_build_pow_challenge.py src/pow_protocol.h config \
  Makefile .gitignore
git commit -m "build: compile immutable challenge page"
```

---

### Task 4: Add the Narrow HTTPS Test Harness

**Files:**
- Create: `tests/integration/lib/PowGate/TestHTTPS.pm`
- Create: `tests/integration/pow_https.t`
- Modify: `tests/integration/lib/PowGate/TestNginx.pm`
- Modify: `tests/integration/pow_reload.t`
- Delete: `tests/integration/pow_module.t`

**Interfaces:**
- Consumes: runtime hashes from `start_nginx()` and pinned `openssl`/`curl`.
- Produces:

```perl
generate_tls_fixture($prefix) -> { certificate => $path, key => $path }
https_request($runtime, protocol => '1.1'|'2', method => $method,
    path => $raw_path, headers => \@pairs, body => $bytes,
    unix_socket => $optional_path) -> {
        status => $integer, protocol => '1.1'|'2', headers => \%multimap,
        body => $bytes, num_connects => $integer, local_port => $integer
    }
https_sequence($runtime, protocol => '1.1'|'2', requests => \@requests)
    -> \@responses
```

- [ ] **Step 1: Write failing helper-contract tests**

Create `pow_https.t` with a `pow off` TLS server and assertions for both
protocols. Each subtest must assert status `200`, exact body, and exact
reported protocol. Add a two-request sequence asserting response count `2`,
the second transfer's `num_connects == 0`, and equal nonzero `local_port`.
Assert fixture modes are `0600` for the key and `0644` for the certificate,
and assert the runtime prefix and both TLS files disappear after
`stop_nginx()`.

- [ ] **Step 2: Run the focused test and observe the missing helper**

```bash
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie sh -lc \
  'make module && prove -Itests/integration/lib -v tests/integration/pow_https.t'
```

Expected: Perl fails to load `PowGate::TestHTTPS`.

- [ ] **Step 3: Implement isolated P-256 certificate generation**

Use safe list-form process execution for this exact OpenSSL operation:

```text
openssl req -x509 -newkey ec
  -pkeyopt ec_paramgen_curve:P-256
  -sha256 -nodes -days 1
  -subj /CN=localhost
  -addext subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1
  -keyout <prefix>/conf/powgate-test.key
  -out <prefix>/conf/powgate-test.crt
```

Bound captured output to 64 KiB, require exit `0`, chmod the final modes, and
return absolute paths. Never write outside the runtime prefix or change a
trust store.

- [ ] **Step 4: Implement bounded curl requests**

Build curl as an argument vector with all of these fixed controls:

```text
--silent --show-error --insecure --max-time 5 --path-as-is
--http1.1 | --http2
--request <METHOD>
--dump-header <prefix temp file>
--output <prefix temp file>
--write-out %{http_version}\n%{http_code}\n%{num_connects}\n%{local_port}\n
https://localhost:<port><raw path>
```

Pass each header as its own `--header` argument so repeated `Accept` values
remain separate. Parse headers as bytes into a lowercase-name multimap while
preserving occurrence order. Handle interim `100 Continue` blocks and return
only the final response block. Reject CR, LF, or NUL in caller-supplied method,
path, or headers. Apply a bounded wall-clock timeout and bounded output.

For `https_sequence()`, place transfers in one curl invocation separated by
`--next`, repeat the fixed TLS/protocol controls after each `--next`, and
return one metadata/body/header record per transfer. Assert requested versus
reported protocol inside the helper, so callers cannot accidentally claim H2
coverage after H1 negotiation.

- [ ] **Step 5: Extend runtime metadata without weakening lifecycle safety**

Allow `start_nginx()` callers to attach `tls` and `unix_socket` metadata to
the owned runtime hash through the existing callbacks. Do not make the HTTPS
helper start or stop NGINX. Preserve process-group ownership checks, bounded
startup, bounded shutdown, and prefix removal exactly.

- [ ] **Step 6: Move existing request probes to HTTPS**

Replace the plaintext Test::Nginx `pow_module.t` smoke with equivalent
`pow off` and exemption coverage in `pow_https.t`, then delete
`pow_module.t`. In `pow_reload.t`, generate the TLS fixture in each prefix,
configure:

```nginx
server {
    listen 127.0.0.1:<port> ssl;
    http2 on;
    ssl_certificate <certificate>;
    ssl_certificate_key <key>;
    location / { pow off; return 200 "generation\n"; }
}
```

Replace `wait_for_http()` response probes with `https_request()` and assert
both protocols wherever the test observes request behavior. Keep reload
signals, generation checks, failed-reload checks, and process ownership
unchanged.

- [ ] **Step 7: Run the HTTPS and reload tests**

```bash
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie sh -lc '
    make module
    prove -Itests/integration/lib -v \
      tests/integration/pow_https.t tests/integration/pow_reload.t
    make check-policy
  '
```

Expected: each protocol subtest reports the requested negotiated version,
connection reuse is proven, reload behavior is unchanged, and policy is OK.

- [ ] **Step 8: Commit the HTTPS harness**

```bash
git add tests/integration/lib/PowGate/TestHTTPS.pm \
  tests/integration/lib/PowGate/TestNginx.pm \
  tests/integration/pow_https.t tests/integration/pow_reload.t \
  tests/integration/pow_module.t
git commit -m "test: require HTTPS request integration"
```

---

### Task 5: Implement Identity, Exemptions, and Bare Challenges

**Files:**
- Create: `tests/integration/pow_challenge.t`
- Modify: `src/ngx_http_pow_module.c`
- Modify: `src/ngx_http_pow_module.h`
- Modify: `tests/integration/lib/PowGate/TestHTTPS.pm`

**Interfaces:**
- Consumes: merged main/location configs, `ngx_cidr_match()`, canonical pure
  IP helpers, nonce derivation, and canonical serializer.
- Produces: protected non-navigation `403` responses and exemption
  `NGX_DECLINED` behavior.

- [ ] **Step 1: Write the failing bare-challenge matrix**

For each case, run both protocol values `1.1` and `2`:

```text
GET with no Accept                    -> 403, empty body, one challenge header
GET with Accept: */*                  -> 403, empty body, one challenge header
POST with Accept: text/html           -> 403, empty body, one challenge header
GET with __pow and __pow_p cookies    -> 403; cookies do not bypass Phase 3
pow off                               -> configured content handler returns 200
IPv4 exempt CIDR                      -> content handler returns 200
IPv6 exempt CIDR                      -> content handler returns 200
nonmatching CIDR                      -> 403
/ exact path exemption                -> 200 for every path
/api path exemption                   -> /api and /api/v1 200, /apiv2 403
query-only difference                 -> same path result
/%73tatic                              -> /static exemption returns 200
/static/../admin with --path-as-is     -> normalized /admin returns 403
merge_slashes on/off                  -> results follow r->uri behavior
```

Parse the challenge header with one strict test regex and assert fixed field
order, difficulty `20`, bucket decimal grammar, and 43-character base64url
nonce. Do not accept extra spaces, padding, duplicate keys, or extra fields.

- [ ] **Step 2: Run the matrix and observe pass-through failures**

```bash
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie sh -lc \
  'make module && prove -Itests/integration/lib -v tests/integration/pow_challenge.t'
```

Expected: protected cases return the configured content response instead of
`403` because the access handler still always declines.

- [ ] **Step 3: Add request-private helper boundaries**

Declare these `static` functions in `ngx_http_pow_module.c` and keep them out
of the public header unless a later file truly consumes them:

```c
static ngx_int_t ngx_http_pow_client_identity(ngx_http_request_t *r,
    ngx_http_pow_loc_conf_t *plcf, ngx_uint_t address_kind,
    uint8_t ip16[POW_IP_LEN], uint8_t *plen);
static ngx_int_t ngx_http_pow_connection_kind(ngx_http_request_t *r,
    ngx_uint_t *address_kind);
static ngx_int_t ngx_http_pow_ip_exempt(ngx_http_request_t *r,
    ngx_http_pow_loc_conf_t *plcf);
static ngx_int_t ngx_http_pow_path_exempt(ngx_http_request_t *r,
    ngx_http_pow_loc_conf_t *plcf);
static ngx_int_t ngx_http_pow_issue_bare(ngx_http_request_t *r,
    const uint8_t *challenge, size_t challenge_len);
```

Use `ngx_http_get_module_main_conf()` for secrets and loc conf for all policy.
Define private `NGX_HTTP_POW_ADDR_IPV4` and `NGX_HTTP_POW_ADDR_IPV6` values.
Follow the exact state-machine order in the approved design: classify the
family, reject unsupported families, check IP exemptions, check path
exemptions, and only then construct the canonical identity.

- [ ] **Step 4: Implement address classification and exemptions**

For `AF_INET`, pass `sin_addr` bytes to `pow_ip16_from_ipv4()` and set plen to
`96 + plcf->bind_ipv4`. For `AF_INET6`, use `IN6_IS_ADDR_V4MAPPED()` to select
the IPv4 rule; otherwise copy all 16 bytes and use `plcf->bind_ipv6`. Call
`pow_ip16_mask()` before derivation.

Call `ngx_cidr_match(r->connection->sockaddr, plcf->exempt_ips)` directly.
Treat `NGX_OK` as exempt, `NGX_DECLINED` as not exempt, and any other value as
an internal error. Compare each configured path to `r->uri` by explicit
length: `/` matches all; otherwise exact length or the next byte `/` is
required. Never inspect `r->unparsed_uri` or `r->args`.

For every other family, log only:

```c
ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
              "pow_gate: unsupported connection address family %d, "
              "request rejected", family);
```

and return `NGX_HTTP_INTERNAL_SERVER_ERROR` before exemption checks.

- [ ] **Step 5: Derive and format the challenge**

After exemptions, reject negative `ngx_time()`, divide its unsigned value by
the validated positive window, derive with `pmcf->secret`, and serialize into
a fixed `uint8_t challenge[POW_CHALLENGE_WIRE_MAX_LEN]`. Any impossible
failure logs a fixed operation/verdict and returns `500` without request data.

- [ ] **Step 6: Implement the transactional bare `403`**

Call `ngx_http_discard_request_body()` before any response commit. Allocate a
pool copy of the challenge, reserve one `ngx_table_elt_t`, immediately set
`hash = 0`, then fill:

```c
ngx_str_set(&header->key, POW_CHALLENGE_HEADER_NAME);
header->value.data = challenge_copy;
header->value.len = challenge_len;
r->headers_out.status = NGX_HTTP_FORBIDDEN;
r->headers_out.content_length_n = 0;
header->hash = 1;
```

Send headers, finalize once with the returned status, and return `NGX_DONE`.
Do not return raw `NGX_HTTP_FORBIDDEN`, because that invokes special-response
and `error_page` processing.

- [ ] **Step 7: Verify the bare matrix and policy**

```bash
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie sh -lc '
    make test-unit
    make module
    prove -Itests/integration/lib -v tests/integration/pow_challenge.t
    make check-policy
  '
```

Expected: both protocols pass every bare/exemption row; no test accepts an
unasserted protocol.

- [ ] **Step 8: Commit identity and the bare branch**

```bash
git add src/ngx_http_pow_module.c src/ngx_http_pow_module.h \
  tests/integration/pow_challenge.t \
  tests/integration/lib/PowGate/TestHTTPS.pm
git commit -m "feat: issue bare deterministic challenges"
```

---

### Task 6: Implement the Exact HTML Challenge Transaction

**Files:**
- Modify: `src/ngx_http_pow_module.c`
- Modify: `tests/integration/pow_challenge.t`
- Modify: `tests/tools/test_build_pow_challenge.py`

**Interfaces:**
- Consumes: canonical serializer spans and generated page prefix/suffix/digest.
- Produces: exact navigational `503` with immutable template bytes and
  versioned CSP.

- [ ] **Step 1: Add failing navigation and exact-byte tests**

Run each row under both protocols:

```text
GET  + Accept text/html                         -> HTML 503
HEAD + Accept text/html                         -> same headers/length, no body
GET  + Accept TeXt/HtMl                         -> HTML 503
GET  + first Accept nonmatch, second text/html  -> HTML 503
POST + Accept text/html                         -> bare 403
GET  + absent/nonmatching/wildcard Accept       -> bare 403
```

For HTML, assert exact status, content type, `Cache-Control: no-store`,
`X-Robots-Tag: noindex`, one CSP, and exact content length. Reconstruct
expected body from the checked-in template split at `<!-- POW:PARAMS -->`
plus this data block:

```text
<script type="application/json" id="pow-params">{"v":1,"d":20,"b":"<bucket>","n":"<nonce>"}</script>
```

Extract the served executable script bytes, independently calculate
`sha256` plus padded standard base64 in Perl, and assert the exact CSP hash.
Assert the JSON difficulty, bucket, and nonce equal the spans from the bare
challenge response obtained in the same bucket.

- [ ] **Step 2: Run and observe that navigations still receive `403`**

```bash
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie sh -lc \
  'make module && prove -Itests/integration/lib -v tests/integration/pow_challenge.t'
```

Expected: all navigation rows fail with status `403`.

- [ ] **Step 3: Implement linked `Accept` navigation detection**

Require `NGX_HTTP_GET` or `NGX_HTTP_HEAD`. Walk
`r->headers_in.accept` followed by each `header->next`, and perform a bounded
case-insensitive substring scan for `text/html` over `header->value.data` and
`header->value.len`. Do not NUL-terminate, parse quality factors, or treat
`*/*` as HTML.

- [ ] **Step 4: Build JSON from serializer spans only**

Precompute exact JSON length from fixed literals and
`pow_challenge_text_t`. Allocate once from `r->pool`, then pointer-walk:

```text
POW_JSON_PREFIX
difficulty span
POW_JSON_BUCKET_PREFIX
bucket span
POW_JSON_NONCE_PREFIX
nonce span
POW_JSON_SUFFIX
```

Verify the final pointer equals the allocated end. Do not call a JSON library,
decimal formatter, base64 encoder, or escaping routine.

- [ ] **Step 5: Assemble the CSP from its one template marker**

Find the single `<H>` in `POW_CSP_POLICY_TEMPLATE` using bounded compile-time
lengths, allocate exact policy length, and copy template prefix, generated
44-byte digest, and template suffix. Treat zero or multiple markers as a
build/programming error caught by tests; do not silently emit a weaker CSP.

- [ ] **Step 6: Reserve and populate the complete response transaction**

Before setting `r->headers_out.status`, allocate JSON, three `ngx_buf_t`
objects and three `ngx_chain_t` links, the CSP value, and reserve list entries
for `Cache-Control`, `X-Robots-Tag`, and `Content-Security-Policy`. Set every
reserved header's `hash = 0` immediately.

Point the chain at immutable generated prefix, pool JSON, and immutable
generated suffix. Mark only the final buffer `last_buf = 1` and
`last_in_chain = 1`. Then set:

```c
r->headers_out.status = NGX_HTTP_SERVICE_UNAVAILABLE;
ngx_str_set(&r->headers_out.content_type, "text/html; charset=utf-8");
r->headers_out.content_length_n = prefix_len + json_len + suffix_len;
r->allow_ranges = 0;
```

Clear ETag/Last-Modified fields using the pinned 1.30.3 precedent, populate
the three headers, set their hashes to `1` only after all values are complete,
send headers, skip the output filter when `r->header_only`, otherwise send the
chain, finalize exactly once, and return `NGX_DONE`.

- [ ] **Step 7: Verify exact delivery and immutable bytes**

```bash
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie sh -lc '
    make test-tools test-unit module
    prove -Itests/integration/lib -v tests/integration/pow_challenge.t
    make check-policy
  '
```

Expected: H1 and H2 receive byte-identical logical bodies and challenges;
HEAD has the GET content length and zero body; CSP recomputation succeeds.

- [ ] **Step 8: Commit the navigation branch**

```bash
git add src/ngx_http_pow_module.c tests/integration/pow_challenge.t \
  tests/tools/test_build_pow_challenge.py
git commit -m "feat: serve exact HTML challenges"
```

---

### Task 7: Prove Determinism, Address Binding, and Fail-Closed Identity

**Files:**
- Modify: `tests/integration/pow_challenge.t`
- Modify: `tests/integration/lib/PowGate/TestHTTPS.pm`
- Modify: `src/ngx_http_pow_module.c`

**Interfaces:**
- Consumes: known secret, observed challenge fields, RealIP module, IPv4,
  IPv6, mapped IPv6, and Unix TLS listeners.
- Produces: independent evidence that every challenge is derived from the
  documented identity and current bucket.

- [ ] **Step 1: Add independent nonce reproduction**

In Perl test code, decode the known 32-byte hex secret and use a standard
HMAC-SHA256 implementation to calculate:

```text
"PGv1-chal" || ip16(16) || plen(1) || bucket(8, big endian)
```

Base64url-encode without padding and compare with the response. Accept only
the response bucket observed from the server; do not predict wall-clock
timing in the test. Add same-bucket repeated-request equality and cross-H1/H2
equality assertions.

- [ ] **Step 2: Add all address forms**

Create isolated listeners for IPv4 loopback, native IPv6 loopback, and an
IPv4-mapped IPv6 connection where the platform exposes it. Assert IPv4 uses
mapped ip16 plus `96 + pow_bind_ipv4`, native IPv6 uses `pow_bind_ipv6`, and
mapped IPv6 follows the IPv4 configuration. If the container kernel lacks
mapped-listener support, fail the golden-environment test instead of silently
skipping it.

- [ ] **Step 3: Add trusted RealIP ordering tests**

Configure `set_real_ip_from 127.0.0.1; real_ip_header X-Forwarded-For;` and
send a fixed address. Assert both nonce identity and CIDR exemption use the
rewritten address. Send the same header without a trusted source declaration
and assert it has no effect.

- [ ] **Step 4: Add Unix-listener fail-closed tests**

Configure a TLS Unix listener under the runtime prefix and use curl's
`--unix-socket` with both forced protocols. Assert status `500`, absence of
all PowGate response headers, and an error-log line containing only the fixed
unsupported-family diagnostic and numeric family. Assert the known URI,
header sentinel, secret, nonce label, and cookie sentinel are absent from the
log.

- [ ] **Step 5: Run identity tests twice across a bucket-safe window**

```bash
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie sh -lc '
    make module
    prove -Itests/integration/lib -v tests/integration/pow_challenge.t
    prove -Itests/integration/lib -v tests/integration/pow_challenge.t
  '
```

Expected: both runs independently reproduce every nonce; no timing-based
flake appears near a bucket boundary because tests use the returned bucket.

- [ ] **Step 6: Commit identity verification**

```bash
git add src/ngx_http_pow_module.c tests/integration/pow_challenge.t \
  tests/integration/lib/PowGate/TestHTTPS.pm
git commit -m "test: verify challenge identity binding"
```

---

### Task 8: Prove Body, Finalization, and NGINX Composition Behavior

**Files:**
- Create: `tests/integration/pow_challenge_composition.t`
- Modify: `tests/integration/lib/PowGate/TestHTTPS.pm`
- Modify: `src/ngx_http_pow_module.c`

**Interfaces:**
- Consumes: complete challenge handler and multi-transfer HTTPS helper.
- Produces: lifecycle and public-response contract tests around NGINX filters,
  subrequests, internal redirects, and persistent connections.

- [ ] **Step 1: Add request-body persistence tests**

For H1 and H2, challenge fixed-length POST bodies and then issue a second GET
through the same curl invocation. Assert the second transfer has
`num_connects == 0`, uses the same local port, negotiates the requested
protocol, and receives a complete response. Add H1 chunked upload, H2 data
body, and `Expect: 100-continue`; each must complete within the helper's five
second deadline and leave the connection/session reusable.

- [ ] **Step 2: Add response override and metadata tests**

For both protocols assert:

```text
Range request                    -> never 206
If-Modified-Since / If-None-Match -> never 304
error_page 403 target            -> bare PowGate 403 remains
error_page 503 target            -> PowGate HTML 503 remains
HEAD navigation                 -> correct Content-Length, no body
```

Assert absence of `Accept-Ranges`, ETag, and Last-Modified on HTML challenges.

- [ ] **Step 3: Add subrequest and internal-redirect tests**

Enable SSI in a content location whose main request is exempt/disabled and
whose included URI has `pow on`; assert the subrequest reaches its configured
content rather than receiving a challenge. Configure an internal
`error_page` redirect into a `pow on` location and assert the internal request
is not challenged. Keep the externally initiated request tests protected so
the bypass cannot be mistaken for a general location exemption.

- [ ] **Step 4: Add CSP intersection tests**

Run one HTML response with:

```nginx
add_header Content-Security-Policy "object-src 'none'" always;
```

and assert two CSP occurrences. Run another without `always` and assert only
PowGate's CSP on status `503`. Never merge the policies in module code.

- [ ] **Step 5: Enforce a response-header allowlist**

Normalize headers into a multimap and define branch-specific allowed names.
Allow standard NGINX transport fields (`server`, `date`, `content-length`,
and protocol-required connection metadata) plus only the documented PowGate
fields. Reject unknown `powgate-*`, debug/internal headers, duplicate
module-owned headers, and the known secret hex in any header name or value.
The `always` case is the sole permitted duplicate CSP scenario.

- [ ] **Step 6: Run composition tests and inspect logs**

```bash
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie sh -lc '
    make module
    prove -Itests/integration/lib -v \
      tests/integration/pow_challenge_composition.t
    make check-policy
  '
```

Expected: all persistence and composition tests pass for asserted H1/H2, and
normal challenge issuance adds no error-log entry.

- [ ] **Step 7: Commit lifecycle coverage**

```bash
git add src/ngx_http_pow_module.c \
  tests/integration/lib/PowGate/TestHTTPS.pm \
  tests/integration/pow_challenge_composition.t
git commit -m "test: cover challenge response lifecycle"
```

---

### Task 9: Make Sanitized and E2E Paths Protocol-Equivalent

**Files:**
- Modify: `tools/run-asan.sh`
- Modify: `Makefile`
- Modify: `tests/e2e/smoke.mjs`
- Modify: `tools/check-policy.sh`

**Interfaces:**
- Consumes: complete normal integration matrix and generated page header.
- Produces: the same production module/runtime behavior under ASan+UBSan and
  an HTTPS Node smoke ready for Phase 4B solver work.

- [ ] **Step 1: Add preflight failures for required HTTPS capabilities**

Before integration, assert `openssl` is available, `curl --version` lists
`HTTP2`, installed NGINX reports SSL and HTTP/2 build support, and the pinned
source exists. These are hard failures in the golden image, never `SKIP`.

- [ ] **Step 2: Enable SSL and HTTP/2 in instrumented NGINX**

Add both flags to the existing sanitized configure command:

```text
--with-http_ssl_module
--with-http_v2_module
```

Generate `build/generated/pow_challenge_page.h` before sanitized configure,
and ensure the add-on include path resolves the same generated bytes as the
normal build. Continue compiling the production source with only compiler and
linker instrumentation changed.

- [ ] **Step 3: Make ASan run the complete integration suite**

Keep `prove -Itests/integration/lib -v tests/integration/*.t` as the one suite
selector. Preserve bounded sanitizer-log collection and fail when either the
test status or any sanitizer log is nonzero. Do not create sanitizer-only
functional branches or omit HTTP/2 cases.

- [ ] **Step 4: Move the Node smoke to ephemeral HTTPS**

Replace `node:http` frontend calls with `node:https`. Generate a P-256 test
certificate/key inside the Node runtime prefix by spawning pinned OpenSSL as
an argument vector. Configure `listen ... ssl; http2 on;`, but make the Node
smoke explicitly request HTTPS/HTTP/1.1 with an agent containing
`rejectUnauthorized: false`. Assert the protected navigation now returns
`503`, exact HTML content type, the fixed CSP, and the inert script; do not
execute proof work in Phase 3.

- [ ] **Step 5: Reconcile the policy comment with test-only TLS randomness**

Keep the production-source RNG ban and its existing grep unchanged. Update
only explanatory policy text so ephemeral certificate generation under
`tests/` is the documented exception and cannot weaken the `src/` scan. Run
`rg -n "RAND_bytes|rand|random" tools/check-policy.sh` and confirm the source
gate still rejects every listed RNG call.

- [ ] **Step 6: Run focused sanitized and E2E gates**

```bash
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie sh -lc '
    make test-e2e
    make asan
    make check-policy
  '
```

Expected: Node validates HTTPS H1 behavior, the complete H1/H2 integration
suite passes under ASan+UBSan, no sanitizer log is produced, and policy is OK.

- [ ] **Step 7: Commit equivalent build paths**

```bash
git add tools/run-asan.sh Makefile tests/e2e/smoke.mjs \
  tools/check-policy.sh
git commit -m "test: sanitize HTTPS challenge paths"
```

---

### Task 10: Publish Accurate Phase 3 Operator Documentation

**Files:**
- Modify: `docs/configuration.md`
- Modify: `docs/security.md`
- Modify: `README.md`
- Modify: `docs/nginx-style.md` only if implementation introduced a reusable response-helper convention not already covered by AGENTS.md.

**Interfaces:**
- Consumes: verified behavior from Tasks 5–9.
- Produces: operator-facing documentation that describes only implemented
  behavior and enduring contributor guidance.

- [ ] **Step 1: Update configuration behavior**

Change Phase 2/pass-through wording to state runtime exemptions and challenge
issuance are implemented. Document exact IP-before-path order, post-RealIP
identity, normalized `r->uri`, unsupported Unix/other families returning
`500`, HTTPS deployment, and the two challenge branches.

Document CSP composition precisely:

```text
PowGate always emits its own CSP. An operator `add_header` policy intersects
with it in browsers. On a 503 response, NGINX adds that operator header only
when the directive uses `always`; PowGate never merges or weakens it.
```

State that the current script is intentionally inert and Phase 4B supplies
the solver without changing the delivery pipeline.

- [ ] **Step 2: Update the security boundary**

Document deterministic challenge exposure, fail-closed unknown identity,
absence of per-request challenge logs, no cookie/proof acceptance yet, exact
header surface, and why request bodies are discarded before final response.
Do not claim abuse protection is complete until proof verification exists.

- [ ] **Step 3: Make README status honest**

Keep the long-term product overview, but add an implementation-status section
that says Phase 3 issues deterministic challenges and that browser solving,
proof verification, and authentication cookies remain subsequent phases.
Update the quick example to HTTPS and retain the warning that network-layer
volumetric protection remains external.

- [ ] **Step 4: Check documentation against executable behavior**

```bash
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie sh -lc '
    rg -n "Phase 2|pass-through|HTTP-only|challenge issuance.*info" \
      README.md docs PLAN.md
    make check-policy
    make test-integration
  '
```

Expected: any remaining Phase 2 references are historical and accurate, no
plaintext/request-logging claim remains, policy is OK, and integration passes.

- [ ] **Step 5: Commit operator documentation**

```bash
git add docs/configuration.md docs/security.md README.md
test ! -n "$(git diff -- docs/nginx-style.md)" || git add docs/nginx-style.md
git commit -m "docs: document challenge issuance"
```

---

### Task 11: Run the Complete Phase Gate and Audit the Diff

**Files:**
- Modify only files required to fix findings; do not add scope during this task.

**Interfaces:**
- Consumes: all Phase 3 tasks.
- Produces: release-quality evidence that Phase 3 is complete and the branch
  contains no unrelated or generated artifacts.

- [ ] **Step 1: Start from a clean build tree**

```bash
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie make clean
git status --short
```

Expected: only intentional tracked source/document changes exist; no generated
header, certificate, key, runtime prefix, sanitizer log, or module binary is
tracked.

- [ ] **Step 2: Run the authoritative completion gate**

```bash
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie make check
```

Expected: policy, tools, unit, coverage, module, full HTTPS H1/H2 integration,
HTTPS e2e, fuzz smoke, and ASan/UBSan all pass with no skip or placeholder.

- [ ] **Step 3: Repeat integration to catch lifecycle leakage**

```bash
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie sh -lc \
  'make test-integration && make test-integration'
```

Expected: both runs pass; no owned NGINX process, socket, certificate, or
prefix survives either run.

- [ ] **Step 4: Audit policy, protocol literals, and generated artifacts**

```bash
git diff --check
git status --short
rg -n "v=1; d=|PowGate-Challenge|POW:PARAMS|default-src 'none'" \
  src html tools docs PLAN.md
git ls-files build out '*.crt' '*.key' '*.so'
```

Expected: no whitespace errors; wire literals have only their sanctioned
source/test/documentation occurrences; the final command prints nothing.

- [ ] **Step 5: Review every terminal path**

Inspect `ngx_http_pow_handler()` and its response helpers against this finite
list and record the review in the commit message body if a fix is required:

```text
disabled/subrequest/internal/exempt -> NGX_DECLINED
completed bare or HTML challenge    -> finalize once, return NGX_DONE
unsupported/invalid/derive/allocate -> NGINX error path, no committed headers
discard failure                     -> propagate NGINX result, no commit
```

Expected: there is no `NGX_OK` allow path, raw `403`/`503` return that invokes
special responses, double finalization, or enabled header with incomplete
fields.

- [ ] **Step 6: Resolve findings in their owning task**

If verification finds a defect, return to the task that owns that file,
repeat its failing-test/minimal-fix/focused-test cycle, and use that task's
exact staging list. Rerun `make check` after the correction. If no correction
is required, do not create an empty commit.
