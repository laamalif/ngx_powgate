# Phase 2 Configuration and Secret Handling Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to
> implement this plan task-by-task.

**Goal:** Implement PowGate's complete configuration surface, passive
activation, bounded secret-file loading and rotation lifecycle, integration
test matrix, sanitizer coverage, and operator documentation without adding
challenge or cookie behavior.

**Architecture:** Keep request/module lifecycle code in
`src/ngx_http_pow_module.c`, place all NGINX configuration APIs in
`src/pow_config.c`, and share only module-internal structures through
`src/ngx_http_pow_module.h`. Standard NGINX 1.30.3 slots handle scalar and
string-array directives; custom code is limited to CIDR conversion and the
transactional descriptor-based secret loader. Configuration tests invoke the
real NGINX binary with isolated prefixes, while reload and sanitizer tests run
the same production source without diagnostic request paths.

**Tech Stack:** C99, NGINX 1.30.3 module APIs, OpenSSL-linked NGINX runtime,
Perl 5/Test::More/Test::Nginx, POSIX filesystem APIs through NGINX wrappers,
clang ASan+UBSan, GNU Make, Podman with
`localhost/ngx-powgate-dev:trixie`.

**Design source:**
`docs/superpowers/specs/2026-07-14-phase2-configuration-design.md`

## Execution rules

- Read `AGENTS.md`, `docs/protocol.md`, `docs/nginx-style.md`, and the design
  source before editing.
- Inspect the named pinned NGINX source precedent before each new NGINX API
  use. `NGX_SOURCE_DIR` inside the golden image is authoritative.
- Run every build and test inside the golden image. Never run `make`, a
  compiler, NGINX, Perl tests, or sanitizers directly on the host.
- Use this exact container shape for every command below:

  ```sh
  podman run --rm --userns=keep-id \
      -v "$PWD:/work:Z" -w /work \
      localhost/ngx-powgate-dev:trixie sh -lc '<command>'
  ```

- Keep the two existing untracked Codex-hook notes and local `.codex` hook
  untouched and out of every commit.
- Do not add a GitHub workflow, new dependency, secret-parser fuzzer,
  temporary directive, diagnostic header, fingerprint log, or alternate
  test-only request behavior.
- Each commit below must contain only the files named in its commit step.

---

### Task 1: Update the protocol specification first

**Files:**

- Modify: `docs/protocol.md`

**Step 1: Read the affected normative sections**

Inspect the `Secret`, `Client work`, `Challenge nonce`, proof verification,
and authentication-cookie sections. Confirm the current text still says
lowercase-only hex, default difficulty 17, and group/other readability.

Run:

```sh
rg -n "lowercase|default 17|group/other|Secret|difficulty|previous" \
    docs/protocol.md
```

Expected: the stale Phase 1 wording is found.

**Step 2: Apply the approved normative changes**

Change the secret contract to state:

```text
The file contains one or two 64-byte ASCII hexadecimal lines. Hex digits are
case-insensitive and may be mixed case. Line 1 is current: it derives every
new challenge nonce and signs every new authentication cookie. Line 2 is
previous and is verification-only. Both are accepted when verifying cookies
and submitted proofs.
```

Define the four accepted LF layouts and reject CRLF, whitespace, BOMs, blank
lines, and extra bytes. Replace the permission statement with the target-mode
rule: no group or other permission bits are allowed; ownership and owner bits
are unrestricted, and descriptor validation follows symlinks.

Change the protocol default difficulty from 17 to 20 and add operator guidance
that 20 through 22 is recommended while 1 through 32 remains valid.

Do not change any wire field, label, width, MAC input, vector, or protocol
version.

**Step 3: Verify internal consistency**

Run:

```sh
rg -n "default 17|lowercase hex|readable by group|readable.*other" \
    docs/protocol.md
```

Expected: no matches.

Run:

```sh
rg -n "default 20|20 through 22|case-insensitive|verification-only|group or other" \
    docs/protocol.md
```

Expected: every approved rule is present once in the relevant normative
section.

**Step 4: Commit the spec-only change**

```sh
git add docs/protocol.md
git commit -m "docs: refine phase two protocol defaults"
```

---

### Task 2: Reconcile project policy and the execution plan

**Files:**

- Modify: `PLAN.md`
- Modify: `AGENTS.md`

**Step 1: Add failing consistency searches to the work log**

Run:

```sh
rg -n 'default 17|lowercase hex|no group/other read|absent.*pow_secret_file|old-cookie validity|slashes merged|pow_\*\.c' \
    PLAN.md AGENTS.md
```

Expected: stale or overly broad rules are found.

**Step 2: Update Phase 2 in `PLAN.md`**

Make Phase 2 match the approved design exactly:

- default difficulty 20 and recommendation 20 through 22;
- case-insensitive secret hex and the four exact LF layouts;
- `NGX_FILE_RDONLY | NGX_FILE_NONBLOCK`, descriptor `fstat`, regular-file
  check, and `(mode & 0077) == 0`;
- current/previous roles and operator-managed atomic rotation;
- `effective_pow_enabled` accumulated during location merges;
- no `init_main_conf` requirement and no handler registration when inactive;
- standard scalar handlers, string-array handler for exempt paths, and custom
  handlers only for CIDR and secret file;
- standard replacement inheritance for exemption arrays;
- `r->uri` slash compression follows `merge_slashes` rather than always
  occurring;
- Phase 2 proves reload re-reading but defers behavioral inheritance to Phase
  3 and cryptographic rotation to Phase 4A;
- the five test categories and project-wide sanitizer policy.

Remove the Phase 2 gate's claim that it proves old-cookie validity.

**Step 3: Update enduring rules in `AGENTS.md`**

Narrow the broad `pow_*.c/.h` pure-core shorthand to the four named families:

```text
pow_parse, pow_crypto, pow_cookie, and pow_challenge
```

Strengthen the secret permission rule to no group/other bits, add nonblocking
open before descriptor validation, and add the approved sanitizer policy:

```text
- Every implemented integration category runs under ASan+UBSan before a
  release.
- Sanitizer findings block release.
- Sanitizer-specific functional paths are forbidden.
- Sanitized tests use production source with instrumentation only.
```

Do not change the rule permitting test-only fault injection that has no
production directive, request path, or release artifact.

**Step 4: Run policy and consistency checks**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc 'make check-policy'
```

Expected: `check-policy: OK`.

Run:

```sh
rg -n 'default 17|lowercase hex|no group/other read|old-cookie validity.*Phase 2|pow_\*\.c/.h' \
    PLAN.md AGENTS.md
```

Expected: no stale normative matches.

**Step 5: Commit policy alignment**

```sh
git add PLAN.md AGENTS.md
git commit -m "docs: align phase two configuration policy"
```

---

### Task 3: Add a reusable real-NGINX configuration-test harness

**Files:**

- Create: `tests/integration/lib/PowGate/TestNginx.pm`
- Create: `tests/integration/pow_config.t`
- Modify: `Makefile`

**Step 1: Inspect the installed Test::Nginx and NGINX command precedents**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc \
    '/usr/sbin/nginx -V; perl -MTest::Nginx::Socket -e "print \$Test::Nginx::Socket::VERSION, qq(\\n)"'
```

Expected: nginx 1.30.3 and Test::Nginx 0.32.

**Step 2: Implement the isolated test helper**

Create a small `PowGate::TestNginx` module exporting:

```perl
our @EXPORT_OK = qw(
    atomic_write
    module_path
    nginx_binary
    run_nginx_t
    write_file
);
```

Required behavior:

- `nginx_binary()` returns `$ENV{TEST_NGINX_BINARY} // '/usr/sbin/nginx'`.
- `module_path()` returns
  `$ENV{POW_MODULE_PATH} // '/work/out/ngx_http_pow_module.so'`.
- `write_file($path, $bytes, $mode)` creates parent directories, writes
  byte-exact content in raw mode, closes successfully, and applies the mode.
- `atomic_write` writes a sibling temporary file, applies mode, closes, and
  renames it over the target.
- `run_nginx_t($http_body, %options)` creates a `File::Temp` prefix with
  `conf`, `logs`, and `html`, lets an optional setup callback create fixtures,
  writes a complete configuration, and executes this argv without a shell:

  ```text
  <selected nginx> -t -p <prefix>/ -c conf/nginx.conf
  ```

- The complete configuration is byte-built from this shape, with safely
  inserted selected paths and `$http_body`:

  ```nginx
  load_module <selected-module>;
  pid logs/nginx.pid;
  error_log logs/error.log notice;

  events {}

  http {
      access_log off;
      <http-body>
  }
  ```
- Fork the command, redirect stdout/stderr to bounded temporary files, and use
  `alarm` plus `waitpid` for a five-second hard timeout. On timeout terminate
  and reap the child, then return a result marked timed out.
- Return a hash containing exit status, signal, combined diagnostic text,
  timeout flag, and prefix path for assertions made inside the callback.
- Never interpolate test values into a shell command.

The helper is test infrastructure only and performs no compilation.

**Step 3: Write a passing harness smoke table**

Create `tests/integration/pow_config.t` with `Test::More` subtests for:

```text
empty http block                         -> nginx -t succeeds
existing pow off directive in a server  -> nginx -t succeeds
unknown pow_not_a_directive              -> nginx -t fails with semantic text
```

Use `done_testing`; assert status and stable diagnostic substrings, not full
stderr formatting.

**Step 4: Wire all integration files through one runner**

Change `Makefile` so normal integration uses:

```make
TEST_NGINX_BINARY=/usr/sbin/nginx \
POW_MODULE_PATH=/work/out/ngx_http_pow_module.so \
TEST_NGINX_SERVROOT=/tmp/ngx-powgate-test \
prove -Itests/integration/lib -v tests/integration/*.t
```

Preserve the `module` prerequisite.

**Step 5: Run the new harness**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc \
    'make module && TEST_NGINX_BINARY=/usr/sbin/nginx POW_MODULE_PATH=/work/out/ngx_http_pow_module.so prove -Itests/integration/lib -v tests/integration/pow_config.t'
```

Expected: all three subtests pass; the intentionally unknown directive is
asserted as a successful negative test.

**Step 6: Run existing integration tests through the aggregate target**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc 'make test-integration'
```

Expected: existing request smoke plus the new configuration harness pass.

**Step 7: Commit test infrastructure**

```sh
git add Makefile tests/integration/lib/PowGate/TestNginx.pm \
    tests/integration/pow_config.t
git commit -m "test: add nginx configuration harness"
```

---

### Task 4: Introduce configuration structures and standard directives

**Files:**

- Create: `src/ngx_http_pow_module.h`
- Create: `src/pow_config.c`
- Modify: `src/ngx_http_pow_module.c`
- Modify: `src/pow_protocol.h`
- Modify: `config`
- Modify: `tests/integration/pow_config.t`

**Step 1: Inspect exact pinned precedents**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc \
    'sed -n "80,140p;760,835p" "$NGX_SOURCE_DIR/src/http/modules/ngx_http_limit_req_module.c"; sed -n "1060,1320p" "$NGX_SOURCE_DIR/src/core/ngx_conf_file.c"; sed -n "240,285p" "$NGX_SOURCE_DIR/src/http/ngx_http.c"'
```

Expected: enum table, slot handlers, loc-conf creation/merge, and lifecycle
order are visible.

**Step 2: Write failing accepted-directive tests**

Add table rows that place every standard directive in `http`, `server`, and
`location` contexts while PowGate remains off:

```nginx
pow off;
pow_difficulty 20;
pow_challenge_window 60s;
pow_cookie_name __pow;
pow_cookie_ttl 1h;
pow_cookie_secure on;
pow_bind_ipv4 32;
pow_bind_ipv6 56;
pow_exempt_path /health;
pow_log_level error;
```

Also accept scalar overrides at nested levels. Do not add secret or activation
tests yet.

**Step 3: Run the test to prove it is red**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc \
    'make module && TEST_NGINX_BINARY=/usr/sbin/nginx POW_MODULE_PATH=/work/out/ngx_http_pow_module.so prove -Itests/integration/lib -v tests/integration/pow_config.t'
```

Expected: FAIL because `pow_difficulty` or the first newly listed directive is
unknown.

**Step 4: Define shared structures and lifecycle declarations**

Create `src/ngx_http_pow_module.h` with NGINX includes, include guards, the
main-conf structure from the approved design, and a loc-conf structure with:

```c
ngx_flag_t   enable;
ngx_int_t    difficulty;
time_t       challenge_window;
ngx_str_t    cookie_name;
time_t       cookie_ttl;
ngx_flag_t   cookie_secure;
ngx_int_t    bind_ipv4;
ngx_int_t    bind_ipv6;
ngx_array_t *exempt_ips;
ngx_array_t *exempt_paths;
ngx_uint_t   log_level;
```

Declare the external command table, module symbol, and fully prefixed
create/merge functions. Do not expose secret-loader internals.

**Step 5: Define constants once**

Add the missing `POW_DIFFICULTY_DEFAULT` as 20 in `src/pow_protocol.h`. Add
the protocol/configuration binding constants explicitly:

```c
#define POW_BIND_IPV4_MIN              8
#define POW_BIND_IPV4_MAX              32
#define POW_BIND_IPV4_DEFAULT          32
#define POW_BIND_IPV6_MIN              POW_IP_PLEN_MIN
#define POW_BIND_IPV6_MAX              POW_IP_PLEN_MAX
#define POW_BIND_IPV6_DEFAULT          56
```

Keep module-only limits such as configurable cookie-name length under an
`NGX_HTTP_POW_*` name in module-side code.

Run:

```sh
rg -n "#define.*(DIFFICULTY|BIND|COOKIE_NAME)" src
```

Expected: each protocol/default value has one production definition.

**Step 6: Move the command table and implement standard slots**

In `src/pow_config.c`:

- define numeric bounds structures for difficulty and bind lengths;
- define the log-level enum table;
- define post-handler declarations for positive window, cookie name, and
  exempt path;
- define command entries only for directives whose standard handlers or
  post-handlers are implemented in this task;
- leave the two custom command entries absent until their handlers are added:
  `pow_exempt_ip` in Task 5 and `pow_secret_file` in Task 6;
- use exact context flags and offsets from the design.

Implement `create_main_conf`, `create_loc_conf`, and `merge_loc_conf`.
Initialize every loc field with the matching unset sentinel. Merge scalars to
the approved defaults and inherit arrays by replacement semantics. Perform
the TTL/window relationship check after merge.

Do not require a secret or change handler registration in this task.

**Step 7: Wire the split into the module build**

- Include the module-internal header from both module-side C files.
- Remove the old local loc-conf typedef and command table from
  `ngx_http_pow_module.c`.
- Point the module context at the exported create/merge functions.
- Add `src/pow_config.c` to `ngx_module_srcs` in `config`.

**Step 8: Implement minimal post-validation needed by accepted cases**

Implement the positive-window, cookie-name, and exempt-path post-handlers
enough for valid default examples. Full rejection tables arrive in Task 5.
The cookie-name loop uses explicit lengths and ASCII byte comparisons; no libc
string parser is permitted.

**Step 9: Run focused tests and policy**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc \
    'make check-policy && make module && TEST_NGINX_BINARY=/usr/sbin/nginx POW_MODULE_PATH=/work/out/ngx_http_pow_module.so prove -Itests/integration/lib -v tests/integration/pow_config.t'
```

Expected: policy passes, module compiles warning-free, and accepted-directive
tests pass.

**Step 10: Commit standard configuration support**

```sh
git add config src/ngx_http_pow_module.h src/ngx_http_pow_module.c \
    src/pow_config.c src/pow_protocol.h tests/integration/pow_config.t
git commit -m "feat: add module configuration surface"
```

---

### Task 5: Complete directive validation and exemption parsing

**Files:**

- Modify: `src/pow_config.c`
- Modify: `tests/integration/pow_config.t`

**Step 1: Inspect the CIDR and post-handler precedents**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc \
    'sed -n "290,370p" "$NGX_SOURCE_DIR/src/http/modules/ngx_http_access_module.c"; sed -n "1060,1125p;1160,1195p;1290,1318p;1460,1488p" "$NGX_SOURCE_DIR/src/core/ngx_conf_file.c"'
```

Expected: `ngx_ptocidr`, `NGX_DONE` warning, string-array post-handler, numeric
bounds, and seconds post-handler behavior are visible.

**Step 2: Add failing table rows for scalar validation**

Add negative cases for:

- difficulty `0` and `33`, with `1` and `32` accepted;
- IPv4 bind `7` and `33`, with `8` and `32` accepted;
- IPv6 bind `31` and `129`, with `32` and `128` accepted;
- challenge window `0` and malformed/overflow times;
- cookie TTL smaller than an inherited or local window;
- invalid secure flags and log levels;
- duplicate scalar directives at one level.

Each row asserts exit failure and a stable constraint substring.

**Step 3: Add failing cookie-name tables**

Accepted rows include length 1, length 64, alphanumeric names, and every
allowed RFC token punctuation byte:

```text
! # $ % & ' * + - . ^ _ ` | ~
```

`$` is accepted only after the first byte. Rejected rows include empty,
length 65, leading `$`, separators, whitespace, controls, and non-ASCII bytes.
Construct binary/control config fixtures through the raw test helper rather
than shell interpolation.

**Step 4: Add failing exemption tables**

Accepted path rows:

```text
/
/health
/a//b
/literal%value
quoted values containing ? or # where NGINX syntax requires quoting
```

Rejected path rows:

```text
empty
health
/health/
```

Accepted CIDRs include IPv4, IPv6, repeated entries, and an entry with host
bits that produces the standard warning. Reject malformed CIDRs.

**Step 5: Run the expanded table and confirm failure**

Run the focused `prove` command from Task 4 Step 9.

Expected: one or more new negative cases are not rejected, or
`pow_exempt_ip` is not implemented.

**Step 6: Implement exact validation**

- Attach `ngx_conf_check_num_bounds` to all closed numeric ranges.
- Reject a zero challenge window in its seconds post-handler.
- Implement the exact cookie-token loop with an explicit switch or lookup
  predicate for RFC separators. Reject leading `$` before the general token
  loop.
- Validate exempt paths through the standard string-array post-handler.
- Implement the CIDR custom handler using a local zeroed `ngx_cidr_t`; call
  `ngx_ptocidr`, log `NGX_DONE` as the access module does, allocate/push only
  after parsing succeeds, and copy the local result into the array.
- Add the `pow_exempt_ip` command entry with all three HTTP configuration
  contexts and the location-conf offset.
- Preserve replacement inheritance and declaration order.
- Make diagnostics identify directive, safe value where useful, violated
  rule, and required bound.

**Step 7: Run focused and aggregate tests**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc \
    'make check-policy && make module && make test-integration'
```

Expected: all validation rows and existing request smoke pass.

**Step 8: Commit validation**

```sh
git add src/pow_config.c tests/integration/pow_config.t
git commit -m "feat: validate module directives"
```

---

### Task 6: Implement transactional secret loading and passive activation

**Files:**

- Create: `tests/integration/pow_secret_file.t`
- Modify: `tests/integration/pow_config.t`
- Modify: `tests/integration/pow_module.t`
- Modify: `src/pow_config.c`
- Modify: `src/ngx_http_pow_module.c`

**Step 1: Inspect pinned file and lifecycle APIs**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc \
    'grep -n "NGX_FILE_RDONLY\|NGX_FILE_NONBLOCK\|ngx_is_file\|ngx_file_access" "$NGX_SOURCE_DIR/src/os/unix/ngx_files.h"; sed -n "1445,1500p" "$NGX_SOURCE_DIR/src/http/modules/ngx_http_geo_module.c"; grep -R -n "ngx_explicit_memzero" "$NGX_SOURCE_DIR/src/http" "$NGX_SOURCE_DIR/src/event" | head -20; sed -n "250,285p;580,665p" "$NGX_SOURCE_DIR/src/http/ngx_http.c"'
```

Expected: nonblocking open flag, descriptor metadata, regular/access macros,
explicit erasure, and postconfiguration-after-merge ordering are visible.

**Step 2: Write failing conditional-activation tests**

Add these configuration rows:

```text
module loaded, no PowGate directive, no secret                  -> pass
pow off, no secret                                               -> pass
http pow on, every server explicitly off, no enabled location    -> pass
server pow on, no secret                                         -> fail
location pow on, no secret                                       -> fail
explicit invalid secret while pow is off                         -> fail
```

The third case must contain no remaining effective server or location with
`pow on`; do not mistake a server-level inherited on value for unreachable
configuration.

**Step 3: Write failing secret grammar tests**

Create `pow_secret_file.t` using the shared helper. Accepted byte fixtures:

```text
64 lower-case hex
64 upper-case hex plus LF
mixed-case current LF mixed-case previous
two lines plus final LF
all-zero current
identical current and previous
```

Rejected fixtures:

```text
empty; 63 bytes; 66 bytes; non-hex; spaces; tabs; BOM; CRLF;
blank second line; leading LF; extra LF; third line; byte 131
```

Every fixture is mode `0600`. For each rejection assert semantic diagnostics
and assert that a recognizable valid-looking secret string is not echoed.

**Step 4: Add context, duplicate, and path tests**

Test:

- a valid absolute path;
- a valid path relative to the NGINX configuration prefix;
- a second `pow_secret_file` returns a duplicate error;
- the directive in `server` and `location` is rejected as not allowed.

**Step 5: Run tests to prove they are red**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc \
    'make module && TEST_NGINX_BINARY=/usr/sbin/nginx POW_MODULE_PATH=/work/out/ngx_http_pow_module.so prove -Itests/integration/lib -v tests/integration/pow_config.t tests/integration/pow_secret_file.t'
```

Expected: FAIL because the secret directive/loader and conditional requirement
are incomplete.

**Step 6: Implement the bounded secret handler**

In `src/pow_config.c`, define only module-side constants needed for the
encoded file cap:

```c
#define NGX_HTTP_POW_SECRET_HEX_LEN       (POW_SECRET_LEN * 2)
#define NGX_HTTP_POW_SECRET_FILE_MAX_LEN  130
#define NGX_HTTP_POW_SECRET_READ_CAP      131
```

Implement helpers with fully prefixed names for:

- recognizing the four legal lengths;
- decoding one ASCII hex nibble with both cases accepted;
- decoding exactly one 64-byte line into a 32-byte temporary;
- reading and validating an opened file;
- wiping all temporary buffers through one cleanup path.

Add `pow_secret_file` to the command table with
`NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1`, the main-conf offset, and no server or
location context flag.

The directive handler must follow this order:

1. return `"is duplicate"` when `secret_set` is already true;
2. copy the configured `ngx_str_t` path and resolve it through
   `ngx_conf_full_name(cf->cycle, &path, 1)`;
3. open with `NGX_FILE_RDONLY | NGX_FILE_NONBLOCK`;
4. call `ngx_fd_info` on that descriptor;
5. require `ngx_is_file(&fi)` and
   `(ngx_file_access(&fi) & 0077) == 0`;
6. require metadata size 64, 65, 129, or 130;
7. read into a fixed 131-byte stack buffer, retry only on `NGX_EINTR`, require
   actual bytes equal metadata size, and require EOF before commit;
8. validate LF positions and all hex bytes;
9. decode into temporary current/previous arrays;
10. close successfully;
11. copy current and optional previous into main conf;
12. set `secret_set`, then `has_prev`;
13. erase the full raw/current/previous temporary buffers on all paths.

Log system errors with saved `ngx_errno` and the safe configured path, never
file content. A close failure rejects the candidate before commit.

**Step 7: Implement effective activation**

In `merge_loc_conf`, after all scalar merging and validation, fetch main conf
with `ngx_http_conf_get_module_main_conf`. If merged `enable` is on, set
`effective_pow_enabled = 1`.

In module postconfiguration:

```text
if effective_pow_enabled == 0 -> return NGX_OK without handler registration
if secret_set == 0            -> log NGX_LOG_EMERG and return NGX_ERROR
otherwise                     -> register the access handler as before
```

Do not add `init_main_conf` and do not infer activation from directive
appearance.

**Step 8: Update the request smoke fixture**

`pow_module.t` currently enables PowGate without a secret. Create a
process-lifetime temporary 64-hex secret in Perl, chmod it `0600`, keep
`load_module` in `main_config`, add the absolute `pow_secret_file` through a
separate `http_config` section, and remove the file in `END`. Keep the request
behavior unchanged: enabled Phase 2 still returns backend 200.

**Step 9: Run focused tests**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc \
    'make check-policy && make module && make test-integration'
```

Expected: configuration, grammar, activation, and request-smoke tests pass.

**Step 10: Commit secret loading and activation**

```sh
git add src/pow_config.c src/ngx_http_pow_module.c \
    tests/integration/pow_config.t tests/integration/pow_module.t \
    tests/integration/pow_secret_file.t
git commit -m "feat: load rotation secrets safely"
```

---

### Task 7: Complete descriptor and permission edge-case coverage

**Files:**

- Modify: `tests/integration/pow_secret_file.t`
- Modify: `tests/integration/lib/PowGate/TestNginx.pm`
- Modify: `src/pow_config.c` only if a test exposes a defect

**Step 1: Add failing filesystem target rows**

Create mode-controlled fixtures for:

```text
regular file 0400          -> pass
regular file 0600          -> pass
regular file 0610          -> fail
regular file 0620          -> fail
regular file 0640          -> fail
regular file 0601          -> fail
regular file 0602          -> fail
regular file 0604          -> fail
directory 0700             -> fail as non-regular
FIFO 0600                  -> fail without timeout
symlink to FIFO            -> fail without timeout
Unix socket node           -> fail as non-regular/open failure
/dev/null                  -> fail as non-regular
symlink to valid 0600 file -> pass
broken symlink             -> fail
```

Use `POSIX::mkfifo`, `symlink`, and `IO::Socket::UNIX` directly from Perl.
Do not use shell setup commands. Retain the five-second per-case timeout and
assert `timed_out` is false for every row.

**Step 2: Add descriptor-size race coverage where deterministic**

The helper may expose a setup callback immediately before exec, but do not add
a flaky concurrent writer test. Cover deterministic shrink/growth checks only
if they can synchronize without production hooks. Otherwise record in the
test comment that the reader compares `fstat` size, actual count, and EOF and
that code review plus sanitizers cover the race branches.

**Step 3: Run the filesystem suite before any fix**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc \
    'make module && TEST_NGINX_BINARY=/usr/sbin/nginx POW_MODULE_PATH=/work/out/ngx_http_pow_module.so prove -Itests/integration/lib -v tests/integration/pow_secret_file.t'
```

Expected: PASS if Task 6 is complete; otherwise a specific edge row fails
without hanging.

**Step 4: Fix only demonstrated defects**

If a row fails, update the smallest corresponding loader branch. Preserve
descriptor-based checks, nonblocking open, fixed buffers, cleanup ordering,
and diagnostics. Do not special-case test filenames or file types.

**Step 5: Run policy and full integration**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc \
    'make check-policy && make test-integration'
```

Expected: no timeout and all integration categories currently present pass.

**Step 6: Commit filesystem coverage**

```sh
git add tests/integration/lib/PowGate/TestNginx.pm \
    tests/integration/pow_secret_file.t src/pow_config.c
git commit -m "test: cover secret file policy"
```

Omit `src/pow_config.c` from `git add` when no production fix was needed.

---

### Task 8: Add the reload lifecycle integration test

**Files:**

- Create: `tests/integration/pow_reload.t`
- Modify: `tests/integration/lib/PowGate/TestNginx.pm`

**Step 1: Add runtime helpers without shell commands**

Extend the helper only where reusable:

- reserve a loopback port through `IO::Socket::INET` with port zero;
- start the selected NGINX with an isolated prefix and `daemon off;` via
  `fork`/`exec`;
- poll a TCP endpoint with a bounded deadline;
- read Linux child PIDs from `/proc/<master>/task/<master>/children`;
- terminate and reap the master in cleanup even after assertion failure.

All wait loops use short polling intervals and an overall deadline below ten
seconds. No unbounded sleep is allowed.

**Step 2: Write the reload lifecycle test**

The test must:

1. create a mode-0600 single-current secret through atomic write;
2. start NGINX with `pow on`, the secret file, and a fixed 200 content
   endpoint;
3. confirm the endpoint responds and capture initial worker children;
4. atomically install invalid secret content;
5. send `SIGHUP` to the master;
6. observe an error-log semantic message, confirm the endpoint still returns
   200, and confirm the old cycle remains available;
7. atomically install `new-current LF old-current LF`, both mixed-case-valid;
8. send `SIGHUP` again;
9. wait until at least one new worker PID appears and the endpoint returns
   200;
10. terminate NGINX and verify clean reaping.

Do not assert cookie validity or expose loaded secret bytes.

**Step 3: Run the reload test normally**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc \
    'make module && TEST_NGINX_BINARY=/usr/sbin/nginx POW_MODULE_PATH=/work/out/ngx_http_pow_module.so prove -Itests/integration/lib -v tests/integration/pow_reload.t'
```

Expected: invalid reload preserves service; valid reload creates a new worker
and preserves service.

**Step 4: Run the aggregate integration target twice**

Run twice to expose leaked processes, fixed-port assumptions, or stale temp
state:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc \
    'make test-integration && make test-integration'
```

Expected: both runs pass and leave no NGINX processes owned by the test
prefixes.

**Step 5: Commit reload coverage**

```sh
git add tests/integration/lib/PowGate/TestNginx.pm \
    tests/integration/pow_reload.t
git commit -m "test: cover secret reload lifecycle"
```

---

### Task 9: Run every Phase 2 integration category under ASan and UBSan

**Files:**

- Modify: `tools/run-asan.sh`
- Modify: `Makefile` only if a shared integration-run target removes
  duplication cleanly

**Step 1: Prove the current sanitizer gap**

Run:

```sh
rg -n "prove|pow_module.t|tests/integration" tools/run-asan.sh Makefile
```

Expected: `run-asan.sh` still names only `pow_module.t`.

**Step 2: Make every harness binary-selectable**

Audit all `.t` files for hard-coded `/usr/sbin/nginx` or module paths.

Run:

```sh
rg -n "/usr/sbin/nginx|/work/out/ngx_http_pow_module.so" \
    tests/integration
```

Expected: paths appear only as documented defaults in the shared helper or
existing Test::Nginx fallback; every test honors `TEST_NGINX_BINARY` and
`POW_MODULE_PATH`.

**Step 3: Expand the sanitized prove command**

Keep the existing full pinned NGINX clang build and its ASan/UBSan options.
Replace the single-test prove invocation with:

```sh
prove -Itests/integration/lib -v tests/integration/*.t
```

Pass the instrumented NGINX and module paths through the existing environment.
Keep `detect_leaks=0` and the dynamic-module ODR exception only for NGINX;
do not weaken abort-on-error, UBSan halt, or unit-test leak detection.

If both normal and sanitizer integration commands would otherwise diverge,
add a private `test-integration-run` Make target containing only `prove`, and
have both callers supply their selected binaries. Do not make `asan` rebuild
the normal nginx.org module unnecessarily.

**Step 4: Run the expanded sanitizer gate**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc 'make asan'
```

Expected: unit tests and all configuration, filesystem, reload, and request
integration files pass with no ASan or UBSan finding.

**Step 5: Run normal integration after sanitizer changes**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc 'make test-integration'
```

Expected: nginx.org runtime integration remains green.

**Step 6: Commit sanitizer enforcement**

```sh
git add tools/run-asan.sh Makefile
git commit -m "test: sanitize configuration integration"
```

Omit `Makefile` if it was not changed.

---

### Task 10: Write operator configuration and security documentation

**Files:**

- Create: `docs/configuration.md`
- Create: `docs/security.md`
- Modify: `README.md`

**Step 1: Write `docs/configuration.md` from implemented behavior**

Include:

- the exact directive table, contexts, defaults, bounds, and log levels;
- default difficulty 20 and recommendation 20 through 22;
- scalar inheritance and exemption-list replacement inheritance;
- conditional secret requirement based on effective enablement;
- cookie-name grammar and fixed proof-cookie name;
- secret relative paths resolving against the config-file prefix;
- exact four-layout mixed-case secret grammar;
- no group/other permission bits, symlink behavior, and examples using
  `chmod 600` or `chmod 400`;
- exemption matching against `r->uri`, path-segment boundary, query exclusion,
  percent/dot normalization, and `merge_slashes` dependency;
- future request evaluation order with IP before path;
- `pow_cookie_secure off` as explicit development-only behavior.

Mark challenge, request exemption behavior, and verification features that
are not implemented until later phases accurately; do not claim Phase 3 or 4
behavior is already shipped.

**Step 2: Write `docs/security.md`**

Include the exact approved statements:

```text
PowGate securely erases temporary parsing buffers. After successful loading,
decoded secrets reside in NGINX cycle configuration memory for the lifetime
of that configuration cycle. NGINX does not guarantee zeroization of
configuration pools when a cycle is destroyed or its workers exit.
```

Document descriptor-based validation, nonblocking FIFO safety, why symlinks
and arbitrary owners are allowed, why every group/other bit is rejected,
parse-validate-commit behavior, atomic replacement, and the two-reload
rotation procedure. State that the first secret derives/signs new artifacts
and the second verifies only.

**Step 3: Update README status and examples**

- Replace the Phase 0-only configuration disclaimer with accurate Phase 2
  status: directives and secret loading exist, while challenge issuance lands
  in Phase 3.
- Change common difficulty to 20 and mention 20 through 22 guidance.
- Move `pow_secret_file` directly under `http {}` in the quickstart; it must
  not remain inside `server {}`.
- Keep the quickstart secret generation compatible with mixed-case parsing and
  mode 0600.
- Link configuration and security documents.

**Step 4: Run a repository-wide stale-text audit**

Run:

```sh
rg -n "default 17|pow_difficulty 17|lowercase hex|group/other read|slashes merged|missing pow_secret_file.*module loaded|old-cookie validity.*Phase 2" \
    README.md PLAN.md AGENTS.md docs/protocol.md docs/configuration.md \
    docs/security.md src
```

Expected: no stale normative wording in the active specification, plan,
policy, operator documentation, README, or source.

**Step 5: Run documentation-adjacent policy tests**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc \
    'make check-policy && make test-integration'
```

Expected: policy and integration pass.

**Step 6: Commit operator documentation**

```sh
git add README.md docs/configuration.md docs/security.md
git commit -m "docs: document module configuration"
```

---

### Task 11: Perform the final Phase 2 audit and full gate

**Files:**

- Modify only files required by a demonstrated audit or test failure

**Step 1: Audit source policy and scope**

Run:

```sh
rg -n "malloc|calloc|realloc|free|strlen|strcpy|strcmp|sprintf|sscanf|strtol|atoi|memcmp" \
    src/pow_config.c src/ngx_http_pow_module.c src/ngx_http_pow_module.h
```

Expected: no banned bare call. Any match must be an approved `ngx_*` wrapper
or removed.

Run:

```sh
rg -n "secret|cookie|nonce|mac|proof" src/pow_config.c \
    src/ngx_http_pow_module.c
```

Manually verify no log format can emit secret material and that allocation,
open, read, close, array-push, and handler-registration failures are checked.

**Step 2: Audit configuration completeness**

Check each directive appears exactly once in the command table and once in
`docs/configuration.md`:

```sh
for name in pow pow_difficulty pow_challenge_window pow_cookie_name \
    pow_cookie_ttl pow_cookie_secure pow_secret_file pow_bind_ipv4 \
    pow_bind_ipv6 pow_exempt_ip pow_exempt_path pow_log_level; do
    rg -n "${name}" src/pow_config.c docs/configuration.md
done
```

Expected: command and documentation coverage for every name.

Manually verify:

- only `pow_secret_file` is main-conf-only;
- main-conf `effective_pow_enabled` reflects merged values;
- inactive module skips handler registration;
- active module without a secret fails;
- arrays replace rather than concatenate across levels;
- secrets commit only after successful close;
- raw and decoded temporaries wipe on every label/return path.

**Step 3: Run the full required gate**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc 'make clean && make check'
```

Expected:

```text
check-policy: OK
all pure-core unit tests pass
parser coverage gate passes
ngx_http_pow_module.so builds against pinned NGINX 1.30.3
all configuration/filesystem/reload/request integration tests pass
e2e smoke passes
both fuzz smoke targets complete without finding
ASan+UBSan unit and all implemented integration categories pass
```

**Step 4: Re-run filesystem and reload tests for flake resistance**

Run:

```sh
podman run --rm --userns=keep-id \
    -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie sh -lc \
    'for i in 1 2 3; do TEST_NGINX_BINARY=/usr/sbin/nginx POW_MODULE_PATH=/work/out/ngx_http_pow_module.so prove -Itests/integration/lib -v tests/integration/pow_secret_file.t tests/integration/pow_reload.t || exit 1; done'
```

Expected: three consecutive passes with no timeout or orphaned NGINX process.

**Step 5: Inspect the final diff and repository state**

Run:

```sh
git status --short
git diff --check
git log --oneline --decorate -12
```

Expected: only the two pre-existing untracked Codex-hook notes remain; no
implementation file is uncommitted, and every Phase 2 commit follows the
project's concise commit style.

**Step 6: Commit only demonstrated final fixes**

If the audit required a correction, stage only that logical correction and
use the appropriate concise type, for example:

```sh
git add <exact-files-fixed>
git commit -m "fix: close secret configuration edge case"
```

Do not create an empty “phase complete” commit. If no fix was needed, this
step has no commit.

## Phase 2 completion criteria

- All twelve directives parse in their defined contexts and reject invalid
  values with actionable, non-secret diagnostics.
- Loading the module without effective `pow on` is passive and secret-free.
- Effective enablement requires one successfully loaded secret file.
- The secret loader is descriptor-based, nonblocking before `fstat`, bounded,
  mixed-case aware, transactional, and temporary-buffer-zeroing.
- Target permissions contain no group/other bits; valid symlinks work and
  FIFOs cannot hang parsing.
- Invalid reload retains the old cycle; valid atomic rotation replaces
  workers.
- Phase 2 makes no behavioral inheritance or cryptographic rotation claim
  reserved for Phases 3 and 4A.
- Normal and ASan+UBSan integration cover every implemented test category.
- `make check` passes from a clean build inside
  `localhost/ngx-powgate-dev:trixie`.
