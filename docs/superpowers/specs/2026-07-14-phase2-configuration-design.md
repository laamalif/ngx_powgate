# Phase 2 Configuration and Secret Handling Design

**Date:** 2026-07-14

**Status:** Approved design

**Scope:** Phase 2 directives, configuration inheritance and validation,
conditional module activation, secret-file loading and rotation, operator
documentation, integration testing, and sanitizer coverage

## Objective

Implement the complete v0.1 configuration surface and secret lifecycle before
adding challenge or verification behavior. Every directive must use an NGINX
1.30.3 precedent, every invalid configuration must fail closed with an
actionable diagnostic, and secret loading must be bounded, descriptor-based,
and transactional.

The request handler continues to allow requests in Phase 2. It is registered
only when a fully merged configuration enables PowGate. Phase 2 does not issue
challenges, inspect cookies, verify proofs, or expose configuration through a
temporary diagnostic request path.

## Design invariants

- Loading the dynamic module without enabling PowGate is passive and does not
  require a secret.
- A secret is mandatory if any fully merged server or location configuration
  has `pow on`.
- Standard NGINX directive handlers and post-handlers are used wherever an
  equivalent exists. Custom handlers are limited to CIDR parsing and secret
  loading.
- Scalar settings inherit through `http` to `server` to `location` and may be
  overridden at each level.
- Exemption arrays follow standard NGINX replacement inheritance: a child
  inherits the parent array only when it declares no entries of its own.
- Custom parsers follow parse, validate, then commit. Standard NGINX slot
  handlers retain their upstream assign-then-post-validate behavior; a failed
  candidate configuration never becomes active.
- Secret I/O uses fixed-size buffers and never allocates in proportion to file
  content.
- File policy is enforced on the opened descriptor, not on a path checked
  before opening.
- Temporary encoded and decoded secret material is erased on every exit path.
- No secret value, MAC, nonce, proof, cookie, or fingerprint is logged.
- No temporary directive, response header, request handler, or sanitizer-only
  functional path is introduced for testing.

## NGINX 1.30.3 precedents

Implementation is based on the pinned source at `NGX_SOURCE_DIR`:

- directive slots, post-handlers, and numeric bounds from
  `src/core/ngx_conf_file.c`;
- enum and merge behavior from
  `src/http/modules/ngx_http_limit_req_module.c`;
- CIDR parsing and host-bit warnings from
  `src/http/modules/ngx_http_access_module.c`;
- duplicate custom-directive handling from
  `src/http/modules/ngx_http_auth_basic_module.c`;
- descriptor metadata, file access, and regular-file checks through the
  wrappers in `src/os/unix/ngx_files.h`;
- HTTP configuration lifecycle and merge ordering from `src/http/ngx_http.c`.

Before implementation uses another NGINX API, the corresponding 1.30.3 source
precedent must be inspected and recorded in the implementation plan.

## Component architecture

### Module and configuration split

`src/ngx_http_pow_module.c` retains:

- the `ngx_module_t` and `ngx_http_module_t` definitions;
- postconfiguration and access-handler registration;
- the Phase 2 access handler, which still returns `NGX_DECLINED`;
- later request-path behavior.

`src/pow_config.c` owns:

- the command table;
- main and location configuration lifecycle functions;
- directive post-handlers and custom handlers;
- merge and cross-field validation;
- secret path resolution, file validation, bounded reading, decoding, and
  transactional commit.

A module-internal header shares configuration structures, the command table,
and lifecycle declarations. Its NGINX-facing identifiers use the
`ngx_http_pow_*` prefix. `pow_config.c` is module-side code despite its
filename and may include NGINX headers.

The four NGINX-free pure-core families remain exactly `pow_parse`,
`pow_crypto`, `pow_cookie`, and `pow_challenge`. The broad `pow_*.c/.h`
shorthand in `AGENTS.md` must be narrowed to those names so it agrees with
`docs/nginx-style.md` and `tools/check-policy.sh`.

No generic configuration library or fifth pure-core component is introduced.

### Main configuration

The main configuration contains:

```c
typedef struct {
    u_char      secret[POW_SECRET_LEN];
    u_char      secret_prev[POW_SECRET_LEN];
    ngx_flag_t  has_prev;
    ngx_flag_t  secret_set;
    ngx_flag_t  effective_pow_enabled;
} ngx_http_pow_main_conf_t;
```

`secret_set` is independent of secret bytes because an all-zero secret is
valid. `effective_pow_enabled` means that at least one completed location
merge produced an effective `pow on`; it does not merely record that the
directive appeared in source text.

`create_main_conf` allocates the structure with `ngx_pcalloc` from `cf->pool`.
There is no main-conf merge function. A no-op `init_main_conf` function is not
added; secret necessity is decided after location merges.

### Location configuration

The location configuration contains the scalar directive values plus
`ngx_array_t *` exemption lists. Numeric slot fields use the types expected by
their NGINX slot handlers. Every scalar begins with the matching
`NGX_CONF_UNSET*` sentinel and every pointer begins as
`NGX_CONF_UNSET_PTR`.

The effective IPv4 binding is stored as the configured IPv4 bit count in the
range 8 through 32. Request code later converts it to the protocol prefix
length `96 + pow_bind_ipv4`. IPv6 binding is already the canonical prefix
length.

## Directive contract

| Directive | Context | Default | Validation |
|---|---|---:|---|
| `pow on\|off` | `http`, `server`, `location` | `off` | Standard flag slot |
| `pow_difficulty N` | `http`, `server`, `location` | `20` | Integer 1 through 32 |
| `pow_challenge_window time` | `http`, `server`, `location` | `60s` | Positive whole seconds |
| `pow_cookie_name token` | `http`, `server`, `location` | `__pow` | 1 through 64 ASCII token bytes; no leading `$` |
| `pow_cookie_ttl time` | `http`, `server`, `location` | `1h` | At least the merged challenge window |
| `pow_cookie_secure on\|off` | `http`, `server`, `location` | `on` | Standard flag slot |
| `pow_secret_file path` | `http` only | none | One occurrence; validated and loaded immediately |
| `pow_bind_ipv4 N` | `http`, `server`, `location` | `32` | Integer 8 through 32 |
| `pow_bind_ipv6 N` | `http`, `server`, `location` | `56` | Integer 32 through 128 |
| `pow_exempt_ip CIDR` | `http`, `server`, `location` | none | Repeatable IPv4 or IPv6 CIDR |
| `pow_exempt_path prefix` | `http`, `server`, `location` | none | Repeatable absolute path prefix |
| `pow_log_level level` | `http`, `server`, `location` | `error` | `info`, `notice`, `warn`, or `error` |

Difficulty 20 is the protocol and implementation default. Operator guidance
recommends 20 through 22 while preserving the configurable range 1 through
32. This default change must be made spec-first in `docs/protocol.md` and then
applied consistently to `PLAN.md`, `README.md`, `src/pow_protocol.h`, and
tests.

### Standard handlers

- Flags use `ngx_conf_set_flag_slot`.
- Numbers use `ngx_conf_set_num_slot` with `ngx_conf_check_num_bounds` where
  the constraint is a simple closed range.
- Times use `ngx_conf_set_sec_slot`; the challenge window adds a post-handler
  rejecting zero.
- Cookie name uses `ngx_conf_set_str_slot` with a validation post-handler.
- Exempt paths use `ngx_conf_set_str_array_slot` with a validation
  post-handler.
- Log level uses `ngx_conf_set_enum_slot` with the same values and mechanism
  as `limit_req_log_level`.

The custom handlers are:

- `pow_exempt_ip`, because it converts text into `ngx_cidr_t` entries;
- `pow_secret_file`, because it performs bounded descriptor I/O and commits a
  compound value.

### Cookie-name grammar

The name is 1 through 64 printable ASCII token bytes. It accepts letters,
digits, and RFC token punctuation and rejects separators, whitespace, control
bytes, and non-ASCII bytes. A leading `$` is rejected to avoid legacy RFC
2109 attribute syntax; `$` in a later position remains valid.

The configurable name affects only the authentication cookie. The proof name
`__pow_p` is protocol-fixed. Neither cookie name is a MAC input.

### Merge and validation

Scalar values use their corresponding `ngx_conf_merge_*` macros with the
defaults above. After each server or location merge:

1. reject a non-positive challenge window defensively;
2. reject `cookie_ttl < challenge_window`;
3. rely on already completed slot post-validation for numeric and token
   bounds;
4. if the merged `pow` value is on, set main-conf
   `effective_pow_enabled = 1`.

Invalid values are errors even within a merged `pow off` context. Disabled
configuration does not create a second, weaker validation mode.

Duplicate scalar directives at one level use the standard NGINX duplicate
error. A second `pow_secret_file` returns `"is duplicate"`. Overrides at a
child configuration level are not duplicates.

### Conditional activation

NGINX 1.30.3 calls module `init_main_conf` before merging server and location
configuration. Secret necessity therefore cannot be decided correctly in
`init_main_conf`.

Location merge accumulates `effective_pow_enabled`. During
postconfiguration, after all merges:

1. if `effective_pow_enabled` is false, return `NGX_OK` without requiring a
   secret or registering the access handler;
2. if it is true and `secret_set` is false, log an actionable
   `NGX_LOG_EMERG` diagnostic and return `NGX_ERROR`;
3. otherwise register the access handler in the access phase.

An explicitly configured `pow_secret_file` is always validated and loaded,
even when PowGate remains disabled. An invalid explicit directive is never
ignored.

This model means that loading the module, or configuring only effective
`pow off` contexts, does not require a secret. An effective `pow on` at any
server or location does.

## Exemption lists

### Inheritance

Both exemption lists use standard NGINX replacement inheritance:

- no child entries means inherit the parent's array;
- one or more child entries replace the inherited array at that level;
- repeated entries at one level append in declaration order;
- duplicate entries are accepted.

Lists are not implicitly concatenated across configuration levels. Phase 2
tests syntax, context, parsing, and merge construction. Behavioral inheritance
is tested through observable responses in Phase 3.

### CIDRs

`pow_exempt_ip` zeroes a local `ngx_cidr_t`, calls `ngx_ptocidr`, and commits
the parsed entry only after successful conversion. Invalid CIDRs fail
configuration. `NGX_DONE` follows `ngx_http_access_module` precedent: accept
the normalized network and emit the standard warning that low address bits
are meaningless.

Phase 3 matches the connection address after RealIP processing. IPv4 and IPv6
CIDRs stay in their native `ngx_cidr_t` representation.

### Paths

Configured path prefixes are stored byte-for-byte. They are not decoded or
normalized during configuration. A prefix must begin with `/`. `/` is the
universal exemption; every other prefix must not end with `/`.

Phase 3 performs a case-sensitive comparison against `r->uri`. A prefix
matches only the exact URI or a URI whose next byte is `/`, so `/api` does not
match `/apiv2`. Query arguments in `r->args` never participate.

NGINX percent-decodes and resolves dot segments while constructing `r->uri`.
Duplicate-slash compression depends on the core `merge_slashes` setting and
must not be described as unconditional. Literal repeated slashes, `%`, `?`,
and `#` remain permitted in configured prefixes because corresponding bytes
can legitimately occur in `r->uri` depending on encoding and server
configuration.

The eventual request evaluation order is frozen now for Phase 3:

1. skip subrequests and internal redirects;
2. fetch the effective location configuration;
3. decline immediately when `pow` is off;
4. check IP exemptions;
5. check path exemptions;
6. decline immediately on either exemption;
7. otherwise continue into PowGate processing.

## Secret-file contract

### Path and file policy

Relative paths resolve against `cf->cycle->conf_prefix` through
`ngx_conf_full_name(..., 1)`. Absolute paths remain absolute.

The handler opens the path with
`NGX_FILE_RDONLY | NGX_FILE_NONBLOCK`, following symlinks. Nonblocking open is
required because a blocking read-only open of a FIFO can hang before
descriptor metadata is available. On the supported Linux platform the flag
is harmless for regular files and also protects a symlink whose target is a
FIFO.

After opening, the handler calls `ngx_fd_info` on the descriptor and requires:

- `ngx_is_file` reports a regular file;
- `(ngx_file_access(&fi) & 0077) == 0`.

Thus owner permissions and ownership are unrestricted, while every group or
other read, write, or execute bit is rejected. Validation applies to the
opened symlink target. Directories, FIFOs, sockets, devices, and other
non-regular targets are rejected.

The descriptor is closed on every path. An open, metadata, read, or close
failure rejects the candidate configuration.

### Exact byte grammar

The accepted file layouts are exactly:

```text
HEX64
HEX64 LF
HEX64 LF HEX64
HEX64 LF HEX64 LF
```

Each `HEX64` is exactly 64 ASCII hexadecimal bytes. Decimal digits and either
uppercase or lowercase `A` through `F` are accepted, including mixed case.
Decoding handles both cases directly; no normalized copy is created.

The first secret is current. It derives every newly issued challenge nonce
and signs every new authentication cookie. The optional second secret is
previous and is used only as a verification fallback. Both secrets are
accepted when verifying authentication cookies and submitted proofs. All-zero
secrets and identical current and previous secrets are valid.

CRLF, carriage returns, BOMs, spaces, tabs, blank lines, extra separators,
non-hex bytes, and third lines are rejected.

### Bounded read and transactional commit

The four legal file sizes are 64, 65, 129, and 130 bytes. Metadata size is
gated before reading. The handler then reads through the descriptor into a
fixed 131-byte stack buffer, accounting for interrupted and short reads. The
actual byte count must equal the descriptor metadata size and the next read
must reach EOF. A shrink, growth, or extra byte therefore rejects the
candidate configuration.

Raw input and decoded current/previous secrets live in temporary fixed-size
buffers. The handler:

1. reads bounded input;
2. validates the complete grammar;
3. decodes both lines into temporary arrays;
4. closes the descriptor successfully;
5. copies into main configuration only after every check succeeds;
6. sets `secret_set` and `has_prev` only after copying;
7. erases raw and decoded temporary buffers with `ngx_explicit_memzero` on
   every success and failure path.

No partially decoded secret becomes active. A failed handler leaves the main
configuration uncommitted and the candidate NGINX cycle is rejected.

### Memory lifetime

After successful loading, decoded secrets reside in NGINX cycle configuration
memory for the lifetime of that configuration cycle. NGINX does not guarantee
zeroization of configuration pools when a cycle is destroyed or its workers
exit. PowGate does not claim otherwise. Temporary parsing buffers are erased;
long-lived configuration storage follows the NGINX lifecycle.

## Rotation and reload

Rotation is operator-managed; NGINX does not automatically promote the old
current secret. The documented procedure is:

1. atomically replace the file with new current on line 1 and old current on
   line 2;
2. run `nginx -t`;
3. reload NGINX;
4. retain the previous secret for at least the maximum authentication-cookie
   TTL;
5. atomically replace the file with the current secret alone and reload
   again.

Old workers retain the old cycle while new workers load the new pair. A
failed test or reload leaves the old cycle serving. Secret updates must use
atomic replacement for defined rotation behavior; a regular-file read is not
a transactional snapshot of a concurrent in-place write.

Phase 2 proves that reload reparses the file and preserves the old cycle on
failure. Phase 4A proves cryptographically that cookies and proofs created
before rotation verify through the previous secret after rotation.

## Diagnostics

Configuration diagnostics identify, when safely available:

- the directive or configured path;
- the invalid value when it is non-secret and safe to render;
- the violated constraint;
- the required constraint.

Examples of the intended semantic content are:

```text
pow_cookie_ttl: value 30s must be at least pow_challenge_window (60s)
pow_cookie_name: value is not a valid cookie token
pow_secret_file: target must grant no group or other permissions
```

Messages avoid generic `invalid configuration` wording. Tests match stable
semantic substrings rather than punctuation or full NGINX formatting.

Secret content, decoded values, MACs, nonces, cookies, proofs, and secret
fingerprints are never logged. Request-path code normally logs only verdicts
and lengths. Any future diagnostic that genuinely needs other untrusted bytes
must bound and escape them through NGINX facilities; cookie values, nonces,
MACs, and secrets remain prohibited regardless of escaping.

## Verification strategy

All compilation and tests run inside
`localhost/ngx-powgate-dev:trixie`. Normal integration uses the nginx.org
1.30.3 runtime package; sanitizer integration rebuilds the pinned 1.30.3
source with instrumentation.

### Test categories

| Category | Purpose |
|---|---|
| Configuration | Directive parsing, validation, allowed contexts, and merge rules |
| Filesystem | Secret grammar, permissions, file types, paths, and symlinks |
| Reload | Configuration-cycle lifecycle and worker replacement |
| Request | Runtime handling, activation, and exemptions |
| Cryptography | Challenges, proofs, cookies, and rotation |

A category is introduced when its production behavior exists. Once
introduced, it remains in normal and sanitizer gates.

### Configuration and filesystem matrix

A table-driven integration test creates isolated NGINX prefixes and invokes
the selected NGINX binary with `-t`. Every harness honors
`TEST_NGINX_BINARY` and `POW_MODULE_PATH`.

Accepted cases include:

- module loaded without PowGate directives or a secret;
- effective `pow off` without a secret;
- an inherited `pow on` overridden to effective off for all server contexts;
- effective `pow on` with a valid secret;
- all scalars in every permitted context and at boundary values;
- repeated and inherited exemption lists;
- cookie-name token punctuation and length boundaries;
- one and two secrets, mixed-case hex, optional final LF, all-zero values,
  and identical values;
- relative and absolute secret paths;
- a symlink to an acceptable regular target.

Rejected cases include:

- effective `pow on` without a secret;
- `pow_secret_file` outside `http` or repeated in `http`;
- duplicate scalar directives at one level;
- invalid flags, enum values, numbers, times, and post-merge relationships;
- malformed cookie names, CIDRs, and exempt paths;
- missing paths and broken symlinks;
- directory, FIFO, symlink-to-FIFO, socket, device, and other non-regular
  targets;
- any target with group or other permission bits;
- every secret grammar violation: empty, short, oversized, malformed,
  whitespace, BOM, CRLF, blank line, extra separator, or third line;
- deterministic concurrent-size anomalies where the harness can create them.

Filesystem cases have a hard timeout. FIFO tests prove configuration cannot
hang. Diagnostics are checked for stable semantic content and for absence of
known secret bytes.

### Reload test

The reload integration test:

1. starts NGINX with a valid current secret;
2. atomically installs invalid secret content and signals reload;
3. observes reload failure and confirms the old cycle still serves;
4. atomically installs new current plus old current;
5. observes a successful reload and worker replacement.

This proves file re-reading and lifecycle behavior without exposing secret
values. It deliberately does not claim old-cookie validity in Phase 2.

Behavioral scalar and exemption inheritance moves to Phase 3, where emitted
challenges and allow/deny outcomes make merged values observable. Current and
previous secret selection moves to Phase 4A, where real cookies and proofs
exercise it. No temporary Phase 2 introspection surface is permitted.

### Sanitizer policy

- Every implemented integration-test category runs under ASan and UBSan
  before release.
- Any sanitizer finding is a release blocker.
- Sanitizer-specific functional behavior or alternate implementation paths
  are prohibited.
- Sanitized tests exercise the same production NGINX and module source; only
  compiler and linker instrumentation may differ.
- Test fixtures and fault injection introduce no production directive,
  request path, or release artifact.
- A category may be absent only until its production feature exists.

`make asan` is extended to run all Phase 2 integration categories against the
instrumented NGINX and module, not only the original request smoke test.

Secret-parser fuzzing remains a future hardening candidate. Phase 2 adds no
AFL++, OSS-Fuzz, new dependency, or fifth pure library solely for this input.
After Phase 4A, coverage can justify a libFuzzer target using the project's
existing toolchain.

## Documentation and policy alignment

Before implementation, the repository documents must be reconciled:

- `docs/protocol.md`: default difficulty 20; case-insensitive secret hex;
  current and previous roles; no group or other target permissions.
- `PLAN.md`: conditional secret requirement, truthful phase test boundaries,
  exact file contract, nonblocking FIFO safety, rotation, exemption
  inheritance and slash semantics, default difficulty, and sanitizer policy.
- `AGENTS.md`: exact four-file pure-core boundary, stronger secret permission
  rule, and enduring sanitizer policy.
- `src/pow_protocol.h`: difficulty default and any missing protocol default or
  bound constants defined once.
- `README.md`: default and recommended difficulty plus the implemented
  configuration status.
- `docs/configuration.md`: directive table, contexts, defaults, inheritance,
  validation, path resolution, exemption semantics, and examples.
- `docs/security.md`: file policy, parsing, memory lifetime, rotation,
  atomic replacement, and failure behavior.

The local `.codex/hooks.json` and the two existing untracked Codex-hook notes
remain local and are not committed or modified.

## Rejected alternatives

- Requiring a secret merely because the module is loaded: unnecessarily
  prevents passive optional-module use.
- Detecting enablement from directive appearance: does not reflect merged
  overrides.
- Checking for a secret in `init_main_conf`: runs before location merges in
  NGINX 1.30.3.
- Registering the access handler when no effective configuration enables the
  module: violates passive-module behavior.
- Checking the path before opening: vulnerable to path races and does not
  validate the opened object.
- Blocking open followed by `fstat`: can hang forever on a FIFO.
- Forbidding symlinks: breaks common secret-delivery mechanisms without
  improving descriptor-based validation.
- Enforcing a particular owner: incompatible with root, rootless, and
  privilege-dropping deployments.
- Rejecting only group/other read bits: permits unauthorized modification and
  future cookie forgery.
- Lowercase-only hex: adds operator friction without a security benefit.
- Additive exemption inheritance: diverges from standard NGINX array
  semantics.
- A temporary diagnostic directive, response header, fingerprint log, or
  request handler: creates non-production behavior and risks secret exposure.
- A separate generic configuration library: unnecessary abstraction for the
  project size.

## Completion gate

Phase 2 is complete only when the production source, documentation, and tests
implement this design and a fresh containerized `make check` passes. The gate
includes policy checks, pure-core unit and coverage tests, module compilation,
all normal integration categories, e2e smoke behavior, fuzz smoke tests, and
the expanded ASan+UBSan run.

No Phase 2 result may claim behavioral exemption inheritance or dual-secret
cookie validity. Those claims become valid only after their Phase 3 and
Phase 4A tests exist.
