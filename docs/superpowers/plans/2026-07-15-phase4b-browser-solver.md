# Phase 4B Browser Solver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the inert challenge-page placeholder with the exact-byte,
dual-backend browser proof-of-work solver and deterministic private controller
defined by the frozen Phase 4B design.

**Architecture:** `html/challenge.html` remains the sole source of the served
page and executable bytes. The public frozen `PowGateSolver` object owns only
pure hashing and bounded sequential search; a private controller owns strict
parameter parsing, backend self-test/fallback, scheduling, visibility, UI,
cookie lifecycle, and reload. The existing generator hashes the exact inline
script and NGINX continues to insert only canonical JSON between generated
prefix/suffix arrays. Node tests evaluate the exact production script with
built-in `node:vm`; NGINX integration continues over explicitly asserted HTTPS
HTTP/1.1 and HTTP/2.

**Tech Stack:** C99 pure core and NGINX 1.30.3 module code, OpenSSL-linked
NGINX, browser JavaScript with no dependencies, Python `unittest`, Node's
built-in test runner and `node:vm`, Perl integration tests, Podman using
`localhost/ngx-powgate-dev:trixie`.

## Global Constraints

- Read and implement against
  `docs/superpowers/specs/2026-07-15-phase4b-browser-solver-design.md`.
- Read `docs/protocol.md`, `docs/nginx-style.md`, and `AGENTS.md` before the
  first source edit. The wire format and CSP policy do not change in this
  phase.
- Work only in the isolated Phase 4B worktree. Do not implement on `master`.
- All compilation and test commands run in Podman. The host may edit and
  inspect files and invoke Podman, but must not compile or execute project
  tests directly.
- Use the fully qualified local image tag
  `localhost/ngx-powgate-dev:trixie` in every command.
- Use test-driven development: add one focused failing assertion, confirm the
  expected failure, implement the minimum contract, then rerun the focused
  test before expanding the table.
- Keep the exact inline script as the only browser implementation. Do not add
  a second solver source, a generated JavaScript source, npm metadata, or a
  production test branch.
- The browser is an independent protocol consumer and necessarily carries the
  fixed v1 proof-cookie serialization it must produce. Every mirrored wire
  value must have a cross-language regression against `src/pow_protocol.h`
  and/or `tests/vectors/v1.json`; do not introduce an untested duplicate.
- Generated challenge arrays and CSP digest remain uncommitted build outputs.
- Do not add a real browser dependency. Phase 4C owns browser-engine behavior,
  backend measurement, and the browser-to-authenticated-request loop.
- Run `make check-policy` after every source edit and before every commit.
- Keep commits small and use `type: imperative summary` at 72 characters or
  fewer.

Use this command shape from the worktree root throughout:

```sh
podman run --rm \
  -v "$PWD:/work:Z" \
  -w /work \
  localhost/ngx-powgate-dev:trixie \
  <command>
```

## File Map

**Modify**

- `html/challenge.html` — canonical accessible page, exact public solver, and
  private controller.
- `src/pow_protocol.h` — single 15 KiB response-body limit constant.
- `src/pow_challenge.h` / `src/pow_challenge.c` — pure, overflow-safe assembled
  body-length validation.
- `src/ngx_http_pow_module.c` — enforce worst-case and actual body length before
  response allocation/commit; preserve the existing three-buffer response.
- `tests/unit/test_challenge.c` — table-driven boundary/overflow tests for the
  body-length helper.
- `tools/build_pow_challenge.py` — use the named semantic limit and preserve
  exact extraction/hash identity and atomic output.
- `tests/tools/test_build_pow_challenge.py` — derive expectations from the real
  template and assert exact script/hash/body-budget behavior.
- `Makefile` — add a dependency-free `test-js` gate and include it exactly
  once in the normal `test-e2e`/`check` graph. JavaScript is not an
  ASan-instrumented category.
- `tests/e2e/smoke.mjs` — use the shared exact-script harness against the page
  served by real NGINX; retain HTTPS and backend-isolation assertions.
- `tests/integration/pow_challenge.t` — assert exact assembled size and updated
  page bytes under HTTP/1.1 and HTTP/2.
- `PLAN.md` — record the frozen Phase 4B contracts and mark the phase complete
  only after the full gate passes.
- `README.md`, `docs/configuration.md`, and `docs/security.md` — describe only
  browser behavior that now exists and keep the Phase 4C boundary honest.
- `AGENTS.md` — record only the enduring exact-production-script and
  cross-language wire-literal regression rules; do not add temporary Phase 4B
  details.

**Create**

- `tests/e2e/lib/challenge-script.mjs` — exact executable-script extraction,
  deterministic VM harness, narrow fake DOM/cookie/timer environment, and
  generated-header byte decoding helpers.
- `tests/e2e/solver.test.mjs` — public namespace, SHA-256, backend, vector, and
  bounded-result tests.
- `tests/e2e/controller.test.mjs` — strict parser, state machine, scheduling,
  visibility, UI, cookie, and reload tables.

---

## Task 1: Enforce the Actual Assembled Challenge-Body Limit

**Files:**

- Modify: `src/pow_protocol.h`
- Modify: `src/pow_challenge.h`
- Modify: `src/pow_challenge.c`
- Modify: `src/ngx_http_pow_module.c`
- Modify: `tests/unit/test_challenge.c`
- Modify: `tests/integration/pow_challenge.t`

### 1.1 Add failing pure-core boundary tests

- [ ] Read the existing `pow_challenge` unit tables and response construction
  in `ngx_http_pow_module.c` again immediately before editing.
- [ ] Add table rows for an overflow-safe helper with this public contract:

```c
int pow_challenge_body_len(size_t prefix_len, size_t json_len,
    size_t suffix_len, size_t *out);
```

The tests must prove:

- a small valid sum succeeds and writes the exact sum;
- `15359` succeeds;
- `15360` and larger fail because the bound is strict;
- overflow in either addition fails;
- `out == NULL` fails;
- on failure, callers treat `out` as uninitialized; tests must not require
  zeroing or a particular retained value.

- [ ] Run the focused unit build and confirm it fails because the helper and
  limit constant do not exist yet:

```sh
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  make build/tests/test_challenge
```

Expected: compile/link failure naming `pow_challenge_body_len` and/or
`POW_CHALLENGE_PAGE_MAX_BODY_LEN`, not an unrelated warning.

### 1.2 Implement the pure limit once

- [ ] Add this wire-visible constant to `src/pow_protocol.h`:

```c
#define POW_CHALLENGE_PAGE_MAX_BODY_LEN 15360
```

- [ ] Declare the helper in `src/pow_challenge.h` and implement it in
  `src/pow_challenge.c` using subtraction-based bounds or explicit
  `SIZE_MAX` guards. Never form an unchecked sum.
- [ ] Return `1` only when the exact total is strictly less than the maximum;
  otherwise return `0`.
- [ ] Run the focused unit test:

```sh
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  make build/tests/test_challenge test-unit
```

Expected: all pure-core unit binaries pass with the full strict warning set.

### 1.3 Enforce worst-case and actual lengths before response commitment

- [ ] Add a compile-time assertion adjacent to the generated challenge-page
  include/use which proves:

```text
sizeof(generated prefix)
  + POW_CHALLENGE_JSON_MAX_LEN
  + sizeof(generated suffix)
  < POW_CHALLENGE_PAGE_MAX_BODY_LEN
```

Use the C89-compatible typedef/static-array pattern already accepted by the
NGINX build; do not introduce a new runtime API or C11 requirement.

- [ ] In `ngx_http_pow_issue_html()`, call `pow_challenge_body_len()` after
  `json_len` is final and before allocating JSON/body buffers or reserving
  response headers. On failure, log only a fixed internal invariant verdict
  and return `NGX_HTTP_INTERNAL_SERVER_ERROR`.
- [ ] Remove the later unchecked sum and use the validated `body_len` for
  `content_length_n`.
- [ ] Preserve the existing allocation → initialization → commit sequence,
  three-buffer body chain, `ngx_http_send_header()`, output filter, single
  finalization, and `NGX_DONE` result.

### 1.4 Prove runtime behavior

- [ ] Add an integration assertion that every non-HEAD HTML challenge has
  `length(body) < POW_CHALLENGE_PAGE_MAX_BODY_LEN`. Read the simple numeric
  define from `src/pow_protocol.h` in the test setup; do not duplicate the
  value in Perl. Continue to assert exact body and content length for both
  HTTPS protocol variants.
- [ ] Run policy, unit, module, and the focused integration file:

```sh
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  sh -c 'make check-policy test-unit module && \
    TEST_NGINX_BINARY=/usr/sbin/nginx \
    POW_MODULE_PATH=/work/out/ngx_http_pow_module.so \
    TEST_NGINX_SERVROOT=/tmp/ngx-powgate-test \
    prove -Itests/integration/lib -v tests/integration/pow_challenge.t'
```

Expected: policy, all unit tests, module build, and the complete challenge
integration file pass; its HTTP/1.1 and HTTP/2 assertions remain active.

### 1.5 Commit

- [ ] Inspect `git diff --check` and confirm no generated header is staged.
- [ ] Commit:

```sh
git add src/pow_protocol.h src/pow_challenge.h src/pow_challenge.c \
  src/ngx_http_pow_module.c tests/unit/test_challenge.c \
  tests/integration/pow_challenge.t
git commit -m "feat: bound challenge response body"
```

---

## Task 2: Build the Exact-Script Harness and Pure JavaScript SHA-256

**Files:**

- Create: `tests/e2e/lib/challenge-script.mjs`
- Create: `tests/e2e/solver.test.mjs`
- Modify: `html/challenge.html`
- Modify: `Makefile`

### 2.1 Introduce the dependency-free Node gate

- [ ] Add `test-js` to `.PHONY` and define it as:

```make
test-js:
	node --test tests/e2e/solver.test.mjs
```

Add `controller.test.mjs` to this recipe in Task 4 when that file is created.

- [ ] Add `test-js` as a prerequisite of `test-e2e`; add it directly to
  `check` only if doing so does not duplicate execution through `test-e2e`.
  The final graph must execute it exactly once in `make check`.

### 2.2 Write the extraction and VM-harness tests first

- [ ] Create a narrow helper that reads raw bytes from
  `html/challenge.html`, requires exactly one literal executable `<script>`
  opening, finds its immediately corresponding `</script>`, and returns the
  bytes between them without normalization. A served page may also contain
  the one attributed non-executable params script; never confuse it with the
  literal executable opening.
- [ ] Keep decoding to UTF-8 explicit and fatal. The helper must not use a
  browser HTML parser or a permissive regular expression that accepts script
  attributes.
- [ ] Create a VM context with only deliberately supplied globals. Inject the
  host `Uint8Array` constructor so test values and production input validation
  share one realm.
- [ ] State in the helper's comment that `node:vm` provides deterministic
  isolation, not a security boundary.
- [ ] Add initial tests asserting that evaluating the current exact script
  installs a frozen `globalThis.PowGateSolver` with exactly the enumerable
  own keys `sha256` and `solve`, both functions.
- [ ] Run and confirm the expected red state against the inert placeholder:

```sh
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  node --test tests/e2e/solver.test.mjs
```

Expected: the namespace assertion fails because the placeholder installs no
solver; extraction itself passes.

### 2.3 Implement only the public namespace and SHA-256 primitive

- [ ] Replace the placeholder script with an IIFE using strict mode. Install
  the public namespace exactly once as:

```js
globalThis.PowGateSolver = Object.freeze({ sha256, solve });
```

At this step `solve()` may reject with a fixed internal error, but it must
already have the final five-argument signature and Promise result type.
- [ ] Implement a compact SHA-256 in the same inline script. `sha256(bytes)`
  must:

  - accept only `Uint8Array`;
  - never mutate the input;
  - allocate fresh 32-byte output on every call;
  - correctly handle all message lengths required by SHA-256;
  - avoid DOM, clocks, timers, provider state, and mutable globals.

- [ ] Keep protocol-independent SHA constants private and immutable. Do not
  export a backend, version, controller, K table, configuration, or state.

### 2.4 Expand SHA and namespace tables

- [ ] Add SHA-256 known answers generated from fixed checked-in hex strings
  for:

  - empty input;
  - representative binary including zero and `0xff` bytes;
  - lengths 55, 56, 63, 64, and 65 bytes;
  - the canonical vector message `nonce_raw || "34"`.

- [ ] Compare digest bytes, not hex produced by production code. Use
  `node:crypto` only in the test side to establish expected bytes where the
  expected literal is not checked in.
- [ ] Assert input preservation, fresh output storage, exact output length,
  synchronous `TypeError` for invalid input types, namespace key count, and
  object freezing.
- [ ] Run:

```sh
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  node --test tests/e2e/solver.test.mjs
```

Expected: namespace and all SHA tests pass; only the intentionally unimplemented
bounded-solver cases remain absent.

### 2.5 Policy, body budget, and commit

- [ ] Run `make check-policy test-js module` in Podman. Building the module
  regenerates the page header and exercises the compile-time worst-case body
  budget after the SHA implementation is added.
- [ ] Search the exact script for forbidden browser dependencies. The search
  is a review aid; the executable negative tests in Task 4 are authoritative.
- [ ] Commit:

```sh
git add Makefile html/challenge.html tests/e2e/lib/challenge-script.mjs \
  tests/e2e/solver.test.mjs
git commit -m "feat: add browser sha256 primitive"
```

---

## Task 3: Implement the Frozen Bounded Solver Contract

**Files:**

- Modify: `html/challenge.html`
- Modify: `tests/e2e/solver.test.mjs`

### 3.1 Add the full result-contract table before implementation

- [ ] Add exact tests for
  `solve(nonce, difficulty, startCounter, maxAttempts, backend)` covering:

  - canonical vector success at counter `34`;
  - a resumable miss with `{ found: false, exhausted: false,
    counter: null, nextCounter: firstUntested, attempts: maxAttempts }`;
  - success at `Number.MAX_SAFE_INTEGER` without increment, using a fixed
    deterministic subtle-provider digest fixture;
  - safe exhaustion after testing `Number.MAX_SAFE_INTEGER` and failing,
    using the complementary fixed provider fixture;
  - success before `maxAttempts` with the actual smaller attempt count;
  - frozen results with exactly `found`, `exhausted`, `counter`,
    `nextCounter`, and `attempts`;
  - sequential repeated calls with no overlapping or skipped candidate;
  - all invalid nonce, difficulty, counter, attempt-bound, and backend inputs.

- [ ] Assert Promise behavior for both backends. Do not assert that the JS
  call returns control before doing its bounded synchronous work.
- [ ] Run the focused test and confirm the expected failures come from the
  placeholder `solve()` implementation.

### 3.2 Implement shared search semantics with backend-specific digests

- [ ] Add private helpers for:

  - safe-integer argument validation;
  - canonical ASCII decimal counter encoding;
  - exact `nonce_raw(32) || counter_ascii` construction;
  - leading-zero-bit comparison for difficulty 1–32;
  - construction and freezing of the exact result object;
  - pure-JS digest and WebCrypto digest dispatch.

- [ ] Preserve one contiguous search loop semantic. For each candidate:

```text
construct exact message
digest through selected backend
increment actual attempts
test leading-zero predicate
if found -> success
if candidate == MAX_SAFE_INTEGER -> exhausted
otherwise advance exactly once
```

- [ ] For `backend === "js"`, execute the bounded loop synchronously before
  returning/resolving its Promise; avoid per-hash Promise overhead.
- [ ] For `backend === "subtle"`, require
  `crypto.subtle.digest("SHA-256", exactMessage)` and await exactly one digest
  per candidate. Never use `Promise.all`, batching, parallel candidates, or
  a different search order.
- [ ] Avoid retaining state between calls. It is acceptable to reuse a
  private scratch buffer only within one invocation; never expose a view of
  it or keep it globally mutable.
- [ ] Never calculate `Number.MAX_SAFE_INTEGER + 1`. Check the exhaustion
  condition before constructing `nextCounter`.

### 3.3 Verify both backends and provider failures

- [ ] Where the container's Node supplies WebCrypto, run the same result
  tables against `"js"` and `"subtle"`; do not skip the JS table.
- [ ] Wrap the fake subtle provider to record each exact digest input and
  assert candidates are sequential and only one digest is outstanding.
- [ ] Test absent `crypto`, absent `subtle`, thrown provider setup, and rejected
  digest. Every provider failure must reject; it must never resolve a miss.
- [ ] Compare both backends on the canonical vector's exact message bytes,
  digest, found counter, and result semantics.
- [ ] Run:

```sh
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  node --test tests/e2e/solver.test.mjs
```

Expected: all public solver-contract tests pass with no skip/TODO.

### 3.4 Verify the body budget and commit

- [ ] Run `make check-policy test-js module` in Podman so the larger production
  script passes the generated-page body budget before commit.
- [ ] Commit:

```sh
git add html/challenge.html tests/e2e/solver.test.mjs
git commit -m "feat: add bounded browser solver"
```

---

## Task 4: Add Strict Initialization, Backend KAT, and Cookie Cleanup

**Files:**

- Modify: `html/challenge.html`
- Create: `tests/e2e/controller.test.mjs`
- Modify: `tests/e2e/lib/challenge-script.mjs`
- Modify: `Makefile`

### 4.1 Build the narrow deterministic controller harness

- [ ] Extend the shared helper with small fakes only for the browser values the
  frozen design allows:

  - one `pow-params` data node;
  - status, progress, and retry elements;
  - `document.hidden`, `document.cookie`, and one visibility listener;
  - `location.protocol`, `location.pathname`, and reload count;
  - monotonic fake `performance.now()`;
  - a FIFO zero-delay timer queue;
  - selectable WebCrypto digest behavior.

- [ ] Model cookie name, value, Path, Secure, and `Max-Age=0` only as far as
  needed to prove the specified visible-cookie contract. Do not create a
  generic browser or HTTP framework.
- [ ] Make forbidden globals throw if read or called: `fetch`,
  `XMLHttpRequest`, `WebSocket`, `Worker`, `importScripts`, dynamic script
  creation, local/session storage, randomness, console, `navigator`, and
  `screen`.
- [ ] Evaluate exact production bytes first and start the private controller
  via one queued zero-delay task. This permits deterministic setup without a
  test-only production branch.
- [ ] Add `tests/e2e/controller.test.mjs` to the `test-js` recipe now that the
  file exists. Keep solver and controller tests in one dependency-free Node
  invocation.

### 4.2 Add strict parameter tests before parsing code

- [ ] Table-test the sole `pow-params` object. Accept only exact own keys
  `v`, `d`, `b`, and `n` with:

  - `v === 1` as a number;
  - integer `d` from 1 through 32;
  - canonical uint64 decimal `b`, lexically bounded by
    `18446744073709551615` without Number or BigInt conversion;
  - canonical 43-character unpadded base64url `n`, valid unused tail bits,
    and exactly 32 decoded bytes.

- [ ] Reject missing nodes, JSON failures, arrays/null, missing or extra own
  keys, inherited substitutions, wrong types, leading-zero buckets, values
  above uint64, base64 padding, bad alphabet, bad tail bits, and wrong decoded
  length.
- [ ] Every invalid case must reach the same static failure state: fixed text,
  progress inactive/hidden as designed, retry visible, no console, no cookie
  write, no mining call, and no automatic reload.

### 4.3 Implement accessible page structure and single-start initialization

- [ ] Update the page to contain exactly one `<main>`, fixed heading, one
  `aria-live="polite"` status, one native `<progress max="1">`, one initially
  hidden `button[type=button]`, one `<noscript>`, the marker/params block, and
  the one executable script.
- [ ] Keep all style inline and the existing CSP unchanged. Add no external
  element, resource, preload, or dynamic script.
- [ ] Implement a private state machine with states `initializing`, `mining`,
  `paused`, `success`, `reloading`, and `failure`. Install handlers at most
  once and make them inert after terminal entry.
- [ ] Resolve the solver functions through the installed
  `globalThis.PowGateSolver` namespace when the queued controller start runs.
  This uses the same production functions and lets the VM harness wrap the
  complete frozen namespace after evaluation without adding a test branch.
- [ ] Failure rendering uses only fixed literal text. Retry calls
  `location.reload()` once and never recursively invokes controller code.

### 4.4 Implement exact proof-cookie scanning and stale-cookie cleanup

- [ ] Add a private forward cookie scanner whose occurrence rule is:

  - segment begins at string start or after `;`;
  - skip only SP and HTAB before the pair;
  - name matches `__pow_p` byte-for-byte and is followed immediately by `=`;
  - value is the remainder of that segment, without decoding or trimming;
  - empty segments are ignored.

- [ ] Validate `location.pathname` starts with `/` and contains no control,
  SP, HTAB, or semicolon byte before placing it in a Path attribute.
- [ ] Derive `/` and every distinct segment-boundary prefix applicable to the
  current pathname. Expire the proof cookie once at each with
  `Max-Age=0; Path=<candidate>; SameSite=Lax`, adding `Secure` only for HTTPS.
- [ ] After cleanup, re-read the cookie jar and require zero exact proof-cookie
  occurrences. A remaining Domain/path-shadowed occurrence is terminal
  failure, not a reload or mining start.
- [ ] Reject schemes other than `http:` and `https:` before writing any cookie.

### 4.5 Implement the production-shaped backend self-test and one fallback

- [ ] Use the immutable v1 vector constants:

```text
nonce = c382cd45c32e81f6f5bdcc5fb29497876a3d4364b688245668ab1b578ff7184f
counter ASCII = "34"
digest = 0028df459a18ed1973ccbfb54439b98bef2e3988fb5072e2fd3b8a1368d275f5
difficulty = 8
```

- [ ] For backend `"js"`, use the same private JS digest primitive used by
  `solve()`. For `"subtle"`, use the same subtle digest adapter used by
  `solve()`.
- [ ] Perform exactly one candidate digest, compare all 32 expected bytes, and
  separately verify the leading-zero predicate. Do not run a proof search and
  do not add a digest field to the public result.
- [ ] Try fixed primary `"js"` first. Fall back once to `"subtle"` only for
  missing capability, setup/digest exception, or KAT mismatch. If both fail,
  enter terminal failure.
- [ ] Slow mining, page hiding, navigation, or a later solve rejection are not
  initialization failures and must never trigger backend switching.

### 4.6 Verify initialization tables

- [ ] Use a post-evaluation wrapper around the writable global namespace in
  the VM harness to induce primary KAT failure and prove exactly one subtle
  fallback without adding a production test switch.
- [ ] Prove primary success performs no subtle KAT, primary failure performs
  one subtle KAT, dual failure shows static failure, and selected backend is
  retained for mining.
- [ ] Prove forbidden globals remain untouched on successful initialization.
- [ ] Run:

```sh
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  node --test tests/e2e/solver.test.mjs tests/e2e/controller.test.mjs
```

Expected: strict parser, page lifecycle, KAT/fallback, cleanup, namespace,
SHA, and bounded-solver tests all pass.

### 4.7 Commit

- [ ] Run `make check-policy test-js test-tools module` in Podman. The module
  build must still satisfy the strict assembled-page budget.
- [ ] Commit:

```sh
git add Makefile html/challenge.html tests/e2e/lib/challenge-script.mjs \
  tests/e2e/controller.test.mjs
git commit -m "feat: initialize browser challenge controller"
```

---

## Task 5: Add Foreground Scheduling, Progress, Success Cookie, and Reload

**Files:**

- Modify: `html/challenge.html`
- Modify: `tests/e2e/controller.test.mjs`
- Modify: `tests/e2e/lib/challenge-script.mjs`

### 5.1 Add scheduling and resumability tests first

- [ ] Table-test mining with fake elapsed time and a wrapped public
  `solve()` that records every call. Prove:

  - the first candidate is zero;
  - calls are contiguous through each returned `nextCounter`;
  - a slice targets approximately 10 ms of foreground elapsed time;
  - block sizes begin small and adapt from observed attempts/time;
  - deadline and visibility are checked between bounded calls;
  - exactly one zero-delay macrotask is queued after an incomplete slice;
  - no timer or new solve call is scheduled while hidden;
  - a running bounded result is retained before entering `paused`;
  - visibility resume retains backend, next counter, total attempts, and
    displayed progress;
  - no duplicate or skipped candidates occur across pause/resume.

- [ ] Keep adaptive policy private and bounded. A suitable initial policy is:

```text
slice target: 10 ms
first block: 1 candidate
inner target: about 2 ms
next block: clamp(floor(attempts * 2 / max(elapsed, 0.25)), 1, 4096)
```

Tests should assert safety properties and adaptation direction, not every
floating-point intermediate, so equivalent bounded tuning remains possible.

### 5.2 Implement controller-owned scheduling

- [ ] Implement one foreground slice function using `performance.now()`.
  The controller, never `solve()`, owns the deadline, block estimate,
  visibility checks, timer yield, and accumulated work.
- [ ] Await each bounded call, commit its frozen result exactly once, and
  transition:

  - `found` → `success`;
  - `exhausted` → fixed terminal failure;
  - resumable miss → retain `nextCounter` and continue/yield;
  - rejection after successful KAT → fixed terminal failure with no fallback.

- [ ] Install one `visibilitychange` listener. Hidden pages schedule no new
  work; visible paused pages schedule exactly one continuation.
- [ ] Ignore late timer/listener activity after `success`, `reloading`, or
  `failure`.

### 5.3 Add and implement probability progress

- [ ] Add tests for the displayed formula:

```js
Math.min(0.99, 1 - Math.exp(-attempts / (2 ** difficulty)))
```

Prove progress is updated only after completed foreground slices, remains
monotonic, exposes no attempts/counters/backend/difficulty in text, remains
below one while mining, does not reset on pause, and becomes exactly one only
after success.
- [ ] Keep progress computation outside every hash loop and bounded solver
call.

### 5.4 Add and implement the success transaction

- [ ] Table-test exact serialization for HTTP and HTTPS:

```text
__pow_p=1.<canonical-bucket>.<canonical-counter>; Path=/; SameSite=Lax
```

Append `; Secure` only for `https:`. Assert the absence of Domain, Expires,
and Max-Age.
- [ ] Require `counter` to be a safe nonnegative integer and serialize with
  `String(counter)`, producing canonical ASCII decimal.
- [ ] After writing, synchronously scan `document.cookie` and require exactly
  one exact-name occurrence whose value is exactly
  `1.<bucket>.<counter>`.
- [ ] Prove blocked writes, zero visible occurrence, duplicates, mismatches,
  a stale shadow, and unsupported schemes enter terminal failure without
  reload.
- [ ] Prove the successful path sets progress to one, writes once, validates
  once, transitions to terminal `reloading`, and calls `location.reload()`
  exactly once.
- [ ] Prove retry navigation is separate: failure never reloads automatically,
  and one retry click invokes one reload without restarting state.

### 5.5 Run controller and solver tests

- [ ] Run:

```sh
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  make check-policy test-js module
```

Expected: exact solver and all controller tables pass without skipped cases,
TODOs, console output, or network/storage access, and the assembled-page
compile-time budget remains green.

### 5.6 Commit

- [ ] Commit:

```sh
git add html/challenge.html tests/e2e/lib/challenge-script.mjs \
  tests/e2e/controller.test.mjs
git commit -m "feat: run browser proof controller"
```

---

## Task 6: Close the Exact-Byte Generator and NGINX Delivery Loop

**Files:**

- Modify: `tools/build_pow_challenge.py`
- Modify: `tests/tools/test_build_pow_challenge.py`
- Modify: `tests/e2e/lib/challenge-script.mjs`
- Modify: `tests/e2e/smoke.mjs`
- Modify: `tests/integration/pow_challenge.t`
- Modify: `tests/integration/pow_challenge_composition.t` if its fixed page
  assertions require the new structure
- Modify: `Makefile`

### 6.1 Make generator tests use the actual production script

- [ ] Remove the hardcoded placeholder `SCRIPT` expectation. Read the real
  template bytes, extract its exact sole executable body, and use those bytes
  as the digest input expected from the generator.
- [ ] Keep synthetic invalid-template cases small and independent. Retain
  rejection of empty input, BOM, NUL, invalid UTF-8, missing/duplicate marker,
  marker after/inside script, multiple/attributed/case-varied scripts, missing
  close, and empty script.
- [ ] Add assertions that:

  - emitted prefix and suffix reconstruct the template minus only the marker;
  - the executable slice extracted from the emitted page is byte-identical to
    the source slice;
  - the emitted 44-byte base64 digest equals SHA-256 of those exact bytes;
  - generated output retains its warning and deterministic atomic replacement;
  - generated output leaves the production C compile-time size assertion in
    control of the worst-case assembled body limit.

- [ ] Run the test before changing the builder and confirm only stale
  placeholder/body-limit expectations fail.

### 6.2 Remove the generator's duplicate semantic limit

- [ ] Keep `POW_CHALLENGE_PAGE_MAX_BODY_LEN` authoritative in
  `src/pow_protocol.h`. Remove the generator's current `PAGE_LIMIT` constant
  and the Python-only `15 kib` invalid-template row; they duplicate a
  protocol constant and measure the template rather than the assembled body.
- [ ] Do not replace them with a numeric Python or Makefile copy. The C
  compile-time worst-case assertion and pure runtime helper from Task 1 own
  the semantic body limit; the NGINX integration test reads the named numeric
  define when asserting actual responses.
- [ ] Preserve every structural template validation, atomic replacement, and
  exact raw-byte extraction. Do not normalize whitespace, line endings,
  Unicode, or script text.

### 6.3 Make the VM harness prove generator/hash identity

- [ ] Add helper logic to invoke the builder into a temporary directory,
  decode the emitted byte arrays, and assert:

```text
exact script bytes from html/challenge.html
  == executable bytes reconstructed from emitted prefix/suffix
  == bytes whose SHA-256 matches the emitted CSP digest array
```

- [ ] Keep this as a test helper only. Never read generated C from production
  JavaScript.
- [ ] Add cross-language drift assertions which read the simple defines in
  `src/pow_protocol.h` and the immutable case in `tests/vectors/v1.json`, then
  prove the exact production script agrees on protocol version, difficulty
  bounds, fixed proof-cookie name, safe counter maximum, nonce/digest/counter
  KAT, and proof serialization. Strip C integer suffixes in test code; never
  copy the numeric or string values into a second test constant.

### 6.4 Update the real-NGINX smoke test

- [ ] Replace the placeholder literal assertion with shared exact-script
  extraction and digest assertions.
- [ ] Continue generating an isolated self-signed certificate inside the
  runtime prefix and using a test-only client TLS exception.
- [ ] Retain explicit TLS, ALPN `http/1.1`, status, exact public header,
  content-length, CSP, and backend-not-reached assertions.
- [ ] Evaluate the served exact production script in the deterministic VM
  harness with a low-cost deterministic controller scenario. Assert zero
  console access/output and a valid terminal harness outcome; do not claim
  browser-engine coverage or perform the Phase 4C authenticated loop.
- [ ] Assert no secret material, debug header, or unexpected PowGate header is
  present.

### 6.5 Retain the full HTTP/1.1 and HTTP/2 exact-byte matrix

- [ ] Update Perl exact-page reconstruction only as required by the new HTML.
  Continue deriving the CSP hash from exact script bytes at test time.
- [ ] Assert the actual assembled body is below the numeric value read from
  `POW_CHALLENGE_PAGE_MAX_BODY_LEN` and content length is exact for non-HEAD
  requests.
- [ ] Confirm both forced HTTPS HTTP/1.1 and HTTP/2 scenarios still assert the
  negotiated protocol rather than merely accepting a successful response.
- [ ] Do not execute browser controller behavior in Perl; Node owns that
  concern.

### 6.6 Run focused delivery gates

- [ ] Run:

```sh
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  make check-policy test-tools test-js module test-integration test-e2e
```

Expected: generator, exact-script, controller, module, all HTTPS integration,
and real-NGINX smoke tests pass. No test is skipped or marked TODO.

### 6.7 Commit

- [ ] Verify `git status --short` contains no `build/generated` or other build
  artifacts.
- [ ] Commit:

```sh
git add Makefile tools/build_pow_challenge.py \
  tests/tools/test_build_pow_challenge.py \
  tests/e2e/lib/challenge-script.mjs tests/e2e/smoke.mjs \
  tests/integration/pow_challenge.t \
  tests/integration/pow_challenge_composition.t
git commit -m "test: verify browser challenge delivery"
```

If `pow_challenge_composition.t` did not change, omit it from `git add`.

---

## Task 7: Documentation, Full Gate, and Phase Freeze

**Files:**

- Modify: `PLAN.md`
- Modify: `README.md`
- Modify: `docs/configuration.md`
- Modify: `docs/security.md`
- Modify: `AGENTS.md`

### 7.1 Update documentation to implemented reality

- [ ] Expand Phase 4B in `PLAN.md` to reference the frozen design and record:

  - exact two-function namespace and five-field result;
  - JS-primary/subtle-single-fallback policy;
  - production-shaped one-candidate KAT;
  - strict parameters and safe counter domain;
  - controller scheduling, hidden pause, progress, cookie cleanup/readback;
  - exact-byte Node/generator/HTTPS H1/H2 tests;
  - strict assembled-body limit.

- [ ] Mark Phase 4B complete only after all Task 7 gates pass. Keep Phase 4C
  explicitly responsible for real browser execution, backend benchmarking,
  CSP enforcement by a browser engine, reload/proof verification/auth-cookie
  issuance, proof clearing, and authenticated backend pass-through.
- [ ] Update README and operational/security docs with concise visitor-facing
  behavior, HTTPS recommendation, JavaScript requirement, statelessness,
  fail-visible browser behavior, and no external resources/tracking.
- [ ] Do not describe Node's VM harness as a browser or security sandbox.
- [ ] Update `AGENTS.md` with the enduring cross-language rule: the browser is
  an independent protocol consumer, so any required mirrored v1 wire literal
  must be pinned by a regression against `src/pow_protocol.h` or the immutable
  canonical vector. Also record exact production-script testing if it is not
  already covered. Do not add task order, tuning values, or temporary Phase 4B
  notes.

### 7.2 Run static completion audits

- [ ] From the host, inspect only (do not execute project code):

```sh
rg -n "placeholder|TODO|FIXME|skip|\.skip\(|test\.skip" \
  html src tests tools Makefile PLAN.md README.md docs AGENTS.md
git status --short
git diff --check
```

- [ ] Classify every hit. Remove stale Phase 4B placeholders/TODOs; do not
  erase legitimate historical or future-phase prose merely to satisfy grep.
- [ ] Verify exactly one `<!-- POW:PARAMS -->` marker and exactly one
  executable `<script>` remain in `html/challenge.html`.
- [ ] Verify no npm lockfile, browser package, committed generated header,
  fault artifact, or test-only production switch was added.

### 7.3 Run a clean full project gate in Podman

- [ ] Remove only generated/build outputs through the project target, then run
  the authoritative complete gate:

```sh
podman run --rm -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  sh -c 'make clean && make check'
```

Expected evidence:

- policy gate passes;
- Python tooling tests pass;
- every pure C unit and coverage gate passes;
- module and both fault variants build in their correct output trees;
- the complete HTTPS HTTP/1.1 and HTTP/2 integration suite passes;
- exact solver/controller Node tests and real-NGINX smoke pass;
- all three fuzz smoke targets pass;
- ASan/UBSan rebuild and implemented categories pass;
- no required case is skipped or TODO.

- [ ] Run the release-duration fuzz gate only if this branch is being prepared
  for a release tag; otherwise record that `make test-fuzz-long` remains the
  release-only gate and do not imply it ran.

### 7.4 Inspect artifacts and request review

- [ ] Run inside Podman or inspect generated file names from the host:

```sh
test -f out/ngx_http_pow_module.so
test -z "$(find out -type f -name '*fault*' -print)"
git status --short
git diff --check
```

- [ ] Review the diff against every bullet in the frozen design, especially:
  exact result terminal states, KAT digest path, MAX_SAFE exhaustion, one
  fallback, terminal handler inactivity, cookie exact-name/readback rules,
  and body-size enforcement before response commitment.
- [ ] Use `superpowers:requesting-code-review` for an independent requirements
  and implementation review before claiming completion or merging.
- [ ] Resolve review findings with focused red/green tests and rerun the
  affected gates. If any source changes after the full gate, rerun at least
  `make check-policy` plus every affected category; rerun full `make check`
  before final approval.

### 7.5 Commit documentation after verified implementation

- [ ] Commit only after the full gate and review are green:

```sh
git add PLAN.md README.md docs/configuration.md docs/security.md
git add AGENTS.md
git commit -m "docs: document browser solver"
```

- [ ] Use `superpowers:verification-before-completion` before reporting the
  branch ready. Report exact commands and outcomes; never summarize a stale or
  pre-fix test run as current evidence.

## Definition of Done

- The inert placeholder is gone and the exact served inline bytes implement
  the frozen two-function solver plus private controller.
- JS and subtle backends share identical sequential bounded-search semantics
  and the exact five-field frozen result.
- The controller validates parameters, performs the one-candidate KAT,
  schedules foreground work, pauses hidden work, reports bounded probability
  progress, cleans and validates proof cookies, and reloads exactly once only
  after readback.
- Failure is visible, static, nondiagnostic, and manually retryable without
  automatic reload loops.
- The generator, emitted digest, NGINX CSP, served executable bytes, and Node
  test bytes are proven identical.
- The actual assembled response remains strictly below 15,360 bytes and is
  rejected before response commitment if the invariant fails.
- HTTPS HTTP/1.1 and HTTP/2 integration, exact Node tests, unit/coverage,
  fuzz-smoke, ASan/UBSan, policy, and artifact gates pass in the golden Podman
  image.
- Documentation describes Phase 4B honestly and leaves real browser behavior
  and backend measurement to Phase 4C.
