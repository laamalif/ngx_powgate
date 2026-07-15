# Phase 4C native browser verification and benchmark design

## Purpose and authority

Phase 4C proves the complete PowGate browser loop in one pinned, native,
sandboxed x86_64 Chromium environment:

```text
503 challenge -> production solver -> proof cookie -> reload
              -> server verification -> auth cookie -> backend 200
```

It also produces reproducible evidence comparing the existing pure-JavaScript
and sequential SubtleCrypto solver backends. Throughput evidence may change
only their fixed pre-search order.

This document supersedes the earlier standalone Chromium feasibility design
and plan. The feasibility check becomes one permanent layer of the Phase 4C
gate. It does not supersede `docs/protocol.md`; Phase 4C changes no v1 wire
format or server verification rule.

The partitioned-cookie amendment at
`2026-07-16-phase4c-partitioned-negative-matrix-amendment.md` supersedes the
original Section 7 negative-case construction. This document incorporates
that amendment so the matrix below is authoritative without cross-document
interpretation.

## 1. Scope, invariants, and non-goals

### Core invariants

- Chromium executes the exact production solver bytes generated from
  `html/challenge.html` and served by NGINX. There is no copied,
  reconstructed, mocked, or second solver.
- NGINX 1.30.3, Chromium, Puppeteer Core, Ajv, Node.js, the Debian snapshot,
  and every golden-image input are pinned.
- Browser targets run inside the canonical rootless Podman image with the
  Chromium sandbox enabled.
- Browser-specific gates require native x86_64 and fail on every other
  architecture. They never skip, emulate, attach to a remote browser, or
  substitute Node.js.
- HTTP/1.1 and HTTP/2 execute separately. Chrome DevTools Protocol (CDP)
  metadata proves the negotiated protocol.
- Wire formats, cookie formats, challenge parameters, server verification,
  and the CSP model remain unchanged. A backend-order decision may change
  only the production script and its deterministic CSP/build outputs.
- Every browser, NGINX process, context, profile, certificate, CDP session,
  temporary directory, and diagnostic resource has bounded, idempotent
  cleanup. Cleanup failure is reported independently and never hides an
  earlier failure.
- Throughput is evidence, not an absolute performance threshold. Correctness,
  responsiveness, environment identity, sandboxing, evidence validity, and
  cleanup are mandatory.

### Non-goals

Phase 4C does not:

- claim compatibility with every browser, device, operating system, or
  architecture;
- require ARM64 browser execution for v0.1;
- introduce x86-specific production code or protocol behavior;
- introduce runtime benchmarking, adaptive backend selection, mid-search
  migration, workers, parallel hashing, batching, or remote CDP;
- tune kernels, buffers, controller slices, or provider calls merely to
  improve throughput;
- alter the stateless protocol, cookies, CSP model, or verification bounds;
- create a reusable HTTP or browser framework.

## 2. Dependencies and locked environment

Phase 4C runs on the designated native x86_64 worker inside the canonical
Debian Trixie image. The host only inspects and starts Podman.

### Locked inputs

- Debian snapshot: `20260713T000000Z`
- NGINX source and runtime: `1.30.3`, with the existing source checksums
- Chromium: `150.0.7871.100-1~deb13u1`
  - package SHA-256:
    `87ce517f9fe47c4dcac35fc314fa4ab87117f2496dc27257de2bba11ef8af610`
- Chromium sandbox: `150.0.7871.100-1~deb13u1`
  - package SHA-256:
    `a02bc28af35c9cdbaaafb0affa004fa203cf4508d4c7fa280efdc7c521a380c3`
- Node.js: `20.19.2+dfsg-1+deb13u2`
  - package SHA-256:
    `3e2d151f46ae1f1ab644fa6d11d85e7cf30d9aa182935bc16b99bf9888be8a85`
- npm: `9.2.0~ds1-3`
  - package SHA-256:
    `1dda3b5d8ebcd9c88de0a697f2c7b3d893fd130d9bd2bafb7f237ce46aec9271`
- Puppeteer Core: `24.43.1`
- Ajv: `8.17.1`
  - integrity:
    `sha512-B/gBuNg5SiMTrPkC+A2+cW0RszwxYmn6VYxB/inlBStS5nx6xHIt/ehKRhIMhqusl7a8LjQoZnjCs5vhwxOQ1g==`

The snapshot must expose every exact package version and checksum. A newer
resolution is a build failure. `chromium` and `chromium-sandbox` must have
identical Debian versions.

`build/versions.env` owns the Debian package locks and golden-image input
lock. `build/browser/package.json` uses exact, range-free development
dependencies. `build/browser/package-lock.json` is authoritative for the npm
graph and integrity metadata.

Installation is:

```sh
npm ci --ignore-scripts --no-audit --no-fund
```

There is no `--omit=dev`: every npm dependency is test infrastructure.
Puppeteer Core never downloads or selects a browser. Every launch names
`/usr/bin/chromium`.

Policy rejects dependency ranges, manifest/lock/version disagreement,
undeclared dependencies, missing integrity metadata, browser-download
packages, and lifecycle-based browser acquisition.

### Golden-image identity

`GOLDEN_IMAGE_LOCK_SHA256` is computed from a fixed ordered encoding of:

- `Containerfile`;
- `build/install-dev.sh`;
- `build/versions.env`, excluding its own lock line;
- `build/browser/package.json`;
- `build/browser/package-lock.json`.

Policy recomputes the lock. Image construction embeds it as an OCI label and
an immutable environment value. In-container targets compare the environment
value with the repository. The host wrapper verifies the OCI label with
`podman image inspect`.

Benchmark evidence records the host-observed image ID, verified label,
embedded lock, and repository digest when one exists. A local build need not
have a repository digest.

### External browser pairing

Puppeteer Core and Debian Chromium are independent exact-version inputs.
Compatibility is not inferred from version numbers. The permanent feasibility
gate proves every API used by Phase 4C: launch, shutdown, contexts, pages,
targets, CDP, HTTPS, network events, protocol metadata, JavaScript, CSP,
cookies, reload, errors, crashes, and cleanup.

### Runtime and sandbox identity

Every browser target verifies:

- `uname -m` is `x86_64`;
- the controller is non-root;
- controller UID/GID equal the host values supplied by `--userns=keep-id`;
- `/proc/self/status` reports `Seccomp: 2`;
- controller `CapEff` is zero;
- installed packages and libraries match their locks;
- Chromium resolves to `/usr/bin/chromium`;
- package, command-line, and CDP Chromium versions agree;
- the tested Git source and worktree state satisfy the target;
- the embedded image lock equals the repository lock.

The zero-`CapEff` requirement is a locked property of this exact tested
rootless `--userns=keep-id` invocation. It is not a general claim that every
secure rootless-container layout must display a zero namespace-scoped
capability mask.

The host rejects rootful execution, privileged mode, added capabilities,
unconfined or weakened seccomp, and emulation. Requested and actual Chromium
descendant command lines are inspected. These arguments are forbidden:

```text
--no-sandbox
--disable-setuid-sandbox
--single-process
--no-zygote
--disable-seccomp-filter-sandbox
--disable-namespace-sandbox
```

Host profiles, remote endpoints, and automatic browser fallback are
prohibited. Allowed arguments are limited to headless operation, an ephemeral
profile, `--disable-dev-shm-usage`, fixture hostname mapping, explicit H1
selection, and bounded diagnostics/background-network isolation.

### TLS isolation

The ephemeral certificate contains SANs for `powgate.test` and
`gate.powgate.test`. Chromium resolves both through the fixed resolver rule.
Certificate relaxation is passed only to the isolated fixture browser. The
harness makes no host trust-store or production TLS change.

## 3. Make targets and architecture enforcement

Existing targets retain their meanings:

- `make check`: architecture-neutral project gate;
- `make test-e2e`: architecture-neutral Node/NGINX served-script smoke;
- `make test-fuzz-long`: release fuzz gate.

Phase 4C adds:

- `make test-browser-feasibility`;
- `make test-browser-e2e`;
- `make benchmark-browser`;
- `make check-browser-x86`.

Each browser target checks native architecture before creating any resource.
Only `x86_64` passes. Every other value fails with the public target name in
the diagnostic. There is no skip, emulation, remote browser, alternate
browser, or weakened success path.

`check-browser-x86` uses sequential recursive Make calls joined by `&&`:

```make
check-browser-x86:
	$(MAKE) test-browser-feasibility && \
	$(MAKE) test-browser-e2e && \
	$(MAKE) benchmark-browser
```

It never invokes the host wrapper from inside the container.

### Canonical host wrapper

`tools/run-browser-x86.sh` is the only supported host boundary. It accepts
exactly one of the four browser target names and rejects every other argument.
It verifies rootless Podman, the exact
`localhost/ngx-powgate-dev:trixie` image, OCI lock, AMD64 image architecture,
repository root, and canonical mount. It records image identity and host
UID/GID, then starts the fixed `--userns=keep-id` container command.

The wrapper accepts no caller Podman option, image, entrypoint, architecture,
network, namespace, capability, security option, device, mount, browser path,
endpoint, or Chromium argument. It rejects non-empty
`POW_GATE_BROWSER_WS_ENDPOINT`, `PUPPETEER_BROWSER_WS_ENDPOINT`,
`PUPPETEER_EXECUTABLE_PATH`, and `CHROME_PATH` with a direct diagnostic.
Values forwarded to the container are populated by the wrapper, not inherited
unchecked.

The wrapper has no SSH logic. A development host may invoke it over SSH, but
SSH is outside the harness.

`benchmark-browser` writes only
`build/benchmark-browser-result.json`. No Make target writes committed
evidence. Dirty development results are non-promotable.

The logical release gate is:

```text
make check
make check-browser-x86
make test-fuzz-long
```

All three Make targets execute inside the golden image. The host performs
only fixed image inspection, metadata collection, container invocation, and
exit-status propagation.

## 4. Shared fixture lifecycle and cleanup contract

`tests/browser/lib/fixture.mjs` owns lifecycle only. It does not decide
whether PowGate behavior is correct.

It owns one runtime root, ephemeral certificates, NGINX configuration and
processes, loopback ports, Chromium profile/process/contexts/pages, CDP
sessions, bounded observations, diagnostics, and cleanup. It exposes raw
resources and observations. It contains no PowGate assertion, case matrix,
cookie-format rule, benchmark decision, or evidence-schema interpretation.

The lifecycle is single-use:

```text
created -> starting -> ready -> stopping -> stopped
                    \-> failed -/
```

`withFixture(options, callback)` guarantees cleanup through `finally`.
Callback failure remains primary; diagnostic and cleanup failures attach as
separately classified secondary failures. Cleanup is idempotent.

### Runtime isolation and diagnostics

Each invocation owns:

```text
build/browser-runtime/<target>-<pid>-<random>/
```

It shares no certificate, key, profile, cache, cookie database, NGINX prefix,
or content. Private keys are owner-only. Successful runs remove the directory.

Failed runs may retain a bounded sanitized bundle under
`build/browser-diagnostics/`. Redaction occurs before persistence. Allowed
content is limited to environment/version identity, verified process metadata
and command lines, exit status, named timeout, bounded event types/counts,
status/protocol/header-name metadata, sanitized NGINX errors, and fixed
verdicts.

Retained diagnostics never contain cookie/proof/auth values, nonces,
challenge JSON, secrets, key contents, raw CDP, unrestricted headers or
console text, cookie databases, browser profiles, or unsanitized access logs.
Overflow fails rather than silently truncating successful evidence.

### Ports and readiness

The fixture reserves loopback ephemeral ports, releases them immediately
before NGINX startup, and retries the entire allocation/start sequence at most
three times. Retry is allowed only when captured NGINX diagnostics identify
an EADDRINUSE-equivalent bind failure for a selected port. Configuration,
module, TLS, permission, directive, unexplained-exit, and readiness failures
fail immediately.

Readiness polls an isolated HTTPS endpoint and verified master state. Fixed
sleeps are never readiness proof.

### Process identity and shutdown

Every process is tracked by PID, parent PID, `/proc/<pid>/stat` start time,
expected executable, and a fixture-specific prefix/profile argument. Every
signal and liveness check revalidates identity, preventing PID-reuse damage.

NGINX uses an isolated prefix, config, PID file, logs, and foreground master.
Shutdown sends `QUIT` directly to the verified master, waits for master and
workers, escalates to `TERM`, then uses `KILL` only as the final bounded
emergency action. Any escalation beyond `QUIT` is a cleanup failure.

Chromium always launches through Puppeteer with `/usr/bin/chromium`, a unique
profile, and the validated arguments. Browser and descendant identities,
arguments, versions, contexts, targets, CDP sessions, disconnects, crashes,
page errors, console metadata, CSP events, request failures, and navigation
metadata are bounded and recorded transiently.

Cleanup freezes observations and sanitizes diagnostics, detaches CDP, closes
pages/contexts/browser, verifies Chromium exit, terminates only remaining
verified Chromium identities, gracefully stops NGINX with bounded escalation,
closes fixture file descriptors, removes runtime material, and verifies no
owned identity remains. It never kills by name, user, broad group, or
unverified PID.

## 5. Browser feasibility gate

`tests/browser/feasibility.mjs` proves the locked browser pairing without
loading PowGate. A minimal isolated NGINX serves static HTTPS, CSP, cookie,
and reload fixtures. `nginx -t` runs before startup.

Two fresh Chromium processes prove normal H2 and explicitly disabled-H2 H1.
CDP must report `h2` or `http/1.1` for the main response. Both SAN hostnames
navigate successfully.

The gate proves launch/version, context/page/target/CDP lifecycle, HTTPS,
resolver behavior, network observation, JavaScript, reload, cookie
creation/inspection/deletion, and clean shutdown. A fixed hashed inline script
executes; an injected unauthorized script does not, and its expected CSP
violation is observed.

The sandbox verdict means that all approved observable acceptance properties
passed; it does not claim to verify every internal Chromium sandbox layer.
Those properties are successful operation without prohibited flags, separate
browser and renderer identities, non-root execution, active seccomp in the
controller and at least one renderer, zero controller capabilities under the
canonical invocation, and no weakened container policy. `/proc` identity
fields including `NoNewPrivs`, `Seccomp`, `CapEff`, `Uid`, and `Gid` are
recorded when available. Optional Chromium process types are validated when
observed but are not universally required.

Disposable pages exercise controlled console, page-error, request-failure,
renderer-loss, and disconnect observation. Each probe has its own event
window and fixed safe identifier. The renderer-crash probe crashes only a
disposable renderer, accepts documented target/page loss races, requires a
separate control page and browser connection to remain usable, and fails if
the browser exits.

Any missing API, timeout, unexpected event, crash outside the controlled
probe, orphan, cleanup escalation, or incompatible pairing fails. Nothing is
skipped based on version detection.

## 6. Positive HTTP/1.1 and HTTP/2 E2E matrix

`tests/browser/e2e.mjs` executes the exact production page. Each protocol run
uses an independent fixture and Chromium process:

```text
Chromium -> HTTPS PowGate listener -> loopback NGINX backend listener
```

The fixture uses the production module and page, a secure fixture secret,
difficulty 8, secure cookies, fixed backend content, and no redirect or
external resource. A dedicated backend log proves protected content reach
without adding another process.

Each protocol process uses four fresh contexts with literal source URLs:

1. `/`
2. `/account;view=full?mode=literal&value=1`
3. `/a%3Bb//c?mode=encoded&value=%2F`
4. `/account/orders?mode=stale`

No URL helper may decode, merge, or reconstruct them. The stale case seeds a
distinguishable host-only Secure path-scoped `__pow_p` on a safe ancestor.
Raw cookie values are never retained.

Every case must produce exactly one 503 document, one uninterrupted proof
search episode, one submitted proof, one reload of the same browser-visible
URL, one server verification path, one backend request, and one final 200.
The controller may make multiple bounded `solve()` calls while yielding; that
does not create another proof-search episode. CDP proves the expected protocol
on both document responses. There is no redirect, third navigation, loop, or
challenge backend reach.

Exactly one controller start occurs for the challenge document. The bounded
calls cover one contiguous counter sequence, exactly one successful proof
cookie write occurs, and no second controller search begins before or after
reload. Phase 4B's exact-script controller trace proves call-by-call counter
continuity; Phase 4C proves the native one-start, one-write, one-reload outcome
without wrapping the positive production namespace.

For encoded/repeated paths, the two authoritative observations are:

- browser-visible `location.pathname + location.search`; and
- the server-received request target, captured transiently from NGINX's
  original `$request_uri` or request-line representation.

CDP proves navigation identity and protocol, but its serialized URL is never
called the raw request target. The isolated NGINX capture contains only a case
identifier and a safely encoded target, is deleted after comparison, and
retains only equality verdicts. Both observations preserve the intended
encoded/query form. The test does not equate normalized `r->uri` with the
server-received target.

The capture uses a fixture-only `escape=json` access-log format with a fixed
safe case header, `$request_uri`, and `$http_cookie`; it is not a retained
diagnostic log. Pinned NGINX 1.30.3 reconstructs HTTP/2 Cookie fragments into
one field with `"; "` separators before request handling, and the H1 case must
observe one Chromium Cookie field. If that one-effective-field precondition
cannot be established, the case fails instead of normalizing multiple fields
through `$http_cookie`'s generic comma-join behavior.

### Challenge assertions

The 503 has exactly one valid `PowGate-Challenge` header. Version, difficulty,
bucket, and nonce equal the served JSON parameters. Retained diagnostics keep
only equality verdicts. CSP, `Cache-Control: no-store`,
`X-Robots-Tag: noindex`, and content type are correct. There is no redirect,
cookie issuance, debug header, internal header, or undeclared PowGate header.

The challenge initiates no subresource, fetch, XHR, WebSocket, worker, beacon,
or external-origin request. The only fixture-origin requests are the two main
documents. Centrally reviewed launch policy disables common background
networking rather than misclassifying browser-service traffic as page traffic.

### Browser-native cookie outcome

The reload request carries exactly one exact-name canonical v1 `__pow_p`.
The authoritative occurrence count comes from the Cookie field bytes in
NGINX's request representation, captured only in the isolated transient
fixture and processed by a narrow test utility linked to the existing
NGINX-free production cookie scanner. The utility consumes length-delimited
field bytes through standard input and emits only counts and fixed verdicts.
It never uses `split(";")`, a browser-cookie API approximation, or a second
cookie grammar. The raw field capture is deleted and never enters retained
diagnostics. Pinned NGINX HTTP/2 reconstruction ordering remains part of the
tested request representation.

After the final 200, browser and response metadata prove exactly one configured
auth cookie exists with `Path=/`, Secure, HttpOnly, SameSite=Lax, host-only
scope, no Domain attribute, and exact v1 value shape. Every exact-name proof
cookie is absent. Where CDP exposes repeated `Set-Cookie` fields faithfully,
issuance and clearing are supporting evidence, not the sole acceptance
mechanism. There are no unrelated PowGate cookies.

The stale cookie is present initially, distinguishable transiently, absent
from reload, and absent finally. Retained evidence stores only:

```text
initial_stale_present
reload_stale_present
reload_root_proof_count
final_proof_count
```

Phase 4B proves cleanup-before-solve ordering. Phase 4C proves the native
outcome with an untouched production namespace.

Every case fails on unexpected console output, page error, rejection, CSP
violation, failed document, crash, popup, worker, socket/fetch request, static
failure UI, retry, disconnect, incomplete navigation, or cleanup escalation.

The positive matrix is eight genuine loops: two protocols times four cases.

## 7. Partitioned proof-cookie fail-closed matrix

Each protocol adds one fresh-context negative case using the exact
browser-native state demonstrated by commit `5b14254`. An HTTPS seed response
from `https://gate.powgate.test/__powgate_partitioned_seed` creates:

```text
Set-Cookie: __pow_p=1.0.0; Path=/; Secure; SameSite=Lax; Partitioned
```

The seed and protected challenge both run as top-level navigations from
`https://gate.powgate.test`; the schemeful top-level site and partition key are
`https://powgate.test`. The cookie has no Domain attribute and is host-only to
`gate.powgate.test`. It has no HttpOnly, Expires, or Max-Age attribute. Only the
real HTTPS response may create it. CDP may inspect storage but never creates,
overwrites, repairs, or deletes the cookie. The literal `1.0.0` is a fixture
value for residual-cookie detection, not a candidate valid proof; the server
must never accept it. Retained diagnostics contain no raw cookie value.

Before production cleanup, the case proves the cookie is stored, exactly one
proof occurrence is page-visible through `document.cookie`, and the initial
request contains one exact proof occurrence according to the production
scanner. After cleanup, the same partitioned cookie remains both page-visible
and present in browser storage. Storage survival without page visibility is
insufficient.

Only these negative pages install the shared narrow solver observer. One
implementation is used by the feasibility spike and permanent E2E case. It
records exactly one namespace assignment and counts `solve()` calls while
preserving the production descriptor, frozen namespace, exact `sha256` and
`solve` exports, receiver, arguments, Promise identity/behavior, and errors.
It performs no cookie, navigation, scheduling, or network mutation. A missing,
repeated, or differently shaped namespace assignment fails before the count is
interpreted. A mandatory observer-free equivalence test is tied to the shared
observer and setup source identity; changing either invalidates equivalence
until the focused control is rerun. Positive and benchmark pages remain
untouched.

The expected terminal result is:

- partitioned cookie stored, initially visible, and present on the request;
- partitioned cookie still stored and page-visible after cleanup;
- namespace assigned exactly once and solver called zero times;
- exactly one document navigation and zero backend requests;
- zero replacement proof cookies and zero auth cookies;
- static failure UI and retry control visible.

After terminal UI appears, `FAIL_CLOSED_QUIET_WINDOW_MS` requires an unchanged
URL, no second document request, automatic retry, solver call, proof/auth cookie
mutation, backend request, console output, page error, unhandled rejection,
CSP violation, crash, or unexpected network event. Context destruction may
remove the cookie only after every assertion completes.

The negative matrix is two cases, one per protocol. Phase 4B owns synthetic
cleanup/serialization cases; Phase 4C owns this browser-native partitioned
residual-cookie case.

## 8. Benchmark methodology and responsiveness

`tests/browser/benchmark.mjs` measures the two existing production backends.
It does not benchmark the private controller or add another solver.

A minimal static HTTPS NGINX page contains the exact generated production
script and CSP hash but no PowGate module. The parameter JSON is exactly `{}`,
which reaches the controller-tested static terminal state before cleanup,
backend selection, or mining. The harness waits for terminal UI, then observes
one fixed `BENCHMARK_CONTROLLER_QUIET_WINDOW_MS` with zero solve, cookie
mutation, navigation, animation-frame-driven DOM mutation, recurring
observable event, or console activity before calling the unchanged public
`solve(nonce, difficulty, startCounter, maxAttempts, backend)`.

The canonical benchmark does not replace or wrap `setTimeout`, `setInterval`,
`requestAnimationFrame`, Promise scheduling, or another browser scheduling
primitive. Timer-registration instrumentation belongs only in separate
controller contract tests.

It verifies script/CSP identity, the frozen two-export namespace, and both
production-shaped backend KATs. No wrapper, provider interception, test branch,
or second solver is installed.

### Workload and continuation

Both backends receive the fixed 32-byte nonce
`c382cd45c32e81f6f5bdcc5fb29497876a3d4364b688245668ab1b578ff7184f`,
difficulty 32, counter zero, contiguous safe counters, and identical
scheduling/stopping rules.

Every result has the exact frozen five-field contract. On success,
`nextCounter` must be `null`. The harness independently verifies the digest,
records a hit, and starts a new unchanged invocation at `counter + 1` only
when the counter is below `Number.MAX_SAFE_INTEGER`. It never mutates or
continues the terminal invocation. Success at the maximum safe integer is a
premature safe-domain terminal failure and never constructs a successor.

### Schedule

There are seven matched pairs:

```text
1 js,subtle   2 subtle,js   3 js,subtle   4 subtle,js
5 js,subtle   6 subtle,js   7 js,subtle
```

Every repetition uses a fresh context/page, two seconds of discarded warm-up,
a fresh recorded counter zero, and a ten-second stopping deadline. One
Chromium process owns all fourteen repetitions. Warm-up results and samples
are discarded.

Warm-up may calibrate only `maxAttempts`, separately per backend/repetition,
within checked-in bounds. It targets about 10 ms, never the 25 ms ceiling,
does not inspect private state, select a backend, or change production
constants, and is recorded. The driver yields between unchanged calls. It
performs no hash, batching, worker, parallel range, provider replacement, or
overlapping digest operation.

The ten-second value stops new calls. A started call finishes. The recorded
interval, throughput, heartbeat, block timings, and overrun all end with that
final result. Throughput is completed candidates divided by monotonic browser
elapsed seconds. Seven raw throughput values are retained; the median is the
sorted fourth, with no trimming.

### Responsiveness

An independent 5 ms heartbeat measures actual callback time minus each
expected deadline. It runs from the first recorded candidate through final
call completion. The page is frontmost and visible throughout.

Every repetition independently requires:

- nearest-rank heartbeat p95 at most 25 ms;
- maximum heartbeat delay at most 100 ms;
- a complete, non-stalled heartbeat series;
- no synchronous JS `solve()` block above 25 ms.

The JS call interval is measured directly around its synchronous work. For
SubtleCrypto, the harness records synchronous call-entry time, total awaited
invocation time, and the derived asynchronous remainder. The remainder
includes provider wait, Promise scheduling, and result processing; it is not
labelled pure provider time. The benchmark never wraps or intercepts
`crypto.subtle.digest()`.

### Decision rule

JavaScript remains primary unless both backends pass every check,
SubtleCrypto median throughput is at least 1.25 times JavaScript median, and
SubtleCrypto wins at least five matched pairs. Throughput alone never fails
the benchmark or changes any code except the later fixed pre-search order.

## 9. Evidence schema, generation, and promotion

Generated and canonical evidence are separate:

```text
build/benchmark-browser-result.json

docs/benchmarks/phase4c-v1/
  schema.json
  README.md
  x86_64-debian-chromium-150.0.7871.100-1%7Edeb13u1.json
```

The schema is Draft 2020-12 with strict object boundaries and fixed
`phase4c-benchmark-v1`. Ajv uses `allErrors: true`, `strict: true`, and
`validateFormats: false` without coercion, defaults, removal, or mutation.

Evidence records provenance-only `generated_at_utc`; all measurement uses
browser `performance.now()`. Its top-level objects are `tested_source`,
`environment`, `workload`, `runs`, `summaries`, `decision`, and `verdicts`;
relevant objects set `additionalProperties: false`.

`tested_source` records commit, clean/promotable verdicts, and script, page,
CSP, generator, and benchmark-implementation SHA-256 values. A dirty run is
valid development evidence but always non-promotable and retains no diff.

`environment` records host/container architecture, Debian snapshot, package
versions/checksums, Node/npm/Puppeteer/Ajv/NGINX/Chromium and CDP versions,
kernel, Podman, CPU model and logical count, requested/observed browser
arguments, UID/GID, seccomp, capability, sandbox and rootless verdicts,
embedded/OCI image locks, image ID, and nullable repository digest. It records
no hostname, username, SSH detail, profile, cookie, or unrestricted
environment variable.

`workload` records the nonce, difficulty, warm-up, stopping deadline,
repetitions and order, heartbeat period/bounds, JS block ceiling, calibration
bounds/target, counter and continuation rules, median rule, 1.25 threshold,
and five-of-seven matched-pair requirement.

Runs use explicit `recorded_start_performance_ms` and
`recorded_end_performance_ms`. They retain complete bounded heartbeat and
invocation arrays, counts, timing, continuity and cleanup verdicts. Hit data
is limited to `valid_hit_count`, nullable `first_valid_hit_offset`, and
`safe_domain_terminal`; exact counters are not persisted. The offset is the
zero-based number of candidates examined before the first valid hit in that
recorded run.

`benchmark_implementation_sha256` hashes a fixed length-prefixed ordered
encoding of the exact benchmark executable bytes and any separately emitted
benchmark-specific in-page driver bytes. It is independent of the production
script hash and has no path-name or concatenation ambiguity.

Raw arrays occur only under runs. Summaries contain derived scalars and exactly
seven throughput values per backend. Executable relational checks recompute
run counts/order, workloads, counter continuity, success continuation,
throughput, nearest-rank p95, medians, matched pairs, summaries, and decision.
Summaries are never trusted as source data. Non-finite, unsafe, incomplete, or
oversized evidence fails.

Positive and negative schema fixtures prove that schema, validator, and
relational-check drift fail the browser tooling tests. Schema validation never
coerces, supplies defaults, removes properties, or mutates the result.

Serialization recursively sorts object keys in ascending ASCII order,
preserves arrays, uses standard finite JSON numbers, UTF-8, two-space
indentation, and one final LF. Generation removes stale output, validates in
memory, writes and flushes a same-directory temporary file, atomically
renames, reopens, reparses, and repeats schema and relational validation.
Failure leaves no canonical-named build result.

Promotion is a narrow explicit tool action. It requires promotable evidence,
a clean worktree before copy, `HEAD` equal to the tested commit, unchanged
tracked source since measurement, matching hashes/locks, full validation, and
a non-existing derived canonical filename. The copy is the final operation.
Evidence retains the tested source commit and `evidence_commit: null`; Git
history records the later evidence-only commit.

The canonical filename is derived by one checked-in function shared by
promotion and validation. Architecture and package name use their locked
ASCII identifiers in
`<architecture>-debian-<package>-<encoded-version>.json`. Every
package-version UTF-8 byte outside
`[A-Za-z0-9._-]` is percent-encoded with uppercase hexadecimal; existing `%`
is therefore encoded as `%25`. This injective rule maps `~` to `%7E` and
prevents two Debian versions from colliding after sanitization. The README and
promotion tool use only this derivation.

The evidence README names the tested source, canonical environment,
reproduction command, mechanical decision rule, selected fixed order, and the
difference between throughput evidence and pass/fail bounds. No automatic run
compares new throughput with the committed result.

Historical v1 evidence and schema are immutable. An incompatible schema change
uses a new versioned directory.

## 10. Backend-order decision procedure

The completed initial candidate retains JS primary and SubtleCrypto fallback.
Run one full unpromoted benchmark and apply the fixed rule. Backend failure is
not a vote for JS: the provisional order remains, Phase 4C is incomplete, and
no evidence is promoted.

If SubtleCrypto qualifies, the only permitted production change is the order
in which the controller initializes and validates candidate backends before
search. The KAT bytes/digest, fallback conditions, API, hashing, buffers,
slices, provider behavior, wire format, and mid-search policy do not change.
Behavioral controller tests prove the order and one-time fallback.

After any order change, commit final source and run all project, browser, fuzz,
sanitizer, schema, and cleanup gates. Any code or benchmark-mechanics repair
restarts measurement.

The benchmark inside `check-browser-x86` proves machinery and current source;
it is not authoritative for promotion. A later standalone benchmark on the
clean, fully gated source is the sole canonical decision record.

Each canonical session is evaluated independently. Sessions are never pooled,
averaged, cherry-picked, or majority-voted. If its decision differs from
production order in either direction, do not promote it: apply only the
permitted order change and restart verification and canonical measurement.

Only matching evidence is promoted and committed separately as:

```text
docs: record Phase 4C browser benchmark
```

## 11. Diagnostics, deadlines, and limits

Every primary or secondary failure record has exactly one category:

```text
host_policy environment_identity fixture_configuration fixture_startup
sandbox_policy browser_pairing browser_runtime protocol_assertion
cookie_assertion controller_assertion benchmark_correctness
benchmark_responsiveness evidence_validation internal_invariant cleanup
```

The target has one primary and zero or more separately classified secondary
failures. Output contains only fixed target/category/operation/verdict/deadline
tokens, safe process metadata, and a sanitized diagnostic path. It never emits
cookie/proof/auth values, nonce/challenge JSON, secrets, query strings,
unrestricted URLs, raw CDP, console payloads, or access logs.

Only demonstrated NGINX bind collision is automatically retried. Browser
launch, navigation, cases, benchmark repetitions, APIs, protocol,
responsiveness, cleanup, and evidence are never retried into success.

### Named operation deadlines

| Constant | Milliseconds |
| --- | ---: |
| `NGINX_CONFIG_TEST_TIMEOUT_MS` | 10,000 |
| `NGINX_READINESS_TIMEOUT_MS` | 15,000 |
| `CHROMIUM_LAUNCH_TIMEOUT_MS` | 30,000 |
| `BROWSER_CONTEXT_TIMEOUT_MS` | 10,000 |
| `CDP_OPERATION_TIMEOUT_MS` | 10,000 |
| `DOCUMENT_NAVIGATION_TIMEOUT_MS` | 30,000 |
| `E2E_TERMINAL_OUTCOME_TIMEOUT_MS` | 30,000 |
| `CONTROLLED_PROBE_TIMEOUT_MS` | 10,000 |
| `FAIL_CLOSED_QUIET_WINDOW_MS` | 1,000 |
| `BENCHMARK_CONTROLLER_QUIET_WINDOW_MS` | 1,000 |
| `DIAGNOSTIC_CAPTURE_TIMEOUT_MS` | 10,000 |
| `PAGE_CONTEXT_CLOSE_TIMEOUT_MS` | 10,000 |
| `CHROMIUM_CLOSE_TIMEOUT_MS` | 15,000 |
| `NGINX_QUIT_TIMEOUT_MS` | 10,000 |
| `NGINX_TERM_TIMEOUT_MS` | 5,000 |
| `NGINX_KILL_TIMEOUT_MS` | 2,000 |

Outer watchdogs are deadlock safeguards outside Node where possible:

| Constant | Milliseconds |
| --- | ---: |
| `FEASIBILITY_TARGET_TIMEOUT_MS` | 180,000 |
| `E2E_TARGET_TIMEOUT_MS` | 600,000 |
| `BENCHMARK_TARGET_TIMEOUT_MS` | 360,000 |
| `BROWSER_AGGREGATE_TIMEOUT_MS` | 1,300,000 |

Each listed target watchdog is a total budget that already includes its final
20-second emergency cleanup grace. At `target_budget - cleanup_grace`, the
outer watchdog sends TERM to the verified test process; it performs final
termination only when the listed total budget expires. Policy verifies that
the aggregate exceeds the three complete child budgets by 160,000 ms, so no
additional hidden child grace is omitted. An outer timeout is
`internal_invariant` unless a specific failure was durably recorded.

```text
OUTER_WATCHDOG_CLEANUP_GRACE_MS = 20000
```

### Benchmark and capture limits

```text
BENCH_MIN_ATTEMPTS = 1
BENCH_MAX_ATTEMPTS = 262144
BENCH_TARGET_BLOCK_MS = 10
BENCH_JS_BLOCK_CEILING_MS = 25

MAX_OBSERVATION_EVENTS_PER_PAGE = 4096
MAX_OBSERVATION_METADATA_BYTES_PER_PAGE = 1 MiB
MAX_RAW_SAMPLES_PER_RUN_SERIES = 8192
MAX_GENERATED_EVIDENCE_BYTES = 16 MiB
MAX_RETAINED_DIAGNOSTIC_BYTES = 2 MiB
MAX_FAILED_BENCHMARK_SAMPLE_EXCERPT = 32
```

Heartbeat accounting records a delay for every elapsed 5 ms scheduled
deadline even when one delayed physical callback observes several deadlines.
After the final invocation, one bounded drain turn records deadlines due at or
before the recorded end without extending elapsed time.

```text
HEARTBEAT_ALLOWED_TIMER_TAIL = 2
minimum_expected_samples =
  floor(recorded_elapsed_ms / HEARTBEAT_PERIOD_MS) - 2
```

Failed benchmarks leave no `build/benchmark-browser-result.json`. A bounded
diagnostic may retain only the failing run/backend, summary p95/maximum/block
verdicts, and at most `MAX_FAILED_BENCHMARK_SAMPLE_EXCERPT` allowlisted timing
samples per relevant series. It never retains a schema-valid partial evidence
object or full raw arrays under the canonical schema/name.

## 12. Final gates and completion criteria

### Browser and sanitizer matrix

`test-browser-e2e` executes the complete ten-case matrix twice:

```text
normal production build: 8 positive + 2 partitioned fail-closed = 10 cases
ASan+UBSan build:         8 positive + 2 partitioned fail-closed = 10 cases
total:                    20 browser cases
```

The sanitized fixture uses a separately built instrumented NGINX binary and
PowGate module. Instrumentation covers NGINX, module C, and linked native
support code used by that instance. Chromium, Node, Puppeteer, harness, and
production script remain the same pinned uninstrumented infrastructure.
Sanitizer preload/options/runtime paths are not propagated into Chromium.

Both executions use identical browser, protocols, URLs, queries, cookies,
script bytes, assertions, and timeouts. Only native server instrumentation
differs. There is no reduced matrix, alternate behavior, directive, protocol,
browser script, or benchmark role.

Reviewed exclusions for locked upstream NGINX intentional unaligned access
must be source- or function-scoped, documented, and negatively controlled. No
exclusion covers PowGate, the entire NGINX binary, a broad HTTP/2 pattern, or
an unknown finding. The negative-control alignment test must still detect an
equivalent project-code fault.

Sanitized execution proves three separate properties:

1. **Build identity.** Hashes and build metadata identify the separately
   instrumented NGINX binary and PowGate module, symbol/runtime inspection
   proves sanitizer instrumentation and linkage, and both artifacts differ
   from their normal-build counterparts.
2. **Runtime identity.** The fixture records the exact sanitized master path
   and hash, verifies every worker is a descendant in that instrumented server
   generation, records every worker generation and verifies every generation
   exits, applies sanitizer environment only to NGINX, and proves that Chromium
   and its harness environment are scrubbed of sanitizer preload, option, and
   runtime-path variables.
3. **Result.** The harness collects every sanitizer report that exists and
   fails on any ASan/UBSan diagnostic, sanitizer initialization failure,
   deadly signal, allocator failure, abnormal exit, or unexpected sanitizer
   stderr signature. A clean process is not required to create an empty report
   file or clean-exit marker.

A separate test-only sanitizer negative control deliberately triggers the
reviewed project-code alignment fault and must produce a captured report under
the same report-collection and suppression policy. It introduces no
production directive, request path, source branch, or release artifact. This
proves instrumentation and report collection without adding clean-run hooks.
Sanitizer diagnostics follow the normal redaction budget.

Feasibility and benchmarking do not load PowGate and are not duplicated under
sanitizers.

### Release gate

Inside the canonical image, with the browser aggregate invoked through the
host wrapper, require:

```text
make check
make check-browser-x86
make test-fuzz-long
```

Existing architecture-neutral ARM64 gates remain required where already
applicable; Phase 4C neither replaces them nor requires an ARM64 browser.
Successful child output must be independently visible.

Final artifact checks require no Phase 4C protocol semantic diff, assembled
body below 15,360 bytes, exact served/generated/CSP bytes, unchanged public
solver/result APIs, no fault artifact under `out/`, no browser dependency in
release output, and no remote/sandbox-bypass/runtime-selection path.

After all gates, run the standalone canonical benchmark, require decision
agreement, promote/review it, and commit evidence separately. After that
evidence-only commit, run at least policy, schema, relational, source/evidence
identity, and documentation-link checks. A machine check must prove the commit
changes only expected benchmark evidence/documentation before browser, fuzz,
and sanitizer reruns may be omitted.

Update `PLAN.md`, benchmark documentation, security/configuration status, and
only enduring `AGENTS.md` rules: native x86 browser gate, mandatory wrapper,
no sandbox weakening, untouched positive production namespace, and sanitizer
coverage. Documentation claims one pinned Chromium/x86_64 environment, not
universal compatibility.

Phase 4C is complete only when final source is clean and fully gated,
canonical evidence names that source and matches production order, the
evidence commit changes no executable input, all expected artifacts exist,
repository status is clean, and no blocker, ambiguity, skip, placeholder, or
orphaned runtime artifact remains.
