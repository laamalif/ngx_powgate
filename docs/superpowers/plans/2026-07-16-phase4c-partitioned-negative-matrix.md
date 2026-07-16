# Phase 4C Partitioned Negative-Matrix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Promote the browser-native Partitioned `__pow_p` state proven by commit `5b14254` into mandatory HTTP/1.1 and HTTP/2 fail-closed cases under both normal and ASan+UBSan NGINX, then retire the isolated feasibility target.

**Architecture:** Extract one immutable cookie descriptor and one descriptor-preserving solver observer shared by the feasibility control and permanent E2E. Add a permanent observer-equivalence prerequisite, execute one partitioned negative case per protocol, then run the identical ten-case matrix with normal and instrumented server artifacts. Keep the experimental spike until both permanent matrices reproduce its tuple.

**Tech Stack:** Node.js 20.19.2, Puppeteer Core 24.43.1, Chromium 150.0.7871.100, NGINX 1.30.3, Clang ASan+UBSan, Make, rootless Podman, native x86_64 `vagrant`.

## Global Constraints

- Follow `2026-07-15-phase4c-browser-e2e-design.md` and `2026-07-16-phase4c-partitioned-negative-matrix-amendment.md`.
- Do not change `docs/protocol.md`, production C behavior, `html/challenge.html`, generated challenge bytes, cookie formats, or verification semantics.
- Run every build/test on `vagrant` inside `localhost/ngx-powgate-dev:trixie`; use eight build jobs on x86_64 where supported.
- Create `__pow_p=1.0.0; Path=/; Secure; SameSite=Lax; Partitioned` only through the real HTTPS seed response. CDP only inspects it.
- Compare `1.0.0` transiently; never retain it in diagnostics.
- Seed and challenge are top-level navigations at `gate.powgate.test`; the partition key is `https://powgate.test`.
- Positive E2E and benchmark paths use the untouched namespace. Only partitioned negative cases install the shared observer.
- Normal and sanitized runs use identical eight-positive/two-negative matrices.
- Keep the experimental target outside `check-browser-x86` until its separate removal.
- No fault, negative-control, or experimental artifact enters `out/`.

Before remote commands export the four approved Podman variables and enter `/home/vagrant/Workspace/ngx_powgate-phase4c`. Architecture-neutral commands use:

```sh
podman run --rm --userns=keep-id \
  -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  sh -eu -c 'node --test tests/browser/e2e.test.mjs'
```

Browser commands use `tools/run-browser-x86.sh test-browser-e2e`.

---

### Task 1: Extract the Shared Cookie and Observer Contract

**Files:**
- Create: `tests/browser/lib/partitioned-proof.mjs`
- Create: `tests/browser/partitioned-proof.test.mjs`
- Modify: `tests/browser/partitioned-feasibility.mjs`
- Modify: `tests/browser/partitioned-feasibility.test.mjs`

**Interfaces:**
- `PARTITIONED_PROOF_FIXTURE`: deeply frozen seed/challenge/cookie descriptor.
- `partitionedObserverBootstrap()`: self-contained pre-document assignment/call observer.
- `partitionedObserverSnapshot(page) -> Promise<frozen record>`.
- `classifyPartitionedCookies(cookies, parentCookies) -> frozen count record`.

- [ ] **Step 1: Write failing descriptor and observer tests**

Require the exact descriptor:

```js
assert.deepEqual(PARTITIONED_PROOF_FIXTURE, {
    challengePath: '/partitioned-feasibility',
    expectedCookie: {
        domain: 'gate.powgate.test',
        expires: -1,
        httpOnly: false,
        partitionKey: {
            hasCrossSiteAncestor: false,
            sourceOrigin: 'https://powgate.test',
        },
        path: '/',
        sameSite: 'Lax',
        secure: true,
        session: true,
    },
    name: '__pow_p',
    seedPath: '/__powgate_partitioned_seed',
    setCookie: '__pow_p=1.0.0; Path=/; Secure; SameSite=Lax; Partitioned',
    value: '1.0.0',
});
```

Assert every nested object is frozen. In `node:vm`, require exactly one namespace assignment, zero initial calls, exact enumerable exports `sha256,solve`, frozen wrapper, production property descriptor, direct return of the original Promise, unchanged rejection, and failure on a second/malformed assignment.

For one exact cookie applicable to `gate.powgate.test` and none applicable to `powgate.test`, require:

```js
{
    authCookieCount: 0,
    newPartitionedProofCount: 0,
    originalPartitionedProofCount: 1,
    unpartitionedProofCount: 0,
}
```

- [ ] **Step 2: Verify RED**

```sh
node --test tests/browser/partitioned-proof.test.mjs \
  tests/browser/partitioned-feasibility.test.mjs
```

Expected: FAIL because the shared module does not exist.

- [ ] **Step 3: Implement the shared module**

Freeze inner objects before the outer descriptor. The observer keeps its
accessor installed through the production script's initialization window so
every assignment is counted. Its getter returns the wrapped namespace. At
`DOMContentLoaded`, after requiring exactly one assignment, it replaces the
temporary accessor with the observer-free control's exact production data
descriptor. This permits repeated-assignment detection without leaving a
different namespace descriptor during controller execution. The wrapper is:

```js
const wrapped = Object.freeze({
    sha256: namespace.sha256,
    solve(...args) {
        solveCalls += 1;
        return Reflect.apply(namespace.solve, namespace, args);
    },
});
```

Use the descriptor proven by the observer-free control. Keep observer/binding properties non-enumerable. Expose only descriptor/export/frozen verdicts, assignment count, solve count, and phase.

- [ ] **Step 4: Refactor the spike**

Replace local cookie, path, header, and observer definitions with imports. Preserve historical verdict keys and challenge-scoped `navigation_count`.

- [ ] **Step 5: Verify GREEN and the known-good browser state**

```sh
node --test tests/browser/partitioned-proof.test.mjs \
  tests/browser/partitioned-feasibility.test.mjs \
  tests/browser/e2e.test.mjs
make check-policy
```

Then run `tools/run-browser-x86.sh test-browser-partitioned-feasibility`.

Expected: `acceptance_reached:true`, one challenge navigation, zero solver/backend calls, and observer/control match.

- [ ] **Step 6: Commit**

```sh
git add tests/browser/lib/partitioned-proof.mjs \
  tests/browser/partitioned-proof.test.mjs \
  tests/browser/partitioned-feasibility.mjs \
  tests/browser/partitioned-feasibility.test.mjs
git commit -m "test: share partitioned proof observer contract"
```

---

### Task 2: Require Observer Equivalence Before E2E

**Files:**
- Create: `tests/browser/partitioned-observer-equivalence.mjs`
- Create: `tests/browser/partitioned-observer-equivalence.test.mjs`
- Modify: `tests/browser/partitioned-feasibility.mjs`
- Modify: `Makefile`
- Modify: `tests/tools/test_run_browser_x86.py`

**Interfaces:**
- `runPartitionedObserverEquivalence() -> Promise<frozen verdict>`.
- Internal target `test-browser-partitioned-observer-equivalence`.
- Explicit `test-browser-e2e` prerequisite.
- Experimental public target remains until Task 5.

- [ ] **Step 1: Write failing equivalence/dependency tests**

Require:

```js
{
    challengePhaseNavigationCountMatches: true,
    cookieStateMatches: true,
    namespaceAssignments: 1,
    observerDescriptorValid: true,
    observerExportsValid: true,
    observerNamespaceFrozen: true,
    solverCalls: 0,
    terminalStateMatches: true,
}
```

Makefile source tests must prove the explicit prerequisite. Do not add the internal target to the public wrapper allowlist.

- [ ] **Step 2: Verify RED**

```sh
node --test tests/browser/partitioned-observer-equivalence.test.mjs
python3 -m unittest -v tests.tools.test_run_browser_x86
```

- [ ] **Step 3: Extract the equivalence runner**

Use fresh contexts against one fixture. After each seed, advance request, document, event, cookie, and backend cursors. Control/observed runs must agree on storage metadata, initial/post-cleanup visibility, scanner count, challenge navigation count, terminal UI, backend count, and quiet-window silence. Observed additionally requires one assignment and zero calls.

Keep `partitioned-feasibility.mjs` as a thin compatibility CLI calling this runner.

- [ ] **Step 4: Add the explicit internal target**

```make
test-browser-partitioned-observer-equivalence: browser-tools module
	./tools/require-browser-x86.sh test-browser-e2e
	timeout --signal=TERM --kill-after=20s 160s \
		node tests/browser/partitioned-observer-equivalence.mjs

test-browser-e2e: test-browser-partitioned-observer-equivalence browser-tools
```

- [ ] **Step 5: Verify GREEN**

Run focused unit tests/policy, then `tools/run-browser-x86.sh test-browser-e2e`.

Expected at this boundary: equivalence passes first, followed by the existing eight positive loops.

- [ ] **Step 6: Commit**

```sh
git add Makefile tests/tools/test_run_browser_x86.py \
  tests/browser/partitioned-feasibility.mjs \
  tests/browser/partitioned-observer-equivalence.mjs \
  tests/browser/partitioned-observer-equivalence.test.mjs
git commit -m "test: require partitioned observer equivalence"
```

---

### Task 3: Promote the Normal H1/H2 Negative Cases

**Files:**
- Modify: `tests/browser/e2e.mjs`
- Modify: `tests/browser/e2e.test.mjs`
- Modify: `tests/browser/lib/partitioned-proof.mjs`
- Modify: `tests/browser/partitioned-proof.test.mjs`

**Interfaces:**
- `partitionedNegativeCase() -> frozen descriptor`.
- `runPartitionedNegativeCase(fixture) -> Promise<frozen record>`.
- `runE2EMatrix()` returns eight positive plus two partitioned negative results.

- [ ] **Step 1: Write failing matrix/scope tests**

Require one negative descriptor, ID `partitioned-fail-closed`, target `/partitioned-feasibility`, exact ASCII target bytes, and:

```js
{
    normalPartitionedNegative: 2,
    normalPositive: 8,
    normalTotal: 10,
    verdict: 'passed',
}
```

Test original-only success and rejection of: unpartitioned root proof, overwritten fixture, differently scoped exact proof, auth cookie, opaque partition key, and string partition key.

- [ ] **Step 2: Verify RED**

```sh
node --test tests/browser/partitioned-proof.test.mjs \
  tests/browser/e2e.test.mjs
```

- [ ] **Step 3: Add the fixture-only seed endpoint**

Add an exact, unprotected location before the protected catch-all:

```nginx
location = /__powgate_partitioned_seed {
    access_log off;
    add_header Set-Cookie "__pow_p=1.0.0; Path=/; Secure; SameSite=Lax; Partitioned";
    default_type text/html;
    return 200 '<!doctype html><title>partitioned seed</title>';
}
```

Generate/validate it from the shared descriptor. Require fixed 200, exactly one relevant Set-Cookie, no unrelated PowGate cookie, redirect, executable script, external resource, auth cookie, or backend reach.

- [ ] **Step 4: Implement challenge-phase observation**

For each protocol: seed through HTTPS, verify exact structured metadata and host-only scope, compare the fixture value transiently, install the shared observer, advance all cursors, navigate once to the challenge, assert 503/script/CSP/protocol, and pass decoded server Cookie bytes to `observeRequest()`.

Require `initialRequestProofCount === 1`, static failure UI, retry control, and:

```text
authCookieCount = 0
backendCount = 0
challengePhaseDocumentNavigationCount = 1
newPartitionedProofCount = 0
namespaceAssignments = 1
originalPartitionedProofCount = 1
solverCalls = 0
unpartitionedProofCount = 0
```

Also require stored/visible before cleanup, stored/visible after cleanup, and no URL change, second challenge document, retry, cookie mutation, network activity, console/error/rejection/CSP/crash during the quiet window.

- [ ] **Step 5: Integrate one negative per protocol**

Run four positives then one fresh-context negative in H2 and H1. Exclude seed activity. Print:

```text
normal_positive=8 normal_partitioned_negative=2 normal_total=10 verdict=passed
```

- [ ] **Step 6: Run Chromium**

Run `tools/run-browser-x86.sh test-browser-e2e`.

Expected: equivalence first, then ten normal cases. Experimental target remains.

- [ ] **Step 7: Commit**

```sh
git add tests/browser/e2e.mjs tests/browser/e2e.test.mjs \
  tests/browser/lib/partitioned-proof.mjs \
  tests/browser/partitioned-proof.test.mjs
git commit -m "test: add partitioned browser fail-closed matrix"
```

---

### Task 4: Run the Identical Matrix Under ASan and UBSan

**Files:**
- Create: `tools/prepare-browser-sanitized.sh`
- Create: `tests/sanitizer/alignment_negative_control.c`
- Create: `tests/browser/sanitizer.test.mjs`
- Create: `tests/tools/test_check_policy.py`
- Modify: `tests/browser/lib/fixture.mjs`
- Modify: `tests/browser/e2e.mjs`
- Modify: `tools/run-asan.sh`
- Modify: `tools/check-policy.sh`
- Modify: `Makefile`

**Interfaces:**
- `prepare-browser-sanitized.sh <output-dir>` writes validated `manifest.json`.
- `collectSanitizerReports(manifest, identities) -> frozen verdict`.
- `test-browser-e2e` runs the same ten cases with normal and sanitized servers.

- [ ] **Step 1: Write failing sanitizer/policy tests**

Reject normal hashes, missing module hash, absent sanitizer flags,
broad/PowGate suppression, missing worker ancestry, Chromium environment
leakage, or reports outside the fixture. Add a standalone project-owned
misaligned `uint32_t` negative control under
`build/sanitizer-negative-control/`.

Create `tests/tools/test_check_policy.py`. Each table row copies the minimum
policy inputs into a temporary tree, injects exactly one forbidden
suppression/flag or `out/` artifact, runs `tools/check-policy.sh`, and requires
the matching fixed diagnostic. Include a clean control. Policy rejects
alignment disabling on PowGate and any negative/fault artifact under `out/`.

```sh
node --test tests/browser/sanitizer.test.mjs
python3 -m unittest -v tests.tools.test_check_policy
make check-policy
```

Expected: sanitizer tests fail before preparation/collection exists.

- [ ] **Step 2: Factor sanitized server preparation**

Move the instrumented NGINX/module build from `run-asan.sh` into the preparation script. Use Clang, eight x86 jobs, SSL, HTTP/2, RealIP, compatibility, and:

```text
-fsanitize=address,undefined -fno-omit-frame-pointer
```

Manifest includes paths, hashes, flags, linkage/symbol inspection, report directory, runtime options, and differing normal/sanitized hashes. Refactor `run-asan.sh` to consume it.

- [ ] **Step 3: Implement ownership/report collection**

Apply sanitizer environment only to verified NGINX master/workers and scrub it from Node/Chromium. Record master path/hash, worker ancestry/generations/exits, and every report. Negative control must produce a captured alignment diagnostic; clean NGINX needs no marker file.

- [ ] **Step 4: Parameterize the identical matrix**

Use:

```js
runE2EMatrix({
    nginxBinary,
    nginxEnvironment,
    modulePath,
    sanitizerManifest,
    serverBuild,
})
```

Only server artifacts/environment differ. Fail on any report, initialization failure, deadly signal, allocator failure, abnormal exit, lost worker, cleanup escalation, or sanitizer stderr signature. Print:

```text
normal=10 sanitized=10 total=20 verdict=passed
```

- [ ] **Step 5: Verify**

```sh
node --test tests/browser/sanitizer.test.mjs
make check-policy
make asan
```

Then run `tools/run-browser-x86.sh test-browser-e2e`.

Expected: existing sanitizer gate, equivalence, normal ten, and sanitized ten pass.

- [ ] **Step 6: Commit**

```sh
git add Makefile tools/prepare-browser-sanitized.sh tools/run-asan.sh \
  tools/check-policy.sh tests/sanitizer/alignment_negative_control.c \
  tests/browser/sanitizer.test.mjs tests/tools/test_check_policy.py \
  tests/browser/lib/fixture.mjs \
  tests/browser/e2e.mjs
git commit -m "test: run partitioned browser matrix under sanitizers"
```

---

### Task 5: Retire the Experimental Target Separately

**Files:**
- Delete: `tests/browser/partitioned-feasibility.mjs`
- Delete: `tests/browser/partitioned-feasibility.test.mjs`
- Modify: `Makefile`
- Modify: `tools/run-browser-x86.sh`
- Modify: `tools/require-browser-x86.sh`
- Modify: `tests/tools/test_run_browser_x86.py`
- Modify: `docs/superpowers/specs/2026-07-16-phase4c-partitioned-cookie-feasibility-design.md`

- [ ] **Step 1: Write failing lifecycle tests**

Restore the four-target public wrapper allowlist and assert the experimental Make target is absent while the permanent equivalence prerequisite remains.

- [ ] **Step 2: Verify RED**

```sh
python3 -m unittest -v tests.tools.test_run_browser_x86
```

Expected: FAIL because the experimental target remains.

- [ ] **Step 3: Remove only experimental files/entries**

Keep shared contract and permanent equivalence files. Update historical status to record removal only after normal/sanitized reproduction; preserve all findings and commits.

- [ ] **Step 4: Verify permanent gates**

```sh
python3 -m unittest -v tests.tools.test_run_browser_x86
node --test tests/browser/partitioned-proof.test.mjs \
  tests/browser/partitioned-observer-equivalence.test.mjs \
  tests/browser/e2e.test.mjs \
  tests/browser/sanitizer.test.mjs
make check-policy
```

Then run `tools/run-browser-x86.sh test-browser-e2e`.

- [ ] **Step 5: Commit separately**

```sh
git add -A Makefile tools/run-browser-x86.sh \
  tools/require-browser-x86.sh tests/tools/test_run_browser_x86.py \
  tests/browser/partitioned-feasibility.mjs \
  tests/browser/partitioned-feasibility.test.mjs \
  docs/superpowers/specs/2026-07-16-phase4c-partitioned-cookie-feasibility-design.md
git commit -m "test: retire partitioned feasibility spike"
```

---

### Task 6: Verify and Return to Remaining Phase 4C Work

**Files:**
- Modify: `docs/superpowers/plans/2026-07-15-phase4c-browser-e2e.md`
- Modify only when truthful: `PLAN.md`

- [ ] **Step 1: Record status without claiming Phase 4C complete**

Mark old Task 7 superseded and partitioned/sanitizer work implemented only after Tasks 1–5 pass. Benchmark, backend-order, aggregate, and evidence work remain open.

- [ ] **Step 2: Run focused gates**

```sh
sh -eu -c 'make check-policy && make test-tools && make test-js'
node --test tests/browser/partitioned-proof.test.mjs \
  tests/browser/partitioned-observer-equivalence.test.mjs \
  tests/browser/e2e.test.mjs \
  tests/browser/sanitizer.test.mjs
```

- [ ] **Step 3: Run browser evidence**

Run `tools/run-browser-x86.sh test-browser-e2e`.

Expected:

```text
normal=10 sanitized=10 total=20 verdict=passed
```

- [ ] **Step 4: Verify boundaries**

```sh
git diff master...HEAD -- docs/protocol.md
test -z "$(find out -type f \( -name '*fault*' -o -name '*negative*' \) -print)"
git diff --check
git status --short
```

Expected: no protocol diff, prohibited artifact, whitespace error, or final dirt.

- [ ] **Step 5: Commit truthful status**

```sh
git add docs/superpowers/plans/2026-07-15-phase4c-browser-e2e.md
git diff --quiet -- PLAN.md || git add PLAN.md
git commit -m "docs: record partitioned browser matrix"
```

## Completion Boundary

This plan completes only the amended negative matrix and sanitizer ownership. It does not complete benchmark implementation, evidence generation, backend-order selection, final aggregate gates, or evidence promotion. Continue with unsuperseded tasks in `2026-07-15-phase4c-browser-e2e.md`.
