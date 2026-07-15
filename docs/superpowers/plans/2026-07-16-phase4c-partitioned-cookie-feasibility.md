# Phase 4C Partitioned-Cookie Feasibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Determine whether pinned Chromium naturally preserves a page-visible Secure Partitioned `__pow_p` cookie after the untouched production controller's cleanup and therefore reaches fail-closed before mining.

**Architecture:** Add one explicitly experimental x86-only target and one dedicated browser executable. The executable reuses the existing fixture lifecycle, receives the cookie from a real HTTPS `Set-Cookie` response, runs observer-free and narrowly observed trials, and prints only a fixed verdict record. It does not alter the permanent E2E matrix or production bytes.

**Tech Stack:** Node.js 20, Puppeteer Core 24.43.1, pinned Chromium 150, NGINX 1.30.3, rootless Podman on the native x86_64 worker.

## Global Constraints

- Execute every test only through `localhost/ngx-powgate-dev:trixie` on `vagrant`; use no host Node.js or compiler.
- The public experimental target is exactly `test-browser-partitioned-feasibility` and is not a prerequisite of any gate.
- Seed only through a real HTTPS `Set-Cookie` response containing `Secure; Partitioned`; do not use CDP cookie creation, profile editing, or database editing.
- Execute the exact generated production page/controller without production or generated-source changes.
- Retain only fixed booleans/counts; never retain cookie values, request Cookie bytes, challenge values, raw CDP, profiles, or unrestricted logs.
- A negative reachability verdict exits zero when the experiment completed correctly; environment, fixture, observer, or incomplete-observation failures exit nonzero.
- Do not change `docs/protocol.md`, `test-browser-e2e`, `check-browser-x86`, or the frozen acceptance matrix.

---

### Task 1: Add the experimental verdict contract and runner

**Files:**
- Create: `tests/browser/partitioned-feasibility.mjs`
- Create: `tests/browser/partitioned-feasibility.test.mjs`
- Modify: `Makefile`
- Modify: `tools/run-browser-x86.sh`

**Interfaces:**
- Produces: `partitionedAcceptance(verdict) -> boolean`.
- Produces: `runPartitionedFeasibility() -> Promise<frozen verdict object>`.
- Produces: public target `test-browser-partitioned-feasibility`.

- [ ] **Step 1: Write the failing verdict-contract test**

Create `tests/browser/partitioned-feasibility.test.mjs` with a table that imports `partitionedAcceptance` and requires exactly these frozen result keys:

```js
const expectedKeys = [
    'acceptance_reached',
    'backend_count',
    'initial_document_visible',
    'initial_request_present',
    'navigation_count',
    'observer_control_matches',
    'partitioned_cookie_stored',
    'post_cleanup_document_visible',
    'post_cleanup_storage_present',
    'solver_calls',
];
```

Require acceptance only when storage, initial visibility/request presence,
post-cleanup visibility/storage, zero solve calls, one navigation, and zero
backend requests are all exact. A storage-only survivor must return false.

- [ ] **Step 2: Run the focused test and verify RED**

Copy the new test to the vagrant worktree and run inside Podman:

```sh
podman run --rm --userns=keep-id \
  -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  node --test tests/browser/partitioned-feasibility.test.mjs
```

Expected: FAIL because `partitioned-feasibility.mjs` does not exist.

- [ ] **Step 3: Implement the fixed verdict helper**

Implement `partitionedAcceptance()` as strict boolean/integer comparisons, not truthiness. Freeze every returned public record. Reject missing, additional, non-boolean, negative, fractional, or unsafe-integer fields before computing acceptance.

- [ ] **Step 4: Implement the real HTTPS spike fixture**

In `partitioned-feasibility.mjs`, render an isolated NGINX configuration with:

```nginx
location = /__powgate_partitioned_seed {
    access_log off;
    add_header Set-Cookie "__pow_p=1.0.0; Path=/; Secure; SameSite=Lax; Partitioned";
    default_type text/html;
    return 200 '<!doctype html><title>partitioned seed</title>';
}

location = /partitioned-feasibility {
    pow on;
    pow_difficulty 8;
    pow_cookie_name PowAuth;
    proxy_pass http://127.0.0.1:<ephemeral-backend-port>;
}
```

Use the existing ephemeral certificate, `withFixture()`, request observation
log, production cookie scanner utility, and exact generated challenge page.
The seed endpoint must be a genuine browser navigation; do not call
`Network.setCookie` or `Storage.setCookies`.

- [ ] **Step 5: Implement the observer-free control and observed trial**

Run two fresh sessions against the same fixture:

1. Observer-free control: seed by HTTPS, prove storage and page visibility,
   navigate the protected page, and record post-cleanup visibility/storage,
   navigation count, and backend count.
2. Observed trial: repeat from a fresh context with one pre-document observer
   that validates and wraps the exact frozen `PowGateSolver` namespace, counts
   `solve()` calls with `Reflect.apply`, and otherwise preserves behavior.

Before interpreting either result, use the production scanner utility on the
decoded single effective NGINX Cookie field to prove the initial protected
request contains exactly one `__pow_p`. The observer-free and observed cookie
storage/visibility/navigation/backend verdicts must match. A mismatch fails the
target rather than yielding a reachability result.

Wait for either the static failure UI or the successful reload/backend path
under the existing named deadlines. After the terminal observation, use the
existing 1,000 ms fail-closed quiet window. Record no raw cookie or request
data.

- [ ] **Step 6: Add the isolated target and wrapper allowlist entry**

Add a Make recipe that performs the architecture/environment check, builds
only existing prerequisites, and runs:

```make
test-browser-partitioned-feasibility: browser-tools module
	./tools/require-browser-x86.sh test-browser-partitioned-feasibility
	timeout --signal=TERM --kill-after=20s 160s \
		node tests/browser/partitioned-feasibility.mjs
```

Add exactly `test-browser-partitioned-feasibility` to the narrow target
allowlist in `tools/run-browser-x86.sh`. Declare the target phony, but do not
add it as a dependency of `check-browser-x86`, `make check`, or another
aggregate or release target.

- [ ] **Step 7: Run focused tests and verify GREEN**

On vagrant, inside the canonical image, run:

```sh
node --test tests/browser/partitioned-feasibility.test.mjs
make check-policy
```

Expected: focused tests and policy pass.

- [ ] **Step 8: Run the native Chromium spike**

From the vagrant repository root with the required rootless Podman exports:

```sh
tools/run-browser-x86.sh test-browser-partitioned-feasibility
```

Expected: one fixed verdict line containing the ten allowed fields. Exit zero
means the experiment completed; `acceptance_reached` alone determines whether
the case is eligible for promotion.

- [ ] **Step 9: Classify and document the outcome**

If `acceptance_reached=true`, stop before changing the acceptance matrix and
request a separate design review.

If `acceptance_reached=false`, remove the experimental executable, unit test,
Make target, and wrapper entry. Update the Phase 4C design and plan to freeze
the 16-case boundary and record the partitioned-cookie verdict alongside the
two already rejected constructions. Keep only the reviewed rationale, not
temporary browser code.

- [ ] **Step 10: Verify repository boundaries and commit**

Run both commands inside the canonical image:

```sh
make check-policy
node --test tests/browser/e2e.test.mjs
```

Then confirm:

```sh
git diff --quiet -- docs/protocol.md
git diff --check
```

For a positive result, commit the isolated spike without promoting it:

```sh
git add Makefile tools/run-browser-x86.sh \
  tests/browser/partitioned-feasibility.mjs \
  tests/browser/partitioned-feasibility.test.mjs
git commit -m "test: probe partitioned proof cookie cleanup"
```

For a negative result, commit only the final design/plan rationale update:

```sh
git add docs/superpowers/specs/2026-07-15-phase4c-browser-e2e-design.md \
  docs/superpowers/plans/2026-07-15-phase4c-browser-e2e.md
git commit -m "docs: freeze browser fail-closed coverage boundary"
```
