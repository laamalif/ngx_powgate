# Phase 4C Native Browser Verification Implementation Plan

> **Partitioned negative-matrix amendment:** Task 7's parent-domain
> construction is superseded by
> `2026-07-16-phase4c-partitioned-negative-matrix.md`. That plan also supplies
> the partitioned-case requirements consumed by Task 8. Do not implement the
> parent-domain steps below; they remain only as historical planning context.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a pinned, sandboxed native x86_64 Chromium gate that proves PowGate's complete browser loop under HTTP/1.1 and HTTP/2, repeats it against ASan+UBSan server artifacts, and records reproducible backend benchmark evidence.

**Architecture:** A rootless-Podman host wrapper admits only the canonical AMD64 golden image and four browser targets. Inside the image, one lifecycle-only fixture owns certificates, NGINX, Chromium, CDP, bounded observations, process identity, diagnostics, and cleanup; separate feasibility, E2E, and benchmark executables own their assertions. Benchmark evidence is schema-validated, relationally recomputed, generated under `build/`, and promoted manually only after the fixed backend-order rule agrees with the final tested source.

**Tech Stack:** Debian Trixie snapshot `20260713T000000Z`, rootless Podman, NGINX `1.30.3`, Chromium `150.0.7871.100-1~deb13u1`, Node.js `20.19.2+dfsg-1+deb13u2`, Puppeteer Core `24.43.1`, Ajv `8.17.1`, OpenSSL, CDP, ASan, UBSan, C99 cookie scanner utility, GNU Make.

## Global Constraints

- Read [the frozen Phase 4C design](../specs/2026-07-15-phase4c-browser-e2e-design.md), `AGENTS.md`, `docs/protocol.md`, and `docs/nginx-style.md` before editing. The design is implementation-authoritative; `docs/protocol.md` must not change.
- All builds, tests, browser runs, fuzzers, sanitizers, and npm operations run inside `localhost/ngx-powgate-dev:trixie`. The host only inspects the image, starts Podman, and propagates exit status.
- Perform AMD64 image builds and all x86 browser gates on `ssh vagrant`, using the required rootless Podman environment and eight build jobs:

```sh
export PATH="$HOME/.local/podman/bin:$PATH"
export PATH="$HOME/.local/podman/lib/podman:$PATH"
export LD_LIBRARY_PATH="$HOME/.local/podman/lib:$LD_LIBRARY_PATH"
export CONTAINERS_NO_SYSTEMD=1
```

- Browser-specific targets require native `uname -m = x86_64` and fail on every other architecture. Do not skip, emulate, attach remotely, select another browser, or weaken the sandbox.
- Never pass `--no-sandbox`, `--disable-setuid-sandbox`, `--single-process`, `--no-zygote`, `--disable-seccomp-filter-sandbox`, or `--disable-namespace-sandbox`; never use privileged Podman, added capabilities, unconfined seccomp, host networking, or a host browser profile.
- Chromium executes the exact production script generated from `html/challenge.html` and served by NGINX. Positive E2E and benchmark pages do not wrap or replace `PowGateSolver`, `crypto.subtle.digest()`, timers, Promises, or production source.
- Keep all wire formats, cookie formats, challenge parameters, server-verification semantics, and CSP policy unchanged. Throughput may change only the controller's fixed pre-search backend order.
- Preserve the existing architecture-neutral `make check`, `make test-e2e`, and `make test-fuzz-long` meanings. New browser code adds no production directive, runtime dependency, release artifact, protocol vector, or fuzz target.
- Browser E2E covers the same ten cases under the normal server and a separately built ASan+UBSan server: eight positive solve loops plus two parent-domain fail-closed cases, for twenty browser cases total.
- Every resource has bounded, idempotent cleanup. A callback failure remains primary; diagnostic and cleanup failures are separate classified secondary failures.
- Freeze these operation deadlines in `tests/browser/lib/constants.mjs`:

```text
NGINX_CONFIG_TEST_TIMEOUT_MS=10000
NGINX_READINESS_TIMEOUT_MS=15000
CHROMIUM_LAUNCH_TIMEOUT_MS=30000
BROWSER_CONTEXT_TIMEOUT_MS=10000
CDP_OPERATION_TIMEOUT_MS=10000
DOCUMENT_NAVIGATION_TIMEOUT_MS=30000
E2E_TERMINAL_OUTCOME_TIMEOUT_MS=30000
CONTROLLED_PROBE_TIMEOUT_MS=10000
FAIL_CLOSED_QUIET_WINDOW_MS=1000
BENCHMARK_CONTROLLER_QUIET_WINDOW_MS=1000
DIAGNOSTIC_CAPTURE_TIMEOUT_MS=10000
PAGE_CONTEXT_CLOSE_TIMEOUT_MS=10000
CHROMIUM_CLOSE_TIMEOUT_MS=15000
NGINX_QUIT_TIMEOUT_MS=10000
NGINX_TERM_TIMEOUT_MS=5000
NGINX_KILL_TIMEOUT_MS=2000
```

- Freeze complete outer budgets `180000/600000/360000/1300000ms` for
  feasibility/E2E/benchmark/aggregate, each child budget including a final
  `20000ms` TERM-to-KILL cleanup grace; the aggregate exceeds child totals by
  `160000ms`.
- Freeze benchmark/capture limits: attempts `1..262144`, target JS block
  `10ms`, absolute JS ceiling `25ms`, `4096` events and `1 MiB` metadata per
  page, `8192` raw samples per run series, `16 MiB` evidence, `2 MiB`
  retained diagnostics, `32` failed-sample excerpts, and heartbeat timer tail
  `2`.
- Keep generated benchmark results ignored under `build/`. No Make target writes `docs/benchmarks/`; promotion is explicit, validated, atomic, and reviewed.
- Use TDD for each task: add a focused failing test, observe the intended failure inside the golden image, implement the minimum behavior, rerun the focused gate, then commit one logical change.

## File Map

### Golden image and policy

- Modify `build/versions.env`: exact Debian package versions/checksums, npm locks, and `GOLDEN_IMAGE_LOCK_SHA256`.
- Modify `build/browser/package.json` and `build/browser/package-lock.json`: exact `devDependencies` for Puppeteer Core and Ajv.
- Modify `build/install-dev.sh`: checksum-verified package installation and lockfile-only npm installation.
- Modify `Containerfile`: embed the computed lock as OCI label and immutable environment value.
- Modify `tools/build-pow-module.sh`: use eight native build jobs on x86_64 and retain two elsewhere.
- Create `tools/golden-image-lock.py`: compute, check, and update the fixed ordered image-input hash.
- Create `tests/tools/test_golden_image_lock.py`: lock encoding, self-line exclusion, and mutation tests.
- Modify `tools/check-policy.sh`: invoke image/npm lock checks and sanitizer suppression policy.

### Invocation and shared browser infrastructure

- Create `tools/run-browser-x86.sh`: sole supported browser host wrapper.
- Create `tools/require-browser-x86.sh`: narrow in-container architecture/identity prerequisite.
- Create `tests/tools/test_run_browser_x86.py`: fake-Podman wrapper policy tests.
- Modify `Makefile`: browser targets, sequential aggregate, watchdogs, helper builds, and evidence checks.
- Create `tests/browser/lib/constants.mjs`: frozen deadlines, limits, failure categories, and launch policy.
- Create `tests/browser/lib/fixture.mjs`: lifecycle-only certificates, NGINX, Chromium, CDP, observations, diagnostics, process identity, and cleanup.
- Create `tests/browser/fixture.test.mjs`: deterministic unit tests for deadlines, process identity, retry classification, diagnostics, and cleanup.
- Create `tests/browser/feasibility.mjs`: static H1/H2 Chromium capability and observable-sandbox gate.

### PowGate E2E and sanitizers

- Create `tests/browser/cookie_occurrences.c`: NGINX-free CLI over `pow_cookie_scan_next()`.
- Create `tests/browser/lib/request-observation.mjs`: exact JSON-log decoding and production-scanner invocation.
- Create `tests/browser/request-observation.test.mjs`: JSON-log decoding and production-scanner equivalence tests.
- Create `tests/browser/e2e.mjs`: H1/H2 positive and parent-domain negative matrices.
- Create `tests/browser/e2e.test.mjs`: matrix definitions, URL preservation, cookie scope, observer, and event-policy unit tests.
- Create `tools/prepare-browser-sanitized.sh`: build and describe reusable instrumented server artifacts.
- Create `tests/sanitizer/alignment_negative_control.c`: project-owned test-only alignment fault.
- Create `tests/browser/sanitizer.test.mjs`: artifact identity, environment scrubbing, report collection, and negative-control tests.
- Modify `tools/run-asan.sh`: reuse the sanitizer build/report contract without changing production behavior.
- Modify `tools/ubsan-nginx.supp`: no new entry unless a separately reviewed locked-upstream finding demands it.

### Benchmark and evidence

- Create `tests/browser/lib/evidence.mjs`: schema loading, relational checks, canonical JSON, filename derivation, atomic generation, and promotion validation.
- Create `tests/browser/evidence.test.mjs`: positive/negative schema and relationship fixtures.
- Create `tests/browser/benchmark.mjs`: exact production solver workload, heartbeat, calibration, raw runs, summaries, and fixed decision rule.
- Create `tests/browser/benchmark-driver.js`: exact benchmark-only in-page orchestration bytes; it contains no hash implementation.
- Create `tests/browser/benchmark.test.mjs`: pure benchmark math, continuation, heartbeat, and decision tests.
- Create `docs/benchmarks/phase4c-v1/schema.json`: Draft 2020-12 evidence schema.
- Create `docs/benchmarks/phase4c-v1/README.md`: reproduction and decision documentation.
- Create `tools/promote-phase4c-evidence.mjs`: explicit validated promotion.
- Create `docs/benchmarks/phase4c-v1/x86_64-debian-chromium-150.0.7871.100-1%7Edeb13u1.json` only after the canonical final run.
- Modify `PLAN.md`, `docs/security.md`, `docs/configuration.md`, and `AGENTS.md`: honest completion status and enduring browser-gate rules.

---

### Task 1: Lock the Browser Toolchain and Golden-Image Identity

**Files:**
- Modify: `build/versions.env`
- Modify: `build/browser/package.json`
- Modify: `build/browser/package-lock.json`
- Modify: `build/install-dev.sh`
- Modify: `Containerfile`
- Modify: `tools/build-pow-module.sh`
- Create: `tools/golden-image-lock.py`
- Create: `tests/tools/test_golden_image_lock.py`
- Modify: `tools/check-policy.sh`

**Interfaces:**
- Produces `python3 tools/golden-image-lock.py compute|check|update`.
- Produces immutable in-container `POWGATE_GOLDEN_IMAGE_LOCK` and OCI label `org.ngx-powgate.golden-image-lock`.
- Produces `/opt/ngx-powgate/browser/node_modules/{puppeteer-core,ajv}` installed only from the committed lockfile.

- [ ] **Step 1: Add failing lock-tool tests**

Create `tests/tools/test_golden_image_lock.py` with temporary copies of the five inputs and these exact cases:

```python
class GoldenImageLockTest(unittest.TestCase):
    def test_encoding_is_ordered_length_prefixed_and_excludes_self_line(self):
        first = compute_lock(self.root)
        self.write("build/versions.env", "GOLDEN_IMAGE_LOCK_SHA256=" + "0" * 64 + "\n", append=True)
        self.assertEqual(compute_lock(self.root), first)

    def test_each_owned_input_changes_the_lock(self):
        baseline = compute_lock(self.root)
        for relative in OWNED_INPUTS:
            with self.subTest(relative=relative):
                clone = self.copy_root()
                self.write_at(clone, relative, b"\nmutation\n", append=True)
                self.assertNotEqual(compute_lock(clone), baseline)

    def test_check_rejects_missing_malformed_and_stale_lock(self):
        for value in (None, "xyz", "0" * 64):
            with self.subTest(value=value):
                self.assertNotEqual(run_check(self.root, value).returncode, 0)
```

The implementation imported by the tests must encode each relative pathname and file body as eight-byte big-endian lengths followed by bytes, in this fixed order:

```python
OWNED_INPUTS = (
    "Containerfile",
    "build/install-dev.sh",
    "build/versions.env",
    "build/browser/package.json",
    "build/browser/package-lock.json",
)
```

Run inside the current golden image:

```sh
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  python3 -m unittest -v tests.tools.test_golden_image_lock
```

Expected: FAIL because `tools/golden-image-lock.py` does not exist.

- [ ] **Step 2: Implement the image-lock tool and policy hook**

Implement these exact functions in `tools/golden-image-lock.py`:

```python
def canonical_body(relative: str, body: bytes) -> bytes:
    if relative == "build/versions.env":
        body = b"".join(line for line in body.splitlines(keepends=True)
                        if not line.startswith(b"GOLDEN_IMAGE_LOCK_SHA256="))
    name = relative.encode("ascii")
    return struct.pack(">Q", len(name)) + name + struct.pack(">Q", len(body)) + body


def compute_lock(root: pathlib.Path) -> str:
    digest = hashlib.sha256()
    for relative in OWNED_INPUTS:
        digest.update(canonical_body(relative, (root / relative).read_bytes()))
    return digest.hexdigest()
```

`update` must replace exactly one `GOLDEN_IMAGE_LOCK_SHA256=` line atomically; `check` must require one lowercase 64-hex value and compare with `hmac.compare_digest()`. Extend `check-policy.sh` to call `python3 tools/golden-image-lock.py check`.

- [ ] **Step 3: Add exact package and npm locks**

Record these values in `build/versions.env`:

```sh
CHROMIUM_VERSION=150.0.7871.100-1~deb13u1
CHROMIUM_SHA256_AMD64=87ce517f9fe47c4dcac35fc314fa4ab87117f2496dc27257de2bba11ef8af610
CHROMIUM_SANDBOX_VERSION=150.0.7871.100-1~deb13u1
CHROMIUM_SANDBOX_SHA256_AMD64=a02bc28af35c9cdbaaafb0affa004fa203cf4508d4c7fa280efdc7c521a380c3
NODEJS_VERSION=20.19.2+dfsg-1+deb13u2
NODEJS_SHA256_AMD64=3e2d151f46ae1f1ab644fa6d11d85e7cf30d9aa182935bc16b99bf9888be8a85
NPM_VERSION=9.2.0~ds1-3
NPM_SHA256_AMD64=1dda3b5d8ebcd9c88de0a697f2c7b3d893fd130d9bd2bafb7f237ce46aec9271
PUPPETEER_CORE_VERSION=24.43.1
AJV_VERSION=8.17.1
```

After all owned inputs have their final Task 1 contents, run
`python3 tools/golden-image-lock.py update`; that command appends the one
computed `GOLDEN_IMAGE_LOCK_SHA256=<64-lowercase-hex>` line.

Change `build/browser/package.json` to exact development-only dependencies:

```json
{
  "name": "ngx-powgate-browser-tests",
  "private": true,
  "version": "1.0.0",
  "devDependencies": {
    "ajv": "8.17.1",
    "puppeteer-core": "24.43.1"
  }
}
```

Generate the lockfile inside the container with `npm install --package-lock-only --ignore-scripts --no-audit --no-fund`; assert Ajv's lock entry has the approved integrity and all registry packages have integrity metadata. Add a policy test that rejects ranges and browser-download packages (`puppeteer`, `@puppeteer/browsers`).

- [ ] **Step 4: Verify Debian artifacts before installation**

In `build/install-dev.sh`, add a helper that downloads exactly one `.deb`, verifies its SHA-256, and installs the verified local path:

```sh
download_locked_deb() {
    package=$1
    version=$2
    checksum=$3
    rm -f ./*.deb
    apt-get download "${package}=${version}"
    set -- ./*.deb
    test "$#" -eq 1
    printf '%s  %s\n' "$checksum" "$1" | sha256sum -c -
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$1"
}
```

Use it for `chromium`, `chromium-sandbox`, `nodejs`, and `npm` on AMD64. Keep ARM64 architecture-neutral installs on their existing locked/supported path without making Chromium a browser gate there. Replace npm installation with:

```sh
npm ci --prefix /opt/ngx-powgate/browser --ignore-scripts --no-audit --no-fund
```

Do not use `--omit=dev`.

- [ ] **Step 5: Embed and verify the image lock**

Add to `Containerfile` without embedding a literal hash in the file being hashed:

```dockerfile
ARG GOLDEN_IMAGE_LOCK_SHA256
LABEL org.ngx-powgate.golden-image-lock=${GOLDEN_IMAGE_LOCK_SHA256}
ENV POWGATE_GOLDEN_IMAGE_LOCK=${GOLDEN_IMAGE_LOCK_SHA256}
```

Run `python3 tools/golden-image-lock.py update`, then:

```sh
python3 tools/golden-image-lock.py check
python3 -m unittest -v tests.tools.test_golden_image_lock
./tools/check-policy.sh
```

Expected: all pass.

- [ ] **Step 6: Use all eight x86 build jobs**

In `tools/build-pow-module.sh`, select the native default without accepting a
browser-target override:

```sh
module_jobs=2
case "$(uname -m)" in
    amd64|x86_64) module_jobs=8 ;;
esac
make -j"$module_jobs" modules
```

Keep `POW_BUILD_JOBS` out of the supported browser wrapper environment so a
caller cannot alter the canonical run. `tools/run-asan.sh` and
`tools/prepare-browser-sanitized.sh` use the same `8`/`2` architecture rule.

- [ ] **Step 7: Build and inspect the canonical AMD64 image on vagrant**

Run on `vagrant`:

```sh
lock=$(awk -F= '$1=="GOLDEN_IMAGE_LOCK_SHA256" {print $2}' build/versions.env)
base=$(awk -F= '$1=="DEBIAN_IMAGE_AMD64" {print $2}' build/versions.env)
podman build --jobs=8 --build-arg TARGETARCH=amd64 \
  --build-arg BASE_IMAGE="$base" \
  --build-arg GOLDEN_IMAGE_LOCK_SHA256="$lock" \
  -t localhost/ngx-powgate-dev:trixie -f Containerfile .
podman image inspect localhost/ngx-powgate-dev:trixie \
  --format '{{.Architecture}} {{index .Labels "org.ngx-powgate.golden-image-lock"}}'
podman run --rm --userns=keep-id localhost/ngx-powgate-dev:trixie \
  sh -eu -c 'test "$POWGATE_GOLDEN_IMAGE_LOCK" = "'"$lock"'"; dpkg-query -W chromium chromium-sandbox nodejs npm; node -e '\''const {createRequire}=require("node:module"); const r=createRequire("/opt/ngx-powgate/browser/package.json"); console.log(r("puppeteer-core/package.json").version, r("ajv/package.json").version)'\'''
```

Expected: `amd64`, matching lock values, exact Debian package versions, and `24.43.1 8.17.1`.

- [ ] **Step 8: Commit**

```sh
git add Containerfile build/versions.env build/install-dev.sh \
  build/browser/package.json build/browser/package-lock.json \
  tools/golden-image-lock.py tools/check-policy.sh tools/build-pow-module.sh \
  tests/tools/test_golden_image_lock.py
git commit -m "build: lock Phase 4C browser environment"
```

---

### Task 2: Enforce the Canonical x86 Host and Container Boundary

**Files:**
- Create: `tools/run-browser-x86.sh`
- Create: `tools/require-browser-x86.sh`
- Create: `tests/tools/test_run_browser_x86.py`
- Modify: `Makefile`

**Interfaces:**
- `tools/run-browser-x86.sh <one-approved-target>` starts the exact image and forwards only verified metadata.
- `tools/require-browser-x86.sh <public-target-name>` validates architecture, UID/GID, seccomp, capabilities, image lock, packages, and browser-control environment.
- Make exposes `test-browser-feasibility`, `test-browser-e2e`, `benchmark-browser`, and sequential `check-browser-x86`.

- [ ] **Step 1: Add fake-Podman wrapper policy tests**

Create `tests/tools/test_run_browser_x86.py`. Its fake `podman` records argv and returns controlled JSON for `info` and `image inspect`. Cover exactly:

```python
APPROVED = (
    "test-browser-feasibility",
    "test-browser-e2e",
    "benchmark-browser",
    "check-browser-x86",
)

def test_rejects_zero_two_or_unknown_targets(self):
    for argv in ((), ("unknown",), (APPROVED[0], APPROVED[1])):
        with self.subTest(argv=argv):
            self.assertNotEqual(self.run_wrapper(*argv).returncode, 0)

def test_rejects_remote_browser_environment(self):
    for name in ("POW_GATE_BROWSER_WS_ENDPOINT",
                 "PUPPETEER_BROWSER_WS_ENDPOINT",
                 "PUPPETEER_EXECUTABLE_PATH", "CHROME_PATH"):
        result = self.run_wrapper(APPROVED[0], env={name: "forbidden"})
        self.assertNotEqual(result.returncode, 0)

def test_success_uses_only_the_fixed_invocation(self):
    result = self.run_wrapper(APPROVED[0])
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertEqual(self.recorded_run_argv(), self.expected_run_argv(APPROVED[0]))
```

The same class uses fake `podman info`/`image inspect` fixtures to reject
rootful operation, non-AMD64 images, a mismatched OCI label, and a working
directory other than the physical repository root.

The success assertion must compare the complete final `podman run` argv,
including `--rm`, `--userns=keep-id`, one canonical
`-v <repo>:/work:Z`, `-w /work`, exact image, and `make <target>`. The six
explicit metadata variables are host UID, host GID, image ID, nullable
repository digest, verified image lock, and Podman version. Run the test
in-container and expect failure because the wrapper is absent.

```sh
python3 -m unittest -v tests.tools.test_run_browser_x86
```

Expected: FAIL with the missing `tools/run-browser-x86.sh` path.

- [ ] **Step 2: Implement the host wrapper**

Create POSIX `tools/run-browser-x86.sh` with:

```sh
case "${1-}" in
    test-browser-feasibility|test-browser-e2e|benchmark-browser|check-browser-x86) target=$1 ;;
    *) echo "error: run-browser-x86 requires exactly one approved browser target" >&2; exit 2 ;;
esac
test "$#" -eq 1
```

Reject non-empty `POW_GATE_BROWSER_WS_ENDPOINT`,
`PUPPETEER_BROWSER_WS_ENDPOINT`, `PUPPETEER_EXECUTABLE_PATH`, and
`CHROME_PATH`. Resolve the repository with `git rev-parse --show-toplevel`
and require physical `$PWD` equality. Parse `podman info --format json` and
`podman image inspect --format json` using Python, require rootless, image
architecture `amd64`, and the exact OCI lock. Forward only wrapper-derived
UID, GID, image ID, nullable repository digest, verified lock, and
`podman version --format '{{.Client.Version}}'`.

- [ ] **Step 3: Implement the in-container guard**

Create `tools/require-browser-x86.sh` with a target-specific diagnostic and these checks:

```sh
test "$(uname -m)" = x86_64 || fail "requires native x86_64; detected $(uname -m)"
test "$(id -u)" -ne 0 || fail "requires non-root controller"
test "$(id -u)" = "$POWGATE_HOST_UID" || fail "UID mapping mismatch"
test "$(id -g)" = "$POWGATE_HOST_GID" || fail "GID mapping mismatch"
test "$(awk '/^Seccomp:/ {print $2}' /proc/self/status)" = 2 || fail "seccomp is not filtering"
test "$(awk '/^CapEff:/ {print $2}' /proc/self/status)" = 0000000000000000 || fail "controller capabilities are not zero"
test "$POWGATE_GOLDEN_IMAGE_LOCK" = "$POWGATE_IMAGE_LOCK" || fail "embedded image lock mismatch"
```

Also reject the four browser-control variables, verify `/usr/bin/chromium` with `command -v` and `readlink -f`, exact `dpkg-query` versions, npm library versions, and `chromium --version`. This zero-capability rule is explicitly the canonical invocation's locked property.

- [ ] **Step 4: Add sequential Make targets and outer watchdogs**

Add a `require-browser-x86-%` prerequisite that calls the guard before any build or fixture prerequisite. Recipes use GNU `timeout` with TERM at `target_budget - 20000ms` and KILL at the total budget. Define:

```make
test-browser-feasibility:
	./tools/require-browser-x86.sh test-browser-feasibility
	timeout --signal=TERM --kill-after=20s 160s node tests/browser/feasibility.mjs

test-browser-e2e:
	./tools/require-browser-x86.sh test-browser-e2e
	$(MAKE) module
	timeout --signal=TERM --kill-after=20s 580s node tests/browser/e2e.mjs

benchmark-browser:
	./tools/require-browser-x86.sh benchmark-browser
	$(MAKE) challenge-page
	timeout --signal=TERM --kill-after=20s 340s node tests/browser/benchmark.mjs

check-browser-x86:
	./tools/require-browser-x86.sh check-browser-x86
	timeout --signal=TERM --kill-after=20s 1280s sh -eu -c \
	  '$(MAKE) test-browser-feasibility && $(MAKE) test-browser-e2e && $(MAKE) benchmark-browser'
```

The watchdog's first duration is the TERM deadline; `--kill-after=20s` makes
the complete budgets exactly `180/600/360/1300` seconds. The target recipes
initially fail because their executables do not exist. Verify non-x86
diagnostics by overriding `uname` with a test fixture in the guard's unit
test; never use `setarch` or emulation for a passing browser target.

- [ ] **Step 5: Run and commit the boundary tests**

```sh
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  python3 -m unittest -v tests.tools.test_run_browser_x86
shellcheck tools/run-browser-x86.sh tools/require-browser-x86.sh
```

Expected: all pass.

```sh
git add Makefile tools/run-browser-x86.sh tools/require-browser-x86.sh \
  tests/tools/test_run_browser_x86.py
git commit -m "build: enforce native x86 browser boundary"
```

---

### Task 3: Build the Bounded Fixture Foundation

**Files:**
- Create: `tests/browser/lib/constants.mjs`
- Create: `tests/browser/lib/fixture.mjs`
- Create: `tests/browser/fixture.test.mjs`

**Interfaces:**
- `withFixture(options, callback) -> Promise<T>` owns a single-use fixture and always cleans it.
- `options` has `{ target, protocolMode, renderNginxConfig, staticFiles, nginxBinary, modulePath, nginxEnvironment }`.
- The callback receives `{ paths, origin, ports, nginx, observations, createBrowserSession, captureRequestObservation }`.
- `createBrowserSession()` returns `{ browser, context, page, cdp, observations, close }` without interpreting PowGate events.

- [ ] **Step 1: Freeze constants and failure types in tests**

In `fixture.test.mjs`, assert every deadline and limit from Design Sections 11–12, including target budgets `180000/600000/360000/1300000`, cleanup grace `20000`, operation deadlines, event/sample/evidence/diagnostic limits, and the exact failure-category set. Add:

```js
assert.ok(BROWSER_AGGREGATE_TIMEOUT_MS
    > FEASIBILITY_TARGET_TIMEOUT_MS + E2E_TARGET_TIMEOUT_MS
      + BENCHMARK_TARGET_TIMEOUT_MS);
assert.equal(BROWSER_AGGREGATE_TIMEOUT_MS
    - FEASIBILITY_TARGET_TIMEOUT_MS - E2E_TARGET_TIMEOUT_MS
    - BENCHMARK_TARGET_TIMEOUT_MS, 160000);
```

Run `node --test tests/browser/fixture.test.mjs`; expect import failure.

- [ ] **Step 2: Implement named deadlines and classified failures**

Create `constants.mjs` with frozen exported objects. In `fixture.mjs`, implement:

```js
export class BrowserTestFailure extends Error {
    constructor(category, operation, message, options = {}) {
        super(message, options);
        if (!FAILURE_CATEGORIES.has(category)) throw new TypeError('invalid category');
        this.category = category;
        this.operation = operation;
        Object.freeze(this);
    }
}

export async function withDeadline(operation, milliseconds, promise) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), milliseconds);
    try { return await promise(controller.signal); }
    finally { clearTimeout(timer); }
}
```

Timeout errors include only fixed operation/deadline tokens. Do not include URLs, cookies, response bodies, console payloads, or raw exceptions in retained output.

- [ ] **Step 3: Implement runtime isolation, process identity, and diagnostics**

Implement `readProcessIdentity(pid)` returning frozen `{pid, ppid, startTime, executable, commandLine}` from `/proc`. `identityStillMatches(identity)` must compare all fields before signal or liveness actions. Unit tests spawn `sleep`, verify identity, corrupt each field, and prove no signal is sent for mismatches.

Create runtime roots only under `build/browser-runtime/<target>-<pid>-<random>/`. Diagnostics use an allowlisted object and recursive byte accounting; overflow is `internal_invariant`, never truncation. On failure persist at most `2 MiB` under `build/browser-diagnostics/`, excluding all raw headers, URLs with queries, cookies, challenge data, profiles, key contents, and CDP payloads.

- [ ] **Step 4: Implement certificates, ports, and NGINX lifecycle**

Generate one ephemeral EC P-256 key/certificate with SANs `powgate.test` and `gate.powgate.test`, owner-only key mode, and no host trust-store changes. Reserve loopback ports, release immediately before NGINX, run `nginx -t -p <prefix> -c <config>`, then foreground NGINX.

Retry the complete allocation/start sequence at most three times only when
sanitized stderr directly identifies an `EADDRINUSE`-equivalent NGINX bind
failure for one selected port. Tests feed bind, config, certificate,
permission, and unexplained-exit samples and require retry only for bind.

Shutdown verified master/worker identities with `QUIT`, then `TERM`, then `KILL`; escalation beyond `QUIT` is a separately classified cleanup failure. Never invoke `nginx -s`, kill by name, or trust a reused PID.

- [ ] **Step 5: Implement the single-use fixture transaction**

Use this state transition contract:

```js
const transitions = Object.freeze({
    created: new Set(['starting']),
    starting: new Set(['ready', 'failed']),
    ready: new Set(['stopping', 'failed']),
    failed: new Set(['stopping']),
    stopping: new Set(['stopped']),
    stopped: new Set()
});
```

`withFixture()` keeps the callback error primary, attaches `diagnosticFailures` and `cleanupFailures`, and guarantees idempotent reverse-order cleanup. Tests call cleanup twice, inject callback/diagnostic/cleanup failures, and assert classification and primary-error preservation.

- [ ] **Step 6: Run focused tests and commit**

```sh
node --test tests/browser/fixture.test.mjs
```

Expected: all fixture-only tests pass without starting Chromium.

```sh
git add tests/browser/lib/constants.mjs tests/browser/lib/fixture.mjs \
  tests/browser/fixture.test.mjs
git commit -m "test: add bounded browser fixture lifecycle"
```

---

### Task 4: Add Chromium Lifecycle and the Permanent Feasibility Gate

**Files:**
- Modify: `tests/browser/lib/fixture.mjs`
- Modify: `tests/browser/fixture.test.mjs`
- Create: `tests/browser/feasibility.mjs`

**Interfaces:**
- `createBrowserSession({ protocolMode, observe })` launches only `/usr/bin/chromium` with central allowed arguments.
- `openObservationWindow(name)` returns `{ cursor, waitFor(predicate), close() }` so expected probe events are consumed and cannot leak into later probes.
- `makeProtocolObserver(cdp) -> { waitForDocument(url), protocolFor(requestId) }` uses CDP response metadata.

- [ ] **Step 1: Add failing launch-policy and observation-window tests**

Test that central launch construction permits only headless, unique profile, `--disable-dev-shm-usage`, fixed resolver rules, H1 selection, and reviewed background-network isolation. Reject every prohibited flag even when introduced through options. Test observation count `4096` and metadata `1 MiB` overflow.

Add per-probe cursor tests: a generated console event is visible only to its own window after that window closes.

```sh
node --test tests/browser/fixture.test.mjs
```

Expected: FAIL because Chromium launch-policy and observation-window exports
are absent.

- [ ] **Step 2: Implement Chromium launch, descendant identity, and cleanup**

Load Puppeteer Core through:

```js
const require = createRequire('/opt/ngx-powgate/browser/package.json');
const puppeteer = require('puppeteer-core');
```

Launch with explicit `/usr/bin/chromium`, `headless: true`, `acceptInsecureCerts: true`, the unique fixture profile, and fixed resolver mapping:

```text
MAP powgate.test 127.0.0.1,MAP gate.powgate.test 127.0.0.1,EXCLUDE localhost
```

The checked-in requested-argument allowlist is exactly:

```text
--disable-dev-shm-usage
--disable-background-networking
--disable-component-update
--disable-default-apps
--disable-domain-reliability
--disable-sync
--metrics-recording-only
--no-default-browser-check
--no-first-run
--host-resolver-rules=MAP powgate.test 127.0.0.1,MAP gate.powgate.test 127.0.0.1,EXCLUDE localhost
```

H1 adds only `--disable-http2`. Inspect requested and observed descendant
command lines, including pinned Puppeteer/Chromium internal arguments, and
reject every prohibited flag. Require separate browser and at least one
renderer identities; record optional zygote/utility/GPU/network/crash-handler
processes without requiring every type. Verify controller and one renderer
`Uid`, `Gid`, `NoNewPrivs`, `Seccomp`, and `CapEff` fields as observable
sandbox evidence.

Scrub `ASAN_OPTIONS`, `UBSAN_OPTIONS`, `LD_PRELOAD`, and sanitizer runtime-path variables from Chromium's environment. Close CDP, pages, contexts, browser, then verified descendants with named deadlines.

- [ ] **Step 3: Implement the H1/H2 static feasibility fixture**

Create `feasibility.mjs` using minimal static NGINX, not PowGate. Run two independent Chromium processes:

```js
for (const protocolMode of ['h2', 'h1']) {
    await withFixture(feasibilityOptions(protocolMode), async (fixture) => {
        await runFeasibilityProbes(fixture, protocolMode);
    });
}
```

The H1 launch disables HTTP/2 explicitly; H2 uses normal ALPN. CDP must report exactly `http/1.1` or `h2` for navigation.

- [ ] **Step 4: Add controlled capability probes**

Use separate observation windows for: allowed exact-hash CSP script; controlled blocked script/CSP event; `Secure; SameSite=Lax; Path=/` cookie set/read/delete; reload with path/query unchanged; one console identifier; one page error identifier; one failed fixture request; and one disposable renderer crash. The crash probe must leave the browser and a control page usable and accept documented racing crash/loss event order, but fail if the whole browser exits.

Finally create a deliberate browser disconnect only after all other probes and assert disconnect observation. The harness states only that all approved observable sandbox acceptance properties passed; it does not claim complete proof of Chromium internals.

- [ ] **Step 5: Run twice through the canonical wrapper and commit**

On `vagrant`:

```sh
tools/run-browser-x86.sh test-browser-feasibility
tools/run-browser-x86.sh test-browser-feasibility
```

Expected: both H1 and H2 runs pass twice, no retained runtime directory, and no orphaned Chromium/NGINX identity.

```sh
git add tests/browser/lib/fixture.mjs tests/browser/fixture.test.mjs \
  tests/browser/feasibility.mjs
git commit -m "test: add permanent chromium feasibility gate"
```

---

### Task 5: Add Exact Request and Cookie Observation Utilities

**Files:**
- Create: `tests/browser/cookie_occurrences.c`
- Create: `tests/browser/lib/request-observation.mjs`
- Create: `tests/browser/request-observation.test.mjs`
- Modify: `Makefile`

**Interfaces:**
- `build/browser-tools/cookie-occurrences <hex-field>` prints only `{"count":N}` and exits nonzero on invalid hex/scanner error.
- `decodeNginxJsonLogString(text) -> Buffer` decodes NGINX `escape=json` bytes before scanning.
- `observeRequest(record) -> { requestUriMatches, proofOccurrenceCount, singleEffectiveCookieField }` retains verdicts only.

- [ ] **Step 1: Add scanner CLI and JSON-decoding tests**

Table-drive fields including empty, one proof, prefix names, empty proof value, four auth values, SP/HTAB, delimiters, and high bytes. For each row compare the CLI count with the existing C unit-table expectation. Add JSON escapes for quote, backslash, control, DEL, UTF-8 bytes, and assert the scanner receives decoded bytes—not the literal `\u00xx` sequences.

Add a failure case for a log record declaring more than one effective Cookie field. The utility must fail rather than concatenate, split, normalize, or scan multiple fields.

```sh
node --test tests/browser/request-observation.test.mjs
```

Expected: FAIL because the request-observation module and scanner CLI are
absent.

- [ ] **Step 2: Implement the production-scanner CLI**

The C program decodes even-length hexadecimal into a fixed `8192`-byte caller buffer, then calls:

```c
rc = pow_cookie_scan_next(field, field_len,
                          (const uint8_t *) "__pow_p",
                          sizeof("__pow_p") - 1, &cursor, &value);
```

It loops forward, counts exact occurrences, and never outputs values. Build with the pure-core warning set and `src/pow_cookie_scan.c`; no NGINX header or allocation.

- [ ] **Step 3: Implement transient NGINX observation decoding**

Implement `decodeNginxJsonLogString()` and `observeRequest()` in
`tests/browser/lib/request-observation.mjs`. Configure an isolated
`escape=json` log containing only a case identifier, `$request_uri`,
`$http_cookie`, and an explicit harness-known H1/H2 effective-field-count
marker. Decode JSON escapes to bytes, compare request URI against a checked-in
`Buffer.from(expected, 'ascii')`, hex-encode the decoded cookie bytes, and
call the scanner CLI.

For H1, reject a request unless the fixture proves Chromium sent one Cookie field. For the locked H2 path, require NGINX's reconstructed single effective `$http_cookie` field and the pinned-source `; ` reconstruction contract. CDP remains authoritative only for negotiated protocol/navigation identity.

- [ ] **Step 4: Run and commit**

```sh
make build/browser-tools/cookie-occurrences
node --test tests/browser/request-observation.test.mjs
```

Expected: all exact-byte and occurrence tests pass.

```sh
git add Makefile tests/browser/cookie_occurrences.c \
  tests/browser/lib/request-observation.mjs \
  tests/browser/request-observation.test.mjs
git commit -m "test: add exact browser request observation"
```

---

### Task 6: Implement the Eight Positive H1/H2 Browser Loops

**Files:**
- Create: `tests/browser/e2e.mjs`
- Create: `tests/browser/e2e.test.mjs`

**Interfaces:**
- `positiveCases()` returns four frozen cases with exact raw target, browser pathname/search, and optional stale-cookie seed.
- `runPositiveCase(fixture, testCase) -> Promise<fixed verdict object>` executes untouched production code.
- `runE2EMatrix({ serverBuild })` runs H2 then H1 with fresh contexts per case.

- [ ] **Step 1: Freeze the matrix and expected URL bytes**

Add exact cases:

```js
Object.freeze([
  { id: 'root', target: '/' },
  { id: 'literal-semicolon', target: '/account;view=full?mode=literal&value=1' },
  { id: 'encoded-repeat', target: '/a%3Bb//c?mode=encoded&value=%2F' },
  { id: 'stale-safe', target: '/account/orders?mode=stale', stalePath: '/account' }
]);
```

Unit tests require no URL helper normalization, exact browser-visible pathname/search, and exact ASCII request-target buffers. The stale cookie is syntactically valid, distinguishable from any fresh proof, host-only, secure, and path-scoped.

```sh
node --test tests/browser/e2e.test.mjs
```

Expected: FAIL because `positiveCases()` and the matrix runner are absent.

- [ ] **Step 2: Render the production PowGate NGINX fixture**

Use the production module, HTTPS-only listeners, RealIP-compatible loopback client identity, fixed test secret file mode `0600`, difficulty `8`, auth cookie name `PowAuth`, and a backend endpoint that increments a fixture-owned counter and returns fixed body `powgate backend ok\n`.

The challenge location must preserve `merge_slashes` behavior intentionally and log only transient request-verdict fields. Use the existing module's exact challenge response; do not recreate HTML or solver bytes.

- [ ] **Step 3: Assert the complete transition contract**

For each protocol/case, assert:

```text
one controller start
one 503 challenge
one contiguous proof-search episode (possibly multiple solve calls)
one successful proof-cookie write
one reload of the same browser-visible URL
one verified proof and transactional auth/clear outcome
one backend 200 and exactly one backend reach
```

Require CDP protocol on both the 503 and 200, no redirect, no extra navigation/reload loop, unchanged `location.pathname + location.search`, and decoded `$request_uri` equality. The 503 has one valid `PowGate-Challenge` whose v/d/b/n equal the embedded JSON, plus CSP, `Cache-Control: no-store`, and `X-Robots-Tag: noindex`; retain only equality verdicts.

Apply an explicit response-header allowlist: NGINX transport headers, the
declared PowGate challenge header, CSP, cache policy, robots policy, and the
browser-native cookie effects below. Reject debug headers, internal module
headers, undeclared PowGate headers, duplicate protocol headers, and any
secret/header value outside the public challenge contract.

- [ ] **Step 4: Assert browser-native cookies and silence**

Through browser/CDP cookies, require exactly one host-only `PowAuth` with `Path=/`, Secure, HttpOnly, SameSite=Lax, no Domain, and exact v1 value shape. Require zero exact `__pow_p` after final 200. Where CDP exposes repeated Set-Cookie fields unambiguously, record issuance/clear as supporting evidence only.

The auth value must be exactly 39 bytes:
`"1." + b64url(payload[10]) + "." + b64url(mac[16])`. Validate its canonical
base64url fields without retaining the value.

Transiently prove the initial stale path cookie was sent, the reload has exactly one fresh root proof occurrence under production scanner semantics, stale is gone, and final proof count is zero. Retain booleans/counts only.

Fail on console output of any level, pageerror, unhandled rejection, crash, failed document request, CSP violation, retry UI, external/subresource/fetch/XHR/WebSocket/worker/beacon request, or any fixture-origin request beyond the two document navigations.

- [ ] **Step 5: Run the normal matrix and commit**

Temporarily expose `node tests/browser/e2e.mjs --server-build normal` for the focused run:

```sh
tools/run-browser-x86.sh test-browser-e2e
```

At this task boundary, the target runs the normal eight cases only and prints a fixed `normal_cases=8 verdict=passed` summary; Task 8 expands it to the mandatory twenty.

```sh
git add tests/browser/e2e.mjs tests/browser/e2e.test.mjs
git commit -m "test: add real browser PowGate solve matrix"
```

---

### Task 7: Add Parent-Domain Fail-Closed Browser Cases

**Files:**
- Modify: `tests/browser/e2e.mjs`
- Modify: `tests/browser/e2e.test.mjs`

**Interfaces:**
- `installNegativeSolverObserver(page) -> Promise<void>` installs one pre-document observational descriptor.
- `runParentDomainNegative(fixture, protocolMode) -> Promise<fixed verdict object>` owns the native undeletable-domain case.

- [ ] **Step 1: Add observer descriptor and domain-cookie tests**

Unit-test a pre-document observer that accepts exactly one `PowGateSolver` assignment, validates exactly enumerable `sha256` and `solve`, preserves `sha256`, uses `Reflect.apply(namespace.solve, namespace, args)`, returns the original Promise behavior, adds no visible export, and freezes the wrapper. Missing/repeated/different namespace assignment fails before reading the solve count.

Test browser-cookie metadata using normalized `domain: 'powgate.test'`, `hostOnly === false` where exposed, applicability to `gate.powgate.test`, and no requirement for a leading dot.

```sh
node --test tests/browser/e2e.test.mjs
```

Expected: FAIL on the new observer/domain-cookie cases before production
matrix code changes.

- [ ] **Step 2: Implement the two negative cases**

Seed through CDP/browser cookies:

```js
{
  name: '__pow_p',
  value: '1.<current-canonical-bucket>.0',
  domain: 'powgate.test',
  path: '/',
  secure: true,
  sameSite: 'Lax'
}
```

Before controller cleanup, capture only `initial_document_cookie_exact_proof_count: 1`. After the 503 and static failure UI, observe `FAIL_CLOSED_QUIET_WINDOW_MS = 1000` and require unchanged URL, one document request total, zero solve calls, zero proof mutation, zero backend requests, zero reload, no automatic retry, and unchanged parent-domain cookie. Remove it explicitly during context cleanup.

Apply the same 503 challenge/header/protocol assertions as the positive
matrix before interpreting the terminal controller result.

- [ ] **Step 3: Run ten normal cases and commit**

```sh
tools/run-browser-x86.sh test-browser-e2e
```

Expected fixed summary: `normal_positive=8 normal_negative=2 verdict=passed`.

```sh
git add tests/browser/e2e.mjs tests/browser/e2e.test.mjs
git commit -m "test: cover undeletable proof cookies in chromium"
```

---

### Task 8: Run the Complete Browser Matrix Under ASan and UBSan

**Files:**
- Create: `tools/prepare-browser-sanitized.sh`
- Create: `tests/sanitizer/alignment_negative_control.c`
- Create: `tests/browser/sanitizer.test.mjs`
- Modify: `tests/browser/lib/fixture.mjs`
- Modify: `tools/run-asan.sh`
- Modify: `tools/check-policy.sh`
- Modify: `tests/browser/e2e.mjs`
- Modify: `Makefile`

**Interfaces:**
- `tools/prepare-browser-sanitized.sh <output-dir>` writes `manifest.json`, instrumented `nginx`, module, hashes, and sanitizer runtime configuration.
- `collectSanitizerReports(manifest, processIdentities) -> fixed verdict` collects reports that exist but does not require clean-run marker files.
- `test-browser-e2e` runs normal 10 then sanitized 10 using identical browser cases/assertions.

- [ ] **Step 1: Add failing policy and negative-control tests**

Extend policy fixtures so any `-fno-sanitize=alignment` applied to PowGate, any PowGate-named suppression, wildcard/broad HTTP/2 suppression, or artifact containing `fault`/`negative-control` under `out/` fails. Keep the current exact upstream suppression allowlist.

Create `alignment_negative_control.c` outside production source. It performs one deliberate misaligned `uint32_t` load from a byte buffer and is compiled only as a standalone test artifact under `build/sanitizer-negative-control/`.

```sh
node --test tests/browser/sanitizer.test.mjs
```

Expected: FAIL because sanitizer manifest/report collection and the negative
control artifact do not exist.

- [ ] **Step 2: Factor reusable sanitized server preparation**

Move the instrumented NGINX/module build portion of `run-asan.sh` into `prepare-browser-sanitized.sh`. Configure locked source with Clang, `--with-debug`, SSL, HTTP/2, RealIP, compatibility, and:

```text
-fsanitize=address,undefined -fno-omit-frame-pointer
```

Use eight jobs on x86_64. Manifest fields include paths, SHA-256 values, compile/link flags, dynamic runtime linkage/symbol inspection, and proof the artifacts differ from normal. “Linked native support code” means project-built native code in this build; do not claim system OpenSSL was rebuilt.

- [ ] **Step 3: Test report collection and environment ownership**

Run the negative control with the same UBSan report directory and require a captured project-owned alignment report. Separately inspect compilation metadata/policy to prove no PowGate suppression or alignment disable; the negative control is not the sole proof. Implement `collectSanitizerReports()` in the lifecycle-owned `tests/browser/lib/fixture.mjs`; E2E interprets its fixed verdict but does not own report-file cleanup.

Tests require sanitizer variables on the NGINX master/workers but absent from Node/Chromium. Record sanitized master exact path/hash, every descendant worker generation, and all exits. Collect every report that exists; fail on any ASan/UBSan report, initialization error, deadly signal, allocator failure, abnormal exit, or sanitizer stderr signature. Do not require empty clean logs or startup/exit markers.

- [ ] **Step 4: Execute the identical sanitized matrix**

Update `e2e.mjs` to call the same frozen `runE2EMatrix()` first with normal paths/environment, then sanitized manifest paths/environment. Only server compiler/linker instrumentation differs. Use the same browser process policy, solver bytes, protocols, URLs, cookies, timeouts, and assertions.

- [ ] **Step 5: Run sanitizer and browser gates, then commit**

```sh
tools/run-browser-x86.sh test-browser-e2e
```

Expected fixed summary: `normal=10 sanitized=10 total=20 verdict=passed`, no sanitizer report, all worker generations exited.

```sh
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie sh -eu -c \
  './tools/check-policy.sh && node --test tests/browser/sanitizer.test.mjs && make asan'
```

Expected: policy, negative control, and existing sanitizer suite pass.

```sh
git add Makefile tools/prepare-browser-sanitized.sh tools/run-asan.sh \
  tools/check-policy.sh tests/sanitizer/alignment_negative_control.c \
  tests/browser/sanitizer.test.mjs tests/browser/lib/fixture.mjs \
  tests/browser/e2e.mjs
git commit -m "test: run browser matrix under sanitizers"
```

---

### Task 9: Define and Validate Versioned Benchmark Evidence

**Files:**
- Create: `docs/benchmarks/phase4c-v1/schema.json`
- Create: `docs/benchmarks/phase4c-v1/README.md`
- Create: `tests/browser/lib/evidence.mjs`
- Create: `tests/browser/evidence.test.mjs`
- Create: `tools/promote-phase4c-evidence.mjs`
- Modify: `.gitignore`
- Modify: `Makefile`

**Interfaces:**
- `validateEvidence(value) -> void` performs Ajv and relational checks without mutation.
- `canonicalJson(value) -> Buffer` recursively ASCII-sorts object keys, preserves array order, indents two spaces, and ends LF.
- `canonicalEvidenceFilename(arch, packageName, version) -> string` percent-encodes unsafe UTF-8 bytes with uppercase hex.
- `writeEvidenceAtomically(path, value) -> Promise<void>` validates before and after atomic replacement.

- [ ] **Step 1: Add schema, filename, and serialization tests**

Use Ajv 2020 explicitly:

```js
const require = createRequire('/opt/ngx-powgate/browser/package.json');
const Ajv2020 = require('ajv/dist/2020.js').default;
```

Tests require `$schema` Draft 2020-12, `additionalProperties: false`, exact 14 runs, exact seven per backend, fixed pair order, and mutation-free validation. Negative fixtures cover extra fields, NaN/Infinity before serialization, unsafe integer, missing samples, wrong median, wrong p95, wrong decision, wrong summary, oversized arrays, and incomplete cleanup.

Filename tests require:

```js
assert.equal(canonicalEvidenceFilename('x86_64', 'chromium',
  '150.0.7871.100-1~deb13u1'),
  'x86_64-debian-chromium-150.0.7871.100-1%7Edeb13u1.json');
assert.equal(encodeVersion('%~'), '%25%7E');
```

Run:

```sh
node --test tests/browser/evidence.test.mjs
```

Expected: FAIL because the schema and evidence library are absent.

- [ ] **Step 2: Implement schema and relational validation**

Create the complete schema from Design Section 9 with fixed
`schema_version: "phase4c-benchmark-v1"`. Raw samples occur only under runs;
summaries contain only derived scalars and seven-element throughput arrays.
Persist hit data only as `valid_hit_count`, nullable
`first_valid_hit_offset`, and `safe_domain_terminal`.

Relational validation recomputes pair order, workload identity, counts, elapsed time, throughput, heartbeat nearest-rank p95, minimum heartbeat samples, maxima, median fourth value, matched wins, summaries, decision, and promotability. It must check every heartbeat deadline once, strictly +5ms, no deadline after recorded end, and that drain samples do not extend throughput elapsed time.

- [ ] **Step 3: Implement canonical atomic generation**

Recursively sort keys with an explicit ASCII comparator, preserve arrays, reject non-finite values, serialize UTF-8/two spaces/final LF, enforce `16 MiB`, write a same-directory temporary file, `fsync`, rename, reopen, parse, and rerun both validators. Delete stale output at target start and remove it on any failed/post-write validation.

- [ ] **Step 4: Implement explicit promotion**

`promote-phase4c-evidence.mjs` accepts only `build/benchmark-browser-result.json`. Before copying, require promotable, clean worktree, `HEAD === tested_source.commit`, unchanged tracked files since benchmark, matching script/page/CSP/benchmark-tool/image locks, and full validation. Derive the filename with the shared function, refuse overwrite, and copy atomically as the final operation.

The initial README documents the schema, reproduction command, fixed rule, and that the canonical evidence file will be added only by the final evidence-only commit.

- [ ] **Step 5: Run and commit evidence tooling**

```sh
node --test tests/browser/evidence.test.mjs
make check-policy
```

Expected: positive and negative schema/relationship fixtures pass.

```sh
git add .gitignore Makefile docs/benchmarks/phase4c-v1/schema.json \
  docs/benchmarks/phase4c-v1/README.md tests/browser/lib/evidence.mjs \
  tests/browser/evidence.test.mjs tools/promote-phase4c-evidence.mjs
git commit -m "test: define Phase 4C benchmark evidence"
```

---

### Task 10: Implement the Reproducible Browser Benchmark

**Files:**
- Create: `tests/browser/benchmark.mjs`
- Create: `tests/browser/benchmark-driver.js`
- Create: `tests/browser/benchmark.test.mjs`
- Modify: `Makefile`

**Interfaces:**
- `runBenchmarkSession(fixture) -> Evidence` returns exactly fourteen validated runs.
- `runBoundedWork(page, backend, config) -> Promise<Run>` calls unchanged public `solve(nonce, difficulty, startCounter, maxAttempts, backend)`.
- `summarizeRuns(runs)` and `decideBackend(summaries)` are pure exported test functions.

- [ ] **Step 1: Add pure continuation, heartbeat, and decision tests**

Test the frozen five-field result states. On found, require `nextCounter === null`, independently verify digest, then derive `counter + 1` only below `Number.MAX_SAFE_INTEGER`; maximum success fails without constructing a successor. Test contiguous no-overlap/no-skip accounting across resumable calls.

Heartbeat tests simulate one delayed callback covering multiple deadlines and require each 5ms deadline exactly once, strict increase, none after end, minimum sample count `floor(elapsed/5)-2`, and drain not changing elapsed time.

Decision tests require JS unless Subtle median is at least `1.25 * JS`, Subtle wins at least five pairs, and every run passes correctness/responsiveness. Backend failure makes Phase 4C incomplete; it is never an automatic JS vote.

```sh
node --test tests/browser/benchmark.test.mjs
```

Expected: FAIL because the benchmark math and driver are absent.

- [ ] **Step 2: Build the inert benchmark page from production bytes**

Use static HTTPS NGINX with exact generated script bytes and CSP hash,
parameter block exactly `{}`, and no PowGate module. Keep benchmark-only
orchestration in `benchmark-driver.js`; execute those exact checked-in bytes
through CDP only after the production controller reaches its terminal state,
and include them in `benchmark_implementation_sha256`. The driver calls the
public solver and contains no SHA-256 or proof implementation.

Before measurement require terminal UI, frozen namespace with exactly
`sha256`/`solve`, both backend KATs, and a 1000ms quiet window with no
additional navigation, cookie mutation, solver call, DOM mutation,
animation-frame-driven mutation, console event, or network request. Do not
infer absence of all internal timers and do not replace scheduling primitives.

- [ ] **Step 3: Implement the fixed 14-run workload**

Use nonce `c382cd45c32e81f6f5bdcc5fb29497876a3d4364b688245668ab1b578ff7184f`, difficulty 32, counter zero, two-second discarded warm-up, seven paired repetitions per backend, ten-second stop-start deadline, one Chromium process, and fresh context/page per repetition. Pair order is `js/subtle`, `subtle/js`, alternating through pair seven.

Calibrate only `maxAttempts`, separately per repetition, from `1..262144`, targeting about 10ms and never zero. Yield between unchanged calls. A call started before the ten-second deadline finishes; heartbeat and recorded elapsed end after it. Continue after a verified success with a new unchanged call at derived successor.

- [ ] **Step 4: Record per-run responsiveness without provider interception**

Measure 5ms heartbeat delays over the whole interval. Each run independently requires p95 <=25ms, max <=100ms, complete samples, foreground `document.hidden === false`, and for JS no synchronous call above 25ms.

For Subtle record synchronous call-entry duration, awaited invocation duration, and derived asynchronous remainder. Label the remainder as provider wait plus Promise scheduling/result processing; never claim pure provider duration and never wrap `crypto.subtle.digest()`.

- [ ] **Step 5: Construct, validate, and atomically write evidence**

Record source/image/environment/workload identity, raw bounded samples, derived summaries, and fixed decision. `benchmark_implementation_sha256` hashes a length-prefixed ordered encoding of `benchmark.mjs` plus separately emitted driver bytes. `generated_at_utc` is provenance only; all timing is `performance.now()`.

On success write `build/benchmark-browser-result.json`; on any correctness, responsiveness, environment, cleanup, schema, or relationship failure leave no result. Failed diagnostics retain only run/backend, scalar verdicts, and at most 32 allowlisted samples per series.

- [ ] **Step 6: Run the unpromoted benchmark and commit**

```sh
node --test tests/browser/benchmark.test.mjs tests/browser/evidence.test.mjs
tools/run-browser-x86.sh benchmark-browser
```

Expected: fourteen valid runs, schema-valid generated evidence, and a printed fixed decision/rationale; throughput values do not independently determine exit status.

```sh
git add Makefile tests/browser/benchmark.mjs tests/browser/benchmark-driver.js \
  tests/browser/benchmark.test.mjs
git commit -m "test: add reproducible browser backend benchmark"
```

---

### Task 11: Apply the Mechanical Backend-Order Decision

**Files:**
- Modify conditionally: `html/challenge.html`
- Modify conditionally: generated page artifacts through `make challenge-page`
- Modify conditionally: `tests/e2e/controller.test.mjs`
- No protocol files.

**Interfaces:**
- Consumes the complete unpromoted evidence from Task 10.
- Produces a fixed controller candidate order that exactly matches the mechanical decision; no other production behavior changes.

- [ ] **Step 1: Independently recompute the decision**

Run:

```sh
node tools/promote-phase4c-evidence.mjs --validate-only build/benchmark-browser-result.json
node -e 'const e=require("./build/benchmark-browser-result.json"); console.log(e.decision)'
```

Require both backends correct/responsive. If either fails, stop: retain the provisional order, do not promote, and do not mark Phase 4C complete.

- [ ] **Step 2: Keep JS or change only candidate order**

If Subtle median is below `1.25 * JS` or it wins fewer than five matched pairs, make no production edit. If and only if it qualifies, change only the private controller candidate list from:

```js
const backendOrder = Object.freeze(['js', 'subtle']);
```

to:

```js
const backendOrder = Object.freeze(['subtle', 'js']);
```

Keep KAT bytes/digest, fallback conditions, public API, kernels, buffers, provider behavior, slices, and no-mid-search rule unchanged. Update controller tests to assert the fixed initialization/KAT order and one pre-search fallback.

- [ ] **Step 3: Regenerate and verify byte-derived artifacts**

```sh
make challenge-page
make test-js
make test-tools
```

Expected: exact served/generated/script/CSP identity and assembled maximum body `<15360` pass.

- [ ] **Step 4: Commit only if the order changed**

```sh
git add html/challenge.html tests/e2e/controller.test.mjs
git commit -m "feat: select measured browser backend order"
```

If JS remains selected, record no empty commit. Each later canonical session is evaluated independently; never pool, average, cherry-pick, or vote across sessions.

---

### Task 12: Complete Aggregate Gates and Operational Documentation

**Files:**
- Modify: `Makefile`
- Modify: `PLAN.md`
- Modify: `docs/security.md`
- Modify: `docs/configuration.md`
- Modify: `AGENTS.md`
- Modify: `docs/benchmarks/phase4c-v1/README.md`

**Interfaces:**
- `make check-browser-x86` runs feasibility, E2E, benchmark sequentially.
- `make test-browser-unit` runs every architecture-neutral browser-tooling
  unit test without launching Chromium.
- `make check-phase4c-evidence` validates committed evidence and evidence-only diff scope without launching Chromium.

- [ ] **Step 1: Add final Make dependencies and lightweight evidence gate**

Ensure architecture/identity checks occur before any resource or prerequisite launches Chromium/NGINX. `check-browser-x86` uses sequential recursive Make joined by `&&`, never parallel prerequisites or the host wrapper.

Define `test-browser-unit` to build the scanner utility and run
`fixture.test.mjs`, `request-observation.test.mjs`, `e2e.test.mjs`,
`sanitizer.test.mjs`, `evidence.test.mjs`, and `benchmark.test.mjs` with the
Node test runner. Add it to architecture-neutral `make check`; none of these
unit tests may launch Chromium or depend on x86 throughput.

Add `check-phase4c-evidence` to run policy, schema, relational, source/evidence identity, and documentation-link checks. It must machine-check that an evidence-only commit changes only the canonical result/README expected paths before permitting omission of browser/fuzz/sanitizer reruns.

- [ ] **Step 2: Update honest operational documentation**

In `PLAN.md`, mark Phase 4C implemented only after all gates. In security/configuration docs, replace any remaining Node-only or browser-unverified statement with the exact native x86 boundary: one pinned Chromium environment, not broad browser/device compatibility.

Add only enduring `AGENTS.md` rules: browser targets use `tools/run-browser-x86.sh`; native x86 only; no sandbox weakening/remote browser; positive tests execute untouched production namespace; browser E2E remains in sanitizer policy. Do not add temporary implementation details or benchmark numbers.

- [ ] **Step 3: Verify protocol and artifact scope**

```sh
git diff 974f197..HEAD -- docs/protocol.md
test -z "$(find out -type f \( -name '*fault*' -o -name '*negative*' \) -print)"
node --test tests/e2e/solver.test.mjs tests/e2e/controller.test.mjs
```

Expected: no protocol diff, no forbidden `out/` artifact, solver API and body-size gates pass.

- [ ] **Step 4: Commit**

```sh
git add Makefile PLAN.md AGENTS.md docs/security.md docs/configuration.md \
  docs/benchmarks/phase4c-v1/README.md
git commit -m "docs: define Phase 4C browser release gate"
```

---

### Task 13: Run Final Gates, Canonical Benchmark, and Evidence Promotion

**Files:**
- Create after measurement: `docs/benchmarks/phase4c-v1/x86_64-debian-chromium-150.0.7871.100-1%7Edeb13u1.json`
- Modify after measurement: `docs/benchmarks/phase4c-v1/README.md`

**Interfaces:**
- Produces independently visible release-gate output for the final source commit.
- Produces one immutable canonical raw evidence file whose `tested_source.commit` names that final source commit and whose `evidence_commit` is `null`.

- [ ] **Step 1: Require a clean final source commit**

```sh
test -z "$(git status --porcelain)"
source_commit=$(git rev-parse HEAD)
```

Record `source_commit`; any source/test/tool repair after this point restarts all later steps.

- [ ] **Step 2: Run architecture-neutral project gates inside the image**

On `vagrant`, from the exact source checkout:

```sh
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie sh -eu -c 'make clean && make check'
```

Expected: independently visible success for policy, tools, unit, coverage, module, H1/H2 integration/E2E, fuzz smoke, ASan, and UBSan.

- [ ] **Step 3: Run the mandatory browser aggregate through the host wrapper**

```sh
tools/run-browser-x86.sh check-browser-x86
```

Expected: feasibility H1/H2 passes, normal/sanitized twenty-case E2E passes, and an unpromoted benchmark completes with valid evidence. This aggregate benchmark proves machinery only and is not authoritative for promotion.

- [ ] **Step 4: Run the long fuzz gate inside the image**

```sh
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie make test-fuzz-long
```

Expected: all three exact fuzzers run 600 seconds and pass.

- [ ] **Step 5: Run the standalone canonical benchmark**

Reconfirm clean tracked source, then:

```sh
tools/run-browser-x86.sh benchmark-browser
node tools/promote-phase4c-evidence.mjs --validate-only \
  build/benchmark-browser-result.json
```

Require `tested_source.commit === source_commit`, `promotable === true`, all verdicts pass, and the decision matches the implemented order. A disagreement is not promoted: apply only the permitted order change and restart Tasks 11–13.

- [ ] **Step 6: Promote as the final working-tree operation**

```sh
node tools/promote-phase4c-evidence.mjs build/benchmark-browser-result.json
git status --short
```

Expected: exactly the canonical JSON is new. The promotion tool never edits
the README because the atomic evidence copy is its final operation. Review
the raw run order, recomputed medians, responsiveness bounds, source/image
hashes, and fixed decision; then update the README's tested-source, result,
and selected-order lines as part of the evidence-only change.

- [ ] **Step 7: Commit evidence separately and run lightweight post-commit checks**

```sh
git add docs/benchmarks/phase4c-v1/
git commit -m "docs: record Phase 4C browser benchmark"
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie make check-phase4c-evidence
```

Expected: the evidence-only diff scope, schema, relational checks, source/evidence identity, policy, and documentation links pass. The canonical evidence names the tested source commit, not the later evidence-only commit.

- [ ] **Step 8: Record final scope evidence**

```sh
git diff 974f197..HEAD -- docs/protocol.md
test -z "$(find out -type f \( -name '*fault*' -o -name '*negative*' \) -print)"
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie python3 tools/golden-image-lock.py check
```

Expected: no protocol diff, no test-only release artifact, and a matching golden-image lock.
