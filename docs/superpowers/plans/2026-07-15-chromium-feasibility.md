# Sandboxed Chromium Feasibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove that pinned Chromium runs sandboxed inside the canonical rootless AMD64 Podman image and correctly exercises a local HTTPS NGINX fixture.

**Architecture:** Extend the golden image with snapshot-pinned Chromium and lockfile-pinned Puppeteer Core. Add one narrow Node harness that owns an ephemeral NGINX/Chromium lifecycle and verifies HTTPS, JavaScript, CSP, secure cookies, reload, and process cleanup.

**Tech Stack:** Debian Trixie snapshot, rootless Podman, Chromium 150, Puppeteer Core 24, Node.js 20, nginx.org NGINX 1.30.3, OpenSSL.

## Global Constraints

- Execute builds and tests only inside `localhost/ngx-powgate-dev:trixie` on `ssh vagrant`.
- Use the required remote rootless-Podman environment exports and `--userns=keep-id`.
- Use eight build jobs on AMD64 where a build command accepts a job count.
- Keep Chromium sandboxing enabled; never use `--no-sandbox`, privileged mode, added capabilities, unconfined seccomp, host networking, or Docker.
- Pin `chromium` and `chromium-sandbox` to `150.0.7871.100-1~deb13u1`.
- Pin `puppeteer-core` to `24.43.1` through a committed npm lockfile.
- Do not change `docs/protocol.md`, production C, the challenge page, or Phase 4C backend policy.

---

### Task 1: Pin browser dependencies in the golden image

**Files:**
- Modify: `build/versions.env`
- Create: `build/browser/package.json`
- Create: `build/browser/package-lock.json`
- Modify: `Containerfile`
- Modify: `build/install-dev.sh`

**Interfaces:**
- Consumes: Debian snapshot `20260713T000000Z` and Node.js 20 from the current image.
- Produces: `/usr/bin/chromium`, `/usr/lib/chromium/chrome-sandbox`, and `/opt/ngx-powgate/browser/node_modules/puppeteer-core`.

- [ ] **Step 1: Add immutable dependency declarations**

Add to `build/versions.env`:

```sh
CHROMIUM_VERSION=150.0.7871.100-1~deb13u1
PUPPETEER_CORE_VERSION=24.43.1
```

Create `build/browser/package.json`:

```json
{
  "name": "ngx-powgate-browser-tests",
  "private": true,
  "version": "1.0.0",
  "dependencies": {
    "puppeteer-core": "24.43.1"
  }
}
```

- [ ] **Step 2: Generate the lockfile inside the current golden image**

Run on `vagrant`, with the worktree copied to a temporary remote checkout:

```sh
podman run --rm --userns=keep-id \
  -v "$PWD:/work:Z" -w /work/build/browser \
  localhost/ngx-powgate-dev:trixie \
  npm install --package-lock-only --ignore-scripts --no-audit --no-fund
```

Verify:

```sh
node -e 'const p=require("./build/browser/package-lock.json"); if (p.packages["node_modules/puppeteer-core"].version !== "24.43.1") process.exit(1)'
rg -n 'T5ScUMAsmhdNbgDR41AGESYeS6V9MSgetkSnVhhW\+gXvzC42VesKCn5ld87gAZDJ6vLHL9GkRvY9WtQWSnwFbw==' build/browser/package-lock.json
```

Expected: both commands exit zero and the lockfile contains integrity metadata for every registry package.

- [ ] **Step 3: Install the pinned inputs**

Copy `build/browser/package.json` and `package-lock.json` into the image before the install script. In `build/install-dev.sh`, add these exact apt arguments:

```sh
    chromium="${CHROMIUM_VERSION}" \
    chromium-sandbox="${CHROMIUM_VERSION}" \
```

After apt installation, install the controller without lifecycle scripts:

```sh
mkdir -p /opt/ngx-powgate/browser
cp /usr/local/share/ngx-powgate/browser/package.json \
    /usr/local/share/ngx-powgate/browser/package-lock.json \
    /opt/ngx-powgate/browser/
npm ci --prefix /opt/ngx-powgate/browser --ignore-scripts --omit=dev \
    --no-audit --no-fund
```

The Containerfile must copy `build/browser/` to
`/usr/local/share/ngx-powgate/browser/` before running the installer.

- [ ] **Step 4: Build and inspect the AMD64 image on vagrant**

Run:

```sh
podman build --jobs=8 --build-arg TARGETARCH=amd64 \
  --build-arg BASE_IMAGE="$(awk -F= '$1=="DEBIAN_IMAGE_AMD64" {print $2}' build/versions.env)" \
  -t localhost/ngx-powgate-dev:trixie -f Containerfile .
podman run --rm --userns=keep-id localhost/ngx-powgate-dev:trixie \
  sh -eu -c 'test "$(id -u)" -ne 0; chromium --version; node -e '\''const {createRequire}=require("node:module"); const r=createRequire("/opt/ngx-powgate/browser/package.json"); console.log(r("puppeteer-core/package.json").version)'\'''
```

Expected: non-root execution, Chromium 150 package output, and `24.43.1`.

- [ ] **Step 5: Commit the image change**

```sh
git add Containerfile build/versions.env build/install-dev.sh build/browser/package.json build/browser/package-lock.json
git commit -m "build: pin sandboxed chromium"
```

---

### Task 2: Add the HTTPS Chromium feasibility gate

**Files:**
- Create: `tests/browser/chromium-feasibility.mjs`
- Modify: `Makefile`

**Interfaces:**
- Consumes: `/usr/bin/chromium`, `/usr/sbin/nginx`, OpenSSL, and image-owned Puppeteer Core.
- Produces: `make test-browser-feasibility`, a single zero/nonzero feasibility verdict.

- [ ] **Step 1: Add the failing Make target**

Add `test-browser-feasibility` to `.PHONY` and define:

```make
test-browser-feasibility: check-test-env
	node tests/browser/chromium-feasibility.mjs
```

Run inside the rebuilt image:

```sh
make test-browser-feasibility
```

Expected: failure because the harness file does not exist.

- [ ] **Step 2: Implement the isolated fixture lifecycle**

Create `tests/browser/chromium-feasibility.mjs` using Node built-ins and image-owned Puppeteer Core. It must:

```js
const require = createRequire('/opt/ngx-powgate/browser/package.json');
const puppeteer = require('puppeteer-core');
```

Allocate one `mkdtemp()` prefix; reserve a loopback port; generate a one-day P-256 certificate; create NGINX temp directories; write a static fixture and NGINX configuration; start `/usr/sbin/nginx` with `daemon off`; and wait for HTTPS readiness with a bounded deadline. Every acquired resource is registered for cleanup immediately and released from a `finally` block.

- [ ] **Step 3: Implement the exact CSP/browser assertions**

The static page contains one allowed script whose exact bytes are hashed with Node SHA-256 and one unapproved inline script. Launch Chromium with:

```js
const browser = await puppeteer.launch({
    acceptInsecureCerts: true,
    executablePath: '/usr/bin/chromium',
    headless: true,
    args: ['--disable-dev-shm-usage'],
    env: browserEnvironment,
    userDataDir
});
```

Inspect `browser.process().spawnargs` and reject `--no-sandbox`,
`--disable-setuid-sandbox`, `--disable-seccomp-filter-sandbox`,
`--disable-namespace-sandbox`, and `--single-process`. Navigate to
`https://127.0.0.1:<port>/feasibility?probe=1`, then assert:

```js
{
    allowedRuns: 1,
    blockedRuns: 0,
    pathname: '/feasibility',
    search: '?probe=1',
    cookieVisible: true
}
```

Reload using `page.reload()`, assert `allowedRuns === 2`, unchanged path/query,
the blocked marker remains absent, and the exact `Secure; SameSite=Lax; Path=/`
cookie remains in the browser context.

- [ ] **Step 4: Enforce bounded process cleanup**

Close the page, context, and browser; wait for the browser PID; scan
`/proc/*/cmdline` for the unique user-data-directory marker; terminate and
reap NGINX; require its PID to disappear; remove the prefix. A remaining
process or prefix is a test failure. Error output names the operation only and
never dumps page content, cookies, keys, or raw browser exceptions.

- [ ] **Step 5: Run the focused gate twice**

Run on `vagrant`:

```sh
podman run --rm --userns=keep-id \
  -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  sh -eu -c 'make test-browser-feasibility && make test-browser-feasibility'
```

Expected: both runs pass, demonstrating clean teardown and repeatability.

- [ ] **Step 6: Commit the feasibility gate**

```sh
git add Makefile tests/browser/chromium-feasibility.mjs
git commit -m "test: add chromium feasibility gate"
```

---

### Task 3: Record independent vagrant evidence

**Files:**
- No production or protocol files.

**Interfaces:**
- Consumes: the two preceding commits and rebuilt AMD64 image.
- Produces: independently visible pass/fail evidence for the pre-Phase 4C decision.

- [ ] **Step 1: Run the focused evidence commands**

```sh
podman run --rm --userns=keep-id \
  -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  sh -eu -c 'chromium --version; node -e '\''const {createRequire}=require("node:module"); const r=createRequire("/opt/ngx-powgate/browser/package.json"); console.log(r("puppeteer-core/package.json").version)'\''; make test-browser-feasibility'
```

Expected: Chromium 150, Puppeteer Core `24.43.1`, and a passing gate without a sandbox-bypass flag.

- [ ] **Step 2: Run the project regression gate**

```sh
podman run --rm --userns=keep-id \
  -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  sh -eu -c 'make clean && make check'
```

Expected: all existing unit, integration, HTTP/1.1, HTTP/2, JS, fuzz-smoke, ASan, and UBSan gates pass.

- [ ] **Step 3: Verify scope boundaries**

```sh
git diff dc8af972ee497d80c2048146e91ff4d059743531 -- docs/protocol.md
test -z "$(find out -type f -name '*fault*' -print 2>/dev/null)"
git status --short
```

Expected: no protocol diff, no fault artifact under `out/`, and only intentional plan/spec files if they have not yet been committed.

