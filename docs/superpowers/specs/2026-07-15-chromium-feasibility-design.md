# Sandboxed Chromium Feasibility Gate Design

## Purpose

This pre-Phase 4C gate answers one question: can the canonical rootless Podman
environment run a pinned, sandboxed Chromium against a local HTTPS NGINX
fixture reliably enough to support Phase 4C?

It does not test PowGate solving, select a hashing backend, collect performance
evidence, or change the v1 protocol. A passing gate permits Phase 4C planning;
it does not complete any Phase 4C acceptance criterion.

## Baseline and execution host

The work depends on the x86 sanitizer portability fix at commit
`dc8af972ee497d80c2048146e91ff4d059743531`. Implementation begins from that
commit after PR #8 is merged or by branching directly from that commit without
changing PR #8.

Execution uses the `vagrant` SSH target and its rootless Podman installation:

```sh
export PATH="$HOME/.local/podman/bin:$PATH"
export PATH="$HOME/.local/podman/lib/podman:$PATH"
export LD_LIBRARY_PATH="$HOME/.local/podman/lib:${LD_LIBRARY_PATH:-}"
export CONTAINERS_NO_SYSTEMD=1
```

The test runs inside `localhost/ngx-powgate-dev:trixie` with
`--userns=keep-id`. It uses Podman's default seccomp, namespaces, capabilities,
and rootless confinement. It must not use `--privileged`, `--cap-add`,
`--security-opt seccomp=unconfined`, host networking, or a Docker fallback.

## Pinned browser inputs

The existing Debian snapshot is
`20260713T000000Z`. Its AMD64 candidate versions are:

- `chromium=150.0.7871.100-1~deb13u1`;
- `chromium-sandbox=150.0.7871.100-1~deb13u1`.

Both packages are installed explicitly through `build/install-dev.sh` so the
`--no-install-recommends` policy cannot omit the sandbox helper. The exact
version is recorded once in `build/versions.env` and applied to both package
names. The fixed Debian snapshot and apt repository metadata authenticate the
package bytes and dependencies.

The image's Debian Node.js is `20.19.2`. Puppeteer Core 25 is excluded because
it requires Node.js `>=22.12.0`. The browser controller is exactly:

- `puppeteer-core=24.43.1`;
- npm integrity
  `sha512-T5ScUMAsmhdNbgDR41AGESYeS6V9MSgetkSnVhhW+gXvzC42VesKCn5ld87gAZDJ6vLHL9GkRvY9WtQWSnwFbw==`.

A committed `package.json` and `package-lock.json` under `build/browser/` pin
the complete transitive dependency graph and every npm integrity value. The
golden image runs `npm ci --ignore-scripts --omit=dev` into
`/opt/ngx-powgate/browser`; Puppeteer never downloads a browser. Test code
loads that exact installation through `node:module.createRequire()` rooted at
`/opt/ngx-powgate/browser/package.json`.

No package is installed on either host. Missing or changed dependencies are
resolved only by updating the committed image inputs and rebuilding
`localhost/ngx-powgate-dev:trixie`.

## Feasibility harness

`tests/browser/chromium-feasibility.mjs` is a narrow executable harness, not a
general browser framework. `make test-browser-feasibility` runs it. The target
is intentionally separate from `make check` until the feasibility decision is
accepted and Phase 4C owns the permanent browser matrix.

The harness creates one private temporary prefix containing:

- a P-256 self-signed certificate and key generated with the existing test
  convention;
- a minimal NGINX configuration and static HTML fixture;
- NGINX logs and PID;
- a writable Chromium home and user-data directory;
- a unique process marker used for cleanup assertions.

It launches the installed nginx.org NGINX binary directly and waits with a
bounded deadline for the HTTPS listener. It then launches:

```js
puppeteer.launch({
    executablePath: '/usr/bin/chromium',
    headless: true,
    args: ['--disable-dev-shm-usage'],
    env: browserEnvironment,
    userDataDir
});
```

Puppeteer's own required headless/automation arguments are allowed. Before any
navigation, the harness examines the effective Chromium spawn arguments and
fails if they contain `--no-sandbox`, `--disable-setuid-sandbox`,
`--disable-seccomp-filter-sandbox`, `--disable-namespace-sandbox`, or
`--single-process`. No project-supplied argument may disable or weaken a
Chromium sandbox layer. Successful launch without those flags is the
feasibility proof for Chromium's default sandbox under the existing rootless
Podman configuration. A sandbox launch failure is terminal; the harness must
not retry with weaker confinement.

Certificate verification is disabled only for this isolated browser context.
There is no production TLS bypass and no machine-wide test CA.

## HTTPS, JavaScript, CSP, cookie, and reload assertions

The NGINX fixture serves one UTF-8 page over
`https://127.0.0.1:<ephemeral-port>/feasibility?probe=1`. The response includes
a restrictive CSP with one exact SHA-256 inline-script hash. It has no external
resources or network calls.

The allowed inline script:

1. increments a visible execution counter;
2. records the current pathname and query;
3. sets a host-only `Secure; SameSite=Lax; Path=/` feasibility cookie;
4. records whether that cookie is visible.

A second inline script without the approved hash attempts to set a distinct
marker. The harness asserts that the approved script ran and the unapproved
marker is absent, proving CSP enforcement rather than merely checking the
header text.

The harness then reloads through Puppeteer without assigning or reconstructing
the URL. After reload it asserts:

- the same pathname and query are present;
- the execution counter reflects a second load;
- the secure cookie remains visible and has the expected exact value;
- the CSP-blocked marker remains absent;
- the page remains reachable over HTTPS.

## Lifecycle and failure handling

Every external operation has a bounded timeout. Initialization follows
allocate/start/validate/commit discipline: the harness retains ownership of
each resource as soon as it is created and cleans up in a `finally` block.

Cleanup order is:

1. close the page;
2. close the browser context;
3. close the browser;
4. wait for Chromium's recorded browser PID to disappear;
5. scan `/proc/*/cmdline` for the unique user-data-directory marker and require
   zero remaining matches;
6. terminate and reap NGINX;
7. require the NGINX process group to be gone;
8. remove the private prefix.

Failure output identifies only the failed operation and bounded process status.
It does not print certificate key bytes, cookies, page contents, arbitrary
browser exception text, request headers, or Chromium profile contents.

The gate fails on any of these conditions:

- Chromium cannot launch with its default sandbox;
- the executable is not exactly `/usr/bin/chromium`;
- a forbidden sandbox flag is present;
- the browser cannot reach the self-signed HTTPS NGINX fixture;
- JavaScript does not run;
- CSP does not block the unapproved script;
- the secure cookie cannot be written, read, or retained across reload;
- reload changes the path or query;
- any Chromium or NGINX process remains;
- cleanup cannot remove the isolated prefix.

No failure is converted into a skip, warning, weaker launch, HTTP fallback, or
Docker fallback.

## Acceptance and Phase 4C handoff

The feasibility decision is positive only when all of the following are
independently visible on `vagrant`:

1. the rebuilt AMD64 image is tagged exactly
   `localhost/ngx-powgate-dev:trixie`;
2. `chromium --version` reports the pinned package version;
3. Puppeteer Core reports `24.43.1` from the image-owned installation;
4. the container runs as the non-root `vagrant` identity through
   `--userns=keep-id`;
5. `make test-browser-feasibility` exits zero under default Podman security;
6. all HTTPS, JavaScript, CSP, cookie, reload, and cleanup assertions execute;
7. `make clean && make check` remains green in the rebuilt image;
8. no fault-named artifact exists under `out/`;
9. `docs/protocol.md` has no diff.

If the sandboxed launch fails, work stops at this gate. Phase 4C must not adopt
`--no-sandbox`, privileged containers, GUI/VNC Chromium images, or remote-CDP
workarounds merely to obtain a passing result. The failure evidence instead
drives a separate environment decision.

If it passes, Phase 4C may reuse the pinned image inputs and narrow lifecycle
patterns while replacing the static feasibility page with the real PowGate
challenge/auth/backend loop. Backend benchmarking, fixed backend ordering,
browser measurements, and release evidence remain Phase 4C responsibilities.
