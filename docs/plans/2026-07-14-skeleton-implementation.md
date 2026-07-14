# Module Skeleton Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to
> implement this plan task-by-task.

**Goal:** Deliver a loadable NGINX 1.30.3 dynamic-module skeleton whose
`pow on;` access handler passes requests through, with reproducible
container-only build, integration, and e2e checks.

**Architecture:** `config` declares one HTTP dynamic module. The module owns
only a location-level `pow on|off` flag and installs an access-phase handler
that always returns `NGX_DECLINED`; it neither parses request data nor creates
state. `make module` copies the checksum-verified source reference from
`NGX_SOURCE_DIR` to a disposable container build directory and produces the
loadable `.so` in `out/`.

**Tech Stack:** C99, NGINX 1.30.3 dynamic-module API, GNU make, Podman,
Test::Nginx, Node.js, Debian Trixie golden image.

## Scope decision

Phase 0 has no pure-core parser or crypto implementation. Do not create fake
unit tests, no-op fuzzers, or sanitizer runs merely to make target names
exist. In this phase, the real gates are `check-policy`, `module`,
`test-integration`, and `test-e2e`. Phase 1 adds the pure core, two useful
fuzzers, `test-unit`, `test-fuzz`, `test-fuzz-long`, `asan`, and then the
mandatory aggregate `check` target and its CI jobs.

Every command below runs through the golden image. From the repository root:

```sh
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie make <target>
```

### Task 1: Record the staged test contract

**Files:**
- Modify: `AGENTS.md`
- Modify: `PLAN.md`

**Step 1: Amend the build-command section in `AGENTS.md`.**

State that `make module`, `make check-policy`, `make test-integration`, and
`make test-e2e` are Phase 0 targets. State that the pure-core test targets
and `make check` are introduced in Phase 1; they must not be represented by
passing placeholders in Phase 0.

**Step 2: Amend Phase 0 tasks 3, 5, and 12 in `PLAN.md`.**

Keep the required target names as the final interface, but state their phase
of introduction. Replace the Phase 0 CI matrix with a build-image job that
runs the four real Phase 0 targets. Move the compiler/runtime matrix and
full aggregate gate to Phase 1.

**Step 3: Verify the documentation contract.**

Run:

```sh
rg -n 'Phase 0|Phase 1|test-fuzz|make check' AGENTS.md PLAN.md
```

Expected: no text says that Phase 0 runs placeholder fuzz, unit, sanitizer,
or aggregate checks.

**Step 4: Commit.**

```sh
git add AGENTS.md PLAN.md
git commit -m "docs: stage skeleton test gates"
```

### Task 2: Add the test-first build and fixture skeleton

**Files:**
- Create: `config`
- Create: `Makefile`
- Create: `src/pow_protocol.h`
- Create: `tests/integration/pow_module.t`
- Create: `tests/e2e/smoke.mjs`
- Create: `src/.gitkeep`
- Create: `html/.gitkeep`
- Create: `tests/unit/.gitkeep`
- Create: `tests/fuzz/.gitkeep`

**Step 1: Create the NGINX addon declaration.**

Use the modern `auto/module` form only:

```sh
ngx_module_type=HTTP
ngx_module_name=ngx_http_pow_module
ngx_module_srcs="$ngx_addon_dir/src/ngx_http_pow_module.c"

. auto/module
```

Do not add legacy `HTTP_MODULES` assignments or link external libraries in
this phase.

**Step 2: Create the protocol-constant header.**

Make it a C99 include guard and define, once, the frozen v1 values required
by later code: protocol version `1`; labels `"PGv1-chal"` and `"PGv1-cook"`
with length `9`; secret `32`; IP `16`; nonce `32`; digest `32`; auth payload
`10`; auth MAC `16`; auth-cookie cap `256`; proof-cookie cap `64`; auth
cookie name `"__pow"`; proof-cookie name `"__pow_p"`; challenge window `60`;
cookie TTL `3600`; difficulty range `1..32`; and proof-counter maximum
`9007199254740991ULL`. Use `POW_` names only and no NGINX header.

**Step 3: Write the integration test before the module exists.**

Use `Test::Nginx::Socket`. Its `--- main_config` loads the absolute module
artifact `/work/out/ngx_http_pow_module.so`; its server configuration enables
`pow on;` for a location that returns `200` with `backend\n`. Assert the
response status and body. Run:

```sh
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie make test-integration
```

Expected: FAIL because the addon source and module artifact do not yet exist.

**Step 4: Write the Node e2e test before the module exists.**

`tests/e2e/smoke.mjs` must start a real Node `http.createServer` backend,
write a temporary NGINX config with `load_module
/work/out/ngx_http_pow_module.so;`, `pow on;`, and `proxy_pass` to that
backend, then spawn `/usr/sbin/nginx` in foreground mode. Poll the frontend
until ready; request it with Node `fetch`; require status `200` and the exact
backend response. In `finally`, terminate nginx, close the backend, and
remove the temporary directory. It must fail rather than skip if the module
does not load or the backend is not reached.

Run:

```sh
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie make test-e2e
```

Expected: FAIL because the module artifact is absent.

**Step 5: Write the Phase 0 Makefile targets.**

`module` must require `$NGX_SOURCE_DIR/src/core/nginx.h`, create a disposable
directory under `/tmp`, copy the reference tree there, run:

```sh
./configure --with-compat --with-cc-opt='-D_FORTIFY_SOURCE=2 \
    -fstack-protector-strong' --add-dynamic-module=/work
make modules
```

and copy `objs/ngx_http_pow_module.so` to `out/ngx_http_pow_module.so`.
Always remove the temporary build directory; do not modify `NGX_SOURCE_DIR`.
`test-integration` and `test-e2e` depend on `module`, invoke `prove -v
tests/integration/pow_module.t` and `node tests/e2e/smoke.mjs` respectively,
and fail on any error. `check-policy` invokes `./tools/check-policy.sh`.

Do not define `test-unit`, `test-fuzz`, `test-fuzz-long`, `asan`, or `check`
until Phase 1 implements their real work.

**Step 6: Check the expected pre-module failures.**

Run the two commands from Steps 3 and 4 and record their non-zero exits. This
is the red state; do not treat an absent module as a skipped test.

**Step 7: Commit.**

```sh
git add config Makefile src/pow_protocol.h src/.gitkeep html/.gitkeep \
    tests
git commit -m "build: add skeleton test harness"
```

### Task 3: Implement the minimal module and make the tests green

**Files:**
- Create: `src/ngx_http_pow_module.c`
- Modify: `Makefile` only if the red-state output exposed a build-path error

**Step 1: Implement the exact module shape.**

Follow `docs/nginx-style.md` and the pinned
`$NGX_SOURCE_DIR/src/http/modules/ngx_http_access_module.c` precedent. Add:

- `ngx_http_pow_loc_conf_t` containing only `ngx_flag_t enable`;
- `pow` command with `NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF`
  and `NGX_CONF_FLAG`, `ngx_conf_set_flag_slot`, and
  `NGX_HTTP_LOC_CONF_OFFSET`;
- `create_loc_conf` allocating from `cf->pool` and setting `enable` to
  `NGX_CONF_UNSET`;
- `merge_loc_conf` using `ngx_conf_merge_value(conf->enable,
  prev->enable, 0)`;
- postconfiguration that gets `ngx_http_core_main_conf_t`, pushes one handler
  to `cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers`, checks the returned
  pointer for `NULL`, and assigns `ngx_http_pow_handler`;
- a handler that immediately returns `NGX_DECLINED`, including the required
  early decline for `r != r->main || r->internal`.

Use `NGX_MODULE_V1` / `NGX_MODULE_V1_PADDING`. No cookies, crypto, request
parsing, logging of request data, allocation from `r->pool`, or configuration
besides `pow` belongs in this task.

**Step 2: Build the dynamic module.**

Run:

```sh
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie make module
```

Expected: exit 0 and `out/ngx_http_pow_module.so` exists.

**Step 3: Run the previously failing integration test.**

Run the Task 2 integration command.

Expected: Test::Nginx reports success; NGINX loads the dynamic module and a
request through `pow on;` returns `backend\n`.

**Step 4: Run the previously failing e2e test.**

Run the Task 2 e2e command.

Expected: Node reports success only after its real backend receives the
proxied request.

**Step 5: Run the policy gate.**

```sh
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie make check-policy
```

Expected: `check-policy: OK`.

**Step 6: Commit.**

```sh
git add src/ngx_http_pow_module.c Makefile
git commit -m "feat: add nginx module skeleton"
```

### Task 4: Add the normative README

**Files:**
- Create: `README.md`

**Step 1: Write the scope statement.**

State that PowGate is one stateless proof-of-work gateway; it stores no
sessions, challenges, databases, or external state. State OpenSSL 3.x-only
support, native NGINX dynamic-module target, NGINX source/runtime versions,
and the Podman-only development rule.

**Step 2: Add the exact quickstart.**

Show the canonical image build and the three Phase 0 checks with the
`localhost/ngx-powgate-dev:trixie` tag. Do not present host `make` commands.

**Step 3: State v0.1 limitations.**

Document JavaScript requirement, search-engine friction, and that cookieless
non-idempotent requests receive 403 rather than transparent completion.

**Step 4: Verify links and image references.**

Run:

```sh
rg -n 'localhost/ngx-powgate-dev:trixie|OpenSSL 3|stateless|non-idempotent' README.md
```

Expected: every image reference includes the `localhost/` prefix.

**Step 5: Commit.**

```sh
git add README.md
git commit -m "docs: add project quickstart"
```

### Task 5: Defer CI until the full test surface exists

**Files:**
- Modify: `PLAN.md`

**Step 1: Record the deferral.**

State that the initial skeleton has no GitHub workflow. CI begins after Phase
1 when the real unit, fuzz, sanitizer, integration, and e2e targets exist.

**Step 2: Preserve the CI constraints for later.**

When introduced, CI builds `localhost/ngx-powgate-dev:trixie` from the
committed Containerfile and runs every project command in that image. It does
not install compilers, Perl modules, Node, or NGINX build dependencies in the
workflow.

**Step 3: Commit.**

```sh
git add PLAN.md
git commit -m "docs: defer ci setup"
```

### Task 6: Run the Phase 0 acceptance gate

**Files:**
- Verify only

**Step 1: Run all local Phase 0 checks from the repository root.**

```sh
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie make check-policy
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie make module
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie make test-integration
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie make test-e2e
```

Expected: all commands exit 0. The integration and e2e tests demonstrate that
the nginx.org 1.30.3 runtime loads the module and allows a real backend
response when `pow on;` is configured.

**Step 2: Verify repository hygiene.**

Run:

```sh
git diff --check HEAD~4..HEAD
git status --short
```

Expected: no whitespace errors and no tracked generated artifact under
`out/`, `.cache/`, or a NGINX build tree.

**Step 3: Record the Phase 0 completion commit.**

Use the existing narrowly scoped commits; do not combine the skeleton with
the later crypto/parser Phase 1 work.
