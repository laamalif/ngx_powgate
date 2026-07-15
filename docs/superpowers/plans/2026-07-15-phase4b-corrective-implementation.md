# Phase 4B Corrective Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the allocation-heavy browser mining path with a shared-compression, single-block JavaScript kernel and make proof-cookie cleanup accept valid URL paths without weakening the first-proof-occurrence safety rule.

**Architecture:** `html/challenge.html` remains the sole production source. Its public general SHA-256 function and private fixed-shape proof kernel share one compression primitive; the JavaScript and SubtleCrypto proof paths share one direct decimal encoder but retain invocation-local storage. The controller skips only unsafe derived cookie paths, then still fails closed if any exact proof cookie remains visible.

**Tech Stack:** Inline browser JavaScript, Node built-in test runner and `node:vm`, Node `crypto`, Python generator tests, NGINX 1.30.3 HTTPS integration, Podman with `localhost/ngx-powgate-dev:trixie`.

## Global Constraints

- Read [the corrective design](../specs/2026-07-15-phase4b-corrective-design.md) and [the original Phase 4B design](../specs/2026-07-15-phase4b-browser-solver-design.md) before editing.
- Run every build and test inside `localhost/ngx-powgate-dev:trixie`; the host may invoke Podman and inspect files only.
- Keep `html/challenge.html` as the only solver/controller source. Add no npm package, generated JavaScript, external resource, Worker, WASM, test branch, or production fault hook.
- Keep `globalThis.PowGateSolver` frozen with exactly `sha256` and `solve`; keep the exact five-field result and always-Promise `solve()` contract.
- Keep pure JavaScript primary and sequential SubtleCrypto as the single pre-search fallback. Never migrate backends after mining begins.
- Hash exactly `nonce_raw(32) || counter_ascii`; do not change any challenge, proof-cookie, server-verification, header, or CSP wire contract.
- Do not modify `docs/protocol.md`, C sources, NGINX APIs, fuzz target code,
  fuzz corpus seeds, or protocol vectors; these JavaScript-only corrections
  introduce no C parser or wire-format input.
- Keep the maximum assembled response strictly below `15360` bytes. Measure generated prefix + maximum canonical JSON + suffix, not the template alone.
- Add no Node performance threshold. Phase 4C owns real-browser measurement and any resulting backend-order decision.
- Use test-driven development: make each named regression fail for the intended reason before changing production script bytes.

## File Map

- Modify `html/challenge.html`: shared compression, decimal encoding, both proof backends, specialized KAT, and safe cleanup candidates.
- Modify `tests/e2e/solver.test.mjs`: independent digest fixtures, typed-array instrumentation, decimal boundaries, safe exhaustion, nonce isolation, and backend agreement.
- Modify `tests/e2e/controller.test.mjs`: KAT fallback transaction and pathname/cookie matrices.
- Modify `tests/e2e/lib/challenge-script.mjs`: only narrow VM/harness support needed by unchanged-production-script tests.
- Modify `docs/superpowers/specs/2026-07-15-phase4b-browser-solver-design.md`: point allocation and pathname details to the corrective design.
- Modify `PLAN.md`: record the corrected 4B kernel/cleanup contract and bounded 4C measurement handoff.
- Modify `docs/security.md` and `docs/configuration.md`: document candidate-bounded cleanup and fail-closed visible duplicates.
- Do not modify `tools/build_pow_challenge.py`, `src/pow_protocol.h`, or `docs/protocol.md`; existing generator/runtime checks remain authoritative.

---

### Task 1: Shared Compression and Specialized JavaScript Kernel

**Files:**
- Modify: `tests/e2e/solver.test.mjs`
- Modify: `html/challenge.html:25-265`

**Interfaces:**
- Produces private `compressBlock(state, block, words) -> undefined`.
- Produces private `resetState(state) -> undefined`.
- Produces private `stateDigest(state) -> Uint8Array(32)` for general SHA and
  the one startup KAT, never the mining loop.
- Produces private `encodeCounter(counter, digits) -> startOffset`.
- Produces private `proofDigestJs(counter, block, words, state, digits) -> undefined`; it performs no validation, requires a safe counter already admitted by `solve()`, requires exact 64-byte block, 64-word schedule, eight-word state, and 16-byte digit arrays, requires the block to contain the 32-byte nonce already, and leaves the digest in `state`.
- Keeps public `sha256(bytes) -> Uint8Array(32)` and `solve(...) -> Promise<frozen result>` unchanged.
- The accepted initial workspace allocation multiset is `Uint8Array` lengths `32`, `64`, `16` and `Uint32Array` lengths `64`, `8`, independent of attempted candidates. Order is not contractual.

- [ ] **Step 1: Add independent fixtures and constructor instrumentation**

Add these test helpers near `expectedDigest()` in `tests/e2e/solver.test.mjs`:

```js
function countedTypedArray(Base, name, records) {
    return class extends Base {
        constructor(...args) {
            super(...args);
            records.push({ name, length: this.length });
        }
    };
}


function allocationMultiset(records) {
    return records.map(({ name, length }) => `${name}:${length}`).sort();
}


function assertNoDifficulty32Winner(nonce, startCounter, attempts) {
    for (let offset = 0; offset < attempts; offset++) {
        const counter = Buffer.from(String(startCounter + offset), 'ascii');
        const digest = expectedDigest(Buffer.concat([nonce, counter]));

        assert.notEqual(digest.readUInt32BE(0), 0,
            `independent fixture unexpectedly wins at ${startCounter + offset}`);
    }
}
```

Use `node:crypto.createHash()` through the existing `expectedDigest()` helper. Do not derive the no-winner fixture with `PowGateSolver.sha256()`.

- [ ] **Step 2: Add specialized-kernel result, allocation, and isolation tests**

Add three tests. The predicate-boundary test uses the checked-in KAT nonce and
exact counter `34`; it deliberately does not claim to inspect the full digest,
which the exact controller KAT proves in Task 3:

```js
test('specialized JS proof path has the KAT difficulty boundary',
    async () => {
        const vector = JSON.parse(await fs.readFile(
            path.join(root, 'tests', 'vectors', 'v1.json'), 'utf8'));
        const nonce = new Uint8Array(Buffer.from(
            vector.cases[0].nonce_hex, 'hex'));
        const solver = await loadSolver();

        for (const difficulty of [8, 10]) {
            assert.deepEqual(resultValues(await solver.solve(
                nonce, difficulty, 34, 1, 'js')), {
                found: true,
                exhausted: false,
                counter: 34,
                nextCounter: null,
                attempts: 1
            });
        }

        assert.deepEqual(resultValues(await solver.solve(
            nonce, 11, 34, 1, 'js')), {
            found: false,
            exhausted: false,
            counter: null,
            nextCounter: 35,
            attempts: 1
        });
    });
```

For allocation structure, evaluate the exact script with subclasses, create the nonce with the injected constructor so validation remains exact, and compare deltas around calls:

```js
test('JS typed-array allocation is constant per bounded solve', async () => {
    const records = [];
    const Uint8 = countedTypedArray(Uint8Array, 'u8', records);
    const Uint32 = countedTypedArray(Uint32Array, 'u32', records);
    const script = await readChallengeScript();
    const context = evaluateChallengeScript(script, {
        Uint8Array: Uint8,
        Uint32Array: Uint32
    });
    const nonce = new Uint8(32);

    assertNoDifficulty32Winner(Buffer.alloc(32), 0, 1000);

    const deltas = [];
    for (const maxAttempts of [1, 10, 1000]) {
        const before = records.length;
        const result = await context.PowGateSolver.solve(
            nonce, 32, 0, maxAttempts, 'js');

        assert.equal(result.found, false);
        assert.equal(result.attempts, maxAttempts);
        const delta = records.slice(before);
        assert.deepEqual(delta[0], { name: 'u8', length: 32 });
        deltas.push(allocationMultiset(delta));
    }

    /* This is the accepted implementation layout, not a public API. */
    assert.deepEqual(deltas[0], [
        'u32:64', 'u32:8', 'u8:16', 'u8:32', 'u8:64'
    ]);
    assert.deepEqual(deltas[1], deltas[0]);
    assert.deepEqual(deltas[2], deltas[0]);
});
```

The first per-call record proves that the defensive nonce snapshot is created
before the JS workspace. The exact five-allocation multiset is an assertion
for the accepted implementation only. A later internal refactor may change it
if it updates this test while preserving positive fixed per-call allocation,
attempt-count independence, invocation isolation, and the body budget.

Also extend the existing generator-byte test immediately, so every subsequent
`make test-js` enforces the page budget:

```js
const constants = await readProtocolConstants();
const maximumJson = Buffer.from(
    '<script type="application/json" id="pow-params">'
    + '{"v":1,"d":32,"b":"99999999999999999999",'
    + '"n":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}'
    + '</script>',
    'ascii'
);
assert.ok(artifacts.prefix.length + maximumJson.length
    + artifacts.suffix.length < constants.pageMaxBodyLen);
```

Add an invocation-isolation regression using different nonces and starting counters. Compare `Promise.all()` results with independently executed sequential calls; document in the test name that synchronous JS calls do not interleave:

```js
test('separate JS solve calls own separate workspaces', async () => {
    const solver = await loadSolver();
    const nonceA = new Uint8Array(32);
    const nonceB = new Uint8Array(32).fill(0xa5);
    const expectedA = resultValues(await solver.solve(nonceA, 32, 3, 7, 'js'));
    const expectedB = resultValues(await solver.solve(nonceB, 32, 19, 5, 'js'));
    const [actualA, actualB] = await Promise.all([
        solver.solve(nonceA, 32, 3, 7, 'js'),
        solver.solve(nonceB, 32, 19, 5, 'js')
    ]);

    assert.deepEqual(resultValues(actualA), expectedA);
    assert.deepEqual(resultValues(actualB), expectedB);
});
```

Extend `sha256 matches fixed messages and padding boundaries` to keep the
explicit `55`, `56`, `63`, `64`, and `65` byte rows plus multi-block binary
input. After obtaining two equal but distinct digest arrays, mutate the first
and assert the second and a newly computed third digest still equal the Node
`createHash()` result:

```js
first[0] ^= 0xff;
assert.deepEqual(Buffer.from(second), expectedDigest(bytes));
assert.deepEqual(Buffer.from(solver.sha256(bytes)), expectedDigest(bytes));
```

- [ ] **Step 3: Run the new tests and verify the allocation regression fails**

Run:

```bash
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  node --test --test-name-pattern='specialized JS|typed-array allocation|separate JS' \
  tests/e2e/solver.test.mjs
```

Expected: the KAT/result and isolation rows may pass through the general hash path, but `JS typed-array allocation is constant per bounded solve` fails because the recorded allocation count grows with `maxAttempts`.

- [ ] **Step 4: Extract one compression primitive and keep general SHA behavior**

In `html/challenge.html`, keep the existing `round` table and replace the duplicated state setup/compression body with the following private structure. The 64 rounds are the existing expressions moved verbatim into `compressBlock()`:

```js
const initial = Object.freeze([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);

function resetState(state) {
    for (let index = 0; index < 8; index++) {
        state[index] = initial[index];
    }
}

function compressBlock(state, block, words) {
    for (let index = 0; index < 16; index++) {
        const at = index * 4;
        words[index] = (block[at] << 24) | (block[at + 1] << 16)
            | (block[at + 2] << 8) | block[at + 3];
    }
    for (let index = 16; index < 64; index++) {
        const x = words[index - 15];
        const y = words[index - 2];
        const s0 = rotate(x, 7) ^ rotate(x, 18) ^ (x >>> 3);
        const s1 = rotate(y, 17) ^ rotate(y, 19) ^ (y >>> 10);
        words[index] = (words[index - 16] + s0 + words[index - 7] + s1)
            >>> 0;
    }

    let a = state[0];
    let b = state[1];
    let c = state[2];
    let d = state[3];
    let e = state[4];
    let f = state[5];
    let g = state[6];
    let h = state[7];

    for (let index = 0; index < 64; index++) {
        const sum1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
        const choose = (e & f) ^ (~e & g);
        const first = (h + sum1 + choose + round[index] + words[index]) >>> 0;
        const sum0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
        const majority = (a & b) ^ (a & c) ^ (b & c);
        const second = (sum0 + majority) >>> 0;

        h = g;
        g = f;
        f = e;
        e = (d + first) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (first + second) >>> 0;
    }

    state[0] = (state[0] + a) >>> 0;
    state[1] = (state[1] + b) >>> 0;
    state[2] = (state[2] + c) >>> 0;
    state[3] = (state[3] + d) >>> 0;
    state[4] = (state[4] + e) >>> 0;
    state[5] = (state[5] + f) >>> 0;
    state[6] = (state[6] + g) >>> 0;
    state[7] = (state[7] + h) >>> 0;
}
```

Use one serializer and refactor general SHA completely:

```js
function stateDigest(state) {
    const digest = new Uint8Array(32);
    for (let index = 0; index < 8; index++) {
        const at = index * 4;
        digest[at] = state[index] >>> 24;
        digest[at + 1] = state[index] >>> 16;
        digest[at + 2] = state[index] >>> 8;
        digest[at + 3] = state[index];
    }
    return digest;
}

function sha256(bytes) {
    if (!(bytes instanceof Uint8Array)) {
        throw new TypeError();
    }

    const paddedLength = Math.ceil((bytes.length + 9) / 64) * 64;
    const padded = new Uint8Array(paddedLength);
    const words = new Uint32Array(64);
    const state = new Uint32Array(8);
    const bitLength = bytes.length * 8;
    const high = Math.floor(bitLength / 0x100000000);
    const low = bitLength >>> 0;
    const end = padded.length;

    padded.set(bytes);
    padded[bytes.length] = 0x80;
    padded[end - 8] = high >>> 24;
    padded[end - 7] = high >>> 16;
    padded[end - 6] = high >>> 8;
    padded[end - 5] = high;
    padded[end - 4] = low >>> 24;
    padded[end - 3] = low >>> 16;
    padded[end - 2] = low >>> 8;
    padded[end - 1] = low;

    resetState(state);
    for (let offset = 0; offset < end; offset += 64) {
        compressBlock(state, padded.subarray(offset, offset + 64), words);
    }
    return stateDigest(state);
}
```

Do not change public validation, input non-mutation, arbitrary-length support,
or fresh-output behavior.

- [ ] **Step 5: Add proof preparation with no explicit per-candidate allocation**

Add the direct encoder and single-block preparation. `encodeCounter()` returns a number, not an object:

```js
function encodeCounter(counter, digits) {
    let start = digits.length;
    let value = counter;

    do {
        const quotient = Math.floor(value / 10);
        digits[--start] = 0x30 + value - quotient * 10;
        value = quotient;
    } while (value !== 0);

    return start;
}

function proofDigestJs(counter, block, words, state, digits) {
    block.fill(0, 32);
    const start = encodeCounter(counter, digits);
    const count = digits.length - start;

    for (let index = 0; index < count; index++) {
        block[32 + index] = digits[start + index];
    }
    block[32 + count] = 0x80;
    const bitLength = (32 + count) * 8;
    block[62] = bitLength >>> 8;
    block[63] = bitLength;

    resetState(state);
    compressBlock(state, block, words);
}

function meetsState(state, difficulty) {
    return difficulty === 32
        ? state[0] === 0
        : (state[0] >>> (32 - difficulty)) === 0;
}
```

The fixed proof message is at most 48 bytes, or 384 bits. `block.fill(0, 32)`
therefore leaves length bytes 56 through 61 explicitly zero; only bytes 62
and 63 need the nonzero low 16 bits. Do not add validation or shape checks to
`proofDigestJs()` or `compressBlock()`.

Replace `solveJs()` with one workspace per call:

```js
function solveJs(nonce, difficulty, startCounter, maxAttempts) {
    const block = new Uint8Array(64);
    const words = new Uint32Array(64);
    const state = new Uint32Array(8);
    const digits = new Uint8Array(16);
    let attempts = 0;
    let candidate = startCounter;

    block.set(nonce);
    for (;;) {
        proofDigestJs(candidate, block, words, state, digits);
        attempts++;

        if (meetsState(state, difficulty)) {
            return solveResult(true, false, candidate, null, attempts);
        }
        if (candidate === Number.MAX_SAFE_INTEGER) {
            return solveResult(false, true, null, null, attempts);
        }
        candidate++;
        if (attempts === maxAttempts) {
            return solveResult(false, false, null, candidate, attempts);
        }
    }
}
```

Remove `String(counter)` and `proofMessage()` from the JavaScript mining path.
Keep `proofMessage()` temporarily only for the existing Subtle and startup-KAT
callers; Task 2 removes the Subtle reference and Task 3 removes the final KAT
reference. Do not create a digest array in `solveJs()`.

- [ ] **Step 6: Run the complete solver table**

Run:

```bash
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  node --test tests/e2e/solver.test.mjs
```

Expected: all solver tests pass, including general SHA padding/multi-block
vectors, canonical counter `34`, difficulty 8/10/11, safe exhaustion, constant
allocation, invocation isolation, and maximum assembled-body size.

- [ ] **Step 7: Commit the JavaScript kernel**

```bash
git add html/challenge.html tests/e2e/solver.test.mjs
git commit -m "feat: specialize browser proof hashing"
```

---

### Task 2: Canonical Sequential SubtleCrypto Preparation

**Files:**
- Modify: `tests/e2e/solver.test.mjs`
- Modify: `html/challenge.html:180-275`

**Interfaces:**
- Consumes private `encodeCounter(counter, digits) -> startOffset` from Task 1.
- Keeps `solveSubtle()` sequential with one awaited provider call per candidate.
- Uses one 48-byte invocation-local backing message buffer and one 16-byte decimal scratch.
- Passes a provider view whose byte range is exactly the 32-byte nonce followed by the current canonical counter.

- [ ] **Step 1: Add a provider capture that records exact views and backing storage**

Add this helper to `tests/e2e/solver.test.mjs`:

```js
function capturingCrypto(byte, records, gate = null) {
    let active = 0;
    let maximumActive = 0;

    return {
        get maximumActive() {
            return maximumActive;
        },
        subtle: {
            async digest(algorithm, view) {
                assert.equal(algorithm, 'SHA-256');
                active++;
                try {
                    maximumActive = Math.max(maximumActive, active);
                    const record = {
                        backing: view.buffer,
                        byteLength: view.byteLength,
                        byteOffset: view.byteOffset,
                        bytes: Buffer.from(view),
                        bytesAfterWait: null
                    };
                    records.push(record);
                    if (gate != null) {
                        await gate();
                    }
                    record.bytesAfterWait = Buffer.from(view);
                    return new Uint8Array(32).fill(byte).buffer;
                } finally {
                    active--;
                }
            }
        }
    };
}


function recordingWebcrypto(records) {
    return {
        subtle: {
            async digest(algorithm, view) {
                records.push({
                    byteLength: view.byteLength,
                    bytes: Buffer.from(view)
                });
                return webcrypto.subtle.digest(algorithm, view);
            }
        }
    };
}
```

- [ ] **Step 2: Add the decimal-transition and exact-view table**

For each counter below, call the Subtle backend with one attempt and a fixed all-`0xff` digest, then assert the captured bytes equal the untouched nonce plus `Buffer.from(String(counter), 'ascii')`, `byteOffset === 0`, and `byteLength === 32 + digit count`:

```js
test('both proof paths use canonical decimal boundaries', async () => {
    const counters = [
        0, 1, 9, 10, 99, 100,
        999999999999999,
        1000000000000000,
        Number.MAX_SAFE_INTEGER
    ];

    for (const counter of counters) {
        const records = [];
        const nonce = new Uint8Array(32).fill(0x5a);
        const solver = await loadSolver({
            crypto: capturingCrypto(0xff, records)
        });
        await solver.solve(nonce, 32, counter, 1, 'subtle');
        const expected = Buffer.concat([
            Buffer.alloc(32, 0x5a),
            Buffer.from(String(counter), 'ascii')
        ]);

        assert.equal(records.length, 1);
        assert.equal(records[0].byteOffset, 0);
        assert.equal(records[0].byteLength, expected.length);
        assert.deepEqual(records[0].bytes, expected);

        const js = await (await loadSolver()).solve(
            nonce, 32, counter, 1, 'js');
        const digest = expectedDigest(expected);
        assert.equal(js.found, digest.readUInt32BE(0) === 0);
    }
});
```

The exact Subtle messages, specialized JS KAT/vector tests, and allocation
instrumentation prove the preparation behavior without a brittle source regex
or production test hook. Source review confirms both backends call the single
private `encodeCounter()` defined in Task 1.

- [ ] **Step 3: Strengthen maximum-counter and nonce-alias tests**

Extend the existing maximum-counter rows with `recordingWebcrypto()` so the
captured Subtle message ends in `9007199254740991`, the provider is called
exactly once, a passing independent nonce returns `found`, and a failing
independent nonce returns `exhausted`. Keep `maxCounterNonce()` based on Node
`createHash()`.

Extend the nonce snapshot test to start two Subtle solves from the same caller-owned nonce at disjoint counter ranges. Hold their first provider calls, mutate the caller nonce, release both, then group records by the ASCII counter suffix:

```js
let waiting = 0;
let release;
let allWaiting;
const released = new Promise((resolve) => {
    release = resolve;
});
const reachedProvider = new Promise((resolve) => {
    allWaiting = resolve;
});
const gate = async () => {
    waiting++;
    if (waiting === 2) {
        allWaiting();
    }
    await released;
};
const records = [];
const nonce = new Uint8Array(32);
const solver = await loadSolver({
    crypto: capturingCrypto(0xff, records, gate)
});
const first = solver.solve(nonce, 1, 0, 2, 'subtle');
const second = solver.solve(nonce, 1, 2, 2, 'subtle');
await reachedProvider;
nonce.fill(0xa5);
release();
await Promise.all([first, second]);

const byCounter = new Map(records.map((record) => [
    record.bytes.subarray(32).toString('ascii'), record
]));
assert.equal(records.length, 4);
assert.deepEqual([...byCounter.keys()].sort(), ['0', '1', '2', '3']);
for (const record of records) {
    assert.deepEqual(record.bytes.subarray(0, 32), Buffer.alloc(32));
    assert.deepEqual(record.bytesAfterWait, record.bytes);
}
assert.equal(byCounter.get('0').backing, byCounter.get('1').backing);
assert.equal(byCounter.get('2').backing, byCounter.get('3').backing);
assert.notEqual(byCounter.get('0').backing, byCounter.get('2').backing);
```

The shared gate Promise is intentionally one-shot: it blocks both invocations'
first provider calls, then remains resolved so counters `1` and `3` run
without another release. `bytes` proves provider-entry input;
`bytesAfterWait` separately proves that the backing buffer was not mutated
while `digest()` remained pending.

Do not add a JS post-call nonce race test. The JS kernel completes
synchronously before `solve()` returns its Promise, so such a test cannot
observe snapshot timing. Task 1's constructor order proves the 32-byte copy
occurs before workspace use; existing tests retain caller-input non-mutation.

- [ ] **Step 4: Run the new Subtle tests and verify they fail structurally**

Run:

```bash
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  node --test --test-name-pattern='canonical decimal|maximum|snapshots|same caller nonce' \
  tests/e2e/solver.test.mjs
```

Expected: canonical message bytes may match, but backing-buffer reuse and exact invocation-local isolation fail because the current implementation allocates a fresh proof message per candidate.

- [ ] **Step 5: Reuse one exact Subtle message backing buffer**

Replace `solveSubtle()` preparation with:

```js
async function solveSubtle(nonce, difficulty, startCounter, maxAttempts) {
    const subtle = globalThis.crypto == null ? null : globalThis.crypto.subtle;
    if (subtle == null || typeof subtle.digest !== 'function') {
        throw new Error();
    }

    const message = new Uint8Array(48);
    const digits = new Uint8Array(16);
    let attempts = 0;
    let candidate = startCounter;

    message.set(nonce);
    for (;;) {
        const start = encodeCounter(candidate, digits);
        const count = digits.length - start;
        for (let index = 0; index < count; index++) {
            message[32 + index] = digits[start + index];
        }

        const view = message.subarray(0, 32 + count);
        const output = await subtle.digest('SHA-256', view);
        const digest = new Uint8Array(output);
        if (digest.length !== 32) {
            throw new Error();
        }

        attempts++;
        if (meetsDifficulty(digest, difficulty)) {
            return solveResult(true, false, candidate, null, attempts);
        }
        if (candidate === Number.MAX_SAFE_INTEGER) {
            return solveResult(false, true, null, null, attempts);
        }
        candidate++;
        if (attempts === maxAttempts) {
            return solveResult(false, false, null, candidate, attempts);
        }
    }
}
```

The next candidate must not touch `message` until the previous `digest()` Promise resolves. Do not use `Promise.all()` or allocate a new backing message array in the loop.
Bytes beyond `view.byteLength` may retain digits from a longer previous
counter and are intentionally irrelevant. The exact view length is part of
the correctness contract; never pass the complete 48-byte buffer.

- [ ] **Step 6: Run both backend suites**

Run:

```bash
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie make test-js
```

Expected: all solver and existing controller tests pass; provider maximum
concurrency remains `1`, messages are contiguous and canonical, both backends
agree with the immutable vector, and the assembled-body assertion remains
below `15360` before commit.

- [ ] **Step 7: Commit the shared preparation path**

```bash
git add html/challenge.html tests/e2e/solver.test.mjs
git commit -m "feat: reuse canonical subtle proof input"
```

---

### Task 3: Specialized Runtime KAT and Transactional Fallback

**Files:**
- Modify: `tests/e2e/controller.test.mjs`
- Modify: `html/challenge.html:285-470`

**Interfaces:**
- Consumes private `proofDigestJs()` and `encodeCounter()` from Tasks 1-2.
- Produces private `backendKat(backend) -> Promise<void>` using the specialized JS digest or exact Subtle provider input.
- Backend selection completes before `nextCounter`, `totalAttempts`, or mining workspace is committed.
- A primary initialization or KAT failure advances no counter, increments no
  attempt count, mutates no controller mining state, and retains no partial
  workspace; fallback starts from the original counter.
- The controller owns only backend choice, `nextCounter`, accumulated
  attempts, slice timing, and UI state. It never receives or stores the block,
  schedule, SHA state, decimal scratch, or digest workspace.
- Test-only corruption exists only in the VM global; production bytes contain no fault selector.

- [ ] **Step 1: Add a narrow VM schedule-corruption helper in the controller test**

Import `vm` in `tests/e2e/controller.test.mjs` and add:

```js
import vm from 'node:vm';

function corruptScheduleConstructor(context) {
    const Base = vm.runInContext('Uint32Array', context);
    context.Uint32Array = class extends Base {
        constructor(value, ...rest) {
            super(typeof value === 'number' && value === 64 ? 63 : value,
                ...rest);
        }
    };
}
```

This is the accepted implementation-plan mechanism, not a production or enduring wire contract. It runs after exact-script evaluation and before the queued controller startup.
The fallback test makes no unrelated call to public `sha256()` after
corruption. The altered constructor exists only long enough to prove the
primary specialized initialization/KAT failure; it is never used as a general
hash-failure fixture.

- [ ] **Step 2: Replace the public-`sha256` KAT override test with specialized corruption**

Rewrite the controller regression as `primary KAT failure falls back once and
full-digest mismatch is terminal`:

1. create a controller harness with real `webcrypto`;
2. corrupt only its schedule constructor;
3. wrap `PowGateSolver.solve` to record mining arguments while returning one resumable result;
4. run the startup timer and then the first mining timer;
5. assert exactly one mining call with backend `subtle`, start counter `0`, and no pre-mining attempts;
6. repeat with a wrong 32-byte Subtle digest that begins `00 28` and therefore
   passes difficulty 8 and 10 but fails 11; assert the static failure UI, no
   mining timer, no proof write, and no reload. This proves the shared KAT
   compares all 32 bytes rather than accepting the leading-bit boundary alone.

Load `katDigestHex` from the immutable `tests/vectors/v1.json` case using the
same repository-root pattern as `solver.test.mjs`. Before constructing the
fallback harness, explicitly preserve the test premise:

```js
assert.notEqual(Buffer.from(wrongDigest).toString('hex'), katDigestHex);
```

This assertion must precede controller startup so a future intentional KAT
fixture change cannot silently turn the wrong-digest row into a success
fixture.

Retain `valid parameters select the primary backend without subtle access`.
After Task 3 it invokes the exact production specialized workspace KAT with
the checked-in expected digest; successful startup proves the uncorrupted JS
full-digest path. The altered-schedule and threshold-valid-wrong-digest rows
independently prove fallback and full-byte rejection without exposing a new
public function. Together these assertions prove that the exact specialized
digest is serialized from all eight state words and compared across all 32
bytes; the Task 1 difficulty-boundary row alone is not treated as a
full-digest KAT.

The core assertions are:

```js
assert.deepEqual(calls.map((args) => ({
    backend: args[4],
    startCounter: args[2]
})), [{ backend: 'subtle', startCounter: 0 }]);
assert.equal(fallback.nodes['pow-progress'].value, 0);

assertFailure(failed);
assert.equal(failed.timers.length, 0);
assert.equal(failed.location.reloadCount, 0);
assert.equal(failed.cookieWrites.some((write) =>
    write.startsWith(`${proofName}=1.`)), false);
assert.equal(failed.cookieWrites.every((write) =>
    write === `${proofName}=; Max-Age=0; Path=/; SameSite=Lax; Secure`), true);
```

Use this complete test shape so the clock cannot leave `mineSlice()` looping:

```js
test('primary KAT failure falls back once and full-digest mismatch is terminal',
    async () => {
        const clock = clockFixture();
        const fallback = await createControllerHarness({
            crypto: webcrypto,
            paramsText: validParams,
            performance: clock.performance
        });
        corruptScheduleConstructor(fallback.context);
        const original = fallback.context.PowGateSolver;
        const calls = [];
        fallback.context.PowGateSolver = Object.freeze({
            sha256: original.sha256,
            async solve(...args) {
                calls.push(args);
                clock.advance(10);
                return Object.freeze({
                    found: false,
                    exhausted: false,
                    counter: null,
                    nextCounter: args[2] + args[3],
                    attempts: args[3]
                });
            }
        });

        await fallback.runNextTimer();
        assert.equal(calls.length, 0);
        assert.equal(fallback.nodes['pow-progress'].value, 0);
        await fallback.runNextTimer();
        assert.deepEqual(calls.map((args) => ({
            backend: args[4],
            startCounter: args[2]
        })), [{ backend: 'subtle', startCounter: 0 }]);

        const wrongDigest = new Uint8Array(32);
        wrongDigest[1] = 0x28;
        assert.notEqual(Buffer.from(wrongDigest).toString('hex'),
            katDigestHex);
        const failed = await createControllerHarness({
            crypto: {
                subtle: {
                    async digest() {
                        return wrongDigest.slice().buffer;
                    }
                }
            },
            paramsText: validParams
        });
        corruptScheduleConstructor(failed.context);
        await failed.runNextTimer();
        assertFailure(failed);
        assert.equal(failed.timers.length, 0);
        assert.equal(failed.location.reloadCount, 0);
        assert.equal(failed.cookieWrites.some((write) =>
            write.startsWith(`${proofName}=1.`)), false);
        assert.equal(failed.cookieWrites.every((write) =>
            write === `${proofName}=; Max-Age=0; Path=/; SameSite=Lax; Secure`),
            true);
    });
```

- [ ] **Step 3: Run the fallback test and verify it fails against the general KAT**

Run:

```bash
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  node --test --test-name-pattern='primary KAT failure' \
  tests/e2e/controller.test.mjs
```

Expected: FAIL because the current KAT calls public general `sha256()` and is unaffected by specialized schedule initialization corruption.

- [ ] **Step 4: Make the KAT exercise the full specialized digest**

Reuse Task 1's private `stateDigest()` and implement the KAT digest path
exactly:

```js
async function katDigest(backend) {
    const nonce = hexBytes(katNonceHex);

    if (backend === 'js') {
        const block = new Uint8Array(64);
        const words = new Uint32Array(64);
        const state = new Uint32Array(8);
        const digits = new Uint8Array(16);
        block.set(nonce);
        proofDigestJs(34, block, words, state, digits);
        return stateDigest(state);
    }

    const subtle = globalThis.crypto == null ? null : globalThis.crypto.subtle;
    if (subtle == null || typeof subtle.digest !== 'function') {
        throw new Error();
    }
    const message = new Uint8Array(34);
    const digits = new Uint8Array(16);
    const start = encodeCounter(34, digits);
    message.set(nonce);
    for (let index = start; index < digits.length; index++) {
        message[32 + index - start] = digits[index];
    }
    return new Uint8Array(await subtle.digest('SHA-256', message));
}

async function backendKat(backend) {
    const digest = await katDigest(backend);

    if (!bytesEqual(digest, hexBytes(katDigestHex))
        || !meetsDifficulty(digest, 8)
        || !meetsDifficulty(digest, 10)
        || meetsDifficulty(digest, 11)) {
        throw new Error();
    }
}
```

Do not call public `sha256()` for the JS KAT. Remove `proofMessage()` after its
last reference disappears. Ensure temporary workspace is lexical to
`katDigest()` and unreachable after rejection. Keep `selectBackend()` at
exactly one primary attempt and one fallback attempt.

Cookie serialization in `finishProof()` may continue using `String(counter)`;
the exact provider-message, allocation, and KAT tests—not source spelling—are
the regression boundary for proof preparation.

- [ ] **Step 5: Verify fallback and mining-failure boundaries**

Run:

```bash
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie make test-js
```

Expected: all solver and controller tests pass, including the assembled-body
budget. Initialization fallback begins at counter zero, the threshold-valid
but full-digest-invalid fallback is terminal, and `a mining rejection is
terminal and does not switch backends` remains green.

- [ ] **Step 6: Commit the KAT transaction**

```bash
git add html/challenge.html tests/e2e/controller.test.mjs
git commit -m "feat: validate specialized browser KAT"
```

---

### Task 4: Candidate-Bounded Proof-Cookie Cleanup

**Files:**
- Modify: `tests/e2e/controller.test.mjs`
- Modify: `tests/e2e/lib/challenge-script.mjs`
- Modify: `html/challenge.html:380-470`

**Interfaces:**
- Produces private `safeCookiePath(path) -> boolean`.
- Keeps `pathCandidates(pathname) -> Set<string>` ordered with `/` first.
- Unsafe complete candidates are skipped independently; the pathname itself remains valid controller input when it begins with `/`.
- Zero visible exact `__pow_p` occurrences after cleanup and exactly one matching occurrence after proof write remain mandatory.

- [ ] **Step 1: Replace the unsafe-path failure table with explicit candidate rows**

Keep invalid scheme and relative-path failures, but move literal semicolon, control, DEL, whitespace, and raw non-ASCII into candidate-bounded cases. Add a table like:

```js
const cases = [
    {
        pathname: '/account/orders;view=full',
        writes: ['/', '/account', '/account/']
    },
    { pathname: '/a%3Bb', writes: ['/', '/a%3Bb'] },
    { pathname: '/a;b', writes: ['/'] },
    { pathname: '/\tunsafe', writes: ['/'] },
    { pathname: '/\x7funsafe', writes: ['/'] },
    { pathname: '/\u00e9', writes: ['/'] },
    {
        pathname: '/a/b/\u00e9',
        writes: ['/', '/a', '/a/', '/a/b', '/a/b/']
    },
    { pathname: '/a;b/c', writes: ['/'] },
    { pathname: '/a,b="c"\\d', writes: ['/', '/a,b="c"\\d'] },
    { pathname: '/a//b', writes: ['/', '/a', '/a/', '/a//', '/a//b'] }
];
```

For each row, initialize with no stale proof and assert the controller reaches
`Checking your browser.`. Extract each serialized `Path=` attribute and assert
the ordered values equal `writes`; apply the safety predicate only to those
path values because cookie attribute separators are semicolons by design. The
punctuation row freezes the intended rule as visible ASCII `0x21..0x7e`
except semicolon, not cookie-token grammar.

The control, DEL, whitespace, and raw non-ASCII rows are synthetic controller
validation cases injected through the VM harness. Phase 4C browser integration
owns browser-realistic semicolon, percent-encoded data, repeated-slash, path,
and query behavior; it must not expect raw C0 controls from a normal browser
URL parser.

Add a stale-cookie row under `/account/orders;view=full` with removable cookies at `/`, `/account`, and `/account/`; all must disappear. Add an undeletable visible proof row and retain the terminal-failure assertion.

- [ ] **Step 2: Prove controller path/query non-mutation before reload**

In `createControllerHarness()`, accept `options.search ?? ''`, expose it as `location.search`, and return it unchanged. Add a test using:

```js
const harness = await initialized({
    pathname: '/a//b;view=full',
    search: '?next=%2Ftarget&x=1'
});
const before = {
    pathname: harness.location.pathname,
    search: harness.location.search
};

assert.deepEqual({
    pathname: harness.location.pathname,
    search: harness.location.search
}, before);
```

After the controlled success path, assert the same pair and one reload. Do not make the controller parse or reconstruct `location.search`.
Name the test `controller does not reconstruct path or query before reload`.
This is a Phase 4B unit claim about assignments to the mocked `location`, not
proof of browser navigation semantics. Phase 4C real-browser E2E owns actual
reload preservation.

- [ ] **Step 3: Run pathname tests and verify semicolon cases fail before mining**

Run:

```bash
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  node --test --test-name-pattern='cleanup|pathname|path and query' \
  tests/e2e/controller.test.mjs
```

Expected: literal-semicolon and synthetic unsafe pathname rows fail because current `pathCandidates()` rejects the whole page.

- [ ] **Step 4: Validate and retain candidates independently**

Replace the global pathname-byte rejection with:

```js
function safeCookiePath(path) {
    for (let index = 0; index < path.length; index++) {
        const code = path.charCodeAt(index);
        if (code < 0x21 || code > 0x7e || code === 0x3b) {
            return false;
        }
    }
    return true;
}

function pathCandidates(pathname) {
    if (typeof pathname !== 'string' || !pathname.startsWith('/')) {
        throw new TypeError();
    }

    const paths = new Set(['/']);
    const add = (path) => {
        if (safeCookiePath(path)) {
            paths.add(path);
        }
    };

    for (let index = 1; index < pathname.length; index++) {
        if (pathname[index] === '/') {
            add(pathname.slice(0, index));
            add(pathname.slice(0, index + 1));
        }
    }
    add(pathname);
    return paths;
}
```

The closure is private and short-lived; it is not in the mining loop. Do not decode `%3B`, normalize repeated slashes, or invent a prefix by truncating at an unsafe byte.

- [ ] **Step 5: Verify cleanup, write-back, and terminal shadow behavior**

Run:

```bash
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie make test-js
```

Expected: all controller and solver tests pass. `%3B` is serialized as
observed, literal `;` is skipped, root cleanup always occurs, visible stale
proof cookies remain terminal, post-write readback still requires one exact
matching value, and the assembled-body assertion remains below `15360` before
commit.

- [ ] **Step 6: Commit valid-path cleanup**

```bash
git add html/challenge.html tests/e2e/controller.test.mjs \
  tests/e2e/lib/challenge-script.mjs
git commit -m "fix: skip unsafe proof cleanup paths"
```

---

### Task 5: Body Budget, Documentation, and Full Release Gates

**Files:**
- Modify: `docs/superpowers/specs/2026-07-15-phase4b-browser-solver-design.md`
- Modify: `PLAN.md`
- Modify: `docs/security.md`
- Modify: `docs/configuration.md`
- Verify unchanged: `docs/protocol.md`

**Interfaces:**
- No production interface changes.
- Generator prefix/suffix and CSP digest remain derived from exact script bytes.
- Phase 4C receives measurement and real-browser validation work only; it does not inherit a Phase 4B correctness or structural-allocation defect.

- [ ] **Step 1: Retain the maximum assembled-body assertion beside exact-byte tests**

Confirm Task 1's `generator hashes the exact executable production bytes`
test still contains:

```js
const constants = await readProtocolConstants();
const maximumJson = Buffer.from(
    '<script type="application/json" id="pow-params">'
    + '{"v":1,"d":32,"b":"99999999999999999999",'
    + '"n":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}'
    + '</script>',
    'ascii'
);

assert.ok(artifacts.prefix.length + maximumJson.length
    + artifacts.suffix.length < constants.pageMaxBodyLen);
```

Also keep the existing integration assertions that actual H1 and H2 response bodies equal template prefix + runtime JSON + suffix and are below the same protocol constant.

- [ ] **Step 2: Run the body test and reduce only non-semantic source bytes if needed**

Run:

```bash
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  node --test --test-name-pattern='generator hashes' tests/e2e/solver.test.mjs
```

Expected: PASS with the final implementation. If it fails, reduce only redundant private setup, private-name verbosity, blank lines, indentation in the round/IV tables, or presentation whitespace. Do not minify, duplicate SHA logic, change public names, remove accessibility structure, weaken CSP, add compression/runtime generation, or raise `15360`.

- [ ] **Step 3: Supersede only the corrected parts of the original design**

Add immediately below the original design title:

```markdown
> **Corrective specification:** The allocation discipline, specialized
> single-block proof kernel, SubtleCrypto input preparation, runtime KAT, and
> pathname cleanup rules are superseded by
> [the Phase 4B corrective design](2026-07-15-phase4b-corrective-design.md).
> All other contracts in this document remain in force.
```

- [ ] **Step 4: Update `PLAN.md` without changing protocol claims**

Under Phase 4B, add a task recording:

```markdown
7. The pure-JavaScript mining path uses one invocation-local, fixed-shape
   single-block workspace and shares one SHA-256 compression primitive with
   public `sha256()`. The pure-JavaScript kernel creates no explicit typed
   array, message buffer, or digest object per candidate. Both backends use
   one direct canonical-decimal encoder. The sequential SubtleCrypto backend
   reuses one invocation-local backing buffer and passes one exact-length view
   per awaited provider call.
   Cleanup always attempts `/`, skips only unsafe complete derived Path
   candidates, and still requires zero visible `__pow_p` occurrences before
   mining. Literal semicolons are skipped; percent-encoded `%3B` is preserved.
```

Replace Phase 4C task 3 with:

```markdown
3. Measure the already-correct JavaScript kernel and sequential SubtleCrypto
   backend in recorded real-browser/device environments, including throughput
   and event-loop responsiveness. Choose one fixed backend order from that
   evidence and make only measurement-supported tuning; no Node timing
   threshold or mid-search fallback is introduced.
```

- [ ] **Step 5: Update operational security and configuration text**

In `docs/security.md`, extend the challenge-page paragraph to state:

```markdown
The pure-JavaScript mining kernel reuses invocation-local fixed-shape SHA-256
workspace and creates no explicit typed-array, message-buffer, or digest
object per candidate. The sequential SubtleCrypto backend reuses one backing
buffer per invocation and passes one exact-length view per awaited provider
call.
Before mining, the controller clears every safely serializable derived proof
cookie path, always including `/`, and fails closed if any exact `__pow_p`
occurrence remains visible.
```

In `docs/configuration.md`, replace the current generic cleanup sentence with:

```markdown
Before mining, the solver performs candidate-bounded proof-cookie cleanup.
It always clears `Path=/`, clears each safely serializable segment-boundary
candidate from the browser's unmodified `location.pathname`, skips unsafe
complete candidates, and then requires no exact `__pow_p` occurrence to remain
visible. A literal semicolon is unsafe for cookie Path serialization; a
percent-encoded `%3B` remains visible ASCII and is preserved as observed.
```

Keep Phase 4C described as real-browser CSP, native cookie, reload/auth-loop,
throughput, responsiveness, and backend-order validation.

Do not add a Phase 4B fuzz seed for this correction. It changes only browser
JavaScript workspace and pathname handling, not any C parser or wire shape;
Phase 4C remains responsible for adding real browser proof/cookie shapes to
the existing corpora.

- [ ] **Step 6: Run documentation and focused delivery checks**

Run:

```bash
git diff --check
test -z "$(git diff -- docs/protocol.md)"
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  sh -c 'make check-policy && make test-tools && make test-js'
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie \
  sh -c 'make test-integration && make test-e2e'
```

Expected: no whitespace errors; `docs/protocol.md` has no diff; policy, generator, Python reference, Node, HTTPS H1/H2 integration, and served-script smoke tests all pass. The actual served body and CSP digest must match the exact checked-in script bytes.

- [ ] **Step 7: Commit documentation and body assertions**

```bash
git add PLAN.md docs/security.md docs/configuration.md \
  docs/superpowers/specs/2026-07-15-phase4b-browser-solver-design.md
git commit -m "docs: record phase 4b browser corrections"
```

- [ ] **Step 8: Run the clean full gate**

Run:

```bash
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie make clean
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
  localhost/ngx-powgate-dev:trixie make check
```

Expected: clean rebuild succeeds; policy, tools, immutable Python vector, C unit and parser coverage, module and fault modules, HTTPS HTTP/1.1 and HTTP/2 integration, exact served-script e2e, all three 60-second fuzzers, and ASan/UBSan pass with no skipped required case.

- [ ] **Step 9: Inspect the final artifact boundary and history**

Run:

```bash
test -z "$(find out -type f -name '*fault*' -print)"
test -z "$(git diff -- docs/protocol.md)"
git status --short
git log --oneline --decorate -8
```

Expected: no fault artifact in `out/`, no protocol diff, clean worktree, and
five focused implementation commits after the design commits.
