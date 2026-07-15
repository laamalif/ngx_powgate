import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
    buildChallengeArtifacts,
    evaluateChallengeScript,
    extractExecutableScript,
    readChallengeScript,
    readProtocolConstants
} from './lib/challenge-script.mjs';


const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)),
    '../..');


async function loadSolver(globals = {}) {
    const script = await readChallengeScript();
    const context = evaluateChallengeScript(script, globals);

    return context.PowGateSolver;
}


function fixedCrypto(byte, messages = []) {
    let active = 0;
    let maximumActive = 0;

    return {
        get maximumActive() {
            return maximumActive;
        },
        subtle: {
            async digest(algorithm, message) {
                assert.equal(algorithm, 'SHA-256');
                active++;
                maximumActive = Math.max(maximumActive, active);
                messages.push(Buffer.from(message));
                await Promise.resolve();
                active--;
                return new Uint8Array(32).fill(byte).buffer;
            }
        }
    };
}


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


function maxCounterNonce(valid) {
    const counter = Buffer.from(String(Number.MAX_SAFE_INTEGER), 'ascii');

    for (let first = 0; first < 256; first++) {
        const nonce = new Uint8Array(32);
        nonce[0] = first;
        const digest = expectedDigest(Buffer.concat([nonce, counter]));

        if ((digest[0] < 0x80) === valid) {
            return nonce;
        }
    }

    throw new Error('unable to construct boundary fixture');
}


function expectedDigest(bytes) {
    return createHash('sha256').update(bytes).digest();
}


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


function resultValues(result) {
    return {
        found: result.found,
        exhausted: result.exhausted,
        counter: result.counter,
        nextCounter: result.nextCounter,
        attempts: result.attempts
    };
}


test('installs the exact frozen two-function namespace', async () => {
    const solver = await loadSolver();

    assert.notEqual(solver, undefined);
    assert.deepEqual(Object.keys(solver), ['sha256', 'solve']);
    assert.equal(typeof solver.sha256, 'function');
    assert.equal(typeof solver.solve, 'function');
    assert.equal(Object.isFrozen(solver), true);
});


test('generator hashes the exact executable production bytes', async () => {
    const script = await readChallengeScript();
    const artifacts = await buildChallengeArtifacts();
    const constants = await readProtocolConstants();
    const reconstructed = Buffer.concat([
        artifacts.prefix,
        artifacts.suffix
    ]);
    const maximumJson = Buffer.from(
        '<script type="application/json" id="pow-params">'
        + '{"v":1,"d":32,"b":"99999999999999999999",'
        + '"n":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}'
        + '</script>',
        'ascii'
    );

    assert.deepEqual(extractExecutableScript(reconstructed), script);
    assert.equal(artifacts.digest.toString('ascii'),
        createHash('sha256').update(script).digest('base64'));
    assert.ok(artifacts.prefix.length + maximumJson.length
        + artifacts.suffix.length < constants.pageMaxBodyLen);
});


test('solver boundaries agree with the C protocol constants', async () => {
    const constants = await readProtocolConstants();
    const solver = await loadSolver();
    const nonce = new Uint8Array(32);

    assert.equal(constants.proofCounterMax, Number.MAX_SAFE_INTEGER);
    await solver.solve(nonce, constants.difficultyMin, 0, 1, 'js');
    await solver.solve(nonce, constants.difficultyMax, 0, 1, 'js');
    await assert.rejects(solver.solve(nonce,
        constants.difficultyMin - 1, 0, 1, 'js'));
    await assert.rejects(solver.solve(nonce,
        constants.difficultyMax + 1, 0, 1, 'js'));
});


test('sha256 matches fixed messages and padding boundaries', async () => {
    const solver = await loadSolver();
    const cases = [
        new Uint8Array(),
        new Uint8Array([0, 1, 2, 127, 128, 254, 255]),
        ...[55, 56, 63, 64, 65].map((length) =>
            Uint8Array.from({ length }, (_, index) =>
                (index * 37 + 11) & 0xff))
    ];

    for (const bytes of cases) {
        const before = bytes.slice();
        const first = solver.sha256(bytes);
        const second = solver.sha256(bytes);

        assert.deepEqual(Buffer.from(first), expectedDigest(bytes));
        assert.deepEqual(bytes, before);
        assert.equal(first instanceof Uint8Array, true);
        assert.equal(first.length, 32);
        assert.notEqual(first, second);
        assert.deepEqual(first, second);
        first[0] ^= 0xff;
        assert.deepEqual(Buffer.from(second), expectedDigest(bytes));
        assert.deepEqual(Buffer.from(solver.sha256(bytes)),
            expectedDigest(bytes));
    }
});


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


test('separate JS solve calls own separate workspaces', async () => {
    const solver = await loadSolver();
    const nonceA = new Uint8Array(32);
    const nonceB = new Uint8Array(32).fill(0xa5);
    const expectedA = resultValues(await solver.solve(nonceA, 32, 3, 7,
        'js'));
    const expectedB = resultValues(await solver.solve(nonceB, 32, 19, 5,
        'js'));
    const [actualA, actualB] = await Promise.all([
        solver.solve(nonceA, 32, 3, 7, 'js'),
        solver.solve(nonceB, 32, 19, 5, 'js')
    ]);

    assert.deepEqual(resultValues(actualA), expectedA);
    assert.deepEqual(resultValues(actualB), expectedB);
});


test('sha256 reproduces the canonical proof digest', async () => {
    const vector = JSON.parse(await fs.readFile(
        path.join(root, 'tests', 'vectors', 'v1.json'), 'utf8'));
    const fixture = vector.cases[0];
    const nonce = Buffer.from(fixture.nonce_hex, 'hex');
    const counter = Buffer.from(fixture.counter_ascii, 'ascii');
    const message = new Uint8Array(Buffer.concat([nonce, counter]));
    const solver = await loadSolver();

    assert.equal(Buffer.from(solver.sha256(message)).toString('hex'),
        fixture.proof_digest_hex);
});


test('sha256 rejects non-Uint8Array inputs synchronously', async () => {
    const solver = await loadSolver();

    assert.notEqual(solver, undefined);

    for (const value of [
        null,
        undefined,
        [],
        new ArrayBuffer(1),
        new DataView(new ArrayBuffer(1)),
        'x'
    ]) {
        assert.throws(() => solver.sha256(value), TypeError);
    }
});


test('solve finds the canonical counter with both real backends', async () => {
    const vector = JSON.parse(await fs.readFile(
        path.join(root, 'tests', 'vectors', 'v1.json'), 'utf8'));
    const fixture = vector.cases[0];
    const nonce = new Uint8Array(Buffer.from(fixture.nonce_hex, 'hex'));

    for (const backend of ['js', 'subtle']) {
        const solver = await loadSolver({ crypto: webcrypto });
        const promise = solver.solve(nonce, fixture.difficulty, 0, 100,
            backend);

        assert.equal(typeof promise.then, 'function');
        assert.deepEqual(resultValues(await promise), {
            found: true,
            exhausted: false,
            counter: fixture.counter,
            nextCounter: null,
            attempts: fixture.counter + 1
        });
    }
});


test('solve returns the exact frozen resumable result', async () => {
    const solver = await loadSolver();
    const nonce = new Uint8Array(32);
    const result = await solver.solve(nonce, 32, 0, 2, 'js');

    assert.deepEqual(Object.keys(result), [
        'found', 'exhausted', 'counter', 'nextCounter', 'attempts'
    ]);
    assert.deepEqual(resultValues(result), {
        found: false,
        exhausted: false,
        counter: null,
        nextCounter: 2,
        attempts: 2
    });
    assert.equal(Object.isFrozen(result), true);
});


test('solve handles the final safe counter without incrementing it',
    async () => {
        const maximum = Number.MAX_SAFE_INTEGER;
        const successSolver = await loadSolver();
        const success = await successSolver.solve(maxCounterNonce(true), 1,
            maximum, 4, 'js');
        const failureSolver = await loadSolver();
        const exhausted = await failureSolver.solve(maxCounterNonce(false), 1,
            maximum, 4, 'js');

        assert.deepEqual(resultValues(success), {
            found: true,
            exhausted: false,
            counter: maximum,
            nextCounter: null,
            attempts: 1
        });
        assert.deepEqual(resultValues(exhausted), {
            found: false,
            exhausted: true,
            counter: null,
            nextCounter: null,
            attempts: 1
        });
    });


test('subtle search is sequential, contiguous, and resumable', async () => {
    const messages = [];
    const crypto = fixedCrypto(0xff, messages);
    const solver = await loadSolver({ crypto });
    const nonce = new Uint8Array(32);
    const first = await solver.solve(nonce, 1, 0, 3, 'subtle');
    const second = await solver.solve(nonce, 1, first.nextCounter, 2,
        'subtle');

    assert.deepEqual(resultValues(first), {
        found: false,
        exhausted: false,
        counter: null,
        nextCounter: 3,
        attempts: 3
    });
    assert.deepEqual(resultValues(second), {
        found: false,
        exhausted: false,
        counter: null,
        nextCounter: 5,
        attempts: 2
    });
    assert.deepEqual(messages.map((message) =>
        message.subarray(32).toString('ascii')), ['0', '1', '2', '3', '4']);
    assert.equal(crypto.maximumActive, 1);
});


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


test('subtle encodes the final safe counter exactly once', async () => {
    const maximum = Number.MAX_SAFE_INTEGER;

    for (const valid of [true, false]) {
        const records = [];
        const nonce = maxCounterNonce(valid);
        const solver = await loadSolver({
            crypto: recordingWebcrypto(records)
        });
        const result = await solver.solve(nonce, 1, maximum, 4, 'subtle');

        assert.equal(records.length, 1);
        assert.equal(records[0].byteLength, 48);
        assert.equal(records[0].bytes.subarray(32).toString('ascii'),
            '9007199254740991');
        assert.equal(result.found, valid);
        assert.equal(result.exhausted, !valid);
        assert.equal(result.attempts, 1);
    }
});


test('solve snapshots the nonce before asynchronous search', async () => {
    const messages = [];
    let releaseFirst;
    const firstDigest = new Promise((resolve) => {
        releaseFirst = resolve;
    });
    const crypto = {
        subtle: {
            async digest(_algorithm, message) {
                messages.push(Buffer.from(message));
                if (messages.length === 1) {
                    await firstDigest;
                }
                return new Uint8Array(32).fill(0xff).buffer;
            }
        }
    };
    const solver = await loadSolver({ crypto });
    const nonce = new Uint8Array(32);
    const pending = solver.solve(nonce, 1, 0, 2, 'subtle');

    nonce.fill(0xa5);
    releaseFirst();
    await pending;

    assert.equal(messages.length, 2);
    assert.deepEqual(messages[0].subarray(0, 32), Buffer.alloc(32));
    assert.deepEqual(messages[1].subarray(0, 32), Buffer.alloc(32));
});


test('subtle calls sharing a caller nonce own isolated snapshots', async () => {
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
    assert.notEqual(byCounter.get('0').backing,
        byCounter.get('2').backing);
});


test('subtle search reports success and safe exhaustion exactly', async () => {
    const maximum = Number.MAX_SAFE_INTEGER;
    const success = await (await loadSolver({ crypto: fixedCrypto(0) }))
        .solve(new Uint8Array(32), 32, maximum, 2, 'subtle');
    const exhausted = await (await loadSolver({
        crypto: fixedCrypto(0xff)
    })).solve(new Uint8Array(32), 1, maximum, 2, 'subtle');

    assert.deepEqual(resultValues(success), {
        found: true,
        exhausted: false,
        counter: maximum,
        nextCounter: null,
        attempts: 1
    });
    assert.deepEqual(resultValues(exhausted), {
        found: false,
        exhausted: true,
        counter: null,
        nextCounter: null,
        attempts: 1
    });
});


test('solve rejects every invalid kernel argument through its Promise',
    async () => {
        const solver = await loadSolver({ crypto: webcrypto });
        const nonce = new Uint8Array(32);
        const cases = [
            [null, 8, 0, 1, 'js'],
            [new Uint8Array(31), 8, 0, 1, 'js'],
            [nonce, 0, 0, 1, 'js'],
            [nonce, 33, 0, 1, 'js'],
            [nonce, 1.5, 0, 1, 'js'],
            [nonce, 8, -1, 1, 'js'],
            [nonce, 8, 1.5, 1, 'js'],
            [nonce, 8, Number.MAX_SAFE_INTEGER + 1, 1, 'js'],
            [nonce, 8, 0, 0, 'js'],
            [nonce, 8, 0, 1.5, 'js'],
            [nonce, 8, 0, Number.MAX_SAFE_INTEGER + 1, 'js'],
            [nonce, 8, 0, 1, 'unknown']
        ];

        for (const args of cases) {
            let promise;

            assert.doesNotThrow(() => {
                promise = solver.solve(...args);
            });
            assert.equal(typeof promise.then, 'function');
            await assert.rejects(promise);
        }
    });


test('subtle provider failures reject instead of becoming misses',
    async () => {
        const nonce = new Uint8Array(32);
        const providers = [
            undefined,
            {},
            { subtle: {} },
            { subtle: { digest() { throw new Error('failed'); } } },
            { subtle: { digest() { return Promise.reject(new Error()); } } },
            { subtle: { digest() { return new Uint8Array(31).buffer; } } }
        ];

        for (const crypto of providers) {
            const solver = await loadSolver({ crypto });
            await assert.rejects(solver.solve(nonce, 8, 0, 1, 'subtle'));
        }
    });
