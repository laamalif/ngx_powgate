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
    const reconstructed = Buffer.concat([
        artifacts.prefix,
        artifacts.suffix
    ]);

    assert.deepEqual(extractExecutableScript(reconstructed), script);
    assert.equal(artifacts.digest.toString('ascii'),
        createHash('sha256').update(script).digest('base64'));
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
    }
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
