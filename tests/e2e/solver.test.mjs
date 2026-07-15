import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
    evaluateChallengeScript,
    readChallengeScript
} from './lib/challenge-script.mjs';


const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)),
    '../..');


async function loadSolver() {
    const script = await readChallengeScript();
    const context = evaluateChallengeScript(script);

    return context.PowGateSolver;
}


function expectedDigest(bytes) {
    return createHash('sha256').update(bytes).digest();
}


test('installs the exact frozen two-function namespace', async () => {
    const solver = await loadSolver();

    assert.notEqual(solver, undefined);
    assert.deepEqual(Object.keys(solver), ['sha256', 'solve']);
    assert.equal(typeof solver.sha256, 'function');
    assert.equal(typeof solver.solve, 'function');
    assert.equal(Object.isFrozen(solver), true);
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
