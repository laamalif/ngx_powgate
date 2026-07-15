import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

import {
    createControllerHarness,
    readChallengePage,
    readProtocolConstants
} from './lib/challenge-script.mjs';


const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)),
    '../..');
const protocolConstants = await readProtocolConstants();
const proofName = protocolConstants.proofCookieName;
const protocolVector = JSON.parse(await fs.readFile(
    path.join(root, 'tests', 'vectors', 'v1.json'), 'utf8'));
const katDigestHex = protocolVector.cases[0].proof_digest_hex;
const validParams = JSON.stringify({
    v: protocolConstants.protocolVersion,
    d: 8,
    b: '29333333',
    n: 'w4LNRcMugfb1vcxfspSXh2o9Q2S2iCRWaKsbV4_3GE8'
});


async function initialized(options = {}) {
    const harness = await createControllerHarness({
        crypto: webcrypto,
        paramsText: validParams,
        ...options
    });

    assert.equal(harness.timers.length, 1);
    assert.equal(harness.timers[0].delay, 0);
    await harness.runNextTimer();
    return harness;
}


function assertFailure(harness) {
    assert.equal(harness.nodes['pow-status'].textContent,
        'Unable to complete the check.');
    assert.equal(harness.nodes['pow-progress'].hidden, true);
    assert.equal(harness.nodes['pow-retry'].hidden, false);
    assert.equal(harness.location.reloadCount, 0);
}


function clockFixture() {
    let value = 0;

    return {
        advance(delta) {
            value += delta;
        },
        performance: {
            now() {
                return value;
            }
        }
    };
}


function corruptSpecializedWorkspace(context) {
    const Base = vm.runInContext('Uint8Array', context);
    let block = null;

    context.Uint8Array = class extends Base {
        constructor(value, ...rest) {
            super(value, ...rest);
            if (typeof value === 'number' && value === 64) {
                block = this;
            } else if (typeof value === 'number' && value === 16
                && block != null)
            {
                block.fill = () => {
                    throw new Error('specialized workspace fault');
                };
            }
        }
    };
}


async function miningHarness(solve, options = {}) {
    const clock = options.clock ?? clockFixture();
    const harness = await createControllerHarness({
        crypto: webcrypto,
        paramsText: validParams,
        performance: clock.performance,
        ...options
    });
    const original = harness.context.PowGateSolver;

    harness.context.PowGateSolver = Object.freeze({
        sha256: original.sha256,
        solve
    });
    await harness.runNextTimer();
    return { clock, harness };
}


test('page has the exact accessible challenge structure', async () => {
    const page = (await readChallengePage()).toString('utf8');

    assert.equal((page.match(/<main(?:\s|>)/g) ?? []).length, 1);
    assert.equal((page.match(/aria-live="polite"/g) ?? []).length, 1);
    assert.equal((page.match(/<progress\s/g) ?? []).length, 1);
    assert.equal((page.match(/<button\s/g) ?? []).length, 1);
    assert.equal((page.match(/<noscript>/g) ?? []).length, 1);
    assert.equal((page.match(/<!-- POW:PARAMS -->/g) ?? []).length, 1);
    assert.equal((page.match(/<script>/g) ?? []).length, 1);
});


test('valid parameters select the primary backend without subtle access',
    async () => {
        const harness = await initialized({ crypto: undefined });

        assert.equal(harness.nodes['pow-status'].textContent,
            'Checking your browser.');
        assert.equal(harness.nodes['pow-retry'].hidden, true);
        assert.equal(harness.cookieWrites.length, 1);
    });


test('strict parameter failures share one static terminal state', async () => {
    const valid = JSON.parse(validParams);
    const cases = [
        '',
        '{',
        'null',
        '[]',
        JSON.stringify({ ...valid, extra: true }),
        JSON.stringify({ d: valid.d, b: valid.b, n: valid.n }),
        JSON.stringify({ ...valid, v: '1' }),
        JSON.stringify({ ...valid, d: 0 }),
        JSON.stringify({ ...valid, d: 33 }),
        JSON.stringify({ ...valid, d: 1.5 }),
        JSON.stringify({ ...valid, b: 1 }),
        JSON.stringify({ ...valid, b: '' }),
        JSON.stringify({ ...valid, b: '00' }),
        JSON.stringify({ ...valid, b: '18446744073709551616' }),
        JSON.stringify({ ...valid, n: `${valid.n}=` }),
        JSON.stringify({ ...valid, n: `${valid.n.slice(0, -1)}!` }),
        JSON.stringify({ ...valid, n: `${valid.n.slice(0, -1)}9` }),
        JSON.stringify({ ...valid, n: valid.n.slice(0, -1) })
    ];

    for (const paramsText of cases) {
        const harness = await initialized({ paramsText });

        assertFailure(harness);
        assert.equal(harness.cookieWrites.length, 0);
        assert.equal(harness.timers.length, 0);
    }
});


test('cleanup expires every visible proof-cookie path before mining',
    async () => {
        const harness = await initialized({
            pathname: '/alpha/beta',
            cookies: [
                { name: proofName, value: 'root', path: '/' },
                { name: proofName, value: 'alpha', path: '/alpha' },
                { name: proofName, value: 'slash', path: '/alpha/' },
                { name: proofName, value: 'exact', path: '/alpha/beta' },
                { name: '__pow_p_old', value: 'keep', path: '/' }
            ]
        });

        assert.deepEqual(harness.cookieWrites, [
            `${proofName}=; Max-Age=0; Path=/; SameSite=Lax; Secure`,
            `${proofName}=; Max-Age=0; Path=/alpha; SameSite=Lax; Secure`,
            `${proofName}=; Max-Age=0; Path=/alpha/; SameSite=Lax; Secure`,
            `${proofName}=; Max-Age=0; Path=/alpha/beta; SameSite=Lax; Secure`
        ]);
        assert.equal(harness.document.cookie, '__pow_p_old=keep');
        assert.equal(harness.nodes['pow-status'].textContent,
            'Checking your browser.');
    });


test('HTTP cleanup omits Secure and invalid scheme or relative path fails',
    async () => {
        const http = await initialized({ protocol: 'http:' });
        assert.equal(http.cookieWrites[0],
            `${proofName}=; Max-Age=0; Path=/; SameSite=Lax`);

        for (const options of [
            { protocol: 'file:' },
            { pathname: 'relative' }
        ]) {
            const harness = await initialized(options);
            assertFailure(harness);
            assert.equal(harness.cookieWrites.length, 0);
        }
    });


test('cleanup retains every independently safe pathname candidate',
    async () => {
        const cases = [
            {
                pathname: '/account/orders;view=full',
                paths: ['/', '/account', '/account/']
            },
            { pathname: '/a%3Bb', paths: ['/', '/a%3Bb'] },
            { pathname: '/a;b', paths: ['/'] },
            { pathname: '/\tunsafe', paths: ['/'] },
            { pathname: '/\x7funsafe', paths: ['/'] },
            { pathname: '/\u00e9', paths: ['/'] },
            {
                pathname: '/a/b/\u00e9',
                paths: ['/', '/a', '/a/', '/a/b', '/a/b/']
            },
            { pathname: '/a;b/c', paths: ['/'] },
            { pathname: '/a,b="c"\\d', paths: ['/', '/a,b="c"\\d'] },
            {
                pathname: '/a//b',
                paths: ['/', '/a', '/a/', '/a//', '/a//b']
            }
        ];

        for (const fixture of cases) {
            const harness = await initialized({
                pathname: fixture.pathname
            });
            const paths = harness.cookieWrites.map((write) =>
                /; Path=([^;]+);/.exec(write)?.[1]);

            assert.equal(harness.nodes['pow-status'].textContent,
                'Checking your browser.');
            assert.deepEqual(paths, fixture.paths);
            for (const pathValue of paths) {
                for (const byte of Buffer.from(pathValue, 'utf8')) {
                    assert.equal(byte >= 0x21 && byte <= 0x7e
                        && byte !== 0x3b, true);
                }
            }
        }
    });


test('unsafe complete paths still clear safe stale ancestors', async () => {
    const harness = await initialized({
        pathname: '/account/orders;view=full',
        cookies: [
            { name: proofName, value: 'root', path: '/' },
            { name: proofName, value: 'account', path: '/account' },
            { name: proofName, value: 'slash', path: '/account/' }
        ]
    });

    assert.equal(harness.document.cookie, '');
    assert.equal(harness.nodes['pow-status'].textContent,
        'Checking your browser.');
});


test('a proof cookie that survives cleanup fails closed', async () => {
    const harness = await initialized({
        cookies: [{
            name: proofName,
            value: 'shadow',
            path: '/',
            undeletable: true
        }]
    });

    assertFailure(harness);
    assert.equal(harness.cookieWrites.length, 1);
    assert.equal(harness.document.cookie, `${proofName}=shadow`);
});


test('controller does not reconstruct path or query before reload',
    async () => {
        const clock = clockFixture();
        const pathname = '/a//b;view=full';
        const search = '?next=%2Ftarget&x=1';
        const { harness } = await miningHarness(async () => {
            clock.advance(1);
            return Object.freeze({
                found: true,
                exhausted: false,
                counter: 34,
                nextCounter: null,
                attempts: 1
            });
        }, { clock, pathname, search });
        const before = {
            pathname: harness.location.pathname,
            search: harness.location.search
        };

        assert.deepEqual(before, { pathname, search });
        await harness.runNextTimer();
        assert.deepEqual({
            pathname: harness.location.pathname,
            search: harness.location.search
        }, before);
        assert.equal(harness.location.reloadCount, 1);
    });


test('primary KAT failure falls back once and full-digest mismatch is terminal',
    async () => {
        const clock = clockFixture();
        const fallback = await createControllerHarness({
            crypto: webcrypto,
            paramsText: validParams,
            performance: clock.performance
        });
        corruptSpecializedWorkspace(fallback.context);
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
            },
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
        corruptSpecializedWorkspace(failed.context);
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


test('failure retry navigates once and does not restart the controller',
    async () => {
        const harness = await initialized({ paramsText: '{}' });

        assertFailure(harness);
        await harness.nodes['pow-retry'].dispatch('click');
        await harness.nodes['pow-retry'].dispatch('click');
        assert.equal(harness.location.reloadCount, 1);
        assert.equal(harness.timers.length, 0);
    });


test('foreground slices are contiguous, adaptive, and time bounded',
    async () => {
        const calls = [];
        const clock = clockFixture();
        const { harness } = await miningHarness(async (
            _nonce, _difficulty, startCounter, maxAttempts, backend
        ) => {
            calls.push({ backend, maxAttempts, startCounter });
            clock.advance(1);
            return Object.freeze({
                found: false,
                exhausted: false,
                counter: null,
                nextCounter: startCounter + maxAttempts,
                attempts: maxAttempts
            });
        }, { clock });

        assert.equal(harness.timers.length, 1);
        await harness.runNextTimer();

        assert.equal(calls[0].startCounter, 0);
        assert.equal(calls[0].maxAttempts, 1);
        assert.equal(calls.every((call) => call.backend === 'js'), true);
        assert.equal(calls.some((call) => call.maxAttempts > 1), true);
        for (let index = 1; index < calls.length; index++) {
            assert.equal(calls[index].startCounter,
                calls[index - 1].startCounter
                    + calls[index - 1].maxAttempts);
        }
        assert.equal(harness.timers.length, 1);
        assert.equal(harness.timers[0].delay, 0);
        assert.ok(harness.nodes['pow-progress'].value > 0);
        assert.ok(harness.nodes['pow-progress'].value < 1);
    });


test('hidden pages pause without losing the next candidate', async () => {
    const starts = [];
    const clock = clockFixture();
    const { harness } = await miningHarness(async (
        _nonce, _difficulty, startCounter, maxAttempts
    ) => {
        starts.push(startCounter);
        clock.advance(10);
        return Object.freeze({
            found: false,
            exhausted: false,
            counter: null,
            nextCounter: startCounter + maxAttempts,
            attempts: maxAttempts
        });
    }, { clock });

    await harness.runNextTimer();
    const progress = harness.nodes['pow-progress'].value;
    harness.document.hidden = true;
    await harness.documentListeners.get('visibilitychange')();
    await harness.runNextTimer();
    assert.equal(starts.length, 1);
    assert.equal(harness.timers.length, 0);
    assert.equal(harness.nodes['pow-progress'].value, progress);

    harness.document.hidden = false;
    await harness.documentListeners.get('visibilitychange')();
    assert.equal(harness.timers.length, 1);
    await harness.runNextTimer();
    assert.equal(starts.length, 2);
    assert.equal(starts[1], 1);
    assert.equal(harness.nodes['pow-progress'].value >= progress, true);
});


test('visibility changes cannot start a second in-flight miner', async () => {
    const starts = [];
    const clock = clockFixture();
    let release;
    const gate = new Promise((resolve) => {
        release = resolve;
    });
    const { harness } = await miningHarness(async (
        _nonce, _difficulty, startCounter, maxAttempts
    ) => {
        starts.push(startCounter);
        await gate;
        clock.advance(10);
        return Object.freeze({
            found: false,
            exhausted: false,
            counter: null,
            nextCounter: startCounter + maxAttempts,
            attempts: maxAttempts
        });
    }, { clock });

    const pending = harness.runNextTimer();
    assert.deepEqual(starts, [0]);
    harness.document.hidden = true;
    await harness.documentListeners.get('visibilitychange')();
    harness.document.hidden = false;
    await harness.documentListeners.get('visibilitychange')();
    assert.equal(harness.timers.length, 0);

    release();
    await pending;
    assert.equal(harness.timers.length, 1);
    assert.deepEqual(starts, [0]);
});


test('progress uses probability and reaches one only on success', async () => {
    const clock = clockFixture();
    const { harness } = await miningHarness(async (
        _nonce, _difficulty, startCounter, maxAttempts
    ) => {
        clock.advance(10);
        return Object.freeze({
            found: false,
            exhausted: false,
            counter: null,
            nextCounter: startCounter + maxAttempts,
            attempts: maxAttempts
        });
    }, { clock });

    await harness.runNextTimer();
    assert.ok(Math.abs(harness.nodes['pow-progress'].value
        - (1 - Math.exp(-1 / 256))) < 1e-12);
    assert.ok(harness.nodes['pow-progress'].value < 1);
    assert.doesNotMatch(harness.nodes['pow-status'].textContent,
        /256|counter|backend|difficulty/i);
});


test('success writes the canonical proof cookie and reloads once',
    async () => {
        for (const [protocol, suffix] of [
            ['https:', '; Secure'],
            ['http:', '']
        ]) {
            const clock = clockFixture();
            const { harness } = await miningHarness(async () => {
                clock.advance(1);
                return Object.freeze({
                    found: true,
                    exhausted: false,
                    counter: 34,
                    nextCounter: null,
                    attempts: 1
                });
            }, { clock, protocol });

            await harness.runNextTimer();
            assert.equal(harness.cookieWrites.at(-1),
                `${proofName}=1.29333333.34; Path=/; SameSite=Lax${suffix}`);
            assert.equal(harness.document.cookie,
                `${proofName}=1.29333333.34`);
            assert.equal(harness.nodes['pow-progress'].value, 1);
            assert.equal(harness.location.reloadCount, 1);
            assert.equal(harness.timers.length, 0);
        }
    });


test('failed proof-cookie readback never reloads', async () => {
    for (const mode of ['blocked', 'duplicate']) {
        const clock = clockFixture();
        const { harness } = await miningHarness(async () => {
            clock.advance(1);
            return Object.freeze({
                found: true,
                exhausted: false,
                counter: 34,
                nextCounter: null,
                attempts: 1
            });
        }, {
            blockCookieWrites: mode === 'blocked',
            clock,
            pathname: mode === 'duplicate' ? '/deep' : '/'
        });

        if (mode === 'duplicate') {
            harness.cookieEntries.push({
                name: proofName,
                value: 'shadow',
                path: '/deep',
                secure: false,
                undeletable: true
            });
        }

        await harness.runNextTimer();
        assertFailure(harness);
        assert.equal(harness.location.reloadCount, 0);
        assert.equal(harness.timers.length, 0);
    }
});


test('a mining rejection is terminal and does not switch backends',
    async () => {
        let calls = 0;
        const { harness } = await miningHarness(async () => {
            calls++;
            throw new Error('mining failed');
        });

        await harness.runNextTimer();
        assert.equal(calls, 1);
        assertFailure(harness);
        assert.equal(harness.timers.length, 0);
    });
