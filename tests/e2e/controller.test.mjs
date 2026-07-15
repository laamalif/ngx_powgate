import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import test from 'node:test';

import {
    createControllerHarness,
    readChallengePage
} from './lib/challenge-script.mjs';


const validParams = JSON.stringify({
    v: 1,
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
                { name: '__pow_p', value: 'root', path: '/' },
                { name: '__pow_p', value: 'alpha', path: '/alpha' },
                { name: '__pow_p', value: 'slash', path: '/alpha/' },
                { name: '__pow_p', value: 'exact', path: '/alpha/beta' },
                { name: '__pow_p_old', value: 'keep', path: '/' }
            ]
        });

        assert.deepEqual(harness.cookieWrites, [
            '__pow_p=; Max-Age=0; Path=/; SameSite=Lax; Secure',
            '__pow_p=; Max-Age=0; Path=/alpha; SameSite=Lax; Secure',
            '__pow_p=; Max-Age=0; Path=/alpha/; SameSite=Lax; Secure',
            '__pow_p=; Max-Age=0; Path=/alpha/beta; SameSite=Lax; Secure'
        ]);
        assert.equal(harness.document.cookie, '__pow_p_old=keep');
        assert.equal(harness.nodes['pow-status'].textContent,
            'Checking your browser.');
    });


test('HTTP cleanup omits Secure and unsafe schemes or paths fail',
    async () => {
        const http = await initialized({ protocol: 'http:' });
        assert.equal(http.cookieWrites[0],
            '__pow_p=; Max-Age=0; Path=/; SameSite=Lax');

        for (const options of [
            { protocol: 'file:' },
            { pathname: 'relative' },
            { pathname: '/bad;path' },
            { pathname: '/bad\tpath' }
        ]) {
            const harness = await initialized(options);
            assertFailure(harness);
            assert.equal(harness.cookieWrites.length, 0);
        }
    });


test('a proof cookie that survives cleanup fails closed', async () => {
    const harness = await initialized({
        cookies: [{
            name: '__pow_p',
            value: 'shadow',
            path: '/',
            undeletable: true
        }]
    });

    assertFailure(harness);
    assert.equal(harness.cookieWrites.length, 1);
    assert.equal(harness.document.cookie, '__pow_p=shadow');
});


test('primary KAT failure falls back once and dual failure is terminal',
    async () => {
        const fallback = await createControllerHarness({
            crypto: webcrypto,
            paramsText: validParams
        });
        const original = fallback.context.PowGateSolver;
        fallback.context.PowGateSolver = Object.freeze({
            sha256() {
                return new Uint8Array(32).fill(0xff);
            },
            solve: original.solve
        });
        await fallback.runNextTimer();
        assert.equal(fallback.nodes['pow-status'].textContent,
            'Checking your browser.');

        const badCrypto = {
            subtle: {
                async digest() {
                    return new Uint8Array(32).fill(0xff).buffer;
                }
            }
        };
        const failed = await createControllerHarness({
            crypto: badCrypto,
            paramsText: validParams
        });
        const failedOriginal = failed.context.PowGateSolver;
        failed.context.PowGateSolver = Object.freeze({
            sha256() {
                return new Uint8Array(32).fill(0xff);
            },
            solve: failedOriginal.solve
        });
        await failed.runNextTimer();
        assertFailure(failed);
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
                '__pow_p=1.29333333.34; Path=/; SameSite=Lax' + suffix);
            assert.equal(harness.document.cookie, '__pow_p=1.29333333.34');
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
                name: '__pow_p',
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
