import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';

import {
    PARTITIONED_PROOF_FIXTURE,
    classifyPartitionedCookies,
    partitionedCookieMatchesFixture,
    partitionedObserverBootstrap,
} from './lib/partitioned-proof.mjs';


function fixtureCookie(overrides = {}) {
    return {
        domain: 'gate.powgate.test',
        expires: -1,
        httpOnly: false,
        name: '__pow_p',
        partitionKey: {
            hasCrossSiteAncestor: false,
            sourceOrigin: 'https://powgate.test',
        },
        path: '/',
        sameSite: 'Lax',
        secure: true,
        session: true,
        value: '1.0.0',
        ...overrides,
    };
}


function observerContext(namespaceSource = `Object.freeze({
    sha256() {},
    solve() { return globalThis.originalPromise; },
})`) {
    const context = vm.createContext({});

    vm.runInContext(`
        globalThis.listeners = Object.create(null);
        globalThis.document = {
            addEventListener(name, listener) {
                globalThis.listeners[name] = listener;
            },
        };
        globalThis.originalPromise = Promise.resolve('ok');
        (${partitionedObserverBootstrap.toString()})();
        globalThis.PowGateSolver = ${namespaceSource};
    `, context);
    return context;
}


test('partitioned fixture freezes the exact proven cookie representation', () => {
    assert.deepEqual(PARTITIONED_PROOF_FIXTURE, {
        challengePath: '/partitioned-feasibility',
        expectedCookie: {
            domain: 'gate.powgate.test',
            expires: -1,
            httpOnly: false,
            partitionKey: {
                hasCrossSiteAncestor: false,
                sourceOrigin: 'https://powgate.test',
            },
            path: '/',
            sameSite: 'Lax',
            secure: true,
            session: true,
        },
        name: '__pow_p',
        seedPath: '/__powgate_partitioned_seed',
        setCookie: '__pow_p=1.0.0; Path=/; Secure; SameSite=Lax; Partitioned',
        value: '1.0.0',
    });
    assert.equal(Object.isFrozen(PARTITIONED_PROOF_FIXTURE), true);
    assert.equal(Object.isFrozen(PARTITIONED_PROOF_FIXTURE.expectedCookie), true);
    assert.equal(Object.isFrozen(
        PARTITIONED_PROOF_FIXTURE.expectedCookie.partitionKey,
    ), true);
});


test('partitioned fixture matcher requires exact structured metadata', () => {
    assert.equal(partitionedCookieMatchesFixture(fixtureCookie()), true);
    assert.equal(partitionedCookieMatchesFixture(fixtureCookie({
        partitionKey: 'https://powgate.test',
    })), false);
    assert.equal(partitionedCookieMatchesFixture(fixtureCookie({
        partitionKey: {
            hasCrossSiteAncestor: true,
            sourceOrigin: 'https://powgate.test',
        },
    })), false);
    assert.equal(partitionedCookieMatchesFixture(fixtureCookie({
        path: '/other',
    })), false);
});


test('partitioned cookie classification separates every replacement scope', () => {
    assert.deepEqual(classifyPartitionedCookies(
        [fixtureCookie()], [], 'PowAuth',
    ), {
        authCookieCount: 0,
        newPartitionedProofCount: 0,
        originalPartitionedProofCount: 1,
        unpartitionedProofCount: 0,
    });
    assert.deepEqual(classifyPartitionedCookies([
        fixtureCookie(),
        fixtureCookie({ partitionKey: undefined, value: '1.1.1' }),
        fixtureCookie({ path: '/other', value: '1.2.2' }),
        { ...fixtureCookie(), name: 'PowAuth', partitionKey: undefined },
    ], [], 'PowAuth'), {
        authCookieCount: 1,
        newPartitionedProofCount: 1,
        originalPartitionedProofCount: 1,
        unpartitionedProofCount: 1,
    });
    assert.throws(
        () => classifyPartitionedCookies([fixtureCookie()], [fixtureCookie()],
            'PowAuth'),
        /partitioned proof cookie is not host-only/,
    );
});


test('partitioned observer preserves namespace behavior and final descriptor', async () => {
    const context = observerContext();

    assert.deepEqual({ ...vm.runInContext(
        '__powgatePartitionedObserver.snapshot()', context,
    ) }, {
        descriptorValid: false,
        exportsValid: true,
        namespaceAssignments: 1,
        namespaceFrozen: true,
        phase: 'assigned',
        solverCalls: 0,
    });
    vm.runInContext('globalThis.returned = PowGateSolver.solve()', context);
    assert.equal(vm.runInContext('returned === originalPromise', context), true);
    vm.runInContext('listeners.DOMContentLoaded()', context);
    assert.deepEqual({ ...vm.runInContext(
        '__powgatePartitionedObserver.snapshot()', context,
    ) }, {
        descriptorValid: true,
        exportsValid: true,
        namespaceAssignments: 1,
        namespaceFrozen: true,
        phase: 'installed',
        solverCalls: 1,
    });
    assert.deepEqual({ ...vm.runInContext(`(() => {
        const descriptor = Object.getOwnPropertyDescriptor(
            globalThis, 'PowGateSolver',
        );
        return {
            configurable: descriptor.configurable,
            enumerable: descriptor.enumerable,
            writable: descriptor.writable,
        };
    })()`, context) }, {
        configurable: true,
        enumerable: true,
        writable: true,
    });
    await vm.runInContext('returned', context);
});


test('partitioned observer rejects repeated and malformed assignment', () => {
    const repeated = observerContext();

    assert.throws(
        () => vm.runInContext(
            'globalThis.PowGateSolver = Object.freeze({sha256() {}, solve() {}})',
            repeated,
        ),
        /assigned more than once/,
    );
    assert.throws(
        () => observerContext('Object.freeze({sha256() {}})'),
        /invalid PowGateSolver namespace/,
    );
});


test('partitioned observer preserves thrown exception identity', () => {
    const context = observerContext(`Object.freeze({
        sha256() {},
        solve() { throw globalThis.sentinel; },
    })`);

    vm.runInContext('globalThis.sentinel = Object.freeze({code: 7})', context);
    assert.equal(vm.runInContext(`(() => {
        try {
            PowGateSolver.solve();
        } catch (error) {
            return error === sentinel;
        }
        return false;
    })()`, context), true);
});
