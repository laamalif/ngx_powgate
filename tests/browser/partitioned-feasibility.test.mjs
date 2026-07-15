import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';

import {
    buildPartitionedVerdict,
    countExactProofs,
    observerBootstrap,
    partitionedAcceptance,
} from './partitioned-feasibility.mjs';


const REACHABLE = Object.freeze({
    backend_count: 0,
    initial_document_visible: true,
    initial_request_present: true,
    navigation_count: 1,
    observer_control_matches: true,
    partitioned_cookie_stored: true,
    post_cleanup_document_visible: true,
    post_cleanup_storage_present: true,
    solver_calls: 0,
});


test('partitioned acceptance requires the complete fail-closed tuple', () => {
    assert.equal(partitionedAcceptance(REACHABLE), true);
    assert.equal(partitionedAcceptance({
        ...REACHABLE,
        post_cleanup_document_visible: false,
    }), false);
    assert.equal(partitionedAcceptance({
        ...REACHABLE,
        solver_calls: 1,
    }), false);
    assert.equal(partitionedAcceptance({
        ...REACHABLE,
        navigation_count: 2,
    }), false);
});


test('partitioned verdict is frozen and has only fixed fields', () => {
    const verdict = buildPartitionedVerdict(REACHABLE);

    assert.equal(Object.isFrozen(verdict), true);
    assert.deepEqual(Object.keys(verdict).sort(), [
        'acceptance_reached',
        'backend_count',
        'initial_document_visible',
        'initial_request_present',
        'navigation_count',
        'observer_control_matches',
        'partitioned_cookie_stored',
        'post_cleanup_document_visible',
        'post_cleanup_storage_present',
        'solver_calls',
    ]);
    assert.equal(verdict.acceptance_reached, true);
});


test('partitioned verdict rejects malformed observations', () => {
    assert.throws(
        () => buildPartitionedVerdict({ ...REACHABLE, extra: true }),
        /invalid partitioned feasibility observations/,
    );
    assert.throws(
        () => buildPartitionedVerdict({ ...REACHABLE, solver_calls: -1 }),
        /invalid partitioned feasibility observations/,
    );
    assert.throws(
        () => buildPartitionedVerdict({
            ...REACHABLE,
            initial_document_visible: 1,
        }),
        /invalid partitioned feasibility observations/,
    );
});


test('page cookie counter is self-contained production-page code', () => {
    const count = vm.runInNewContext(
        `(${countExactProofs.toString()})(cookie)`,
        { cookie: 'a=1; __pow_p=1.0.0; __pow_p_old=2' },
    );

    assert.equal(count, 1);
});


test('observer bootstrap reports installation without enumerable exports', () => {
    const context = vm.createContext({});
    vm.runInContext(`
        globalThis.__powgateSpikeSolveCall = () => {};
        globalThis.document = {
            getElementById(id) {
                return id === 'pow-params' ? {} : null;
            },
            addEventListener(_name, listener) {
                globalThis.listener = listener;
            },
        };
        globalThis.PowGateSolver = Object.freeze({
            sha256() {},
            solve() { return Promise.resolve(); },
        });
    `, context);
    vm.runInContext(`(${observerBootstrap.toString()})()`, context);

    assert.equal(vm.runInContext(
        'Object.prototype.propertyIsEnumerable.call('
        + 'globalThis, "__powgateSpikeObserver")', context,
    ), false);
    assert.equal(vm.runInContext(
        '__powgateSpikeObserver.snapshot().phase', context,
    ), 'waiting');
    vm.runInContext('listener()', context);
    assert.deepEqual({ ...vm.runInContext(
        '__powgateSpikeObserver.snapshot()', context,
    ) }, {
        descriptorValid: true,
        exportsValid: true,
        namespaceFrozen: true,
        phase: 'installed',
    });
});
