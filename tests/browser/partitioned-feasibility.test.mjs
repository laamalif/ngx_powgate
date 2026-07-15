import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';

import {
    buildPartitionedVerdict,
    countExactProofs,
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
