import assert from 'node:assert/strict';
import test from 'node:test';

import {
    buildObserverEquivalence,
} from './partitioned-observer-equivalence.mjs';


const CONTROL = Object.freeze({
    backend_count: 0,
    initial_document_visible: true,
    initial_request_present: true,
    navigation_count: 1,
    partitioned_cookie_stored: true,
    post_cleanup_document_visible: true,
    post_cleanup_storage_present: true,
    solve_calls: 0,
    terminal: 'failure',
});
const SNAPSHOT = Object.freeze({
    descriptorValid: true,
    exportsValid: true,
    namespaceAssignments: 1,
    namespaceFrozen: true,
    phase: 'installed',
    solverCalls: 0,
});


test('observer equivalence freezes the complete permanent contract', () => {
    const verdict = buildObserverEquivalence(CONTROL, CONTROL, SNAPSHOT);

    assert.equal(Object.isFrozen(verdict), true);
    assert.deepEqual(verdict, {
        challengePhaseNavigationCountMatches: true,
        cookieStateMatches: true,
        namespaceAssignments: 1,
        observerDescriptorValid: true,
        observerExportsValid: true,
        observerNamespaceFrozen: true,
        solverCalls: 0,
        terminalStateMatches: true,
    });
});


test('observer equivalence exposes a mismatched control as a failed verdict', () => {
    const verdict = buildObserverEquivalence(CONTROL, {
        ...CONTROL,
        post_cleanup_document_visible: false,
    }, SNAPSHOT);

    assert.equal(verdict.cookieStateMatches, false);
    assert.equal(verdict.terminalStateMatches, true);
});


test('observer equivalence rejects malformed records', () => {
    assert.throws(
        () => buildObserverEquivalence(CONTROL, CONTROL, {
            ...SNAPSHOT,
            namespaceAssignments: -1,
        }),
        /invalid partitioned observer snapshot/,
    );
    assert.throws(
        () => buildObserverEquivalence(CONTROL, {
            ...CONTROL,
            extra: true,
        }, SNAPSHOT),
        /invalid partitioned trial record/,
    );
});
