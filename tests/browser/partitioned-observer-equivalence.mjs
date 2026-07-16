import assert from 'node:assert/strict';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
    runPartitionedTrials,
} from './lib/partitioned-trials.mjs';

const TRIAL_FIELDS = Object.freeze([
    'backend_count',
    'initial_document_visible',
    'initial_request_present',
    'navigation_count',
    'partitioned_cookie_stored',
    'post_cleanup_document_visible',
    'post_cleanup_storage_present',
    'solve_calls',
    'terminal',
]);
const SNAPSHOT_FIELDS = Object.freeze([
    'descriptorValid',
    'exportsValid',
    'namespaceAssignments',
    'namespaceFrozen',
    'phase',
    'solverCalls',
]);


function validateTrial(trial) {
    if (trial === null || typeof trial !== 'object' || Array.isArray(trial)
        || Object.keys(trial).sort().join(',') !== TRIAL_FIELDS.join(',')) {
        throw new TypeError('invalid partitioned trial record');
    }
    const booleans = [
        'initial_document_visible',
        'initial_request_present',
        'partitioned_cookie_stored',
        'post_cleanup_document_visible',
        'post_cleanup_storage_present',
    ];
    if (!booleans.every((field) => typeof trial[field] === 'boolean')
        || !['backend_count', 'navigation_count', 'solve_calls'].every(
            (field) => Number.isSafeInteger(trial[field])
                && trial[field] >= 0,
        )
        || !['backend', 'failure'].includes(trial.terminal)) {
        throw new TypeError('invalid partitioned trial record');
    }
}


function validateSnapshot(snapshot) {
    if (snapshot === null || typeof snapshot !== 'object'
        || Array.isArray(snapshot)
        || Object.keys(snapshot).sort().join(',')
            !== SNAPSHOT_FIELDS.join(',')
        || !Number.isSafeInteger(snapshot.namespaceAssignments)
        || snapshot.namespaceAssignments < 0
        || !Number.isSafeInteger(snapshot.solverCalls)
        || snapshot.solverCalls < 0
        || !['assigned', 'installed', 'waiting'].includes(snapshot.phase)
        || !['descriptorValid', 'exportsValid', 'namespaceFrozen'].every(
            (field) => typeof snapshot[field] === 'boolean',
        )) {
        throw new TypeError('invalid partitioned observer snapshot');
    }
}


export function buildObserverEquivalence(control, observed, snapshot) {
    validateTrial(control);
    validateTrial(observed);
    validateSnapshot(snapshot);
    const cookieFields = [
        'initial_document_visible',
        'initial_request_present',
        'partitioned_cookie_stored',
        'post_cleanup_document_visible',
        'post_cleanup_storage_present',
    ];
    const cookieStateMatches = cookieFields.every((field) =>
        control[field] === true && observed[field] === true);

    return Object.freeze({
        challengePhaseNavigationCountMatches:
            control.navigation_count === 1 && observed.navigation_count === 1,
        cookieStateMatches,
        namespaceAssignments: snapshot.namespaceAssignments,
        observerDescriptorValid: snapshot.descriptorValid,
        observerExportsValid: snapshot.exportsValid,
        observerNamespaceFrozen: snapshot.namespaceFrozen,
        solverCalls: snapshot.solverCalls,
        terminalStateMatches: control.terminal === 'failure'
            && observed.terminal === 'failure'
            && control.backend_count === 0 && observed.backend_count === 0,
    });
}


export async function runPartitionedObserverEquivalence() {
    const trials = await runPartitionedTrials({
        target: 'test-browser-partitioned-observer-equivalence',
    });
    const verdict = buildObserverEquivalence(
        trials.control, trials.observed, trials.observerSnapshot,
    );
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
    return verdict;
}


async function main() {
    const verdict = await runPartitionedObserverEquivalence();
    process.stdout.write(`${JSON.stringify(verdict)}\n`);
}


if (process.argv[1] !== undefined
    && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
    try {
        await main();
    } catch (_error) {
        process.stderr.write('partitioned-observer-equivalence: failed\n');
        process.exitCode = 1;
    }
}
