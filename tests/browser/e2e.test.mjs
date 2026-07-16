import assert from 'node:assert/strict';
import test from 'node:test';

import {
    buildCombinedMatrixResult,
    buildMatrixResult,
    buildNormalMatrixResult,
    partitionedNegativeCase,
    positiveCases,
} from './e2e.mjs';


test('positive browser matrix freezes exact URL and request-target bytes', () => {
    const cases = positiveCases();

    assert.equal(Object.isFrozen(cases), true);
    assert.deepEqual(cases.map((row) => ({
        id: row.id,
        target: row.target,
        pathname: row.pathname,
        search: row.search,
        stalePath: row.stalePath,
        requestTargetHex: row.expectedRequestTarget.toString('hex'),
    })), [
        {
            id: 'root',
            target: '/',
            pathname: '/',
            search: '',
            stalePath: null,
            requestTargetHex: Buffer.from('/', 'ascii').toString('hex'),
        },
        {
            id: 'literal-semicolon',
            target: '/account;view=full?mode=literal&value=1',
            pathname: '/account;view=full',
            search: '?mode=literal&value=1',
            stalePath: null,
            requestTargetHex: Buffer.from(
                '/account;view=full?mode=literal&value=1', 'ascii',
            ).toString('hex'),
        },
        {
            id: 'encoded-repeat',
            target: '/a%3Bb//c?mode=encoded&value=%2F',
            pathname: '/a%3Bb//c',
            search: '?mode=encoded&value=%2F',
            stalePath: null,
            requestTargetHex: Buffer.from(
                '/a%3Bb//c?mode=encoded&value=%2F', 'ascii',
            ).toString('hex'),
        },
        {
            id: 'stale-safe',
            target: '/account/orders?mode=stale',
            pathname: '/account/orders',
            search: '?mode=stale',
            stalePath: '/account',
            requestTargetHex: Buffer.from(
                '/account/orders?mode=stale', 'ascii',
            ).toString('hex'),
        },
    ]);

    for (const row of cases) {
        assert.equal(Object.isFrozen(row), true);
        assert.equal(Buffer.isBuffer(row.expectedRequestTarget), true);
        assert.equal(
            row.expectedRequestTarget.equals(Buffer.from(row.target, 'ascii')),
            true,
        );
    }
});


test('partitioned negative case freezes the challenge-phase target', () => {
    const testCase = partitionedNegativeCase();

    assert.equal(Object.isFrozen(testCase), true);
    assert.deepEqual({
        id: testCase.id,
        requestTargetHex: testCase.expectedRequestTarget.toString('hex'),
        target: testCase.target,
    }, {
        id: 'partitioned-fail-closed',
        requestTargetHex: Buffer.from(
            '/partitioned-feasibility', 'ascii',
        ).toString('hex'),
        target: '/partitioned-feasibility',
    });
});


test('normal matrix result requires eight positive and two negative cases', () => {
    assert.deepEqual(buildNormalMatrixResult(8, 2), {
        normalPartitionedNegative: 2,
        normalPositive: 8,
        normalTotal: 10,
        verdict: 'passed',
    });
    assert.throws(
        () => buildNormalMatrixResult(8, 1),
        /incomplete normal browser matrix/,
    );
});


test('sanitized and combined results require the identical ten-case matrix', () => {
    const normal = buildMatrixResult('normal', 8, 2);
    const sanitized = buildMatrixResult('sanitized', 8, 2);

    assert.deepEqual(sanitized, {
        sanitizedPartitionedNegative: 2,
        sanitizedPositive: 8,
        sanitizedTotal: 10,
        verdict: 'passed',
    });
    assert.deepEqual(buildCombinedMatrixResult(normal, sanitized), {
        combinedTotal: 20,
        normalPartitionedNegative: 2,
        normalPositive: 8,
        normalTotal: 10,
        sanitizedPartitionedNegative: 2,
        sanitizedPositive: 8,
        sanitizedTotal: 10,
        verdict: 'passed',
    });
    assert.throws(
        () => buildMatrixResult('sanitized', 8, 1),
        /incomplete sanitized browser matrix/,
    );
});
