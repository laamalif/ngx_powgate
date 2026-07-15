import assert from 'node:assert/strict';
import test from 'node:test';

import { positiveCases } from './e2e.mjs';


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
