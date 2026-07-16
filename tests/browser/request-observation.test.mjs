import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import test from 'node:test';

import {
    decodeNginxJsonLogString,
    observeRequest,
} from './lib/request-observation.mjs';

const execFileAsync = promisify(execFile);
const scannerPath = 'build/browser-tools/cookie-occurrences';


async function scan(field) {
    const { stdout, stderr } = await execFileAsync(
        scannerPath,
        [Buffer.from(field).toString('hex')],
        { encoding: 'utf8' },
    );

    assert.equal(stderr, '');
    return JSON.parse(stdout).count;
}


test('production scanner CLI counts exact proof-cookie occurrences', async () => {
    const cases = [
        { field: Buffer.alloc(0), count: 0 },
        { field: Buffer.from('__pow_p=one'), count: 1 },
        { field: Buffer.from('__pow_p='), count: 1 },
        { field: Buffer.from('__pow_p_extra=x; __pow_p=y'), count: 1 },
        { field: Buffer.from('x__pow_p=x; __pow_p=y'), count: 1 },
        { field: Buffer.from(' ;\t__pow_p=a;; __pow_p=b'), count: 2 },
        { field: Buffer.from('__pow_p =x; __pow_p= y'), count: 1 },
        { field: Buffer.from('__pow=a; __pow=b; __pow=c; __pow=d'), count: 0 },
        {
            field: Buffer.from([
                0xff, 0x3b, 0x20, 0x5f, 0x5f, 0x70, 0x6f, 0x77,
                0x5f, 0x70, 0x3d, 0x80,
            ]),
            count: 1,
        },
    ];

    for (const row of cases) {
        assert.equal(await scan(row.field), row.count, row.field.toString('hex'));
    }
});


test('scanner CLI rejects malformed hexadecimal input', async () => {
    for (const value of ['0', 'gg', '00ffz0', '00'.repeat(8193)]) {
        await assert.rejects(execFileAsync(scannerPath, [value]));
    }
});


test('NGINX JSON log strings decode to exact bytes before scanning', () => {
    const cases = [
        { encoded: '', expected: Buffer.alloc(0) },
        { encoded: String.raw`quote\"slash\\`, expected: Buffer.from('quote"slash\\') },
        {
            encoded: String.raw`\u0000\u0009\u001f\u007f`,
            expected: Buffer.from([0x00, 0x09, 0x1f, 0x7f]),
        },
        {
            encoded: String.raw`\b\f\n\r\t`,
            expected: Buffer.from([0x08, 0x0c, 0x0a, 0x0d, 0x09]),
        },
        { encoded: 'é', expected: Buffer.from([0xc3, 0xa9]) },
        {
            encoded: String.raw`__pow_p=\u0001x`,
            expected: Buffer.from('__pow_p=\x01x'),
        },
    ];

    for (const row of cases) {
        assert.deepEqual(decodeNginxJsonLogString(row.encoded), row.expected);
    }

    for (const invalid of [String.raw`\u0100`, '\\', String.raw`\x20`]) {
        assert.throws(() => decodeNginxJsonLogString(invalid));
    }
});


test('request observation retains verdicts and uses decoded cookie bytes', async () => {
    const result = await observeRequest({
        requestUri: String.raw`/a%3Bb//c?value=%2F`,
        expectedRequestUri: Buffer.from('/a%3Bb//c?value=%2F', 'ascii'),
        cookie: String.raw`x=\u0001; __pow_p=proof`,
        effectiveCookieFieldCount: 1,
        scannerPath,
    });

    assert.deepEqual(result, {
        proofOccurrenceCount: 1,
        requestUriMatches: true,
        singleEffectiveCookieField: true,
    });
    assert.equal(
        Object.values(result).some((value) => typeof value === 'string'),
        false,
    );
});


test('request observation fails rather than merging Cookie fields', async () => {
    for (const count of [0, 2, 3]) {
        await assert.rejects(observeRequest({
            requestUri: '/',
            expectedRequestUri: Buffer.from('/'),
            cookie: '__pow_p=x',
            effectiveCookieFieldCount: count,
            scannerPath,
        }), /exactly one effective Cookie field/);
    }
});
