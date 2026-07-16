import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const HEX = /^[0-9a-fA-F]$/;
const SHORT_ESCAPES = Object.freeze({
    b: 0x08,
    f: 0x0c,
    n: 0x0a,
    r: 0x0d,
    t: 0x09,
});


function decodeEscapedByte(text, offset) {
    const escape = text[offset + 1];

    if (escape === '"') {
        return { byte: 0x22, next: offset + 2 };
    }

    if (escape === '\\') {
        return { byte: 0x5c, next: offset + 2 };
    }

    if (Object.hasOwn(SHORT_ESCAPES, escape)) {
        return { byte: SHORT_ESCAPES[escape], next: offset + 2 };
    }

    if (escape !== 'u'
        || text.slice(offset + 2, offset + 4) !== '00'
        || text.length < offset + 6
        || !HEX.test(text[offset + 4])
        || !HEX.test(text[offset + 5]))
    {
        throw new TypeError('invalid NGINX JSON log escape');
    }

    return {
        byte: Number.parseInt(text.slice(offset + 4, offset + 6), 16),
        next: offset + 6,
    };
}


export function decodeNginxJsonLogString(text) {
    if (typeof text !== 'string') {
        throw new TypeError('NGINX JSON log value must be a string');
    }

    const parts = [];
    let literalStart = 0;
    let offset = 0;

    while (offset < text.length) {
        const code = text.charCodeAt(offset);

        if (code === 0x5c) {
            if (literalStart < offset) {
                parts.push(Buffer.from(text.slice(literalStart, offset), 'utf8'));
            }

            const decoded = decodeEscapedByte(text, offset);
            parts.push(Buffer.from([decoded.byte]));
            offset = decoded.next;
            literalStart = offset;
            continue;
        }

        if (code < 0x20) {
            throw new TypeError('unescaped control byte in NGINX JSON log value');
        }

        offset++;
    }

    if (literalStart < text.length) {
        parts.push(Buffer.from(text.slice(literalStart), 'utf8'));
    }

    return Buffer.concat(parts);
}


async function proofOccurrenceCount(scannerPath, cookieBytes) {
    const { stdout, stderr } = await execFileAsync(
        scannerPath,
        [cookieBytes.toString('hex')],
        {
            encoding: 'utf8',
            maxBuffer: 1024,
            windowsHide: true,
        },
    );

    if (stderr !== '') {
        throw new Error('cookie scanner emitted diagnostics');
    }

    let result;

    try {
        result = JSON.parse(stdout);
    } catch (_error) {
        throw new Error('cookie scanner returned invalid JSON');
    }

    if (result === null
        || typeof result !== 'object'
        || Array.isArray(result)
        || Object.keys(result).length !== 1
        || !Number.isSafeInteger(result.count)
        || result.count < 0)
    {
        throw new Error('cookie scanner returned an invalid count');
    }

    return result.count;
}


export async function observeRequest(record) {
    if (record === null || typeof record !== 'object') {
        throw new TypeError('request observation must be an object');
    }

    if (record.effectiveCookieFieldCount !== 1) {
        throw new Error('request must contain exactly one effective Cookie field');
    }

    if (!Buffer.isBuffer(record.expectedRequestUri)) {
        throw new TypeError('expected request URI must be bytes');
    }

    if (typeof record.scannerPath !== 'string' || record.scannerPath === '') {
        throw new TypeError('cookie scanner path is required');
    }

    const requestUri = decodeNginxJsonLogString(record.requestUri);
    const cookie = decodeNginxJsonLogString(record.cookie);
    const count = await proofOccurrenceCount(record.scannerPath, cookie);

    return Object.freeze({
        proofOccurrenceCount: count,
        requestUriMatches: requestUri.equals(record.expectedRequestUri),
        singleEffectiveCookieField: true,
    });
}
