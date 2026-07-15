import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
    extractExecutableScript,
    readChallengeScript,
} from '../e2e/lib/challenge-script.mjs';
import {
    BrowserTestFailure,
    withDeadline,
    withFixture,
} from './lib/fixture.mjs';
import {
    decodeNginxJsonLogString,
    observeRequest,
} from './lib/request-observation.mjs';
import { DEADLINES } from './lib/constants.mjs';
import {
    PARTITIONED_PROOF_FIXTURE,
    classifyPartitionedCookies,
    countExactProofCookies,
    partitionedCookieMatchesFixture,
    partitionedObserverBootstrap,
    partitionedObserverSnapshot,
} from './lib/partitioned-proof.mjs';

const AUTH_COOKIE_NAME = 'PowAuth';
const PROOF_COOKIE_NAME = '__pow_p';
const BACKEND_BODY = 'powgate backend ok\n';
const SECRET_HEX = '000102030405060708090a0b0c0d0e0f'
    + '101112131415161718191a1b1c1d1e1f';
const EXPECTED_CSP_PREFIX = "default-src 'none'; base-uri 'none'; "
    + "form-action 'none'; frame-ancestors 'none'; script-src 'sha256-";
const EXPECTED_CSP_SUFFIX = "'; style-src 'unsafe-inline'";
const ALLOWED_RESPONSE_HEADERS = new Set([
    'cache-control',
    'connection',
    'content-length',
    'content-security-policy',
    'content-type',
    'date',
    'powgate-challenge',
    'server',
    'set-cookie',
    'transfer-encoding',
    'x-robots-tag',
]);
const REQUEST_LOG_PATTERN = /^\{"request_uri":"((?:\\.|[^"\\])*)","cookie":"((?:\\.|[^"\\])*)","status":([0-9]{3})\}$/u;
const SCANNER_PATH = path.resolve('build/browser-tools/cookie-occurrences');

let currentOperation = 'initialization';


function frozenCase(id, target, pathname, search, stalePath = null) {
    return Object.freeze({
        id,
        target,
        pathname,
        search,
        stalePath,
        expectedRequestTarget: Buffer.from(target, 'ascii'),
    });
}


const POSITIVE_CASES = Object.freeze([
    frozenCase('root', '/', '/', ''),
    frozenCase(
        'literal-semicolon',
        '/account;view=full?mode=literal&value=1',
        '/account;view=full',
        '?mode=literal&value=1',
    ),
    frozenCase(
        'encoded-repeat',
        '/a%3Bb//c?mode=encoded&value=%2F',
        '/a%3Bb//c',
        '?mode=encoded&value=%2F',
    ),
    frozenCase(
        'stale-safe',
        '/account/orders?mode=stale',
        '/account/orders',
        '?mode=stale',
        '/account',
    ),
]);
const PARTITIONED_NEGATIVE_CASE = Object.freeze({
    expectedRequestTarget: Buffer.from(
        PARTITIONED_PROOF_FIXTURE.challengePath, 'ascii',
    ),
    id: 'partitioned-fail-closed',
    target: PARTITIONED_PROOF_FIXTURE.challengePath,
});

export function positiveCases() {
    return POSITIVE_CASES;
}


export function partitionedNegativeCase() {
    return PARTITIONED_NEGATIVE_CASE;
}


export function buildNormalMatrixResult(positive, partitionedNegative) {
    if (positive !== 8 || partitionedNegative !== 2) {
        throw new Error('incomplete normal browser matrix');
    }
    return Object.freeze({
        normalPartitionedNegative: partitionedNegative,
        normalPositive: positive,
        normalTotal: positive + partitionedNegative,
        verdict: 'passed',
    });
}


async function renderNginxConfiguration({ paths, ports, modulePath }) {
    const secretPath = path.join(paths.root, 'powgate.secret');
    const requestLog = path.join(paths.logs, 'request-observation.log');
    const backendLog = path.join(paths.logs, 'backend-count.log');

    await fs.writeFile(secretPath, `${SECRET_HEX}\n`, { mode: 0o600 });

    return `load_module ${modulePath};
worker_processes 1;
pid ${paths.nginxPid};
error_log ${paths.nginxErrorLog} notice;
events { worker_connections 256; }
http {
    log_format powgate_browser escape=json '{"request_uri":"$request_uri","cookie":"$http_cookie","status":$status}';
    log_format powgate_backend '$status';
    pow_secret_file ${secretPath};
    client_body_temp_path ${paths.clientBodyTemp};
    proxy_temp_path ${paths.proxyTemp};
    fastcgi_temp_path ${paths.fastcgiTemp};
    uwsgi_temp_path ${paths.uwsgiTemp};
    scgi_temp_path ${paths.scgiTemp};
    server {
        listen 127.0.0.1:${ports.backend};
        access_log ${backendLog} powgate_backend;
        location / {
            default_type text/plain;
            return 200 "${BACKEND_BODY.replace('\n', '\\n')}";
        }
    }
    server {
        listen 127.0.0.1:${ports.https} ssl;
        http2 on;
        merge_slashes off;
        ssl_certificate ${paths.certificate};
        ssl_certificate_key ${paths.privateKey};
        access_log ${requestLog} powgate_browser;
        location = /__powgate_ready { access_log off; return 204; }
        location = ${PARTITIONED_PROOF_FIXTURE.seedPath} {
            access_log off;
            add_header Set-Cookie "${PARTITIONED_PROOF_FIXTURE.setCookie}";
            default_type text/html;
            return 200 '<!doctype html><title>partitioned seed</title>';
        }
        location = /favicon.ico { access_log off; return 204; }
        location / {
            pow on;
            pow_difficulty 8;
            pow_cookie_name ${AUTH_COOKIE_NAME};
            proxy_pass http://127.0.0.1:${ports.backend};
        }
    }
}
`;
}


function parseObservationLine(line) {
    const match = REQUEST_LOG_PATTERN.exec(line);

    if (match === null) {
        throw new Error('invalid NGINX request observation record');
    }

    return Object.freeze({
        requestUri: match[1],
        cookie: match[2],
        status: Number.parseInt(match[3], 10),
    });
}


async function readLines(filename) {
    try {
        const text = await fs.readFile(filename, 'utf8');
        return text.split('\n').filter((line) => line !== '');
    } catch (error) {
        if (error?.code === 'ENOENT') {
            return [];
        }
        throw error;
    }
}


function assertHeaderAllowlist(response) {
    const names = Object.keys(response.headers());
    assert.equal(names.every((name) => ALLOWED_RESPONSE_HEADERS.has(name)), true);
}


function parseChallenge(value) {
    const match = /^v=1; d=([1-9][0-9]*); b=(0|[1-9][0-9]*); n=([A-Za-z0-9_-]{43})$/u
        .exec(value);

    assert.notEqual(match, null);
    return Object.freeze({
        version: 1,
        difficulty: Number.parseInt(match[1], 10),
        bucket: match[2],
        nonce: match[3],
    });
}


function parseParams(body) {
    const match = /<script type="application\/json" id="pow-params">(.*?)<\/script>/su
        .exec(body);

    assert.notEqual(match, null);
    const value = JSON.parse(match[1]);
    assert.deepEqual(Object.keys(value), ['v', 'd', 'b', 'n']);
    return value;
}


function assertCanonicalBase64Url(value, expectedLength) {
    assert.match(value, /^[A-Za-z0-9_-]+$/u);
    const decoded = Buffer.from(value, 'base64url');
    assert.equal(decoded.length, expectedLength);
    assert.equal(decoded.toString('base64url'), value);
}


function assertAuthCookie(cookie) {
    assert.equal(cookie.name, AUTH_COOKIE_NAME);
    assert.equal(cookie.value.length, 39);
    const fields = cookie.value.split('.');
    assert.deepEqual(fields.length, 3);
    assert.equal(fields[0], '1');
    assertCanonicalBase64Url(fields[1], 10);
    assertCanonicalBase64Url(fields[2], 16);
    assert.equal(cookie.domain, 'gate.powgate.test');
    assert.equal(cookie.path, '/');
    assert.equal(cookie.secure, true);
    assert.equal(cookie.httpOnly, true);
    assert.equal(cookie.sameSite, 'Lax');
}


async function assertChallengeResponse(response, body) {
    assertHeaderAllowlist(response);
    const headers = response.headers();
    assert.equal(headers['cache-control'], 'no-store');
    assert.equal(headers['content-type'], 'text/html; charset=utf-8');
    assert.equal(headers['x-robots-tag'], 'noindex');
    assert.equal('set-cookie' in headers, false);
    assert.equal(Buffer.byteLength(body, 'utf8') < 15360, true);
    const challenge = parseChallenge(headers['powgate-challenge']);
    const params = parseParams(body);
    assert.deepEqual(challenge, {
        version: params.v,
        difficulty: params.d,
        bucket: params.b,
        nonce: params.n,
    });
    assert.equal(params.d, 8);
    const script = extractExecutableScript(Buffer.from(body, 'utf8'));
    assert.deepEqual(script, await readChallengeScript());
    const digest = createHash('sha256').update(script).digest('base64');
    assert.equal(
        headers['content-security-policy'],
        `${EXPECTED_CSP_PREFIX}${digest}${EXPECTED_CSP_SUFFIX}`,
    );
    return Object.freeze({ challenge, params });
}


async function waitForDocumentCount(session, count) {
    return withDeadline(
        'browser_document_sequence', DEADLINES.e2e_terminal_outcome,
        async (signal) => {
            while (!signal.aborted) {
                if (session.documentResponses.length >= count) {
                    return;
                }
                await new Promise((resolve) => setTimeout(resolve, 10));
            }
        },
    );
}


async function enableDocumentBodyCapture(session) {
    const bodies = [];
    let failure = null;

    const handler = (event) => {
        Promise.resolve().then(async () => {
            if (event.responseStatusCode === 503) {
                const response = await session.cdp.send(
                    'Fetch.getResponseBody', { requestId: event.requestId },
                );
                bodies.push(Object.freeze({
                    body: Buffer.from(
                        response.body,
                        response.base64Encoded ? 'base64' : 'utf8',
                    ).toString('utf8'),
                    status: 503,
                }));
            }
            await session.cdp.send('Fetch.continueRequest', {
                requestId: event.requestId,
            });
        }).catch((error) => {
            failure ??= error;
        });
    };

    session.cdp.on('Fetch.requestPaused', handler);
    await session.cdp.send('Fetch.enable', {
        patterns: [{
            requestStage: 'Response',
            resourceType: 'Document',
            urlPattern: '*',
        }],
    });

    return Object.freeze({
        take(status) {
            if (failure !== null) {
                throw failure;
            }
            const index = bodies.findIndex((entry) => entry.status === status);
            if (index === -1) {
                throw new Error('captured document body is unavailable');
            }
            return bodies.splice(index, 1)[0].body;
        },
        async close() {
            session.cdp.off('Fetch.requestPaused', handler);
            await session.cdp.send('Fetch.disable');
            if (failure !== null) {
                throw failure;
            }
        },
    });
}


async function seedStaleCookie(session, fixture, testCase) {
    if (testCase.stalePath === null) {
        return;
    }

    const result = await session.cdp.send('Network.setCookie', {
        name: PROOF_COOKIE_NAME,
        value: '1.0.0',
        url: `${fixture.origin}${testCase.target}`,
        path: testCase.stalePath,
        secure: true,
        httpOnly: false,
        sameSite: 'Lax',
    });
    assert.notEqual(result.success, false);
}


async function assertRequestObservations(fixture, testCase, beforeCount) {
    const filename = path.join(
        fixture.paths.logs, 'request-observation.log',
    );
    const allLines = await readLines(filename);
    const lines = allLines.slice(beforeCount).map(parseObservationLine);

    currentOperation = `${fixture.protocolMode}_${testCase.id}_request_log_count`;
    assert.equal(lines.length, 2);
    currentOperation = `${fixture.protocolMode}_${testCase.id}_request_log_status`;
    assert.deepEqual(lines.map((record) => record.status), [503, 200]);

    currentOperation = `${fixture.protocolMode}_${testCase.id}_request_log_uri`;
    for (const record of lines) {
        assert.equal(
            decodeNginxJsonLogString(record.requestUri)
                .equals(testCase.expectedRequestTarget),
            true,
        );
    }

    currentOperation = `${fixture.protocolMode}_${testCase.id}_request_log_initial_cookie`;
    if (testCase.stalePath === null) {
        assert.equal(lines[0].cookie, '');
    } else {
        const stale = await observeRequest({
            requestUri: lines[0].requestUri,
            expectedRequestUri: testCase.expectedRequestTarget,
            cookie: lines[0].cookie,
            effectiveCookieFieldCount: 1,
            scannerPath: SCANNER_PATH,
        });
        assert.deepEqual(stale, {
            proofOccurrenceCount: 1,
            requestUriMatches: true,
            singleEffectiveCookieField: true,
        });
    }

    currentOperation = `${fixture.protocolMode}_${testCase.id}_request_log_reload_cookie`;
    const reload = await observeRequest({
        requestUri: lines[1].requestUri,
        expectedRequestUri: testCase.expectedRequestTarget,
        cookie: lines[1].cookie,
        effectiveCookieFieldCount: 1,
        scannerPath: SCANNER_PATH,
    });
    assert.deepEqual(reload, {
        proofOccurrenceCount: 1,
        requestUriMatches: true,
        singleEffectiveCookieField: true,
    });
}


async function countVisibleProofCookies(page) {
    return page.evaluate(
        `(${countExactProofCookies.toString()})(document.cookie)`,
    );
}


async function assertPartitionedRequestObservation(
    fixture, testCase, beforeCount,
) {
    const filename = path.join(
        fixture.paths.logs, 'request-observation.log',
    );
    const lines = (await readLines(filename)).slice(beforeCount)
        .map(parseObservationLine);

    assert.equal(lines.length, 1);
    assert.equal(lines[0].status, 503);
    const observation = await observeRequest({
        requestUri: lines[0].requestUri,
        expectedRequestUri: testCase.expectedRequestTarget,
        cookie: lines[0].cookie,
        effectiveCookieFieldCount: 1,
        scannerPath: SCANNER_PATH,
    });
    assert.deepEqual(observation, {
        proofOccurrenceCount: 1,
        requestUriMatches: true,
        singleEffectiveCookieField: true,
    });
    return observation.proofOccurrenceCount;
}


export async function runPositiveCase(fixture, testCase) {
    const expectedProtocol = fixture.protocolMode === 'h2' ? 'h2' : 'http/1.1';
    const requestLog = path.join(fixture.paths.logs, 'request-observation.log');
    const backendLog = path.join(fixture.paths.logs, 'backend-count.log');
    const requestCountBefore = (await readLines(requestLog)).length;
    const backendCountBefore = (await readLines(backendLog)).length;
    const session = await fixture.createBrowserSession({
        protocolMode: fixture.protocolMode,
        observe: { allowChallengeStatusConsole: true },
    });
    const bodyCapture = await enableDocumentBodyCapture(session);
    let primaryFailure;

    try {
        await seedStaleCookie(session, fixture, testCase);
        const url = `${fixture.origin}${testCase.target}`;
        const auditWindow = session.observations.openWindow('positive_audit');
        const requests = [];
        const responses = [];
        let finalResponseSeen = false;
        session.page.on('request', (request) => {
            requests.push(Object.freeze({
                afterFinalResponse: finalResponseSeen,
                navigation: request.isNavigationRequest(),
                resourceType: request.resourceType(),
                url: request.url(),
            }));
        });
        session.page.on('response', (response) => {
            if (response.request().isNavigationRequest()) {
                responses.push(response);
                if (response.status() === 200) {
                    finalResponseSeen = true;
                }
            }
        });

        const finalResponsePromise = session.page.waitForResponse(
            (response) => response.request().isNavigationRequest()
                && response.url() === url && response.status() === 200,
            { timeout: DEADLINES.e2e_terminal_outcome },
        );
        currentOperation = `${fixture.protocolMode}_${testCase.id}_navigation`;
        const initialResponse = await session.page.goto(url, {
            waitUntil: 'load',
            timeout: DEADLINES.document_navigation,
        });
        currentOperation = `${fixture.protocolMode}_${testCase.id}_initial_status`;
        assert.equal(initialResponse.status(), 503);
        currentOperation = `${fixture.protocolMode}_${testCase.id}_initial_body`;
        const initialBody = bodyCapture.take(503);
        currentOperation = `${fixture.protocolMode}_${testCase.id}_terminal_response`;
        const finalResponse = await finalResponsePromise;
        currentOperation = `${fixture.protocolMode}_${testCase.id}_document_sequence`;
        await waitForDocumentCount(session, 2);
        currentOperation = `${fixture.protocolMode}_${testCase.id}_backend_dom`;
        await session.page.waitForFunction(
            () => document.body?.innerText === 'powgate backend ok\n',
            { timeout: DEADLINES.e2e_terminal_outcome },
        );
        await new Promise((resolve) => setTimeout(resolve, 100));

        currentOperation = `${fixture.protocolMode}_${testCase.id}_responses`;
        assert.equal(responses.length, 2);
        assert.deepEqual(responses.map((response) => response.status()), [503, 200]);
        assert.equal(responses.some((response) => response.status() >= 300
            && response.status() < 400), false);
        assert.deepEqual(
            session.documentResponses.map((record) => record.status),
            [503, 200],
        );
        assert.deepEqual(
            session.documentResponses.map((record) => record.protocol),
            [expectedProtocol, expectedProtocol],
        );
        assert.equal(await finalResponse.text(), BACKEND_BODY);
        assert.equal(
            await session.page.evaluate(() => location.pathname + location.search),
            testCase.pathname + testCase.search,
        );

        currentOperation = `${fixture.protocolMode}_${testCase.id}_challenge`;
        assertHeaderAllowlist(finalResponse);
        await assertChallengeResponse(initialResponse, initialBody);

        currentOperation = `${fixture.protocolMode}_${testCase.id}_cookies`;
        const cookies = await session.context.cookies(url);
        const authCookies = cookies.filter((cookie) =>
            cookie.name === AUTH_COOKIE_NAME);
        const proofCookies = cookies.filter((cookie) =>
            cookie.name === PROOF_COOKIE_NAME);
        assert.equal(authCookies.length, 1);
        assertAuthCookie(authCookies[0]);
        assert.equal(proofCookies.length, 0);

        currentOperation = `${fixture.protocolMode}_${testCase.id}_request_count`;
        const documentRequests = requests.filter((request) => request.navigation);
        const auxiliaryRequests = requests.filter((request) => !request.navigation);
        assert.equal(documentRequests.length, 2);
        assert.equal(auxiliaryRequests.length, 1);
        currentOperation = `${fixture.protocolMode}_${testCase.id}_request_shape`;
        assert.equal(documentRequests.every((request) =>
            request.resourceType === 'document' && request.url === url), true);
        assert.deepEqual(auxiliaryRequests.map((request) => ({
            afterFinalResponse: request.afterFinalResponse,
            resourceType: request.resourceType,
            url: request.url,
        })), [{
            afterFinalResponse: true,
            resourceType: 'other',
            url: `${fixture.origin}/favicon.ico`,
        }]);
        currentOperation = `${fixture.protocolMode}_${testCase.id}_event_silence`;
        const auditEvents = auditWindow.snapshot();
        assert.deepEqual(auditEvents, [{
            consoleType: 'error',
            identifier: 'challenge_status',
            type: 'console',
        }]);
        auditWindow.close();
        session.assertHealthy();
        currentOperation = `${fixture.protocolMode}_${testCase.id}_request_log`;
        await assertRequestObservations(fixture, testCase, requestCountBefore);
        currentOperation = `${fixture.protocolMode}_${testCase.id}_backend_count`;
        assert.equal((await readLines(backendLog)).length - backendCountBefore, 1);

        return Object.freeze({
            authCookieValid: true,
            backendReachCount: 1,
            challengeCount: 1,
            finalStatus: 200,
            proofOccurrenceCountOnReload: 1,
            protocol: expectedProtocol,
            requestTargetMatches: true,
        });
    } catch (error) {
        primaryFailure = error;
        throw error;
    } finally {
        try {
            await bodyCapture.close();
            await session.close();
        } catch (cleanupError) {
            if (primaryFailure === undefined) {
                throw cleanupError;
            }
            primaryFailure.cleanupFailures ??= [];
            primaryFailure.cleanupFailures.push(cleanupError);
        }
    }
}


export async function runPartitionedNegativeCase(fixture, testCase) {
    const expectedProtocol = fixture.protocolMode === 'h2' ? 'h2' : 'http/1.1';
    const requestLog = path.join(fixture.paths.logs, 'request-observation.log');
    const backendLog = path.join(fixture.paths.logs, 'backend-count.log');
    const backendCountBefore = (await readLines(backendLog)).length;
    const session = await fixture.createBrowserSession({
        protocolMode: fixture.protocolMode,
        observe: { allowChallengeStatusConsole: true },
    });
    const bodyCapture = await enableDocumentBodyCapture(session);
    const protectedUrl = `${fixture.origin}${testCase.target}`;
    let primaryFailure;

    try {
        currentOperation = `${fixture.protocolMode}_${testCase.id}_seed`;
        const seedResponse = await session.page.goto(
            `${fixture.origin}${PARTITIONED_PROOF_FIXTURE.seedPath}`,
            {
                waitUntil: 'load',
                timeout: DEADLINES.document_navigation,
            },
        );
        assert.equal(seedResponse.status(), 200);
        assert.equal(
            await seedResponse.text(),
            '<!doctype html><title>partitioned seed</title>',
        );
        assert.equal(
            seedResponse.headers()['set-cookie'],
            PARTITIONED_PROOF_FIXTURE.setCookie,
        );
        await new Promise((resolve) => setTimeout(resolve, 100));
        assert.equal((await readLines(backendLog)).length - backendCountBefore, 0);

        currentOperation = `${fixture.protocolMode}_${testCase.id}_seed_cookie`;
        const seededCookies = await session.context.cookies(protectedUrl);
        currentOperation = `${fixture.protocolMode}_${testCase.id}_seed_classification`;
        const seededClassification = classifyPartitionedCookies(
            seededCookies, [], AUTH_COOKIE_NAME,
        );
        assert.deepEqual(seededClassification, {
            authCookieCount: 0,
            newPartitionedProofCount: 0,
            originalPartitionedProofCount: 1,
            unpartitionedProofCount: 0,
        });
        currentOperation = `${fixture.protocolMode}_${testCase.id}_seed_descriptor`;
        assert.equal(
            seededCookies.filter(partitionedCookieMatchesFixture).length,
            1,
        );
        currentOperation = `${fixture.protocolMode}_${testCase.id}_seed_visibility`;
        assert.equal(await countVisibleProofCookies(session.page), 1);

        await session.page.evaluateOnNewDocument(
            partitionedObserverBootstrap,
        );
        const requestCountBefore = (await readLines(requestLog)).length;
        const documentStart = session.documentResponses.length;
        const auditWindow = session.observations.openWindow(
            'partitioned_negative_audit',
        );
        const requests = [];
        session.page.on('request', (request) => {
            requests.push(Object.freeze({
                navigation: request.isNavigationRequest(),
                resourceType: request.resourceType(),
                url: request.url(),
            }));
        });

        currentOperation = `${fixture.protocolMode}_${testCase.id}_challenge`;
        const initialResponse = await session.page.goto(protectedUrl, {
            waitUntil: 'load',
            timeout: DEADLINES.document_navigation,
        });
        assert.equal(initialResponse.status(), 503);
        const initialBody = bodyCapture.take(503);
        await assertChallengeResponse(initialResponse, initialBody);
        await session.page.waitForFunction(() => {
            const status = document.getElementById('pow-status');
            const retry = document.getElementById('pow-retry');
            return status?.textContent === 'Unable to complete the check.'
                && retry?.hidden === false;
        }, { timeout: DEADLINES.e2e_terminal_outcome });

        currentOperation = `${fixture.protocolMode}_${testCase.id}_audit`;
        assert.deepEqual(auditWindow.snapshot(), [{
            consoleType: 'error',
            identifier: 'challenge_status',
            type: 'console',
        }]);
        auditWindow.close();
        const quietWindow = session.observations.openWindow(
            'partitioned_negative_quiet',
        );
        const requestCountAtQuietStart = requests.length;
        const cookieCountAtQuietStart = await countVisibleProofCookies(
            session.page,
        );
        await new Promise((resolve) => setTimeout(
            resolve, DEADLINES.fail_closed_quiet_window,
        ));
        assert.deepEqual(quietWindow.snapshot(), []);
        quietWindow.close();
        assert.equal(requests.length, requestCountAtQuietStart);
        assert.equal(await countVisibleProofCookies(session.page),
            cookieCountAtQuietStart);
        assert.equal(
            await session.page.evaluate(() => location.pathname + location.search),
            testCase.target,
        );

        currentOperation = `${fixture.protocolMode}_${testCase.id}_sequence`;
        const documents = session.documentResponses.slice(documentStart);
        assert.deepEqual(documents.map((record) => ({
            protocol: record.protocol,
            status: record.status,
            url: record.url,
        })), [{
            protocol: expectedProtocol,
            status: 503,
            url: protectedUrl,
        }]);
        assert.deepEqual(requests.map((request) => ({
            navigation: request.navigation,
            resourceType: request.resourceType,
            url: request.url,
        })), [{
            navigation: true,
            resourceType: 'document',
            url: protectedUrl,
        }]);

        currentOperation = `${fixture.protocolMode}_${testCase.id}_request_log`;
        const initialRequestProofCount =
            await assertPartitionedRequestObservation(
                fixture, testCase, requestCountBefore,
            );

        currentOperation = `${fixture.protocolMode}_${testCase.id}_observer`;
        const observer = await partitionedObserverSnapshot(session.page);
        assert.deepEqual(observer, {
            descriptorValid: true,
            exportsValid: true,
            namespaceAssignments: 1,
            namespaceFrozen: true,
            phase: 'installed',
            solverCalls: 0,
        });

        currentOperation = `${fixture.protocolMode}_${testCase.id}_cookies`;
        const finalCookies = await session.context.cookies(protectedUrl);
        const finalClassification = classifyPartitionedCookies(
            finalCookies, [], AUTH_COOKIE_NAME,
        );
        assert.deepEqual(finalClassification, {
            authCookieCount: 0,
            newPartitionedProofCount: 0,
            originalPartitionedProofCount: 1,
            unpartitionedProofCount: 0,
        });
        assert.equal(
            finalCookies.filter(partitionedCookieMatchesFixture).length,
            1,
        );
        assert.equal(await countVisibleProofCookies(session.page), 1);
        assert.equal((await readLines(backendLog)).length - backendCountBefore, 0);
        session.assertHealthy();

        return Object.freeze({
            authCookieCount: finalClassification.authCookieCount,
            backendCount: 0,
            challengePhaseDocumentNavigationCount: documents.length,
            failureUiVisible: true,
            initialDocumentVisible: true,
            initialRequestProofCount,
            namespaceAssignments: observer.namespaceAssignments,
            newPartitionedProofCount:
                finalClassification.newPartitionedProofCount,
            originalPartitionedProofCount:
                finalClassification.originalPartitionedProofCount,
            partitionedCookieStored: true,
            postCleanupDocumentVisible: true,
            postCleanupStoragePresent: true,
            protocol: expectedProtocol,
            retryControlVisible: true,
            solverCalls: observer.solverCalls,
            unpartitionedProofCount:
                finalClassification.unpartitionedProofCount,
        });
    } catch (error) {
        primaryFailure = error;
        throw error;
    } finally {
        try {
            await bodyCapture.close();
            await session.close();
        } catch (cleanupError) {
            if (primaryFailure === undefined) {
                throw cleanupError;
            }
            primaryFailure.cleanupFailures ??= [];
            primaryFailure.cleanupFailures.push(cleanupError);
        }
    }
}


export async function runE2EMatrix({ serverBuild = 'normal' } = {}) {
    if (serverBuild !== 'normal') {
        throw new TypeError('unsupported server build');
    }

    let partitionedNegativePassed = 0;
    let positivePassed = 0;

    for (const protocolMode of ['h2', 'h1']) {
        currentOperation = `${protocolMode}_fixture_start`;
        await withFixture({
            target: `test-browser-e2e-${serverBuild}-${protocolMode}`,
            protocolMode,
            nginxBinary: '/usr/sbin/nginx',
            modulePath: path.resolve('out/ngx_http_pow_module.so'),
            renderNginxConfig: renderNginxConfiguration,
        }, async (fixture) => {
            const matrixFixture = Object.freeze({ ...fixture, protocolMode });
            for (const testCase of positiveCases()) {
                await runPositiveCase(matrixFixture, testCase);
                positivePassed++;
            }
            await runPartitionedNegativeCase(
                matrixFixture, partitionedNegativeCase(),
            );
            partitionedNegativePassed++;
        });
    }

    return buildNormalMatrixResult(
        positivePassed, partitionedNegativePassed,
    );
}


async function main() {
    const arguments_ = process.argv.slice(2);
    if (arguments_.length !== 2 || arguments_[0] !== '--server-build'
        || arguments_[1] !== 'normal') {
        throw new TypeError('usage: e2e.mjs --server-build normal');
    }
    const result = await runE2EMatrix({ serverBuild: arguments_[1] });
    process.stdout.write(
        `normal_positive=${result.normalPositive} `
        + `normal_partitioned_negative=${result.normalPartitionedNegative} `
        + `normal_total=${result.normalTotal} verdict=${result.verdict}\n`,
    );
}


if (process.argv[1] !== undefined
    && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
    try {
        await main();
    } catch (error) {
        if (error instanceof BrowserTestFailure) {
            process.stderr.write(
                `browser-e2e: ${error.category} ${error.operation} failed\n`,
            );
        } else {
            process.stderr.write(
                `browser-e2e: assertion ${currentOperation} failed\n`,
            );
        }
        process.exitCode = 1;
    }
}
