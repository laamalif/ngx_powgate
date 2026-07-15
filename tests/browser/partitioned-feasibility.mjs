import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
    BrowserTestFailure,
    withFixture,
} from './lib/fixture.mjs';
import { observeRequest } from './lib/request-observation.mjs';
import { DEADLINES } from './lib/constants.mjs';

const BOOLEAN_FIELDS = Object.freeze([
    'initial_document_visible',
    'initial_request_present',
    'observer_control_matches',
    'partitioned_cookie_stored',
    'post_cleanup_document_visible',
    'post_cleanup_storage_present',
]);
const INTEGER_FIELDS = Object.freeze([
    'backend_count',
    'navigation_count',
    'solver_calls',
]);
const OBSERVATION_FIELDS = Object.freeze([
    ...BOOLEAN_FIELDS,
    ...INTEGER_FIELDS,
].sort());
const AUTH_COOKIE_NAME = 'PowAuth';
const BACKEND_BODY = 'powgate partitioned backend ok\n';
const PROOF_COOKIE_NAME = '__pow_p';
const PROTECTED_TARGET = '/partitioned-feasibility';
const REQUEST_LOG_PATTERN = /^\{"request_uri":"((?:\\.|[^"\\])*)","cookie":"((?:\\.|[^"\\])*)","status":([0-9]{3})\}$/u;
const SCANNER_PATH = path.resolve('build/browser-tools/cookie-occurrences');
const SECRET_HEX = '000102030405060708090a0b0c0d0e0f'
    + '101112131415161718191a1b1c1d1e1f';

let currentOperation = 'initialization';


function validateObservations(observations) {
    if (observations === null || typeof observations !== 'object'
        || Array.isArray(observations)
        || Object.keys(observations).sort().join('\n')
            !== OBSERVATION_FIELDS.join('\n')) {
        throw new TypeError('invalid partitioned feasibility observations');
    }
    for (const field of BOOLEAN_FIELDS) {
        if (typeof observations[field] !== 'boolean') {
            throw new TypeError('invalid partitioned feasibility observations');
        }
    }
    for (const field of INTEGER_FIELDS) {
        if (!Number.isSafeInteger(observations[field])
            || observations[field] < 0) {
            throw new TypeError('invalid partitioned feasibility observations');
        }
    }
}


export function partitionedAcceptance(observations) {
    validateObservations(observations);
    return observations.partitioned_cookie_stored === true
        && observations.initial_document_visible === true
        && observations.initial_request_present === true
        && observations.post_cleanup_document_visible === true
        && observations.post_cleanup_storage_present === true
        && observations.observer_control_matches === true
        && observations.solver_calls === 0
        && observations.navigation_count === 1
        && observations.backend_count === 0;
}


export function buildPartitionedVerdict(observations) {
    validateObservations(observations);
    return Object.freeze({
        acceptance_reached: partitionedAcceptance(observations),
        backend_count: observations.backend_count,
        initial_document_visible: observations.initial_document_visible,
        initial_request_present: observations.initial_request_present,
        navigation_count: observations.navigation_count,
        observer_control_matches: observations.observer_control_matches,
        partitioned_cookie_stored: observations.partitioned_cookie_stored,
        post_cleanup_document_visible:
            observations.post_cleanup_document_visible,
        post_cleanup_storage_present:
            observations.post_cleanup_storage_present,
        solver_calls: observations.solver_calls,
    });
}


export function countExactProofs(text) {
    const proofName = '__pow_p';
    let count = 0;
    let cursor = 0;

    while (cursor <= text.length) {
        let end = text.indexOf(';', cursor);
        if (end === -1) {
            end = text.length;
        }
        while (cursor < end && (text.charCodeAt(cursor) === 0x20
            || text.charCodeAt(cursor) === 0x09)) {
            cursor++;
        }
        if (text.slice(cursor, cursor + proofName.length + 1)
            === `${proofName}=`) {
            count++;
        }
        if (end === text.length) {
            break;
        }
        cursor = end + 1;
    }
    return count;
}


export function observerBootstrap() {
    const bindingName = '__powgateSpikeSolveCall';
    const state = {
        descriptorValid: false,
        exportsValid: false,
        namespaceFrozen: false,
        phase: 'waiting',
    };

    Object.defineProperty(globalThis, '__powgateSpikeObserver', {
        configurable: false,
        enumerable: false,
        value: Object.freeze({
            snapshot() {
                return Object.freeze({ ...state });
            },
        }),
        writable: false,
    });

    document.addEventListener('DOMContentLoaded', () => {
        if (document.getElementById('pow-params') === null) {
            state.phase = 'ignored';
            return;
        }
        const namespace = globalThis.PowGateSolver;
        const descriptor = Object.getOwnPropertyDescriptor(
            globalThis, 'PowGateSolver',
        );
        const keys = namespace === null || typeof namespace !== 'object'
            ? [] : Object.keys(namespace);
        if (descriptor === undefined || descriptor.value !== namespace
            || keys.length !== 2 || keys[0] !== 'sha256' || keys[1] !== 'solve'
            || typeof namespace.sha256 !== 'function'
            || typeof namespace.solve !== 'function'
            || !Object.isFrozen(namespace)) {
            throw new TypeError('invalid PowGateSolver namespace');
        }
        const notify = globalThis[bindingName];
        Object.defineProperty(globalThis, bindingName, {
            configurable: false,
            enumerable: false,
            value: notify,
            writable: false,
        });
        const wrapped = Object.freeze({
            sha256: namespace.sha256,
            solve(...args) {
                notify();
                return Reflect.apply(namespace.solve, namespace, args);
            },
        });
        Object.defineProperty(globalThis, 'PowGateSolver', {
            configurable: descriptor.configurable,
            enumerable: descriptor.enumerable,
            value: wrapped,
            writable: descriptor.writable,
        });
        const current = globalThis.PowGateSolver;
        const currentDescriptor = Object.getOwnPropertyDescriptor(
            globalThis, 'PowGateSolver',
        );
        state.descriptorValid = currentDescriptor !== undefined
            && currentDescriptor.value === wrapped;
        state.exportsValid = Object.keys(current).join(',') === 'sha256,solve';
        state.namespaceFrozen = Object.isFrozen(current);
        state.phase = 'installed';
    }, { capture: true, once: true });
}


async function renderNginxConfiguration({ paths, ports, modulePath }) {
    const backendLog = path.join(paths.logs, 'partitioned-backend.log');
    const requestLog = path.join(paths.logs, 'partitioned-request.log');
    const secretPath = path.join(paths.root, 'powgate.secret');

    await fs.writeFile(secretPath, `${SECRET_HEX}\n`, { mode: 0o600 });
    return `load_module ${modulePath};
worker_processes 1;
pid ${paths.nginxPid};
error_log ${paths.nginxErrorLog} notice;
events { worker_connections 256; }
http {
    log_format powgate_partitioned escape=json '{"request_uri":"$request_uri","cookie":"$http_cookie","status":$status}';
    log_format powgate_partitioned_backend '$status';
    pow_secret_file ${secretPath};
    client_body_temp_path ${paths.clientBodyTemp};
    proxy_temp_path ${paths.proxyTemp};
    fastcgi_temp_path ${paths.fastcgiTemp};
    uwsgi_temp_path ${paths.uwsgiTemp};
    scgi_temp_path ${paths.scgiTemp};
    server {
        listen 127.0.0.1:${ports.backend};
        access_log ${backendLog} powgate_partitioned_backend;
        location / {
            default_type text/plain;
            return 200 "${BACKEND_BODY.replace('\n', '\\n')}";
        }
    }
    server {
        listen 127.0.0.1:${ports.https} ssl;
        http2 on;
        ssl_certificate ${paths.certificate};
        ssl_certificate_key ${paths.privateKey};
        access_log ${requestLog} powgate_partitioned;
        location = /__powgate_ready { access_log off; return 204; }
        location = /__powgate_partitioned_seed {
            access_log off;
            add_header Set-Cookie "__pow_p=1.0.0; Path=/; Secure; SameSite=Lax; Partitioned";
            default_type text/html;
            return 200 '<!doctype html><title>partitioned seed</title>';
        }
        location = /favicon.ico { access_log off; return 204; }
        location = ${PROTECTED_TARGET} {
            pow on;
            pow_difficulty 8;
            pow_cookie_name ${AUTH_COOKIE_NAME};
            proxy_pass http://127.0.0.1:${ports.backend};
        }
    }
}
`;
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


function parseObservationLine(line) {
    const match = REQUEST_LOG_PATTERN.exec(line);
    if (match === null) {
        throw new Error('invalid partitioned request observation');
    }
    return Object.freeze({
        requestUri: match[1],
        cookie: match[2],
        status: Number.parseInt(match[3], 10),
    });
}


async function partitionedCookies(session, url) {
    const cookies = await session.context.cookies(url);
    return cookies.filter((cookie) => cookie.name === PROOF_COOKIE_NAME
        && cookie.domain === 'gate.powgate.test' && cookie.path === '/'
        && cookie.partitionKey !== undefined);
}


async function installObserver(session, counter) {
    await session.cdp.send('Runtime.addBinding', {
        name: '__powgateSpikeSolveCall',
    });
    session.cdp.on('Runtime.bindingCalled', (event) => {
        if (event.name === '__powgateSpikeSolveCall') {
            counter.calls++;
        }
    });
    await session.page.evaluateOnNewDocument(observerBootstrap);
}


async function waitForTerminal(session, backendPromise) {
    const failurePromise = session.page.waitForFunction(() => {
        const status = document.getElementById('pow-status');
        const retry = document.getElementById('pow-retry');
        return status?.textContent === 'Unable to complete the check.'
            && retry?.hidden === false;
    }, { timeout: DEADLINES.e2e_terminal_outcome }).then(() => 'failure');
    return Promise.race([
        failurePromise,
        backendPromise.then(() => 'backend'),
    ]);
}


async function runTrial(fixture, observed) {
    const backendLog = path.join(fixture.paths.logs, 'partitioned-backend.log');
    const requestLog = path.join(fixture.paths.logs, 'partitioned-request.log');
    const beforeBackend = (await readLines(backendLog)).length;
    const beforeRequests = (await readLines(requestLog)).length;
    const session = await fixture.createBrowserSession({
        protocolMode: 'h2',
        observe: { allowChallengeStatusConsole: true },
    });
    const solveCounter = { calls: 0 };
    const protectedUrl = `${fixture.origin}${PROTECTED_TARGET}`;
    let primaryFailure;

    try {
        currentOperation = 'partitioned_seed_navigation';
        await session.page.goto(`${fixture.origin}/__powgate_partitioned_seed`, {
            timeout: DEADLINES.document_navigation,
            waitUntil: 'load',
        });
        const storedBefore = await partitionedCookies(session, protectedUrl);
        const initialVisible = await session.page.evaluate(
            `(${countExactProofs.toString()})(document.cookie)`,
        );
        if (observed) {
            await installObserver(session, solveCounter);
        }

        const documentStart = session.documentResponses.length;
        const backendPromise = session.page.waitForResponse(
            (response) => response.request().isNavigationRequest()
                && response.url() === protectedUrl && response.status() === 200,
            { timeout: DEADLINES.e2e_terminal_outcome },
        );
        currentOperation = 'partitioned_protected_navigation';
        const initialResponse = await session.page.goto(protectedUrl, {
            timeout: DEADLINES.document_navigation,
            waitUntil: 'load',
        });
        assert.equal(initialResponse.status(), 503);
        const terminal = await waitForTerminal(session, backendPromise);
        await new Promise((resolve) => setTimeout(
            resolve, DEADLINES.fail_closed_quiet_window,
        ));

        const postVisible = await session.page.evaluate(
            `(${countExactProofs.toString()})(document.cookie)`,
        );
        const storedAfter = await partitionedCookies(session, protectedUrl);
        const documents = session.documentResponses.slice(documentStart)
            .filter((record) => record.url === protectedUrl);
        await new Promise((resolve) => setTimeout(resolve, 100));
        const requestLines = (await readLines(requestLog))
            .slice(beforeRequests).map(parseObservationLine);
        assert.equal(requestLines.length >= 1, true);
        const initialRequest = await observeRequest({
            requestUri: requestLines[0].requestUri,
            expectedRequestUri: Buffer.from(PROTECTED_TARGET, 'ascii'),
            cookie: requestLines[0].cookie,
            effectiveCookieFieldCount: 1,
            scannerPath: SCANNER_PATH,
        });
        assert.equal(initialRequest.requestUriMatches, true);
        assert.equal(initialRequest.singleEffectiveCookieField, true);

        if (observed && terminal === 'failure') {
            assert.deepEqual(await session.page.evaluate(() =>
                globalThis.__powgateSpikeObserver.snapshot()), {
                descriptorValid: true,
                exportsValid: true,
                namespaceFrozen: true,
                phase: 'installed',
            });
        }
        session.assertHealthy();

        return Object.freeze({
            backend_count: (await readLines(backendLog)).length - beforeBackend,
            initial_document_visible: initialVisible === 1,
            initial_request_present:
                initialRequest.proofOccurrenceCount === 1,
            navigation_count: documents.length,
            partitioned_cookie_stored: storedBefore.length === 1,
            post_cleanup_document_visible: postVisible === 1,
            post_cleanup_storage_present: storedAfter.length === 1,
            solve_calls: solveCounter.calls,
            terminal,
        });
    } catch (error) {
        primaryFailure = error;
        throw error;
    } finally {
        try {
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


function controlMatches(control, observed) {
    const fields = [
        'backend_count',
        'initial_document_visible',
        'initial_request_present',
        'navigation_count',
        'partitioned_cookie_stored',
        'post_cleanup_document_visible',
        'post_cleanup_storage_present',
        'terminal',
    ];
    return fields.every((field) => control[field] === observed[field]);
}


export async function runPartitionedFeasibility() {
    let verdict;

    await withFixture({
        target: 'test-browser-partitioned-feasibility',
        protocolMode: 'h2',
        nginxBinary: '/usr/sbin/nginx',
        modulePath: path.resolve('out/ngx_http_pow_module.so'),
        renderNginxConfig: renderNginxConfiguration,
    }, async (fixture) => {
        const control = await runTrial(fixture, false);
        const observed = await runTrial(fixture, true);
        verdict = buildPartitionedVerdict({
            backend_count: observed.backend_count,
            initial_document_visible: observed.initial_document_visible,
            initial_request_present: observed.initial_request_present,
            navigation_count: observed.navigation_count,
            observer_control_matches: controlMatches(control, observed),
            partitioned_cookie_stored: observed.partitioned_cookie_stored,
            post_cleanup_document_visible:
                observed.post_cleanup_document_visible,
            post_cleanup_storage_present:
                observed.post_cleanup_storage_present,
            solver_calls: observed.solve_calls,
        });
    });
    return verdict;
}


async function main() {
    const verdict = await runPartitionedFeasibility();
    process.stdout.write(`${JSON.stringify(verdict)}\n`);
}


if (process.argv[1] !== undefined
    && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
    try {
        await main();
    } catch (error) {
        if (error instanceof BrowserTestFailure) {
            process.stderr.write(
                `partitioned-feasibility: ${error.category} `
                + `${error.operation} failed\n`,
            );
        } else {
            process.stderr.write(
                `partitioned-feasibility: assertion ${currentOperation} failed\n`,
            );
        }
        process.exitCode = 1;
    }
}
