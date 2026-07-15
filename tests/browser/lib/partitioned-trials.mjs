import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';

import {
    withFixture,
} from './fixture.mjs';
import { observeRequest } from './request-observation.mjs';
import { DEADLINES } from './constants.mjs';
import {
    PARTITIONED_PROOF_FIXTURE,
    countExactProofCookies,
    partitionedCookieMatchesFixture,
    partitionedObserverBootstrap,
    partitionedObserverSnapshot,
} from './partitioned-proof.mjs';

export { countExactProofCookies as countExactProofs };

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
const REQUEST_LOG_PATTERN = /^\{"request_uri":"((?:\\.|[^"\\])*)","cookie":"((?:\\.|[^"\\])*)","status":([0-9]{3})\}$/u;
const SCANNER_PATH = path.resolve('build/browser-tools/cookie-occurrences');
const SECRET_HEX = '000102030405060708090a0b0c0d0e0f'
    + '101112131415161718191a1b1c1d1e1f';

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
        location = ${PARTITIONED_PROOF_FIXTURE.seedPath} {
            access_log off;
            add_header Set-Cookie "${PARTITIONED_PROOF_FIXTURE.setCookie}";
            default_type text/html;
            return 200 '<!doctype html><title>partitioned seed</title>';
        }
        location = /favicon.ico { access_log off; return 204; }
        location = ${PARTITIONED_PROOF_FIXTURE.challengePath} {
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
    return cookies.filter(partitionedCookieMatchesFixture);
}


async function installObserver(session) {
    await session.page.evaluateOnNewDocument(partitionedObserverBootstrap);
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
    const protectedUrl = `${fixture.origin}${
        PARTITIONED_PROOF_FIXTURE.challengePath}`;
    let solveCalls = 0;
    let observerSnapshot = null;
    let primaryFailure;

    try {
        await session.page.goto(`${fixture.origin}${
            PARTITIONED_PROOF_FIXTURE.seedPath}`, {
            timeout: DEADLINES.document_navigation,
            waitUntil: 'load',
        });
        const storedBefore = await partitionedCookies(session, protectedUrl);
        const initialVisible = await session.page.evaluate(
            `(${countExactProofCookies.toString()})(document.cookie)`,
        );
        if (observed) {
            await installObserver(session);
        }

        const documentStart = session.documentResponses.length;
        const backendPromise = session.page.waitForResponse(
            (response) => response.request().isNavigationRequest()
                && response.url() === protectedUrl && response.status() === 200,
            { timeout: DEADLINES.e2e_terminal_outcome },
        );
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
            `(${countExactProofCookies.toString()})(document.cookie)`,
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
            expectedRequestUri: Buffer.from(
                PARTITIONED_PROOF_FIXTURE.challengePath, 'ascii',
            ),
            cookie: requestLines[0].cookie,
            effectiveCookieFieldCount: 1,
            scannerPath: SCANNER_PATH,
        });
        assert.equal(initialRequest.requestUriMatches, true);
        assert.equal(initialRequest.singleEffectiveCookieField, true);

        if (observed && terminal === 'failure') {
            observerSnapshot = await partitionedObserverSnapshot(session.page);
            assert.deepEqual(observerSnapshot, {
                descriptorValid: true,
                exportsValid: true,
                namespaceAssignments: 1,
                namespaceFrozen: true,
                phase: 'installed',
                solverCalls: 0,
            });
            solveCalls = observerSnapshot.solverCalls;
        }
        session.assertHealthy();

        return Object.freeze({
            backend_count: (await readLines(backendLog)).length - beforeBackend,
            initial_document_visible: initialVisible === 1,
            initial_request_present:
                initialRequest.proofOccurrenceCount === 1,
            navigation_count: documents.length,
            observer_snapshot: observerSnapshot,
            partitioned_cookie_stored: storedBefore.length === 1,
            post_cleanup_document_visible: postVisible === 1,
            post_cleanup_storage_present: storedAfter.length === 1,
            solve_calls: solveCalls,
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
    const trials = await runPartitionedTrials();

    return buildPartitionedVerdict({
        backend_count: trials.observed.backend_count,
        initial_document_visible: trials.observed.initial_document_visible,
        initial_request_present: trials.observed.initial_request_present,
        navigation_count: trials.observed.navigation_count,
        observer_control_matches: controlMatches(
            trials.control, trials.observed,
        ),
        partitioned_cookie_stored:
            trials.observed.partitioned_cookie_stored,
        post_cleanup_document_visible:
            trials.observed.post_cleanup_document_visible,
        post_cleanup_storage_present:
            trials.observed.post_cleanup_storage_present,
        solver_calls: trials.observed.solve_calls,
    });
}


export async function runPartitionedTrials({
    target = 'test-browser-partitioned-feasibility',
} = {}) {
    let trials;

    await withFixture({
        target,
        protocolMode: 'h2',
        nginxBinary: '/usr/sbin/nginx',
        modulePath: path.resolve('out/ngx_http_pow_module.so'),
        renderNginxConfig: renderNginxConfiguration,
    }, async (fixture) => {
        const control = await runTrial(fixture, false);
        const observed = await runTrial(fixture, true);
        const {
            observer_snapshot: _controlSnapshot,
            ...controlRecord
        } = control;
        const {
            observer_snapshot: observerSnapshot,
            ...observedRecord
        } = observed;
        trials = Object.freeze({
            control: Object.freeze(controlRecord),
            observed: Object.freeze(observedRecord),
            observerSnapshot,
        });
    });
    return trials;
}
