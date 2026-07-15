import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { promises as fs } from 'node:fs';
import https from 'node:https';
import { test } from 'node:test';

import {
    BENCHMARK_TARGET_TIMEOUT_MS,
    BROWSER_AGGREGATE_TIMEOUT_MS,
    CAPTURE_LIMITS,
    DEADLINES,
    E2E_TARGET_TIMEOUT_MS,
    FAILURE_CATEGORIES,
    FEASIBILITY_TARGET_TIMEOUT_MS,
    OUTER_WATCHDOG_CLEANUP_GRACE_MS,
} from './lib/constants.mjs';
import {
    BrowserTestFailure,
    FixtureTransaction,
    ObservationBuffer,
    buildChromiumLaunchArguments,
    buildDiagnosticBundle,
    identityStillMatches,
    isNginxBindCollision,
    readProcessIdentity,
    signalVerifiedProcess,
    validateChromiumProcessArguments,
    withDeadline,
    withFixture,
} from './lib/fixture.mjs';


const expectedDeadlines = Object.freeze({
    nginx_config_test: 10000,
    nginx_readiness: 15000,
    chromium_launch: 30000,
    browser_context: 10000,
    cdp_operation: 10000,
    document_navigation: 30000,
    e2e_terminal_outcome: 30000,
    controlled_probe: 10000,
    fail_closed_quiet_window: 1000,
    benchmark_controller_quiet_window: 1000,
    diagnostic_capture: 10000,
    page_context_close: 10000,
    chromium_close: 15000,
    nginx_quit: 10000,
    nginx_term: 5000,
    nginx_kill: 2000,
});

const expectedFailures = Object.freeze([
    'host_policy',
    'environment_identity',
    'fixture_configuration',
    'fixture_startup',
    'sandbox_policy',
    'browser_pairing',
    'browser_runtime',
    'protocol_assertion',
    'cookie_assertion',
    'controller_assertion',
    'benchmark_correctness',
    'benchmark_responsiveness',
    'evidence_validation',
    'internal_invariant',
    'cleanup',
]);


test('freezes every Phase 4C deadline, failure category and capture limit', () => {
    assert.deepEqual(DEADLINES, expectedDeadlines);
    assert.deepEqual([...FAILURE_CATEGORIES], expectedFailures);
    assert.deepEqual(CAPTURE_LIMITS, {
        bench_min_attempts: 1,
        bench_max_attempts: 262144,
        bench_target_block_ms: 10,
        bench_js_block_ceiling_ms: 25,
        max_observation_events_per_page: 4096,
        max_observation_metadata_bytes_per_page: 1024 * 1024,
        max_raw_samples_per_run_series: 8192,
        max_generated_evidence_bytes: 16 * 1024 * 1024,
        max_retained_diagnostic_bytes: 2 * 1024 * 1024,
        max_failed_benchmark_sample_excerpt: 32,
        heartbeat_allowed_timer_tail: 2,
    });
    assert.equal(FEASIBILITY_TARGET_TIMEOUT_MS, 180000);
    assert.equal(E2E_TARGET_TIMEOUT_MS, 600000);
    assert.equal(BENCHMARK_TARGET_TIMEOUT_MS, 360000);
    assert.equal(BROWSER_AGGREGATE_TIMEOUT_MS, 1300000);
    assert.equal(OUTER_WATCHDOG_CLEANUP_GRACE_MS, 20000);
    assert.ok(BROWSER_AGGREGATE_TIMEOUT_MS
        > FEASIBILITY_TARGET_TIMEOUT_MS + E2E_TARGET_TIMEOUT_MS
          + BENCHMARK_TARGET_TIMEOUT_MS);
    assert.equal(BROWSER_AGGREGATE_TIMEOUT_MS
        - FEASIBILITY_TARGET_TIMEOUT_MS - E2E_TARGET_TIMEOUT_MS
        - BENCHMARK_TARGET_TIMEOUT_MS, 160000);
    assert.ok(Object.isFrozen(DEADLINES));
    assert.ok(Object.isFrozen(CAPTURE_LIMITS));
    assert.equal(FAILURE_CATEGORIES.add, undefined);
    assert.equal(FAILURE_CATEGORIES.delete, undefined);
    assert.equal(FAILURE_CATEGORIES.clear, undefined);
});


test('named deadlines reject with fixed classified metadata', async () => {
    await assert.rejects(
        withDeadline('controlled_probe', 5, (signal) => new Promise((resolve) => {
            signal.addEventListener('abort', resolve, { once: true });
        })),
        (error) => {
            assert.ok(error instanceof BrowserTestFailure);
            assert.equal(error.category, 'browser_runtime');
            assert.equal(error.operation, 'controlled_probe');
            assert.equal(error.message, 'operation deadline exceeded: controlled_probe');
            return true;
        },
    );
    assert.equal(
        await withDeadline('controlled_probe', 100, async () => 'complete'),
        'complete',
    );
    assert.throws(
        () => new BrowserTestFailure('unknown', 'probe', 'bad'),
        /invalid category/,
    );
});


test('process signals require a complete matching Linux identity', async (t) => {
    const child = spawn('/usr/bin/sleep', ['30'], { stdio: 'ignore' });
    t.after(() => {
        try {
            child.kill('SIGKILL');
        } catch {
            /* already gone */
        }
    });
    const identity = await readProcessIdentity(child.pid);
    assert.equal(await identityStillMatches(identity), true);
    assert.ok(Object.isFrozen(identity));
    assert.ok(Object.isFrozen(identity.commandLine));

    for (const [field, value] of [
        ['pid', identity.pid + 1000000],
        ['ppid', identity.ppid + 1],
        ['startTime', `${identity.startTime}0`],
        ['executable', `${identity.executable}.other`],
        ['commandLine', Object.freeze([...identity.commandLine, '--other'])],
    ]) {
        const mismatch = Object.freeze({ ...identity, [field]: value });
        assert.equal(await identityStillMatches(mismatch), false, field);
        assert.equal(await signalVerifiedProcess(mismatch, 'SIGTERM'), false, field);
        assert.equal(await identityStillMatches(identity), true, field);
    }

    assert.equal(await signalVerifiedProcess(identity, 'SIGTERM'), true);
    await new Promise((resolve) => child.once('exit', resolve));
    assert.equal(await identityStillMatches(identity), false);
});


test('NGINX retry classification accepts only selected-port bind collisions', () => {
    const ports = [18443, 18080];
    const rows = [
        ['nginx: [emerg] bind() to 127.0.0.1:18443 failed (98: Address already in use)', true],
        ['nginx: [emerg] bind() to [::1]:18080 failed (98: Address already in use)', true],
        ['nginx: [emerg] bind() to 127.0.0.1:19999 failed (98: Address already in use)', false],
        ['nginx: [emerg] unknown directive "pow"', false],
        ['nginx: [emerg] cannot load certificate', false],
        ['nginx: [emerg] open() failed (13: Permission denied)', false],
        ['', false],
    ];
    for (const [stderr, expected] of rows) {
        assert.equal(isNginxBindCollision(stderr, ports), expected, stderr);
    }
});


test('diagnostics retain only allowlisted bounded metadata', () => {
    const bundle = buildDiagnosticBundle({
        target: 'test-browser-feasibility',
        category: 'fixture_startup',
        operation: 'nginx_readiness',
        verdict: 'failed',
        timeoutMs: 15000,
        process: { pid: 42, executable: '/usr/sbin/nginx' },
        response: { status: 503, protocol: 'h2', headerNames: ['content-type'] },
        cookie: 'must-not-survive',
        url: 'https://gate.powgate.test/private?secret=value',
        rawHeaders: { cookie: 'must-not-survive' },
    });
    assert.deepEqual(bundle, {
        category: 'fixture_startup',
        operation: 'nginx_readiness',
        process: { executable: '/usr/sbin/nginx', pid: 42 },
        response: { headerNames: ['content-type'], protocol: 'h2', status: 503 },
        target: 'test-browser-feasibility',
        timeoutMs: 15000,
        verdict: 'failed',
    });
    assert.ok(Object.isFrozen(bundle));
    assert.throws(
        () => buildDiagnosticBundle({ target: 'x'.repeat(2 * 1024 * 1024) }),
        (error) => error instanceof BrowserTestFailure
            && error.category === 'internal_invariant',
    );
});


test('fixture transaction is single-use and cleanup is idempotent', async () => {
    const calls = [];
    const transaction = new FixtureTransaction({
        start: async () => calls.push('start'),
        diagnostics: async () => calls.push('diagnostics'),
        cleanup: async () => calls.push('cleanup'),
    });
    await transaction.start();
    assert.equal(transaction.state, 'ready');
    await transaction.cleanup();
    await transaction.cleanup();
    assert.equal(transaction.state, 'stopped');
    assert.deepEqual(calls, ['start', 'cleanup']);
    await assert.rejects(transaction.start(), /cannot start/);
});


test('fixture transaction preserves primary and classifies secondary failures', async () => {
    const primary = new BrowserTestFailure(
        'protocol_assertion', 'case_outcome', 'fixed failure',
    );
    const transaction = new FixtureTransaction({
        start: async () => {},
        diagnostics: async () => {
            throw new Error('diagnostic failed');
        },
        cleanup: async () => {
            throw new Error('cleanup failed');
        },
    });
    await assert.rejects(
        transaction.run(async () => {
            throw primary;
        }),
        (error) => {
            assert.equal(error, primary);
            assert.equal(error.diagnosticFailures.length, 1);
            assert.equal(error.diagnosticFailures[0].category, 'internal_invariant');
            assert.equal(error.cleanupFailures.length, 1);
            assert.equal(error.cleanupFailures[0].category, 'cleanup');
            return true;
        },
    );
});


test('fixture startup failure still captures diagnostics and cleans once', async () => {
    const calls = [];
    const primary = new BrowserTestFailure(
        'fixture_configuration', 'nginx_config_test', 'fixed failure',
    );
    const transaction = new FixtureTransaction({
        start: async () => {
            calls.push('start');
            throw primary;
        },
        diagnostics: async () => calls.push('diagnostics'),
        cleanup: async () => calls.push('cleanup'),
    });
    await assert.rejects(transaction.run(async () => {}), (error) => error === primary);
    assert.deepEqual(calls, ['start', 'diagnostics', 'cleanup']);
    assert.equal(transaction.state, 'stopped');
});


function getFixture(origin, pathname) {
    return new Promise((resolve, reject) => {
        const url = new URL(pathname, origin);
        const request = https.get({
            hostname: '127.0.0.1',
            port: url.port,
            path: `${url.pathname}${url.search}`,
            servername: url.hostname,
            rejectUnauthorized: false,
        }, (response) => {
            response.resume();
            response.once('end', () => resolve(response.statusCode));
        });
        request.once('error', reject);
    });
}


test('withFixture owns an isolated HTTPS NGINX lifecycle', async () => {
    let observed;
    await withFixture({
        target: 'fixture-test',
        protocolMode: 'h2',
        nginxBinary: '/usr/sbin/nginx',
        staticFiles: { 'index.html': 'fixture\n' },
        renderNginxConfig({ paths, ports }) {
            return `
worker_processes 1;
pid ${paths.nginxPid};
error_log ${paths.nginxErrorLog} notice;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path ${paths.clientBodyTemp};
    proxy_temp_path ${paths.proxyTemp};
    fastcgi_temp_path ${paths.fastcgiTemp};
    uwsgi_temp_path ${paths.uwsgiTemp};
    scgi_temp_path ${paths.scgiTemp};
    server {
        listen 127.0.0.1:${ports.https} ssl;
        http2 on;
        ssl_certificate ${paths.certificate};
        ssl_certificate_key ${paths.privateKey};
        location = /__powgate_ready { return 204; }
        location / { root ${paths.content}; }
    }
}
`;
        },
    }, async (fixture) => {
        observed = fixture;
        assert.match(fixture.paths.root, /build\/browser-runtime\/fixture-test-/u);
        assert.equal((await fs.stat(fixture.paths.privateKey)).mode & 0o777, 0o600);
        const certificate = new X509Certificate(
            await fs.readFile(fixture.paths.certificate),
        );
        assert.match(certificate.subjectAltName, /DNS:powgate\.test/u);
        assert.match(certificate.subjectAltName, /DNS:gate\.powgate\.test/u);
        assert.equal(await identityStillMatches(fixture.nginx.master), true);
        assert.equal(await getFixture(fixture.origin, '/__powgate_ready'), 204);
        assert.equal(await getFixture(fixture.origin, '/index.html'), 200);
    });
    assert.equal(observed.nginx.cleanupEscalated, false);
    assert.equal(await identityStillMatches(observed.nginx.master), false);
    await assert.rejects(fs.stat(observed.paths.root), { code: 'ENOENT' });
});


test('Chromium launch policy is exact and rejects weakening', () => {
    const common = [
        '--disable-dev-shm-usage',
        '--disable-background-networking',
        '--disable-component-update',
        '--disable-default-apps',
        '--disable-domain-reliability',
        '--disable-sync',
        '--metrics-recording-only',
        '--no-default-browser-check',
        '--no-first-run',
        '--host-resolver-rules=MAP powgate.test 127.0.0.1,MAP gate.powgate.test 127.0.0.1,EXCLUDE localhost',
    ];
    assert.deepEqual(buildChromiumLaunchArguments({ protocolMode: 'h2' }), common);
    assert.deepEqual(
        buildChromiumLaunchArguments({ protocolMode: 'h1' }),
        [...common, '--disable-http2'],
    );
    assert.throws(
        () => buildChromiumLaunchArguments({
            protocolMode: 'h2', extraArguments: ['--no-sandbox'],
        }),
        (error) => error instanceof BrowserTestFailure
            && error.category === 'sandbox_policy',
    );
    for (const argument of [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--single-process',
        '--no-zygote',
        '--disable-seccomp-filter-sandbox',
        '--disable-namespace-sandbox',
    ]) {
        assert.throws(
            () => validateChromiumProcessArguments(['/usr/bin/chromium', argument]),
            /prohibited Chromium argument/,
        );
    }
    assert.throws(
        () => validateChromiumProcessArguments([
            '/usr/lib/chromium/chromium --type=renderer --no-sandbox',
        ]),
        /prohibited Chromium argument/,
    );
    assert.doesNotThrow(() => validateChromiumProcessArguments([
        '/usr/bin/chromium', '--type=renderer', '--renderer-client-id=4',
    ]));
});


test('observation windows consume only their own bounded events', async () => {
    const observations = new ObservationBuffer({ maxEvents: 3, maxBytes: 1024 });
    const first = observations.openWindow('first_probe');
    observations.record(Object.freeze({ type: 'console', identifier: 'first' }));
    assert.equal(
        (await first.waitFor((event) => event.identifier === 'first')).identifier,
        'first',
    );
    first.close();

    const second = observations.openWindow('second_probe');
    assert.deepEqual(second.snapshot(), []);
    observations.record(Object.freeze({ type: 'page_error', identifier: 'second' }));
    assert.equal(
        (await second.waitFor((event) => event.identifier === 'second')).type,
        'page_error',
    );
    second.close();
    assert.throws(() => second.snapshot(), /closed observation window/);

    observations.record(Object.freeze({ type: 'request_failure' }));
    assert.throws(
        () => observations.record(Object.freeze({ type: 'overflow' })),
        (error) => error instanceof BrowserTestFailure
            && error.category === 'internal_invariant',
    );
    const bytes = new ObservationBuffer({ maxEvents: 10, maxBytes: 24 });
    assert.throws(
        () => bytes.record(Object.freeze({ type: 'x'.repeat(40) })),
        /metadata limit exceeded/,
    );
});
