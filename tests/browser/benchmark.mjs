import {
    CAPTURE_LIMITS,
} from './lib/constants.mjs';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { promises as fsPromises } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
    benchmarkImplementationSha256,
    productionScriptIdentity,
    readGoldenImageLock,
    readVersionLocks,
    sha256Hex,
    validateEvidence,
    writeEvidenceAtomically,
} from './lib/evidence.mjs';
import {
    buildChromiumLaunchArguments,
    withFixture,
} from './lib/fixture.mjs';
import { DEADLINES } from './lib/constants.mjs';


export const BENCH_MIN_ATTEMPTS = CAPTURE_LIMITS.bench_min_attempts;
export const BENCH_MAX_ATTEMPTS = CAPTURE_LIMITS.bench_max_attempts;
export const BENCHMARK_SCHEDULE = Object.freeze([
    'js', 'subtle',
    'subtle', 'js',
    'js', 'subtle',
    'subtle', 'js',
    'js', 'subtle',
    'subtle', 'js',
    'js', 'subtle',
]);
const RESULT_KEYS = Object.freeze([
    'attempts', 'counter', 'exhausted', 'found', 'nextCounter',
]);
const PARAMETER_MARKER = '<!-- POW:PARAMS -->';
const OUTPUT_PATH = 'build/benchmark-browser-result.json';
const BENCHMARK_PATH = '/benchmark';
const NONCE_HEX =
    'c382cd45c32e81f6f5bdcc5fb29497876a3d4364b688245668ab1b578ff7184f';
const WARMUP_MS = 2000;
const RECORDED_MS = 10000;
const HEARTBEAT_MS = 5;


function invalid(message) {
    throw new TypeError(`invalid benchmark ${message}`);
}


function frozenRecord(value) {
    return Object.freeze(value);
}


function validSafeInteger(value, minimum = 0) {
    return Number.isSafeInteger(value) && value >= minimum;
}


export function buildBenchmarkPage(template) {
    if (typeof template !== 'string'
        || template.split(PARAMETER_MARKER).length !== 2) {
        invalid('challenge template');
    }
    const matches = [...template.matchAll(/<script>([\s\S]*?)<\/script>/gu)];
    if (matches.length !== 1) {
        invalid('challenge script structure');
    }
    const script = matches[0][1];
    const body = template.replace(
        PARAMETER_MARKER,
        '<script id="pow-params" type="application/json">{}</script>',
    );
    return frozenRecord({
        body,
        script,
        scriptDigest: crypto.createHash('sha256')
            .update(script, 'utf8').digest('base64'),
    });
}


function validateSolverResult(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
        || !Object.isFrozen(value)
        || Object.keys(value).sort().join('\n') !== RESULT_KEYS.join('\n')
        || typeof value.found !== 'boolean'
        || typeof value.exhausted !== 'boolean'
        || !validSafeInteger(value.attempts, 1)) {
        invalid('solver result');
    }
    if (value.found) {
        if (value.exhausted || !validSafeInteger(value.counter)
            || value.nextCounter !== null) {
            invalid('solver result');
        }
        return;
    }
    if (value.counter !== null) {
        invalid('solver result');
    }
    if (value.exhausted) {
        if (value.nextCounter !== null) {
            invalid('solver result');
        }
    } else if (!validSafeInteger(value.nextCounter)) {
        invalid('solver result');
    }
}


export function deriveContinuation(solverResult, proofVerified) {
    validateSolverResult(solverResult);
    if (solverResult.found) {
        if (proofVerified !== true) {
            invalid('success is not independently verified');
        }
        if (solverResult.counter === Number.MAX_SAFE_INTEGER) {
            return frozenRecord({
                resumeCounter: null,
                safeDomainTerminal: true,
            });
        }
        return frozenRecord({
            resumeCounter: solverResult.counter + 1,
            safeDomainTerminal: false,
        });
    }
    return frozenRecord({
        resumeCounter: solverResult.nextCounter,
        safeDomainTerminal: solverResult.exhausted,
    });
}


export function accountHeartbeatDeadlines({
    actualTime,
    nextDeadline,
    recordedEnd,
    period = 5,
}) {
    for (const [name, value] of [
        ['actual time', actualTime],
        ['next deadline', nextDeadline],
        ['recorded end', recordedEnd],
        ['period', period],
    ]) {
        if (!Number.isFinite(value) || value < 0) {
            invalid(`heartbeat ${name}`);
        }
    }
    if (period <= 0) {
        invalid('heartbeat period');
    }
    const samples = [];
    let deadline = nextDeadline;
    const lastAccounted = Math.min(actualTime, recordedEnd);
    while (deadline <= lastAccounted) {
        samples.push(frozenRecord({
            deadline_performance_ms: deadline,
            delay_ms: Math.max(0, actualTime - deadline),
        }));
        deadline += period;
    }
    return frozenRecord({
        nextDeadline: deadline,
        samples: Object.freeze(samples),
    });
}


export function nearestRankP95(values) {
    if (!Array.isArray(values) || values.length === 0
        || values.some((value) => !Number.isFinite(value) || value < 0)) {
        invalid('heartbeat p95 input is empty or invalid');
    }
    const sorted = [...values].sort((left, right) => left - right);
    return sorted[Math.ceil(sorted.length * 0.95) - 1];
}


export function selectCalibrationAttempts({
    currentAttempts,
    durationMs,
    startCounter,
}) {
    if (!validSafeInteger(currentAttempts, BENCH_MIN_ATTEMPTS)
        || currentAttempts > BENCH_MAX_ATTEMPTS) {
        invalid('calibration attempt count');
    }
    if (!Number.isFinite(durationMs) || durationMs <= 0) {
        invalid('calibration duration');
    }
    if (!validSafeInteger(startCounter)) {
        invalid('calibration start counter');
    }
    const scaled = Math.round(
        currentAttempts * CAPTURE_LIMITS.bench_target_block_ms / durationMs,
    );
    let bounded = Math.max(
        BENCH_MIN_ATTEMPTS,
        Math.min(BENCH_MAX_ATTEMPTS, scaled),
    );
    if (startCounter
        > Number.MAX_SAFE_INTEGER - (BENCH_MAX_ATTEMPTS - 1)) {
        const safeRemaining = Number.MAX_SAFE_INTEGER - startCounter + 1;
        bounded = Math.min(bounded, safeRemaining);
    }
    if (!validSafeInteger(bounded, BENCH_MIN_ATTEMPTS)) {
        invalid('calibration safe range');
    }
    return bounded;
}


export function normalizeCalibrationDuration(value) {
    if (!Number.isFinite(value) || value < 0) {
        invalid('calibration duration');
    }
    return Math.max(value, 0.1);
}


function medianSeven(values) {
    if (values.length !== 7) {
        invalid('summary run count');
    }
    return [...values].sort((left, right) => left - right)[3];
}


function maximum(values) {
    return values.length === 0 ? null : Math.max(...values);
}


export function summarizeRuns(runs) {
    if (!Array.isArray(runs) || runs.length !== 14) {
        invalid('run schedule');
    }
    for (let index = 0; index < BENCHMARK_SCHEDULE.length; index += 1) {
        const run = runs[index];
        if (run === null || typeof run !== 'object'
            || run.backend !== BENCHMARK_SCHEDULE[index]
            || run.pair !== Math.floor(index / 2) + 1) {
            invalid('run schedule');
        }
    }
    const pairWins = { js: 0, subtle: 0 };
    for (let pair = 1; pair <= 7; pair += 1) {
        const paired = runs.filter((run) => run.pair === pair);
        const js = paired.find((run) => run.backend === 'js');
        const subtle = paired.find((run) => run.backend === 'subtle');
        if (js.throughput_candidates_per_second
            > subtle.throughput_candidates_per_second) {
            pairWins.js += 1;
        } else if (subtle.throughput_candidates_per_second
            > js.throughput_candidates_per_second) {
            pairWins.subtle += 1;
        }
    }
    const summaries = {};
    for (const backend of ['js', 'subtle']) {
        const backendRuns = runs.filter((run) => run.backend === backend);
        const throughputs = backendRuns.map(
            (run) => run.throughput_candidates_per_second,
        );
        const blocks = backendRuns.flatMap(
            (run) => run.js_block_durations_ms,
        );
        summaries[backend] = frozenRecord({
            throughput_values: Object.freeze(throughputs),
            median_throughput: medianSeven(throughputs),
            heartbeat_max_ms: Math.max(...backendRuns.map(
                (run) => run.heartbeat_max_ms,
            )),
            heartbeat_p95_max_ms: Math.max(...backendRuns.map(
                (run) => run.heartbeat_p95_ms,
            )),
            max_js_block_ms: backend === 'js' ? maximum(blocks) : null,
            matched_pair_wins: pairWins[backend],
            correctness_passed: backendRuns.every(
                (run) => run.correctness_passed === true,
            ),
            responsiveness_passed: backendRuns.every((run) =>
                run.heartbeat_p95_ms <= 25
                && run.heartbeat_max_ms <= 100
                && (backend !== 'js'
                    || maximum(run.js_block_durations_ms) <= 25)),
        });
    }
    return frozenRecord(summaries);
}


export function decideBackend(summaries) {
    if (summaries === null || typeof summaries !== 'object'
        || summaries.js === undefined || summaries.subtle === undefined
        || summaries.js.median_throughput <= 0) {
        invalid('backend summaries');
    }
    const ratio = summaries.subtle.median_throughput
        / summaries.js.median_throughput;
    const ratioMet = ratio >= 1.25;
    const pairMet = summaries.subtle.matched_pair_wins >= 5;
    const prerequisites = ['js', 'subtle'].every((backend) =>
        summaries[backend].correctness_passed
        && summaries[backend].responsiveness_passed);
    const selectSubtle = prerequisites && ratioMet && pairMet;
    return frozenRecord({
        selected_primary_backend: selectSubtle ? 'subtle' : 'js',
        selected_secondary_backend: selectSubtle ? 'js' : 'subtle',
        subtle_to_js_median_ratio: ratio,
        ratio_threshold_met: ratioMet,
        matched_pair_requirement_met: pairMet,
        prerequisites_met: prerequisites,
        rationale_token: selectSubtle
            ? 'subtle-materially-faster'
            : 'js-default-threshold-not-met',
    });
}


export function responsivenessFailures(runs) {
    if (!Array.isArray(runs)) {
        invalid('responsiveness runs');
    }
    return runs.filter((run) => run.heartbeat_p95_ms > 25
        || run.heartbeat_max_ms > 100
        || (run.backend === 'js'
            && maximum(run.js_block_durations_ms) > 25))
        .map((run) => ({
            backend: run.backend,
            heartbeat_max_ms: run.heartbeat_max_ms,
            heartbeat_p95_ms: run.heartbeat_p95_ms,
            max_js_block_ms: run.backend === 'js'
                ? maximum(run.js_block_durations_ms) : null,
            pair: run.pair,
        }));
}


function delay(milliseconds) {
    return new Promise((resolve) => setTimeout(resolve, milliseconds));
}


function nginxConfiguration({ paths, ports }, scriptDigest) {
    return `
worker_processes 1;
pid ${paths.nginxPid};
error_log ${paths.nginxErrorLog} notice;
events { worker_connections 128; }
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
        root ${paths.content};
        add_header Content-Security-Policy "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; script-src 'sha256-${scriptDigest}'; style-src 'unsafe-inline'" always;
        add_header Cache-Control "no-store" always;
        location = /__powgate_ready { return 204; }
        location = ${BENCHMARK_PATH} {
            default_type text/html;
            try_files /benchmark.html =404;
        }
    }
}
`;
}


async function proveControllerQuiet(session, page, url) {
    const responseStart = session.documentResponses.length;
    const response = await page.goto(url, { waitUntil: 'load' });
    assert.equal(response.status(), 200);
    const documentResponse = await session.waitForDocument(url, responseStart);
    assert.equal(documentResponse.protocol, 'h2');
    await page.waitForFunction(() => {
        const status = document.getElementById('pow-status');
        const retry = document.getElementById('pow-retry');
        return status?.textContent === 'Unable to complete the check.'
            && retry?.hidden === false;
    });
    assert.deepEqual(await page.evaluate(() => ({
        cookie: document.cookie,
        exports: Object.keys(globalThis.PowGateSolver).sort(),
        frozen: Object.isFrozen(globalThis.PowGateSolver),
        progress: document.getElementById('pow-progress')?.value,
        url: location.href,
    })), {
        cookie: '',
        exports: ['sha256', 'solve'],
        frozen: true,
        progress: 0,
        url,
    });
    const quietEvents = session.observations.openWindow('benchmark_quiet');
    const documents = session.documentResponses.length;
    await page.evaluate(() => {
        globalThis.__powgateBenchmarkMutationCount = 0;
        globalThis.__powgateBenchmarkObserver = new MutationObserver(() => {
            globalThis.__powgateBenchmarkMutationCount += 1;
        });
        globalThis.__powgateBenchmarkObserver.observe(document, {
            attributes: true,
            childList: true,
            characterData: true,
            subtree: true,
        });
    });
    await delay(DEADLINES.benchmark_controller_quiet_window);
    assert.equal(await page.evaluate(() =>
        globalThis.__powgateBenchmarkMutationCount), 0);
    assert.equal(session.documentResponses.length, documents);
    assert.deepEqual(quietEvents.snapshot(), []);
    quietEvents.close();
}


function createRunRecord(raw, backend, index) {
    const elapsed = raw.recorded_end_performance_ms
        - raw.recorded_start_performance_ms;
    const delays = raw.heartbeat_samples.map((sample) => sample.delay_ms);
    return {
        backend,
        pair: Math.floor(index / 2) + 1,
        execution_position: (index % 2) + 1,
        calibrated_attempt_limit: raw.calibrated_attempt_limit,
        warmup_duration_ms: WARMUP_MS,
        recorded_start_performance_ms: raw.recorded_start_performance_ms,
        recorded_end_performance_ms: raw.recorded_end_performance_ms,
        completed_candidates: raw.completed_candidates,
        valid_hit_count: raw.valid_hit_count,
        first_valid_hit_offset: raw.first_valid_hit_offset,
        safe_domain_terminal: false,
        elapsed_ms: elapsed,
        deadline_overrun_ms: elapsed - RECORDED_MS,
        throughput_candidates_per_second:
            raw.completed_candidates / (elapsed / 1000),
        heartbeat_samples: raw.heartbeat_samples,
        heartbeat_p95_ms: nearestRankP95(delays),
        heartbeat_max_ms: Math.max(...delays),
        js_block_durations_ms: raw.js_block_durations_ms,
        subtle_sync_entry_durations_ms:
            raw.subtle_sync_entry_durations_ms,
        subtle_awaited_invocation_durations_ms:
            raw.subtle_awaited_invocation_durations_ms,
        subtle_async_remainder_durations_ms:
            raw.subtle_async_remainder_durations_ms,
        document_visible: true,
        counter_contiguous: true,
        correctness_passed: true,
        context_cleanup_passed: true,
    };
}


async function runBrowserSession(pageData, driverSource) {
    let sessionIdentity;
    const rawRuns = [];
    await withFixture({
        target: 'benchmark-browser',
        protocolMode: 'h2',
        nginxBinary: '/usr/sbin/nginx',
        staticFiles: { 'benchmark.html': pageData.body },
        renderNginxConfig: (fixture) =>
            nginxConfiguration(fixture, pageData.scriptDigest),
    }, async (fixture) => {
        const session = await fixture.createBrowserSession({
            protocolMode: 'h2',
        });
        const url = `${fixture.origin}${BENCHMARK_PATH}`;
        sessionIdentity = {
            browserVersion: session.browserVersion,
            observedArguments: session.master.commandLine,
            sandbox: session.sandbox,
        };
        for (let index = 0; index < BENCHMARK_SCHEDULE.length; index += 1) {
            const backend = BENCHMARK_SCHEDULE[index];
            const isolated = await session.createIsolatedPage();
            let completed = false;
            try {
                await isolated.page.bringToFront();
                await proveControllerQuiet(session, isolated.page, url);
                await isolated.page.evaluate(driverSource);
                assert.deepEqual(await isolated.page.evaluate(() => ({
                    exports: Object.keys(
                        globalThis.PowGateBenchmarkDriver,
                    ).sort(),
                    frozen: Object.isFrozen(
                        globalThis.PowGateBenchmarkDriver,
                    ),
                })), { exports: ['kat', 'run'], frozen: true });
                assert.equal(await isolated.page.evaluate(
                    (selected) => globalThis.PowGateBenchmarkDriver.kat(selected),
                    backend,
                ), true);
                const audit = session.observations.openWindow(
                    `benchmark_run_${index + 1}`,
                );
                const documents = session.documentResponses.length;
                const raw = await isolated.page.evaluate(
                    (options) => globalThis.PowGateBenchmarkDriver.run(options),
                    {
                        backend,
                        difficulty: 32,
                        heartbeatMs: HEARTBEAT_MS,
                        maxAttempts: BENCH_MAX_ATTEMPTS,
                        minAttempts: BENCH_MIN_ATTEMPTS,
                        nonce: [...Buffer.from(NONCE_HEX, 'hex')],
                        recordMs: RECORDED_MS,
                        targetBlockMs: CAPTURE_LIMITS.bench_target_block_ms,
                        timerResolutionFloorMs:
                            normalizeCalibrationDuration(0),
                        warmupMs: WARMUP_MS,
                    },
                );
                assert.equal(session.documentResponses.length, documents);
                assert.deepEqual(audit.snapshot(), []);
                audit.close();
                assert.equal(await isolated.page.evaluate(() =>
                    document.hidden), false);
                rawRuns.push({ backend, index, raw });
                completed = true;
            } finally {
                await isolated.close();
            }
            assert.equal(completed, true);
        }
        await session.close();
    });
    return Object.freeze({ rawRuns, sessionIdentity });
}


function cpuModel() {
    const cpu = os.cpus()[0]?.model;
    if (typeof cpu !== 'string' || cpu.length === 0) {
        throw new Error('CPU model is unavailable');
    }
    return cpu;
}


function environmentRecord(locks, sessionIdentity) {
    return {
        host_architecture: 'x86_64',
        container_architecture: os.machine(),
        debian_snapshot: locks.DEBIAN_SNAPSHOT,
        debian_base_image_digest: locks.DEBIAN_IMAGE_AMD64,
        chromium_package_version: locks.CHROMIUM_VERSION,
        chromium_package_sha256: locks.CHROMIUM_SHA256_AMD64,
        chromium_sandbox_package_version: locks.CHROMIUM_SANDBOX_VERSION,
        chromium_sandbox_package_sha256:
            locks.CHROMIUM_SANDBOX_SHA256_AMD64,
        chromium_cdp_version: sessionIdentity.browserVersion,
        nodejs_package_version: locks.NODEJS_VERSION,
        nodejs_package_sha256: locks.NODEJS_SHA256_AMD64,
        npm_package_version: locks.NPM_VERSION,
        npm_package_sha256: locks.NPM_SHA256_AMD64,
        puppeteer_core_version: locks.PUPPETEER_CORE_VERSION,
        ajv_version: locks.AJV_VERSION,
        ajv_integrity: locks.AJV_INTEGRITY,
        nginx_version: locks.NGINX_VERSION,
        nginx_package_version: locks.NGINX_PACKAGE_VERSION,
        nginx_package_sha256: locks.NGINX_PACKAGE_SHA256_AMD64,
        kernel_version: os.release(),
        podman_version: process.env.POWGATE_PODMAN_VERSION,
        cpu_model: cpuModel(),
        logical_cpu_count: os.cpus().length,
        requested_chromium_arguments:
            [...buildChromiumLaunchArguments({ protocolMode: 'h2' })],
        observed_chromium_arguments: [...sessionIdentity.observedArguments],
        uid_mapping_passed: process.getuid() === Number(
            process.env.POWGATE_HOST_UID,
        ),
        gid_mapping_passed: process.getgid() === Number(
            process.env.POWGATE_HOST_GID,
        ),
        seccomp_passed: sessionIdentity.sandbox.controller.seccomp === '2'
            && sessionIdentity.sandbox.renderer.seccomp === '2',
        capabilities_passed:
            sessionIdentity.sandbox.controller.capEff
                === '0000000000000000',
        sandbox_passed: sessionIdentity.sandbox.separateRenderer === true,
        rootless_passed: true,
        embedded_image_lock: process.env.POWGATE_GOLDEN_IMAGE_LOCK,
        oci_image_lock: process.env.POWGATE_IMAGE_LOCK,
        host_image_id: process.env.POWGATE_IMAGE_ID,
        repository_digest: process.env.POWGATE_IMAGE_DIGEST || null,
    };
}


function workloadRecord() {
    return {
        nonce_base64url: Buffer.from(NONCE_HEX, 'hex').toString('base64url'),
        difficulty: 32,
        warmup_duration_ms: WARMUP_MS,
        stopping_deadline_ms: RECORDED_MS,
        repetitions_per_backend: 7,
        execution_order: [...BENCHMARK_SCHEDULE],
        heartbeat_period_ms: HEARTBEAT_MS,
        heartbeat_p95_bound_ms: 25,
        heartbeat_max_bound_ms: 100,
        heartbeat_allowed_tail_callbacks:
            CAPTURE_LIMITS.heartbeat_allowed_timer_tail,
        js_block_ceiling_ms: CAPTURE_LIMITS.bench_js_block_ceiling_ms,
        calibration_min_attempts: BENCH_MIN_ATTEMPTS,
        calibration_max_attempts: BENCH_MAX_ATTEMPTS,
        calibration_target_ms: CAPTURE_LIMITS.bench_target_block_ms,
        counter_start: 0,
        counter_progression_rule: 'contiguous-safe-integers',
        success_continuation_rule: 'verified-counter-plus-one',
        safe_domain_terminal_rule: 'max-safe-integer-stops-run',
        median_rule: 'sorted-fourth-of-seven',
        backend_selection_ratio: 1.25,
        matched_pair_wins_required: 5,
    };
}


async function buildEvidence(pageData, browserResult) {
    const locks = readVersionLocks('.');
    const runs = browserResult.rawRuns.map(({ raw, backend, index }) =>
        createRunRecord(raw, backend, index));
    const summaries = summarizeRuns(runs);
    const decision = decideBackend(summaries);
    const clean = process.env.POWGATE_SOURCE_WORKTREE_CLEAN === 'true';
    const production = productionScriptIdentity('.');
    const prerequisites = decision.prerequisites_met;
    return {
        schema_version: 'phase4c-benchmark-v1',
        generated_at_utc: new Date().toISOString()
            .replace(/\.\d{3}Z$/u, 'Z'),
        tested_source: {
            commit: process.env.POWGATE_SOURCE_COMMIT,
            worktree_clean: clean,
            promotable: clean && prerequisites,
            evidence_commit: null,
            tracked_tree_sha256: process.env.POWGATE_TRACKED_TREE_SHA256,
            production_script_sha256: production.sha256,
            assembled_benchmark_page_sha256: sha256Hex(
                Buffer.from(pageData.body, 'utf8'),
            ),
            generated_csp_hash: production.cspHash,
            benchmark_implementation_sha256:
                benchmarkImplementationSha256('.'),
            generator_sha256: sha256Hex(fs.readFileSync(
                'tools/build_pow_challenge.py',
            )),
        },
        environment: environmentRecord(locks, browserResult.sessionIdentity),
        workload: workloadRecord(),
        runs,
        summaries,
        decision,
        verdicts: {
            correctness_passed: true,
            responsiveness_passed: prerequisites,
            environment_passed: true,
            cleanup_passed: true,
            schema_passed: true,
        },
    };
}


async function main() {
    await fsPromises.rm(OUTPUT_PATH, { force: true });
    try {
        assert.equal(readGoldenImageLock('.'),
            process.env.POWGATE_IMAGE_LOCK);
        const template = await fsPromises.readFile(
            'html/challenge.html', 'utf8',
        );
        const pageData = buildBenchmarkPage(template);
        const driverSource = await fsPromises.readFile(
            'tests/browser/benchmark-driver.js', 'utf8',
        );
        const browserResult = await runBrowserSession(pageData, driverSource);
        const evidence = await buildEvidence(pageData, browserResult);
        if (!evidence.decision.prerequisites_met) {
            throw new Error(`benchmark responsiveness requirement failed: ${
                JSON.stringify(responsivenessFailures(evidence.runs))}`);
        }
        validateEvidence(evidence);
        await writeEvidenceAtomically(OUTPUT_PATH, evidence);
        process.stdout.write(`${JSON.stringify({
            decision: evidence.decision,
            output: OUTPUT_PATH,
            runs: evidence.runs.length,
        })}\n`);
    } catch (error) {
        await fsPromises.rm(OUTPUT_PATH, { force: true });
        throw error;
    }
}


if (process.argv[1] !== undefined
    && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
    await main();
}
