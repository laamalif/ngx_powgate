import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import test from 'node:test';

import {
    BENCH_MAX_ATTEMPTS,
    BENCH_MIN_ATTEMPTS,
    BENCHMARK_SCHEDULE,
    accountHeartbeatDeadlines,
    buildBenchmarkPage,
    decideBackend,
    deriveContinuation,
    nearestRankP95,
    normalizeCalibrationDuration,
    selectCalibrationAttempts,
    summarizeRuns,
    responsivenessFailures,
} from './benchmark.mjs';
import { benchmarkImplementationSha256 } from './lib/evidence.mjs';


function result(overrides = {}) {
    return Object.freeze({
        found: false,
        exhausted: false,
        counter: null,
        nextCounter: 10,
        attempts: 10,
        ...overrides,
    });
}


function decisionRuns({ subtleRatio = 1.3, subtleWins = 7,
    valid = true, responsive = true } = {}) {
    const runs = [];
    for (let pair = 1; pair <= 7; pair += 1) {
        const subtleWinner = pair <= subtleWins;
        const jsThroughput = 1000;
        const subtleThroughput = subtleWinner
            ? 1000 * subtleRatio
            : 900;
        for (const backend of BENCHMARK_SCHEDULE.slice(
            (pair - 1) * 2, pair * 2,
        )) {
            runs.push({
                backend,
                pair,
                throughput_candidates_per_second:
                    backend === 'js' ? jsThroughput : subtleThroughput,
                heartbeat_p95_ms: responsive ? 1 : 26,
                heartbeat_max_ms: responsive ? 2 : 101,
                js_block_durations_ms: backend === 'js' ? [10] : [],
                correctness_passed: valid,
            });
        }
    }
    return runs;
}


test('success continuation requires verified terminal result', () => {
    const success = result({
        found: true,
        counter: 34,
        nextCounter: null,
        attempts: 35,
    });

    assert.throws(() => deriveContinuation(success, false), /verified/);
    assert.deepEqual(deriveContinuation(success, true), {
        resumeCounter: 35,
        safeDomainTerminal: false,
    });
    assert.throws(() => deriveContinuation({
        ...success,
        nextCounter: 35,
    }, true), /result/);
});


test('maximum safe success terminates without constructing a successor', () => {
    const continuation = deriveContinuation(result({
        found: true,
        counter: Number.MAX_SAFE_INTEGER,
        nextCounter: null,
        attempts: 1,
    }), true);

    assert.deepEqual(continuation, {
        resumeCounter: null,
        safeDomainTerminal: true,
    });
});


test('resumable continuation preserves the first untested counter', () => {
    assert.deepEqual(deriveContinuation(result({
        nextCounter: 100,
        attempts: 25,
    }), false), {
        resumeCounter: 100,
        safeDomainTerminal: false,
    });
    assert.deepEqual(deriveContinuation(result({
        exhausted: true,
        nextCounter: null,
        attempts: 1,
    }), false), {
        resumeCounter: null,
        safeDomainTerminal: true,
    });
});


test('delayed heartbeat accounts for every elapsed deadline exactly once', () => {
    const first = accountHeartbeatDeadlines({
        actualTime: 18,
        nextDeadline: 5,
        recordedEnd: 20,
        period: 5,
    });
    assert.deepEqual(first, {
        nextDeadline: 20,
        samples: [
            { deadline_performance_ms: 5, delay_ms: 13 },
            { deadline_performance_ms: 10, delay_ms: 8 },
            { deadline_performance_ms: 15, delay_ms: 3 },
        ],
    });
    const second = accountHeartbeatDeadlines({
        actualTime: 27,
        nextDeadline: first.nextDeadline,
        recordedEnd: 24,
        period: 5,
    });
    assert.deepEqual(second, {
        nextDeadline: 25,
        samples: [{ deadline_performance_ms: 20, delay_ms: 7 }],
    });
});


test('nearest-rank p95 uses the ceiling rank', () => {
    assert.equal(nearestRankP95([100, 1, 2, 3, 4]), 100);
    assert.equal(nearestRankP95(Array.from({ length: 20 }, (_, i) => i + 1)),
        19);
    assert.throws(() => nearestRankP95([]), /empty/);
});


test('calibration is bounded, positive, and safe at the counter boundary', () => {
    assert.equal(selectCalibrationAttempts({
        currentAttempts: 100,
        durationMs: 20,
        startCounter: 0,
    }), 50);
    assert.equal(selectCalibrationAttempts({
        currentAttempts: 1,
        durationMs: 1000,
        startCounter: 0,
    }), BENCH_MIN_ATTEMPTS);
    assert.equal(selectCalibrationAttempts({
        currentAttempts: BENCH_MAX_ATTEMPTS,
        durationMs: 0.001,
        startCounter: 0,
    }), BENCH_MAX_ATTEMPTS);
    assert.equal(selectCalibrationAttempts({
        currentAttempts: 100,
        durationMs: 1,
        startCounter: Number.MAX_SAFE_INTEGER,
    }), 1);
    assert.throws(() => selectCalibrationAttempts({
        currentAttempts: 0,
        durationMs: 1,
        startCounter: 0,
    }), /attempt/);
});


test('browser timer resolution is floored before calibration', () => {
    assert.equal(normalizeCalibrationDuration(0), 0.1);
    assert.equal(normalizeCalibrationDuration(0.25), 0.25);
    assert.throws(() => normalizeCalibrationDuration(-1), /duration/);
    assert.throws(() => normalizeCalibrationDuration(Number.NaN), /duration/);
});


test('schedule is exactly seven alternating matched pairs', () => {
    assert.deepEqual(BENCHMARK_SCHEDULE, [
        'js', 'subtle', 'subtle', 'js', 'js', 'subtle', 'subtle',
        'js', 'js', 'subtle', 'subtle', 'js', 'js', 'subtle',
    ]);
    assert.equal(Object.isFrozen(BENCHMARK_SCHEDULE), true);
});


test('mechanical decision requires ratio, wins, validity, and responsiveness',
    () => {
        const selected = decideBackend(summarizeRuns(decisionRuns()));
        assert.equal(selected.selected_primary_backend, 'subtle');
        assert.equal(selected.ratio_threshold_met, true);
        assert.equal(selected.matched_pair_requirement_met, true);
        assert.equal(selected.prerequisites_met, true);

        for (const runs of [
            decisionRuns({ subtleRatio: 1.249 }),
            decisionRuns({ subtleWins: 4 }),
            decisionRuns({ valid: false }),
            decisionRuns({ responsive: false }),
        ]) {
            const decision = decideBackend(summarizeRuns(runs));
            assert.equal(decision.selected_primary_backend, 'js');
            if (!decision.prerequisites_met) {
                assert.equal(decision.rationale_token,
                    'js-default-threshold-not-met');
            }
        }
    });


test('responsiveness diagnostics retain only bounded aggregate verdicts', () => {
    const runs = decisionRuns();
    runs[0].heartbeat_p95_ms = 26;
    runs[0].heartbeat_max_ms = 101;
    runs[0].js_block_durations_ms = [10, 26];

    assert.deepEqual(responsivenessFailures(runs), [{
        backend: 'js',
        heartbeat_max_ms: 101,
        heartbeat_p95_ms: 26,
        max_js_block_ms: 26,
        pair: 1,
    }]);
});


test('benchmark page embeds exact production script with inert parameters',
    async () => {
        const template = await fs.readFile('html/challenge.html', 'utf8');
        const match = template.match(/<script>([\s\S]*?)<\/script>/u);
        assert.ok(match);

        const page = buildBenchmarkPage(template);
        assert.equal(page.script, match[1]);
        assert.equal((page.body.match(/<script>/gu) ?? []).length, 1);
        assert.match(page.body,
            /<script id="pow-params" type="application\/json">\{\}<\/script>/u);
        assert.equal(page.body.includes('PowGateBenchmark'), false);
        assert.equal(page.scriptDigest, crypto.createHash('sha256')
            .update(match[1], 'utf8').digest('base64'));
    });


test('checked-in driver calls only the unchanged public solver API',
    async () => {
        const source = await fs.readFile(
            'tests/browser/benchmark-driver.js', 'utf8',
        );
        assert.match(source, /PowGateSolver\.solve/u);
        assert.doesNotMatch(source, /crypto\.subtle\.digest/u);
        assert.doesNotMatch(source, /\bWorker\b/u);
        assert.doesNotMatch(source, /Promise\.all/u);
        assert.doesNotMatch(source, /globalThis\.PowGateSolver\s*=/u);
    });


test('benchmark implementation identity covers executable and page driver',
    async () => {
        const expected = crypto.createHash('sha256');
        for (const file of [
            'tests/browser/benchmark.mjs',
            'tests/browser/benchmark-driver.js',
        ]) {
            const bytes = await fs.readFile(file);
            const length = Buffer.alloc(8);
            length.writeBigUInt64BE(BigInt(bytes.length));
            expected.update(length);
            expected.update(bytes);
        }
        assert.equal(
            benchmarkImplementationSha256('.'),
            expected.digest('hex'),
        );
    });
