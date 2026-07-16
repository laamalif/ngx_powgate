import crypto from 'node:crypto';
import fs from 'node:fs';
import fsPromises from 'node:fs/promises';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';


const require = createRequire('/opt/ngx-powgate/browser/package.json');
const Ajv2020 = require('ajv/dist/2020.js').default;
const SCHEMA_PATH = new URL(
    '../../../docs/benchmarks/phase4c-v1/schema.json', import.meta.url,
);
const SCHEMA = JSON.parse(fs.readFileSync(SCHEMA_PATH, 'utf8'));
const MAX_EVIDENCE_BYTES = 16 * 1024 * 1024;
const BACKENDS = Object.freeze(['js', 'subtle']);
const BENCHMARK_IMPLEMENTATION_FILES = Object.freeze([
    'tests/browser/benchmark.mjs',
]);
const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    validateFormats: false,
});
const validateSchema = ajv.compile(SCHEMA);


function fail(message) {
    throw new TypeError(`invalid Phase 4C evidence: ${message}`);
}


function equalNumber(actual, expected) {
    const scale = Math.max(1, Math.abs(actual), Math.abs(expected));
    return Math.abs(actual - expected) <= Number.EPSILON * scale * 16;
}


function maximum(values) {
    return values.length === 0 ? null : Math.max(...values);
}


function nearestRankP95(values) {
    if (values.length === 0) {
        fail('heartbeat series is empty');
    }
    const sorted = [...values].sort((a, b) => a - b);
    return sorted[Math.ceil(sorted.length * 0.95) - 1];
}


function medianSeven(values) {
    if (values.length !== 7) {
        fail('backend does not have seven throughput values');
    }
    return [...values].sort((a, b) => a - b)[3];
}


function assertNumber(actual, expected, label) {
    if (!equalNumber(actual, expected)) {
        fail(`${label} mismatch`);
    }
}


function validateRun(run, index, evidence) {
    const workload = evidence.workload;
    const expectedBackend = workload.execution_order[index];
    const expectedPair = Math.floor(index / 2) + 1;
    const expectedPosition = (index % 2) + 1;
    const elapsed = run.recorded_end_performance_ms
        - run.recorded_start_performance_ms;
    const expectedThroughput = run.completed_candidates / (elapsed / 1000);
    const delays = run.heartbeat_samples.map((sample) => sample.delay_ms);
    const expectedSamples = Math.floor(
        elapsed / workload.heartbeat_period_ms,
    ) - workload.heartbeat_allowed_tail_callbacks;

    if (run.backend !== expectedBackend || run.pair !== expectedPair
        || run.execution_position !== expectedPosition) {
        fail(`run ${index} order mismatch`);
    }
    if (elapsed <= 0 || elapsed < workload.stopping_deadline_ms) {
        fail(`run ${index} elapsed interval is incomplete`);
    }
    assertNumber(run.elapsed_ms, elapsed, `run ${index} elapsed`);
    assertNumber(
        run.deadline_overrun_ms,
        elapsed - workload.stopping_deadline_ms,
        `run ${index} deadline overrun`,
    );
    assertNumber(
        run.throughput_candidates_per_second,
        expectedThroughput,
        `run ${index} throughput`,
    );
    if (run.heartbeat_samples.length < expectedSamples) {
        fail(`run ${index} heartbeat series is incomplete`);
    }
    for (let sampleIndex = 0;
        sampleIndex < run.heartbeat_samples.length; sampleIndex += 1) {
        const sample = run.heartbeat_samples[sampleIndex];
        const expectedDeadline = run.recorded_start_performance_ms
            + ((sampleIndex + 1) * workload.heartbeat_period_ms);
        assertNumber(
            sample.deadline_performance_ms,
            expectedDeadline,
            `run ${index} heartbeat deadline ${sampleIndex}`,
        );
        if (sample.deadline_performance_ms
            > run.recorded_end_performance_ms) {
            fail(`run ${index} heartbeat deadline exceeds recorded end`);
        }
    }
    assertNumber(
        run.heartbeat_p95_ms,
        nearestRankP95(delays),
        `run ${index} heartbeat p95`,
    );
    assertNumber(
        run.heartbeat_max_ms,
        Math.max(...delays),
        `run ${index} heartbeat maximum`,
    );
    if (run.valid_hit_count === 0
        && run.first_valid_hit_offset !== null) {
        fail(`run ${index} has an offset without a valid hit`);
    }
    if (run.valid_hit_count > 0
        && (run.first_valid_hit_offset === null
            || run.first_valid_hit_offset >= run.completed_candidates)) {
        fail(`run ${index} has invalid hit metadata`);
    }
    if (!run.document_visible || !run.counter_contiguous
        || !run.correctness_passed || !run.context_cleanup_passed
        || run.safe_domain_terminal) {
        fail(`run ${index} has a failing mandatory verdict`);
    }
    if (run.backend === 'js') {
        if (run.js_block_durations_ms.length === 0
            || run.subtle_sync_entry_durations_ms.length !== 0
            || run.subtle_awaited_invocation_durations_ms.length !== 0
            || run.subtle_async_remainder_durations_ms.length !== 0) {
            fail(`run ${index} has invalid JavaScript timing ownership`);
        }
    } else {
        const count = run.subtle_awaited_invocation_durations_ms.length;
        if (run.js_block_durations_ms.length !== 0 || count === 0
            || run.subtle_sync_entry_durations_ms.length !== count
            || run.subtle_async_remainder_durations_ms.length !== count) {
            fail(`run ${index} has invalid SubtleCrypto timing ownership`);
        }
        for (let timingIndex = 0; timingIndex < count; timingIndex += 1) {
            assertNumber(
                run.subtle_async_remainder_durations_ms[timingIndex],
                run.subtle_awaited_invocation_durations_ms[timingIndex]
                    - run.subtle_sync_entry_durations_ms[timingIndex],
                `run ${index} asynchronous remainder ${timingIndex}`,
            );
        }
    }
}


function backendRuns(evidence, backend) {
    return evidence.runs.filter((run) => run.backend === backend);
}


function validateSummaries(evidence) {
    const summaries = evidence.summaries;
    const pairWinners = { js: 0, subtle: 0 };

    for (let pair = 1; pair <= 7; pair += 1) {
        const runs = evidence.runs.filter((run) => run.pair === pair);
        const js = runs.find((run) => run.backend === 'js');
        const subtle = runs.find((run) => run.backend === 'subtle');
        if (js.throughput_candidates_per_second
            > subtle.throughput_candidates_per_second) {
            pairWinners.js += 1;
        } else if (subtle.throughput_candidates_per_second
            > js.throughput_candidates_per_second) {
            pairWinners.subtle += 1;
        }
    }

    for (const backend of BACKENDS) {
        const runs = backendRuns(evidence, backend);
        const summary = summaries[backend];
        const throughputs = runs.map(
            (run) => run.throughput_candidates_per_second,
        );
        const heartbeatMax = Math.max(...runs.map(
            (run) => run.heartbeat_max_ms,
        ));
        const heartbeatP95Max = Math.max(...runs.map(
            (run) => run.heartbeat_p95_ms,
        ));
        const jsBlocks = runs.flatMap((run) => run.js_block_durations_ms);
        const responsive = runs.every((run) =>
            run.heartbeat_p95_ms <= evidence.workload.heartbeat_p95_bound_ms
            && run.heartbeat_max_ms
                <= evidence.workload.heartbeat_max_bound_ms
            && (backend !== 'js' || maximum(run.js_block_durations_ms)
                <= evidence.workload.js_block_ceiling_ms));

        for (let index = 0; index < 7; index += 1) {
            assertNumber(
                summary.throughput_values[index],
                throughputs[index],
                `${backend} throughput summary ${index}`,
            );
        }
        assertNumber(
            summary.median_throughput,
            medianSeven(throughputs),
            `${backend} median`,
        );
        assertNumber(
            summary.heartbeat_max_ms,
            heartbeatMax,
            `${backend} heartbeat maximum summary`,
        );
        assertNumber(
            summary.heartbeat_p95_max_ms,
            heartbeatP95Max,
            `${backend} heartbeat p95 summary`,
        );
        if (backend === 'js') {
            assertNumber(
                summary.max_js_block_ms,
                Math.max(...jsBlocks),
                'JavaScript block maximum summary',
            );
        } else if (summary.max_js_block_ms !== null) {
            fail('SubtleCrypto summary has a JavaScript block maximum');
        }
        if (summary.matched_pair_wins !== pairWinners[backend]
            || summary.correctness_passed !== runs.every(
                (run) => run.correctness_passed,
            )
            || summary.responsiveness_passed !== responsive) {
            fail(`${backend} summary verdict mismatch`);
        }
    }
}


function validateDecision(evidence) {
    const js = evidence.summaries.js;
    const subtle = evidence.summaries.subtle;
    const decision = evidence.decision;
    const ratio = subtle.median_throughput / js.median_throughput;
    const ratioMet = ratio >= evidence.workload.backend_selection_ratio;
    const pairMet = subtle.matched_pair_wins
        >= evidence.workload.matched_pair_wins_required;
    const prerequisites = BACKENDS.every((backend) =>
        evidence.summaries[backend].correctness_passed
        && evidence.summaries[backend].responsiveness_passed)
        && evidence.verdicts.correctness_passed
        && evidence.verdicts.responsiveness_passed
        && evidence.verdicts.environment_passed
        && evidence.verdicts.cleanup_passed
        && evidence.verdicts.schema_passed;
    const selectSubtle = prerequisites && ratioMet && pairMet;

    assertNumber(
        decision.subtle_to_js_median_ratio,
        ratio,
        'backend median ratio',
    );
    if (decision.ratio_threshold_met !== ratioMet
        || decision.matched_pair_requirement_met !== pairMet
        || decision.prerequisites_met !== prerequisites
        || decision.selected_primary_backend
            !== (selectSubtle ? 'subtle' : 'js')
        || decision.selected_secondary_backend
            !== (selectSubtle ? 'js' : 'subtle')
        || decision.rationale_token !== (selectSubtle
            ? 'subtle-materially-faster'
            : 'js-default-threshold-not-met')) {
        fail('backend decision mismatch');
    }
    const promotable = evidence.tested_source.worktree_clean
        && prerequisites;
    if (evidence.tested_source.promotable !== promotable) {
        fail('promotability mismatch');
    }
}


export function validateEvidence(evidence) {
    if (!validateSchema(evidence)) {
        throw new TypeError(
            `invalid Phase 4C evidence schema: ${JSON.stringify(
                validateSchema.errors,
            )}`,
        );
    }
    evidence.runs.forEach((run, index) => validateRun(run, index, evidence));
    if (backendRuns(evidence, 'js').length !== 7
        || backendRuns(evidence, 'subtle').length !== 7) {
        fail('backend run count mismatch');
    }
    if (evidence.workload.calibration_min_attempts
        > evidence.workload.calibration_max_attempts) {
        fail('calibration bounds are reversed');
    }
    validateSummaries(evidence);
    validateDecision(evidence);
}


function canonicalValue(value, ancestors) {
    if (typeof value === 'number') {
        if (!Number.isFinite(value)) {
            throw new TypeError('canonical JSON numbers must be finite');
        }
        if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
            throw new TypeError('canonical JSON integers must be safe');
        }
        return value;
    }
    if (value === null || typeof value === 'string'
        || typeof value === 'boolean') {
        return value;
    }
    if (typeof value !== 'object') {
        throw new TypeError('canonical JSON contains an unsupported value');
    }
    if (ancestors.has(value)) {
        throw new TypeError('canonical JSON contains a cycle');
    }
    ancestors.add(value);
    let result;
    if (Array.isArray(value)) {
        result = value.map((item) => canonicalValue(item, ancestors));
    } else {
        result = {};
        const keys = Object.keys(value);
        for (const key of keys) {
            if (!/^[\x20-\x7e]+$/u.test(key)) {
                throw new TypeError('canonical JSON object keys must be ASCII');
            }
        }
        keys.sort((left, right) => Buffer.compare(
            Buffer.from(left, 'ascii'), Buffer.from(right, 'ascii'),
        ));
        for (const key of keys) {
            result[key] = canonicalValue(value[key], ancestors);
        }
    }
    ancestors.delete(value);
    return result;
}


export function canonicalJson(value) {
    const canonical = canonicalValue(value, new Set());
    return Buffer.from(`${JSON.stringify(canonical, null, 2)}\n`, 'utf8');
}


export function encodeVersion(version) {
    if (typeof version !== 'string' || version.length === 0) {
        throw new TypeError('package version must be a non-empty string');
    }
    let encoded = '';
    for (const byte of Buffer.from(version, 'utf8')) {
        const character = String.fromCharCode(byte);
        if (/[A-Za-z0-9._-]/u.test(character)) {
            encoded += character;
        } else {
            encoded += `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
        }
    }
    return encoded;
}


export function canonicalEvidenceFilename(architecture, packageName, version) {
    for (const [label, value] of [
        ['architecture', architecture], ['package', packageName],
    ]) {
        if (typeof value !== 'string'
            || !/^[A-Za-z0-9._-]+$/u.test(value)) {
            throw new TypeError(`${label} identifier is invalid`);
        }
    }
    return `${architecture}-debian-${packageName}-${encodeVersion(version)}.json`;
}


export async function writeEvidenceAtomically(output, evidence, {
    validate = validateEvidence,
} = {}) {
    const directory = path.dirname(output);
    const temporary = path.join(
        directory,
        `.${path.basename(output)}.${process.pid}.${crypto.randomUUID()}.tmp`,
    );

    await fsPromises.mkdir(directory, { recursive: true });
    await fsPromises.rm(output, { force: true });
    try {
        validate(evidence);
        const bytes = canonicalJson(evidence);
        if (bytes.length > MAX_EVIDENCE_BYTES) {
            throw new RangeError('Phase 4C evidence exceeds 16 MiB');
        }
        const handle = await fsPromises.open(temporary, 'wx', 0o600);
        try {
            await handle.writeFile(bytes);
            await handle.sync();
        } finally {
            await handle.close();
        }
        await fsPromises.rename(temporary, output);
        const written = await fsPromises.readFile(output);
        const reparsed = JSON.parse(written.toString('utf8'));
        validate(reparsed);
        if (!written.equals(canonicalJson(reparsed))) {
            throw new TypeError('written Phase 4C evidence is not canonical');
        }
    } catch (error) {
        await fsPromises.rm(temporary, { force: true });
        await fsPromises.rm(output, { force: true });
        throw error;
    }
}


export function sha256Hex(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}


export function trackedTreeSha256(root) {
    const listing = execFileSync('git', ['ls-files', '--stage', '-z'], {
        cwd: root,
    });
    return sha256Hex(listing);
}


export function productionScriptIdentity(root) {
    const html = fs.readFileSync(path.join(root, 'html/challenge.html'));
    const opening = Buffer.from('<script>');
    const closing = Buffer.from('</script>');
    const openAt = html.indexOf(opening);
    const closeAt = html.indexOf(closing, openAt + opening.length);
    if (openAt === -1 || closeAt === -1
        || html.indexOf(opening, openAt + opening.length) !== -1
        || html.indexOf(closing, closeAt + closing.length) !== -1) {
        throw new TypeError('challenge template has invalid script structure');
    }
    const script = html.subarray(openAt + opening.length, closeAt);
    return Object.freeze({
        sha256: sha256Hex(script),
        cspHash: `sha256-${crypto.createHash('sha256')
            .update(script).digest('base64')}`,
    });
}


export function benchmarkImplementationSha256(root) {
    const hash = crypto.createHash('sha256');
    for (const relative of BENCHMARK_IMPLEMENTATION_FILES) {
        const bytes = fs.readFileSync(path.join(root, relative));
        const length = Buffer.alloc(8);
        length.writeBigUInt64BE(BigInt(bytes.length));
        hash.update(length);
        hash.update(bytes);
    }
    return hash.digest('hex');
}


export function readVersionLocks(root) {
    const contents = fs.readFileSync(
        path.join(root, 'build/versions.env'), 'ascii',
    );
    const locks = Object.create(null);
    for (const line of contents.split('\n')) {
        if (line === '' || line.startsWith('#')) {
            continue;
        }
        const separator = line.indexOf('=');
        if (separator <= 0) {
            throw new TypeError('version lock contains an invalid line');
        }
        const name = line.slice(0, separator);
        if (Object.hasOwn(locks, name)) {
            throw new TypeError('version lock contains a duplicate name');
        }
        locks[name] = line.slice(separator + 1);
    }
    return Object.freeze(locks);
}


export function readGoldenImageLock(root) {
    const lock = readVersionLocks(root).GOLDEN_IMAGE_LOCK_SHA256;
    if (lock === undefined || !/^[0-9a-f]{64}$/u.test(lock)) {
        throw new TypeError('golden image lock is missing');
    }
    return lock;
}
