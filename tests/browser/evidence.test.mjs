import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import test from 'node:test';

import {
    canonicalEvidenceFilename,
    canonicalJson,
    encodeVersion,
    validateEvidence,
    writeEvidenceAtomically,
} from './lib/evidence.mjs';
import {
    promotePhase4CEvidence,
} from '../../tools/promote-phase4c-evidence.mjs';
import {
    checkCommittedPhase4CEvidence,
} from '../../tools/check-phase4c-evidence.mjs';


const ROOT = path.resolve(import.meta.dirname, '../..');
const SCHEMA_PATH = path.join(
    ROOT, 'docs/benchmarks/phase4c-v1/schema.json',
);
const RESULT_PATH = 'build/benchmark-browser-result.json';
const LOCK = 'a'.repeat(64);


function sha256(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}


function heartbeatSamples(start, end, period) {
    const samples = [];

    for (let deadline = start + period; deadline <= end; deadline += period) {
        samples.push({ deadline_performance_ms: deadline, delay_ms: 1 });
    }
    return samples;
}


function median(values) {
    return [...values].sort((a, b) => a - b)[3];
}


function syntheticEvidence() {
    const order = [
        'js', 'subtle', 'subtle', 'js', 'js', 'subtle', 'subtle',
        'js', 'js', 'subtle', 'subtle', 'js', 'js', 'subtle',
    ];
    const runs = order.map((backend, index) => {
        const pair = Math.floor(index / 2) + 1;
        const completed = (backend === 'js' ? 10000 : 13000) + pair;
        const start = 100;
        const end = 10100;
        const throughput = completed / 10;

        return {
            backend,
            pair,
            execution_position: (index % 2) + 1,
            calibrated_attempt_limit: 128,
            warmup_duration_ms: 2000,
            recorded_start_performance_ms: start,
            recorded_end_performance_ms: end,
            completed_candidates: completed,
            valid_hit_count: 0,
            first_valid_hit_offset: null,
            safe_domain_terminal: false,
            elapsed_ms: 10000,
            deadline_overrun_ms: 0,
            throughput_candidates_per_second: throughput,
            heartbeat_samples: heartbeatSamples(start, end, 5),
            heartbeat_p95_ms: 1,
            heartbeat_max_ms: 1,
            js_block_durations_ms: backend === 'js' ? [10] : [],
            subtle_sync_entry_durations_ms:
                backend === 'subtle' ? [0.25] : [],
            subtle_awaited_invocation_durations_ms:
                backend === 'subtle' ? [2] : [],
            subtle_async_remainder_durations_ms:
                backend === 'subtle' ? [1.75] : [],
            document_visible: true,
            counter_contiguous: true,
            correctness_passed: true,
            context_cleanup_passed: true,
        };
    });
    const jsThroughputs = runs.filter((run) => run.backend === 'js')
        .map((run) => run.throughput_candidates_per_second);
    const subtleThroughputs = runs.filter((run) => run.backend === 'subtle')
        .map((run) => run.throughput_candidates_per_second);
    const jsMedian = median(jsThroughputs);
    const subtleMedian = median(subtleThroughputs);

    return {
        schema_version: 'phase4c-benchmark-v1',
        generated_at_utc: '2026-07-16T12:00:00Z',
        tested_source: {
            commit: '1'.repeat(40),
            worktree_clean: true,
            promotable: true,
            evidence_commit: null,
            tracked_tree_sha256: '2'.repeat(64),
            production_script_sha256: '3'.repeat(64),
            assembled_benchmark_page_sha256: '4'.repeat(64),
            generated_csp_hash: `sha256-${Buffer.alloc(32, 5).toString('base64')}`,
            benchmark_implementation_sha256: '6'.repeat(64),
            generator_sha256: '7'.repeat(64),
        },
        environment: {
            host_architecture: 'x86_64',
            container_architecture: 'x86_64',
            debian_snapshot: '20260713T000000Z',
            debian_base_image_digest:
                `docker.io/library/debian@sha256:${'d'.repeat(64)}`,
            chromium_package_version: '150.0.7871.100-1~deb13u1',
            chromium_package_sha256: '8'.repeat(64),
            chromium_sandbox_package_version:
                '150.0.7871.100-1~deb13u1',
            chromium_sandbox_package_sha256: 'a'.repeat(64),
            chromium_cdp_version: 'Chrome/150.0.7871.100',
            nodejs_package_version: '20.19.2+dfsg-1+deb13u2',
            nodejs_package_sha256: 'b'.repeat(64),
            npm_package_version: '9.2.0~ds1-3',
            npm_package_sha256: 'c'.repeat(64),
            puppeteer_core_version: '24.43.1',
            ajv_version: '8.17.1',
            ajv_integrity:
                'sha512-B/gBuNg5SiMTrPkC+A2+cW0RszwxYmn6VYxB/inlBStS5nx6xHIt/ehKRhIMhqusl7a8LjQoZnjCs5vhwxOQ1g==',
            nginx_version: '1.30.3',
            nginx_package_version: '1.30.3-1~trixie',
            nginx_package_sha256: 'e'.repeat(64),
            kernel_version: '6.12.0',
            podman_version: '5.4.2',
            cpu_model: 'Synthetic CPU',
            logical_cpu_count: 8,
            requested_chromium_arguments: ['--headless=new'],
            observed_chromium_arguments: ['--headless=new'],
            uid_mapping_passed: true,
            gid_mapping_passed: true,
            seccomp_passed: true,
            capabilities_passed: true,
            sandbox_passed: true,
            rootless_passed: true,
            embedded_image_lock: LOCK,
            oci_image_lock: LOCK,
            host_image_id: `sha256:${'9'.repeat(64)}`,
            repository_digest: null,
        },
        workload: {
            nonce_base64url:
                'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            difficulty: 32,
            warmup_duration_ms: 2000,
            stopping_deadline_ms: 10000,
            repetitions_per_backend: 7,
            execution_order: order,
            heartbeat_period_ms: 5,
            heartbeat_p95_bound_ms: 25,
            heartbeat_max_bound_ms: 100,
            heartbeat_allowed_tail_callbacks: 0,
            js_block_ceiling_ms: 25,
            calibration_min_attempts: 1,
            calibration_max_attempts: 65536,
            calibration_target_ms: 10,
            counter_start: 0,
            counter_progression_rule: 'contiguous-safe-integers',
            success_continuation_rule: 'verified-counter-plus-one',
            safe_domain_terminal_rule: 'max-safe-integer-stops-run',
            median_rule: 'sorted-fourth-of-seven',
            backend_selection_ratio: 1.25,
            matched_pair_wins_required: 5,
        },
        runs,
        summaries: {
            js: {
                throughput_values: jsThroughputs,
                median_throughput: jsMedian,
                heartbeat_max_ms: 1,
                heartbeat_p95_max_ms: 1,
                max_js_block_ms: 10,
                matched_pair_wins: 0,
                correctness_passed: true,
                responsiveness_passed: true,
            },
            subtle: {
                throughput_values: subtleThroughputs,
                median_throughput: subtleMedian,
                heartbeat_max_ms: 1,
                heartbeat_p95_max_ms: 1,
                max_js_block_ms: null,
                matched_pair_wins: 7,
                correctness_passed: true,
                responsiveness_passed: true,
            },
        },
        decision: {
            selected_primary_backend: 'subtle',
            selected_secondary_backend: 'js',
            subtle_to_js_median_ratio: subtleMedian / jsMedian,
            ratio_threshold_met: true,
            matched_pair_requirement_met: true,
            prerequisites_met: true,
            rationale_token: 'subtle-materially-faster',
        },
        verdicts: {
            correctness_passed: true,
            responsiveness_passed: true,
            environment_passed: true,
            cleanup_passed: true,
            schema_passed: true,
        },
    };
}


function clone(value) {
    return structuredClone(value);
}


function runGit(root, ...args) {
    return execFileSync('git', args, {
        cwd: root,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
}


async function writePromotionRepository(root) {
    const script = Buffer.from('globalThis.PowGateSolver = Object.freeze({});');
    const html = Buffer.concat([
        Buffer.from('<!doctype html><script>'), script, Buffer.from('</script>'),
    ]);
    const generator = Buffer.from('#!/usr/bin/env python3\n');
    const benchmark = Buffer.from('export const benchmark = true;\n');
    const benchmarkDriver = Buffer.from('globalThis.driver = true;\n');

    await fs.mkdir(path.join(root, 'html'), { recursive: true });
    await fs.mkdir(path.join(root, 'tools'), { recursive: true });
    await fs.mkdir(path.join(root, 'tests/browser'), { recursive: true });
    await fs.mkdir(path.join(root, 'build'), { recursive: true });
    await fs.writeFile(path.join(root, '.gitignore'), 'build/\n');
    await fs.writeFile(path.join(root, 'html/challenge.html'), html);
    await fs.writeFile(path.join(root, 'tools/build_pow_challenge.py'), generator);
    await fs.writeFile(path.join(root, 'tests/browser/benchmark.mjs'), benchmark);
    await fs.writeFile(
        path.join(root, 'tests/browser/benchmark-driver.js'), benchmarkDriver,
    );
    await fs.writeFile(
        path.join(root, 'build/versions.env'),
        [
            'DEBIAN_SNAPSHOT=20260713T000000Z',
            `DEBIAN_IMAGE_AMD64=docker.io/library/debian@sha256:${'d'.repeat(64)}`,
            'NGINX_VERSION=1.30.3',
            'NGINX_PACKAGE_VERSION=1.30.3-1~trixie',
            `NGINX_PACKAGE_SHA256_AMD64=${'e'.repeat(64)}`,
            'CHROMIUM_VERSION=150.0.7871.100-1~deb13u1',
            `CHROMIUM_SHA256_AMD64=${'8'.repeat(64)}`,
            'CHROMIUM_SANDBOX_VERSION=150.0.7871.100-1~deb13u1',
            `CHROMIUM_SANDBOX_SHA256_AMD64=${'a'.repeat(64)}`,
            'NODEJS_VERSION=20.19.2+dfsg-1+deb13u2',
            `NODEJS_SHA256_AMD64=${'b'.repeat(64)}`,
            'NPM_VERSION=9.2.0~ds1-3',
            `NPM_SHA256_AMD64=${'c'.repeat(64)}`,
            'PUPPETEER_CORE_VERSION=24.43.1',
            'AJV_VERSION=8.17.1',
            'AJV_INTEGRITY=sha512-B/gBuNg5SiMTrPkC+A2+cW0RszwxYmn6VYxB/inlBStS5nx6xHIt/ehKRhIMhqusl7a8LjQoZnjCs5vhwxOQ1g==',
            `GOLDEN_IMAGE_LOCK_SHA256=${LOCK}`,
            '',
        ].join('\n'),
    );
    runGit(root, 'init', '-q');
    runGit(root, 'config', 'user.email', 'powgate-test@example.invalid');
    runGit(root, 'config', 'user.name', 'PowGate Test');
    runGit(root, 'add', '.');
    runGit(root, 'commit', '-qm', 'fixture');

    const evidence = syntheticEvidence();
    const tracked = execFileSync(
        'git', ['ls-files', '--stage', '-z'], { cwd: root },
    );
    evidence.tested_source.commit = runGit(root, 'rev-parse', 'HEAD');
    evidence.tested_source.tracked_tree_sha256 = sha256(tracked);
    evidence.tested_source.production_script_sha256 = sha256(script);
    evidence.tested_source.generated_csp_hash =
        `sha256-${crypto.createHash('sha256').update(script).digest('base64')}`;
    evidence.tested_source.generator_sha256 = sha256(generator);
    const implementation = crypto.createHash('sha256');
    for (const bytes of [benchmark, benchmarkDriver]) {
        const length = Buffer.alloc(8);
        length.writeBigUInt64BE(BigInt(bytes.length));
        implementation.update(length);
        implementation.update(bytes);
    }
    evidence.tested_source.benchmark_implementation_sha256 =
        implementation.digest('hex');
    await fs.mkdir(path.join(root, 'build'), { recursive: true });
    await fs.writeFile(path.join(root, RESULT_PATH), canonicalJson(evidence));
    return evidence;
}


test('schema is strict Draft 2020-12 and validation does not mutate', async () => {
    const schema = JSON.parse(await fs.readFile(SCHEMA_PATH, 'utf8'));
    const evidence = syntheticEvidence();
    const before = canonicalJson(evidence);

    assert.equal(
        schema.$schema, 'https://json-schema.org/draft/2020-12/schema',
    );
    assert.equal(schema.additionalProperties, false);
    assert.equal(schema.properties.schema_version.const,
        'phase4c-benchmark-v1');
    for (const field of [
        'debian_base_image_digest',
        'chromium_sandbox_package_sha256',
        'nodejs_package_sha256',
        'npm_package_sha256',
        'nginx_package_sha256',
    ]) {
        assert.equal(schema.$defs.environment.required.includes(field), true);
    }
    validateEvidence(evidence);
    assert.deepEqual(canonicalJson(evidence), before);
});


test('canonical JSON recursively sorts ASCII keys and preserves arrays', () => {
    const encoded = canonicalJson({ z: 1, a: { y: 2, b: [3, { d: 4, c: 5 }] } });

    assert.equal(Buffer.isBuffer(encoded), true);
    assert.equal(encoded.toString('utf8'), [
        '{',
        '  "a": {',
        '    "b": [',
        '      3,',
        '      {',
        '        "c": 5,',
        '        "d": 4',
        '      }',
        '    ],',
        '    "y": 2',
        '  },',
        '  "z": 1',
        '}',
        '',
    ].join('\n'));
    assert.throws(() => canonicalJson({ value: Number.NaN }), /finite/);
    assert.throws(() => canonicalJson({ value: Number.POSITIVE_INFINITY }),
        /finite/);
});


test('canonical filename percent-encodes Debian version bytes injectively', () => {
    assert.equal(encodeVersion('%~'), '%25%7E');
    assert.equal(canonicalEvidenceFilename(
        'x86_64', 'chromium', '150.0.7871.100-1~deb13u1',
    ), 'x86_64-debian-chromium-150.0.7871.100-1%7Edeb13u1.json');
    assert.throws(
        () => canonicalEvidenceFilename('../x86_64', 'chromium', '1'),
        /identifier/,
    );
});


test('relational validation rejects incomplete or inconsistent evidence', () => {
    const cases = [
        ['extra property', (value) => { value.extra = true; }],
        ['thirteen runs', (value) => { value.runs.pop(); }],
        ['wrong pair order', (value) => {
            value.runs[0].backend = 'subtle';
        }],
        ['wrong throughput', (value) => {
            value.runs[0].throughput_candidates_per_second += 1;
        }],
        ['wrong heartbeat p95', (value) => {
            value.runs[0].heartbeat_p95_ms = 2;
        }],
        ['missing heartbeat sample', (value) => {
            value.runs[0].heartbeat_samples.pop();
        }],
        ['wrong median', (value) => {
            value.summaries.js.median_throughput += 1;
        }],
        ['wrong decision', (value) => {
            value.decision.selected_primary_backend = 'js';
        }],
        ['incomplete cleanup', (value) => {
            value.runs[0].context_cleanup_passed = false;
        }],
        ['unsafe integer', (value) => {
            value.runs[0].completed_candidates = Number.MAX_SAFE_INTEGER + 1;
        }],
        ['oversized samples', (value) => {
            value.runs[0].js_block_durations_ms = Array(8193).fill(1);
        }],
    ];

    validateEvidence(syntheticEvidence());
    for (const [name, mutate] of cases) {
        const evidence = syntheticEvidence();
        mutate(evidence);
        assert.throws(() => validateEvidence(evidence), undefined, name);
    }
});


test('atomic evidence writing replaces stale output and removes failed output',
    async () => {
        const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'powgate-ev-'));
        const output = path.join(directory, 'result.json');
        const evidence = syntheticEvidence();

        try {
            await fs.writeFile(output, 'stale\n');
            await writeEvidenceAtomically(output, evidence);
            assert.deepEqual(await fs.readFile(output), canonicalJson(evidence));
            assert.deepEqual(
                (await fs.readdir(directory)).sort(), ['result.json'],
            );

            let calls = 0;
            await assert.rejects(writeEvidenceAtomically(output, evidence, {
                validate(value) {
                    calls += 1;
                    validateEvidence(value);
                    if (calls === 2) {
                        throw new Error('post-write validation failed');
                    }
                },
            }), /post-write validation failed/);
            await assert.rejects(fs.access(output));
            assert.deepEqual(await fs.readdir(directory), []);
        } finally {
            await fs.rm(directory, { recursive: true, force: true });
        }
    });


test('promotion accepts only the exact clean validated source and refuses overwrite',
    async () => {
        const root = await fs.mkdtemp(path.join(os.tmpdir(), 'powgate-promote-'));

        try {
            await writePromotionRepository(root);
            await assert.rejects(promotePhase4CEvidence({
                root,
                source: path.join(root, 'build/other.json'),
            }), /benchmark-browser-result/);

            const destination = await promotePhase4CEvidence({
                root,
                source: path.join(root, RESULT_PATH),
            });
            assert.equal(path.basename(destination),
                'x86_64-debian-chromium-150.0.7871.100-1%7Edeb13u1.json');
            await assert.rejects(promotePhase4CEvidence({
                root,
                source: path.join(root, RESULT_PATH),
            }), /exists/);
        } finally {
            await fs.rm(root, { recursive: true, force: true });
        }
    });


test('promotion rejects non-promotable, dirty, HEAD, lock, and hash mismatch',
    async () => {
        const mutations = [
            ['non-promotable', (evidence) => {
                evidence.tested_source.promotable = false;
                evidence.tested_source.worktree_clean = false;
            }],
            ['HEAD mismatch', (evidence) => {
                evidence.tested_source.commit = '0'.repeat(40);
            }],
            ['lock mismatch', (evidence) => {
                evidence.environment.embedded_image_lock = 'b'.repeat(64);
            }],
            ['package lock mismatch', (evidence) => {
                evidence.environment.chromium_package_sha256 = 'f'.repeat(64);
            }],
            ['hash mismatch', (evidence) => {
                evidence.tested_source.production_script_sha256 = 'c'.repeat(64);
            }],
            ['invalid filename identity', (evidence) => {
                evidence.environment.container_architecture = '../x86_64';
            }],
        ];

        for (const [name, mutate] of mutations) {
            const root = await fs.mkdtemp(
                path.join(os.tmpdir(), 'powgate-promote-reject-'),
            );
            try {
                const evidence = await writePromotionRepository(root);
                mutate(evidence);
                await fs.writeFile(
                    path.join(root, RESULT_PATH), canonicalJson(evidence),
                );
                await assert.rejects(promotePhase4CEvidence({
                    root,
                    source: path.join(root, RESULT_PATH),
                }), undefined, name);
            } finally {
                await fs.rm(root, { recursive: true, force: true });
            }
        }

        const root = await fs.mkdtemp(path.join(os.tmpdir(), 'powgate-dirty-'));
        try {
            await writePromotionRepository(root);
            await fs.appendFile(path.join(root, 'html/challenge.html'), '\n');
            await assert.rejects(promotePhase4CEvidence({
                root,
                source: path.join(root, RESULT_PATH),
            }), /clean/);
        } finally {
            await fs.rm(root, { recursive: true, force: true });
        }
    });


test('committed evidence check binds an evidence-only commit to source and docs',
    async () => {
        const root = await fs.mkdtemp(path.join(os.tmpdir(), 'powgate-check-'));

        try {
            const evidence = await writePromotionRepository(root);
            const destination = await promotePhase4CEvidence({
                root,
                source: path.join(root, RESULT_PATH),
            });
            const relative = path.relative(root, destination);
            const readme = path.join(root, 'docs/benchmarks/phase4c-v1/README.md');
            await fs.writeFile(readme, [
                '# Canonical evidence',
                '',
                `Tested source: \`${evidence.tested_source.commit}\``,
                `Result: [${path.basename(relative)}](./${path.basename(relative)})`,
                'Selected primary backend: `subtle`',
                '',
            ].join('\n'));
            runGit(root, 'add', 'docs/benchmarks/phase4c-v1');
            runGit(root, 'commit', '-qm', 'evidence only');

            const checked = await checkCommittedPhase4CEvidence({ root });
            assert.equal(checked.relativeEvidence, relative);
            assert.equal(checked.testedSourceCommit,
                evidence.tested_source.commit);

            await fs.writeFile(readme, '# missing identities\n');
            await assert.rejects(
                checkCommittedPhase4CEvidence({ root }), /README/,
            );
        } finally {
            await fs.rm(root, { recursive: true, force: true });
        }
    });


test('committed evidence check rejects a non-evidence change in final commit',
    async () => {
        const root = await fs.mkdtemp(
            path.join(os.tmpdir(), 'powgate-check-scope-'),
        );

        try {
            const evidence = await writePromotionRepository(root);
            const destination = await promotePhase4CEvidence({
                root,
                source: path.join(root, RESULT_PATH),
            });
            const basename = path.basename(destination);
            const readme = path.join(root, 'docs/benchmarks/phase4c-v1/README.md');
            await fs.writeFile(readme, [
                `Tested source: \`${evidence.tested_source.commit}\``,
                `Result: [${basename}](./${basename})`,
                'Selected primary backend: `subtle`',
                '',
            ].join('\n'));
            await fs.appendFile(path.join(root, 'html/challenge.html'), '\n');
            runGit(root, 'add', '.');
            runGit(root, 'commit', '-qm', 'mixed evidence and source');

            await assert.rejects(
                checkCommittedPhase4CEvidence({ root }), /evidence-only/,
            );
        } finally {
            await fs.rm(root, { recursive: true, force: true });
        }
    });
