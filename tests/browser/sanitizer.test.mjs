import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
    buildSanitizedNginxEnvironment,
    collectSanitizerReports,
    validateSanitizerManifest,
} from './lib/sanitizer.mjs';


function sha256(value) {
    return createHash('sha256').update(value).digest('hex');
}


async function fixtureManifest(root, overrides = {}) {
    const nginxPath = path.join(root, 'nginx');
    const modulePath = path.join(root, 'ngx_http_pow_module.so');
    const negativeReportPath = path.join(root, 'negative-control.log');
    const nginx = Buffer.from('ELF __asan_init __ubsan_handle_type_mismatch_v1');
    const module = Buffer.from('ELF __asan_report_load4 __ubsan_handle_pointer_overflow');
    const negativeReport = Buffer.from('runtime error: load of misaligned address\n');

    await Promise.all([
        fs.writeFile(nginxPath, nginx),
        fs.writeFile(modulePath, module),
        fs.writeFile(negativeReportPath, negativeReport),
    ]);
    return {
        schemaVersion: 'phase4c-sanitized-v1',
        flags: {
            compile: '-fsanitize=address,undefined -fno-omit-frame-pointer',
            link: '-fsanitize=address,undefined',
        },
        module: {
            asanInstrumented: true,
            path: modulePath,
            sha256: sha256(module),
            ubsanInstrumented: true,
        },
        negativeControl: {
            reportDetected: true,
            reportPath: negativeReportPath,
            reportSha256: sha256(negativeReport),
        },
        nginx: {
            asanInstrumented: true,
            path: nginxPath,
            sha256: sha256(nginx),
            ubsanInstrumented: true,
        },
        normal: {
            moduleSha256: '1'.repeat(64),
            nginxSha256: '2'.repeat(64),
        },
        runtime: {
            asan: 'abort_on_error=1:detect_leaks=0:detect_odr_violation=0',
            suppressionPath: path.resolve('tools/ubsan-nginx.supp'),
            ubsan: 'halt_on_error=1:print_stacktrace=1',
        },
        ...overrides,
    };
}


test('sanitizer manifest proves distinct instrumented artifacts', async (t) => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pow-san-manifest-'));
    t.after(() => fs.rm(root, { recursive: true, force: true }));
    const manifest = await fixtureManifest(root);

    const validated = await validateSanitizerManifest(manifest);

    assert.equal(Object.isFrozen(validated), true);
    assert.equal(validated.nginx.sha256, manifest.nginx.sha256);
    assert.equal(validated.module.sha256, manifest.module.sha256);
});


test('sanitizer manifest rejects incomplete or weakened identity', async (t) => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pow-san-reject-'));
    t.after(() => fs.rm(root, { recursive: true, force: true }));
    const manifest = await fixtureManifest(root);

    const rows = [
        { ...manifest, flags: { ...manifest.flags, compile: '-O2' } },
        { ...manifest, module: { ...manifest.module, sha256: '' } },
        { ...manifest, normal: {
            ...manifest.normal, nginxSha256: manifest.nginx.sha256,
        } },
        { ...manifest, negativeControl: {
            ...manifest.negativeControl, reportDetected: false,
        } },
        { ...manifest, nginx: {
            ...manifest.nginx, ubsanInstrumented: false,
        } },
    ];
    for (const row of rows) {
        await assert.rejects(
            validateSanitizerManifest(row),
            /invalid sanitizer manifest/,
        );
    }
});


test('sanitizer environment is NGINX-only and fixture-scoped', async (t) => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pow-san-env-'));
    t.after(() => fs.rm(root, { recursive: true, force: true }));
    const manifest = await fixtureManifest(root);
    const reports = path.join(root, 'reports');
    const environment = await buildSanitizedNginxEnvironment(
        manifest, reports, {
            ASAN_OPTIONS: 'caller-controlled',
            LD_PRELOAD: '/tmp/forbidden.so',
            PATH: '/usr/bin',
            UBSAN_OPTIONS: 'caller-controlled',
        },
    );

    assert.equal(environment.PATH, '/usr/bin');
    assert.equal('LD_PRELOAD' in environment, false);
    assert.equal(environment.ASAN_OPTIONS,
        `${manifest.runtime.asan}:log_path=${reports}/asan`);
    assert.equal(environment.UBSAN_OPTIONS,
        `${manifest.runtime.ubsan}:suppressions=${manifest.runtime.suppressionPath}`
        + `:log_path=${reports}/ubsan`);
    assert.equal(Object.isFrozen(environment), true);
});


test('sanitizer report collection requires clean complete worker exit', async (t) => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'pow-san-report-'));
    t.after(() => fs.rm(root, { recursive: true, force: true }));
    await fs.mkdir(root, { recursive: true });

    assert.deepEqual(await collectSanitizerReports({
        cleanupEscalated: false,
        masterExitedCleanly: true,
        reportDirectory: root,
        stderr: '',
        workerGenerationCount: 1,
        workersExited: true,
    }), {
        clean: true,
        reportCount: 0,
        workerGenerationCount: 1,
        workersExited: true,
    });

    await fs.writeFile(path.join(root, 'ubsan.42'), 'runtime error: bad\n');
    await assert.rejects(collectSanitizerReports({
        cleanupEscalated: false,
        masterExitedCleanly: true,
        reportDirectory: root,
        stderr: '',
        workerGenerationCount: 1,
        workersExited: true,
    }), /sanitizer report detected/);
    await fs.rm(path.join(root, 'ubsan.42'));

    for (const row of [
        { stderr: 'AddressSanitizer:DEADLYSIGNAL' },
        { masterExitedCleanly: false },
        { workersExited: false },
        { cleanupEscalated: true },
        { workerGenerationCount: 0 },
    ]) {
        await assert.rejects(collectSanitizerReports({
            cleanupEscalated: false,
            masterExitedCleanly: true,
            reportDirectory: root,
            stderr: '',
            workerGenerationCount: 1,
            workersExited: true,
            ...row,
        }), /sanitizer execution failed/);
    }
});
