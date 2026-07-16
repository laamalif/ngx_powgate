import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';


const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const COMPILE_FLAGS = '-fsanitize=address,undefined -fno-omit-frame-pointer';
const LINK_FLAGS = '-fsanitize=address,undefined';
const SANITIZER_ENVIRONMENT = Object.freeze([
    'ASAN_OPTIONS',
    'ASAN_SYMBOLIZER_PATH',
    'LD_PRELOAD',
    'LLVM_SYMBOLIZER_PATH',
    'LSAN_OPTIONS',
    'MSAN_OPTIONS',
    'UBSAN_OPTIONS',
    'UBSAN_SYMBOLIZER_PATH',
]);
const STDERR_FAILURE = /(?:AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:|DEADLYSIGNAL|allocator[^\n]*fail|sanitizer[^\n]*initialization[^\n]*fail)/iu;


function invalid() {
    throw new Error('invalid sanitizer manifest');
}


function exactKeys(value, keys) {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
        && Object.keys(value).sort().join('\n') === [...keys].sort().join('\n');
}


function deepFreeze(value) {
    if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
        for (const child of Object.values(value)) {
            deepFreeze(child);
        }
        Object.freeze(value);
    }
    return value;
}


async function fileSha256(filename) {
    return createHash('sha256').update(await fs.readFile(filename)).digest('hex');
}


async function instrumentedArtifact(value) {
    if (!exactKeys(value, [
        'asanInstrumented', 'path', 'sha256', 'ubsanInstrumented',
    ]) || value.asanInstrumented !== true || value.ubsanInstrumented !== true
        || typeof value.path !== 'string' || !path.isAbsolute(value.path)
        || !SHA256_PATTERN.test(value.sha256)) {
        invalid();
    }
    const bytes = await fs.readFile(value.path);
    if (createHash('sha256').update(bytes).digest('hex') !== value.sha256
        || !bytes.includes(Buffer.from('__asan'))
        || !bytes.includes(Buffer.from('__ubsan'))) {
        invalid();
    }
}


export async function validateSanitizerManifest(manifest) {
    try {
        if (!exactKeys(manifest, [
            'flags', 'module', 'negativeControl', 'nginx', 'normal',
            'runtime', 'schemaVersion',
        ]) || manifest.schemaVersion !== 'phase4c-sanitized-v1'
            || !exactKeys(manifest.flags, ['compile', 'link'])
            || manifest.flags.compile !== COMPILE_FLAGS
            || manifest.flags.link !== LINK_FLAGS
            || !exactKeys(manifest.normal, ['moduleSha256', 'nginxSha256'])
            || !SHA256_PATTERN.test(manifest.normal.moduleSha256)
            || !SHA256_PATTERN.test(manifest.normal.nginxSha256)
            || !exactKeys(manifest.runtime, [
                'asan', 'suppressionPath', 'ubsan',
            ])
            || manifest.runtime.asan
                !== 'abort_on_error=1:detect_leaks=0:detect_odr_violation=0'
            || manifest.runtime.ubsan
                !== 'halt_on_error=1:print_stacktrace=1'
            || typeof manifest.runtime.suppressionPath !== 'string'
            || !path.isAbsolute(manifest.runtime.suppressionPath)
            || !exactKeys(manifest.negativeControl, [
                'reportDetected', 'reportPath', 'reportSha256',
            ])
            || manifest.negativeControl.reportDetected !== true
            || typeof manifest.negativeControl.reportPath !== 'string'
            || !path.isAbsolute(manifest.negativeControl.reportPath)
            || !SHA256_PATTERN.test(manifest.negativeControl.reportSha256)) {
            invalid();
        }
        await Promise.all([
            instrumentedArtifact(manifest.nginx),
            instrumentedArtifact(manifest.module),
        ]);
        if (manifest.nginx.sha256 === manifest.normal.nginxSha256
            || manifest.module.sha256 === manifest.normal.moduleSha256
            || await fileSha256(manifest.negativeControl.reportPath)
                !== manifest.negativeControl.reportSha256
            || !(await fs.readFile(
                manifest.negativeControl.reportPath, 'utf8'
            )).includes('runtime error: load of misaligned address')) {
            invalid();
        }
        await fs.access(manifest.runtime.suppressionPath);
        return deepFreeze(structuredClone(manifest));
    } catch (error) {
        if (error?.message === 'invalid sanitizer manifest') {
            throw error;
        }
        invalid();
    }
}


export async function loadSanitizerManifest(filename) {
    if (typeof filename !== 'string' || !path.isAbsolute(filename)) {
        invalid();
    }
    let manifest;
    try {
        manifest = JSON.parse(await fs.readFile(filename, 'utf8'));
    } catch {
        invalid();
    }
    return validateSanitizerManifest(manifest);
}


export async function buildSanitizedNginxEnvironment(
    manifest, reportDirectory, baseEnvironment = process.env,
) {
    await validateSanitizerManifest(manifest);
    if (typeof reportDirectory !== 'string' || !path.isAbsolute(reportDirectory)
        || baseEnvironment === null || typeof baseEnvironment !== 'object'
        || Array.isArray(baseEnvironment)) {
        throw new TypeError('invalid sanitizer environment');
    }
    await fs.mkdir(reportDirectory, { recursive: true });
    const environment = { ...baseEnvironment };
    for (const name of SANITIZER_ENVIRONMENT) {
        delete environment[name];
    }
    environment.ASAN_OPTIONS = `${manifest.runtime.asan}`
        + `:log_path=${path.join(reportDirectory, 'asan')}`;
    environment.UBSAN_OPTIONS = `${manifest.runtime.ubsan}`
        + `:suppressions=${manifest.runtime.suppressionPath}`
        + `:log_path=${path.join(reportDirectory, 'ubsan')}`;
    return Object.freeze(environment);
}


export async function collectSanitizerReports(input) {
    if (!exactKeys(input, [
        'cleanupEscalated', 'masterExitedCleanly', 'reportDirectory', 'stderr',
        'workerGenerationCount', 'workersExited',
    ]) || typeof input.reportDirectory !== 'string'
        || !path.isAbsolute(input.reportDirectory)
        || typeof input.stderr !== 'string'
        || !Number.isSafeInteger(input.workerGenerationCount)) {
        throw new TypeError('invalid sanitizer report input');
    }
    const entries = await fs.readdir(input.reportDirectory, {
        withFileTypes: true,
    });
    if (entries.some((entry) => !entry.isFile())) {
        throw new Error('sanitizer execution failed');
    }
    if (entries.length !== 0) {
        throw new Error('sanitizer report detected');
    }
    if (input.cleanupEscalated !== false || input.masterExitedCleanly !== true
        || input.workersExited !== true
        || input.workerGenerationCount < 1
        || STDERR_FAILURE.test(input.stderr)) {
        throw new Error('sanitizer execution failed');
    }
    return Object.freeze({
        clean: true,
        reportCount: 0,
        workerGenerationCount: input.workerGenerationCount,
        workersExited: true,
    });
}
