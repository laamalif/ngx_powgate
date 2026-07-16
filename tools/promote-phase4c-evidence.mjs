#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

import {
    benchmarkImplementationSha256,
    canonicalEvidenceFilename,
    canonicalJson,
    productionScriptIdentity,
    readGoldenImageLock,
    readVersionLocks,
    sha256Hex,
    trackedTreeSha256,
    validateEvidence,
} from '../tests/browser/lib/evidence.mjs';


const SOURCE = 'build/benchmark-browser-result.json';
const DESTINATION_DIRECTORY = 'docs/benchmarks/phase4c-v1';


function git(root, args) {
    return execFileSync('git', args, {
        cwd: root,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
}


async function exists(file) {
    try {
        await fs.access(file);
        return true;
    } catch (error) {
        if (error.code === 'ENOENT') {
            return false;
        }
        throw error;
    }
}


async function copyExclusivelyAtomically(sourceBytes, destination) {
    const directory = path.dirname(destination);
    const temporary = path.join(
        directory,
        `.${path.basename(destination)}.${process.pid}.${crypto.randomUUID()}.tmp`,
    );

    await fs.mkdir(directory, { recursive: true });
    try {
        const handle = await fs.open(temporary, 'wx', 0o644);
        try {
            await handle.writeFile(sourceBytes);
            await handle.sync();
        } finally {
            await handle.close();
        }
        await fs.link(temporary, destination);
    } finally {
        await fs.rm(temporary, { force: true });
    }
}


export async function promotePhase4CEvidence({
    root = process.cwd(),
    source = path.join(root, SOURCE),
} = {}) {
    const repositoryRoot = path.resolve(root);
    const requiredSource = path.join(repositoryRoot, SOURCE);
    const resolvedSource = path.resolve(source);

    if (resolvedSource !== requiredSource) {
        throw new TypeError(`promotion accepts only ${SOURCE}`);
    }
    const sourceBytes = await fs.readFile(requiredSource);
    const evidence = JSON.parse(sourceBytes.toString('utf8'));
    validateEvidence(evidence);
    if (!sourceBytes.equals(canonicalJson(evidence))) {
        throw new TypeError('benchmark evidence source is not canonical');
    }
    const filename = canonicalEvidenceFilename(
        evidence.environment.container_architecture,
        'chromium',
        evidence.environment.chromium_package_version,
    );
    const destination = path.join(
        repositoryRoot, DESTINATION_DIRECTORY, filename,
    );
    if (await exists(destination)) {
        throw new Error(`canonical benchmark evidence already exists: ${filename}`);
    }
    if (!evidence.tested_source.promotable
        || !evidence.tested_source.worktree_clean) {
        throw new Error('benchmark evidence is not promotable');
    }
    if (git(repositoryRoot, ['status', '--porcelain', '--untracked-files=all'])
        !== '') {
        throw new Error('promotion requires a clean worktree');
    }
    const head = git(repositoryRoot, ['rev-parse', 'HEAD']);
    if (head !== evidence.tested_source.commit) {
        throw new Error('tested source commit does not match HEAD');
    }
    if (trackedTreeSha256(repositoryRoot)
        !== evidence.tested_source.tracked_tree_sha256) {
        throw new Error('tracked source identity does not match evidence');
    }
    const imageLock = readGoldenImageLock(repositoryRoot);
    if (evidence.environment.embedded_image_lock !== imageLock
        || evidence.environment.oci_image_lock !== imageLock) {
        throw new Error('golden image lock does not match evidence');
    }
    const versionLocks = readVersionLocks(repositoryRoot);
    const lockedEnvironment = [
        ['DEBIAN_SNAPSHOT', 'debian_snapshot'],
        ['DEBIAN_IMAGE_AMD64', 'debian_base_image_digest'],
        ['NGINX_VERSION', 'nginx_version'],
        ['NGINX_PACKAGE_VERSION', 'nginx_package_version'],
        ['NGINX_PACKAGE_SHA256_AMD64', 'nginx_package_sha256'],
        ['CHROMIUM_VERSION', 'chromium_package_version'],
        ['CHROMIUM_SHA256_AMD64', 'chromium_package_sha256'],
        ['CHROMIUM_SANDBOX_VERSION', 'chromium_sandbox_package_version'],
        ['CHROMIUM_SANDBOX_SHA256_AMD64',
            'chromium_sandbox_package_sha256'],
        ['NODEJS_VERSION', 'nodejs_package_version'],
        ['NODEJS_SHA256_AMD64', 'nodejs_package_sha256'],
        ['NPM_VERSION', 'npm_package_version'],
        ['NPM_SHA256_AMD64', 'npm_package_sha256'],
        ['PUPPETEER_CORE_VERSION', 'puppeteer_core_version'],
        ['AJV_VERSION', 'ajv_version'],
        ['AJV_INTEGRITY', 'ajv_integrity'],
    ];
    for (const [lockName, evidenceName] of lockedEnvironment) {
        if (versionLocks[lockName] !== evidence.environment[evidenceName]) {
            throw new Error(`package lock does not match evidence: ${lockName}`);
        }
    }
    const script = productionScriptIdentity(repositoryRoot);
    if (script.sha256 !== evidence.tested_source.production_script_sha256
        || script.cspHash !== evidence.tested_source.generated_csp_hash) {
        throw new Error('production script identity does not match evidence');
    }
    const generator = await fs.readFile(
        path.join(repositoryRoot, 'tools/build_pow_challenge.py'),
    );
    if (sha256Hex(generator) !== evidence.tested_source.generator_sha256) {
        throw new Error('challenge generator identity does not match evidence');
    }
    if (benchmarkImplementationSha256(repositoryRoot)
        !== evidence.tested_source.benchmark_implementation_sha256) {
        throw new Error('benchmark implementation identity does not match evidence');
    }

    await copyExclusivelyAtomically(sourceBytes, destination);
    return destination;
}


async function main() {
    if (process.argv.length !== 3 || process.argv[2] !== SOURCE) {
        process.stderr.write(
            `usage: promote-phase4c-evidence.mjs ${SOURCE}\n`,
        );
        process.exitCode = 2;
        return;
    }
    try {
        const destination = await promotePhase4CEvidence({
            root: process.cwd(),
            source: path.resolve(process.argv[2]),
        });
        process.stdout.write(`${path.relative(process.cwd(), destination)}\n`);
    } catch (_error) {
        process.stderr.write('promote-phase4c-evidence: failed\n');
        process.exitCode = 1;
    }
}


if (process.argv[1] !== undefined
    && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
    await main();
}
