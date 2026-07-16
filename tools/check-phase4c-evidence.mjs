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
    sha256Hex,
    validateEvidence,
} from '../tests/browser/lib/evidence.mjs';


const EVIDENCE_DIRECTORY = 'docs/benchmarks/phase4c-v1';
const README = `${EVIDENCE_DIRECTORY}/README.md`;


function git(root, args, options = {}) {
    return execFileSync('git', args, {
        cwd: root,
        encoding: options.encoding ?? 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
    });
}


function trackedCommitTreeSha256(root, commit) {
    const listing = git(root, [
        'ls-tree', '-r', '-z',
        '--format=%(objectmode) %(objectname) 0%x09%(path)', commit,
    ], { encoding: null });
    return sha256Hex(listing);
}


async function canonicalResult(root) {
    const directory = path.join(root, EVIDENCE_DIRECTORY);
    const names = (await fs.readdir(directory)).filter((name) => (
        name.endsWith('.json') && name !== 'schema.json'
    ));
    if (names.length !== 1) {
        throw new Error('exactly one canonical Phase 4C result is required');
    }
    const relative = `${EVIDENCE_DIRECTORY}/${names[0]}`;
    const bytes = await fs.readFile(path.join(root, relative));
    const evidence = JSON.parse(bytes.toString('utf8'));
    validateEvidence(evidence);
    if (!bytes.equals(canonicalJson(evidence))) {
        throw new Error('canonical Phase 4C result is not canonical JSON');
    }
    const expected = canonicalEvidenceFilename(
        evidence.environment.container_architecture,
        'chromium',
        evidence.environment.chromium_package_version,
    );
    if (names[0] !== expected) {
        throw new Error('canonical Phase 4C result filename is invalid');
    }
    return { evidence, relative };
}


function verifyEvidenceOnlyCommit(root, sourceCommit, relativeEvidence) {
    const head = git(root, ['rev-parse', 'HEAD']).trim();
    const parent = git(root, ['rev-parse', 'HEAD^']).trim();
    if (parent !== sourceCommit) {
        throw new Error('evidence commit does not directly follow tested source');
    }
    const changed = git(root, [
        'diff-tree', '--no-commit-id', '--name-only', '-r', head,
    ]).trim().split('\n').filter(Boolean).sort();
    const expected = [README, relativeEvidence].sort();
    if (changed.length !== expected.length
        || changed.some((name, index) => name !== expected[index])) {
        throw new Error('final commit is not an evidence-only change');
    }
}


async function verifyReadme(root, evidence, relativeEvidence) {
    const contents = await fs.readFile(path.join(root, README), 'utf8');
    const basename = path.basename(relativeEvidence);
    const required = [
        evidence.tested_source.commit,
        `./${basename}`,
        `\`${evidence.decision.selected_primary_backend}\``,
    ];
    if (required.some((value) => !contents.includes(value))) {
        throw new Error('benchmark README does not link the canonical identities');
    }
}


export async function checkCommittedPhase4CEvidence({
    root = process.cwd(),
} = {}) {
    const repositoryRoot = path.resolve(root);
    const { evidence, relative } = await canonicalResult(repositoryRoot);
    const sourceCommit = evidence.tested_source.commit;

    if (!evidence.tested_source.promotable
        || !evidence.tested_source.worktree_clean) {
        throw new Error('canonical Phase 4C evidence is not promotable');
    }
    verifyEvidenceOnlyCommit(repositoryRoot, sourceCommit, relative);
    if (trackedCommitTreeSha256(repositoryRoot, sourceCommit)
        !== evidence.tested_source.tracked_tree_sha256) {
        throw new Error('tested source tree identity does not match evidence');
    }
    const script = productionScriptIdentity(repositoryRoot);
    if (script.sha256 !== evidence.tested_source.production_script_sha256
        || script.cspHash !== evidence.tested_source.generated_csp_hash) {
        throw new Error('production script identity does not match evidence');
    }
    if (benchmarkImplementationSha256(repositoryRoot)
        !== evidence.tested_source.benchmark_implementation_sha256) {
        throw new Error('benchmark implementation identity does not match evidence');
    }
    const generator = await fs.readFile(
        path.join(repositoryRoot, 'tools/build_pow_challenge.py'),
    );
    if (sha256Hex(generator) !== evidence.tested_source.generator_sha256) {
        throw new Error('challenge generator identity does not match evidence');
    }
    await verifyReadme(repositoryRoot, evidence, relative);
    return Object.freeze({
        relativeEvidence: relative,
        testedSourceCommit: sourceCommit,
    });
}


async function main() {
    if (process.argv.length !== 2) {
        process.stderr.write('usage: check-phase4c-evidence.mjs\n');
        process.exitCode = 2;
        return;
    }
    try {
        const checked = await checkCommittedPhase4CEvidence();
        process.stdout.write(
            `Phase 4C evidence: PASS (${checked.relativeEvidence})\n`,
        );
    } catch (_error) {
        process.stderr.write('check-phase4c-evidence: failed\n');
        process.exitCode = 1;
    }
}


if (process.argv[1] !== undefined
    && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
    await main();
}
