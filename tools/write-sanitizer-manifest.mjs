import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import { validateSanitizerManifest } from '../tests/browser/lib/sanitizer.mjs';


async function sha256(filename) {
    return createHash('sha256').update(await fs.readFile(filename)).digest('hex');
}


async function main() {
    const [output, nginxPath, modulePath, normalNginxPath, normalModulePath,
        negativeReportPath] = process.argv.slice(2).map((value) =>
        path.resolve(value));
    if (negativeReportPath === undefined) {
        throw new TypeError('invalid sanitizer manifest arguments');
    }
    const manifest = {
        schemaVersion: 'phase4c-sanitized-v1',
        flags: {
            compile: '-fsanitize=address,undefined -fno-omit-frame-pointer',
            link: '-fsanitize=address,undefined',
        },
        module: {
            asanInstrumented: true,
            path: modulePath,
            sha256: await sha256(modulePath),
            ubsanInstrumented: true,
        },
        negativeControl: {
            reportDetected: true,
            reportPath: negativeReportPath,
            reportSha256: await sha256(negativeReportPath),
        },
        nginx: {
            asanInstrumented: true,
            path: nginxPath,
            sha256: await sha256(nginxPath),
            ubsanInstrumented: true,
        },
        normal: {
            moduleSha256: await sha256(normalModulePath),
            nginxSha256: await sha256(normalNginxPath),
        },
        runtime: {
            asan: 'abort_on_error=1:detect_leaks=0:detect_odr_violation=0',
            suppressionPath: path.resolve('tools/ubsan-nginx.supp'),
            ubsan: 'halt_on_error=1:print_stacktrace=1',
        },
    };
    await validateSanitizerManifest(manifest);
    const temporary = `${output}.tmp-${process.pid}`;
    await fs.mkdir(path.dirname(output), { recursive: true });
    await fs.writeFile(temporary, `${JSON.stringify(manifest, null, 2)}\n`, {
        encoding: 'utf8',
        mode: 0o600,
    });
    await fs.rename(temporary, output);
    await validateSanitizerManifest(JSON.parse(await fs.readFile(output, 'utf8')));
}


try {
    await main();
} catch (_error) {
    process.stderr.write('write-sanitizer-manifest: failed\n');
    process.exitCode = 1;
}
