import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
    runPartitionedFeasibility,
} from './lib/partitioned-trials.mjs';

export {
    buildPartitionedVerdict,
    countExactProofs,
    partitionedAcceptance,
    runPartitionedFeasibility,
} from './lib/partitioned-trials.mjs';


async function main() {
    const verdict = await runPartitionedFeasibility();
    process.stdout.write(`${JSON.stringify(verdict)}\n`);
}


if (process.argv[1] !== undefined
    && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
    try {
        await main();
    } catch (_error) {
        process.stderr.write('partitioned-feasibility: failed\n');
        process.exitCode = 1;
    }
}
