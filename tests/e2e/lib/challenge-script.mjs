import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';


const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)),
    '../../..');
const templatePath = path.join(root, 'html', 'challenge.html');
const scriptOpen = Buffer.from('<script>');
const scriptClose = Buffer.from('</script>');


export function extractExecutableScript(page) {
    const openAt = page.indexOf(scriptOpen);

    if (openAt === -1
        || page.indexOf(scriptOpen, openAt + scriptOpen.length) !== -1)
    {
        throw new Error('invalid executable script opening');
    }

    const bodyAt = openAt + scriptOpen.length;
    const closeAt = page.indexOf(scriptClose, bodyAt);

    if (closeAt === -1) {
        throw new Error('invalid executable script closing');
    }

    return page.subarray(bodyAt, closeAt);
}


export async function readChallengeScript() {
    return extractExecutableScript(await fs.readFile(templatePath));
}


export function evaluateChallengeScript(script, globals = {}) {
    /* node:vm gives deterministic globals, not a security boundary. */
    const context = vm.createContext({ TypeError, Uint8Array, ...globals });
    const source = new TextDecoder('utf-8', { fatal: true }).decode(script);

    new vm.Script(source, { filename: 'html/challenge.html' })
        .runInContext(context);

    return context;
}
