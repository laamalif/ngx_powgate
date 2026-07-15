import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import vm from 'node:vm';


const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)),
    '../../..');
const templatePath = path.join(root, 'html', 'challenge.html');
const builderPath = path.join(root, 'tools', 'build_pow_challenge.py');
const protocolPath = path.join(root, 'src', 'pow_protocol.h');
const scriptOpen = Buffer.from('<script>');
const scriptClose = Buffer.from('</script>');
const execFileAsync = promisify(execFile);


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


export async function readChallengePage() {
    return await fs.readFile(templatePath);
}


function emittedArray(header, name) {
    const pattern = new RegExp(
        `static const u_char\\s+${name}\\[\\]\\s*=\\s*\\{(.*?)\\};`,
        's'
    );
    const match = pattern.exec(header);

    if (match == null) {
        throw new Error(`missing generated array ${name}`);
    }

    return Buffer.from([...match[1].matchAll(/0x([0-9a-f]{2})/g)]
        .map((value) => Number.parseInt(value[1], 16)));
}


export async function buildChallengeArtifacts() {
    const temporary = await fs.mkdtemp(path.join(os.tmpdir(),
        'ngx-powgate-page-'));
    const output = path.join(temporary, 'pow_challenge_page.h');

    try {
        await execFileAsync('python3', [builderPath, templatePath, output], {
            cwd: root
        });
        const header = await fs.readFile(output, 'ascii');
        return {
            digest: emittedArray(header,
                'ngx_http_pow_script_sha256_base64'),
            prefix: emittedArray(header, 'ngx_http_pow_challenge_prefix'),
            suffix: emittedArray(header, 'ngx_http_pow_challenge_suffix')
        };
    } finally {
        await fs.rm(temporary, { force: true, recursive: true });
    }
}


export async function readProtocolConstants() {
    const header = await fs.readFile(protocolPath, 'utf8');
    const define = (name) => {
        const match = new RegExp(`^#define ${name}\\s+(.+)$`, 'm')
            .exec(header);
        if (match == null) {
            throw new Error(`missing protocol constant ${name}`);
        }
        return match[1].trim();
    };
    const number = (name) => Number(define(name).replace(/U?LL$/, ''));
    const string = (name) => {
        const value = define(name);
        if (!/^"[^"]*"$/.test(value)) {
            throw new Error(`nonliteral protocol string ${name}`);
        }
        return value.slice(1, -1);
    };

    return Object.freeze({
        difficultyMax: number('POW_DIFFICULTY_MAX'),
        difficultyMin: number('POW_DIFFICULTY_MIN'),
        pageMaxBodyLen: number('POW_CHALLENGE_PAGE_MAX_BODY_LEN'),
        proofCookieName: string('POW_PROOF_COOKIE_NAME'),
        proofCounterMax: number('POW_PROOF_COUNTER_MAX'),
        protocolVersion: number('POW_PROTOCOL_VERSION')
    });
}


export function evaluateChallengeScript(script, globals = {}) {
    /* node:vm gives deterministic globals, not a security boundary. */
    const math = Object.create(Math);
    const sandbox = {
        Math: math,
        TypeError,
        Uint8Array,
        setTimeout: () => 0,
        ...globals
    };
    const forbidden = [
        'console', 'fetch', 'XMLHttpRequest', 'WebSocket', 'Worker',
        'importScripts', 'localStorage', 'sessionStorage', 'navigator',
        'screen'
    ];

    Object.defineProperty(math, 'random', {
        get() {
            throw new Error('forbidden browser dependency');
        }
    });

    for (const name of forbidden) {
        if (!Object.hasOwn(sandbox, name)) {
            Object.defineProperty(sandbox, name, {
                configurable: true,
                get() {
                    throw new Error('forbidden browser dependency');
                }
            });
        }
    }

    const context = vm.createContext(sandbox);
    const source = new TextDecoder('utf-8', { fatal: true }).decode(script);

    new vm.Script(source, { filename: 'html/challenge.html' })
        .runInContext(context);

    return context;
}


function pathMatches(requestPath, cookiePath) {
    return requestPath === cookiePath
        || (requestPath.startsWith(cookiePath)
            && (cookiePath.endsWith('/')
                || requestPath[cookiePath.length] === '/'));
}


function makeNode(textContent = '') {
    const listeners = new Map();

    return {
        hidden: false,
        max: 1,
        textContent,
        value: 0,
        addEventListener(name, callback) {
            if (listeners.has(name)) {
                throw new Error('duplicate element listener');
            }
            listeners.set(name, callback);
        },
        async dispatch(name) {
            const callback = listeners.get(name);
            if (callback != null) {
                await callback();
            }
        }
    };
}


export async function createControllerHarness(options = {}) {
    const protocol = options.protocol ?? 'https:';
    const pathname = options.pathname ?? '/';
    const cookieEntries = (options.cookies ?? []).map((entry) => ({
        name: entry.name,
        value: entry.value,
        path: entry.path ?? '/',
        secure: entry.secure ?? false,
        undeletable: entry.undeletable ?? false
    }));
    const cookieWrites = [];
    const timers = [];
    const documentListeners = new Map();
    const nodes = {
        'pow-params': makeNode(options.paramsText ?? ''),
        'pow-status': makeNode('Please wait.'),
        'pow-progress': makeNode(),
        'pow-retry': makeNode('Retry')
    };

    nodes['pow-retry'].hidden = true;

    const document = {
        hidden: options.hidden ?? false,
        get cookie() {
            return cookieEntries
                .filter((entry) => pathMatches(pathname, entry.path)
                    && (!entry.secure || protocol === 'https:'))
                .map((entry) => `${entry.name}=${entry.value}`)
                .join('; ');
        },
        set cookie(serialized) {
            cookieWrites.push(serialized);
            const segments = serialized.split(';');
            const separator = segments[0].indexOf('=');
            const name = segments[0].slice(0, separator);
            const value = segments[0].slice(separator + 1);
            const attributes = new Map();

            for (const segment of segments.slice(1)) {
                const trimmed = segment.trim();
                const at = trimmed.indexOf('=');
                const key = (at === -1 ? trimmed : trimmed.slice(0, at))
                    .toLowerCase();
                attributes.set(key, at === -1 ? true : trimmed.slice(at + 1));
            }

            const pathValue = attributes.get('path') ?? '/';
            if (attributes.get('max-age') === '0') {
                for (let index = cookieEntries.length - 1; index >= 0;
                    index--)
                {
                    const entry = cookieEntries[index];
                    if (!entry.undeletable && entry.name === name
                        && entry.path === pathValue)
                    {
                        cookieEntries.splice(index, 1);
                    }
                }
                return;
            }

            if (options.blockCookieWrites) {
                return;
            }

            for (let index = cookieEntries.length - 1; index >= 0; index--) {
                const entry = cookieEntries[index];
                if (!entry.undeletable && entry.name === name
                    && entry.path === pathValue)
                {
                    cookieEntries.splice(index, 1);
                }
            }

            cookieEntries.push({
                name,
                value,
                path: pathValue,
                secure: attributes.has('secure'),
                undeletable: false
            });
        },
        addEventListener(name, callback) {
            if (documentListeners.has(name)) {
                throw new Error('duplicate document listener');
            }
            documentListeners.set(name, callback);
        },
        createElement() {
            throw new Error('forbidden dynamic element');
        },
        getElementById(id) {
            return nodes[id] ?? null;
        }
    };
    const location = {
        pathname,
        protocol,
        reloadCount: 0,
        reload() {
            this.reloadCount++;
        }
    };
    const globals = {
        crypto: options.crypto,
        document,
        location,
        performance: options.performance ?? { now: () => 0 },
        setTimeout(callback, delay) {
            timers.push({ callback, delay });
            return timers.length;
        }
    };
    const script = options.script ?? await readChallengeScript();
    const context = evaluateChallengeScript(script, globals);

    return {
        context,
        cookieEntries,
        cookieWrites,
        document,
        documentListeners,
        location,
        nodes,
        timers,
        async runNextTimer() {
            const timer = timers.shift();
            if (timer == null) {
                throw new Error('no timer queued');
            }
            await timer.callback();
            await Promise.resolve();
        }
    };
}
