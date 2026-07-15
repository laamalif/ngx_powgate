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


export async function readChallengePage() {
    return await fs.readFile(templatePath);
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
    const script = await readChallengeScript();
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
