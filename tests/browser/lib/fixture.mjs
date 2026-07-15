import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';

import {
    CAPTURE_LIMITS,
    DEADLINES,
    FAILURE_CATEGORIES,
} from './constants.mjs';


const SAFE_TOKEN = /^[A-Za-z0-9_.-]+$/;

const transitions = Object.freeze({
    created: new Set(['starting']),
    starting: new Set(['ready', 'failed']),
    ready: new Set(['stopping', 'failed']),
    failed: new Set(['stopping']),
    stopping: new Set(['stopped']),
    stopped: new Set(),
});


function fixedFailure(category, operation, message) {
    return new BrowserTestFailure(category, operation, message);
}


function arraysEqual(first, second) {
    return first.length === second.length
        && first.every((value, index) => value === second[index]);
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


function safeToken(value, name) {
    if (typeof value !== 'string' || !SAFE_TOKEN.test(value)) {
        throw fixedFailure(
            'internal_invariant', 'diagnostic_capture',
            `invalid diagnostic field: ${name}`,
        );
    }
    return value;
}


function classifySecondary(category, operation, error) {
    if (error instanceof BrowserTestFailure) {
        return error;
    }
    return fixedFailure(category, operation, `secondary failure: ${operation}`);
}


function delay(milliseconds) {
    return new Promise((resolve) => setTimeout(resolve, milliseconds));
}


async function runCaptured(executable, arguments_, options) {
    const child = spawn(executable, arguments_, {
        cwd: options.cwd,
        env: options.env,
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let overflow;
    const append = (name, chunk) => {
        const next = (name === 'stdout' ? stdout : stderr) + chunk.toString('utf8');
        if (Buffer.byteLength(next, 'utf8') > 1024 * 1024) {
            overflow = fixedFailure(
                'internal_invariant', options.operation,
                'captured process output limit exceeded',
            );
            child.kill('SIGKILL');
            return;
        }
        if (name === 'stdout') {
            stdout = next;
        } else {
            stderr = next;
        }
    };
    child.stdout.on('data', (chunk) => append('stdout', chunk));
    child.stderr.on('data', (chunk) => append('stderr', chunk));
    const result = await withDeadline(
        options.operation,
        options.timeout,
        (signal) => new Promise((resolve, reject) => {
            signal.addEventListener('abort', () => child.kill('SIGTERM'), {
                once: true,
            });
            child.once('error', () => reject(fixedFailure(
                'fixture_startup', options.operation,
                `process launch failed: ${options.operation}`,
            )));
            child.once('close', (code, childSignal) => {
                if (overflow !== undefined) {
                    reject(overflow);
                    return;
                }
                resolve(Object.freeze({
                    code,
                    signal: childSignal,
                    stdout,
                    stderr,
                }));
            });
        }),
    );
    return result;
}


async function reservePort() {
    const server = net.createServer();
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, resolve);
    });
    return Object.freeze({
        port: server.address().port,
        close: () => new Promise((resolve, reject) => {
            server.close((error) => error === undefined ? resolve() : reject(error));
        }),
    });
}


async function reserveFixturePorts() {
    const httpsReservation = await reservePort();
    let backendReservation;
    try {
        backendReservation = await reservePort();
    } catch (error) {
        await httpsReservation.close();
        throw error;
    }
    return {
        values: Object.freeze({
            https: httpsReservation.port,
            backend: backendReservation.port,
        }),
        async close() {
            await Promise.all([
                httpsReservation.close(),
                backendReservation.close(),
            ]);
        },
    };
}


async function createRuntimePaths(target) {
    if (typeof target !== 'string' || !SAFE_TOKEN.test(target)) {
        throw fixedFailure(
            'fixture_configuration', 'runtime_root',
            'invalid fixture target',
        );
    }
    const runtimeBase = path.resolve('build/browser-runtime');
    await fs.mkdir(runtimeBase, { recursive: true });
    const root = await fs.mkdtemp(path.join(
        runtimeBase, `${target}-${process.pid}-${randomBytes(4).toString('hex')}-`,
    ));
    const nginxPrefix = path.join(root, 'nginx');
    const content = path.join(root, 'content');
    const certificates = path.join(root, 'certificates');
    const logs = path.join(root, 'logs');
    const clientBodyTemp = path.join(nginxPrefix, 'client_body_temp');
    const proxyTemp = path.join(nginxPrefix, 'proxy_temp');
    const fastcgiTemp = path.join(nginxPrefix, 'fastcgi_temp');
    const uwsgiTemp = path.join(nginxPrefix, 'uwsgi_temp');
    const scgiTemp = path.join(nginxPrefix, 'scgi_temp');
    await Promise.all([
        fs.mkdir(nginxPrefix, { recursive: true }),
        fs.mkdir(content, { recursive: true }),
        fs.mkdir(certificates, { recursive: true }),
        fs.mkdir(logs, { recursive: true }),
        fs.mkdir(clientBodyTemp, { recursive: true }),
        fs.mkdir(proxyTemp, { recursive: true }),
        fs.mkdir(fastcgiTemp, { recursive: true }),
        fs.mkdir(uwsgiTemp, { recursive: true }),
        fs.mkdir(scgiTemp, { recursive: true }),
    ]);
    return Object.freeze({
        root,
        nginxPrefix,
        content,
        certificates,
        logs,
        certificate: path.join(certificates, 'fixture.crt'),
        privateKey: path.join(certificates, 'fixture.key'),
        nginxConfig: path.join(nginxPrefix, 'nginx.conf'),
        nginxPid: path.join(nginxPrefix, 'nginx.pid'),
        nginxErrorLog: path.join(logs, 'nginx-error.log'),
        clientBodyTemp,
        proxyTemp,
        fastcgiTemp,
        uwsgiTemp,
        scgiTemp,
    });
}


async function writeStaticFiles(contentRoot, files) {
    if (files === undefined) {
        return;
    }
    if (files === null || typeof files !== 'object' || Array.isArray(files)) {
        throw fixedFailure(
            'fixture_configuration', 'static_files',
            'invalid static file map',
        );
    }
    for (const [relative, body] of Object.entries(files)) {
        if (typeof body !== 'string' && !Buffer.isBuffer(body)) {
            throw fixedFailure(
                'fixture_configuration', 'static_files',
                'invalid static file body',
            );
        }
        const destination = path.resolve(contentRoot, relative);
        if (!destination.startsWith(`${contentRoot}${path.sep}`)) {
            throw fixedFailure(
                'fixture_configuration', 'static_files',
                'static file escapes fixture root',
            );
        }
        await fs.mkdir(path.dirname(destination), { recursive: true });
        await fs.writeFile(destination, body, { mode: 0o644 });
    }
}


async function generateCertificate(paths) {
    const result = await runCaptured('/usr/bin/openssl', [
        'req', '-x509', '-new', '-newkey', 'ec',
        '-pkeyopt', 'ec_paramgen_curve:P-256',
        '-nodes', '-sha256', '-days', '1',
        '-subj', '/CN=gate.powgate.test',
        '-addext', 'subjectAltName=DNS:powgate.test,DNS:gate.powgate.test',
        '-keyout', paths.privateKey,
        '-out', paths.certificate,
    ], {
        operation: 'certificate_generation',
        timeout: DEADLINES.controlled_probe,
        cwd: paths.root,
        env: process.env,
    });
    if (result.code !== 0) {
        throw fixedFailure(
            'fixture_configuration', 'certificate_generation',
            'fixture certificate generation failed',
        );
    }
    await fs.chmod(paths.privateKey, 0o600);
    await fs.chmod(paths.certificate, 0o644);
}


async function descendantsOf(parentIdentity) {
    const entries = await fs.readdir('/proc');
    const identities = [];
    const pendingParents = new Set([parentIdentity.pid]);
    let changed = true;
    while (changed) {
        changed = false;
        for (const entry of entries) {
            if (!/^\d+$/u.test(entry)) {
                continue;
            }
            const pid = Number.parseInt(entry, 10);
            if (identities.some((identity) => identity.pid === pid)) {
                continue;
            }
            try {
                const identity = await readProcessIdentity(pid);
                if (pendingParents.has(identity.ppid)) {
                    identities.push(identity);
                    pendingParents.add(identity.pid);
                    changed = true;
                }
            } catch (error) {
                if (error?.code !== 'ENOENT' && error?.code !== 'ESRCH') {
                    throw error;
                }
            }
        }
    }
    return identities;
}


async function refreshOwnedProcessIdentity(identity, requiredArgument) {
    try {
        const current = await readProcessIdentity(identity.pid);
        if (current.ppid !== identity.ppid
            || current.startTime !== identity.startTime
            || current.executable !== identity.executable
            || !current.commandLine.some((value) => value.includes(requiredArgument))) {
            return null;
        }
        return current;
    } catch (error) {
        if (error?.code === 'ENOENT' || error?.code === 'ESRCH') {
            return null;
        }
        throw error;
    }
}


async function waitUntilGone(identity, milliseconds) {
    const deadline = Date.now() + milliseconds;
    while (Date.now() < deadline) {
        if (!await identityStillMatches(identity)) {
            return true;
        }
        await delay(20);
    }
    return !await identityStillMatches(identity);
}


function requestReadiness(origin, signal) {
    return new Promise((resolve, reject) => {
        const url = new URL('/__powgate_ready', origin);
        const request = https.get({
            hostname: '127.0.0.1',
            port: url.port,
            path: url.pathname,
            servername: url.hostname,
            rejectUnauthorized: false,
            signal,
        }, (response) => {
            response.resume();
            response.once('end', () => resolve(response.statusCode === 204));
        });
        request.once('error', reject);
    });
}


async function waitForNginxReady(runtime) {
    await withDeadline(
        'nginx_readiness', DEADLINES.nginx_readiness, async (signal) => {
        while (!signal.aborted) {
            if (runtime.stderrOverflow) {
                throw fixedFailure(
                    'internal_invariant', 'nginx_observation',
                    'NGINX observation limit exceeded',
                );
            }
            if (runtime.child.exitCode !== null) {
                throw fixedFailure(
                    'fixture_startup', 'nginx_readiness',
                    'NGINX exited before readiness',
                );
            }
            try {
                if (await requestReadiness(runtime.origin, signal)) {
                    return;
                }
            } catch (error) {
                if (signal.aborted) {
                    throw error;
                }
            }
            await delay(25);
        }
    });
}


class NginxFixtureRuntime {
    constructor(options) {
        if (options === null || typeof options !== 'object'
            || typeof options.renderNginxConfig !== 'function') {
            throw new TypeError('invalid fixture options');
        }
        this.options = options;
        this.paths = null;
        this.ports = null;
        this.origin = null;
        this.child = null;
        this.stderr = '';
        this.stderrOverflow = false;
        this.reservations = null;
        this.nginx = {
            master: null,
            workers: [],
            cleanupEscalated: false,
        };
        this.diagnosticPath = null;
    }

    async start() {
        this.paths = await createRuntimePaths(this.options.target);
        await generateCertificate(this.paths);
        await writeStaticFiles(this.paths.content, this.options.staticFiles);
        const binary = this.options.nginxBinary ?? '/usr/sbin/nginx';
        for (let attempt = 1; attempt <= 3; attempt += 1) {
            this.reservations = await reserveFixturePorts();
            this.ports = this.reservations.values;
            this.origin = `https://gate.powgate.test:${this.ports.https}`;
            const configuration = await this.options.renderNginxConfig({
                paths: this.paths,
                ports: this.ports,
                certificate: Object.freeze({
                    hosts: Object.freeze(['powgate.test', 'gate.powgate.test']),
                }),
                modulePath: this.options.modulePath,
                protocolMode: this.options.protocolMode,
            });
            if (typeof configuration !== 'string') {
                throw fixedFailure(
                    'fixture_configuration', 'nginx_config_render',
                    'NGINX configuration renderer returned invalid data',
                );
            }
            await fs.writeFile(this.paths.nginxConfig, configuration, {
                encoding: 'utf8',
                mode: 0o600,
            });
            const prefix = `${this.paths.nginxPrefix}${path.sep}`;
            const configTest = await runCaptured(binary, [
                '-t', '-e', this.paths.nginxErrorLog,
                '-p', prefix, '-c', this.paths.nginxConfig,
            ], {
                operation: 'nginx_config_test',
                timeout: DEADLINES.nginx_config_test,
                cwd: this.paths.root,
                env: this.options.nginxEnvironment ?? process.env,
            });
            if (configTest.code !== 0) {
                throw fixedFailure(
                    'fixture_configuration', 'nginx_config_test',
                    'NGINX configuration rejected',
                );
            }
            await this.reservations.close();
            this.reservations = null;
            this.child = spawn(binary, [
                '-e', this.paths.nginxErrorLog,
                '-p', prefix, '-c', this.paths.nginxConfig,
                '-g', 'daemon off;',
            ], {
                cwd: this.paths.root,
                env: this.options.nginxEnvironment ?? process.env,
                stdio: ['ignore', 'pipe', 'pipe'],
            });
            this.child.stderr.on('data', (chunk) => {
                const next = this.stderr + chunk.toString('utf8');
                if (Buffer.byteLength(next, 'utf8') > 1024 * 1024) {
                    this.stderrOverflow = true;
                    return;
                }
                this.stderr = next;
            });
            this.child.stdout.resume();
            try {
                this.nginx.master = await readProcessIdentity(this.child.pid);
                await waitForNginxReady(this);
                this.nginx.master = await refreshOwnedProcessIdentity(
                    this.nginx.master, this.paths.nginxPrefix,
                );
                if (this.nginx.master === null) {
                    throw fixedFailure(
                        'internal_invariant', 'process_identity',
                        'NGINX master identity changed unexpectedly',
                    );
                }
                this.nginx.workers = await descendantsOf(this.nginx.master);
                return;
            } catch (error) {
                await delay(25);
                const collision = isNginxBindCollision(this.stderr, [
                    this.ports.https, this.ports.backend,
                ]);
                const current = this.nginx.master === null ? null
                    : await refreshOwnedProcessIdentity(
                        this.nginx.master, this.paths.nginxPrefix,
                    );
                if (current !== null) {
                    await signalVerifiedProcess(current, 'SIGTERM');
                    await waitUntilGone(current, 2000);
                }
                if (!collision || attempt === 3) {
                    throw error instanceof BrowserTestFailure ? error : fixedFailure(
                        'fixture_startup', 'nginx_readiness',
                        'NGINX fixture failed before readiness',
                    );
                }
                this.child = null;
                this.stderr = '';
                this.stderrOverflow = false;
                this.nginx.master = null;
                this.nginx.workers = [];
            }
        }
    }

    view() {
        return Object.freeze({
            paths: this.paths,
            origin: this.origin,
            ports: this.ports,
            nginx: this.nginx,
        });
    }

    async captureDiagnostics(error) {
        const category = error instanceof BrowserTestFailure
            ? error.category : 'internal_invariant';
        const operation = error instanceof BrowserTestFailure
            ? error.operation : 'fixture_failure';
        const bundle = buildDiagnosticBundle({
            target: this.options.target,
            category,
            operation,
            verdict: 'failed',
            process: this.nginx.master === null ? undefined : {
                pid: this.nginx.master.pid,
                executable: this.nginx.master.executable,
            },
        });
        const directory = path.resolve('build/browser-diagnostics');
        await fs.mkdir(directory, { recursive: true });
        this.diagnosticPath = path.join(
            directory,
            `${this.options.target}-${process.pid}-${randomBytes(4).toString('hex')}.json`,
        );
        await fs.writeFile(
            this.diagnosticPath,
            `${JSON.stringify(bundle, null, 2)}\n`,
            { encoding: 'utf8', mode: 0o600 },
        );
    }

    async cleanup() {
        let cleanupFailure;
        if (this.reservations !== null) {
            await this.reservations.close();
            this.reservations = null;
        }
        if (this.nginx.master !== null) {
            if (!await identityStillMatches(this.nginx.master)) {
                const refreshed = await refreshOwnedProcessIdentity(
                    this.nginx.master, this.paths.nginxPrefix,
                );
                if (refreshed !== null) {
                    this.nginx.master = refreshed;
                }
            }
        }
        if (this.nginx.master !== null
            && await identityStillMatches(this.nginx.master)) {
            this.nginx.workers = await descendantsOf(this.nginx.master);
            await signalVerifiedProcess(this.nginx.master, 'SIGQUIT');
            if (!await waitUntilGone(
                this.nginx.master, DEADLINES.nginx_quit,
            )) {
                this.nginx.cleanupEscalated = true;
                const identities = [this.nginx.master, ...this.nginx.workers];
                for (const identity of identities) {
                    await signalVerifiedProcess(identity, 'SIGTERM');
                }
                if (!await waitUntilGone(
                    this.nginx.master, DEADLINES.nginx_term,
                )) {
                    for (const identity of identities) {
                        await signalVerifiedProcess(identity, 'SIGKILL');
                    }
                    await waitUntilGone(
                        this.nginx.master, DEADLINES.nginx_kill,
                    );
                }
                cleanupFailure = fixedFailure(
                    'cleanup', 'nginx_shutdown',
                    'NGINX graceful shutdown escalated',
                );
            }
            for (const worker of this.nginx.workers) {
                if (await identityStillMatches(worker)) {
                    cleanupFailure ??= fixedFailure(
                        'cleanup', 'nginx_shutdown',
                        'NGINX worker remained after shutdown',
                    );
                }
            }
        } else if (this.child !== null && this.child.exitCode === null) {
            cleanupFailure = fixedFailure(
                'cleanup', 'process_identity',
                'NGINX master identity could not be verified',
            );
        }
        if (this.paths !== null) {
            await fs.rm(this.paths.root, { recursive: true, force: true });
        }
        if (cleanupFailure !== undefined) {
            throw cleanupFailure;
        }
    }
}


export class BrowserTestFailure extends Error {
    constructor(category, operation, message, options = {}) {
        super(message, options);
        if (!FAILURE_CATEGORIES.has(category)) {
            throw new TypeError('invalid category');
        }
        if (typeof operation !== 'string' || !SAFE_TOKEN.test(operation)) {
            throw new TypeError('invalid operation');
        }
        this.name = 'BrowserTestFailure';
        this.category = category;
        this.operation = operation;
        this.diagnosticFailures = [];
        this.cleanupFailures = [];
        Object.freeze(this);
    }
}


export async function withDeadline(operation, milliseconds, work) {
    if (typeof operation !== 'string' || !SAFE_TOKEN.test(operation)
        || !Number.isSafeInteger(milliseconds) || milliseconds <= 0
        || typeof work !== 'function') {
        throw new TypeError('invalid deadline');
    }
    const controller = new AbortController();
    let timer;
    const deadline = new Promise((resolve, reject) => {
        timer = setTimeout(() => {
            reject(fixedFailure(
                'browser_runtime', operation,
                `operation deadline exceeded: ${operation}`,
            ));
            controller.abort();
        }, milliseconds);
    });
    try {
        return await Promise.race([
            Promise.resolve().then(() => work(controller.signal)),
            deadline,
        ]);
    } finally {
        clearTimeout(timer);
    }
}


export async function readProcessIdentity(pid) {
    if (!Number.isSafeInteger(pid) || pid <= 0) {
        throw new TypeError('invalid pid');
    }
    const directory = `/proc/${pid}`;
    const [stat, executable, commandLineBytes] = await Promise.all([
        fs.readFile(`${directory}/stat`, 'utf8'),
        fs.readlink(`${directory}/exe`),
        fs.readFile(`${directory}/cmdline`),
    ]);
    const close = stat.lastIndexOf(')');
    if (close < 0) {
        throw fixedFailure(
            'internal_invariant', 'process_identity',
            'invalid process identity record',
        );
    }
    const fields = stat.slice(close + 2).trim().split(/\s+/u);
    if (fields.length < 20) {
        throw fixedFailure(
            'internal_invariant', 'process_identity',
            'invalid process identity record',
        );
    }
    const commandLine = commandLineBytes.toString('utf8').split('\0');
    if (commandLine.at(-1) === '') {
        commandLine.pop();
    }
    return Object.freeze({
        pid,
        ppid: Number.parseInt(fields[1], 10),
        startTime: fields[19],
        executable,
        commandLine: Object.freeze(commandLine),
    });
}


export async function identityStillMatches(identity) {
    if (identity === null || typeof identity !== 'object') {
        return false;
    }
    try {
        const current = await readProcessIdentity(identity.pid);
        return current.ppid === identity.ppid
            && current.startTime === identity.startTime
            && current.executable === identity.executable
            && arraysEqual(current.commandLine, identity.commandLine);
    } catch (error) {
        if (error?.code === 'ENOENT' || error?.code === 'ESRCH') {
            return false;
        }
        throw error;
    }
}


export async function signalVerifiedProcess(identity, signal) {
    if (!await identityStillMatches(identity)) {
        return false;
    }
    try {
        process.kill(identity.pid, signal);
        return true;
    } catch (error) {
        if (error?.code === 'ESRCH') {
            return false;
        }
        throw error;
    }
}


export function isNginxBindCollision(stderr, selectedPorts) {
    if (typeof stderr !== 'string' || !Array.isArray(selectedPorts)
        || !stderr.includes('bind()')
        || !stderr.includes('Address already in use')) {
        return false;
    }
    return selectedPorts.some((port) => Number.isSafeInteger(port)
        && port > 0 && port <= 65535 && stderr.includes(`:${port}`));
}


export function buildDiagnosticBundle(input) {
    if (input === null || typeof input !== 'object') {
        throw new TypeError('invalid diagnostic input');
    }
    const output = {};
    if (input.target !== undefined) {
        output.target = safeToken(input.target, 'target');
    }
    if (input.category !== undefined) {
        if (!FAILURE_CATEGORIES.has(input.category)) {
            throw fixedFailure(
                'internal_invariant', 'diagnostic_capture',
                'invalid diagnostic field: category',
            );
        }
        output.category = input.category;
    }
    if (input.operation !== undefined) {
        output.operation = safeToken(input.operation, 'operation');
    }
    if (input.verdict !== undefined) {
        output.verdict = safeToken(input.verdict, 'verdict');
    }
    if (input.timeoutMs !== undefined) {
        if (!Number.isSafeInteger(input.timeoutMs) || input.timeoutMs < 0) {
            throw fixedFailure(
                'internal_invariant', 'diagnostic_capture',
                'invalid diagnostic field: timeoutMs',
            );
        }
        output.timeoutMs = input.timeoutMs;
    }
    if (input.process !== undefined) {
        const processRecord = {};
        if (Number.isSafeInteger(input.process.pid) && input.process.pid > 0) {
            processRecord.pid = input.process.pid;
        }
        if (typeof input.process.executable === 'string'
            && input.process.executable.startsWith('/')) {
            processRecord.executable = input.process.executable;
        }
        output.process = processRecord;
    }
    if (input.response !== undefined) {
        const response = {};
        if (Number.isSafeInteger(input.response.status)) {
            response.status = input.response.status;
        }
        if (input.response.protocol !== undefined) {
            response.protocol = safeToken(input.response.protocol, 'protocol');
        }
        if (Array.isArray(input.response.headerNames)) {
            response.headerNames = input.response.headerNames.map(
                (name) => safeToken(name, 'header_name'),
            );
        }
        output.response = response;
    }
    const bytes = Buffer.byteLength(JSON.stringify(output), 'utf8');
    if (bytes > CAPTURE_LIMITS.max_retained_diagnostic_bytes) {
        throw fixedFailure(
            'internal_invariant', 'diagnostic_capture',
            'diagnostic size limit exceeded',
        );
    }
    return deepFreeze(output);
}


export class FixtureTransaction {
    #hooks;
    #state = 'created';
    #cleanupPromise = null;

    constructor(hooks = {}) {
        this.#hooks = Object.freeze({
            start: hooks.start ?? (async () => {}),
            diagnostics: hooks.diagnostics ?? (async () => {}),
            cleanup: hooks.cleanup ?? (async () => {}),
        });
        for (const hook of Object.values(this.#hooks)) {
            if (typeof hook !== 'function') {
                throw new TypeError('invalid fixture hook');
            }
        }
    }

    get state() {
        return this.#state;
    }

    #transition(next) {
        if (!transitions[this.#state].has(next)) {
            throw fixedFailure(
                'internal_invariant', 'fixture_state',
                `invalid fixture transition: ${this.#state}-${next}`,
            );
        }
        this.#state = next;
    }

    async start() {
        if (this.#state !== 'created') {
            throw fixedFailure(
                'internal_invariant', 'fixture_start',
                'fixture cannot start from current state',
            );
        }
        this.#transition('starting');
        try {
            await this.#hooks.start();
            this.#transition('ready');
        } catch (error) {
            this.#transition('failed');
            throw error;
        }
    }

    async cleanup() {
        if (this.#state === 'stopped') {
            return;
        }
        if (this.#cleanupPromise !== null) {
            return this.#cleanupPromise;
        }
        if (this.#state !== 'ready' && this.#state !== 'failed') {
            throw fixedFailure(
                'internal_invariant', 'fixture_cleanup',
                'fixture cannot clean up from current state',
            );
        }
        this.#transition('stopping');
        this.#cleanupPromise = (async () => {
            try {
                await this.#hooks.cleanup();
            } finally {
                this.#transition('stopped');
            }
        })();
        return this.#cleanupPromise;
    }

    async run(callback) {
        if (typeof callback !== 'function') {
            throw new TypeError('invalid fixture callback');
        }
        let primary;
        let result;
        try {
            await this.start();
            result = await callback(this);
        } catch (error) {
            primary = error;
            if (this.#state === 'ready') {
                this.#transition('failed');
            }
            try {
                await this.#hooks.diagnostics(error);
            } catch (diagnosticError) {
                primary.diagnosticFailures ??= [];
                primary.diagnosticFailures.push(classifySecondary(
                    'internal_invariant', 'diagnostic_capture', diagnosticError,
                ));
            }
        }
        try {
            await this.cleanup();
        } catch (cleanupError) {
            if (primary === undefined) {
                throw classifySecondary('cleanup', 'fixture_cleanup', cleanupError);
            }
            primary.cleanupFailures ??= [];
            primary.cleanupFailures.push(classifySecondary(
                'cleanup', 'fixture_cleanup', cleanupError,
            ));
        }
        if (primary !== undefined) {
            throw primary;
        }
        return result;
    }
}


export async function withFixture(options, callback) {
    if (typeof callback !== 'function') {
        throw new TypeError('invalid fixture callback');
    }
    const runtime = new NginxFixtureRuntime(options);
    const transaction = new FixtureTransaction({
        start: () => runtime.start(),
        diagnostics: (error) => runtime.captureDiagnostics(error),
        cleanup: () => runtime.cleanup(),
    });
    return transaction.run(() => callback(runtime.view()));
}
