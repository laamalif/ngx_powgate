import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import https from 'node:https';
import { createRequire } from 'node:module';
import net from 'node:net';
import path from 'node:path';

import {
    CAPTURE_LIMITS,
    DEADLINES,
    FAILURE_CATEGORIES,
} from './constants.mjs';
import {
    buildSanitizedNginxEnvironment,
    collectSanitizerReports,
    validateSanitizerManifest,
} from './sanitizer.mjs';


const SAFE_TOKEN = /^[A-Za-z0-9_.-]+$/;
const HOST_RESOLVER_RULE = 'MAP powgate.test 127.0.0.1,MAP gate.powgate.test 127.0.0.1,EXCLUDE localhost';
const CHROMIUM_ARGUMENTS = Object.freeze([
    '--disable-dev-shm-usage',
    '--disable-background-networking',
    '--disable-component-update',
    '--disable-default-apps',
    '--disable-domain-reliability',
    '--disable-sync',
    '--metrics-recording-only',
    '--no-default-browser-check',
    '--no-first-run',
    `--host-resolver-rules=${HOST_RESOLVER_RULE}`,
]);
const PROHIBITED_CHROMIUM_ARGUMENTS = Object.freeze([
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--single-process',
    '--no-zygote',
    '--disable-seccomp-filter-sandbox',
    '--disable-namespace-sandbox',
]);
const requireFromBrowserImage = createRequire(
    '/opt/ngx-powgate/browser/package.json',
);

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


async function waitForChildClose(child, milliseconds) {
    if (child === null || child.exitCode !== null || child.signalCode !== null) {
        return;
    }
    await Promise.race([
        new Promise((resolve) => child.once('close', resolve)),
        delay(milliseconds),
    ]);
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
    const chromiumProfile = path.join(root, 'chromium-profile');
    const chromiumHome = path.join(root, 'chromium-home');
    const chromiumConfig = path.join(chromiumHome, '.config');
    const chromiumCache = path.join(chromiumHome, '.cache');
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
        fs.mkdir(chromiumProfile, { recursive: true }),
        fs.mkdir(chromiumConfig, { recursive: true }),
        fs.mkdir(chromiumCache, { recursive: true }),
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
        chromiumProfile,
        chromiumHome,
        chromiumConfig,
        chromiumCache,
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


async function readProcessStatus(pid) {
    const text = await fs.readFile(`/proc/${pid}/status`, 'utf8');
    const values = {};
    for (const line of text.split('\n')) {
        const separator = line.indexOf(':');
        if (separator > 0) {
            values[line.slice(0, separator)] = line.slice(separator + 1).trim();
        }
    }
    return Object.freeze({
        uid: values.Uid ?? '',
        gid: values.Gid ?? '',
        noNewPrivs: values.NoNewPrivs ?? '',
        seccomp: values.Seccomp ?? '',
        capEff: values.CapEff ?? '',
    });
}


export function scrubChromiumEnvironment(environment, paths) {
    const scrubbed = { ...environment };
    for (const name of [
        'ASAN_OPTIONS',
        'UBSAN_OPTIONS',
        'LSAN_OPTIONS',
        'MSAN_OPTIONS',
        'LD_PRELOAD',
        'ASAN_SYMBOLIZER_PATH',
        'UBSAN_SYMBOLIZER_PATH',
        'LLVM_SYMBOLIZER_PATH',
    ]) {
        delete scrubbed[name];
    }
    scrubbed.HOME = paths.chromiumHome;
    scrubbed.XDG_CONFIG_HOME = paths.chromiumConfig;
    scrubbed.XDG_CACHE_HOME = paths.chromiumCache;
    return scrubbed;
}


async function chromiumProcessesForRuntime(runtimeRoot) {
    const identities = [];
    for (const entry of await fs.readdir('/proc')) {
        if (!/^\d+$/u.test(entry)) {
            continue;
        }
        try {
            const identity = await readProcessIdentity(Number.parseInt(entry, 10));
            const owned = identity.commandLine.some((value) =>
                value.includes(runtimeRoot));
            const chromium = identity.executable.includes('/chromium')
                || identity.executable.endsWith('/chrome_crashpad_handler');
            if (owned && chromium) {
                identities.push(identity);
            }
        } catch (error) {
            if (error?.code !== 'ENOENT' && error?.code !== 'ESRCH') {
                throw error;
            }
        }
    }
    return identities;
}


async function waitForRenderer(master) {
    return withDeadline(
        'chromium_renderer', DEADLINES.chromium_launch, async (signal) => {
        while (!signal.aborted) {
            const descendants = await descendantsOf(master);
            const renderer = descendants.find((identity) =>
                identity.commandLine.some((value) =>
                    value.split(/\s+/u).includes('--type=renderer')));
            if (renderer !== undefined) {
                return Object.freeze({ descendants, renderer });
            }
            await delay(25);
        }
        throw fixedFailure(
            'sandbox_policy', 'chromium_renderer',
            'Chromium renderer was not observed',
        );
    });
}


class BrowserSession {
    constructor(runtime, options) {
        this.runtime = runtime;
        this.options = options;
        this.browser = null;
        this.context = null;
        this.page = null;
        this.cdp = null;
        this.observations = new ObservationBuffer();
        this.documentResponses = [];
        this.master = null;
        this.descendants = [];
        this.ownedProcesses = [];
        this.renderer = null;
        this.sandbox = null;
        this.browserVersion = null;
        this.closed = false;
        this.observationFailure = null;
        this.expectedDisconnect = false;
        this.pages = new Set();
        this.cdpSessions = new Set();
    }

    #record(event) {
        try {
            this.observations.record(event);
        } catch (error) {
            this.observationFailure ??= error;
        }
    }

    #observePage(page) {
        this.pages.add(page);
        const allowedErrors = new Set(
            this.options.observe?.pageErrorIdentifiers ?? [],
        );
        page.on('console', (message) => {
            this.#record(Object.freeze({
                type: 'console',
                consoleType: message.type(),
                identifier: classifyConsoleMessage(
                    message.text(), this.options.observe,
                ),
            }));
        });
        page.on('pageerror', (error) => {
            const identifier = [...allowedErrors].find((value) =>
                error.message === value || error.message.endsWith(value));
            this.#record(Object.freeze({
                type: 'page_error',
                identifier: identifier ?? 'unexpected',
            }));
        });
        page.on('error', () => this.#record(Object.freeze({
            type: 'page_crash',
        })));
        page.on('requestfailed', (request) => this.#record(Object.freeze({
            type: 'request_failure',
            resourceType: request.resourceType(),
        })));
    }

    async #attachCdp(page) {
        const cdp = await withDeadline(
            'cdp_operation', DEADLINES.cdp_operation,
            () => page.createCDPSession(),
        );
        this.cdpSessions.add(cdp);
        await withDeadline(
            'cdp_operation', DEADLINES.cdp_operation,
            async () => {
                await cdp.send('Network.enable');
                await cdp.send('Audits.enable');
            },
        );
        cdp.on('Network.responseReceived', (event) => {
            if (event.type === 'Document') {
                this.documentResponses.push(Object.freeze({
                    requestId: event.requestId,
                    url: event.response.url,
                    protocol: event.response.protocol,
                    status: event.response.status,
                }));
            }
        });
        cdp.on('Audits.issueAdded', (event) => {
            if (event.issue?.code === 'ContentSecurityPolicyIssue') {
                this.#record(Object.freeze({ type: 'csp_violation' }));
            }
        });
        return cdp;
    }

    async start() {
        const puppeteer = requireFromBrowserImage('puppeteer-core');
        const arguments_ = buildChromiumLaunchArguments(this.options);
        const environment = scrubChromiumEnvironment(
            process.env, this.runtime.paths,
        );
        this.browser = await withDeadline(
            'chromium_launch', DEADLINES.chromium_launch,
            () => puppeteer.launch({
                executablePath: '/usr/bin/chromium',
                headless: true,
                acceptInsecureCerts: true,
                userDataDir: this.runtime.paths.chromiumProfile,
                args: arguments_,
                env: environment,
                timeout: DEADLINES.chromium_launch,
                handleSIGINT: false,
                handleSIGTERM: false,
                handleSIGHUP: false,
            }),
        );
        this.browser.once('disconnected', () => this.#record(Object.freeze({
            type: 'browser_disconnected',
        })));
        this.browser.on('targetdestroyed', (target) => this.#record(Object.freeze({
            type: 'target_destroyed',
            targetType: target.type(),
        })));
        const browserProcess = this.browser.process();
        if (browserProcess === null || !Number.isSafeInteger(browserProcess.pid)) {
            throw fixedFailure(
                'browser_pairing', 'chromium_process',
                'Chromium process identity is unavailable',
            );
        }
        this.master = await readProcessIdentity(browserProcess.pid);
        validateChromiumProcessArguments(this.master.commandLine);
        this.context = await withDeadline(
            'browser_context', DEADLINES.browser_context,
            () => this.browser.createBrowserContext(),
        );
        this.page = await withDeadline(
            'browser_context', DEADLINES.browser_context,
            () => this.context.newPage(),
        );
        this.#observePage(this.page);
        this.cdp = await this.#attachCdp(this.page);
        const version = await withDeadline(
            'cdp_operation', DEADLINES.cdp_operation,
            () => this.cdp.send('Browser.getVersion'),
        );
        this.browserVersion = version.product;
        const processes = await waitForRenderer(this.master);
        this.descendants = processes.descendants;
        this.renderer = processes.renderer;
        this.ownedProcesses = await chromiumProcessesForRuntime(
            this.runtime.paths.root,
        );
        for (const identity of this.ownedProcesses) {
            validateChromiumProcessArguments(identity.commandLine);
        }
        const [controllerStatus, rendererStatus] = await Promise.all([
            readProcessStatus(process.pid),
            readProcessStatus(this.renderer.pid),
        ]);
        if (rendererStatus.seccomp !== '2'
            || rendererStatus.capEff !== '0000000000000000'
            || controllerStatus.seccomp !== '2'
            || controllerStatus.capEff !== '0000000000000000') {
            throw fixedFailure(
                'sandbox_policy', 'chromium_sandbox',
                'observable Chromium sandbox properties failed',
            );
        }
        this.sandbox = Object.freeze({
            controller: controllerStatus,
            renderer: rendererStatus,
            separateRenderer: this.renderer.pid !== this.master.pid,
        });
        return this;
    }

    async createPage() {
        this.assertHealthy();
        const page = await withDeadline(
            'browser_context', DEADLINES.browser_context,
            () => this.context.newPage(),
        );
        this.#observePage(page);
        const cdp = await this.#attachCdp(page);
        return Object.freeze({ page, cdp });
    }

    waitForDocument(url, startIndex = 0) {
        return withDeadline(
            'cdp_operation', DEADLINES.cdp_operation, async (signal) => {
            while (!signal.aborted) {
                const response = this.documentResponses.slice(startIndex)
                    .find((entry) => entry.url === url);
                if (response !== undefined) {
                    return response;
                }
                await delay(10);
            }
            throw fixedFailure(
                'protocol_assertion', 'document_protocol',
                'document protocol observation missing',
            );
        });
    }

    assertHealthy() {
        if (this.observationFailure !== null) {
            throw this.observationFailure;
        }
        if (this.browser !== null && !this.browser.connected
            && !this.expectedDisconnect) {
            throw fixedFailure(
                'browser_runtime', 'chromium_connection',
                'Chromium disconnected unexpectedly',
            );
        }
    }

    async disconnectForProbe() {
        this.assertHealthy();
        this.expectedDisconnect = true;
        await withDeadline(
            'chromium_close', DEADLINES.chromium_close,
            () => this.browser.close(),
        );
    }

    async close() {
        if (this.closed) {
            return;
        }
        this.closed = true;
        let failure;
        const connected = this.browser !== null && this.browser.connected;
        for (const cdp of connected ? [...this.cdpSessions].reverse() : []) {
            try {
                await withDeadline(
                    'cdp_operation', DEADLINES.cdp_operation,
                    () => cdp.detach(),
                );
            } catch (error) {
                failure ??= error;
            }
        }
        for (const page of connected ? [...this.pages].reverse() : []) {
            try {
                if (!page.isClosed()) {
                    await withDeadline(
                        'page_context_close', DEADLINES.page_context_close,
                        () => page.close(),
                    );
                }
            } catch (error) {
                failure ??= error;
            }
        }
        if (this.context !== null && connected) {
            try {
                await withDeadline(
                    'page_context_close', DEADLINES.page_context_close,
                    () => this.context.close(),
                );
            } catch (error) {
                failure ??= error;
            }
        }
        if (this.browser !== null && connected) {
            try {
                await withDeadline(
                    'chromium_close', DEADLINES.chromium_close,
                    () => this.browser.close(),
                );
            } catch (error) {
                failure ??= error;
            }
        }
        if (this.master !== null && await identityStillMatches(this.master)) {
            failure ??= fixedFailure(
                'cleanup', 'chromium_close',
                'Chromium remained after browser close',
            );
            await signalVerifiedProcess(this.master, 'SIGTERM');
            if (!await waitUntilGone(this.master, 5000)) {
                await signalVerifiedProcess(this.master, 'SIGKILL');
                await waitUntilGone(this.master, 2000);
            }
        }
        for (const identity of this.ownedProcesses) {
            if (await identityStillMatches(identity)) {
                failure ??= fixedFailure(
                    'cleanup', 'chromium_close',
                    'Chromium helper remained after browser close',
                );
                await signalVerifiedProcess(identity, 'SIGTERM');
                if (!await waitUntilGone(identity, 2000)) {
                    await signalVerifiedProcess(identity, 'SIGKILL');
                    await waitUntilGone(identity, 1000);
                }
            }
        }
        this.runtime.browserSessions.delete(this);
        if (failure !== undefined) {
            throw failure;
        }
    }
}


class NginxFixtureRuntime {
    constructor(options) {
        if (options === null || typeof options !== 'object'
            || typeof options.renderNginxConfig !== 'function'
            || (options.sanitizerManifest !== undefined
                && options.nginxEnvironment !== undefined)) {
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
        this.nginxEnvironment = null;
        this.sanitizer = null;
        this.diagnosticPath = null;
        this.browserSessions = new Set();
    }

    async start() {
        this.paths = await createRuntimePaths(this.options.target);
        if (this.options.sanitizerManifest === undefined) {
            this.nginxEnvironment = this.options.nginxEnvironment ?? process.env;
        } else {
            const manifest = await validateSanitizerManifest(
                this.options.sanitizerManifest,
            );
            const reportDirectory = path.join(
                this.paths.logs, 'sanitizer-reports',
            );
            this.nginxEnvironment = await buildSanitizedNginxEnvironment(
                manifest, reportDirectory, process.env,
            );
            this.sanitizer = {
                initialWorkers: [],
                manifest,
                reportDirectory,
                workerGenerationCount: 0,
            };
        }
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
                env: this.nginxEnvironment,
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
                env: this.nginxEnvironment,
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
                if (this.sanitizer !== null) {
                    this.sanitizer.initialWorkers = this.nginx.workers.filter(
                        (worker) => worker.executable
                            === this.nginx.master.executable,
                    );
                    if (this.sanitizer.initialWorkers.length < 1) {
                        throw fixedFailure(
                            'fixture_startup', 'sanitizer_workers',
                            'instrumented NGINX worker was not observed',
                        );
                    }
                    this.sanitizer.workerGenerationCount = 1;
                }
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
            createBrowserSession: async (options) => {
                const session = new BrowserSession(this, options);
                this.browserSessions.add(session);
                try {
                    return await session.start();
                } catch (error) {
                    try {
                        await session.close();
                    } catch {
                        /* the startup failure remains primary */
                    }
                    throw error;
                }
            },
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
        let sanitizerMasterWasAlive = false;
        for (const session of [...this.browserSessions].reverse()) {
            try {
                await session.close();
            } catch (error) {
                cleanupFailure ??= classifySecondary(
                    'cleanup', 'chromium_close', error,
                );
            }
        }
        if (this.reservations !== null) {
            await this.reservations.close();
            this.reservations = null;
        }
        if (this.nginx.master !== null) {
            if (this.sanitizer !== null) {
                sanitizerMasterWasAlive = await identityStillMatches(
                    this.nginx.master,
                );
            }
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
            if (this.sanitizer !== null) {
                const initial = this.sanitizer.initialWorkers.map((worker) =>
                    `${worker.pid}:${worker.startTime}`).sort();
                const current = this.nginx.workers.filter((worker) =>
                    worker.executable === this.nginx.master.executable)
                    .map((worker) => `${worker.pid}:${worker.startTime}`).sort();
                if (!arraysEqual(initial, current)) {
                    cleanupFailure ??= fixedFailure(
                        'cleanup', 'sanitizer_workers',
                        'instrumented NGINX worker generation changed',
                    );
                }
            }
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
        if (this.sanitizer !== null) {
            await waitForChildClose(this.child, 1000);
            const workersExited = (await Promise.all(
                this.sanitizer.initialWorkers.map((worker) =>
                    identityStillMatches(worker)),
            )).every((alive) => !alive);
            const masterExited = this.nginx.master !== null
                && !await identityStillMatches(this.nginx.master);
            try {
                await collectSanitizerReports({
                    cleanupEscalated: this.nginx.cleanupEscalated,
                    masterExitedCleanly: sanitizerMasterWasAlive
                        && masterExited && this.child?.exitCode === 0
                        && this.child?.signalCode === null,
                    reportDirectory: this.sanitizer.reportDirectory,
                    stderr: this.stderr,
                    workerGenerationCount:
                        this.sanitizer.workerGenerationCount,
                    workersExited,
                });
            } catch (error) {
                cleanupFailure ??= fixedFailure(
                    'cleanup', 'sanitizer_reports',
                    'sanitized NGINX execution failed', { cause: error },
                );
            }
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


export function classifyConsoleMessage(text, options = {}) {
    if (typeof text !== 'string' || options === null
        || typeof options !== 'object' || Array.isArray(options)) {
        throw new TypeError('invalid console observation');
    }
    const allowed = new Set(options.consoleIdentifiers ?? []);
    if (allowed.has(text)) {
        return text;
    }
    if (options.allowChallengeStatusConsole === true
        && /^Failed to load resource: the server responded with a status of 503(?:\s|$)/u
            .test(text))
    {
        return 'challenge_status';
    }
    if (options.allowCspConsole === true
        && (text.startsWith('Refused to execute inline script')
            || text.includes('Content Security Policy')))
    {
        return 'csp_enforcement';
    }
    if (options.allowNetworkFailureConsole === true
        && text.startsWith('Failed to load resource:'))
    {
        return 'network_failure';
    }
    return 'unexpected';
}


export function validateChromiumProcessArguments(arguments_) {
    if (!Array.isArray(arguments_)
        || arguments_.some((argument) => typeof argument !== 'string')) {
        throw new TypeError('invalid Chromium arguments');
    }
    const tokens = arguments_.flatMap((argument) => argument.split(/\s+/u));
    for (const argument of tokens) {
        for (const prohibited of PROHIBITED_CHROMIUM_ARGUMENTS) {
            if (argument === prohibited || argument.startsWith(`${prohibited}=`)) {
                throw fixedFailure(
                    'sandbox_policy', 'chromium_arguments',
                    `prohibited Chromium argument: ${prohibited}`,
                );
            }
        }
    }
}


export function buildChromiumLaunchArguments(options) {
    if (options === null || typeof options !== 'object'
        || (options.protocolMode !== 'h1' && options.protocolMode !== 'h2')) {
        throw new TypeError('invalid Chromium launch options');
    }
    if (options.extraArguments !== undefined
        && (!Array.isArray(options.extraArguments)
            || options.extraArguments.length !== 0)) {
        validateChromiumProcessArguments(options.extraArguments ?? []);
        throw fixedFailure(
            'sandbox_policy', 'chromium_arguments',
            'additional Chromium arguments are forbidden',
        );
    }
    const arguments_ = [...CHROMIUM_ARGUMENTS];
    if (options.protocolMode === 'h1') {
        arguments_.push('--disable-http2');
    }
    validateChromiumProcessArguments(arguments_);
    return Object.freeze(arguments_);
}


export class ObservationBuffer {
    #events = [];
    #metadataBytes = 0;
    #maxEvents;
    #maxBytes;
    #waiters = new Set();

    constructor(options = {}) {
        this.#maxEvents = options.maxEvents
            ?? CAPTURE_LIMITS.max_observation_events_per_page;
        this.#maxBytes = options.maxBytes
            ?? CAPTURE_LIMITS.max_observation_metadata_bytes_per_page;
        if (!Number.isSafeInteger(this.#maxEvents) || this.#maxEvents <= 0
            || !Number.isSafeInteger(this.#maxBytes) || this.#maxBytes <= 0) {
            throw new TypeError('invalid observation limits');
        }
    }

    record(event) {
        if (event === null || typeof event !== 'object' || Array.isArray(event)) {
            throw new TypeError('invalid observation event');
        }
        if (this.#events.length >= this.#maxEvents) {
            throw fixedFailure(
                'internal_invariant', 'observation_buffer',
                'observation event limit exceeded',
            );
        }
        const bytes = Buffer.byteLength(JSON.stringify(event), 'utf8');
        if (this.#metadataBytes + bytes > this.#maxBytes) {
            throw fixedFailure(
                'internal_invariant', 'observation_buffer',
                'observation metadata limit exceeded',
            );
        }
        const frozen = deepFreeze({ ...event });
        this.#events.push(frozen);
        this.#metadataBytes += bytes;
        for (const waiter of [...this.#waiters]) {
            if (!waiter.window.closed && waiter.predicate(frozen)) {
                clearTimeout(waiter.timer);
                this.#waiters.delete(waiter);
                waiter.resolve(frozen);
            }
        }
        return frozen;
    }

    openWindow(name) {
        safeToken(name, 'observation_window');
        const buffer = this;
        const window = {
            name,
            cursor: this.#events.length,
            closed: false,
            snapshot() {
                if (this.closed) {
                    throw new Error('closed observation window');
                }
                return buffer.#events.slice(this.cursor);
            },
            waitFor(predicate, milliseconds = DEADLINES.controlled_probe) {
                if (this.closed || typeof predicate !== 'function'
                    || !Number.isSafeInteger(milliseconds) || milliseconds <= 0) {
                    throw new TypeError('invalid observation wait');
                }
                const existing = this.snapshot().find(predicate);
                if (existing !== undefined) {
                    return Promise.resolve(existing);
                }
                return new Promise((resolve, reject) => {
                    const waiter = {
                        window: this,
                        predicate,
                        resolve,
                        reject,
                        timer: null,
                    };
                    waiter.timer = setTimeout(() => {
                        buffer.#waiters.delete(waiter);
                        reject(fixedFailure(
                            'browser_runtime', name,
                            `operation deadline exceeded: ${name}`,
                        ));
                    }, milliseconds);
                    buffer.#waiters.add(waiter);
                });
            },
            close() {
                if (this.closed) {
                    return;
                }
                this.closed = true;
                for (const waiter of [...buffer.#waiters]) {
                    if (waiter.window === this) {
                        clearTimeout(waiter.timer);
                        buffer.#waiters.delete(waiter);
                        waiter.reject(fixedFailure(
                            'browser_runtime', name,
                            `observation window closed: ${name}`,
                        ));
                    }
                }
            },
        };
        return window;
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
