import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
    BrowserTestFailure,
    withDeadline,
    withFixture,
} from './lib/fixture.mjs';
import { DEADLINES } from './lib/constants.mjs';


const CONSOLE_IDENTIFIER = 'POWGATE_FEASIBILITY_CONSOLE';
const PAGE_ERROR_IDENTIFIER = 'POWGATE_FEASIBILITY_PAGE_ERROR';
const pathname = '/feasibility?probe=1';
const allowedScript = `globalThis.feasibilityAllowed = true;
document.cookie = "powgate_feasibility=1; Path=/; Secure; SameSite=Lax";
console.log("${CONSOLE_IDENTIFIER}");`;
const blockedScript = 'globalThis.feasibilityBlocked = true;';
const scriptDigest = createHash('sha256').update(allowedScript, 'utf8')
    .digest('base64');
const pageBody = `<!doctype html>
<meta charset="utf-8">
<title>PowGate browser feasibility</title>
<main id="status">ready</main>
<script>${allowedScript}</script>
<script>${blockedScript}</script>
`;
let currentOperation = 'initialization';


function nginxConfiguration({ paths, ports }) {
    return `
worker_processes 1;
pid ${paths.nginxPid};
error_log ${paths.nginxErrorLog} notice;
events { worker_connections 128; }
http {
    access_log off;
    client_body_temp_path ${paths.clientBodyTemp};
    proxy_temp_path ${paths.proxyTemp};
    fastcgi_temp_path ${paths.fastcgiTemp};
    uwsgi_temp_path ${paths.uwsgiTemp};
    scgi_temp_path ${paths.scgiTemp};
    server {
        listen 127.0.0.1:${ports.https} ssl;
        http2 on;
        ssl_certificate ${paths.certificate};
        ssl_certificate_key ${paths.privateKey};
        root ${paths.content};
        add_header Content-Security-Policy "default-src 'none'; script-src 'sha256-${scriptDigest}'; img-src https://gate.powgate.test:1" always;
        location = /__powgate_ready { return 204; }
        location = /feasibility {
            default_type text/html;
            try_files /feasibility.html =404;
        }
    }
}
`;
}


function unexpectedEvents(events, allowed) {
    return events.filter((event) => !allowed.some((predicate) => predicate(event)));
}


async function runProtocol(protocolMode) {
    currentOperation = `${protocolMode}_fixture_start`;
    await withFixture({
        target: `test-browser-feasibility-${protocolMode}`,
        protocolMode,
        nginxBinary: '/usr/sbin/nginx',
        staticFiles: { 'feasibility.html': pageBody },
        renderNginxConfig: nginxConfiguration,
    }, async (fixture) => {
        currentOperation = `${protocolMode}_browser_start`;
        const session = await fixture.createBrowserSession({
            protocolMode,
            observe: {
                consoleIdentifiers: [CONSOLE_IDENTIFIER],
                pageErrorIdentifiers: [PAGE_ERROR_IDENTIFIER],
                allowCspConsole: true,
                allowNetworkFailureConsole: true,
            },
        });
        const url = `${fixture.origin}${pathname}`;
        const allEvents = session.observations.openWindow('complete_run');
        const firstDocument = session.documentResponses.length;
        const consoleWindow = session.observations.openWindow('console_probe');
        const cspWindow = session.observations.openWindow('csp_probe');
        currentOperation = `${protocolMode}_navigation`;
        const response = await session.page.goto(url, { waitUntil: 'load' });
        assert.equal(response.status(), 200);
        const protocol = await session.waitForDocument(url, firstDocument);
        assert.equal(protocol.protocol, protocolMode === 'h2' ? 'h2' : 'http/1.1');
        assert.equal(await session.page.evaluate(() => globalThis.feasibilityAllowed), true);
        assert.equal(
            await session.page.evaluate(() => globalThis.feasibilityBlocked),
            undefined,
        );
        assert.equal(
            (await consoleWindow.waitFor((event) =>
                event.type === 'console'
                    && event.identifier === CONSOLE_IDENTIFIER)).identifier,
            CONSOLE_IDENTIFIER,
        );
        await cspWindow.waitFor((event) => event.type === 'csp_violation');
        consoleWindow.close();
        cspWindow.close();

        currentOperation = `${protocolMode}_cookie`;
        const cookies = await session.context.cookies(url);
        const cookie = cookies.find((entry) => entry.name === 'powgate_feasibility');
        assert.ok(cookie);
        assert.equal(cookie.value, '1');
        assert.equal(cookie.secure, true);
        assert.equal(cookie.sameSite, 'Lax');
        assert.equal(cookie.path, '/');
        assert.match(await session.page.evaluate(() => document.cookie),
            /(?:^|; )powgate_feasibility=1(?:;|$)/u);
        await session.cdp.send('Network.deleteCookies', {
            name: 'powgate_feasibility',
            url,
        });
        assert.equal(
            (await session.context.cookies(url))
                .some((entry) => entry.name === 'powgate_feasibility'),
            false,
        );

        currentOperation = `${protocolMode}_reload`;
        const reloadStart = session.documentResponses.length;
        await session.page.reload({ waitUntil: 'load' });
        assert.equal(
            await session.page.evaluate(() => location.pathname + location.search),
            pathname,
        );
        const reloadProtocol = await session.waitForDocument(url, reloadStart);
        assert.equal(
            reloadProtocol.protocol,
            protocolMode === 'h2' ? 'h2' : 'http/1.1',
        );

        currentOperation = `${protocolMode}_page_error`;
        const errorWindow = session.observations.openWindow('page_error_probe');
        await session.page.evaluate((identifier) => {
            setTimeout(() => {
                throw new Error(identifier);
            }, 0);
        }, PAGE_ERROR_IDENTIFIER);
        await errorWindow.waitFor((event) =>
            event.type === 'page_error'
                && event.identifier === PAGE_ERROR_IDENTIFIER);
        errorWindow.close();

        currentOperation = `${protocolMode}_request_failure`;
        const requestWindow = session.observations.openWindow('request_failure_probe');
        await session.page.evaluate(() => {
            const image = new Image();
            image.src = 'https://gate.powgate.test:1/expected-failure';
            document.body.append(image);
        });
        await requestWindow.waitFor((event) =>
            event.type === 'request_failure' && event.resourceType === 'image');
        requestWindow.close();

        currentOperation = `${protocolMode}_renderer_crash`;
        const crashWindow = session.observations.openWindow('renderer_crash_probe');
        const disposable = await session.createPage();
        await disposable.page.goto('about:blank');
        try {
            await withDeadline(
                'renderer_crash_probe', DEADLINES.controlled_probe,
                () => disposable.cdp.send('Page.crash'));
        } catch {
            /* the locked pairing may report target loss before command completion */
        }
        await crashWindow.waitFor((event) =>
            event.type === 'page_crash' || event.type === 'target_destroyed');
        crashWindow.close();
        assert.equal(session.browser.connected, true);
        assert.equal(await session.page.evaluate(() => 6 * 7), 42);

        currentOperation = `${protocolMode}_disconnect`;
        const disconnectWindow = session.observations.openWindow('disconnect_probe');
        await session.disconnectForProbe();
        await disconnectWindow.waitFor((event) =>
            event.type === 'browser_disconnected');
        disconnectWindow.close();
        assert.equal(session.sandbox.separateRenderer, true);
        assert.ok(session.ownedProcesses.length >= 2);
        assert.equal(session.ownedProcesses.every((identity) =>
            identity.commandLine.some((value) => value.includes(fixture.paths.root))), true);

        currentOperation = `${protocolMode}_event_audit`;
        const allowed = [
            (event) => event.type === 'console'
                && (event.identifier === CONSOLE_IDENTIFIER
                    || event.identifier === 'csp_enforcement'
                    || event.identifier === 'network_failure'),
            (event) => event.type === 'csp_violation',
            (event) => event.type === 'page_error'
                && event.identifier === PAGE_ERROR_IDENTIFIER,
            (event) => event.type === 'request_failure'
                && event.resourceType === 'image',
            (event) => event.type === 'page_crash',
            (event) => event.type === 'target_destroyed',
            (event) => event.type === 'browser_disconnected',
        ];
        const unexpected = unexpectedEvents(allEvents.snapshot(), allowed);
        assert.deepEqual(unexpected, []);
        allEvents.close();
    });
}


try {
    for (const protocolMode of ['h2', 'h1']) {
        await runProtocol(protocolMode);
    }
} catch (error) {
    if (error instanceof BrowserTestFailure) {
        process.stderr.write(
            `browser-feasibility: ${error.category} ${error.operation} failed\n`,
        );
    } else {
        process.stderr.write(
            `browser-feasibility: assertion ${currentOperation} failed\n`,
        );
    }
    process.exitCode = 1;
}
