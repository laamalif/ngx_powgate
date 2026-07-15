import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { promises as fs } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';


const nginxBinary = process.env.NGX_BINARY ?? '/usr/sbin/nginx';
const modulePath = process.env.POW_MODULE_PATH
    ?? '/work/out/ngx_http_pow_module.so';


async function listen(server) {
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    return server.address().port;
}


async function reservePort() {
    const server = net.createServer();
    const port = await listen(server);

    await new Promise((resolve, reject) => {
        server.close((error) => error == null ? resolve() : reject(error));
    });

    return port;
}


async function run(command, args) {
    const child = spawn(command, args, { stdio: 'ignore' });
    const [code, signal] = await once(child, 'exit');

    assert.equal(signal, null, `${command} terminated by ${signal}`);
    assert.equal(code, 0, `${command} exited with ${code}`);
}


async function requestFrontend(port, agent) {
    return await new Promise((resolve, reject) => {
        const request = https.request({
            agent,
            headers: { accept: 'text/html' },
            host: '127.0.0.1',
            method: 'GET',
            path: '/',
            port
        }, resolve);

        request.on('error', reject);
        request.end();
    });
}


async function waitForFrontend(port, agent) {
    let lastError;

    for (let attempt = 0; attempt < 100; attempt++) {
        try {
            return await requestFrontend(port, agent);
        } catch (error) {
            lastError = error;
            await new Promise((resolve) => setTimeout(resolve, 50));
        }
    }

    throw lastError;
}


async function responseBody(response) {
    const chunks = [];

    response.on('data', (chunk) => chunks.push(chunk));
    await once(response, 'end');
    return Buffer.concat(chunks).toString('utf8');
}


async function stop(child) {
    if (child.exitCode == null) {
        child.kill('SIGTERM');
        await once(child, 'exit');
    }
}


let backendRequests = 0;
const backend = http.createServer((request, response) => {
    backendRequests++;
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('backend\n');
});
const backendPort = await listen(backend);
const frontendPort = await reservePort();
const prefix = await fs.mkdtemp(path.join(os.tmpdir(), 'ngx-powgate-e2e-'));
const configPath = path.join(prefix, 'nginx.conf');
const secretPath = path.join(prefix, 'powgate.secret');
const certificatePath = path.join(prefix, 'powgate-test.crt');
const keyPath = path.join(prefix, 'powgate-test.key');
const agent = new https.Agent({
    ALPNProtocols: ['http/1.1'],
    rejectUnauthorized: false
});
let nginx;

try {
    await Promise.all([
        fs.mkdir(path.join(prefix, 'client_temp')),
        fs.mkdir(path.join(prefix, 'proxy_temp')),
        fs.mkdir(path.join(prefix, 'fastcgi_temp')),
        fs.mkdir(path.join(prefix, 'uwsgi_temp')),
        fs.mkdir(path.join(prefix, 'scgi_temp'))
    ]);
    await fs.writeFile(secretPath, '00'.repeat(32), { mode: 0o600 });
    await run('openssl', [
        'req', '-x509', '-newkey', 'ec',
        '-pkeyopt', 'ec_paramgen_curve:P-256',
        '-sha256', '-nodes', '-days', '1',
        '-subj', '/CN=localhost',
        '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
        '-keyout', keyPath,
        '-out', certificatePath
    ]);
    await fs.chmod(keyPath, 0o600);

    const config = `load_module ${modulePath};
worker_processes 1;
error_log /dev/stderr notice;
pid ${path.join(prefix, 'nginx.pid')};
events { worker_connections 64; }
http {
    access_log off;
    pow_secret_file ${secretPath};
    client_body_temp_path ${path.join(prefix, 'client_temp')};
    proxy_temp_path ${path.join(prefix, 'proxy_temp')};
    fastcgi_temp_path ${path.join(prefix, 'fastcgi_temp')};
    uwsgi_temp_path ${path.join(prefix, 'uwsgi_temp')};
    scgi_temp_path ${path.join(prefix, 'scgi_temp')};
    server {
        listen 127.0.0.1:${frontendPort} ssl;
        http2 on;
        ssl_certificate ${certificatePath};
        ssl_certificate_key ${keyPath};
        location / {
            pow on;
            proxy_pass http://127.0.0.1:${backendPort};
        }
    }
}
`;

    await fs.writeFile(configPath, config);

    nginx = spawn(nginxBinary, [
        '-p', prefix,
        '-c', configPath,
        '-e', '/dev/stderr',
        '-g', 'daemon off;'
    ], { stdio: 'inherit' });

    const response = await waitForFrontend(frontendPort, agent);
    const body = await responseBody(response);
    const script = body.match(/<script>([\s\S]*?)<\/script>/)?.[1];

    assert.equal(response.statusCode, 503);
    assert.equal(response.httpVersion, '1.1');
    assert.equal(response.socket.alpnProtocol, 'http/1.1');
    assert.equal(response.headers['content-type'],
        'text/html; charset=utf-8');
    assert.match(response.headers['powgate-challenge'],
        /^v=1; d=20; b=(?:0|[1-9][0-9]*); n=[A-Za-z0-9_-]{43}$/);
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.equal(response.headers['x-robots-tag'], 'noindex');
    assert.equal(typeof script, 'string');
    assert.equal(script, '/* PowGate placeholder script v1 */\nvoid 0;\n');

    const digest = createHash('sha256').update(script).digest('base64');
    assert.equal(response.headers['content-security-policy'],
        "default-src 'none'; base-uri 'none'; form-action 'none'; "
        + "frame-ancestors 'none'; script-src 'sha256-"
        + `${digest}'; style-src 'unsafe-inline'`);
    assert.equal(Number(response.headers['content-length']),
        Buffer.byteLength(body));
    assert.equal(backendRequests, 0);
} finally {
    agent.destroy();

    if (nginx != null) {
        await stop(nginx);
    }

    await new Promise((resolve, reject) => {
        backend.close((error) => error == null ? resolve() : reject(error));
    });
    await fs.rm(prefix, { force: true, recursive: true });
}
