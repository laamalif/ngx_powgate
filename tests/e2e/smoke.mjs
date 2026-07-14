import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { promises as fs } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';


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


async function waitForFrontend(port) {
    let lastError;

    for (let attempt = 0; attempt < 100; attempt++) {
        try {
            const response = await fetch(`http://127.0.0.1:${port}/`);

            return response;
        } catch (error) {
            lastError = error;
            await new Promise((resolve) => setTimeout(resolve, 50));
        }
    }

    throw lastError;
}


async function stop(child) {
    if (child.exitCode == null) {
        child.kill('SIGTERM');
        await once(child, 'exit');
    }
}


const backend = http.createServer((request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('backend\n');
});
const backendPort = await listen(backend);
const frontendPort = await reservePort();
const prefix = await fs.mkdtemp(path.join(os.tmpdir(), 'ngx-powgate-e2e-'));
const configPath = path.join(prefix, 'nginx.conf');
let nginx;

try {
    await fs.writeFile(configPath, `load_module /work/out/ngx_http_pow_module.so;
worker_processes 1;
error_log stderr notice;
pid ${path.join(prefix, 'nginx.pid')};
events { worker_connections 64; }
http {
    access_log off;
    server {
        listen 127.0.0.1:${frontendPort};
        location / {
            pow on;
            proxy_pass http://127.0.0.1:${backendPort};
        }
    }
}
`);

    nginx = spawn('/usr/sbin/nginx', [
        '-p', prefix,
        '-c', configPath,
        '-g', 'daemon off;'
    ], { stdio: 'inherit' });

    const response = await waitForFrontend(frontendPort);

    assert.equal(response.status, 200);
    assert.equal(await response.text(), 'backend\n');
} finally {
    if (nginx != null) {
        await stop(nginx);
    }

    await new Promise((resolve, reject) => {
        backend.close((error) => error == null ? resolve() : reject(error));
    });
    await fs.rm(prefix, { force: true, recursive: true });
}
