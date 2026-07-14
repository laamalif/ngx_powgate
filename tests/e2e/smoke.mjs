import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { promises as fs } from 'node:fs';
import http from 'node:http';
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
const secretPath = path.join(prefix, 'powgate.secret');
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
        listen 127.0.0.1:${frontendPort};
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
