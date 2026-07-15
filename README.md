# ngx_powgate

A lightweight proof-of-work abuse gate for NGINX.

ngx_powgate is designed to protect self-hosted services by requiring clients
to complete a small browser-based proof-of-work challenge before reaching the
upstream application. It runs inside NGINX with no external service, database,
or challenge backend.

## v0.1 features

- Native NGINX dynamic module
- Stateless challenge verification
- HMAC-derived challenges with no server-side sessions
- Browser proof-of-work solver
- No external JavaScript, tracking, or third-party dependencies
- IPv4 and IPv6 prefix binding
- Signed authentication cookies and secret rotation
- HTTP/2-compatible protocol
- Fuzz-tested parsers and ASan/UBSan-hardened builds

## Flow

1. A client requests a protected resource.
2. ngx_powgate checks for a valid authentication cookie.
3. If none is present, it returns a lightweight challenge.
4. The browser solves a SHA-256 proof-of-work puzzle.
5. The client receives a signed cookie.
6. Future requests pass directly to the upstream service.

The module is designed to make cheap automated abuse more expensive while
leaving normal visitors invisible after the first successful challenge.

## Implementation status

Phase 4B is implemented. The module validates its complete configuration,
loads bounded current and previous secrets, supports operator-driven secret
rotation, applies IPv4/IPv6 and normalized-path exemptions, and issues
deterministic challenges over HTTP/1.1 and HTTP/2.
Browser navigations receive the exact generated HTML page and versioned CSP;
other requests receive an empty challenge response.

The server now verifies authentication cookies and submitted proofs, applies
current policy across reloads, falls back to one previous secret, issues both
response cookies transactionally, and passes authenticated requests onward.
These paths are tested against an independent Python reference solver.

The generated page contains a self-contained, time-sliced browser solver with
pure-JavaScript SHA-256 and a WebCrypto fallback. Exact production script
bytes are exercised in Node and through a real NGINX HTTPS response. Phase 4C
adds the real-browser CSP, cookie, reload, and authenticated pass-through
matrix; Phase 4B does not claim that browser-engine coverage.

## Requirements

- nginx.org NGINX 1.30.3, or a binary-compatible NGINX 1.30.3 build
- OpenSSL 3.x
- Linux
- HTTPS in production; plain HTTP is only for explicit development use with
  `pow_cookie_secure off`

## Configuration

Phase 4B provides the complete directive surface, inheritance, validation,
secret loading, runtime exemptions, deterministic challenge issuance, and
server-side cookie/proof verification.

Load the module:

```nginx
load_module modules/ngx_http_pow_module.so;
```

Configure the secret at `http` scope and enable PowGate where needed:

```nginx
http {
    pow_secret_file /etc/nginx/powgate.secret;

    server {
        listen 443 ssl;
        http2 on;
        ssl_certificate /etc/nginx/tls/fullchain.pem;
        ssl_certificate_key /etc/nginx/tls/private.key;

        pow on;

        location / {
            proxy_pass http://backend;
        }
    }
}
```

Create a secret:

```sh
(umask 077 && openssl rand -hex 32 > /etc/nginx/powgate.secret)
chmod 600 /etc/nginx/powgate.secret
```

Reload NGINX:

```sh
nginx -t && nginx -s reload
```

Common settings:

```nginx
pow_difficulty 20;
pow_challenge_window 60s;
pow_cookie_ttl 1h;

pow_bind_ipv4 32;
pow_bind_ipv6 56;

pow_exempt_ip 192.168.0.0/16;
pow_exempt_path /health;
```

Difficulty 20 is the default. Values from 20 through 22 are recommended;
measure representative client hardware before choosing another value.

See the [configuration reference](docs/configuration.md) and
[security and secret lifecycle guide](docs/security.md) for the exact
directive, file-policy, inheritance, and rotation contracts.

## v0.1 security model

The completed v0.1 design provides:

- Protection against unauthenticated automated request floods
- Offline cookie-forgery resistance using HMAC-SHA256
- Deterministic secret-derived challenges
- Bounded replay exposure through time buckets and IP-prefix binding

It does not attempt to provide:

- Bot fingerprinting
- User tracking
- CAPTCHA replacement
- DDoS protection after traffic saturates the network link

Use upstream network protection for large-scale volumetric attacks. The wire
format is defined in [docs/protocol.md](docs/protocol.md).
