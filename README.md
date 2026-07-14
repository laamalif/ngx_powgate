# ngx_powgate

PowGate is a native NGINX dynamic module that makes anonymous automation pay
a small SHA-256 proof-of-work cost. Its v0.1 scope is deliberately narrow:
stateless verification with two HMACs and no challenge storage, sessions,
database, cache, Redis, external service, fingerprinting, or reputation data.

The current Phase 0 skeleton provides `pow on|off;`, loads as
`ngx_http_pow_module.so`, and passes requests through. The frozen protocol and
later phases add challenge, proof, and cookie behavior.

## Requirements

- Podman
- The project-managed Debian Trixie golden image
- OpenSSL 3.x (provided by the golden image; OpenSSL 1.1 is unsupported)

All compilation, tests, fuzzing, and integration work runs in the golden
image. Do not install project dependencies or run a project `make` target on
the host.

## Quickstart

Build the image from the committed lock file and Containerfile:

```sh
podman build -t localhost/ngx-powgate-dev:trixie -f Containerfile .
```

Run the Phase 0 checks from the repository root:

```sh
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie make check-policy
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie make module
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie make test-integration
podman run --rm --userns=keep-id -v "$PWD:/work:Z" -w /work \
    localhost/ngx-powgate-dev:trixie make test-e2e
```

## v0.1 limitations

Proof solving requires JavaScript, so clients without JavaScript cannot pass a
challenge. Search engines may not execute the challenge and can therefore be
blocked. A cookieless non-idempotent request, such as a form `POST`, receives
403 rather than transparent completion; v0.1 does not replay requests.

The wire format is defined by [docs/protocol.md](docs/protocol.md). Treat it
as the source of truth for every challenge, cookie, and MAC byte.
