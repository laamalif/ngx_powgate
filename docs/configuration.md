# PowGate configuration

PowGate implements configuration, secret loading, runtime exemptions,
deterministic challenge issuance, server-side cookie/proof verification, and
the self-contained browser solver through Phase 4B.

## Directives

| Directive | Context | Default | Accepted value |
|---|---|---|---|
| `pow on\|off` | `http`, `server`, `location` | `off` | `on` or `off` |
| `pow_difficulty N` | `http`, `server`, `location` | `20` | Integer from 1 through 32 |
| `pow_challenge_window time` | `http`, `server`, `location` | `60s` | Positive NGINX time value resolved to whole seconds |
| `pow_cookie_name token` | `http`, `server`, `location` | `__pow` | 1 through 64 ASCII token bytes; must not begin with `$` or equal reserved `__pow_p` |
| `pow_cookie_ttl time` | `http`, `server`, `location` | `1h` | NGINX time value at least as large as the effective `pow_challenge_window` |
| `pow_cookie_secure on\|off` | `http`, `server`, `location` | `on` | `on` or `off` |
| `pow_secret_file path` | `http` only | none | One regular secret file; may appear only once |
| `pow_bind_ipv4 N` | `http`, `server`, `location` | `32` | Integer from 8 through 32 |
| `pow_bind_ipv6 N` | `http`, `server`, `location` | `56` | Integer from 32 through 128 |
| `pow_exempt_ip CIDR` | `http`, `server`, `location` | none | Repeatable IPv4 or IPv6 CIDR |
| `pow_exempt_path path` | `http`, `server`, `location` | none | Repeatable `/` or absolute path without a trailing slash |
| `pow_log_level level` | `http`, `server`, `location` | `error` | `info`, `notice`, `warn`, or `error` |

Difficulty 20 is the default. Values from 20 through 22 are recommended;
measure the solver experience on representative client hardware before using
another value.

`pow_log_level` sets the severity of bounded client-invalid verification
summaries. A request can produce at most one auth summary and one proof
summary; records contain fixed verdicts plus an occurrence count or value
length, never artifact bytes. Internal/provider failures always use
`NGX_LOG_ERR` and are not affected by this directive. Configuration errors
use NGINX's `emerg` level. A CIDR with nonzero host bits is accepted after
NGINX normalizes it and produces a `warn` message.

## Inheritance

Scalar settings inherit from `http` to `server` to `location`. A child may
override an inherited scalar. Repeating the same scalar at one configuration
level is an error.

`pow_exempt_ip` and `pow_exempt_path` use replacement inheritance:

- A child with no entries inherits the parent's entire list.
- One or more entries at the child level replace the parent's list.
- Repeated entries at the same level append in declaration order.
- Duplicate entries are accepted.

Invalid values are rejected even where the effective `pow` setting is `off`.

## Activation and secrets

Loading the module does not by itself require `pow_secret_file`. A secret is
required if `pow on` remains effective in any fully merged server or location
configuration. Configurations whose effective locations are all `pow off`
remain passive and need no secret. An explicitly configured secret file is
always loaded and validated, even if PowGate is disabled.

`pow_secret_file` is valid only directly within `http {}` and may occur only
once. Relative paths resolve against NGINX's configuration-file prefix (the
same prefix used for other configuration-relative paths); absolute paths stay
absolute.

The file contains one or two 32-byte secrets encoded as hexadecimal. Let
`HEX64` mean exactly 64 ASCII hexadecimal bytes. Digits and uppercase or
lowercase `A` through `F` are accepted and may be mixed. Exactly four byte
layouts are valid:

```text
HEX64
HEX64 LF
HEX64 LF HEX64
HEX64 LF HEX64 LF
```

`LF` is one byte, `0x0A`. CRLF, other whitespace, byte-order marks, blank
lines, non-hexadecimal bytes, and extra bytes are rejected. The first line is
the current secret: it derives challenges, verifies first, and signs every new
authentication cookie. The optional second line is the previous secret and is
verification-only. A proof falls back to it only after an invalid
current-secret check; an internal error never triggers fallback.

The opened target must be a regular file and must have no group or other mode
bits: `(mode & 0077) == 0`. Symlinks are followed and the resulting target is
validated. Ownership and owner permissions are intentionally unrestricted,
so both of these common modes are valid:

```sh
chmod 600 /etc/nginx/powgate.secret
chmod 400 /etc/nginx/powgate.secret
```

See [security.md](security.md) for file-validation and rotation details.

## Cookie settings

`pow_cookie_name` accepts the ASCII letters and digits plus these token
punctuation bytes:

```text
! # $ % & ' * + - . ^ _ ` | ~
```

Whitespace, control and non-ASCII bytes, and token separators are rejected.
The first byte may not be `$`; `$` is allowed later in the name. This setting
renames only the authentication cookie. The proof-cookie name `__pow_p` is
fixed by protocol and has no configuration channel, so the exact
case-sensitive name `__pow_p` is reserved and rejected as an auth-cookie
name. Case variants such as `__POW_P` remain valid when they satisfy the
normal token grammar and do not collide with another reserved protocol name.
Cookie names are not MAC inputs.

`pow_cookie_secure` defaults to `on`. Setting it to `off` is an explicit,
non-default development-only opt-out that omits only the authentication
cookie's `Secure` attribute. PowGate never infers this setting from the
request scheme.

## Verification behavior

Cookie fields are scanned in effective receipt order with exact,
case-sensitive names. PowGate tries at most the first four configured auth
cookie occurrences. If none verifies, a separate scan evaluates only the
first exact `__pow_p` occurrence; an invalid first proof shadows later ones.

Proofs use the request's current difficulty and address-binding prefix. Auth
cookies carry their signed difficulty and prefix and must satisfy the current
configured floors. A reload may therefore invalidate an in-flight proof or a
cookie that no longer satisfies tightened policy; no policy history is kept.

A valid proof creates the configured auth cookie and clears `__pow_p` at
`Path=/`. Both `Set-Cookie` fields are committed together. Any arithmetic,
cryptographic, allocation, or construction failure returns `500`, emits no
PowGate cookie, and never passes the request to protected content.

## Exemptions

PowGate uses this fixed evaluation order after skipping
subrequests and internal redirects and confirming that `pow` is enabled:

1. Check IP exemptions.
2. Check path exemptions.
3. Allow the request immediately when either check matches.
4. Otherwise continue into PowGate processing.

`pow_exempt_ip` accepts IPv4 and IPv6 CIDRs. NGINX normalizes a CIDR with host
bits set and logs its standard warning. Request matching uses the connection
address after RealIP processing.

Configured exempt paths are stored byte-for-byte. `/` matches every path;
another value matches only an exact URI or a URI whose next byte is `/`.
Therefore `/api` matches `/api` and `/api/v1`, but not `/apiv1`.

Path matching is case-sensitive and uses NGINX's `r->uri`: the
normalized, percent-decoded path used by location processing. Query arguments
live in `r->args` and never participate. NGINX resolves dot segments before
the comparison. Compression of repeated slashes depends on the core
`merge_slashes` setting; it is not an unconditional PowGate behavior.

## Challenge responses

PowGate v1 supports client identity binding only for IPv4 and IPv6
connections after RealIP processing. An enabled request on a Unix-domain
listener or any other address family returns `500` before exemptions are
evaluated. PowGate never invents an address or treats an unknown transport as
trusted.

Every non-exempt request without a valid auth cookie or proof receives a
deterministic `PowGate-Challenge` header.
A GET or HEAD request is treated as browser navigation when any received
`Accept` field contains `text/html`, case-insensitively. Navigations receive
an exact HTML `503`; every other method/media-type combination receives an
empty `403`. Request bodies are discarded with NGINX's request-body API before
either response is committed.

The HTML response includes `Cache-Control: no-store`, `X-Robots-Tag: noindex`,
and PowGate's versioned `Content-Security-Policy`. Its single executable
script is the self-contained Phase 4B solver. The build hashes its exact bytes
for the CSP and NGINX inserts only the non-executable JSON parameters. The
assembled response must remain smaller than 15 KiB.

The solver mines in bounded foreground slices, pauses while the document is
hidden, reports probability-based progress, writes the fixed `__pow_p` proof
cookie, verifies the browser made exactly one such cookie visible, and then
reloads. It performs no network requests and uses no storage, workers,
tracking, or external resources. Phase 4C remains responsible for validation
inside a real browser engine.

Before mining, the solver performs candidate-bounded proof-cookie cleanup. It
always clears `Path=/`, clears each safely serializable segment-boundary
candidate from the browser's unmodified `location.pathname`, skips unsafe
complete candidates, and then requires no exact `__pow_p` occurrence to
remain visible. A literal semicolon is unsafe for cookie Path serialization;
a percent-encoded `%3B` remains visible ASCII and is preserved as observed.

PowGate always emits its own CSP. An operator `add_header` policy intersects
with it in browsers. On a 503 response, NGINX adds that operator header only
when the directive uses `always`; PowGate never merges or weakens it.

Deploy the challenge endpoint over HTTPS. Test-only clients disable
certificate verification solely for their ephemeral self-signed fixtures;
the production module has no TLS-verification bypass.

## Phase 4B example

```nginx
load_module modules/ngx_http_pow_module.so;

http {
    pow_secret_file /etc/nginx/powgate.secret;

    pow_difficulty 20;
    pow_challenge_window 60s;
    pow_cookie_ttl 1h;

    server {
        listen 443 ssl;
        http2 on;
        # Replace these placeholders with this server's TLS certificate paths.
        ssl_certificate /etc/nginx/tls/fullchain.pem;
        ssl_certificate_key /etc/nginx/tls/private.key;

        pow on;

        location /health {
            pow off;
        }

        location / {
            proxy_pass http://backend;
        }
    }
}
```

This configuration issues deterministic challenges, serves the bundled
browser solver, verifies submitted proofs and auth cookies, and passes valid
requests to the backend.
