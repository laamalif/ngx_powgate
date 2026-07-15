# PowGate security and secret lifecycle

Through Phase 4B, PowGate implements configuration validation, bounded secret
loading, deterministic challenges, proof and auth-cookie verification,
transactional cookie issuance, policy reloads, dual-secret rotation, and the
self-contained browser solver.

## Request boundary

Challenge nonces are HMAC-SHA256 outputs derived from the current secret, the
post-RealIP client address prefix, and the current time bucket. They are
intentionally exposed to clients in the challenge header and HTML parameters.
The same inputs in the same bucket produce the same challenge; there is no
per-request randomness, stored session, or challenge database.

Only IPv4 and IPv6 connection addresses are valid identities. Unsupported
address families, including Unix-domain listeners, fail closed with `500`
before exemption evaluation. The diagnostic contains the numeric family and
fixed verdict only. Normal challenge issuance is not logged per request, and
request-path diagnostics never include request bytes, URI, arguments, headers,
cookies, nonce, MAC, or secret material.

PowGate owns a deliberately small public response surface. Bare challenges
contain one `PowGate-Challenge` header and an empty `403` body. Browser
navigations add the exact HTML body, content type, `Cache-Control: no-store`,
`X-Robots-Tag: noindex`, and the versioned CSP. Range and conditional metadata
cannot turn these responses into `206` or `304`, and configured `error_page`
targets do not replace them. Operator CSP headers remain separate policies;
PowGate never combines or weakens them.

NGINX's standard discard API handles request bodies before PowGate commits a
challenge response. This prevents unread fixed-length or chunked bodies from
being mistaken for the next request on a persistent connection. With H1
`Expect: 100-continue`, a client may close and reconnect after receiving the
early final challenge; HTTP/2 cancellation remains stream-scoped.

The challenge page contains one exact, build-hashed executable script and no
external resources. Its private controller strictly parses the inserted
parameters, self-tests a pure-JavaScript SHA-256 backend with one WebCrypto
fallback, mines in bounded foreground slices, pauses while hidden, and writes
the fixed proof cookie before reloading. Failures become a static retry UI;
they do not expose exception details or enter reload loops.

Node tests execute the exact production script and a real NGINX HTTPS smoke
test verifies served-byte and CSP-hash identity. Phase 4C still owns the
real-browser proof of CSP enforcement, native cookie behavior, reload, auth
cookie issuance, and backend pass-through.

## Verification bounds and failure behavior

PowGate scans at most four exact auth-cookie occurrences and independently
checks only the first exact proof-cookie occurrence. Each auth occurrence
uses the current-secret MAC and, only after mismatch, one previous-secret or
dummy-current MAC. A proof performs at most two nonce derivations and two
proof checks. It retains no request, challenge, or configuration history.

Client-invalid artifacts follow the normal challenge path. Provider,
arithmetic, allocation, and invariant failures return `500`; they never
downgrade to a challenge or pass-through. After a valid proof, both response
cookies remain inert until construction and reservation succeed, then their
header hashes are committed together. Fault-injected integration tests prove
that failure at either reservation exposes no cookie and never reaches the
backend.

Verification summaries use the configured severity and contain fixed tokens,
bounded counts, and lengths only. They are written without NGINX request-log
context, so URI, headers, cookies, client IP, and request bodies are absent.
Internal errors use fixed `NGX_LOG_ERR` records and never appear as client
invalidity.

## Secret-file validation

PowGate opens the configured path with read-only and nonblocking flags,
following symlinks. Nonblocking open prevents a path that resolves to a FIFO
from hanging NGINX configuration loading before its type can be inspected.
After opening, PowGate obtains metadata from the file descriptor with NGINX's
`ngx_fd_info()` wrapper around `fstat()`. It does not validate path metadata
before the open, avoiding a path-check-to-open race.

The opened target must be a regular file. Directories, FIFOs, sockets,
devices, broken symlinks, and other non-regular targets are rejected. Symlinks
are allowed because container secret mounts and secret managers commonly use
symlink-based atomic delivery. Validation applies to the opened target, not
the link itself.

Ownership and owner permission bits are unrestricted because the correct
owner depends on how NGINX is deployed: root-parsed configuration, rootless
containers, and privilege-dropped masters differ. Every group and other mode
bit is rejected with `(mode & 0077) == 0`, including write and execute bits as
well as read bits. This gives one simple invariant for the opened inode and
avoids treating unusual modes as safe by accident.

## Bounded transactional loading

Only file sizes corresponding to the four protocol layouts are accepted: 64,
65, 129, or 130 bytes. PowGate reads into a fixed 131-byte stack buffer. It
checks descriptor size, the complete byte grammar, the actual byte count, and
EOF, detecting growth, shrinkage, and extra data during the read.

The loader follows parse → validate → commit:

1. Read into bounded temporary storage.
2. Validate the entire layout and decode into temporary arrays.
3. Close the descriptor successfully.
4. Copy both decoded values and their state flags into the candidate NGINX
   configuration only after every prior step succeeds.

A failure leaves the candidate configuration uncommitted and rejects that
configuration cycle. The descriptor is closed on every path, and raw and
decoded temporary buffers are explicitly erased on success and failure.

PowGate securely erases temporary parsing buffers. After successful loading,
decoded secrets reside in NGINX cycle configuration memory for the lifetime
of that configuration cycle. NGINX does not guarantee zeroization of
configuration pools when a cycle is destroyed or its workers exit.

## Secret roles

The first secret is current. It derives every new challenge nonce, verifies
first, and signs every new authentication cookie. The optional second secret
is previous and is used only as a verification fallback. A current-secret
provider error stops verification; it never falls back as though the artifact
were invalid.

## Rotation

Secret files must be replaced atomically, for example by writing a complete
mode-0600 temporary file in the same directory and renaming it over the
configured path. Do not rewrite the live file in place: a regular-file read is
not a transactional snapshot of a concurrent write.

Use this two-reload procedure:

1. Atomically replace the file with the new current secret on line 1 and the
   old current secret on line 2.
2. Run `nginx -t`, then reload NGINX. New workers use the new pair while old
   workers retain their prior configuration cycle.
3. Use the deployment's process supervision to observe that every worker from
   the old cycle has exited. Do not start the retention clock at reload: a
   draining old worker can still issue artifacts with the old current secret.
4. From the old workers' exit, retain the previous secret for at least the
   larger of:
   - the maximum effective `pow_cookie_ttl` in the old cycle; and
   - twice the maximum effective `pow_challenge_window` in the old cycle.
5. Atomically replace the file with the current secret alone.
6. Run `nginx -t`, then reload NGINX a second time.

The cookie interval covers an authentication cookie issued immediately before
the final old worker exits. The two-window interval covers a challenge issued
in that worker's current bucket: its proof remains acceptable through the next
bucket under the protocol's one-bucket clock-skew rule.

NGINX never promotes line 2 automatically. Each reload reparses the configured
file. If configuration testing or reload fails, the previous configuration
cycle continues serving, so correct atomic replacement does not partially
change the active secret pair.

Integration tests revalidate file permissions on reload, wait for all workers
from the prior generation to retire, prove that pre-rotation artifacts verify
through the previous secret, and prove that they fail after it is removed.
