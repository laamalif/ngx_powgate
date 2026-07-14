# PowGate security and secret lifecycle

Phase 2 implements configuration validation, bounded secret loading, and
reload lifecycle behavior. It does not yet consume secrets to create or
verify challenges, proofs, or authentication cookies; those cryptographic
request paths arrive in later phases.

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

The first secret is current. In the later request-processing phases, it
derives every new challenge nonce and signs every new authentication cookie.
The optional second secret is previous and is used only as a verification
fallback. Both are loaded in Phase 2; cryptographic consumption is implemented
in Phase 4.

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
3. Keep the previous secret for at least the maximum authentication-cookie
   TTL.
4. Atomically replace the file with the current secret alone.
5. Run `nginx -t`, then reload NGINX a second time.

NGINX never promotes line 2 automatically. Each reload reparses the configured
file. If configuration testing or reload fails, the previous configuration
cycle continues serving, so correct atomic replacement does not partially
change the active secret pair.

Phase 2 tests this file and reload lifecycle. Phase 4 tests that artifacts
created before the first reload verify through the previous secret and stop
verifying after the second secret is removed.
