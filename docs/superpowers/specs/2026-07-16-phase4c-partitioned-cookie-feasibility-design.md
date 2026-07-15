# Phase 4C Partitioned-Cookie Feasibility Spike

## Status

Commit `5b14254` reached the complete acceptance tuple in pinned native
Chromium. The construction is promoted by
`2026-07-16-phase4c-partitioned-negative-matrix-amendment.md`; this document is
retained as the historical feasibility contract and evidence rationale. The
experimental target remains temporarily available only as a known-good
comparison point during permanent-matrix implementation.

## Purpose

This spike determined whether pinned native x86_64 Chromium could naturally
produce a partitioned proof-cookie state that reaches PowGate's browser
controller fail-closed branch. It was defined as exploratory evidence and did
not itself change the Phase 4C acceptance matrix, production code, protocol,
generated challenge bytes, or release gates. The later reviewed amendment owns
promotion into the permanent matrix.

The public experimental target is exactly:

```text
test-browser-partitioned-feasibility
```

It is not a prerequisite of `check-browser-x86`, `make check`, or another
release target. The canonical host wrapper may invoke it only through the same
native x86_64, rootless, sandboxed Podman boundary used by existing browser
targets.

## Browser-native state

A fixture endpoint returns a real HTTPS response that sets a non-HttpOnly
proof cookie with:

```text
name:       __pow_p
Secure:     true
Partitioned:true
SameSite:   Lax
```

The fixture chooses a browser-valid path that matches the protected
navigation. Chromium, not CDP or the test harness, parses and stores the
`Set-Cookie` response. The spike must not edit a browser profile, cookie
database, production source, generated page, or controller state. It must not
use a CDP cookie command to manufacture a state unavailable to ordinary HTTPS
content.

The protected navigation executes the exact generated production controller
served by NGINX. The initial request must carry the seeded cookie according to
the production-compatible cookie scanner. Before cleanup, the page must see
exactly one matching occurrence through `document.cookie`.

## Observation boundary

The result contains only these fixed verdicts and counts:

```text
partitioned_cookie_stored
initial_document_visible
initial_request_present
post_cleanup_document_visible
post_cleanup_storage_present
solver_calls
navigation_count
backend_count
```

No cookie value, Cookie header, challenge value, nonce, URL query, raw CDP
traffic, profile data, or unrestricted log is retained.

A pre-document observer may wrap `globalThis.PowGateSolver` only to count
`solve()` calls. It preserves the production namespace descriptor, exact
`sha256` and `solve` exports, receiver, arguments, Promise behavior, errors,
and frozen shape. It adds no enumerable production-visible export. Missing,
repeated, or differently shaped namespace assignment invalidates the result.

The spike runs an observer-free control using the same HTTPS seed and page
state. Cookie storage and page-visibility verdicts must match the observed run.
This proves that call counting does not change cookie behavior or scheduling.

## Acceptance rule

The case is eligible for a later Phase 4C design change only when pinned
Chromium naturally produces all of:

```text
initial_document_visible = true
post_cleanup_document_visible = true
solver_calls = 0
navigation_count = 1
backend_count = 0
```

`partitioned_cookie_stored`, `initial_request_present`, and
`post_cleanup_storage_present` must also be true. Storage survival without
post-cleanup `document.cookie` visibility is insufficient because the
production controller decides from the page-visible cookie surface.

The seed navigation is completed before the challenge observation cursor is
created. The historical implementation field named `navigation_count` means
challenge-phase document navigations only; the permanent contract uses the
unambiguous `challenge_phase_document_navigation_count` name.

Likewise, historical `initial_request_present` recorded a production-scanner
count equal to one. The permanent contract exposes that stronger meaning
directly as `initial_request_proof_count = 1`.

The experimental target reports the complete fixed verdict record and exits
zero when the experiment executed correctly, regardless of whether the
acceptance tuple was reached. Environment, fixture, protocol, observer,
cleanup, or incomplete-observation failures exit nonzero. A negative
reachability result is evidence, not a test failure.

## Outcome handling

The tuple was reached by commit `5b14254`. No target changed automatically.
The separately reviewed amendment promotes one H1 and one H2 case into the
normal and sanitized browser matrices.

The rejected-outcome boundary does not apply because the tuple was reached.
The authoritative matrix is the amendment's twenty-case normal/sanitized
boundary.

The final rationale records all three evaluated browser-native constructions:

- a parent-domain cookie may remain in storage while disappearing from
  `document.cookie` after root cleanup;
- pinned Chromium rejects a path-matching literal-semicolon cookie through
  CDP and normalizes a real HTTPS quoted-semicolon `Path` to `/`.
- the host-only root Partitioned cookie from the real HTTPS seed response
  remains stored and page-visible after cleanup and reaches fail-closed before
  mining.

The spike itself never becomes canonical benchmark evidence. It remains
outside `check-browser-x86` until the permanent H1/H2 cases pass under normal
and sanitized NGINX, then is removed in a separate cleanup commit. Neither the
spike nor its promotion changes `docs/protocol.md`.
