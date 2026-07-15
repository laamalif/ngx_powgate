# Phase 4C Partitioned Negative-Matrix Amendment

## Authority and evidence

This amendment supersedes Section 7 and every negative-matrix reference in
`2026-07-15-phase4c-browser-e2e-design.md`. The original design is updated in
the same commit so it remains the single consolidated Phase 4C contract.

Commit `5b14254` demonstrated the construction in pinned native x86_64
Chromium through both an observer-free control and an observed trial. The
cookie remained stored and page-visible after the untouched production
cleanup, the controller entered its static failure state, `solve()` was never
called, no reload occurred, and the backend was never reached. Policy passed
and `docs/protocol.md` remained unchanged.

This is browser verification of existing v1 fail-closed behavior. It changes
no wire format, server verification rule, challenge byte, cookie format, or
production controller behavior.

## Exact browser-native construction

The permanent negative case uses:

```text
seed URL:       https://gate.powgate.test/__powgate_partitioned_seed
challenge URL:  https://gate.powgate.test/partitioned-feasibility
top-level site: https://powgate.test
partition key:  https://powgate.test
Set-Cookie:     __pow_p=1.0.0; Path=/; Secure; SameSite=Lax; Partitioned
```

The seed and challenge are top-level navigations that preserve this exact
partition context. The cookie is host-only to `gate.powgate.test` because it
has no Domain attribute. It has no HttpOnly, Expires, or Max-Age attribute.
Its path is exactly `/`.

The browser creates the cookie only by processing the real HTTPS seed
response. CDP may inspect storage after creation but never creates, overwrites,
repairs, or deletes the cookie. The literal `1.0.0` is an intentionally invalid
fixture value used only to exercise residual-cookie detection. The server must
never accept it as proof, and no retained diagnostic stores the raw value.

`/__powgate_partitioned_seed` is fixture-only. It is not protected by PowGate,
does not reach the protected backend, emits exactly the intended Set-Cookie and
no unrelated PowGate cookie, and returns fixed non-executable content with no
redirect or external resource. The harness completes and verifies the seed
response and stored cookie, then advances every navigation, request, cookie,
and event observation cursor before the challenge phase. Seed activity is
excluded from challenge-phase navigation and backend counts.

Pinned Chromium storage metadata must prove:

```text
partitionKey.sourceOrigin = https://powgate.test
partitionKey.hasCrossSiteAncestor = false
domain = gate.powgate.test
path = /
secure = true
httpOnly = false
sameSite = Lax
session = true
expires = -1
```

The absent Domain attribute, applicability to the challenge origin, and
non-applicability to `https://powgate.test/` through the browser cookie API
jointly prove host-only scope. An opaque partition key or a representation that
does not expose the structured source origin fails this pinned-environment
contract. No assertion is weakened to accept an ambiguous normalized value.

The checked-in immutable cookie descriptor owns the exact expected structured
partition-key representation demonstrated by `5b14254`, including origin
serialization. The spike, focused equivalence contract, and permanent matrix
import that same constant. No independently reconstructed, coerced, or loosely
normalized representation is accepted.

## Mandatory state and terminal behavior

Before production cleanup, each case proves:

```text
partitioned_cookie_stored = true
initial_document_visible = true
initial_request_proof_count = 1
```

`initial_request_proof_count` is computed from the server-received Cookie
representation using the NGINX-free production scanner. It proves both
presence and absence of an unexpected duplicate; browser storage metadata or
a simplified string split is not a substitute.

After the cleanup attempt, each case proves:

```text
post_cleanup_document_visible = true
post_cleanup_storage_present = true
```

Post-cleanup page visibility is decisive. Storage survival alone does not
exercise the controller's residual-cookie branch.

The terminal state requires:

```text
namespace_assignments = 1
solver_calls = 0
challenge_phase_document_navigation_count = 1
backend_count = 0
original_partitioned_proof_count = 1
new_partitioned_proof_count = 0
unpartitioned_proof_count = 0
auth_cookie_count = 0
failure_ui_visible = true
retry_control_visible = true
```

The original partitioned cookie is checked transiently for exact equality with
the fixture value but the value is never retained. Cookie inspection covers
all exact-name proof and configured auth cookies applicable to the challenge
origin and current partition context. It proves that no second partitioned,
unpartitioned host-only, or differently scoped exact-name proof cookie exists.

During the fixed fail-closed quiet window, the URL remains unchanged and no
second challenge-phase document request, automatic retry, solver call,
proof/auth cookie mutation, backend request, console event, page error,
unhandled rejection, CSP violation, crash, or unexpected network event occurs.

## Observer boundary

The feasibility spike and permanent E2E case share exactly one narrow observer
implementation. It records namespace assignment count and solver-call count
while preserving:

- the production property descriptor;
- the exact `sha256` and `solve` export set;
- the frozen namespace;
- receiver and argument forwarding;
- returned Promise identity and behavior;
- thrown errors and rejected Promises.

It adds no enumerable production-visible export and performs no cookie,
navigation, scheduling, or network mutation. Missing, repeated, or malformed
namespace assignment fails the case before counts are interpreted.

A focused browser equivalence contract compares observer-free and observed
runs. Both the spike and permanent E2E import the observer and immutable cookie
setup descriptor from one checked-in module; that module identity is the
equivalence source identity. The focused equivalence contract is a mandatory
test, so changing either shared export necessarily reruns it before the matrix
can pass. The mandatory H1/H2 matrix runs the observed negative case and need
not duplicate the observer-free control on every gate.

The Make dependency is explicit:

```text
test-browser-e2e
  -> test-browser-partitioned-observer-equivalence
  -> permanent browser matrix
```

The permanent matrix cannot pass after a shared observer or cookie-descriptor
change without executing the focused control comparison.

## Mandatory matrix and sanitizer ownership

The permanent negative matrix is:

```text
HTTP/2   x partitioned proof-cookie fail-closed
HTTP/1.1 x partitioned proof-cookie fail-closed
```

The complete browser matrix is:

```text
normal production build: 8 positive + 2 partitioned fail-closed = 10 cases
ASan+UBSan build:         8 positive + 2 partitioned fail-closed = 10 cases
total:                    20 browser cases
```

Normal and sanitized cases use identical cookie setup, production script,
observer, protocols, URLs, assertions, and quiet-window rules. Only NGINX and
module compiler/linker instrumentation differs. The permanent cases must
reproduce the feasibility tuple under both server builds.

## Evidence-driven rationale

Three browser-native constructions were evaluated:

1. A parent-domain proof cookie remained in browser storage but disappeared
   from `document.cookie` after root cleanup. It did not reach the controller's
   page-visible residual-cookie branch.
2. Pinned Chromium could not create the required visible, path-matching
   literal-semicolon cookie. CDP rejected the path and a real HTTPS quoted Path
   normalized to `/`.
3. The host-only root Partitioned cookie created by the real HTTPS response
   remained stored and page-visible after cleanup and naturally reached the
   fail-closed branch before mining.

The third construction is selected because it is the only demonstrated state
that exercises the intended production boundary without profile editing,
cookie-database mutation, CDP state manufacture, or production hooks.

## Implementation and temporary-target lifecycle

Implementation proceeds in this order:

1. commit this reviewed amendment;
2. add the H1/H2 cases to the normal permanent E2E matrix;
3. run the identical cases under ASan+UBSan;
4. require the permanent matrix to reproduce the spike tuple;
5. remove `test-browser-partitioned-feasibility` in a separate cleanup commit;
6. retain the spike result and rejected constructions as rationale.

The experimental target remains outside `check-browser-x86` while it serves as
a known-good comparison point. It is not canonical benchmark evidence and is
not itself a release gate. Promotion changes neither `docs/protocol.md` nor
the v1 protocol.
