# Phase 4B browser solver design

## Status and scope

Phase 4B replaces the inert challenge-page script with the real browser
proof-of-work solver. A browser can consume the v1 JSON challenge data, search
for a valid counter without freezing the page, write the fixed proof cookie,
and reload. The deterministic solver and private controller are tested from
the exact executable bytes checked into `html/challenge.html`.

This phase includes:

- a synchronous pure-JavaScript SHA-256 implementation;
- an asynchronous WebCrypto digest adapter;
- a stable, frozen two-function solver namespace;
- a deterministic bounded search contract for both backends;
- one production-shaped backend known-answer test;
- foreground time slicing, hidden-page pause/resume, and probabilistic
  progress;
- strict challenge-parameter parsing;
- defensive proof-cookie cleanup, write-back validation, and reload;
- static, nondiagnostic failure UI and manual retry;
- exact-byte, controller, generator, CSP, HTTP/1.1, and HTTP/2 tests.

It excludes:

- runtime backend benchmarking or dynamic performance-based selection;
- Web Workers, Blob workers, WASM, external scripts, or npm dependencies;
- a real browser engine and the full browser-to-authenticated-request loop,
  which remain Phase 4C;
- server-side verification changes, protocol-format changes, or new NGINX
  APIs;
- any server, challenge, session, or client-storage state.

The compatibility floor is evergreen browsers from approximately the last
three years. Phase 4B fixes the pure-JavaScript backend as primary and
WebCrypto as the single fallback. Phase 4C measures both in a real browser
harness and may reverse only those two fixed identifiers.

## Enduring invariants

- `html/challenge.html` is the sole source of the complete page and executable
  script. There is no separate solver source to copy or embed.
- NGINX inserts only the canonical non-executable JSON block. Every other
  served byte comes unchanged from the generated prefix and suffix.
- The executable bytes tested by Node are the bytes hashed by the generator
  and served under the CSP hash.
- Solver primitives never read clocks, the DOM, visibility, cookies, storage,
  or mutable global state.
- The controller owns every browser lifecycle concern. It starts once and
  has exactly one terminal path.
- Search order is sequential and total over JavaScript safe nonnegative
  integers. No call overlaps, skips, wraps, or constructs
  `Number.MAX_SAFE_INTEGER + 1`.
- Mining is scheduled by elapsed foreground time, not a fixed counter batch.
  Bounded kernel calls exist only to make deadline polling possible.
- A hidden page schedules no new work. It resumes from the first untested
  counter without repeating backend selection or completed work.
- The visitor never sees exception text, stack traces, challenge values,
  backend details, counters, attempts, or difficulty internals.
- Automatic reload happens only after a proof-cookie write is synchronously
  read back as one exact matching occurrence.
- The maximum assembled response body is strictly less than 15 KiB.

## Architecture and ownership

The existing response pipeline remains:

```text
html/challenge.html
        |
        v
tools/build_pow_challenge.py
        |
        +-- generated prefix bytes
        +-- generated suffix bytes
        `-- SHA-256 of exact executable script bytes
                    |
                    v
NGINX prefix + canonical JSON + suffix
```

The generated arrays and digest are build outputs only. They are never
committed or hand-edited. The generator retains atomic replacement: invalid
input or output failure cannot replace a previously valid generated header.

The pinned NGINX 1.30.3 source audit confirms that the current module follows
the core response precedent: allocate all buffers before sending headers,
then pass an explicit chain to `ngx_http_output_filter()`. Phase 4B adds no
NGINX API and does not alter response finalization, header composition, or the
three-buffer prefix/JSON/suffix chain.

The inline script has two layers:

1. `globalThis.PowGateSolver`, frozen with exactly `sha256` and `solve`.
2. A private controller for parameter parsing, backend policy, self-test,
   scheduling, visibility, progress, cookies, DOM state, retry, and reload.

The public object has no additional enumerable property, version, backend
selector, configuration object, state object, or page-controller function.
Backend-specific digest implementations share search semantics and one result
contract; they do not pretend to share a hashing implementation.

## Public solver contract

The script installs exactly:

```js
globalThis.PowGateSolver = Object.freeze({ sha256, solve });
```

### `sha256(bytes)`

`sha256()` accepts only a `Uint8Array`. It never mutates the input and returns
a fresh 32-byte `Uint8Array`. It is synchronous, deterministic,
pure-JavaScript, and independent of all browser state.

### `solve(nonce, difficulty, startCounter, maxAttempts, backend)`

`solve()` always has a Promise result type. It validates:

- `nonce` is a `Uint8Array` of exactly 32 bytes;
- `difficulty` is an integer from 1 through 32;
- `startCounter` is a safe integer from 0 through
  `Number.MAX_SAFE_INTEGER`;
- `maxAttempts` is a positive safe integer;
- `backend` is the exact string `"js"` or `"subtle"`.

Invalid arguments, an unavailable backend, or a digest-provider failure reject
the Promise. There are no callbacks, partial results, or backend-specific
return shapes. The controller maps every rejection to its fixed failure
policy and never exposes the rejected value.

The `"js"` backend performs its bounded block synchronously, then returns and
resolves the common Promise. The call may therefore occupy the main thread
before its Promise is returned; the controller keeps blocks short. The
`"subtle"` backend performs exactly one awaited
`crypto.subtle.digest("SHA-256", message)` per candidate. It never batches or
parallelizes candidates with `Promise.all()`.

Both backends:

1. examine candidates sequentially from `startCounter`;
2. encode each candidate as canonical ASCII decimal only at the hashing
   boundary;
3. hash `nonce_raw(32) || counter_ascii`;
4. apply the same leading-zero-bit comparison;
5. stop immediately on success, safe-domain exhaustion, or the
   `maxAttempts` upper bound;
6. retain no state after resolving or rejecting.

The solver never constructs, encodes, hashes, evaluates, or returns a counter
outside the safe-integer domain.

### Frozen result

Every successful Promise resolution is exactly this frozen five-field object:

```js
Object.freeze({
  found,
  exhausted,
  counter,
  nextCounter,
  attempts
});
```

Its states are:

| Outcome | `found` | `exhausted` | `counter` | `nextCounter` | `attempts` |
| --- | --- | --- | --- | --- | --- |
| Valid candidate found | `true` | `false` | Successful safe-integer candidate | `null` | Candidates tested through success |
| Safe domain exhausted | `false` | `true` | `null` | `null` | Candidates tested, including `MAX_SAFE_INTEGER` |
| Attempt bound reached | `false` | `false` | `null` | First untested safe-integer candidate | Exactly `maxAttempts` |

`attempts` is a positive safe integer no greater than `maxAttempts`. The
actual examined range is contiguous, begins at `startCounter`, and contains
no more than `maxAttempts` candidates. A failed test of
`Number.MAX_SAFE_INTEGER` returns exhaustion before any increment. A
resumable result identifies the first untested safe counter and therefore
never overlaps or skips work.

## Backend initialization and known-answer test

The controller tries the fixed primary backend first. Before mining, it runs
one production-shaped known-answer test through `solve()`:

```text
fixed nonce_raw(32)
        + canonical fixed counter ASCII
        -> one SHA-256 operation
        -> leading-zero-bit count
        -> fixed difficulty comparison
        -> expected successful counter
```

This performs exactly one candidate hash, not a proof search. It tests the
actual counter encoding, message construction, digest, leading-zero
calculation, threshold comparison, and result contract.

Initialization/self-test failure means:

- WebCrypto is unavailable when `"subtle"` is selected;
- backend setup or digest invocation rejects or throws;
- the known-answer result rejects, mismatches, or violates its frozen shape.

Only such a failure selects the secondary backend, once, and runs the same
test once. A mining failure after the backend passes self-test is terminal;
the controller does not switch backends mid-search. Slow work, a hidden page,
throttling, or navigation are lifecycle events, not backend failures.

## Parameter parsing

The executable script reads the text content of the sole element with ID
`pow-params`, passes it once to `JSON.parse()`, and treats the result only as
data. It never evaluates or rewrites the parameter block.

The object must have exactly the own keys `v`, `d`, `b`, and `n`:

- `v` is the number `1`;
- `d` is an integer from 1 through 32;
- `b` is a canonical uint64 decimal string;
- `n` is a canonical 43-character unpadded base64url string decoding to
  exactly 32 bytes.

The bucket validator accepts `"0"` or a nonzero digit followed by at most 19
digits. A 20-digit value is compared lexically with
`"18446744073709551615"`; it is never converted to Number or BigInt. Nonce
validation checks the exact alphabet, exact length, canonical unused tail
bits, and decoded length before the value reaches a backend.

Any missing element, duplicate element lookup result, JSON failure, extra or
inherited semantic field, wrong type, noncanonical representation, or range
failure enters the static failure UI.

## Private controller lifecycle

The controller is a single-start state machine:

```text
initializing -> mining <-> paused -> success -> reloading
      `------------------------------------------> failure
```

All event handlers are installed at most once. They become inactive after
entering `success`, `reloading`, or `failure`, so no terminal state can start
another miner, cookie write, retry handler, or reload path.

- `initializing` parses parameters, cleans proof cookies, and selects one
  backend through the KAT policy.
- `mining` owns the next candidate, total attempts, adaptive work estimate,
  slice deadline, and progress.
- `paused` retains all mining and backend state. It performs no reset,
  self-test, progress change, or backend selection.
- `success` stops scheduling, sets progress to one, serializes and verifies
  the proof cookie, and transitions once to `reloading` or `failure`.
- `reloading` is terminal and permits no further controller action.
- `failure` stops scheduling and renders only fixed text plus retry.

The retry action is navigation only: it calls `location.reload()` and never
mutates or recursively restarts controller state.

## Foreground scheduling and progress

Scheduling uses `performance.now()` and a target slice duration of
approximately 10 ms. A slice performs one or more bounded `solve()` calls,
checking the deadline and `document.hidden` between calls. Work blocks start
small and adapt from observed completed attempts and elapsed time so deadline
polling remains frequent across fast desktops, slow mobile devices, and the
per-call overhead of WebCrypto. Block size changes are controller state only;
they never change search order or the kernel contract.

After a completed foreground slice, the controller updates the UI and yields
with a zero-delay macrotask. It does not update progress per hash.

When `document.hidden` becomes true, the controller schedules no new kernel
call. A bounded call already in progress may finish; its result is committed,
then the controller enters `paused`. A single `visibilitychange` handler
resumes from the retained `nextCounter` when the page becomes visible.

Displayed progress estimates the probability that a sequential uniform
search would already have succeeded:

```text
progress = min(0.99, 1 - exp(-attempts / 2^difficulty))
```

The calculation is separate from the hashing loop and happens only after
completed slices. It is monotonic, never displays raw work or protocol
values, remains below completion while mining, and becomes exactly `1` only
after success.

## Page and browser-state contract

The UTF-8 page contains exactly:

- one `<main>` element;
- fixed heading and status text, with status in an `aria-live="polite"`
  region;
- one native `<progress max="1">` element;
- one initially hidden `<button type="button">` retry control;
- one `<noscript>` statement that JavaScript is required;
- the one NGINX-inserted non-executable parameter block;
- the one inline executable script.

The page references no external resource. The script does not call or inspect
fetch, `XMLHttpRequest`, WebSocket, Worker, `importScripts`, dynamic script
creation, local or session storage, analytics, randomness, console methods,
`navigator`, `screen`, user-agent data, or other unrelated browser state. Its
only browser reads are the required DOM nodes, `document.hidden`,
`document.cookie`, `location.protocol`, `location.pathname`,
`performance.now()`, and the selected digest provider.

Failure UI is static and contains no exception-derived text. It replaces the
progress UI with a concise fixed message and exposes the retry button. No
failure path logs to the console.

The existing CSP remains unchanged:

```text
default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; script-src 'sha256-<H>'; style-src 'unsafe-inline'
```

Changing any executable byte, including the namespace names, changes `<H>`;
the generator handles this mechanically. The CSP policy itself remains a
versioned protocol constant and is not weakened for testing or fallback.

## Defensive proof-cookie lifecycle

An occurrence in `document.cookie` is a semicolon-delimited cookie pair whose
name exactly equals `__pow_p` and is immediately followed by `=`. It is not a
substring match. The scanner skips only SP and HTAB before a pair and returns
the remaining value bytes without decoding or trimming.

Before mining, the controller:

1. requires `location.pathname` to begin with `/` and rejects control, SP,
   HTAB, or semicolon bytes unsafe in a Path attribute;
2. derives `/` and every distinct applicable segment-boundary prefix of the
   current pathname;
3. expires `__pow_p` once at each path with
   `Max-Age=0; Path=<candidate>; SameSite=Lax`, adding `Secure` on HTTPS;
4. re-reads `document.cookie` and requires zero exact-name proof cookies.

This removes ordinary root, default-path, and visible path-scoped stale proof
cookies. A hostile Domain cookie or unusual cookie that remains visible is
detected and causes terminal failure rather than a reload loop.

On success the controller sets progress to completion, then serializes the
counter with `String(counter)`, producing the
same canonical ASCII decimal accepted by the protocol: digits only, no
leading zero except `"0"`, and within the safe-integer range. The controller
writes exactly:

```text
__pow_p=1.<canonical-bucket>.<canonical-counter>; Path=/; SameSite=Lax
```

It appends `; Secure` only for `location.protocol === "https:"`. HTTP is
allowed without Secure for the explicit development configuration. Any other
scheme fails. The proof cookie has no Domain, Expires, or Max-Age attribute.

The controller synchronously re-reads the cookie jar and requires exactly one
exact-name occurrence whose value equals the new proof. Only then does it call
`location.reload()`. A blocked write, duplicate, mismatch, or remaining
shadowing cookie enters failure and never reloads automatically.

## Exact-byte and body-size contract

The literal `<!-- POW:PARAMS -->` marker remains the only template insertion
point. The generator continues to reject multiple markers, multiple or
attributed executable scripts, invalid UTF-8, NUL, and empty script bodies.
It hashes only the exact bytes between the literal `<script>` and
`</script>`, including whitespace.

`POW_CHALLENGE_PAGE_MAX_BODY_LEN` is the single named maximum-body constant,
with value `15360`, defined alongside the challenge protocol constants. The
maximum-body invariant is:

```text
sizeof(generated prefix)
  + POW_CHALLENGE_JSON_MAX_LEN
  + sizeof(generated suffix)
  < POW_CHALLENGE_PAGE_MAX_BODY_LEN
```

The module enforces the worst-case invariant at build time using the generated
array sizes. It also checks the actual
`prefix_len + json_len + suffix_len` after runtime insertion decisions are
final and before any response header or body-chain commitment. The semantic
limit is never measured against template or executable-script size alone.

## Testing strategy

All tests run inside `localhost/ngx-powgate-dev:trixie`. Phase 4B adds no npm
package, browser framework, host compilation, or host test path.

### Exact production-script tests

A Node built-in test extracts the sole executable script from
`html/challenge.html` and evaluates those exact bytes with `node:vm`.
`node:vm` is used for deterministic globals and namespace isolation; it is
not treated or described as a security boundary.

Tests prove:

- the extracted executable bytes are exactly those passed to the generator's
  SHA-256 operation and represented by the emitted CSP digest;
- the namespace is frozen and has exactly the two expected enumerable
  functions;
- SHA-256 known answers cover empty input, representative binary input, and
  padding/block boundaries around 55, 56, 63, 64, and 65 bytes;
- `sha256()` does not mutate input and returns fresh digest storage;
- repeated bounded calls find the immutable canonical vector counter;
- success, exhaustion, and attempt-bound results match the exact truth table;
- result objects are frozen and contain exactly five fields;
- invalid arguments and unavailable backends reject;
- JS and WebCrypto agree on message bytes, digest, found counter, and result
  semantics wherever Node supplies WebCrypto;
- the subtle backend remains sequential and never batches candidates.

### Controller tests

The same exact script runs against narrow fake DOM, cookie, clock, timer,
visibility, location, and digest-provider objects. There is no production
test branch. Forbidden APIs such as fetch, `XMLHttpRequest`, Worker, and
`importScripts`, plus unrelated state such as storage, `navigator`, and
`screen`, are absent or throw on access so accidental dependencies fail the
test.

Controller tables cover:

- every strict parameter grammar and range rejection;
- the primary KAT, one fallback, and terminal dual failure;
- time-deadline scheduling and adaptive bounded blocks;
- pause/resume with unchanged backend, counter, attempts, and progress;
- probability progress monotonicity and success-only completion;
- path-prefix cleanup and zero-occurrence postcondition;
- HTTP and HTTPS cookie serialization;
- blocked writes, duplicates, mismatches, and non-HTTP schemes;
- one success reload, one retry navigation, and inert terminal handlers;
- static failure content and zero console output.

### Generator and NGINX integration

Python generator tests retain deterministic output, exact extraction/hash
identity, atomic replacement, generated-file warnings, and invalid-template
tables. Integration tests continue reconstructing the expected body directly
from the checked-in template and canonical JSON block, then assert exact body,
content length, CSP digest, and public headers under forced HTTPS HTTP/1.1 and
HTTP/2. They additionally assert the assembled body remains below 15,360
bytes and no generated or fault artifact enters release output.

The existing Node NGINX smoke test updates its exact-script expectation and
executes the served production script in the deterministic controller
harness. It does not claim to be a browser engine.

### Phase boundary and gate

For Phase 4B, "renders with no console errors" means the exact production
script completes its controller lifecycle in the deterministic Node DOM
harness without console access or output. Phase 4C remains responsible for a
real browser engine, real cookie behavior, CSP execution, backend measurement,
reload, server proof verification, auth-cookie issuance, proof-cookie clearing,
and authenticated backend pass-through.

The Phase 4B gate is:

- exact-script Node unit and controller tables green;
- generator tests green;
- normal and ASan/UBSan unit/integration categories green;
- HTTPS HTTP/1.1 and HTTP/2 exact-byte/CSP tests green;
- `make check` green in the golden Podman image;
- no skipped, TODO, placeholder, or test-only production behavior.
