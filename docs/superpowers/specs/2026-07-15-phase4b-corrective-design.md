# Phase 4B browser-kernel and valid-path corrective design

## Purpose

This corrective pass closes two issues found after the initial Phase 4B
merge:

1. valid URL paths containing bytes that are unsafe in a cookie `Path`
   attribute must not make the challenge page fail merely because a derived
   cleanup candidate cannot be serialized; and
2. the pure-JavaScript mining path must be structurally fit for its fixed
   workload instead of allocating general-purpose SHA-256 storage for every
   candidate.

Phase 4B continues to own correctness, architecture, and obvious efficiency
defects. Phase 4C owns real-browser measurement, the recorded backend-order
decision, and tuning justified by that evidence.

This work changes no challenge parameter, proof calculation, cookie wire
format, server verification rule, response header, or CSP policy. Therefore
`docs/protocol.md` remains unchanged.

## Frozen decisions retained

- `html/challenge.html` remains the sole browser implementation. There is no
  second solver source, generated JavaScript source, package dependency, or
  test-only production path.
- `globalThis.PowGateSolver` remains frozen with exactly `sha256` and `solve`.
- Public `sha256(bytes)` retains arbitrary-length `Uint8Array` support and
  returns a fresh 32-byte `Uint8Array`.
- `solve()` retains its always-Promise API and exact frozen five-field result.
- The pure-JavaScript backend is the fixed Phase 4B primary. WebCrypto is the
  single pre-search fallback after primary initialization or KAT failure.
- A failure after mining begins is terminal. Mid-search backend migration is
  prohibited.
- The server continues to evaluate only the first exact `__pow_p`
  occurrence. Browser cleanup must not proceed while a visible stale proof
  cookie can shadow the new root cookie.
- The maximum assembled body remains strictly less than 15,360 bytes. The
  compile-time worst-case check, runtime actual-length check, and served-body
  tests are not weakened.
- The general SHA-256 constants, round logic, and protocol literals remain
  single-source within the production script.

## Phase boundary

### Phase 4B owns

- one pure-JavaScript proof digest path with no explicit typed-array or
  message-object allocation per candidate for the fixed v1 proof message
  shape;
- caller-local workspace for each bounded JS `solve()` invocation;
- exact counter encoding and single-block padding correctness;
- the specialized full-digest runtime KAT;
- safe handling of every browser pathname without serializing unsafe cookie
  attributes;
- structural allocation, exact-byte, unit, integration, fuzz, and sanitizer
  gates.

### Phase 4C owns

- execution in real supported browser engines and representative devices;
- JS-kernel and sequential-SubtleCrypto throughput measurement;
- event-loop responsiveness and device/browser variance measurement;
- a recorded, reproducible backend-order decision;
- only tuning supported by those measurements;
- the complete browser → NGINX → proof cookie → auth cookie → backend loop;
- real proof/cookie shapes added to the existing fuzz corpora.

Phase 4B adds no Node timing threshold. Containerized Node/V8 speed is not a
proxy for visitor browsers.

## Shared SHA-256 compression architecture

The script has one private block-compression primitive, conceptually:

```js
compressBlock(state, block, words)
```

Its inputs are caller-owned typed arrays with exact shapes:

- `state`: eight `Uint32Array` words, initialized by the caller;
- `block`: one 64-byte `Uint8Array` block;
- `words`: one 64-word `Uint32Array` schedule.

`compressBlock()` loads the first 16 big-endian words, expands the schedule,
runs the 64 SHA-256 rounds, and adds the working words into `state`. It
allocates nothing, retains nothing, performs no validation, and is not
exported. Callers own validation, padding, state initialization, and digest
serialization.

The existing round constants remain one private immutable table. No second
constants table or duplicated round loop is permitted.

## General public `sha256()`

The public function keeps its frozen behavior:

1. require a `Uint8Array`;
2. prepare the general padded representation for arbitrary input length;
3. allocate one schedule and one state for the call;
4. initialize the standard SHA-256 IV;
5. call `compressBlock()` for every padded block;
6. serialize all eight words into a fresh 32-byte digest.

General hashing may allocate per public call. It is not the mining hot path.
Existing empty, binary, padding-boundary, multi-block, freshness, and
non-mutation tests remain authoritative.

## Canonical decimal encoder

One private encoder is used by both proof backends. Conceptually:

```js
encodeCounter(counter, digits)
```

`digits` is a caller-owned 16-byte `Uint8Array`. The encoder requires a safe
nonnegative integer already admitted by `solve()` validation, writes canonical
ASCII decimal from right to left, and returns the start offset and digit count
without allocating a string or another array.

The representation is exact:

- zero is one byte, `0x30`;
- positive values have no leading zero;
- the maximum value is `9007199254740991`;
- no NUL or unused scratch byte is part of the prepared proof message.

The JS proof block and the SubtleCrypto message copy the same returned digit
span. No second decimal conversion path exists.

## Specialized single-block proof digest

Every v1 proof message is:

```text
nonce_raw(32) || counter_ascii(1..16)
```

The message is 33 through 48 bytes. With the `0x80` byte and eight-byte bit
length it always occupies exactly one SHA-256 block.

Each bounded `solve(..., "js")` call creates one local workspace providing:

- storage for one 64-byte block;
- storage for one 64-word schedule;
- storage for one eight-word state/digest buffer;
- storage for one 16-byte decimal scratch buffer;
- the existing defensive nonce copy made once at the public `solve()`
  boundary.

The storage may be separate typed arrays or non-overlapping typed-array views
over a larger invocation-local allocation. Its physical layout is not a
public or permanent design contract.

The workspace is lexical to that invocation and is not stored on the page,
controller, namespace, backend, or another closure that outlives the call.

The controller owns the immutable parsed challenge parameters and, for mining
orchestration, only the selected backend, next counter, accumulated attempts,
slice timing, and UI state. It never receives or stores the proof block,
schedule, SHA state, decimal scratch, or digest workspace.

The nonce is copied into block bytes 0 through 31 once. For each candidate:

1. clear only block bytes 32 through 63;
2. encode the candidate into the reusable decimal scratch;
3. copy the returned digit span beginning at block byte 32;
4. write `0x80` immediately after the digits;
5. write `(32 + digit_count) * 8` as the final 64-bit big-endian length (the
   high bytes are zero for this fixed shape);
6. reset all eight state words to the SHA-256 IV;
7. call the shared compression primitive once;
8. test the required leading bits directly from the first resulting state
   word.

For difficulties 1 through 31 the predicate is:

```js
(state[0] >>> (32 - difficulty)) === 0
```

Difficulty 32 is handled separately as `state[0] === 0`; JavaScript's
modulo-32 shift semantics must never turn it into an unconditional result.

There is no `String(counter)`, per-candidate message array, padded array,
schedule, state array, digest array, or result object. The frozen result is
created only once when a bounded `solve()` call terminates.

The SubtleCrypto backend remains sequential and prepares one provider input
view per candidate. It uses the shared decimal encoder and reuses one
invocation-local 48-byte message buffer; it does not allocate a fresh backing
message buffer per candidate. It must await each `subtle.digest()` before
mutating that buffer for the next candidate. The `ArrayBufferView` passed to
the provider has `byteOffset` and `byteLength` covering exactly
`nonce_raw || counter_ascii`, or `32 + digit_count` bytes. Padding and unused
scratch bytes are never included. Creating the exact-length view is permitted;
batching and parallel provider calls are not.

## Specialized runtime KAT

The startup KAT exercises the specialized JS proof digest, not only the
general public hash path:

1. decode the fixed 32-byte nonce;
2. prepare and compress counter `34` through the specialized workspace;
3. serialize the eight resulting state words into one KAT digest buffer;
4. compare all 32 bytes with the fixed expected digest;
5. assert difficulty 8 passes;
6. assert difficulty 10 passes;
7. assert difficulty 11 fails.

The known digest begins `00 28`, so it has exactly ten leading zero bits.
These checks cover byte-aligned and non-byte-aligned predicates, including a
failing threshold.

The runtime does not redundantly compare the specialized digest with public
`sha256()`. Both use the same compression primitive, and Node tests retain
the independent general-hash and protocol-vector checks.

Fallback tests corrupt only specialized-JS initialization in the controlled
VM after evaluating the exact production script and before controller
startup. The implementation plan selects the narrowest deterministic
mechanism; it may substitute a schedule constructor that yields an invalid
schedule shape. The SubtleCrypto backend remains untouched. The dual-failure
case additionally makes SubtleCrypto unavailable. No production fault flag,
counter, directive, alternate KAT path, or modified script byte is introduced.

Backend selection finishes before mining state is committed. A primary
initialization or KAT failure advances no counter, records no attempt, mutates
no controller mining state, and retains no partial workspace. The validated
fallback begins at the original start counter.

## Structural allocation contract

Phase 4B does not claim that the JS runtime performs no allocation of any
kind. It proves the narrower property relevant to the audited defect:

> Explicit `Uint8Array` and `Uint32Array` allocations made by the production
> JavaScript remain constant per bounded JS `solve()` call, independent of
> the number of candidates examined.

Node evaluates the exact production script with constructor subclasses that
count allocations while preserving:

- `instanceof` behavior;
- typed-array prototypes and constructor overloads;
- `BYTES_PER_ELEMENT`;
- inherited static methods used by the script.

The test records deltas around bounded JS calls with maximum attempts 1, 10,
and 1000. The fixture uses difficulty 32 and a range that Node's built-in
`node:crypto` independently proves has no winner outside the instrumented
production VM. Each result must report the requested number of attempts.

The accepted implementation records a stable, positive per-call allocation
multiset documented by the implementation plan. The multiset must be equal
across the three attempt counts. A later refactor may change that fixed
per-call multiset only when attempt-count independence, invocation isolation,
and the page budget remain proven. The enduring contract is no per-candidate
typed-array allocation and no page-global hashing workspace, not one permanent
storage layout.

This test does not claim to count engine-internal number, Promise, or frozen
result allocations.

## Invocation isolation

Two JS solves with different nonces and starting counters are compared with
independent sequential reference results. `Promise.all()` is retained as a
public-API regression, but the test documentation states that the synchronous
JS kernels do not interleave on one event loop: each bounded kernel completes
before its Promise is returned. Per-call ownership is established by the
workspace allocation contract and the absence of persistent hashing storage,
not by pretending Node executes the kernels concurrently.

The asynchronous SubtleCrypto path may interleave naturally and retains only
invocation-local preparation data.

## Valid-path cleanup contract

Cleanup accepts only `http:` or `https:` and requires
`location.pathname` to be a string beginning with `/`. Unsupported schemes or
a structurally invalid pathname remain terminal.

Candidate derivation is ordered and exact:

1. add `/` first;
2. scan the actual `location.pathname` left to right;
3. at each slash after the first byte, derive the prefix before that slash and
   the slash-terminated prefix through that slash;
4. derive the complete pathname;
5. retain each distinct candidate only when that complete candidate is safe.

A candidate is safe for direct cookie `Path` serialization only when every
UTF-16 code unit is visible ASCII `0x21` through `0x7e` other than semicolon
`0x3b`. This rejects control characters, DEL, whitespace, raw non-ASCII, and
semicolon. Browser-percent-encoded non-ASCII remains ordinary visible ASCII.

Safety is evaluated independently for each derived candidate. The controller
does not truncate at an unsafe byte, normalize slashes, decode percent escapes,
or reject the page merely because one candidate is unsafe.

For example, `/account/orders;view=full` retains:

```text
/
/account
/account/
```

It does not invent `/account/orders` by truncating at the semicolon, and it
does not serialize the unsafe complete pathname.

Repeated slashes are preserved exactly. For `/a//b`, candidates follow the
existing segment-boundary rule and retain `/`, `/a`, `/a/`, `/a//`, and
`/a//b`; PowGate performs no path normalization.

The controller expires `__pow_p` at every retained candidate using the
current HTTP/HTTPS `Secure` rule. It then rescans `document.cookie`. If any
exact-name proof occurrence remains visible, cleanup has genuinely failed and
the controller enters its static failure state without mining.

Thus an unsafe pathname candidate is skipped, while an undeletable Domain or
path-scoped shadow cookie remains fail-visible. This distinction preserves
the server's first-proof-occurrence rule and prevents automatic reload loops.

## Proof write and reload contract

The existing success invariant is unchanged:

1. write the canonical proof cookie at `Path=/`;
2. rescan `document.cookie`;
3. require exactly one exact-name occurrence;
4. require its value to equal the newly constructed proof exactly;
5. only then call `location.reload()`.

The controller does not ignore a parent-Domain duplicate or assume that the
server will find a later valid proof. Auth-cookie iteration does not apply to
`__pow_p`.

Reload is a navigation on the current document and therefore preserves the
browser's path and query. Cleanup reads only `location.pathname`; it never
reads, parses, normalizes, or reconstructs the query.

## Test matrix

### Decimal and proof preparation

The SubtleCrypto adapter captures the complete `ArrayBufferView` supplied to
`digest()` and compares it with `nonce_raw || counter_ascii` for:

- `0`;
- `1`;
- `9`;
- `10`;
- `99`;
- `100`;
- `999999999999999`;
- `1000000000000000`;
- `9007199254740991`.

Every row proves that nonce bytes are unchanged, digits immediately follow
the nonce, and no NUL or unused scratch byte enters the provider input.
Negative, fractional, and unsafe counters remain rejected before encoding.

The safe-integer boundary has two independently prepared rows beginning at
`Number.MAX_SAFE_INTEGER` with one permitted attempt:

- a passing digest returns `found` at that exact counter;
- a failing digest returns `exhausted`.

In both rows the encoder receives `Number.MAX_SAFE_INTEGER` exactly once, and
the solver never constructs or encodes a larger value.

### Hashing and solver behavior

- all existing general SHA-256 known answers and padding boundaries;
- existing canonical protocol digest and counter vectors;
- specialized full-digest KAT with difficulty 8/10/11 checks;
- JS and SubtleCrypto result agreement;
- exact five-field frozen results and safe-domain exhaustion;
- constant typed-array allocation deltas for 1, 10, and 1000 attempts;
- distinct-invocation JS and interleavable SubtleCrypto isolation cases;
- after `solve()` is called, mutating the caller's original nonce does not
  change either backend's result because the invocation-local snapshot is
  authoritative;
- two calls sharing the same caller nonce object produce the same results as
  independent copies and cannot affect one another;
- no page-global or controller-owned hashing workspace.

### Path and cookie behavior

- browser-realistic `/account;view=full` reaches mining when no stale proof
  exists;
- browser-realistic `/account/orders;view=full` clears `/`, `/account`, and
  `/account/` but never serializes a semicolon candidate;
- `/a%3Bb` is serialized exactly as observed in `location.pathname`, while
  the literal-semicolon candidate `/a;b` is skipped;
- Node controller unit tests inject synthetic pathname strings to prove that
  a control, DEL, whitespace, or raw non-ASCII code unit immediately after
  `/` still leaves root cleanup active and never reaches `document.cookie`;
- repeated slashes remain byte-for-byte unnormalized;
- safe path behavior remains unchanged;
- a visible undeletable exact-name proof after cleanup is terminal;
- a blocked, mismatched, zero, or duplicate post-write occurrence is terminal;
- exactly one matching post-write occurrence reloads once;
- pathname and query remain unchanged across the reload action.

Phase 4C real-browser integration repeats semicolon, percent-encoded,
repeated-slash, pathname-preservation, and query-preservation cases. It does
not expect a browser URL parser to expose synthetic raw control characters.

### Delivery and project gates

- generator output remains deterministic and hashes the exact executable
  bytes;
- generated prefix + maximum JSON + suffix remains below 15,360 bytes;
- actual served H1 and H2 bodies remain exact and below the same limit;
- public headers and CSP remain unchanged;
- `make check-policy`, JS tests, generator tests, C unit/coverage tests,
  module/fault builds, HTTPS integration, all three fuzzers, and ASan/UBSan
  remain green in `localhost/ngx-powgate-dev:trixie`;
- no skipped, TODO, placeholder, test-only production behavior, npm package,
  or external browser resource is introduced.

## Page-budget discipline

The current worst-case assembled page has little spare capacity. The
implementation must share compression logic rather than add a second SHA-256
implementation. It may remove redundant private setup, private-name verbosity,
or presentation whitespace while preserving source readability,
accessibility, exact-byte tests, and the canonical page structure.

No minifier, runtime decompressor, generated JavaScript source, external
resource, weakened CSP, or larger body limit is permitted.

## Documentation changes

- amend the original Phase 4B design with a short supersession reference to
  this corrective design;
- update `PLAN.md` to record the allocation-disciplined proof kernel, valid
  pathname behavior, and bounded Phase 4C benchmark handoff;
- refine `docs/security.md` and `docs/configuration.md` to describe safe
  candidate-bounded cleanup and fail-closed handling of every visible
  remaining proof occurrence;
- update test/generator documentation only where commands or ownership
  statements change;
- leave `docs/protocol.md` untouched.

The current operational documents already describe the live Phase 4B solver;
there is no stale inert-placeholder claim to remove.
