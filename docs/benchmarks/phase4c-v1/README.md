# Phase 4C browser benchmark evidence v1

This directory owns the immutable schema and one manually promoted canonical
result from the pinned native x86_64 Chromium environment. The benchmark
implementation generates only ignored development results; it never replaces
the reviewed result in this directory.

Generated development results belong at:

```text
build/benchmark-browser-result.json
```

That file remains ignored. `make benchmark-browser` creates or replaces it,
validates its schema and relational invariants, and never updates this
directory.

Canonical evidence is promoted explicitly with:

```sh
node tools/promote-phase4c-evidence.mjs \
  build/benchmark-browser-result.json
```

Promotion requires schema-valid canonical bytes, a clean worktree, exact
tested-source and golden-image identities, matching production-script,
generator, and benchmark-tool hashes, and a destination derived from the
locked architecture and Chromium Debian version. Existing evidence is never
overwritten.

The mechanical decision remains:

- JavaScript is the default primary backend.
- SubtleCrypto becomes primary only when every correctness and responsiveness
  prerequisite passes, its median throughput is at least 1.25 times the
  JavaScript median, and it wins at least five of seven matched pairs.
- Throughput is evidence, not an acceptance threshold.

The exploratory Task 10 result was not promoted. The canonical result is:

- Tested source: `9b968c8e133fba07cce03425064187ff672c8561`
- Result:
  [x86_64-debian-chromium-150.0.7871.100-1%7Edeb13u1.json](./x86_64-debian-chromium-150.0.7871.100-1%7Edeb13u1.json)
- Environment: Debian snapshot `20260713T000000Z`, native `x86_64`, Chromium
  `150.0.7871.100-1~deb13u1`, and the locked golden-image identity recorded in
  the result.
- Selected primary backend: `js`
- Selected secondary backend: `subtle`

Both backends passed correctness and per-repetition responsiveness. JavaScript
won all seven matched pairs. Its median throughput was approximately
`566684.46` candidates/second versus `174007.67` for SubtleCrypto, a ratio of
approximately `0.3071`. The fixed `1.25` ratio and five-of-seven matched-pair
requirements were therefore not met, so the existing JavaScript-first order
remains unchanged.

Reproduce the canonical measurement on the designated worker from the tested
source commit with:

```sh
tools/run-browser-x86.sh benchmark-browser
```

Then validate and promote the ignored result explicitly as documented above.
Historical v1 evidence and this schema are never rewritten; an incompatible
future format requires a new versioned directory.
