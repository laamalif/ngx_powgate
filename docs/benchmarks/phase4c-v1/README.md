# Phase 4C browser benchmark evidence v1

This directory owns the immutable schema and, after final Phase 4C review,
one manually promoted canonical result from the pinned native x86_64 Chromium
environment. Task 9 adds validation and promotion tooling only; it does not
generate or commit benchmark evidence.

Generated development results belong at:

```text
build/benchmark-browser-result.json
```

That file remains ignored. `make benchmark-browser` will create it only after
Task 10 implements the browser measurement. It never updates this directory.

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

The selected order, tested source commit, exact reproduction command, and
canonical environment will be recorded here only when the final evidence-only
commit is promoted. Historical v1 evidence and this schema are not rewritten;
an incompatible future format requires a new versioned directory.
