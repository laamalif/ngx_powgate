# Phase 4C browser benchmark evidence v1

This directory owns the immutable schema and, after final Phase 4C review,
one manually promoted canonical result from the pinned native x86_64 Chromium
environment. The benchmark implementation generates only ignored development
results until the clean final-source release sequence explicitly promotes one.

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

The exploratory Task 10 result retained JavaScript as primary because the
mechanical threshold was not met. That result is not canonical and is never
promoted. The selected order, final tested source commit, exact reproduction
command, and canonical environment will be recorded here only with the later
evidence-only commit. Historical v1 evidence and this schema are not
rewritten; an incompatible future format requires a new versioned directory.
