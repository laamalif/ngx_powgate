#!/bin/sh

# ngx_powgate policy gate — mechanical enforcement of the hard rules.
#
# Runs in `make check` (as `make check-policy`), in CI, and on every source
# edit via the Codex PostToolUse hook. A rule that can fail the build
# lives here; AGENTS.md keeps only judgment rules. Extend this script in the
# same commit that introduces any new banned construct. Never bypass it.
#
# Enforced elsewhere, deliberately not here:
#   - length caps & MAC input construction -> unit tables + tests/vectors/v1.json
#   - NGX_DECLINED semantics & subrequest bail -> request-path matrix (Phase 5)
#   - "never log cookie/nonce/secret"         -> log grep-test (Phase 5)
#   - scope (no state, no deps)               -> humans

set -u

cd "$(dirname "$0")/.." || exit 1

if [ ! -d src ]; then
    echo "check-policy: src/ not present yet; nothing to check"
    exit 0
fi

all_files=$(find src -name '*.c' -o -name '*.h')

if [ -z "$all_files" ]; then
    echo "check-policy: no C sources yet; nothing to check"
    exit 0
fi

pure_files=$(printf '%s\n' "$all_files" \
    | grep -E '/(pow_crypto|pow_parse|pow_cookie|pow_cookie_scan|pow_challenge)\.[ch]$')

pure_headers=$(printf '%s\n' "$pure_files" | grep -E '\.h$')

nonct_files=$(printf '%s\n' "$all_files" | grep -v '/pow_crypto\.c$')

fail=0

violation() {
    echo "POLICY VIOLATION [$1]"
    echo "$2"
    echo
    fail=1
}

# 1. banned libc string/format functions on request data (hard rules 1+2);
#    the ngx_-prefixed wrappers are the sanctioned forms and do not match
#    because the preceding character class excludes '_'
hits=$(grep -En \
    '(^|[^A-Za-z0-9_])(strcpy|strcat|gets|sprintf|sscanf|strlen|strtol|strcmp|atoi)[[:space:]]*\(' \
    $all_files)
[ -n "$hits" ] && violation "banned libc function; use the ngx_* form" "$hits"

# 2. bare memcmp outside pow_crypto.c (hard rule 2); the constant-time
#    wrapper pow_ct_eq lives in pow_crypto.c and wraps CRYPTO_memcmp
if [ -n "$nonct_files" ]; then
    hits=$(grep -En '(^|[^A-Za-z0-9_])memcmp[[:space:]]*\(' $nonct_files)
    [ -n "$hits" ] && violation "memcmp outside pow_crypto.c; use pow_ct_eq" "$hits"
fi

# 3. heap allocation (hard rule 3); r->pool / cf->pool only
hits=$(grep -En '(^|[^A-Za-z0-9_])(malloc|calloc|realloc|free)[[:space:]]*\(' \
    $all_files)
[ -n "$hits" ] && violation "heap allocation; use ngx_pnalloc/ngx_pcalloc" "$hits"

# 4. nginx headers in the pure-core file families (hard rule 4); the
#    pure core is NGINX-free by contract, C99 stdint/stddef types only
if [ -n "$pure_files" ]; then
    hits=$(grep -En '#[[:space:]]*include[[:space:]]*[<"]ngx' $pure_files)
    [ -n "$hits" ] && violation "nginx header in pure core" "$hits"
fi

if [ -n "$pure_headers" ]; then
    hits=$(grep -En '#[[:space:]]*include' $pure_headers \
        | grep -Ev '<(stddef|stdint)\.h>|"pow_[a-z_]+\.h"')
    [ -n "$hits" ] \
        && violation "non-C99 or external include in pure-core header" "$hits"
fi

# 5. RNG (hard rule 7); production code needs no randomness. Ephemeral TLS
#    certificate generation under tests/ is the sole test-only exception;
#    this src/-only scan remains unchanged if that fixture changes.
hits=$(grep -En \
    '(^|[^A-Za-z0-9_])(rand|random|srand|srandom|drand48|RAND_bytes)[[:space:]]*\(' \
    $all_files)
[ -n "$hits" ] && violation "RNG call; the design needs no randomness" "$hits"

if [ "$fail" -ne 0 ]; then
    exit 1
fi

echo "check-policy: OK"
exit 0
