#!/bin/sh

set -u

cd "$(dirname "$0")/.." || exit 1

coverage_dir=${1:-build/coverage}
fail=0

check_function() {
    report=$1
    function_name=$2

    if ! awk -v target="$function_name" '
        /^function / {
            if (inside) {
                exit
            }
            if ($2 == target) {
                found = 1
                inside = 1
            }
            next
        }

        inside && /^branch / {
            branches++
            if ($4 == "0") {
                missed = 1
            }
        }

        END {
            if (!found || branches == 0 || missed) {
                exit 1
            }
        }
    ' "$report"
    then
        echo "parser coverage: $function_name missed a conditional branch"
        fail=1
    fi
}

run_report() {
    object=$1
    report=$2

    rm -f "$report"
    if ! gcov -b -c -f "$object" >/dev/null; then
        echo "parser coverage: gcov failed for $object"
        exit 1
    fi
}

run_report "$coverage_dir/test_parse-pow_parse.gcno" pow_parse.c.gcov
check_function pow_parse.c.gcov pow_split_dot_fields
check_function pow_parse.c.gcov pow_parse_u64
check_function pow_parse.c.gcov pow_b64url_decode_exact
check_function pow_parse.c.gcov pow_b64url_value
rm -f pow_parse.c.gcov

run_report "$coverage_dir/test_challenge-pow_challenge.gcno" \
    pow_challenge.c.gcov
check_function pow_challenge.c.gcov pow_proof_cookie_parse
rm -f pow_challenge.c.gcov

run_report "$coverage_dir/test_cookie-pow_cookie.gcno" pow_cookie.c.gcov
check_function pow_cookie.c.gcov pow_cookie_parse
rm -f pow_cookie.c.gcov

if [ "$fail" -ne 0 ]; then
    exit 1
fi

echo "parser coverage: all conditional branches executed"
