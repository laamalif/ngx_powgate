#include <stddef.h>
#include <stdint.h>

#include "pow_cookie_scan.h"
#include "pow_protocol.h"


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const uint8_t       name[] = POW_AUTH_COOKIE_NAME;
    pow_cookie_scan_result_t   rc;
    pow_cookie_value_t         value;
    const uint8_t             *previous_end;
    size_t                     before, cursor, iterations;

    cursor = 0;
    iterations = 0;
    previous_end = data;

    for ( ;; ) {
        before = cursor;
        value.data = NULL;
        value.len = SIZE_MAX;

        rc = pow_cookie_scan_next(data, size, name, sizeof(name) - 1,
                                  &cursor, &value);

        if (rc == POW_COOKIE_SCAN_DONE) {
            if (cursor != size || value.data != NULL
                || value.len != SIZE_MAX)
            {
                __builtin_trap();
            }

            break;
        }

        if (rc != POW_COOKIE_SCAN_FOUND || cursor <= before
            || value.data < data || value.data > data + size
            || value.len > size || value.data + value.len > data + size
            || value.data < previous_end)
        {
            __builtin_trap();
        }

        previous_end = value.data + value.len;
        iterations++;
        if (iterations > size + 1) {
            __builtin_trap();
        }
    }

    return 0;
}
