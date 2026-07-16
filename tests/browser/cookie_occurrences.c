#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "pow_cookie_scan.h"
#include "pow_protocol.h"


#define COOKIE_FIELD_MAX  8192


static int
hex_value(uint8_t ch, uint8_t *value)
{
    if (ch >= '0' && ch <= '9') {
        *value = (uint8_t) (ch - '0');
        return 1;
    }

    if (ch >= 'a' && ch <= 'f') {
        *value = (uint8_t) (ch - 'a' + 10);
        return 1;
    }

    if (ch >= 'A' && ch <= 'F') {
        *value = (uint8_t) (ch - 'A' + 10);
        return 1;
    }

    return 0;
}


static int
decode_hex(const char *hex, uint8_t *field, size_t *field_len)
{
    uint8_t  high, low;
    size_t   hex_len, i;

    hex_len = 0;

    while (hex[hex_len] != '\0' && hex_len <= COOKIE_FIELD_MAX * 2) {
        hex_len++;
    }

    if (hex_len > COOKIE_FIELD_MAX * 2 || (hex_len & 1) != 0) {
        return 0;
    }

    *field_len = hex_len / 2;

    for (i = 0; i < *field_len; i++) {
        if (hex_value((uint8_t) hex[i * 2], &high) == 0
            || hex_value((uint8_t) hex[i * 2 + 1], &low) == 0)
        {
            return 0;
        }

        field[i] = (uint8_t) ((uint8_t) (high << 4) | low);
    }

    return 1;
}


int
main(int argc, char **argv)
{
    static const uint8_t      proof_name[] = POW_PROOF_COOKIE_NAME;
    uint8_t                   field[COOKIE_FIELD_MAX];
    pow_cookie_scan_result_t  rc;
    pow_cookie_value_t        value;
    size_t                    count, cursor, field_len;

    if (argc != 2 || decode_hex(argv[1], field, &field_len) == 0) {
        fputs("error: invalid cookie field hexadecimal\n", stderr);
        return 2;
    }

    count = 0;
    cursor = 0;

    for ( ;; ) {
        rc = pow_cookie_scan_next(field, field_len,
                                  proof_name, sizeof(proof_name) - 1,
                                  &cursor, &value);

        if (rc == POW_COOKIE_SCAN_DONE) {
            break;
        }

        if (rc != POW_COOKIE_SCAN_FOUND) {
            fputs("error: cookie scanner failure\n", stderr);
            return 3;
        }

        count++;
    }

    if (printf("{\"count\":%zu}\n", count) < 0) {
        return 4;
    }

    return 0;
}
