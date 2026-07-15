#include <stddef.h>
#include <stdint.h>

#include "pow_cookie_scan.h"


typedef enum {
    POW_COOKIE_SEGMENT_LEADING,
    POW_COOKIE_SEGMENT_NAME,
    POW_COOKIE_SEGMENT_EQUALS,
    POW_COOKIE_SEGMENT_VALUE,
    POW_COOKIE_SEGMENT_SKIP
} pow_cookie_segment_state_t;


pow_cookie_scan_result_t
pow_cookie_scan_next(const uint8_t *field, size_t field_len,
    const uint8_t *name, size_t name_len, size_t *cursor,
    pow_cookie_value_t *out)
{
    int                         ended_by_delimiter;
    uint8_t                     ch;
    pow_cookie_segment_state_t  state;
    size_t                      matched, pos, segment_end;
    size_t                      value_start;

    if (field == NULL || name == NULL || name_len == 0 || cursor == NULL
        || out == NULL || *cursor > field_len)
    {
        return POW_COOKIE_SCAN_ERROR;
    }

    pos = *cursor;

    while (pos < field_len) {
        ended_by_delimiter = 0;
        state = POW_COOKIE_SEGMENT_LEADING;
        matched = 0;
        value_start = 0;

        while (pos < field_len) {
            ch = field[pos++];

            if (ch == ';') {
                ended_by_delimiter = 1;
                break;
            }

            if (state == POW_COOKIE_SEGMENT_LEADING) {
                if (ch == ' ' || ch == '\t') {
                    continue;
                }

                state = POW_COOKIE_SEGMENT_NAME;
            }

            if (state == POW_COOKIE_SEGMENT_NAME) {
                if (ch != name[matched]) {
                    state = POW_COOKIE_SEGMENT_SKIP;
                    continue;
                }

                matched++;
                if (matched == name_len) {
                    state = POW_COOKIE_SEGMENT_EQUALS;
                }

                continue;
            }

            if (state == POW_COOKIE_SEGMENT_EQUALS) {
                if (ch == '=') {
                    state = POW_COOKIE_SEGMENT_VALUE;
                    value_start = pos;
                } else {
                    state = POW_COOKIE_SEGMENT_SKIP;
                }
            }
        }

        if (state == POW_COOKIE_SEGMENT_VALUE) {
            segment_end = pos;
            if (ended_by_delimiter != 0) {
                segment_end--;
            }

            out->data = field + value_start;
            out->len = segment_end - value_start;
            *cursor = pos;

            return POW_COOKIE_SCAN_FOUND;
        }
    }

    *cursor = field_len;

    return POW_COOKIE_SCAN_DONE;
}
