/*
 * Copyright (C) ngx_powgate authors
 */


#include <stddef.h>
#include <stdint.h>

#include "pow_parse.h"
#include "pow_protocol.h"


static int pow_b64url_value(uint8_t ch);


int
pow_split_dot_fields(const uint8_t *buf, size_t len, pow_span_t *fields,
    size_t field_count)
{
    size_t  field;
    size_t  i;
    size_t  start;

    if (buf == NULL || fields == NULL || len == 0 || field_count == 0) {
        return 0;
    }

    field = 0;
    start = 0;

    for (i = 0; i <= len; i++) {
        if (i != len && buf[i] != (uint8_t) POW_FIELD_SEPARATOR) {
            continue;
        }

        if (i == start || field >= field_count) {
            return 0;
        }

        fields[field].data = buf + start;
        fields[field].len = i - start;
        field++;
        start = i + 1;
    }

    return field == field_count ? 1 : 0;
}


int
pow_parse_u64(const uint8_t *buf, size_t len, size_t max_digits,
    uint64_t max_value, uint64_t *out)
{
    uint64_t  digit;
    uint64_t  value;
    size_t    i;

    if (buf == NULL || out == NULL || len == 0 || max_digits == 0
        || len > max_digits)
    {
        return 0;
    }

    if (len > 1 && buf[0] == (uint8_t) '0') {
        return 0;
    }

    value = 0;

    for (i = 0; i < len; i++) {
        if (buf[i] < (uint8_t) '0' || buf[i] > (uint8_t) '9') {
            return 0;
        }

        digit = (uint64_t) (buf[i] - (uint8_t) '0');

        if (digit > max_value || value > (max_value - digit) / 10) {
            return 0;
        }

        value = value * 10 + digit;
    }

    *out = value;

    return 1;
}


size_t
pow_b64url_encoded_len(size_t input_len)
{
    size_t  full;
    size_t  remainder;
    size_t  result;

    if (input_len == 0) {
        return 0;
    }

    full = input_len / 3;
    remainder = input_len % 3;

    if (full > SIZE_MAX / 4) {
        return 0;
    }

    result = full * 4;

    if (remainder != 0) {
        if (result > SIZE_MAX - remainder - 1) {
            return 0;
        }

        result += remainder + 1;
    }

    return result;
}


size_t
pow_b64url_encode(const uint8_t *src, size_t src_len, uint8_t *dst,
    size_t dst_cap)
{
    static const uint8_t  alphabet[] = POW_B64URL_ALPHABET;
    size_t                i;
    size_t                o;
    size_t                required;

    if (src == NULL || dst == NULL) {
        return 0;
    }

    required = pow_b64url_encoded_len(src_len);
    if (required == 0 || dst_cap < required) {
        return 0;
    }

    i = 0;
    o = 0;

    while (src_len - i >= 3) {
        dst[o++] = alphabet[src[i] >> 2];
        dst[o++] = alphabet[((src[i] & 0x03U) << 4)
                            | (src[i + 1] >> 4)];
        dst[o++] = alphabet[((src[i + 1] & 0x0fU) << 2)
                            | (src[i + 2] >> 6)];
        dst[o++] = alphabet[src[i + 2] & 0x3fU];
        i += 3;
    }

    if (src_len - i == 1) {
        dst[o++] = alphabet[src[i] >> 2];
        dst[o++] = alphabet[(src[i] & 0x03U) << 4];

    } else if (src_len - i == 2) {
        dst[o++] = alphabet[src[i] >> 2];
        dst[o++] = alphabet[((src[i] & 0x03U) << 4)
                            | (src[i + 1] >> 4)];
        dst[o++] = alphabet[(src[i + 1] & 0x0fU) << 2];
    }

    return o;
}


int
pow_b64url_decode_exact(const uint8_t *src, size_t src_len, uint8_t *dst,
    size_t expected_len)
{
    size_t   i;
    size_t   o;
    size_t   remainder;
    int      value;
    uint8_t  v0;
    uint8_t  v1;
    uint8_t  v2;
    uint8_t  v3;

    if (src == NULL || dst == NULL || src_len == 0 || expected_len == 0
        || pow_b64url_encoded_len(expected_len) != src_len)
    {
        return 0;
    }

    i = 0;
    o = 0;
    remainder = src_len % 4;

    while (src_len - i >= 4) {
        value = pow_b64url_value(src[i]);
        if (value < 0) {
            return 0;
        }
        v0 = (uint8_t) value;

        value = pow_b64url_value(src[i + 1]);
        if (value < 0) {
            return 0;
        }
        v1 = (uint8_t) value;

        value = pow_b64url_value(src[i + 2]);
        if (value < 0) {
            return 0;
        }
        v2 = (uint8_t) value;

        value = pow_b64url_value(src[i + 3]);
        if (value < 0) {
            return 0;
        }
        v3 = (uint8_t) value;

        dst[o++] = (uint8_t) ((v0 << 2) | (v1 >> 4));
        dst[o++] = (uint8_t) ((v1 << 4) | (v2 >> 2));
        dst[o++] = (uint8_t) ((v2 << 6) | v3);
        i += 4;
    }

    if (remainder == 2) {
        value = pow_b64url_value(src[i]);
        if (value < 0) {
            return 0;
        }
        v0 = (uint8_t) value;

        value = pow_b64url_value(src[i + 1]);
        if (value < 0) {
            return 0;
        }
        v1 = (uint8_t) value;

        if ((v1 & 0x0fU) != 0) {
            return 0;
        }

        dst[o++] = (uint8_t) ((v0 << 2) | (v1 >> 4));

    } else if (remainder == 3) {
        value = pow_b64url_value(src[i]);
        if (value < 0) {
            return 0;
        }
        v0 = (uint8_t) value;

        value = pow_b64url_value(src[i + 1]);
        if (value < 0) {
            return 0;
        }
        v1 = (uint8_t) value;

        value = pow_b64url_value(src[i + 2]);
        if (value < 0) {
            return 0;
        }
        v2 = (uint8_t) value;

        if ((v2 & 0x03U) != 0) {
            return 0;
        }

        dst[o++] = (uint8_t) ((v0 << 2) | (v1 >> 4));
        dst[o++] = (uint8_t) ((v1 << 4) | (v2 >> 2));

    }

    return 1;
}


static int
pow_b64url_value(uint8_t ch)
{
    if (ch >= (uint8_t) 'A' && ch <= (uint8_t) 'Z') {
        return (int) (ch - (uint8_t) 'A');
    }

    if (ch >= (uint8_t) 'a' && ch <= (uint8_t) 'z') {
        return (int) (ch - (uint8_t) 'a') + 26;
    }

    if (ch >= (uint8_t) '0' && ch <= (uint8_t) '9') {
        return (int) (ch - (uint8_t) '0') + 52;
    }

    if (ch == (uint8_t) '-') {
        return 62;
    }

    if (ch == (uint8_t) '_') {
        return 63;
    }

    return -1;
}
