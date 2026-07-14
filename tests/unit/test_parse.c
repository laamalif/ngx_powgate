#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "pow_parse.h"
#include "test.h"


static int
bytes_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    size_t  i;

    for (i = 0; i < len; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }

    return 1;
}


static int
test_split(void)
{
    static const uint8_t  valid[] = "1.a.b";
    static const uint8_t *invalid[] = {
        (const uint8_t *) "",
        (const uint8_t *) ".a.b",
        (const uint8_t *) "1..b",
        (const uint8_t *) "1.a.",
        (const uint8_t *) "1.a",
        (const uint8_t *) "1.a.b.c"
    };
    static const size_t  invalid_len[] = { 0, 4, 4, 4, 3, 7 };
    pow_span_t            fields[3];
    size_t                i;

    TEST_ASSERT(pow_split_dot_fields(valid, sizeof(valid) - 1, fields,
                                     3) == 1);
    TEST_ASSERT(fields[0].len == 1 && fields[0].data[0] == '1');
    TEST_ASSERT(fields[1].len == 1 && fields[1].data[0] == 'a');
    TEST_ASSERT(fields[2].len == 1 && fields[2].data[0] == 'b');

    for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        TEST_ASSERT(pow_split_dot_fields(invalid[i], invalid_len[i], fields,
                                         3) == 0);
    }

    TEST_ASSERT(pow_split_dot_fields(NULL, 1, fields, 3) == 0);
    TEST_ASSERT(pow_split_dot_fields(valid, sizeof(valid) - 1, NULL, 3) == 0);
    TEST_ASSERT(pow_split_dot_fields(valid, sizeof(valid) - 1, fields, 0) == 0);

    return 0;
}


static int
test_decimal(void)
{
    static const struct {
        const uint8_t  *text;
        size_t          len;
        uint64_t        value;
    } valid[] = {
        { (const uint8_t *) "0", 1, UINT64_C(0) },
        { (const uint8_t *) "1", 1, UINT64_C(1) },
        { (const uint8_t *) "9", 1, UINT64_C(9) },
        { (const uint8_t *) "10", 2, UINT64_C(10) },
        { (const uint8_t *) "18446744073709551615", 20, UINT64_MAX }
    };
    static const struct {
        const uint8_t  *text;
        size_t          len;
        size_t          max_digits;
        uint64_t        max_value;
    } invalid[] = {
        { (const uint8_t *) "", 0, 20, UINT64_MAX },
        { (const uint8_t *) "00", 2, 20, UINT64_MAX },
        { (const uint8_t *) "01", 2, 20, UINT64_MAX },
        { (const uint8_t *) "+1", 2, 20, UINT64_MAX },
        { (const uint8_t *) "-1", 2, 20, UINT64_MAX },
        { (const uint8_t *) " 1", 2, 20, UINT64_MAX },
        { (const uint8_t *) "1 ", 2, 20, UINT64_MAX },
        { (const uint8_t *) "1a", 2, 20, UINT64_MAX },
        { (const uint8_t *) "18446744073709551616", 20, 20, UINT64_MAX },
        { (const uint8_t *) "100", 3, 2, UINT64_MAX },
        { (const uint8_t *) "11", 2, 2, UINT64_C(10) }
    };
    uint64_t  value;
    size_t    i;

    for (i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
        value = UINT64_C(99);
        TEST_ASSERT(pow_parse_u64(valid[i].text, valid[i].len, 20,
                                  UINT64_MAX, &value) == 1);
        TEST_ASSERT(value == valid[i].value);
    }

    for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        TEST_ASSERT(pow_parse_u64(invalid[i].text, invalid[i].len,
                                  invalid[i].max_digits,
                                  invalid[i].max_value, &value) == 0);
    }

    TEST_ASSERT(pow_parse_u64(NULL, 1, 20, UINT64_MAX, &value) == 0);
    TEST_ASSERT(pow_parse_u64((const uint8_t *) "1", 1, 20,
                              UINT64_MAX, NULL) == 0);
    TEST_ASSERT(pow_parse_u64((const uint8_t *) "1", 1, 0,
                              UINT64_MAX, &value) == 0);

    return 0;
}


static int
test_base64_known(void)
{
    static const struct {
        uint8_t        input[3];
        size_t         input_len;
        const uint8_t *encoded;
        size_t         encoded_len;
    } cases[] = {
        { { 0xff, 0x00, 0x00 }, 1, (const uint8_t *) "_w", 2 },
        { { 0xff, 0xee, 0x00 }, 2, (const uint8_t *) "_-4", 3 },
        { { 0xff, 0xee, 0xdd }, 3, (const uint8_t *) "_-7d", 4 }
    };
    uint8_t  decoded[3];
    uint8_t  encoded[4];
    size_t   i, len;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        TEST_ASSERT(pow_b64url_encoded_len(cases[i].input_len)
                    == cases[i].encoded_len);
        len = pow_b64url_encode(cases[i].input, cases[i].input_len,
                                encoded, sizeof(encoded));
        TEST_ASSERT(len == cases[i].encoded_len);
        TEST_ASSERT(bytes_equal(encoded, cases[i].encoded, len) == 1);
        TEST_ASSERT(pow_b64url_decode_exact(encoded, len, decoded,
                                            cases[i].input_len) == 1);
        TEST_ASSERT(bytes_equal(decoded, cases[i].input,
                                cases[i].input_len) == 1);
    }

    TEST_ASSERT(pow_b64url_encoded_len(0) == 0);
    TEST_ASSERT(pow_b64url_encoded_len(SIZE_MAX) == 0);
    TEST_ASSERT(pow_b64url_encode(cases[0].input, 1, encoded, 1) == 0);

    return 0;
}


static int
test_base64_round_trip(void)
{
    static const size_t  lengths[] = { 1, 2, 3, 10, 16, 32, 256 };
    uint8_t              decoded[256];
    uint8_t              encoded[342];
    uint8_t              input[256];
    size_t               i, j, len;

    for (i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t) i;
    }

    for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        if (lengths[i] != sizeof(input)) {
            for (j = 0; j < lengths[i]; j++) {
                input[j] = 0;
            }
        }

        len = pow_b64url_encode(input, lengths[i], encoded, sizeof(encoded));
        TEST_ASSERT(len == pow_b64url_encoded_len(lengths[i]));
        TEST_ASSERT(pow_b64url_decode_exact(encoded, len, decoded,
                                            lengths[i]) == 1);
        TEST_ASSERT(bytes_equal(input, decoded, lengths[i]) == 1);

        for (j = 0; j < sizeof(input); j++) {
            input[j] = (uint8_t) j;
        }
    }

    return 0;
}


static int
test_base64_reject(void)
{
    static const struct {
        const uint8_t  *text;
        size_t          len;
        size_t          decoded_len;
    } cases[] = {
        { (const uint8_t *) "=", 1, 1 },
        { (const uint8_t *) "AA=", 3, 1 },
        { (const uint8_t *) "AA+", 3, 2 },
        { (const uint8_t *) "AA/", 3, 2 },
        { (const uint8_t *) "A", 1, 1 },
        { (const uint8_t *) "AA", 2, 2 },
        { (const uint8_t *) "AB", 2, 1 },
        { (const uint8_t *) "AAB", 3, 2 }
    };
    uint8_t  decoded[4];
    size_t   i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        TEST_ASSERT(pow_b64url_decode_exact(cases[i].text, cases[i].len,
                                            decoded,
                                            cases[i].decoded_len) == 0);
    }

    TEST_ASSERT(pow_b64url_decode_exact(NULL, 2, decoded, 1) == 0);
    TEST_ASSERT(pow_b64url_decode_exact((const uint8_t *) "AA", 2,
                                        NULL, 1) == 0);

    return 0;
}


int
main(void)
{
    TEST_ASSERT(test_split() == 0);
    TEST_ASSERT(test_decimal() == 0);
    TEST_ASSERT(test_base64_known() == 0);
    TEST_ASSERT(test_base64_round_trip() == 0);
    TEST_ASSERT(test_base64_reject() == 0);

    printf("test_parse: PASS\n");

    return 0;
}
