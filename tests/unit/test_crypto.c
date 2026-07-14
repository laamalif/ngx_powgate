#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "pow_crypto.h"
#include "pow_protocol.h"
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
test_sha256(void)
{
    static const uint8_t  empty_expected[POW_DIGEST_LEN] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    static const uint8_t  abc_expected[POW_DIGEST_LEN] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    static const uint8_t  empty[] = { 0 };
    static const uint8_t  abc[] = "abc";
    uint8_t               digest[POW_DIGEST_LEN];

    TEST_ASSERT(pow_sha256(empty, 0, digest) == 1);
    TEST_ASSERT(bytes_equal(digest, empty_expected, sizeof(digest)) == 1);
    TEST_ASSERT(pow_sha256(abc, sizeof(abc) - 1, digest) == 1);
    TEST_ASSERT(bytes_equal(digest, abc_expected, sizeof(digest)) == 1);
    TEST_ASSERT(pow_sha256(NULL, 0, digest) == 0);
    TEST_ASSERT(pow_sha256(abc, sizeof(abc) - 1, NULL) == 0);

    return 0;
}


static int
test_hmac(void)
{
    static const uint8_t  key1[20] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b
    };
    static const uint8_t  msg1[] = "Hi There";
    static const uint8_t  expected1[POW_DIGEST_LEN] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };
    static const uint8_t  key2[] = "Jefe";
    static const uint8_t  msg2[] = "what do ya want for nothing?";
    static const uint8_t  expected2[POW_DIGEST_LEN] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
    };
    uint8_t  digest[POW_DIGEST_LEN];

    TEST_ASSERT(pow_hmac_sha256(key1, sizeof(key1), msg1,
                                sizeof(msg1) - 1, digest) == 1);
    TEST_ASSERT(bytes_equal(digest, expected1, sizeof(digest)) == 1);
    TEST_ASSERT(pow_hmac_sha256(key2, sizeof(key2) - 1, msg2,
                                sizeof(msg2) - 1, digest) == 1);
    TEST_ASSERT(bytes_equal(digest, expected2, sizeof(digest)) == 1);
    TEST_ASSERT(pow_hmac_sha256(NULL, sizeof(key1), msg1,
                                sizeof(msg1) - 1, digest) == 0);
    TEST_ASSERT(pow_hmac_sha256(key1, (size_t) INT_MAX + 1, msg1,
                                sizeof(msg1) - 1, digest) == 0);
    TEST_ASSERT(pow_hmac_sha256(key1, sizeof(key1), NULL,
                                sizeof(msg1) - 1, digest) == 0);
    TEST_ASSERT(pow_hmac_sha256(key1, sizeof(key1), msg1,
                                sizeof(msg1) - 1, NULL) == 0);

    return 0;
}


static int
test_constant_time_equality(void)
{
    uint8_t  a[POW_AUTH_MAC_LEN] = { 0 };
    uint8_t  b[POW_AUTH_MAC_LEN] = { 0 };

    TEST_ASSERT(pow_ct_eq(a, b, sizeof(a)) == 1);
    b[0] = 1;
    TEST_ASSERT(pow_ct_eq(a, b, sizeof(a)) == 0);
    b[0] = 0;
    b[sizeof(b) - 1] = 1;
    TEST_ASSERT(pow_ct_eq(a, b, sizeof(a)) == 0);
    TEST_ASSERT(pow_ct_eq(a, b, 0) == 1);
    TEST_ASSERT(pow_ct_eq(NULL, b, sizeof(a)) == 0);
    TEST_ASSERT(pow_ct_eq(a, NULL, sizeof(a)) == 0);

    return 0;
}


static int
test_leading_zero_bits(void)
{
    static const struct {
        uint8_t   prefix[5];
        uint16_t  expected;
    } cases[] = {
        { { 0xff, 0, 0, 0, 0 }, 0 },
        { { 0x7f, 0, 0, 0, 0 }, 1 },
        { { 0x01, 0, 0, 0, 0 }, 7 },
        { { 0x00, 0xff, 0, 0, 0 }, 8 },
        { { 0x00, 0x7f, 0, 0, 0 }, 9 },
        { { 0x00, 0x00, 0xff, 0, 0 }, 16 },
        { { 0x00, 0x00, 0x00, 0xff, 0 }, 24 },
        { { 0x00, 0x00, 0x00, 0x00, 0xff }, 32 }
    };
    uint8_t  digest[POW_DIGEST_LEN];
    size_t   i, j;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        for (j = 0; j < sizeof(digest); j++) {
            digest[j] = 0xff;
        }
        for (j = 0; j < sizeof(cases[i].prefix); j++) {
            digest[j] = cases[i].prefix[j];
        }
        TEST_ASSERT(pow_leading_zero_bits(digest) == cases[i].expected);
    }

    for (i = 0; i < sizeof(digest); i++) {
        digest[i] = 0;
    }
    TEST_ASSERT(pow_leading_zero_bits(digest) == 256);
    TEST_ASSERT(pow_leading_zero_bits(NULL) == 0);

    return 0;
}


int
main(void)
{
    TEST_ASSERT(test_sha256() == 0);
    TEST_ASSERT(test_hmac() == 0);
    TEST_ASSERT(test_constant_time_equality() == 0);
    TEST_ASSERT(test_leading_zero_bits() == 0);

    printf("test_crypto: PASS\n");

    return 0;
}
