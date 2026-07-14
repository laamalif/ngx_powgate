#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "pow_challenge.h"
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


static void
copy_bytes(uint8_t *dst, const uint8_t *src, size_t len)
{
    size_t  i;

    for (i = 0; i < len; i++) {
        dst[i] = src[i];
    }
}


static int
test_ip_mapping(void)
{
    static const uint8_t  ipv4[4] = { 192, 0, 2, 129 };
    static const uint8_t  mapped[POW_IP_LEN] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 129
    };
    static const uint8_t  ipv6[POW_IP_LEN] = {
        0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78,
        0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x79
    };
    uint8_t  out[POW_IP_LEN];

    pow_ip16_from_ipv4(ipv4, out);
    TEST_ASSERT(bytes_equal(out, mapped, sizeof(out)) == 1);

    pow_ip16_from_ipv6(ipv6, out);
    TEST_ASSERT(bytes_equal(out, ipv6, sizeof(out)) == 1);

    return 0;
}


static int
test_ip_masking(void)
{
    static const uint8_t  ipv6[POW_IP_LEN] = {
        0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78,
        0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x79
    };
    static const uint8_t  expected56[POW_IP_LEN] = {
        0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    static const uint8_t  expected64[POW_IP_LEN] = {
        0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78,
        0, 0, 0, 0, 0, 0, 0, 0
    };
    static const uint8_t  expected127[POW_IP_LEN] = {
        0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78,
        0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78
    };
    static const uint8_t  zero[POW_IP_LEN] = { 0 };
    static const uint8_t  ipv4[4] = { 192, 0, 2, 129 };
    static const uint8_t  expected120[POW_IP_LEN] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 0
    };
    uint8_t  out[POW_IP_LEN];

    copy_bytes(out, ipv6, sizeof(out));
    TEST_ASSERT(pow_ip16_mask(out, 0) == 1);
    TEST_ASSERT(bytes_equal(out, zero, sizeof(out)) == 1);

    copy_bytes(out, ipv6, sizeof(out));
    TEST_ASSERT(pow_ip16_mask(out, 56) == 1);
    TEST_ASSERT(bytes_equal(out, expected56, sizeof(out)) == 1);

    copy_bytes(out, ipv6, sizeof(out));
    TEST_ASSERT(pow_ip16_mask(out, 64) == 1);
    TEST_ASSERT(bytes_equal(out, expected64, sizeof(out)) == 1);

    copy_bytes(out, ipv6, sizeof(out));
    TEST_ASSERT(pow_ip16_mask(out, 127) == 1);
    TEST_ASSERT(bytes_equal(out, expected127, sizeof(out)) == 1);

    copy_bytes(out, ipv6, sizeof(out));
    TEST_ASSERT(pow_ip16_mask(out, 128) == 1);
    TEST_ASSERT(bytes_equal(out, ipv6, sizeof(out)) == 1);

    copy_bytes(out, ipv6, sizeof(out));
    TEST_ASSERT(pow_ip16_mask(out, 129) == 0);

    pow_ip16_from_ipv4(ipv4, out);
    TEST_ASSERT(pow_ip16_mask(out, 120) == 1);
    TEST_ASSERT(bytes_equal(out, expected120, sizeof(out)) == 1);

    pow_ip16_from_ipv4(ipv4, out);
    TEST_ASSERT(pow_ip16_mask(out, 128) == 1);
    TEST_ASSERT(out[15] == 129);

    TEST_ASSERT(pow_ip16_mask(NULL, 64) == 0);

    return 0;
}


static int
test_bucket_skew(void)
{
    static const struct {
        uint64_t  claimed;
        uint64_t  current;
        int       expected;
    } cases[] = {
        { UINT64_C(0), UINT64_C(0), 1 },
        { UINT64_C(1), UINT64_C(0), 1 },
        { UINT64_C(0), UINT64_C(1), 1 },
        { UINT64_C(2), UINT64_C(0), 0 },
        { UINT64_C(0), UINT64_C(2), 0 },
        { UINT64_C(100), UINT64_C(101), 1 },
        { UINT64_C(102), UINT64_C(101), 1 },
        { UINT64_C(99), UINT64_C(101), 0 },
        { UINT64_C(103), UINT64_C(101), 0 },
        { UINT64_MAX, UINT64_MAX, 1 },
        { UINT64_MAX - 1, UINT64_MAX, 1 },
        { UINT64_C(0), UINT64_MAX, 0 }
    };
    size_t  i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        TEST_ASSERT(pow_bucket_within_skew(cases[i].claimed, cases[i].current)
                    == cases[i].expected);
    }

    return 0;
}


static int
test_nonce_and_proof(void)
{
    static const uint8_t  raw_ip[POW_IP_LEN] = {
        0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78,
        0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78
    };
    static const uint8_t  expected[POW_NONCE_LEN] = {
        0xc3, 0x82, 0xcd, 0x45, 0xc3, 0x2e, 0x81, 0xf6,
        0xf5, 0xbd, 0xcc, 0x5f, 0xb2, 0x94, 0x97, 0x87,
        0x6a, 0x3d, 0x43, 0x64, 0xb6, 0x88, 0x24, 0x56,
        0x68, 0xab, 0x1b, 0x57, 0x8f, 0xf7, 0x18, 0x4f
    };
    static const uint8_t  counter[] = "34";
    uint8_t               secret[POW_SECRET_LEN];
    uint8_t               ip[POW_IP_LEN];
    uint8_t               nonce[POW_NONCE_LEN];
    size_t                i;

    for (i = 0; i < sizeof(secret); i++) {
        secret[i] = (uint8_t) i;
    }

    copy_bytes(ip, raw_ip, sizeof(ip));
    TEST_ASSERT(pow_ip16_mask(ip, 56) == 1);
    TEST_ASSERT(pow_challenge_derive(secret, ip, 56, UINT64_C(29333333),
                                     nonce) == 1);
    TEST_ASSERT(bytes_equal(nonce, expected, sizeof(nonce)) == 1);
    TEST_ASSERT(pow_proof_check(nonce, counter, sizeof(counter) - 1, 8) == 1);
    TEST_ASSERT(pow_proof_check(nonce, counter, sizeof(counter) - 1, 10) == 1);
    TEST_ASSERT(pow_proof_check(nonce, counter, sizeof(counter) - 1, 11) == 0);
    TEST_ASSERT(pow_proof_check(nonce, counter, sizeof(counter) - 1, 0) == 0);
    TEST_ASSERT(pow_proof_check(nonce, counter, sizeof(counter) - 1, 33) == 0);
    TEST_ASSERT(pow_proof_check(nonce, counter, 0, 8) == 0);
    TEST_ASSERT(pow_challenge_derive(secret, ip, 129, UINT64_C(1), nonce) == 0);

    return 0;
}


static int
test_proof_parse_valid(void)
{
    static const uint8_t  ordinary[] = "1.29333333.34";
    static const uint8_t  zero[] = "1.0.0";
    static const uint8_t  maximum[] = "1.18446744073709551615.9007199254740991";
    pow_proof_t            proof;

    TEST_ASSERT(pow_proof_cookie_parse(ordinary, sizeof(ordinary) - 1,
                                       &proof) == 1);
    TEST_ASSERT(proof.bucket == UINT64_C(29333333));
    TEST_ASSERT(proof.counter == UINT64_C(34));
    TEST_ASSERT(proof.counter_len == 2);
    TEST_ASSERT(proof.counter_ascii[0] == '3');
    TEST_ASSERT(proof.counter_ascii[1] == '4');

    TEST_ASSERT(pow_proof_cookie_parse(zero, sizeof(zero) - 1, &proof) == 1);
    TEST_ASSERT(proof.bucket == 0 && proof.counter == 0);

    TEST_ASSERT(pow_proof_cookie_parse(maximum, sizeof(maximum) - 1,
                                       &proof) == 1);
    TEST_ASSERT(proof.bucket == UINT64_MAX);
    TEST_ASSERT(proof.counter == POW_PROOF_COUNTER_MAX);

    return 0;
}


static int
test_proof_parse_reject(void)
{
    static const uint8_t *cases[] = {
        (const uint8_t *) "",
        (const uint8_t *) "2.1.1",
        (const uint8_t *) "1.1",
        (const uint8_t *) "1.1.1.1",
        (const uint8_t *) "1..1",
        (const uint8_t *) "1.01.1",
        (const uint8_t *) "1.1.01",
        (const uint8_t *) "1.184467440737095516150.1",
        (const uint8_t *) "1.18446744073709551616.1",
        (const uint8_t *) "1.1.00000000000000001",
        (const uint8_t *) "1.1.9007199254740992"
    };
    static const size_t  lengths[] = {
        0, 5, 3, 7, 4, 6, 6, 25, 24, 21, 20
    };
    uint8_t      too_long[POW_PROOF_COOKIE_MAX_LEN + 1];
    pow_proof_t  proof;
    size_t       i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        TEST_ASSERT(pow_proof_cookie_parse(cases[i], lengths[i], &proof) == 0);
    }

    for (i = 0; i < sizeof(too_long); i++) {
        too_long[i] = (uint8_t) '1';
    }

    TEST_ASSERT(pow_proof_cookie_parse(too_long, sizeof(too_long),
                                       &proof) == 0);
    TEST_ASSERT(pow_proof_cookie_parse(NULL, 1, &proof) == 0);
    TEST_ASSERT(pow_proof_cookie_parse((const uint8_t *) "1.1.1", 5,
                                       NULL) == 0);

    return 0;
}


int
main(void)
{
    TEST_ASSERT(test_ip_mapping() == 0);
    TEST_ASSERT(test_ip_masking() == 0);
    TEST_ASSERT(test_bucket_skew() == 0);
    TEST_ASSERT(test_nonce_and_proof() == 0);
    TEST_ASSERT(test_proof_parse_valid() == 0);
    TEST_ASSERT(test_proof_parse_reject() == 0);

    printf("test_challenge: PASS\n");

    return 0;
}
