#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "pow_cookie.h"
#include "pow_parse.h"
#include "pow_protocol.h"
#include "pow_verify.h"
#include "test.h"


static const uint8_t  vector_ip[POW_IP_LEN] = {
    0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78,
    0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78
};


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
fill_secret(uint8_t secret[POW_SECRET_LEN], uint8_t start)
{
    size_t  i;

    for (i = 0; i < POW_SECRET_LEN; i++) {
        secret[i] = (uint8_t) (start + (uint8_t) i);
    }
}


static size_t
build_raw_wire(const uint8_t payload[POW_AUTH_PAYLOAD_LEN],
    const uint8_t mac[POW_AUTH_MAC_LEN], uint8_t out[POW_AUTH_COOKIE_WIRE_LEN])
{
    size_t  len;
    size_t  offset;

    offset = 0;
    out[offset++] = (uint8_t) POW_VERSION_TEXT[0];
    out[offset++] = (uint8_t) POW_FIELD_SEPARATOR;

    len = pow_b64url_encode(payload, POW_AUTH_PAYLOAD_LEN, out + offset,
                            POW_AUTH_PAYLOAD_B64_LEN);
    if (len != POW_AUTH_PAYLOAD_B64_LEN) {
        return 0;
    }
    offset += len;
    out[offset++] = (uint8_t) POW_FIELD_SEPARATOR;

    len = pow_b64url_encode(mac, POW_AUTH_MAC_LEN, out + offset,
                            POW_AUTH_MAC_B64_LEN);
    if (len != POW_AUTH_MAC_B64_LEN) {
        return 0;
    }

    return offset + len;
}


static int
build_and_parse(const uint8_t secret[POW_SECRET_LEN], uint64_t expiry,
    uint8_t difficulty, uint8_t plen, pow_cookie_t *parsed,
    uint8_t wire[POW_AUTH_COOKIE_WIRE_LEN])
{
    size_t  len;

    len = pow_cookie_build(secret, expiry, difficulty, plen, vector_ip, wire,
                           POW_AUTH_COOKIE_WIRE_LEN);
    if (len != POW_AUTH_COOKIE_WIRE_LEN) {
        return 0;
    }

    return pow_cookie_parse(wire, len, parsed);
}


static int
test_build_and_parse_vector(void)
{
    static const uint8_t  expected[] =
        "1.AAAAAGtJ0gAIOA.GfPZjHRTfYY8nuiwWBi_Rg";
    static const uint8_t  payload[POW_AUTH_PAYLOAD_LEN] = {
        0x00, 0x00, 0x00, 0x00, 0x6b, 0x49, 0xd2, 0x00, 0x08, 0x38
    };
    static const uint8_t  mac[POW_AUTH_MAC_LEN] = {
        0x19, 0xf3, 0xd9, 0x8c, 0x74, 0x53, 0x7d, 0x86,
        0x3c, 0x9e, 0xe8, 0xb0, 0x58, 0x18, 0xbf, 0x46
    };
    uint8_t       secret[POW_SECRET_LEN];
    uint8_t       wire[POW_AUTH_COOKIE_WIRE_LEN];
    pow_cookie_t  parsed;
    size_t        len;

    fill_secret(secret, 0);
    len = pow_cookie_build(secret, UINT64_C(1800000000), 8, 56, vector_ip,
                           wire, sizeof(wire));
    TEST_ASSERT(len == POW_AUTH_COOKIE_WIRE_LEN);
    TEST_ASSERT(bytes_equal(wire, expected, sizeof(expected) - 1) == 1);
    TEST_ASSERT(pow_cookie_parse(wire, len, &parsed) == 1);
    TEST_ASSERT(parsed.expiry == UINT64_C(1800000000));
    TEST_ASSERT(parsed.difficulty == 8);
    TEST_ASSERT(parsed.plen == 56);
    TEST_ASSERT(bytes_equal(parsed.payload, payload, sizeof(payload)) == 1);
    TEST_ASSERT(bytes_equal(parsed.mac, mac, sizeof(mac)) == 1);

    TEST_ASSERT(pow_cookie_build(secret, UINT64_C(1800000000), 8, 56,
                                 vector_ip, wire, sizeof(wire) - 1) == 0);
    TEST_ASSERT(pow_cookie_build(secret, UINT64_C(1800000000), 0, 56,
                                 vector_ip, wire, sizeof(wire)) == 0);
    TEST_ASSERT(pow_cookie_build(secret, UINT64_C(1800000000), 33, 56,
                                 vector_ip, wire, sizeof(wire)) == 0);
    TEST_ASSERT(pow_cookie_build(secret, UINT64_C(1800000000), 8, 31,
                                 vector_ip, wire, sizeof(wire)) == 0);
    TEST_ASSERT(pow_cookie_build(secret, UINT64_C(1800000000), 8, 129,
                                 vector_ip, wire, sizeof(wire)) == 0);
    TEST_ASSERT(pow_cookie_build(NULL, UINT64_C(1800000000), 8, 56,
                                 vector_ip, wire, sizeof(wire)) == 0);

    return 0;
}


static int
test_parse_rejects_structure_and_encoding(void)
{
    static const uint8_t *cases[] = {
        (const uint8_t *) "",
        (const uint8_t *) "2.AAAAAGtJ0gAIOA.GfPZjHRTfYY8nuiwWBi_Rg",
        (const uint8_t *) "11.AAAAAGtJ0gAIOA.GfPZjHRTfYY8nuiwWBi_Rg",
        (const uint8_t *) "1.AAAAAGtJ0gAIOA",
        (const uint8_t *) "1.AAAAAGtJ0gAIOA.GfPZjHRTfYY8nuiwWBi_Rg.x",
        (const uint8_t *) "1..GfPZjHRTfYY8nuiwWBi_Rg",
        (const uint8_t *) "1.AAAAAGtJ0gAIO=.GfPZjHRTfYY8nuiwWBi_Rg",
        (const uint8_t *) "1.AAAAAGtJ0gAIO+.GfPZjHRTfYY8nuiwWBi_Rg",
        (const uint8_t *) "1.AAAAAGtJ0gAIOB.GfPZjHRTfYY8nuiwWBi_Rg",
        (const uint8_t *) "1.AAAAAGtJ0gAIOA.GfPZjHRTfYY8nuiwWBi_Rh",
        (const uint8_t *) "1.AAAAAGtJ0gAIO.GfPZjHRTfYY8nuiwWBi_Rg",
        (const uint8_t *) "1.AAAAAGtJ0gAIOA.GfPZjHRTfYY8nuiwWBi_R"
    };
    static const size_t  lengths[] = {
        0, 39, 40, 16, 41, 25, 39, 39, 39, 39, 38, 38
    };
    uint8_t       too_long[POW_AUTH_COOKIE_MAX_LEN + 1];
    pow_cookie_t  parsed;
    size_t        i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        TEST_ASSERT(pow_cookie_parse(cases[i], lengths[i], &parsed) == 0);
    }

    for (i = 0; i < sizeof(too_long); i++) {
        too_long[i] = (uint8_t) '1';
    }
    TEST_ASSERT(pow_cookie_parse(too_long, sizeof(too_long), &parsed) == 0);
    TEST_ASSERT(pow_cookie_parse(NULL, 1, &parsed) == 0);
    TEST_ASSERT(pow_cookie_parse((const uint8_t *) "1.x.y", 5, NULL) == 0);

    return 0;
}


static int
test_parse_rejects_payload_bounds(void)
{
    uint8_t       mac[POW_AUTH_MAC_LEN] = { 0 };
    uint8_t       payload[POW_AUTH_PAYLOAD_LEN] = { 0 };
    uint8_t       wire[POW_AUTH_COOKIE_WIRE_LEN];
    pow_cookie_t  parsed;
    size_t        len;

    payload[POW_AUTH_DIFFICULTY_OFFSET] = 0;
    payload[POW_AUTH_PLEN_OFFSET] = 56;
    len = build_raw_wire(payload, mac, wire);
    TEST_ASSERT(len == sizeof(wire));
    TEST_ASSERT(pow_cookie_parse(wire, len, &parsed) == 0);

    payload[POW_AUTH_DIFFICULTY_OFFSET] = 33;
    TEST_ASSERT(pow_cookie_parse(wire, build_raw_wire(payload, mac, wire),
                                 &parsed) == 0);

    payload[POW_AUTH_DIFFICULTY_OFFSET] = 8;
    payload[POW_AUTH_PLEN_OFFSET] = 31;
    TEST_ASSERT(pow_cookie_parse(wire, build_raw_wire(payload, mac, wire),
                                 &parsed) == 0);

    payload[POW_AUTH_PLEN_OFFSET] = 129;
    TEST_ASSERT(pow_cookie_parse(wire, build_raw_wire(payload, mac, wire),
                                 &parsed) == 0);

    return 0;
}


static int
test_verify_secrets_and_policy(void)
{
    uint8_t       current[POW_SECRET_LEN];
    uint8_t       previous[POW_SECRET_LEN];
    uint8_t       wrong[POW_SECRET_LEN];
    uint8_t       wrong_ip[POW_IP_LEN];
    uint8_t       wire[POW_AUTH_COOKIE_WIRE_LEN];
    pow_cookie_t  parsed;
    size_t        i;

    fill_secret(current, 0);
    fill_secret(previous, 32);
    fill_secret(wrong, 64);

    TEST_ASSERT(build_and_parse(current, UINT64_C(1800000000), 8, 56,
                                &parsed, wire) == 1);
    TEST_ASSERT(pow_cookie_verify(current, NULL, &parsed, vector_ip,
                                  UINT64_C(1799999999), 8, 56)
                == POW_VERIFY_VALID);
    TEST_ASSERT(pow_cookie_verify(wrong, current, &parsed, vector_ip,
                                  UINT64_C(1799999999), 8, 56)
                == POW_VERIFY_VALID);
    TEST_ASSERT(pow_cookie_verify(wrong, NULL, &parsed, vector_ip,
                                  UINT64_C(1799999999), 8, 56)
                == POW_VERIFY_INVALID);
    TEST_ASSERT(pow_cookie_verify(wrong, previous, &parsed, vector_ip,
                                  UINT64_C(1799999999), 8, 56)
                == POW_VERIFY_INVALID);
    TEST_ASSERT(pow_cookie_verify(current, NULL, &parsed, vector_ip,
                                  UINT64_C(1800000000), 8, 56)
                == POW_VERIFY_INVALID);
    TEST_ASSERT(pow_cookie_verify(current, NULL, &parsed, vector_ip,
                                  UINT64_C(1800000001), 8, 56)
                == POW_VERIFY_INVALID);
    TEST_ASSERT(pow_cookie_verify(current, NULL, &parsed, vector_ip,
                                  UINT64_C(1799999999), 9, 56)
                == POW_VERIFY_INVALID);
    TEST_ASSERT(pow_cookie_verify(current, NULL, &parsed, vector_ip,
                                  UINT64_C(1799999999), 8, 57)
                == POW_VERIFY_INVALID);

    for (i = 0; i < sizeof(wrong_ip); i++) {
        wrong_ip[i] = vector_ip[i];
    }
    wrong_ip[6] ^= 1;
    TEST_ASSERT(pow_cookie_verify(current, NULL, &parsed, wrong_ip,
                                  UINT64_C(1799999999), 8, 56)
                == POW_VERIFY_INVALID);

    TEST_ASSERT(build_and_parse(previous, UINT64_C(1800000000), 9, 64,
                                &parsed, wire) == 1);
    TEST_ASSERT(pow_cookie_verify(current, previous, &parsed, vector_ip,
                                  UINT64_C(1799999999), 8, 56)
                == POW_VERIFY_VALID);

    TEST_ASSERT(pow_cookie_verify(current, previous, &parsed, vector_ip,
                                  UINT64_C(1799999999), 0, 56)
                == POW_VERIFY_ERROR);
    TEST_ASSERT(pow_cookie_verify(current, previous, &parsed, vector_ip,
                                  UINT64_C(1799999999), 33, 56)
                == POW_VERIFY_ERROR);
    TEST_ASSERT(pow_cookie_verify(current, previous, &parsed, vector_ip,
                                  UINT64_C(1799999999), 8, 31)
                == POW_VERIFY_ERROR);
    TEST_ASSERT(pow_cookie_verify(current, previous, &parsed, vector_ip,
                                  UINT64_C(1799999999), 8, 129)
                == POW_VERIFY_ERROR);
    TEST_ASSERT(pow_cookie_verify(NULL, previous, &parsed, vector_ip,
                                  UINT64_C(1799999999), 8, 56)
                == POW_VERIFY_ERROR);
    TEST_ASSERT(pow_cookie_verify(current, previous, NULL, vector_ip,
                                  UINT64_C(1799999999), 8, 56)
                == POW_VERIFY_ERROR);
    TEST_ASSERT(pow_cookie_verify(current, previous, &parsed, NULL,
                                  UINT64_C(1799999999), 8, 56)
                == POW_VERIFY_ERROR);

    parsed.difficulty = 0;
    TEST_ASSERT(pow_cookie_verify(current, previous, &parsed, vector_ip,
                                  UINT64_C(1799999999), 8, 56)
                == POW_VERIFY_ERROR);
    parsed.difficulty = 9;
    parsed.plen = 129;
    TEST_ASSERT(pow_cookie_verify(current, previous, &parsed, vector_ip,
                                  UINT64_C(1799999999), 8, 56)
                == POW_VERIFY_ERROR);

    return 0;
}


static int
test_every_wire_mutation_fails(void)
{
    uint8_t       mutated[POW_AUTH_COOKIE_WIRE_LEN];
    uint8_t       secret[POW_SECRET_LEN];
    uint8_t       wire[POW_AUTH_COOKIE_WIRE_LEN];
    pow_cookie_t  parsed;
    size_t        i, j;

    fill_secret(secret, 0);
    TEST_ASSERT(build_and_parse(secret, UINT64_C(1800000000), 8, 56,
                                &parsed, wire) == 1);

    for (i = 0; i < sizeof(wire); i++) {
        for (j = 0; j < sizeof(wire); j++) {
            mutated[j] = wire[j];
        }
        mutated[i] ^= 1;

        if (pow_cookie_parse(mutated, sizeof(mutated), &parsed) == 1) {
            TEST_ASSERT(pow_cookie_verify(secret, NULL, &parsed, vector_ip,
                                          UINT64_C(1799999999), 8, 56)
                        == POW_VERIFY_INVALID);
        }
    }

    return 0;
}


int
main(void)
{
    TEST_ASSERT(test_build_and_parse_vector() == 0);
    TEST_ASSERT(test_parse_rejects_structure_and_encoding() == 0);
    TEST_ASSERT(test_parse_rejects_payload_bounds() == 0);
    TEST_ASSERT(test_verify_secrets_and_policy() == 0);
    TEST_ASSERT(test_every_wire_mutation_fails() == 0);

    printf("test_cookie: PASS\n");

    return 0;
}
