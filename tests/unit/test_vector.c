#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "pow_challenge.h"
#include "pow_cookie.h"
#include "pow_crypto.h"
#include "pow_protocol.h"
#include "test.h"
#include "vector_v1.h"


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


int
main(void)
{
    uint8_t       cookie[POW_AUTH_COOKIE_WIRE_LEN];
    uint8_t       digest[POW_DIGEST_LEN];
    uint8_t       ip16[POW_IP_LEN];
    uint8_t       message[POW_NONCE_LEN + POW_COUNTER_DECIMAL_MAX_LEN];
    uint8_t       nonce[POW_NONCE_LEN];
    pow_cookie_t  parsed;
    size_t        i;
    size_t        len;

    pow_ip16_from_ipv6(vector_v1_ip16, ip16);
    TEST_ASSERT(pow_ip16_mask(ip16, vector_v1_plen) == 1);
    TEST_ASSERT(bytes_equal(ip16, vector_v1_masked_ip16, POW_IP_LEN) == 1);

    TEST_ASSERT(pow_challenge_derive(vector_v1_secret, ip16, vector_v1_plen,
                                     vector_v1_bucket, nonce) == 1);
    TEST_ASSERT(bytes_equal(nonce, vector_v1_nonce, POW_NONCE_LEN) == 1);
    TEST_ASSERT(pow_proof_check(nonce, vector_v1_counter_ascii,
                                vector_v1_counter_ascii_len,
                                vector_v1_difficulty) == 1);
    for (i = 0; i < POW_NONCE_LEN; i++) {
        message[i] = nonce[i];
    }
    for (i = 0; i < vector_v1_counter_ascii_len; i++) {
        message[POW_NONCE_LEN + i] = vector_v1_counter_ascii[i];
    }
    TEST_ASSERT(pow_sha256(message,
                           POW_NONCE_LEN + vector_v1_counter_ascii_len,
                           digest) == 1);
    TEST_ASSERT(bytes_equal(digest, vector_v1_proof_digest,
                            POW_DIGEST_LEN) == 1);

    len = pow_cookie_build(vector_v1_secret, vector_v1_expiry,
                           vector_v1_difficulty, vector_v1_plen,
                           vector_v1_ip16, cookie, sizeof(cookie));
    TEST_ASSERT(len == vector_v1_auth_cookie_len);
    TEST_ASSERT(bytes_equal(cookie, vector_v1_auth_cookie, len) == 1);
    TEST_ASSERT(pow_cookie_parse(cookie, len, &parsed) == 1);
    TEST_ASSERT(bytes_equal(parsed.payload, vector_v1_auth_payload,
                            POW_AUTH_PAYLOAD_LEN) == 1);
    TEST_ASSERT(bytes_equal(parsed.mac, vector_v1_auth_mac,
                            POW_AUTH_MAC_LEN) == 1);
    TEST_ASSERT(pow_cookie_verify(vector_v1_secret, NULL, &parsed,
                                  vector_v1_ip16, vector_v1_expiry - 1,
                                  vector_v1_difficulty,
                                  vector_v1_plen) == 1);

    printf("test_vector: PASS\n");

    return 0;
}
