#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "pow_challenge.h"
#include "pow_cookie.h"
#include "pow_protocol.h"
#include "pow_verify.h"
#include "test.h"


void pow_test_crypto_reset(void);
void pow_test_crypto_fail_hmac(size_t call);
void pow_test_crypto_fail_sha(size_t call);
void pow_test_crypto_set_sha_first(uint8_t value);
size_t pow_test_crypto_hmac_calls(void);
size_t pow_test_crypto_sha_calls(void);


static void
fill_bytes(uint8_t *dst, size_t len, uint8_t value)
{
    size_t  i;

    for (i = 0; i < len; i++) {
        dst[i] = value;
    }
}


static void
init_cookie(pow_cookie_t *cookie, uint8_t mac_value)
{
    size_t  i;

    cookie->expiry = UINT64_C(2);
    cookie->difficulty = POW_DIFFICULTY_MIN;
    cookie->plen = POW_IP_PLEN_MIN;

    for (i = 0; i < POW_AUTH_PAYLOAD_LEN; i++) {
        cookie->payload[i] = 0;
    }
    cookie->payload[POW_AUTH_DIFFICULTY_OFFSET] = POW_DIFFICULTY_MIN;
    cookie->payload[POW_AUTH_PLEN_OFFSET] = POW_IP_PLEN_MIN;

    fill_bytes(cookie->mac, POW_AUTH_MAC_LEN, mac_value);
}


static int
test_auth_attempts(void)
{
    uint8_t       current[POW_SECRET_LEN];
    uint8_t       ip16[POW_IP_LEN];
    uint8_t       previous[POW_SECRET_LEN];
    pow_cookie_t  cookie;

    fill_bytes(current, sizeof(current), 1);
    fill_bytes(previous, sizeof(previous), 2);
    fill_bytes(ip16, sizeof(ip16), 0);

    pow_test_crypto_reset();
    init_cookie(&cookie, 1);
    TEST_ASSERT(pow_cookie_verify(current, previous, &cookie, ip16, 0,
                                  POW_DIFFICULTY_MIN, POW_IP_PLEN_MIN)
                == POW_VERIFY_VALID);
    TEST_ASSERT(pow_test_crypto_hmac_calls() == 1);

    pow_test_crypto_reset();
    init_cookie(&cookie, 2);
    TEST_ASSERT(pow_cookie_verify(current, previous, &cookie, ip16, 0,
                                  POW_DIFFICULTY_MIN, POW_IP_PLEN_MIN)
                == POW_VERIFY_VALID);
    TEST_ASSERT(pow_test_crypto_hmac_calls() == 2);

    pow_test_crypto_reset();
    init_cookie(&cookie, 2);
    TEST_ASSERT(pow_cookie_verify(current, NULL, &cookie, ip16, 0,
                                  POW_DIFFICULTY_MIN, POW_IP_PLEN_MIN)
                == POW_VERIFY_INVALID);
    TEST_ASSERT(pow_test_crypto_hmac_calls() == 2);

    pow_test_crypto_reset();
    init_cookie(&cookie, 3);
    TEST_ASSERT(pow_cookie_verify(current, previous, &cookie, ip16, 0,
                                  POW_DIFFICULTY_MIN, POW_IP_PLEN_MIN)
                == POW_VERIFY_INVALID);
    TEST_ASSERT(pow_test_crypto_hmac_calls() == 2);

    pow_test_crypto_reset();
    pow_test_crypto_fail_hmac(1);
    init_cookie(&cookie, 1);
    TEST_ASSERT(pow_cookie_verify(current, previous, &cookie, ip16, 0,
                                  POW_DIFFICULTY_MIN, POW_IP_PLEN_MIN)
                == POW_VERIFY_ERROR);
    TEST_ASSERT(pow_test_crypto_hmac_calls() == 1);

    pow_test_crypto_reset();
    pow_test_crypto_fail_hmac(2);
    init_cookie(&cookie, 2);
    TEST_ASSERT(pow_cookie_verify(current, previous, &cookie, ip16, 0,
                                  POW_DIFFICULTY_MIN, POW_IP_PLEN_MIN)
                == POW_VERIFY_ERROR);
    TEST_ASSERT(pow_test_crypto_hmac_calls() == 2);

    return 0;
}


static int
test_proof_provider_failure(void)
{
    static const uint8_t  counter[] = "1";
    uint8_t               nonce[POW_NONCE_LEN];

    fill_bytes(nonce, sizeof(nonce), 0);

    pow_test_crypto_reset();
    TEST_ASSERT(pow_proof_check(nonce, counter, sizeof(counter) - 1,
                                POW_DIFFICULTY_MIN)
                == POW_VERIFY_VALID);
    TEST_ASSERT(pow_test_crypto_sha_calls() == 1);

    pow_test_crypto_reset();
    pow_test_crypto_set_sha_first(0x80U);
    TEST_ASSERT(pow_proof_check(nonce, counter, sizeof(counter) - 1,
                                POW_DIFFICULTY_MIN)
                == POW_VERIFY_INVALID);
    TEST_ASSERT(pow_test_crypto_sha_calls() == 1);

    pow_test_crypto_reset();
    pow_test_crypto_fail_sha(1);
    TEST_ASSERT(pow_proof_check(nonce, counter, sizeof(counter) - 1,
                                POW_DIFFICULTY_MIN)
                == POW_VERIFY_ERROR);
    TEST_ASSERT(pow_test_crypto_sha_calls() == 1);

    return 0;
}


int
main(void)
{
    TEST_ASSERT(test_auth_attempts() == 0);
    TEST_ASSERT(test_proof_provider_failure() == 0);

    puts("test_verify_errors: PASS");
    return 0;
}
