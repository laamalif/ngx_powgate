#include <stddef.h>
#include <stdint.h>

#include "pow_crypto.h"


static size_t   pow_test_fail_hmac_call;
static size_t   pow_test_fail_sha_call;
static size_t   pow_test_hmac_calls;
static size_t   pow_test_sha_calls;
static uint8_t  pow_test_sha_first;


void
pow_test_crypto_reset(void)
{
    pow_test_fail_hmac_call = 0;
    pow_test_fail_sha_call = 0;
    pow_test_hmac_calls = 0;
    pow_test_sha_calls = 0;
    pow_test_sha_first = 0;
}


void
pow_test_crypto_fail_hmac(size_t call)
{
    pow_test_fail_hmac_call = call;
}


void
pow_test_crypto_fail_sha(size_t call)
{
    pow_test_fail_sha_call = call;
}


void
pow_test_crypto_set_sha_first(uint8_t value)
{
    pow_test_sha_first = value;
}


size_t
pow_test_crypto_hmac_calls(void)
{
    return pow_test_hmac_calls;
}


size_t
pow_test_crypto_sha_calls(void)
{
    return pow_test_sha_calls;
}


int
pow_sha256(const uint8_t *msg, size_t msg_len,
    uint8_t out[POW_DIGEST_LEN])
{
    size_t  i;

    (void) msg;
    (void) msg_len;

    pow_test_sha_calls++;
    if (pow_test_sha_calls == pow_test_fail_sha_call) {
        return 0;
    }

    for (i = 0; i < POW_DIGEST_LEN; i++) {
        out[i] = 0;
    }
    out[0] = pow_test_sha_first;

    return 1;
}


int
pow_hmac_sha256(const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len, uint8_t out[POW_DIGEST_LEN])
{
    size_t  i;

    (void) key;
    (void) key_len;
    (void) msg;
    (void) msg_len;

    pow_test_hmac_calls++;
    if (pow_test_hmac_calls == pow_test_fail_hmac_call) {
        return 0;
    }

    for (i = 0; i < POW_DIGEST_LEN; i++) {
        out[i] = (uint8_t) pow_test_hmac_calls;
    }

    return 1;
}


int
pow_ct_eq(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t  difference;
    size_t   i;

    difference = 0;
    for (i = 0; i < len; i++) {
        difference |= (uint8_t) (a[i] ^ b[i]);
    }

    return difference == 0 ? 1 : 0;
}


uint16_t
pow_leading_zero_bits(const uint8_t digest[POW_DIGEST_LEN])
{
    uint8_t   byte;
    uint16_t  bits;
    size_t    i;

    bits = 0;

    for (i = 0; i < POW_DIGEST_LEN; i++) {
        byte = digest[i];
        if (byte == 0) {
            bits = (uint16_t) (bits + 8U);
            continue;
        }

        while ((byte & 0x80U) == 0) {
            bits++;
            byte <<= 1;
        }

        break;
    }

    return bits;
}
