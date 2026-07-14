/*
 * Copyright (C) ngx_powgate authors
 */


#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "pow_crypto.h"
#include "pow_protocol.h"


int
pow_sha256(const uint8_t *msg, size_t msg_len,
    uint8_t out[POW_DIGEST_LEN])
{
    if (msg == NULL || out == NULL) {
        return 0;
    }

    return SHA256(msg, msg_len, out) != NULL ? 1 : 0;
}


int
pow_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg,
    size_t msg_len, uint8_t out[POW_DIGEST_LEN])
{
    unsigned int  out_len;

    if (key == NULL || msg == NULL || out == NULL
        || key_len > (size_t) INT_MAX)
    {
        return 0;
    }

    out_len = 0;

    if (HMAC(EVP_sha256(), key, (int) key_len, msg, msg_len, out,
             &out_len)
        == NULL)
    {
        return 0;
    }

    return out_len == POW_DIGEST_LEN ? 1 : 0;
}


int
pow_ct_eq(const uint8_t *a, const uint8_t *b, size_t len)
{
    if (a == NULL || b == NULL) {
        return 0;
    }

    if (len == 0) {
        return 1;
    }

    return CRYPTO_memcmp(a, b, len) == 0 ? 1 : 0;
}


uint16_t
pow_leading_zero_bits(const uint8_t digest[POW_DIGEST_LEN])
{
    uint16_t  count;
    uint8_t   mask;
    size_t    i;

    if (digest == NULL) {
        return 0;
    }

    count = 0;

    for (i = 0; i < POW_DIGEST_LEN; i++) {
        if (digest[i] == 0) {
            count = (uint16_t) (count + 8);
            continue;
        }

        mask = 0x80U;

        while ((digest[i] & mask) == 0) {
            count++;
            mask = (uint8_t) (mask >> 1);
        }

        break;
    }

    return count;
}
