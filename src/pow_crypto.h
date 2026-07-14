#ifndef POW_CRYPTO_H
#define POW_CRYPTO_H


#include <stddef.h>
#include <stdint.h>

#include "pow_protocol.h"


int pow_sha256(const uint8_t *msg, size_t msg_len,
    uint8_t out[POW_DIGEST_LEN]);
int pow_hmac_sha256(const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len, uint8_t out[POW_DIGEST_LEN]);
int pow_ct_eq(const uint8_t *a, const uint8_t *b, size_t len);
uint16_t pow_leading_zero_bits(const uint8_t digest[POW_DIGEST_LEN]);


#endif /* POW_CRYPTO_H */
