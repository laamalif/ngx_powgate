#ifndef POW_CHALLENGE_H
#define POW_CHALLENGE_H


#include <stddef.h>
#include <stdint.h>

#include "pow_protocol.h"
#include "pow_verify.h"


typedef struct {
    uint64_t  bucket;
    uint64_t  counter;
    uint8_t   counter_ascii[POW_COUNTER_DECIMAL_MAX_LEN];
    size_t    counter_len;
} pow_proof_t;


typedef struct {
    size_t  len;
    size_t  difficulty_offset;
    size_t  difficulty_len;
    size_t  bucket_offset;
    size_t  bucket_len;
    size_t  nonce_offset;
    size_t  nonce_len;
} pow_challenge_text_t;


void pow_ip16_from_ipv4(const uint8_t ipv4[POW_IPV4_LEN],
    uint8_t out[POW_IP_LEN]);
void pow_ip16_from_ipv6(const uint8_t ipv6[POW_IP_LEN],
    uint8_t out[POW_IP_LEN]);
int pow_ip16_mask(uint8_t ip16[POW_IP_LEN], uint8_t plen);
int pow_bucket_within_skew(uint64_t claimed, uint64_t current);
int pow_challenge_derive(const uint8_t secret[POW_SECRET_LEN],
    const uint8_t ip16[POW_IP_LEN], uint8_t plen, uint64_t bucket,
    uint8_t nonce[POW_NONCE_LEN]);
int pow_challenge_serialize(uint8_t difficulty, uint64_t bucket,
    const uint8_t nonce[POW_NONCE_LEN], uint8_t *buf, size_t buf_cap,
    pow_challenge_text_t *out);
pow_verify_result_t pow_proof_check(
    const uint8_t nonce[POW_NONCE_LEN],
    const uint8_t *counter_ascii, size_t counter_len, uint8_t difficulty);
int pow_proof_cookie_parse(const uint8_t *buf, size_t len,
    pow_proof_t *out);


#endif /* POW_CHALLENGE_H */
