/*
 * Copyright (C) ngx_powgate authors
 */


#include <stddef.h>
#include <stdint.h>

#include "pow_challenge.h"
#include "pow_crypto.h"
#include "pow_parse.h"
#include "pow_protocol.h"


static void pow_write_u64_be(uint8_t *dst, uint64_t value);


void
pow_ip16_from_ipv4(const uint8_t ipv4[4], uint8_t out[POW_IP_LEN])
{
    size_t  i;

    if (ipv4 == NULL || out == NULL) {
        return;
    }

    for (i = 0; i < POW_IP_LEN; i++) {
        out[i] = 0;
    }

    out[POW_IPV4_MAPPED_FF_OFFSET] = 0xffU;
    out[POW_IPV4_MAPPED_FF_OFFSET + 1] = 0xffU;

    for (i = 0; i < 4; i++) {
        out[POW_IPV4_MAPPED_ADDR_OFFSET + i] = ipv4[i];
    }
}


void
pow_ip16_from_ipv6(const uint8_t ipv6[POW_IP_LEN],
    uint8_t out[POW_IP_LEN])
{
    size_t  i;

    if (ipv6 == NULL || out == NULL) {
        return;
    }

    for (i = 0; i < POW_IP_LEN; i++) {
        out[i] = ipv6[i];
    }
}


int
pow_ip16_mask(uint8_t ip16[POW_IP_LEN], uint8_t plen)
{
    size_t   boundary;
    size_t   i;
    uint8_t  bits;
    uint8_t  mask;

    if (ip16 == NULL || plen > 128) {
        return 0;
    }

    if (plen == 128) {
        return 1;
    }

    boundary = (size_t) plen / 8;
    bits = (uint8_t) (plen % 8);

    if (bits != 0) {
        mask = (uint8_t) (0xffU << (8 - bits));
        ip16[boundary] &= mask;
        boundary++;
    }

    for (i = boundary; i < POW_IP_LEN; i++) {
        ip16[i] = 0;
    }

    return 1;
}


int
pow_bucket_within_skew(uint64_t claimed, uint64_t current)
{
    if (claimed <= current) {
        return current - claimed <= 1 ? 1 : 0;
    }

    return claimed - current <= 1 ? 1 : 0;
}


int
pow_challenge_derive(const uint8_t secret[POW_SECRET_LEN],
    const uint8_t ip16[POW_IP_LEN], uint8_t plen, uint64_t bucket,
    uint8_t nonce[POW_NONCE_LEN])
{
    static const uint8_t  label[] = POW_CHALLENGE_LABEL;
    uint8_t               message[POW_CHALLENGE_LABEL_LEN + POW_IP_LEN + 1
                                  + POW_U64_BE_LEN];
    size_t                i;
    size_t                offset;

    if (secret == NULL || ip16 == NULL || nonce == NULL || plen > 128) {
        return 0;
    }

    offset = 0;

    for (i = 0; i < POW_CHALLENGE_LABEL_LEN; i++) {
        message[offset++] = label[i];
    }

    for (i = 0; i < POW_IP_LEN; i++) {
        message[offset++] = ip16[i];
    }

    message[offset++] = plen;
    pow_write_u64_be(message + offset, bucket);

    return pow_hmac_sha256(secret, POW_SECRET_LEN, message, sizeof(message),
                           nonce);
}


int
pow_proof_check(const uint8_t nonce[POW_NONCE_LEN],
    const uint8_t *counter_ascii, size_t counter_len, uint8_t difficulty)
{
    uint8_t  digest[POW_DIGEST_LEN];
    uint8_t  message[POW_NONCE_LEN + POW_COUNTER_DECIMAL_MAX_LEN];
    size_t   i;

    if (nonce == NULL || counter_ascii == NULL || counter_len == 0
        || counter_len > POW_COUNTER_DECIMAL_MAX_LEN
        || difficulty < POW_DIFFICULTY_MIN
        || difficulty > POW_DIFFICULTY_MAX)
    {
        return 0;
    }

    for (i = 0; i < POW_NONCE_LEN; i++) {
        message[i] = nonce[i];
    }

    for (i = 0; i < counter_len; i++) {
        message[POW_NONCE_LEN + i] = counter_ascii[i];
    }

    if (pow_sha256(message, POW_NONCE_LEN + counter_len, digest) == 0) {
        return 0;
    }

    return pow_leading_zero_bits(digest) >= difficulty ? 1 : 0;
}


int
pow_proof_cookie_parse(const uint8_t *buf, size_t len, pow_proof_t *out)
{
    pow_span_t  fields[POW_PROOF_FIELD_COUNT];
    uint64_t    bucket;
    uint64_t    counter;
    size_t      i;

    if (buf == NULL || out == NULL || len > POW_PROOF_COOKIE_MAX_LEN) {
        return 0;
    }

    if (pow_split_dot_fields(buf, len, fields, POW_PROOF_FIELD_COUNT) == 0) {
        return 0;
    }

    if (fields[0].len != POW_VERSION_TEXT_LEN
        || fields[0].data[0] != (uint8_t) POW_VERSION_TEXT[0])
    {
        return 0;
    }

    if (pow_parse_u64(fields[1].data, fields[1].len,
                      POW_BUCKET_DECIMAL_MAX_LEN, UINT64_MAX, &bucket)
        == 0)
    {
        return 0;
    }

    if (pow_parse_u64(fields[2].data, fields[2].len,
                      POW_COUNTER_DECIMAL_MAX_LEN, POW_PROOF_COUNTER_MAX,
                      &counter)
        == 0)
    {
        return 0;
    }

    out->bucket = bucket;
    out->counter = counter;
    out->counter_len = fields[2].len;

    for (i = 0; i < fields[2].len; i++) {
        out->counter_ascii[i] = fields[2].data[i];
    }

    return 1;
}


static void
pow_write_u64_be(uint8_t *dst, uint64_t value)
{
    size_t  i;

    for (i = 0; i < POW_U64_BE_LEN; i++) {
        dst[POW_U64_BE_LEN - 1 - i] = (uint8_t) (value & 0xffU);
        value >>= 8;
    }
}
