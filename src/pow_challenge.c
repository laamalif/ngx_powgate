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
static size_t pow_u64_decimal_len(uint64_t value);
static void pow_write_u64_decimal(uint8_t *dst, size_t len, uint64_t value);


void
pow_ip16_from_ipv4(const uint8_t ipv4[POW_IPV4_LEN],
    uint8_t out[POW_IP_LEN])
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

    for (i = 0; i < POW_IPV4_LEN; i++) {
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

    if (ip16 == NULL || plen > POW_IP_PLEN_MAX) {
        return 0;
    }

    if (plen == POW_IP_PLEN_MAX) {
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
pow_challenge_body_len(size_t prefix_len, size_t json_len,
    size_t suffix_len, size_t *out)
{
    size_t  remaining;

    if (out == NULL || prefix_len >= POW_CHALLENGE_PAGE_MAX_BODY_LEN) {
        return 0;
    }

    remaining = POW_CHALLENGE_PAGE_MAX_BODY_LEN - prefix_len;

    if (json_len >= remaining) {
        return 0;
    }

    remaining -= json_len;

    if (suffix_len >= remaining) {
        return 0;
    }

    *out = prefix_len + json_len + suffix_len;

    return 1;
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

    if (secret == NULL || ip16 == NULL || nonce == NULL
        || plen > POW_IP_PLEN_MAX)
    {
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
pow_challenge_serialize(uint8_t difficulty, uint64_t bucket,
    const uint8_t nonce[POW_NONCE_LEN], uint8_t *buf, size_t buf_cap,
    pow_challenge_text_t *out)
{
    static const uint8_t   version_prefix[] =
        POW_CHALLENGE_VERSION_PREFIX;
    static const uint8_t   bucket_prefix[] = POW_CHALLENGE_BUCKET_PREFIX;
    static const uint8_t   nonce_prefix[] = POW_CHALLENGE_NONCE_PREFIX;
    pow_challenge_text_t    result;
    size_t                  encoded_len;
    size_t                  i;
    size_t                  offset;
    size_t                  required;

    if (difficulty < POW_DIFFICULTY_MIN
        || difficulty > POW_DIFFICULTY_MAX
        || nonce == NULL || buf == NULL || out == NULL)
    {
        return 0;
    }

    result.difficulty_len = pow_u64_decimal_len(difficulty);
    result.bucket_len = pow_u64_decimal_len(bucket);
    required = POW_CHALLENGE_VERSION_PREFIX_LEN + result.difficulty_len
               + POW_CHALLENGE_BUCKET_PREFIX_LEN + result.bucket_len
               + POW_CHALLENGE_NONCE_PREFIX_LEN + POW_NONCE_B64URL_LEN;

    if (buf_cap < required) {
        return 0;
    }

    offset = 0;

    for (i = 0; i < POW_CHALLENGE_VERSION_PREFIX_LEN; i++) {
        buf[offset++] = version_prefix[i];
    }

    result.difficulty_offset = offset;
    pow_write_u64_decimal(buf + offset, result.difficulty_len, difficulty);
    offset += result.difficulty_len;

    for (i = 0; i < POW_CHALLENGE_BUCKET_PREFIX_LEN; i++) {
        buf[offset++] = bucket_prefix[i];
    }

    result.bucket_offset = offset;
    pow_write_u64_decimal(buf + offset, result.bucket_len, bucket);
    offset += result.bucket_len;

    for (i = 0; i < POW_CHALLENGE_NONCE_PREFIX_LEN; i++) {
        buf[offset++] = nonce_prefix[i];
    }

    result.nonce_offset = offset;
    result.nonce_len = POW_NONCE_B64URL_LEN;
    encoded_len = pow_b64url_encode(nonce, POW_NONCE_LEN, buf + offset,
                                    buf_cap - offset);
    if (encoded_len != result.nonce_len) {
        return 0;
    }

    result.len = offset + encoded_len;
    *out = result;

    return 1;
}


pow_verify_result_t
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
        return POW_VERIFY_ERROR;
    }

    for (i = 0; i < POW_NONCE_LEN; i++) {
        message[i] = nonce[i];
    }

    for (i = 0; i < counter_len; i++) {
        message[POW_NONCE_LEN + i] = counter_ascii[i];
    }

    if (pow_sha256(message, POW_NONCE_LEN + counter_len, digest) == 0) {
        return POW_VERIFY_ERROR;
    }

    return pow_leading_zero_bits(digest) >= difficulty
           ? POW_VERIFY_VALID : POW_VERIFY_INVALID;
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


static size_t
pow_u64_decimal_len(uint64_t value)
{
    size_t  len;

    len = 1;

    while (value >= 10) {
        value /= 10;
        len++;
    }

    return len;
}


static void
pow_write_u64_decimal(uint8_t *dst, size_t len, uint64_t value)
{
    while (len != 0) {
        len--;
        dst[len] = (uint8_t) ('0' + value % 10);
        value /= 10;
    }
}
