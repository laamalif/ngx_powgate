/*
 * Copyright (C) ngx_powgate authors
 */


#include <stddef.h>
#include <stdint.h>

#include "pow_challenge.h"
#include "pow_cookie.h"
#include "pow_crypto.h"
#include "pow_parse.h"
#include "pow_protocol.h"


static int pow_cookie_mac(const uint8_t secret[POW_SECRET_LEN],
    const uint8_t payload[POW_AUTH_PAYLOAD_LEN],
    const uint8_t ip16[POW_IP_LEN], uint8_t mac[POW_AUTH_MAC_LEN]);
static uint64_t pow_read_u64_be(const uint8_t *src);
static void pow_write_u64_be(uint8_t *dst, uint64_t value);


size_t
pow_cookie_build(const uint8_t secret[POW_SECRET_LEN], uint64_t expiry,
    uint8_t difficulty, uint8_t plen, const uint8_t ip16[POW_IP_LEN],
    uint8_t *buf, size_t buflen)
{
    uint8_t  ip_masked[POW_IP_LEN];
    uint8_t  mac[POW_AUTH_MAC_LEN];
    uint8_t  payload[POW_AUTH_PAYLOAD_LEN];
    size_t   i;
    size_t   len;
    size_t   offset;

    if (secret == NULL || ip16 == NULL || buf == NULL
        || buflen < POW_AUTH_COOKIE_WIRE_LEN
        || difficulty < POW_DIFFICULTY_MIN
        || difficulty > POW_DIFFICULTY_MAX || plen < POW_IP_PLEN_MIN
        || plen > POW_IP_PLEN_MAX)
    {
        return 0;
    }

    pow_write_u64_be(payload + POW_AUTH_EXPIRY_OFFSET, expiry);
    payload[POW_AUTH_DIFFICULTY_OFFSET] = difficulty;
    payload[POW_AUTH_PLEN_OFFSET] = plen;

    for (i = 0; i < POW_IP_LEN; i++) {
        ip_masked[i] = ip16[i];
    }

    if (pow_ip16_mask(ip_masked, plen) == 0
        || pow_cookie_mac(secret, payload, ip_masked, mac) == 0)
    {
        return 0;
    }

    offset = 0;
    buf[offset++] = (uint8_t) POW_VERSION_TEXT[0];
    buf[offset++] = (uint8_t) POW_FIELD_SEPARATOR;

    len = pow_b64url_encode(payload, POW_AUTH_PAYLOAD_LEN, buf + offset,
                            buflen - offset);
    if (len != POW_AUTH_PAYLOAD_B64_LEN) {
        return 0;
    }
    offset += len;
    buf[offset++] = (uint8_t) POW_FIELD_SEPARATOR;

    len = pow_b64url_encode(mac, POW_AUTH_MAC_LEN, buf + offset,
                            buflen - offset);
    if (len != POW_AUTH_MAC_B64_LEN) {
        return 0;
    }
    offset += len;

    return offset == POW_AUTH_COOKIE_WIRE_LEN ? offset : 0;
}


int
pow_cookie_parse(const uint8_t *buf, size_t len, pow_cookie_t *out)
{
    pow_span_t  fields[POW_AUTH_FIELD_COUNT];
    uint8_t     mac[POW_AUTH_MAC_LEN];
    uint8_t     payload[POW_AUTH_PAYLOAD_LEN];
    size_t      i;

    if (buf == NULL || out == NULL || len > POW_AUTH_COOKIE_MAX_LEN) {
        return 0;
    }

    if (pow_split_dot_fields(buf, len, fields, POW_AUTH_FIELD_COUNT) == 0) {
        return 0;
    }

    if (fields[0].len != POW_VERSION_TEXT_LEN
        || fields[0].data[0] != (uint8_t) POW_VERSION_TEXT[0])
    {
        return 0;
    }

    if (fields[1].len != POW_AUTH_PAYLOAD_B64_LEN
        || pow_b64url_decode_exact(fields[1].data, fields[1].len, payload,
                                   POW_AUTH_PAYLOAD_LEN)
           == 0)
    {
        return 0;
    }

    if (fields[2].len != POW_AUTH_MAC_B64_LEN
        || pow_b64url_decode_exact(fields[2].data, fields[2].len, mac,
                                   POW_AUTH_MAC_LEN)
           == 0)
    {
        return 0;
    }

    if (payload[POW_AUTH_DIFFICULTY_OFFSET] < POW_DIFFICULTY_MIN
        || payload[POW_AUTH_DIFFICULTY_OFFSET] > POW_DIFFICULTY_MAX
        || payload[POW_AUTH_PLEN_OFFSET] < POW_IP_PLEN_MIN
        || payload[POW_AUTH_PLEN_OFFSET] > POW_IP_PLEN_MAX)
    {
        return 0;
    }

    out->expiry = pow_read_u64_be(payload + POW_AUTH_EXPIRY_OFFSET);
    out->difficulty = payload[POW_AUTH_DIFFICULTY_OFFSET];
    out->plen = payload[POW_AUTH_PLEN_OFFSET];

    for (i = 0; i < POW_AUTH_PAYLOAD_LEN; i++) {
        out->payload[i] = payload[i];
    }

    for (i = 0; i < POW_AUTH_MAC_LEN; i++) {
        out->mac[i] = mac[i];
    }

    return 1;
}


pow_verify_result_t
pow_cookie_verify(const uint8_t secret[POW_SECRET_LEN],
    const uint8_t *previous_secret, const pow_cookie_t *parsed,
    const uint8_t ip16[POW_IP_LEN], uint64_t now, uint8_t min_difficulty,
    uint8_t min_plen)
{
    const uint8_t  *second_secret;
    uint8_t         current_mac[POW_AUTH_MAC_LEN];
    uint8_t         ip_masked[POW_IP_LEN];
    uint8_t         second_mac[POW_AUTH_MAC_LEN];
    int             current_match;
    int             second_match;
    size_t          i;

    if (secret == NULL || parsed == NULL || ip16 == NULL
        || min_difficulty < POW_DIFFICULTY_MIN
        || min_difficulty > POW_DIFFICULTY_MAX
        || min_plen < POW_IP_PLEN_MIN || min_plen > POW_IP_PLEN_MAX
        || parsed->difficulty < POW_DIFFICULTY_MIN
        || parsed->difficulty > POW_DIFFICULTY_MAX
        || parsed->plen < POW_IP_PLEN_MIN
        || parsed->plen > POW_IP_PLEN_MAX)
    {
        return POW_VERIFY_ERROR;
    }

    for (i = 0; i < POW_IP_LEN; i++) {
        ip_masked[i] = ip16[i];
    }

    if (pow_ip16_mask(ip_masked, parsed->plen) == 0
        || pow_cookie_mac(secret, parsed->payload, ip_masked, current_mac) == 0)
    {
        return POW_VERIFY_ERROR;
    }

    current_match = pow_ct_eq(current_mac, parsed->mac, POW_AUTH_MAC_LEN);

    if (current_match == 0) {
        second_secret = previous_secret != NULL ? previous_secret : secret;

        if (pow_cookie_mac(second_secret, parsed->payload, ip_masked,
                           second_mac)
            == 0)
        {
            return POW_VERIFY_ERROR;
        }

        second_match = pow_ct_eq(second_mac, parsed->mac, POW_AUTH_MAC_LEN);

        if (previous_secret == NULL || second_match == 0) {
            return POW_VERIFY_INVALID;
        }
    }

    if (parsed->expiry <= now || parsed->difficulty < min_difficulty
        || parsed->plen < min_plen)
    {
        return POW_VERIFY_INVALID;
    }

    return POW_VERIFY_VALID;
}


static int
pow_cookie_mac(const uint8_t secret[POW_SECRET_LEN],
    const uint8_t payload[POW_AUTH_PAYLOAD_LEN],
    const uint8_t ip16[POW_IP_LEN], uint8_t mac[POW_AUTH_MAC_LEN])
{
    static const uint8_t  label[] = POW_COOKIE_LABEL;
    uint8_t               digest[POW_DIGEST_LEN];
    uint8_t               message[POW_COOKIE_LABEL_LEN
                                  + POW_AUTH_PAYLOAD_LEN + POW_IP_LEN];
    size_t                i;
    size_t                offset;

    if (secret == NULL || payload == NULL || ip16 == NULL || mac == NULL) {
        return 0;
    }

    offset = 0;

    for (i = 0; i < POW_COOKIE_LABEL_LEN; i++) {
        message[offset++] = label[i];
    }

    for (i = 0; i < POW_AUTH_PAYLOAD_LEN; i++) {
        message[offset++] = payload[i];
    }

    for (i = 0; i < POW_IP_LEN; i++) {
        message[offset++] = ip16[i];
    }

    if (pow_hmac_sha256(secret, POW_SECRET_LEN, message, sizeof(message),
                        digest)
        == 0)
    {
        return 0;
    }

    for (i = 0; i < POW_AUTH_MAC_LEN; i++) {
        mac[i] = digest[i];
    }

    return 1;
}


static uint64_t
pow_read_u64_be(const uint8_t *src)
{
    uint64_t  value;
    size_t    i;

    value = 0;

    for (i = 0; i < POW_U64_BE_LEN; i++) {
        value = (value << 8) | src[i];
    }

    return value;
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
