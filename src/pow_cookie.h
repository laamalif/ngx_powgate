#ifndef POW_COOKIE_H
#define POW_COOKIE_H


#include <stddef.h>
#include <stdint.h>

#include "pow_protocol.h"


typedef struct {
    uint64_t  expiry;
    uint8_t   difficulty;
    uint8_t   plen;
    uint8_t   payload[POW_AUTH_PAYLOAD_LEN];
    uint8_t   mac[POW_AUTH_MAC_LEN];
} pow_cookie_t;


size_t pow_cookie_build(const uint8_t secret[POW_SECRET_LEN],
    uint64_t expiry, uint8_t difficulty, uint8_t plen,
    const uint8_t ip16[POW_IP_LEN], uint8_t *buf, size_t buflen);
int pow_cookie_parse(const uint8_t *buf, size_t len, pow_cookie_t *out);
int pow_cookie_verify(const uint8_t secret[POW_SECRET_LEN],
    const uint8_t *previous_secret, const pow_cookie_t *parsed,
    const uint8_t ip16[POW_IP_LEN], uint64_t now,
    uint8_t min_difficulty, uint8_t min_plen);


#endif /* POW_COOKIE_H */
