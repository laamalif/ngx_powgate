#include <stddef.h>
#include <stdint.h>

#include "pow_cookie.h"
#include "pow_protocol.h"


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const uint8_t  ip16[POW_IP_LEN] = { 0 };
    static const uint8_t  previous[POW_SECRET_LEN] = { 1 };
    static const uint8_t  secret[POW_SECRET_LEN] = { 0 };
    pow_cookie_t          parsed;

    if (pow_cookie_parse(data, size, &parsed) == 1) {
        (void) pow_cookie_verify(secret, previous, &parsed, ip16, 0,
                                 POW_DIFFICULTY_MIN, POW_IP_PLEN_MIN);
    }

    return 0;
}
