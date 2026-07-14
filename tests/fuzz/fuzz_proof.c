#include <stddef.h>
#include <stdint.h>

#include "pow_challenge.h"
#include "pow_protocol.h"


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const uint8_t  ip16[POW_IP_LEN] = { 0 };
    static const uint8_t  secret[POW_SECRET_LEN] = { 0 };
    uint8_t               nonce[POW_NONCE_LEN];
    pow_proof_t           proof;

    if (pow_proof_cookie_parse(data, size, &proof) == 1
        && pow_bucket_within_skew(proof.bucket, UINT64_C(29333333)) == 1
        && pow_challenge_derive(secret, ip16, 56, proof.bucket, nonce) == 1)
    {
        (void) pow_proof_check(nonce, proof.counter_ascii,
                               proof.counter_len, POW_DIFFICULTY_MIN);
    }

    return 0;
}
