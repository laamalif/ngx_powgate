#ifndef POW_PROTOCOL_H
#define POW_PROTOCOL_H


#define POW_PROTOCOL_VERSION            1

#define POW_CHALLENGE_LABEL             "PGv1-chal"
#define POW_CHALLENGE_LABEL_LEN         9
#define POW_COOKIE_LABEL                "PGv1-cook"
#define POW_COOKIE_LABEL_LEN            9

#define POW_SECRET_LEN                  32
#define POW_IP_LEN                      16
#define POW_NONCE_LEN                   32
#define POW_DIGEST_LEN                  32
#define POW_AUTH_PAYLOAD_LEN            10
#define POW_AUTH_MAC_LEN                16

#define POW_AUTH_COOKIE_MAX_LEN         256
#define POW_PROOF_COOKIE_MAX_LEN        64

#define POW_AUTH_COOKIE_NAME            "__pow"
#define POW_PROOF_COOKIE_NAME           "__pow_p"

#define POW_CHALLENGE_WINDOW_DEFAULT    60
#define POW_COOKIE_TTL_DEFAULT          3600
#define POW_DIFFICULTY_MIN              1
#define POW_DIFFICULTY_MAX              32

#define POW_PROOF_COUNTER_MAX           9007199254740991ULL


#endif /* POW_PROTOCOL_H */
