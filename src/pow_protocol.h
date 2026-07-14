#ifndef POW_PROTOCOL_H
#define POW_PROTOCOL_H


#define POW_PROTOCOL_VERSION            1
#define POW_VERSION_TEXT                "1"
#define POW_VERSION_TEXT_LEN            1
#define POW_FIELD_SEPARATOR             '.'
#define POW_B64URL_ALPHABET             \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

#define POW_CHALLENGE_LABEL             "PGv1-chal"
#define POW_CHALLENGE_LABEL_LEN         9
#define POW_COOKIE_LABEL                "PGv1-cook"
#define POW_COOKIE_LABEL_LEN            9

#define POW_SECRET_LEN                  32
#define POW_IPV4_LEN                    4
#define POW_IP_LEN                      16
#define POW_IP_PLEN_MIN                 32
#define POW_IP_PLEN_MAX                 128
#define POW_NONCE_LEN                   32
#define POW_DIGEST_LEN                  32
#define POW_AUTH_PAYLOAD_LEN            10
#define POW_AUTH_MAC_LEN                16
#define POW_U64_BE_LEN                  8

#define POW_PROOF_FIELD_COUNT           3
#define POW_AUTH_FIELD_COUNT            3
#define POW_BUCKET_DECIMAL_MAX_LEN      20
#define POW_COUNTER_DECIMAL_MAX_LEN     16

#define POW_AUTH_PAYLOAD_B64_LEN        14
#define POW_AUTH_MAC_B64_LEN            22
#define POW_AUTH_COOKIE_WIRE_LEN        39

#define POW_AUTH_EXPIRY_OFFSET          0
#define POW_AUTH_DIFFICULTY_OFFSET      8
#define POW_AUTH_PLEN_OFFSET            9

#define POW_IPV4_MAPPED_FF_OFFSET       10
#define POW_IPV4_MAPPED_ADDR_OFFSET     12

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
