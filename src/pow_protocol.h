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
#define POW_CHALLENGE_HEADER_NAME       "PowGate-Challenge"
#define POW_CHALLENGE_VERSION_PREFIX    "v=" POW_VERSION_TEXT "; d="
#define POW_CHALLENGE_VERSION_PREFIX_LEN 7
#define POW_CHALLENGE_BUCKET_PREFIX     "; b="
#define POW_CHALLENGE_BUCKET_PREFIX_LEN 4
#define POW_CHALLENGE_NONCE_PREFIX      "; n="
#define POW_CHALLENGE_NONCE_PREFIX_LEN  4

#define POW_CHALLENGE_JSON_PREFIX       \
    "<script type=\"application/json\" id=\"pow-params\">{\"v\":" \
    POW_VERSION_TEXT ",\"d\":"
#define POW_CHALLENGE_JSON_BUCKET_PREFIX ",\"b\":\""
#define POW_CHALLENGE_JSON_NONCE_PREFIX "\",\"n\":\""
#define POW_CHALLENGE_JSON_SUFFIX       "\"}</script>"

#define POW_CSP_HASH_MARKER             "<H>"
#define POW_CSP_HASH_MARKER_LEN         3
#define POW_CSP_SCRIPT_HASH_LEN         44
#define POW_CSP_POLICY_TEMPLATE         \
    "default-src 'none'; base-uri 'none'; form-action 'none'; " \
    "frame-ancestors 'none'; script-src 'sha256-" \
    POW_CSP_HASH_MARKER "'; style-src 'unsafe-inline'"

#define POW_HTML_MEDIA_TYPE             "text/html"
#define POW_HTML_MEDIA_TYPE_LEN         9
#define POW_HTML_CONTENT_TYPE           POW_HTML_MEDIA_TYPE "; charset=utf-8"
#define POW_CACHE_CONTROL_HEADER_NAME   "Cache-Control"
#define POW_CACHE_CONTROL_HEADER_VALUE  "no-store"
#define POW_ROBOTS_HEADER_NAME          "X-Robots-Tag"
#define POW_ROBOTS_HEADER_VALUE         "noindex"
#define POW_CSP_HEADER_NAME             "Content-Security-Policy"

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
#define POW_DIFFICULTY_DECIMAL_MAX_LEN  2
#define POW_BUCKET_DECIMAL_MAX_LEN      20
#define POW_COUNTER_DECIMAL_MAX_LEN     16
#define POW_NONCE_B64URL_LEN             43
#define POW_CHALLENGE_WIRE_MAX_LEN       \
    (POW_CHALLENGE_VERSION_PREFIX_LEN + POW_DIFFICULTY_DECIMAL_MAX_LEN \
     + POW_CHALLENGE_BUCKET_PREFIX_LEN + POW_BUCKET_DECIMAL_MAX_LEN \
     + POW_CHALLENGE_NONCE_PREFIX_LEN + POW_NONCE_B64URL_LEN)
#define POW_CHALLENGE_JSON_MAX_LEN       \
    (sizeof(POW_CHALLENGE_JSON_PREFIX) - 1 \
     + POW_DIFFICULTY_DECIMAL_MAX_LEN \
     + sizeof(POW_CHALLENGE_JSON_BUCKET_PREFIX) - 1 \
     + POW_BUCKET_DECIMAL_MAX_LEN \
     + sizeof(POW_CHALLENGE_JSON_NONCE_PREFIX) - 1 \
     + POW_NONCE_B64URL_LEN + sizeof(POW_CHALLENGE_JSON_SUFFIX) - 1)
#define POW_CHALLENGE_PAGE_MAX_BODY_LEN 15360

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
#define POW_COOKIE_NAME_SEPARATOR       '='
#define POW_SET_COOKIE_HEADER_NAME      "Set-Cookie"
#define POW_AUTH_MAX_AGE_PREFIX         "; Max-Age="
#define POW_AUTH_SECURE_SUFFIX          \
    "; Path=/; Secure; HttpOnly; SameSite=Lax"
#define POW_AUTH_INSECURE_SUFFIX        "; Path=/; HttpOnly; SameSite=Lax"
#define POW_PROOF_COOKIE_CLEAR_VALUE    \
    POW_PROOF_COOKIE_NAME "=; Max-Age=0; Path=/"

#define POW_CHALLENGE_WINDOW_DEFAULT    60
#define POW_COOKIE_TTL_DEFAULT          3600
#define POW_DIFFICULTY_MIN              1
#define POW_DIFFICULTY_MAX              32
#define POW_DIFFICULTY_DEFAULT          20
#define POW_BIND_IPV4_MIN               8
#define POW_BIND_IPV4_MAX               32
#define POW_BIND_IPV4_DEFAULT           32
#define POW_BIND_IPV6_MIN               POW_IP_PLEN_MIN
#define POW_BIND_IPV6_MAX               POW_IP_PLEN_MAX
#define POW_BIND_IPV6_DEFAULT           56

#define POW_PROOF_COUNTER_MAX           9007199254740991ULL


#endif /* POW_PROTOCOL_H */
