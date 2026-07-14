#ifndef POW_PARSE_H
#define POW_PARSE_H


#include <stddef.h>
#include <stdint.h>


typedef struct {
    const uint8_t  *data;
    size_t          len;
} pow_span_t;


int pow_split_dot_fields(const uint8_t *buf, size_t len,
    pow_span_t *fields, size_t field_count);
int pow_parse_u64(const uint8_t *buf, size_t len, size_t max_digits,
    uint64_t max_value, uint64_t *out);
size_t pow_b64url_encoded_len(size_t input_len);
size_t pow_b64url_encode(const uint8_t *src, size_t src_len,
    uint8_t *dst, size_t dst_cap);
int pow_b64url_decode_exact(const uint8_t *src, size_t src_len,
    uint8_t *dst, size_t expected_len);


#endif /* POW_PARSE_H */
