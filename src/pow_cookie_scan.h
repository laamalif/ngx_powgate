#ifndef POW_COOKIE_SCAN_H
#define POW_COOKIE_SCAN_H


#include <stddef.h>
#include <stdint.h>


typedef struct {
    const uint8_t  *data;
    size_t          len;
} pow_cookie_value_t;


typedef enum {
    POW_COOKIE_SCAN_ERROR = -1,
    POW_COOKIE_SCAN_DONE = 0,
    POW_COOKIE_SCAN_FOUND = 1
} pow_cookie_scan_result_t;


pow_cookie_scan_result_t pow_cookie_scan_next(
    const uint8_t *field, size_t field_len,
    const uint8_t *name, size_t name_len,
    size_t *cursor, pow_cookie_value_t *out);


#endif /* POW_COOKIE_SCAN_H */
