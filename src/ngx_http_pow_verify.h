#ifndef NGX_HTTP_POW_VERIFY_H
#define NGX_HTTP_POW_VERIFY_H


#include "ngx_http_pow_module.h"


typedef enum {
    NGX_HTTP_POW_VERIFY_ERROR = -1,
    NGX_HTTP_POW_VERIFY_NONE = 0,
    NGX_HTTP_POW_VERIFY_OK = 1
} ngx_http_pow_verify_result_t;


ngx_http_pow_verify_result_t ngx_http_pow_verify_request(
    ngx_http_request_t *r, ngx_http_pow_main_conf_t *pmcf,
    ngx_http_pow_loc_conf_t *plcf, const uint8_t ip16[POW_IP_LEN],
    uint8_t plen, uint64_t now);


#endif /* NGX_HTTP_POW_VERIFY_H */
