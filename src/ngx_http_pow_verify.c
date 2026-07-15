/*
 * Copyright (C) ngx_powgate authors
 */


#include "ngx_http_pow_verify.h"
#include "pow_cookie.h"
#include "pow_cookie_scan.h"


#define NGX_HTTP_POW_AUTH_OCCURRENCE_MAX  4


ngx_http_pow_verify_result_t
ngx_http_pow_verify_request(ngx_http_request_t *r,
    ngx_http_pow_main_conf_t *pmcf, ngx_http_pow_loc_conf_t *plcf,
    const uint8_t ip16[POW_IP_LEN], uint8_t plen, uint64_t now)
{
    const uint8_t                  *previous_secret;
    size_t                          cursor;
    ngx_table_elt_t                *field;
    ngx_uint_t                      occurrences;
    pow_cookie_scan_result_t        scan_rc;
    pow_cookie_t                    parsed;
    pow_cookie_value_t              value;
    pow_verify_result_t             verify_rc;

    if (r == NULL || pmcf == NULL || plcf == NULL || ip16 == NULL
        || plen < POW_IP_PLEN_MIN || plen > POW_IP_PLEN_MAX)
    {
        return NGX_HTTP_POW_VERIFY_ERROR;
    }

    previous_secret = pmcf->has_prev ? pmcf->secret_prev : NULL;
    occurrences = 0;

    for (field = r->headers_in.cookie; field != NULL; field = field->next) {
        cursor = 0;

        while (occurrences < NGX_HTTP_POW_AUTH_OCCURRENCE_MAX) {
            scan_rc = pow_cookie_scan_next(
                field->value.data, field->value.len,
                plcf->cookie_name.data, plcf->cookie_name.len,
                &cursor, &value
            );

            if (scan_rc == POW_COOKIE_SCAN_DONE) {
                break;
            }

            if (scan_rc == POW_COOKIE_SCAN_ERROR) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "pow_gate: operation=auth_scan "
                              "verdict=failed");
                return NGX_HTTP_POW_VERIFY_ERROR;
            }

            occurrences++;

            if (value.len > POW_AUTH_COOKIE_MAX_LEN
                || pow_cookie_parse(value.data, value.len, &parsed) != 1)
            {
                continue;
            }

            verify_rc = pow_cookie_verify(
                pmcf->secret, previous_secret, &parsed, ip16, now,
                (uint8_t) plcf->difficulty, plen
            );

            if (verify_rc == POW_VERIFY_VALID) {
                return NGX_HTTP_POW_VERIFY_OK;
            }

            if (verify_rc == POW_VERIFY_ERROR) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "pow_gate: operation=auth_verify "
                              "verdict=failed");
                return NGX_HTTP_POW_VERIFY_ERROR;
            }
        }

        if (occurrences == NGX_HTTP_POW_AUTH_OCCURRENCE_MAX) {
            break;
        }
    }

    if (occurrences != 0) {
        ngx_log_error(plcf->log_level, r->connection->log, 0,
                      "pow_gate: operation=auth verdict=invalid "
                      "occurrences=%ui", occurrences);
    }

    return NGX_HTTP_POW_VERIFY_NONE;
}
