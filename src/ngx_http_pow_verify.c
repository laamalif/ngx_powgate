/*
 * Copyright (C) ngx_powgate authors
 */


#include "ngx_http_pow_verify.h"
#include "pow_challenge.h"
#include "pow_cookie.h"
#include "pow_cookie_scan.h"


#define NGX_HTTP_POW_AUTH_OCCURRENCE_MAX  4


#if defined(POW_TEST_FAIL_FIRST_SET_COOKIE) \
    && defined(POW_TEST_FAIL_SECOND_SET_COOKIE)
#error "only one PowGate Set-Cookie fault may be enabled"
#endif


static ngx_http_pow_verify_result_t ngx_http_pow_verify_proof(
    ngx_http_request_t *r, ngx_http_pow_main_conf_t *pmcf,
    ngx_http_pow_loc_conf_t *plcf, const uint8_t ip16[POW_IP_LEN],
    uint8_t plen, uint64_t now);
static ngx_int_t ngx_http_pow_issue_auth(ngx_http_request_t *r,
    ngx_http_pow_main_conf_t *pmcf, ngx_http_pow_loc_conf_t *plcf,
    const uint8_t ip16[POW_IP_LEN], uint8_t plen, uint64_t now);
static ngx_table_elt_t *ngx_http_pow_set_cookie_slot(ngx_http_request_t *r,
    ngx_uint_t ordinal);


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
        if (r != NULL && r->connection != NULL) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "pow_gate: operation=verify_request "
                          "verdict=failed");
        }

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
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
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
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
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
        ngx_log_error(plcf->log_level, ngx_cycle->log, 0,
                      "pow_gate: operation=auth verdict=invalid "
                      "occurrences=%ui", occurrences);
    }

    return ngx_http_pow_verify_proof(r, pmcf, plcf, ip16, plen, now);
}


static ngx_http_pow_verify_result_t
ngx_http_pow_verify_proof(ngx_http_request_t *r,
    ngx_http_pow_main_conf_t *pmcf, ngx_http_pow_loc_conf_t *plcf,
    const uint8_t ip16[POW_IP_LEN], uint8_t plen, uint64_t now)
{
    uint8_t                     nonce[POW_NONCE_LEN];
    uint8_t                     proof_ip16[POW_IP_LEN];
    uint64_t                    current_bucket;
    size_t                      cursor;
    ngx_int_t                   issue_rc;
    ngx_table_elt_t            *field;
    pow_cookie_scan_result_t    scan_rc;
    pow_cookie_value_t          value;
    pow_proof_t                 proof;
    pow_verify_result_t         verify_rc;

    for (field = r->headers_in.cookie; field != NULL; field = field->next) {
        cursor = 0;
        scan_rc = pow_cookie_scan_next(
            field->value.data, field->value.len,
            (const uint8_t *) POW_PROOF_COOKIE_NAME,
            sizeof(POW_PROOF_COOKIE_NAME) - 1, &cursor, &value
        );

        if (scan_rc == POW_COOKIE_SCAN_FOUND) {
            goto found;
        }

        if (scan_rc == POW_COOKIE_SCAN_ERROR) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "pow_gate: operation=proof_scan verdict=failed");
            return NGX_HTTP_POW_VERIFY_ERROR;
        }
    }

    return NGX_HTTP_POW_VERIFY_NONE;

found:

    if (value.len > POW_PROOF_COOKIE_MAX_LEN
        || pow_proof_cookie_parse(value.data, value.len, &proof) != 1)
    {
        goto invalid;
    }

    current_bucket = now / (uint64_t) plcf->challenge_window;

    if (pow_bucket_within_skew(proof.bucket, current_bucket) != 1) {
        goto invalid;
    }

    ngx_memcpy(proof_ip16, ip16, POW_IP_LEN);

    if (pow_ip16_mask(proof_ip16, plen) != 1
        || pow_challenge_derive(pmcf->secret, proof_ip16, plen, proof.bucket,
                                nonce)
           != 1)
    {
        goto error;
    }

    verify_rc = pow_proof_check(nonce, proof.counter_ascii,
                                proof.counter_len,
                                (uint8_t) plcf->difficulty);

    if (verify_rc == POW_VERIFY_ERROR) {
        goto error;
    }

    if (verify_rc == POW_VERIFY_INVALID && pmcf->has_prev) {
        if (pow_challenge_derive(pmcf->secret_prev, proof_ip16, plen,
                                 proof.bucket, nonce)
            != 1)
        {
            goto error;
        }

        verify_rc = pow_proof_check(nonce, proof.counter_ascii,
                                    proof.counter_len,
                                    (uint8_t) plcf->difficulty);

        if (verify_rc == POW_VERIFY_ERROR) {
            goto error;
        }
    }

    if (verify_rc == POW_VERIFY_INVALID) {
        goto invalid;
    }

    issue_rc = ngx_http_pow_issue_auth(r, pmcf, plcf, ip16, plen, now);
    if (issue_rc != NGX_OK) {
        goto issue_error;
    }

    return NGX_HTTP_POW_VERIFY_OK;

invalid:

    ngx_log_error(plcf->log_level, ngx_cycle->log, 0,
                  "pow_gate: operation=proof verdict=invalid "
                  "value_len=%uz", value.len);

    return NGX_HTTP_POW_VERIFY_NONE;

issue_error:

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                  "pow_gate: operation=cookie_issue verdict=failed");

    return NGX_HTTP_POW_VERIFY_ERROR;

error:

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                  "pow_gate: operation=proof_verify verdict=failed");

    return NGX_HTTP_POW_VERIFY_ERROR;
}


static ngx_int_t
ngx_http_pow_issue_auth(ngx_http_request_t *r,
    ngx_http_pow_main_conf_t *pmcf, ngx_http_pow_loc_conf_t *plcf,
    const uint8_t ip16[POW_IP_LEN], uint8_t plen, uint64_t now)
{
    u_char           *auth;
    u_char           *auth_end;
    u_char           *p;
    u_char           *proof_clear;
    const u_char     *suffix;
    u_char           *ttl_end;
    uint8_t          *auth_value;
    uint64_t          expiry;
    size_t            auth_len;
    size_t            built;
    size_t            suffix_len;
    size_t            ttl_len;
    u_char            ttl[NGX_TIME_T_LEN];
    ngx_table_elt_t   *auth_header;
    ngx_table_elt_t   *proof_header;

    if ((uint64_t) plcf->cookie_ttl > UINT64_MAX - now) {
        return NGX_ERROR;
    }

    expiry = now + (uint64_t) plcf->cookie_ttl;
    ttl_end = ngx_snprintf(ttl, sizeof(ttl), "%T", plcf->cookie_ttl);
    ttl_len = (size_t) (ttl_end - ttl);

    if (plcf->cookie_secure) {
        suffix = (const u_char *) POW_AUTH_SECURE_SUFFIX;
        suffix_len = sizeof(POW_AUTH_SECURE_SUFFIX) - 1;
    } else {
        suffix = (const u_char *) POW_AUTH_INSECURE_SUFFIX;
        suffix_len = sizeof(POW_AUTH_INSECURE_SUFFIX) - 1;
    }

    auth_len = plcf->cookie_name.len + 1 + POW_AUTH_COOKIE_WIRE_LEN
               + sizeof(POW_AUTH_MAX_AGE_PREFIX) - 1 + ttl_len
               + suffix_len;
    auth = ngx_pnalloc(r->pool, auth_len);
    if (auth == NULL) {
        return NGX_ERROR;
    }

    proof_clear = ngx_pnalloc(r->pool,
                              sizeof(POW_PROOF_COOKIE_CLEAR_VALUE) - 1);
    if (proof_clear == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(auth, plcf->cookie_name.data, plcf->cookie_name.len);
    *p++ = (u_char) POW_COOKIE_NAME_SEPARATOR;
    auth_value = p;
    built = pow_cookie_build(
        pmcf->secret, expiry, (uint8_t) plcf->difficulty, plen, ip16,
        auth_value, POW_AUTH_COOKIE_WIRE_LEN
    );
    if (built != POW_AUTH_COOKIE_WIRE_LEN) {
        return NGX_ERROR;
    }
    p += built;
    p = ngx_cpymem(p, POW_AUTH_MAX_AGE_PREFIX,
                   sizeof(POW_AUTH_MAX_AGE_PREFIX) - 1);
    p = ngx_cpymem(p, ttl, ttl_len);
    p = ngx_cpymem(p, suffix, suffix_len);
    auth_end = auth + auth_len;

    if (p != auth_end) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(proof_clear, POW_PROOF_COOKIE_CLEAR_VALUE,
                   sizeof(POW_PROOF_COOKIE_CLEAR_VALUE) - 1);
    if (p != proof_clear + sizeof(POW_PROOF_COOKIE_CLEAR_VALUE) - 1) {
        return NGX_ERROR;
    }

    auth_header = ngx_http_pow_set_cookie_slot(r, 1);
    if (auth_header == NULL) {
        return NGX_ERROR;
    }

    proof_header = ngx_http_pow_set_cookie_slot(r, 2);
    if (proof_header == NULL) {
        return NGX_ERROR;
    }

    ngx_str_set(&auth_header->key, POW_SET_COOKIE_HEADER_NAME);
    auth_header->value.data = auth;
    auth_header->value.len = auth_len;

    ngx_str_set(&proof_header->key, POW_SET_COOKIE_HEADER_NAME);
    proof_header->value.data = proof_clear;
    proof_header->value.len = sizeof(POW_PROOF_COOKIE_CLEAR_VALUE) - 1;

    auth_header->hash = 1;
    proof_header->hash = 1;

    return NGX_OK;
}


static ngx_table_elt_t *
ngx_http_pow_set_cookie_slot(ngx_http_request_t *r, ngx_uint_t ordinal)
{
    ngx_table_elt_t  *header;

#if defined(POW_TEST_FAIL_FIRST_SET_COOKIE)
    if (ordinal == 1) {
        return NULL;
    }
#endif

#if defined(POW_TEST_FAIL_SECOND_SET_COOKIE)
    if (ordinal == 2) {
        return NULL;
    }
#endif

    header = ngx_list_push(&r->headers_out.headers);
    if (header == NULL) {
        return NULL;
    }

    header->hash = 0;
    header->next = NULL;

    return header;
}
