/*
 * Copyright (C) ngx_powgate authors
 */


#include "ngx_http_pow_module.h"
#include "ngx_http_pow_verify.h"
#include "pow_challenge.h"
#include "pow_challenge_page.h"


#define NGX_HTTP_POW_ADDR_IPV4  1
#define NGX_HTTP_POW_ADDR_IPV6  2


static ngx_int_t ngx_http_pow_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_pow_connection_kind(ngx_http_request_t *r,
    ngx_uint_t *kind);
static ngx_int_t ngx_http_pow_ip_exempt(ngx_http_request_t *r,
    ngx_http_pow_loc_conf_t *plcf);
static ngx_int_t ngx_http_pow_path_exempt(ngx_http_request_t *r,
    ngx_http_pow_loc_conf_t *plcf);
static ngx_int_t ngx_http_pow_client_identity(ngx_http_request_t *r,
    ngx_http_pow_loc_conf_t *plcf, ngx_uint_t kind,
    uint8_t ip16[POW_IP_LEN], uint8_t *plen);
static ngx_int_t ngx_http_pow_issue_bare(ngx_http_request_t *r,
    const uint8_t *challenge, size_t challenge_len);
static ngx_int_t ngx_http_pow_is_navigation(ngx_http_request_t *r);
static ngx_int_t ngx_http_pow_build_csp(ngx_http_request_t *r,
    ngx_str_t *csp);
static ngx_int_t ngx_http_pow_issue_html(ngx_http_request_t *r,
    const uint8_t *challenge, const pow_challenge_text_t *challenge_text);
static ngx_int_t ngx_http_pow_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_pow_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_pow_init,                     /* postconfiguration */

    ngx_http_pow_create_main_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_pow_create_loc_conf,          /* create location configuration */
    ngx_http_pow_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_pow_module = {
    NGX_MODULE_V1,
    &ngx_http_pow_module_ctx,              /* module context */
    ngx_http_pow_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_pow_handler(ngx_http_request_t *r)
{
    uint8_t                       challenge[POW_CHALLENGE_WIRE_MAX_LEN];
    uint8_t                       challenge_ip16[POW_IP_LEN];
    uint8_t                       ip16[POW_IP_LEN];
    uint8_t                       nonce[POW_NONCE_LEN];
    uint8_t                       plen;
    time_t                        now;
    uint64_t                      bucket;
    ngx_int_t                     rc;
    ngx_uint_t                    kind;
    pow_challenge_text_t          challenge_text;
    ngx_http_pow_verify_result_t  verify_rc;
    ngx_http_pow_loc_conf_t      *plcf;
    ngx_http_pow_main_conf_t     *pmcf;

    if (r != r->main || r->internal) {
        return NGX_DECLINED;
    }

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_pow_module);

    if (plcf->enable == 0) {
        return NGX_DECLINED;
    }

    rc = ngx_http_pow_connection_kind(r, &kind);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "pow_gate: unsupported connection address family %d, "
                      "request rejected",
                      r->connection->sockaddr->sa_family);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_pow_ip_exempt(r, plcf);
    if (rc == NGX_OK) {
        return NGX_DECLINED;
    }
    if (rc != NGX_DECLINED) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_pow_path_exempt(r, plcf) == NGX_OK) {
        return NGX_DECLINED;
    }

    if (ngx_http_pow_client_identity(r, plcf, kind, ip16, &plen)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "pow_gate: operation=client_identity verdict=failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    now = ngx_time();
    if (now < 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "pow_gate: operation=time_bucket verdict=failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    bucket = (uint64_t) now / (uint64_t) plcf->challenge_window;
    pmcf = ngx_http_get_module_main_conf(r, ngx_http_pow_module);

    verify_rc = ngx_http_pow_verify_request(r, pmcf, plcf, ip16, plen,
                                            (uint64_t) now);

    if (verify_rc == NGX_HTTP_POW_VERIFY_OK) {
        return NGX_DECLINED;
    }

    if (verify_rc == NGX_HTTP_POW_VERIFY_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(challenge_ip16, ip16, POW_IP_LEN);

    if (pow_ip16_mask(challenge_ip16, plen) != 1
        || pow_challenge_derive(pmcf->secret, challenge_ip16, plen, bucket,
                                nonce)
           != 1
        || pow_challenge_serialize((uint8_t) plcf->difficulty, bucket, nonce,
                                   challenge, sizeof(challenge),
                                   &challenge_text) != 1)
    {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "pow_gate: operation=challenge_format verdict=failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    if (ngx_http_pow_is_navigation(r) == NGX_OK) {
        return ngx_http_pow_issue_html(r, challenge, &challenge_text);
    }

    return ngx_http_pow_issue_bare(r, challenge, challenge_text.len);
}


static ngx_int_t
ngx_http_pow_connection_kind(ngx_http_request_t *r, ngx_uint_t *kind)
{
    struct sockaddr_in6  *sin6;

    switch (r->connection->sockaddr->sa_family) {

    case AF_INET:
        *kind = NGX_HTTP_POW_ADDR_IPV4;
        return NGX_OK;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;

        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            *kind = NGX_HTTP_POW_ADDR_IPV4;
        } else {
            *kind = NGX_HTTP_POW_ADDR_IPV6;
        }

        return NGX_OK;
#endif
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_pow_ip_exempt(ngx_http_request_t *r,
    ngx_http_pow_loc_conf_t *plcf)
{
    ngx_int_t  rc;

    if (plcf->exempt_ips == NULL) {
        return NGX_DECLINED;
    }

    rc = ngx_cidr_match(r->connection->sockaddr, plcf->exempt_ips);

    if (rc == NGX_OK || rc == NGX_DECLINED) {
        return rc;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_pow_path_exempt(ngx_http_request_t *r,
    ngx_http_pow_loc_conf_t *plcf)
{
    ngx_str_t  *path;
    ngx_uint_t  i;

    if (plcf->exempt_paths == NULL) {
        return NGX_DECLINED;
    }

    path = plcf->exempt_paths->elts;

    for (i = 0; i < plcf->exempt_paths->nelts; i++) {
        if (path[i].len == 1 && path[i].data[0] == '/') {
            return NGX_OK;
        }

        if (r->uri.len < path[i].len
            || ngx_strncmp(r->uri.data, path[i].data, path[i].len) != 0)
        {
            continue;
        }

        if (r->uri.len == path[i].len
            || r->uri.data[path[i].len] == '/')
        {
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_pow_client_identity(ngx_http_request_t *r,
    ngx_http_pow_loc_conf_t *plcf, ngx_uint_t kind,
    uint8_t ip16[POW_IP_LEN], uint8_t *plen)
{
    uint8_t              *address;
    struct sockaddr_in   *sin;
    struct sockaddr_in6  *sin6;

    if (kind == NGX_HTTP_POW_ADDR_IPV4) {
        if (r->connection->sockaddr->sa_family == AF_INET) {
            sin = (struct sockaddr_in *) r->connection->sockaddr;
            address = (uint8_t *) &sin->sin_addr;
        } else {
            sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
            address = (uint8_t *) &sin6->sin6_addr
                      + POW_IPV4_MAPPED_ADDR_OFFSET;
        }

        pow_ip16_from_ipv4(address, ip16);
        *plen = (uint8_t) (96 + plcf->bind_ipv4);

    } else if (kind == NGX_HTTP_POW_ADDR_IPV6) {
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        pow_ip16_from_ipv6((uint8_t *) &sin6->sin6_addr, ip16);
        *plen = (uint8_t) plcf->bind_ipv6;

    } else {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_pow_issue_bare(ngx_http_request_t *r, const uint8_t *challenge,
    size_t challenge_len)
{
    u_char           *value;
    ngx_int_t         rc;
    ngx_table_elt_t  *header;

    value = ngx_pnalloc(r->pool, challenge_len);
    if (value == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(value, challenge, challenge_len);

    header = ngx_list_push(&r->headers_out.headers);
    if (header == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    header->hash = 0;
    header->next = NULL;
    ngx_str_set(&header->key, POW_CHALLENGE_HEADER_NAME);
    header->value.len = challenge_len;
    header->value.data = value;

    r->headers_out.status = NGX_HTTP_FORBIDDEN;
    r->headers_out.content_length_n = 0;
    header->hash = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_OK && !r->header_only) {
        rc = ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    ngx_http_finalize_request(r, rc);

    return NGX_DONE;
}


static ngx_int_t
ngx_http_pow_is_navigation(ngx_http_request_t *r)
{
    ngx_table_elt_t  *accept;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    for (accept = r->headers_in.accept; accept; accept = accept->next) {
        if (accept->value.len < POW_HTML_MEDIA_TYPE_LEN) {
            continue;
        }

        if (ngx_strlcasestrn(accept->value.data,
                             accept->value.data + accept->value.len,
                             (u_char *) POW_HTML_MEDIA_TYPE,
                             POW_HTML_MEDIA_TYPE_LEN - 1)
            != NULL)
        {
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_pow_build_csp(ngx_http_request_t *r, ngx_str_t *csp)
{
    static u_char  policy[] = POW_CSP_POLICY_TEMPLATE;
    u_char        *after;
    u_char        *marker;
    u_char        *p;
    size_t         after_len;
    size_t         policy_len;
    size_t         prefix_len;

    policy_len = sizeof(POW_CSP_POLICY_TEMPLATE) - 1;

    if (ngx_http_pow_script_sha256_base64_len != POW_CSP_SCRIPT_HASH_LEN) {
        return NGX_ERROR;
    }

    marker = ngx_strnstr(policy, POW_CSP_HASH_MARKER, policy_len);
    if (marker == NULL) {
        return NGX_ERROR;
    }

    after = marker + POW_CSP_HASH_MARKER_LEN;
    after_len = policy + policy_len - after;

    if (ngx_strnstr(after, POW_CSP_HASH_MARKER, after_len) != NULL) {
        return NGX_ERROR;
    }

    prefix_len = marker - policy;
    csp->len = policy_len - POW_CSP_HASH_MARKER_LEN
               + POW_CSP_SCRIPT_HASH_LEN;
    csp->data = ngx_pnalloc(r->pool, csp->len);
    if (csp->data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(csp->data, policy, prefix_len);
    p = ngx_cpymem(p, ngx_http_pow_script_sha256_base64,
                   ngx_http_pow_script_sha256_base64_len);
    p = ngx_cpymem(p, after, after_len);

    if (p != csp->data + csp->len) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_pow_issue_html(ngx_http_request_t *r, const uint8_t *challenge,
    const pow_challenge_text_t *challenge_text)
{
    u_char           *challenge_value;
    u_char           *json;
    u_char           *p;
    size_t            body_len;
    size_t            json_len;
    ngx_buf_t        *body[3];
    ngx_chain_t      *chain[3];
    ngx_int_t         rc;
    ngx_str_t         csp;
    ngx_table_elt_t  *cache_control;
    ngx_table_elt_t  *challenge_header;
    ngx_table_elt_t  *csp_header;
    ngx_table_elt_t  *robots;

    challenge_value = ngx_pnalloc(r->pool, challenge_text->len);
    if (challenge_value == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(challenge_value, challenge, challenge_text->len);

    json_len = sizeof(POW_CHALLENGE_JSON_PREFIX) - 1
               + challenge_text->difficulty_len
               + sizeof(POW_CHALLENGE_JSON_BUCKET_PREFIX) - 1
               + challenge_text->bucket_len
               + sizeof(POW_CHALLENGE_JSON_NONCE_PREFIX) - 1
               + challenge_text->nonce_len
               + sizeof(POW_CHALLENGE_JSON_SUFFIX) - 1;
    json = ngx_pnalloc(r->pool, json_len);
    if (json == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(json, POW_CHALLENGE_JSON_PREFIX,
                   sizeof(POW_CHALLENGE_JSON_PREFIX) - 1);
    p = ngx_cpymem(p, challenge + challenge_text->difficulty_offset,
                   challenge_text->difficulty_len);
    p = ngx_cpymem(p, POW_CHALLENGE_JSON_BUCKET_PREFIX,
                   sizeof(POW_CHALLENGE_JSON_BUCKET_PREFIX) - 1);
    p = ngx_cpymem(p, challenge + challenge_text->bucket_offset,
                   challenge_text->bucket_len);
    p = ngx_cpymem(p, POW_CHALLENGE_JSON_NONCE_PREFIX,
                   sizeof(POW_CHALLENGE_JSON_NONCE_PREFIX) - 1);
    p = ngx_cpymem(p, challenge + challenge_text->nonce_offset,
                   challenge_text->nonce_len);
    p = ngx_cpymem(p, POW_CHALLENGE_JSON_SUFFIX,
                   sizeof(POW_CHALLENGE_JSON_SUFFIX) - 1);

    if (p != json + json_len || ngx_http_pow_build_csp(r, &csp) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    body[0] = ngx_calloc_buf(r->pool);
    body[1] = ngx_calloc_buf(r->pool);
    body[2] = ngx_calloc_buf(r->pool);
    chain[0] = ngx_alloc_chain_link(r->pool);
    chain[1] = ngx_alloc_chain_link(r->pool);
    chain[2] = ngx_alloc_chain_link(r->pool);

    if (body[0] == NULL || body[1] == NULL || body[2] == NULL
        || chain[0] == NULL || chain[1] == NULL || chain[2] == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    challenge_header = ngx_list_push(&r->headers_out.headers);
    if (challenge_header == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    challenge_header->hash = 0;
    challenge_header->next = NULL;

    cache_control = ngx_list_push(&r->headers_out.headers);
    if (cache_control == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    cache_control->hash = 0;
    cache_control->next = NULL;

    robots = ngx_list_push(&r->headers_out.headers);
    if (robots == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    robots->hash = 0;
    robots->next = NULL;

    csp_header = ngx_list_push(&r->headers_out.headers);
    if (csp_header == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    csp_header->hash = 0;
    csp_header->next = NULL;

    ngx_str_set(&challenge_header->key, POW_CHALLENGE_HEADER_NAME);
    challenge_header->value.data = challenge_value;
    challenge_header->value.len = challenge_text->len;
    ngx_str_set(&cache_control->key, POW_CACHE_CONTROL_HEADER_NAME);
    ngx_str_set(&cache_control->value, POW_CACHE_CONTROL_HEADER_VALUE);
    ngx_str_set(&robots->key, POW_ROBOTS_HEADER_NAME);
    ngx_str_set(&robots->value, POW_ROBOTS_HEADER_VALUE);
    ngx_str_set(&csp_header->key, POW_CSP_HEADER_NAME);
    csp_header->value = csp;

    body[0]->pos = (u_char *) ngx_http_pow_challenge_prefix;
    body[0]->last = body[0]->pos + ngx_http_pow_challenge_prefix_len;
    body[0]->memory = 1;
    body[1]->pos = json;
    body[1]->last = json + json_len;
    body[1]->memory = 1;
    body[2]->pos = (u_char *) ngx_http_pow_challenge_suffix;
    body[2]->last = body[2]->pos + ngx_http_pow_challenge_suffix_len;
    body[2]->memory = 1;
    body[2]->last_buf = 1;
    body[2]->last_in_chain = 1;

    chain[0]->buf = body[0];
    chain[0]->next = chain[1];
    chain[1]->buf = body[1];
    chain[1]->next = chain[2];
    chain[2]->buf = body[2];
    chain[2]->next = NULL;

    body_len = ngx_http_pow_challenge_prefix_len + json_len
               + ngx_http_pow_challenge_suffix_len;
    r->headers_out.status = NGX_HTTP_SERVICE_UNAVAILABLE;
    ngx_str_set(&r->headers_out.content_type, POW_HTML_CONTENT_TYPE);
    r->headers_out.content_type_len = r->headers_out.content_type.len;
    r->headers_out.content_type_lowcase = NULL;
    r->headers_out.content_length_n = (off_t) body_len;
    r->allow_ranges = 0;
    ngx_http_clear_accept_ranges(r);
    ngx_http_clear_last_modified(r);
    ngx_http_clear_etag(r);

    challenge_header->hash = 1;
    cache_control->hash = 1;
    robots->hash = 1;
    csp_header->hash = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_OK && !r->header_only) {
        rc = ngx_http_output_filter(r, chain[0]);
    }

    ngx_http_finalize_request(r, rc);

    return NGX_DONE;
}


static ngx_int_t
ngx_http_pow_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_handler_pt        *h;
    ngx_http_pow_main_conf_t   *pmcf;

    pmcf = ngx_http_conf_get_module_main_conf(cf,
                                              ngx_http_pow_module);

    if (pmcf->effective_pow_enabled == 0) {
        return NGX_OK;
    }

    if (pmcf->secret_set == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pow_secret_file: required when pow is enabled");
        return NGX_ERROR;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_pow_handler;

    return NGX_OK;
}
