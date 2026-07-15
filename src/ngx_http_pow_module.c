/*
 * Copyright (C) ngx_powgate authors
 */


#include "ngx_http_pow_module.h"
#include "pow_challenge.h"


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
    uint8_t                    challenge[POW_CHALLENGE_WIRE_MAX_LEN];
    uint8_t                    ip16[POW_IP_LEN];
    uint8_t                    nonce[POW_NONCE_LEN];
    uint8_t                    plen;
    time_t                     now;
    uint64_t                   bucket;
    ngx_int_t                  rc;
    ngx_uint_t                 kind;
    pow_challenge_text_t       challenge_text;
    ngx_http_pow_loc_conf_t  *plcf;
    ngx_http_pow_main_conf_t *pmcf;

    if (r != r->main || r->internal) {
        return NGX_DECLINED;
    }

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_pow_module);

    if (plcf->enable == 0) {
        return NGX_DECLINED;
    }

    rc = ngx_http_pow_connection_kind(r, &kind);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
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
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "pow_gate: operation=client_identity verdict=failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    now = ngx_time();
    if (now < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "pow_gate: operation=time_bucket verdict=failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    bucket = (uint64_t) now / (uint64_t) plcf->challenge_window;
    pmcf = ngx_http_get_module_main_conf(r, ngx_http_pow_module);

    if (pow_challenge_derive(pmcf->secret, ip16, plen, bucket, nonce) != 1
        || pow_challenge_serialize((uint8_t) plcf->difficulty, bucket, nonce,
                                   challenge, sizeof(challenge),
                                   &challenge_text) != 1)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "pow_gate: operation=challenge_format verdict=failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
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

    if (pow_ip16_mask(ip16, *plen) != 1) {
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
