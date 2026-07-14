/*
 * Copyright (C) ngx_powgate authors
 */


#include "ngx_http_pow_module.h"


static ngx_int_t ngx_http_pow_handler(ngx_http_request_t *r);
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
    ngx_http_pow_loc_conf_t  *plcf;

    if (r != r->main || r->internal) {
        return NGX_DECLINED;
    }

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_pow_module);

    if (plcf->enable == 0) {
        return NGX_DECLINED;
    }

    return NGX_DECLINED;
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
