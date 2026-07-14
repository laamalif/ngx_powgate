/*
 * Copyright (C) ngx_powgate authors
 */


#include "ngx_http_pow_module.h"


#define NGX_HTTP_POW_COOKIE_NAME_MAX  64


static char *ngx_http_pow_positive_window(ngx_conf_t *cf, void *post,
    void *data);
static char *ngx_http_pow_valid_cookie_name(ngx_conf_t *cf, void *post,
    void *data);
static char *ngx_http_pow_valid_exempt_path(ngx_conf_t *cf, void *post,
    void *data);
static ngx_int_t ngx_http_pow_is_token_char(u_char ch);


static ngx_conf_num_bounds_t  ngx_http_pow_difficulty_bounds = {
    ngx_conf_check_num_bounds, POW_DIFFICULTY_MIN, POW_DIFFICULTY_MAX
};


static ngx_conf_num_bounds_t  ngx_http_pow_bind_ipv4_bounds = {
    ngx_conf_check_num_bounds, POW_BIND_IPV4_MIN, POW_BIND_IPV4_MAX
};


static ngx_conf_num_bounds_t  ngx_http_pow_bind_ipv6_bounds = {
    ngx_conf_check_num_bounds, POW_BIND_IPV6_MIN, POW_BIND_IPV6_MAX
};


static ngx_conf_post_t  ngx_http_pow_window_post = {
    ngx_http_pow_positive_window
};


static ngx_conf_post_t  ngx_http_pow_cookie_name_post = {
    ngx_http_pow_valid_cookie_name
};


static ngx_conf_post_t  ngx_http_pow_exempt_path_post = {
    ngx_http_pow_valid_exempt_path
};


static ngx_conf_enum_t  ngx_http_pow_log_levels[] = {
    { ngx_string("info"), NGX_LOG_INFO },
    { ngx_string("notice"), NGX_LOG_NOTICE },
    { ngx_string("warn"), NGX_LOG_WARN },
    { ngx_string("error"), NGX_LOG_ERR },
    { ngx_null_string, 0 }
};


ngx_command_t  ngx_http_pow_commands[] = {

    { ngx_string("pow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pow_loc_conf_t, enable),
      NULL },

    { ngx_string("pow_difficulty"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pow_loc_conf_t, difficulty),
      &ngx_http_pow_difficulty_bounds },

    { ngx_string("pow_challenge_window"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pow_loc_conf_t, challenge_window),
      &ngx_http_pow_window_post },

    { ngx_string("pow_cookie_name"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pow_loc_conf_t, cookie_name),
      &ngx_http_pow_cookie_name_post },

    { ngx_string("pow_cookie_ttl"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pow_loc_conf_t, cookie_ttl),
      NULL },

    { ngx_string("pow_cookie_secure"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pow_loc_conf_t, cookie_secure),
      NULL },

    { ngx_string("pow_bind_ipv4"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pow_loc_conf_t, bind_ipv4),
      &ngx_http_pow_bind_ipv4_bounds },

    { ngx_string("pow_bind_ipv6"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pow_loc_conf_t, bind_ipv6),
      &ngx_http_pow_bind_ipv6_bounds },

    { ngx_string("pow_exempt_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pow_loc_conf_t, exempt_paths),
      &ngx_http_pow_exempt_path_post },

    { ngx_string("pow_log_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pow_loc_conf_t, log_level),
      &ngx_http_pow_log_levels },

      ngx_null_command
};


void *
ngx_http_pow_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_pow_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pow_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


void *
ngx_http_pow_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_pow_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pow_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->difficulty = NGX_CONF_UNSET;
    conf->challenge_window = NGX_CONF_UNSET;
    conf->cookie_name.len = 0;
    conf->cookie_name.data = NULL;
    conf->cookie_ttl = NGX_CONF_UNSET;
    conf->cookie_secure = NGX_CONF_UNSET;
    conf->bind_ipv4 = NGX_CONF_UNSET;
    conf->bind_ipv6 = NGX_CONF_UNSET;
    conf->exempt_ips = NGX_CONF_UNSET_PTR;
    conf->exempt_paths = NGX_CONF_UNSET_PTR;
    conf->log_level = NGX_CONF_UNSET_UINT;

    return conf;
}


char *
ngx_http_pow_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_pow_loc_conf_t  *prev = parent;
    ngx_http_pow_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->difficulty, prev->difficulty,
                         POW_DIFFICULTY_DEFAULT);
    ngx_conf_merge_sec_value(conf->challenge_window,
                             prev->challenge_window,
                             POW_CHALLENGE_WINDOW_DEFAULT);
    ngx_conf_merge_str_value(conf->cookie_name, prev->cookie_name,
                             POW_AUTH_COOKIE_NAME);
    ngx_conf_merge_sec_value(conf->cookie_ttl, prev->cookie_ttl,
                             POW_COOKIE_TTL_DEFAULT);
    ngx_conf_merge_value(conf->cookie_secure, prev->cookie_secure, 1);
    ngx_conf_merge_value(conf->bind_ipv4, prev->bind_ipv4,
                         POW_BIND_IPV4_DEFAULT);
    ngx_conf_merge_value(conf->bind_ipv6, prev->bind_ipv6,
                         POW_BIND_IPV6_DEFAULT);
    ngx_conf_merge_ptr_value(conf->exempt_ips, prev->exempt_ips, NULL);
    ngx_conf_merge_ptr_value(conf->exempt_paths, prev->exempt_paths, NULL);
    ngx_conf_merge_uint_value(conf->log_level, prev->log_level, NGX_LOG_ERR);

    if (conf->challenge_window <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pow_challenge_window: value must be positive");
        return NGX_CONF_ERROR;
    }

    if (conf->cookie_ttl < conf->challenge_window) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pow_cookie_ttl: value %T must be greater than "
                           "or equal to pow_challenge_window (%T)",
                           conf->cookie_ttl, conf->challenge_window);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_pow_positive_window(ngx_conf_t *cf, void *post, void *data)
{
    time_t  *window;

    window = data;

    if (*window > 0) {
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "pow_challenge_window: value must be positive");

    return NGX_CONF_ERROR;
}


static char *
ngx_http_pow_valid_cookie_name(ngx_conf_t *cf, void *post, void *data)
{
    size_t      i;
    ngx_str_t  *name;

    name = data;

    if (name->len == 0 || name->len > NGX_HTTP_POW_COOKIE_NAME_MAX
        || name->data[0] == '$')
    {
        goto invalid;
    }

    for (i = 0; i < name->len; i++) {
        if (ngx_http_pow_is_token_char(name->data[i]) != NGX_OK) {
            goto invalid;
        }
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "pow_cookie_name: value is not a valid cookie token");

    return NGX_CONF_ERROR;
}


static char *
ngx_http_pow_valid_exempt_path(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *path;

    path = data;

    if (path->len == 0 || path->data[0] != '/'
        || (path->len > 1 && path->data[path->len - 1] == '/'))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pow_exempt_path: value must be / or an absolute "
                           "path without a trailing slash");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_pow_is_token_char(u_char ch)
{
    if ((ch >= '0' && ch <= '9')
        || (ch >= 'A' && ch <= 'Z')
        || (ch >= 'a' && ch <= 'z'))
    {
        return NGX_OK;
    }

    switch (ch) {
    case '!':
    case '#':
    case '$':
    case '%':
    case '&':
    case '\'':
    case '*':
    case '+':
    case '-':
    case '.':
    case '^':
    case '_':
    case '`':
    case '|':
    case '~':
        return NGX_OK;

    default:
        return NGX_ERROR;
    }
}
