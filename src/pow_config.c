/*
 * Copyright (C) ngx_powgate authors
 */


#include "ngx_http_pow_module.h"


#define NGX_HTTP_POW_COOKIE_NAME_MAX          64
#define NGX_HTTP_POW_SECRET_HEX_LEN           (POW_SECRET_LEN * 2)
#define NGX_HTTP_POW_SECRET_FILE_MAX_LEN      130
#define NGX_HTTP_POW_SECRET_READ_CAP          131


static char *ngx_http_pow_positive_window(ngx_conf_t *cf, void *post,
    void *data);
static char *ngx_http_pow_valid_cookie_name(ngx_conf_t *cf, void *post,
    void *data);
static char *ngx_http_pow_valid_exempt_path(ngx_conf_t *cf, void *post,
    void *data);
static char *ngx_http_pow_exempt_ip(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_pow_secret_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_pow_secret_length_valid(off_t size);
static ngx_int_t ngx_http_pow_hex_nibble(u_char ch);
static ngx_int_t ngx_http_pow_decode_secret(const u_char *src, u_char *dst);
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

    { ngx_string("pow_secret_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_pow_secret_file,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
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

    { ngx_string("pow_exempt_ip"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_pow_exempt_ip,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

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
    ngx_http_pow_main_conf_t  *pmcf;
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

    if (conf->enable == 1) {
        pmcf = ngx_http_conf_get_module_main_conf(cf,
                                                  ngx_http_pow_module);
        pmcf->effective_pow_enabled = 1;
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


static char *
ngx_http_pow_exempt_ip(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                  rc;
    ngx_str_t                 *value;
    ngx_cidr_t                 cidr;
    ngx_cidr_t                *entry;
    ngx_array_t               *array;
    ngx_http_pow_loc_conf_t   *plcf;

    plcf = conf;
    value = cf->args->elts;

    ngx_memzero(&cidr, sizeof(ngx_cidr_t));

    rc = ngx_ptocidr(&value[1], &cidr);
    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pow_exempt_ip: value \"%V\" must be a valid "
                           "IPv4 or IPv6 CIDR", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "low address bits of %V are meaningless",
                           &value[1]);
    }

    array = plcf->exempt_ips;

    if (array == NGX_CONF_UNSET_PTR) {
        array = ngx_array_create(cf->pool, 4, sizeof(ngx_cidr_t));
        if (array == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    entry = ngx_array_push(array);
    if (entry == NULL) {
        return NGX_CONF_ERROR;
    }

    *entry = cidr;
    plcf->exempt_ips = array;

    return NGX_CONF_OK;
}


static char *
ngx_http_pow_secret_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                    raw[NGX_HTTP_POW_SECRET_READ_CAP];
    u_char                    current[POW_SECRET_LEN];
    u_char                    previous[POW_SECRET_LEN];
    u_char                   *p;
    ssize_t                   n;
    size_t                    total;
    off_t                     size;
    ngx_err_t                 err;
    ngx_fd_t                  fd;
    ngx_flag_t                has_prev;
    ngx_str_t                 path;
    ngx_str_t                *value;
    ngx_file_info_t           fi;
    ngx_http_pow_main_conf_t *pmcf;
    char                     *result;

    pmcf = conf;
    fd = NGX_INVALID_FILE;
    result = NGX_CONF_ERROR;
    has_prev = 0;
    total = 0;

    ngx_memzero(raw, sizeof(raw));
    ngx_memzero(current, sizeof(current));
    ngx_memzero(previous, sizeof(previous));

    if (pmcf->secret_set != 0) {
        result = "is duplicate";
        goto done;
    }

    value = cf->args->elts;

    if (ngx_strlchr(value[1].data, value[1].data + value[1].len, '\0')
        != NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pow_secret_file: path must not contain a "
                           "NUL byte");
        goto done;
    }

    path.len = value[1].len;
    path.data = ngx_pnalloc(cf->pool, path.len + 1);
    if (path.data == NULL) {
        goto done;
    }

    p = ngx_cpymem(path.data, value[1].data, path.len);
    *p = '\0';

    if (ngx_conf_full_name(cf->cycle, &path, 1) != NGX_OK) {
        goto done;
    }

    fd = ngx_open_file(path.data, NGX_FILE_RDONLY | NGX_FILE_NONBLOCK,
                       NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        err = ngx_errno;
        ngx_conf_log_error(NGX_LOG_EMERG, cf, err,
                           "pow_secret_file: " ngx_open_file_n
                           " \"%V\" failed", &path);
        goto done;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        err = ngx_errno;
        ngx_conf_log_error(NGX_LOG_EMERG, cf, err,
                           "pow_secret_file: " ngx_fd_info_n
                           " \"%V\" failed", &path);
        goto done;
    }

    if (ngx_is_file(&fi) == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pow_secret_file: target \"%V\" must be a "
                           "regular file", &path);
        goto done;
    }

    if ((ngx_file_access(&fi) & 0077) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pow_secret_file: target \"%V\" must grant no "
                           "group or other permissions", &path);
        goto done;
    }

    size = ngx_file_size(&fi);
    if (ngx_http_pow_secret_length_valid(size) != NGX_OK) {
        goto invalid;
    }

    for ( ;; ) {
        if (total == NGX_HTTP_POW_SECRET_READ_CAP) {
            goto invalid;
        }

        n = ngx_read_fd(fd, raw + total,
                        NGX_HTTP_POW_SECRET_READ_CAP - total);

        if (n == NGX_ERROR) {
            err = ngx_errno;

            if (err == NGX_EINTR) {
                continue;
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, err,
                               "pow_secret_file: " ngx_read_fd_n
                               " \"%V\" failed", &path);
            goto done;
        }

        if (n == 0) {
            break;
        }

        total += (size_t) n;
    }

    if ((off_t) total != size) {
        goto invalid;
    }

    if (size > NGX_HTTP_POW_SECRET_HEX_LEN
        && raw[NGX_HTTP_POW_SECRET_HEX_LEN] != LF)
    {
        goto invalid;
    }

    if (size == NGX_HTTP_POW_SECRET_FILE_MAX_LEN
        && raw[NGX_HTTP_POW_SECRET_FILE_MAX_LEN - 1] != LF)
    {
        goto invalid;
    }

    if (ngx_http_pow_decode_secret(raw, current) != NGX_OK) {
        goto invalid;
    }

    if (size > NGX_HTTP_POW_SECRET_HEX_LEN + 1) {
        if (ngx_http_pow_decode_secret(
                raw + NGX_HTTP_POW_SECRET_HEX_LEN + 1, previous)
            != NGX_OK)
        {
            goto invalid;
        }

        has_prev = 1;
    }

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        err = ngx_errno;
        fd = NGX_INVALID_FILE;
        ngx_conf_log_error(NGX_LOG_EMERG, cf, err,
                           "pow_secret_file: " ngx_close_file_n
                           " \"%V\" failed", &path);
        goto done;
    }

    fd = NGX_INVALID_FILE;

    ngx_memcpy(pmcf->secret, current, POW_SECRET_LEN);

    if (has_prev == 1) {
        ngx_memcpy(pmcf->secret_prev, previous, POW_SECRET_LEN);
    }

    pmcf->secret_set = 1;
    pmcf->has_prev = has_prev;
    result = NGX_CONF_OK;
    goto done;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "pow_secret_file: content must contain one or two "
                       "64-byte hexadecimal lines");

done:

    if (fd != NGX_INVALID_FILE) {
        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            err = ngx_errno;
            ngx_conf_log_error(NGX_LOG_EMERG, cf, err,
                               "pow_secret_file: " ngx_close_file_n
                               " \"%V\" failed", &path);
            result = NGX_CONF_ERROR;
        }
    }

    ngx_explicit_memzero(raw, sizeof(raw));
    ngx_explicit_memzero(current, sizeof(current));
    ngx_explicit_memzero(previous, sizeof(previous));

    return result;
}


static ngx_int_t
ngx_http_pow_secret_length_valid(off_t size)
{
    if (size == NGX_HTTP_POW_SECRET_HEX_LEN
        || size == NGX_HTTP_POW_SECRET_HEX_LEN + 1
        || size == (NGX_HTTP_POW_SECRET_HEX_LEN * 2) + 1
        || size == NGX_HTTP_POW_SECRET_FILE_MAX_LEN)
    {
        return NGX_OK;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_pow_hex_nibble(u_char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }

    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }

    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_pow_decode_secret(const u_char *src, u_char *dst)
{
    size_t     i;
    ngx_int_t  high;
    ngx_int_t  low;

    for (i = 0; i < POW_SECRET_LEN; i++) {
        high = ngx_http_pow_hex_nibble(src[i * 2]);
        low = ngx_http_pow_hex_nibble(src[i * 2 + 1]);

        if (high == NGX_ERROR || low == NGX_ERROR) {
            return NGX_ERROR;
        }

        dst[i] = (u_char) ((high << 4) | low);
    }

    return NGX_OK;
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
