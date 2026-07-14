#ifndef NGX_HTTP_POW_MODULE_H
#define NGX_HTTP_POW_MODULE_H


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "pow_protocol.h"


typedef struct {
    u_char       secret[POW_SECRET_LEN];
    u_char       secret_prev[POW_SECRET_LEN];
    ngx_flag_t   has_prev;
    ngx_flag_t   secret_set;
    ngx_flag_t   effective_pow_enabled;
} ngx_http_pow_main_conf_t;


typedef struct {
    ngx_flag_t   enable;
    ngx_int_t    difficulty;
    time_t       challenge_window;
    ngx_str_t    cookie_name;
    time_t       cookie_ttl;
    ngx_flag_t   cookie_secure;
    ngx_int_t    bind_ipv4;
    ngx_int_t    bind_ipv6;
    ngx_array_t *exempt_ips;
    ngx_array_t *exempt_paths;
    ngx_uint_t   log_level;
} ngx_http_pow_loc_conf_t;


extern ngx_command_t  ngx_http_pow_commands[];
extern ngx_module_t   ngx_http_pow_module;


void *ngx_http_pow_create_main_conf(ngx_conf_t *cf);
void *ngx_http_pow_create_loc_conf(ngx_conf_t *cf);
char *ngx_http_pow_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);


#endif /* NGX_HTTP_POW_MODULE_H */
