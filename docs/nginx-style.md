# ngx_powgate — NGINX Code Style Guide

ngx_powgate code must read as if it were an upstream nginx module. The
authority is nginx's own development guide
(nginx.org/en/docs/dev/development_guide.html) and the source of core
modules — when in doubt, open `ngx_http_limit_req_module.c` or
`ngx_http_realip_module.c` in `$NGX_SOURCE_DIR` and imitate them. This file
condenses the rules ngx_powgate actually exercises.

## File layout

Every module-side `.c` file, in this order:

```c

/*
 * Copyright (C) ngx_powgate authors
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "pow_protocol.h"


typedef struct {
    ngx_flag_t                 enable;
    ngx_uint_t                 difficulty;
    time_t                     challenge_window;
    time_t                     cookie_ttl;
    ngx_str_t                  cookie_name;
    ngx_array_t               *exempt_cidrs;    /* ngx_cidr_t */
    ngx_array_t               *exempt_paths;    /* ngx_str_t */
} ngx_http_pow_loc_conf_t;


static ngx_int_t ngx_http_pow_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_pow_init(ngx_conf_t *cf);
static void *ngx_http_pow_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_pow_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
```

then the `ngx_command_t` table, module ctx, module definition, then
function definitions — public shape first, helpers after.

## Functions

Return type on its own line; name starts the next line; two blank lines
between functions; `static` for everything not exported:

```c
static ngx_int_t
ngx_http_pow_handler(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_http_pow_loc_conf_t  *plcf;

    if (r != r->main || r->internal) {
        return NGX_DECLINED;
    }

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_pow_module);

    if (!plcf->enable) {
        return NGX_DECLINED;
    }

    ...
}
```

Wrapped parameter lists continue with a 4-space indent (see the
`merge_loc_conf` prototype above), not aligned under the opening paren.

## Declarations

All variables are declared at the top of the function (not mid-block),
one per line, names aligned in a column, roughly ordered from short types
to long, pointers last:

```c
    size_t                     len;
    u_char                    *p, *last;
    ngx_int_t                  rc;
    ngx_str_t                 *value;
    ngx_table_elt_t           *set_cookie;
```

No declarations with initializers that call functions; assign after the
declaration block.

## Expressions and control flow

- Explicit comparisons: `if (p == NULL)`, `if (rc != NGX_OK)`,
  `if (len == 0)` — never `if (!p)` for pointers or `if (rc)` for codes.
- Braces always, even for single statements. Opening brace on the same
  line for `if`/`for`/`while`/`do`.
- Early return on error; no deep nesting. `goto failed;` is acceptable
  only when cleanup is genuinely shared.
- `switch` cases aligned with the `switch`, `default:` always present.

## Types and naming

- `ngx_int_t` / `ngx_uint_t` for general integers, `size_t` for lengths,
  `u_char *` for byte buffers, `time_t` for seconds, `ngx_msec_t` for ms.
- All module-side identifiers carry the full prefix:
  `ngx_http_pow_*` for functions and statics,
  `ngx_http_pow_*_t` for types.
- Module-side constants: `NGX_HTTP_POW_*`, defined in one place.
- `/* comment */` only — no `//`. Comments are sparse, lowercase, and
  explain *why*, not *what*.

## Strings and buffers

- `ngx_str_t` everywhere; literals via `ngx_string("...")` and
  `ngx_null_string`; literal lengths via `sizeof("...") - 1`.
- Build buffers by pointer-walking with `ngx_cpymem`/`ngx_sprintf` into a
  buffer of precomputed exact size:

```c
    len = plcf->cookie_name.len + 1 + val_len
          + sizeof("; Max-Age=; Path=/; Secure; HttpOnly; SameSite=Lax") - 1
          + NGX_TIME_T_LEN;

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    set_cookie->value.data = p;
    p = ngx_cpymem(p, plcf->cookie_name.data, plcf->cookie_name.len);
    *p++ = '=';
    ...
    set_cookie->value.len = p - set_cookie->value.data;
```

- Never libc string functions on request data; `ngx_atoi`, `ngx_strncmp`,
  `ngx_strcasestrn` with explicit lengths.

## Configuration

- Prefer the standard slot handlers over custom parsers:
  `ngx_conf_set_flag_slot`, `ngx_conf_set_num_slot`,
  `ngx_conf_set_sec_slot`, `ngx_conf_set_str_slot`,
  `ngx_conf_set_enum_slot`. A custom handler is justified only for
  compound directives (CIDR lists, the secret file).
- Command table entries aligned in nginx's column style:

```c
static ngx_command_t  ngx_http_pow_commands[] = {

    { ngx_string("pow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pow_loc_conf_t, enable),
      NULL },

      ngx_null_command
};
```

- `create_loc_conf` sets every field to `NGX_CONF_UNSET*`;
  `merge_loc_conf` uses `ngx_conf_merge_value`, `ngx_conf_merge_uint_value`,
  `ngx_conf_merge_sec_value`, `ngx_conf_merge_str_value` — and performs
  cross-field validation (window vs ttl) after merging, returning a
  `NGX_CONF_ERROR` with `ngx_conf_log_error(NGX_LOG_EMERG, ...)`.
- Post-1.23 header APIs only; linked-list `r->headers_in.cookie` via
  `ngx_http_parse_multi_header_lines(r, r->headers_in.cookie, &name, &val)`.

## Logging

- Request context: `ngx_log_error(level, r->connection->log, 0, ...)`;
  debug tracing via `ngx_log_debug*(NGX_LOG_DEBUG_HTTP, ...)`.
- The configurable severity for verification-failure logs follows the
  `limit_req_log_level` precedent (enum directive: `info | notice | warn |
  error`, one derived "delay level" style constant if needed).
- Config context: `ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, ...)`.

## Formatting mechanics

- 4-space indent, spaces only, no tabs.
- 80-column limit.
- Two blank lines between top-level definitions; single blank lines to
  separate logical blocks inside functions; a blank line after the
  declaration block.
- One space after keywords (`if (`, `for (`), none after function names.
- `sizeof(x)` with parentheses always.

## Compiler flags

Module code builds with the flags nginx's own `auto/cc/gcc` selects:

```
-W -Wall -Wpointer-arith -Wno-unused-parameter -Werror
```

Do **not** add `-Wconversion` (nginx headers do not compile clean under
it) or fight nginx's flag set; the module must build warning-free inside
an unmodified `./configure --with-compat` build. Hardening flags
(`-D_FORTIFY_SOURCE=2`, `-fstack-protector-strong`) are added via
`--with-cc-opt` in the Makefile, never by editing nginx's auto files.

The pure core is the exception in the strict direction: `pow_parse.c`,
`pow_crypto.c`, `pow_cookie_scan.c`, `pow_cookie.c`, `pow_challenge.c`, and
`pow_verify.h` include no nginx headers. Standalone unit and fuzz builds
compile the source files with
`-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror`. The same files
also compile inside the nginx build with nginx's flags — they must be
clean under both.

## Sanctioned deviation: the pure core

`pow_parse.c`, `pow_crypto.c`, `pow_cookie_scan.c`, `pow_cookie.c`,
`pow_challenge.c`, and `pow_verify.h` form a freestanding library so the fuzz
harnesses need no nginx runtime. Their rules:

- No nginx headers. Types are C99 `stdint.h`/`stddef.h` (`uint8_t`,
  `uint64_t`, `size_t`). At the module boundary, `u_char *` and `uint8_t *`
  interconvert directly.
- Identifiers prefixed `pow_`; constants `POW_*` in `pow_protocol.h`.
- Everything else — layout, declaration alignment, comment style, explicit
  comparisons, 80 columns — follows this guide identically. A reader
  moving between `pow_cookie.c` and the module file should notice only the
  type prefixes change.

The one-file tradition: many core nginx modules are a single `.c`. ngx_powgate
deviates for exactly one reason — fuzzability of the hostile-input
parsers — and confines the deviation to the pure-core files listed above.
All nginx API usage lives outside that core; module-side files follow
module-side naming for every nginx-facing function.
