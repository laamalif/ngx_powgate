use Test::Nginx::Socket -Base;

repeat_each(1);
plan tests => repeat_each() * blocks() * 2;

run_tests();


__DATA__

=== TEST 1: pow on passes the request to content
--- main_config eval
"load_module "
    . ($ENV{POW_MODULE_PATH} // "/work/out/ngx_http_pow_module.so")
    . ";"
--- config
location /pow {
    pow on;
    return 200 "backend\n";
}
--- request
GET /pow
--- response_status
200
--- response_body
backend
