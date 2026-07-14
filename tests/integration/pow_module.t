use File::Temp qw(tempfile);
use Test::Nginx::Socket -Base;

our $powgate_secret_path;

my ($secret_fh, $secret_path) = tempfile(
    'powgate-secret-XXXXXX',
    TMPDIR => 1,
    UNLINK => 0,
);

binmode $secret_fh, ':raw' or die "binmode $secret_path: $!";
print {$secret_fh} '0123456789abcdef' x 4
    or die "write $secret_path: $!";
close $secret_fh or die "close $secret_path: $!";
chmod 0600, $secret_path or die "chmod $secret_path: $!";
$powgate_secret_path = $secret_path;

END {
    unlink $secret_path if defined $secret_path;
}

repeat_each(1);
plan tests => repeat_each() * blocks() * 2;

run_tests();


__DATA__

=== TEST 1: pow on passes the request to content
--- main_config eval
"load_module "
    . ($ENV{POW_MODULE_PATH} // "/work/out/ngx_http_pow_module.so")
    . ";"
--- http_config eval
"pow_secret_file $main::powgate_secret_path;"
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
