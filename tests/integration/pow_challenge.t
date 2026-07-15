use strict;
use warnings;

use Digest::SHA qw(hmac_sha256 sha256);
use MIME::Base64 qw(encode_base64);
use Socket qw(AF_INET AF_INET6 inet_pton);
use Test::More;

use PowGate::TestHTTPS qw(
    generate_tls_fixture
    https_request
    https_sequence
);
use PowGate::TestNginx qw(start_nginx stop_nginx write_file);


my $secret = '00' x 32;
my $runtime;
my $mapped_runtime;
my $error;
my $template;
my $template_prefix;
my $template_suffix;
my $script_digest;
my $page_max_body_len;


{
    open my $template_fh, '<:raw', 'html/challenge.html'
        or die "open challenge template: $!";
    local $/;
    $template = <$template_fh>;
    close $template_fh or die "close challenge template: $!";

    ($template_prefix, $template_suffix) = split(
        /<!-- POW:PARAMS -->/,
        $template,
        -1,
    );
    my ($script) = $template =~ m{<script>(.*?)</script>}s;
    die "challenge template contract is invalid"
        if !defined $template_suffix || !defined $script;
    $script_digest = encode_base64(sha256($script), '');

    open my $protocol_fh, '<:raw', 'src/pow_protocol.h'
        or die "open protocol header: $!";
    local $/;
    my $protocol = <$protocol_fh>;
    close $protocol_fh or die "close protocol header: $!";

    ($page_max_body_len) = $protocol =~
        /^#define POW_CHALLENGE_PAGE_MAX_BODY_LEN ([0-9]+)$/m;
    die "challenge body limit is not a simple numeric define"
        if !defined $page_max_body_len;
}


sub assert_bare_challenge {
    my ($response, $name) = @_;
    my $values = $response->{headers}{'powgate-challenge'};

    is $response->{status}, 403, "$name status";
    is $response->{body}, '', "$name body is empty";
    is_deeply $response->{headers}{'content-length'}, ['0'],
        "$name content length";
    is ref($values), 'ARRAY', "$name challenge header exists";
    is scalar(@{$values // []}), 1, "$name has one challenge header";
    like $values->[0],
        qr/\Av=1; d=20; b=(?:0|[1-9][0-9]{0,19}); n=[A-Za-z0-9_-]{43}\z/,
        "$name challenge grammar is canonical";
}


sub assert_html_challenge {
    my ($response, $name, $head) = @_;
    my $values = $response->{headers}{'powgate-challenge'};
    my $challenge = ref($values) eq 'ARRAY' ? $values->[0] : '';
    my ($difficulty, $bucket, $nonce) = $challenge =~
        /\Av=1; d=(20); b=(0|[1-9][0-9]{0,19}); n=([A-Za-z0-9_-]{43})\z/;
    my $json = '<script type="application/json" id="pow-params">'
        . '{"v":1,"d":' . ($difficulty // '')
        . ',"b":"' . ($bucket // '')
        . '","n":"' . ($nonce // '') . '"}</script>';
    my $expected = $template_prefix . $json . $template_suffix;
    my $csp = "default-src 'none'; base-uri 'none'; form-action 'none'; "
        . "frame-ancestors 'none'; script-src 'sha256-$script_digest'; "
        . "style-src 'unsafe-inline'";

    is $response->{status}, 503, "$name status";
    is scalar(@{$values // []}), 1, "$name has one challenge header";
    ok defined($difficulty), "$name challenge grammar is canonical";
    is_deeply $response->{headers}{'content-type'},
        ['text/html; charset=utf-8'], "$name content type";
    is_deeply $response->{headers}{'cache-control'}, ['no-store'],
        "$name cache control";
    is_deeply $response->{headers}{'x-robots-tag'}, ['noindex'],
        "$name robots policy";
    is_deeply $response->{headers}{'content-security-policy'}, [$csp],
        "$name CSP";
    is_deeply $response->{headers}{'content-length'},
        [length($expected) . ''], "$name content length";
    is $response->{body}, $head ? '' : $expected, "$name exact body";
    cmp_ok length($response->{body}), '<', $page_max_body_len,
        "$name actual body is below protocol limit" if !$head;
}


sub challenge_fields {
    my ($response) = @_;
    my $values = $response->{headers}{'powgate-challenge'};
    my $challenge = ref($values) eq 'ARRAY' ? $values->[0] : '';
    my ($bucket, $nonce) = $challenge =~
        /\Av=1; d=20; b=(0|[1-9][0-9]{0,19}); n=([A-Za-z0-9_-]{43})\z/;

    die "invalid challenge response" if !defined $bucket;
    return ($bucket, $nonce, $challenge);
}


sub masked_ip16 {
    my ($address, $plen) = @_;
    my @bytes = unpack 'C*', $address;
    my $whole = int($plen / 8);
    my $bits = $plen % 8;

    if ($bits != 0) {
        $bytes[$whole] &= (0xff << (8 - $bits)) & 0xff;
        $whole++;
    }
    for my $index ($whole .. 15) {
        $bytes[$index] = 0;
    }

    return pack 'C*', @bytes;
}


sub ipv4_ip16 {
    my ($address) = @_;
    return ("\0" x 10) . "\xff\xff" . inet_pton(AF_INET, $address);
}


sub expected_nonce {
    my ($secret_hex, $ip16, $plen, $bucket) = @_;
    my $message = 'PGv1-chal' . masked_ip16($ip16, $plen)
        . pack('C', $plen) . pack('Q>', 0 + $bucket);
    my $encoded = encode_base64(
        hmac_sha256($message, pack('H*', $secret_hex)),
        '',
    );

    $encoded =~ tr{+/}{-_};
    $encoded =~ s/=+\z//;
    return $encoded;
}


sub assert_nonce_identity {
    my ($response, $ip16, $plen, $name) = @_;
    my ($bucket, $nonce) = challenge_fields($response);

    is $nonce, expected_nonce($secret, $ip16, $plen, $bucket),
        "$name nonce identity";
}


sub read_log {
    my ($runtime) = @_;
    my $path = "$runtime->{prefix}/logs/error.log";
    open my $fh, '<:raw', $path or die "open runtime error log: $!";
    local $/;
    my $bytes = <$fh>;
    close $fh or die "close runtime error log: $!";
    return $bytes;
}


eval {
    $runtime = start_nginx(sub {
        my ($prefix, $port) = @_;
        my $tls = generate_tls_fixture($prefix);

        write_file("$prefix/conf/pow.secret", $secret, 0600);

        return <<"NGINX";
pow_secret_file pow.secret;

server {
    listen 127.0.0.1:$port ssl default_server;
    listen [::1]:$port ssl default_server;
    http2 on;
    ssl_certificate $tls->{certificate};
    ssl_certificate_key $tls->{key};

    pow on;
    pow_exempt_ip 192.0.2.0/24;
    pow_exempt_ip ::1/128;
    pow_exempt_path /api;
    pow_exempt_path /static;
    pow_exempt_path /a/b;

    location /disabled {
        pow off;
        empty_gif;
    }

    location /ip-exempt {
        pow_exempt_ip 127.0.0.1/32;
        empty_gif;
    }

    location /root-exempt {
        pow_exempt_path /;
        empty_gif;
    }

    location /identity {
        pow_exempt_ip 192.0.2.0/24;
        empty_gif;
    }

    location / {
        empty_gif;
    }
}

server {
    listen 127.0.0.1:$port ssl;
    listen [::1]:$port ssl;
    http2 on;
    server_name merged-off;
    ssl_certificate $tls->{certificate};
    ssl_certificate_key $tls->{key};
    merge_slashes off;

    pow on;
    pow_exempt_path /a/b;

    location / {
        empty_gif;
    }
}

server {
    listen 127.0.0.1:$port ssl;
    http2 on;
    server_name trusted-realip;
    ssl_certificate $tls->{certificate};
    ssl_certificate_key $tls->{key};
    set_real_ip_from 127.0.0.1;
    real_ip_header X-Forwarded-For;
    pow on;
    location / { empty_gif; }
}

server {
    listen 127.0.0.1:$port ssl;
    http2 on;
    server_name trusted-exempt;
    ssl_certificate $tls->{certificate};
    ssl_certificate_key $tls->{key};
    set_real_ip_from 127.0.0.1;
    real_ip_header X-Forwarded-For;
    pow on;
    pow_exempt_ip 198.51.100.0/24;
    location / { empty_gif; }
}

server {
    listen 127.0.0.1:$port ssl;
    http2 on;
    server_name untrusted-realip;
    ssl_certificate $tls->{certificate};
    ssl_certificate_key $tls->{key};
    real_ip_header X-Forwarded-For;
    pow on;
    location / { empty_gif; }
}

server {
    listen unix:$prefix/powgate.sock ssl;
    http2 on;
    ssl_certificate $tls->{certificate};
    ssl_certificate_key $tls->{key};
    pow on;
    location / { empty_gif; }
}
NGINX
    });

    $mapped_runtime = start_nginx(sub {
        my ($prefix, $port) = @_;
        my $tls = generate_tls_fixture($prefix);

        write_file("$prefix/conf/pow.secret", $secret, 0600);

        return <<"NGINX";
pow_secret_file pow.secret;

server {
    listen [::]:$port ssl ipv6only=off;
    http2 on;
    ssl_certificate $tls->{certificate};
    ssl_certificate_key $tls->{key};
    pow on;
    pow_bind_ipv4 24;
    pow_bind_ipv6 64;
    location / { empty_gif; }
}
NGINX
    });

    for my $protocol ('1.1', '2') {
        subtest "bare challenge matrix over HTTPS $protocol" => sub {
            my @bare_cases = (
                [ 'absent Accept',
                  { method => 'GET', path => '/protected' } ],
                [ 'wildcard Accept',
                  { method => 'GET', path => '/protected',
                    headers => [[Accept => '*/*']] } ],
                [ 'POST remains non-navigation',
                  { method => 'POST', path => '/protected', body => 'payload',
                    headers => [[Accept => 'text/html']] } ],
                [ 'cookies do not bypass Phase 3',
                  { method => 'GET', path => '/protected',
                    headers => [[Cookie => '__pow=x; __pow_p=1.0.0']] } ],
                [ 'nonmatching CIDR',
                  { method => 'GET', path => '/cidr-miss' } ],
                [ 'path segment boundary',
                  { method => 'GET', path => '/apiv2' } ],
                [ 'normalized dot segments',
                  { method => 'GET', path => '/static/../admin' } ],
            );

            for my $case (@bare_cases) {
                my $response = https_request(
                    $runtime,
                    protocol => $protocol,
                    host => '127.0.0.1',
                    %{$case->[1]},
                );

                is $response->{protocol}, $protocol,
                    "$case->[0] negotiates $protocol";
                assert_bare_challenge($response, $case->[0]);
            }

            my @allowed_cases = (
                [ 'disabled location', '/disabled' ],
                [ 'matching IPv4 CIDR', '/ip-exempt' ],
                [ 'exact exempt path', '/api' ],
                [ 'descendant exempt path', '/api/v1' ],
                [ 'query excluded from matching', '/api?x=/admin' ],
                [ 'percent-decoded path', '/%73tatic' ],
                [ 'root exemption exact', '/root-exempt' ],
                [ 'root exemption descendant', '/root-exempt/child' ],
                [ 'merged slash path', '/a//b' ],
            );

            for my $case (@allowed_cases) {
                my $response = https_request(
                    $runtime,
                    protocol => $protocol,
                    host => '127.0.0.1',
                    method => 'GET',
                    path => $case->[1],
                );

                is $response->{protocol}, $protocol,
                    "$case->[0] negotiates $protocol";
                is $response->{status}, 200, "$case->[0] is allowed";
                ok length($response->{body}) > 0, "$case->[0] body";
                ok !exists $response->{headers}{'powgate-challenge'},
                    "$case->[0] has no challenge header";
            }

            my $unmerged = https_request(
                $runtime,
                protocol => $protocol,
                host => 'merged-off',
                resolve_to => '127.0.0.1',
                method => 'GET',
                path => '/a//b',
            );
            is $unmerged->{protocol}, $protocol,
                "unmerged slash path negotiates $protocol";
            assert_bare_challenge($unmerged, 'unmerged slash path');

            my $ipv6 = https_request(
                $runtime,
                protocol => $protocol,
                host => '::1',
                method => 'GET',
                path => '/ipv6-exempt',
            );
            is $ipv6->{protocol}, $protocol,
                "matching IPv6 CIDR negotiates $protocol";
            is $ipv6->{status}, 200, 'matching IPv6 CIDR is allowed';
            ok length($ipv6->{body}) > 0, 'matching IPv6 CIDR body';
            ok !exists $ipv6->{headers}{'powgate-challenge'},
                'matching IPv6 CIDR has no challenge header';
        };

        subtest "HTML challenge matrix over HTTPS $protocol" => sub {
            my $responses = https_sequence(
                $runtime,
                protocol => $protocol,
                host => '127.0.0.1',
                requests => [
                    { method => 'GET', path => '/navigation-pair' },
                    { method => 'GET', path => '/navigation-pair',
                      headers => [[Accept => 'text/html']] },
                ],
            );

            is $responses->[0]{protocol}, $protocol,
                "paired bare request negotiates $protocol";
            assert_bare_challenge($responses->[0], 'paired bare request');
            is $responses->[1]{protocol}, $protocol,
                "HTML GET negotiates $protocol";
            assert_html_challenge($responses->[1], 'HTML GET', 0);
            is_deeply $responses->[1]{headers}{'powgate-challenge'},
                $responses->[0]{headers}{'powgate-challenge'},
                'bare and HTML fields agree in the same bucket';

            my @cases = (
                [ 'HTML HEAD',
                  { method => 'HEAD', path => '/navigation-head',
                    headers => [[Accept => 'text/html']] }, 1 ],
                [ 'mixed-case HTML media type',
                  { method => 'GET', path => '/navigation-case',
                    headers => [[Accept => 'TeXt/HtMl']] }, 0 ],
                [ 'later repeated Accept matches',
                  { method => 'GET', path => '/navigation-repeated',
                    headers => [
                        [Accept => 'application/json'],
                        [Accept => 'text/html'],
                    ] }, 0 ],
            );

            for my $case (@cases) {
                my $response = https_request(
                    $runtime,
                    protocol => $protocol,
                    host => '127.0.0.1',
                    %{$case->[1]},
                );

                is $response->{protocol}, $protocol,
                    "$case->[0] negotiates $protocol";
                assert_html_challenge($response, $case->[0], $case->[2]);
            }
        };
    }

    subtest 'independent deterministic identity reproduction' => sub {
        my %observed;

        for my $protocol ('1.1', '2') {
            my $ipv4 = https_request(
                $runtime,
                protocol => $protocol,
                host => '127.0.0.1',
                method => 'GET',
                path => '/identity/v4',
            );
            my $ipv4_repeat = https_request(
                $runtime,
                protocol => $protocol,
                host => '127.0.0.1',
                method => 'GET',
                path => '/identity/v4-repeat',
            );

            is $ipv4->{status}, 403, "IPv4 $protocol is challenged";
            assert_nonce_identity(
                $ipv4,
                ipv4_ip16('127.0.0.1'),
                128,
                "IPv4 $protocol",
            );
            my (undef, undef, $first) = challenge_fields($ipv4);
            my (undef, undef, $second) = challenge_fields($ipv4_repeat);
            is $second, $first, "IPv4 $protocol repeats in one bucket";
            $observed{$protocol} = $first;

            my $mapped = https_request(
                $mapped_runtime,
                protocol => $protocol,
                host => '127.0.0.1',
                method => 'GET',
                path => '/mapped',
            );
            is $mapped->{status}, 403,
                "mapped IPv6 $protocol is challenged";
            assert_nonce_identity(
                $mapped,
                ipv4_ip16('127.0.0.1'),
                120,
                "mapped IPv6 $protocol uses IPv4 policy",
            );

            my $native = https_request(
                $mapped_runtime,
                protocol => $protocol,
                host => '::1',
                method => 'GET',
                path => '/native',
            );
            is $native->{status}, 403,
                "native IPv6 $protocol is challenged";
            assert_nonce_identity(
                $native,
                inet_pton(AF_INET6, '::1'),
                64,
                "native IPv6 $protocol",
            );

            my $trusted = https_request(
                $runtime,
                protocol => $protocol,
                host => 'trusted-realip',
                resolve_to => '127.0.0.1',
                method => 'GET',
                path => '/realip',
                headers => [[ 'X-Forwarded-For' => '198.51.100.44' ]],
            );
            is $trusted->{status}, 403,
                "trusted RealIP $protocol is challenged";
            assert_nonce_identity(
                $trusted,
                ipv4_ip16('198.51.100.44'),
                128,
                "trusted RealIP $protocol",
            );

            my $exempt = https_request(
                $runtime,
                protocol => $protocol,
                host => 'trusted-exempt',
                resolve_to => '127.0.0.1',
                method => 'GET',
                path => '/realip-exempt',
                headers => [[ 'X-Forwarded-For' => '198.51.100.44' ]],
            );
            is $exempt->{status}, 200,
                "trusted RealIP CIDR exempts $protocol";

            my $untrusted = https_request(
                $runtime,
                protocol => $protocol,
                host => 'untrusted-realip',
                resolve_to => '127.0.0.1',
                method => 'GET',
                path => '/realip-untrusted',
                headers => [[ 'X-Forwarded-For' => '198.51.100.44' ]],
            );
            is $untrusted->{status}, 403,
                "untrusted RealIP $protocol is challenged";
            assert_nonce_identity(
                $untrusted,
                ipv4_ip16('127.0.0.1'),
                128,
                "untrusted RealIP $protocol ignores the header",
            );
        }

        is $observed{'2'}, $observed{'1.1'},
            'HTTP/1.1 and HTTP/2 challenges agree in one bucket';
    };

    subtest 'unsupported Unix identity fails closed without request data'
        => sub {
        for my $protocol ('1.1', '2') {
            my $response = https_request(
                $runtime,
                protocol => $protocol,
                unix_socket => "$runtime->{prefix}/powgate.sock",
                method => 'GET',
                path => '/unix-secret-path',
                headers => [
                    [ 'X-Pow-Sentinel' => 'header-sentinel' ],
                    [ Cookie => '__pow=cookie-sentinel' ],
                ],
            );

            is $response->{protocol}, $protocol,
                "Unix listener negotiates $protocol";
            is $response->{status}, 500,
                "Unix listener rejects $protocol";
            for my $name (qw(
                powgate-challenge
                cache-control
                x-robots-tag
                content-security-policy
            )) {
                ok !exists $response->{headers}{$name},
                    "Unix $protocol omits $name";
            }
        }

        my $log = read_log($runtime);
        like $log,
            qr/pow_gate:\x20unsupported\x20connection\x20address
               \x20family\x20\d+,\x20request\x20rejected/x,
            'unsupported family verdict is logged';
        unlike $log, qr/unix-secret-path/, 'Unix URI is not logged';
        unlike $log, qr/header-sentinel/, 'Unix header is not logged';
        unlike $log, qr/cookie-sentinel/, 'Unix cookie is not logged';
        unlike $log, qr/PGv1-chal/, 'nonce label is not logged';
        unlike $log, qr/\Q$secret\E/, 'secret bytes are not logged';
    };
};
$error = $@;

my $mapped_cleanup = stop_nginx($mapped_runtime);
ok $mapped_cleanup->{reaped}, 'mapped runtime is reaped';
ok $mapped_cleanup->{group_gone}, 'mapped process group is gone';
my $cleanup = stop_nginx($runtime);
ok $cleanup->{reaped}, 'challenge runtime is reaped';
ok $cleanup->{group_gone}, 'challenge process group is gone';

die $error if $error ne '';

done_testing();
