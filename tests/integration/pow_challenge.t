use strict;
use warnings;

use Digest::SHA qw(sha256);
use MIME::Base64 qw(encode_base64);
use Test::More;

use PowGate::TestHTTPS qw(
    generate_tls_fixture
    https_request
    https_sequence
);
use PowGate::TestNginx qw(start_nginx stop_nginx write_file);


my $secret = '00' x 32;
my $runtime;
my $error;
my $template;
my $template_prefix;
my $template_suffix;
my $script_digest;


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
};
$error = $@;

my $cleanup = stop_nginx($runtime);
ok $cleanup->{reaped}, 'challenge runtime is reaped';
ok $cleanup->{group_gone}, 'challenge process group is gone';

die $error if $error ne '';

done_testing();
