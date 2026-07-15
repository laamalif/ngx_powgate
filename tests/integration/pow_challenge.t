use strict;
use warnings;

use Test::More;

use PowGate::TestHTTPS qw(generate_tls_fixture https_request);
use PowGate::TestNginx qw(start_nginx stop_nginx write_file);


my $secret = '00' x 32;
my $runtime;
my $error;


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
    }
};
$error = $@;

my $cleanup = stop_nginx($runtime);
ok $cleanup->{reaped}, 'challenge runtime is reaped';
ok $cleanup->{group_gone}, 'challenge process group is gone';

die $error if $error ne '';

done_testing();
