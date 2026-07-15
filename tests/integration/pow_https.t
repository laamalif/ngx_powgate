use strict;
use warnings;

use Test::More;

use lib 'tests/integration/lib';
use PowGate::TestHTTPS qw(
    generate_tls_fixture
    https_request
    https_sequence
);
use PowGate::TestNginx qw(start_nginx stop_nginx);


my $runtime;
my $tls;
my $prefix;
my $error;

eval {
    $runtime = start_nginx(sub {
        my ($selected_prefix, $port) = @_;

        $prefix = $selected_prefix;
        $tls = generate_tls_fixture($selected_prefix);

        return <<"NGINX";
server {
    listen 127.0.0.1:$port ssl;
    http2 on;
    ssl_certificate $tls->{certificate};
    ssl_certificate_key $tls->{key};

    location / {
        pow off;
        default_type text/plain;
        return 200 "ready\\n";
    }
}
NGINX
    });

    is((stat($tls->{key}))[2] & 07777, 0600,
       'ephemeral private key mode is 0600');
    is((stat($tls->{certificate}))[2] & 07777, 0644,
       'ephemeral certificate mode is 0644');

    for my $protocol ('1.1', '2') {
        subtest "HTTPS protocol $protocol" => sub {
            my $response = https_request(
                $runtime,
                protocol => $protocol,
                method => 'GET',
                path => '/',
            );

            is($response->{protocol}, $protocol,
               'negotiated protocol is exact');
            is($response->{status}, 200, 'status is parsed');
            is($response->{body}, "ready\n", 'body is exact');
            is_deeply($response->{headers}{'content-type'},
                      ['text/plain'], 'headers are a lowercase multimap');

            my $responses = https_sequence(
                $runtime,
                protocol => $protocol,
                requests => [
                    { method => 'GET', path => '/one' },
                    { method => 'GET', path => '/two' },
                ],
            );

            is(scalar @$responses, 2, 'sequence returns two responses');
            is($responses->[0]{status}, 200, 'first transfer succeeds');
            is($responses->[1]{status}, 200, 'second transfer succeeds');
            is($responses->[1]{num_connects}, 0,
               'second transfer reuses the TLS connection');
            ok($responses->[0]{local_port} > 0,
               'first transfer reports a local port');
            is($responses->[1]{local_port}, $responses->[0]{local_port},
               'both transfers use the same local port');
        };
    }
};
$error = $@;

my $cleanup = stop_nginx($runtime);
ok($cleanup->{reaped}, 'NGINX master is reaped');
ok($cleanup->{group_gone}, 'NGINX process group is gone');
ok(!defined($prefix) || !-e $prefix, 'runtime prefix is removed');
ok(!defined($tls) || !-e $tls->{key}, 'ephemeral key is removed');
ok(!defined($tls) || !-e $tls->{certificate},
   'ephemeral certificate is removed');

die $error if $error ne '';

done_testing();
