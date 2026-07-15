use strict;
use warnings;

use Test::More;

use lib 'tests/integration/lib';
use PowGate::TestHTTPS qw(generate_tls_fixture https_request);
use PowGate::TestNginx qw(start_nginx stop_nginx write_file);
use PowGate::TestReference qw(auth_cookie_value);


my $secret = '000102030405060708090a0b0c0d0e0f'
    . '101112131415161718191a1b1c1d1e1f';
my $client_ip = '198.51.100.44';
my $expiry = time + 3600;
my $runtime;
my $error;


sub auth_value {
    my (%overrides) = @_;

    return auth_cookie_value(
        secret_hex => $secret,
        ip => $overrides{ip} // $client_ip,
        expiry => $overrides{expiry} // $expiry,
        difficulty => $overrides{difficulty} // 1,
        plen => $overrides{plen} // 128,
    );
}


sub request {
    my ($protocol, $cookie, $path, @extra_headers) = @_;
    my @headers = (
        ['X-Forwarded-For' => $client_ip],
        @extra_headers,
    );

    push @headers, [Cookie => $cookie] if defined $cookie;

    return https_request(
        $runtime,
        protocol => $protocol,
        method => 'GET',
        path => $path // '/',
        headers => \@headers,
    );
}


sub assert_allowed {
    my ($response, $name) = @_;

    is $response->{status}, 200, "$name is allowed";
    ok !exists $response->{headers}{'powgate-challenge'},
        "$name has no challenge";
}


sub assert_challenged {
    my ($response, $name) = @_;

    is $response->{status}, 403, "$name is challenged";
    is scalar(@{$response->{headers}{'powgate-challenge'} // []}), 1,
        "$name has one challenge";
}


sub read_log {
    open my $fh, '<:raw', "$runtime->{prefix}/logs/error.log"
        or die "open error log: $!";
    local $/;
    my $bytes = <$fh>;
    close $fh or die "close error log: $!";
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
    listen 127.0.0.1:$port ssl;
    http2 on;
    ssl_certificate $tls->{certificate};
    ssl_certificate_key $tls->{key};
    set_real_ip_from 127.0.0.1;
    real_ip_header X-Forwarded-For;

    pow on;
    pow_difficulty 1;
    pow_cookie_name PoWAuth;
    pow_log_level notice;

    location /difficulty-two {
        pow_difficulty 2;
        empty_gif;
    }

    location / {
        empty_gif;
    }
}
NGINX
    });

    my $valid = auth_value();
    my $wrong_ip = auth_value(ip => '198.51.100.45');
    my $expired = auth_value(expiry => 1);
    my $low_prefix = auth_value(plen => 127);
    my $tampered = $valid;

    substr($tampered, -1, 1) = substr($tampered, -1, 1) eq 'A' ? 'B' : 'A';
    is length($valid), 39, 'reference auth value has fixed v1 length';

    for my $protocol ('1.1', '2') {
        subtest "HTTPS auth protocol $protocol" => sub {
            assert_allowed(
                request($protocol, "PoWAuth=$valid"),
                'exact configured auth name',
            );
            assert_challenged(request($protocol, undef), 'no cookie');
            assert_challenged(
                request($protocol, "__pow=$valid"),
                'default name is unrelated',
            );
            assert_challenged(
                request($protocol, "powauth=$valid"),
                'case variant is unrelated',
            );

            my @invalid = (
                ['malformed', 'PoWAuth=garbage', '/'],
                ['oversized', 'PoWAuth=' . ('x' x 257), '/'],
                ['tampered', "PoWAuth=$tampered", '/'],
                ['expired', "PoWAuth=$expired", '/'],
                ['wrong IP', "PoWAuth=$wrong_ip", '/'],
                ['low prefix', "PoWAuth=$low_prefix", '/'],
                ['low difficulty', "PoWAuth=$valid", '/difficulty-two'],
            );

            for my $case (@invalid) {
                assert_challenged(
                    request($protocol, $case->[1], $case->[2]),
                    $case->[0],
                );
            }

            assert_allowed(
                request($protocol, "PoWAuth=x; PoWAuth=$valid"),
                'valid second occurrence',
            );
            assert_allowed(
                request(
                    $protocol,
                    "PoWAuth=x; PoWAuth=y; PoWAuth=z; PoWAuth=$valid",
                ),
                'valid fourth occurrence',
            );
            assert_challenged(
                request(
                    $protocol,
                    "PoWAuth=a; PoWAuth=b; PoWAuth=c; PoWAuth=d; "
                    . "PoWAuth=$valid",
                ),
                'valid fifth occurrence is not inspected',
            );

            assert_allowed(
                request(
                    $protocol,
                    ";;\tPoWAuth=$valid;;",
                ),
                'empty segments and leading HTAB',
            );
            assert_allowed(
                request(
                    $protocol,
                    "XPoWAuth=$valid; PoWAuthX=$valid; PoWAuth =$valid; "
                    . "PoWAuth= $valid; PoWAuth=$valid",
                ),
                'exact name and whitespace rules',
            );
            assert_allowed(
                request(
                    $protocol,
                    undef,
                    '/',
                    [Cookie => 'a=b'],
                    [Cookie => "PoWAuth=$valid"],
                ),
                'duplicate Cookie fields preserve effective order',
            );
            assert_allowed(
                request(
                    $protocol,
                    "__pow_p=invalid-proof; PoWAuth=$valid",
                ),
                'auth success stops before proof handling',
            );
        };
    }

    my $sentinel = 'SENTINEL-DO-NOT-LOG';
    my $before = read_log();
    assert_challenged(
        request('1.1', "PoWAuth=$sentinel"),
        'sentinel invalid auth',
    );
    my $delta = substr(read_log(), length($before));

    is(() = $delta =~ /operation=auth verdict=invalid occurrences=1/g, 1,
       'one bounded auth failure summary is logged');
    unlike $delta, qr/\Q$sentinel\E/, 'attacker cookie bytes are not logged';
    unlike $delta, qr/operation=proof/, 'proof failure is not logged';
};
$error = $@;

my $cleanup = stop_nginx($runtime);
ok($cleanup->{reaped}, 'NGINX master is reaped');
ok($cleanup->{group_gone}, 'NGINX process group is gone');

die $error if $error ne '';

done_testing();
