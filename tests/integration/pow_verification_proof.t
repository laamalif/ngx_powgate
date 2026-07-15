use strict;
use warnings;

use Test::More;

use lib 'tests/integration/lib';
use PowGate::TestBackend qw(
    backend_reach_count
    start_backend
    stop_backend
);
use PowGate::TestHTTPS qw(generate_tls_fixture https_request);
use PowGate::TestNginx qw(start_nginx stop_nginx write_file);
use PowGate::TestReference qw(
    parse_challenge
    refsolve_json
    set_cookie_values
);


my $secret = '000102030405060708090a0b0c0d0e0f'
    . '101112131415161718191a1b1c1d1e1f';
my $client_ip = '198.51.100.44';
my $other_ip = '198.51.100.45';
my $runtime;
my $backend;
my $error;


sub request {
    my ($protocol, %options) = @_;
    my @headers = (
        ['X-Forwarded-For' => $options{ip} // $client_ip],
        @{$options{headers} // []},
    );

    return https_request(
        $runtime,
        protocol => $protocol,
        method => $options{method} // 'GET',
        path => $options{path} // '/',
        headers => \@headers,
        defined($options{body}) ? (body => $options{body}) : (),
    );
}


sub current_bucket {
    my ($protocol) = @_;
    my $response = request($protocol);
    my $values = $response->{headers}{'powgate-challenge'} // [];

    is $response->{status}, 403, 'bucket observation is challenged';
    is scalar(@$values), 1, 'bucket observation has one challenge';
    return parse_challenge($values->[0])->{bucket};
}


sub proof_output {
    my (%options) = @_;

    return refsolve_json(
        'mine',
        '--secret-hex', $options{secret_hex} // $secret,
        '--ip', $options{ip} // $client_ip,
        '--plen', $options{plen} // 128,
        '--bucket', $options{bucket},
        '--difficulty', $options{difficulty} // 1,
        '--start-counter', $options{start_counter} // 0,
    );
}


sub proof_check {
    my (%options) = @_;

    return refsolve_json(
        'proof-check',
        '--secret-hex', $options{secret_hex} // $secret,
        '--ip', $options{ip} // $client_ip,
        '--plen', $options{plen} // 128,
        '--bucket', $options{bucket},
        '--difficulty', $options{difficulty} // 1,
        '--counter', $options{counter},
    )->{valid};
}


sub proof_invalid_for_client {
    my ($bucket, $source_ip) = @_;
    my $start = 0;

    for (1 .. 64) {
        my $proof = proof_output(
            bucket => $bucket,
            ip => $source_ip,
            start_counter => $start,
        );

        return $proof
            if !proof_check(
                bucket => $bucket,
                counter => $proof->{counter},
                ip => $client_ip,
            );
        $start = $proof->{counter} + 1;
    }

    die "could not find bounded alternate-context proof";
}


sub invalid_counter {
    my ($bucket) = @_;

    for my $counter (0 .. 64) {
        return $counter if !proof_check(
            bucket => $bucket,
            counter => $counter,
        );
    }

    die "could not find bounded invalid proof counter";
}


sub assert_challenge {
    my ($response, $name) = @_;

    is $response->{status}, 403, "$name is challenged";
    is scalar(@{$response->{headers}{'powgate-challenge'} // []}), 1,
        "$name has one challenge";
    is scalar(set_cookie_values($response)), 0,
        "$name emits no Set-Cookie";
}


sub submit_valid_proof {
    my ($protocol, %options) = @_;

    for (1 .. 3) {
        my $observed = current_bucket($protocol);
        my $bucket = $observed + ($options{offset} // 0);
        my $proof = proof_output(bucket => $bucket);

        next if current_bucket($protocol) != $observed;

        return request(
            $protocol,
            method => $options{method} // 'GET',
            path => $options{path} // '/',
            body => $options{body},
            headers => [[Cookie => "__pow_p=$proof->{proof_cookie}"]],
        );
    }

    die "bucket changed during bounded proof submission";
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
    $backend = start_backend();
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
    pow_cookie_name PowAuth;
    pow_log_level notice;

    location /insecure {
        pow_cookie_secure off;
        proxy_pass http://127.0.0.1:$backend->{port};
    }

    location / {
        proxy_pass http://127.0.0.1:$backend->{port};
    }
}
NGINX
    });

    for my $protocol ('1.1', '2') {
        subtest "HTTPS proof protocol $protocol" => sub {
            my $body = "proof-body-$protocol\0exact";
            my $response = submit_valid_proof(
                $protocol,
                method => 'POST',
                body => $body,
            );
            my @cookies = set_cookie_values($response);
            my $secure_pattern = qr{
                \APowAuth=
                (1\.[A-Za-z0-9_-]{14}\.[A-Za-z0-9_-]{22});
                [ ]Max-Age=3600;[ ]Path=/;[ ]Secure;
                [ ]HttpOnly;[ ]SameSite=Lax\z
            }x;
            my ($auth) = ($cookies[0] // '') =~
                /\APowAuth=(1\.[A-Za-z0-9_-]{14}\.[A-Za-z0-9_-]{22});/;

            is $response->{status}, 200, 'valid proof reaches backend';
            is $response->{body}, $body, 'request body reaches backend exactly';
            is scalar(@cookies), 2, 'valid proof creates two cookie fields';
            like $cookies[0], $secure_pattern,
                'auth cookie is exact and secure by default';
            is length($auth), 39, 'issued auth value has fixed length';
            is $cookies[1], '__pow_p=; Max-Age=0; Path=/',
                'proof cookie is cleared at fixed root path';
            unlike join("\n", @cookies), qr/(?:Domain|Expires)=/i,
                'cookie fields omit Domain and Expires';

            my $follow_up = request(
                $protocol,
                headers => [[Cookie => "PowAuth=$auth"]],
            );
            is $follow_up->{status}, 200, 'issued auth cookie passes';
            is scalar(set_cookie_values($follow_up)), 0,
                'auth pass emits no replacement cookie';

            my $insecure = submit_valid_proof(
                $protocol,
                path => '/insecure',
            );
            my @insecure_cookies = set_cookie_values($insecure);

            is $insecure->{status}, 200, 'development opt-out proof passes';
            like $insecure_cookies[0],
                qr/; Path=\/; HttpOnly; SameSite=Lax\z/,
                'development auth cookie keeps non-Secure attributes';
            unlike $insecure_cookies[0], qr/; Secure(?:;|\z)/,
                'development opt-out omits only Secure';

            for my $offset (-1, 0, 1) {
                is submit_valid_proof($protocol, offset => $offset)->{status},
                    200, "bucket offset $offset is accepted";
            }

            my $bucket = current_bucket($protocol);
            for my $case (
                ['malformed', '__pow_p=garbage'],
                ['oversized', '__pow_p=' . ('x' x 65)],
                ['wrong counter',
                 '__pow_p=1.' . $bucket . '.' . invalid_counter($bucket)],
                ['stale bucket',
                 '__pow_p=' . proof_output(bucket => $bucket - 2)
                    ->{proof_cookie}],
                ['future bucket',
                 '__pow_p=' . proof_output(bucket => $bucket + 2)
                    ->{proof_cookie}],
                ['wrong IP',
                 '__pow_p=' . proof_invalid_for_client($bucket, $other_ip)
                    ->{proof_cookie}],
            ) {
                assert_challenge(
                    request(
                        $protocol,
                        headers => [[Cookie => $case->[1]]],
                    ),
                    $case->[0],
                );
            }

            my $valid = proof_output(bucket => $bucket)->{proof_cookie};
            assert_challenge(
                request(
                    $protocol,
                    headers => [[Cookie =>
                        "__pow_p=invalid; __pow_p=$valid"]],
                ),
                'invalid first proof shadows valid second',
            );

            my $auth_fail_before = read_log();
            my $auth_fail_proof_pass = request(
                $protocol,
                headers => [[Cookie =>
                    "PowAuth=a; PowAuth=b; PowAuth=c; PowAuth=d; "
                    . "__pow_p=$valid"]],
            );
            my $auth_fail_delta = substr(
                read_log(), length($auth_fail_before)
            );

            is $auth_fail_proof_pass->{status}, 200,
                'four failed auth values do not hide proof';
            is(() = $auth_fail_delta =~
                /operation=auth verdict=invalid occurrences=4/g, 1,
                'auth failure contributes one summary before proof success');
            unlike $auth_fail_delta, qr/verdict=valid|operation=proof/,
                'proof success adds no log summary';

            my $proof_fail_before = read_log();
            assert_challenge(
                request(
                    $protocol,
                    headers => [[Cookie => '__pow_p=LOG-SENTINEL']],
                ),
                'invalid proof logging case',
            );
            my $proof_fail_delta = substr(
                read_log(), length($proof_fail_before)
            );

            is(() = $proof_fail_delta =~
                /operation=proof verdict=invalid value_len=12/g, 1,
                'invalid proof emits one length-only summary');
            unlike $proof_fail_delta, qr/LOG-SENTINEL/,
                'invalid proof bytes are not logged';
        };
    }

    cmp_ok backend_reach_count($backend), '>', 0,
        'backend reach marker records successful requests';
};
$error = $@;

my $backend_cleanup = stop_backend($backend);
ok($backend_cleanup->{reaped}, 'test backend is reaped');
ok(!defined($backend) || !-e $backend->{directory},
   'test backend prefix is removed');
my $cleanup = stop_nginx($runtime);
ok($cleanup->{reaped}, 'NGINX master is reaped');
ok($cleanup->{group_gone}, 'NGINX process group is gone');

die $error if $error ne '';

done_testing();
