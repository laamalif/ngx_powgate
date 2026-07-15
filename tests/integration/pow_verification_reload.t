use strict;
use warnings;

use Test::More;
use Time::HiRes qw(CLOCK_MONOTONIC clock_gettime sleep);

use lib 'tests/integration/lib';
use PowGate::TestBackend qw(start_backend stop_backend);
use PowGate::TestHTTPS qw(generate_tls_fixture https_request);
use PowGate::TestNginx qw(
    atomic_write
    nginx_child_pids
    signal_nginx
    start_nginx
    stop_nginx
    wait_for_worker_generation
    write_file
);
use PowGate::TestReference qw(
    auth_cookie_value
    parse_challenge
    refsolve_json
    set_cookie_values
);


my $secret_a = '000102030405060708090a0b0c0d0e0f'
    . '101112131415161718191a1b1c1d1e1f';
my $secret_b = 'f0e0d0c0b0a090807060504030201000'
    . '112233445566778899aabbccddeeff00';
my $ipv4 = '198.51.100.44';
my $ipv4_peer = '198.51.100.45';
my $ipv6 = '2001:db8:1::44';
my $ipv6_peer = '2001:db8:1::45';


sub policy {
    my ($difficulty, $bind_ipv4, $bind_ipv6) = @_;

    return "pow on;\n"
        . "pow_difficulty $difficulty;\n"
        . "pow_bind_ipv4 $bind_ipv4;\n"
        . "pow_bind_ipv6 $bind_ipv6;\n"
        . "pow_cookie_name PowAuth;\n"
        . "pow_log_level notice;\n";
}


sub request {
    my ($runtime, $protocol, %options) = @_;

    return https_request(
        $runtime,
        protocol => $protocol,
        method => 'GET',
        path => '/',
        headers => [
            ['X-Forwarded-For' => $options{ip} // $ipv4],
            defined($options{cookie})
                ? ([Cookie => $options{cookie}]) : (),
        ],
    );
}


sub current_bucket {
    my ($runtime, $protocol, $ip) = @_;
    my $response = request($runtime, $protocol, ip => $ip);
    my $value = $response->{headers}{'powgate-challenge'}[0];

    die "reload test could not observe a challenge"
        if $response->{status} != 403 || !defined $value;
    return parse_challenge($value)->{bucket};
}


sub proof_check {
    my (%options) = @_;

    return refsolve_json(
        'proof-check',
        '--secret-hex', $options{secret_hex},
        '--ip', $options{ip},
        '--plen', $options{plen},
        '--bucket', $options{bucket},
        '--difficulty', $options{difficulty},
        '--counter', $options{counter},
    )->{valid};
}


sub proof_with_invalid_alternate {
    my (%options) = @_;
    my $start = 0;

    for (1 .. 128) {
        my $proof = refsolve_json(
            'mine',
            '--secret-hex', $options{secret_hex},
            '--ip', $options{ip},
            '--plen', $options{plen},
            '--bucket', $options{bucket},
            '--difficulty', $options{difficulty},
            '--start-counter', $start,
        );
        my $alternate = $options{alternate};

        return $proof if !proof_check(
            secret_hex => $alternate->{secret_hex},
            ip => $alternate->{ip},
            plen => $alternate->{plen},
            bucket => $options{bucket},
            difficulty => $alternate->{difficulty},
            counter => $proof->{counter},
        );
        $start = $proof->{counter} + 1;
    }

    die "reload test could not find bounded context-separated proof";
}


sub auth_value {
    my (%options) = @_;

    return auth_cookie_value(
        secret_hex => $options{secret_hex},
        ip => $options{ip},
        expiry => time + 3600,
        difficulty => $options{difficulty},
        plen => $options{plen},
    );
}


sub reload_valid {
    my ($runtime, $policy_path, $secret_path, $policy_bytes,
        $secret_bytes, $name) = @_;
    my $old = nginx_child_pids($runtime);

    ok @$old > 0, "$name observes the old worker generation";
    atomic_write($policy_path, $policy_bytes, 0600);
    atomic_write($secret_path, $secret_bytes, 0600);
    ok signal_nginx($runtime, 'HUP'), "$name delivers HUP";

    my $new = wait_for_worker_generation($runtime, $old, 8);

    ok grep({ my $pid = $_; !grep { $_ == $pid } @$old } @$new),
        "$name observes a new worker and retires every old worker";
}


sub read_log {
    my ($runtime) = @_;

    open my $fh, '<:raw', "$runtime->{prefix}/logs/error.log"
        or die "open reload error log: $!";
    local $/;
    my $bytes = <$fh>;
    close $fh or die "close reload error log: $!";
    return $bytes;
}


sub wait_for_log {
    my ($runtime, $offset, $pattern) = @_;
    my $deadline = clock_gettime(CLOCK_MONOTONIC) + 4;

    while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
        my $delta = substr(read_log($runtime), $offset);

        return $delta if $delta =~ $pattern;
        sleep 0.05;
    }

    die "reload diagnostic did not appear before deadline";
}


sub run_matrix {
    my ($protocol) = @_;
    my $backend = start_backend();
    my $runtime;
    my $policy_path;
    my $secret_path;
    my $error;

    eval {
        $runtime = start_nginx(sub {
            my ($prefix, $port) = @_;
            my $tls = generate_tls_fixture($prefix);

            $policy_path = "$prefix/conf/pow-policy.conf";
            $secret_path = "$prefix/conf/pow.secret";
            write_file($policy_path, policy(1, 24, 64), 0600);
            write_file($secret_path, $secret_a, 0600);

            return <<"NGINX";
pow_secret_file pow.secret;

server {
    listen 127.0.0.1:$port ssl;
    http2 on;
    ssl_certificate $tls->{certificate};
    ssl_certificate_key $tls->{key};
    set_real_ip_from 127.0.0.1;
    real_ip_header X-Forwarded-For;
    include pow-policy.conf;

    location / {
        proxy_pass http://127.0.0.1:$backend->{port};
    }
}
NGINX
        });

        my $bucket = current_bucket($runtime, $protocol, $ipv4);
        my $difficulty_proof = proof_with_invalid_alternate(
            secret_hex => $secret_a,
            ip => $ipv4,
            plen => 120,
            bucket => $bucket,
            difficulty => 1,
            alternate => {
                secret_hex => $secret_a,
                ip => $ipv4,
                plen => 120,
                difficulty => 2,
            },
        );
        my $difficulty_auth = auth_value(
            secret_hex => $secret_a,
            ip => $ipv4,
            difficulty => 1,
            plen => 120,
        );

        is request(
            $runtime, $protocol,
            cookie => "__pow_p=$difficulty_proof->{proof_cookie}",
        )->{status}, 200, 'lower-difficulty proof passes before tightening';
        is request(
            $runtime, $protocol,
            cookie => "PowAuth=$difficulty_auth",
        )->{status}, 200, 'lower-difficulty auth passes before tightening';

        reload_valid(
            $runtime, $policy_path, $secret_path,
            policy(2, 24, 64), $secret_a,
            'difficulty reload',
        );

        is request(
            $runtime, $protocol,
            cookie => "__pow_p=$difficulty_proof->{proof_cookie}",
        )->{status}, 403,
            'in-flight proof is checked against current difficulty';
        is request(
            $runtime, $protocol,
            cookie => "PowAuth=$difficulty_auth",
        )->{status}, 403,
            'auth difficulty floor tightens after reload';

        $bucket = current_bucket($runtime, $protocol, $ipv4);
        my $ipv4_proof = proof_with_invalid_alternate(
            secret_hex => $secret_a,
            ip => $ipv4,
            plen => 120,
            bucket => $bucket,
            difficulty => 2,
            alternate => {
                secret_hex => $secret_a,
                ip => $ipv4,
                plen => 128,
                difficulty => 2,
            },
        );
        my $ipv6_bucket = current_bucket($runtime, $protocol, $ipv6);
        my $ipv6_proof = proof_with_invalid_alternate(
            secret_hex => $secret_a,
            ip => $ipv6,
            plen => 64,
            bucket => $ipv6_bucket,
            difficulty => 2,
            alternate => {
                secret_hex => $secret_a,
                ip => $ipv6,
                plen => 128,
                difficulty => 2,
            },
        );
        my $ipv4_auth = auth_value(
            secret_hex => $secret_a,
            ip => $ipv4,
            difficulty => 2,
            plen => 120,
        );
        my $ipv6_auth = auth_value(
            secret_hex => $secret_a,
            ip => $ipv6,
            difficulty => 2,
            plen => 64,
        );

        is request(
            $runtime, $protocol,
            cookie => "__pow_p=$ipv4_proof->{proof_cookie}",
        )->{status}, 200, 'IPv4 proof passes under /24 policy';
        is request(
            $runtime, $protocol,
            ip => $ipv6,
            cookie => "__pow_p=$ipv6_proof->{proof_cookie}",
        )->{status}, 200, 'IPv6 proof passes under /64 policy';
        is request(
            $runtime, $protocol,
            ip => $ipv4_peer,
            cookie => "PowAuth=$ipv4_auth",
        )->{status}, 200, 'IPv4 /24 auth passes for a subnet peer';
        is request(
            $runtime, $protocol,
            ip => $ipv6_peer,
            cookie => "PowAuth=$ipv6_auth",
        )->{status}, 200, 'IPv6 /64 auth passes for a subnet peer';

        reload_valid(
            $runtime, $policy_path, $secret_path,
            policy(2, 32, 128), $secret_a,
            'binding reload',
        );

        is request(
            $runtime, $protocol,
            cookie => "__pow_p=$ipv4_proof->{proof_cookie}",
        )->{status}, 403, 'proof uses current IPv4 /32 binding';
        is request(
            $runtime, $protocol,
            ip => $ipv6,
            cookie => "__pow_p=$ipv6_proof->{proof_cookie}",
        )->{status}, 403, 'proof uses current IPv6 /128 binding';
        is request(
            $runtime, $protocol,
            ip => $ipv4_peer,
            cookie => "PowAuth=$ipv4_auth",
        )->{status}, 403, 'IPv4 auth prefix floor tightens to /32';
        is request(
            $runtime, $protocol,
            ip => $ipv6_peer,
            cookie => "PowAuth=$ipv6_auth",
        )->{status}, 403, 'IPv6 auth prefix floor tightens to /128';

        my $rotation_auth = auth_value(
            secret_hex => $secret_a,
            ip => $ipv4,
            difficulty => 2,
            plen => 128,
        );
        $bucket = current_bucket($runtime, $protocol, $ipv4);
        my $rotation_proof = proof_with_invalid_alternate(
            secret_hex => $secret_a,
            ip => $ipv4,
            plen => 128,
            bucket => $bucket,
            difficulty => 2,
            alternate => {
                secret_hex => $secret_b,
                ip => $ipv4,
                plen => 128,
                difficulty => 2,
            },
        );

        is request(
            $runtime, $protocol,
            cookie => "PowAuth=$rotation_auth",
        )->{status}, 200, 'current-secret auth passes before rotation';
        is request(
            $runtime, $protocol,
            cookie => "__pow_p=$rotation_proof->{proof_cookie}",
        )->{status}, 200, 'current-secret proof passes before rotation';

        my $old_workers = nginx_child_pids($runtime);
        my $log_offset = length(read_log($runtime));

        atomic_write($secret_path, "$secret_b\n$secret_a", 0644);
        ok signal_nginx($runtime, 'HUP'),
            'insecure secret reload signal is delivered';
        my $permission_delta = wait_for_log(
            $runtime, $log_offset,
            qr/must grant no group or other permissions/,
        );

        like $permission_delta,
            qr/must grant no group or other permissions/,
            'reload revalidates secret-file permissions';
        is_deeply nginx_child_pids($runtime), $old_workers,
            'rejected secret reload retains the old worker generation';

        reload_valid(
            $runtime, $policy_path, $secret_path,
            policy(2, 32, 128), "$secret_b\n$secret_a",
            'rotation reload',
        );

        is request(
            $runtime, $protocol,
            cookie => "PowAuth=$rotation_auth",
        )->{status}, 200, 'previous-secret auth passes after rotation';
        is request(
            $runtime, $protocol,
            cookie => "__pow_p=$rotation_proof->{proof_cookie}",
        )->{status}, 200, 'pre-rotation proof passes through previous secret';

        $bucket = current_bucket($runtime, $protocol, $ipv4);
        my $new_proof = refsolve_json(
            'mine',
            '--secret-hex', $secret_b,
            '--ip', $ipv4,
            '--plen', 128,
            '--bucket', $bucket,
            '--difficulty', 2,
        );
        my $new_response = request(
            $runtime, $protocol,
            cookie => "__pow_p=$new_proof->{proof_cookie}",
        );
        my ($new_auth) = join("\n", set_cookie_values($new_response)) =~
            /\APowAuth=([^;]+)/m;

        is $new_response->{status}, 200,
            'new current secret verifies and issues auth';
        ok defined($new_auth), 'new current secret issues an auth value';

        reload_valid(
            $runtime, $policy_path, $secret_path,
            policy(2, 32, 128), $secret_b,
            'previous-secret removal reload',
        );

        is request(
            $runtime, $protocol,
            cookie => "PowAuth=$rotation_auth",
        )->{status}, 403, 'old auth fails after previous secret removal';
        is request(
            $runtime, $protocol,
            cookie => "__pow_p=$rotation_proof->{proof_cookie}",
        )->{status}, 403, 'old proof fails after previous secret removal';
        is request(
            $runtime, $protocol,
            cookie => "PowAuth=$new_auth",
        )->{status}, 200,
            'first secret signed new auth and survives previous removal';
    };
    $error = $@;

    my $backend_cleanup = stop_backend($backend);
    ok $backend_cleanup->{reaped}, 'reload backend is reaped';
    my $nginx_cleanup = stop_nginx($runtime);
    ok $nginx_cleanup->{reaped}, 'reload NGINX master is reaped';
    ok $nginx_cleanup->{group_gone}, 'reload NGINX process group is gone';

    die $error if $error ne '';
}


for my $protocol ('1.1', '2') {
    subtest "reload verification over HTTPS $protocol" => sub {
        run_matrix($protocol);
    };
}

done_testing();
