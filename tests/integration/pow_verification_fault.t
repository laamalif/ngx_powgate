use strict;
use warnings;

use Test::More;

use lib 'tests/integration/lib';
use PowGate::TestBackend qw(
    backend_reach_count
    start_backend
    stop_backend
);
use PowGate::TestHTTPS qw(
    generate_tls_fixture
    https_request
    https_sequence
);
use PowGate::TestNginx qw(start_nginx stop_nginx write_file);
use PowGate::TestReference qw(
    parse_challenge
    refsolve_json
    set_cookie_values
);


my $secret = '000102030405060708090a0b0c0d0e0f'
    . '101112131415161718191a1b1c1d1e1f';
my $client_ip = '198.51.100.44';
my @variants = (
    ['first', $ENV{POW_FAULT_FIRST_MODULE_PATH}],
    ['second', $ENV{POW_FAULT_SECOND_MODULE_PATH}],
);


for my $variant (@variants) {
    die "POW fault $variant->[0] module path is required"
        if !defined($variant->[1]) || $variant->[1] eq '';
    die "POW fault $variant->[0] module does not exist"
        if !-f $variant->[1];
}


sub read_log {
    my ($runtime) = @_;

    open my $fh, '<:raw', "$runtime->{prefix}/logs/error.log"
        or die "open fault error log: $!";
    local $/;
    my $bytes = <$fh>;
    close $fh or die "close fault error log: $!";
    return $bytes;
}


sub run_variant {
    my ($name, $module, $protocol) = @_;
    my $backend = start_backend();
    my $runtime;
    my $error;

    eval {
        $runtime = start_nginx(
            sub {
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
    pow_log_level notice;

    location /fault-sentinel {
        proxy_pass http://127.0.0.1:$backend->{port};
    }
}
NGINX
            },
            module_path => $module,
        );

        my $challenge = https_request(
            $runtime,
            protocol => $protocol,
            method => 'GET',
            path => '/fault-sentinel',
            headers => [['X-Forwarded-For' => $client_ip]],
        );
        my $bucket = parse_challenge(
            $challenge->{headers}{'powgate-challenge'}[0]
        )->{bucket};
        my $proof = refsolve_json(
            'mine',
            '--secret-hex', $secret,
            '--ip', $client_ip,
            '--plen', 128,
            '--bucket', $bucket,
            '--difficulty', 1,
        )->{proof_cookie};
        my $cookie_sentinel = "FAULT-COOKIE-$name-$protocol";
        my $body_sentinel = "FAULT-BODY-$name-$protocol";
        my $log_offset = length(read_log($runtime));
        my $requests = [
            {
                method => 'POST',
                path => '/fault-sentinel',
                body => $body_sentinel,
                headers => [
                    ['X-Forwarded-For' => $client_ip],
                    [Cookie =>
                        "sentinel=$cookie_sentinel; __pow_p=$proof"],
                ],
            },
            {
                method => 'POST',
                path => '/fault-sentinel',
                body => $body_sentinel,
                headers => [
                    ['X-Forwarded-For' => $client_ip],
                    [Cookie =>
                        "sentinel=$cookie_sentinel; __pow_p=$proof"],
                ],
            },
        ];
        my $responses = https_sequence(
            $runtime,
            protocol => $protocol,
            requests => $requests,
        );
        my $delta = substr(read_log($runtime), $log_offset);

        for my $index (0 .. 1) {
            is $responses->[$index]{status}, 500,
                "fault $name request $index returns 500";
            is scalar(set_cookie_values($responses->[$index])), 0,
                "fault $name request $index emits no cookie";
            ok !exists $responses->[$index]{headers}{'powgate-challenge'},
                "fault $name request $index emits no challenge";
        }

        if ($protocol eq '2') {
            is $responses->[1]{num_connects}, 0,
                "fault $name reuses the HTTP/2 connection";
        } else {
            is $responses->[1]{num_connects}, 1,
                "fault $name uses a fresh HTTP/1.1 connection after "
                . "the unread-body error";
        }
        is backend_reach_count($backend), 0,
            "fault $name never reaches the backend";
        is(() = $delta =~
            /operation=cookie_issue verdict=failed/g, 2,
            "fault $name logs one fixed internal error per request");
        unlike $delta, qr/operation=(?:auth|proof) verdict=invalid/,
            "fault $name emits no client-invalid summary";
        unlike $delta, qr/\Q$cookie_sentinel\E/,
            "fault $name does not log cookie sentinel";
        unlike $delta, qr/\Q$body_sentinel\E/,
            "fault $name does not log body sentinel";
        unlike $delta, qr/fault-sentinel/,
            "fault $name does not log URI sentinel";
    };
    $error = $@;

    my $backend_cleanup = stop_backend($backend);
    ok $backend_cleanup->{reaped}, "fault $name backend is reaped";
    my $nginx_cleanup = stop_nginx($runtime);
    ok $nginx_cleanup->{reaped}, "fault $name NGINX master is reaped";
    ok $nginx_cleanup->{group_gone},
        "fault $name NGINX process group is gone";

    die $error if $error ne '';
}


for my $variant (@variants) {
    for my $protocol ('1.1', '2') {
        subtest "fault $variant->[0] over HTTPS $protocol" => sub {
            run_variant($variant->[0], $variant->[1], $protocol);
        };
    }
}

done_testing();
