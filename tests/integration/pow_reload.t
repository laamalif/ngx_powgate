use strict;
use warnings;

use Fcntl qw(SEEK_SET);
use File::Temp qw(tempdir);
use IO::Socket::INET;
use Time::HiRes qw(CLOCK_MONOTONIC clock_gettime sleep);
use Test::More;

use PowGate::TestHTTPS qw(generate_tls_fixture https_request);
use PowGate::TestNginx qw(
    atomic_write
    nginx_child_pids
    signal_nginx
    start_nginx
    stop_nginx
    write_file
);

my $current = '0123456789aBcDeF' x 4;
my $next = 'fEdCbA9876543210' x 4;
my $invalid = 'not-a-valid-secret';
my $runtime;


END {
    stop_nginx($runtime) if defined $runtime;
}


sub wait_until {
    my ($predicate, $seconds) = @_;
    my $deadline = clock_gettime(CLOCK_MONOTONIC) + $seconds;

    do {
        my $value = $predicate->();

        return $value if $value;
        sleep 0.05;
    } while (clock_gettime(CLOCK_MONOTONIC) < $deadline);

    return;
}


sub log_suffix {
    my ($path, $offset) = @_;
    my $bytes = '';

    return $bytes if !-e $path;

    open my $fh, '<:raw', $path or die "open $path: $!";
    seek $fh, $offset, SEEK_SET or die "seek $path: $!";

    while (length($bytes) < 64 * 1024) {
        my $chunk;
        my $read = sysread $fh, $chunk, 4096;

        if (!defined $read) {
            next if $!{EINTR};
            die "read $path: $!";
        }

        last if $read == 0;
        $bytes .= substr $chunk, 0, 64 * 1024 - length($bytes);
    }

    close $fh or die "close $path: $!";

    return $bytes;
}


sub contains_pid {
    my ($pids, $wanted) = @_;

    for my $pid (@$pids) {
        return 1 if $pid == $wanted;
    }

    return 0;
}


sub isolated_pid_alive {
    my ($pid, $pgid) = @_;

    return 0 if !defined $pid || $pid !~ /\A\d+\z/ || $pid <= 1;
    return 0 if !defined $pgid || $pgid !~ /\A\d+\z/ || $pgid <= 1;
    return 0 if $pgid == getpgrp(0);
    return 0 if getpgrp($pid) != $pgid;

    return kill 0, $pid;
}


subtest 'missing runtime binary fails during startup' => sub {
    my $directory = tempdir(CLEANUP => 1);
    my $missing = "$directory/missing-nginx";
    my $started = clock_gettime(CLOCK_MONOTONIC);
    my $error;

    eval {
        my $failed = start_nginx(
            sub { return ''; },
            nginx_binary => $missing,
        );

        stop_nginx($failed);
    };
    $error = $@;

    like $error, qr/exec .*missing-nginx.*failed/,
        'exec failure is reported before a runtime is returned';
    cmp_ok clock_gettime(CLOCK_MONOTONIC) - $started, '<', 5,
        'exec failure is bounded';
};


subtest 'invalid module fails during startup' => sub {
    my $directory = tempdir(CLEANUP => 1);
    my $missing = "$directory/missing-module.so";
    my $started = clock_gettime(CLOCK_MONOTONIC);
    my $error;

    eval {
        my $failed = start_nginx(
            sub { return ''; },
            module_path => $missing,
        );

        stop_nginx($failed);
    };
    $error = $@;

    like $error, qr/(?:dlopen\(\).*failed|cannot open shared object file)/,
        'module load failure is reported before a runtime is returned';
    cmp_ok clock_gettime(CLOCK_MONOTONIC) - $started, '<', 5,
        'module load failure is bounded';
};


subtest 'post-fork exception reaps the owned child' => sub {
    my $caller_pid = $$;
    my $child_pid;
    my $prefix;
    my $error;

    eval {
        my $failed = start_nginx(
            sub { return ''; },
            after_fork => sub {
                my ($runtime) = @_;

                $child_pid = $runtime->{pid};
                $prefix = $runtime->{prefix};
                die "injected post-fork failure\n";
            },
        );

        stop_nginx($failed);
    };
    $error = $@;

    like $error, qr/injected post-fork failure/,
        'injected parent failure is propagated';
    is $$, $caller_pid, 'caller survives post-fork cleanup';
    ok defined $child_pid && $child_pid > 1,
        'owned child PID was recorded before injected failure';
    ok defined $prefix && !-e $prefix,
        'prefix is removed only after complete post-fork cleanup';
};


subtest 'occupied port retries with a fresh runtime attempt' => sub {
    my @attempts;
    my $listener;
    my $retry_runtime;
    my $retry_tls;
    my $error;

    eval {
        $retry_runtime = start_nginx(
            sub {
                my ($prefix, $port) = @_;

                push @attempts, [$prefix, $port];
                $retry_tls = generate_tls_fixture($prefix);

                return <<"NGINX";
    server {
        listen 127.0.0.1:$port ssl;
        http2 on;
        ssl_certificate $retry_tls->{certificate};
        ssl_certificate_key $retry_tls->{key};
        location / { pow off; return 200 "retry\\n"; }
    }
NGINX
            },
            after_port_selection => sub {
                my ($prefix, $port) = @_;

                if (@attempts == 1) {
                    $listener = IO::Socket::INET->new(
                        LocalAddr => '127.0.0.1',
                        LocalPort => $port,
                        Listen => 1,
                        Proto => 'tcp',
                    ) or die "occupy first runtime port: $!";
                } else {
                    close $listener
                        or die "close occupied runtime port: $!";
                    undef $listener;
                }
            },
        );

        for my $protocol ('1.1', '2') {
            my $response = https_request(
                $retry_runtime,
                protocol => $protocol,
                method => 'GET',
                path => '/',
            );

            is $response->{status}, 200,
                "retry runtime serves HTTPS $protocol";
            is $response->{protocol}, $protocol,
                "retry runtime negotiates $protocol";
        }
    };
    $error = $@;

    close $listener if defined $listener;
    my $stopped = stop_nginx($retry_runtime);
    $retry_runtime = undef;

    is scalar @attempts, 2, 'bind failure triggers one fresh attempt';

    SKIP: {
        skip 'retry attempt was not observed', 3 if @attempts < 2;

        isnt $attempts[0][0], $attempts[1][0],
            'retry uses a fresh runtime prefix';
        isnt $attempts[0][1], $attempts[1][1],
            'retry reserves a fresh runtime port';
        ok !-e $attempts[0][0],
            'failed bind attempt is cleaned before retry returns';
    }

    ok !defined $listener, 'occupied listener is closed before retry';
    ok $stopped->{reaped} && $stopped->{group_gone},
        'successful retry runtime is completely cleaned';
    fail("occupied-port retry aborted: $error") if $error ne '';
};


subtest 'forced cleanup terminates the isolated process group' => sub {
    my $directory = tempdir(CLEANUP => 1);
    my $fake_nginx = "$directory/nginx";
    my $fake_runtime;
    my $child_pid;
    my $prefix;
    my $master_pid;
    my $test_error;

    write_file(
        $fake_nginx,
        <<'PERL',
#!/usr/bin/perl
use strict;
use warnings;

my $prefix;

for (my $i = 0; $i < @ARGV; $i++) {
    $prefix = $ARGV[$i + 1] if $ARGV[$i] eq '-p';
}

die "missing -p" if !defined $prefix;

open my $pid_fh, '>:raw', "$prefix/logs/nginx.pid"
    or die "open master pid: $!";
print {$pid_fh} "$$\n" or die "write master pid: $!";
close $pid_fh or die "close master pid: $!";

$SIG{TERM} = 'IGNORE';

my $child = fork;
die "fork descendant: $!" if !defined $child;

if ($child == 0) {
    $SIG{TERM} = 'IGNORE';
    while (1) {
        select undef, undef, undef, 30;
    }
}

open my $child_fh, '>:raw', "$prefix/logs/child.pid"
    or die "open child pid: $!";
print {$child_fh} "$child\n" or die "write child pid: $!";
close $child_fh or die "close child pid: $!";

while (1) {
    select undef, undef, undef, 30;
}
PERL
        0700,
    );

    eval {
        $fake_runtime = start_nginx(
            sub { return ''; },
            nginx_binary => $fake_nginx,
        );
        $prefix = $fake_runtime->{prefix};
        $master_pid = $fake_runtime->{pid};

        $child_pid = wait_until(
            sub {
                my $path = "$fake_runtime->{prefix}/logs/child.pid";

                return if !-e $path;
                open my $fh, '<:raw', $path or die "open $path: $!";
                my $pid = <$fh>;
                close $fh or die "close $path: $!";
                chomp $pid;
                return $pid;
            },
            5,
        );

        die "fake descendant PID was not observed\n"
            if !defined $child_pid;
        die "injected fake assertion failure\n";
    };
    $test_error = $@;

    my $stopped;
    my $cleanup_error;

    eval { $stopped = stop_nginx($fake_runtime); };
    $cleanup_error = $@;
    $fake_runtime = undef;

    like $test_error, qr/injected fake assertion failure/,
        'injected assertion exception is captured';
    is $cleanup_error, '', 'exception-path cleanup succeeds';
    ok defined $child_pid && $child_pid > 1,
        'TERM-resistant descendant PID is valid';
    ok defined $master_pid && $master_pid > 1
        && getpgrp(0) != $master_pid,
        'runtime group differs from the caller group';

    SKIP: {
        skip 'exception-path cleanup did not return', 3
            if !defined $stopped;

        ok $stopped->{reaped}, 'TERM-resistant master is reaped';
        ok $stopped->{forced}, 'forced process-group cleanup is reported';
        ok $stopped->{group_gone}, 'isolated process group is gone';
    }

    ok !-e $prefix, 'runtime prefix is removed after complete cleanup';

    my $descendant_gone = wait_until(
        sub {
            return isolated_pid_alive($child_pid, $master_pid) ? undef : 1;
        },
        2,
    );

    ok $descendant_gone, 'TERM-resistant descendant is gone';
};


my $error;
my $tls;

eval {
    $runtime = start_nginx(
        sub {
            my ($prefix, $port) = @_;

            atomic_write("$prefix/conf/pow.secret", $current, 0600);
            $tls = generate_tls_fixture($prefix);

            return <<"NGINX";
    pow_secret_file pow.secret;

    server {
        listen 127.0.0.1:$port ssl;
        http2 on;
        ssl_certificate $tls->{certificate};
        ssl_certificate_key $tls->{key};

        location / {
            pow off;
            return 200 "backend\\n";
        }
    }
NGINX
        },
    );

    for my $protocol ('1.1', '2') {
        my $response = https_request(
            $runtime,
            protocol => $protocol,
            method => 'GET',
            path => '/',
        );

        is $response->{status}, 200,
            "initial worker serves HTTPS $protocol";
        is $response->{protocol}, $protocol,
            "initial worker negotiates $protocol";
    }

    my $initial_workers = wait_until(
        sub {
            my $pids = nginx_child_pids($runtime);

            return @$pids ? $pids : undef;
        },
        5,
    );

    ok $initial_workers && @$initial_workers,
        'initial worker process is observable';

    my $error_log = "$runtime->{prefix}/logs/error.log";
    my $error_offset = -e $error_log ? -s $error_log : 0;

    atomic_write("$runtime->{prefix}/conf/pow.secret", $invalid, 0600);
    ok signal_nginx($runtime, 'HUP'),
        'invalid reload signal is delivered';

    my $invalid_event = wait_until(
        sub {
            my $suffix = log_suffix($error_log, $error_offset);

            return $suffix
                if $suffix =~ /pow_secret_file: content must contain one or two/;
            return;
        },
        5,
    );

    like $invalid_event,
        qr/pow_secret_file: content must contain one or two 64-byte/,
        'invalid reload emits a new semantic diagnostic';
    unlike $invalid_event, qr/\Q$invalid\E/,
        'invalid secret content is not logged';
    unlike $invalid_event, qr/\Q$current\E|\Q$next\E/,
        'valid secret content is not logged';

    for my $protocol ('1.1', '2') {
        my $response = https_request(
            $runtime,
            protocol => $protocol,
            method => 'GET',
            path => '/',
        );

        is $response->{status}, 200,
            "invalid reload leaves HTTPS $protocol serving";
        is $response->{protocol}, $protocol,
            "invalid reload still negotiates $protocol";
    }

    my $after_invalid = nginx_child_pids($runtime);
    my $old_worker_survives = 0;

    for my $pid (@$initial_workers) {
        $old_worker_survives = 1 if contains_pid($after_invalid, $pid);
    }

    ok $old_worker_survives, 'invalid reload retains an old worker';

    atomic_write(
        "$runtime->{prefix}/conf/pow.secret",
        "$next\n$current\n",
        0600,
    );
    ok signal_nginx($runtime, 'HUP'),
        'valid reload signal is delivered';

    my $new_workers = wait_until(
        sub {
            my $pids = nginx_child_pids($runtime);

            for my $pid (@$pids) {
                return $pids if !contains_pid($initial_workers, $pid);
            }

            return;
        },
        5,
    );

    ok $new_workers && @$new_workers,
        'valid reload creates a new worker process';

    for my $protocol ('1.1', '2') {
        my $response = https_request(
            $runtime,
            protocol => $protocol,
            method => 'GET',
            path => '/',
        );

        is $response->{status}, 200,
            "valid reload preserves HTTPS $protocol";
        is $response->{protocol}, $protocol,
            "valid reload negotiates $protocol";
    }
};
$error = $@;

my $stopped = stop_nginx($runtime);
$runtime = undef;

ok $stopped->{reaped}, 'NGINX master is reaped during cleanup';
ok !$stopped->{forced}, 'NGINX master exits during the TERM grace period';

fail("reload lifecycle aborted: $error") if $error ne '';

done_testing;
