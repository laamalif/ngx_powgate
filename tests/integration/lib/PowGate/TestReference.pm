package PowGate::TestReference;

use strict;
use warnings;

use Exporter qw(import);
use IO::Select;
use IPC::Open3;
use JSON::PP qw(decode_json);
use POSIX qw(WNOHANG);
use Symbol qw(gensym);
use Time::HiRes qw(CLOCK_MONOTONIC clock_gettime sleep);

our @EXPORT_OK = qw(
    auth_cookie_value
    parse_challenge
    refsolve_json
    set_cookie_values
);

my $OUTPUT_LIMIT = 4096;
my $TIMEOUT = 5;


sub _run_refsolve {
    my (@arguments) = @_;
    my $stderr = gensym;
    my ($stdin, $stdout);
    my $pid = open3(
        $stdin, $stdout, $stderr,
        $^X, 'tools/refsolve.py', @arguments,
    );
    my $selector = IO::Select->new($stdout, $stderr);
    my %buffers = (stdout => '', stderr => '');
    my %handles = (
        fileno($stdout) => 'stdout',
        fileno($stderr) => 'stderr',
    );
    my $deadline = clock_gettime(CLOCK_MONOTONIC) + $TIMEOUT;
    my $status;

    close $stdin or die "close refsolve stdin: $!";

    while ($selector->count != 0
           && clock_gettime(CLOCK_MONOTONIC) < $deadline)
    {
        for my $fh ($selector->can_read(0.05)) {
            my $chunk;
            my $read = sysread $fh, $chunk, 1024;

            if (!defined $read) {
                next if $!{EINTR};
                die "read refsolve output: $!";
            }

            if ($read == 0) {
                $selector->remove($fh);
                close $fh or die "close refsolve output: $!";
                next;
            }

            my $name = $handles{fileno $fh};

            die "refsolve output exceeds limit"
                if length($buffers{$name}) + $read > $OUTPUT_LIMIT;
            $buffers{$name} .= $chunk;
        }
    }

    if ($selector->count != 0) {
        kill 'TERM', $pid;
        sleep 0.05;
        kill 'KILL', $pid if waitpid($pid, WNOHANG) == 0;
        waitpid($pid, 0);
        die "refsolve timed out";
    }

    while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
        my $waited = waitpid $pid, WNOHANG;

        if ($waited == $pid) {
            $status = $?;
            last;
        }
        if ($waited == -1) {
            next if $!{EINTR};
            die "wait refsolve: $!";
        }
        sleep 0.01;
    }

    if (!defined $status) {
        kill 'TERM', $pid;
        sleep 0.05;
        kill 'KILL', $pid if waitpid($pid, WNOHANG) == 0;
        waitpid($pid, 0);
        die "refsolve timed out";
    }

    die "refsolve failed: $buffers{stderr}"
        if ($status & 127) != 0 || ($status >> 8) != 0;
    die "refsolve wrote diagnostics: $buffers{stderr}"
        if $buffers{stderr} ne '';

    return $buffers{stdout};
}


sub refsolve_json {
    my (@arguments) = @_;
    my $decoded = eval { decode_json(_run_refsolve(@arguments)) };

    die "refsolve returned invalid JSON: $@" if $@ ne '';
    die "refsolve JSON must be an object" if ref($decoded) ne 'HASH';

    return $decoded;
}


sub auth_cookie_value {
    my (%arguments) = @_;
    my $output = refsolve_json(
        'auth',
        '--secret-hex', $arguments{secret_hex},
        '--ip', $arguments{ip},
        '--expiry', $arguments{expiry},
        '--difficulty', $arguments{difficulty},
        '--plen', $arguments{plen},
    );

    die "refsolve auth response is incomplete"
        if !defined $output->{auth_cookie}
           || ref($output->{auth_cookie});

    return $output->{auth_cookie};
}


sub parse_challenge {
    my ($value) = @_;
    my ($difficulty, $bucket, $nonce);
    my $pattern = qr{
        \Av=1;[ ]d=([1-9]|[12][0-9]|3[0-2]);
        [ ]b=(0|[1-9][0-9]{0,19});[ ]n=([A-Za-z0-9_-]{43})\z
    }x;

    die "challenge must be scalar bytes" if !defined $value || ref($value);
    ($difficulty, $bucket, $nonce) = $value =~ $pattern;
    die "invalid PowGate challenge" if !defined $nonce;

    return {
        bucket => $bucket,
        difficulty => 0 + $difficulty,
        nonce => $nonce,
    };
}


sub set_cookie_values {
    my ($response) = @_;

    die "response must be a hash reference" if ref($response) ne 'HASH';
    return @{$response->{headers}{'set-cookie'} // []};
}


1;
