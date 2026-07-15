package PowGate::TestHTTPS;

use strict;
use warnings;

use Exporter qw(import);
use File::Temp qw(tempfile);
use IO::Select;
use IPC::Open3;
use POSIX qw(WNOHANG);
use Symbol qw(gensym);
use Time::HiRes qw(CLOCK_MONOTONIC clock_gettime sleep);

our @EXPORT_OK = qw(
    generate_tls_fixture
    https_request
    https_sequence
);

my $OUTPUT_LIMIT = 64 * 1024;


sub _read_pipe {
    my ($selector, $buffers, $handles, $wait) = @_;

    for my $fh ($selector->can_read($wait)) {
        my $chunk;
        my $read = sysread $fh, $chunk, 16 * 1024;

        if (!defined $read) {
            next if $!{EINTR};
            die "read command output: $!";
        }

        if ($read == 0) {
            $selector->remove($fh);
            close $fh or die "close command output: $!";
            next;
        }

        my $name = $handles->{fileno $fh};
        my $remaining = $OUTPUT_LIMIT - length $buffers->{$name};

        $buffers->{$name} .= substr $chunk, 0, $remaining
            if $remaining > 0;
    }
}


sub _run_command {
    my ($timeout, @command) = @_;
    my $stderr = gensym;
    my ($stdin, $stdout);
    my $pid = open3($stdin, $stdout, $stderr, @command);
    my $selector = IO::Select->new($stdout, $stderr);
    my %buffers = (stdout => '', stderr => '');
    my %handles = (
        fileno($stdout) => 'stdout',
        fileno($stderr) => 'stderr',
    );
    my $deadline = clock_gettime(CLOCK_MONOTONIC) + $timeout;
    my $raw_status;
    my $reaped = 0;

    close $stdin or die "close command stdin: $!";

    while ($selector->count != 0
           && clock_gettime(CLOCK_MONOTONIC) < $deadline)
    {
        _read_pipe($selector, \%buffers, \%handles, 0.05);
    }

    if ($selector->count != 0) {
        kill 'TERM', $pid;
        sleep 0.1;
        my $waited = waitpid($pid, WNOHANG);

        if ($waited == 0) {
            kill 'KILL', $pid;
            waitpid($pid, 0);
        }

        for my $fh ($selector->handles) {
            $selector->remove($fh);
            close $fh;
        }

        die "command timed out";
    }

    while (!$reaped && clock_gettime(CLOCK_MONOTONIC) < $deadline) {
        my $waited = waitpid($pid, WNOHANG);

        if ($waited == $pid) {
            $raw_status = $?;
            $reaped = 1;
            last;
        }

        if ($waited == -1) {
            next if $!{EINTR};
            die "wait command: $!";
        }

        sleep 0.01;
    }

    if (!$reaped) {
        kill 'TERM', $pid;
        sleep 0.1;
        kill 'KILL', $pid if waitpid($pid, WNOHANG) == 0;
        waitpid($pid, 0);
        die "command timed out";
    }

    return {
        exit_status => $raw_status >> 8,
        signal => $raw_status & 127,
        stderr => $buffers{stderr},
        stdout => $buffers{stdout},
    };
}


sub generate_tls_fixture {
    my ($prefix) = @_;
    my $certificate;
    my $key;
    my $result;

    die "TLS fixture requires a runtime prefix"
        if !defined $prefix || ref($prefix) || $prefix eq '';
    die "TLS fixture prefix contains a NUL or newline"
        if $prefix =~ /[\x00\r\n]/;

    $certificate = "$prefix/conf/powgate-test.crt";
    $key = "$prefix/conf/powgate-test.key";
    $result = _run_command(
        10,
        'openssl', 'req', '-x509', '-newkey', 'ec',
        '-pkeyopt', 'ec_paramgen_curve:P-256',
        '-sha256', '-nodes', '-days', '1',
        '-subj', '/CN=localhost',
        '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1',
        '-keyout', $key,
        '-out', $certificate,
    );

    die "OpenSSL certificate generation failed: $result->{stderr}"
        if $result->{exit_status} != 0 || $result->{signal} != 0;

    chmod 0600, $key or die "chmod TLS key: $!";
    chmod 0644, $certificate or die "chmod TLS certificate: $!";

    return { certificate => $certificate, key => $key };
}


sub _temporary_path {
    my ($prefix, $stem) = @_;
    my ($fh, $path) = tempfile(
        "powgate-$stem-XXXXXX",
        DIR => $prefix,
        UNLINK => 0,
    );

    close $fh or die "close temporary HTTPS file: $!";
    return $path;
}


sub _validate_request {
    my ($request) = @_;
    my $headers;

    die "HTTPS request must be a hash reference"
        if ref($request) ne 'HASH';
    $headers = $request->{headers} // [];
    die "invalid HTTPS method"
        if !defined $request->{method}
           || ref($request->{method})
           || $request->{method} !~ /\A[A-Z]+\z/;
    die "invalid HTTPS path"
        if !defined $request->{path}
           || ref($request->{path})
           || $request->{path} !~ m{\A/}
           || $request->{path} =~ /[\x00\r\n]/;
    die "HTTPS headers must be an array reference"
        if ref($headers) ne 'ARRAY';

    for my $header (@$headers) {
        die "HTTPS header must be a name/value pair"
            if ref($header) ne 'ARRAY' || @$header != 2;
        die "invalid HTTPS header name"
            if !defined $header->[0]
               || ref($header->[0])
               || $header->[0] !~ /\A[A-Za-z0-9-]+\z/;
        die "invalid HTTPS header value"
            if !defined $header->[1]
               || ref($header->[1])
               || $header->[1] =~ /[\x00\r\n]/;
    }
}


sub _curl_transfer_arguments {
    my ($runtime, $protocol, $request, $header_path, $body_path,
        $request_body_path, $host, $unix_socket) = @_;
    my @arguments = (
        '--silent', '--show-error', '--insecure',
        '--max-time', '5', '--path-as-is',
        '--retry', '20', '--retry-connrefused', '--retry-delay', '0',
        $protocol eq '1.1' ? '--http1.1' : '--http2',
        '--request', $request->{method},
        '--dump-header', $header_path,
        '--output', $body_path,
        '--write-out',
        "POWGATE_META\t%{http_version}\t%{http_code}"
        . "\t%{num_connects}\t%{local_port}\n",
    );

    if (defined $unix_socket) {
        push @arguments, '--unix-socket', $unix_socket;
    }

    for my $header (@{$request->{headers} // []}) {
        push @arguments, '--header', "$header->[0]: $header->[1]";
    }

    if (defined $request->{body}) {
        push @arguments, '--data-binary', "\@$request_body_path";
    }

    if ($host =~ /:/ && $host !~ /^\[/) {
        $host = "[$host]";
    }

    push @arguments, "https://$host:$runtime->{port}$request->{path}";
    return @arguments;
}


sub _read_file {
    my ($path) = @_;
    my $bytes;
    my $fh;

    open $fh, '<:raw', $path or die "open HTTPS output: $!";
    local $/;
    $bytes = <$fh>;
    close $fh or die "close HTTPS output: $!";

    die "HTTPS output exceeds limit" if length($bytes) > $OUTPUT_LIMIT;
    return $bytes;
}


sub _parse_headers {
    my ($bytes) = @_;
    my @blocks = grep { /\AHTTP\// } split /\r?\n\r?\n/, $bytes;
    my $block = $blocks[-1];
    my @lines;
    my %headers;
    my $status;

    die "curl returned no HTTP header block" if !defined $block;
    @lines = split /\r?\n/, $block;
    die "invalid HTTP status line"
        if shift(@lines) !~ m{\AHTTP/(?:1\.0|1\.1|2)\s+(\d{3})(?:\s|\z)};
    $status = 0 + $1;

    for my $line (@lines) {
        my ($name, $value) = split /:/, $line, 2;

        die "invalid response header" if !defined $value;
        $name = lc $name;
        $value =~ s/\A[ \t]+//;
        $value =~ s/[ \t]+\z//;
        push @{$headers{$name}}, $value;
    }

    return ($status, \%headers);
}


sub https_sequence {
    my ($runtime, %options) = @_;
    my $protocol = $options{protocol};
    my $requests = $options{requests};
    my $host = $options{host} // 'localhost';
    my $unix_socket = $options{unix_socket};
    my @arguments = ('curl');
    my @artifacts;
    my @responses;
    my $result;
    my @metadata;

    die "HTTPS runtime is invalid"
        if ref($runtime) ne 'HASH'
           || !defined $runtime->{prefix}
           || !defined $runtime->{port};
    die "HTTPS protocol must be 1.1 or 2"
        if !defined $protocol || ($protocol ne '1.1' && $protocol ne '2');
    die "HTTPS requests must be a nonempty array reference"
        if ref($requests) ne 'ARRAY' || !@$requests;
    die "invalid HTTPS host"
        if ref($host) || $host =~ /[\x00\r\n]/;
    die "invalid Unix socket path"
        if defined $unix_socket
           && (ref($unix_socket) || $unix_socket =~ /[\x00\r\n]/);

    eval {
        for my $index (0 .. $#$requests) {
            my $request = $requests->[$index];
            my $header_path;
            my $body_path;
            my $request_body_path;

            _validate_request($request);
            $header_path = _temporary_path($runtime->{prefix}, 'headers');
            $body_path = _temporary_path($runtime->{prefix}, 'body');
            push @artifacts, $header_path, $body_path;

            if (defined $request->{body}) {
                $request_body_path = _temporary_path(
                    $runtime->{prefix}, 'request-body'
                );
                open my $body_fh, '>:raw', $request_body_path
                    or die "open HTTPS request body: $!";
                print {$body_fh} $request->{body}
                    or die "write HTTPS request body: $!";
                close $body_fh or die "close HTTPS request body: $!";
                push @artifacts, $request_body_path;
            }

            push @arguments, '--next' if $index != 0;
            push @arguments, _curl_transfer_arguments(
                $runtime, $protocol, $request, $header_path, $body_path,
                $request_body_path, $host, $unix_socket
            );
            push @responses, {
                body_path => $body_path,
                header_path => $header_path,
            };
        }

        $result = _run_command(6 * scalar(@$requests) + 2, @arguments);
        die "curl HTTPS request failed: $result->{stderr}"
            if $result->{exit_status} != 0 || $result->{signal} != 0;

        @metadata = $result->{stdout} =~
            /^POWGATE_META\t([^\t\n]+)\t(\d{3})\t(\d+)\t(\d+)$/gm;
        die "curl HTTPS metadata count mismatch"
            if @metadata != 4 * @$requests;

        for my $index (0 .. $#responses) {
            my $reported_protocol = $metadata[$index * 4];
            my $reported_status = 0 + $metadata[$index * 4 + 1];
            my ($header_status, $headers) = _parse_headers(
                _read_file($responses[$index]{header_path})
            );

            die "curl negotiated $reported_protocol, expected $protocol"
                if $reported_protocol ne $protocol;
            die "curl status metadata mismatch"
                if $reported_status != $header_status;

            $responses[$index] = {
                body => _read_file($responses[$index]{body_path}),
                headers => $headers,
                local_port => 0 + $metadata[$index * 4 + 3],
                num_connects => 0 + $metadata[$index * 4 + 2],
                protocol => $reported_protocol,
                status => $reported_status,
            };
        }
    };
    my $error = $@;

    unlink @artifacts if @artifacts;
    die $error if $error ne '';

    return \@responses;
}


sub https_request {
    my ($runtime, %options) = @_;
    my $protocol = delete $options{protocol};
    my $host = delete $options{host};
    my $unix_socket = delete $options{unix_socket};
    my $response = https_sequence(
        $runtime,
        protocol => $protocol,
        requests => [\%options],
        defined($host) ? (host => $host) : (),
        defined($unix_socket) ? (unix_socket => $unix_socket) : (),
    );

    return $response->[0];
}


1;
