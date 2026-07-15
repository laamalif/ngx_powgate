package PowGate::TestBackend;

use strict;
use warnings;

use Exporter qw(import);
use File::Path qw(remove_tree);
use File::Temp qw(tempdir);
use IO::Socket::INET;
use POSIX qw(WNOHANG _exit);
use Time::HiRes qw(CLOCK_MONOTONIC clock_gettime sleep);

our @EXPORT_OK = qw(
    backend_reach_count
    start_backend
    stop_backend
);

my $HEADER_LIMIT = 16 * 1024;
my $BODY_LIMIT = 64 * 1024;


sub _write_all {
    my ($fh, $bytes) = @_;
    my $offset = 0;

    while ($offset < length($bytes)) {
        my $written = syswrite $fh, $bytes,
            length($bytes) - $offset, $offset;

        next if !defined($written) && $!{EINTR};
        return 0 if !defined($written) || $written == 0;
        $offset += $written;
    }

    return 1;
}


sub _read_request {
    my ($client) = @_;
    my $bytes = '';
    my $header_end;

    while (length($bytes) <= $HEADER_LIMIT) {
        my $chunk;
        my $read = sysread $client, $chunk, 4096;

        next if !defined($read) && $!{EINTR};
        return if !defined($read) || $read == 0;
        $bytes .= $chunk;
        $header_end = index($bytes, "\r\n\r\n");
        last if $header_end >= 0;
    }

    return if !defined($header_end) || $header_end < 0;

    my $headers = substr($bytes, 0, $header_end + 4, '');
    my ($length) = $headers =~ /\r\nContent-Length:[ \t]*(\d+)[ \t]*\r\n/i;

    $length = 0 if !defined $length;
    return if $length > $BODY_LIMIT || length($bytes) > $length;

    while (length($bytes) < $length) {
        my $chunk;
        my $read = sysread $client, $chunk, $length - length($bytes);

        next if !defined($read) && $!{EINTR};
        return if !defined($read) || $read == 0;
        $bytes .= $chunk;
    }

    return $bytes;
}


sub _serve {
    my ($listener, $record_path) = @_;

    local $SIG{TERM} = sub { _exit(0) };
    local $SIG{INT} = sub { _exit(0) };

    for (;;) {
        my $client = $listener->accept;

        next if !defined($client) && $!{EINTR};
        _exit(1) if !defined $client;

        my $body = _read_request($client);

        if (defined $body) {
            open my $record, '>>:raw', $record_path or _exit(1);
            print {$record} "1\n" or _exit(1);
            close $record or _exit(1);

            my $header = "HTTP/1.1 200 OK\r\n"
                . "Content-Type: application/octet-stream\r\n"
                . "Content-Length: " . length($body) . "\r\n"
                . "Connection: close\r\n\r\n";

            _write_all($client, $header . $body) or _exit(1);
        }

        close $client or _exit(1);
    }
}


sub start_backend {
    my $directory = tempdir(
        'ngx-powgate-backend-XXXXXX',
        TMPDIR => 1,
        CLEANUP => 0,
    );
    my $record_path = "$directory/reached";
    my $listener = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1',
        LocalPort => 0,
        Listen => 16,
        Proto => 'tcp',
        ReuseAddr => 1,
    ) or die "start test backend: $!";
    my $port = $listener->sockport;
    my $pid = fork;

    die "fork test backend: $!" if !defined $pid;
    if ($pid == 0) {
        _serve($listener, $record_path);
        _exit(1);
    }

    close $listener or die "close parent backend listener: $!";

    return {
        directory => $directory,
        pid => $pid,
        port => $port,
        record_path => $record_path,
        stopped => 0,
    };
}


sub backend_reach_count {
    my ($backend) = @_;
    my $count = 0;
    my $fh;

    return 0 if !-e $backend->{record_path};
    open $fh, '<:raw', $backend->{record_path}
        or die "open backend record: $!";
    $count++ while <$fh>;
    close $fh or die "close backend record: $!";

    return $count;
}


sub stop_backend {
    my ($backend) = @_;

    return { reaped => 1 } if !defined $backend || $backend->{stopped};

    kill 'TERM', $backend->{pid};
    my $deadline = clock_gettime(CLOCK_MONOTONIC) + 2;

    while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
        my $waited = waitpid $backend->{pid}, WNOHANG;

        if ($waited == $backend->{pid}) {
            $backend->{stopped} = 1;
            remove_tree($backend->{directory});
            return { reaped => 1 };
        }
        if ($waited == -1 && !$!{EINTR}) {
            $backend->{stopped} = 1 if $!{ECHILD};
            remove_tree($backend->{directory}) if $backend->{stopped};
            return { reaped => $backend->{stopped} ? 1 : 0 };
        }
        sleep 0.02;
    }

    kill 'KILL', $backend->{pid};
    waitpid $backend->{pid}, 0;
    $backend->{stopped} = 1;
    remove_tree($backend->{directory});
    return { reaped => 1, forced => 1 };
}


1;
