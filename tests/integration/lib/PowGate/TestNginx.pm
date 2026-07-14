package PowGate::TestNginx;

use strict;
use warnings;

use Exporter qw(import);
use File::Basename qw(dirname);
use File::Path qw(make_path);
use File::Temp qw(tempdir tempfile);
use IO::Select;
use POSIX qw(WNOHANG);
use Time::HiRes qw(CLOCK_MONOTONIC clock_gettime);

our @EXPORT_OK = qw(
    atomic_write
    module_path
    nginx_binary
    run_nginx_t
    write_file
);

my $DIAGNOSTIC_LIMIT = 64 * 1024;
my $NGINX_T_TIMEOUT = 5;


sub nginx_binary {
    return $ENV{TEST_NGINX_BINARY} // '/usr/sbin/nginx';
}


sub module_path {
    return $ENV{POW_MODULE_PATH} // '/work/out/ngx_http_pow_module.so';
}


sub _write_bytes {
    my ($fh, $path, $bytes) = @_;
    my $length = length $bytes;
    my $offset = 0;

    while ($offset < $length) {
        my $written = syswrite $fh, $bytes, $length - $offset, $offset;

        if (!defined $written) {
            next if $!{EINTR};
            die "write $path: $!";
        }

        die "write $path: wrote zero bytes" if $written == 0;
        $offset += $written;
    }
}


sub write_file {
    my ($path, $bytes, $mode) = @_;
    my $parent = dirname $path;

    make_path($parent) if !-d $parent;

    open my $fh, '>:raw', $path or die "open $path: $!";
    _write_bytes($fh, $path, $bytes);
    close $fh or die "close $path: $!";
    chmod $mode, $path or die "chmod $path: $!";

    return;
}


sub atomic_write {
    my ($path, $bytes, $mode) = @_;
    my $parent = dirname $path;

    make_path($parent) if !-d $parent;

    my ($fh, $temporary) = tempfile(
        '.powgate.XXXXXX',
        DIR => $parent,
        UNLINK => 0,
    );

    my $ok = eval {
        binmode $fh, ':raw' or die "binmode $temporary: $!";
        _write_bytes($fh, $temporary, $bytes);
        chmod $mode, $temporary or die "chmod $temporary: $!";
        close $fh or die "close $temporary: $!";
        rename $temporary, $path or die "rename $temporary to $path: $!";
        1;
    };

    if (!$ok) {
        my $error = $@;

        close $fh if defined fileno $fh;
        unlink $temporary;
        die $error;
    }

    return;
}


sub _nginx_quote {
    my ($value) = @_;

    die "nginx path contains a NUL or newline"
        if $value =~ /[\x00\r\n]/;

    $value =~ s/([\\"\$])/\\$1/g;

    return qq{"$value"};
}


sub _drain_diagnostics {
    my ($selector, $diagnostic, $wait) = @_;

    for my $fh ($selector->can_read($wait)) {
        my $chunk;
        my $read = sysread($fh, $chunk, 16 * 1024);

        if (!defined $read) {
            next if $!{EINTR};
            die "read nginx diagnostic pipe: $!";
        }

        if ($read == 0) {
            $selector->remove($fh);
            close $fh or die "close nginx diagnostic pipe: $!";
            next;
        }

        my $remaining = $DIAGNOSTIC_LIMIT - length $$diagnostic;

        $$diagnostic .= substr $chunk, 0, $remaining if $remaining > 0;
    }
}


sub _terminate_child {
    my ($pid, $selector, $diagnostic) = @_;
    my $deadline = clock_gettime(CLOCK_MONOTONIC) + 1;

    kill 'TERM', $pid;

    while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
        _drain_diagnostics($selector, $diagnostic, 0.05);

        my $waited = waitpid $pid, WNOHANG;

        return $? if $waited == $pid;

        if ($waited == -1) {
            next if $!{EINTR};
            die "waitpid nginx -t: $!";
        }
    }

    kill 'KILL', $pid;

    while (waitpid($pid, 0) == -1) {
        next if $!{EINTR};
        die "waitpid nginx -t after kill: $!";
    }

    return $?;
}


sub _finish_diagnostics {
    my ($selector, $diagnostic) = @_;

    while ($selector->count != 0) {
        my @ready = $selector->can_read(0);

        last if !@ready;
        _drain_diagnostics($selector, $diagnostic, 0);
    }

    for my $fh ($selector->handles) {
        $selector->remove($fh);
        close $fh or die "close nginx diagnostic pipe: $!";
    }
}


sub run_nginx_t {
    my ($http_body, %options) = @_;
    my $prefix = tempdir('ngx-powgate-config-XXXXXX', TMPDIR => 1,
                         CLEANUP => 1);
    my $selected_module = $options{module_path} // module_path();
    my $selected_nginx = $options{nginx_binary} // nginx_binary();
    my $setup = $options{setup};
    my $configuration;
    my ($stdout_reader, $stdout_writer);
    my ($stderr_reader, $stderr_writer);
    my $diagnostic = '';
    my $selector;
    my $pid;
    my $raw_status;
    my $timed_out = 0;
    my $child_reaped = 0;
    my $run_error;

    make_path("$prefix/conf", "$prefix/logs", "$prefix/html");
    $setup->($prefix) if defined $setup;

    $configuration = 'load_module ' . _nginx_quote($selected_module) . ";\n"
        . "pid logs/nginx.pid;\n"
        . "error_log logs/error.log notice;\n\n"
        . "events {}\n\n"
        . "http {\n"
        . "    access_log off;\n"
        . "    client_body_temp_path logs/client_body_temp;\n"
        . "    proxy_temp_path logs/proxy_temp;\n"
        . "    fastcgi_temp_path logs/fastcgi_temp;\n"
        . "    uwsgi_temp_path logs/uwsgi_temp;\n"
        . "    scgi_temp_path logs/scgi_temp;\n"
        . $http_body . "\n"
        . "}\n";

    write_file("$prefix/conf/nginx.conf", $configuration, 0600);

    pipe $stdout_reader, $stdout_writer or die "pipe nginx stdout: $!";
    pipe $stderr_reader, $stderr_writer or die "pipe nginx stderr: $!";

    $pid = fork;
    die "fork nginx -t: $!" if !defined $pid;

    if ($pid == 0) {
        close $stdout_reader;
        close $stderr_reader;
        open STDOUT, '>&', $stdout_writer or die "redirect nginx stdout: $!";
        open STDERR, '>&', $stderr_writer or die "redirect nginx stderr: $!";
        close $stdout_writer;
        close $stderr_writer;
        exec {$selected_nginx} $selected_nginx, '-t', '-p', "$prefix/",
            '-c', 'conf/nginx.conf';
        die "exec $selected_nginx: $!";
    }

    close $stdout_writer or die "close nginx stdout writer: $!";
    close $stderr_writer or die "close nginx stderr writer: $!";

    $selector = IO::Select->new($stdout_reader, $stderr_reader);

    {
        local $SIG{ALRM} = sub {
            return if $child_reaped;
            $timed_out = 1;
            die "nginx -t timeout\n";
        };

        eval {
            alarm $NGINX_T_TIMEOUT;

            for (;;) {
                _drain_diagnostics($selector, \$diagnostic, 0.05);

                my $waited = waitpid $pid, WNOHANG;

                if ($waited == $pid) {
                    $raw_status = $?;
                    $child_reaped = 1;
                    alarm 0;
                    last;
                }

                if ($waited == -1) {
                    next if $!{EINTR};
                    die "waitpid nginx -t: $!";
                }
            }
        };

        $run_error = $@;
        alarm 0;
    }

    if ($timed_out) {
        $raw_status = _terminate_child($pid, $selector, \$diagnostic);
        $child_reaped = 1;

    } elsif ($run_error ne '') {
        _terminate_child($pid, $selector, \$diagnostic)
            if !$child_reaped;
        die $run_error;
    }

    _finish_diagnostics($selector, \$diagnostic);

    my $signal = $raw_status & 127;
    my $exit_status = $raw_status >> 8;

    return {
        diagnostic => $diagnostic,
        exit_status => $exit_status,
        prefix => $prefix,
        signal => $signal,
        timed_out => $timed_out,
    };
}


1;
