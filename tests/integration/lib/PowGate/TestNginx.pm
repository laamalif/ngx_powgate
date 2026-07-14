package PowGate::TestNginx;

use strict;
use warnings;

use Exporter qw(import);
use Fcntl qw(FD_CLOEXEC F_GETFD F_SETFD);
use File::Basename qw(dirname);
use File::Path qw(make_path remove_tree);
use File::Temp qw(tempdir tempfile);
use IO::Select;
use IO::Socket::INET;
use POSIX qw(WNOHANG _exit);
use Time::HiRes qw(CLOCK_MONOTONIC clock_gettime sleep);

our @EXPORT_OK = qw(
    atomic_write
    module_path
    nginx_child_pids
    nginx_binary
    run_nginx_t
    signal_nginx
    start_nginx
    stop_nginx
    wait_for_http
    write_file
);

my $DIAGNOSTIC_LIMIT = 64 * 1024;
my $NGINX_T_TIMEOUT = 5;
my $RUNTIME_START_TIMEOUT = 8;
my $RUNTIME_START_ATTEMPTS = 3;
my $RUNTIME_STOP_GRACE = 2;
my $RUNTIME_FORCE_GRACE = 1;


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


sub _reserve_loopback_port {
    my $socket = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1',
        LocalPort => 0,
        Listen => 1,
        Proto => 'tcp',
    ) or die "reserve loopback port: $!";
    my $port = $socket->sockport;

    close $socket or die "close reserved loopback port: $!";

    return $port;
}


sub _read_bounded_file {
    my ($path) = @_;
    my $bytes = '';
    my $fh;

    return $bytes if !-e $path;

    if (!open $fh, '<:raw', $path) {
        return $bytes if $!{ENOENT};
        die "open $path: $!";
    }

    while (length($bytes) < $DIAGNOSTIC_LIMIT) {
        my $chunk;
        my $read = sysread $fh, $chunk,
            $DIAGNOSTIC_LIMIT - length($bytes);

        if (!defined $read) {
            next if $!{EINTR};
            die "read $path: $!";
        }

        last if $read == 0;
        $bytes .= $chunk;
    }

    close $fh or die "close $path: $!";

    return $bytes;
}


sub _runtime_diagnostic {
    my ($runtime, $exec_error) = @_;
    my $diagnostic = substr $exec_error, 0, $DIAGNOSTIC_LIMIT;

    my $remaining = $DIAGNOSTIC_LIMIT - length($diagnostic);

    $diagnostic .= substr(
        _read_bounded_file("$runtime->{prefix}/logs/error.log"),
        0,
        $remaining,
    ) if $remaining > 0;

    return $diagnostic;
}


sub _runtime_child_is_owned {
    my ($runtime) = @_;

    return ref($runtime) eq 'HASH'
        && $runtime->{child_owned}
        && defined $runtime->{pid}
        && $runtime->{pid} =~ /\A\d+\z/
        && $runtime->{pid} > 1;
}


sub _runtime_group_is_safe {
    my ($runtime) = @_;

    return $runtime->{group_verified}
        && $runtime->{pgid} == $runtime->{pid}
        && $runtime->{pgid} > 1
        && $runtime->{pgid} != getpgrp(0);
}


sub _signal_runtime_child {
    my ($runtime, $signal) = @_;

    return 0 if !_runtime_child_is_owned($runtime);

    if ($runtime->{group_verified}) {
        return 0 if !_runtime_group_is_safe($runtime);
        return 0 if getpgrp($runtime->{pid}) != $runtime->{pgid};
    }

    return kill $signal, $runtime->{pid};
}


sub _signal_runtime_group {
    my ($runtime, $signal) = @_;

    return 0 if !_runtime_group_is_safe($runtime);

    return kill $signal, -$runtime->{pgid};
}


sub _verify_runtime_group {
    my ($runtime) = @_;
    my $pgid = getpgrp($runtime->{pid});

    return 0 if $pgid != $runtime->{pid};
    return 0 if $pgid <= 1 || $pgid == getpgrp(0);

    $runtime->{pgid} = $pgid;
    $runtime->{group_verified} = 1;

    return 1;
}


sub _runtime_group_alive {
    my ($runtime) = @_;

    return 0 if !_runtime_group_is_safe($runtime);
    return 1 if kill 0, -$runtime->{pgid};
    return 1 if $!{EPERM};
    return 0;
}


sub _poll_runtime_exit {
    my ($runtime, $deadline) = @_;

    return 0 if !_runtime_child_is_owned($runtime);

    while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
        if (!$runtime->{reaped}) {
            my $waited = waitpid $runtime->{pid}, WNOHANG;

            if ($waited == $runtime->{pid}) {
                $runtime->{raw_status} = $?;
                $runtime->{reaped} = 1;
            } elsif ($waited == -1 && !$!{EINTR}) {
                $runtime->{reaped} = 1 if $!{ECHILD};
            }
        }

        return 1 if $runtime->{reaped} && !_runtime_group_alive($runtime);
        sleep 0.05;
    }

    return 0;
}


sub _remove_runtime_prefix {
    my ($prefix) = @_;
    my $errors;

    return if !defined $prefix || !-e $prefix;

    remove_tree($prefix, { error => \$errors });

    die "remove runtime prefix $prefix failed\n"
        if (defined $errors && @$errors) || -e $prefix;
}


sub _cleanup_runtime {
    my ($runtime) = @_;
    my $forced = 0;
    my $complete;

    if (!$runtime->{reaped}) {
        _signal_runtime_child($runtime, 'TERM');
    }

    $complete = _poll_runtime_exit(
        $runtime,
        clock_gettime(CLOCK_MONOTONIC) + $RUNTIME_STOP_GRACE,
    );

    if (!$complete) {
        $forced = 1;

        if (_runtime_group_is_safe($runtime)) {
            _signal_runtime_group($runtime, 'TERM');
            $complete = _poll_runtime_exit(
                $runtime,
                clock_gettime(CLOCK_MONOTONIC) + $RUNTIME_FORCE_GRACE,
            );

            if (!$complete) {
                _signal_runtime_group($runtime, 'KILL');
                $complete = _poll_runtime_exit(
                    $runtime,
                    clock_gettime(CLOCK_MONOTONIC) + $RUNTIME_FORCE_GRACE,
                );
            }
        } else {
            _signal_runtime_child($runtime, 'KILL')
                if !$runtime->{reaped};
            $complete = _poll_runtime_exit(
                $runtime,
                clock_gettime(CLOCK_MONOTONIC) + $RUNTIME_FORCE_GRACE,
            );
        }
    }

    if ($complete && defined $runtime->{prefix}) {
        _remove_runtime_prefix($runtime->{prefix});
    }

    return {
        exit_status => ($runtime->{raw_status} // 0) >> 8,
        forced => $forced,
        group_gone => !_runtime_group_alive($runtime),
        reaped => $runtime->{reaped} ? 1 : 0,
        signal => ($runtime->{raw_status} // 0) & 127,
    };
}


sub _child_start_error {
    my ($fh, $message) = @_;
    my $offset = 0;

    while ($offset < length($message)) {
        my $written = syswrite $fh, $message,
            length($message) - $offset, $offset;

        last if !defined $written && !$!{EINTR};
        next if !defined $written;
        last if $written == 0;
        $offset += $written;
    }

    _exit(127);
}


sub _wait_for_exec {
    my ($reader, $deadline) = @_;
    my $selector = IO::Select->new($reader);
    my $message = '';

    while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
        for my $fh ($selector->can_read(0.05)) {
            my $chunk;
            my $read = sysread $fh, $chunk, 16 * 1024;

            if (!defined $read) {
                next if $!{EINTR};
                die "read nginx startup pipe: $!";
            }

            if ($read == 0) {
                close $fh or die "close nginx startup pipe: $!";
                return $message;
            }

            my $remaining = $DIAGNOSTIC_LIMIT - length($message);

            $message .= substr $chunk, 0, $remaining if $remaining > 0;
        }
    }

    close $reader or die "close nginx startup pipe: $!";

    return $message . "nginx runtime exec handshake timed out\n";
}


sub _read_runtime_pid {
    my ($runtime) = @_;
    my $path = "$runtime->{prefix}/logs/nginx.pid";
    my $bytes;

    return if !-e $path;
    $bytes = _read_bounded_file($path);

    return if $bytes !~ /\A(\d+)\s*\z/;
    return 0 + $1;
}


sub _wait_for_runtime_start {
    my ($runtime, $deadline) = @_;

    while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
        my $diagnostic = _runtime_diagnostic($runtime, '');
        my $runtime_pid = _read_runtime_pid($runtime);
        my $waited = waitpid $runtime->{pid}, WNOHANG;

        if ($waited == $runtime->{pid}) {
            my $final_diagnostic;

            $runtime->{raw_status} = $?;
            $runtime->{reaped} = 1;
            $final_diagnostic = _runtime_diagnostic($runtime, '');

            return {
                diagnostic => $final_diagnostic,
                retry => $final_diagnostic =~ /address already in use/i
                    ? 1 : 0,
            };
        }

        if ($waited == -1 && !$!{EINTR}) {
            return {
                diagnostic => "nginx runtime is no longer a child\n"
                    . $diagnostic,
                retry => 0,
            };
        }

        if (defined $runtime_pid) {
            if ($runtime_pid != $runtime->{pid}) {
                return {
                    diagnostic => "nginx pid file does not match forked "
                        . "foreground master\n" . $diagnostic,
                    retry => 0,
                };
            }

            return { ready => 1 }
                if _runtime_group_is_safe($runtime)
                   && kill(0, $runtime->{pid});
        }

        if ($diagnostic =~ /address already in use/i) {
            return { diagnostic => $diagnostic, retry => 1 };
        }

        sleep 0.05;
    }

    return {
        diagnostic => "nginx runtime startup timed out\n"
            . _runtime_diagnostic($runtime, ''),
        retry => 0,
    };
}


sub _start_nginx_attempt {
    my ($http_builder, $selected_nginx, $selected_module,
        $after_port_selection, $after_fork, $deadline) = @_;
    my $prefix = tempdir('ngx-powgate-runtime-XXXXXX', TMPDIR => 1,
                         CLEANUP => 0);
    my $port;
    my $http_body;
    my $configuration;
    my ($startup_reader, $startup_writer);
    my $runtime;
    my $pid;
    my $flags;
    my $exec_error;
    my $result;

    eval {
        make_path("$prefix/conf", "$prefix/logs", "$prefix/html");
        $port = _reserve_loopback_port();
        $http_body = $http_builder->($prefix, $port);

        die "HTTP configuration builder must return bytes"
            if !defined $http_body || ref($http_body);

        $configuration = 'load_module ' . _nginx_quote($selected_module)
            . ";\n"
            . "daemon off;\n"
            . "master_process on;\n"
            . "worker_processes 1;\n"
            . "pid logs/nginx.pid;\n"
            . "error_log logs/error.log notice;\n\n"
            . "events { worker_connections 64; }\n\n"
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
        $after_port_selection->($prefix, $port)
            if defined $after_port_selection;
        pipe $startup_reader, $startup_writer
            or die "pipe nginx startup: $!";
        $flags = fcntl($startup_writer, F_GETFD, 0);
        die "get nginx startup pipe flags: $!" if !defined $flags;
        fcntl($startup_writer, F_SETFD, $flags | FD_CLOEXEC)
            or die "set nginx startup pipe close-on-exec: $!";

        $pid = fork;
        die "fork nginx runtime: $!" if !defined $pid;

        if ($pid == 0) {
            close $startup_reader;
            setpgrp 0, 0;

            if (getpgrp(0) != $$) {
                _child_start_error(
                    $startup_writer,
                    "isolate nginx runtime process group failed\n",
                );
            }

            open STDIN, '<', '/dev/null'
                or _child_start_error(
                    $startup_writer,
                    "redirect nginx runtime stdin failed: $!\n",
                );
            open STDOUT, '>', '/dev/null'
                or _child_start_error(
                    $startup_writer,
                    "redirect nginx runtime stdout failed: $!\n",
                );
            open STDERR, '>', '/dev/null'
                or _child_start_error(
                    $startup_writer,
                    "redirect nginx runtime stderr failed: $!\n",
                );
            exec {$selected_nginx} $selected_nginx, '-p', "$prefix/",
                '-c', 'conf/nginx.conf', '-e', "$prefix/logs/error.log"
                or _child_start_error(
                $startup_writer,
                "exec $selected_nginx failed: $!\n",
            );
        }

        $runtime = {
            child_owned => 1,
            group_verified => 0,
            pgid => 0,
            pid => $pid,
            port => $port,
            prefix => $prefix,
            raw_status => 0,
            reaped => 0,
        };

        setpgrp $pid, $pid;
        die "isolate nginx runtime process group failed\n"
            if !_verify_runtime_group($runtime);

        $after_fork->($runtime) if defined $after_fork;
        close $startup_writer or die "close nginx startup writer: $!";

        $exec_error = _wait_for_exec($startup_reader, $deadline);

        if (!_verify_runtime_group($runtime)) {
            $result = {
                diagnostic => "nginx runtime process group was not "
                    . "isolated\n"
                    . _runtime_diagnostic($runtime, $exec_error),
                runtime => $runtime,
                retry => 0,
            };
        } elsif ($exec_error ne '') {
            $result = {
                diagnostic => _runtime_diagnostic($runtime, $exec_error),
                runtime => $runtime,
                retry => 0,
            };
        } else {
            my $startup = _wait_for_runtime_start($runtime, $deadline);

            if ($startup->{ready}) {
                $result = { runtime => $runtime, ready => 1 };
            } else {
                $result = {
                    diagnostic => $startup->{diagnostic},
                    runtime => $runtime,
                    retry => $startup->{retry},
                };
            }
        }
    };

    if ($@ ne '') {
        my $error = $@;

        if (defined $runtime) {
            my $cleanup = _cleanup_runtime($runtime);

            $error .= "nginx runtime cleanup incomplete\n"
                if !$cleanup->{reaped} || !$cleanup->{group_gone};
        } else {
            _remove_runtime_prefix($prefix);
        }

        die $error;
    }

    return $result;
}


sub start_nginx {
    my ($http_builder, %options) = @_;
    my $selected_module = $options{module_path} // module_path();
    my $selected_nginx = $options{nginx_binary} // nginx_binary();
    my $after_port_selection = $options{after_port_selection};
    my $after_fork = $options{after_fork};
    my $deadline = clock_gettime(CLOCK_MONOTONIC)
        + $RUNTIME_START_TIMEOUT;
    my $attempt = 0;
    my $last_diagnostic = '';

    die "start_nginx requires an HTTP configuration builder"
        if ref($http_builder) ne 'CODE';
    die "after_port_selection must be a code reference"
        if defined $after_port_selection
           && ref($after_port_selection) ne 'CODE';
    die "after_fork must be a code reference"
        if defined $after_fork && ref($after_fork) ne 'CODE';

    while ($attempt < $RUNTIME_START_ATTEMPTS
           && clock_gettime(CLOCK_MONOTONIC) < $deadline)
    {
        $attempt++;

        my $result = _start_nginx_attempt(
            $http_builder,
            $selected_nginx,
            $selected_module,
            $after_port_selection,
            $after_fork,
            $deadline,
        );

        return $result->{runtime} if $result->{ready};

        $last_diagnostic = $result->{diagnostic} // '';
        my $cleanup = _cleanup_runtime($result->{runtime});

        die "nginx runtime cleanup incomplete: $last_diagnostic"
            if !$cleanup->{reaped} || !$cleanup->{group_gone};

        last if !$result->{retry};
    }

    die "nginx runtime startup failed: $last_diagnostic";
}


sub signal_nginx {
    my ($runtime, $signal) = @_;

    die "signal_nginx requires a signal name"
        if !defined $signal || ref($signal) || $signal eq '';

    return _signal_runtime_child($runtime, $signal);
}


sub nginx_child_pids {
    my ($runtime) = @_;
    my $pid = $runtime->{pid};
    my $path = "/proc/$pid/task/$pid/children";
    my $children = '';
    my $fh;

    return [] if !-e $path;

    if (!open $fh, '<:raw', $path) {
        return [] if $!{ENOENT};
        die "open $path: $!";
    }

    for (;;) {
        my $chunk;
        my $read = sysread $fh, $chunk, 4096;

        if (!defined $read) {
            next if $!{EINTR};
            die "read $path: $!";
        }

        last if $read == 0;
        $children .= $chunk;
    }

    close $fh or die "close $path: $!";

    my @pids = $children =~ /(\d+)/g;

    return \@pids;
}


sub wait_for_http {
    my ($runtime, $path, $seconds) = @_;
    my $deadline;

    $path = '/' if !defined $path;
    $seconds = 5 if !defined $seconds;

    die "HTTP poll deadline must be greater than zero and below ten seconds"
        if $seconds <= 0 || $seconds >= 10;
    die "HTTP request path contains a NUL or newline"
        if $path =~ /[\x00\r\n]/;

    $deadline = clock_gettime(CLOCK_MONOTONIC) + $seconds;

    do {
        my $socket = IO::Socket::INET->new(
            PeerAddr => '127.0.0.1',
            PeerPort => $runtime->{port},
            Proto => 'tcp',
            Timeout => 0.2,
        );

        if (defined $socket) {
            my $request = "GET $path HTTP/1.0\r\n"
                . "Host: localhost\r\nConnection: close\r\n\r\n";
            my $offset = 0;
            my $response = '';
            my $selector = IO::Select->new($socket);

            while ($offset < length($request)) {
                my $written = syswrite $socket, $request,
                    length($request) - $offset, $offset;

                if (!defined $written) {
                    next if $!{EINTR};
                    last;
                }

                last if $written == 0;
                $offset += $written;
            }

            while ($offset == length($request)
                   && length($response) < 64 * 1024
                   && clock_gettime(CLOCK_MONOTONIC) < $deadline)
            {
                my @ready = $selector->can_read(0.1);

                next if !@ready;

                my $chunk;
                my $read = sysread $socket, $chunk, 4096;

                if (!defined $read) {
                    next if $!{EINTR};
                    last;
                }

                last if $read == 0;
                $response .= substr $chunk, 0,
                    64 * 1024 - length($response);
            }

            close $socket or die "close HTTP polling socket: $!";

            return $response if $response =~ /\r\n\r\n/;
        }

        sleep 0.05;
    } while (clock_gettime(CLOCK_MONOTONIC) < $deadline);

    return;
}


sub stop_nginx {
    my ($runtime) = @_;

    return { forced => 0, group_gone => 1, reaped => 1 }
        if !defined $runtime;

    return _cleanup_runtime($runtime);
}


1;
