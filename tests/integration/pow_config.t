use strict;
use warnings;

use File::Temp qw(tempdir);
use POSIX qw(WNOHANG);
use Test::More;

use PowGate::TestNginx qw(run_nginx_t write_file);

my @cases = (
    {
        name => 'empty http block',
        body => '',
        succeeds => 1,
    },
    {
        name => 'pow off in server',
        body => <<'NGINX',
    server {
        listen 127.0.0.1:8080;
        pow off;
    }
NGINX
        succeeds => 1,
    },
    {
        name => 'standard directives in http',
        body => <<'NGINX',
    pow off;
    pow_difficulty 20;
    pow_challenge_window 60s;
    pow_cookie_name __pow;
    pow_cookie_ttl 1h;
    pow_cookie_secure on;
    pow_bind_ipv4 32;
    pow_bind_ipv6 56;
    pow_exempt_path /health;
    pow_log_level error;
NGINX
        succeeds => 1,
    },
    {
        name => 'standard directives in server',
        body => <<'NGINX',
    server {
        listen 127.0.0.1:8080;
        pow off;
        pow_difficulty 20;
        pow_challenge_window 60s;
        pow_cookie_name __pow;
        pow_cookie_ttl 1h;
        pow_cookie_secure on;
        pow_bind_ipv4 32;
        pow_bind_ipv6 56;
        pow_exempt_path /health;
        pow_log_level error;
    }
NGINX
        succeeds => 1,
    },
    {
        name => 'standard directives in location with nested overrides',
        body => <<'NGINX',
    pow off;
    pow_difficulty 20;
    pow_challenge_window 60s;
    pow_cookie_name __pow;
    pow_cookie_ttl 1h;
    pow_cookie_secure on;
    pow_bind_ipv4 32;
    pow_bind_ipv6 56;
    pow_exempt_path /health;
    pow_log_level error;

    server {
        listen 127.0.0.1:8080;
        pow off;
        pow_difficulty 21;
        pow_challenge_window 90s;
        pow_cookie_name pow_server;
        pow_cookie_ttl 2h;
        pow_cookie_secure off;
        pow_bind_ipv4 24;
        pow_bind_ipv6 64;
        pow_exempt_path /ready;
        pow_log_level warn;

        location /protected {
            pow off;
            pow_difficulty 22;
            pow_challenge_window 120s;
            pow_cookie_name pow_location;
            pow_cookie_ttl 3h;
            pow_cookie_secure on;
            pow_bind_ipv4 16;
            pow_bind_ipv6 96;
            pow_exempt_path /live;
            pow_log_level notice;
        }
    }
NGINX
        succeeds => 1,
    },
    {
        name => 'unknown directive',
        body => "    pow_not_a_directive on;\n",
        succeeds => 0,
        diagnostic => qr/unknown directive\s+"pow_not_a_directive"/,
    },
);

for my $case (@cases) {
    subtest $case->{name} => sub {
        my $result = run_nginx_t($case->{body});

        ok !$result->{timed_out}, 'nginx -t completed before timeout';
        is $result->{signal}, 0, 'nginx -t was not terminated by a signal';

        if ($case->{succeeds}) {
            is $result->{exit_status}, 0, 'nginx -t succeeds';
        } else {
            isnt $result->{exit_status}, 0, 'nginx -t rejects configuration';
            like $result->{diagnostic}, $case->{diagnostic},
                'diagnostic identifies the unknown directive';
        }
    };
}

subtest 'diagnostic capture is bounded without blocking' => sub {
    my $directory = tempdir(CLEANUP => 1);
    my $fake_nginx = "$directory/nginx";

    write_file(
        $fake_nginx,
        <<'PERL',
#!/usr/bin/perl
use strict;
use warnings;
print STDOUT 'o' x (2 * 1024 * 1024);
print STDERR 'e' x (2 * 1024 * 1024);
PERL
        0700,
    );

    my $result = run_nginx_t('', nginx_binary => $fake_nginx);

    ok !$result->{timed_out}, 'large diagnostics do not block the child';
    is $result->{exit_status}, 0, 'fake nginx exits successfully';
    is $result->{signal}, 0, 'fake nginx was not terminated by a signal';
    is length($result->{diagnostic}), 64 * 1024,
        'combined diagnostics are capped at 64 KiB';
};

subtest 'hard timeout kills and reaps an uncooperative child' => sub {
    my $directory = tempdir(CLEANUP => 1);
    my $fake_nginx = "$directory/nginx";

    write_file(
        $fake_nginx,
        <<'PERL',
#!/usr/bin/perl
use strict;
use warnings;
$SIG{TERM} = 'IGNORE';
print STDERR "$$\n";
while (1) {
    sleep 30;
}
PERL
        0700,
    );

    my $result = run_nginx_t('', nginx_binary => $fake_nginx);

    ok $result->{timed_out}, 'alarm marks the command timed out';
    is $result->{signal}, 9, 'uncooperative child is killed';
    like $result->{diagnostic}, qr/\A(\d+)\n/, 'child reports its pid';

    my ($pid) = $result->{diagnostic} =~ /\A(\d+)\n/;

    is waitpid($pid, WNOHANG), -1, 'child was already reaped';
};

done_testing;
