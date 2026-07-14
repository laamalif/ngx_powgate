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
        name => 'inherited pow on overridden off in every server',
        body => <<'NGINX',
    pow on;

    server {
        listen 127.0.0.1:8080;
        pow off;

        location /also-off {
            pow off;
        }
    }
NGINX
        succeeds => 1,
    },
    {
        name => 'pow on in server requires a secret',
        body => <<'NGINX',
    server {
        listen 127.0.0.1:8080;
        pow on;
    }
NGINX
        succeeds => 0,
        diagnostic => qr/pow_secret_file: required when pow is enabled/,
    },
    {
        name => 'pow on in location requires a secret',
        body => <<'NGINX',
    server {
        listen 127.0.0.1:8080;

        location /protected {
            pow on;
        }
    }
NGINX
        succeeds => 0,
        diagnostic => qr/pow_secret_file: required when pow is enabled/,
    },
    {
        name => 'explicit invalid secret is rejected while pow is off',
        body => "    pow off;\n    pow_secret_file missing.secret;\n",
        succeeds => 0,
        diagnostic => qr/pow_secret_file: open\(\).*failed/,
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

my @accepted_scalars = (
    [ 'difficulty lower bound', 'pow_difficulty 1;' ],
    [ 'difficulty upper bound', 'pow_difficulty 32;' ],
    [ 'IPv4 binding lower bound', 'pow_bind_ipv4 8;' ],
    [ 'IPv4 binding upper bound', 'pow_bind_ipv4 32;' ],
    [ 'IPv6 binding lower bound', 'pow_bind_ipv6 32;' ],
    [ 'IPv6 binding upper bound', 'pow_bind_ipv6 128;' ],
);

for my $row (@accepted_scalars) {
    push @cases, {
        name => $row->[0],
        body => "    $row->[1]\n",
        succeeds => 1,
    };
}

my @rejected_scalars = (
    [ 'difficulty below lower bound', 'pow_difficulty 0;',
        qr/value must be between 1 and 32/ ],
    [ 'difficulty above upper bound', 'pow_difficulty 33;',
        qr/value must be between 1 and 32/ ],
    [ 'IPv4 binding below lower bound', 'pow_bind_ipv4 7;',
        qr/value must be between 8 and 32/ ],
    [ 'IPv4 binding above upper bound', 'pow_bind_ipv4 33;',
        qr/value must be between 8 and 32/ ],
    [ 'IPv6 binding below lower bound', 'pow_bind_ipv6 31;',
        qr/value must be between 32 and 128/ ],
    [ 'IPv6 binding above upper bound', 'pow_bind_ipv6 129;',
        qr/value must be between 32 and 128/ ],
    [ 'zero challenge window', 'pow_challenge_window 0;',
        qr/pow_challenge_window: value must be positive/ ],
    [ 'malformed challenge window', 'pow_challenge_window never;',
        qr/pow_challenge_window.*invalid value/ ],
    [ 'overflowing challenge window',
        'pow_challenge_window 999999999999999999999999999999999999s;',
        qr/pow_challenge_window.*invalid value/ ],
    [ 'invalid secure flag', 'pow_cookie_secure maybe;',
        qr/invalid value "maybe".*pow_cookie_secure/ ],
    [ 'invalid log level', 'pow_log_level debug;',
        qr/invalid value "debug"/ ],
);

for my $row (@rejected_scalars) {
    push @cases, {
        name => $row->[0],
        body => "    $row->[1]\n",
        succeeds => 0,
        diagnostic => $row->[2],
    };
}

push @cases, (
    {
        name => 'local cookie TTL below local challenge window',
        body => <<'NGINX',
    pow_challenge_window 61s;
    pow_cookie_ttl 60s;

    server {
        listen 127.0.0.1:8080;
    }
NGINX
        succeeds => 0,
        diagnostic =>
            qr/pow_cookie_ttl: value 60.*pow_challenge_window \(61\)/,
    },
    {
        name => 'local cookie TTL below inherited challenge window',
        body => <<'NGINX',
    pow_challenge_window 61s;
    server {
        listen 127.0.0.1:8080;
        pow_cookie_ttl 60s;
    }
NGINX
        succeeds => 0,
        diagnostic =>
            qr/pow_cookie_ttl: value 60.*pow_challenge_window \(61\)/,
    },
);

my @scalar_directives = (
    [ pow => 'off' ],
    [ pow_difficulty => '20' ],
    [ pow_challenge_window => '60s' ],
    [ pow_cookie_name => '__pow' ],
    [ pow_cookie_ttl => '1h' ],
    [ pow_cookie_secure => 'on' ],
    [ pow_bind_ipv4 => '32' ],
    [ pow_bind_ipv6 => '56' ],
    [ pow_log_level => 'error' ],
);

for my $row (@scalar_directives) {
    my ($directive, $value) = @$row;

    push @cases, {
        name => "duplicate $directive at one level",
        body => "    $directive $value;\n    $directive $value;\n",
        succeeds => 0,
        diagnostic => qr/"\Q$directive\E" directive is duplicate/,
    };
}

my $token_punctuation = q{a!#$%&'*+-.^_`|~};
my @accepted_cookie_names = (
    [ 'one-byte cookie name', 'a' ],
    [ '64-byte cookie name', 'a' x 64 ],
    [ 'alphanumeric cookie name', 'PowGate20' ],
    [ 'all RFC token punctuation', $token_punctuation ],
    [ 'dollar after first byte', 'a$' ],
);

for my $row (@accepted_cookie_names) {
    push @cases, {
        name => $row->[0],
        body => qq{    pow_cookie_name "$row->[1]";\n},
        succeeds => 1,
    };
}

my @rejected_cookie_names = (
    [ 'empty cookie name', '' ],
    [ '65-byte cookie name', 'a' x 65 ],
    [ 'leading dollar cookie name', '$pow' ],
    [ 'cookie name containing whitespace', 'pow gate' ],
    [ 'cookie name containing control byte', "pow\x01gate" ],
    [ 'cookie name containing non-ASCII byte', "pow\x{c2}\x{a3}" ],
);

for my $separator ('(', ')', '<', '>', '@', ',', ';', ':', '/', '[', ']',
                   '?', '=', '{', '}')
{
    push @rejected_cookie_names,
        [ "cookie name containing separator $separator",
          "pow${separator}gate" ];
}

for my $row (@rejected_cookie_names) {
    push @cases, {
        name => $row->[0],
        body => qq{    pow_cookie_name "$row->[1]";\n},
        succeeds => 0,
        diagnostic => qr/pow_cookie_name: value is not a valid cookie token/,
    };
}

push @cases, (
    {
        name => 'cookie name containing backslash separator',
        body => qq{    pow_cookie_name "pow\\\\gate";\n},
        succeeds => 0,
        diagnostic =>
            qr/pow_cookie_name: value is not a valid cookie token/,
    },
    {
        name => 'cookie name containing quote separator',
        body => qq{    pow_cookie_name "pow\\\"gate";\n},
        succeeds => 0,
        diagnostic =>
            qr/pow_cookie_name: value is not a valid cookie token/,
    },
);

my @accepted_paths = (
    [ 'root exempt path', '/' ],
    [ 'ordinary exempt path', '/health' ],
    [ 'repeated-slash exempt path', '/a//b' ],
    [ 'literal-percent exempt path', '/literal%value' ],
    [ 'question-mark exempt path', '/literal?value' ],
    [ 'hash exempt path', '/literal#value' ],
);

for my $row (@accepted_paths) {
    push @cases, {
        name => $row->[0],
        body => qq{    pow_exempt_path "$row->[1]";\n},
        succeeds => 1,
    };
}

my @rejected_paths = (
    [ 'empty exempt path', '' ],
    [ 'relative exempt path', 'health' ],
    [ 'trailing-slash exempt path', '/health/' ],
);

for my $row (@rejected_paths) {
    push @cases, {
        name => $row->[0],
        body => qq{    pow_exempt_path "$row->[1]";\n},
        succeeds => 0,
        diagnostic =>
            qr/pow_exempt_path: value must be \/.*without a trailing slash/,
    };
}

push @cases, (
    {
        name => 'CIDRs in all contexts accept repeated declarations',
        body => <<'NGINX',
    pow_exempt_ip 192.0.2.0/24;
    pow_exempt_ip 2001:db8::/32;

    server {
        listen 127.0.0.1:8080;
        pow_exempt_ip 198.51.100.0/24;
        pow_exempt_ip 2001:db8:1::/48;

        location / {
            pow_exempt_ip 203.0.113.0/24;
            pow_exempt_ip 2001:db8:2::/48;
        }
    }
NGINX
        succeeds => 1,
    },
    {
        name => 'CIDR host bits are normalized with standard warning',
        body => "    pow_exempt_ip 192.0.2.7/24;\n",
        succeeds => 1,
        diagnostic => qr/low address bits of 192\.0\.2\.7\/24 are meaningless/,
    },
    {
        name => 'malformed IPv4 CIDR',
        body => "    pow_exempt_ip 192.0.2.1/33;\n",
        succeeds => 0,
        diagnostic =>
            qr/pow_exempt_ip: value "192\.0\.2\.1\/33" must be.*CIDR/,
    },
    {
        name => 'malformed IPv6 CIDR',
        body => "    pow_exempt_ip 2001:db8::/129;\n",
        succeeds => 0,
        diagnostic =>
            qr/pow_exempt_ip: value "2001:db8::\/129" must be.*CIDR/,
    },
);

for my $case (@cases) {
    subtest $case->{name} => sub {
        my $result = run_nginx_t($case->{body});

        ok !$result->{timed_out}, 'nginx -t completed before timeout';
        is $result->{signal}, 0, 'nginx -t was not terminated by a signal';

        if ($case->{succeeds}) {
            is $result->{exit_status}, 0, 'nginx -t succeeds';

            if ($case->{diagnostic}) {
                like $result->{diagnostic}, $case->{diagnostic},
                    'diagnostic contains expected semantic warning';
            }
        } else {
            isnt $result->{exit_status}, 0, 'nginx -t rejects configuration';
            like $result->{diagnostic}, $case->{diagnostic},
                'diagnostic contains expected semantic constraint';
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
