use strict;
use warnings;

use File::Temp qw(tempdir);
use Test::More;

use PowGate::TestNginx qw(run_nginx_t write_file);

my $lower = '0123456789abcdef' x 4;
my $upper = '0123456789ABCDEF' x 4;
my $mixed = '0123456789aBcDeF' x 4;
my $other = 'fEdCbA9876543210' x 4;
my $sentinel = '0123456789abcdef';

my @accepted = (
    [ 'lowercase without final LF', $lower ],
    [ 'uppercase with final LF', "$upper\n" ],
    [ 'mixed current and previous without final LF',
      "$mixed\n$other" ],
    [ 'mixed current and previous with final LF',
      "$mixed\n$other\n" ],
    [ 'all-zero current', '0' x 64 ],
    [ 'identical current and previous', "$mixed\n$mixed" ],
);

for my $row (@accepted) {
    subtest $row->[0] => sub {
        my $result = run_nginx_t(
            "    pow_secret_file pow.secret;\n",
            setup => sub {
                my ($prefix) = @_;

                write_file("$prefix/conf/pow.secret", $row->[1], 0600);
            },
        );

        ok !$result->{timed_out}, 'nginx -t completed before timeout';
        is $result->{signal}, 0, 'nginx -t was not signalled';
        is $result->{exit_status}, 0, 'secret grammar is accepted';
    };
}

my @rejected = (
    [ 'empty file', '', undef ],
    [ '63 bytes', substr($lower, 0, 63), $sentinel ],
    [ '66 bytes', $lower . "\n\n", $sentinel ],
    [ 'non-hex byte', substr($lower, 0, 63) . 'g', $sentinel ],
    [ 'space in line', substr($lower, 0, 31) . ' ' .
        substr($lower, 32), $sentinel ],
    [ 'tab in line', substr($lower, 0, 31) . "\t" .
        substr($lower, 32), $sentinel ],
    [ 'UTF-8 BOM', "\xef\xbb\xbf" . $lower, $sentinel ],
    [ 'CRLF', $lower . "\r\n", $sentinel ],
    [ 'blank second line', $lower . "\n\n", $sentinel ],
    [ 'leading LF', "\n" . $lower, $sentinel ],
    [ 'extra final LF', $lower . "\n\n", $sentinel ],
    [ 'third line', $lower . "\n" . ('b' x 64) . "\n" .
        ('c' x 64), $sentinel ],
    [ '131 bytes', $lower . ('a' x 67), $sentinel ],
);

for my $row (@rejected) {
    subtest $row->[0] => sub {
        my $result = run_nginx_t(
            "    pow_secret_file pow.secret;\n",
            setup => sub {
                my ($prefix) = @_;

                write_file("$prefix/conf/pow.secret", $row->[1], 0600);
            },
        );

        ok !$result->{timed_out}, 'nginx -t completed before timeout';
        is $result->{signal}, 0, 'nginx -t was not signalled';
        isnt $result->{exit_status}, 0, 'secret grammar is rejected';
        like $result->{diagnostic},
            qr/pow_secret_file: content must contain one or two 64-byte/,
            'diagnostic identifies the required grammar';

        if (defined $row->[2]) {
            ok index($row->[1], $row->[2]) >= 0,
                'malformed fixture contains the disclosure sentinel';
            unlike $result->{diagnostic}, qr/\Q$row->[2]\E/,
                'diagnostic does not disclose malformed secret content';
        } else {
            is length($row->[1]), 0,
                'empty fixture contains no secret bytes to disclose';
        }
    };
}

subtest 'absolute secret path' => sub {
    my $directory = tempdir(CLEANUP => 1);
    my $path = "$directory/pow.secret";

    write_file($path, $lower, 0600);

    my $result = run_nginx_t(qq{    pow_secret_file "$path";\n});

    ok !$result->{timed_out}, 'nginx -t completed before timeout';
    is $result->{exit_status}, 0, 'absolute path is accepted';
};

subtest 'relative secret path uses configuration prefix' => sub {
    my $result = run_nginx_t(
        "    pow_secret_file nested/pow.secret;\n",
        setup => sub {
            my ($prefix) = @_;

            write_file("$prefix/conf/nested/pow.secret", $lower, 0600);
        },
    );

    ok !$result->{timed_out}, 'nginx -t completed before timeout';
    is $result->{exit_status}, 0, 'configuration-prefix path is accepted';
};

subtest 'embedded NUL in secret path is rejected before open' => sub {
    my $path_sentinel = 'powgate-hidden-path-suffix';
    my $result = run_nginx_t(
        "    pow_secret_file pow.secret\0$path_sentinel;\n",
        setup => sub {
            my ($prefix) = @_;

            write_file("$prefix/conf/pow.secret", $lower, 0600);
        },
    );

    ok !$result->{timed_out}, 'nginx -t completed before timeout';
    isnt $result->{exit_status}, 0, 'embedded NUL path is rejected';
    like $result->{diagnostic},
        qr/pow_secret_file: path must not contain a NUL byte/,
        'diagnostic identifies the bounded path constraint';
    unlike $result->{diagnostic}, qr/\Q$path_sentinel\E/,
        'diagnostic does not disclose bytes after the NUL';
};

subtest 'duplicate secret directive' => sub {
    my $result = run_nginx_t(
        "    pow_secret_file pow.secret;\n" x 2,
        setup => sub {
            my ($prefix) = @_;

            write_file("$prefix/conf/pow.secret", $lower, 0600);
        },
    );

    isnt $result->{exit_status}, 0, 'duplicate is rejected';
    like $result->{diagnostic}, qr/"pow_secret_file" directive is duplicate/,
        'diagnostic identifies duplicate directive';
};

for my $context (
    [ server => <<'NGINX' ],
    server {
        listen 127.0.0.1:8080;
        pow_secret_file pow.secret;
    }
NGINX
    [ location => <<'NGINX' ],
    server {
        listen 127.0.0.1:8080;
        location / {
            pow_secret_file pow.secret;
        }
    }
NGINX
) {
    subtest "secret directive rejected in $context->[0] context" => sub {
        my $result = run_nginx_t($context->[1]);

        isnt $result->{exit_status}, 0, 'context is rejected';
        like $result->{diagnostic},
            qr/"pow_secret_file" directive is not allowed here/,
            'diagnostic identifies invalid context';
    };
}

done_testing;
