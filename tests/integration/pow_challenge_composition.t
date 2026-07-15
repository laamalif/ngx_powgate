use strict;
use warnings;

use Test::More;

use PowGate::TestHTTPS qw(
    generate_tls_fixture
    https_request
    https_sequence
);
use PowGate::TestNginx qw(start_nginx stop_nginx write_file);


my $secret = '4f' x 32;
my $runtime;
my $error;


sub assert_reused_sequence {
    my ($responses, $protocol, $name, $reuse) = @_;

    is scalar(@$responses), 2, "$name response count";
    is $responses->[0]{protocol}, $protocol, "$name first protocol";
    is $responses->[0]{status}, 403, "$name first challenge";
    is $responses->[1]{protocol}, $protocol, "$name second protocol";
    is $responses->[1]{status}, 403, "$name second challenge";
    if ($reuse) {
        is $responses->[1]{num_connects}, 0,
            "$name reuses the connection";
        is $responses->[1]{local_port}, $responses->[0]{local_port},
            "$name keeps the local port";
    } else {
        is_deeply $responses->[0]{headers}{connection}, ['keep-alive'],
            "$name server permits keepalive";
        is $responses->[1]{num_connects}, 1,
            "$name reconnects after curl aborts the upload";
        isnt $responses->[1]{local_port}, $responses->[0]{local_port},
            "$name uses a new local port";
    }
}


sub assert_header_contract {
    my ($response, $branch, $name, $csp_count) = @_;
    my %common = map { $_ => 1 } qw(
        server
        date
        content-length
        connection
        powgate-challenge
    );
    my %html = map { $_ => 1 } qw(
        content-type
        cache-control
        x-robots-tag
        content-security-policy
    );
    my %allowed = %common;

    @allowed{keys %html} = values %html if $branch eq 'html';

    for my $header (sort keys %{$response->{headers}}) {
        ok $allowed{$header}, "$name allows header $header";
        unlike $header, qr/^powgate-(?!challenge$)/,
            "$name has no unknown PowGate header";

        for my $value (@{$response->{headers}{$header}}) {
            unlike $value, qr/\Q$secret\E/i,
                "$name header $header omits the secret";
        }
    }

    is scalar(@{$response->{headers}{'powgate-challenge'} // []}), 1,
        "$name has one challenge header";

    if ($branch eq 'html') {
        for my $header (qw(cache-control x-robots-tag)) {
            is scalar(@{$response->{headers}{$header} // []}), 1,
                "$name has one $header";
        }
        is scalar(@{$response->{headers}{'content-security-policy'} // []}),
            $csp_count, "$name CSP count";
    }
}


eval {
    $runtime = start_nginx(sub {
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
    pow on;
    error_page 403 = /error-403;
    error_page 503 = /error-503;

    location = /error-403 {
        internal;
        pow off;
        return 200 "overridden 403\\n";
    }

    location = /error-503 {
        internal;
        pow off;
        return 200 "overridden 503\\n";
    }

    location = /always-csp {
        add_header Content-Security-Policy "object-src 'none'" always;
        empty_gif;
    }

    location = /ordinary-csp {
        add_header Content-Security-Policy "object-src 'none'";
        empty_gif;
    }

    location = /ssi-main {
        pow off;
        ssi on;
        default_type text/html;
        return 200 "<!--# include virtual=\\"/ssi-fragment\\" -->";
    }

    location = /ssi-fragment {
        pow on;
        empty_gif;
    }

    location = /internal-start {
        pow off;
        error_page 418 = /internal-target;
        return 418;
    }

    location = /internal-target {
        internal;
        pow on;
        empty_gif;
    }

    location / {
        empty_gif;
    }
}
NGINX
    });

    for my $protocol ('1.1', '2') {
        subtest "request-body lifecycle over HTTPS $protocol" => sub {
            my @cases = (
                [ 'fixed body', 1,
                  { method => 'POST', path => '/body-fixed',
                    body => 'fixed-body' } ],
                [ 'expect continue', $protocol eq '2',
                  { method => 'POST', path => '/body-expect',
                    body => 'expect-body',
                    headers => [[Expect => '100-continue']] } ],
            );

            push @cases, [ 'chunked body', 1,
                { method => 'POST', path => '/body-chunked',
                  body => 'chunked-body',
                  headers => [[ 'Transfer-Encoding' => 'chunked' ]] } ]
                if $protocol eq '1.1';

            for my $case (@cases) {
                my $responses = https_sequence(
                    $runtime,
                    protocol => $protocol,
                    host => '127.0.0.1',
                    requests => [
                        $case->[2],
                        { method => 'GET', path => '/after-body' },
                    ],
                );

                assert_reused_sequence(
                    $responses,
                    $protocol,
                    "$case->[0] $protocol",
                    $case->[1],
                );
            }
        };

        subtest "response composition over HTTPS $protocol" => sub {
            my $range = https_request(
                $runtime,
                protocol => $protocol,
                host => '127.0.0.1',
                method => 'GET',
                path => '/range',
                headers => [[Range => 'bytes=0-1']],
            );
            is $range->{status}, 403, 'range cannot produce 206';
            ok !exists $range->{headers}{'accept-ranges'},
                'bare response has no Accept-Ranges';
            assert_header_contract($range, 'bare', 'bare range response', 0);

            for my $conditional (
                [ 'If-Modified-Since' => 'Wed, 21 Oct 2015 07:28:00 GMT' ],
                [ 'If-None-Match' => '"powgate-sentinel"' ],
            ) {
                my $response = https_request(
                    $runtime,
                    protocol => $protocol,
                    host => '127.0.0.1',
                    method => 'GET',
                    path => '/conditional',
                    headers => [
                        [Accept => 'text/html'],
                        $conditional,
                    ],
                );

                is $response->{status}, 503,
                    "$conditional->[0] cannot produce 304";
                ok !exists $response->{headers}{etag},
                    "$conditional->[0] response has no ETag";
                ok !exists $response->{headers}{'last-modified'},
                    "$conditional->[0] response has no Last-Modified";
                ok !exists $response->{headers}{'accept-ranges'},
                    "$conditional->[0] response has no Accept-Ranges";
            }

            my $bare = https_request(
                $runtime,
                protocol => $protocol,
                host => '127.0.0.1',
                method => 'GET',
                path => '/error-page-bare',
            );
            is $bare->{status}, 403, 'error_page does not replace bare 403';

            my $html = https_request(
                $runtime,
                protocol => $protocol,
                host => '127.0.0.1',
                method => 'GET',
                path => '/error-page-html',
                headers => [[Accept => 'text/html']],
            );
            is $html->{status}, 503, 'error_page does not replace HTML 503';
            assert_header_contract($html, 'html', 'HTML response', 1);

            my $head = https_request(
                $runtime,
                protocol => $protocol,
                host => '127.0.0.1',
                method => 'HEAD',
                path => '/head',
                headers => [[Accept => 'text/html']],
            );
            is $head->{status}, 503, 'HEAD remains an HTML challenge';
            is $head->{body}, '', 'HEAD body is empty';
            cmp_ok 0 + $head->{headers}{'content-length'}[0], '>', 0,
                'HEAD advertises the GET content length';

            my $always = https_request(
                $runtime,
                protocol => $protocol,
                host => '127.0.0.1',
                method => 'GET',
                path => '/always-csp',
                headers => [[Accept => 'text/html']],
            );
            is $always->{status}, 503, 'always CSP response status';
            assert_header_contract(
                $always,
                'html',
                'always CSP response',
                2,
            );
            ok grep($_ eq "object-src 'none'",
                    @{$always->{headers}{'content-security-policy'}}),
                'operator always CSP is preserved';

            my $ordinary = https_request(
                $runtime,
                protocol => $protocol,
                host => '127.0.0.1',
                method => 'GET',
                path => '/ordinary-csp',
                headers => [[Accept => 'text/html']],
            );
            is $ordinary->{status}, 503, 'ordinary CSP response status';
            assert_header_contract(
                $ordinary,
                'html',
                'ordinary CSP response',
                1,
            );
        };

        subtest "subrequest boundaries over HTTPS $protocol" => sub {
            my $ssi = https_request(
                $runtime,
                protocol => $protocol,
                host => '127.0.0.1',
                method => 'GET',
                path => '/ssi-main',
            );
            is $ssi->{status}, 200, 'SSI main request is allowed';
            like $ssi->{body}, qr/GIF89a/, 'SSI subrequest reaches content';
            ok !exists $ssi->{headers}{'powgate-challenge'},
                'SSI main response has no challenge';

            my $internal = https_request(
                $runtime,
                protocol => $protocol,
                host => '127.0.0.1',
                method => 'GET',
                path => '/internal-start',
            );
            is $internal->{status}, 200, 'internal redirect reaches content';
            like $internal->{body}, qr/GIF89a/,
                'internal target is not challenged';
            ok !exists $internal->{headers}{'powgate-challenge'},
                'internal response has no challenge';

            my $external = https_request(
                $runtime,
                protocol => $protocol,
                host => '127.0.0.1',
                method => 'GET',
                path => '/external-protected',
            );
            is $external->{status}, 403,
                'external protected request is still challenged';
        };
    }

    my $log = do {
        open my $fh, '<:raw', "$runtime->{prefix}/logs/error.log"
            or die "open composition error log: $!";
        local $/;
        my $bytes = <$fh>;
        close $fh or die "close composition error log: $!";
        $bytes;
    };
    unlike $log, qr/pow_gate:/,
        'normal challenge issuance adds no PowGate error log';
};
$error = $@;

my $cleanup = stop_nginx($runtime);
ok $cleanup->{reaped}, 'composition runtime is reaped';
ok $cleanup->{group_gone}, 'composition process group is gone';

die $error if $error ne '';

done_testing();
