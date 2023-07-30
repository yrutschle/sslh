#! /usr/bin/perl -w

# Test script for sslh

# Uses Conf::Libconfig to read sslh config file: install
# with:
# cpan Conf::Libconfig

use strict;
use IO::Socket::INET6;
use Test::More qw/no_plan/;
use Conf::Libconfig;

my $conf = new Conf::Libconfig;
$conf->read_file("test.cfg");


my $no_listen = 8083;  # Port on which no-one listens
my $pidfile = $conf->lookup_value("pidfile");
my $sslh_port = $conf->fetch_array("listen")->[0]->{port};
my $user = (getpwuid $<)[0]; # Run under current username

# Which tests do we run
my $SSH_SHY_CNX =       0;
my $PROBES_NOFRAG =     1;
my $PROBES_AGAIN =      1;
my $SSL_MIX_SSH =       1;
my $SSH_MIX_SSL =       1;
my $DROP_CNX =          1;

# Robustness tests. These are mostly to achieve full test
# coverage, but do not necessarily result in an actual test
# (e.g. some tests need to be run with valgrind to check all
# memory management code).
my $RB_CNX_NOSERVER =           0;
my $RB_PARAM_NOHOST =           0;
my $RB_WRONG_USERNAME =         0;
my $RB_OPEN_PID_FILE =          0;
my $RB_RESOLVE_ADDRESS =        0;
my $RB_CL_PARAMS =              0;

`lcov --directory . --zerocounters`;

sub verbose_exec
{
    my ($cmd) = @_;

    warn "$cmd\n";
    if (!fork) {
        exec $cmd;
    }
}

# We want to keep track of tests to print a report at the
# end, so we centralise all calls to Test::More::is here
my $cnt = 1;   # test counter
my @results;
sub my_is {
    my ($a, $b, $desc) = @_;

    my $res =  is($a, $b, $desc);
    push @results, [$cnt++, $desc, $res];
}



# For SNI/ALPN, build a protocol name as such:
# tls:sni1,sni2,...;alpn1,alpn2,...
# input: a protocol entry from Libconfig
sub make_sni_alpn_name {
    my ($prot) = @_;

   return "tls:" . (join ",", @{$prot->{sni_hostnames} // []})
           . ";" . (join ",", @{$prot->{alpn_protocols} // [] });
}


# Tests one probe: given input data, connect, verify we get
# the expected server, verify shoveling works
# Named options:
# data: what to write
# expected: expected protocol prefix
# no_frag: don't print byte-per-byte
sub test_probe {
    my (%opts) = @_;

    my $cnx = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
    warn "$!\n" unless $cnx;
    return unless $cnx;

    my $pattern = $opts{data};
    if ($opts{no_frag}) {
        syswrite $cnx, $pattern;
    } else {
        while (length $pattern) {
            syswrite $cnx, (substr $pattern, 0, 1, '');
            select undef, undef, undef, .01;
        }
    }

    my $data;
    my $n = sysread $cnx, $data, 1024;
    $data =~ /^(.*?): /;
    my $prefix = $1;
    $data =~ s/$prefix: //g;
    print "Received $n bytes: protocol $prefix data [$data]\n";
    close $cnx;

    $opts{expected} =~ s/^ssl/tls/; # to remove in 1.21
    my_is($prefix, $opts{expected}, "$opts{binary}:$opts{expected}: probe connected correctly");
    my_is($data, $opts{data}, "$opts{binary}:$opts{expected}: data shoveled correctly");
}

# Test all probes, with or without fragmentation
# options:
#     no_frag: write test patterns all at once (also
#     available per-protocol as some probes don't support
#     fragmentation)
sub test_probes {
    my (%in_opts) = @_;

    my @probes = @{$conf->fetch_array("protocols")};
    foreach my $p (@probes) {
        my %protocols = (
            'ssh' => { data => "SSH-2.0 tester" },
            'socks5' => { data => "\x05\x04\x01\x02\x03\x04" },
            'http' => { 
                data => "GET index.html HTTP/1.1",
                no_frag => 1 },
            'tls' => { 
                # Packet with SNI and ALPN (`openssl s_client -connect localhost:443 -alpn alpn1 -servername sni1`)
                data_sni_alpn => "\x16\x03\x01\x00\xc4\x01\x00\x00\xc0\x03\x03\x03\x19\x01\x00\x40\x14\x13\xcc\x1b\x94\xad\x20\x5d\x13\x1a\x8d\xd2\x65\x23\x70\xde\xd1\x3c\x5d\x05\x19\xcb\x27\x0d\x7c\x2c\x89\x00\x00\x38\xc0\x2c\xc0\x30\x00\x9f\xcc\xa9\xcc\xa8\xcc\xaa\xc0\x2b\xc0\x2f\x00\x9e\xc0\x24\xc0\x28\x00\x6b\xc0\x23\xc0\x27\x00\x67\xc0\x0a\xc0\x14\x00\x39\xc0\x09\xc0\x13\x00\x33\x00\x9d\x00\x9c\x00\x3d\x00\x3c\x00\x35\x00\x2f\x00\xff\x01\x00\x00\x5f\x00\x00\x00\x09\x00\x07\x00\x00\x04\$sni\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x19\x00\x18\x00\x23\x00\x00\x00\x0d\x00\x20\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03\x00\x10\x00\x08\x00\x06\x05\$alpn\x00\x16\x00\x00\x00\x17\x00\x00hello sni/alpn",
                # Packet with SNI alone
                data_sni => "\x16\x03\x01\x00\xb8\x01\x00\x00\xb4\x03\x03\x97\xe4\xe9\xad\x86\xe1\x21\xfd\xc4\x5b\x27\x0e\xad\x4b\x55\xc2\x50\xe4\x1c\x86\x2f\x37\x25\xde\xe8\x9c\x59\xfc\x1b\xa9\x37\x32\x00\x00\x38\xc0\x2c\xc0\x30\x00\x9f\xcc\xa9\xcc\xa8\xcc\xaa\xc0\x2b\xc0\x2f\x00\x9e\xc0\x24\xc0\x28\x00\x6b\xc0\x23\xc0\x27\x00\x67\xc0\x0a\xc0\x14\x00\x39\xc0\x09\xc0\x13\x00\x33\x00\x9d\x00\x9c\x00\x3d\x00\x3c\x00\x35\x00\x2f\x00\xff\x01\x00\x00\x53\x00\x00\x00\x09\x00\x07\x00\x00\x04\$sni\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x19\x00\x18\x00\x23\x00\x00\x00\x0d\x00\x20\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03\x00\x16\x00\x00\x00\x17\x00\x00hello sni",
                # packet with ALPN alone
                data_alpn => "\x16\x03\x01\x00\xb7\x01\x00\x00\xb3\x03\x03\xe2\x90\xa2\x29\x03\x31\xad\x98\x44\x51\x54\x90\x5b\xd9\x51\x0e\x66\xb5\x3f\xe8\x8b\x09\xc9\xe4\x2b\x97\x24\xef\xad\x56\x06\xc9\x00\x00\x38\xc0\x2c\xc0\x30\x00\x9f\xcc\xa9\xcc\xa8\xcc\xaa\xc0\x2b\xc0\x2f\x00\x9e\xc0\x24\xc0\x28\x00\x6b\xc0\x23\xc0\x27\x00\x67\xc0\x0a\xc0\x14\x00\x39\xc0\x09\xc0\x13\x00\x33\x00\x9d\x00\x9c\x00\x3d\x00\x3c\x00\x35\x00\x2f\x00\xff\x01\x00\x00\x52\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x19\x00\x18\x00\x23\x00\x00\x00\x0d\x00\x20\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03\x00\x10\x00\x08\x00\x06\x05\$alpn\x00\x16\x00\x00\x00\x17\x00\x00hello alpn",
                # packet with no SNI, no ALPN
                data => "\x16\x03\x01\x00\xab\x01\x00\x00\xa7\x03\x03\x89\x22\x33\x95\x43\x7a\xc3\x89\x45\x51\x12\x3c\x28\x24\x1b\x6a\x78\xbf\xbe\x95\xd8\x90\x58\xd7\x65\xf7\xbb\x2d\xb2\x8d\xa0\x75\x00\x00\x38\xc0\x2c\xc0\x30\x00\x9f\xcc\xa9\xcc\xa8\xcc\xaa\xc0\x2b\xc0\x2f\x00\x9e\xc0\x24\xc0\x28\x00\x6b\xc0\x23\xc0\x27\x00\x67\xc0\x0a\xc0\x14\x00\x39\xc0\x09\xc0\x13\x00\x33\x00\x9d\x00\x9c\x00\x3d\x00\x3c\x00\x35\x00\x2f\x00\xff\x01\x00\x00\x46\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x19\x00\x18\x00\x23\x00\x00\x00\x0d\x00\x20\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03\x00\x16\x00\x00\x00\x17\x00\x00hello tls alone"
            },
            'openvpn' => { data => "\x00\x00" },
            'syslog' => { data => "<42> My syslog message" },
            'tinc' => { data => "0 hello" },
            'xmpp' => {data => "I should get a real jabber connection initialisation here" },
            'adb' => { data => "CNXN....................host:..." },
            'anyprot' => {data => "hello anyprot this needs to be longer than xmpp and adb which expect about 50 characters, which I all have to write before the timeout!" },
        );

        my $pattern = $protocols{$p->{name}}->{data};

        my %opts = %in_opts;
        $opts{no_frag} = 1 if $protocols{$p->{name}}->{no_frag};

        if ($p->{sni_hostnames} or $p->{alpn_protocols}) {
            my $pname = make_sni_alpn_name($p);

            my @sni = @{$p->{sni_hostnames} // [""] };
            my @alpn = @{$p->{alpn_protocols} // [""] };

            foreach my $sni ( @sni ) {
                foreach my $alpn ( @alpn ) {
                    print "sni: $sni\nalpn: $alpn\n";
                    $pattern = $protocols{tls}->{
                        "data". ($sni ?  "_sni" : "") . 
                                ($alpn ?  "_alpn": "")
                    };
                    $pattern =~ s/(\$\w+)/$1/eeg;

                    test_probe(
                        data => $pattern,
                        expected => $pname,
                        %opts
                    );
                }
            }
        } elsif ($p->{name} eq 'regex') {
            foreach my $test (@{$p->{test_patterns}}) {
                test_probe(
                    data => $test->{pattern},
                    expected => $test->{result},
                    %opts
                );
            }
        } else {
            test_probe(
                data => $pattern,
                expected => $p->{name},
                %opts
            );

        }
    }
}



# Start an echoserver for each service
foreach my $s (@{$conf->fetch_array("protocols")}) {
    my $prefix = $s->{name};

    $prefix =~ s/^ssl/tls/; # To remove in 1.21

    if ($s->{sni_hostnames} or $s->{alpn_protocols}) {
        $prefix = make_sni_alpn_name($s);
    }

    verbose_exec "./echosrv --listen $s->{host}:$s->{port} --prefix '$prefix: '";
}


#my @binaries = ('sslh-select', 'sslh-fork');
my @binaries = ('sslh-select');

for my $binary (@binaries) {
    warn "Testing $binary\n";

# Start sslh with the right plumbing
    my ($sslh_pid, $valgrind);
    if (!($sslh_pid = fork)) {
        my $user = (getpwuid $<)[0]; # Run under current username
        my $cmd = "./$binary -v 4 -f -u $user -F test.cfg";
        #$valgrind = 1;
        #$cmd = "valgrind --leak-check=full $cmd";
        verbose_exec $cmd;
        exit 0;
    }
    warn "spawned $sslh_pid\n";
    sleep 1; # Give everyone some time to start
    sleep 5 if $valgrind;  # valgrind can be heavy -- wait 5 seconds


    my $test_data = "hello world\n";
    my $ssl_test_data =  "\x16\x03\x01\x00\xab\x01\x00\x00\xa7\x03\x03\x89\x22\x33\x95\x43\x7a\xc3\x89\x45\x51\x12\x3c\x28\x24\x1b\x6a\x78\xbf\xbe\x95\xd8\x90\x58\xd7\x65\xf7\xbb\x2d\xb2\x8d\xa0\x75\x00\x00\x38\xc0\x2c\xc0\x30\x00\x9f\xcc\xa9\xcc\xa8\xcc\xaa\xc0\x2b\xc0\x2f\x00\x9e\xc0\x24\xc0\x28\x00\x6b\xc0\x23\xc0\x27\x00\x67\xc0\x0a\xc0\x14\x00\x39\xc0\x09\xc0\x13\x00\x33\x00\x9d\x00\x9c\x00\x3d\x00\x3c\x00\x35\x00\x2f\x00\xff\x01\x00\x00\x46\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x19\x00\x18\x00\x23\x00\x00\x00\x0d\x00\x20\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03\x00\x16\x00\x00\x00\x17\x00\x00hello tls alone";

# Test: Shy SSH connection
    if ($SSH_SHY_CNX) {
        print "***Test: Shy SSH connection\n";
        my $cnx_h = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
        warn "$!\n" unless $cnx_h;
        if (defined $cnx_h) {
            sleep 13;
            print $cnx_h $test_data;
            my $data = <$cnx_h>;
            my_is($data, "ssh: $test_data", "$binary: Shy SSH connection");
        }
    }

# Test: One SSL half-started then one SSH
    if ($SSL_MIX_SSH) {
        print "***Test: One SSL half-started then one SSH\n";
        my $cnx_l = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
        warn "$!\n" unless $cnx_l;
        if (defined $cnx_l) {
            print $cnx_l $ssl_test_data;
            my $cnx_h= new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
            warn "$!\n" unless $cnx_h;
            if (defined $cnx_h) {
                sleep 3;
                print $cnx_h $test_data;
                my $data_h = <$cnx_h>;
                my_is($data_h, "ssh: $test_data", "$binary: SSH during SSL being established");
            }
            my $data;
            my $n = sysread $cnx_l, $data, 1024;
            my_is($data, "tls: $ssl_test_data", "$binary: SSL connection interrupted by SSH");
        }
    }

# Test: One SSH half-started then one SSL
    if ($SSH_MIX_SSL) {
        print "***Test: One SSH half-started then one SSL\n";
        my $cnx_h = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
        warn "$!\n" unless $cnx_h;
        if (defined $cnx_h) {
            sleep 3;
            my $cnx_l = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
            warn "$!\n" unless $cnx_l;
            if (defined $cnx_l) {
                print $cnx_l $ssl_test_data;
                my $data;
                my $n = sysread $cnx_l, $data, 1024;
                my_is($data, "tls: $ssl_test_data", "$binary: SSL during SSH being established");
            }
            print $cnx_h $test_data;
            my $data = <$cnx_h>;
            my_is($data, "ssh: $test_data", "$binary: SSH connection interrupted by SSL");
        }
    }

# Test: Drop connection without writing anything
    if ($DROP_CNX) {
        print "***Test: Connect but don't write anything\n";
        my $cnx_h = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
        warn "$!\n" unless $cnx_h;
        if ($cnx_h) {
            close $cnx_h;
            my_is(1, "$binary: Connect and write nothing");
            # The goal of the test is to check sslh doesn't
            # crash
        }
    }


    if ($PROBES_NOFRAG) {
        test_probes(no_frag => 1, binary => $binary);
    }

    if ($PROBES_AGAIN) {
        test_probes(binary => $binary);
    }

    my $pid = `cat $pidfile`;
    warn "killing $pid\n";
    kill TERM => $pid or warn "kill process: $!\n";
    sleep 1;
}

# Robustness: Connecting to non-existant server
if ($RB_CNX_NOSERVER) {
    print "***Test: Connecting to non-existant server\n";
    my $sslh_pid;
    if (!($sslh_pid = fork)) {
        exec "./sslh-select -v 3 -f -u $user --listen localhost:$sslh_port --ssh localhost:$no_listen --tls localhost:$no_listen -P $pidfile";
    }
    warn "spawned $sslh_pid\n";

    sleep 1;

    my $cnx_h = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
    warn "$!\n" unless $cnx_h;
    if (defined $cnx_h) {
        sleep 1;
        my $test_data = "hello";
        print $cnx_h $test_data;
    }
    # Ideally we should check a log is emitted.

    kill TERM => `cat $pidfile` or warn "kill: $!\n";
    sleep 1;
}


my $ssh_conf = (grep { $_->{name} eq "ssh" } @{$conf->fetch_array("protocols")})[0];
my $ssh_address = $ssh_conf->{host} . ":" .  $ssh_conf->{port};

# Use the last TLS echoserv (no SNI/ALPN)
my $ssl_conf = (grep { $_->{name} eq "tls" } @{$conf->fetch_array("protocols")})[-1];
my $ssl_address = $ssl_conf->{host} . ":" .  $ssl_conf->{port};


# Robustness: No hostname in address
if ($RB_PARAM_NOHOST) {
    print "***Test: No hostname in address\n";
    my $sslh_pid;
    if (!($sslh_pid = fork)) {
        exec "./sslh-select -v 3 -f -u $user --listen $sslh_port --ssh $ssh_address --tls $ssl_address -P $pidfile";
    }
    warn "spawned $sslh_pid\n";
    waitpid $sslh_pid, 0;
    my $code = $? >> 8;
    warn "exited with $code\n";
    my_is($code, 6, "Exit status on illegal option");
}

# Robustness: User does not exist
if ($RB_WRONG_USERNAME) {
    print "***Test: Changing to non-existant username\n";
    my $sslh_pid;
    if (!($sslh_pid = fork)) {
        exec "./sslh-select -v 3 -f -u ${user}_doesnt_exist --listen localhost:$no_listen --ssh $ssh_address --tls $ssl_address -P $pidfile";
    }
    warn "spawned $sslh_pid\n";
    waitpid $sslh_pid, 0;
    my $code = $? >> 8;
    warn "exited with $code\n";
    my_is($code, 2, "Exit status on non-existant username");
}

# Robustness: Can't open PID file
if ($RB_OPEN_PID_FILE) {
    print "***Test: Can't open PID file\n";
    my $sslh_pid;
    if (!($sslh_pid = fork)) {
        exec "./sslh-select -v 3 -f -u $user --listen localhost:$no_listen --ssh $ssh_address --tls $ssl_address -P /dont_exist/$pidfile";
        # You don't have a /dont_exist/ directory, do you?!
    }
    warn "spawned $sslh_pid\n";
    waitpid $sslh_pid, 0;
    my $code = $? >> 8;
    warn "exited with $code\n";
    my_is($code, 3, "Exit status if can't open PID file");
}

# Robustness: Can't resolve address
if ($RB_RESOLVE_ADDRESS) {
    print "***Test: Can't resolve address\n";
    my $sslh_pid;
    if (!($sslh_pid = fork)) {
        my $user = (getpwuid $<)[0]; # Run under current username
        exec "./sslh-select -v 3 -f -u $user --listen blahblah.nonexistent:9000 --ssh $ssh_address --tls $ssl_address -P $pidfile";
    }
    warn "spawned $sslh_pid\n";
    waitpid $sslh_pid, 0;
    my $code = $? >> 8;
    warn "exited with $code\n";
    my_is($code, 4, "Exit status if can't resolve address");
}

# Robustness: verify all command line options work
if ($RB_CL_PARAMS) {
    print "***Test: Command line parameters\n";
    my $sslh_pid;
    if (!($sslh_pid = fork)) {
        my $user = (getpwuid $<)[0]; # Run under current username
        # This doesn't test --inetd
        exec "./sslh-select -v 3 -f -u $user -P $pidfile".
        " -n --transparent --timeout 10 -C /tmp".
        " --syslog-facility auth --on-timeout ssh".
        " --listen localhost:$no_listen --ssh $ssh_address --tls $ssl_address".
        " --openvpn localhost:$no_listen".
        " --tinc localhost:$no_listen".
        " --xmpp localhost:$no_listen".
        " --http localhost:$no_listen".
        " --adb localhost:$no_listen".
        " --socks5 localhost:$no_listen".
        " --anyprot localhost:$no_listen";
        exit 0;
    }
    warn "spawned $sslh_pid\n";
    # It will die soon because $user cannot chroot (you
    # don't test as root, do you?)

    waitpid $sslh_pid, 0;
    my $code = $? >> 8;
    warn "exited with $code\n";
    my_is($code, 1, "Command line arguments");


    print "***Test: Bad command line parameters\n";
    my $sslh_pid;
    if (!($sslh_pid = fork)) {
        my $user = (getpwuid $<)[0]; # Run under current username
        # This doesn't test --inetd
        exec "./sslh-select -v 3 -f -u $user -P $pidfile".
        " -n --transparent --timeout 10 -C /tmp".
        " --fakeoption".
        " --anyprot localhost:$no_listen";
        exit 0;
    }
    warn "spawned $sslh_pid\n";

    waitpid $sslh_pid, 0;
    my $code = $? >> 8;
    warn "exited with $code\n";
    my_is($code, 6, "Bad command line parameters");
}

`lcov --directory . --capture --output-file sslh_cov.info`;
`genhtml sslh_cov.info`;

`killall echosrv`;


format test_results_top =
ID  | Description                                                       | Status
----+-------------------------------------------------------------------+-------
.

format test_results = 
@>> | @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< |   @>>
$_->[0], $_->[1], $_->[2] ? "OK" : "NOK"
.

format_name STDOUT "test_results";
format_top_name STDOUT "test_results_top";
map { write; } @results;
