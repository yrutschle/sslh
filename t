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
my $SSH_SHY_CNX =       1;
my $SSH_PROBE_AGAIN =   1;
my $PROBES =            1;
my $SSL_MIX_SSH =       1;
my $SSH_MIX_SSL =       1;

# Robustness tests. These are mostly to achieve full test
# coverage, but do not necessarily result in an actual test
# (e.g. some tests need to be run with valgrind to check all
# memory management code).
my $RB_CNX_NOSERVER =           1;
my $RB_PARAM_NOHOST =           1;
my $RB_WRONG_USERNAME =         1;
my $RB_OPEN_PID_FILE =          1;
my $RB_RESOLVE_ADDRESS =        1;

`lcov --directory . --zerocounters`;

sub verbose_exec
{
    my ($cmd) = @_;

    warn "$cmd\n";
    if (!fork) {
        exec $cmd;
    }
}

# Start an echoserver for each service
foreach my $s (@{$conf->fetch_array("protocols")}) {
    verbose_exec "./echosrv --listen $s->{host}:$s->{port} --prefix '$s->{name}: '";
}


my @binaries = ('sslh-select', 'sslh-fork');
for my $binary (@binaries) {
    warn "Testing $binary\n";

# Start sslh with the right plumbing
    my $sslh_pid;
    if (!($sslh_pid = fork)) {
        my $user = (getpwuid $<)[0]; # Run under current username
        #my $cmd = "./$binary -v -f -u $user --listen localhost:$sslh_port --ssh $ssh_address --ssl $ssl_address -P $pidfile";
        my $cmd = "./$binary -v -f -u $user -Ftest.cfg";
        verbose_exec $cmd;
        #exec "valgrind --leak-check=full ./$binary -v -f -u $user --listen localhost:$sslh_port --ssh $ssh_address -ssl $ssl_address -P $pidfile";
        exit 0;
    }
    warn "spawned $sslh_pid\n";
    sleep 5;  # valgrind can be heavy -- wait 5 seconds


    my $test_data = "hello world\n";
#    my $ssl_test_data = (pack 'n', ((length $test_data) + 2)) .  $test_data;
    my $ssl_test_data = "\x16\x03\x03$test_data\n";

# Test: Shy SSH connection
    if ($SSH_SHY_CNX) {
        print "***Test: Shy SSH connection\n";
        my $cnx_h = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
        warn "$!\n" unless $cnx_h;
        if (defined $cnx_h) {
            sleep 3;
            print $cnx_h $test_data;
            my $data = <$cnx_h>;
            is($data, "ssh: $test_data", "Shy SSH connection");
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
                is($data_h, "ssh: $test_data", "SSH during SSL being established");
            }
            my $data;
            my $n = sysread $cnx_l, $data, 1024;
            is($data, "ssl: $ssl_test_data", "SSL connection interrupted by SSH");
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
                is($data, "ssl: $ssl_test_data", "SSL during SSH being established");
            }
            print $cnx_h $test_data;
            my $data = <$cnx_h>;
            is($data, "ssh: $test_data", "SSH connection interrupted by SSL");
        }
    }


    # Test: probes. For each probe, write one byte at a time
    # and check we get connected to the right server. 
    if ($PROBES) {
        my @probes = @{$conf->fetch_array("protocols")};
        foreach my $p (@probes) {
            my %protocols = (
                'ssh' => { data => "SSH-2.0 tester" },
                'socks5' => { data => "\x05\x04\x01\x02\x03\x04" },
                'http' => { 
                    data => "GET index.html HTTP/1.1",
                    no_fragment => 1 },
                'ssl' => { data => "\x16\x03\x031234" },
                'openvpn' => { data => "\x00\x00" },
                'tinc' => { data => "0 hello" },
                'xmpp' => {data => "I should get a real jabber connection initialisation here" },
                'adb' => { data => "CNXN....................host:..." },
                'anyprot' => {data => "hello, this needs to be longer than the longest probe that returns PROBE_AGAIN" },
            );

            my $cnx = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
            warn "$!\n" unless $cnx;
            if (defined $cnx) {
                my $pattern = $protocols{$p->{name}}->{data};
                if ($protocols{$p->{name}}->{no_fragment}) {
                    syswrite $cnx, $pattern;
                } else {
                    while (length $pattern) {
                        syswrite $cnx, (substr $pattern, 0, 1, '');
                        select undef, undef, undef, .1;
                    }
                }

                my $data;
                my $n = sysread $cnx, $data, 1024;
                $data =~ /^(.*?): /;
                my $prefix = $1;
                $data =~ s/$prefix: //g;
                print "Received: protocol $prefix data [$data]\n";
                close $cnx;

                is($prefix, $p->{name});
                is($data, $protocols{$p->{name}}->{data});
            }
        }
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
        exec "./sslh-select -v -f -u $user --listen localhost:$sslh_port --ssh localhost:$no_listen --ssl localhost:$no_listen -P $pidfile";
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

my $ssl_conf = (grep { $_->{name} eq "ssl" } @{$conf->fetch_array("protocols")})[0];
my $ssl_address = $ssl_conf->{host} . ":" .  $ssl_conf->{port};


# Robustness: No hostname in address
if ($RB_PARAM_NOHOST) {
    print "***Test: No hostname in address\n";
    my $sslh_pid;
    if (!($sslh_pid = fork)) {
        exec "./sslh-select -v -f -u $user --listen $sslh_port --ssh $ssh_address --ssl $ssl_address -P $pidfile";
    }
    warn "spawned $sslh_pid\n";
    waitpid $sslh_pid, 0;
    my $code = $? >> 8;
    warn "exited with $code\n";
    is($code, 1, "Exit status on illegal option");
}

# Robustness: User does not exist
if ($RB_WRONG_USERNAME) {
    print "***Test: Changing to non-existant username\n";
    my $sslh_pid;
    if (!($sslh_pid = fork)) {
        exec "./sslh-select -v -f -u ${user}_doesnt_exist --listen localhost:$sslh_port --ssh $ssh_address --ssl $ssl_address -P $pidfile";
    }
    warn "spawned $sslh_pid\n";
    waitpid $sslh_pid, 0;
    my $code = $? >> 8;
    warn "exited with $code\n";
    is($code, 2, "Exit status on non-existant username");
}

# Robustness: Can't open PID file
if ($RB_OPEN_PID_FILE) {
    print "***Test: Can't open PID file\n";
    my $sslh_pid;
    if (!($sslh_pid = fork)) {
        exec "./sslh-select -v -f -u $user --listen localhost:$sslh_port --ssh $ssh_address --ssl $ssl_address -P /dont_exist/$pidfile";
        # You don't have a /dont_exist/ directory, do you?!
    }
    warn "spawned $sslh_pid\n";
    waitpid $sslh_pid, 0;
    my $code = $? >> 8;
    warn "exited with $code\n";
    is($code, 3, "Exit status if can't open PID file");
}

# Robustness: Can't resolve address
if ($RB_RESOLVE_ADDRESS) {
    print "***Test: Can't resolve address\n";
    my $sslh_pid;
    if (!($sslh_pid = fork)) {
        my $user = (getpwuid $<)[0]; # Run under current username
        exec "./sslh-select -v -f -u $user --listen blahblah.dontexist:9000 --ssh $ssh_address --ssl $ssl_address -P $pidfile";
    }
    warn "spawned $sslh_pid\n";
    waitpid $sslh_pid, 0;
    my $code = $? >> 8;
    warn "exited with $code\n";
    is($code, 4, "Exit status if can't resolve address");
}

`lcov --directory . --capture --output-file sslh_cov.info`;
`genhtml sslh_cov.info`;

`killall echosrv`;

