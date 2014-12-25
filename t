#! /usr/bin/perl -w

# Test script for sslh

use strict;
use IO::Socket::INET6;
use Test::More qw/no_plan/;

# We use ports 9000, 9001 and 9002 -- hope that won't clash
# with anything...
my $ssh_address = "ip6-localhost:9000";
my $ssl_address = "ip6-localhost:9001";
my $sslh_port = 9002;
my $no_listen = 9003;  # Port on which no-one listens
my $pidfile = "/tmp/sslh_test.pid";

# Which tests do we run
my $SSL_CNX =           1;
my $SSH_SHY_CNX =       1;
my $SSH_BOLD_CNX =      1;
my $SSH_PROBE_AGAIN =   1;
my $SSL_MIX_SSH =       1;
my $SSH_MIX_SSL =       1;
my $BIG_MSG =           0; # This test is unreliable
my $STALL_CNX =         0; # This test needs fixing

# Robustness tests. These are mostly to achieve full test
# coverage, but do not necessarily result in an actual test
# (e.g. some tests need to be run with valgrind to check all
# memory management code).
my $RB_CNX_NOSERVER =           1;
my $RB_PARAM_NOHOST =           1;
my $RB_WRONG_USERNAME =         1;
my $RB_OPEN_PID_FILE =          1;
my $RB_BIND_ADDRESS =           1;
my $RB_RESOLVE_ADDRESS =        1;

`lcov --directory . --zerocounters`;


my ($ssh_pid, $ssl_pid);

if (!($ssh_pid = fork)) {
    exec "./echosrv --listen $ssh_address --prefix 'ssh: '";
}

if (!($ssl_pid = fork)) {
    exec "./echosrv --listen $ssl_address --prefix 'ssl: '";
}

my @binaries = ('sslh-select', 'sslh-fork');
for my $binary (@binaries) {
    warn "Testing $binary\n";

# Start sslh with the right plumbing
    my $sslh_pid;
    if (!($sslh_pid = fork)) {
        my $user = (getpwuid $<)[0]; # Run under current username
        my $cmd = "./$binary -v -f -u $user --listen localhost:$sslh_port --ssh $ssh_address --ssl $ssl_address -P $pidfile";
        warn "$cmd\n";
        #exec $cmd;
        exec "valgrind --leak-check=full ./$binary -v -f -u $user --listen localhost:$sslh_port --ssh $ssh_address -ssl $ssl_address -P $pidfile";
        exit 0;
    }
    warn "spawned $sslh_pid\n";
    sleep 5;  # valgrind can be heavy -- wait 5 seconds


    my $test_data = "hello world\n";
#    my $ssl_test_data = (pack 'n', ((length $test_data) + 2)) .  $test_data;
    my $ssl_test_data = "\x16\x03\x03$test_data\n";

# Test: SSL connection
    if ($SSL_CNX) {
        print "***Test: SSL connection\n";
        my $cnx_l = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
        warn "$!\n" unless $cnx_l;
        if (defined $cnx_l) {
            print $cnx_l $ssl_test_data;
            my $data;
            my $n = sysread $cnx_l, $data, 1024;
            is($data, "ssl: $ssl_test_data", "SSL connection");
        }
    }

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

# Test: Bold SSH connection
    if ($SSH_BOLD_CNX) {
        print "***Test: Bold SSH connection\n";
        my $cnx_h = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
        warn "$!\n" unless $cnx_h;
        if (defined $cnx_h) {
            my $td = "SSH-2.0 testsuite\t$test_data";
            print $cnx_h $td;
            my $data = <$cnx_h>;
            is($data, "ssh: $td", "Bold SSH connection");
        }
    }

# Test: PROBE_AGAIN, incomplete first frame
    if ($SSH_PROBE_AGAIN) {
        print "***Test: incomplete SSH first frame\n";
        my $cnx_h = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
        warn "$!\n" unless $cnx_h;
        if (defined $cnx_h) {
            my $td = "SSH-2.0 testsuite\t$test_data";
            print $cnx_h substr $td, 0, 2;
            sleep 1;
            print $cnx_h substr $td, 2;
            my $data = <$cnx_h>;
            is($data, "ssh: $td", "Incomplete first SSH frame");
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


# Test: Big messages (careful: don't go over echosrv's buffer limit (1M))
    if ($BIG_MSG) {
        print "***Test: big message\n";
        my $cnx_l = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
        warn "$!\n" unless $cnx_l;
        my $rept = 1000;
        my $test_data2 = $ssl_test_data . ("helloworld"x$rept);
        if (defined $cnx_l) {
            my $n = syswrite $cnx_l, $test_data2;
            my ($data);
            $n = sysread $cnx_l, $data, 1 << 20;
            is($data, "ssl: ". $test_data2, "Big message");
        }
    }

# Test: Stalled connection
# Create two connections, stall one, check the other one
# works, unstall first and check it works fine
# This test needs fixing.
# Now that echosrv no longer works on "lines" (finishing
# with '\n'), it may cut blocks randomly with prefixes.
# The whole thing needs to be re-thought as it'll only
# work by chance.
    if ($STALL_CNX) {
        print "***Test: Stalled connection\n";
        my $cnx_1 = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
        warn "$!\n" unless defined $cnx_1;
        my $cnx_2 = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
        warn "$!\n" unless defined $cnx_2;
        my $test_data2 = "helloworld";
        sleep 4;
        my $rept = 1000;
        if (defined $cnx_1 and defined $cnx_2) {
            print $cnx_1 ($test_data2 x $rept);
            print $cnx_1 "\n";
            print $cnx_2 ($test_data2 x $rept);
            print $cnx_2 "\n";
            my $data = <$cnx_2>;
            is($data, "ssh: " . ($test_data2 x $rept) . "\n", "Stalled connection (1)");
            print $cnx_2 ($test_data2 x $rept);
            print $cnx_2 "\n";
            $data = <$cnx_2>;
            is($data, "ssh: " . ($test_data2 x $rept) . "\n", "Stalled connection (2)");
            $data = <$cnx_1>;
            is($data, "ssh: " . ($test_data2 x $rept) . "\n", "Stalled connection (3)");

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
        my $user = (getpwuid $<)[0]; # Run under current username
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


# Robustness: No hostname in address
if ($RB_PARAM_NOHOST) {
    print "***Test: No hostname in address\n";
    my $sslh_pid;
    if (!($sslh_pid = fork)) {
        my $user = (getpwuid $<)[0]; # Run under current username
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
        my $user = (getpwuid $<)[0]; # Run under current username
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
        my $user = (getpwuid $<)[0]; # Run under current username
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

