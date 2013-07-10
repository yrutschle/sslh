#! /usr/bin/perl -w

# Test script for sslh

# The principle is to create two listening sockets which
# will act as the ssh and ssl servers, and then perform a
# number of connections in various combinations to check
# that the server behaves properly.

use strict;
use IO::Socket::INET;
use Test::More qw/no_plan/;

# We use ports 9000, 9001 and 9002 -- hope that won't clash
# with anything...
my $ssh_port = 9000;
my $ssl_port = 9001;
my $sslh_port = 9002;
my $pidfile = "/tmp/sslh.pid";

# How many connections will be created during the last test
my $NUM_SSL_CNX = 20;
my $NUM_SSH_CNX = 20;

# Which tests do we run
my $SSL_CNX =           1;
my $SSH_SHY_CNX =       1;
my $SSH_BOLD_CNX =      1;
my $SSL_MIX_SSH =       1;
my $SSH_MIX_SSL =       1;
my $BIG_MSG =           1;
my $MANY_CNX =          1;

# the Listen parameter needs to be bigger than the max number of connexions
# we'll make during the last test (we open a bunch of SSH connexions, and 
# accept them all at once afterwards)
my $ssh_listen = new IO::Socket::INET(LocalHost=> "localhost:$ssh_port", Blocking => 1, Reuse => 1, Listen => $NUM_SSH_CNX + 1);
die "error1: $!\n" unless $ssh_listen;

my $ssl_listen = new IO::Socket::INET(LocalHost=> "localhost:$ssl_port", Blocking => 1, Reuse => 1, Listen => $NUM_SSL_CNX + 1);
die "error2: $!\n" unless $ssl_listen;

# Start sslh with the right plumbing
my $sslh_pid;
if (!($sslh_pid = fork)) {
    my $user = (getpwuid $<)[0]; # Run under current username
    exec "./sslh-fork -v -u $user -p localhost:$sslh_port -s localhost:$ssh_port -l localhost:$ssl_port -P $pidfile";
    #exec "./sslh-select -v -f -u $user -p localhost:$sslh_port -s localhost:$ssh_port -l localhost:$ssl_port -P $pidfile";
    #exec "valgrind --leak-check=full ./sslh-select -v -f -u $user -p localhost:$sslh_port -s localhost:$ssh_port -l localhost:$ssl_port -P $pidfile";
    exit 0;
}
warn "spawned $sslh_pid\n";
sleep 1;


my $test_data = "hello world\n";

# Test: SSL connection
if ($SSL_CNX) {
    print "***Test: SSL connection\n";
    my $cnx_l = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
    warn "$!\n" unless $cnx_l;
    if (defined $cnx_l) {
        print $cnx_l $test_data;
        my $ssl_data = $ssl_listen->accept;
        my $data = <$ssl_data>;
        is($data, $test_data, "SSL connection");
    }
}

# Test: Shy SSH connection
if ($SSH_SHY_CNX) {
    print "***Test: Shy SSH connection\n";
    my $cnx_h = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
    warn "$!\n" unless $cnx_h;
    if (defined $cnx_h) {
        sleep 3;
        my $ssh_data = $ssh_listen->accept;
        print $cnx_h $test_data;
        my $data = <$ssh_data>;
        is($data, $test_data, "Shy SSH connection");
    }
}

# Test: Bold SSH connection
if ($SSH_BOLD_CNX) {
    print "***Test: Bold SSH connection\n";
    my $cnx_h = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
    warn "$!\n" unless $cnx_h;
    if (defined $cnx_h) {
        my $td = "SSH-2.0 testsuite\n$test_data";
        print $cnx_h $td;
        my $ssh_data = $ssh_listen->accept;
        my $data = <$ssh_data>;
        $data .= <$ssh_data>;
        is($data, $td, "Bold SSH connection");
    }
}

# Test: One SSL half-started then one SSH
if ($SSL_MIX_SSH) {
    print "***Test: One SSL half-started then one SSH\n";
    my $cnx_l = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
    warn "$!\n" unless $cnx_l;
    if (defined $cnx_l) {
        print $cnx_l $test_data;
        my $cnx_h= new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
        warn "$!\n" unless $cnx_h;
        if (defined $cnx_h) {
            sleep 3;
            my $ssh_data = $ssh_listen->accept;
            print $cnx_h $test_data;
            my $data_h = <$ssh_data>;
            is($data_h, $test_data, "SSH during SSL being established");
        }
        my $ssl_data = $ssl_listen->accept;
        my $data = <$ssl_data>;
        is($data, $test_data, "SSL connection interrupted by SSH");
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
            print $cnx_l $test_data;
            my $ssl_data = $ssl_listen->accept;
            my $data = <$ssl_data>;
            is($data, $test_data, "SSL during SSH being established");
        }
        my $ssh_data = $ssh_listen->accept;
        print $cnx_h $test_data;
        my $data = <$ssh_data>;
        is($data, $test_data, "SSH connection interrupted by SSL");
    }
}


# Test: Big messages
if ($BIG_MSG) {
    print "***Test: big message\n";
    my $cnx_l = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
    warn "$!\n" unless $cnx_l;
    my $test_data2 = "helloworld";
    my $rept = 10000;
    if (defined $cnx_l) {
        print $cnx_l ($test_data2 x $rept);
        print $cnx_l "\n";
        my $ssl_data = $ssl_listen->accept;
        my $data = <$ssl_data>;
        is($data, $test_data2 x $rept . "\n", "Big message");
    }
}

# Test: several connections active at once
# We start 50 SSH connexions, then open 50 SSL connexion, then accept the 50
# SSH connexions, then we randomize the order of connexions and write 1000
# messages on each connexion and check we get it on the other end.
if ($MANY_CNX) {
    print "***Test: several connexions active at once\n";
    my (@cnx_h, @ssh_data);
    for (1..$NUM_SSH_CNX) {
        my $cnx_h = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
        warn "----> $!\n" unless defined $cnx_h;
        if (defined $cnx_h) {
            push @cnx_h, $cnx_h;
        }
    }
    my (@cnx_l, @ssl_data);
    for (1..$NUM_SSL_CNX) {
        my $cnx_l = new IO::Socket::INET(PeerHost => "localhost:$sslh_port");
        warn "----> $!\n" unless defined $cnx_l;
        if (defined $cnx_l) {
            push @cnx_l, $cnx_l;
            print $cnx_l " ";
            push @ssl_data, ($ssl_listen->accept)[0];
        }
    }
    # give time to the connections to turn to SSH
    sleep 4; 
    # and accept all SSH connections...
    for (1..$NUM_SSH_CNX) {
        push @ssh_data, $ssh_listen->accept;
    }

# Make up a random order so we don't always hit the
# connexions in the same order

# fisher_yates_shuffle( \@array ) : generate a random permutation
# of @array in place (from
# http://docstore.mik.ua/orelly/perl/cookbook/ch04_18.htm,
# modified to shuffle two arrays in the same way)
    sub fisher_yates_shuffle {
        my ($array1, $array2) = @_;
        my $i;
        for ($i = @$array1; --$i; ) {
            my $j = int rand ($i+1);
            next if $i == $j;
            @$array1[$i,$j] = @$array1[$j,$i];
            @$array2[$i,$j] = @$array2[$j,$i];
        }
    }

    my @cnx = (@cnx_l, @cnx_l);
    my @rcv = (@ssl_data, @ssl_data);

    fisher_yates_shuffle(\@rcv, \@cnx); 

# Send a bunch of messages
    for my $cnt (1..1000) {
        foreach (@cnx) {
            print $_ "$cnt$test_data";
        }
        foreach (@rcv) {
            my $data = <$_>;
            like($data, qr/ ?$cnt$test_data/, "Multiple messages [$cnt]");
        }
    }
}



kill 15, `cat $pidfile` or warn "kill: $!\n";
