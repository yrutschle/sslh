#! /usr/bin/perl

# Creates a script of random accesses and deletes

use strict;


my $i = 0;
sub mkstr {
    $i++;
    return chr(ord('a') + ($i / 26) % 26) . chr(ord('a') + $i % 26);
}

my @elems;


sub add_elem {
    my $val = int(rand(32));
    my $str = mkstr($val);
    push @elems, "$val $str";
    print "a $val $str\n";
}

sub del_elem {
    my $remove = splice(@elems, rand @elems, 1);
    print "d $remove\n";
}

while (1) {
    if (@elems < 5) {
        add_elem;
    } elsif (@elems > 28) {
        del_elem;
    } else {
        if (rand() < .5) {
            add_elem;
        } else {
            del_elem;
        }
    }
}
