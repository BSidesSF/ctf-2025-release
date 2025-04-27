#!/usr/bin/perl

use strict;
use warnings;


my $DOT_L = 31;

my $DOT_FNAME = 'yellow_dot.png';

my $PAD_L = 20;
my $IMG_W = 15 * $DOT_L + $PAD_L * 2;
my $IMG_H = 8 * $DOT_L + $PAD_L * 2;



my $char = ord('z');

my $ALL_LET = 'abCdeFghijklmnopqrsTuvwxyz{}f';
my $FLAG = 'CTF{plsverifynow}';

my $c = 1;
foreach my $l (split(//, $ALL_LET)) {

    my @cols;
    my $idx;

    $idx = index($FLAG, $l);

    if ($idx >= 0) {

        # Good card

        my $year = 96;
        my $month = 2;
        my $day = 27;

        my $hour = 6;
        my $min = 0;

        my $SN_1 = 37;
        my $SN_2 = 13;
        my $SN_3 = 3;
        my $SN_4 = 0;

        @cols = (0, $min + $idx, 0, 0, $hour, $day, $month, $year, 0, 127, $SN_1, $SN_2, $SN_3, $SN_4, ord($l));

        print sprintf('%02d-%d-%d at %02d:%02d -- Printer Serial %02d%02d%02d%02d -- Letter %02x (%03d; "%s") (REAL)',
                      $year, $month, $day, $hour, $min + $idx, $SN_4, $SN_3, $SN_2, $SN_1, ord($l), ord($l), $l), "\n";
    } else {
        $idx = index($ALL_LET, $l);

        my $year = 24;
        my $month = 6;
        my $day = 29;

        my $hour = 8;
        my $min = 17;

        my $SN_1 = 8;
        my $SN_2 = 50;
        my $SN_3 = 41;
        my $SN_4 = 46;

        @cols = (0, $min + $idx, 0, 0, $hour, $day, $month, $year, 0, 127, $SN_1, $SN_2, $SN_3, $SN_4, ord($l));

        print sprintf('%02d-%d-%d at %d:%d -- Printer Serial %02d%02d%02d%02d -- Letter %02x (%03d; "%s") (FAKE)',
                      $year, $month, $day, $hour, $min + $idx, $SN_4, $SN_3, $SN_2, $SN_1, ord($l), ord($l), $l), "\n";
    }


    # Fix column parity (must be odd)
    for (my $i = 1; $i < 15; $i++) {
        my $n = $cols[$i];

        my $p = parity_c($n);

        if ($p == 0) {
            $cols[$i] |= 128;
        }
    }

    # Fix row parity
    for (my $i = 0; $i < 7; $i++) {

        my $mask = 1 << $i;

        my $p = parity_r(\@cols, $i);

        if ($p == 0) {
            $cols[0] |= $mask;
        }
    }


    # Final top-left bit
    if (parity_c($cols[0]) != parity_r(\@cols, 128)) {
        $cols[0] |= 128;
    }


    print_dots(\@cols);

    output_dots_img(\@cols, sprintf('dot_imgs/raw_dot_grid_%02d_%s.png', $c, $l));

    $c++;
}

sub parity_c {
    my $n = shift;

    my $parity = 0;

    while ($n > 0) {
        if (($n & 1) == 1) {
            $parity ^= 1;
        }

        $n >>= 1;
    }

    return $parity;
}


sub parity_r {
    my $cref = shift;
    my $b = shift;

    my $mask = 1 << $b;

    my $parity = 0;

    foreach my $n (@{$cref}) {
        if (($n & $mask) > 0) {
            $parity ^= 1;
        }
    }

    return $parity;
}


sub print_dots {
    my $cref = shift;

    my $mask = 128;

    while ($mask > 0) {
        foreach my $c (@{$cref}) {
            if (($c & $mask) > 0) {
                print 'o';
            } else {
                print ' ';
            }
        }
        print "\n";

        $mask >>= 1;
    }
}


sub output_dots_img {
    my $cref = shift;
    my $outname = shift;


    my $cmd = sprintf('magick -size %dx%d xc:white', $IMG_W, $IMG_H);

    my $mask = 128;

    my $y = 0;
    while ($mask > 0) {
        my $x = 0;
        foreach my $c (@{$cref}) {
            if (($c & $mask) > 0) {

                my $ox = ($x * $DOT_L) + $PAD_L;
                my $oy = ($y * $DOT_L) + $PAD_L;

                $cmd .= sprintf(' \\( %s -background white -rotate %d -crop %dx%d -repage +%d+%d \\)', $DOT_FNAME, rand(360), $DOT_L, $DOT_L, $ox, $oy);

            }

            $x++;
        }

        $mask >>= 1;
        $y++;
    }

    $cmd .= sprintf(' -layers flatten -alpha off "png:%s"', $outname);

    my $ret = `$cmd`;
}
