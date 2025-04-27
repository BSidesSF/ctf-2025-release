#!/usr/bin/perl

use strict;
use warnings;

use Digest::MD5 qw(md5_hex);


sub state_to_img {
    my $tsec = shift;
    my $shex = shift;
    my $outfile = shift;

    my $IDIR = '/tmp';

    my $W = 1400;
    my $H = 1200;

    my $W_out = 1200;
    my $H_out = 800;

    my $xo = 576; # x offset into mask
    my $yo = 360;   # y offset into mask

    my $TW = 23; # Tile width
    my $TH = 64; # Tile height


    my $cmd = sprintf('magick -size %dx%d xc:black \\( %s/%s -repage +%d+%d \\)', $W, $H, '.', 'template.png', 0, 0);

    for (my $i = 0; $i < 16; $i++) {
        my $digfname = sprintf('digits/%s.png', substr($shex, $i, 1));

        my $tx = $xo + $i * $TW;
        my $ty = $yo;

        my $tile = sprintf(' \\( %s -repage +%d+%d \\)', $digfname, $tx, $ty);

        $cmd .= $tile;
    }

    my $tstr = sprintf("%d", $tsec);
    for (my $i = 0; $i < 10; $i++) {
        my $digfname = sprintf('digits/%s.png', substr($tstr, $i, 1));

        my $tx = $xo + ($i + 3) * $TW;
        my $ty = $yo + $TH + 3;

        my $tile = sprintf(' \\( %s -repage +%d+%d \\)', $digfname, $tx, $ty);

        $cmd .= $tile;
    }


    $cmd = $cmd . sprintf(' -layers flatten ');

    $cmd = $cmd . sprintf(' -virtual-pixel transparent -distort perspective "605,353 637,354  605,483 633,462  908,353 868,315  908,483 854,412"');


    $cmd = $cmd . sprintf(' -layers flatten -crop 1020x678+3+3\\! -resize %dx%d\\! jpeg:/tmp/%s', $W_out, $H_out, $outfile);




    my $ret = `$cmd`;
}


sub next_state {
    my $s = shift;

    my $ns = substr(md5_hex(pack('H*', $s)), 0, 16);

    return $ns;
}


sub gen_video_frames {

    my $t = 1999634432;
    my $s = 'ef2e0101b4ff85de';


    for (my $i = 0; $i < 60; $i++) {

        my $frame = sprintf('aclock_%05d.jpg', $i);
        state_to_img($t + $i, $s, $frame);

        $s = next_state($s);
    }

}

gen_video_frames();
