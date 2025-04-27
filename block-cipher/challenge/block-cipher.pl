#!/usr/bin/perl

use strict;
use warnings;

use MIME::Base64;

#use bignum upgrade => undef; # Keep things as integers

# aaabbbcccddd eeefffggghhh iiijjjkkklll mmmnnnoooppp

my $DEBUG = 0;

my $W = 400;
my $H = 400;
my $PAD_W = -10;
my $PAD_H = -10;
my $SM_W = 195;
my $SM_H = 195;
my $OUT_W = 1500; # Everything scaled to this

my $IDIR = './imgs';

my $SNAME = 'symmetric\'s truly horrible perl hack to approximate a webserver';

my $HTML_START = << 'ENDHTMLSTART';
<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="content-type" content="text/html; charset=UTF-8">
    <title>block-cipher</title>
    <style type="text/css">
      div {
          padding-top: 16px;
          padding-right: 16px;
          padding-bottom: 16px;
          padding-left: 16px;
      }
      .container {
          align:center;
      }
      .block-cipher {
          float:center;
          text-align:center;
      }
      .form {
          color: white;
          font-size: 16pt;
      }
      .back {
          background-image: repeating-linear-gradient(rgba(25, 25, 25, 1), rgba(50, 50, 50), rgba(25, 25, 25, 1));
      }
      img {
          max-width:1200px;
          border: 5px solid #323232;
      }
    </style>
  </head>
  <body class="back">
    <div class="form">
         <form method="get" action="/">
               <p>Key:<br /><input type="text" name="key" value="%s" size="8" maxlength="8" /></p>
               <p>Words:<br /><input type="text" name="words" value="%s" size="100" autofocus /></p>
               <p><input type="submit" name="click" value="Encrypt" /></p>
        </form>
    </div>
    <div class="container">
ENDHTMLSTART
;

my $HTML_END = << 'ENDHTMLEND';
    </div>
  </body>
</html>
ENDHTMLEND
;


#alarm 5;


my $lc = 0;
my $got_get = 0;
my $error = 0;
my $hc = 0;

my $words = '';
my $key = '';

while (<STDIN>) {
    $lc++;

    my $line = $_;

    $line =~ s/[\n\r]*$//g;

    if ($DEBUG == 1) {
        warn 'input line #', $lc, ': ', $line, "\n";
    }

    if ($lc == 1) {

        if ($line =~ m/\/favicon\.ico/) {
            $hc = 1;
            next;
        }

        #warn 'line 1', "\n";
        #warn $line, "\n";
        if ($line =~ m/^GET\s\/\?(.*?)\sHTTP\/1\.[01]\s*$/) {
            my $uri = $1;

            if ($DEBUG == 1) {
                warn 'Request: ', $uri, "\n";
            }

            # fix spaces
            $uri =~ s/(?:%20|\+)/ /g;

            $got_get = 1;

            if ($uri =~ m/key=([1-4]+)/) {
                $key = $1
            } else {
                if ($DEBUG == 1) {

                    warn 'Did not get key in URI', "\n";
                }

                $got_get = 0;
            }

            if ($uri =~ m/words=([a-z ]+)/) {
                $words = $1
            } else {
                if ($DEBUG == 1) {

                    warn 'Did not get words in URI', "\n";
                }

                $got_get = 0;
            }

            #warn 'got get with key ', $key, ' and msg ', $msg, "\n";
        }
    } else {
        if ($line =~ m/^User-Agent: .*GoogleHC.*$/) {
            $hc = 1;
        }
        last if ($line =~ m/^[\r\n]*$/);
    }
}

if ($hc == 1) {
  print "HTTP/1.0 200 OK\r\n";
  print "\r\n";
  exit 0;
}


if ($got_get !=  1) {

    if ($DEBUG == 1) {

        warn 'Did not get valid GET', "\n";
    }

    $error = 1;
}

my @key_l = map {int($_) - 1} split(//, $key);

my @nums_ll = words_to_numlists($words);

my $img_bytes = '';
if (scalar @nums_ll < 1) {

    if ($DEBUG == 1) {
        warn 'Could not parse at least one word', "\n";
    }
    $error = 1;

} else {

    $img_bytes = nums_ll_to_img(\@nums_ll);
}


if ($error == 1) {
    if ($DEBUG == 1) {
        warn 'Error, redirecting', "\n";
    }
    print 'HTTP/1.0 303 See Other', "\r\n";
    print "Server: ", $SNAME, "\r\n";
    print 'Location: /?key=1234&words=example%20message', "\r\n";
    print "\r\n";

    exit 0;
}

my $html = sprintf($HTML_START, $key, $words);

$html .= "\n" . img_to_html($img_bytes) . "\n";

$html .= $HTML_END;

print 'HTTP/1.0 200 OK', "\r\n";
print 'Server: ', $SNAME, "\r\n";
print sprintf('Content-Length: %d', length($html)), "\r\n";
print 'Content-Type: text/html', "\r\n";
print "\r\n";
print $html;


sub nums_ll_to_img {
    my $nums_ll_ref = shift;

    my @nums_ll = @{$nums_ll_ref};

    my $MAX_ROW = scalar(@nums_ll);
    my $MAX_COL = 0;
    for (my $ROW = 0; $ROW < scalar(@nums_ll); $ROW++) {
        if (scalar(@{$nums_ll[$ROW]}) > $MAX_COL) {
            $MAX_COL = scalar(@{$nums_ll[$ROW]});
        }
    }

    my $cmd = sprintf('convert -size %dx%d xc:white -set colorspace Grey', $W * $MAX_COL + ($PAD_W * ($MAX_COL - 1)), $H * $MAX_ROW + ($PAD_H * ($MAX_ROW - 1)));

    my $key_idx = 0;
    for (my $ROW = 0; $ROW < scalar(@nums_ll); $ROW++) {
        for (my $COL = 0; $COL < scalar(@{$nums_ll[$ROW]}); $COL++) {

            my @blocks = num_to_blocks($nums_ll[$ROW][$COL]);

            if ($DEBUG == 1) {
                warn 'Encoding blocks (', join(', ', @blocks), ') into image block', "\n";
            }

            # Block format (5, 5, 7, 4, 4, 2, 4);
            #               a, b, c, ar, br, cr, allr

            my ($b_a, $b_b, $b_c, $b_ar, $b_br, $b_cr, $b_allr) = @blocks;

            # Start a whole square
            $cmd .= ' \\( \\(';

            my ($ox, $oy) = (($COL * ($W + $PAD_W)), $ROW * ($H + $PAD_H));

            my ($rfile, $bx, $by, $br);

            # block a
            $rfile = sprintf('%s/a_%d.png', $IDIR, $b_a);

            $br = $b_ar * 90;

            if (($key_l[$key_idx] & 2) != 0) {
                $bx = ($ox + ($W / 2)) - $SM_W;
            } else {
                $bx = $ox + ($W / 2);
            }

            if (($key_l[$key_idx] & 1) != 0) {
                $by = $oy + ($H / 2);
            } else {
                $by = ($oy + ($H / 2)) - $SM_H;
            }

            $cmd .= sprintf(' \\( %s -rotate %d -crop %dx%d -repage +%d+%d -compose Multiply \\)', $rfile, $br, $SM_W, $SM_H, $bx, $by);

            # block b
            $rfile = sprintf('%s/b_%d.png', $IDIR, $b_b);

            $br = $b_br * 90;

            if (($key_l[$key_idx] & 2) != 0) {
                $bx = ($ox + ($W / 2)) - $SM_W;
            } else {
                $bx = $ox + ($W / 2);
            }

            if (($key_l[$key_idx] & 1) != 0) {
                $by = ($oy + ($H / 2)) - $SM_H;
            } else {
                $by = $oy + ($H / 2);
            }

            $cmd .= sprintf(' \\( %s -rotate %d -crop %dx%d -repage +%d+%d -compose Multiply \\)', $rfile, $br, $SM_W, $SM_H, $bx, $by);

            # block c
            $rfile = sprintf('%s/c_%d.png', $IDIR, $b_c);

            $br = $b_cr * 180;

            my $flop = '';
            if (($key_l[$key_idx] & 2) != 0) {
                $bx = $ox + ($W / 2);
                $flop = ' -flop';
            } else {
                $bx = ($ox + ($W / 2)) - $SM_W;
            }

            $by = ($oy + ($H / 2)) - $SM_H;

            $cmd .= sprintf(' \\( %s -rotate %d -crop %dx%d -repage +%d+%d -compose Multiply \\)', $rfile, $br, $SM_W, 2 * $SM_H, $bx, $by);

            # border and final rotation

            $rfile = sprintf('%s/border.png', $IDIR);


            $br = $b_allr * 90;
            $bx = $ox;
            $by = $oy;
            $cmd .= sprintf(' \\( %s%s -repage +%d+%d -compose Multiply \\) \\) -layers merge +repage -rotate %d -repage +%d+%d', $rfile, $flop, $bx, $by, $br, $ox, $oy);
            $cmd .= ' \\)';

            $key_idx++;
            $key_idx %= scalar(@key_l);
        } # COL
    } # ROW

    $cmd .= ' -layers flatten -alpha off -define png:compression-filter=1 -define png:compression-level=9 png:-';

    if ($DEBUG == 1) {
        warn $cmd, "\n";
    }

    return `$cmd`;
}


sub img_to_html {
    my $img = shift;

    my $html = sprintf('<div class="block-cipher"><p><img src="data:image/png;base64,%s" alt="" /></p></div>', "\n" . encode_base64($img));

    return $html;
}


sub words_to_numlists {
    my $words = shift;

    my @nums_ll = ();

    my @words = split(/\s+/, $words);

    if (scalar(@words) > 10) {
        if ($DEBUG == 1) {
            warn 'too many words', "\n";
        }
        $error = 1;
        return;
    }

    foreach my $word (split(/\s+/, $words)) {
        push @nums_ll, word_to_numlist($word);
    }

    return @nums_ll;
}


sub word_to_numlist {
    my $word = shift;

    if (length($word) > 30) {
        if ($DEBUG == 1) {
            warn 'Word too long', "\n";
        }
        $error = 1;
        return;
    }

    if (length($word) % 3 != 0) {
        # Pad word to multiple of 3
        $word .= '.' x (3 - (length($word) % 3));
    }

    my @nums = ();

    for (my $i = 0; $i < length($word); $i += 3) {
        push @nums, trip_to_num(substr($word, $i, 3));
    }

    if ($DEBUG == 1) {
        warn 'Nums for word ', $word, ': (', join(', ', @nums), ')', "\n";
    }

    return \@nums;
}


sub trip_to_num {
    my $trip = shift;

    my $n = 0;
    $n += let_to_num(substr($trip, 0, 1));
    $n += let_to_num(substr($trip, 1, 1)) * 27;
    $n += let_to_num(substr($trip, 2, 1)) * 27 * 27;

    if ($DEBUG == 1) {
        warn 'Got ', $n, ' for trip ', $trip, "\n";
    }

    return $n;
}


sub let_to_num {
    my $l = shift;

    if ($l =~ m/^[a-z]$/) {
        return (ord($l) - ord('a')) + 1;
    } else {
        return 0;
    }
}


sub num_to_blocks {
    my $n = shift;

    my @radix = (5, 5, 7, 4, 4, 2, 4);

    my @blocks = ();

    foreach my $r (@radix) {
        my $d = $n % $r;

        push @blocks, $d;

        $n = int(($n - $d) / $r);
    }

    return @blocks;
}
