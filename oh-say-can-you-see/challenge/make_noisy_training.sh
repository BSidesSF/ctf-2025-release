#!/bin/bash

mkdir -p data/pirate
mkdir -p data/italy
mkdir -p data/ctf
mkdir -p data/us

for I in `seq 0 512`; do
    magick \( pirate_flag.png -attenuate 50.0 +noise Uniform \) -flatten -colorspace gray data/pirate/img_${I}.png;
    magick \( italy_flag.png -attenuate 50.0 +noise Uniform \) -flatten -colorspace gray data/italy/img_${I}.png;
    magick \( true_flag.png -attenuate 50.0 +noise Uniform \) -flatten -colorspace gray data/ctf/img_${I}.png;
    magick \( us_flag.png -attenuate 50.0 +noise Uniform \) -flatten -colorspace gray data/us/img_${I}.png;
done
