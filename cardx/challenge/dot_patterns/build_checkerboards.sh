#!/bin/bash

ls -1 dot_imgs/raw_dot_*.png | while read LINE; do magick -size 1010x576 xc:white \( $LINE -repage +0+0 \) \( $LINE -repage +505+288 \) -layers flatten -alpha off png:$(echo $LINE | sed -r 's/raw_/checker_/'); done

