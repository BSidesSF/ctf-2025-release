#!/usr/bin/env python3

from PIL import Image
import sys

im_src_name = sys.argv[1]
im_flg_name = sys.argv[2]
im_res_name = sys.argv[3]

scale = 16 # Flag must be at least this many times smaller than src in height and width
offset = 8

print(f"Using image source {im_src_name} with flag {im_flg_name} and saving to {im_res_name}")


im_src = Image.open(im_src_name)
im_src_pdata = im_src.load()

im_flg = Image.open(im_flg_name)
im_flg_pdata = im_flg.load()

flg_w, flg_h = im_flg.size

for y in range(flg_h):
    for x in range(flg_w):
        im_src_pdata[x * scale + offset, y * scale + offset] = im_flg_pdata[x, y]

im_src.save(im_res_name)
