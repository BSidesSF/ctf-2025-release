#!/usr/bin/python

from PIL import Image
import sys
import struct

im = Image.open(sys.argv[1])

pdata = im.load()

w, h = im.size


i = 0
with open(sys.argv[2], "wb") as outfile:
    outfile.write(struct.pack('>HH', w, h))
    outfile.write(struct.pack('>HHH', 0, 256, 256))
    outfile.write(struct.pack('>HHHH', 0, 0, 0, 0))

    for y in range(h):
        for x in range(w):

            pl = pdata[x, y]

            r, g, b = pl[0], pl[1], pl[2]

            r5 = round(r * (31 / 255))
            g5 = round(g * (31 / 255))
            b5 = round(b * (31 / 255))

            rgb16 = (r5 << 10) | (g5 << 5) | b5

            outfile.write(struct.pack('<H', rgb16))
