#!/usr/bin/python

import sys
import struct

with open(sys.argv[1], mode='rb') as file:
    r16data = file.read()

w, h = struct.unpack(r'>HH', r16data[:4])

print(f'Dimensions {w}x{h}\n')

with open(sys.argv[2], "wb") as outfile:
    outfile.write(bytes("P7\n", 'utf-8'))
    outfile.write(bytes(f"WIDTH {w}\n", 'utf-8'))
    outfile.write(bytes(f"HEIGHT {h}\n", 'utf-8'))
    outfile.write(bytes("DEPTH 4\n", 'utf-8'))
    outfile.write(bytes("MAXVAL 255\n", 'utf-8'))
    outfile.write(bytes("TUPLTYPE RGB_ALPHA\n", 'utf-8'))
    outfile.write(bytes("ENDHDR\n", 'utf-8'))

    for y in range(h):
        for x in range(w):
            i = 18 + (y * w + x) * 2

            rgba = struct.unpack("<H", r16data[i:i+2])[0]

            #print(f"Got RGBA value {rgba:02x} at [{x}, {y}] offset {i}")

            # r = ((rgba & 0xf800) >> 11) << 3
            # g = ((rgba & 0x07c0) >> 6) << 3
            # b = ((rgba & 0x003e) >> 1) << 3
            # a = (1 - (rgba & 0x0001)) * 255

            # r = ((rgba & 0x7c00) >> 10) << 3
            # g = ((rgba & 0x03e0) >> 5) << 3
            # b = ((rgba & 0x001f) >> 0) << 3
            # a = 255

            r = round(((rgba & 0x7c00) >> 10) * (255 / 31))
            g = round(((rgba & 0x03e0) >> 5) * (255 / 31))
            b = round(((rgba & 0x001f) >> 0) * (255 / 31))
            #a = (1 - ((rgba & 0x8000) >> 15)) * 255
            a = 255

            #print(f"R G B A {r} {g} {b} {a}")

            # if x < w - 1:
            #     print(f"{r} {g} {b} {a}", end=' ', file=outfile)
            # else:
            #     print(f"{r} {g} {b} {a}", end='\n', file=outfile)

            outfile.write(struct.pack("BBBB", r, g, b, a))
