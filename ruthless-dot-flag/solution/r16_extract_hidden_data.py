#!/usr/bin/python

import sys
import struct

with open(sys.argv[1], mode='rb') as file:
    r16data = file.read()

w, h = struct.unpack(r'>HH', r16data[:4])

print(f'Dimensions {w}x{h}\n')


def bits_to_bytes(bits):

    byte_l = []

    for n in range(0, len(bits) // 8):
        byte_num = 0
        for b in range(8):
            byte_num |= bits[(n * 8) + b] << (7 - b)

        byte_l.append(byte_num)

    return bytes(byte_l)


bits = []
for y in range(h):
    for x in range(w):
        i = 18 + (y * w + x) * 2

        rgba = struct.unpack("<H", r16data[i:i+2])[0]

        m = (rgba & 0x8000) >> 15

        bits.append(m)

#print(f"Got bits: {bits}")

with open(sys.argv[2], mode='wb') as outfile:
    outfile.write(bits_to_bytes(bits))

