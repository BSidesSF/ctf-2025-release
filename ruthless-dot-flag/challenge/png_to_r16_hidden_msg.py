#!/usr/bin/python

from PIL import Image
import sys
import struct

im = Image.open(sys.argv[1])

pdata = im.load()

w, h = im.size


def msg_to_bits(msg):

    bits = []

    for b in msg:
        for i in range(7, -1, -1):
            bits.append(((1 << i) & b) >> i)

    return bits


with open(sys.argv[2], mode='rb') as msgfile:
    msgdata = msgfile.read()


bits = msg_to_bits(msgdata)

print(f"bit string for msg is {bits}")

i = 0
with open(sys.argv[3], "wb") as outfile:
    outfile.write(struct.pack('>HH', w, h))
    outfile.write(struct.pack('>HHH', 0, 256, 256))
    outfile.write(struct.pack('>HHHH', 0, 0, 0, 0))

    for y in range(h):
        for x in range(w):

            if i < len(bits):
                m = bits[i]
                #m = 0
            else:
                m = 0

            i += 1


            pl = pdata[x, y]

            r, g, b = pl[0], pl[1], pl[2]

            r5 = round(r * (31 / 255))
            g5 = round(g * (31 / 255))
            b5 = round(b * (31 / 255))

            rgb16 = (m << 15) | (r5 << 10) | (g5 << 5) | b5

            outfile.write(struct.pack('<H', rgb16))
