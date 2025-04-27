#!/usr/bin/env python3


def block_to_n(bl):

    radix = (5, 5, 7, 4, 4, 2, 4)

    n = 0

    for i in range(len(radix) - 1, -1, -1):
        n *= radix[i]
        n += bl[i]

    return n


def num_to_let(num):

    if num == 0:
        return ''

    return chr(ord('a') + (num - 1))


def n_to_trip(n):

    l1num = n % 27
    n //= 27
    l2num = n % 27
    n //= 27
    l3num = n

    return num_to_let(l1num) + num_to_let(l2num) + num_to_let(l3num)


def decode_word(bll):

    word = ''
    for bl in bll:
        n = block_to_n(bl)
        #print(f"Got {n} for {bl}")
        word += n_to_trip(n)

    return word


w1_bll = [(4, 3, 4, 3, 2, 0, 0),
          (2, 0, 6, 3, 2, 0, 2),
          (4, 1, 1, 3, 2, 1, 1),
          (2, 0, 2, 1, 1, 1, 0),
          (3, 1, 3, 2, 0, 1, 2)]
w1 = decode_word(w1_bll)

w2_bll = [(2, 4, 3, 2, 1, 0, 2),
          (1, 2, 4, 3, 1, 1, 0),
          (2, 3, 3, 3, 2, 0, 2),
          (2, 2, 6, 1, 1, 1, 2),
          (0, 4, 4, 0, 3, 1, 1)]
w2 = decode_word(w2_bll)

w3_bll = [(2, 1, 4, 0, 0, 1, 2),
          (4, 2, 4, 0, 3, 1, 1),
          (2, 0, 4, 2, 3, 1, 0),
          (1, 2, 0, 3, 1, 0, 0),
          (0, 1, 6, 0, 0, 0, 0)]
w3 = decode_word(w3_bll)

w4_bll = [(0, 2, 0, 3, 1, 0, 0),
          (4, 0, 1, 1, 2, 1, 1),
          (0, 3, 2, 3, 1, 0, 0),
          (3, 4, 6, 3, 3, 1, 1),
          (4, 2, 1, 2, 0, 1, 1)]
w4 = decode_word(w4_bll)

w5_bll = [(4, 4, 1, 3, 3, 1, 1),
          (3, 4, 2, 0, 2, 1, 2),
          (4, 0, 5, 0, 1, 0, 0),
          (3, 4, 6, 3, 3, 1, 1),
          (4, 2, 0, 0, 0, 0, 0)]
w5 = decode_word(w5_bll)


print(f"CTF{{{w1}_{w2}_{w3}_{w4}_{w5}}}")
