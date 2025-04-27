#!/usr/bin/env python3

import sympy



def all_pat_len(n):

    def pat_rec(d, l):
        nonlocal pats

        if d == n:
            pats.append(l)
            return

        pat_rec(d + 1, l + [0])
        pat_rec(d + 1, l + [1])

    pats = []
    pat_rec(0, [])

    return pats


def full_pat(pat):

    r = []
    for i in range(0, 512):
        r.append(pat[i % len(pat)])

    return r


def swap_shorts(r):

    for i in range(0, 512 // 32):
        r[(i * 32):(i * 32) + 16], r[(i * 32) + 16:(i * 32) + 32] = r[(i * 32) + 16:(i * 32) + 32], r[(i * 32):(i * 32) + 16]

    return r


def bit_list_to_int(r):

    n = 0
    p2 = 2 ** 511

    for i in r:
        if i == 1:
            n += p2

        p2 //= 2

    return n


def first_prime(n):

    while not sympy.ntheory.primetest.isprime(n):
        n += 1

    return n


def prime_from_pat(pat):

    r = full_pat(pat)
    r = swap_shorts(r)

    # Set top 2 bits
    r[0], r[1] = 1, 1

    # Clear bottom 16 bits
    for i in range(512 - 16, 512):
        r[i] = 0

    n = bit_list_to_int(r)

    p = first_prime(n)

    return p


primes = {}
for plen in [1, 3, 5, 7, 9]:
    for pat in all_pat_len(plen):
        p = prime_from_pat(pat)

        primes[p] = 0
        #print(f"p: {p :0512b}")

for p in primes.keys():
    print(p)
