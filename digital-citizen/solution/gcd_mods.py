#!/usr/bin/env python3

import sys
import re
import math

mod_re = re.compile(r'^\d+$')

mods = {}
with open(sys.argv[1]) as f:
    for modulus in f:
        modulus = modulus.rstrip("\n")

        m = re.match(mod_re, modulus)

        if m is None:
            print(f"Modulus input {modulus} is invalid")
            continue

        mint = int(modulus)

        if mint in mods:
            print(f"Duplicate modulus found: {mint}")
        else:
            mods[mint] = 0


mod_l = list(mods.keys())

primes = {}

# Do all-pairwise GCD. There is a more efficient
# algorithm for this (batch GCD)
for i in range(0, len(mod_l)):
    for j in range(i + 1, len(mod_l)):
        g = math.gcd(mod_l[i], mod_l[j])

        if g > 1:
            p1 = mod_l[i] // g
            p2 = mod_l[j] // g

            primes[p1] = primes.get(p1, 0) + 1
            primes[p2] = primes.get(p2, 0) + 1
            primes[g] = primes.get(g, 0) + 1

for p, c in sorted(primes.items(), key=lambda item: item[1], reverse=True):
    print(f"{c} {p :0512b}")
