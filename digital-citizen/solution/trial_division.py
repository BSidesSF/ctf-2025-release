#!/usr/bin/env python3

import sys

m = int(sys.argv[2], 16)

with open(sys.argv[1]) as f:
    for p in f:
        p = p.rstrip("\n")

        p = int(p)

        if m % p == 0:
            print(f"Factored {m} into {p} and {m // p}")
            print(f"p bits: {p :0512b}")
            print(f"q bits: {m // p :0512b}")

