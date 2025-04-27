#!/usr/bin/env python

import sys
import hashlib

# Use faster code like md5_brent.c to find
# a recent state that you can
# quickly fast-forward
known_t = 1742837767
known_cstate = bytes.fromhex("cc9ef28a7f481569")

def md5_trunc(input_bytes: bytes) -> bytes:
    if len(input_bytes) != 8:
        raise ValueError("Input must be exactly 8 bytes (64 bits).")

    # Compute MD5 hash
    md5_hash = hashlib.md5(input_bytes).digest()

    # Return the first 8 bytes (64 bits)
    return md5_hash[:8]


cstate = known_cstate
for i in range(int(sys.argv[1]) - known_t):
    cstate = md5_trunc(cstate)

print(cstate.hex())
