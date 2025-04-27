#!/usr/bin/env python3

import sys
import hashlib

# Found with aes_cmac.py
N = (1 << 2047) + (0xffbafc003cc2ef1acd2696de5debd9fd << 128) + 0x275
P = 89
Q = N // P
E = 65537
D = pow(E, -1, (P - 1) * (Q - 1))

if pow(pow(5 << 200, D, N), E, N) != 5 << 200:
    print("Invalid key!")
    exit(1)


def output_blob(blob):

    for i in range(0, len(blob), 32):
        print(blob[i:i+32].hex())

    print("END")


with open(sys.argv[1], 'rb') as scf:
    firmware = scf.read()

if len(firmware) > 1024:
    print("Firmware can not be longer than 1024 bytes")
    exit(1)

if len(firmware) < 1024:
    print(f"Got {len(firmware)} bytes, padding with nulls to 1024", file=sys.stderr);
    firmware = firmware + (b'\x00' * (1024 - len(firmware)))


firmware_hash = hashlib.sha256(firmware).digest()

print(f"Firmware SHA256: {firmware_hash.hex()}", file=sys.stderr)

hash_padding = bytes.fromhex("01" + "ff" * 202 + "003031300d060960864801650304020105000420")
padded_hash = hash_padding + firmware_hash

print("Signing padded hash", file=sys.stderr)

S = pow(int.from_bytes(padded_hash, 'big'), D, N)

blob = N.to_bytes(256, 'big') + firmware + S.to_bytes(256, 'big')

output_blob(blob)
