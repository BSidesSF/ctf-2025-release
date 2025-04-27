#!/usr/bin/env python3

from Crypto.Cipher import AES # pycryptodome

with open("flag.png", "rb") as flag:
    flag_bytes = flag.read()

K = bytes.fromhex("5f4dcc3b5aa765d61d8327deb882cf99")
aes = AES.new(K, AES.MODE_CBC)

if len(flag_bytes) % 16 != 0:
    flag_bytes += b'\x00' * (16 - (len(flag_bytes) % 16))

X = aes.encrypt(flag_bytes)

with open("flag.png.enc", "wb") as enc:
    enc.write(X)

