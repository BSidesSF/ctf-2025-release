#!/usr/bin/env python3

from Crypto.Cipher import AES # pycryptodome

with open("flag.png.enc", "rb") as enc:
    enc_bytes = enc.read()

K = bytes.fromhex("5f4dcc3b5aa765d61d8327deb882cf99")
aes = AES.new(K, AES.MODE_CBC)

F = aes.decrypt(enc_bytes)

# We don't have the IV so the first block (16 bytes) will be
# corrupted but since this is a PNG we can predict exactly
# what those 16 bytes should be:
# 00000000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.PNG........IHDR|
HDR = b'\x89PNG\x0d\x0a\x1a\x0a\x00\x00\x00\x0dIHDR'

with open("dec_flag.png", "wb") as flag:
    flag.write(HDR + F[16:])
