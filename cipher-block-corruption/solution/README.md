## `cipher-block-corruption` -- a simple CBC-without-IV decryption challenge

Players are given an encrypted PNG image of the flag and the python script showing how it was encrypted. Notably the AES key is embedded in the python script but the IV was not specified so the IV was chosen randomly by the encryption library (PyCryptodome).

The CBC mode of operation "recovers" from corrupted blocks. Since the IV isn't known the first block can't be decrypted properly but all subsequent blocks can be. Since the flag is a PNG which has a known header, the first block (16 bytes) can be restored trivially.

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

Note that because of padding there will be extra nulls at the end of the file which will be ignored by every PNG image library.

Flag is: CTF{is_my_flag_showing}
