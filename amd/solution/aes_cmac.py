#!/usr/bin/env python3

import multiprocessing
import sympy
import time

from Crypto.Cipher import AES


def factor(n, result_queue):
    #factors = sympy.factorint(n, limit=2**24)  # fast limit; adjust if needed
    factors = sympy.factorint(n, limit=None)
    result_queue.put(factors)


def timed_factor(n, timeout=60):
    result_queue = multiprocessing.Queue()
    proc = multiprocessing.Process(target=factor, args=(n, result_queue))
    proc.start()
    proc.join(timeout)
    if proc.is_alive():
        proc.terminate()
        proc.join()
        return None  # Timed out
    else:
        return result_queue.get()


def left_shift(block):
    """Left shifts a 16-byte block by 1 bit."""
    shifted = int.from_bytes(block, byteorder='big') << 1
    shifted &= (1 << 128) - 1  # Trim to 128 bits
    return shifted.to_bytes(16, byteorder='big')


def xor_bytes(a, b):
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


def generate_subkey(K):
    """Generate CMAC subkey K1."""
    const_Rb = 0x87
    aes = AES.new(K, AES.MODE_ECB)
    L = aes.encrypt(b'\x00' * 16)
    K1 = left_shift(L)
    if (L[0] & 0x80):
        K1 = bytearray(K1)
        K1[-1] ^= const_Rb
        K1 = bytes(K1)
    return K1


def aes_cmac(message, K):
    if len(message) % 16 != 0:
        raise ValueError("Message length must be a multiple of 16 bytes.")

    aes = AES.new(K, AES.MODE_ECB)
    K1 = generate_subkey(K)

    n = len(message) // 16
    last_block = xor_bytes(message[-16:], K1)

    X = b'\x00' * 16
    for i in range(n - 1):
        block = message[i * 16:(i + 1) * 16]
        X = aes.encrypt(xor_bytes(X, block))

    T = aes.encrypt(xor_bytes(X, last_block))
    return T


def break_aes_cmac(message, K, H):

    aes = AES.new(K, AES.MODE_ECB)
    K1 = generate_subkey(K)

    n = len(message) // 16
    last_block = xor_bytes(message[-16:], K1)

    # Compute MAC all the way up to the last two blocks
    X = b'\x00' * 16
    for i in range(n - 2):
        block = message[i * 16:(i + 1) * 16]
        X = aes.encrypt(xor_bytes(X, block))

    # run last block bacwards
    XL = xor_bytes(aes.decrypt(H), last_block)

    # Now aes(X xor M') must be XL so compute M'
    MP = xor_bytes(aes.decrypt(XL), X)

    return message[:len(message) - 32] + MP + message[-16:]


if __name__ == "__main__":
    # Example usage:
    K = bytes.fromhex("000102030405060708090a0b0c0d0e0f")  # 128-bit AES key
    H = bytes.fromhex("9ccc7c881faa8225ba686d772ac60dc3")  # goal CMAC
    data = bytes.fromhex('80' + '00' * 255)  # 256-byte message

    while True:

        new_data = break_aes_cmac(data, K, H)



        mac = aes_cmac(new_data, K)
        if mac == H:
            print(f"Trying to factor {new_data.hex()}")

            f = timed_factor(int.from_bytes(new_data), timeout=20)

            if not f is None:
                fcount = len(f.keys())
                print(f"Found {fcount} factors: {f}")

                if fcount == 2 and list(f.values()) == [1, 1] and not 2 in f:
                    break

        else:
            print(f"CMAC break failed: {mac.hex()} (goal was {H.hex()})")
            print(new_data.hex())

        i = int.from_bytes(data[-4:])
        i += 1
        data = data[:-4] + i.to_bytes(4, 'big')
