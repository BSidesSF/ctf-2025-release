# subprime

This challenge focuses on the weaknesses of RSA if the initial prime numbers
chosen are too small.

## Solution

1. Players receive a ciphertext of an array of integers along with a public key
pair with the public exponent (e) and the modulus (n).
2. If the initial prime numbers used, say p and q are small enough, a computer
can easily derive them from the modulus (n) through prime factorization.
3. After that it's simply a matter of retracing the steps of the RSA algorithm
until each number in the ciphertext array is decoded.
4. Looking at the range of decoded numbers, it's clear that they're ASCII
encoded.

Received n = 98563159, e = 1009

Attempting to find prime factors p and q from n...

Found primes: p = 9883, q = 9973

Calculated phi(n) = 98543304

Verified: gcd(e, phi) = gcd(1009, 98543304) = 1

Calculating private exponent d...

--- RSA Key Information ---

Smaller prime p: 9883

Larger prime q:  9973

Modulus n:       98563159

Phi(n):          98543304

Public Key (e, n):  (1009, 98563159)

Private Key (d, n): (31545577, 98563159)

Received ciphertext to decode: [23637004, 83925846, 2209113, 27583995, 30323096, 31771886, 30323096, 75901128, 31771886, 53482472, 97809030, 69683388, 68450410, 39905961, 75846723, 75901128, 53482472, 56293282, 69683388, 68450410, 63432789, 9450820, 81966837]

Decoding using Private Key (d=31545577, n=98563159)...

--- Decryption Result ---

Decoded message (numeric): [67, 84, 70, 123, 110, 48, 110, 95, 48, 112, 116, 33, 109, 64, 108, 95, 112, 82, 33, 109, 51, 36, 125]

Plaintext: CTF{n0n_0pt!m@l_pR!m3$}

## Resources

There are several online tools available for this kind of operation as long as
the participant knows what they're looking for. For example,
[BabyRSA](https://github.com/mrdebator/BabyRSA).
