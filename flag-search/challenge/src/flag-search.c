#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/evp.h>


uint8_t ctext[16] = {0xe3, 0xac, 0xb4, 0x23, 0x12, 0xea, 0x23, 0x5c,
                     0x1a, 0x18, 0xc5, 0x71, 0xb4, 0x1b, 0x1e, 0x7f};

uint8_t ukey[16];


// Function to count set bits in a 128-bit integer
int bit_count(__uint128_t x) {
    int count = 0;
    while (x) {
        count += x & 1;
        x >>= 1;
    }
    return count;
}


// Converts a hex character to a 4-bit value
int hex_to_nibble(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return 10 + (c - 'a');
    if ('A' <= c && c <= 'F') return 10 + (c - 'A');
    return -1;
}


// Reads big-endian 128-bit integer from hex string
bool read_hex_lsb_first(__uint128_t *out) {
    char input[33];
    if (scanf("%32s", input) != 1) return false;

    size_t len = strlen(input);
    if (len != 32) {
        printf("Input must be 32 hex characters (128 bits)\n");
        return false;
    }

    __uint128_t result = 0;
    for (int i = 31; i >= 0; i--) {
        int val = hex_to_nibble(input[31 - i]);
        if (val < 0) {
            printf("Invalid hex character: %c\n", input[i]);
            return false;
        }
        result |= ((__uint128_t)val) << (i * 4);  // LSB-first
    }

    *out = result;
    return true;
}


void check_failed(int i) {
    printf("Check on first %d bits failed!\n", i);
}


int main(void) {

    char line[4096];
    int banner_fd = open("banner.txt", O_RDONLY);
    ssize_t blen = read(banner_fd, line, 4096);
    write(1, line, blen);
    close(banner_fd);

    __uint128_t key;
    printf("Enter 128-bit key: ");
    if (!read_hex_lsb_first(&key)) return 1;

    printf("\nChecking key %016lx%016lx\n", (uint64_t)(key >> 64), (uint64_t)(key & 0xffffffffffffffff));

    for (int i = 0; i < 16; i++) {
        ukey[i] = (key >> ((15 - i) * 8)) & 0xff;
        //printf("%02x", ukey[i]);
    }
    //printf("\n");

    __uint128_t v = 0;
    __uint128_t p2 = 1;
    __uint128_t bc = (__uint128_t)1 << 127;
    printf("\n");
    for (int i = 0; i <= 128; i++) {

        //printf("i: %d; v: %016llx%016llx\n", i, (uint64_t)(v >> 64), (uint64_t)(v & 0xffffffffffffffff));

        switch(i) {
        case 4:
            if (v % 5 != 0) {
                check_failed(i);
                return 1;
            }
            break;

        case 12:
            if (v % 100 != 95) {
                check_failed(i);
                return 1;
            }
            break;

        case 16:
            if (bit_count(v) != 11) {
                check_failed(i);
                return 1;
            }
            break;

        case 18:
            if (bit_count(v * 1234) != 13) {
                check_failed(i);
                return 1;
            }
            break;

        case 21:
            if (v % 100 != 83) {
                check_failed(i);
                return 1;
            }
            break;

        case 28:
            if (v % 100 != 59) {
                check_failed(i);
                return 1;
            }
            break;

        case 36:
            if (bit_count(v) != 20) {
                check_failed(i);
                return 1;
            }
            break;

        case 38:
            if (v % 13 != 1) {
                check_failed(i);
                return 1;
            }
            break;

        case 44:
            if (v % 13 != 5) {
                check_failed(i);
                return 1;
            }
            break;

        case 56:
            if (v % 101 != 31) {
                check_failed(i);
                return 1;
            }
            break;

        case 58:
            if (bit_count(v) != 30) {
                check_failed(i);
                return 1;
            }
            break;

        case 60:
            if (v % 17 != 6) {
                check_failed(i);
                return 1;
            }
            break;

        case 64:
            if (v % 177 != 62) {
                check_failed(i);
                return 1;
            }
            break;

        case 68:
            if (bit_count(v) != 39) {
                check_failed(i);
                return 1;
            }
            break;

        case 74:
            if (bit_count(v * 5) != 40) {
                check_failed(i);
                return 1;
            }
            break;

        case 80:
            if (v % 13 != 5) {
                check_failed(i);
                return 1;
            }
            break;

        case 86:
            if (v % 12345 != 11160) {
                check_failed(i);
                return 1;
            }
            break;

        case 92:
            if (bit_count(v) != 53) {
                check_failed(i);
                return 1;
            }
            break;

        case 98:
            if (v % 17 != 7) {
                check_failed(i);
                return 1;
            }
            break;

        case 102:
            if (v % 19 != 4) {
                check_failed(i);
                return 1;
            }
            break;

        case 108:
            if (bit_count(v) != 61) {
                check_failed(i);
                return 1;
            }
            break;

        case 114:
            if (v % 11 != 10) {
                check_failed(i);
                return 1;
            }
            break;

        case 120:
            if (v % 41 != 14) {
                check_failed(i);
                return 1;
            }
            break;

        case 122:
            if (bit_count(v) != 67) {
                check_failed(i);
                return 1;
            }
            break;

        case 124:
            if (v % 13 != 2) {
                check_failed(i);
                return 1;
            }
            break;

        case 126:
            if (v % 17 != 16) {
                check_failed(i);
                return 1;
            }
            break;

        case 127:
            if (v % 101 != 41) {
                check_failed(i);
                return 1;
            }
            break;

        case 128:
            if (v % 1003 != 735) {
                check_failed(i);
                return 1;
            }
            break;


        }
        // Update value with next bit
        if ((key & bc) != 0) {
            v += p2;

        }
        p2 <<= 1;
        bc >>= 1;

    }

    char flag[17];
    int outlen = 0, tmplen = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        fprintf(stderr, "Error creating EVP_CIPHER_CTX\n");
        return 1;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, ukey, NULL)) {
        fprintf(stderr, "DecryptInit failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    // Disable padding (single AES block)
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (!EVP_DecryptUpdate(ctx, (unsigned char *)flag, &outlen, ctext, 16)) {
        fprintf(stderr, "DecryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    if (!EVP_DecryptFinal_ex(ctx, (unsigned char *)flag + outlen, &tmplen)) {
        fprintf(stderr, "DecryptFinal failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    outlen += tmplen;
    flag[16] = '\0';

    printf("Decrypted flag: %s\n", flag);



    return 0;
}
