#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/evp.h>

#define MAX_LINE_LEN 80

#define RSA_KEY_SIZE  2048 // bits
#define FIRMWARE_SIZE 8192 // bits

// AES CMAC KEY
// https://www.rfc-editor.org/rfc/rfc4493.html#appendix-A
uint8_t key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

// feca3c730601be7fd57f1f0b668b4637
uint8_t trusted_cmac[16] = {
    0xfe, 0xca, 0x3c, 0x73, 0x06, 0x01, 0xbe, 0x7f,
    0xd5, 0x7f, 0x1f, 0x0b, 0x66, 0x8b, 0x46, 0x37
};


int compute_rsa_key_aes_cmac(uint8_t *rsa_key, uint8_t *key_cmac) {

    // Assume rsa_key is exactly RSA_KEY_SIZE / 8 in length in bytes
    // Assume key_cmac is exactly 16 bytes (AES block size)

    // fill in:
    // Initialize AES CMAC with key from key[16] global var (use included openssl libcrypto)

    // fill in:
    // Compute AES CMAC of rsa_key (use included libcrypto)

}


int compute_firmware_cmac(uint8_t *firmware, uint8_t *firmware_cmac) {

    // Assume firmware is exactly FIRMWARE_SIZE / 8 in length in bytes
    // Assume firmware_cmac is exactly 16 bytes (AES block size)

    // fill in:
    // Initialize AES CMAC with key from key[16] global var (use included openssl libcrypto)

    // fill in:
    // Compute AES CMAC of firmware (use included libcrypto)

}





int main(void) {

    printf("Welcome to the Advanced-Machinecode-Defense (AMD) Firware Updater!\n");
    printf("Please enter firmware blob for update:\n");

    // Allocate stack memory to recieve the firmware
    // The RSA_KEY_SIZE is needed twice because the firmware
    // is laid out as RSA KEY + FIRMWARE + RSA SIGNATURE
    // and RSA signatures are the same size as the RSA key modulus
    uint8_t firmware[(RSA_KEY_SIZE + FIRMWARE_SIZE + RSA_KEY_SIZE) / 8]; // bytes

    int done = 0;
    int ln = 0; // line number
    int error = 0;
    while (done != 0) {
        ln++;

        char line[MAX_LINE_LEN + 1]; // Allow up to 80 chars of input per line + 1 null pad to terminate string
        int len;

        // fill in: fetch line of input from stdin making sure that it is 80 chars (MAX_LINE_LEN) or less

        // Remove possible trailing \n or \r
        for (int i = 0; i < MAX_LINE_LEN; i++) {
            if ((line[i] == '\r') || (line[i] == '\n') || (line[i] == '\0')) {
                line[i] = '\0';
                len = i;
                break;
            }
        }

        if (ln == 1) {
            if (strncmp(line, "BEGIN", MAX_LINE_LEN) != 0) {
                printf("ERROR: Firmware update must start with \"BEGIN\" on the first line.\n");
                error = 1;
                done = 1;
                break;
            }
            continue;
        }

        if (strncmp(line, "END", MAX_LINE_LEN) == 0) {
            // fill in: if full firmware hasn't been received then print error and break


            printf("INFO: \"END\" received, peforming checks.\n");
            done = 1;
            break;
        }

        // fill in: check that line length is even and made up of only lowercase hexidecimal characters

        // fill in: decode hexidecimal line byte-by-byte storing the decoding in firmware[]
        // If more firmware is recieved that will fit in the allocated memory then print
        // error and break.
    }

    if (error != 0) {
        return 1;
    }

    // Firmware recieved and decoded.

    uint8_t key_cmac[16];
    // fill in
    // call int compute_rsa_key_aes_cmac(uint8_t *rsa_key, uint8_t *key_cmac) with the first RSA_KEY_SIZE / 8 bytes
    // of the firmware buffer

    if (memcmp(key_cmac, trusted_cmac, 16) != 0) {
        printf("ERROR: AES CMAC of provided RSA key does not match trusted value\n");

        // fill in: print("INFO: computed AES CMAC of RSA KEY: ("); fill in print value

        // fill in: print("INFO: trusted AES CMAC of RSA KEY: ("); fill in print trusted_cmac

        return 1;
    }

    printf("INFO: Provided RSA key passes validation\n");

    uint8_t firmware_cmac[16];
    // fill in
    // compute firmware_cmac of the firmware portion of firmware[] which starts after the RSA key


    // Note that the RSA key provided is only the modulus. The public exponent of the key is hardcoded as 65537
    // It is enough to use the the modulus and public exponent to verify the signature

    // fill in using the firmware_cmac and the validated rsa key check that the RSA signature
    // which is stored in the last portion of firmware[] after the rsa key + firmware matches
    // the firmware_cmac we computed.


    return 0;
}
