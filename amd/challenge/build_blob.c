#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/bn.h>

#define RSA_KEY_SIZE 256     // 2048 bits = 256 bytes
#define FIRMWARE_SIZE 1024   // 1KB firmware
#define SIGNATURE_SIZE 256   // RSA 2048-bit signature

void print_hex_blob(uint8_t *blob, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", blob[i]);
        if ((i + 1) % 32 == 0) printf("\n");
    }
    if (len % 32 != 0) printf("\n");
}

void print_rsa_public_key_openssl3(EVP_PKEY *pkey) {
    BIGNUM *n = NULL, *e = NULL;

    // Extract public key components from the provider-based EVP_PKEY
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) ||
        !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e)) {
        fprintf(stderr, "ERROR: Failed to extract RSA key parameters from EVP_PKEY\n");
        return;
    }

    fprintf(stderr, "RSA Public Key Components:\n");

    fprintf(stderr, "  Modulus (n): ");
    BN_print_fp(stderr, n);
    fprintf(stderr, "\n");

    fprintf(stderr, "  Exponent (e): ");
    BN_print_fp(stderr, e);
    fprintf(stderr, "\n");

    // Optional: also print in hex (with leading zeros preserved)
    int n_len = BN_num_bytes(n);
    int e_len = BN_num_bytes(e);
    uint8_t *n_buf = malloc(n_len);
    uint8_t *e_buf = malloc(e_len);
    BN_bn2bin(n, n_buf);
    BN_bn2bin(e, e_buf);

    fprintf(stderr, "  Modulus (hex): ");
    for (int i = 0; i < n_len; i++) fprintf(stderr, "%02x", n_buf[i]);
    fprintf(stderr, "\n");

    fprintf(stderr, "  Exponent (hex): ");
    for (int i = 0; i < e_len; i++) fprintf(stderr, "%02x", e_buf[i]);
    fprintf(stderr, "\n");

    free(n_buf);
    free(e_buf);
    BN_free(n);
    BN_free(e);
}


int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <rsa_private_key.pem> <firmware.bin>\n", argv[0]);
        return 1;
    }

    const char *key_path = argv[1];
    const char *firmware_path = argv[2];
    uint8_t blob[RSA_KEY_SIZE + FIRMWARE_SIZE + SIGNATURE_SIZE];

    uint8_t *rsa_mod = blob;
    uint8_t *firmware = blob + RSA_KEY_SIZE;
    uint8_t *signature = firmware + FIRMWARE_SIZE;

    // --- Load RSA Private Key (PEM) ---
    FILE *key_file = fopen(key_path, "r");
    if (!key_file) {
        perror("Error opening RSA key file");
        return 1;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (!pkey) {
        fprintf(stderr, "Error reading RSA private key\n");
        return 1;
    }

    print_rsa_public_key_openssl3(pkey);

    // --- Extract Modulus (n) from RSA Key ---
    BIGNUM *n = NULL;
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n)) {
        fprintf(stderr, "Error extracting RSA modulus\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    if (BN_bn2binpad(n, rsa_mod, RSA_KEY_SIZE) != RSA_KEY_SIZE) {
        fprintf(stderr, "Error serializing RSA modulus\n");
        BN_free(n);
        EVP_PKEY_free(pkey);
        return 1;
    }
    BN_free(n); // done with modulus

    // --- Read Firmware File ---
    FILE *fw_file = fopen(firmware_path, "rb");
    if (!fw_file) {
        perror("Error opening firmware file");
        EVP_PKEY_free(pkey);
        return 1;
    }

    size_t fw_read = fread(firmware, 1, FIRMWARE_SIZE, fw_file);
    fclose(fw_file);
    if (fw_read != FIRMWARE_SIZE) {
        fprintf(stderr, "Firmware must be exactly %d bytes (read %zu)\n", FIRMWARE_SIZE, fw_read);
        EVP_PKEY_free(pkey);
        return 1;
    }

    // --- Compute SHA-256 hash of firmware ---
    uint8_t digest[SHA256_DIGEST_LENGTH];
    if (!EVP_Digest(firmware, FIRMWARE_SIZE, digest, NULL, EVP_sha256(), NULL)) {
        fprintf(stderr, "SHA-256 failed\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    // --- Sign digest with RSA + SHA256 (PKCS#1 v1.5) ---
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx ||
        EVP_PKEY_sign_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        fprintf(stderr, "Error initializing RSA signature context\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    size_t sig_len = SIGNATURE_SIZE;
    if (EVP_PKEY_sign(ctx, signature, &sig_len, digest, sizeof(digest)) <= 0) {
        fprintf(stderr, "RSA signature failed\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    fprintf(stderr, "Final signature size: %zu\n", sig_len);

    // Verify signature
    EVP_PKEY_CTX *verify_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!verify_ctx ||
        EVP_PKEY_verify_init(verify_ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(verify_ctx, RSA_PKCS1_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(verify_ctx, EVP_sha256()) <= 0) {
        printf("ERROR: Signature verification context setup failed\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    fprintf(stderr, "INFO: will verify signature: ");
    for (int i = 0; i < RSA_KEY_SIZE; i++) fprintf(stderr, "%02x", signature[i]);
    printf("\n");

    int sig_result = EVP_PKEY_verify(verify_ctx, signature, RSA_KEY_SIZE, digest, 32);
    if (sig_result == 1) {
        fprintf(stderr, "SUCCESS: Firmware signature is VALID.\n");
    } else {
        fprintf(stderr, "ERROR: Invalid firmware signature (%d).\n", sig_result);
        EVP_PKEY_free(pkey);
        return 1;
    }

    EVP_PKEY_CTX_free(verify_ctx);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    // --- Output blob as hex (64 hex chars per line) ---
    print_hex_blob(blob, sizeof(blob));

    return 0;
}
