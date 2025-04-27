#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/resource.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/param_build.h>


// ----- Configuration -----
#define RSA_KEY_SIZE  256  // 2048 bits
#define FIRMWARE_SIZE 1024 // bytes

// 9ccc7c881faa8225ba686d772ac60dc3
const uint8_t trusted_cmac[16] = {
    0x9c, 0xcc, 0x7c, 0x88, 0x1f, 0xaa, 0x82, 0x25,
    0xba, 0x68, 0x6d, 0x77, 0x2a, 0xc6, 0x0d, 0xc3
};

const uint8_t aes_key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

// ----- Modern CMAC using EVP_MAC -----
int compute_rsa_key_aes_cmac(uint8_t *rsa_key, uint8_t *key_cmac) {
    int ret = 0;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (!mac) goto cleanup;

    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) goto cleanup;

    params[0] = OSSL_PARAM_construct_utf8_string("cipher", "AES-128-CBC", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_init(ctx, aes_key, sizeof(aes_key), params)) goto cleanup;
    if (!EVP_MAC_update(ctx, rsa_key, RSA_KEY_SIZE)) goto cleanup;
    size_t outlen = 0;
    if (!EVP_MAC_final(ctx, key_cmac, &outlen, 16)) goto cleanup;

    ret = 1; // success

cleanup:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ret;
}

// ----- SHA-256 Digest -----
int compute_firmware_sha256(uint8_t *firmware, size_t len, uint8_t *digest_out) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return 0;

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) return 0;
    if (EVP_DigestUpdate(mdctx, firmware, len) != 1) return 0;
    if (EVP_DigestFinal_ex(mdctx, digest_out, NULL) != 1) return 0;

    EVP_MD_CTX_free(mdctx);
    return 1;
}

// ----- RSA Public Key from modulus using EVP_PKEY_fromdata -----
EVP_PKEY *load_rsa_pubkey_from_modulus(const uint8_t *modulus_bin, size_t modulus_len) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;

    // Build BIGNUMs for modulus and exponent
    BIGNUM *n = BN_bin2bn(modulus_bin, modulus_len, NULL);
    BIGNUM *e = BN_new();
    BN_set_word(e, 65537);

    // Create the param builder
    bld = OSSL_PARAM_BLD_new();
    if (!bld) goto cleanup;

    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e)) {
        fprintf(stderr, "Failed to push BIGNUMs into param builder\n");
        goto cleanup;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params) goto cleanup;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) goto cleanup;

    if (EVP_PKEY_fromdata_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

cleanup:
    BN_free(n);
    BN_free(e);
    OSSL_PARAM_BLD_free(bld);
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}



void print_rsa_public_key_openssl3(EVP_PKEY *pkey) {
    BIGNUM *n = NULL;

    // Extract public key components from the provider-based EVP_PKEY
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n)) {
        fprintf(stderr, "ERROR: Failed to extract RSA key parameters from EVP_PKEY\n");
        return;
    }

    int n_len = BN_num_bytes(n);
    uint8_t *n_buf = malloc(n_len);
    BN_bn2bin(n, n_buf);

    fprintf(stderr, "INFO: Modulus: ");
    for (int i = 0; i < n_len; i++) fprintf(stderr, "%02x", n_buf[i]);
    fprintf(stderr, "\n");

    free(n_buf);
    BN_free(n);
}


void handle_alarm(int sig) {
    (void)sig;
    fprintf(stderr, "ERROR: Hardware watchdog triggered.\n");
    exit(1);
}


void cpu_time_handler(int sig) {
    (void)sig;
    fprintf(stderr, "ERROR: CPU time limit exceeded — exiting.\n");
    exit(1);
}


// ----- Main -----
int main() {

    // Register the signal handler
    signal(SIGALRM, handle_alarm);

    // Set up SIGXCPU signal handler
    struct sigaction sa;
    sa.sa_handler = cpu_time_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGXCPU, &sa, NULL);

    // Set RLIMIT_CPU to 5 seconds
    struct rlimit rl;
    rl.rlim_cur = 5;  // Soft limit
    rl.rlim_max = 6;  // Hard limit (can go slightly over before forced kill)
    if (setrlimit(RLIMIT_CPU, &rl) != 0) {
        perror("setrlimit");
        return 1;
    }

    uint8_t firmware_blob[RSA_KEY_SIZE + FIRMWARE_SIZE + RSA_KEY_SIZE];
    int offset = 0;
    char line[4096];

    int banner_fd = open("banner.txt", O_RDONLY);
    ssize_t blen = read(banner_fd, line, 4096);
    write(1, line, blen);

    printf("Welcome to the Advanced Machinecode Defense update utility!\n");
    printf("Enter hex lines of firmware blob. Type 'END' when finished:\n");

    while (fgets(line, sizeof(line), stdin)) {
        if (strncmp(line, "END", 3) == 0) break;

        int len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = 0;

        if (len % 2 != 0) {
            printf("ERROR: Hex input length must be even.\n");
            return 1;
        }

        for (int i = 0; i < len; i++) {
            if (!isxdigit(line[i])) {
                printf("ERROR: Invalid hex character.\n");
                return 1;
            }
        }

        for (int i = 0; i < len; i += 2) {
            if (offset >= RSA_KEY_SIZE + FIRMWARE_SIZE + RSA_KEY_SIZE) {
                printf("ERROR: Firmware blob exceeds max size.\n");
                return 1;
            }
            char byte_str[3] = { line[i], line[i+1], 0 };
            firmware_blob[offset++] = (uint8_t)strtol(byte_str, NULL, 16);
        }
    }

    int expected_size = (RSA_KEY_SIZE + FIRMWARE_SIZE + RSA_KEY_SIZE);
    if (offset != expected_size) {
        printf("ERROR: Expected %d bytes, got %d.\n", expected_size, offset);
        return 1;
    }

    uint8_t *rsa_mod = firmware_blob;
    uint8_t *firmware = firmware_blob + RSA_KEY_SIZE;
    uint8_t *signature = firmware + FIRMWARE_SIZE;

    // Validate RSA key using AES CMAC
    uint8_t cmac[16];
    if (!compute_rsa_key_aes_cmac(rsa_mod, cmac)) {
        printf("ERROR: Failed to compute RSA key CMAC\n");
        return 1;
    }

    printf("INFO: Computed RSA key CMAC: ");
    for (int i = 0; i < 16; i++) printf("%02x", cmac[i]);
    printf("\n");
    printf("INFO: Trusted CMAC: ");
    for (int i = 0; i < 16; i++) printf("%02x", trusted_cmac[i]);
    printf("\n");

    if (memcmp(cmac, trusted_cmac, 16) != 0) {
        printf("ERROR: RSA key CMAC mismatch!\n");
        return 1;
    }

    printf("INFO: RSA key is trusted.\n");

    // Hash firmware with SHA-256
    uint8_t firmware_digest[32];
    if (!compute_firmware_sha256(firmware, FIRMWARE_SIZE, firmware_digest)) {
        printf("ERROR: SHA-256 hash failed\n");
        return 1;
    }

    printf("INFO: SHA256 of firmware: ");
    for (int i = 0; i < 32; i++) printf("%02x", firmware_digest[i]);
    printf("\n");

    // Load public key from modulus
    EVP_PKEY *pkey = load_rsa_pubkey_from_modulus(rsa_mod, RSA_KEY_SIZE);
    if (!pkey) {
        printf("ERROR: Failed to construct RSA public key\n");
        return 1;
    }

    print_rsa_public_key_openssl3(pkey);

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

    printf("INFO: will verify signature: ");
    for (int i = 0; i < RSA_KEY_SIZE; i++) printf("%02x", signature[i]);
    printf("\n");

    int sig_result = EVP_PKEY_verify(verify_ctx, signature, RSA_KEY_SIZE, firmware_digest, 32);
    if (sig_result == 1) {
        printf("INFO: Firmware signature is valid.\n");
    } else {
        printf("ERROR: Invalid firmware signature (%d).\n", sig_result);
        EVP_PKEY_free(pkey);
        return 1;
    }

    EVP_PKEY_CTX_free(verify_ctx);
    EVP_PKEY_free(pkey);


    printf("INFO: Allocating new writable memory for machinecode.\n");
    uint8_t *mc = mmap(0, FIRMWARE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);

    if (mc == MAP_FAILED) {
        printf("ERROR: Memory allocation failed: %s\n", strerror(errno));
        return 1;
    }

    printf("INFO: Copying verified machinecode to writable memory.\n");
    memcpy(mc, firmware, FIRMWARE_SIZE);

    printf("INFO: Changing memory protection to executable.\n");
    if (mprotect(mc, FIRMWARE_SIZE, PROT_READ | PROT_EXEC) != 0) {
        printf("ERROR: Changing memory to executable failed: %s\n", strerror(errno));
        return 1;
    }

    printf("INFO: Starting hardware watchdog with 5 second timeout.\n");
    alarm(5);

    printf("INFO: Calling newly loaded machinecode function.\n");
    ((void (*)(void))mc)();

    alarm(0);

    printf("INFO: machinecode returned, exiting.\n");

    return 0;
}
