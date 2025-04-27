#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/evp.h>

#define TRUNCLEN 8 /* bytes of the hash to use */


static inline unsigned int md5(EVP_MD_CTX *ctx, const EVP_MD *md, uint8_t *d, int len, uint8_t *h) {

    unsigned int md_len;

    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, d, len);
    EVP_DigestFinal_ex(ctx, h, &md_len);

    return md_len;
}


void brent_md5() {

    const EVP_MD *md = EVP_md5();
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

    uint8_t x0[EVP_MAX_MD_SIZE];
    uint8_t tort[EVP_MAX_MD_SIZE];
    uint8_t hare[EVP_MAX_MD_SIZE];

    memset(x0, 0, EVP_MAX_MD_SIZE);
    memset(tort, 0, EVP_MAX_MD_SIZE);
    memset(hare, 0, EVP_MAX_MD_SIZE);

    (void)md5(mdctx, md, x0, TRUNCLEN, hare);

    uint64_t pwr = 1;
    uint64_t lam = 1;

    while (memcmp(tort, hare, TRUNCLEN) != 0) {
        if (pwr == lam) {
            fprintf(stderr, "Hit cycle power limit %llu, doubling\n", pwr);
            memcpy(tort, hare, TRUNCLEN);
            pwr *= 2;
            lam = 0;
        }

        (void)md5(mdctx, md, hare, TRUNCLEN, hare);

        lam += 1;
    }

    fprintf(stderr, "Found cycle of length %llu (tort == hare == ", lam);
    for (int i = 0; i < TRUNCLEN; i++) {
        fprintf(stderr, "%02x", tort[i]);
    }
    fprintf(stderr, ")\n");

    memcpy(tort, x0, TRUNCLEN);
    memcpy(hare, x0, TRUNCLEN);

    for (uint64_t i = 0; i < lam; i++) {
        (void)md5(mdctx, md, hare, TRUNCLEN, hare);
    }

    uint64_t mu = 0;
    while (memcmp(tort, hare, TRUNCLEN) != 0) {
        (void)md5(mdctx, md, hare, TRUNCLEN, hare);
        (void)md5(mdctx, md, tort, TRUNCLEN, tort);

        mu += 1;
    }

    fprintf(stderr, "Found cycle of length %llu starting at %llu\n", lam, mu);

    EVP_MD_CTX_destroy(mdctx);
}


void populate_state_dir() {

    const EVP_MD *md = EVP_md5();
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

    uint8_t x[EVP_MAX_MD_SIZE];

    memset(x, 0, EVP_MAX_MD_SIZE);

    /* 0eb8d7716b9566cf -- 0e b8 d7 71 6b 95 66 cf*/
    x[0] = 0x0e;
    x[1] = 0xb8;
    x[2] = 0xd7;
    x[3] = 0x71;
    x[4] = 0x6b;
    x[5] = 0x95;
    x[6] = 0x66;
    x[7] = 0xcf;

    for (uint64_t t = 1500000000; t < 2100000000; t++) {
        if ((t & 0xFFFFF) == 0) {
            char fname[32];
            snprintf(fname, 32, "state/%llu", t);
            int fd = open(fname, O_WRONLY | O_CREAT | O_EXCL);

            for (int i = 0; i < TRUNCLEN; i++) {
                dprintf(fd, "%02x", x[i]);
            }
            dprintf(fd, "\n");

            close(fd);
        }

        (void)md5(mdctx, md, x, TRUNCLEN, x);
    }

}


void solve() {

    int64_t t_known = 1999634432; /* Known, possibly future time */
    int64_t t_goal = 1742826261;  /* Current time */
    int64_t cycle_len = 3385752161;

    int64_t steps = (cycle_len - (t_known - t_goal)) % cycle_len;

    const EVP_MD *md = EVP_md5();
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

    uint8_t x[EVP_MAX_MD_SIZE];

    memset(x, 0, EVP_MAX_MD_SIZE);

    x[0] = 0xef;
    x[1] = 0x2e;
    x[2] = 0x01;
    x[3] = 0x01;
    x[4] = 0xb4;
    x[5] = 0xff;
    x[6] = 0x85;
    x[7] = 0xde;

    fprintf(stderr, "Running %lld steps to find state at %lld from %lld\n", steps, t_goal, t_known);
    uint64_t progress = steps / 100;
    for (int64_t i = 0; i < steps; i++) {
        if (i % progress == 0) {
            fprintf(stderr, ".");
        }
        (void)md5(mdctx, md, x, TRUNCLEN, x);
    }

    printf("\nState found: ");
    for (int i = 0; i < TRUNCLEN; i++) {
        printf("%02x", x[i]);
    }
    printf("\n");

}


int main(void) {

    /*brent_md5();*/
    /*populate_state_dir();*/
    solve();

    return 0;
}
