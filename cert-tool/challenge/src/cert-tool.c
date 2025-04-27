#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/wait.h>
#include <fcntl.h>


void run_command_with_stdin(const char *command, const uint8_t *input, int inlen) {
    int pipefd[2];

    if (pipe(pipefd) == -1) {
        perror("pipe");
        exit(1);
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(1);
    }

    if (pid == 0) {
        // Child process
        close(pipefd[1]); // Close write end
        dup2(pipefd[0], STDIN_FILENO); // Redirect stdin to pipe read end
        close(pipefd[0]);

        // Run the shell to interpret the command
        execl("/bin/sh", "sh", "-c", command, (char *)NULL);
        perror("execl");
        exit(1);
    } else {
        // Parent process
        close(pipefd[0]); // Close read end
        int wlen = write(pipefd[1], input, inlen);

        if (wlen < inlen) {
            fprintf(stderr, "Write into pipe of %d truncated to %d\n", inlen, wlen);
        }

        close(pipefd[1]); // Send EOF to child
        wait(NULL); // Wait for child to finish
    }
}


int base64_decode(const char *input, uint8_t *output, size_t input_len, size_t output_size) {

    int bits = 0;

    for (size_t i = 0; i < input_len; i++) {
        char c = input[i];
        int val;

        if (c >= 'A' && c <= 'Z') {
            val = c - 'A';
        } else if (c >= 'a' && c <= 'z') {
            val = c - 'a' + 26;
        } else if (c >= '0' && c <= '9') {
            val = c - '0' + 52;
        } else if (c == '+') {
            val = 62;
        } else if (c == '/') {
            val = 63;
        } else if (c == '=') {
            bits -= 2;
            continue;
        } else {
            continue; // Skip non-base64 characters (e.g. whitespace, newlines)
        }

        if ((bits + 6) / 8 >= (int)output_size) {
            printf("Base64 input too large for output buffer size %ld\n", output_size);
            exit(1);
        }

        /* modulus (not divisor) */
        int bits_mod = ((bits % 8) + 8) % 8;

        //printf("bits: %d; bits_mod: %d\n", bits, bits_mod);

        /* This is flooring division which makes the challenge super easy */
        int adjust = (bits >> 31) & (8 - 1);
        int byte_idx = (bits - adjust) / 8;

        /* This is integer division which is harder but a more realistic bug */
        /*int byte_idx = bits / 8;*/

        if (bits_mod == 0) {
            //printf("Operating on byte_idx %d\n", byte_idx);
            output[byte_idx] &= 0x03;
            output[byte_idx] |= val << 2;
        } else if (bits_mod == 2) {
            //printf("Operating on byte_idx %d\n", byte_idx);
            output[byte_idx] &= 0xC0;
            output[byte_idx] |= val;
        } else if (bits_mod == 4) {
            //printf("Operating on byte_idx %d & %d\n", byte_idx, byte_idx + 1);
            output[byte_idx] &= 0xF0;
            output[byte_idx] |= (val >> 2);

            output[byte_idx + 1] &= 0x3F;
            output[byte_idx + 1] |= (val & 0x03) << 6;
        } else if (bits_mod == 6) {
            //printf("Operating on byte_idx %d & %d\n", byte_idx, byte_idx + 1);
            output[byte_idx] &= 0xFC;
            output[byte_idx] |= (val >> 4);

            output[byte_idx + 1] &= 0x0F;
            output[byte_idx + 1] |= (val & 0x0F) << 4;
        }

        bits += 6;
    }

    return bits / 8; // number of bytes written to output
}


int main() {

    /*const char *data = "hello world\nthis is stdin!\n"; */
    /*const char *cmd = "cat";  // or "grep world", "wc -l", etc. */


    char line[256];
    char input[4096];
    long unsigned int input_idx = 0;

    int banner_fd = open("banner.txt", O_RDONLY);
    ssize_t blen = read(banner_fd, input, 4096);
    ssize_t wlen = write(1, input, blen);

    if (wlen < blen) {
        fprintf(stderr, "Write of %ld truncated to %ld\n", blen, wlen);
        return -1;
    }

    printf("Enter a base64-encoded certificate:\n");
    printf("(End input with a line consisting only a '.')\n");

    while (fgets(line, sizeof(line) - 1, stdin)) {
        line[255] = 0;

        int len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = 0;
        }

        if (strncmp(line, "", 255) == 0) { continue; }
        if (line[0] == '-') { continue; }

        if (strncmp(line, ".", 255) == 0) { break; }

        if (256 + input_idx < sizeof(input)) {
            strncpy(&input[input_idx], line, 256);
        } else {
            printf("Maximum input length %ld exceeded!\n", sizeof(input));
            exit(1);
        }

        input_idx += len;
    }

    /*write(1, input, input_idx);*/

    uint8_t data[128 + 4096]; // 128 for cmd, 4096 for input
    strncpy((char *)data, "openssl x509 -in /dev/stdin -inform DER -text -noout", 127);
    /*strncpy((char *)&data[128], "openssl x509 -in /dev/stdin -inform DER -text", 128);*/

    int b64len = base64_decode(input, &data[128], input_idx, 4096);

    /* int wlen = write(1, &data[128], b64len); */

    /* if (wlen < b64len) { */
    /*     fprintf(stderr, "Write of %d truncated to %d\n", b64len, wlen); */
    /* } */

    /*fprintf(stderr, "Running cmd: %s\n", data);*/
    run_command_with_stdin((char *)data, &data[128], b64len);

    return 0;
}
