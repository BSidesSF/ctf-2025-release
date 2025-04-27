#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define KEY 0xab

int main(int argc, char *argv[]) {
  fprintf(stderr, "\033[1mOBSCURATRON\033[0m\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "\033[1mWARNING: RESTRICTED ACCESS FOR AUTHORIZED DRAGON GUARDIANS ONLY\033[0m\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "This application is designed to securely encrypt sensitive dragon files, protecting them from\n");
  fprintf(stderr, "unauthorized access. All files encrypted with this tool are safeguarded with the highest level of\n");
  fprintf(stderr, "cryptographic security to ensure the confidentiality and integrity of dragon-related data.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "\033[1mUSE OF THIS APPLICATION IS SUBJECT TO THE FOLLOWING TERMS:\033[0m\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "\033[1mConfidentiality\033[0m: All encrypted data must be handled with utmost care to prevent unauthorized disclosure.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "\033[1mSecurity\033[0m: Users are responsible for maintaining the security of their encryption keys and access credentials.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "\033[1mCompliance\033[0m: Use of this application must comply with all relevant laws and regulations regarding data protection and encryption.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Type your message and press ctrl-D to end!\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Alternatively, use redirects: %s < infile.pdf > outfile.pdf.enc\n", argv[0]);

  int current_character = fgetc(stdin) ^ KEY;
  int next_character;

  putchar(current_character);
  for(next_character = fgetc(stdin); next_character >= 0; current_character = next_character, next_character = fgetc(stdin)) {
    next_character = current_character ^ next_character;
    putchar(next_character);
  }

  return 0;
}
