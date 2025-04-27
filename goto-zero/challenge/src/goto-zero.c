#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#define disable_buffering(_fd) setvbuf(_fd, NULL, _IONBF, 0)

int main(int argc, char *argv[]) {
  disable_buffering(stdout);
  disable_buffering(stderr);
  srand(time(NULL));
  int count = rand() % 8 + 8;
  char buffer[32];

  printf("Enter %d characters then press enter!\n", count - 1);
  int i;
  for(i = 0; i < count; i++) {
    getchar();
  }

  puts("What is your name?\n");
  fgets(buffer, 256, stdin);

  printf("Good job, %s", buffer);
}

__asm__("int $3");
__asm__("pop %rdi");
__asm__("ret");
__asm__("pop %rdx");
__asm__("ret");
