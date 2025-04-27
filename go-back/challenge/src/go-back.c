#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void main(int argc, char *argv[])
{
  FILE *f= fopen("flag.txt", "r");
  if(!f) {
    printf("Couldn't open flag file!\n");
    perror("fopen");
    exit(1);
  }

  char flag[32];
  fgets(flag, 32, f);
  fclose(f);

  if(argc != 2) {
    printf("Oops!\n");
    exit(1);
  }

  // no timing attacks!! seriously
  usleep(rand() % 1000);

  if(!strcmp(flag, argv[1])) {
    printf("Yay!\n");
  }
}
