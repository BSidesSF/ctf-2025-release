#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>

#define disable_buffering(_fd) setvbuf(_fd, NULL, _IONBF, 0)
#define MAX_FILE_SIZE 4096
#define STARTING_SIZE 16

void __attribute__((stack_protect)) do_replace(char *filename, int offset, char *new_data, int new_data_length) {
  // printf("Filename: %s\n", filename);
  FILE *f = fopen(filename, "r+b");
  if(!f) {
    printf("Couldn't open file for writing: %s\n", filename);
    perror("fopen");
    exit(1);
  }

  // printf("%08x\n", offset);
  if(fseek(f, offset, SEEK_SET) != 0) {
    perror("fseek");
    exit(1);
  }
  fwrite(new_data, 1, new_data_length, f);
  fclose(f);
}

// This is alllll because I need to let them put NULLs in their strings!
char *read_string(char *prompt, int *length) {
  printf("%s\n", prompt);
  printf("> ");
  fflush(stdout);

  char *str = malloc(STARTING_SIZE);
  str[0] = '\0';
  int max_size = STARTING_SIZE;
  int i;
  for(i = 0; str[i - 1] != '\n'; i++) {
    // Expand as needed
    if(i >= max_size) {
      max_size *= 2;
      if(max_size > MAX_FILE_SIZE) {
        printf("Too big!\n");
        exit(1);
      }
      str = realloc(str, max_size);
    }

    str[i] = fgetc(stdin);
  }

  str[i - 1] = '\0';
  *length = i - 1;

  return str;
}

int __attribute__((no_reorder)) __attribute__((stack_protect)) main(int argc, char *argv[])
{
  disable_buffering(stdout);
  disable_buffering(stderr);
  prctl(PR_SET_DUMPABLE, 1);

  printf("--------------------------------------------------------\n");
  printf("THIS APPLICATION IS ONLY FOR OFFICIAL DRAGON-HUNTER USE!\n");
  printf("--------------------------------------------------------\n");
  printf("\n");


  printf("If you believe a document about dragons has been leaked, this\n");
  printf("application will help you censor it!\n");
  printf("\n");

  if(argc != 2) {
    printf("Usage: %s <file>\n", argv[0]);
    printf("\n");
    exit(1);
  }

  // Using a struct here to make sure the data lines up correctly
  struct {
    char line[128];
    int offset;
    char filename[128];
  } data;

  data.offset = 0;
  strncpy(data.filename, argv[1], 128);

  FILE *f;

  f = fopen(data.filename, "r+");
  if(!f) {
    printf("Couldn't open file for reading: %s\n", data.filename);
    perror("fopen");
    exit(1);
  }

  int search_size;
  char *search = read_string("String to find?", &search_size);

  int replace_size;
  char *replace = read_string("String to replace it with?", &replace_size);

  for(;;) {
    if(!fgets(data.line, 100, f)) {
      printf("Done!\n");
      return 0;
    }

    if(ftell(f) > MAX_FILE_SIZE) {
      printf("File is too big!\n");
      exit(0);
    }

    char *match;
    if(match = strstr(data.line, search)) {
      printf("Updating %s...\n", data.filename);
      // printf("Before: %s\n", data.line);
      do_replace(data.filename, data.offset + (match - data.line), replace, replace_size);

      memcpy(match, replace, replace_size);
      // printf("After: %s\n", data.line);
      // printf("--\n");
    }

    data.offset += strlen(data.line);
  }

  return 0;
}
