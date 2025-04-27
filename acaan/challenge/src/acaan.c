#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

#define disable_buffering(_fd) setvbuf(_fd, NULL, _IONBF, 0)

int main(int argc, char *argv[]) {
  disable_buffering(stdout);
  disable_buffering(stderr);

  printf("Welcome to ACAAN (Any Computerfile At Any Number)!\n");
  printf("\n");

  // Read the filename - hopefully 128 characters is enough!
  char filename[128];
  printf("Filename?\n");
  fgets(filename, 127, stdin);
  filename[strlen(filename) - 1] = '\0';
  printf("\n");

  // Read the offset. If they don't send a number, well, they can live with
  // their decisions
  uint32_t offset;
  char offset_str[20];
  printf("Offset into the file (either decimal, or 0xhex)?\n");
  fgets(offset_str, 19, stdin);
  if(!strncmp(offset_str, "0x", 2)) {
    offset = strtol(offset_str + 2, NULL, 16);
  } else {
    offset = strtol(offset_str, NULL, 10);
  }
  printf("\n");

  // Read the data, with some inspiration from SMTP
  printf("Data to replace it with? (Binary is fine - end with \"\\n.\\n\" or by closing the socket)\n");
  uint32_t total_bytes_read = 0;
  uint8_t data[2048]; // Surely this is enough!
  while(total_bytes_read < 2048) {
    size_t bytes_read = read(STDIN_FILENO, data + total_bytes_read, 2048 - total_bytes_read);

    // Done?
    if(bytes_read <= 0) {
      break;
    }

    total_bytes_read += bytes_read;

    if(total_bytes_read >= 3 && data[total_bytes_read - 1] == '\n' && data[total_bytes_read - 2] == '.' && data[total_bytes_read - 3] == '\n') {
      total_bytes_read -= 3;
      break;
    }
  }
  printf("\n");

  printf("Replacing %u bytes from file %s at offset %u! Hope this is everything you were hoping for!\n", total_bytes_read, filename, offset);

  int fd = open(filename, O_RDWR|O_CLOEXEC);
  if(fd < 0) {
    printf("Couldn't open %s!\n", filename);
    perror("open");
    exit(1);
  }

  pwrite(fd, &data, total_bytes_read, offset);
  close(fd);

  return 0;
}
