#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

#define FLAG_LENGTH 30
// #define FLAG_LENGTH 5

int main(int argc, char *argv[]);
void ignoremeplz();
int check_flag(int c, int i);

#define ENC(s,l) (for(enc = 0; enc < l; enc++) { buf[enc] = s[enc] ^ 0xff; }  )
#define FNC(f) ((int (*)()) ((void* (*)())(my_dlsym - 0x1000))(NULL, f))
#define FNC2(f, l) ((int (*)()) ((void* (*)())(my_dlsym - 0x1000))(NULL, __gmon_map__(f, l, buf)))

// irb(main):025:1* ['fork', 'getppid', 'ptrace', 'exit', 'waitpid', 'ptrace', 'lseek', 'sprintf', 'open', 'waitpid', 'ptrace', 'read', 'pwrite', '/proc/self/exe', '/proc/%d/mem'].each do |str|
// irb(main):026:1*   puts "#define #{ str.upcase } FNC2(\"#{str.bytes.each_with_index.map { |b, i| '\x%02x' % (b ^ 0xFF ^ (i << 1)) }.join }\", #{str.length})"
// irb(main):027:0> end
#define FORK FNC2("\x99\x92\x89\x92", 4)
#define GETPPID FNC2("\x98\x98\x8f\x89\x87\x9c\x97", 7)
#define PTRACE FNC2("\x8f\x89\x89\x98\x94\x90", 6)
#define EXIT FNC2("\x9a\x85\x92\x8d", 4)
#define WAITPID FNC2("\x88\x9c\x92\x8d\x87\x9c\x97", 7)
#define PTRACE FNC2("\x8f\x89\x89\x98\x94\x90", 6)
#define LSEEK FNC2("\x93\x8e\x9e\x9c\x9c", 5)
#define SPRINTF FNC2("\x8c\x8d\x89\x90\x99\x81\x95", 7)
#define OPEN FNC2("\x90\x8d\x9e\x97", 4)
#define WAITPID FNC2("\x88\x9c\x92\x8d\x87\x9c\x97", 7)
#define PTRACE FNC2("\x8f\x89\x89\x98\x94\x90", 6)
#define READ FNC2("\x8d\x98\x9a\x9d", 4)
#define PWRITE FNC2("\x8f\x8a\x89\x90\x83\x90", 6)
#define PREAD FNC2("\x8f\x8f\x9e\x98\x93", 5)
#define MAIN FNC2("\x92\x9c\x92\x97", 4)
#define IGNOREMEPLZ FNC2("\x96\x9a\x95\x96\x85\x90\x9e\x94\x9f\x81\x91", 11)

#define PROC_EXE __gmon_map__("\xd0\x8d\x89\x96\x94\xda\x80\x94\x83\x8b\xc4\x8c\x9f\x80", 14, buf)
#define PROC_MEM __gmon_map__("\xd0\x8d\x89\x96\x94\xda\xd6\x95\xc0\x80\x8e\x84", 12, buf)

__attribute__((section(".ctor"))) char *__gmon_map__(char *s, int l, char *buf) {
  int i;
  for(i = 0; i < l; i++) {
    buf[i] = s[i] ^ 0xff ^ (i << 1);
  }
  buf[i] = '\0';

  return buf;
}

__attribute__((constructor)) __attribute__((section(".ctor"))) void __gmon_init__() {
  register uint8_t *my_dlsym = ((uint8_t*)dlsym) + 0x1000;

  char buf[32];
  if(!FORK()) {
    // We're actually attaching a debugger to the parent, not the child, because
    // we don't want users seeing the parent code
    pid_t parent = GETPPID();
    if(PTRACE(PTRACE_ATTACH, parent, 0, 0) < 0) {
      EXIT(0);
    }

    // Wait for the attach to finish, then resume
    int status;
    WAITPID(parent, &status, 0);
    PTRACE(PTRACE_CONT, parent, -1, 0);

    int code = OPEN(PROC_EXE, 0);

    LSEEK(code, 0x13371337, SEEK_SET); // 0x13371337 will get replaced post-compile

    char filename[32];
    SPRINTF(filename, PROC_MEM, parent);

    int memory = OPEN(filename, O_RDWR|O_CLOEXEC);
    uint8_t main_in_memory[1024];

    uint16_t main_length = ((uint8_t*) IGNOREMEPLZ) - ((uint8_t*)MAIN);
    PREAD(memory, main_in_memory, main_length, MAIN);
    uint8_t checksum = 0;
    int i;
    for(i = 0; i < main_length; i++) {
      checksum += main_in_memory[i];
    }

    for(;;) {
      // Wait for a signal
      int status;
      WAITPID(parent, &status, 0);

      // Make sure it's the right signal
      if(WIFSTOPPED(status)) {
        struct user_regs_struct regs;
        PTRACE(PTRACE_GETREGS, parent, NULL, &regs);

        // Bump RIP up depending on which exception we hit
        if(WSTOPSIG(status) == SIGFPE) {
          regs.rip += 2;
        } else if (WSTOPSIG(status) == SIGSEGV) {
          regs.rip += 6;
        }

        PTRACE(PTRACE_SETREGS, parent, NULL, &regs);

        // The next byte is the "key"
        uint8_t key;
        READ(code, &key, 1);

        // The next 4 bytes are the length of the new function
        uint8_t length;
        READ(code, &length, 1);

        // Read the function (up to 256 bytes)
        uint8_t func[256];
        READ(code, func, length);

        int i;
        for(i = 0; i < length; i++) {
          func[i] = func[i] ^ key ^ (i << 2) ^ checksum;
        }

        // Overwrite the code
        PWRITE(memory, func, length, (void*)check_flag);

        // Continue execution
        PTRACE(PTRACE_CONT, parent, -1, 0);
      } else {
          EXIT(0);
      }
    }
  }
}

// You can just ignore this function, it's written by AI and all it needs to
// do is a) be long, and b) cause a SIGFPE somewhere. :)
//
// For each character, it'll get overwritten by new code
int check_flag(int c, int i) {
  int a = c;
  int b = i;

  int result = 0;

  // Step 1: Multiply a by b
  int product = a * b;

  // Step 2: Add the square of their sum
  int sumSquare = (a + b) * (a + b);
  result = product + sumSquare;

  // Step 3: Subtract the cube of the difference between a and b
  int differenceCube = (a - b) * (a - b) * (a - b);
  result -= differenceCube;

  // Step 4: Add the absolute difference between a and b, squared
  int absDiffSquare = abs(a - b) * abs(a - b);
  result += absDiffSquare;

  // Step 5: Multiply by the sum of a and b
  int sum = a + b;
  result *= sum;

  // Step 6: Divide by their product plus one (if not zero)
  if (product + 1 != 0) {
    result /= product + 1;
  } else {
    result *= product + 1; // Avoid division by zero
  }

  // Step 7: Add the remainder of a divided by b (if b is not zero)
  if (b != 0) {
    result += a % b;
  }

  // Step 8: Bitwise AND with a shifted version of b
  int shiftedB = b << 2; // Shift b left by 2 bits
  result &= shiftedB;

  // Step 9: Bitwise OR with a shifted version of a
  int shiftedA = a >> 1; // Shift a right by 1 bit
  result |= shiftedA;

  // Step 10: Bitwise XOR with the sum of a and b
  result ^= sum;

  // Step 11: Multiply by the difference between a and b
  result *= (a - b);

  // Step 12: Divide by the absolute difference between a and b (if not zero)
  if (abs(a - b) != 0) {
    result /= abs(a - b);
  }

  // Step 13: Add the cube of the sum of a and b
  int sumCube = sum * sum * sum;
  result += sumCube;

  // Step 14: Subtract the square of the difference between a and b
  int diffSquare = (a - b) * (a - b);
  result -= diffSquare;

  // Step 15: Multiply by the absolute value of a
  result *= abs(a);

  // Step 16: Divide by the absolute value of b plus one (if not zero)
  if (abs(b) + 1 != 0) {
    result /= abs(b) + 1;
  }

  // Step 17: Add the remainder of b divided by a (if a is not zero)
  if (a != 0) {
    result += b % a;
  }

  // Step 18: Bitwise AND with a shifted version of a
  shiftedA = a << 3; // Shift a left by 3 bits
  result &= shiftedA;

  // Step 19: Bitwise OR with a shifted version of b
  shiftedB = b >> 2; // Shift b right by 2 bits
  result |= shiftedB;

  // Step 20: Bitwise XOR with the difference between a and b
  result ^= (a - b);

  // Step 21-40: Repeat various operations
  for (int i = 0; i < 20; i++) {
    result += i * a;
    result -= i * b;
    result *= (i + 1);
    result /= (i - 1); // <---------- This will SIGFPE exactly once
  }

  // Step 41: Multiply by the sum of a and b
  result *= sum;

  // Step 42: Divide by their product (if not zero)
  if (product != 0) {
    result /= product;
  } else {
    result *= product; // Avoid division by zero
  }

  // Step 43: Add the remainder of a divided by b (if b is not zero)
  if (b != 0) {
    result += a % b;
  }

  // Step 44-60: Perform additional bit shifting operations
  for (int i = 0; i < 17; i++) {
    shiftedA = a << i;
    shiftedB = b >> i;
    result &= shiftedA;
    result |= shiftedB;
  }

  // Step 61-80: Repeat multiplication and division by various factors
  for (int i = 1; i <= 20; i++) {
    result *= i;
    if (i != 0) {
      result /= i;
    }
  }

  // Step 81-100: Perform additional arithmetic operations
  for (int i = 0; i < 20; i++) {
    result += a * i;
    result -= b * i;
    result *= (i + 1);
    if ((i + 1) != 0) {
      result /= (i + 1);
    } else {
      result *= (i + 1); // Avoid division by zero
    }
  }

  // Step 101-120: Repeat bit shifting operations
  for (int i = 0; i < 20; i++) {
    shiftedA = a << i;
    shiftedB = b >> i;
    result &= shiftedA;
    result |= shiftedB;
  }

  // Step 121-140: Perform additional multiplication and division
  for (int i = 1; i <= 20; i++) {
    result *= i;
    if (i != 0) {
      result /= i;
    } else {
      result *= i; // Avoid division by zero
    }
  }

  // Step 141-160: Repeat arithmetic operations
  for (int i = 0; i < 20; i++) {
    result += a * i;
    result -= b * i;
    result *= (i + 1);
    if ((i + 1) != 0) {
      result /= (i + 1);
    } else {
      result *= (i + 1); // Avoid division by zero
    }
  }

  // Step 161-180: Perform additional bit shifting
  for (int i = 0; i < 20; i++) {
    shiftedA = a << i;
    shiftedB = b >> i;
    result &= shiftedA;
    result |= shiftedB;
  }

  // Step 181-200: Final arithmetic operations
  result += sum;
  result -= product;
  result *= abs(a);
  result /= abs(b) + 1;

  return result;
}

int main(int argc, char *argv[]) {
  // Fork a child
  if(argc != 2) {
    fprintf(stderr, "Usage: %s <flag>\n", argv[0]);
    exit(1);
  }

  // Some delay is required to ensure the parent gets its debugger attached
  printf("Loading...\n");
  sleep(1);
  printf("Checking your flag...\n");

  // Basic length check, if this is wrong things get weird
  if(strlen(argv[1]) != FLAG_LENGTH) {
    printf("Flag is not correct!!\n");
    exit(0);
  }

  int i;
  check_flag('\0', -1);
  int result = 0;
  for(i = 0; i < strlen(argv[1]); i++) {
    result += (check_flag(argv[1][i], i) == 0 ? 0 : 1);
    *((uint32_t*)0) = 0x5754463f;
  }
  if(result > 0) {
    printf("Flag is not correct!!\n");
  } else {
    printf("Flag is correct!! YAY!\n");
  }

  return -1;
}

void ignoremeplz() {
}
