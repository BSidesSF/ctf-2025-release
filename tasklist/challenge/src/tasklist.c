#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdarg.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <gnu/libc-version.h>

#define ENTRY_SIZE 256

#define UNUSED_OK(x) (void)(x)

#include "crypted.h"

// Forward declaration
struct _list_entry;

typedef void (*PrintHandler)(const struct _list_entry *entry, int fd);
typedef int (*CompleteHandler)(struct _list_entry *entry);

typedef struct _list_entry {
  uint32_t            id;
  bool                completed;
  PrintHandler        print_handler;
  CompleteHandler     complete_handler;
  uint8_t             entry[ENTRY_SIZE];
  struct _list_entry  *next;
} list_entry;

typedef struct _io_fds {
  int in;
  int out;
} io_fds;

typedef int (*CommandHandler)(io_fds *fds, list_entry **head, char **args, void *user_data);

// bottom 5 bits are a shift, top 3 are an index
typedef uint32_t charmask[8];

#define CHARMASK_IDX(x) (((x) >> 5) & 0x7)
#define CHARMASK_BIT(x) (1 << ((x) & 0x1f))

static inline void charmask_set(charmask mask, uint8_t val) {
  mask[CHARMASK_IDX(val)] |= CHARMASK_BIT(val);
}

static inline int charmask_check(charmask mask, uint8_t val) {
  uint32_t bit = CHARMASK_BIT(val);
  return ((mask[CHARMASK_IDX(val)] & bit) == bit) ? 1 : 0;
}

/* Command handlers */
struct handler_entry {
  char *name;
  CommandHandler handler;
  const bool uses_args;
  const char *help;
};

int AddEntry(io_fds *fds, list_entry **head, char **args, void *user_data);
int DeleteEntry(io_fds *fds, list_entry **head, char **args, void *user_data);
int EditEntry(io_fds *fds, list_entry **head, char **args, void *user_data);
int CompleteEntry(io_fds *fds, list_entry **head, char **args, void *user_data);
int HelpCommand(io_fds *fds, list_entry **head, char **args, void *user_data);
int ListEntries(io_fds *fds, list_entry **head, char **args, void *user_data);
int ExitCommand(io_fds *fds, list_entry **head, char **args, void *user_data);
int PInfoCommand(io_fds *fds, list_entry **head, char **args, void *user_data);

int prompt(io_fds *fds, char *dest, size_t buf_size, const char *format, ...);
int cmd_prompt(io_fds *fds, char *buf, size_t buf_size, char **args_out, size_t max_args);
int fdvprintf(int fd, const char *format, va_list ap);
int fdprintf(int fd, const char *format, ...);
int id_from_args(char **args);
int valid_id_from_args(int ofd, list_entry **head, char **args);
int handle_line(io_fds *fds, list_entry **head, char **args, void *user_data);

void PrintEntry(const list_entry *what, int fd);
int MarkCompleted(list_entry *what);

struct handler_entry command_handlers[] = {
  {
    .name = "list",
    .handler = ListEntries,
    .uses_args = true,
    .help = "List entries (use \"list all\" to show completed as well)",
  },
  {
    .name = "add",
    .handler = AddEntry,
    .uses_args = false,
    .help = "Add new entry",
  },
  {
    .name = "delete",
    .handler = DeleteEntry,
    .uses_args = true,
    .help = "Delete entry <arg>",
  },
  {
    .name = "edit",
    .handler = EditEntry,
    .uses_args = true,
    .help = "Edit entry <arg>",
  },
  {
    .name = "complete",
    .handler = CompleteEntry,
    .uses_args = true,
    .help = "Complete entry <arg>",
  },
  {
    .name = "exit",
    .handler = ExitCommand,
    .uses_args = false,
    .help = "Exit",
  },
  {
    .name = "help",
    .handler = HelpCommand,
    .uses_args = false,
    .help = "Show this help",
  },
  {
    .name = NULL,
    .handler = NULL,
  },
  {
    .name = NULL,
    .handler = NULL,
  },
  {
    .name = NULL,
    .handler = NULL,
  },
};

// Read until one of the following:
// - an error or EOF on read
// - a single read times out with the timeval specified
// - a character in the end_mask is seen
// - the buffer is filled
ssize_t read_until(int fd, uint8_t *buf, size_t buf_size, charmask end_mask, int timeout) {
  size_t total = 0;
  uint8_t aux = 0;
  while (1) {
    struct pollfd fds[] = {
      {
        .fd = fd,
        .revents = 0,
        .events = POLLIN,
      },
    };
    int polled = poll(fds, 1, timeout);
    if (polled == -1) {
      if (errno == EINTR) {
        continue;
      }
      perror("poll");
      return -1;
    } else if (polled == 0) {
      // timeout
      break;
    }
    if (fds[0].revents != POLLIN) {
      return -2;
    }
    uint8_t *start = &buf[total];
    // we only read one to check the end_mask
    ssize_t nread = read(fd, start, 1);
    if (nread == -1) {
      if (errno == EINTR || errno == EAGAIN) {
        continue;
      }
      perror("read");
      return -1;
    } else if (nread == 0) {
      // hit EOF
      break;
    }
    total += nread;
    if (!aux && *start == '\r') {
      aux = '\r';
      continue;
    }
    if (charmask_check(end_mask, *start)) {
      break;
    }
    if (total >= buf_size) {
      break;
    }
  }
  return total;
}

int cmd_prompt(io_fds *fds, char *buf, size_t buf_size, char **args_out, size_t max_args) {
  int rd = prompt(fds, buf, buf_size, "> ");
  if (rd < 1) {
    return rd;
  }
  int nargs = 1;
  memset(args_out, 0, (sizeof(char *))*max_args);
  args_out[0] = buf;
  if (isspace(buf[rd-1])) {
    buf[rd-1] = '\0';
  }
  for (int i=0; i<rd-1; i++) {
    if (!buf[i]) {
      break;
    }
    if (isspace(buf[i])) {
      buf[i]='\0';
      if (buf[i+1]) {
        args_out[nargs++] = &buf[i+1];
        if (nargs >= ((int)max_args)-1) {
          break;
        }
      }
    }
  }
  return nargs;
}

int main(int argc, char **argv) {
  UNUSED_OK(argc);
  UNUSED_OK(argv);
  io_fds fds = {
    .in = STDIN_FILENO,
    .out = STDOUT_FILENO,
  };
  char cmd_buf[512];
  char *args[8];
  list_entry *head = NULL;
  int failures = 0;
  while(1) {
    int nargs = cmd_prompt(&fds, cmd_buf, sizeof(cmd_buf), args, sizeof(args)/sizeof(char *));
    if (nargs < 1) {
      return nargs;
    }
    if (!args[0] || !strlen(args[0]))
      continue;
    if (handle_line(&fds, &head, args, NULL)) {
      failures++;
      if (failures >= 3) {
        fdprintf(fds.out, "Too many errors, exiting!");
        exit(-1);
      }
    } else {
      failures = 0;
    }
  }
  return 0;
}

int handle_line(io_fds *fds, list_entry **head, char **args, void *user_data) {
  struct handler_entry *cmd = &command_handlers[0];
  while (cmd->name) {
    if (!strcasecmp(cmd->name, args[0])) {
      if (cmd->uses_args) {
        args++;
      } else {
        args = NULL;
      }
      return cmd->handler(fds, head, args, user_data);
    }
    cmd++;
  }
  // command not found
  fdprintf(fds->out, "Unknown command: %s\n", args[0]);
  return -1;
}

int AddEntry(io_fds *fds, list_entry **head, char **args, void *user_data) {
  UNUSED_OK(args);
  UNUSED_OK(user_data);
  list_entry *new = calloc(1, sizeof(list_entry));
  if (!new)
    return -1;
  new->id = 1;
  // Prompt for contents
  int rd = prompt(fds, (char *)new->entry, sizeof(new->entry), "Task: ");
  if (rd == -1) {
    free(new);
    return -1;
  }
  // Set handlers
  new->print_handler = PrintEntry;
  new->complete_handler = MarkCompleted;
  // Attach to list
  if (*head) {
    list_entry *tail = *head;
    while(tail->next) {
      tail = tail->next;
    }
    tail->next = new;
    new->id = tail->id+1;
  } else {
    *head = new;
  }
  return 0;
}

int DeleteEntry(io_fds *fds, list_entry **head, char **args, void *user_data){
  UNUSED_OK(user_data);
  int id = valid_id_from_args(fds->out, head, args);
  if (id == -1) return -1;
  if (!head || !*head) {
    fdprintf(fds->out, "No entries\n");
    return -1;
  }
  list_entry *node = *head;
  // check first
  if ((int)(node->id) == id) {
    *head = node->next;
    free(node);
    return 0;
  }
  // walk the list
  while (node) {
    if (!node->next) {
      fdprintf(fds->out, "Entry not found\n");
      return -1;
    }
    if ((int)(node->next->id) == id) {
      list_entry *tmp = node->next->next;
      free(node->next);
      node->next = tmp;
      return 0;
    }
    node = node->next;
  }
  return -1;
}

int EditEntry(io_fds *fds, list_entry **head, char **args, void *user_data){
  UNUSED_OK(user_data);
  int id = valid_id_from_args(fds->out, head, args);
  if (id == -1) return -1;
  if (!head || !*head) {
    fdprintf(fds->out, "No entries\n");
    return -1;
  }
  list_entry *node = *head;
  while (node) {
    if ((int)(node->id) == id) {
      int rd = prompt(fds, (char *)node->entry, sizeof(node->entry), "Update task: ");
      if (rd == -1) {
        return -1;
      }
      return 0;
    }
    node = node->next;
  }
  fdprintf(fds->out, "Entry not found\n");
  return -1;
}

int CompleteEntry(io_fds *fds, list_entry **head, char **args, void *user_data){
  UNUSED_OK(user_data);
  int id = valid_id_from_args(fds->out, head, args);
  if (id == -1) return -1;
  if (!head || !*head) {
    fdprintf(fds->out, "No entries\n");
    return -1;
  }
  list_entry *node = *head;
  while (node) {
    if ((int)(node->id) == id) {
      return node->complete_handler(node);
    }
    node = node->next;
  }
  fdprintf(fds->out, "Entry not found\n");
  return -1;
}

int ListEntries(io_fds *fds, list_entry **head, char **args, void *user_data){
  UNUSED_OK(user_data);
  if (!head || !*head) {
    fdprintf(fds->out, "No entries\n");
    return -1;
  }
  bool all = false;
  bool completed_only = false;

  if (args) {
    int i = 0;
    char *arg = args[0];
    while (arg) {
      if (!strcmp(arg, "all")) {
        all = true;
      } else if (!strcmp(arg, "completed")) {
        completed_only = true;
      } else {
        fdprintf(fds->out, "Unknown argument %s\n", arg);
        return -1;
      }
      arg = args[++i];
    }
  }
  
  list_entry *node = *head;
  while (node) {
    bool include = all || (node->completed == completed_only);
    if (include && node->print_handler) {
      node->print_handler(node, fds->out);
    }
    node = node->next;
  }
  return 0;
}

int HelpCommand(io_fds *fds, list_entry **head, char **args, void *user_data){
  UNUSED_OK(head);
  UNUSED_OK(args);
  UNUSED_OK(user_data);
  struct handler_entry *cmd = &command_handlers[0];
  size_t name_len = 0;
  while (cmd->name) {
    name_len = (strlen(cmd->name) > name_len) ? strlen(cmd->name) : name_len;
    cmd++;
  }
  cmd = &command_handlers[0];
  while (cmd->name) {
    if (cmd->help)
      fdprintf(fds->out, "[%*s] %s\n", name_len, cmd->name, cmd->help);
    cmd++;
  }
  return 0;
}

int ExitCommand(io_fds *fds, list_entry **head, char **args, void *user_data) {
  UNUSED_OK(fds);
  UNUSED_OK(head);
  UNUSED_OK(args);
  UNUSED_OK(user_data);
  exit(0);
}

int fd_writeall(int fd, char *buf, size_t n) {
  int t = 0;
  while (n) {
    int w = write(fd, buf, n);
    if (w == -1 && errno != EINTR) {
      return -1;
    }
    buf = &buf[w];
    n -= w;
    t += w;
  }
  return t;
}

int fdprintf(int fd, const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  int rv = fdvprintf(fd, format, ap);
  va_end(ap);
  return rv;
}

int fdvprintf(int fd, const char *format, va_list ap) {
  // first we try on the stack
  char buf[256];
  va_list ap2;
  va_copy(ap2, ap);
  int sz = vsnprintf(buf, sizeof(buf), format, ap2);
  va_end(ap2);
  if (sz < (int)sizeof(buf)) {
    return fd_writeall(fd, buf, sz);
  }
  sz++;
  char *mbuf = malloc(sz);
  if (!mbuf) {
    return -1;
  }
  sz = vsnprintf(mbuf, sz, format, ap);
  sz = fd_writeall(fd, mbuf, sz);
  free(mbuf);
  return sz;
}

int prompt(io_fds *fds, char *dest, size_t buf_size, const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  int wrote = fdvprintf(fds->out, format, ap);
  va_end(ap);
  if (wrote == -1) {
    return -1;
  }
  charmask mask = {0};
  charmask_set(mask, '\n');
  ssize_t got = read_until(fds->in, (uint8_t *)dest, buf_size, mask, 3*60*1000);
  if (got == -1) {
    return -1;
  }
  if (got < (ssize_t)buf_size) {
    dest[got] = '\0';
    if (got > 0 && dest[got-1] == '\n')
      dest[got-1] = '\0';
  }
  return (int)got;
}

int id_from_args(char **args) {
  if (!args)
    return -1;
  char *first = args[0];
  if (!first)
    return -1;
  if (!*first)
    return -1;
  char *end;
  long rv = strtol(args[0], &end, 10);
  if (*end != '\0') {
    return -1;
  }
  int i = (int)rv;
  if (i < 0) {
    return -1;
  }
  return i;
}

int valid_id_from_args(int ofd, list_entry **head, char **args) {
  int id = id_from_args(args);
  if (id == -1) {
    fdprintf(ofd, "no valid id\n");
    return -1;
  }
  if (!head || !*head) {
    return -1;
  }
  list_entry *node = *head;
  while (node) {
    if ((int)node->id == id) {
      return id;
    }
    node = node->next;
  }
  fdprintf(ofd, "no entry with id %d\n", id);
  return -1;
}

__attribute__((constructor))
void preppinfo(void) {
  static char name[] = "qjogp";
  struct handler_entry *cmd = &command_handlers[1];
  while(cmd->name) cmd++;
  // cmd should now point to the first empty one
  cmd->name = &name[0];
  char *c = &name[0];
  while(*c) {
    *c = *c-1;
    c++;
  }
  cmd->handler = PInfoCommand;
}

int PInfoCommand(io_fds *fds, list_entry **head, char **args, void *user_data) {
  UNUSED_OK(args);
  UNUSED_OK(user_data);
  fdprintf(fds->out, HACKTHEPLANET);
  fdprintf(fds->out, PINFO_FD, fds->in, fds->out);
  fdprintf(fds->out, PINFO_HEAD, head);
  fdprintf(fds->out, PINFO_PINFO, PInfoCommand);
  fdprintf(fds->out, PINFO_LIBC, (char *)gnu_get_libc_version(), (char *)gnu_get_libc_release);
  return 0;
}

void PrintEntry(const list_entry *what, int fd) {
  fdprintf(fd, "[%02d][%c] %s\n", what->id, what->completed?'X':' ', what->entry);
}

int MarkCompleted(list_entry *what) {
  what->completed = true;
  return 0;
}