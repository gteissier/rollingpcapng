#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "util.h"

static const char *ctl_path = "/tmp/rpcapng.ctl";

static void usage(const char *arg0) {
  fprintf(stderr, "usage: %s [-c ctl_path] mode [arg]\n"
     "  -c ctl_path: Unix path of control socket\n"
     "  mode can be:\n"
     "  tag <tag>: set the comment for newly captured packets\n"
     "  clear: reset the packet ring buffer\n"
     "  dump <file>: dump the packet ring buffer to a file\n"
     "  arg is limited to 254 bytes\n" , arg0);

  exit(1);
}

int main(int argc, char **argv) {
  int c;
  const char *mode = NULL;
  const char *arg = NULL;
  int fd;
  char buffer[256];
  size_t size;
  struct sockaddr_un addr;
  struct timeval start, end, elapsed;
  int ret;

  while ((c = getopt(argc, argv, "c:h")) != -1) {
    switch (c) {
    case 'c':
      ctl_path = optarg;
      break;
    case '?':
    case 'h':
      usage(argv[0]);
    }
  }

  if (optind < argc - 2 || optind >= argc) {
    usage(argv[0]);
  }



  mode = argv[optind];
  if (strlen(mode) == 3 && strcmp(mode, "tag") == 0) {
    if (optind != argc - 2) {
      usage(argv[0]);
    }

    arg = argv[optind+1];

    size = strlen(arg) + 1;
    if (size > 255) {
      usage(argv[0]);
    }

    buffer[0] = 't';
    strncpy(&buffer[1], arg, sizeof(buffer)-2);
  }
  else if (strlen(mode) == 4 && strcmp(mode, "dump") == 0) {
    if (optind != argc - 2) {
      usage(argv[0]);
    }

    arg = argv[optind+1];

    size = strlen(arg) + 1;
    if (size > 255) {
      usage(argv[0]);
    }

    buffer[0] = 'd';
    strncpy(&buffer[1], arg, sizeof(buffer)-2);
  }
  else if (strlen(mode) == 5 && strcmp(mode, "clear") == 0) {
    if (optind != argc - 1) {
      usage(argv[0]);
    }

    buffer[0] = 'c';
    size = 1;
  }
  else {
    usage(argv[0]);
  }


  
  fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  check(fd != -1);

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  addr.sun_path[0] = 0;

  ret = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
  check(ret == 0);


  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, ctl_path, sizeof(addr.sun_path)-1);


  ret = gettimeofday(&start, NULL);
  check(ret == 0);

  ret = sendto(fd, buffer, size, 0, (struct sockaddr *) &addr, sizeof(addr));
  if (ret == -1) {
    perror("sendto");
  }
  check(ret == size);

  ret = recv(fd, buffer, sizeof(buffer), 0);
  check(ret > 0);

  ret = gettimeofday(&end, NULL);
  check(ret == 0);

  timersub(&end, &start, &elapsed);
  printf("processed in %ld.%06ld s\n", elapsed.tv_sec, elapsed.tv_usec);
  
  close(fd);

  return 0;
}
