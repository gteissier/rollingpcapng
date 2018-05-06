#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <sys/un.h>
#include <pwd.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <linux/audit.h>
#include <stddef.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <linux/if_packet.h>
#include <linux/filter.h>

#include "tagged-packet.h"
#include "pcapng.h"
#include "util.h"



static int pagesize;
volatile int quit = 0;

static const char *interface = NULL;
static int packet_ring_frames= 1024;
static int packet_buffer_frames = 1024;
static const char *ctl_path = "/tmp/rpcapng.ctl";
static const char *user = NULL;

struct rxring {
  /* initialized during startup */
  int fd;
  void *ring;

  /* updated by kernel and by userspace */
  int offset;
};
static void rxring_init(struct rxring *r, const char *iface);
static void rxring_fini(struct rxring *r);
static void rxring_process(struct rxring *r, int revents);

static struct rxring rx;


static int ctl_fd;

static struct packet_ring pr;


static int get_ifindex(const char *iface) {
  int sd;
  struct ifreq ifr;
  int ret;

  sd = socket(PF_INET, SOCK_DGRAM, 0);
  check(sd != -1);

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

  ret = ioctl(sd, SIOCGIFINDEX, &ifr);
  check(ret == 0);

  close(sd);

  return ifr.ifr_ifindex;
}

static struct sock_filter bpf[] = {
{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 8, 0x000086dd },
{ 0x30, 0, 0, 0x00000014 },
{ 0x15, 2, 0, 0x00000084 },
{ 0x15, 1, 0, 0x00000006 },
{ 0x15, 0, 17, 0x00000011 },
{ 0x28, 0, 0, 0x00000036 },
{ 0x15, 14, 0, 0x00000016 },
{ 0x28, 0, 0, 0x00000038 },
{ 0x15, 12, 13, 0x00000016 },
{ 0x15, 0, 12, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 2, 0, 0x00000084 },
{ 0x15, 1, 0, 0x00000006 },
{ 0x15, 0, 8, 0x00000011 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 6, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x48, 0, 0, 0x0000000e },
{ 0x15, 2, 0, 0x00000016 },
{ 0x48, 0, 0, 0x00000010 },
{ 0x15, 0, 1, 0x00000016 },
{ 0x6, 0, 0, 0x00000000 },
{ 0x6, 0, 0, 0x00040000 },
};

static void rxring_init(struct rxring *r, const char *iface) {
  int ret;
  struct sockaddr_ll addr;
  struct sock_fprog prog;
  struct tpacket_req tp;

  ret = socket(PF_PACKET, SOCK_RAW|SOCK_NONBLOCK, 0);
  check(ret != -1);
  r->fd = ret;


  memset(&addr, 0, sizeof(addr));
  addr.sll_family = AF_PACKET;
  addr.sll_ifindex = get_ifindex(iface);
  addr.sll_protocol = htons(ETH_P_ALL);

  ret = bind(r->fd, (struct sockaddr *) &addr, sizeof(addr));
  check(ret == 0);


  prog.len = sizeof(bpf)/sizeof(bpf[0]);
  prog.filter = bpf;

  ret = setsockopt(r->fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
  check(ret == 0);


  tp.tp_block_size = packet_ring_frames * pagesize;
  tp.tp_block_nr = 1;
  tp.tp_frame_size = pagesize;
  tp.tp_frame_nr = packet_ring_frames;

  ret = setsockopt(r->fd, SOL_PACKET, PACKET_RX_RING, (void*) &tp, sizeof(tp));
  check(ret == 0);

  r->ring = mmap(0, tp.tp_block_size * tp.tp_block_nr,
    PROT_READ | PROT_WRITE, MAP_SHARED, r->fd, 0);
  check(r->ring != MAP_FAILED);

  r->offset = 0;
}

static void rxring_fini(struct rxring *r) {
  munmap(r->ring, packet_ring_frames * pagesize);
  close(r->fd);
}

static void rxring_process(struct rxring *r, int revents) {
  struct tpacket_hdr *header;
  struct packet *p;

  const void *bytes;
  size_t size;

  while (1) {
    header = (void *) r->ring + (r->offset * pagesize);
    assert((((unsigned long) header) & (pagesize - 1)) == 0);

    if (!(header->tp_status & TP_STATUS_USER)) {
      break;
    }

    // first, initialize frame content and size
    bytes = ((void *) header) + header->tp_mac;
    size = header->tp_snaplen;

    p = packet_ring_get(&pr);
    packet_fill(p, header->tp_sec, header->tp_usec,
      bytes, size);

    // last, release frame to kernel
    header->tp_status = TP_STATUS_KERNEL;
    r->offset = (r->offset + 1) & (packet_ring_frames - 1);
  }
}

static void on_sig(int signo) {
  quit = 1;
}

static void ctl_process(int revents) {
  int ret;
  struct sockaddr_un addr;
  socklen_t addr_size = sizeof(addr);
  char buffer[256+1];
  FILE *f;
  struct packet *p;


  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;

  ret = recvfrom(ctl_fd, buffer, 256, 0, (struct sockaddr *) &addr, &addr_size);
  check(ret != -1);
  check(ret < sizeof(buffer));
  buffer[ret] = 0;

  if (buffer[0] == 't') {
    check(ret > 1);

    tag_append(&buffer[1]);
  }
  else if (buffer[0] == 'd') {
    check(ret > 1);

    f = fopen(&buffer[1], "wb");
    check(f != NULL);

    pcapng_write_shblock(f);
    pcapng_write_idblock(f);

    TAILQ_FOREACH(p, &pr.avail_packets, _next) {
      pcapng_write_epblock(f, p);
    }

    fclose(f);
  }
  else if (buffer[0] == 'c') {
    TAILQ_FOREACH(p, &pr.avail_packets, _next) {
      packet_ring_put(&pr, p);
    }
  }

  addr_size = sizeof(addr);
  sendto(ctl_fd, "ok\n", 3, 0, (const struct sockaddr *) &addr, addr_size);
}

#define syscall_arg(_n) (offsetof(struct seccomp_data, args[_n]))
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))

#if defined(__i386__)
# define REG_SYSCALL	REG_EAX
# define ARCH_NR	AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define REG_SYSCALL	REG_RAX
# define ARCH_NR	AUDIT_ARCH_X86_64
#else
# warning "Platform does not support seccomp filter yet"
# define REG_SYSCALL	0
# define ARCH_NR	0
#endif

#define VALIDATE_ARCHITECTURE \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define EXAMINE_SYSCALL \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr)

#define ALLOW_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#define KILL_PROCESS \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

static __attribute__((unused)) void filter_syscalls() {
  int ret;

  static struct sock_filter filter[] = {
#include "rpcapng.seccomp"
  };

  static struct sock_fprog prog = {
    .len = sizeof(filter)/sizeof(filter[0]),
    .filter = filter,
  };

  ret = prctl(PR_SET_DUMPABLE, 0);
  check(ret == 0);

  ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0);
  check(ret == 0);

  ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
  check(ret == 0);
}


static void usage(const char *arg0) {
  fprintf(stderr, "usage: %s -i <interface> [-r rx_ring_size] [-R roll_ring_size]"
    " [-c ctl_path] [-Z user]\n"
    "  -i <interface>: the network interface to capture from\n"
    "  -r rx_ring_size: the number of slots in the PF_PACKET rx ring used to pull packets from NIC\n"
    "     DUE TO IMPLEMENTATION, USE ONLY A POWER OF TWO\n"
    "     defaults to 1024\n"
    "  -R roll_ring_size: the number of slots in the network blackbox\n"
    "     defaults to 1024\n"
    "  -c ctl_path: Unix path of control socket\n"
    "     defaults to /tmp/rpcapng.ctl\n"
    "  -Z user: run under user identity, once privileged ops are done\n", arg0);

  exit(1);
}

int main(int argc, char **argv) {
  int ret;
  int c;
  struct sockaddr_un addr;
  struct pollfd fds[2];
  struct passwd *passwd;
  uid_t uid = 0;
  gid_t gid = 0;

  pagesize = getpagesize();

  while ((c = getopt(argc, argv, "i:c:r:R:Z:h")) != -1) {
    switch (c) {
    case 'i':
      interface = optarg;
      break;
    case 'c':
      ctl_path = optarg;
      break;
    case 'r':
      packet_ring_frames = atoi(optarg);
      break;
    case 'R':
      packet_buffer_frames = atoi(optarg);
      break;
    case 'Z':
      user = optarg;
      break;
    case '?':
    case 'h':
      usage(argv[0]);
    }
  }

  if (!interface || ((packet_ring_frames & (packet_ring_frames-1)) != 0)) {
    usage(argv[0]);
  }

  if (user) {
    passwd = getpwnam(user);
    if (!passwd) {
      fprintf(stderr, "user %s is not valid\n", user);
      exit(1);
    }

    uid = passwd->pw_uid;
    gid = passwd->pw_gid;
  }


  packet_ring_init(&pr, 1024);
  rxring_init(&rx, "ens3");


  if (user) {
    ret = setgid(gid);
    check(ret == 0);
    ret = setuid(uid);
    check(ret == 0);
  }


  filter_syscalls();

  signal(SIGINT, on_sig);

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, ctl_path, sizeof(addr.sun_path)-1);

  ctl_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  check(ctl_fd != -1);

  ret = bind(ctl_fd, (struct sockaddr *) &addr, sizeof(addr));
  check(ret == 0);


  while (!quit) {
    memset(fds, 0, sizeof(fds));

    fds[0].fd = rx.fd;
    fds[0].events = POLLIN;
    fds[1].fd = ctl_fd;
    fds[1].events = POLLIN;

    ret = poll(fds, 2, 100);
    if (ret > 0) {
      if (fds[0].revents & POLLIN) {
        rxring_process(&rx, fds[0].revents);
      }
      if (fds[1].revents & POLLIN) {
        ctl_process(fds[1].revents);
      }
    }
  }


  rxring_fini(&rx);
  packet_ring_fini(&pr);

  close(ctl_fd);
  unlink(ctl_path);

  return 0;
}
