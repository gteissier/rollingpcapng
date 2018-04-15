#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>

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

#include <ev.h>

#include "tagged-packet.h"

#define check(what)	do {				\
  if (!(what)) {					\
    fprintf(stderr, "%s:%d " #what " failed (%m)\n", __FILE__,  \
      __LINE__);					\
    exit(1);						\
  }							\
} while (0)


static struct ev_loop *loop;
static int pagesize;
static int ring_frames;



struct rxring {
  /* initialized during startup */
  int fd;
  void *ring;
  ev_io ready;

  /* updated by kernel and by userspace */
  int offset;
};
static void rxring_init(struct rxring *r, const char *iface);
static void rxring_fini(struct rxring *r);
static void rxring_process(struct ev_loop *l, ev_io *io, int revents);

static struct rxring rx;


#define CTL_PATH	"/tmp/rpcapng.ctl"
static int ctl_fd;
static ev_io ctl_ready;

static struct packet_ring pr;


static int get_ifindex(const char *iface) {
  int sd;
  struct ifreq ifr;
  int ret;

  sd = socket(PF_INET, SOCK_DGRAM, 0);
  check(sd != -1);

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface, IFNAMSIZ);

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


  tp.tp_block_size = ring_frames * pagesize;
  tp.tp_block_nr = 1;
  tp.tp_frame_size = pagesize;
  tp.tp_frame_nr = ring_frames;

  ret = setsockopt(r->fd, SOL_PACKET, PACKET_RX_RING, (void*) &tp, sizeof(tp));
  check(ret == 0);

  r->ring = mmap(0, tp.tp_block_size * tp.tp_block_nr,
    PROT_READ | PROT_WRITE, MAP_SHARED, r->fd, 0);
  check(r->ring != MAP_FAILED);

  r->offset = 0;

  ev_io_init(&r->ready, rxring_process, r->fd, EV_READ);
  r->ready.data = r;
  ev_io_start(loop, &r->ready);
  r->ready.data = r;
}

static void rxring_fini(struct rxring *r) {
  munmap(r->ring, ring_frames * pagesize);
  close(r->fd);
}

static void rxring_process(struct ev_loop *l, ev_io *io, int revents) {
  struct tpacket_hdr *header;
  struct packet *p;
  struct rxring *r = io->data;

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
    r->offset = (r->offset + 1) & (ring_frames - 1);
  }
}


static void sig_process(struct ev_loop *l, ev_signal *s, int revents) {
  ev_break(loop, EVBREAK_ALL);
}

static void ctl_process(struct ev_loop *l, ev_io *w, int revents) {
  int ret;
  char buffer[256+1];

  ret = read(ctl_fd, buffer, 256);
  check(ret != -1);
  check(ret < sizeof(buffer));
  buffer[ret] = 0;

  if (buffer[0] == 't') {
    check(ret > 1);

    tag_append(&buffer[1]);
    printf("append tag %s\n", &buffer[1]);
  }
  else if (buffer[0] == 'd') {
    check(ret > 1);

    printf("dump to %s\n", &buffer[1]);
  }
}

int main(int argc, char **argv) {
  int ret;
  ev_signal signal_watcher;

  loop = EV_DEFAULT;
  pagesize = getpagesize();
  ring_frames = 1024;

  ev_signal_init(&signal_watcher, sig_process, SIGINT);
  ev_signal_start(loop, &signal_watcher);


  ret = mkfifo(CTL_PATH, 0666);
  check(ret != -1);

  ctl_fd = open(CTL_PATH, O_RDONLY);
  check(ctl_fd != -1);

  ev_io_init(&ctl_ready, ctl_process, ctl_fd, EV_READ);
  ev_io_start(loop, &ctl_ready);


  packet_ring_init(&pr, 10000);
  rxring_init(&rx, "ens33");


  ev_run(loop, 0);


  rxring_fini(&rx);
  packet_ring_fini(&pr);


  return 0;
}
