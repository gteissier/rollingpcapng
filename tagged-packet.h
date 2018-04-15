#ifndef TAGGED_PACKET_H
#define TAGGED_PACKET_H

#include <sys/types.h>
#include <sys/queue.h>

struct tag {
  char *desc;
  size_t refcount;
  TAILQ_ENTRY(tag) _next;
};

TAILQ_HEAD(tag_list, tag);

struct tag *tag_get();
void tag_put(struct tag *);
void tag_append(const char *desc);



struct packet {
  TAILQ_ENTRY(packet) _next;

  struct tag *tag;

  unsigned int sec, usec;
  size_t size;

  unsigned char data[4096];
};

TAILQ_HEAD(packet_list, packet);

void packet_fill(struct packet *, unsigned int, unsigned int,
  const void *, size_t);

struct packet_ring {
  int n_packets;
  struct packet *packets;

  struct packet_list free_packets;
  struct packet_list avail_packets;
};

void packet_ring_init(struct packet_ring *, int);
void packet_ring_fini(struct packet_ring *);

struct packet *packet_ring_get(struct packet_ring *);

#endif /* TAGGED_PACKET_H */
