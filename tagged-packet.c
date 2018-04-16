#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "tagged-packet.h"


#define check(what)     do {                            \
  if (!(what)) {                                        \
    fprintf(stderr, "%s:%d " #what " failed (%m)\n", __FILE__,  \
      __LINE__);                                        \
    exit(1);                                            \
  }                                                     \
} while (0)

static struct tag_list tags = TAILQ_HEAD_INITIALIZER(tags);

struct tag *tag_get() {
  struct tag *t;
  t = TAILQ_LAST(&tags, tag_list);
  if (t) {
    t->refcount += 1;
  }
  return t;
}

void tag_put(struct tag *t) {
  if (!t) {
    return;
  }
  t->refcount -= 1;
  if (t->refcount <= 0) {
    TAILQ_REMOVE(&tags, t, _next);
    free(t->desc);
    free(t);
  }
}

void tag_append(const char *desc) {
  struct tag *t;

  t = malloc(sizeof(*t));
  check(t != NULL);
  t->desc = strdup(desc);
  check(t->desc != NULL);

  t->refcount = 0;

  TAILQ_INSERT_TAIL(&tags, t, _next);
}



void packet_fill(struct packet *p, unsigned int sec, unsigned int usec,
  const void *ptr, size_t size) {
  p->tag = tag_get();

  p->sec = sec;
  p->usec = usec;

  check(size <= sizeof(p->data));
  memcpy(p->data, ptr, size);

  p->size = size;
}


void packet_ring_init(struct packet_ring *r, int n_packets) {
  int i;

  r->n_packets = n_packets;
  r->packets = calloc(sizeof(*r->packets), n_packets);
  check(r->packets != NULL);

  TAILQ_INIT(&r->free_packets);
  TAILQ_INIT(&r->avail_packets);

  for (i = 0; i < n_packets; i++) {
    TAILQ_INSERT_TAIL(&r->free_packets, &r->packets[i], _next);
  }
}

void packet_ring_fini(struct packet_ring *r) {
  free(r->packets);

  TAILQ_INIT(&r->free_packets);
  TAILQ_INIT(&r->avail_packets);
}

struct packet *packet_ring_get(struct packet_ring *r) {
  struct packet *p;

  p = TAILQ_FIRST(&r->free_packets);
  if (p == NULL) {
    p = TAILQ_FIRST(&r->avail_packets);
    check(p != NULL);

    tag_put(p->tag);
    TAILQ_REMOVE(&r->avail_packets, p, _next);

    p->tag = NULL;
    TAILQ_INSERT_TAIL(&r->avail_packets, p, _next);
  }
  else {
    TAILQ_REMOVE(&r->free_packets, p, _next);
    p->tag = NULL;
    TAILQ_INSERT_TAIL(&r->avail_packets, p, _next);
  }

  return p;
}

void packet_ring_put(struct packet_ring *r, struct packet *p) {
  TAILQ_REMOVE(&r->avail_packets, p, _next);
  tag_put(p->tag);
  TAILQ_INSERT_TAIL(&r->free_packets, p, _next);
}
