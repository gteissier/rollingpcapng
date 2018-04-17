#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>


#include "pcapng.h"
#include "util.h"


void pcapng_write_shblock(FILE *f) {
  int ret;
  uint32_t u32;
  uint16_t u16;

  u32 = 0x0a0d0d0a;
  ret = fwrite(&u32, sizeof(u32), 1, f);
  check(ret == 1);
  u32 = 28;
  ret = fwrite(&u32, sizeof(u32), 1, f);
  check(ret == 1);
  u32 = 0x1a2b3c4d;
  ret = fwrite(&u32, sizeof(u32), 1, f);
  check(ret == 1);

  u16 = 1;
  ret = fwrite(&u16, sizeof(u16), 1, f);
  check(ret == 1);
  u16 = 0;
  ret = fwrite(&u16, sizeof(u16), 1, f);
  check(ret == 1);

  ret = fwrite("\xff\xff\xff\xff\xff\xff\xff\xff", 8, 1, f);
  check(ret == 1);

  u32 = 28;
  ret = fwrite(&u32, sizeof(u32), 1, f);
  check(ret == 1);
}

void pcapng_write_idblock(FILE *f) {
  int ret;
  uint32_t u32;
  uint16_t u16;

  // write block info
  u32 = 1; /* type=1 for ID block */
  ret = fwrite(&u32, sizeof(u32), 1, f);
  check(ret == 1);

  u32 = 20; /* ID block contains 2*u16 + u32 */
  ret = fwrite(&u32, sizeof(u32), 1, f);
  check(ret == 1);

  // ID block content
  u16 = 1;
  ret = fwrite(&u16, sizeof(u16), 1, f);
  check(ret == 1);

  u16 = 0;
  ret = fwrite(&u16, sizeof(u16), 1, f);
  check(ret == 1);

  u32 = 0xffffffff;
  ret = fwrite(&u32, sizeof(u32), 1, f);
  check(ret == 1);

  u32 = 20; /* ID block contains 2*u16 + u32 */
  ret = fwrite(&u32, sizeof(u32), 1, f);
  check(ret == 1);
}

void pcapng_write_epblock(FILE *f, const struct packet *p) {
  char *body;
  size_t body_size;
  FILE *fbody;
  int ret;
  uint16_t u16;
  uint32_t u32;
  uint64_t u64;
  size_t padlen;

  body = NULL;
  body_size = 0;

  fbody = open_memstream(&body, &body_size);

  u32 = 0;
  ret = fwrite(&u32, sizeof(u32), 1, fbody);
  check(ret == 1);

  u64 = 1000000*p->sec + p->usec;
  u32 = u64>>32;
  ret = fwrite(&u32, sizeof(u32), 1, fbody);
  check(ret == 1);
  u32 = u64 & 0xffffffff;
  ret = fwrite(&u32, sizeof(u32), 1, fbody);
  check(ret == 1);

  u32 = p->size;
  ret = fwrite(&u32, sizeof(u32), 1, fbody);
  check(ret == 1);
  ret = fwrite(&u32, sizeof(u32), 1, fbody);
  check(ret == 1);

  ret = fwrite(p->data, 1, p->size, fbody);
  check(ret == p->size);

  padlen = p->size;
  while (padlen % 4 != 0) {
    ret = fwrite("\x00", 1, 1, fbody);
    check(ret == 1);
    padlen += 1;
  }

  if (p->tag) {
    // write option list, currently one comment
    u16 = 1;
    ret = fwrite(&u16, sizeof(u16), 1, fbody);
    check(ret == 1);

    u16 = strlen(p->tag->desc);
    ret = fwrite(&u16, sizeof(u16), 1, fbody);
    check(ret == 1);

    ret = fwrite(p->tag->desc, strlen(p->tag->desc), 1, fbody);
    check(ret == 1);

    padlen = strlen(p->tag->desc);
    while (padlen % 4 != 0) {
      ret = fwrite("\x00", 1, 1, fbody);
      check(ret == 1);
      padlen += 1;
    }

    u32 = 0;
    ret = fwrite(&u32, sizeof(u32), 1, fbody);
    check(ret == 1);
  }

  fclose(fbody);

  u32 = 6;
  ret = fwrite(&u32, sizeof(u32), 1, f);
  check(ret == 1);

  u32 = body_size+12;
  ret = fwrite(&u32, sizeof(u32), 1, f);
  check(ret == 1);

  ret = fwrite(body, body_size, 1, f);
  check(ret == 1);

  u32 = body_size+12;
  ret = fwrite(&u32, sizeof(u32), 1, f);
  check(ret == 1);

  free(body);
}
