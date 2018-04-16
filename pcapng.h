#ifndef PCAPNG_H
#define PCAPNG_H

#include <stdio.h>

#include "tagged-packet.h"

void pcapng_write_shblock(FILE *);
void pcapng_write_idblock(FILE *);

void pcapng_write_epblock(FILE *, const struct packet *);

#endif /* PCAPNG_H */
