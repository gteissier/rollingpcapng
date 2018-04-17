#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>

#define check(what)     do {                            \
  if (!(what)) {                                        \
    fprintf(stderr, "%s:%d " #what " failed (%m)\n", __FILE__,  \
      __LINE__);                                        \
    exit(1);                                            \
  }                                                     \
} while (0)

#endif /* UTIL_H */
