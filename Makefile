CC=gcc
CFLAGS=-g -O0 -Wall -Werror \
  -fPIE -fpie \
  -Wformat -Wformat-security -Werror=format-security \
  -D_FORTIFY_SOURCE=2 \
  -fstack-protector-strong
LDFLAGS=-g -fpie -Wl,-pie -Wl,-z,relro,-z,now,-z,defs

all: daemon.o rpcapng.seccomp tagged-packet.o pcapng.o \
  ctl.o
	$(CC) $(LDFLAGS) -o rpcapng daemon.o tagged-packet.o pcapng.o
	$(CC) $(LDFLAGS) -o rpcapngctl ctl.o
	rm -f daemon.o
