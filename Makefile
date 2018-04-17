CFLAGS=-g -O0 -Wall -Werror \
  -fPIE -fpie \
  -Wformat -Wformat-security -Werror=format-security \
  -D_FORTIFY_SOURCE=2 \
  -fstack-protector-strong

all: daemon.o tagged-packet.o pcapng.o \
  ctl.o
	$(CC) -fpie -g -Wl,-z,relro,-z,now -o rpcapng daemon.o tagged-packet.o pcapng.o
	$(CC) -fpie -g -Wl,-z,relro,-z,now -o rpcapngctl ctl.o
