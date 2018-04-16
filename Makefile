CFLAGS=-g -O0 -Wall -Werror \
  -fPIE -fpie \
  -Wformat -Wformat-security -Werror=format-security \
  -D_FORTIFY_SOURCE=2 \
  -fstack-protector-strong
  
all: rpcapng.o tagged-packet.o pcapng.o
	$(CC) -fpie -g -Wl,-z,relro,-z,now -o rpcapng rpcapng.o tagged-packet.o pcapng.o -lev
