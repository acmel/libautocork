CC := gcc
CFLAGS := -O2 -g -Wall -fPIC

all: libautocork.so tcp_nodelay_client tcp_nodelay_server

libautocork.so:	libautocork.o
	$(CC) $(CFLAGS) -shared -o libautocork.so libautocork.o -ldl -lrt

tcp_nodelay_client: tcp_nodelay_client.c
	$(CC) $(CFLAGS) tcp_nodelay_client.c -o tcp_nodelay_client -lrt

tcp_nodelay_server: tcp_nodelay_server.c
	$(CC) $(CFLAGS) tcp_nodelay_server.c -o tcp_nodelay_server -lrt

clean:
	rm -f tcp_nodelay_client tcp_nodelay_server *.o *.so *~
