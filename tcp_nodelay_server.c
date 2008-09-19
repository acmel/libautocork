/*
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define NR_DATA_ENTRIES 100
#define SIZE_DATA_ENTRY 2
#define SIZE_RESPONSE 2

int buffers_received;
int rate;

#define NSEC_PER_SEC 1000000000L

static int64_t timespec_delta(const struct timespec *large,
                           const struct timespec *small)
{
        time_t secs = large->tv_sec - small->tv_sec;
        int64_t nsecs = large->tv_nsec - small->tv_nsec;

        if (nsecs < 0) {
                secs--;
                nsecs += NSEC_PER_SEC;
        }
        return secs * NSEC_PER_SEC + nsecs;
}

static void tcp_nodelay(int fd)
{
	int value = 1;
	if (setsockopt(fd, SOL_TCP, TCP_NODELAY, &value, sizeof(value)) != 0)
		perror("setsockopt(TCP_NODELAY):");
}

static void __tcp_cork(int fd, int cork)
{
	int value = cork;
	if (setsockopt(fd, SOL_TCP, TCP_CORK, &value, sizeof(value)) != 0)
		perror("setsockopt(TCP_CORK):");
}

static void tcp_cork(int fd)
{
	__tcp_cork(fd, 1);
}

static void tcp_uncork(int fd)
{
	__tcp_cork(fd, 0);
}

static char response[SIZE_RESPONSE];

static int nread(int fd, char *bf, int len)
{
	do {
		int n = read(fd, bf, len);

		if (n <= 0)
			return -1;
		else
			++buffers_received;

		len -= n;
		bf += n;
	} while (len != 0);
	return 0;
}

static int exchange_packet(int fd, const int cork)
{
	char data[NR_DATA_ENTRIES * SIZE_DATA_ENTRY];

	if (nread(fd, data, sizeof(data)) != 0)
		return -1;

	if (cork)
		tcp_cork(fd);

	if (!rate && write(fd, response, SIZE_RESPONSE) != SIZE_RESPONSE) {
		fprintf(stderr, "server: write failed!\n");
		return -1;
	}

	if (cork)
		tcp_uncork(fd);

	return 0;
}

int main(int argc, char **argv)
{
	uint64_t max = 0, min = 3600 * NSEC_PER_SEC, avg = 0;
	struct addrinfo *host;
	struct addrinfo hints = {
		.ai_family   = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags    = AI_PASSIVE,
	};
	const char *port;
	int rc = 1, fd, client, cork = 0, no_delay = 0;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <port> [no_delay|cork]\n", argv[0]);
		goto out;
	}

	if (argc > 2) {
		cork = strcmp(argv[2], "cork") == 0;
		no_delay = strcmp(argv[2], "no_delay") == 0;
		rate = strcmp(argv[2], "rate") == 0;
	}

	port = argv[1];

	rc = getaddrinfo(NULL, port, &hints, &host);
	if (rc != 0) {
		fprintf(stderr, "error using getaddrinfo: %s\n", gai_strerror(rc));
		goto out;
	}
	
	fd = socket(host->ai_family, host->ai_socktype, host->ai_protocol);
	if (fd < 0) {
		perror("socket: ");
		goto out_freeaddrinfo;
	}

	if (bind(fd, host->ai_addr, host->ai_addrlen) < 0) {
		perror("bind: ");
		goto out_close_server;
	}

	memset(response, 'Z', SIZE_RESPONSE);

	listen(fd, 1);
	while (1) {
		char peer[1024];
		uint64_t delta;
		struct timespec start, finish;

		puts("server: waiting for connection");

		client = accept(fd, host->ai_addr, &host->ai_addrlen);
		if (client < 0) {
			perror("accept: ");
			goto out_close_server;
		}

		rc = getnameinfo(host->ai_addr, host->ai_addrlen,
				 peer, sizeof(peer), NULL, 0, 0);
		if (rc != 0) {
			fprintf(stderr, "error using getnameinfo: %s\n",
				gai_strerror(rc));
			continue;
		}

		printf("server: accept from %s\n", peer);

		if (no_delay)
			tcp_nodelay(client);

		clock_gettime(CLOCK_MONOTONIC, &start);
		if (rate) {
			struct timespec packet_start, packet_finish;

			packet_start = start;
			for (;;) {
				if (exchange_packet(client, cork) != 0)
					break;
				clock_gettime(CLOCK_MONOTONIC, &packet_finish);
				delta = timespec_delta(&packet_finish, &packet_start);
				if (delta > max)
					max = delta;
				if (delta < min)
					min = delta;
				if (avg == 0)
					avg = delta;
				else
					avg = (avg + delta) / 2;
				packet_start = packet_finish;
			}
			finish = packet_finish;
			printf("server: min=%lldns, max=%lldns, avg=%lldns\n",
			       (unsigned long long)min,
			       (unsigned long long)max,
			       (unsigned long long)avg);
		} else {
			while (exchange_packet(client, cork) == 0);
			clock_gettime(CLOCK_MONOTONIC, &finish);
		}
		delta = timespec_delta(&finish, &start);
		printf("server: received %d buffers, avg ipi: %lldns\n",
		       buffers_received,
		       (unsigned long long)(delta / buffers_received));
		buffers_received = 0;

		close(client);
	}
out_close_server:
	close(fd);
out_freeaddrinfo:
	freeaddrinfo(host);
out:
	return rc;
}
