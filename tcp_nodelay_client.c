/*
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.

  Build it with:

  gcc tcp_nodelay_client.c -o tcp_nodelay_client -lrt
*/

#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define DEFAULT_PORT "5001"
#define DEFAULT_NR_LOGICAL_PACKETS 10000

static int verbose;
static int use_cork;
static int use_no_delay;
static int use_single_request;
static int use_header_plus_payload;

static int nr_logical_packets = DEFAULT_NR_LOGICAL_PACKETS;
static const char *port = DEFAULT_PORT;
static unsigned int rate;
static uint64_t interval;

#define __stringify_1(x) #x
#define __stringify(x) __stringify_1(x)

#ifndef __unused
#define __unused __attribute__ ((unused))
#endif

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

static void timespec_add(struct timespec *t, const uint64_t nsecs)
{
	t->tv_nsec += nsecs;
	while (t->tv_nsec >= NSEC_PER_SEC) {
		t->tv_sec++;
		t->tv_nsec -= NSEC_PER_SEC;
	}
}

#define NR_DATA_ENTRIES 100
#define SIZE_DATA_ENTRY 2
#define SIZE_RESPONSE 2

static char data[NR_DATA_ENTRIES][SIZE_DATA_ENTRY];

static int value;

static void tcp_nodelay(int fd)
{
	value = 1;
	if (setsockopt(fd, SOL_TCP, TCP_NODELAY, &value, sizeof(value)) != 0)
		perror("setsockopt(TCP_NODELAY):");
}

static void __tcp_cork(int fd, int cork)
{
	value = cork;
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

static void nread(int fd, char *bf, int len)
{
	do {
		int n = read(fd, bf, len);

		if (n < 0) {
			perror("client read:");
			exit(1);
		}

		len -= n;
		bf += n;
	} while (len != 0);
}

static void send_packet(int fd)
{
	int i;

	if (use_cork)
		tcp_cork(fd);

	if (use_single_request) {
		i = NR_DATA_ENTRIES * SIZE_DATA_ENTRY;
		if (write(fd, data, i) != i) {
			fprintf(stderr, "client: write failed!\n");
			exit(1);
		}
	} else if (use_header_plus_payload) {
		i = (NR_DATA_ENTRIES - 3) * SIZE_DATA_ENTRY;
		if (write(fd, data, 3 * SIZE_DATA_ENTRY) != 3 * SIZE_DATA_ENTRY) {
			fprintf(stderr, "client: write failed!\n");
			exit(1);
		}
		if (write(fd, &data[3], i) != i) {
			fprintf(stderr, "client: write failed!\n");
			exit(1);
		}
	} else for (i = 0; i < NR_DATA_ENTRIES; ++i) {
		if (write(fd, data[i], SIZE_DATA_ENTRY) != SIZE_DATA_ENTRY) {
			fprintf(stderr, "client: write failed!\n");
			exit(1);
		}
	}

	if (use_cork)
		tcp_uncork(fd);
}

static void exchange_packet(int fd)
{
	char response[SIZE_RESPONSE];

	send_packet(fd);
	nread(fd, response, SIZE_RESPONSE);
}

static const struct argp_option client_options[] = {
	{
		.key  = 'c',
		.name = "cork",
		.doc  = "use TCP_CORK",
	},
	{
		.key  = 'n',
		.name = "no_delay",
		.doc  = "use TCP_NODELAY",
	},
	{
		.key  = 'p',
		.name = "port",
		.arg  = "PORT",
		.doc  = "connect to PORT [DEFAULT=" DEFAULT_PORT "]",
	},
	{
		.key  = 'r',
		.name = "rate",
		.arg  = "RATE",
		.doc  = "Send RATE packets per second [DEFAULT=Don't rate limit]",
	},
	{
		.key  = 'H',
		.name = "header_plus_payload",
		.doc  = "send logical packets header + payload",
	},
	{
		.key  = 's',
		.name = "single_request",
		.doc  = "send logical packets as a single request",
	},
	{
		.key  = 'N',
		.name = "nr_logical_packets",
		.arg  = "NR",
		.doc  = "send NR logical packets [DEFAULT=" __stringify(DEFAULT_NR_LOGICAL_PACKETS) "]",
	},
	{
		.key  = 'v',
		.name = "verbose",
		.doc  = "be verbose",
	},
	{
		.name = NULL,
	}
};

static error_t client_options_parser(int key, char *arg __unused,
				     struct argp_state *state)
{
	switch (key) {
	case 'c': use_cork = 1;				break;
	case 'H': use_header_plus_payload = 1;		break;
	case 'n': use_no_delay = 1;			break;
	case 'p': port = arg;				break;
	case 'r': rate = atoi(arg);
		  interval = NSEC_PER_SEC / rate;	break;
	case 's': use_single_request = 1;		break;
	case 'v': verbose = 1;				break;
	case 'N': nr_logical_packets = atoi(arg);	break;
	default:  return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const char client_args_doc[] = "[SERVER]";

static struct argp client_argp = {
	.options  = client_options,
	.parser	  = client_options_parser,
	.args_doc = client_args_doc,
};

int main(int argc, char *argv[])
{
	struct timespec start, finish, next, left;
	float delta;
	float total_rate;
	struct addrinfo *host;
	struct addrinfo hints = {
		.ai_family   = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};
	char *hostname;
	int remaining, fd, i, rc;

	argp_parse(&client_argp, argc, argv, 0, &remaining, NULL);

	if (argc - remaining != 1) {
		argp_help(&client_argp, stderr, ARGP_HELP_SEE, "tcp_nodelay_client");
		return EXIT_FAILURE;
	}

	hostname = argv[remaining];

	rc = getaddrinfo(hostname, port, &hints, &host);
	if (rc != 0) {
		fprintf(stderr, "error using getaddrinfo: %s\n", gai_strerror(rc));
		goto out;
	}

	fd = socket(host->ai_family, host->ai_socktype, host->ai_protocol);
	if (fd < 0) {
		perror("socket: ");
		goto out_freeaddrinfo;
	}

	if (connect(fd, host->ai_addr, host->ai_addrlen) < 0) {
		perror("connect: ");
		goto out_close;
	}

	for (i = 0; i < NR_DATA_ENTRIES; ++i)
		memset(data[i], 'A' + i, SIZE_DATA_ENTRY);

	clock_gettime(CLOCK_MONOTONIC, &start);

	if (use_no_delay)
		tcp_nodelay(fd);

	i = nr_logical_packets;
	printf("rate: %d packets/s\n", rate);
	printf("interval: %lldns\n", (unsigned long long)interval);
	if (interval != 0) {
		next = start;
		timespec_add(&next, interval);
		while (i--) {
			send_packet(fd);
			if (clock_nanosleep(CLOCK_MONOTONIC,
					    TIMER_ABSTIME,
					    &next, &left) != 0) {
				printf("couldn't achieve a rate of %d packets/s!\n", rate);
				break;
			}
			timespec_add(&next, interval);
		}
	} else
		while (i--)
			exchange_packet(fd);

	clock_gettime(CLOCK_MONOTONIC, &finish);
	delta = timespec_delta(&finish, &start) / 1000000.0;

	total_rate = (nr_logical_packets * NR_DATA_ENTRIES * SIZE_DATA_ENTRY) / delta;

	if (verbose)
		printf("%d packets (%s) sent in %f ms: ",
		      nr_logical_packets,
		      use_header_plus_payload ? "2 buffers" :
		      use_single_request ? "1 buffer" : "100 buffers", delta);

	printf("%f", total_rate);
	
	if (verbose)
		printf(" bytes/ms %s",
		       use_cork ? "using TCP_CORK" : use_no_delay ? "using TCP_NODELAY" : "");
	putchar('\n');

	rc = 0;
out_close:
	close(fd);
out_freeaddrinfo:
	freeaddrinfo(host);
out:
	return rc;
}
