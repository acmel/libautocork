/*
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2.1 of the GNU Lesser General Public License as
  published by the Free Software Foundation.
*/

#define _GNU_SOURCE
#include <dlfcn.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

#include <netinet/tcp.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#define LIBNAME "libautocork"
#define LIBC "libc.so.6"

static int autocork_debug = -1;

/* If non-zero says how many app buffers can be autocorked */
static int autocork_max_qlen;

static unsigned int dump_interval = 300; /* 5 minutes */

#define NSEC_PER_SEC 1000000000L
#define USEC_PER_SEC 1000000L
#define NSEC_PER_USEC 1000L

static inline unsigned long timespec_delta_us(const struct timespec *lhs,
					      const struct timespec *rhs)
{
	long sec = lhs->tv_sec - rhs->tv_sec;
	long nsec = lhs->tv_nsec - rhs->tv_nsec;

	while (nsec >= NSEC_PER_SEC) {
		nsec -= NSEC_PER_SEC;
		++sec;
	}
	while (nsec < 0) {
		nsec += NSEC_PER_SEC;
		--sec;
	}
	return sec * USEC_PER_SEC + nsec / NSEC_PER_USEC;
}

/**
 * ewma  -  Exponentially weighted moving average
 * @weight: Weight to be used as damping factor, in units of 1/10
 */
static inline unsigned long ewma(const unsigned long avg,
				 const unsigned long newval,
				 const unsigned char weight)
{
	return avg ? (weight * avg + (10 - weight) * newval) / 10 : newval;
}

struct stats {
	unsigned int nr_samples;
	unsigned int avg;
	unsigned int max;
	unsigned int min;
};

void stats__add_sample(struct stats *self, unsigned long sample)
{
	if (self->nr_samples++ != 0) {
		self->avg = ewma(self->avg, sample, 9);
		if (sample > self->max)
			self->max = sample;
		if (sample < self->min)
			self->min = sample;
	} else
		self->avg = self->min = self->max = sample;
}

enum uncorkers {
	UNCORKER_poll	  = 1 << 0,
	UNCORKER_ppoll	  = 1 << 1,
	UNCORKER_pselect  = 1 << 2,
	UNCORKER_read	  = 1 << 3,
	UNCORKER_readv	  = 1 << 4,
	UNCORKER_recv	  = 1 << 5,
	UNCORKER_recvfrom = 1 << 6,
	UNCORKER_recvmsg  = 1 << 7,
	UNCORKER_select	  = 1 << 8,
	UNCORKER_check_qlen  = 1 << 9,
};

static const char *uncorkers_str[] = {
	"poll",
	"ppoll",
	"pselect",
	"read",
	"readv",
	"recv",
	"recvfrom",
	"recvmsg",
	"select",
	"check_qlen",
};

static void fprintf_uncorkers(FILE *fp, int mask)
{
	int i = 0, first = 1;

	while (mask != 0) {
		if (mask & 1) {
			if (!first)
				fputc(',', fp);
			else
				first = 0;
			fputs(uncorkers_str[i], fp);
		}
		++i;
		mask >>= 1;
	}
}

struct file {
	unsigned short	pending_frames;
	unsigned short  uncorkers;
	unsigned char	autocork;
	struct stats	lat_stats;
	struct stats	pktsize_stats;
	struct stats	qlen_stats;
	struct timespec tstamp;
};

#define FD_AUTOCORK_TABLE_NR_ENTRIES 512

static struct file fd_autocork_table[FD_AUTOCORK_TABLE_NR_ENTRIES];
static int first_autocork_fd = FD_AUTOCORK_TABLE_NR_ENTRIES;
static int last_autocork_fd;
static int nr_autocork_fds;

static inline int autocork_needed(const int fd)
{
	return fd_autocork_table[fd].autocork;
}

static inline void take_tstamp(const int fd)
{
	clock_gettime(CLOCK_MONOTONIC, &fd_autocork_table[fd].tstamp);
}

void *get_symbol(char *symbol)
{
	static void *libc;
	void *sympointer;
	char *err;

	if (libc == NULL) {
		libc = dlopen(LIBC, RTLD_LAZY);
		if (libc == NULL) {
			fprintf(stderr, "%s: unable to dlopen %s\n", LIBNAME, LIBC);
			exit(-1);
		}
	}

	sympointer = dlsym(libc, symbol);
	err = dlerror();
	if (err != NULL) {
		fprintf(stderr, "%s: %s\n", LIBNAME, err);
		exit(-1);
	}
	return sympointer;
}

static void libautocork__fprintf_stats(FILE *fp)
{
	int fd;

	for (fd = 0; fd < FD_AUTOCORK_TABLE_NR_ENTRIES; ++fd) {
		if (fd_autocork_table[fd].lat_stats.nr_samples != 0) {
			fprintf(fp, "%d: %u %u %u %u %u %u %u %u %u %u %u ", fd,
				fd_autocork_table[fd].lat_stats.nr_samples,
				fd_autocork_table[fd].lat_stats.avg,
				fd_autocork_table[fd].lat_stats.min,
				fd_autocork_table[fd].lat_stats.max,
				fd_autocork_table[fd].qlen_stats.avg,
				fd_autocork_table[fd].qlen_stats.min,
				fd_autocork_table[fd].qlen_stats.max,
				fd_autocork_table[fd].pktsize_stats.nr_samples,
				fd_autocork_table[fd].pktsize_stats.avg,
				fd_autocork_table[fd].pktsize_stats.min,
				fd_autocork_table[fd].pktsize_stats.max);
			fprintf_uncorkers(fp, fd_autocork_table[fd].uncorkers);
			fprintf(fp, " %d\n", autocork_max_qlen);
		}
	}
	fflush(fp);
}

static FILE *dump_fp;

static void libautocork__exit(void)
{
	if (dump_fp != NULL) {
		libautocork__fprintf_stats(dump_fp);
		fclose(dump_fp);
	}
}

static void libautocork__init(void)
{
	char *s = getenv("AUTOCORK_DEBUG");

	autocork_debug = 0; /* No debug */
	if (s != NULL)
		autocork_debug = atoi(s);

	s = getenv("AUTOCORK_DUMP_INTERVAL");
	if (s != NULL)
		dump_interval = atoi(s);

	s = getenv("AUTOCORK_MAX_QLEN");
	if (s != NULL)
		autocork_max_qlen = atoi(s);

	if (dump_interval != 0) {
		char filename[PATH_MAX];

		snprintf(filename, sizeof(filename), "%s/libautocork.%d.debug",
			 getenv("HOME"), getpid());
		dump_fp = fopen(filename, "w");
		if (dump_fp != NULL)
			fputs("# fd: corklat:samples avg min max qlen:avg min max pktsz:samples avg min max uncorkers envmaxqlen\n", dump_fp);
	}

	atexit(libautocork__exit);
}

#define hook(name) \
	if (libc_##name == NULL) \
		libc_##name = get_symbol(#name);

static int (*libc_setsockopt)(int s, int level, int optname,
			      const void *optval, socklen_t optlen);
	
int setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
{
	hook(setsockopt);

	if (autocork_debug == -1)
		libautocork__init();

	if (level == SOL_TCP && optname == TCP_NODELAY) {
		int val = *(int *)optval;
		optname = TCP_CORK;

		if (val != 0) {
			if (!autocork_needed(s)) {
				fd_autocork_table[s].autocork = 1;
				fd_autocork_table[s].pending_frames = 0;
				++nr_autocork_fds;

				if (s < first_autocork_fd)
					first_autocork_fd = s;
				if (s > last_autocork_fd)
					last_autocork_fd = s;
			}
		} else if (autocork_needed(s)) {
			fd_autocork_table[s].autocork = 0;
			fd_autocork_table[s].pending_frames = 0;
			if (--nr_autocork_fds == 0) {
				first_autocork_fd = FD_AUTOCORK_TABLE_NR_ENTRIES;
				last_autocork_fd = 0;
			} else if (s == first_autocork_fd) {
				int i;
				for (i = first_autocork_fd + 1; i <= last_autocork_fd; ++i)
					if (autocork_needed(i)) {
						first_autocork_fd = i;
						break;
					}
			} else if (s == last_autocork_fd) {
				int i;
				for (i = last_autocork_fd - 1; i >= first_autocork_fd; --i)
					if (autocork_needed(i)) {
						last_autocork_fd = i;
						break;
					}
			}
		}

		if (autocork_debug > 0)
			fprintf(stderr, "%s: turning TCP_CORK %s fd %d\n",
				LIBNAME, fd_autocork_table[s].autocork ? "ON" : "OFF", s);
	}

	return libc_setsockopt(s, level, optname, optval, optlen);
}

static inline void __push_pending_frames(int fd, const int uncorker, const char *routine)
{
	int value = 0;

	if (autocork_debug > 1)
		fprintf(stderr, "%s: autocorking fd %d on %s\n",
			LIBNAME, fd, routine);
	libc_setsockopt(fd, SOL_TCP, TCP_CORK, &value, sizeof(value));

	if (dump_interval != 0) {
		struct timespec now;
		static struct timespec last_stat_dump;

		clock_gettime(CLOCK_MONOTONIC, &now);
		stats__add_sample(&fd_autocork_table[fd].lat_stats,
				  timespec_delta_us(&now, &fd_autocork_table[fd].tstamp));
		stats__add_sample(&fd_autocork_table[fd].qlen_stats,
				  fd_autocork_table[fd].pending_frames);
		fd_autocork_table[fd].uncorkers |= uncorker;

		if (now.tv_sec - last_stat_dump.tv_sec > dump_interval) {
			libautocork__fprintf_stats(dump_fp);
			last_stat_dump = now;
		}
	}

	fd_autocork_table[fd].pending_frames = 0;
}

#define push_pending_frames(fd, routine) __push_pending_frames(fd, UNCORKER_##routine, #routine)

static inline int pending_frames(const int fd)
{
	return fd_autocork_table[fd].pending_frames;
}
	
ssize_t read(int fd, void *buf, size_t count)
{
	static int (*libc_read)(int fd, void *buf, size_t count);

	hook(read);

	if (pending_frames(fd))
		push_pending_frames(fd, read);

	return libc_read(fd, buf, count);
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
	static int (*libc_readv)(int fd, const struct iovec *iov, int iovcnt);

	hook(readv);

	if (pending_frames(fd))
		push_pending_frames(fd, readv);

	return libc_readv(fd, iov, iovcnt);
}

ssize_t recv(int s, void *buf, size_t count, int flags)
{
	static int (*libc_recv)(int s, void *buf, size_t count, int flags);

	hook(recv);

	if (pending_frames(s))
		push_pending_frames(s, recv);

	return libc_recv(s, buf, count, flags);
}

ssize_t recvmsg(int s, struct msghdr *msg, int flags)
{
	static int (*libc_recvmsg)(int s, struct msghdr *buf, int flags);

	hook(recvmsg);

	if (pending_frames(s))
		push_pending_frames(s, recvmsg);

	return libc_recvmsg(s, msg, flags);
}

ssize_t recvfrom(int s, void *buf, size_t len, int flags,
		 struct sockaddr *from, socklen_t *fromlen)
{
	static int (*libc_recvfrom)(int s, void *buf, size_t len, int flags,
				    struct sockaddr *from, socklen_t *fromlen);

	hook(recvfrom);

	if (pending_frames(s))
		push_pending_frames(s, recvfrom);

	return libc_recvfrom(s, buf, len, flags, from, fromlen);
}

static inline void __select_check_fds(fd_set *readfds, const int uncorker,
				      const char *function)
{
	int fd;

	for (fd = first_autocork_fd; fd <= last_autocork_fd; ++fd)
		if (FD_ISSET(fd, readfds) && pending_frames(fd))
			__push_pending_frames(fd, uncorker, function);
}

#define select_check_fds(readfds, routine) \
	__select_check_fds(readfds, UNCORKER_##routine, #routine)

int select(int nfds, fd_set *readfds, fd_set *writefds,
	   fd_set *exceptfds, struct timeval *timeout)
{
	static ssize_t (*libc_select)(int nfds, fd_set *readfds, fd_set *writefds,
				      fd_set *exceptfds, struct timeval *timeout);

	hook(select);

	if (readfds != NULL && nr_autocork_fds != 0)
		select_check_fds(readfds, select);

	return libc_select(nfds, readfds, writefds, exceptfds, timeout);
}

int pselect(int nfds, fd_set *readfds, fd_set *writefds,
	    fd_set *exceptfds, const struct timespec *timeout,
	    const sigset_t *sigmask)
{
	static ssize_t (*libc_pselect)(int nfds, fd_set *readfds, fd_set *writefds,
				       fd_set *exceptfds, const struct timespec *timeout,
				       const sigset_t *sigmask);

	hook(pselect);

	if (readfds != NULL && nr_autocork_fds != 0)
		select_check_fds(readfds, pselect);

	return libc_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

static inline void __poll_check_fds(struct pollfd *fds, nfds_t nfds,
				    const int uncorker, const char *function)
{
	int i;
	for (i = 0; i < nfds; ++i)
		if ((fds[i].events & POLLIN) && pending_frames(fds[i].fd))
			__push_pending_frames(fds[i].fd, uncorker, function);
}

#define poll_check_fds(fds, nfds, routine) \
	__poll_check_fds(fds, nfds, UNCORKER_##routine, #routine)

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	static ssize_t (*libc_poll)(struct pollfd *fds, nfds_t nfds, int timeout);

	hook(poll);

	if (nr_autocork_fds != 0)
		poll_check_fds(fds, nfds, poll);

	return libc_poll(fds, nfds, timeout);
}

int ppoll(struct pollfd *fds, nfds_t nfds,
	  const struct timespec *timeout, const sigset_t *sigmask)
{
	static ssize_t (*libc_ppoll)(struct pollfd *fds, nfds_t nfds,
				     const struct timespec *timeout,
				     const sigset_t *sigmask);

	hook(ppoll);

	if (nr_autocork_fds != 0)
		poll_check_fds(fds, nfds, ppoll);

	return libc_ppoll(fds, nfds, timeout, sigmask);
}

static void set_pending_frames(int fd, size_t len)
{
	if (!pending_frames(fd)) {
		int value = 1;
		take_tstamp(fd);
		libc_setsockopt(fd, SOL_TCP, TCP_CORK, &value, sizeof(value));
	}

	++fd_autocork_table[fd].pending_frames;
	stats__add_sample(&fd_autocork_table[fd].pktsize_stats, len);
}

static void check_qlen(int fd)
{
	if (autocork_max_qlen != 0 &&
	    autocork_needed(fd) &&
	    fd_autocork_table[fd].pending_frames >= autocork_max_qlen)
		push_pending_frames(fd, check_qlen);
}

ssize_t write(int fd, const void *buf, size_t count)
{
	static ssize_t (*libc_write)(int fd, const void *buf, size_t count);
	ssize_t rc;

	hook(write);

	if (autocork_needed(fd))
		set_pending_frames(fd, count);

	rc = libc_write(fd, buf, count);
	check_qlen(fd);
	return rc;
}

static size_t iov_totlen(const struct iovec *iov, int iovcnt)
{
	int i, len = 0;

	for (i = 0; i < iovcnt; ++i)
		len += iov[i].iov_len;

	return len;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
	static ssize_t (*libc_writev)(int fd, const struct iovec *iov, int iovcnt);
	ssize_t rc;

	hook(writev);

	if (autocork_needed(fd))
		set_pending_frames(fd, iov_totlen(iov, iovcnt));

	rc = libc_writev(fd, iov, iovcnt);
	check_qlen(fd);
	return rc;
}

ssize_t send(int s, const void *buf, size_t len, int flags)
{
	static ssize_t (*libc_send)(int s, const void *buf, size_t len, int flags);
	ssize_t rc;

	hook(send);

	if (autocork_needed(s))
		set_pending_frames(s, len);

	rc = libc_send(s, buf, len, flags);
	check_qlen(s);
	return rc;
}

ssize_t sendto(int s, const void *buf, size_t len, int flags,
	       const struct sockaddr *to, socklen_t tolen)
{
	static ssize_t (*libc_sendto)(int s, const void *buf, size_t len, int flags,
				      const struct sockaddr *to, socklen_t tolen);
	ssize_t rc;

	hook(sendto);

	if (autocork_needed(s))
		set_pending_frames(s, len);

	rc = libc_sendto(s, buf, len, flags, to, tolen);
	check_qlen(s);
	return rc;
}

ssize_t sendmsg(int s, const struct msghdr *msg, int flags)
{
	static ssize_t (*libc_sendmsg)(int s, const struct msghdr *msg, int flags);
	ssize_t rc;

	hook(sendmsg);

	if (autocork_needed(s))
		set_pending_frames(s, iov_totlen(msg->msg_iov, msg->msg_iovlen));

	rc = libc_sendmsg(s, msg, flags);
	check_qlen(s);
	return rc;
}
