/*
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#define _GNU_SOURCE
#include <dlfcn.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <netinet/tcp.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#define LIBNAME "libautocork"
#define LIBC "libc.so.6"

#define FD_AUTOCORK_TABLE_NR_ENTRIES 512

static unsigned char fd_autocork_table[FD_AUTOCORK_TABLE_NR_ENTRIES];
static int first_autocork_fd = FD_AUTOCORK_TABLE_NR_ENTRIES;
static int last_autocork_fd;
static int nr_autocork_fds;

enum fd_flags {
	FDFL_AUTOCORK	= 1 << 1,
	FDFL_SENTDATA	= 1 << 2,
};

static int autocork_debug = -1;

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

#define hook(name) \
	if (libc_##name == NULL) \
		libc_##name = get_symbol(#name);

static int (*libc_setsockopt)(int s, int level, int optname,
			      const void *optval, socklen_t optlen);
	
int setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
{
	hook(setsockopt);

	if (autocork_debug == -1) {
		char *s = getenv("AUTOCORK_DEBUG");

		if (s == NULL)
			autocork_debug = 0; /* No debug */
		else
			autocork_debug = atoi(s);
	}

	if (level == SOL_TCP && optname == TCP_NODELAY) {
		int val = *(int *)optval;
		optname = TCP_CORK;

		if (val != 0) {
			if (!(fd_autocork_table[s] & FDFL_AUTOCORK)) {
				fd_autocork_table[s] = FDFL_AUTOCORK;
				++nr_autocork_fds;

				if (s < first_autocork_fd)
					first_autocork_fd = s;
				if (s > last_autocork_fd)
					last_autocork_fd = s;
			}
		} else if (fd_autocork_table[s] & FDFL_AUTOCORK) {
			fd_autocork_table[s] = 0;
			if (--nr_autocork_fds == 0) {
				first_autocork_fd = FD_AUTOCORK_TABLE_NR_ENTRIES;
				last_autocork_fd = 0;
			} else if (s == first_autocork_fd) {
				int i;
				for (i = first_autocork_fd + 1; i <= last_autocork_fd; ++i)
					if (fd_autocork_table[i] & FDFL_AUTOCORK) {
						first_autocork_fd = i;
						break;
					}
			} else if (s == last_autocork_fd) {
				int i;
				for (i = last_autocork_fd - 1; i >= first_autocork_fd; --i)
					if (fd_autocork_table[i] & FDFL_AUTOCORK) {
						last_autocork_fd = i;
						break;
					}
			}
		}

		if (autocork_debug > 0)
			fprintf(stderr, "%s: turning TCP_CORK %s fd %d\n",
				LIBNAME, fd_autocork_table[s] ? "ON" : "OFF", s);
	}

	return libc_setsockopt(s, level, optname, optval, optlen);
}

static inline void __push_pending_frames(int fd, const char *routine)
{
	int value = 0;

	if (autocork_debug > 1)
		fprintf(stderr, "%s: autocorking fd %d on %s\n",
			LIBNAME, fd, routine);
	libc_setsockopt(fd, SOL_TCP, TCP_CORK, &value, sizeof(value));
	value = 1;
	libc_setsockopt(fd, SOL_TCP, TCP_CORK, &value, sizeof(value));
	fd_autocork_table[fd] &= ~FDFL_SENTDATA;
}

#define push_pending_frames(fd) __push_pending_frames(fd, __func__)

static inline int pending_frames(const int fd)
{
	return fd_autocork_table[fd] & FDFL_SENTDATA;
}

static inline int autocork_needed(const int fd)
{
	return fd_autocork_table[fd] & FDFL_AUTOCORK;
}
	
ssize_t read(int fd, void *buf, size_t count)
{
	static int (*libc_read)(int fd, void *buf, size_t count);

	hook(read);

	if (pending_frames(fd))
		push_pending_frames(fd);

	return libc_read(fd, buf, count);
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
	static int (*libc_readv)(int fd, const struct iovec *iov, int iovcnt);

	hook(readv);

	if (pending_frames(fd))
		push_pending_frames(fd);

	return libc_readv(fd, iov, iovcnt);
}

ssize_t recv(int s, void *buf, size_t count, int flags)
{
	static int (*libc_recv)(int s, void *buf, size_t count, int flags);

	hook(recv);

	if (pending_frames(s))
		push_pending_frames(s);

	return libc_recv(s, buf, count, flags);
}

ssize_t recvmsg(int s, struct msghdr *msg, int flags)
{
	static int (*libc_recvmsg)(int s, struct msghdr *buf, int flags);

	hook(recvmsg);

	if (pending_frames(s))
		push_pending_frames(s);

	return libc_recvmsg(s, msg, flags);
}

ssize_t recvfrom(int s, void *buf, size_t len, int flags,
		 struct sockaddr *from, socklen_t *fromlen)
{
	static int (*libc_recvfrom)(int s, void *buf, size_t len, int flags,
				    struct sockaddr *from, socklen_t *fromlen);

	hook(recvfrom);

	if (pending_frames(s))
		push_pending_frames(s);

	return libc_recvfrom(s, buf, len, flags, from, fromlen);
}

static inline void select_check_fds(fd_set *readfds, const char *function)
{
	int fd;

	for (fd = first_autocork_fd; fd <= last_autocork_fd; ++fd)
		if (FD_ISSET(fd, readfds) && pending_frames(fd))
			__push_pending_frames(fd, function);
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
	   fd_set *exceptfds, struct timeval *timeout)
{
	static ssize_t (*libc_select)(int nfds, fd_set *readfds, fd_set *writefds,
				      fd_set *exceptfds, struct timeval *timeout);

	hook(select);

	if (readfds != NULL && nr_autocork_fds != 0)
		select_check_fds(readfds, __func__);

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
		select_check_fds(readfds, __func__);

	return libc_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

static inline void poll_check_fds(struct pollfd *fds, nfds_t nfds,
				  const char *function)
{
	int i;
	for (i = 0; i < nfds; ++i)
		if ((fds[i].events & POLLIN) && pending_frames(fds[i].fd))
			__push_pending_frames(fds[i].fd, function);
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	static ssize_t (*libc_poll)(struct pollfd *fds, nfds_t nfds, int timeout);

	hook(poll);

	if (nr_autocork_fds != 0)
		poll_check_fds(fds, nfds, __func__);

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
		poll_check_fds(fds, nfds, __func__);

	return libc_ppoll(fds, nfds, timeout, sigmask);
}

ssize_t write(int fd, const void *buf, size_t count)
{
	static ssize_t (*libc_write)(int fd, const void *buf, size_t count);

	hook(write);

	if (autocork_needed(fd))
		fd_autocork_table[fd] |= FDFL_SENTDATA;

	return libc_write(fd, buf, count);
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
	static ssize_t (*libc_writev)(int fd, const struct iovec *iov, int iovcnt);

	hook(writev);

	if (autocork_needed(fd))
		fd_autocork_table[fd] |= FDFL_SENTDATA;

	return libc_writev(fd, iov, iovcnt);
}

ssize_t send(int s, const void *buf, size_t len, int flags)
{
	static ssize_t (*libc_send)(int s, const void *buf, size_t len, int flags);

	hook(send);

	if (autocork_needed(s))
		fd_autocork_table[s] |= FDFL_SENTDATA;

	return libc_send(s, buf, len, flags);
}

ssize_t sendto(int s, const void *buf, size_t len, int flags,
	       const struct sockaddr *to, socklen_t tolen)
{
	static ssize_t (*libc_sendto)(int s, const void *buf, size_t len, int flags,
				      const struct sockaddr *to, socklen_t tolen);

	hook(sendto);

	if (autocork_needed(s))
		fd_autocork_table[s] |= FDFL_SENTDATA;

	return libc_sendto(s, buf, len, flags, to, tolen);
}

ssize_t sendmsg(int s, const struct msghdr *msg, int flags)
{
	static ssize_t (*libc_sendmsg)(int s, const struct msghdr *msg, int flags);

	hook(sendmsg);

	if (autocork_needed(s))
		fd_autocork_table[s] |= FDFL_SENTDATA;

	return libc_sendmsg(s, msg, flags);
}
