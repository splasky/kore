/*
 * Copyright (c) 2013-2022 Joris Vink <joris@coders.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>
#include <sys/random.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>

#include <poll.h>
#include <sched.h>

#include "kore.h"
#include "seccomp.h"

#if defined(KORE_USE_PGSQL)
#include "pgsql.h"
#endif

#if defined(KORE_USE_TASKS)
#include "tasks.h"
#endif

#if defined(KORE_USE_IO_URING)

/*
 * io_uring-based platform backend.
 *
 * Replaces the epoll event loop with io_uring for all I/O operations.
 * Uses multishot poll for POLLIN monitoring with generation-based
 * CQE validation to safely handle fd reuse after connection teardown.
 * POLLOUT is not monitored to avoid CQ flooding (the send queue is
 * flushed synchronously after http_process).
 */

static struct io_uring		ring;
static int			ring_initialized = 0;

/*
 * fd-indexed lookup table mapping file descriptors to their
 * kore_event owner, poll event mask, and generation counter.
 *
 * The generation counter solves the multishot poll stale-CQE problem:
 * when a connection is disconnected and its fd is reused by a new
 * connection, the old multishot poll may still have CQEs in-flight.
 * Each event_schedule increments the generation; CQEs carrying an
 * old generation are silently skipped.
 *
 * This avoids using io_uring cancel operations entirely, which
 * eliminates the race where cancel-by-fd accidentally cancels
 * a new connection's poll that reused the same fd number.
 */
#define FD_TABLE_SIZE		65536

struct fd_entry {
	void		*owner;
	int		events;
	u_int32_t	generation;
};

static struct fd_entry		fd_table[FD_TABLE_SIZE];

/*
 * Encode fd and generation into a single u64 for io_uring user_data.
 * Lower 32 bits = fd, upper 32 bits = generation.
 */
#define UDATA_ENCODE(fd, gen)	\
    (((u_int64_t)(gen) << 32) | ((u_int64_t)(u_int32_t)(fd)))
#define UDATA_FD(ud)		((int)((ud) & 0xffffffffULL))
#define UDATA_GEN(ud)		((u_int32_t)((ud) >> 32))

void
kore_platform_init(void)
{
	long		n;

	kore_seccomp_init();

	if ((n = sysconf(_SC_NPROCESSORS_ONLN)) == -1) {
		cpu_count = 1;
	} else {
		cpu_count = (u_int16_t)n;
	}
}

void
kore_platform_worker_setcpu(struct kore_worker *kw)
{
	cpu_set_t	cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(kw->cpu, &cpuset);

	if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) == -1)
		kore_log(LOG_NOTICE, "kore_worker_setcpu(): %s", errno_s);
}

void
kore_platform_event_init(void)
{
	u_int32_t	entries;

	if (ring_initialized) {
		io_uring_queue_exit(&ring);
		ring_initialized = 0;
	}

	entries = worker_max_connections + nlisteners;
	if (entries < 256)
		entries = 256;

	if (io_uring_queue_init(entries, &ring, 0) < 0)
		fatal("io_uring_queue_init(): %s", errno_s);

	ring_initialized = 1;
}

void
kore_platform_event_cleanup(void)
{
	if (ring_initialized) {
		memset(fd_table, 0, sizeof(fd_table));
		io_uring_queue_exit(&ring);
		ring_initialized = 0;
	}
}

void
kore_platform_event_wait(u_int64_t timer)
{
	struct io_uring_cqe	*cqe;
	struct __kernel_timespec	ts;
	unsigned		head;
	int			ret, fd;
	struct kore_event	*evt;

	if (timer == KORE_WAIT_INFINITE) {
		ret = io_uring_submit_and_wait(&ring, 1);
	} else {
		ts.tv_sec = timer / 1000;
		ts.tv_nsec = (timer % 1000) * 1000000;
		ret = io_uring_submit_and_wait_timeout(&ring, &cqe, 1,
		    &ts, NULL);
	}

	if (ret < 0 && ret != -ETIME && ret != -EINTR)
		fatal("io_uring_submit_and_wait: %s", strerror(-ret));

	io_uring_for_each_cqe(&ring, head, cqe) {
		u_int64_t	ud;
		u_int32_t	gen;

		ud = io_uring_cqe_get_data64(cqe);
		fd = UDATA_FD(ud);
		gen = UDATA_GEN(ud);

		if (fd <= 0 || fd >= FD_TABLE_SIZE)
			continue;

		/*
		 * Skip stale CQEs: either the fd has been
		 * unregistered (owner == NULL) or the generation
		 * doesn't match (fd was reused by a new connection).
		 */
		if (fd_table[fd].owner == NULL)
			continue;
		if (fd_table[fd].generation != gen)
			continue;

		evt = (struct kore_event *)fd_table[fd].owner;

		if (cqe->res < 0) {
			if (cqe->res != -ECANCELED)
				evt->handle(fd_table[fd].owner, 1);
			continue;
		}

		evt->flags &= ~(KORE_EVENT_READ | KORE_EVENT_WRITE);

		if (cqe->res & POLLIN) {
			evt->flags |= KORE_EVENT_READ;
			/*
			 * Always set WRITE so net_send_flush() can
			 * drain the send queue after http_process()
			 * queues a response. We don't monitor POLLOUT
			 * to avoid CQ flooding.
			 */
			evt->flags |= KORE_EVENT_WRITE;
		}
		if (cqe->res & POLLOUT)
			evt->flags |= KORE_EVENT_WRITE;

		if (cqe->res & (POLLERR | POLLHUP | POLLRDHUP)) {
			evt->handle(fd_table[fd].owner, 1);
		} else {
			evt->handle(fd_table[fd].owner, 0);
		}
	}

	io_uring_cq_advance(&ring, io_uring_cq_ready(&ring));
}

void
kore_platform_event_all(int fd, void *c)
{
	/*
	 * Only monitor POLLIN. POLLOUT is not monitored because
	 * io_uring multishot poll is level-triggered, which would
	 * flood the CQ with continuous POLLOUT CQEs (the socket
	 * buffer is almost always writable). Instead, we set
	 * KORE_EVENT_WRITE on every POLLIN delivery so that
	 * net_send_flush() can run when the connection handler
	 * or http_process() calls it.
	 */
	kore_platform_event_schedule(fd,
	    POLLIN | POLLRDHUP, IORING_POLL_ADD_MULTI, c);
}

void
kore_platform_event_level_all(int fd, void *c)
{
	kore_platform_event_schedule(fd,
	    POLLIN | POLLRDHUP, IORING_POLL_ADD_MULTI, c);
}

void
kore_platform_event_level_read(int fd, void *c)
{
	kore_platform_event_schedule(fd,
	    POLLIN | POLLRDHUP, IORING_POLL_ADD_MULTI, c);
}

void
kore_platform_event_schedule(int fd, int type, int flags, void *udata)
{
	struct io_uring_sqe	*sqe;

	if (fd < 0 || fd >= FD_TABLE_SIZE)
		fatal("fd %d out of fd_table range", fd);

	fd_table[fd].owner = udata;
	fd_table[fd].events = type;
	fd_table[fd].generation++;

	sqe = io_uring_get_sqe(&ring);
	if (sqe == NULL)
		fatal("io_uring_get_sqe(): ring full");

	io_uring_prep_poll_add(sqe, fd, type);

	if (flags & IORING_POLL_ADD_MULTI)
		sqe->len |= IORING_POLL_ADD_MULTI;

	io_uring_sqe_set_data64(sqe,
	    UDATA_ENCODE(fd, fd_table[fd].generation));
}

void
kore_platform_schedule_read(int fd, void *data)
{
	kore_platform_event_schedule(fd, POLLIN, IORING_POLL_ADD_MULTI, data);
}

void
kore_platform_schedule_write(int fd, void *data)
{
	kore_platform_event_schedule(fd, POLLOUT, IORING_POLL_ADD_MULTI, data);
}

void
kore_platform_disable_read(int fd)
{
	struct io_uring_sqe	*sqe;
	u_int64_t		ud;

	if (fd < 0 || fd >= FD_TABLE_SIZE)
		return;

	/*
	 * Cancel the multishot poll by its exact user_data value
	 * (fd + generation). This ensures we only cancel THIS
	 * poll, not a new poll on a reused fd with a different
	 * generation. The generation check in event_wait provides
	 * a second safety net for any CQEs that arrive between
	 * clearing the table and the cancel taking effect.
	 */
	ud = UDATA_ENCODE(fd, fd_table[fd].generation);

	fd_table[fd].owner = NULL;
	fd_table[fd].events = 0;

	if (!ring_initialized)
		return;

	sqe = io_uring_get_sqe(&ring);
	if (sqe == NULL)
		return;

	io_uring_prep_cancel64(sqe, ud, 0);
	io_uring_sqe_set_data64(sqe, 0);
}

void
kore_platform_enable_accept(void)
{
	struct listener		*l;
	struct kore_server	*srv;

	LIST_FOREACH(srv, &kore_servers, list) {
		LIST_FOREACH(l, &srv->listeners, list) {
			kore_platform_event_schedule(l->fd,
			    POLLIN, IORING_POLL_ADD_MULTI, l);
		}
	}
}

void
kore_platform_disable_accept(void)
{
	struct listener		*l;
	struct kore_server	*srv;

	LIST_FOREACH(srv, &kore_servers, list) {
		LIST_FOREACH(l, &srv->listeners, list)
			kore_platform_disable_read(l->fd);
	}
}

void
kore_platform_proctitle(const char *title)
{
	kore_proctitle(title);
}

#if defined(KORE_USE_PLATFORM_SENDFILE)
int
kore_platform_sendfile(struct connection *c, struct netbuf *nb)
{
	struct io_uring_sqe	*sqe;
	off_t			smin;
	size_t			len;

	smin = nb->fd_len - nb->fd_off;
	len = MIN(SENDFILE_PAYLOAD_MAX, smin);

	sqe = io_uring_get_sqe(&ring);
	if (sqe == NULL) {
		/*
		 * Ring is full, tell caller to retry. Clear WRITE
		 * flag so the event loop will re-trigger us.
		 */
		c->evt.flags &= ~KORE_EVENT_WRITE;
		return (KORE_RESULT_OK);
	}

	/*
	 * Use splice for zero-copy file->socket transfer via io_uring.
	 * First splice from file to pipe, then from pipe to socket.
	 * For simplicity we use sendmsg with the file data.
	 *
	 * Actually, the cleanest approach with io_uring is to just
	 * use IORING_OP_SPLICE or fall back to sendfile(2) via
	 * poll-driven path. We use the traditional sendfile here
	 * submitted synchronously since io_uring splice requires
	 * a pipe intermediary. The poll model ensures the fd is ready.
	 */
	{
		ssize_t		sent;
		size_t		prevoff;

		prevoff = nb->fd_off;
resend:
		sent = sendfile(c->fd, nb->file_ref->fd, &nb->fd_off, len);
		if (sent == -1) {
			if (errno == EAGAIN) {
				c->evt.flags &= ~KORE_EVENT_WRITE;
				return (KORE_RESULT_OK);
			}
			return (KORE_RESULT_ERROR);
		}

		if (nb->fd_off - prevoff != (size_t)len)
			goto resend;

		if (sent == 0 || nb->fd_off == nb->fd_len) {
			net_remove_netbuf(c, nb);
			c->snb = NULL;
		}
	}

	return (KORE_RESULT_OK);
}
#endif

void
kore_platform_sandbox(void)
{
	kore_seccomp_enable();
}

u_int32_t
kore_platform_random_uint32(void)
{
	ssize_t		ret;
	u_int32_t	val;

	if ((ret = getrandom(&val, sizeof(val), 0)) == -1)
		fatalx("getrandom(): %s", errno_s);

	if ((size_t)ret != sizeof(val))
		fatalx("getrandom() %zd != %zu", ret, sizeof(val));

	return (val);
}

#else /* !KORE_USE_IO_URING -- legacy epoll backend */

#include <sys/epoll.h>
#include <sys/sendfile.h>

static int			efd = -1;
static u_int32_t		event_count = 0;
static struct epoll_event	*events = NULL;

void
kore_platform_init(void)
{
	long		n;

	kore_seccomp_init();

	if ((n = sysconf(_SC_NPROCESSORS_ONLN)) == -1) {
		cpu_count = 1;
	} else {
		cpu_count = (u_int16_t)n;
	}
}

void
kore_platform_worker_setcpu(struct kore_worker *kw)
{
	cpu_set_t	cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(kw->cpu, &cpuset);

	if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) == -1)
		kore_log(LOG_NOTICE, "kore_worker_setcpu(): %s", errno_s);
}

void
kore_platform_event_init(void)
{
	if (efd != -1)
		close(efd);
	if (events != NULL)
		kore_free(events);

	if ((efd = epoll_create(10000)) == -1)
		fatal("epoll_create(): %s", errno_s);

	event_count = worker_max_connections + nlisteners;
	events = kore_calloc(event_count, sizeof(struct epoll_event));
}

void
kore_platform_event_cleanup(void)
{
	if (efd != -1) {
		close(efd);
		efd = -1;
	}

	if (events != NULL) {
		kore_free(events);
		events = NULL;
	}
}

void
kore_platform_event_wait(u_int64_t timer)
{
	u_int32_t		r;
	struct kore_event	*evt;
	int			n, i, timeo;

	if (timer == KORE_WAIT_INFINITE)
		timeo = -1;
	else
		timeo = timer;

	n = epoll_wait(efd, events, event_count, timeo);
	if (n == -1) {
		if (errno == EINTR)
			return;
		fatal("epoll_wait(): %s", errno_s);
	}

	r = 0;
	for (i = 0; i < n; i++) {
		if (events[i].data.ptr == NULL)
			fatal("events[%d].data.ptr == NULL", i);

		r = 0;
		evt = (struct kore_event *)events[i].data.ptr;

		if (events[i].events & EPOLLIN)
			evt->flags |= KORE_EVENT_READ;

		if (events[i].events & EPOLLOUT)
			evt->flags |= KORE_EVENT_WRITE;

		if (events[i].events & EPOLLERR ||
		    events[i].events & EPOLLHUP ||
		    events[i].events & EPOLLRDHUP)
			r = 1;

		evt->handle(events[i].data.ptr, r);
	}
}

void
kore_platform_event_level_all(int fd, void *c)
{
	kore_platform_event_schedule(fd, EPOLLIN | EPOLLOUT | EPOLLRDHUP, 0, c);
}

void
kore_platform_event_level_read(int fd, void *c)
{
	kore_platform_event_schedule(fd, EPOLLIN | EPOLLRDHUP, 0, c);
}

void
kore_platform_event_all(int fd, void *c)
{
	kore_platform_event_schedule(fd,
	    EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET, 0, c);
}

void
kore_platform_event_schedule(int fd, int type, int flags, void *udata)
{
	struct epoll_event	evt;

	evt.events = type;
	evt.data.ptr = udata;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &evt) == -1) {
		if (errno == EEXIST) {
			if (epoll_ctl(efd, EPOLL_CTL_MOD, fd, &evt) == -1)
				fatal("epoll_ctl() MOD: %s", errno_s);
		} else {
			fatal("epoll_ctl() ADD: %s", errno_s);
		}
	}
}

void
kore_platform_schedule_read(int fd, void *data)
{
	kore_platform_event_schedule(fd, EPOLLIN | EPOLLET, 0, data);
}

void
kore_platform_schedule_write(int fd, void *data)
{
	kore_platform_event_schedule(fd, EPOLLOUT | EPOLLET, 0, data);
}

void
kore_platform_disable_read(int fd)
{
	if (epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL) == -1)
		fatal("kore_platform_disable_read: %s", errno_s);
}

void
kore_platform_enable_accept(void)
{
	struct listener		*l;
	struct kore_server	*srv;

	LIST_FOREACH(srv, &kore_servers, list) {
		LIST_FOREACH(l, &srv->listeners, list)
			kore_platform_event_schedule(l->fd, EPOLLIN, 0, l);
	}
}

void
kore_platform_disable_accept(void)
{
	struct listener		*l;
	struct kore_server	*srv;

	LIST_FOREACH(srv, &kore_servers, list) {
		LIST_FOREACH(l, &srv->listeners, list) {
			if (epoll_ctl(efd, EPOLL_CTL_DEL, l->fd, NULL) == -1) {
				fatal("kore_platform_disable_accept: %s",
				    errno_s);
			}
		}
	}
}

void
kore_platform_proctitle(const char *title)
{
	kore_proctitle(title);
}

#if defined(KORE_USE_PLATFORM_SENDFILE)
int
kore_platform_sendfile(struct connection *c, struct netbuf *nb)
{
	off_t		smin;
	ssize_t		sent;
	size_t		len, prevoff;

	prevoff = nb->fd_off;
	smin = nb->fd_len - nb->fd_off;
	len = MIN(SENDFILE_PAYLOAD_MAX, smin);

resend:
	sent = sendfile(c->fd, nb->file_ref->fd, &nb->fd_off, len);
	if (sent == -1) {
		if (errno == EAGAIN) {
			c->evt.flags &= ~KORE_EVENT_WRITE;
			return (KORE_RESULT_OK);
		}

		return (KORE_RESULT_ERROR);
	}

	if (nb->fd_off - prevoff != (size_t)len)
		goto resend;

	if (sent == 0 || nb->fd_off == nb->fd_len) {
		net_remove_netbuf(c, nb);
		c->snb = NULL;
	}

	return (KORE_RESULT_OK);
}
#endif

void
kore_platform_sandbox(void)
{
	kore_seccomp_enable();
}

u_int32_t
kore_platform_random_uint32(void)
{
	ssize_t		ret;
	u_int32_t	val;

	if ((ret = getrandom(&val, sizeof(val), 0)) == -1)
		fatalx("getrandom(): %s", errno_s);

	if ((size_t)ret != sizeof(val))
		fatalx("getrandom() %zd != %zu", ret, sizeof(val));

	return (val);
}

#endif /* KORE_USE_IO_URING */
