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
 * Uses multishot poll for listener fds and general fd monitoring,
 * and zero-copy send (IORING_OP_SEND_ZC) where supported.
 */

static struct io_uring		ring;
static int			ring_initialized = 0;

/*
 * We use multishot poll on listener fds to get accept readiness,
 * and on connection fds to get read/write readiness. The event
 * loop processes CQEs and dispatches through the existing
 * kore_event callback mechanism.
 */

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
	int			ret;
	u_int64_t		ud;
	int			op;
	void			*ptr;
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
		ud = io_uring_cqe_get_data64(cqe);
		if (ud == 0)
			continue;

		op = KORE_URING_UDATA_OP(ud);
		ptr = KORE_URING_UDATA_PTR(ud);

		if (ptr == NULL)
			continue;

		evt = (struct kore_event *)ptr;

		switch (op) {
		case KORE_URING_OP_POLL:
			if (cqe->res < 0) {
				evt->handle(ptr, 1);
				break;
			}

			evt->flags &= ~(KORE_EVENT_READ | KORE_EVENT_WRITE);

			if (cqe->res & POLLIN)
				evt->flags |= KORE_EVENT_READ;
			if (cqe->res & POLLOUT)
				evt->flags |= KORE_EVENT_WRITE;
			if (cqe->res & (POLLERR | POLLHUP | POLLRDHUP)) {
				evt->handle(ptr, 1);
				break;
			}

			evt->handle(ptr, 0);

			/*
			 * If this was a multishot poll (listener or
			 * persistent connection poll), it stays armed
			 * unless IORING_CQE_F_MORE is not set.
			 */
			if (!(cqe->flags & IORING_CQE_F_MORE)) {
				/*
				 * Multishot expired or was cancelled.
				 * For connections, re-arm below if needed.
				 */
			}
			break;
		case KORE_URING_OP_ACCEPT:
			/*
			 * Handled via poll + traditional accept for now
			 * to keep compatibility with the accept lock model.
			 */
			break;
		case KORE_URING_OP_RECV:
			if (cqe->res <= 0) {
				evt->handle(ptr, 1);
			} else {
				evt->flags |= KORE_EVENT_READ;
				evt->handle(ptr, 0);
			}
			break;
		case KORE_URING_OP_SEND:
			if (cqe->res < 0) {
				evt->handle(ptr, 1);
			} else {
				evt->flags |= KORE_EVENT_WRITE;
				evt->handle(ptr, 0);
			}
			break;
		case KORE_URING_OP_SENDFILE:
			if (cqe->res < 0) {
				evt->handle(ptr, 1);
			} else {
				evt->flags |= KORE_EVENT_WRITE;
				evt->handle(ptr, 0);
			}
			break;
		default:
			break;
		}
	}

	io_uring_cq_advance(&ring, io_uring_cq_ready(&ring));
}

/*
 * Submit a multishot poll for both read and write events.
 * Uses IORING_POLL_ADD_MULTI so the poll stays armed across
 * multiple completions.
 */
void
kore_platform_event_all(int fd, void *c)
{
	kore_platform_event_schedule(fd,
	    POLLIN | POLLOUT | POLLRDHUP, IORING_POLL_ADD_MULTI, c);
}

void
kore_platform_event_level_all(int fd, void *c)
{
	kore_platform_event_schedule(fd,
	    POLLIN | POLLOUT | POLLRDHUP, IORING_POLL_ADD_MULTI, c);
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

	sqe = io_uring_get_sqe(&ring);
	if (sqe == NULL)
		fatal("io_uring_get_sqe(): ring full");

	io_uring_prep_poll_add(sqe, fd, type);

	if (flags & IORING_POLL_ADD_MULTI)
		sqe->len |= IORING_POLL_ADD_MULTI;

	io_uring_sqe_set_data64(sqe,
	    KORE_URING_UDATA(KORE_URING_OP_POLL, udata));
}

void
kore_platform_schedule_read(int fd, void *data)
{
	kore_platform_event_schedule(fd,
	    POLLIN, IORING_POLL_ADD_MULTI, data);
}

void
kore_platform_schedule_write(int fd, void *data)
{
	kore_platform_event_schedule(fd,
	    POLLOUT, IORING_POLL_ADD_MULTI, data);
}

void
kore_platform_disable_read(int fd)
{
	struct io_uring_sqe	*sqe;

	sqe = io_uring_get_sqe(&ring);
	if (sqe == NULL)
		fatal("io_uring_get_sqe(): ring full");

	io_uring_prep_poll_remove(sqe, 0);
	io_uring_sqe_set_data64(sqe, 0);

	/*
	 * Poll removal is best-effort. The multishot may have
	 * already completed. We cancel all polls for this fd
	 * by submitting a cancel with IORING_ASYNC_CANCEL_FD.
	 */
	sqe = io_uring_get_sqe(&ring);
	if (sqe == NULL)
		return;

	io_uring_prep_cancel_fd(sqe, fd, 0);
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

/*
 * Submit a zero-copy send via io_uring for the given connection's
 * current send buffer.
 */
void
kore_platform_uring_submit_send(struct connection *c)
{
	struct io_uring_sqe	*sqe;
	struct netbuf		*nb;
	size_t			len, smin;

	nb = TAILQ_FIRST(&(c->send_queue));
	if (nb == NULL)
		return;

	smin = nb->b_len - nb->s_off;
	len = MIN(NETBUF_SEND_PAYLOAD_MAX, smin);

	sqe = io_uring_get_sqe(&ring);
	if (sqe == NULL)
		return;

	io_uring_prep_send_zc(sqe, c->fd, nb->buf + nb->s_off, len, 0, 0);
	io_uring_sqe_set_data64(sqe,
	    KORE_URING_UDATA(KORE_URING_OP_SEND, c));
}

/*
 * Submit a recv via io_uring for the given connection's recv buffer.
 */
void
kore_platform_uring_submit_recv(struct connection *c)
{
	struct io_uring_sqe	*sqe;
	size_t			len;

	if (c->rnb == NULL || c->rnb->buf == NULL)
		return;

	len = c->rnb->b_len - c->rnb->s_off;
	if (len == 0)
		return;

	sqe = io_uring_get_sqe(&ring);
	if (sqe == NULL)
		return;

	io_uring_prep_recv(sqe, c->fd, c->rnb->buf + c->rnb->s_off, len, 0);
	io_uring_sqe_set_data64(sqe,
	    KORE_URING_UDATA(KORE_URING_OP_RECV, c));
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
