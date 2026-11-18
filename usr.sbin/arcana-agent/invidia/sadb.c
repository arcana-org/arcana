/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: what the kernel's PF_KEY says of the host's SAs and policies,
 * told as RFC 9061's IKE-less notifications (ietf-i2nsf-ikeless,
 * PLAN-SDN-YANG 6.2.3).  A thread of its own holds a PF_KEY socket
 * SADB_REGISTERed for ESP, to which the kernel sends, as they happen:
 *
 *	SADB_ACQUIRE	an outbound packet met a policy whose SA is not
 *			there (key_acquire()): sadb-acquire, the policy
 *			and its selector, read by SADB_X_SPDDUMP by the
 *			policy's id
 *	SADB_EXPIRE	an SA's soft or hard lifetime is reached
 *			(key_expire()): sadb-expire, soft or not, with what
 *			the SA has carried and how long it has been there
 *
 * The kernel has no message for an SA's sequence number running out:
 * every SADB_CHECK seconds the SAs are dumped (SADB_DUMP) and each
 * without ESN whose counter (SADB_X_EXT_SA2's, the packets sent on it)
 * is past SEQ_NEAR, an eighth of the space from its end, is told once as
 * sadb-seq-overflow.  The counter is the low 32 bits alone (key.c's
 * key_setsadbxsa2()), so an SA with ESN is never told.
 *
 * Names: RFC 9061 names an SA and a policy by the controller's names,
 * the IKE-less lists' (6.2.4); until those, the kernel's own: an SA
 * "esp/<destination>/0x<SPI>", unique as the kernel's key is, a policy
 * "spd/<its id>".  The host's network only: a vnet jail's PF_KEY is
 * its own and is not watched.  Where PF_KEY cannot be opened (no
 * ipsec.ko) it is tried again every SADB_RETRY seconds, said once.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <net/pfkeyv2.h>
#include <netinet/in.h>
#include <netipsec/ipsec.h>

#include <arpa/inet.h>

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"
#include "collect.h"

#define	SADB_CHECK	10		/* seconds between the counters' reads */
#define	SADB_RETRY	60		/* seconds before PF_KEY is tried again */
#define	SEQ_NEAR	0xe0000000u	/* a counter this far is told */
#define	SEQ_TOLD	256		/* the SAs told, remembered */

/* The SAs told of their counters, so that each is told once. */
static struct told {
	struct sockaddr_storage	dst;
	uint32_t		spi;
} told[SEQ_TOLD];
static size_t	ntold;

/* An address as text; "" none. */
static void
addr_text(const struct sockaddr_storage *ss, char *b, size_t len)
{
	const void	*v = ss;

	b[0] = '\0';
	if (ss->ss_family == AF_INET)
		inet_ntop(AF_INET, &((const struct sockaddr_in *)v)->sin_addr,
		    b, len);
	else if (ss->ss_family == AF_INET6)
		inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)v)->
		    sin6_addr, b, len);
}

static uint16_t
addr_port(const struct sockaddr_storage *ss)
{
	const void	*v = ss;

	if (ss->ss_family == AF_INET)
		return (ntohs(((const struct sockaddr_in *)v)->sin_port));
	if (ss->ss_family == AF_INET6)
		return (ntohs(((const struct sockaddr_in6 *)v)->sin6_port));
	return (0);
}

/* An SA's name, the kernel's key: esp/<destination>/0x<SPI>. */
static const char *
sa_name(struct work *w, const struct pfkey_sa *sa)
{
	char	a[INET6_ADDRSTRLEN];

	addr_text(&sa->dst, a, sizeof(a));
	return (wfmt(w, "esp/%s/0x%08x", a, sa->spi));
}

/* ---- SADB_ACQUIRE ------------------------------------------------------ */

struct find_sp {
	uint32_t	id;
	struct pfkey_sp	sp;
	bool		found;
};

static void
find_sp(const struct pfkey_sp *sp, void *arg)
{
	struct find_sp	*f = arg;

	if (sp->id == f->id && !f->found) {
		f->sp = *sp;
		f->found = true;
	}
}

/* A selector's end as an ip-prefix of RFC 9061's (inet's union: the
 * family its member, both a string), FULLMASK the address's length. */
static void
prefix_of(struct work *w, const struct sockaddr_storage *ss, uint8_t plen,
    unsigned *which, const char **v)
{
	char	a[INET6_ADDRSTRLEN];
	unsigned max = ss->ss_family == AF_INET6 ? 128 : 32;

	addr_text(ss, a, sizeof(a));
	*which = ss->ss_family == AF_INET6 ? 1 : 0;
	*v = wfmt(w, "%s/%u", a, plen > max ? max : plen);
}

/*
 * An SADB_ACQUIRE: its policy by its id (SADB_X_SPDDUMP, on this
 * socket), the selector the policy's, local its source for an outbound
 * one; where the policy is gone, the SA's ends as the kernel gave them.
 */
static void
acquired(struct work *w, int fd, const struct sadb_msg *r, size_t len)
{
	struct ietf_i2nsf_ikeless_sadb_acquire			 n;
	struct ietf_i2nsf_ikeless_sadb_acquire_traffic_selector	 ts;
	struct ietf_i2nsf_ikeless_sadb_acquire_traffic_selector_local_ports lp;
	struct ietf_i2nsf_ikeless_sadb_acquire_traffic_selector_remote_ports rp;
	struct find_sp	 f;
	const struct sockaddr_storage *l, *rm;
	const char	*e;
	uint8_t		 lplen, rplen;

	memset(&f, 0, sizeof(f));
	pfkey_sp_of(r, len, &f.sp);
	f.id = f.sp.id;
	if (f.id != 0)
		(void)pfkey_spddump(w, fd, find_sp, &f, &e);
	/* Else the SA's ends alone, as the kernel sent them (FULLMASK). */
	memset(&n, 0, sizeof(n));
	memset(&ts, 0, sizeof(ts));
	if (f.sp.dir == IPSEC_DIR_INBOUND) {
		l = &f.sp.dst;
		lplen = f.sp.dplen;
		rm = &f.sp.src;
		rplen = f.sp.splen;
	} else {
		l = &f.sp.src;
		lplen = f.sp.splen;
		rm = &f.sp.dst;
		rplen = f.sp.dplen;
	}
	n.ipsec_policy_name = wfmt(w, "spd/%u", f.sp.id);
	ts.has_local_prefix = ts.has_remote_prefix = true;
	prefix_of(w, l, lplen, &ts.local_prefix.which, &ts.local_prefix.v.m0);
	prefix_of(w, rm, rplen, &ts.remote_prefix.which,
	    &ts.remote_prefix.v.m0);
	ts.has_inner_protocol = true;
	if (f.sp.proto == IPSEC_ULPROTO_ANY) {
		ts.inner_protocol.which = 1;
		ts.inner_protocol.v.m1 =
		    IETF_I2NSF_IKELESS_SADB_ACQUIRE_TRAFFIC_SELECTOR_INNER_PROTOCOL_M1_ANY;
	} else
		ts.inner_protocol.v.m0 = f.sp.proto;
	/* A port of the selector's, a range of one; none, any. */
	if (addr_port(l) != 0) {
		lp.start = lp.end = addr_port(l);
		ts.local_ports.n = 1;
		ts.local_ports.v = &lp;
	}
	if (addr_port(rm) != 0) {
		rp.start = rp.end = addr_port(rm);
		ts.remote_ports.n = 1;
		ts.remote_ports.v = &rp;
	}
	n.traffic_selector = &ts;
	yang_sadb_acquire(&n);
}

/* ---- SADB_EXPIRE ------------------------------------------------------- */

/* An SADB_EXPIRE: soft or hard, what the SA carried, how long it has
 * been there. */
static void
expired(struct work *w, const struct sadb_msg *r, size_t len)
{
	struct ietf_i2nsf_ikeless_sadb_expire			 n;
	struct ietf_i2nsf_ikeless_sadb_expire_lifetime_current	 lc;
	struct pfkey_sa	 sa;
	time_t		 now;

	pfkey_sa_of(r, len, &sa);
	memset(&n, 0, sizeof(n));
	memset(&lc, 0, sizeof(lc));
	n.ipsec_sa_name = sa_name(w, &sa);
	n.has_soft_lifetime_expire = true;
	n.soft_lifetime_expire = (sa.lifetimes & PFKEY_LT_HARD) == 0;
	now = time(NULL);
	if (sa.added != 0 && (uint64_t)now >= sa.added) {
		lc.has_time = true;
		lc.time = (uint32_t)((uint64_t)now - sa.added);
	}
	lc.has_bytes = true;
	lc.bytes = sa.bytes;
	lc.has_packets = true;
	lc.packets = sa.packets;
	n.lifetime_current = &lc;
	yang_sadb_expire(&n);
}

/* What the kernel tells, as it comes on the thread's socket: told at
 * once, or, met while a request of the thread's own waits for its
 * replies (pfkey.c's hook), queued and told once it has them. */
#define	NEWS_QUEUE	16
struct news {
	struct work	*w;
	int		 fd;
	size_t		 n;
	struct {
		unsigned char	buf[1024] __aligned(8);
		size_t		len;
	}		 q[NEWS_QUEUE];
};

static void
news_one(struct news *nw, const struct sadb_msg *r, size_t len)
{

	if (r->sadb_msg_type == SADB_EXPIRE)
		expired(nw->w, r, len);
	else if (r->sadb_msg_type == SADB_ACQUIRE)
		acquired(nw->w, nw->fd, r, len);
}

static void
news_queue(const struct sadb_msg *r, size_t len, void *arg)
{
	struct news	*nw = arg;

	if (nw->n == NEWS_QUEUE || len > sizeof(nw->q[0].buf))
		return;
	memcpy(nw->q[nw->n].buf, r, len);
	nw->q[nw->n++].len = len;
}

static void
news_drain(struct news *nw)
{

	for (size_t i = 0; i < nw->n; i++)
		news_one(nw, (const struct sadb_msg *)(const void *)
		    nw->q[i].buf, nw->q[i].len);
	nw->n = 0;
}

/* ---- The counters ------------------------------------------------------ */

static bool
told_of(const struct pfkey_sa *sa)
{

	for (size_t i = 0; i < ntold; i++)
		if (told[i].spi == sa->spi && memcmp(&told[i].dst, &sa->dst,
		    sizeof(sa->dst)) == 0)
			return (true);
	return (false);
}

struct seen {
	struct work	*w;
	struct told	 now[SEQ_TOLD];
	size_t		 n;
};

/* An SA past SEQ_NEAR without ESN, told once; those told kept while
 * they are there. */
static void
counted(const struct pfkey_sa *sa, void *arg)
{
	struct ietf_i2nsf_ikeless_sadb_seq_overflow	 n;
	struct seen	*s = arg;

	if ((sa->flags & SADB_X_SAFLAGS_ESN) != 0 || sa->seq < SEQ_NEAR)
		return;
	if (!told_of(sa)) {
		memset(&n, 0, sizeof(n));
		n.ipsec_sa_name = sa_name(s->w, sa);
		yang_sadb_seq_overflow(&n);
	}
	if (s->n < nitems(s->now)) {
		memset(&s->now[s->n], 0, sizeof(s->now[s->n]));
		memcpy(&s->now[s->n].dst, &sa->dst, sizeof(sa->dst));
		s->now[s->n++].spi = sa->spi;
	}
}

static void
counters(struct work *w, int fd)
{
	struct seen	*s;
	const char	*e;

	if ((s = calloc(1, sizeof(*s))) == NULL)
		return;
	s->w = w;
	if (pfkey_dump(w, fd, counted, s, &e) == 0) {
		memcpy(told, s->now, s->n * sizeof(s->now[0]));
		ntold = s->n;
	}
	free(s);
}

/* ---- The thread -------------------------------------------------------- */

static void *
watcher(void *arg)
{
	struct work	 w;
	struct news	*nw;
	struct pollfd	 pfd;
	const char	*e;
	unsigned char	 buf[4096] __aligned(8);
	time_t		 next;
	ssize_t		 len;
	bool		 said;
	int		 fd;

	(void)arg;
	if ((nw = calloc(1, sizeof(*nw))) == NULL) {
		logmsg(LOG_WARNING, "the SAs' expiries and acquires are not "
		    "told: %s", strerror(errno));
		return (NULL);
	}
	said = false;
	for (;;) {
		work_init(&w);
		e = NULL;
		if ((fd = pfkey_open(&w, &e)) == -1 ||
		    pfkey_register(&w, fd, &e) == -1) {
			if (!said)
				logmsg(LOG_NOTICE, "the SAs' expiries and "
				    "acquires are not told: %s; tried again "
				    "every %d s", e != NULL ? e : "PF_KEY",
				    SADB_RETRY);
			said = true;
			if (fd != -1)
				close(fd);
			work_free(&w);
			sleep(SADB_RETRY);
			continue;
		}
		said = false;
		nw->w = &w;
		nw->fd = fd;
		nw->n = 0;
		pfkey_news(news_queue, nw);
		next = 0;
		for (;;) {
			if (time(NULL) >= next) {
				counters(&w, fd);
				next = time(NULL) + SADB_CHECK;
			}
			news_drain(nw);
			/* What each told was made of goes with it. */
			work_free(&w);
			work_init(&w);
			pfd.fd = fd;
			pfd.events = POLLIN;
			pfd.revents = 0;
			if (poll(&pfd, 1, 1000) == -1 && errno != EINTR)
				break;
			if ((pfd.revents & (POLLIN | POLLHUP | POLLERR)) == 0)
				continue;
			len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
			if (len == 0 || (len == -1 && errno != EAGAIN &&
			    errno != EINTR && errno != ENOBUFS))
				break;
			if (len < (ssize_t)sizeof(struct sadb_msg))
				continue;
			if ((size_t)PFKEY_UNUNIT64(((struct sadb_msg *)(void *)
			    buf)->sadb_msg_len) != (size_t)len ||
			    ((struct sadb_msg *)(void *)buf)->sadb_msg_pid != 0)
				continue;
			switch (((struct sadb_msg *)(void *)buf)->sadb_msg_type) {
			case SADB_ACQUIRE:
			case SADB_EXPIRE:
				news_one(nw, (struct sadb_msg *)(void *)buf,
				    (size_t)len);
				break;
			}
		}
		pfkey_news(NULL, NULL);
		logmsg(LOG_NOTICE, "PF_KEY's news: the socket failed: %s; "
		    "registering again", strerror(errno));
		close(fd);
		work_free(&w);
		sleep(1);
	}
	return (NULL);
}

/* At the start: the kernel's news watched, on the host's network. */
void
sadb_watch_start(void)
{
	pthread_t	tid;
	int		error;

	if ((error = pthread_create(&tid, NULL, watcher, NULL)) != 0) {
		logmsg(LOG_WARNING, "the SAs' expiries and acquires are not "
		    "told: pthread_create: %s", strerror(error));
		return;
	}
	(void)pthread_detach(tid);
}
