/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: the BGP Monitoring Protocol (RFC 7854) station of an edge's
 * BIRD instances.  A service that monitors its routes has each of its
 * instances send BMP to 127.0.0.1, port opts.bmp_port + the instance's
 * FIB (sdconf.c writes the protocol); the agent listens there and keeps
 * what it hears for the sdwan read, so that the console sees each BGP
 * peer and its updates without a port of its own open to the edges.
 *
 * The listener is the FIB's (SO_SETFIB) and wildcard: lo0 is FIB 0's,
 * and with net.inet.tcp.bind_all_fibs 0 a socket of another FIB binds
 * none of its addresses, while a connection from FIB N to 127.0.0.1
 * reaches a wildcard listener of FIB N and no other.  Wildcard, it is
 * open on the FIB's other addresses too: a far end that is not the
 * loopback is closed at once (a packet from 127/8 that came in on
 * another interface is dropped by the kernel).  A vnet jail's edge has
 * its listener made in the jail's network by the helper and handed
 * over.
 *
 * One thread reads every station.  A station has one connection, its
 * instance's; a new one takes its place (BIRD connects again after a
 * restart), its peers down until it says them up again.  Everything
 * read is checked against what is there; a message over BMP_MSG_MAX, a
 * version not 3, or a Route Monitoring message whose BGP message is not
 * an UPDATE drops the connection, said in the station's error.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	BMP_STATIONS	64		/* every edge's, all told */
#define	BMP_PEERS	128		/* a station's */
#define	BMP_MSG_MAX	(256 * 1024)	/* a message's bytes, at most: a Peer
					 * Up holds two OPENs of 64 KiB */
#define	BMP_PPH		42		/* the per-peer header */

enum {
	BMP_ROUTE = 0, BMP_STATS = 1, BMP_PEER_DOWN = 2, BMP_PEER_UP = 3,
	BMP_INIT = 4, BMP_TERM = 5, BMP_MIRROR = 6
};

struct bmppeer {
	char		addr[INET6_ADDRSTRLEN];
	char		local[INET6_ADDRSTRLEN];
	char		bgpid[INET_ADDRSTRLEN];
	uint64_t	rd;		/* its distinguisher */
	uint32_t	as;
	uint8_t		type;		/* global, RD, local */
	bool		up;
	int		down_reason;	/* RFC 7854 4.9, 0 none */
	int64_t		since;		/* ms: up or down since */
	int64_t		last;		/* ms: its last update */
	uint64_t	ann[2], wd[2];	/* [pre, post policy] */
};

struct bmpupd {
	int64_t		t;
	char		peer[INET6_ADDRSTRLEN];
	char		prefix[INET6_ADDRSTRLEN + 4];
	char		nexthop[INET6_ADDRSTRLEN];
	char		aspath[160];
	bool		post;
	bool		withdraw;
};

struct bmpst {
	struct bmp_station s;
	int		 port;
	int		 lfd, cfd;
	int64_t		 since;		/* connected, or not, since */
	char		 sysname[64];
	char		 sysdescr[128];
	char		 error[160];
	uint8_t		*buf;
	size_t		 len;
	uint64_t	 messages;
	struct bmppeer	 peers[BMP_PEERS];
	int		 npeers;
	struct bmpupd	*upd;		/* the last s.kept, a ring */
	int		 first, nupd;
};

static pthread_mutex_t	 bmp_lock = PTHREAD_MUTEX_INITIALIZER;
static struct bmpst	*stations[BMP_STATIONS];
static int		 nstations;
static bool		 bmp_running;
static int		 wake[2] = { -1, -1 };

static int64_t
now_ms(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return ((int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

/* The port of FIB fib's station, -1 when there is none. */
int
bmp_port(int fib)
{

	if (fib < 0 || opts.bmp_port <= 0 || opts.bmp_port + fib > 65535)
		return (-1);
	return (opts.bmp_port + fib);
}

/* A listener of FIB fib, wildcard, on port: -1 with errno. */
int
bmp_listen(int fib, int port)
{
	struct sockaddr_in	sin;
	int			fd, one, error;

	if ((fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    0)) == -1)
		return (-1);
	one = 1;
	if ((fib > 0 && setsockopt(fd, SOL_SOCKET, SO_SETFIB, &fib,
	    sizeof(fib)) == -1) || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
	    &one, sizeof(one)) == -1)
		goto bad;
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons((uint16_t)port);
	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) == -1 ||
	    listen(fd, 4) == -1)
		goto bad;
	return (fd);
bad:
	error = errno;
	close(fd);
	errno = error;
	return (-1);
}

static void
st_error(struct bmpst *st, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vsnprintf(st->error, sizeof(st->error), fmt, ap);
	va_end(ap);
}

/* Its connection gone: every peer down, by no word of BIRD's. */
static void
st_drop(struct bmpst *st)
{
	int	i;

	if (st->cfd != -1)
		close(st->cfd);
	st->cfd = -1;
	st->len = 0;
	st->since = now_ms();
	for (i = 0; i < st->npeers; i++)
		if (st->peers[i].up) {
			st->peers[i].up = false;
			st->peers[i].since = st->since;
			st->peers[i].down_reason = 0;
		}
}

static void
st_free(struct bmpst *st)
{

	if (st == NULL)
		return;
	if (st->cfd != -1)
		close(st->cfd);
	if (st->lfd != -1)
		close(st->lfd);
	free(st->buf);
	free(st->upd);
	free(st);
}

static uint32_t
be32(const uint8_t *p)
{

	return ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	    (uint32_t)p[2] << 8 | p[3]);
}

static uint16_t
be16(const uint8_t *p)
{

	return ((uint16_t)(p[0] << 8 | p[1]));
}

/* An address of 16 octets as BMP gives them: IPv4 in the last 4 when
 * v6 is false. */
static void
addr16(const uint8_t *p, bool v6, char *buf, size_t len)
{

	if (!v6 || inet_ntop(AF_INET6, p, buf, (socklen_t)len) == NULL) {
		if (inet_ntop(AF_INET, p + 12, buf, (socklen_t)len) == NULL)
			snprintf(buf, len, "?");
	}
}

/* The peer of a per-peer header, made when new: NULL when the station
 * has its fill. */
static struct bmppeer *
peer_of(struct bmpst *st, const uint8_t *h)
{
	struct bmppeer	*p;
	char		 a[INET6_ADDRSTRLEN];
	uint64_t	 rd;
	int		 i;

	addr16(h + 10, (h[1] & 0x80) != 0, a, sizeof(a));
	rd = (uint64_t)be32(h + 2) << 32 | be32(h + 6);
	for (i = 0; i < st->npeers; i++)
		if (st->peers[i].rd == rd && strcmp(st->peers[i].addr, a) == 0)
			break;
	if (i == st->npeers) {
		if (st->npeers == BMP_PEERS)
			return (NULL);
		p = &st->peers[st->npeers++];
		memset(p, 0, sizeof(*p));
		snprintf(p->addr, sizeof(p->addr), "%s", a);
		p->rd = rd;
		p->since = now_ms();
	}
	p = &st->peers[i];
	p->type = h[0];
	p->as = be32(h + 26);
	if (inet_ntop(AF_INET, h + 30, p->bgpid, sizeof(p->bgpid)) == NULL)
		p->bgpid[0] = '\0';
	return (p);
}

static void
upd_keep(struct bmpst *st, const struct bmppeer *p, bool post, bool wd,
    const char *prefix, const char *nh, const char *aspath)
{
	struct bmpupd	*u;

	if (st->upd == NULL || st->s.kept <= 0)
		return;
	if (st->nupd < st->s.kept)
		u = &st->upd[(st->first + st->nupd++) % st->s.kept];
	else {
		u = &st->upd[st->first];
		st->first = (st->first + 1) % st->s.kept;
	}
	memset(u, 0, sizeof(*u));
	u->t = now_ms();
	snprintf(u->peer, sizeof(u->peer), "%s", p->addr);
	snprintf(u->prefix, sizeof(u->prefix), "%s", prefix);
	snprintf(u->nexthop, sizeof(u->nexthop), "%s", wd ? "" : nh);
	snprintf(u->aspath, sizeof(u->aspath), "%s", wd ? "" : aspath);
	u->post = post;
	u->withdraw = wd;
}

/*
 * The prefixes of an NLRI field (RFC 4271 4.3) of family af, each
 * kept as announced or withdrawn: -1 when one runs past the field.
 */
static int
prefixes(struct bmpst *st, struct bmppeer *p, bool post, bool wd, int af,
    const uint8_t *q, size_t n, const char *nh, const char *aspath)
{
	uint8_t	a[16];
	char	s[INET6_ADDRSTRLEN], pfx[INET6_ADDRSTRLEN + 4];
	size_t	bytes;
	int	plen, max;

	max = af == AF_INET ? 32 : 128;
	while (n > 0) {
		plen = q[0];
		bytes = ((size_t)plen + 7) / 8;
		if (plen > max || bytes + 1 > n)
			return (-1);
		memset(a, 0, sizeof(a));
		memcpy(a, q + 1, bytes);
		if (inet_ntop(af, a, s, sizeof(s)) == NULL)
			return (-1);
		snprintf(pfx, sizeof(pfx), "%s/%d", s, plen);
		if (wd)
			p->wd[post]++;
		else
			p->ann[post]++;
		upd_keep(st, p, post, wd, pfx, nh, aspath);
		q += bytes + 1;
		n -= bytes + 1;
	}
	p->last = now_ms();
	return (0);
}

/* An AS_PATH (RFC 4271 4.3, RFC 6793) as words: sets in braces. */
static int
aspath_text(const uint8_t *q, size_t n, bool two, char *buf, size_t len)
{
	size_t	w, used, k, cnt;
	int	r;

	w = two ? 2 : 4;
	buf[0] = '\0';
	used = 0;
	while (n > 0) {
		if (n < 2)
			return (-1);
		cnt = q[1];
		if (n < 2 + cnt * w)
			return (-1);
		for (k = 0; k < cnt; k++) {
			r = snprintf(buf + used, len - used, "%s%s%u%s",
			    used > 0 ? " " : "", q[0] == 1 && k == 0 ? "{" : "",
			    w == 2 ? (unsigned)be16(q + 2 + k * w) :
			    (unsigned)be32(q + 2 + k * w), q[0] == 1 && k + 1 ==
			    cnt ? "}" : "");
			if (r < 0 || (size_t)r >= len - used) {
				buf[len - 1] = '\0';
				return (0);
			}
			used += (size_t)r;
		}
		q += 2 + cnt * w;
		n -= 2 + cnt * w;
	}
	return (0);
}

/* A BGP UPDATE (RFC 4271 4.3) of peer p: -1 when it is not one. */
static int
update(struct bmpst *st, struct bmppeer *p, bool post, bool two,
    const uint8_t *m, size_t n)
{
	const uint8_t	*attrs, *a, *q;
	char		 nh[INET6_ADDRSTRLEN], nh6[INET6_ADDRSTRLEN];
	char		 aspath[160];
	size_t		 wlen, alen, l, k, nhl, rest;
	unsigned	 afi, safi;
	int		 af, i;

	if (n < 19 || be16(m + 16) != n || m[18] != 2)
		return (-1);
	for (i = 0; i < 16; i++)
		if (m[i] != 0xff)
			return (-1);
	m += 19;
	n -= 19;
	if (n < 2 || (wlen = be16(m)) + 4 > n)
		return (-1);
	alen = be16(m + 2 + wlen);
	if (wlen + 4 + alen > n)
		return (-1);
	attrs = m + 4 + wlen;
	nh[0] = nh6[0] = aspath[0] = '\0';
	/* What the path carries first, for the announcements. */
	for (a = attrs, rest = alen; rest > 0; a += k + l, rest -= k + l) {
		if (rest < 3)
			return (-1);
		k = (a[0] & 0x10) != 0 ? 4 : 3;
		if (rest < k)
			return (-1);
		l = k == 4 ? be16(a + 2) : a[2];
		if (l > rest - k)
			return (-1);
		q = a + k;
		if (a[1] == 2 && aspath_text(q, l, two, aspath,
		    sizeof(aspath)) != 0)
			return (-1);
		if (a[1] == 3 && l == 4 && inet_ntop(AF_INET, q, nh,
		    sizeof(nh)) == NULL)
			return (-1);
		if (a[1] == 14 && l >= 5) {
			nhl = q[3];
			if (nhl + 5 > l)
				return (-1);
			afi = be16(q);
			if (afi == 2 && nhl >= 16)
				(void)inet_ntop(AF_INET6, q + 4, nh6, sizeof(nh6));
			else if (afi == 1 && nhl >= 4)
				(void)inet_ntop(AF_INET, q + 4, nh6, sizeof(nh6));
		}
	}
	/* The withdrawn, the announced; then the multiprotocol ones. */
	if (prefixes(st, p, post, true, AF_INET, m + 2, wlen, "", "") != 0 ||
	    prefixes(st, p, post, false, AF_INET, attrs + alen, n - 4 - wlen -
	    alen, nh, aspath) != 0)
		return (-1);
	for (a = attrs, rest = alen; rest > 0; a += k + l, rest -= k + l) {
		k = (a[0] & 0x10) != 0 ? 4 : 3;
		l = k == 4 ? be16(a + 2) : a[2];
		q = a + k;
		if ((a[1] != 14 && a[1] != 15) || l < 3)
			continue;
		afi = be16(q);
		safi = q[2];
		af = afi == 1 ? AF_INET : afi == 2 ? AF_INET6 : 0;
		if (af == 0 || safi != 1)
			continue;
		if (a[1] == 15) {
			if (prefixes(st, p, post, true, af, q + 3, l - 3, "",
			    "") != 0)
				return (-1);
			continue;
		}
		if (l < 5 || (nhl = q[3]) + 5 > l)
			return (-1);
		if (prefixes(st, p, post, false, af, q + 5 + nhl, l - 5 - nhl,
		    nh6, aspath) != 0)
			return (-1);
	}
	return (0);
}

/* The TLVs of an Initiation (RFC 7854 4.3): its sysDescr, sysName. */
static void
init_tlvs(struct bmpst *st, const uint8_t *q, size_t n)
{
	size_t	l;
	char	*dst;
	size_t	dlen, i;

	while (n >= 4) {
		l = be16(q + 2);
		if (l > n - 4)
			return;
		dst = be16(q) == 1 ? st->sysdescr : be16(q) == 2 ?
		    st->sysname : NULL;
		dlen = be16(q) == 1 ? sizeof(st->sysdescr) :
		    sizeof(st->sysname);
		if (dst != NULL) {
			for (i = 0; i < l && i + 1 < dlen; i++)
				dst[i] = q[4 + i] >= 0x20 && q[4 + i] < 0x7f ?
				    (char)q[4 + i] : '?';
			dst[i] = '\0';
		}
		q += 4 + l;
		n -= 4 + l;
	}
}

/* One message, the common header's 6 octets first: -1 drops the
 * connection, its reason in the station's error. */
static int
message(struct bmpst *st, const uint8_t *m, size_t n)
{
	struct bmppeer	*p;
	const uint8_t	*b;
	size_t		 bn;

	st->messages++;
	if (m[5] == BMP_INIT || m[5] == BMP_TERM) {
		if (m[5] == BMP_INIT)
			init_tlvs(st, m + 6, n - 6);
		return (m[5] == BMP_TERM ? -1 : 0);
	}
	if (m[5] > BMP_MIRROR) {
		st_error(st, "a message of type %u, none RFC 7854 has", m[5]);
		return (-1);
	}
	if (n < 6 + BMP_PPH) {
		st_error(st, "a message of type %u shorter than its per-peer "
		    "header", m[5]);
		return (-1);
	}
	b = m + 6 + BMP_PPH;
	bn = n - 6 - BMP_PPH;
	if (m[5] == BMP_STATS || m[5] == BMP_MIRROR)
		return (0);
	if ((p = peer_of(st, m + 6)) == NULL)
		return (0);
	switch (m[5]) {
	case BMP_PEER_UP:
		if (bn >= 16)
			addr16(b, (m[7] & 0x80) != 0, p->local, sizeof(p->local));
		p->up = true;
		p->down_reason = 0;
		p->since = now_ms();
		break;
	case BMP_PEER_DOWN:
		p->up = false;
		p->down_reason = bn > 0 ? b[0] : 0;
		p->since = now_ms();
		break;
	case BMP_ROUTE:
		if (update(st, p, (m[7] & 0x40) != 0, (m[7] & 0x20) != 0, b,
		    bn) != 0) {
			st_error(st, "peer %s: a route monitoring message whose "
			    "BGP message is not an UPDATE as RFC 4271 has it",
			    p->addr);
			return (-1);
		}
		break;
	}
	return (0);
}

/* What came on a station's connection: each whole message read, the
 * rest kept for the next; -1 drops the connection. */
static int
st_parse(struct bmpst *st)
{
	size_t	off, n;

	off = 0;
	while (st->len - off >= 6) {
		if (st->buf[off] != 3) {
			st_error(st, "BMP version %u, not 3", st->buf[off]);
			return (-1);
		}
		n = be32(st->buf + off + 1);
		if (n < 6 || n > BMP_MSG_MAX) {
			st_error(st, "a message of %zu bytes", n);
			return (-1);
		}
		if (st->len - off < n)
			break;
		if (message(st, st->buf + off, n) != 0)
			return (-1);
		off += n;
	}
	memmove(st->buf, st->buf + off, st->len - off);
	st->len -= off;
	return (0);
}

/* A station's connection readable. */
static void
st_read(struct bmpst *st)
{
	ssize_t	r;

	if (st->buf == NULL && (st->buf = malloc(BMP_MSG_MAX)) == NULL) {
		st_error(st, "no memory");
		st_drop(st);
		return;
	}
	r = read(st->cfd, st->buf + st->len, BMP_MSG_MAX - st->len);
	if (r == -1 && (errno == EAGAIN || errno == EINTR))
		return;
	if (r <= 0) {
		if (r == -1)
			st_error(st, "read: %s", strerror(errno));
		st_drop(st);
		return;
	}
	st->len += (size_t)r;
	if (st_parse(st) != 0)
		st_drop(st);
}

/* A connection on a station's listener: the loopback's alone. */
static void
st_accept(struct bmpst *st)
{
	struct sockaddr_storage	ss;
	socklen_t		sl;
	int			fd;
	bool			lo;

	sl = sizeof(ss);
	if ((fd = accept4(st->lfd, (struct sockaddr *)&ss, &sl, SOCK_CLOEXEC |
	    SOCK_NONBLOCK)) == -1)
		return;
	lo = (ss.ss_family == AF_INET && ntohl(((struct sockaddr_in *)&ss)->
	    sin_addr.s_addr) == INADDR_LOOPBACK) || (ss.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *)&ss)->sin6_addr));
	if (!lo) {
		close(fd);
		return;
	}
	st_drop(st);
	st->cfd = fd;
	st->error[0] = '\0';
	st->since = now_ms();
}

static void *
bmp_thread(void *arg __unused)
{
	struct pollfd	 pfd[1 + BMP_STATIONS * 2];
	struct bmpst	*who[1 + BMP_STATIONS * 2];
	char		 c[64];
	int		 i, n;

	for (;;) {
		pthread_mutex_lock(&bmp_lock);
		n = 0;
		pfd[n].fd = wake[0];
		pfd[n].events = POLLIN;
		who[n++] = NULL;
		for (i = 0; i < nstations; i++) {
			if (stations[i]->lfd != -1) {
				pfd[n].fd = stations[i]->lfd;
				pfd[n].events = POLLIN;
				who[n++] = stations[i];
			}
			if (stations[i]->cfd != -1) {
				pfd[n].fd = stations[i]->cfd;
				pfd[n].events = POLLIN;
				who[n++] = stations[i];
			}
		}
		pthread_mutex_unlock(&bmp_lock);
		if (poll(pfd, (nfds_t)n, 10000) <= 0)
			continue;
		if ((pfd[0].revents & POLLIN) != 0)
			while (read(wake[0], c, sizeof(c)) > 0)
				;
		pthread_mutex_lock(&bmp_lock);
		for (i = 1; i < n; i++) {
			if (pfd[i].revents == 0)
				continue;
			/* Still a station, and still its descriptor: a set
			 * may have changed them since the poll began. */
			for (int k = 0; k < nstations; k++) {
				if (stations[k] != who[i])
					continue;
				if (pfd[i].fd == who[i]->lfd)
					st_accept(who[i]);
				else if (pfd[i].fd == who[i]->cfd)
					st_read(who[i]);
				break;
			}
		}
		pthread_mutex_unlock(&bmp_lock);
	}
	return (NULL);
}

/*
 * jail's edge (the host's when "") has stations for v (n of them) and
 * no others: one kept, with what it heard, when its instance, FIB and
 * jail are as they were; a new one listening; those not named closed.
 * Each one's error says why it does not listen.
 */
void
bmp_set(const char *jail, const struct bmp_station *v, int n)
{
	struct bmpst	*keep[BMP_STATIONS], *st;
	pthread_t	 tid;
	int		 i, k, nk;
	bool		 found;

	if (jail == NULL)
		jail = "";
	pthread_mutex_lock(&bmp_lock);
	if (wake[0] == -1 && pipe2(wake, O_CLOEXEC | O_NONBLOCK) == -1) {
		pthread_mutex_unlock(&bmp_lock);
		logmsg(LOG_WARNING, "bmp: pipe: %s", strerror(errno));
		return;
	}
	nk = 0;
	for (i = 0; i < nstations; i++) {
		st = stations[i];
		found = false;
		for (k = 0; k < n && strcmp(st->s.jail, jail) == 0; k++)
			if (strcmp(v[k].name, st->s.name) == 0 && v[k].fib ==
			    st->s.fib) {
				found = true;
				break;
			}
		if (strcmp(st->s.jail, jail) != 0 || found)
			keep[nk++] = st;
		else
			st_free(st);
	}
	nstations = nk;
	memcpy(stations, keep, sizeof(*keep) * (size_t)nk);
	for (k = 0; k < n; k++) {
		for (i = 0; i < nstations; i++)
			if (strcmp(stations[i]->s.jail, jail) == 0 && strcmp(
			    stations[i]->s.name, v[k].name) == 0)
				break;
		if (i < nstations) {
			st = stations[i];
			/* How many kept may change; what was kept goes. */
			if (st->s.kept != v[k].kept) {
				free(st->upd);
				st->upd = v[k].kept > 0 ? calloc((size_t)v[k].kept,
				    sizeof(*st->upd)) : NULL;
				st->first = st->nupd = 0;
				st->s.kept = st->upd != NULL ? v[k].kept : 0;
			}
			continue;
		}
		if (nstations == BMP_STATIONS || (st = calloc(1,
		    sizeof(*st))) == NULL) {
			logmsg(LOG_WARNING, "bmp: %s: no room for its station",
			    v[k].name);
			continue;
		}
		st->s = v[k];
		snprintf(st->s.jail, sizeof(st->s.jail), "%s", jail);
		st->cfd = -1;
		st->since = now_ms();
		st->upd = v[k].kept > 0 ? calloc((size_t)v[k].kept,
		    sizeof(*st->upd)) : NULL;
		if (st->upd == NULL)
			st->s.kept = 0;
		st->port = bmp_port(v[k].fib);
		if (st->port == -1) {
			st->lfd = -1;
			st_error(st, "FIB %d has no port: --bmp-port %d and the "
			    "FIB pass 65535", v[k].fib, opts.bmp_port);
		} else if ((st->lfd = v[k].jid > 0 ? helper_bmp_socket(v[k].jid,
		    v[k].fib, st->port) : bmp_listen(v[k].fib, st->port)) ==
		    -1)
			st_error(st, "no listener on port %d of FIB %d: %s",
			    st->port, v[k].fib, v[k].jid > 0 ? "the helper "
			    "made none" : strerror(errno));
		stations[nstations++] = st;
	}
	if (nstations > 0 && !bmp_running) {
		if (pthread_create(&tid, NULL, bmp_thread, NULL) == 0) {
			(void)pthread_detach(tid);
			bmp_running = true;
		}
	}
	pthread_mutex_unlock(&bmp_lock);
	(void)write(wake[1], "", 1);
}

static void
put_s(ucl_object_t *o, const char *k, const char *v)
{

	if (v != NULL && v[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromstring(v), k, 0, true);
}

static void
put_i(ucl_object_t *o, const char *k, int64_t v)
{

	ucl_object_insert_key(o, ucl_object_fromint(v), k, 0, true);
}

/* Instance name's station of jail's edge, for the sdwan read; NULL
 * when it has none.  Its updates newest first. */
ucl_object_t *
bmp_json(const char *jail, const char *name)
{
	const struct bmpst	*st;
	const struct bmppeer	*p;
	const struct bmpupd	*u;
	ucl_object_t		*o, *arr, *e;
	int			 i, k;

	if (jail == NULL)
		jail = "";
	o = NULL;
	pthread_mutex_lock(&bmp_lock);
	for (i = 0; i < nstations; i++) {
		st = stations[i];
		if (strcmp(st->s.jail, jail) != 0 || strcmp(st->s.name, name) !=
		    0)
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		if (st->port != -1)
			put_i(o, "port", st->port);
		ucl_object_insert_key(o, ucl_object_frombool(st->lfd != -1),
		    "listening", 0, true);
		ucl_object_insert_key(o, ucl_object_frombool(st->cfd != -1),
		    "connected", 0, true);
		put_i(o, "since", st->since / 1000);
		put_s(o, "sys_name", st->sysname);
		put_s(o, "sys_descr", st->sysdescr);
		put_i(o, "messages", (int64_t)st->messages);
		put_s(o, "error", st->error);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (k = 0; k < st->npeers; k++) {
			p = &st->peers[k];
			e = ucl_object_typed_new(UCL_OBJECT);
			put_s(e, "address", p->addr);
			if (p->rd != 0)
				put_i(e, "distinguisher", (int64_t)p->rd);
			put_i(e, "as", p->as);
			put_s(e, "bgp_id", p->bgpid);
			put_s(e, "local", p->local);
			ucl_object_insert_key(e, ucl_object_frombool(p->up),
			    "up", 0, true);
			put_i(e, "since", p->since / 1000);
			if (!p->up && p->down_reason > 0)
				put_i(e, "down_reason", p->down_reason);
			put_i(e, "announced", (int64_t)p->ann[0]);
			put_i(e, "withdrawn", (int64_t)p->wd[0]);
			put_i(e, "announced_post", (int64_t)p->ann[1]);
			put_i(e, "withdrawn_post", (int64_t)p->wd[1]);
			if (p->last > 0)
				put_i(e, "last", p->last / 1000);
			ucl_array_append(arr, e);
		}
		ucl_object_insert_key(o, arr, "peers", 0, true);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (k = st->nupd - 1; k >= 0; k--) {
			u = &st->upd[(st->first + k) % st->s.kept];
			e = ucl_object_typed_new(UCL_OBJECT);
			put_i(e, "t", u->t / 1000);
			put_s(e, "peer", u->peer);
			put_s(e, "policy", u->post ? "post" : "pre");
			put_s(e, "action", u->withdraw ? "withdraw" : "announce");
			put_s(e, "prefix", u->prefix);
			put_s(e, "next_hop", u->nexthop);
			put_s(e, "as_path", u->aspath);
			ucl_array_append(arr, e);
		}
		ucl_object_insert_key(o, arr, "updates", 0, true);
		break;
	}
	pthread_mutex_unlock(&bmp_lock);
	return (o);
}
