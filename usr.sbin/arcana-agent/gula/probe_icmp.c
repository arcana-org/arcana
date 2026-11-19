/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula, the echoes (ICMP echo, Mplify 119 §11.4): the host's targets
 * share one raw socket a FIB and a family, the FIB set on it once
 * (SO_SETFIB), opened when a target first needs it and closed when none
 * does.  A raw socket hears every echo reply of its FIB on the host, so
 * one a target woke for every reply and read each (targets × replies);
 * one a FIB reads each once and tells it to its target by the echo's
 * id and sequence (probe_echo.c), the ids each family's own among the
 * live targets.  The kernel hands an ICMP reply to the raw sockets of
 * the FIB of the interface it came in on: a probe sent in a tunnel's
 * table (its tunnelfib) over an uplink in another never hears its reply
 * on its own FIB's socket (net.inet.raw.bind_all_fibs 0; with 1 every
 * raw socket hears every table's).  So while a host target is in another
 * table than 0, and the sockets are held to their tables, every FIB up
 * to RX_FIBS has its socket for its family, and a reply is its target's
 * whichever FIB it came in.
 *
 * A target's DSCP is its packets' own: IPv6's traffic class goes with
 * each echo as ancillary data (IPV6_TCLASS, ip6(4) and RFC 3542 6.5,
 * which raw sockets take); a raw IPv4 socket takes no IP_TOS control
 * message (ip(4) has none, rip_output builds the header from the
 * socket's), so the FIB's socket has IP_TOS set to the target's before
 * a send of another DSCP than the last: one socket still, the option
 * per packet in effect, as the engine sends one at a time.  A target
 * sets nothing else on its socket (no source, interface, TTL nor
 * don't-fragment), so none needs a socket of its own.
 *
 * A jail's targets share a socket too, one a jail, a FIB and a family
 * (struct jsock): made by the helper inside the jail, its FIB set there
 * (jail_socket(), on the engine's worker), and handed over (SCM_RIGHTS),
 * so that the jail's routing tables carry the probes, a host socket
 * cannot stand in; once, for the first target that needs it, the others
 * waiting for the same answer (jsock_want(), jsock_made()), and closed
 * when none uses it.  The DSCP is set as on a FIB's, and its replies are
 * told to the jail's targets by their ids as the host's are (the ids are
 * each family's own among all the targets, the jails' too).  As on the
 * host, while a jail's target is in another table than 0, the jail has
 * a socket every FIB (the jail's own net.fibs, up to RX_FIBS) for its
 * family, kept for the replies (listen) and asked of the worker as the
 * table says (jsock_ask()); one the helper could not make asked again
 * later, the wait doubling as a target's.  A vnet jail's net.fibs may
 * be fewer than the host's: it is read in the jail by the helper, on
 * the worker, once a jail started (struct jfibs, by its jid), and a FIB
 * it lacks is not asked for (the host's count until it is read; a
 * socket of one it lacks, kept for the replies, is dropped, not asked
 * again).  An echo's
 * round trip is timed by the kernel (SO_TIMESTAMP, the monotonic clock),
 * not by when the prober got to its reply.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"
#include "stamp.h"
#include "probe_int.h"

#define	RX_FIBS		16
#define	JS_RETRY	1.0	/* s: a jail's socket not made asked again */
#define	JS_RETRY_MAX	60.0
#define	RCVBUF		(1024 * 1024)	/* a FIB's socket's room, at best */
#define	FSOCKS_MAX	(2 * (RX_FIBS + TARGETS_MAX))

/* A FIB's socket of a family: the TOS it has (IPv4's), kept for every
 * FIB's replies (listen), the host's targets that send on it. */
struct fsock {
	int	fd, af, fib, tos;
	bool	listen;
	int	users;
};

static struct fsock	 fsocks[FSOCKS_MAX];
static int		 nfsocks;
static int		 nfibs = -1;
/* The host's targets' echo ids, the table's (icmp_table()). */
static struct echo_ids	 ids;

/* A jail's socket of a FIB and a family: being made by the worker
 * (opening, gen the answer it waits for), the TOS it has (IPv4's), kept
 * for every FIB's replies (listen; not made, fd -1, asked again at
 * open_at), the targets that send on it. */
struct jsock {
	char		jail[64];
	int		fd, af, fib, tos;
	uint32_t	gen;
	bool		opening, listen;
	double		open_at, open_wait;
	int		users;
};

#define	JSOCKS_MAX	(2 * (RX_FIBS + TARGETS_MAX))

static struct jsock	 jsocks[JSOCKS_MAX];
static int		 njsocks;
static uint32_t		 jgen;
/* The jails' targets' echo ids. */
static struct echo_ids	 jids;

/* A jail's own net.fibs, read in it on the worker (jail_fibs()), by
 * the jail's number: one started again is read again. */
struct jfibs {
	char	jail[64];
	int	jid, fibs;
};

#define	JFIBS_MAX	64

static pthread_mutex_t	 jf_mtx = PTHREAD_MUTEX_INITIALIZER;
static struct jfibs	 jfibs[JFIBS_MAX];
static int		 njfibs;

/* An echo socket's replies timed by the kernel, on the prober's
 * clock (CLOCK_MONOTONIC, SCM_MONOTONIC). */
static void
icmp_timed(int fd)
{
	int	on = 1, v = SO_TS_MONOTONIC;

	(void)setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on));
	(void)setsockopt(fd, SOL_SOCKET, SO_TS_CLOCK, &v, sizeof(v));
}

/* ICMPv6's echo replies alone on a socket. */
static void
icmp6_replies(int fd)
{
	struct icmp6_filter	f;

	ICMP6_FILTER_SETBLOCKALL(&f);
	ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &f);
	(void)setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &f, sizeof(f));
}

/*
 * FIB fib's echo socket of family af, made when it has none: timed, in
 * its table, IPv6's replies alone.  The descriptor, or -1 and why in err
 * (not kept: the next target to need it tries again).
 */
static int
fsock_get(int af, int fib, char *err, size_t len)
{
	struct fsock	*f;
	int		 fd, i, rcv;

	for (i = 0; i < nfsocks; i++)
		if (fsocks[i].af == af && fsocks[i].fib == fib)
			return (fsocks[i].fd);
	if (nfsocks == FSOCKS_MAX) {
		snprintf(err, len, "socket: %s", strerror(EMFILE));
		return (-1);
	}
	if ((fd = socket(af, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    af == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6)) == -1) {
		snprintf(err, len, "socket: %s%s", strerror(errno), errno ==
		    EPERM || errno == EACCES ? " (probing needs root)" : "");
		return (-1);
	}
	icmp_timed(fd);
	/* Every target's replies, and on a raw IPv4 socket whatever other
	 * ICMP the host takes in (the loopback's own requests too): a raw
	 * socket's room (net.inet.raw.recvspace, 9216) holds some ninety
	 * echoes, less than a round of many targets' replies. */
	for (rcv = RCVBUF; rcv >= 16 * 1024 && setsockopt(fd, SOL_SOCKET,
	    SO_RCVBUF, &rcv, sizeof(rcv)) == -1; rcv /= 2)
		;
	if (setsockopt(fd, SOL_SOCKET, SO_SETFIB, &fib, sizeof(fib)) == -1) {
		snprintf(err, len, "fib %d: %s", fib, strerror(errno));
		close(fd);
		return (-1);
	}
	if (af == AF_INET6)
		icmp6_replies(fd);
	f = &fsocks[nfsocks++];
	memset(f, 0, sizeof(*f));
	f->fd = fd;
	f->af = af;
	f->fib = fib;
	logmsg(LOG_DEBUG, "probe: echo socket of FIB %d, %s", fib, af ==
	    AF_INET ? "inet" : "inet6");
	return (fd);
}

static struct fsock *
fsock_of(int fd)
{

	for (int i = 0; i < nfsocks; i++)
		if (fsocks[i].fd == fd)
			return (&fsocks[i]);
	return (NULL);
}

static struct jsock *
jsock_of(int fd)
{

	for (int i = 0; fd != -1 && i < njsocks; i++)
		if (jsocks[i].fd == fd)
			return (&jsocks[i]);
	return (NULL);
}

static struct jsock *
jsock_find(const char *jail, int fib, int af)
{

	for (int i = 0; i < njsocks; i++)
		if (jsocks[i].af == af && jsocks[i].fib == fib &&
		    strcmp(jsocks[i].jail, jail) == 0)
			return (&jsocks[i]);
	return (NULL);
}

static void
jsock_drop(struct jsock *j)
{

	if (j->fd != -1)
		close(j->fd);
	*j = jsocks[--njsocks];
}

/* How many FIBs have a socket kept for the replies, up to RX_FIBS; 0
 * when raw sockets are told to take every table's packets: those hear
 * the reply on the target's own, no other needed (each would read it
 * again). */
static int
listen_fibs(void)
{
	size_t	len = sizeof(nfibs);
	int	all = 0;
	size_t	alen = sizeof(all);

	if (sysctlbyname("net.inet.raw.bind_all_fibs", &all, &alen, NULL,
	    0) == 0 && all != 0)
		return (0);
	if (nfibs < 0 && (sysctlbyname("net.fibs", &nfibs, &len, NULL, 0) !=
	    0 || nfibs < 1))
		nfibs = 1;
	return (nfibs < RX_FIBS ? nfibs : RX_FIBS);
}

/* The FIBs of jail jid as read there last; -1 not read since it
 * started. */
static int
jail_fibs_read(const char *jail, int jid)
{
	int	n = -1;

	pthread_mutex_lock(&jf_mtx);
	for (int i = 0; i < njfibs; i++)
		if (jfibs[i].jid == jid && strcmp(jfibs[i].jail, jail) == 0)
			n = jfibs[i].fibs;
	pthread_mutex_unlock(&jf_mtx);
	return (n);
}

/*
 * The FIBs of jail jid, its own net.fibs, read in it by the helper the
 * first time since it started and kept: on the worker (a fork and an
 * exec).  The host's when the helper does not tell.
 */
static int
jail_fibs(const char *jail, int jid)
{
	size_t	len;
	int	n, i;

	if ((n = jail_fibs_read(jail, jid)) > 0)
		return (n);
	if (helper_sysctl_int(jid, "net.fibs", &n) != 0 || n < 1) {
		len = sizeof(n);
		if (sysctlbyname("net.fibs", &n, &len, NULL, 0) != 0 || n < 1)
			n = 1;
	}
	pthread_mutex_lock(&jf_mtx);
	for (i = 0; i < njfibs; i++)
		if (strcmp(jfibs[i].jail, jail) == 0)
			break;
	if (i == njfibs) {
		/* Full: the first one's place taken. */
		if (njfibs < JFIBS_MAX)
			njfibs++;
		else
			i = 0;
	}
	snprintf(jfibs[i].jail, sizeof(jfibs[i].jail), "%s", jail);
	jfibs[i].jid = jid;
	jfibs[i].fibs = n;
	pthread_mutex_unlock(&jf_mtx);
	logmsg(LOG_DEBUG, "probe: jail %s has %d FIB%s", jail, n, n == 1 ?
	    "" : "s");
	return (n);
}

/* Every FIB's socket of family af, up to RX_FIBS, kept from now on: a
 * reply may come in on an interface of another table. */
static void
fsock_listen(int af)
{
	struct fsock	*f;
	char		 e[128];
	int		 fd, nf;

	nf = listen_fibs();
	for (int fib = 0; fib < nf; fib++)
		if ((fd = fsock_get(af, fib, e, sizeof(e))) != -1 &&
		    (f = fsock_of(fd)) != NULL)
			f->listen = true;
}

/* A jail's socket kept for the replies that was not made: asked again
 * later, the wait doubling as a target's. */
static void
jsock_later(struct jsock *j, double now)
{

	j->open_wait = j->open_wait <= 0 ? JS_RETRY : j->open_wait * 2;
	if (j->open_wait > JS_RETRY_MAX)
		j->open_wait = JS_RETRY_MAX;
	j->open_at = now + j->open_wait;
}

/* Every FIB's socket of family af in jail, up to RX_FIBS and the FIBs
 * the jail has (once read), kept for the replies: those there marked,
 * the others to be asked of the worker (jsock_ask()), as many as there
 * is room for. */
static void
jsock_listen(const char *jail, int af)
{
	struct jsock	*j;
	int		 nf, jid, jf;

	nf = listen_fibs();
	if (nf > 0 && (jid = jail_getid(jail)) >= 0 && (jf =
	    jail_fibs_read(jail, jid)) > 0 && jf < nf)
		nf = jf;
	for (int fib = 0; fib < nf; fib++) {
		if ((j = jsock_find(jail, fib, af)) == NULL) {
			if (njsocks == JSOCKS_MAX)
				return;
			j = &jsocks[njsocks++];
			memset(j, 0, sizeof(*j));
			snprintf(j->jail, sizeof(j->jail), "%s", jail);
			j->fd = -1;
			j->af = af;
			j->fib = fib;
		}
		j->listen = true;
	}
}

/*
 * The next jail's socket kept for the replies that is due to be asked
 * of the worker: its jail (len), FIB, family and answer *genp, now being
 * made; false, none is.
 */
bool
jsock_ask(double now, char *jail, size_t len, int *fib, int *af,
    uint32_t *genp)
{
	struct jsock	*j;

	for (int i = 0; i < njsocks; i++) {
		j = &jsocks[i];
		if (!j->listen || j->opening || j->fd != -1 || now < j->open_at)
			continue;
		j->opening = true;
		j->gen = *genp = ++jgen;
		snprintf(jail, len, "%s", j->jail);
		*fib = j->fib;
		*af = j->af;
		return (true);
	}
	return (false);
}

/*
 * Its echo socket, its FIB's, the host's (a jail's is its jail's, FIB's
 * and family's: jsock_want()); false and why when it is not made.
 */
bool
target_open(struct target *t)
{

	/* Kind stamp: no echo, so no raw socket (nor root) needed; its UDP
	 * socket is made as it sends (probe_stamp.c). */
	if (t->kind == KIND_STAMP) {
		t->error[0] = '\0';
		return (true);
	}
	if (t->jail[0] != '\0')
		return (false);
	if ((t->sock = fsock_get(t->af, t->fib, t->error,
	    sizeof(t->error))) == -1)
		return (false);
	/* Its reply may come in on an interface of another table. */
	if (t->fib != 0)
		fsock_listen(t->af);
	t->error[0] = '\0';
	return (true);
}

/*
 * A jail's echo socket of FIB fib, made in its network by the helper,
 * its FIB set there, so that its routing tables carry the probes: a fork
 * and an exec, so on the engine's worker, never its thread.  The
 * descriptor, or -1 and why in err; *lacks, the jail has no such FIB
 * (its own net.fibs).
 */
int
jail_socket(const char *jail, int af, int fib, char *err, size_t len,
    bool *lacks)
{
	int	jid, s, nf;

	*lacks = false;
	if ((jid = jail_getid(jail)) < 0) {
		snprintf(err, len, "jail %s is not running", jail);
		return (-1);
	}
	if (fib > 0 && fib >= (nf = jail_fibs(jail, jid))) {
		*lacks = true;
		snprintf(err, len, "jail %s has no FIB %d (its net.fibs is "
		    "%d)", jail, fib, nf);
		return (-1);
	}
	if ((s = helper_icmp_socket(jid, af, fib)) == -1) {
		snprintf(err, len, "no socket in jail %s (probing needs root)",
		    jail);
		return (-1);
	}
	(void)fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
	return (s);
}

/*
 * A jail's target's echo socket, the one of its jail, FIB and family:
 * JS_HAVE, t->sock it; JS_WAIT, being made, the target waits for the
 * worker's answer (jsock_made()); JS_ASK, the target the first to need
 * it (or the one kept for the replies not made), the worker to be asked
 * for answer *genp; JS_FULL, none to be had, why in t->error.
 */
int
jsock_want(struct target *t, uint32_t *genp)
{
	struct jsock	*j;

	if ((j = jsock_find(t->jail, t->fib, t->af)) != NULL) {
		if (j->opening)
			return (JS_WAIT);
		if (j->fd != -1) {
			t->sock = j->fd;
			t->error[0] = '\0';
			return (JS_HAVE);
		}
		/* Kept for the replies and not made: asked again now. */
		j->opening = true;
		j->gen = *genp = ++jgen;
		return (JS_ASK);
	}
	if (njsocks == JSOCKS_MAX) {
		snprintf(t->error, sizeof(t->error), "socket: %s",
		    strerror(EMFILE));
		return (JS_FULL);
	}
	j = &jsocks[njsocks++];
	memset(j, 0, sizeof(*j));
	snprintf(j->jail, sizeof(j->jail), "%s", t->jail);
	j->fd = -1;
	j->af = t->af;
	j->fib = t->fib;
	j->opening = true;
	j->gen = *genp = ++jgen;
	return (JS_ASK);
}

/*
 * The worker's answer gen for jail's socket of FIB fib and family af: fd
 * the helper's (in its table), or -1 and why in err (lacks: the jail
 * has no such FIB).  Set up (timed, IPv6's replies alone) and kept, its
 * descriptor for the targets that wait for it (wanted), or kept for the
 * replies alone; -1, the waiting to be told why (err); -2, nothing to
 * tell (not waited for: closed, or one kept for the replies to be asked
 * again later, from now, unless the jail lacks its FIB).
 */
int
jsock_made(const char *jail, int fib, int af, uint32_t gen, int fd,
    bool lacks, bool wanted, double now, const char *err)
{
	struct jsock	*j;
	int		 rcv;

	if ((j = jsock_find(jail, fib, af)) == NULL || !j->opening ||
	    j->gen != gen) {
		if (fd != -1)
			close(fd);
		return (-2);
	}
	j->opening = false;
	if (fd == -1 && j->listen && !lacks) {
		logmsg(LOG_DEBUG, "probe: no echo socket of jail %s, FIB %d, "
		    "%s: %s", jail, fib, af == AF_INET ? "inet" : "inet6",
		    err != NULL ? err : "not asked");
		jsock_later(j, now);
		return (wanted ? -1 : -2);
	}
	j->fd = fd;
	if (fd == -1 || (!wanted && !j->listen)) {
		jsock_drop(j);
		return (wanted ? -1 : -2);
	}
	icmp_timed(fd);
	for (rcv = RCVBUF; rcv >= 16 * 1024 && setsockopt(fd, SOL_SOCKET,
	    SO_RCVBUF, &rcv, sizeof(rcv)) == -1; rcv /= 2)
		;
	if (af == AF_INET6)
		icmp6_replies(fd);
	j->open_wait = 0;
	logmsg(LOG_DEBUG, "probe: echo socket of jail %s, FIB %d, %s", jail,
	    fib, af == AF_INET ? "inet" : "inet6");
	return (fd);
}

/*
 * The table's targets (n of them) as the sockets know them, at each
 * change of them: the host's echo ids and the jails' for the replies,
 * the jails' sockets kept for every FIB's replies, and each socket's
 * users; one no target uses, and kept for no FIB's replies (nor being
 * made), closed.
 */
void
icmp_table(struct target *v, int n)
{
	int	i, k;
	bool	other[2] = { false, false };

	/* A jail's target in another table than 0: every FIB's socket of
	 * its family in the jail kept for the replies. */
	for (k = 0; k < njsocks; k++)
		jsocks[k].listen = false;
	for (i = 0; i < n; i++)
		if (v[i].id[0] != '\0' && v[i].jail[0] != '\0' && v[i].fib !=
		    0 && v[i].kind != KIND_STAMP)
			jsock_listen(v[i].jail, v[i].af);

	echo_ids_clear(&ids);
	echo_ids_clear(&jids);
	for (i = 0; i < n; i++)
		if (v[i].id[0] != '\0' && v[i].jail[0] != '\0')
			echo_ids_add(&jids, v[i].af, v[i].ident, i);
		else if (v[i].id[0] != '\0') {
			echo_ids_add(&ids, v[i].af, v[i].ident, i);
			if (v[i].fib != 0 && v[i].kind != KIND_STAMP)
				other[v[i].af == AF_INET6] = true;
		}
	echo_ids_sort(&ids);
	echo_ids_sort(&jids);
	/* No target of a family in another table than 0 any more: its
	 * sockets no longer kept for the replies. */
	for (k = 0; k < nfsocks; k++) {
		fsocks[k].users = 0;
		if (!other[fsocks[k].af == AF_INET6])
			fsocks[k].listen = false;
	}
	for (k = 0; k < njsocks; k++)
		jsocks[k].users = 0;
	for (i = 0; i < n; i++) {
		if (v[i].sock == -1)
			continue;
		for (k = 0; k < nfsocks; k++)
			if (fsocks[k].fd == v[i].sock)
				fsocks[k].users++;
		for (k = 0; k < njsocks; k++)
			if (jsocks[k].fd == v[i].sock)
				jsocks[k].users++;
	}
	for (k = 0; k < nfsocks; )
		if (fsocks[k].users == 0 && !fsocks[k].listen) {
			close(fsocks[k].fd);
			fsocks[k] = fsocks[--nfsocks];
		} else
			k++;
	for (k = 0; k < njsocks; )
		if (jsocks[k].users == 0 && !jsocks[k].opening &&
		    !jsocks[k].listen)
			jsock_drop(&jsocks[k]);
		else
			k++;
}

/* The sockets to poll, the FIBs' and the jails', into pfd (max), each
 * one's family into afs: how many. */
int
icmp_pollfds(struct pollfd *pfd, int *afs, int max)
{
	int	i, n;

	for (n = 0; n < nfsocks && n < max; n++) {
		pfd[n].fd = fsocks[n].fd;
		pfd[n].events = POLLIN;
		pfd[n].revents = 0;
		afs[n] = fsocks[n].af;
	}
	for (i = 0; i < njsocks && n < max; i++) {
		if (jsocks[i].opening || jsocks[i].fd == -1)
			continue;
		pfd[n].fd = jsocks[i].fd;
		pfd[n].events = POLLIN;
		pfd[n].revents = 0;
		afs[n++] = jsocks[i].af;
	}
	return (n);
}

static uint16_t
cksum(const void *p, size_t len)
{
	const uint16_t	*w = p;
	uint32_t	 sum;

	sum = 0;
	while (len > 1) {
		sum += *w++;
		len -= 2;
	}
	if (len == 1)
		sum += *(const uint8_t *)w;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return ((uint16_t)~sum);
}

/* An echo request (len bytes) to the target, with its DSCP, on its
 * FIB's socket or its jail's: for this packet. */
static ssize_t
icmp_out(struct target *t, const unsigned char *pkt, size_t len)
{
	struct fsock	*f;
	struct jsock	*j;
	struct msghdr	 msg;
	struct iovec	 iov;
	struct cmsghdr	*cm;
	union {
		struct cmsghdr	hdr;
		char		buf[CMSG_SPACE(sizeof(int))];
	}		 cout;
	int		 v = t->dscp << 2;

	int		*tos;

	if ((f = fsock_of(t->sock)) != NULL)
		tos = &f->tos;
	else if ((j = jsock_of(t->sock)) != NULL)
		tos = &j->tos;
	else
		return (sendto(t->sock, pkt, len, 0, (const struct sockaddr *)
		    &t->sa, t->sa.ss_len));
	if (t->af == AF_INET) {
		if (*tos != v && setsockopt(t->sock, IPPROTO_IP, IP_TOS, &v,
		    sizeof(v)) == 0)
			*tos = v;
		return (sendto(t->sock, pkt, len, 0, (const struct sockaddr *)
		    &t->sa, t->sa.ss_len));
	}
	memset(&msg, 0, sizeof(msg));
	memset(&cout, 0, sizeof(cout));
	iov.iov_base = __DECONST(unsigned char *, pkt);
	iov.iov_len = len;
	msg.msg_name = &t->sa;
	msg.msg_namelen = t->sa.ss_len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cout.buf;
	msg.msg_controllen = sizeof(cout.buf);
	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_level = IPPROTO_IPV6;
	cm->cmsg_type = IPV6_TCLASS;
	cm->cmsg_len = CMSG_LEN(sizeof(v));
	memcpy(CMSG_DATA(cm), &v, sizeof(v));
	return (sendmsg(t->sock, &msg, 0));
}

/* An echo request, timed as it goes (not by the prober's pass). */
void
icmp_send(struct target *t)
{
	unsigned char	pkt[PKT_MAX];
	size_t		len;
	int		slot;
	bool		full;

	/* A slot: the oldest in the air gone, if none is free. */
	slot = echo_slot(t->out, OUT_MAX, &full);
	if (full)
		miss(t);
	len = (size_t)t->size;
	if (len < 8)
		len = 8;
	memset(pkt, 0, len);
	t->seq++;
	if (t->af == AF_INET) {
		struct icmp	*ic = (struct icmp *)(void *)pkt;

		ic->icmp_type = ICMP_ECHO;
		ic->icmp_code = 0;
		ic->icmp_id = htons(t->ident);
		ic->icmp_seq = htons(t->seq);
		ic->icmp_cksum = 0;
		ic->icmp_cksum = cksum(pkt, len);
	} else {
		struct icmp6_hdr	*ic = (struct icmp6_hdr *)(void *)pkt;

		ic->icmp6_type = ICMP6_ECHO_REQUEST;
		ic->icmp6_code = 0;
		ic->icmp6_id = htons(t->ident);
		ic->icmp6_seq = htons(t->seq);
	}
	t->out[slot].seq = t->seq;
	t->out[slot].sent = now_s();
	t->out[slot].live = true;
	t->sent++;
	if (icmp_out(t, pkt, len) == -1) {
		t->out[slot].live = false;
		miss(t);
		snprintf(t->error, sizeof(t->error), "sendto: %s",
		    strerror(errno));
	} else
		t->error[0] = '\0';
}

/*
 * A reply read into pkt (len bytes), and when it came in (*at), as the
 * kernel timed it (SCM_MONOTONIC), else now; its length, or -1.
 */
static ssize_t
icmp_recv(int sock, unsigned char *pkt, size_t len, double now, double *at)
{
	struct sockaddr_storage	 from;
	struct msghdr		 msg;
	struct iovec		 iov;
	struct cmsghdr		*cm;
	struct timespec		 ts;
	union {
		struct cmsghdr	hdr;
		char		buf[256];
	}			 cin;
	ssize_t			 n;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = pkt;
	iov.iov_len = len;
	msg.msg_name = &from;
	msg.msg_namelen = sizeof(from);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cin.buf;
	msg.msg_controllen = sizeof(cin.buf);
	if ((n = recvmsg(sock, &msg, 0)) <= 0)
		return (-1);
	*at = now;
	for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm))
		if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type ==
		    SCM_MONOTONIC && cm->cmsg_len >= CMSG_LEN(sizeof(ts))) {
			memcpy(&ts, CMSG_DATA(cm), sizeof(ts));
			*at = (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
		}
	return (n);
}

/* The reply of sequence seq to the target: a hit, its round trip from
 * when it went to when the kernel took it in; else passed over. */
static void
icmp_reply(struct target *t, uint16_t seq, double at)
{
	int	slot;

	if ((slot = echo_take(t->out, OUT_MAX, seq)) == -1)
		return;
	if (at < t->out[slot].sent)
		at = t->out[slot].sent;
	hit(t, (at - t->out[slot].sent) * 1000);
	pm_hit(t, (at - t->out[slot].sent) * 1000, NULL);
}

/* What a socket fd of family af has, a FIB's or a jail's: each echo
 * reply to the target of its id, of the table v (n of them), the host's
 * or, on a jail's socket (its own FIB's or another's, kept for the
 * replies), one of that jail's. */
void
icmp_recv_sock(int fd, int af, struct target *v, int n, double now)
{
	const struct echo_ids	*e;
	const struct jsock	*js;
	unsigned char		 pkt[PKT_MAX + 64];
	ssize_t			 len;
	double			 at;
	uint16_t		 id, seq;
	int			 i;

	js = jsock_of(fd);
	e = js != NULL ? &jids : &ids;
	for (;;) {
		if ((len = icmp_recv(fd, pkt, sizeof(pkt), now, &at)) <= 0)
			return;
		if (echo_parse(af, pkt, (size_t)len, &id, &seq) != 0 ||
		    (i = echo_ids_find(e, af, id)) < 0 || i >= n ||
		    (js != NULL && strcmp(v[i].jail, js->jail) != 0))
			continue;
		icmp_reply(&v[i], seq, at);
	}
}
