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
 * A jail's target is the exception: its socket is made by the helper
 * inside the jail (jail_socket(), on the engine's worker), so that the
 * jail's routing tables carry its probes: a host socket cannot stand in.
 * It is its own (own), its FIB and DSCP set on it, its replies read from
 * it alone.  An echo's round trip is timed by the kernel (SO_TIMESTAMP,
 * the monotonic clock), not by when the prober got to its reply.
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

/* Every FIB's socket of family af, up to RX_FIBS, kept from now on: a
 * reply may come in on an interface of another table. */
static void
fsock_listen(int af)
{
	struct fsock	*f;
	size_t		 len = sizeof(nfibs);
	char		 e[128];
	int		 fd, all = 0;
	size_t		 alen = sizeof(all);

	/* Raw sockets told to take every table's packets hear the reply on
	 * the target's own: no other needed (each would read it again). */
	if (sysctlbyname("net.inet.raw.bind_all_fibs", &all, &alen, NULL,
	    0) == 0 && all != 0)
		return;
	if (nfibs < 0 && (sysctlbyname("net.fibs", &nfibs, &len, NULL, 0) !=
	    0 || nfibs < 1))
		nfibs = 1;
	for (int fib = 0; fib < nfibs && fib < RX_FIBS; fib++)
		if ((fd = fsock_get(af, fib, e, sizeof(e))) != -1 &&
		    (f = fsock_of(fd)) != NULL)
			f->listen = true;
}

/*
 * Its echo socket, its FIB's, the host's (a jail's is made by the
 * worker: jail_socket()); false and why when it is not made.
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
	t->own = false;
	/* Its reply may come in on an interface of another table. */
	if (t->fib != 0)
		fsock_listen(t->af);
	t->error[0] = '\0';
	return (true);
}

/*
 * A jail's echo socket, made in its network by the helper so that its
 * routing tables carry the probes: a fork and an exec, so on the
 * engine's worker, never its thread.  The descriptor, or -1 and why in
 * err.
 */
int
jail_socket(const char *jail, int af, char *err, size_t len)
{
	int	jid, s;

	if ((jid = jail_getid(jail)) < 0) {
		snprintf(err, len, "jail %s is not running", jail);
		return (-1);
	}
	if ((s = helper_icmp_socket(jid, af)) == -1) {
		snprintf(err, len, "no socket in jail %s (probing needs root)",
		    jail);
		return (-1);
	}
	(void)fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
	return (s);
}

/* A jail's echo socket (t->sock, its own) set: its table, its DSCP, the
 * replies alone and timed; false and why when its table is refused. */
bool
target_setup(struct target *t)
{
	int	v;

	t->own = true;
	icmp_timed(t->sock);
	v = t->fib;
	if (setsockopt(t->sock, SOL_SOCKET, SO_SETFIB, &v, sizeof(v)) == -1) {
		snprintf(t->error, sizeof(t->error), "fib %d: %s", t->fib,
		    strerror(errno));
		target_close(t);
		return (false);
	}
	v = t->dscp << 2;
	if (t->af == AF_INET)
		(void)setsockopt(t->sock, IPPROTO_IP, IP_TOS, &v, sizeof(v));
	else {
		(void)setsockopt(t->sock, IPPROTO_IPV6, IPV6_TCLASS, &v,
		    sizeof(v));
		icmp6_replies(t->sock);
	}
	t->error[0] = '\0';
	return (true);
}

/*
 * The table's targets (n of them) as the FIBs' sockets know them, at
 * each change of them: the host's echo ids for the replies, and each
 * socket's users; one no target uses, and kept for no FIB's replies,
 * closed.
 */
void
icmp_table(struct target *v, int n)
{
	int	i, k;
	bool	other[2] = { false, false };

	echo_ids_clear(&ids);
	for (i = 0; i < n; i++)
		if (v[i].id[0] != '\0' && v[i].jail[0] == '\0') {
			echo_ids_add(&ids, v[i].af, v[i].ident, i);
			if (v[i].fib != 0 && v[i].kind != KIND_STAMP)
				other[v[i].af == AF_INET6] = true;
		}
	echo_ids_sort(&ids);
	/* No target of a family in another table than 0 any more: its
	 * sockets no longer kept for the replies. */
	for (k = 0; k < nfsocks; k++) {
		fsocks[k].users = 0;
		if (!other[fsocks[k].af == AF_INET6])
			fsocks[k].listen = false;
	}
	for (i = 0; i < n; i++)
		if (v[i].sock != -1 && !v[i].own)
			for (k = 0; k < nfsocks; k++)
				if (fsocks[k].fd == v[i].sock)
					fsocks[k].users++;
	for (k = 0; k < nfsocks; )
		if (fsocks[k].users == 0 && !fsocks[k].listen) {
			close(fsocks[k].fd);
			fsocks[k] = fsocks[--nfsocks];
		} else
			k++;
}

/* The FIBs' sockets to poll, into pfd (max), each one's family into
 * afs: how many. */
int
icmp_pollfds(struct pollfd *pfd, int *afs, int max)
{
	int	n;

	for (n = 0; n < nfsocks && n < max; n++) {
		pfd[n].fd = fsocks[n].fd;
		pfd[n].events = POLLIN;
		pfd[n].revents = 0;
		afs[n] = fsocks[n].af;
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

/* An echo request (len bytes) to the target, with its DSCP: on its own
 * socket, set; on its FIB's, for this packet. */
static ssize_t
icmp_out(struct target *t, const unsigned char *pkt, size_t len)
{
	struct fsock	*f;
	struct msghdr	 msg;
	struct iovec	 iov;
	struct cmsghdr	*cm;
	union {
		struct cmsghdr	hdr;
		char		buf[CMSG_SPACE(sizeof(int))];
	}		 cout;
	int		 v = t->dscp << 2;

	if (t->own || (f = fsock_of(t->sock)) == NULL)
		return (sendto(t->sock, pkt, len, 0, (const struct sockaddr *)
		    &t->sa, t->sa.ss_len));
	if (t->af == AF_INET) {
		if (f->tos != v && setsockopt(f->fd, IPPROTO_IP, IP_TOS, &v,
		    sizeof(v)) == 0)
			f->tos = v;
		return (sendto(f->fd, pkt, len, 0, (const struct sockaddr *)
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
	return (sendmsg(f->fd, &msg, 0));
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

/* What a FIB's socket fd of family af has: each echo reply to the
 * host's target of its id, of the table v (n of them). */
void
icmp_recv_fib(int fd, int af, struct target *v, int n, double now)
{
	unsigned char	 pkt[PKT_MAX + 64];
	ssize_t		 len;
	double		 at;
	uint16_t	 id, seq;
	int		 i;

	for (;;) {
		if ((len = icmp_recv(fd, pkt, sizeof(pkt), now, &at)) <= 0)
			return;
		if (echo_parse(af, pkt, (size_t)len, &id, &seq) != 0 ||
		    (i = echo_ids_find(&ids, af, id)) < 0 || i >= n)
			continue;
		icmp_reply(&v[i], seq, at);
	}
}

/* What a jail's target's own socket has: its echo replies. */
void
icmp_recv_own(struct target *t, double now)
{
	unsigned char	 pkt[PKT_MAX + 64];
	ssize_t		 len;
	double		 at;
	uint16_t	 id, seq;

	for (;;) {
		if ((len = icmp_recv(t->sock, pkt, sizeof(pkt), now, &at)) <= 0)
			return;
		if (echo_parse(t->af, pkt, (size_t)len, &id, &seq) != 0 ||
		    id != t->ident)
			continue;
		icmp_reply(t, seq, at);
	}
}
