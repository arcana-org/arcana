/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * PF_KEYv2 (RFC 2367) in the agent's own process: the messages
 * setkey(8) sends, built here as its parse.y builds them, on a PF_KEY
 * socket of the host's network or, for work in a vnet jail, of the
 * jail's (the helper makes it there, scope.c).  Each request's reply
 * is read back, told apart from the kernel's copies of other sockets'
 * messages by its sequence number and this process's id.  The keys are
 * in the messages alone, never in a step or a title.
 *
 * Only SADB_ADD, SADB_DELETE, SADB_GET and SADB_DUMP: the kernel
 * updates a larval SA (SADB_GETSPI's, an IKE daemon's) and, of a
 * mature one, only its lifetimes and NAT-T addresses (key_update()), so
 * manual keys change by a new SA, its own SPI.
 *
 * The SPD: SADB_X_SPDADD with the policy as libipsec's
 * ipsec_set_policy(3) lays it out (struct sadb_x_policy, then each
 * request and its two addresses) and the selector as setkey(8)'s
 * spdadd sends it; SADB_X_SPDDUMP; SADB_X_SPDDELETE2, by the id a dump
 * read, never SADB_X_SPDDELETE, by the selector, which takes whichever
 * policy has it (key_spddelete()).  A policy of an ipsec(4) interface
 * is scoped to it (IPSEC_POLICYSCOPE_IFNET, its index in the priority
 * field); the rest are global, sorted by priority, setkey's 0 first.
 *
 * The kernel's news (6.2.3, sadb.c): a socket SADB_REGISTERed is sent
 * SADB_ACQUIRE and SADB_EXPIRE as they happen, between the replies to
 * what it asks; a thread that registered its socket gives them, as they
 * come, to the hook it set (pfkey_news()).
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include <net/if.h>
#include <net/pfkeyv2.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netipsec/ipsec.h>

#include <arpa/inet.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "agent.h"

/* A message as it is built: the largest, an SA added with both keys
 * and NAT-T, is under 500 bytes. */
struct pkmsg {
	unsigned char	buf[1024] __aligned(8);
	size_t		len;
	bool		over;
};

static uint32_t	pk_seq;

/* The kernel's news met on this thread's registered socket. */
static __thread void	(*pk_news)(const struct sadb_msg *, size_t, void *);
static __thread void	*pk_news_arg;

/* What the kernel tells a registered socket, as it comes on this
 * thread's sockets, given to fn; NULL none. */
void
pfkey_news(void (*fn)(const struct sadb_msg *, size_t, void *), void *arg)
{

	pk_news = fn;
	pk_news_arg = arg;
}

/* The socket: a test's stand-in, the jail's, or the host's. */
int
pfkey_open(struct work *w, const char **errp)
{
	struct sockaddr_un	sun;
	struct timeval		tv;
	int			fd;

	if (opts.pfkey_path != NULL) {
		/* Records, as PF_KEY's are: a message a read. */
		memset(&sun, 0, sizeof(sun));
		sun.sun_family = AF_UNIX;
		if (strlcpy(sun.sun_path, opts.pfkey_path,
		    sizeof(sun.sun_path)) >= sizeof(sun.sun_path)) {
			*errp = "PF_KEY: the stand-in's path is too long";
			return (-1);
		}
		if ((fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0)) !=
		    -1 && connect(fd, (struct sockaddr *)&sun,
		    sizeof(sun)) == -1) {
			*errp = wfmt(w, "PF_KEY: %s: %s", opts.pfkey_path,
			    strerror(errno));
			close(fd);
			return (-1);
		}
	} else if (w->jail != NULL) {
		if ((fd = helper_pfkey_socket(w->jid)) == -1) {
			*errp = wfmt(w, "PF_KEY: no socket in the jail %s's "
			    "network", w->jail);
			return (-1);
		}
	} else
		fd = socket(PF_KEY, SOCK_RAW | SOCK_CLOEXEC, PF_KEY_V2);
	if (fd == -1) {
		*errp = wfmt(w, "PF_KEY: %s%s", strerror(errno), errno ==
		    EPROTONOSUPPORT || errno == EAFNOSUPPORT ? " (is ipsec.ko "
		    "loaded?)" : "");
		return (-1);
	}
	/* The kernel answers at once: a reply not there in this long
	 * never comes. */
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return (fd);
}

static void
pk_init(struct pkmsg *m, uint8_t type)
{
	struct sadb_msg	*h;

	memset(m, 0, sizeof(*m));
	h = (struct sadb_msg *)(void *)m->buf;
	h->sadb_msg_version = PF_KEY_V2;
	h->sadb_msg_type = type;
	h->sadb_msg_satype = SADB_SATYPE_ESP;
	h->sadb_msg_seq = __atomic_add_fetch(&pk_seq, 1, __ATOMIC_RELAXED);
	if (h->sadb_msg_seq == 0)
		h->sadb_msg_seq = __atomic_add_fetch(&pk_seq, 1,
		    __ATOMIC_RELAXED);
	h->sadb_msg_pid = (uint32_t)getpid();
	m->len = sizeof(*h);
}

/* An extension of len bytes and data after it, 8-byte aligned, its
 * length and type filled in; NULL when the message has no room. */
static void *
pk_ext(struct pkmsg *m, uint16_t type, size_t len, const void *data,
    size_t dlen)
{
	struct sadb_ext	*e;
	size_t		 n;

	n = PFKEY_ALIGN8(len + dlen);
	if (m->over || m->len + n > sizeof(m->buf)) {
		m->over = true;
		return (NULL);
	}
	e = (struct sadb_ext *)(void *)(m->buf + m->len);
	e->sadb_ext_len = PFKEY_UNIT64(n);
	e->sadb_ext_type = type;
	if (dlen > 0)
		memcpy(m->buf + m->len + len, data, dlen);
	m->len += n;
	return (e);
}

static void
pk_addr(struct pkmsg *m, uint16_t type, const struct sockaddr *sa)
{
	struct sadb_address	*a;

	if ((a = pk_ext(m, type, sizeof(*a), sa, sa->sa_len)) == NULL)
		return;
	a->sadb_address_proto = IPSEC_ULPROTO_ANY;
	a->sadb_address_prefixlen = sa->sa_family == AF_INET6 ? 128 : 32;
}

static void
pk_key(struct pkmsg *m, uint16_t type, const unsigned char *key, size_t len)
{
	struct sadb_key	*k;

	if ((k = pk_ext(m, type, sizeof(*k), key, len)) != NULL)
		k->sadb_key_bits = (uint16_t)(len * 8);
}

static const char *
pk_name(uint8_t type)
{

	switch (type) {
	case SADB_ADD:
		return ("SADB_ADD");
	case SADB_DELETE:
		return ("SADB_DELETE");
	case SADB_GET:
		return ("SADB_GET");
	case SADB_DUMP:
		return ("SADB_DUMP");
	case SADB_X_SPDADD:
		return ("SADB_X_SPDADD");
	case SADB_X_SPDDELETE2:
		return ("SADB_X_SPDDELETE2");
	case SADB_X_SPDDUMP:
		return ("SADB_X_SPDDUMP");
	case SADB_REGISTER:
		return ("SADB_REGISTER");
	}
	return ("PF_KEY");
}

/*
 * m sent and its replies read: each given to fn, if any, until the
 * last (a dump's has sequence number 0).  0, or -1 and why, errno the
 * kernel's.
 */
static int
pk_call(struct work *w, int fd, struct pkmsg *m,
    void (*fn)(const struct sadb_msg *, size_t, void *), void *arg,
    const char **errp)
{
	const struct sadb_msg	*q, *r;
	unsigned char		 rbuf[4096] __aligned(8);
	ssize_t			 n;
	bool			 dump;

	q = (const struct sadb_msg *)(void *)m->buf;
	if (m->over) {
		*errp = wfmt(w, "%s: the message is too long", pk_name(
		    q->sadb_msg_type));
		errno = EMSGSIZE;
		return (-1);
	}
	((struct sadb_msg *)(void *)m->buf)->sadb_msg_len = PFKEY_UNIT64(m->len);
	if (send(fd, m->buf, m->len, 0) != (ssize_t)m->len) {
		*errp = wfmt(w, "%s: send: %s", pk_name(q->sadb_msg_type),
		    strerror(errno));
		return (-1);
	}
	dump = q->sadb_msg_type == SADB_DUMP || q->sadb_msg_type ==
	    SADB_X_SPDDUMP;
	for (;;) {
		if ((n = recv(fd, rbuf, sizeof(rbuf), 0)) == -1) {
			if (errno == EINTR)
				continue;
			*errp = wfmt(w, "%s: %s", pk_name(q->sadb_msg_type),
			    errno == EAGAIN ? "no reply" : strerror(errno));
			return (-1);
		}
		if (n == 0) {
			*errp = wfmt(w, "%s: the socket was closed", pk_name(
			    q->sadb_msg_type));
			errno = ECONNRESET;
			return (-1);
		}
		r = (const struct sadb_msg *)(void *)rbuf;
		if ((size_t)n < sizeof(*r) || (size_t)PFKEY_UNUNIT64(r->sadb_msg_len)
		    != (size_t)n)
			continue;
		/* Another socket's, or the kernel's own news. */
		if (r->sadb_msg_pid != q->sadb_msg_pid || r->sadb_msg_type !=
		    q->sadb_msg_type || (!dump && r->sadb_msg_seq !=
		    q->sadb_msg_seq)) {
			if (pk_news != NULL && r->sadb_msg_pid == 0 &&
			    (r->sadb_msg_type == SADB_ACQUIRE ||
			    r->sadb_msg_type == SADB_EXPIRE))
				pk_news(r, (size_t)n, pk_news_arg);
			continue;
		}
		if (r->sadb_msg_errno != 0) {
			errno = r->sadb_msg_errno;
			*errp = wfmt(w, "%s: %s", pk_name(q->sadb_msg_type),
			    strerror(errno));
			OPENSSL_cleanse(rbuf, sizeof(rbuf));
			return (-1);
		}
		if (fn != NULL)
			fn(r, (size_t)n, arg);
		if (!dump || r->sadb_msg_seq == 0)
			break;
	}
	OPENSSL_cleanse(rbuf, sizeof(rbuf));
	return (0);
}

/* An SA put in by SADB_ADD: ESP on sa's reqid and mode, its window and
 * flags, NAT-T's ESP in UDP when it has ports. */
int
pfkey_add(struct work *w, int fd, const struct pfkey_sa *sa,
    const char **errp)
{
	struct pkmsg		 m;
	struct sadb_sa		*s;
	struct sadb_x_sa2	*s2;
	struct sadb_x_sa_replay	*rp;
	struct sadb_x_nat_t_type *nt;
	struct sadb_x_nat_t_port *np;
	int			 rc;

	pk_init(&m, SADB_ADD);
	if (sa->ekeylen > 0)
		pk_key(&m, SADB_EXT_KEY_ENCRYPT, sa->ekey, sa->ekeylen);
	if (sa->akeylen > 0)
		pk_key(&m, SADB_EXT_KEY_AUTH, sa->akey, sa->akeylen);
	if ((s = pk_ext(&m, SADB_EXT_SA, sizeof(*s), NULL, 0)) != NULL) {
		s->sadb_sa_spi = htonl(sa->spi);
		s->sadb_sa_replay = sa->replay > UINT8_MAX ? UINT8_MAX :
		    (uint8_t)sa->replay;
		s->sadb_sa_auth = sa->aalg;
		s->sadb_sa_encrypt = sa->ealg;
		s->sadb_sa_flags = sa->flags;
	}
	if ((s2 = pk_ext(&m, SADB_X_EXT_SA2, sizeof(*s2), NULL, 0)) != NULL) {
		s2->sadb_x_sa2_mode = sa->mode;
		s2->sadb_x_sa2_reqid = sa->reqid;
	}
	/* A window over 255 bytes: in packets, its own extension. */
	if (sa->replay > UINT8_MAX && (rp = pk_ext(&m, SADB_X_EXT_SA_REPLAY,
	    sizeof(*rp), NULL, 0)) != NULL)
		rp->sadb_x_sa_replay_replay = sa->replay << 3;
	if (sa->natt) {
		if ((nt = pk_ext(&m, SADB_X_EXT_NAT_T_TYPE, sizeof(*nt), NULL,
		    0)) != NULL)
			nt->sadb_x_nat_t_type_type = UDP_ENCAP_ESPINUDP;
		pk_addr(&m, SADB_X_EXT_NAT_T_OAI, (const struct sockaddr *)
		    &sa->src);
		if ((np = pk_ext(&m, SADB_X_EXT_NAT_T_SPORT, sizeof(*np), NULL,
		    0)) != NULL)
			np->sadb_x_nat_t_port_port = htons(sa->sport);
		pk_addr(&m, SADB_X_EXT_NAT_T_OAR, (const struct sockaddr *)
		    &sa->dst);
		if ((np = pk_ext(&m, SADB_X_EXT_NAT_T_DPORT, sizeof(*np), NULL,
		    0)) != NULL)
			np->sadb_x_nat_t_port_port = htons(sa->dport);
	}
	pk_addr(&m, SADB_EXT_ADDRESS_SRC, (const struct sockaddr *)&sa->src);
	pk_addr(&m, SADB_EXT_ADDRESS_DST, (const struct sockaddr *)&sa->dst);
	rc = pk_call(w, fd, &m, NULL, NULL, errp);
	OPENSSL_cleanse(&m, sizeof(m));
	return (rc);
}

/* The SA of spi from src to dst taken out; with spi 0, every ESP SA
 * from src to dst (the kernel's key_delete_all()). */
int
pfkey_delete(struct work *w, int fd, const struct sockaddr *src,
    const struct sockaddr *dst, uint32_t spi, const char **errp)
{
	struct pkmsg	 m;
	struct sadb_sa	*s;

	pk_init(&m, SADB_DELETE);
	if (spi != 0 && (s = pk_ext(&m, SADB_EXT_SA, sizeof(*s), NULL, 0)) !=
	    NULL)
		s->sadb_sa_spi = htonl(spi);
	pk_addr(&m, SADB_EXT_ADDRESS_SRC, src);
	pk_addr(&m, SADB_EXT_ADDRESS_DST, dst);
	return (pk_call(w, fd, &m, NULL, NULL, errp));
}

/* A reply's SA as struct pfkey_sa has it, without its keys. */
static void
pk_parse(const struct sadb_msg *r, size_t len, struct pfkey_sa *sa)
{
	const struct sadb_ext		*e;
	const struct sadb_sa		*s;
	const struct sadb_x_sa2		*s2;
	const struct sadb_lifetime	*lt;
	const struct sadb_address	*a;
	const struct sockaddr		*so;
	size_t				 off, n;

	memset(sa, 0, sizeof(*sa));
	for (off = sizeof(*r); off + sizeof(*e) <= len; off += n) {
		e = (const struct sadb_ext *)(const void *)((const char *)r +
		    off);
		n = PFKEY_UNUNIT64(e->sadb_ext_len);
		if (n < sizeof(*e) || off + n > len)
			break;
		switch (e->sadb_ext_type) {
		case SADB_EXT_SA:
			if (n < sizeof(*s))
				break;
			s = (const struct sadb_sa *)(const void *)e;
			sa->spi = ntohl(s->sadb_sa_spi);
			if (sa->replay == 0)
				sa->replay = s->sadb_sa_replay;
			sa->state = s->sadb_sa_state;
			sa->aalg = s->sadb_sa_auth;
			sa->ealg = s->sadb_sa_encrypt;
			sa->flags = s->sadb_sa_flags;
			break;
		case SADB_X_EXT_SA2:
			if (n < sizeof(*s2))
				break;
			s2 = (const struct sadb_x_sa2 *)(const void *)e;
			sa->mode = s2->sadb_x_sa2_mode;
			sa->reqid = s2->sadb_x_sa2_reqid;
			sa->seq = s2->sadb_x_sa2_sequence;
			break;
		case SADB_X_EXT_SA_REPLAY:
			if (n >= sizeof(struct sadb_x_sa_replay))
				sa->replay = ((const struct sadb_x_sa_replay *)
				    (const void *)e)->sadb_x_sa_replay_replay >>
				    3;
			break;
		case SADB_EXT_LIFETIME_CURRENT:
			if (n < sizeof(*lt))
				break;
			lt = (const struct sadb_lifetime *)(const void *)e;
			sa->packets = lt->sadb_lifetime_allocations;
			sa->bytes = lt->sadb_lifetime_bytes;
			sa->added = lt->sadb_lifetime_addtime;
			sa->used = lt->sadb_lifetime_usetime;
			break;
		case SADB_EXT_LIFETIME_SOFT:
			sa->lifetimes |= PFKEY_LT_SOFT;
			break;
		case SADB_EXT_LIFETIME_HARD:
			sa->lifetimes |= PFKEY_LT_HARD;
			break;
		case SADB_EXT_ADDRESS_SRC:
		case SADB_EXT_ADDRESS_DST:
			a = (const struct sadb_address *)(const void *)e;
			so = (const struct sockaddr *)(a + 1);
			if (n < sizeof(*a) + sizeof(*so) || so->sa_len >
			    sizeof(struct sockaddr_storage) || sizeof(*a) +
			    so->sa_len > n)
				break;
			memcpy(e->sadb_ext_type == SADB_EXT_ADDRESS_SRC ?
			    &sa->src : &sa->dst, so, so->sa_len);
			break;
		case SADB_X_EXT_NAT_T_TYPE:
			sa->natt = true;
			break;
		case SADB_X_EXT_NAT_T_SPORT:
		case SADB_X_EXT_NAT_T_DPORT:
			if (n < sizeof(struct sadb_x_nat_t_port))
				break;
			if (e->sadb_ext_type == SADB_X_EXT_NAT_T_SPORT)
				sa->sport = ntohs(((const struct
				    sadb_x_nat_t_port *)e)->sadb_x_nat_t_port_port);
			else
				sa->dport = ntohs(((const struct
				    sadb_x_nat_t_port *)e)->sadb_x_nat_t_port_port);
			break;
		}
	}
}

static void
pk_one(const struct sadb_msg *r, size_t len, void *arg)
{

	pk_parse(r, len, arg);
}

/* A message's SA (an SADB_EXPIRE's), as a reply's. */
void
pfkey_sa_of(const struct sadb_msg *r, size_t len, struct pfkey_sa *sa)
{

	pk_parse(r, len, sa);
}

/* This socket told the kernel's news (SADB_REGISTER, for ESP): SADB_ACQUIRE
 * and SADB_EXPIRE come to it from now on. */
int
pfkey_register(struct work *w, int fd, const char **errp)
{
	struct pkmsg	m;

	pk_init(&m, SADB_REGISTER);
	return (pk_call(w, fd, &m, NULL, NULL, errp));
}

/* The SA of spi from src to dst as the kernel has it (SADB_GET). */
int
pfkey_get(struct work *w, int fd, const struct sockaddr *src,
    const struct sockaddr *dst, uint32_t spi, struct pfkey_sa *sa,
    const char **errp)
{
	struct pkmsg	 m;
	struct sadb_sa	*s;

	memset(sa, 0, sizeof(*sa));
	pk_init(&m, SADB_GET);
	if ((s = pk_ext(&m, SADB_EXT_SA, sizeof(*s), NULL, 0)) != NULL)
		s->sadb_sa_spi = htonl(spi);
	pk_addr(&m, SADB_EXT_ADDRESS_SRC, src);
	pk_addr(&m, SADB_EXT_ADDRESS_DST, dst);
	return (pk_call(w, fd, &m, pk_one, sa, errp));
}

struct pk_each {
	void	(*fn)(const struct pfkey_sa *, void *);
	void	*arg;
};

static void
pk_each(const struct sadb_msg *r, size_t len, void *arg)
{
	struct pk_each	*e = arg;
	struct pfkey_sa	 sa;

	pk_parse(r, len, &sa);
	e->fn(&sa, e->arg);
}

/* Every ESP SA of the network, each given to fn (SADB_DUMP); none is
 * no error. */
int
pfkey_dump(struct work *w, int fd, void (*fn)(const struct pfkey_sa *,
    void *), void *arg, const char **errp)
{
	struct pkmsg	m;
	struct pk_each	e;

	pk_init(&m, SADB_DUMP);
	e.fn = fn;
	e.arg = arg;
	if (pk_call(w, fd, &m, pk_each, &e, errp) == -1)
		return (errno == ENOENT ? 0 : -1);
	return (0);
}

/* ---- The SPD ---------------------------------------------------------- */

/* A selector's address: its prefix and upper-layer protocol, the port
 * in the sockaddr (setkey's spdadd). */
static void
pk_spaddr(struct pkmsg *m, uint16_t type, const struct sockaddr *sa,
    uint8_t plen, uint8_t proto)
{
	struct sadb_address	*a;

	if ((a = pk_ext(m, type, sizeof(*a), sa, sa->sa_len)) == NULL)
		return;
	a->sadb_address_proto = proto;
	a->sadb_address_prefixlen = plen;
}

/* A reply's policy as struct pfkey_sp has it: its first request, and
 * how many there are. */
static void
pk_spparse(const struct sadb_msg *r, size_t len, struct pfkey_sp *sp)
{
	const struct sadb_ext		*e;
	const struct sadb_address	*a;
	const struct sadb_x_policy	*xp;
	const struct sadb_x_ipsecrequest *xr;
	const struct sockaddr		*so, *so2;
	size_t				 off, n, roff, rn;

	memset(sp, 0, sizeof(*sp));
	for (off = sizeof(*r); off + sizeof(*e) <= len; off += n) {
		e = (const struct sadb_ext *)(const void *)((const char *)r +
		    off);
		n = PFKEY_UNUNIT64(e->sadb_ext_len);
		if (n < sizeof(*e) || off + n > len)
			break;
		switch (e->sadb_ext_type) {
		case SADB_EXT_ADDRESS_SRC:
		case SADB_EXT_ADDRESS_DST:
			a = (const struct sadb_address *)(const void *)e;
			so = (const struct sockaddr *)(a + 1);
			if (n < sizeof(*a) + sizeof(*so) || so->sa_len >
			    sizeof(struct sockaddr_storage) || sizeof(*a) +
			    so->sa_len > n)
				break;
			sp->proto = a->sadb_address_proto;
			if (e->sadb_ext_type == SADB_EXT_ADDRESS_SRC) {
				memcpy(&sp->src, so, so->sa_len);
				sp->splen = a->sadb_address_prefixlen;
			} else {
				memcpy(&sp->dst, so, so->sa_len);
				sp->dplen = a->sadb_address_prefixlen;
			}
			break;
		case SADB_X_EXT_POLICY:
			if (n < sizeof(*xp))
				break;
			xp = (const struct sadb_x_policy *)(const void *)e;
			sp->type = xp->sadb_x_policy_type;
			sp->dir = xp->sadb_x_policy_dir;
			sp->scope = xp->sadb_x_policy_scope;
			sp->id = xp->sadb_x_policy_id;
			sp->priority = xp->sadb_x_policy_priority;
			for (roff = sizeof(*xp); roff + sizeof(*xr) <= n;
			    roff += rn) {
				xr = (const struct sadb_x_ipsecrequest *)(const
				    void *)((const char *)e + roff);
				rn = xr->sadb_x_ipsecrequest_len;
				if (rn < sizeof(*xr) || roff + rn > n)
					break;
				if (sp->nreq++ > 0)
					continue;
				sp->rproto = (uint8_t)xr->sadb_x_ipsecrequest_proto;
				sp->mode = xr->sadb_x_ipsecrequest_mode;
				sp->level = xr->sadb_x_ipsecrequest_level;
				sp->reqid = xr->sadb_x_ipsecrequest_reqid;
				if (rn < sizeof(*xr) + 2 * sizeof(*so))
					continue;
				so = (const struct sockaddr *)(xr + 1);
				so2 = (const struct sockaddr *)(const void *)
				    ((const char *)so + so->sa_len);
				if (so->sa_len < sizeof(*so) || so->sa_len >
				    sizeof(struct sockaddr_storage) ||
				    sizeof(*xr) + so->sa_len + sizeof(*so2) > rn ||
				    so2->sa_len > sizeof(struct sockaddr_storage) ||
				    sizeof(*xr) + so->sa_len + so2->sa_len > rn)
					continue;
				memcpy(&sp->tsrc, so, so->sa_len);
				memcpy(&sp->tdst, so2, so2->sa_len);
			}
			break;
		}
	}
}

/* A message's policy (an SADB_ACQUIRE's: its id and direction, the
 * SA's ends as the selector), as a reply's. */
void
pfkey_sp_of(const struct sadb_msg *r, size_t len, struct pfkey_sp *sp)
{

	pk_spparse(r, len, sp);
}

static void
pk_spone(const struct sadb_msg *r, size_t len, void *arg)
{
	struct pfkey_sp	*sp = arg;
	struct pfkey_sp	 got;

	/* The reply to SPDADD: the id, all the rest as asked. */
	pk_spparse(r, len, &got);
	sp->id = got.id;
}

/*
 * A policy put in (SADB_X_SPDADD): the selector, the direction, the
 * priority, and for an ipsec one its one request, the tunnel's ends
 * after it in tunnel mode; sp->id the kernel's, from its reply.
 */
int
pfkey_spdadd(struct work *w, int fd, struct pfkey_sp *sp, const char **errp)
{
	struct pkmsg			 m;
	struct sadb_x_policy		*xp;
	struct sadb_x_ipsecrequest	*xr;
	unsigned char			 req[sizeof(*xr) + 2 *
					     sizeof(struct sockaddr_storage)]
					     __aligned(8);
	size_t				 rlen;

	pk_init(&m, SADB_X_SPDADD);
	((struct sadb_msg *)(void *)m.buf)->sadb_msg_satype =
	    SADB_SATYPE_UNSPEC;
	rlen = 0;
	if (sp->type == IPSEC_POLICY_IPSEC) {
		memset(req, 0, sizeof(req));
		xr = (struct sadb_x_ipsecrequest *)(void *)req;
		rlen = sizeof(*xr);
		if (sp->mode == IPSEC_MODE_TUNNEL) {
			memcpy(req + rlen, &sp->tsrc, sp->tsrc.ss_len);
			rlen += sp->tsrc.ss_len;
			memcpy(req + rlen, &sp->tdst, sp->tdst.ss_len);
			rlen += sp->tdst.ss_len;
		}
		/* In bytes, as ipsec_set_policy() has it. */
		xr->sadb_x_ipsecrequest_len = (uint16_t)rlen;
		xr->sadb_x_ipsecrequest_proto = sp->rproto;
		xr->sadb_x_ipsecrequest_mode = sp->mode;
		xr->sadb_x_ipsecrequest_level = sp->level;
		xr->sadb_x_ipsecrequest_reqid = sp->reqid;
	}
	if ((xp = pk_ext(&m, SADB_X_EXT_POLICY, sizeof(*xp), req, rlen)) !=
	    NULL) {
		xp->sadb_x_policy_type = sp->type;
		xp->sadb_x_policy_dir = sp->dir;
		xp->sadb_x_policy_priority = sp->priority;
	}
	pk_spaddr(&m, SADB_EXT_ADDRESS_SRC, (const struct sockaddr *)&sp->src,
	    sp->splen, sp->proto);
	pk_spaddr(&m, SADB_EXT_ADDRESS_DST, (const struct sockaddr *)&sp->dst,
	    sp->dplen, sp->proto);
	return (pk_call(w, fd, &m, pk_spone, sp, errp));
}

/* The policy of id taken out (SADB_X_SPDDELETE2). */
int
pfkey_spddelete(struct work *w, int fd, uint32_t id, const char **errp)
{
	struct pkmsg		 m;
	struct sadb_x_policy	*xp;

	pk_init(&m, SADB_X_SPDDELETE2);
	((struct sadb_msg *)(void *)m.buf)->sadb_msg_satype =
	    SADB_SATYPE_UNSPEC;
	if ((xp = pk_ext(&m, SADB_X_EXT_POLICY, sizeof(*xp), NULL, 0)) != NULL)
		xp->sadb_x_policy_id = id;
	return (pk_call(w, fd, &m, NULL, NULL, errp));
}

struct pk_speach {
	void	(*fn)(const struct pfkey_sp *, void *);
	void	*arg;
};

static void
pk_speach(const struct sadb_msg *r, size_t len, void *arg)
{
	struct pk_speach	*e = arg;
	struct pfkey_sp		 sp;

	pk_spparse(r, len, &sp);
	e->fn(&sp, e->arg);
}

/* Every policy of the network, each given to fn (SADB_X_SPDDUMP), the
 * interfaces' too; none is no error. */
int
pfkey_spddump(struct work *w, int fd, void (*fn)(const struct pfkey_sp *,
    void *), void *arg, const char **errp)
{
	struct pkmsg		m;
	struct pk_speach	e;

	pk_init(&m, SADB_X_SPDDUMP);
	((struct sadb_msg *)(void *)m.buf)->sadb_msg_satype =
	    SADB_SATYPE_UNSPEC;
	e.fn = fn;
	e.arg = arg;
	if (pk_call(w, fd, &m, pk_speach, &e, errp) == -1)
		return (errno == ENOENT ? 0 : -1);
	return (0);
}

/* A selector's end as setkey -DP writes it: address/prefix[port]. */
static const char *
pk_sel(struct work *w, const struct sockaddr_storage *ss, uint8_t plen)
{
	char		 a[INET6_ADDRSTRLEN];
	const void	*v = ss;
	uint16_t	 port;

	a[0] = '\0';
	port = 0;
	if (ss->ss_family == AF_INET) {
		inet_ntop(AF_INET, &((const struct sockaddr_in *)v)->sin_addr,
		    a, sizeof(a));
		port = ntohs(((const struct sockaddr_in *)v)->sin_port);
	} else if (ss->ss_family == AF_INET6) {
		inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)v)->
		    sin6_addr, a, sizeof(a));
		port = ntohs(((const struct sockaddr_in6 *)v)->sin6_port);
	}
	return (port == 0 ? wfmt(w, "%s/%u[any]", a, plen) : wfmt(w,
	    "%s/%u[%u]", a, plen, port));
}

/* An upper-layer protocol as setkey -DP names it. */
static const char *
pk_proto(struct work *w, uint8_t proto)
{

	switch (proto) {
	case IPSEC_ULPROTO_ANY:
		return ("any");
	case IPPROTO_TCP:
		return ("tcp");
	case IPPROTO_UDP:
		return ("udp");
	case IPPROTO_ICMP:
		return ("icmp");
	case IPPROTO_ICMPV6:
		return ("ipv6-icmp");
	case IPPROTO_SCTP:
		return ("sctp");
	case IPPROTO_GRE:
		return ("gre");
	}
	return (wfmt(w, "%u", proto));
}

struct pk_text {
	struct work	*w;
	char		*text;
	size_t		 n;
};

static void
pk_text_one(const struct pfkey_sp *sp, void *arg)
{
	static const char *const dirs[] = { "any", "in", "out", "fwd" };
	static const char *const types[] = { "discard", "none", "ipsec",
	    "entrust", "bypass" };
	static const char *const modes[] = { "any", "transport", "tunnel" };
	static const char *const levels[] = { "default", "use", "require",
	    "unique" };
	struct pk_text	*t = arg;
	struct work	*w = t->w;
	char		 ifn[IF_NAMESIZE], a[INET6_ADDRSTRLEN], b[INET6_ADDRSTRLEN];
	const void	*va = &sp->tsrc, *vb = &sp->tdst;
	const char	*req, *scope;

	req = "";
	if (sp->type == IPSEC_POLICY_IPSEC && sp->nreq > 0) {
		a[0] = b[0] = '\0';
		if (sp->tsrc.ss_family == AF_INET) {
			inet_ntop(AF_INET, &((const struct sockaddr_in *)va)->
			    sin_addr, a, sizeof(a));
			inet_ntop(AF_INET, &((const struct sockaddr_in *)vb)->
			    sin_addr, b, sizeof(b));
		} else if (sp->tsrc.ss_family == AF_INET6) {
			inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)va)->
			    sin6_addr, a, sizeof(a));
			inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)vb)->
			    sin6_addr, b, sizeof(b));
		}
		req = wfmt(w, "\t%s/%s/%s%s%s/%s", sp->rproto == IPPROTO_ESP ?
		    "esp" : sp->rproto == IPPROTO_AH ? "ah" : sp->rproto ==
		    IPPROTO_IPCOMP ? "ipcomp" : "?", sp->mode < nitems(modes) ?
		    modes[sp->mode] : "?", a, a[0] != '\0' ? "-" : "", b,
		    sp->level < nitems(levels) ? levels[sp->level] : "?");
		if (sp->reqid != 0)
			req = wfmt(w, "%s%c%u", req, sp->reqid >
			    IPSEC_MANUAL_REQID_MAX ? '#' : ':', sp->reqid);
		req = wfmt(w, "%s\n", req);
		if (sp->nreq > 1)
			req = wfmt(w, "%s\t(%d requests more)\n", req,
			    sp->nreq - 1);
	}
	if (sp->scope == IPSEC_POLICYSCOPE_IFNET)
		scope = wfmt(w, "ifnet ifname=%s", if_indextoname(sp->priority,
		    ifn) != NULL ? ifn : "?");
	else
		scope = wfmt(w, "%s priority=%u%s", sp->scope ==
		    IPSEC_POLICYSCOPE_PCB ? "pcb" : "global", sp->priority,
		    sp->priority == PFKEY_SP_MARK && sp->type == IPSEC_POLICY_IPSEC ?
		    " (Arcana's)" : "");
	t->text = wfmt(w, "%s%s %s %s\n\t%s %s\n%s\tspid=%u scope=%s\n",
	    t->text, pk_sel(w, &sp->src, sp->splen), pk_sel(w, &sp->dst,
	    sp->dplen), pk_proto(w, sp->proto), sp->dir < nitems(dirs) ?
	    dirs[sp->dir] : "?", sp->type < nitems(types) ? types[sp->type] :
	    "?", req, sp->id, scope);
	t->n++;
}

/*
 * The SPD as setkey -DP shows it, read by SADB_X_SPDDUMP: each policy,
 * whose it is (an ipsec(4) interface's, Arcana's by its priority mark,
 * or the rest: ipsec.conf's, an IKE daemon's); NULL when it cannot be
 * read.
 */
const char *
pfkey_spd_text(struct work *w)
{
	struct pk_text	 t;
	const char	*e;
	int		 fd;

	e = NULL;
	if ((fd = pfkey_open(w, &e)) == -1)
		return (NULL);
	memset(&t, 0, sizeof(t));
	t.w = w;
	t.text = wstrdup(w, "");
	if (pfkey_spddump(w, fd, pk_text_one, &t, &e) == -1) {
		close(fd);
		return (NULL);
	}
	close(fd);
	return (t.n == 0 ? "No SPD entries.\n" : t.text);
}
