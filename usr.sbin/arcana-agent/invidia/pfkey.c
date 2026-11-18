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
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include <net/pfkeyv2.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netipsec/ipsec.h>

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
	dump = q->sadb_msg_type == SADB_DUMP;
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
		    q->sadb_msg_seq))
			continue;
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
