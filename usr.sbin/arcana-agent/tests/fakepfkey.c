/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * fakepfkey: a stand-in for the kernel's PF_KEY (RFC 2367), for
 * agent_test.sh's SA cases, which arcana-agent --pfkey speaks to on a
 * unix socket.  It keeps the SAs added and answers SADB_ADD,
 * SADB_DELETE, SADB_GET and SADB_DUMP as the kernel does (RFC 2367,
 * sys/netipsec/key.c), and writes each message it is sent to the log
 * as setkey(8)'s line of it, read from the message's own bytes.  While
 * the file refuse names is there, it refuses SADB_ADD (EINVAL).
 *
 * usage: fakepfkey socket log refuse
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <net/pfkeyv2.h>
#include <netinet/in.h>

#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	NCLIENTS	16
#define	NSAS		64

struct entry {
	struct sockaddr_storage	 src, dst;
	uint32_t		 spi;
	unsigned char		 msg[1024] __aligned(8);
	size_t			 len;
};

static struct entry	 sas[NSAS];
static size_t		 nsas;
static const char	*logpath, *refuse;

/* What a message says, as found in its extensions. */
struct parsed {
	const struct sadb_sa		*sa;
	const struct sadb_x_sa2		*sa2;
	const struct sadb_x_sa_replay	*replay;
	const struct sadb_address	*src, *dst, *oai, *oar;
	const struct sadb_key		*ekey, *akey;
	const struct sadb_x_nat_t_type	*ntype;
	const struct sadb_x_nat_t_port	*sport, *dport;
	bool				 bad;
};

static void
parse(const unsigned char *buf, size_t len, struct parsed *p)
{
	const struct sadb_ext	*e;
	size_t			 off, n;

	memset(p, 0, sizeof(*p));
	for (off = sizeof(struct sadb_msg); off < len; off += n) {
		e = (const struct sadb_ext *)(const void *)(buf + off);
		n = PFKEY_UNUNIT64(e->sadb_ext_len);
		if (off + sizeof(*e) > len || n < sizeof(*e) || off + n > len ||
		    n % 8 != 0) {
			p->bad = true;
			return;
		}
		switch (e->sadb_ext_type) {
		case SADB_EXT_SA:
			p->sa = (const void *)e;
			break;
		case SADB_X_EXT_SA2:
			p->sa2 = (const void *)e;
			break;
		case SADB_X_EXT_SA_REPLAY:
			p->replay = (const void *)e;
			break;
		case SADB_EXT_ADDRESS_SRC:
			p->src = (const void *)e;
			break;
		case SADB_EXT_ADDRESS_DST:
			p->dst = (const void *)e;
			break;
		case SADB_X_EXT_NAT_T_OAI:
			p->oai = (const void *)e;
			break;
		case SADB_X_EXT_NAT_T_OAR:
			p->oar = (const void *)e;
			break;
		case SADB_EXT_KEY_ENCRYPT:
			p->ekey = (const void *)e;
			break;
		case SADB_EXT_KEY_AUTH:
			p->akey = (const void *)e;
			break;
		case SADB_X_EXT_NAT_T_TYPE:
			p->ntype = (const void *)e;
			break;
		case SADB_X_EXT_NAT_T_SPORT:
			p->sport = (const void *)e;
			break;
		case SADB_X_EXT_NAT_T_DPORT:
			p->dport = (const void *)e;
			break;
		default:
			p->bad = true;
		}
	}
}

static const struct sockaddr *
addr_of(const struct sadb_address *a)
{

	return ((const struct sockaddr *)(a + 1));
}

static const char *
addr_str(const struct sadb_address *a, char *buf, size_t len)
{
	const struct sockaddr	*sa = addr_of(a);
	const void		*v = sa;

	if (sa->sa_family == AF_INET)
		inet_ntop(AF_INET, &((const struct sockaddr_in *)v)->sin_addr,
		    buf, len);
	else if (sa->sa_family == AF_INET6)
		inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)v)->
		    sin6_addr, buf, len);
	else
		snprintf(buf, len, "?");
	return (buf);
}

static bool
same_addr(const struct sockaddr *a, const struct sockaddr_storage *b)
{

	return (a->sa_len == b->ss_len && memcmp(a, b, a->sa_len) == 0);
}

static const char *
ealg(int n)
{

	return (n == SADB_X_EALG_AESCBC ? "aes-cbc" : n == SADB_X_EALG_AESGCM16
	    ? "aes-gcm-16" : "?");
}

static const char *
aalg(int n)
{

	return (n == SADB_AALG_SHA1HMAC ? "hmac-sha1" : n ==
	    SADB_X_AALG_SHA2_256 ? "hmac-sha2-256" : n == SADB_X_AALG_SHA2_512 ?
	    "hmac-sha2-512" : "?");
}

static void
key_hex(FILE *fp, const struct sadb_key *k)
{
	const unsigned char	*b = (const unsigned char *)(k + 1);

	fprintf(fp, "0x");
	for (int i = 0; i < k->sadb_key_bits / 8; i++)
		fprintf(fp, "%02x", b[i]);
}

/* The message as setkey(8)'s line of it. */
static void
log_msg(const struct sadb_msg *m, const struct parsed *p)
{
	FILE	*fp;
	char	 s[INET6_ADDRSTRLEN], d[INET6_ADDRSTRLEN];
	int	 mode;

	if ((fp = fopen(logpath, "a")) == NULL)
		err(1, "%s", logpath);
	if (p->bad || m->sadb_msg_version != PF_KEY_V2 ||
	    (m->sadb_msg_type != SADB_DUMP && (p->src == NULL || p->dst ==
	    NULL)))
		fprintf(fp, "malformed type %d ;\n", m->sadb_msg_type);
	else if (m->sadb_msg_satype != SADB_SATYPE_ESP)
		fprintf(fp, "not esp: satype %d ;\n", m->sadb_msg_satype);
	else if (m->sadb_msg_type == SADB_DUMP)
		fprintf(fp, "dump esp ;\n");
	else if (m->sadb_msg_type == SADB_ADD && p->sa != NULL && p->sa2 !=
	    NULL && p->ekey != NULL) {
		mode = p->sa2->sadb_x_sa2_mode;
		fprintf(fp, "add %s %s esp %#x -m %s -u %u -r %u",
		    addr_str(p->src, s, sizeof(s)), addr_str(p->dst, d,
		    sizeof(d)), ntohl(p->sa->sadb_sa_spi), mode == 2 ? "tunnel" :
		    mode == 1 ? "transport" : "any", p->sa2->sadb_x_sa2_reqid,
		    p->replay != NULL ? p->replay->sadb_x_sa_replay_replay >> 3 :
		    p->sa->sadb_sa_replay);
		if (p->sa->sadb_sa_flags & SADB_X_SAFLAGS_ESN)
			fprintf(fp, " -esn");
		/* setkey's SAs may wrap: anything else told. */
		if ((p->sa->sadb_sa_flags & ~(SADB_X_SAFLAGS_ESN |
		    SADB_X_EXT_CYCSEQ)) != 0 || (p->sa->sadb_sa_flags &
		    SADB_X_EXT_CYCSEQ) == 0)
			fprintf(fp, " -flags %#x", p->sa->sadb_sa_flags);
		if (p->ntype != NULL && p->oai != NULL && p->oar != NULL &&
		    p->sport != NULL && p->dport != NULL)
			fprintf(fp, " -natt %s[%u] %s[%u]", addr_str(p->oai, s,
			    sizeof(s)), ntohs(p->sport->sadb_x_nat_t_port_port),
			    addr_str(p->oar, d, sizeof(d)),
			    ntohs(p->dport->sadb_x_nat_t_port_port));
		fprintf(fp, " -E %s ", ealg(p->sa->sadb_sa_encrypt));
		key_hex(fp, p->ekey);
		if (p->akey != NULL) {
			fprintf(fp, " -A %s ", aalg(p->sa->sadb_sa_auth));
			key_hex(fp, p->akey);
		}
		fprintf(fp, " ;\n");
	} else if (m->sadb_msg_type == SADB_DELETE && p->sa == NULL)
		fprintf(fp, "deleteall %s %s esp ;\n", addr_str(p->src, s,
		    sizeof(s)), addr_str(p->dst, d, sizeof(d)));
	else if ((m->sadb_msg_type == SADB_DELETE || m->sadb_msg_type ==
	    SADB_GET) && p->sa != NULL)
		fprintf(fp, "%s %s %s esp %#x ;\n", m->sadb_msg_type ==
		    SADB_GET ? "get" : "delete", addr_str(p->src, s, sizeof(s)),
		    addr_str(p->dst, d, sizeof(d)), ntohl(p->sa->sadb_sa_spi));
	else
		fprintf(fp, "unexpected type %d ;\n", m->sadb_msg_type);
	fclose(fp);
}

/* A reply of the request's type, sequence number and process. */
static void
reply(int fd, const struct sadb_msg *q, const unsigned char *body,
    size_t len, int error, uint32_t seq)
{
	unsigned char	 buf[1024] __aligned(8);
	struct sadb_msg	*r;

	if (body == NULL || error != 0) {
		body = (const void *)q;
		len = sizeof(*q);
	}
	memcpy(buf, body, len);
	r = (struct sadb_msg *)(void *)buf;
	r->sadb_msg_type = q->sadb_msg_type;
	r->sadb_msg_errno = (uint8_t)error;
	r->sadb_msg_seq = seq;
	r->sadb_msg_pid = q->sadb_msg_pid;
	r->sadb_msg_len = PFKEY_UNIT64(len);
	/* A record each, as the kernel's replies are. */
	(void)send(fd, buf, len, MSG_EOR);
}

static struct entry *
find(const struct parsed *p)
{

	for (size_t i = 0; i < nsas; i++)
		if (sas[i].spi == p->sa->sadb_sa_spi && same_addr(addr_of(p->src),
		    &sas[i].src) && same_addr(addr_of(p->dst), &sas[i].dst))
			return (&sas[i]);
	return (NULL);
}

static void
drop(struct entry *e)
{

	*e = sas[--nsas];
}

static void
handle(int fd, const unsigned char *buf, size_t len)
{
	const struct sadb_msg	*q = (const void *)buf;
	struct parsed		 p;
	struct entry		*e;
	struct sadb_sa		*sa;
	size_t			 i;

	if (len < sizeof(*q) || (size_t)PFKEY_UNUNIT64(q->sadb_msg_len) != len)
		return;
	parse(buf, len, &p);
	log_msg(q, &p);
	if (p.bad || (q->sadb_msg_type != SADB_DUMP && (p.src == NULL ||
	    p.dst == NULL))) {
		reply(fd, q, NULL, 0, EINVAL, q->sadb_msg_seq);
		return;
	}
	switch (q->sadb_msg_type) {
	case SADB_ADD:
		if (p.sa == NULL || access(refuse, F_OK) == 0 ||
		    len > sizeof(sas[0].msg)) {
			reply(fd, q, NULL, 0, EINVAL, q->sadb_msg_seq);
			return;
		}
		if ((e = find(&p)) != NULL)
			drop(e);
		if (nsas == NSAS) {
			reply(fd, q, NULL, 0, ENOBUFS, q->sadb_msg_seq);
			return;
		}
		e = &sas[nsas++];
		memset(e, 0, sizeof(*e));
		memcpy(&e->src, addr_of(p.src), addr_of(p.src)->sa_len);
		memcpy(&e->dst, addr_of(p.dst), addr_of(p.dst)->sa_len);
		e->spi = p.sa->sadb_sa_spi;
		memcpy(e->msg, buf, len);
		e->len = len;
		/* Mature once in, as the kernel's added SAs are. */
		parse(e->msg, e->len, &p);
		sa = (struct sadb_sa *)(uintptr_t)p.sa;
		sa->sadb_sa_state = SADB_SASTATE_MATURE;
		reply(fd, q, NULL, 0, 0, q->sadb_msg_seq);
		return;
	case SADB_DELETE:
		if (p.sa == NULL) {
			for (i = nsas; i-- > 0;)
				if (same_addr(addr_of(p.src), &sas[i].src) &&
				    same_addr(addr_of(p.dst), &sas[i].dst))
					drop(&sas[i]);
			reply(fd, q, NULL, 0, 0, q->sadb_msg_seq);
			return;
		}
		if ((e = find(&p)) == NULL) {
			reply(fd, q, NULL, 0, ESRCH, q->sadb_msg_seq);
			return;
		}
		drop(e);
		reply(fd, q, NULL, 0, 0, q->sadb_msg_seq);
		return;
	case SADB_GET:
		if (p.sa == NULL || (e = find(&p)) == NULL) {
			reply(fd, q, NULL, 0, ESRCH, q->sadb_msg_seq);
			return;
		}
		reply(fd, q, e->msg, e->len, 0, q->sadb_msg_seq);
		return;
	case SADB_DUMP:
		if (nsas == 0) {
			reply(fd, q, NULL, 0, ENOENT, q->sadb_msg_seq);
			return;
		}
		for (i = 0; i < nsas; i++)
			reply(fd, q, sas[i].msg, sas[i].len, 0,
			    (uint32_t)(nsas - 1 - i));
		return;
	}
	reply(fd, q, NULL, 0, EOPNOTSUPP, q->sadb_msg_seq);
}

int
main(int argc, char **argv)
{
	struct sockaddr_un	 sun;
	struct pollfd		 pfd[1 + NCLIENTS];
	unsigned char		 buf[4096] __aligned(8);
	ssize_t			 n;
	int			 ls, i, k;

	if (argc != 4)
		errx(2, "usage: fakepfkey socket log refuse");
	logpath = argv[2];
	refuse = argv[3];
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, argv[1], sizeof(sun.sun_path));
	(void)unlink(argv[1]);
	if ((ls = socket(AF_UNIX, SOCK_SEQPACKET, 0)) == -1 ||
	    bind(ls, (struct sockaddr *)&sun, sizeof(sun)) == -1 ||
	    listen(ls, NCLIENTS) == -1)
		err(1, "%s", argv[1]);
	pfd[0].fd = ls;
	pfd[0].events = POLLIN;
	for (i = 1; i <= NCLIENTS; i++) {
		pfd[i].fd = -1;
		pfd[i].events = POLLIN;
	}
	for (;;) {
		if (poll(pfd, 1 + NCLIENTS, -1) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "poll");
		}
		if (pfd[0].revents & POLLIN) {
			if ((k = accept(ls, NULL, NULL)) != -1) {
				for (i = 1; i <= NCLIENTS && pfd[i].fd != -1; i++)
					;
				if (i > NCLIENTS)
					close(k);
				else
					pfd[i].fd = k;
			}
		}
		for (i = 1; i <= NCLIENTS; i++) {
			if (pfd[i].fd == -1 || pfd[i].revents == 0)
				continue;
			if ((n = recv(pfd[i].fd, buf, sizeof(buf), 0)) <= 0) {
				close(pfd[i].fd);
				pfd[i].fd = -1;
				continue;
			}
			handle(pfd[i].fd, buf, (size_t)n);
		}
	}
}
