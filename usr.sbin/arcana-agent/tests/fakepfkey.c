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
 * sys/netipsec/key.c), keeps the policies added and answers
 * SADB_X_SPDADD (EEXIST for a selector and direction there already),
 * SADB_X_SPDUPDATE (in place of the policy of the selector and
 * direction, a new id), SADB_X_SPDDELETE2 (by id) and SADB_X_SPDDUMP,
 * and writes each message
 * it is sent to the log as setkey(8)'s line of it, read from the
 * message's own bytes.  While the file refuse names is there, it
 * refuses SADB_ADD (EINVAL).  With seed, two policies not Arcana's are
 * there from the start: ipsec.conf's (priority 0) on the request
 * Arcana's would have for ipsec0 of reqid 100 from 10.202.0.1 to
 * 10.202.0.2, and an ipsec(4) interface's own (ifnet scope, index 1).
 *
 * SADB_REGISTER makes a client's socket one the kernel's news go to;
 * what such a socket sends (the agent's watcher: its dumps) is not
 * logged.  With news, seed's policies are there and, each time the file
 * log.news is, it is taken away and the registered sockets are sent
 * what the kernel would send: an SADB_ACQUIRE of ipsec.conf's policy
 * (id 1) between 10.202.0.1 and 10.202.0.2, and SADB_EXPIRE soft, then
 * hard, of an SA of SPI 0x1001 between them, which is there from then
 * on, its sequence counter at 0xfffff000 and no ESN.
 *
 * Each time the file log.count is there, it is read and taken away: its
 * lines "SPI packets bytes" (the SPI in hex) set what the SA of the SPI
 * has carried, its current lifetime as a dump tells it.
 *
 * usage: fakepfkey socket log refuse [seed | news]
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <net/pfkeyv2.h>
#include <netinet/in.h>
#include <netipsec/ipsec.h>

#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define	NCLIENTS	16
#define	NSAS		64
#define	NSPS		64

struct entry {
	struct sockaddr_storage	 src, dst;
	uint32_t		 spi;
	unsigned char		 msg[1024] __aligned(8);
	size_t			 len;
};

static struct entry	 sas[NSAS];
static size_t		 nsas;

/* A policy: its message as it was added, the kernel's id in it. */
struct policy {
	uint32_t		 id;
	unsigned char		 msg[1024] __aligned(8);
	size_t			 len;
};

static struct policy	 sps[NSPS];
static size_t		 nsps;
static uint32_t		 spid = 1;
static const char	*logpath, *refuse;
static bool		 registered[NCLIENTS + 1];

/* What a message says, as found in its extensions. */
struct parsed {
	const struct sadb_sa		*sa;
	const struct sadb_x_sa2		*sa2;
	const struct sadb_x_sa_replay	*replay;
	const struct sadb_address	*src, *dst, *oai, *oar;
	const struct sadb_key		*ekey, *akey;
	const struct sadb_x_nat_t_type	*ntype;
	const struct sadb_x_nat_t_port	*sport, *dport;
	const struct sadb_x_policy	*xpl;
	const struct sadb_lifetime	*soft, *hard, *cur;
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
		case SADB_X_EXT_POLICY:
			p->xpl = (const void *)e;
			break;
		case SADB_EXT_LIFETIME_SOFT:
			p->soft = (const void *)e;
			break;
		case SADB_EXT_LIFETIME_HARD:
			p->hard = (const void *)e;
			break;
		case SADB_EXT_LIFETIME_CURRENT:
			p->cur = (const void *)e;
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

/* A selector's end as setkey(8) writes it: address/prefix[port]. */
static const char *
sel_str(const struct sadb_address *a, char *buf, size_t len)
{
	const struct sockaddr	*sa = addr_of(a);
	const void		*v = sa;
	char			 s[INET6_ADDRSTRLEN];
	unsigned		 port;

	addr_str(a, s, sizeof(s));
	port = ntohs(sa->sa_family == AF_INET6 ? ((const struct sockaddr_in6 *)
	    v)->sin6_port : ((const struct sockaddr_in *)v)->sin_port);
	if (port == 0)
		snprintf(buf, len, "%s/%u[any]", s, a->sadb_address_prefixlen);
	else
		snprintf(buf, len, "%s/%u[%u]", s, a->sadb_address_prefixlen,
		    port);
	return (buf);
}

/* A policy's -P as setkey(8) has it, the priority told. */
static void
policy_str(FILE *fp, const struct sadb_x_policy *x)
{
	const struct sadb_x_ipsecrequest	*r;
	const struct sockaddr			*a, *b;
	const void				*va, *vb;
	char					 s[INET6_ADDRSTRLEN];
	char					 d[INET6_ADDRSTRLEN];
	size_t					 off, n;

	fprintf(fp, "-P %s prio %#x %s", x->sadb_x_policy_dir ==
	    IPSEC_DIR_INBOUND ? "in" : x->sadb_x_policy_dir ==
	    IPSEC_DIR_OUTBOUND ? "out" : "?", x->sadb_x_policy_priority,
	    x->sadb_x_policy_type == IPSEC_POLICY_IPSEC ? "ipsec" :
	    x->sadb_x_policy_type == IPSEC_POLICY_NONE ? "none" :
	    x->sadb_x_policy_type == IPSEC_POLICY_DISCARD ? "discard" : "?");
	n = PFKEY_UNUNIT64(x->sadb_x_policy_len);
	for (off = sizeof(*x); off + sizeof(*r) <= n; off +=
	    r->sadb_x_ipsecrequest_len) {
		r = (const void *)((const char *)x + off);
		if (r->sadb_x_ipsecrequest_len < sizeof(*r) || off +
		    r->sadb_x_ipsecrequest_len > n) {
			fprintf(fp, " malformed-request");
			return;
		}
		s[0] = d[0] = '\0';
		if (r->sadb_x_ipsecrequest_len > sizeof(*r)) {
			a = (const void *)(r + 1);
			b = (const void *)((const char *)a + a->sa_len);
			va = a;
			vb = b;
			if (a->sa_family == AF_INET) {
				inet_ntop(AF_INET, &((const struct sockaddr_in *)
				    va)->sin_addr, s, sizeof(s));
				inet_ntop(AF_INET, &((const struct sockaddr_in *)
				    vb)->sin_addr, d, sizeof(d));
			} else {
				inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)
				    va)->sin6_addr, s, sizeof(s));
				inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)
				    vb)->sin6_addr, d, sizeof(d));
			}
		}
		fprintf(fp, " %s/%s/%s%s%s/%s", r->sadb_x_ipsecrequest_proto ==
		    IPPROTO_ESP ? "esp" : "?", r->sadb_x_ipsecrequest_mode ==
		    IPSEC_MODE_TUNNEL ? "tunnel" : r->sadb_x_ipsecrequest_mode ==
		    IPSEC_MODE_TRANSPORT ? "transport" : "any", s, s[0] != '\0' ?
		    "-" : "", d, r->sadb_x_ipsecrequest_level ==
		    IPSEC_LEVEL_UNIQUE ? "unique" : r->sadb_x_ipsecrequest_level ==
		    IPSEC_LEVEL_REQUIRE ? "require" : r->sadb_x_ipsecrequest_level
		    == IPSEC_LEVEL_USE ? "use" : "?");
		if (r->sadb_x_ipsecrequest_reqid != 0)
			fprintf(fp, ":%u", r->sadb_x_ipsecrequest_reqid);
	}
}

/* The message as setkey(8)'s line of it. */
static void
log_msg(const struct sadb_msg *m, const struct parsed *p)
{
	FILE	*fp;
	char	 s[INET6_ADDRSTRLEN + 12], d[INET6_ADDRSTRLEN + 12];
	int	 mode;

	if ((fp = fopen(logpath, "a")) == NULL)
		err(1, "%s", logpath);
	if (m->sadb_msg_type == SADB_X_SPDADD || m->sadb_msg_type ==
	    SADB_X_SPDUPDATE || m->sadb_msg_type == SADB_X_SPDDELETE2 ||
	    m->sadb_msg_type == SADB_X_SPDDUMP) {
		if (p->bad || m->sadb_msg_version != PF_KEY_V2 ||
		    m->sadb_msg_satype != SADB_SATYPE_UNSPEC || (m->sadb_msg_type
		    != SADB_X_SPDDUMP && p->xpl == NULL) || ((m->sadb_msg_type ==
		    SADB_X_SPDADD || m->sadb_msg_type == SADB_X_SPDUPDATE) &&
		    (p->src == NULL || p->dst == NULL ||
		    p->src->sadb_address_proto != p->dst->sadb_address_proto)))
			fprintf(fp, "malformed type %d ;\n", m->sadb_msg_type);
		else if (m->sadb_msg_type == SADB_X_SPDDUMP)
			fprintf(fp, "spddump ;\n");
		else if (m->sadb_msg_type == SADB_X_SPDDELETE2)
			fprintf(fp, "spddelete2 %u ;\n", p->xpl->sadb_x_policy_id);
		else {
			fprintf(fp, "%s %s %s ", m->sadb_msg_type ==
			    SADB_X_SPDUPDATE ? "spdupdate" : "spdadd",
			    sel_str(p->src, s, sizeof(s)),
			    sel_str(p->dst, d, sizeof(d)));
			if (p->src->sadb_address_proto == IPSEC_ULPROTO_ANY)
				fprintf(fp, "any ");
			else
				fprintf(fp, "%u ", p->src->sadb_address_proto);
			policy_str(fp, p->xpl);
			fprintf(fp, " ;\n");
		}
		fclose(fp);
		return;
	}
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
		/* setkey's -lh and -ls: seconds, bytes, then packets. */
		if (p->hard != NULL)
			fprintf(fp, " -lh %ju %ju %u", (uintmax_t)
			    p->hard->sadb_lifetime_addtime, (uintmax_t)
			    p->hard->sadb_lifetime_bytes,
			    p->hard->sadb_lifetime_allocations);
		if (p->soft != NULL)
			fprintf(fp, " -ls %ju %ju %u", (uintmax_t)
			    p->soft->sadb_lifetime_addtime, (uintmax_t)
			    p->soft->sadb_lifetime_bytes,
			    p->soft->sadb_lifetime_allocations);
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

/* Whether two policies are of one selector and direction, as
 * key_getsp() compares them. */
static bool
same_policy(const struct parsed *a, const struct parsed *b)
{

	return (a->xpl->sadb_x_policy_dir == b->xpl->sadb_x_policy_dir &&
	    a->src->sadb_address_proto == b->src->sadb_address_proto &&
	    a->src->sadb_address_prefixlen == b->src->sadb_address_prefixlen &&
	    a->dst->sadb_address_prefixlen == b->dst->sadb_address_prefixlen &&
	    addr_of(a->src)->sa_len == addr_of(b->src)->sa_len && memcmp(
	    addr_of(a->src), addr_of(b->src), addr_of(a->src)->sa_len) == 0 &&
	    addr_of(a->dst)->sa_len == addr_of(b->dst)->sa_len && memcmp(
	    addr_of(a->dst), addr_of(b->dst), addr_of(a->dst)->sa_len) == 0);
}

/* A policy kept, its id and scope as the kernel gives them; NULL when
 * there is no room. */
static struct policy *
policy_keep(const unsigned char *buf, size_t len, uint8_t scope,
    uint32_t priority)
{
	struct policy		*e;
	struct parsed		 p;
	struct sadb_x_policy	*x;

	if (nsps == NSPS || len > sizeof(sps[0].msg))
		return (NULL);
	e = &sps[nsps++];
	memcpy(e->msg, buf, len);
	e->len = len;
	e->id = spid++;
	parse(e->msg, e->len, &p);
	x = (struct sadb_x_policy *)(uintptr_t)p.xpl;
	x->sadb_x_policy_id = e->id;
	x->sadb_x_policy_scope = scope;
	x->sadb_x_policy_priority = priority;
	return (e);
}

static void
handle_spd(int fd, const struct sadb_msg *q, const unsigned char *buf,
    size_t len, const struct parsed *p)
{
	struct parsed	 k;
	struct policy	*e;
	size_t		 i;

	if (p->bad || q->sadb_msg_satype != SADB_SATYPE_UNSPEC ||
	    (q->sadb_msg_type != SADB_X_SPDDUMP && p->xpl == NULL)) {
		reply(fd, q, NULL, 0, EINVAL, q->sadb_msg_seq);
		return;
	}
	switch (q->sadb_msg_type) {
	case SADB_X_SPDADD:
	case SADB_X_SPDUPDATE:
		if (p->src == NULL || p->dst == NULL) {
			reply(fd, q, NULL, 0, EINVAL, q->sadb_msg_seq);
			return;
		}
		for (i = 0; i < nsps; i++) {
			parse(sps[i].msg, sps[i].len, &k);
			if (!same_policy(&k, p) || k.xpl->sadb_x_policy_scope !=
			    IPSEC_POLICYSCOPE_GLOBAL)
				continue;
			if (q->sadb_msg_type == SADB_X_SPDADD) {
				reply(fd, q, NULL, 0, EEXIST, q->sadb_msg_seq);
				return;
			}
			/* key_spdadd(): the one there unlinked. */
			sps[i] = sps[--nsps];
			break;
		}
		if ((e = policy_keep(buf, len, IPSEC_POLICYSCOPE_GLOBAL,
		    p->xpl->sadb_x_policy_priority)) == NULL) {
			reply(fd, q, NULL, 0, ENOBUFS, q->sadb_msg_seq);
			return;
		}
		reply(fd, q, e->msg, e->len, 0, q->sadb_msg_seq);
		return;
	case SADB_X_SPDDELETE2:
		for (i = 0; i < nsps; i++)
			if (sps[i].id == p->xpl->sadb_x_policy_id) {
				sps[i] = sps[--nsps];
				reply(fd, q, NULL, 0, 0, q->sadb_msg_seq);
				return;
			}
		reply(fd, q, NULL, 0, EINVAL, q->sadb_msg_seq);
		return;
	case SADB_X_SPDDUMP:
		if (nsps == 0) {
			reply(fd, q, NULL, 0, ENOENT, q->sadb_msg_seq);
			return;
		}
		for (i = 0; i < nsps; i++)
			reply(fd, q, sps[i].msg, sps[i].len, 0,
			    (uint32_t)(nsps - 1 - i));
		return;
	}
}

/* seed's policies: an SPDADD of each, as setkey(8) would send it. */
static void
seed(void)
{
	unsigned char			 buf[256] __aligned(8);
	struct sadb_msg			*m;
	struct sadb_x_policy		*x;
	struct sadb_x_ipsecrequest	*r;
	struct sadb_address		*a;
	struct sockaddr_in		*sin;
	size_t				 len;
	int				 k;

	for (k = 0; k < 2; k++) {
		memset(buf, 0, sizeof(buf));
		m = (struct sadb_msg *)(void *)buf;
		m->sadb_msg_version = PF_KEY_V2;
		m->sadb_msg_type = SADB_X_SPDADD;
		len = sizeof(*m);
		x = (struct sadb_x_policy *)(void *)(buf + len);
		x->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
		x->sadb_x_policy_type = IPSEC_POLICY_IPSEC;
		x->sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;
		r = (struct sadb_x_ipsecrequest *)(x + 1);
		r->sadb_x_ipsecrequest_len = sizeof(*r) + 2 * sizeof(*sin);
		r->sadb_x_ipsecrequest_proto = IPPROTO_ESP;
		r->sadb_x_ipsecrequest_mode = IPSEC_MODE_TUNNEL;
		r->sadb_x_ipsecrequest_level = IPSEC_LEVEL_UNIQUE;
		r->sadb_x_ipsecrequest_reqid = 100;
		sin = (struct sockaddr_in *)(void *)(r + 1);
		sin[0].sin_len = sin[1].sin_len = sizeof(*sin);
		sin[0].sin_family = sin[1].sin_family = AF_INET;
		inet_pton(AF_INET, "10.202.0.1", &sin[0].sin_addr);
		inet_pton(AF_INET, "10.202.0.2", &sin[1].sin_addr);
		x->sadb_x_policy_len = PFKEY_UNIT64(sizeof(*x) +
		    r->sadb_x_ipsecrequest_len);
		len += PFKEY_UNUNIT64(x->sadb_x_policy_len);
		for (int i = 0; i < 2; i++) {
			a = (struct sadb_address *)(void *)(buf + len);
			a->sadb_address_len = PFKEY_UNIT64(sizeof(*a) +
			    sizeof(*sin));
			a->sadb_address_exttype = i == 0 ? SADB_EXT_ADDRESS_SRC :
			    SADB_EXT_ADDRESS_DST;
			a->sadb_address_proto = IPSEC_ULPROTO_ANY;
			sin = (struct sockaddr_in *)(void *)(a + 1);
			sin->sin_len = sizeof(*sin);
			sin->sin_family = AF_INET;
			if (k == 0) {
				/* ipsec.conf's: 10.77.0.0/24 to 10.78.0.0/24. */
				a->sadb_address_prefixlen = 24;
				inet_pton(AF_INET, i == 0 ? "10.77.0.0" :
				    "10.78.0.0", &sin->sin_addr);
			} else
				a->sadb_address_prefixlen = 0;
			len += PFKEY_UNUNIT64(a->sadb_address_len);
		}
		m->sadb_msg_len = PFKEY_UNIT64(len);
		(void)policy_keep(buf, len, k == 0 ? IPSEC_POLICYSCOPE_GLOBAL :
		    IPSEC_POLICYSCOPE_IFNET, k == 0 ? 0 : 1);
	}
}

static void
handle(int fd, const unsigned char *buf, size_t len, bool *reg)
{
	const struct sadb_msg	*q = (const void *)buf;
	struct parsed		 p;
	struct entry		*e;
	struct sadb_sa		*sa;
	size_t			 i;

	if (len < sizeof(*q) || (size_t)PFKEY_UNUNIT64(q->sadb_msg_len) != len)
		return;
	if (q->sadb_msg_type == SADB_REGISTER) {
		*reg = true;
		reply(fd, q, NULL, 0, 0, q->sadb_msg_seq);
		return;
	}
	parse(buf, len, &p);
	if (!*reg)
		log_msg(q, &p);
	if (q->sadb_msg_type == SADB_X_SPDADD || q->sadb_msg_type ==
	    SADB_X_SPDUPDATE || q->sadb_msg_type == SADB_X_SPDDELETE2 ||
	    q->sadb_msg_type == SADB_X_SPDDUMP) {
		handle_spd(fd, q, buf, len, &p);
		return;
	}
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

/* An address extension of 10.202.0.1 or .2 at buf + *len. */
static void
news_addr(unsigned char *buf, size_t *len, uint16_t type, const char *a,
    uint8_t plen)
{
	struct sadb_address	*ad;
	struct sockaddr_in	*sin;

	ad = (struct sadb_address *)(void *)(buf + *len);
	ad->sadb_address_len = PFKEY_UNIT64(sizeof(*ad) + sizeof(*sin));
	ad->sadb_address_exttype = type;
	ad->sadb_address_proto = IPSEC_ULPROTO_ANY;
	ad->sadb_address_prefixlen = plen;
	sin = (struct sockaddr_in *)(void *)(ad + 1);
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	inet_pton(AF_INET, a, &sin->sin_addr);
	*len += PFKEY_UNUNIT64(ad->sadb_address_len);
}

/* The SA of SPI 0x1001 as the kernel tells it, type's message: its SA,
 * SA2 (the counter), current lifetime and lt's (0 none), its ends. */
static size_t
news_sa(unsigned char *buf, uint8_t type, uint16_t lt)
{
	struct sadb_msg		*m;
	struct sadb_sa		*sa;
	struct sadb_x_sa2	*s2;
	struct sadb_lifetime	*l;
	size_t			 len;

	memset(buf, 0, 512);
	m = (struct sadb_msg *)(void *)buf;
	m->sadb_msg_version = PF_KEY_V2;
	m->sadb_msg_type = type;
	m->sadb_msg_satype = SADB_SATYPE_ESP;
	len = sizeof(*m);
	sa = (struct sadb_sa *)(void *)(buf + len);
	sa->sadb_sa_len = PFKEY_UNIT64(sizeof(*sa));
	sa->sadb_sa_exttype = SADB_EXT_SA;
	sa->sadb_sa_spi = htonl(0x1001);
	sa->sadb_sa_state = SADB_SASTATE_MATURE;
	sa->sadb_sa_encrypt = SADB_EALG_NULL;
	sa->sadb_sa_flags = SADB_X_EXT_CYCSEQ;
	len += sizeof(*sa);
	s2 = (struct sadb_x_sa2 *)(void *)(buf + len);
	s2->sadb_x_sa2_len = PFKEY_UNIT64(sizeof(*s2));
	s2->sadb_x_sa2_exttype = SADB_X_EXT_SA2;
	s2->sadb_x_sa2_mode = IPSEC_MODE_TUNNEL;
	s2->sadb_x_sa2_sequence = 0xfffff000u;
	s2->sadb_x_sa2_reqid = 100;
	len += sizeof(*s2);
	l = (struct sadb_lifetime *)(void *)(buf + len);
	l->sadb_lifetime_len = PFKEY_UNIT64(sizeof(*l));
	l->sadb_lifetime_exttype = SADB_EXT_LIFETIME_CURRENT;
	l->sadb_lifetime_allocations = 5;
	l->sadb_lifetime_bytes = 1234;
	l->sadb_lifetime_addtime = (uint64_t)time(NULL) - 30;
	len += sizeof(*l);
	if (lt != 0) {
		l = (struct sadb_lifetime *)(void *)(buf + len);
		l->sadb_lifetime_len = PFKEY_UNIT64(sizeof(*l));
		l->sadb_lifetime_exttype = lt;
		l->sadb_lifetime_addtime = lt == SADB_EXT_LIFETIME_SOFT ? 30 :
		    60;
		len += sizeof(*l);
	}
	news_addr(buf, &len, SADB_EXT_ADDRESS_SRC, "10.202.0.1", 32);
	news_addr(buf, &len, SADB_EXT_ADDRESS_DST, "10.202.0.2", 32);
	m->sadb_msg_len = PFKEY_UNIT64(len);
	return (len);
}

/* log.count there: what SAs have carried, their current lifetimes. */
static void
count(void)
{
	char			 path[PATH_MAX], line[128];
	struct parsed		 p;
	struct sadb_lifetime	*l;
	struct sadb_msg		*m;
	unsigned		 spi, pk;
	unsigned long long	 by;
	FILE			*fp;

	snprintf(path, sizeof(path), "%s.count", logpath);
	if ((fp = fopen(path, "r")) == NULL)
		return;
	(void)unlink(path);
	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line, "%x %u %llu", &spi, &pk, &by) != 3)
			continue;
		for (size_t i = 0; i < nsas; i++) {
			if (ntohl(sas[i].spi) != spi)
				continue;
			parse(sas[i].msg, sas[i].len, &p);
			if ((l = (struct sadb_lifetime *)(uintptr_t)p.cur) ==
			    NULL) {
				if (sas[i].len + sizeof(*l) > sizeof(sas[i].msg))
					continue;
				l = (struct sadb_lifetime *)(void *)(sas[i].msg +
				    sas[i].len);
				memset(l, 0, sizeof(*l));
				l->sadb_lifetime_len = PFKEY_UNIT64(sizeof(*l));
				l->sadb_lifetime_exttype =
				    SADB_EXT_LIFETIME_CURRENT;
				l->sadb_lifetime_addtime = (uint64_t)time(NULL);
				sas[i].len += sizeof(*l);
				m = (struct sadb_msg *)(void *)sas[i].msg;
				m->sadb_msg_len = PFKEY_UNIT64(sas[i].len);
			}
			l->sadb_lifetime_allocations = pk;
			l->sadb_lifetime_bytes = by;
		}
	}
	fclose(fp);
}

/* log.news there: the kernel's news to the registered sockets. */
static void
news(struct pollfd *pfd)
{
	unsigned char		 buf[512] __aligned(8);
	char			 path[PATH_MAX];
	struct sadb_msg		*m;
	struct sadb_x_policy	*x;
	struct entry		*e;
	size_t			 len[3];
	unsigned char		 msg[3][512] __aligned(8);

	snprintf(path, sizeof(path), "%s.news", logpath);
	if (unlink(path) != 0)
		return;
	/* The SA there from now on, as a dump has it. */
	if (nsas < NSAS) {
		e = &sas[nsas++];
		memset(e, 0, sizeof(*e));
		e->len = news_sa(e->msg, SADB_DUMP, 0);
		e->spi = htonl(0x1001);
		inet_pton(AF_INET, "10.202.0.1",
		    &((struct sockaddr_in *)&e->src)->sin_addr);
		inet_pton(AF_INET, "10.202.0.2",
		    &((struct sockaddr_in *)&e->dst)->sin_addr);
		e->src.ss_len = e->dst.ss_len = sizeof(struct sockaddr_in);
		e->src.ss_family = e->dst.ss_family = AF_INET;
	}
	/* SADB_ACQUIRE: the SA's ends at FULLMASK, the policy's id. */
	memset(buf, 0, sizeof(buf));
	m = (struct sadb_msg *)(void *)buf;
	m->sadb_msg_version = PF_KEY_V2;
	m->sadb_msg_type = SADB_ACQUIRE;
	m->sadb_msg_satype = SADB_SATYPE_ESP;
	m->sadb_msg_seq = 7;
	len[0] = sizeof(*m);
	news_addr(buf, &len[0], SADB_EXT_ADDRESS_SRC, "10.202.0.1", 0xff);
	news_addr(buf, &len[0], SADB_EXT_ADDRESS_DST, "10.202.0.2", 0xff);
	x = (struct sadb_x_policy *)(void *)(buf + len[0]);
	x->sadb_x_policy_len = PFKEY_UNIT64(sizeof(*x));
	x->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	x->sadb_x_policy_type = IPSEC_POLICY_IPSEC;
	x->sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;
	x->sadb_x_policy_id = 1;
	len[0] += sizeof(*x);
	m->sadb_msg_len = PFKEY_UNIT64(len[0]);
	memcpy(msg[0], buf, len[0]);
	len[1] = news_sa(msg[1], SADB_EXPIRE, SADB_EXT_LIFETIME_SOFT);
	len[2] = news_sa(msg[2], SADB_EXPIRE, SADB_EXT_LIFETIME_HARD);
	for (int i = 1; i <= NCLIENTS; i++)
		if (pfd[i].fd != -1 && registered[i])
			for (int k = 0; k < 3; k++)
				(void)send(pfd[i].fd, msg[k], len[k], MSG_EOR);
}

int
main(int argc, char **argv)
{
	struct sockaddr_un	 sun;
	struct pollfd		 pfd[1 + NCLIENTS];
	unsigned char		 buf[4096] __aligned(8);
	ssize_t			 n;
	int			 ls, i, k;
	bool			 newsy;

	if (argc != 4 && (argc != 5 || (strcmp(argv[4], "seed") != 0 &&
	    strcmp(argv[4], "news") != 0)))
		errx(2, "usage: fakepfkey socket log refuse [seed | news]");
	logpath = argv[2];
	refuse = argv[3];
	newsy = argc == 5 && strcmp(argv[4], "news") == 0;
	if (argc == 5)
		seed();
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
		if (poll(pfd, 1 + NCLIENTS, 100) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "poll");
		}
		if (newsy)
			news(pfd);
		count();
		if (pfd[0].revents & POLLIN) {
			if ((k = accept(ls, NULL, NULL)) != -1) {
				for (i = 1; i <= NCLIENTS && pfd[i].fd != -1; i++)
					;
				if (i > NCLIENTS)
					close(k);
				else {
					pfd[i].fd = k;
					registered[i] = false;
				}
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
			handle(pfd[i].fd, buf, (size_t)n, &registered[i]);
		}
	}
}
