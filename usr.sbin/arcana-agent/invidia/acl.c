/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: RFC 8519's access control lists (ietf-access-control-list),
 * compiled to ipfw(8) (PLAN-SDN-YANG 6.1).
 *
 * An ACL is a band of rule numbers of its own, its ACEs one number
 * each in their order, ended by a return; nothing reaches a band but
 * by a call.  The attachment points are calls in an attachment block,
 * one a number in their order (an interface's ingress ACLs, then its
 * egress ones): "call band ip from any to any in recv if" for ingress,
 * "out xmit if" for egress; the block is entered by one call at rule 8,
 * before the SD-WAN's rules (9 to 99, set 30), and ends with a return.
 * A return goes on at the first rule numbered past the call's, so each
 * call has a number of its own.  Rule 60000 skips past the ACLs' to
 * 65000: a packet the admin's rules let fall that far meets what it
 * would have met without them.  The numbers:
 *
 *	8		the entry, call 60001 (only where an ACL is attached)
 *	60000		the guard, skipto 65000
 *	60001-60999	the attachment block, its return last
 *	61000-64999	the bands, each from a multiple of 10, in the
 *			order the ACLs are configured
 *
 * The name map: the n-th ACL of the configuration is band n, its m-th
 * ACE the band's m-th rule; every rule says where it is in its comment
 * ("acl:n.m"; acl:n.in and acl:n.out an attachment of band n,
 * acl:n.end its return, acl:entry, acl:guard, acl:attach-end) and then
 * the names, ACL/ACE, %XX where a name has what ipfw's reading of a
 * file would split or end (blanks, '#') and '/' and '%' themselves, cut
 * with a '~' where ipfw's 80 characters of comment end.  What the
 * kernel has is read back by those comments against the configuration
 * kept (acls.cbor, the YANG-CBOR of running's acls, beside the agent's
 * files): an ACL installed is one whose band is whole.
 *
 * Everything goes in at once: the rules are loaded into set 28,
 * disabled, and set 28 is swapped with set 29, so the packets see the
 * old ACLs or the new and never half of either; the old ones, set 28
 * then, are deleted.  The admin's rules are never touched: a rule of
 * another set at rule 8 or at 60000 to 64999, or a rule in set 28 or
 * 29 that is no ACL's, refuses the change, nothing loaded.  A confirmed
 * commit undone is cblink's: running's acls as they were are applied
 * again (cbl_yds.c).
 *
 * What 6.1.1 compiles: the ACL's type (IPv4, IPv6, none), the IPv4 and
 * IPv6 networks and protocol, the TCP and UDP ports with their
 * operators, the ICMP type, the forwarding actions (reject an ICMP
 * unreachable, administratively prohibited).  Every other match, and
 * logging other than log-none, is refused, nothing loaded: an ACE is
 * never installed matching more than it says.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <net/if.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <cblink.h>
#include <cbl_schema.h>

#include "agent.h"
#include "collect.h"

#define	ACL_FILE	"acls.cbor"
#define	ACL_LOAD	"acls.load"
#define	ACL_FILE_MAX	(4 * 1024 * 1024)
#define	ACL_SET		29
#define	ACL_STAGE	28
#define	ACL_ENTRY	8
#define	ACL_GUARD	60000
#define	ACL_ATTACH	60001
#define	ACL_ATTACH_END	60999
#define	ACL_BANDS	61000
#define	ACL_BANDS_END	64999
#define	ACL_PAST	65000
#define	ACL_ALIGN	10
#define	ACL_COMMENT	80	/* ipfw's longest */
#define	ACL_PREFIX	"acl:"

typedef struct ietf_access_control_list_acls yacls;
typedef struct ietf_access_control_list_acls_acl yacl;
typedef struct ietf_access_control_list_acls_acl_aces_ace yace;
typedef struct ietf_access_control_list_acls_acl_aces_ace_matches ymatch;
typedef struct ietf_access_control_list_acls_attachment_points_interface
    yattach;

static pthread_mutex_t	acl_lock = PTHREAD_MUTEX_INITIALIZER;

/* A rule of the kernel's: its number, set and comment ("" none). */
struct krule {
	long		 num;
	int		 set;
	const char	*comment;
};

static const struct cbl_ynode *
acl_node(void)
{

	return (ynode_named("ietf-access-control-list", "acls"));
}

/* An identity of ietf-access-control-list's, its SID; 0: none. */
static uint64_t
acl_ident(const char *name)
{
	const struct cbl_yident	*id;

	for (uint32_t i = 0; i < ymodel_schema.nident; i++) {
		id = &ymodel_schema.ident[i];
		if (strcmp(id->name, name) == 0 &&
		    strcmp(id->module->name, "ietf-access-control-list") == 0)
			return (id->sid);
	}
	return (0);
}

/* ---- The name map ---------------------------------------------------- */

/* A name as a comment has it: [A-Za-z0-9._-] as it is, the rest %XX. */
static void
name_put(char *buf, size_t len, size_t *off, const char *s)
{
	static const char	hex[] = "0123456789ABCDEF";
	unsigned char		c;

	for (; *s != '\0' && *off + 4 < len; s++) {
		c = (unsigned char)*s;
		if (isalnum(c) || c == '.' || c == '_' || c == '-')
			buf[(*off)++] = (char)c;
		else {
			buf[(*off)++] = '%';
			buf[(*off)++] = hex[c >> 4];
			buf[(*off)++] = hex[c & 15];
		}
	}
	buf[*off] = '\0';
}

/*
 * A rule's comment: acl:tag, then acl's name and ace's, either NULL,
 * cut with '~' where ipfw's 80 characters end (never inside a %XX).
 */
static void
comment_of(char *out, size_t outlen, const char *tag, const char *acl,
    const char *ace)
{
	char	buf[512];
	size_t	off, cut;

	off = (size_t)snprintf(buf, sizeof(buf), ACL_PREFIX "%s", tag);
	if (acl != NULL) {
		buf[off++] = ' ';
		name_put(buf, sizeof(buf), &off, acl);
	}
	if (ace != NULL) {
		buf[off++] = '/';
		name_put(buf, sizeof(buf), &off, ace);
	}
	buf[off] = '\0';
	if (off > ACL_COMMENT) {
		cut = ACL_COMMENT - 1;
		if (buf[cut - 1] == '%')
			cut -= 1;
		else if (buf[cut - 2] == '%')
			cut -= 2;
		buf[cut++] = '~';
		buf[cut] = '\0';
	}
	snprintf(out, outlen, "%s", buf);
}

/* The bands: the first number of each ACL's; -1 and why where they do
 * not fit. */
static int
bands_of(const yacls *c, int *band, char *err, size_t errlen)
{
	size_t	i, n;
	int	next;

	next = ACL_BANDS;
	for (i = 0; i < c->acl.n; i++) {
		n = c->acl.v[i].aces != NULL ? c->acl.v[i].aces->ace.n : 0;
		if ((size_t)next + n > ACL_BANDS_END) {
			snprintf(err, errlen, "acl %s: more ACEs than rules %d "
			    "to %d hold, with the ACLs before it", c->acl.v[i].name,
			    ACL_BANDS, ACL_BANDS_END);
			return (-1);
		}
		band[i] = next;
		next += (int)n + 1;
		next = roundup(next, ACL_ALIGN);
	}
	return (0);
}

/* An ACL's place in the configuration, by its name; -1: none. */
static int
acl_index(const yacls *c, const char *name)
{

	for (size_t i = 0; i < c->acl.n; i++)
		if (strcmp(c->acl.v[i].name, name) == 0)
			return ((int)i);
	return (-1);
}

/* ---- The compiler ---------------------------------------------------- */

/* An interface's name as ipfw reads it in a file, a word. */
static bool
ifname_ok(const char *s)
{
	size_t	n;

	if ((n = strlen(s)) == 0 || n >= IFNAMSIZ)
		return (false);
	return (strspn(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "0123456789._:-") == n);
}

/* A prefix as the model's pattern has it, a word of ipfw's. */
static bool
prefix_ok(const char *s)
{
	size_t	n;

	return (s != NULL && (n = strlen(s)) > 0 && n < 64 &&
	    strspn(s, "0123456789abcdefABCDEF.:/") == n &&
	    strchr(s, '/') != NULL);
}

/* A port match, of TCP's or UDP's (the same members): which 0 none, 1 a
 * range, 2 an operator. */
struct pmatch {
	int		 which;
	uint16_t	 lower, upper, port;
	bool		 has_op;
	int		 op;		/* lte 0, gte 1, eq 2, neq 3 */
};

#define	PMATCH(p, m) do {						\
	memset(&(m), 0, sizeof(m));					\
	if ((p) != NULL) {						\
		(m).which = (int)(p)->port_range_or_operator;		\
		(m).lower = (p)->lower_port;				\
		(m).upper = (p)->upper_port;				\
		(m).port = (p)->port;					\
		(m).has_op = (p)->has_operator;				\
		(m).op = (int)(p)->operator;				\
	}								\
} while (0)

/* A port match as ipfw's option, appended to b. */
static int
port_words(char *b, size_t len, const char *opt, const struct pmatch *m,
    char *err, size_t errlen)
{
	size_t	off = strlen(b);

	switch (m->which) {
	case 0:
		return (0);
	case 1:
		if (m->lower > m->upper) {
			snprintf(err, errlen, "%s: lower-port %u is above "
			    "upper-port %u", opt, m->lower, m->upper);
			return (-1);
		}
		snprintf(b + off, len - off, " %s %u-%u", opt, m->lower,
		    m->upper);
		return (0);
	default:
		switch (m->has_op ? m->op : 2) {
		case 0:
			snprintf(b + off, len - off, " %s 0-%u", opt, m->port);
			break;
		case 1:
			snprintf(b + off, len - off, " %s %u-65535", opt,
			    m->port);
			break;
		case 3:
			snprintf(b + off, len - off, " not %s %u", opt, m->port);
			break;
		default:
			snprintf(b + off, len - off, " %s %u", opt, m->port);
			break;
		}
		return (0);
	}
}

/* What 6.1.1 does not compile, refused by name: nothing is installed
 * that matches more than the ACE says. */
#define	REFUSE(cond, what) do {						\
	if (cond) {							\
		snprintf(err, errlen, "acl %s, ace %s: %s is not compiled "	\
		    "into ipfw by this agent", acl, e->name, (what));	\
		return (-1);						\
	}								\
} while (0)

/*
 * An ACE as ipfw's rules at number num, into fp: one, or two where a
 * reject of either family needs each its own unreachable.  fam is the
 * ACL's family (4, 6; 0 either).
 */
static int
ace_compile(FILE *fp, const char *acl, int fam, int num, const yace *e,
    const char *cm, char *err, size_t errlen)
{
	const ymatch	*m = e->matches;
	struct pmatch	 sp, dp;
	char		 more[200], proto[16];
	const char	*src, *dst, *act;
	uint64_t	 fwd;
	int		 p, fams[2], nf;

	src = dst = "any";
	more[0] = '\0';
	p = -1;
	if (e->actions == NULL || !e->actions->has_forwarding) {
		snprintf(err, errlen, "acl %s, ace %s: no forwarding action",
		    acl, e->name);
		return (-1);
	}
	REFUSE(e->actions->has_logging && e->actions->logging !=
	    acl_ident("log-none"), "logging");
	if (m != NULL) {
		REFUSE(m->l2 != 0, "an Ethernet match");
		REFUSE(m->egress_interface != NULL, "egress-interface");
		REFUSE(m->ingress_interface != NULL, "ingress-interface");
		if (m->ipv4 != NULL) {
			if (fam == 6) {
				snprintf(err, errlen, "acl %s, ace %s: an IPv4 "
				    "match in an IPv6 ACL", acl, e->name);
				return (-1);
			}
			fam = 4;
			REFUSE(m->ipv4->has_dscp, "ipv4 dscp");
			REFUSE(m->ipv4->has_ecn, "ipv4 ecn");
			REFUSE(m->ipv4->has_length, "ipv4 length");
			REFUSE(m->ipv4->has_ttl, "ipv4 ttl");
			REFUSE(m->ipv4->has_ihl, "ipv4 ihl");
			REFUSE(m->ipv4->flags.len > 0, "ipv4 flags");
			REFUSE(m->ipv4->has_offset, "ipv4 offset");
			REFUSE(m->ipv4->has_identification,
			    "ipv4 identification");
			if (m->ipv4->has_protocol)
				p = m->ipv4->protocol;
			if (m->ipv4->source_ipv4_network != NULL)
				src = m->ipv4->source_ipv4_network;
			if (m->ipv4->destination_ipv4_network != NULL)
				dst = m->ipv4->destination_ipv4_network;
		}
		if (m->ipv6 != NULL) {
			if (fam == 4) {
				snprintf(err, errlen, "acl %s, ace %s: an IPv6 "
				    "match in an IPv4 ACL", acl, e->name);
				return (-1);
			}
			fam = 6;
			REFUSE(m->ipv6->has_dscp, "ipv6 dscp");
			REFUSE(m->ipv6->has_ecn, "ipv6 ecn");
			REFUSE(m->ipv6->has_length, "ipv6 length");
			REFUSE(m->ipv6->has_ttl, "ipv6 ttl");
			REFUSE(m->ipv6->has_flow_label, "ipv6 flow-label");
			if (m->ipv6->has_protocol)
				p = m->ipv6->protocol;
			if (m->ipv6->source_ipv6_network != NULL)
				src = m->ipv6->source_ipv6_network;
			if (m->ipv6->destination_ipv6_network != NULL)
				dst = m->ipv6->destination_ipv6_network;
		}
		if ((src != NULL && strcmp(src, "any") != 0 &&
		    !prefix_ok(src)) || (dst != NULL && strcmp(dst, "any") != 0 &&
		    !prefix_ok(dst))) {
			snprintf(err, errlen, "acl %s, ace %s: a network that "
			    "is no prefix", acl, e->name);
			return (-1);
		}
		if (m->tcp != NULL) {
			REFUSE(m->tcp->has_sequence_number, "tcp sequence-number");
			REFUSE(m->tcp->has_acknowledgement_number,
			    "tcp acknowledgement-number");
			REFUSE(m->tcp->has_data_offset, "tcp data-offset");
			REFUSE(m->tcp->has_reserved, "tcp reserved");
			REFUSE(m->tcp->flags.len > 0, "tcp flags");
			REFUSE(m->tcp->has_window_size, "tcp window-size");
			REFUSE(m->tcp->has_urgent_pointer, "tcp urgent-pointer");
			REFUSE(m->tcp->options.len > 0, "tcp options");
			PMATCH(m->tcp->source_port, sp);
			PMATCH(m->tcp->destination_port, dp);
			if (p != -1 && p != 6) {
				snprintf(err, errlen, "acl %s, ace %s: a TCP "
				    "match with protocol %d", acl, e->name, p);
				return (-1);
			}
			p = 6;
			if (port_words(more, sizeof(more), "src-port", &sp, err,
			    errlen) != 0 || port_words(more, sizeof(more),
			    "dst-port", &dp, err, errlen) != 0)
				return (-1);
		}
		if (m->udp != NULL) {
			REFUSE(m->udp->has_length, "udp length");
			PMATCH(m->udp->source_port, sp);
			PMATCH(m->udp->destination_port, dp);
			if (p != -1 && p != 17) {
				snprintf(err, errlen, "acl %s, ace %s: a UDP "
				    "match with protocol %d", acl, e->name, p);
				return (-1);
			}
			p = 17;
			if (port_words(more, sizeof(more), "src-port", &sp, err,
			    errlen) != 0 || port_words(more, sizeof(more),
			    "dst-port", &dp, err, errlen) != 0)
				return (-1);
		}
		if (m->icmp != NULL) {
			REFUSE(m->icmp->has_code, "icmp code");
			REFUSE(m->icmp->rest_of_header.len > 0,
			    "icmp rest-of-header");
			if (fam == 0) {
				snprintf(err, errlen, "acl %s, ace %s: an ICMP "
				    "match needs its family: an ipv4 or ipv6 "
				    "match, or the ACL's type", acl, e->name);
				return (-1);
			}
			if (p != -1 && p != (fam == 4 ? 1 : 58)) {
				snprintf(err, errlen, "acl %s, ace %s: an ICMP "
				    "match with protocol %d", acl, e->name, p);
				return (-1);
			}
			p = fam == 4 ? 1 : 58;
			if (m->icmp->has_type)
				snprintf(more + strlen(more), sizeof(more) -
				    strlen(more), " %s %u", fam == 4 ?
				    "icmptypes" : "icmp6types", m->icmp->type);
		}
	}
	switch (p) {
	case -1:
		snprintf(proto, sizeof(proto), "ip");
		break;
	case 1:
		snprintf(proto, sizeof(proto), "icmp");
		break;
	case 6:
		snprintf(proto, sizeof(proto), "tcp");
		break;
	case 17:
		snprintf(proto, sizeof(proto), "udp");
		break;
	case 58:
		snprintf(proto, sizeof(proto), "ipv6-icmp");
		break;
	default:
		snprintf(proto, sizeof(proto), "%d", p);
		break;
	}
	fwd = e->actions->forwarding;
	nf = 0;
	if (fam == 0 && fwd == acl_ident("reject")) {
		fams[nf++] = 4;
		fams[nf++] = 6;
	} else
		fams[nf++] = fam;
	for (int i = 0; i < nf; i++) {
		if (fwd == acl_ident("accept"))
			act = "allow";
		else if (fwd == acl_ident("drop"))
			act = "deny";
		else if (fwd == acl_ident("reject"))
			act = fams[i] == 6 ? "unreach6 admin-prohib" :
			    "unreach filter-prohib";
		else {
			snprintf(err, errlen, "acl %s, ace %s: a forwarding "
			    "action this agent does not know", acl, e->name);
			return (-1);
		}
		fprintf(fp, "add %d set %d %s %s from %s to %s%s%s // %s\n", num,
		    ACL_STAGE, act, proto, src, dst, more, fams[i] == 4 ? " ip4" :
		    fams[i] == 6 ? " ip6" : "", cm);
	}
	return (0);
}

#undef	REFUSE

/*
 * The ACLs as ipfw's commands for the staging set, a line each, into
 * fp; how many rules into *nrules.  -1 and why when one cannot be.
 */
static int
acl_compile(const yacls *c, FILE *fp, int *nrules, char *err, size_t errlen)
{
	const yacl	*l;
	const yattach	*ap;
	char		 cm[ACL_COMMENT + 1], tag[32];
	int		*band, fam, num, k;
	size_t		 i, j;

	*nrules = 0;
	if (c == NULL || (c->acl.n == 0 && (c->attachment_points == NULL ||
	    c->attachment_points->interface.n == 0)))
		return (0);
	if ((band = calloc(c->acl.n + 1, sizeof(*band))) == NULL) {
		snprintf(err, errlen, "%s", strerror(errno));
		return (-1);
	}
	if (bands_of(c, band, err, errlen) != 0)
		goto bad;
	comment_of(cm, sizeof(cm), "guard", NULL, NULL);
	fprintf(fp, "add %d set %d skipto %d ip from any to any // %s\n",
	    ACL_GUARD, ACL_STAGE, ACL_PAST, cm);
	(*nrules)++;
	for (i = 0; i < c->acl.n; i++) {
		l = &c->acl.v[i];
		fam = 0;
		if (l->has_type) {
			if (l->type == acl_ident("ipv4-acl-type"))
				fam = 4;
			else if (l->type == acl_ident("ipv6-acl-type"))
				fam = 6;
			else {
				snprintf(err, errlen, "acl %s: its type is not "
				    "compiled into ipfw by this agent", l->name);
				goto bad;
			}
		}
		for (j = 0; l->aces != NULL && j < l->aces->ace.n; j++) {
			snprintf(tag, sizeof(tag), "%zu.%zu", i, j + 1);
			comment_of(cm, sizeof(cm), tag, l->name,
			    l->aces->ace.v[j].name);
			if (ace_compile(fp, l->name, fam, band[i] + (int)j,
			    &l->aces->ace.v[j], cm, err, errlen) != 0)
				goto bad;
			(*nrules)++;
		}
		snprintf(tag, sizeof(tag), "%zu.end", i);
		comment_of(cm, sizeof(cm), tag, l->name, NULL);
		fprintf(fp, "add %d set %d return ip from any to any // %s\n",
		    band[i] + (int)j, ACL_STAGE, cm);
		(*nrules)++;
	}
	/* The attachment block, entered at rule 8 when it calls any. */
	num = ACL_ATTACH;
	for (i = 0; c->attachment_points != NULL &&
	    i < c->attachment_points->interface.n; i++) {
		ap = &c->attachment_points->interface.v[i];
		if (!ifname_ok(ap->interface_id)) {
			snprintf(err, errlen, "attachment point %s: no interface "
			    "name ipfw reads", ap->interface_id);
			goto bad;
		}
		for (int dir = 0; dir < 2; dir++) {
			const struct ietf_access_control_list_acls_attachment_points_interface_ingress_acl_sets
			    *in = ap->ingress != NULL ? ap->ingress->acl_sets :
			    NULL;
			const struct ietf_access_control_list_acls_attachment_points_interface_egress_acl_sets
			    *out = ap->egress != NULL ? ap->egress->acl_sets :
			    NULL;
			size_t n = dir == 0 ? (in != NULL ? in->acl_set.n : 0) :
			    (out != NULL ? out->acl_set.n : 0);

			for (j = 0; j < n; j++) {
				const char *name = dir == 0 ?
				    in->acl_set.v[j].name : out->acl_set.v[j].name;

				if ((k = acl_index(c, name)) == -1) {
					snprintf(err, errlen, "attachment point "
					    "%s: no acl %s", ap->interface_id,
					    name);
					goto bad;
				}
				if (num >= ACL_ATTACH_END) {
					snprintf(err, errlen, "more attachments "
					    "than rules %d to %d hold",
					    ACL_ATTACH, ACL_ATTACH_END - 1);
					goto bad;
				}
				snprintf(tag, sizeof(tag), "%d.%s", k, dir == 0 ?
				    "in" : "out");
				comment_of(cm, sizeof(cm), tag, ap->interface_id,
				    NULL);
				fprintf(fp, "add %d set %d call %d ip from any to "
				    "any %s %s // %s\n", num++, ACL_STAGE, band[k],
				    dir == 0 ? "in recv" : "out xmit",
				    ap->interface_id, cm);
				(*nrules)++;
			}
		}
	}
	if (num > ACL_ATTACH) {
		comment_of(cm, sizeof(cm), "attach-end", NULL, NULL);
		fprintf(fp, "add %d set %d return ip from any to any // %s\n",
		    num, ACL_STAGE, cm);
		comment_of(cm, sizeof(cm), "entry", NULL, NULL);
		fprintf(fp, "add %d set %d call %d ip from any to any // %s\n",
		    ACL_ENTRY, ACL_STAGE, ACL_ATTACH, cm);
		*nrules += 2;
	}
	free(band);
	return (0);
bad:
	free(band);
	return (-1);
}

/* ---- The kernel ------------------------------------------------------ */

/*
 * The kernel's rules, ipfw -S list's: each number, set and comment.
 * -1 where ipfw cannot be read (not loaded, or not there).
 */
static int
kernel_rules(struct work *w, struct krule **out, size_t *np)
{
	struct execres	 res;
	struct krule	*v;
	const char	*p, *nl, *c;
	char		*argv[4], *line;
	size_t		 n, cap;
	long		 num;
	int		 set, off;

	*out = NULL;
	*np = 0;
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"-S";
	argv[2] = (char *)(uintptr_t)"list";
	argv[3] = NULL;
	if (run_exec_max(w, argv, &res, ARC_MAX_JSON) != 0 || res.out == NULL)
		return (-1);
	n = cap = 0;
	v = NULL;
	for (p = res.out; *p != '\0'; p = *nl != '\0' ? nl + 1 : nl) {
		nl = p + strcspn(p, "\n");
		line = wstrndup(w, p, (size_t)(nl - p));
		if (sscanf(line, "%ld set %d %n", &num, &set, &off) != 2)
			continue;
		if (n == cap) {
			struct krule	*nv;

			cap = cap == 0 ? 64 : cap * 2;
			nv = wcalloc(w, cap, sizeof(*v));
			if (n > 0)
				memcpy(nv, v, n * sizeof(*v));
			v = nv;
		}
		v[n].num = num;
		v[n].set = set;
		c = strstr(line + off, "// ");
		v[n].comment = c != NULL ? c + 3 : "";
		n++;
	}
	*out = v;
	*np = n;
	return (0);
}

/* Whether the kernel's rules leave the ACLs' numbers and sets to them. */
static int
kernel_free(const struct krule *k, size_t n, char *err, size_t errlen)
{

	for (size_t i = 0; i < n; i++) {
		if (k[i].set == ACL_SET || k[i].set == ACL_STAGE) {
			if (strncmp(k[i].comment, ACL_PREFIX,
			    strlen(ACL_PREFIX)) != 0) {
				snprintf(err, errlen, "rule %ld is in set %d, "
				    "which the ACLs keep, and is not an ACL's: "
				    "move it to another set first", k[i].num,
				    k[i].set);
				return (-1);
			}
			continue;
		}
		if (k[i].num == ACL_ENTRY || (k[i].num >= ACL_GUARD &&
		    k[i].num < ACL_PAST)) {
			snprintf(err, errlen, "rule %ld of set %d is at a number "
			    "the ACLs keep (%d, %d to %d): renumber it first",
			    k[i].num, k[i].set, ACL_ENTRY, ACL_GUARD,
			    ACL_PAST - 1);
			return (-1);
		}
	}
	return (0);
}

static int
ipfw_quiet(struct work *w, const char *const *words, char *err,
    size_t errlen)
{
	struct execres	 res;
	char		*argv[12];
	int		 k;

	k = 0;
	argv[k++] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[k++] = (char *)(uintptr_t)"-q";
	for (; *words != NULL && k < 11; words++)
		argv[k++] = (char *)(uintptr_t)*words;
	argv[k] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		if (err != NULL)
			snprintf(err, errlen, "%s", exec_error(w, &res, "ipfw"));
		return (-1);
	}
	return (0);
}

#define	IPFW(w, err, errlen, ...)	\
	ipfw_quiet((w), (const char *const []){ __VA_ARGS__, NULL }, (err), \
	    (errlen))

/*
 * The ACLs c made what the kernel has, all at once (above); none, set
 * 29 deleted.  -1 and why, the kernel as it was.
 */
static int
acl_apply(struct work *w, const yacls *c, char *err, size_t errlen)
{
	struct krule	*k;
	char		 path[MAXPATHLEN], *buf;
	size_t		 nk, blen;
	FILE		*fp;
	int		 nrules, fd, rc;
	bool		 ours;

	buf = NULL;
	blen = 0;
	if ((fp = open_memstream(&buf, &blen)) == NULL) {
		snprintf(err, errlen, "open_memstream: %s", strerror(errno));
		return (-1);
	}
	rc = acl_compile(c, fp, &nrules, err, errlen);
	if (fclose(fp) != 0 && rc == 0) {
		snprintf(err, errlen, "the rules: %s", strerror(errno));
		rc = -1;
	}
	if (rc != 0) {
		free(buf);
		return (-1);
	}
	wadopt(w, buf);
	if (kernel_rules(w, &k, &nk) != 0) {
		if (nrules == 0)
			return (0);
		snprintf(err, errlen, "ipfw cannot be read (ipfw(4) not "
		    "loaded?): the ACLs would be kept and not enforced");
		return (-1);
	}
	if (kernel_free(k, nk, err, errlen) != 0)
		return (-1);
	if (nrules == 0) {
		ours = false;
		for (size_t i = 0; i < nk; i++)
			ours |= k[i].set == ACL_SET || k[i].set == ACL_STAGE;
		if (ours && (IPFW(w, err, errlen, "-f", "delete", "set",
		    "29") != 0 || IPFW(w, err, errlen, "-f", "delete", "set",
		    "28") != 0))
			return (-1);
		return (0);
	}
	sdwan_conf_path(ACL_LOAD, path, sizeof(path));
	if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	    O_NOFOLLOW, 0600)) == -1 || write(fd, buf, blen) !=
	    (ssize_t)blen) {
		snprintf(err, errlen, "%s: %s", path, strerror(errno));
		if (fd != -1)
			close(fd);
		return (-1);
	}
	close(fd);
	/* The staging set emptied and disabled, the rules into it, then
	 * swapped in: set 28 holds the old ones, disabled, and goes. */
	(void)IPFW(w, NULL, 0, "-f", "delete", "set", "28");
	rc = -1;
	if (IPFW(w, err, errlen, "set", "disable", "28") != 0)
		goto out;
	if (IPFW(w, err, errlen, path) != 0) {
		(void)IPFW(w, NULL, 0, "-f", "delete", "set", "28");
		goto out;
	}
	if (IPFW(w, err, errlen, "set", "swap", "28", "29") != 0) {
		(void)IPFW(w, NULL, 0, "-f", "delete", "set", "28");
		goto out;
	}
	(void)IPFW(w, NULL, 0, "set", "enable", "29");
	(void)IPFW(w, NULL, 0, "-f", "delete", "set", "28");
	rc = 0;
out:
	(void)unlink(path);
	return (rc);
}

/* ---- Running, kept ----------------------------------------------------- */

/* The kept acls into data; none, nothing.  0, or an errno. */
static int
kept_read(struct ietf_access_control_list *data, cbl_yarena *a)
{
	struct stat	 sb;
	char		 path[MAXPATHLEN], why[160];
	uint8_t		*p;
	ssize_t		 n;
	int		 fd, error;

	sdwan_conf_path(ACL_FILE, path, sizeof(path));
	if ((fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) == -1)
		return (errno == ENOENT ? 0 : errno);
	if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_size <= 0 ||
	    sb.st_size > ACL_FILE_MAX || (p = malloc((size_t)sb.st_size)) ==
	    NULL) {
		close(fd);
		logmsg(LOG_ERR, "%s: cannot be read", path);
		return (EIO);
	}
	n = read(fd, p, (size_t)sb.st_size);
	close(fd);
	if (n != sb.st_size) {
		free(p);
		return (EIO);
	}
	error = cbl_ydecode_member(acl_node(), p, (size_t)n, data, a,
	    CBL_YD_STRICT, why, sizeof(why));
	free(p);
	if (error != 0)
		logmsg(LOG_ERR, "%s: %s", path, why);
	return (error);
}

/* data's acls kept; none, the file gone. */
static int
kept_write(const struct ietf_access_control_list *data, char *err,
    size_t errlen)
{
	struct cbl_ybuf	 b = { NULL, 0, 0 };
	char		 path[MAXPATHLEN], tmp[MAXPATHLEN];
	int		 error, fd;

	sdwan_conf_path(ACL_FILE, path, sizeof(path));
	if (data == NULL || data->acls == NULL) {
		if (unlink(path) == -1 && errno != ENOENT) {
			snprintf(err, errlen, "%s: %s", path, strerror(errno));
			return (-1);
		}
		return (0);
	}
	if ((error = cbl_yencode_member(acl_node(), data, &b)) != 0) {
		snprintf(err, errlen, "%s", strerror(error));
		return (-1);
	}
	snprintf(tmp, sizeof(tmp), "%s.new", path);
	error = 0;
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	    O_NOFOLLOW, 0600)) == -1)
		error = errno;
	else {
		if (write(fd, b.p, b.len) != (ssize_t)b.len || fsync(fd) != 0)
			error = errno != 0 ? errno : EIO;
		if (close(fd) != 0 && error == 0)
			error = errno;
		if (error == 0 && rename(tmp, path) != 0)
			error = errno;
		if (error != 0)
			(void)unlink(tmp);
	}
	cbl_ybuf_free(&b);
	if (error != 0) {
		snprintf(err, errlen, "%s: %s", path, strerror(error));
		return (-1);
	}
	return (0);
}

/* ---- Read back ----------------------------------------------------------- */

/* Whether set 29 has the rule of the name map's tag, its names acl's
 * and ace's (either NULL): its comment as acl_compile() writes it. */
static bool
has_rule(const struct krule *k, size_t nk, const char *tag, const char *acl,
    const char *ace)
{
	char	cm[ACL_COMMENT + 1];

	comment_of(cm, sizeof(cm), tag, acl, ace);
	for (size_t i = 0; i < nk; i++)
		if (k[i].set == ACL_SET && strcmp(k[i].comment, cm) == 0)
			return (true);
	return (false);
}

/*
 * Running's acls as the kernel has them, into out: each ACL whose band
 * is whole (every ACE's rule and the return, by the name map), each
 * attachment whose call is there; nothing where ipfw cannot be read.
 */
static int
acl_installed(struct work *w, const yacls *c, cbl_yarena *a,
    const yacls **out)
{
	struct ietf_access_control_list_acls_attachment_points *aps;
	struct ietf_access_control_list_acls_attachment_points_interface *ifs;
	struct ietf_access_control_list_acls_attachment_points_interface_ingress
	    *ing;
	struct ietf_access_control_list_acls_attachment_points_interface_ingress_acl_sets
	    *ins;
	struct ietf_access_control_list_acls_attachment_points_interface_ingress_acl_sets_acl_set
	    *inv;
	struct ietf_access_control_list_acls_attachment_points_interface_egress
	    *eg;
	struct ietf_access_control_list_acls_attachment_points_interface_egress_acl_sets
	    *outs;
	struct ietf_access_control_list_acls_attachment_points_interface_egress_acl_sets_acl_set
	    *outv;
	struct krule	*k;
	yacls		*r;
	yacl		*v;
	char		 tag[32];
	size_t		 nk, i, j, n, m, nin, nout;
	bool		*whole, have;

	*out = NULL;
	if (kernel_rules(w, &k, &nk) != 0)
		return (0);
	if ((r = cbl_yarena_alloc(a, sizeof(*r))) == NULL ||
	    (v = cbl_yarena_alloc(a, (c->acl.n + 1) * sizeof(*v))) == NULL ||
	    (whole = cbl_yarena_alloc(a, (c->acl.n + 1) * sizeof(*whole))) ==
	    NULL)
		return (ENOMEM);
	memset(r, 0, sizeof(*r));
	n = 0;
	for (i = 0; i < c->acl.n; i++) {
		m = c->acl.v[i].aces != NULL ? c->acl.v[i].aces->ace.n : 0;
		snprintf(tag, sizeof(tag), "%zu.end", i);
		have = has_rule(k, nk, tag, c->acl.v[i].name, NULL);
		for (j = 0; have && j < m; j++) {
			snprintf(tag, sizeof(tag), "%zu.%zu", i, j + 1);
			have = has_rule(k, nk, tag, c->acl.v[i].name,
			    c->acl.v[i].aces->ace.v[j].name);
		}
		if ((whole[i] = have))
			v[n++] = c->acl.v[i];
	}
	r->acl.n = n;
	r->acl.v = v;
	if (c->attachment_points != NULL &&
	    c->attachment_points->interface.n > 0 &&
	    has_rule(k, nk, "entry", NULL, NULL)) {
		n = c->attachment_points->interface.n;
		if ((aps = cbl_yarena_alloc(a, sizeof(*aps))) == NULL ||
		    (ifs = cbl_yarena_alloc(a, n * sizeof(*ifs))) == NULL)
			return (ENOMEM);
		m = 0;
		for (i = 0; i < n; i++) {
			const yattach *ap = &c->attachment_points->interface.v[i];

			nin = ap->ingress != NULL && ap->ingress->acl_sets !=
			    NULL ? ap->ingress->acl_sets->acl_set.n : 0;
			nout = ap->egress != NULL && ap->egress->acl_sets !=
			    NULL ? ap->egress->acl_sets->acl_set.n : 0;
			if ((ing = cbl_yarena_alloc(a, sizeof(*ing))) == NULL ||
			    (ins = cbl_yarena_alloc(a, sizeof(*ins))) == NULL ||
			    (inv = cbl_yarena_alloc(a, (nin + 1) *
			    sizeof(*inv))) == NULL ||
			    (eg = cbl_yarena_alloc(a, sizeof(*eg))) == NULL ||
			    (outs = cbl_yarena_alloc(a, sizeof(*outs))) == NULL ||
			    (outv = cbl_yarena_alloc(a, (nout + 1) *
			    sizeof(*outv))) == NULL)
				return (ENOMEM);
			memset(ing, 0, sizeof(*ing));
			memset(ins, 0, sizeof(*ins));
			memset(eg, 0, sizeof(*eg));
			memset(outs, 0, sizeof(*outs));
			for (j = 0; j < nin; j++) {
				const char *name = ap->ingress->acl_sets->
				    acl_set.v[j].name;
				int x = acl_index(c, name);

				snprintf(tag, sizeof(tag), "%d.in", x);
				if (x != -1 && whole[x] && has_rule(k, nk, tag,
				    ap->interface_id, NULL))
					inv[ins->acl_set.n++].name = name;
			}
			for (j = 0; j < nout; j++) {
				const char *name = ap->egress->acl_sets->
				    acl_set.v[j].name;
				int x = acl_index(c, name);

				snprintf(tag, sizeof(tag), "%d.out", x);
				if (x != -1 && whole[x] && has_rule(k, nk, tag,
				    ap->interface_id, NULL))
					outv[outs->acl_set.n++].name = name;
			}
			if (ins->acl_set.n == 0 && outs->acl_set.n == 0)
				continue;
			memset(&ifs[m], 0, sizeof(ifs[m]));
			ifs[m].interface_id = ap->interface_id;
			if (ins->acl_set.n > 0) {
				ins->acl_set.v = inv;
				ing->acl_sets = ins;
				ifs[m].ingress = ing;
			}
			if (outs->acl_set.n > 0) {
				outs->acl_set.v = outv;
				eg->acl_sets = outs;
				ifs[m].egress = eg;
			}
			m++;
		}
		if (m > 0) {
			aps->interface.n = m;
			aps->interface.v = ifs;
			r->attachment_points = aps;
		}
	}
	if (r->acl.n > 0 || r->attachment_points != NULL)
		*out = r;
	return (0);
}

/* ---- The model's ---------------------------------------------------------- */

/*
 * The acls: running's kept; the operational datastore's, those of them
 * the kernel has (acl_installed()).
 */
int
acl_get(bool operational, cbl_yarena *a, struct ietf_access_control_list *data)
{
	struct ietf_access_control_list	 kept;
	struct work			 w;
	int				 error;

	memset(&kept, 0, sizeof(kept));
	pthread_mutex_lock(&acl_lock);
	error = kept_read(&kept, a);
	pthread_mutex_unlock(&acl_lock);
	if (error != 0 || kept.acls == NULL)
		return (error);
	if (!operational) {
		data->acls = kept.acls;
		return (0);
	}
	work_init(&w);
	w.nice = true;
	error = acl_installed(&w, kept.acls, a, &data->acls);
	work_free(&w);
	return (error);
}

/*
 * after's acls compiled and made the kernel's, then kept; refused, -1
 * and why, the kernel and the file as they were.
 */
int
acl_edit(const struct ietf_access_control_list *after, char *err,
    size_t errlen)
{
	struct work	w;
	int		rc;

	err[0] = '\0';
	work_init(&w);
	pthread_mutex_lock(&acl_lock);
	rc = acl_apply(&w, after != NULL ? after->acls : NULL, err, errlen);
	if (rc == 0)
		rc = kept_write(after, err, errlen);
	pthread_mutex_unlock(&acl_lock);
	work_free(&w);
	if (rc == 0)
		logmsg(LOG_NOTICE, "acls: %zu applied", after != NULL &&
		    after->acls != NULL ? after->acls->acl.n : 0);
	return (rc);
}

/* At the start: the kept ACLs made the kernel's again. */
void
acl_start(void)
{
	struct ietf_access_control_list	 kept;
	struct work			 w;
	cbl_yarena			*a;
	char				 err[256];

	if ((a = cbl_yarena_new()) == NULL)
		return;
	memset(&kept, 0, sizeof(kept));
	if (kept_read(&kept, a) == 0 && kept.acls != NULL) {
		work_init(&w);
		pthread_mutex_lock(&acl_lock);
		if (acl_apply(&w, kept.acls, err, sizeof(err)) != 0)
			logmsg(LOG_ERR, "acls: the kept ACLs not applied: %s",
			    err);
		pthread_mutex_unlock(&acl_lock);
		work_free(&w);
	}
	cbl_yarena_free(a);
}
