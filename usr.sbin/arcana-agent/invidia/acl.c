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
 * What is compiled (6.1.1, 6.1.2): the ACL's type (IPv4, IPv6, the
 * Ethernet and mixed ones, none); the IPv4 and IPv6 networks, protocol,
 * DSCP (dscp), length (iplen, IPv6's payload and its header), IPv4's
 * TTL (ipttl), ECN not-ECT or CE (iptos), flags (frag),
 * identification (ipid), IPv6's flow label (flow-id); the TCP
 * and UDP ports with their operators, TCP's sequence and
 * acknowledgement numbers, flags but CWR and ECE, window (tcpseq,
 * tcpack, tcpflags, tcpwin); the ICMP type; the ingress and egress
 * interface (recv, xmit); the MAC addresses with their masks and the
 * ethertype IPv4's or IPv6's (mac, mac-type, on the way in, above); the
 * forwarding actions (reject an ICMP unreachable, administratively
 * prohibited) and logging (6.1.4: log-syslog "log logdst syslog", to
 * syslogd(8) as LOG_SECURITY whatever net.inet.ip.fw.verbose, at most
 * net.inet.ip.fw.verbose_limit packets a rule).  Bits leaves (IPv4's
 * and TCP's flags) match the bits named set, the others as they may be.
 *
 * Every other match is refused (6.1.3), nothing loaded: an ACE is never
 * installed matching more than it says.  The refusal is an extended ack
 * (cblink's error, RFC 8040's errors): error-path the node at fault (a
 * SID, the ACL and ACE named in the message), error-tag
 * operation-not-supported for what ipfw cannot say, invalid-value for
 * what does not hold together, in-use for an admin's rule in the way,
 * resource-denied for more than the numbers hold, and the message why.
 *
 * Statistics (6.1.4, acl-aggregate-stats): an ACE's matched-packets and
 * matched-octets are its rules' counters (ipfw -a list), the rules of
 * every family it has summed, the layer-2 pass's tagging rule not (the
 * IP pass's decides); the band is one for every attachment, so the
 * counters are the aggregate RFC 8519 asks for.  They count from the
 * last edit: each loads the rules anew.
 *
 * RFC 9899's defined sets (ietf-acl-enh, 6.1.5), compiled into the ACEs
 * that name them: an IPv4 or IPv6 prefix set is an addr table,
 * "src-ip table(T)" or "dst-ip table(T)"; a port set the ranges its
 * entries cover, a port list where ipfw's 30 hold them, a number table
 * ("lookup dst-port T") where not; a protocol set an or-block of
 * protocols ("{ proto 6 or proto 17 }"); an ICMP type set a list
 * (icmptypes, icmp6types); an alias its parts, the destination its
 * prefixes' addr table, its ports and its protocols as the sets', an
 * ACE naming several a rule each at its number.  Every option is
 * and-ed with the RFC 8519 matches beside it.  The tables are the
 * ACLs', named "acl-G-K.I": G the generation, K the kind (4 and 6 a
 * prefix set's, a an alias's prefixes, p a port set's ports, q an
 * alias's), I the set's place in its list.  An edit fills the tables of
 * the generation not in use, shadows nothing references yet, before
 * the rules that name them go into set 28; the set swap makes rules and
 * tables live at once, and the old generation's tables are destroyed
 * once set 28 has let go of them.  No table is ever swapped (ipfw's
 * table swap corrupts tables with values, docs/TODO.md) nor changed
 * while a rule uses it.  The operational datastore's prefix sets are
 * what the live tables hold.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <net/if.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
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
#define	ACL_TABLE	"acl-"		/* the ACLs' tables, acl-G-K.I */
#define	ACL_PORTLIST	30		/* ipfw's longest port list, in ranges */
#define	ACL_TABLE_PORTS	8192		/* the most ports a port table holds */
#define	ACL_PORTS	65536

typedef struct ietf_access_control_list_acls yacls;
typedef struct ietf_access_control_list_acls_acl yacl;
typedef struct ietf_access_control_list_acls_acl_aces_ace yace;
typedef struct ietf_access_control_list_acls_acl_aces_ace_matches ymatch;
typedef struct ietf_access_control_list_acls_attachment_points_interface
    yattach;
typedef struct ietf_access_control_list_acls_acl_enh_defined_sets ysets;
typedef struct ietf_access_control_list_acls_acl_enh_defined_sets_port_sets_port_set
    yportset;
typedef struct ietf_access_control_list_acls_acl_enh_defined_sets_aliases_alias
    yalias;

static pthread_mutex_t	acl_lock = PTHREAD_MUTEX_INITIALIZER;

/* A rule of the kernel's: its number, set, counters and comment ("" none);
 * count whether its action is count (a layer-2 pass's tagging), gen the
 * generation of the ACLs' tables it names (-1 none). */
struct krule {
	long		 num;
	int		 set;
	int		 gen;
	bool		 count;
	uintmax_t	 pkts, bytes;
	const char	*comment;
};

/* A table of the ACLs' as the kernel has it: its name and entries, each
 * the key as ipfw lists it. */
struct ktable {
	const char	*name;
	size_t		 n;
	const char	**entry;
};

/* Why an edit is refused: the message, the node at fault, the errno. */
struct aclerr {
	char		 msg[512];
	uint64_t	 sid;		/* 0: the acls */
	int		 error;
};

static const struct cbl_ynode *
acl_node(void)
{

	return (ynode_named("ietf-access-control-list", "acls"));
}

/*
 * A refusal into ae: errno error, the node at fault by its path below
 * acls ("acl/aces/ace/matches/ipv4/ihl"; NULL the acls), the message.
 * -1, for the caller to return.
 */
static int __printflike(4, 5)
fault(struct aclerr *ae, int error, const char *node, const char *fmt, ...)
{
	const struct cbl_ynode	*n;
	va_list			 ap;

	va_start(ap, fmt);
	vsnprintf(ae->msg, sizeof(ae->msg), fmt, ap);
	va_end(ap);
	ae->error = error;
	n = node != NULL ? ynet_node("ietf-access-control-list", "acls",
	    node) : NULL;
	ae->sid = n != NULL ? n->sid : 0;
	return (-1);
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
bands_of(const yacls *c, int *band, struct aclerr *ae)
{
	size_t	i, n;
	int	next;

	next = ACL_BANDS;
	for (i = 0; i < c->acl.n; i++) {
		n = c->acl.v[i].aces != NULL ? c->acl.v[i].aces->ace.n : 0;
		if ((size_t)next + n > ACL_BANDS_END)
			return (fault(ae, ENOBUFS, "acl/aces/ace", "acl %s: "
			    "more ACEs than rules %d to %d hold, with the ACLs "
			    "before it", c->acl.v[i].name, ACL_BANDS,
			    ACL_BANDS_END));
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

/* A port match as ipfw's option, appended to b; node its path below
 * acls, for a refusal. */
static int
port_words(char *b, size_t len, const char *opt, const struct pmatch *m,
    const char *acl, const char *ace, const char *node, struct aclerr *ae)
{
	char	path[96];
	size_t	off = strlen(b);

	switch (m->which) {
	case 0:
		return (0);
	case 1:
		if (m->lower > m->upper) {
			snprintf(path, sizeof(path), "%s/lower-port", node);
			return (fault(ae, EINVAL, path, "acl %s, ace %s: %s: "
			    "lower-port %u is above upper-port %u", acl, ace,
			    opt, m->lower, m->upper));
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

/* Words appended to an option buffer. */
static void __printflike(3, 4)
words_add(char *b, size_t len, const char *fmt, ...)
{
	va_list	ap;
	size_t	off = strlen(b);

	va_start(ap, fmt);
	vsnprintf(b + off, len - off, fmt, ap);
	va_end(ap);
}

/* Whether a bits value (RFC 9254: position p in byte p / 8, from the
 * low bit) has position pos set. */
static bool
bit_set(const struct cbl_bytes *b, unsigned pos)
{

	return (pos / 8 < b->len &&
	    (((const uint8_t *)b->p)[pos / 8] & (1u << (pos % 8))) != 0);
}

/* A MAC address as the model's pattern has it, a word of ipfw's. */
static bool
mac_ok(const char *s)
{

	return (strlen(s) == 17 && strspn(s, "0123456789abcdefABCDEF:") == 17);
}

/* A MAC match as ipfw's word: any, the address, the address&mask; -1
 * where it is none or a mask has no address. */
static int
mac_word(char *b, size_t len, const char *addr, const char *mask)
{

	if (addr == NULL) {
		snprintf(b, len, "any");
		return (mask == NULL ? 0 : -1);
	}
	if (!mac_ok(addr) || (mask != NULL && !mac_ok(mask)))
		return (-1);
	snprintf(b, len, "%s%s%s", addr, mask != NULL ? "&" : "",
	    mask != NULL ? mask : "");
	return (0);
}

/* ---- The defined sets (RFC 9899) --------------------------------------- */

/* A defined set's place in its list by name, every set's struct starting
 * with its name; -1: none. */
static int
set_index(const void *v, size_t n, size_t size, const char *name)
{

	for (size_t i = 0; i < n; i++)
		if (strcmp(*(const char *const *)(const void *)
		    ((const char *)v + i * size), name) == 0)
			return ((int)i);
	return (-1);
}

#define	SET_INDEX(c, l, name)						\
	((c) == NULL ? -1 : set_index((c)->l.v, (c)->l.n,		\
	    sizeof(*(c)->l.v), (name)))

/* A table of the ACLs': generation gen, kind ('4', '6' a prefix set's,
 * 'a' an alias's prefixes, 'p' a port set's ports, 'q' an alias's), the
 * set's place i in its list. */
static void
table_name(char *b, size_t len, int gen, char kind, size_t i)
{

	snprintf(b, len, ACL_TABLE "%d-%c.%zu", gen, kind, i);
}

/* Ports from lo to hi into a bitmap of the 65536. */
static void
ports_add(uint8_t *map, unsigned lo, unsigned hi)
{

	for (unsigned p = lo; p <= hi && p < ACL_PORTS; p++)
		setbit(map, p);
}

/*
 * A bitmap's ports as ipfw's ranges, "a-b,c", the first ACL_PORTLIST
 * into b; how many ranges into *nr, how many ports into *np.
 */
static void
ports_ranges(const uint8_t *map, char *b, size_t len, size_t *nr, size_t *np)
{
	size_t	off;
	unsigned lo;

	*nr = *np = 0;
	b[0] = '\0';
	off = 0;
	for (unsigned p = 0; p < ACL_PORTS; p++) {
		if (isclr(map, p))
			continue;
		for (lo = p; p + 1 < ACL_PORTS && isset(map, p + 1); p++)
			;
		*np += p - lo + 1;
		if (++*nr <= ACL_PORTLIST && off < len) {
			if (lo == p)
				off += (size_t)snprintf(b + off, len - off, "%s%u",
				    off > 0 ? "," : "", lo);
			else
				off += (size_t)snprintf(b + off, len - off,
				    "%s%u-%u", off > 0 ? "," : "", lo, p);
		}
	}
}

/*
 * A port set's ports into map: each entry a range or a port with its
 * operator (lte, gte, eq, neq).  -1 and why where a range is upside
 * down.
 */
static int
portset_fill(const yportset *s, uint8_t *map, struct aclerr *ae)
{
	const struct ietf_access_control_list_acls_acl_enh_defined_sets_port_sets_port_set_port_port_range_or_operator
	    *r;

	for (size_t j = 0; j < s->port.n; j++) {
		if ((r = s->port.v[j].port_range_or_operator) == NULL)
			continue;
		if (r->has_lower_port) {
			if (r->upper_port < r->lower_port)
				return (fault(ae, EINVAL, "defined-sets/port-sets/"
				    "port-set/port/port-range-or-operator/"
				    "lower-port", "port set %s, port %s: "
				    "lower-port %u is above upper-port %u",
				    s->name, s->port.v[j].id, r->lower_port,
				    r->upper_port));
			ports_add(map, r->lower_port, r->upper_port);
			continue;
		}
		if (!r->has_port)
			continue;
		switch (r->has_operator ? (int)r->operator : 2) {
		case 0:
			ports_add(map, 0, r->port);
			break;
		case 1:
			ports_add(map, r->port, ACL_PORTS - 1);
			break;
		case 3:
			if (r->port > 0)
				ports_add(map, 0, r->port - 1u);
			ports_add(map, r->port + 1u, ACL_PORTS - 1);
			break;
		default:
			ports_add(map, r->port, r->port);
			break;
		}
	}
	return (0);
}

/* An alias's ports into map, each range's upper port its lower where it
 * has none. */
static void
alias_ports(const yalias *al, uint8_t *map)
{

	for (size_t j = 0; j < al->port_range.n; j++)
		ports_add(map, al->port_range.v[j].lower_port,
		    al->port_range.v[j].has_upper_port ?
		    al->port_range.v[j].upper_port :
		    al->port_range.v[j].lower_port);
}

/* An ICMP type of a set's, the number or the IANA module's name (its
 * enum's value is the type's). */
#define	ICMP_TYPE(t)							\
	((t).which == 0 ? (unsigned)(t).v.m0 : (unsigned)(t).v.m1)

/*
 * The tables of the defined sets, generation gen, as ipfw's commands
 * into fp: each prefix set's (an addr table, empty where the set is) and
 * each alias's prefixes'; the ports of a port set or an alias where
 * ipfw's port list would not hold them (a number table).  -1 and why
 * where one cannot be.
 */
static int
tables_compile(const ysets *ds, int gen, FILE *fp, struct aclerr *ae)
{
	const struct ietf_access_control_list_acls_acl_enh_defined_sets_ipv4_prefix_sets_prefix_set
	    *s4;
	const struct ietf_access_control_list_acls_acl_enh_defined_sets_ipv6_prefix_sets_prefix_set
	    *s6;
	const yalias	*al;
	const char	*pfx;
	uint8_t		*map;
	char		 t[64], list[16];
	size_t		 i, j, nr, np;
	int		 rc;

	if (ds == NULL)
		return (0);
	for (i = 0; ds->ipv4_prefix_sets != NULL &&
	    i < ds->ipv4_prefix_sets->prefix_set.n; i++) {
		s4 = &ds->ipv4_prefix_sets->prefix_set.v[i];
		table_name(t, sizeof(t), gen, '4', i);
		fprintf(fp, "table %s create type addr\n", t);
		for (j = 0; j < s4->prefix.n; j++) {
			if (!prefix_ok(s4->prefix.v[j]))
				return (fault(ae, EINVAL, "defined-sets/"
				    "ipv4-prefix-sets/prefix-set/prefix",
				    "ipv4 prefix set %s: %s is no prefix ipfw "
				    "reads", s4->name, s4->prefix.v[j]));
			fprintf(fp, "table %s add %s\n", t, s4->prefix.v[j]);
		}
	}
	for (i = 0; ds->ipv6_prefix_sets != NULL &&
	    i < ds->ipv6_prefix_sets->prefix_set.n; i++) {
		s6 = &ds->ipv6_prefix_sets->prefix_set.v[i];
		table_name(t, sizeof(t), gen, '6', i);
		fprintf(fp, "table %s create type addr\n", t);
		for (j = 0; j < s6->prefix.n; j++) {
			if (!prefix_ok(s6->prefix.v[j]))
				return (fault(ae, EINVAL, "defined-sets/"
				    "ipv6-prefix-sets/prefix-set/prefix",
				    "ipv6 prefix set %s: %s is no prefix ipfw "
				    "reads", s6->name, s6->prefix.v[j]));
			fprintf(fp, "table %s add %s\n", t, s6->prefix.v[j]);
		}
	}
	for (i = 0; ds->aliases != NULL && i < ds->aliases->alias.n; i++) {
		al = &ds->aliases->alias.v[i];
		if (al->prefix.n == 0)
			continue;
		table_name(t, sizeof(t), gen, 'a', i);
		fprintf(fp, "table %s create type addr\n", t);
		for (j = 0; j < al->prefix.n; j++) {
			pfx = al->prefix.v[j].which == 0 ? al->prefix.v[j].v.m0 :
			    al->prefix.v[j].v.m1;
			if (!prefix_ok(pfx))
				return (fault(ae, EINVAL, "defined-sets/aliases/"
				    "alias/prefix", "alias %s: %s is no prefix "
				    "ipfw reads", al->name, pfx));
			fprintf(fp, "table %s add %s\n", t, pfx);
		}
	}
	if ((map = malloc(ACL_PORTS / NBBY)) == NULL)
		return (fault(ae, ENOMEM, NULL, "%s", strerror(errno)));
	rc = 0;
	for (i = 0; rc == 0 && ds->port_sets != NULL &&
	    i < ds->port_sets->port_set.n; i++) {
		memset(map, 0, ACL_PORTS / NBBY);
		if ((rc = portset_fill(&ds->port_sets->port_set.v[i], map,
		    ae)) != 0)
			break;
		ports_ranges(map, list, sizeof(list), &nr, &np);
		if (nr <= ACL_PORTLIST)
			continue;
		if (np > ACL_TABLE_PORTS) {
			rc = fault(ae, ENOBUFS, "defined-sets/port-sets/port-set",
			    "port set %s: %zu ranges and %zu ports, more than "
			    "ipfw's port list (%d ranges) and this agent's port "
			    "table (%d ports) hold",
			    ds->port_sets->port_set.v[i].name, nr, np,
			    ACL_PORTLIST, ACL_TABLE_PORTS);
			break;
		}
		table_name(t, sizeof(t), gen, 'p', i);
		fprintf(fp, "table %s create type number\n", t);
		for (unsigned p = 0; p < ACL_PORTS; p++)
			if (isset(map, p))
				fprintf(fp, "table %s add %u\n", t, p);
	}
	for (i = 0; rc == 0 && ds->aliases != NULL &&
	    i < ds->aliases->alias.n; i++) {
		memset(map, 0, ACL_PORTS / NBBY);
		alias_ports(&ds->aliases->alias.v[i], map);
		ports_ranges(map, list, sizeof(list), &nr, &np);
		if (nr <= ACL_PORTLIST)
			continue;
		if (np > ACL_TABLE_PORTS) {
			rc = fault(ae, ENOBUFS, "defined-sets/aliases/alias/"
			    "port-range", "alias %s: %zu ranges and %zu ports, "
			    "more than ipfw's port list (%d ranges) and this "
			    "agent's port table (%d ports) hold",
			    ds->aliases->alias.v[i].name, nr, np, ACL_PORTLIST,
			    ACL_TABLE_PORTS);
			break;
		}
		table_name(t, sizeof(t), gen, 'q', i);
		fprintf(fp, "table %s create type number\n", t);
		for (unsigned p = 0; p < ACL_PORTS; p++)
			if (isset(map, p))
				fprintf(fp, "table %s add %u\n", t, p);
	}
	free(map);
	return (rc);
}

/*
 * A prefix set an ACE names (name; NULL none), of family fam, as ipfw's
 * option opt (src-ip, dst-ip) on its table, appended to b.
 */
static int
prefixlist_words(char *b, size_t len, const char *opt, const ysets *ds,
    int gen, int fam, const char *name, const char *acl, const char *ace,
    const char *node, struct aclerr *ae)
{
	char	t[64];
	int	i;

	if (name == NULL)
		return (0);
	i = fam == 4 ? SET_INDEX(ds != NULL ? ds->ipv4_prefix_sets : NULL,
	    prefix_set, name) : SET_INDEX(ds != NULL ? ds->ipv6_prefix_sets :
	    NULL, prefix_set, name);
	if (i == -1)
		return (fault(ae, EINVAL, node, "acl %s, ace %s: no ipv%d prefix "
		    "set %s", acl, ace, fam, name));
	table_name(t, sizeof(t), gen, fam == 4 ? '4' : '6', (size_t)i);
	words_add(b, len, " %s table(%s)", opt, t);
	return (0);
}

/*
 * A port set an ACE names, as ipfw's option opt (src-port, dst-port)
 * appended to b: its ranges, or its table where a port list would not
 * hold them.  node is the reference's path below acls.
 */
static int
portset_words(char *b, size_t len, const char *opt, const ysets *ds, int gen,
    const char *name, const char *acl, const char *ace, const char *node,
    struct aclerr *ae)
{
	uint8_t	*map;
	char	 list[512], t[64];
	size_t	 nr, np;
	int	 i;

	if ((i = SET_INDEX(ds != NULL ? ds->port_sets : NULL, port_set,
	    name)) == -1)
		return (fault(ae, EINVAL, node, "acl %s, ace %s: no port set %s",
		    acl, ace, name));
	if ((map = calloc(1, ACL_PORTS / NBBY)) == NULL)
		return (fault(ae, ENOMEM, NULL, "%s", strerror(errno)));
	if (portset_fill(&ds->port_sets->port_set.v[i], map, ae) != 0) {
		free(map);
		return (-1);
	}
	ports_ranges(map, list, sizeof(list), &nr, &np);
	free(map);
	if (nr == 0)
		return (fault(ae, EINVAL, node, "acl %s, ace %s: port set %s "
		    "holds no port: the ACE would match nothing", acl, ace,
		    name));
	if (nr <= ACL_PORTLIST)
		words_add(b, len, " %s %s", opt, list);
	else {
		table_name(t, sizeof(t), gen, 'p', (size_t)i);
		words_add(b, len, " lookup %s %s", opt, t);
	}
	return (0);
}

/* Protocols as ipfw's option appended to b: one "proto N", several an
 * or-block of them.  -1 where one is 0, which ipfw reads as any. */
static int
proto_block(char *b, size_t len, const int *v, size_t n)
{

	for (size_t j = 0; j < n; j++)
		if (v[j] == 0)
			return (-1);
	words_add(b, len, n > 1 ? " {" : "");
	for (size_t j = 0; j < n; j++)
		words_add(b, len, "%s proto %d", j > 0 ? " or" : "", v[j]);
	words_add(b, len, n > 1 ? " }" : "");
	return (0);
}

/* A protocol set an ACE names, appended to b (proto_block()); a name as
 * /etc/protocols has it. */
static int
protoset_words(char *b, size_t len, const ysets *ds, const char *name,
    const char *acl, const char *ace, const char *node, struct aclerr *ae)
{
	const struct ietf_access_control_list_acls_acl_enh_defined_sets_protocol_sets_protocol_set
	    *s;
	struct protoent	 pe, *res;
	char		 buf[1024];
	int		*v, i, rc;

	if ((i = SET_INDEX(ds != NULL ? ds->protocol_sets : NULL,
	    protocol_set, name)) == -1)
		return (fault(ae, EINVAL, node, "acl %s, ace %s: no protocol "
		    "set %s", acl, ace, name));
	s = &ds->protocol_sets->protocol_set.v[i];
	if (s->protocol.n == 0)
		return (fault(ae, EINVAL, node, "acl %s, ace %s: protocol set "
		    "%s holds no protocol: the ACE would match nothing", acl,
		    ace, name));
	if ((v = calloc(s->protocol.n, sizeof(*v))) == NULL)
		return (fault(ae, ENOMEM, NULL, "%s", strerror(errno)));
	rc = 0;
	for (size_t j = 0; rc == 0 && j < s->protocol.n; j++) {
		if (s->protocol.v[j].which == 0) {
			v[j] = s->protocol.v[j].v.m0;
			continue;
		}
		if (getprotobyname_r(s->protocol.v[j].v.m1, &pe, buf,
		    sizeof(buf), &res) != 0 || res == NULL)
			rc = fault(ae, EINVAL, "defined-sets/protocol-sets/"
			    "protocol-set/protocol", "protocol set %s: %s is "
			    "no protocol /etc/protocols names", name,
			    s->protocol.v[j].v.m1);
		else
			v[j] = pe.p_proto;
	}
	if (rc == 0 && proto_block(b, len, v, s->protocol.n) != 0)
		rc = fault(ae, EOPNOTSUPP, "defined-sets/protocol-sets/"
		    "protocol-set/protocol", "protocol set %s: protocol 0 is "
		    "not compiled into ipfw by this agent: ipfw reads proto 0 "
		    "as any protocol", name);
	free(v);
	return (rc);
}

/*
 * An ICMP type set an ACE names (an ICMPv6 one where v6), its types as
 * icmptypes' or icmp6types' list appended to b; a type with its code or
 * the rest of its header refused (ipfw reads the type alone).
 */
static int
icmpset_words(char *b, size_t len, bool v6, const ysets *ds, const char *name,
    const char *acl, const char *ace, const char *node, struct aclerr *ae)
{
	char	 list[2048];	/* 256 types at most, the list's keys */
	size_t	 n, off;
	int	 i;

	list[0] = '\0';
	off = 0;
	if (!v6) {
		const struct ietf_access_control_list_acls_acl_enh_defined_sets_icmpv4_type_sets_set
		    *s;

		if ((i = SET_INDEX(ds != NULL ? ds->icmpv4_type_sets : NULL,
		    set, name)) == -1)
			return (fault(ae, EINVAL, node, "acl %s, ace %s: no "
			    "icmpv4 type set %s", acl, ace, name));
		s = &ds->icmpv4_type_sets->set.v[i];
		n = s->icmpv4_type.n;
		for (size_t j = 0; j < n; j++) {
			const struct ietf_access_control_list_acls_acl_enh_defined_sets_icmpv4_type_sets_set_icmpv4_type
			    *ty = &s->icmpv4_type.v[j];

			if (ty->has_code || ty->rest_of_header.len > 0)
				return (fault(ae, EOPNOTSUPP, ty->has_code ?
				    "defined-sets/icmpv4-type-sets/set/"
				    "icmpv4-type/code" : "defined-sets/"
				    "icmpv4-type-sets/set/icmpv4-type/"
				    "rest-of-header", "icmpv4 type set %s: a "
				    "type's %s is not compiled into ipfw by "
				    "this agent: icmptypes reads the type alone",
				    name, ty->has_code ? "code" :
				    "rest-of-header"));
			off += (size_t)snprintf(list + off, sizeof(list) - off,
			    "%s%u", j > 0 ? "," : "", ICMP_TYPE(ty->type));
		}
	} else {
		const struct ietf_access_control_list_acls_acl_enh_defined_sets_icmpv6_type_sets_set
		    *s;

		if ((i = SET_INDEX(ds != NULL ? ds->icmpv6_type_sets : NULL,
		    set, name)) == -1)
			return (fault(ae, EINVAL, node, "acl %s, ace %s: no "
			    "icmpv6 type set %s", acl, ace, name));
		s = &ds->icmpv6_type_sets->set.v[i];
		n = s->icmpv6_type.n;
		for (size_t j = 0; j < n; j++) {
			const struct ietf_access_control_list_acls_acl_enh_defined_sets_icmpv6_type_sets_set_icmpv6_type
			    *ty = &s->icmpv6_type.v[j];

			if (ty->has_code || ty->rest_of_header.len > 0)
				return (fault(ae, EOPNOTSUPP, ty->has_code ?
				    "defined-sets/icmpv6-type-sets/set/"
				    "icmpv6-type/code" : "defined-sets/"
				    "icmpv6-type-sets/set/icmpv6-type/"
				    "rest-of-header", "icmpv6 type set %s: a "
				    "type's %s is not compiled into ipfw by "
				    "this agent: icmp6types reads the type alone",
				    name, ty->has_code ? "code" :
				    "rest-of-header"));
			off += (size_t)snprintf(list + off, sizeof(list) - off,
			    "%s%u", j > 0 ? "," : "", ICMP_TYPE(ty->type));
		}
	}
	if (n == 0)
		return (fault(ae, EINVAL, node, "acl %s, ace %s: icmpv%d type "
		    "set %s holds no type: the ACE would match nothing", acl,
		    ace, v6 ? 6 : 4, name));
	words_add(b, len, " %s %s", v6 ? "icmp6types" : "icmptypes", list);
	return (0);
}

/*
 * An alias an ACE names, decomposed into b: the destination in its
 * prefixes' table (the alias names its target), its protocols as a
 * protocol set's, its ports as a port set's (the destination's).  Its
 * VLANs, FQDNs and URIs refused.
 */
static int
alias_words(char *b, size_t len, const ysets *ds, int gen, const char *name,
    const char *acl, const char *ace, struct aclerr *ae)
{
	const yalias	*al;
	uint8_t		*map;
	char		 list[512], t[64];
	size_t		 nr, np;
	int		*v, i, rc;

	if ((i = SET_INDEX(ds != NULL ? ds->aliases : NULL, alias,
	    name)) == -1)
		return (fault(ae, EINVAL, "acl/aces/ace/matches/alias-name",
		    "acl %s, ace %s: no alias %s", acl, ace, name));
	al = &ds->aliases->alias.v[i];
	if (al->vlan.n > 0)
		return (fault(ae, EOPNOTSUPP, "defined-sets/aliases/alias/vlan",
		    "alias %s: vlan is not compiled into ipfw by this agent: "
		    "the ACLs decide on the IP pass, where a frame's 802.1Q tag "
		    "is gone", name));
	if (al->fqdn.n > 0)
		return (fault(ae, EOPNOTSUPP, "defined-sets/aliases/alias/fqdn",
		    "alias %s: fqdn is not compiled into ipfw by this agent: "
		    "ipfw matches addresses, never the names they came from",
		    name));
	if (al->uri.n > 0)
		return (fault(ae, EOPNOTSUPP, "defined-sets/aliases/alias/uri",
		    "alias %s: uri is not compiled into ipfw by this agent: "
		    "ipfw reads no application layer", name));
	if (al->prefix.n == 0 && al->protocol.n == 0 && al->port_range.n == 0)
		return (fault(ae, EINVAL, "acl/aces/ace/matches/alias-name",
		    "acl %s, ace %s: alias %s names no prefix, protocol or "
		    "port to match", acl, ace, name));
	if (al->prefix.n > 0) {
		table_name(t, sizeof(t), gen, 'a', (size_t)i);
		words_add(b, len, " dst-ip table(%s)", t);
	}
	if (al->protocol.n > 0) {
		if ((v = calloc(al->protocol.n, sizeof(*v))) == NULL)
			return (fault(ae, ENOMEM, NULL, "%s", strerror(errno)));
		for (size_t j = 0; j < al->protocol.n; j++)
			v[j] = al->protocol.v[j];
		rc = proto_block(b, len, v, al->protocol.n);
		free(v);
		if (rc != 0)
			return (fault(ae, EOPNOTSUPP, "defined-sets/aliases/"
			    "alias/protocol", "alias %s: protocol 0 is not "
			    "compiled into ipfw by this agent: ipfw reads proto "
			    "0 as any protocol", name));
	}
	if (al->port_range.n > 0) {
		if ((map = calloc(1, ACL_PORTS / NBBY)) == NULL)
			return (fault(ae, ENOMEM, NULL, "%s", strerror(errno)));
		alias_ports(al, map);
		ports_ranges(map, list, sizeof(list), &nr, &np);
		free(map);
		if (nr <= ACL_PORTLIST)
			words_add(b, len, " dst-port %s", list);
		else {
			table_name(t, sizeof(t), gen, 'q', (size_t)i);
			words_add(b, len, " lookup dst-port %s", t);
		}
	}
	return (0);
}

/* ---- The ACEs -------------------------------------------------------- */

/*
 * What ipfw cannot say, refused (6.1.3): the node at fault by its path
 * below the ACE's matches or actions, what of it, and why ipfw cannot;
 * nothing is installed that matches more than the ACE says.
 */
#define	REFUSE(cond, node, what, why) do {				\
	if (cond)							\
		return (fault(ae, EOPNOTSUPP, "acl/aces/ace/" node,	\
		    "acl %s, ace %s: %s is not compiled into ipfw by this "	\
		    "agent: %s", acl, e->name, (what), (why)));		\
} while (0)

/* What does not hold together, refused: invalid-value. */
#define	INVALID(node, ...)						\
	return (fault(ae, EINVAL, "acl/aces/ace/" node, __VA_ARGS__))

#define	ATT_IN	1		/* attached on an interface's way in */
#define	ATT_OUT	2		/* on its way out */

/*
 * An ACE as ipfw's rules at number num, into fp.  fam is the ACL's
 * family (4, 6; 0 either), att how the ACL is attached (ATT_IN,
 * ATT_OUT), l2 whether it has an Ethernet match, ds the defined sets
 * and gen their tables' generation.  An ACL with one
 * decides on the IP pass alone ("not layer2"): an Ethernet match is a
 * rule of the layer-2 pass that tags the frame with the ACE's number,
 * which the ACE's rule looks for on the IP pass ("tagged"); a frame
 * comes up from ether_demux() with its tags, so this holds on the way
 * in alone.  One rule, or two where a reject of either family needs
 * each its own unreachable, and the tagging one before; an ACE naming
 * aliases has those for each alias, every one at its number.
 */
static int
ace_compile(FILE *fp, const char *acl, int fam, int att, bool l2, int num,
    const yace *e, const char *cm, const ysets *ds, int gen,
    struct aclerr *ae)
{
	const ymatch	*m = e->matches;
	struct pmatch	 sp, dp;
	char		 more[4096], aw[2048], ethw[160], frag[32], tcpf[48];
	char		 l2w[32], dmac[40], smac[40], proto[16], act[48];
	const char	*src, *dst, *log;
	uint64_t	 fwd;
	unsigned	 et;
	size_t		 na;
	int		 p, fams[2], nf;

	src = dst = "any";
	more[0] = aw[0] = ethw[0] = frag[0] = tcpf[0] = l2w[0] = '\0';
	p = -1;
	if (e->actions == NULL || !e->actions->has_forwarding)
		INVALID("actions/forwarding", "acl %s, ace %s: no forwarding "
		    "action", acl, e->name);
	/* RFC 9899's actions are 6.1.7's: refused until then. */
	REFUSE(e->actions->acl_enh_log_action != NULL,
	    "actions/ietf-acl-enh:log-action", "log-action", "not yet "
	    "(logging, RFC 8519's, is log-syslog)");
	REFUSE(e->actions->acl_enh_counter_action != NULL,
	    "actions/ietf-acl-enh:counter-action", "counter-action", "not yet "
	    "(the ACE's statistics are its rule's counters)");
	REFUSE(e->actions->has_acl_enh_rate_limit,
	    "actions/ietf-acl-enh:rate-limit", "rate-limit", "not yet (a "
	    "dummynet pipe)");
	/* Logging: to syslogd(8), the rule's own destination. */
	log = "";
	if (e->actions->has_logging && e->actions->logging ==
	    acl_ident("log-syslog"))
		log = " log logdst syslog";
	else
		REFUSE(e->actions->has_logging && e->actions->logging !=
		    acl_ident("log-none"), "actions/logging", "a log action "
		    "other than log-syslog and log-none", "ipfw logs to "
		    "syslogd(8), bpf(4) or the routing socket");
	if (m != NULL && m->eth != NULL) {
		if (mac_word(dmac, sizeof(dmac),
		    m->eth->destination_mac_address,
		    m->eth->destination_mac_address_mask) != 0)
			INVALID("matches/eth/destination-mac-address-mask",
			    "acl %s, ace %s: a MAC mask without its address",
			    acl, e->name);
		if (mac_word(smac, sizeof(smac), m->eth->source_mac_address,
		    m->eth->source_mac_address_mask) != 0)
			INVALID("matches/eth/source-mac-address-mask",
			    "acl %s, ace %s: a MAC mask without its address",
			    acl, e->name);
		if (strcmp(dmac, "any") != 0 || strcmp(smac, "any") != 0)
			words_add(ethw, sizeof(ethw), " mac %s %s", dmac, smac);
		if (m->eth->has_ethertype) {
			et = m->eth->ethertype.which == 0 ?
			    m->eth->ethertype.v.m0 :
			    (unsigned)m->eth->ethertype.v.m1;
			REFUSE(et != 0x0800 && et != 0x86dd,
			    "matches/eth/ethertype", "an ethertype other than "
			    "IPv4's or IPv6's", "other frames meet ipfw on the "
			    "layer-2 pass alone, and the ACL decides on the IP "
			    "pass");
			if (fam == (et == 0x0800 ? 6 : 4))
				INVALID("matches/eth/ethertype", "acl %s, ace "
				    "%s: ethertype 0x%04x in an IPv%d ACL", acl,
				    e->name, et, fam);
			fam = et == 0x0800 ? 4 : 6;
			words_add(ethw, sizeof(ethw), " mac-type 0x%04x", et);
		}
	}
	if (m != NULL) {
		if (m->ipv4 != NULL) {
			if (fam == 6)
				INVALID("matches/ipv4", "acl %s, ace %s: an "
				    "IPv4 match in an IPv6 ACL", acl, e->name);
			fam = 4;
			if (m->ipv4->has_dscp)
				words_add(more, sizeof(more), " dscp %u",
				    m->ipv4->dscp);
			REFUSE(m->ipv4->has_ecn && m->ipv4->ecn != 0 &&
			    m->ipv4->ecn != 3, "matches/ipv4/ecn",
			    "ipv4 ecn 1 or 2 (ECT)", "iptos reads ECN's two "
			    "bits at once (congestion, 0x03), neither alone");
			if (m->ipv4->has_ecn)
				words_add(more, sizeof(more), " iptos %s",
				    m->ipv4->ecn == 3 ? "congestion" :
				    "!congestion");
			if (m->ipv4->has_length)
				words_add(more, sizeof(more), " iplen %u",
				    m->ipv4->length);
			if (m->ipv4->has_ttl)
				words_add(more, sizeof(more), " ipttl %u",
				    m->ipv4->ttl);
			REFUSE(m->ipv4->has_ihl, "matches/ipv4/ihl", "ipv4 ihl",
			    "ipfw has no header length match (ipoptions names "
			    "options, not how long they are)");
			/* The flags named set, the others as they may be. */
			if (bit_set(&m->ipv4->flags, 0))
				words_add(frag, sizeof(frag), ",rf");
			if (bit_set(&m->ipv4->flags, 1))
				words_add(frag, sizeof(frag), ",df");
			if (bit_set(&m->ipv4->flags, 2))
				words_add(frag, sizeof(frag), ",mf");
			REFUSE(m->ipv4->has_offset, "matches/ipv4/offset",
			    "ipv4 offset", "frag reads whether the offset is "
			    "0, never its value, and the model's is 20 up");
			if (frag[0] != '\0')
				words_add(more, sizeof(more), " frag %s",
				    frag + 1);
			if (m->ipv4->has_identification)
				words_add(more, sizeof(more), " ipid %u",
				    m->ipv4->identification);
			REFUSE(m->ipv4->acl_enh_ipv4_fragment != NULL,
			    "matches/ipv4/ietf-acl-enh:ipv4-fragment",
			    "ipv4-fragment", "not yet (frag and its offset)");
			if (m->ipv4->has_protocol)
				p = m->ipv4->protocol;
			if (m->ipv4->source_ipv4_network != NULL)
				src = m->ipv4->source_ipv4_network;
			if (m->ipv4->destination_ipv4_network != NULL)
				dst = m->ipv4->destination_ipv4_network;
			/* RFC 9899's sets: the prefix lists' tables, the
			 * protocol set's or-block. */
			if (prefixlist_words(more, sizeof(more), "src-ip", ds,
			    gen, 4, m->ipv4->acl_enh_source_ipv4_prefix_list,
			    acl, e->name, "acl/aces/ace/matches/ipv4/"
			    "source-ipv4-prefix-list", ae) != 0 ||
			    prefixlist_words(more, sizeof(more), "dst-ip", ds,
			    gen, 4,
			    m->ipv4->acl_enh_destination_ipv4_prefix_list,
			    acl, e->name, "acl/aces/ace/matches/ipv4/"
			    "destination-ipv4-prefix-list", ae) != 0)
				return (-1);
			if (m->ipv4->acl_enh_protocol_set != NULL &&
			    protoset_words(more, sizeof(more), ds,
			    m->ipv4->acl_enh_protocol_set, acl, e->name,
			    "acl/aces/ace/matches/ipv4/protocol-set", ae) != 0)
				return (-1);
		}
		if (m->ipv6 != NULL) {
			if (fam == 4)
				INVALID("matches/ipv6", "acl %s, ace %s: an "
				    "IPv6 match in an IPv4 ACL", acl, e->name);
			fam = 6;
			if (m->ipv6->has_dscp)
				words_add(more, sizeof(more), " dscp %u",
				    m->ipv6->dscp);
			REFUSE(m->ipv6->has_ecn, "matches/ipv6/ecn", "ipv6 ecn",
			    "iptos, ipfw's ECN match, reads IPv4's header "
			    "alone");
			/* iplen is IPv6's whole length, the payload's and
			 * the 40 bytes of its header. */
			REFUSE(m->ipv6->has_length && m->ipv6->length > 65535 -
			    40, "matches/ipv6/length", "ipv6 length above "
			    "65495", "iplen is the whole packet's, the 40 "
			    "bytes of the header with it, and goes to 65535");
			if (m->ipv6->has_length)
				words_add(more, sizeof(more), " iplen %u",
				    m->ipv6->length + 40u);
			REFUSE(m->ipv6->has_ttl, "matches/ipv6/ttl",
			    "ipv6 ttl (the hop limit)", "ipfw has no hop limit "
			    "match (ipttl reads IPv4's header alone)");
			if (m->ipv6->has_flow_label)
				words_add(more, sizeof(more), " flow-id %u",
				    m->ipv6->flow_label);
			REFUSE(m->ipv6->acl_enh_ipv6_fragment != NULL,
			    "matches/ipv6/ietf-acl-enh:ipv6-fragment",
			    "ipv6-fragment", "not yet (ext6 frag)");
			REFUSE(m->ipv6->has_acl_enh_extension_header,
			    "matches/ipv6/ietf-acl-enh:extension-header",
			    "extension-header", "not yet (ext6)");
			if (m->ipv6->has_protocol)
				p = m->ipv6->protocol;
			if (m->ipv6->source_ipv6_network != NULL)
				src = m->ipv6->source_ipv6_network;
			if (m->ipv6->destination_ipv6_network != NULL)
				dst = m->ipv6->destination_ipv6_network;
			if (prefixlist_words(more, sizeof(more), "src-ip", ds,
			    gen, 6, m->ipv6->acl_enh_source_ipv6_prefix_list,
			    acl, e->name, "acl/aces/ace/matches/ipv6/"
			    "source-ipv6-prefix-list", ae) != 0 ||
			    prefixlist_words(more, sizeof(more), "dst-ip", ds,
			    gen, 6,
			    m->ipv6->acl_enh_destination_ipv6_prefix_list,
			    acl, e->name, "acl/aces/ace/matches/ipv6/"
			    "destination-ipv6-prefix-list", ae) != 0)
				return (-1);
			if (m->ipv6->acl_enh_protocol_set != NULL &&
			    protoset_words(more, sizeof(more), ds,
			    m->ipv6->acl_enh_protocol_set, acl, e->name,
			    "acl/aces/ace/matches/ipv6/protocol-set", ae) != 0)
				return (-1);
		}
		if (strcmp(src, "any") != 0 && !prefix_ok(src))
			return (fault(ae, EINVAL, fam == 4 ?
			    "acl/aces/ace/matches/ipv4/source-ipv4-network" :
			    "acl/aces/ace/matches/ipv6/source-ipv6-network",
			    "acl %s, ace %s: a network that is no prefix", acl,
			    e->name));
		if (strcmp(dst, "any") != 0 && !prefix_ok(dst))
			return (fault(ae, EINVAL, fam == 4 ?
			    "acl/aces/ace/matches/ipv4/destination-ipv4-network" :
			    "acl/aces/ace/matches/ipv6/destination-ipv6-network",
			    "acl %s, ace %s: a network that is no prefix", acl,
			    e->name));
		if (m->tcp != NULL) {
			REFUSE(m->tcp->has_data_offset,
			    "matches/tcp/data-offset", "tcp data-offset",
			    "ipfw has no TCP header length match");
			REFUSE(m->tcp->has_reserved, "matches/tcp/reserved",
			    "tcp reserved", "tcpflags names fin, syn, rst, psh, "
			    "ack and urg alone");
			REFUSE(bit_set(&m->tcp->flags, 1) ||
			    bit_set(&m->tcp->flags, 2), "matches/tcp/flags",
			    "tcp flags cwr and ece", "tcpflags names fin, syn, "
			    "rst, psh, ack and urg alone");
			REFUSE(m->tcp->has_urgent_pointer,
			    "matches/tcp/urgent-pointer", "tcp urgent-pointer",
			    "ipfw has no urgent pointer match");
			REFUSE(m->tcp->options.len > 0, "matches/tcp/options",
			    "tcp options", "tcpoptions tells which options are "
			    "there, never their bytes");
			REFUSE(m->tcp->acl_enh_flags_bitmask != NULL,
			    "matches/tcp/ietf-acl-enh:flags-bitmask",
			    "flags-bitmask", "not yet (tcpflags)");
			PMATCH(m->tcp->source_port, sp);
			PMATCH(m->tcp->destination_port, dp);
			if (p != -1 && p != 6)
				INVALID("matches/tcp", "acl %s, ace %s: a TCP "
				    "match with protocol %d", acl, e->name, p);
			p = 6;
			if (port_words(more, sizeof(more), "src-port", &sp, acl,
			    e->name, "acl/aces/ace/matches/tcp/source-port",
			    ae) != 0 || port_words(more, sizeof(more),
			    "dst-port", &dp, acl, e->name,
			    "acl/aces/ace/matches/tcp/destination-port",
			    ae) != 0)
				return (-1);
			if ((m->tcp->acl_enh_source_tcp_port_set != NULL &&
			    portset_words(more, sizeof(more), "src-port", ds,
			    gen, m->tcp->acl_enh_source_tcp_port_set, acl,
			    e->name, "acl/aces/ace/matches/tcp/"
			    "source-tcp-port-set", ae) != 0) ||
			    (m->tcp->acl_enh_destination_tcp_port_set != NULL &&
			    portset_words(more, sizeof(more), "dst-port", ds,
			    gen, m->tcp->acl_enh_destination_tcp_port_set, acl,
			    e->name, "acl/aces/ace/matches/tcp/"
			    "destination-tcp-port-set", ae) != 0))
				return (-1);
			if (m->tcp->has_sequence_number)
				words_add(more, sizeof(more), " tcpseq %u",
				    m->tcp->sequence_number);
			if (m->tcp->has_acknowledgement_number)
				words_add(more, sizeof(more), " tcpack %u",
				    m->tcp->acknowledgement_number);
			/* The flags named set, the others as they may be
			 * (RFC 9899's flags-bitmask says which, 6.1.6). */
			if (bit_set(&m->tcp->flags, 3))
				words_add(tcpf, sizeof(tcpf), ",urg");
			if (bit_set(&m->tcp->flags, 4))
				words_add(tcpf, sizeof(tcpf), ",ack");
			if (bit_set(&m->tcp->flags, 5))
				words_add(tcpf, sizeof(tcpf), ",psh");
			if (bit_set(&m->tcp->flags, 6))
				words_add(tcpf, sizeof(tcpf), ",rst");
			if (bit_set(&m->tcp->flags, 7))
				words_add(tcpf, sizeof(tcpf), ",syn");
			if (bit_set(&m->tcp->flags, 8))
				words_add(tcpf, sizeof(tcpf), ",fin");
			if (tcpf[0] != '\0')
				words_add(more, sizeof(more), " tcpflags %s",
				    tcpf + 1);
			if (m->tcp->has_window_size)
				words_add(more, sizeof(more), " tcpwin %u",
				    m->tcp->window_size);
		}
		if (m->udp != NULL) {
			REFUSE(m->udp->has_length, "matches/udp/length",
			    "udp length", "ipfw has no UDP length match (iplen "
			    "is the IP packet's, its options and extension "
			    "headers with it)");
			PMATCH(m->udp->source_port, sp);
			PMATCH(m->udp->destination_port, dp);
			if (p != -1 && p != 17)
				INVALID("matches/udp", "acl %s, ace %s: a UDP "
				    "match with protocol %d", acl, e->name, p);
			p = 17;
			if (port_words(more, sizeof(more), "src-port", &sp, acl,
			    e->name, "acl/aces/ace/matches/udp/source-port",
			    ae) != 0 || port_words(more, sizeof(more),
			    "dst-port", &dp, acl, e->name,
			    "acl/aces/ace/matches/udp/destination-port",
			    ae) != 0)
				return (-1);
			if ((m->udp->acl_enh_source_udp_port_set != NULL &&
			    portset_words(more, sizeof(more), "src-port", ds,
			    gen, m->udp->acl_enh_source_udp_port_set, acl,
			    e->name, "acl/aces/ace/matches/udp/"
			    "source-udp-port-set", ae) != 0) ||
			    (m->udp->acl_enh_destination_udp_port_set != NULL &&
			    portset_words(more, sizeof(more), "dst-port", ds,
			    gen, m->udp->acl_enh_destination_udp_port_set, acl,
			    e->name, "acl/aces/ace/matches/udp/"
			    "destination-udp-port-set", ae) != 0))
				return (-1);
		}
		if (m->icmp != NULL) {
			REFUSE(m->icmp->has_code, "matches/icmp/code",
			    "icmp code", "icmptypes and icmp6types read the "
			    "type alone");
			REFUSE(m->icmp->rest_of_header.len > 0,
			    "matches/icmp/rest-of-header",
			    "icmp rest-of-header", "ipfw reads nothing of ICMP "
			    "past its type");
			/* A type set names its family. */
			if (m->icmp->acl_enh_icmpv4_set != NULL &&
			    m->icmp->acl_enh_icmpv6_set != NULL)
				INVALID("matches/icmp/ietf-acl-enh:icmpv6-set",
				    "acl %s, ace %s: an icmpv4 and an icmpv6 type "
				    "set at once", acl, e->name);
			if ((m->icmp->acl_enh_icmpv4_set != NULL && fam == 6) ||
			    (m->icmp->acl_enh_icmpv6_set != NULL && fam == 4))
				INVALID("matches/icmp", "acl %s, ace %s: an "
				    "icmpv%d type set in an IPv%d ACE", acl,
				    e->name, fam == 6 ? 4 : 6, fam);
			if (m->icmp->acl_enh_icmpv4_set != NULL)
				fam = 4;
			else if (m->icmp->acl_enh_icmpv6_set != NULL)
				fam = 6;
			if (fam == 0)
				INVALID("matches/icmp", "acl %s, ace %s: an ICMP "
				    "match needs its family: an ipv4 or ipv6 "
				    "match, the ACL's type or a type set", acl,
				    e->name);
			if (p != -1 && p != (fam == 4 ? 1 : 58))
				INVALID("matches/icmp", "acl %s, ace %s: an ICMP "
				    "match with protocol %d", acl, e->name, p);
			p = fam == 4 ? 1 : 58;
			if (m->icmp->has_type)
				words_add(more, sizeof(more), " %s %u",
				    fam == 4 ? "icmptypes" : "icmp6types",
				    m->icmp->type);
			if (m->icmp->acl_enh_icmpv4_set != NULL ||
			    m->icmp->acl_enh_icmpv6_set != NULL) {
				if (icmpset_words(more, sizeof(more), fam == 6,
				    ds, fam == 6 ? m->icmp->acl_enh_icmpv6_set :
				    m->icmp->acl_enh_icmpv4_set, acl, e->name,
				    fam == 6 ? "acl/aces/ace/matches/icmp/"
				    "icmpv6-set" : "acl/aces/ace/matches/icmp/"
				    "icmpv4-set", ae) != 0)
					return (-1);
			}
		}
		if (m->ingress_interface != NULL) {
			if (!ifname_ok(m->ingress_interface))
				INVALID("matches/ingress-interface", "acl %s, "
				    "ace %s: ingress-interface %s is no "
				    "interface name ipfw reads", acl, e->name,
				    m->ingress_interface);
			words_add(more, sizeof(more), " recv %s",
			    m->ingress_interface);
		}
		if (m->egress_interface != NULL) {
			REFUSE(att & ATT_IN, "matches/egress-interface",
			    "egress-interface in an ACL attached on an "
			    "interface's way in", "routing has not chosen it "
			    "yet");
			if (!ifname_ok(m->egress_interface))
				INVALID("matches/egress-interface", "acl %s, "
				    "ace %s: egress-interface %s is no interface "
				    "name ipfw reads", acl, e->name,
				    m->egress_interface);
			words_add(more, sizeof(more), " xmit %s",
			    m->egress_interface);
		}
	}
	/* Where the ACL decides on the IP pass alone, an ACE matching
	 * any frame would leave ARP and the rest to the layer-2 pass. */
	if (l2 && fam == 0 && p == -1)
		return (fault(ae, EOPNOTSUPP, "acl/aces/ace", "acl %s, ace %s: "
		    "an ACE of an ACL with an Ethernet match that matches "
		    "frames other than IP's (they meet ipfw on the layer-2 "
		    "pass alone): name the family, by the ACL's type, an ipv4 "
		    "or ipv6 match, the protocol or the ethertype", acl,
		    e->name));
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
	if (l2 && m != NULL && m->eth != NULL) {
		fprintf(fp, "add %d set %d count tag %d ip from any to any "
		    "layer2%s // %s\n", num, ACL_STAGE, num, ethw, cm);
		snprintf(l2w, sizeof(l2w), " not layer2 tagged %d", num);
	} else if (l2)
		snprintf(l2w, sizeof(l2w), " not layer2");
	fwd = e->actions->forwarding;
	nf = 0;
	if (fam == 0 && fwd == acl_ident("reject")) {
		fams[nf++] = 4;
		fams[nf++] = 6;
	} else
		fams[nf++] = fam;
	if (fwd == acl_ident("accept"))
		snprintf(act, sizeof(act), "allow%s", log);
	else if (fwd == acl_ident("drop"))
		snprintf(act, sizeof(act), "deny%s", log);
	else if (fwd != acl_ident("reject"))
		return (fault(ae, EOPNOTSUPP, "acl/aces/ace/actions/forwarding",
		    "acl %s, ace %s: a forwarding action this agent does not "
		    "know", acl, e->name));
	/* The aliases, any one matching: a rule each. */
	na = m != NULL ? m->acl_enh_alias_name.n : 0;
	for (size_t j = 0; j < (na > 0 ? na : 1); j++) {
		aw[0] = '\0';
		if (na > 0 && alias_words(aw, sizeof(aw), ds, gen,
		    m->acl_enh_alias_name.v[j], acl, e->name, ae) != 0)
			return (-1);
		if (strlen(more) + 1 >= sizeof(more) ||
		    strlen(aw) + 1 >= sizeof(aw))
			return (fault(ae, ENOBUFS, "acl/aces/ace", "acl %s, ace "
			    "%s: more matches than one ipfw rule of this agent's "
			    "holds", acl, e->name));
		for (int i = 0; i < nf; i++) {
			if (fwd == acl_ident("reject"))
				snprintf(act, sizeof(act), "%s%s", fams[i] == 6 ?
				    "unreach6 admin-prohib" :
				    "unreach filter-prohib", log);
			fprintf(fp, "add %d set %d %s %s from %s to %s%s%s%s%s "
			    "// %s\n", num, ACL_STAGE, act, proto, src, dst,
			    more, aw, l2w, fams[i] == 4 ? " ip4" : fams[i] == 6 ?
			    " ip6" : "", cm);
		}
	}
	return (0);
}

#undef	INVALID
#undef	REFUSE

/* Whether an ACL has an Ethernet match. */
static bool
acl_l2(const yacl *l)
{

	for (size_t j = 0; l->aces != NULL && j < l->aces->ace.n; j++)
		if (l->aces->ace.v[j].matches != NULL &&
		    l->aces->ace.v[j].matches->eth != NULL)
			return (true);
	return (false);
}

/* How each ACL is attached, ATT_IN and ATT_OUT, into att; -1 and why
 * where an attachment names no ACL. */
static int
attached(const yacls *c, int *att, struct aclerr *ae)
{
	const yattach	*ap;
	const char	*name;
	size_t		 i, j, nin, nout;
	int		 k;

	for (i = 0; c->attachment_points != NULL &&
	    i < c->attachment_points->interface.n; i++) {
		ap = &c->attachment_points->interface.v[i];
		nin = ap->ingress != NULL && ap->ingress->acl_sets != NULL ?
		    ap->ingress->acl_sets->acl_set.n : 0;
		nout = ap->egress != NULL && ap->egress->acl_sets != NULL ?
		    ap->egress->acl_sets->acl_set.n : 0;
		for (j = 0; j < nin + nout; j++) {
			name = j < nin ?
			    ap->ingress->acl_sets->acl_set.v[j].name :
			    ap->egress->acl_sets->acl_set.v[j - nin].name;
			if ((k = acl_index(c, name)) == -1)
				return (fault(ae, EINVAL, j < nin ?
				    "attachment-points/interface/ingress/"
				    "acl-sets/acl-set/name" :
				    "attachment-points/interface/egress/"
				    "acl-sets/acl-set/name", "attachment point "
				    "%s: no acl %s", ap->interface_id, name));
			att[k] |= j < nin ? ATT_IN : ATT_OUT;
		}
	}
	return (0);
}

/*
 * The ACLs as ipfw's commands for the staging set, a line each, into
 * fp, the defined sets' tables of generation gen first; how many rules
 * into *nrules, the first ACL with an Ethernet match into *l2 (NULL
 * none).  -1 and why when one cannot be.
 */
static int
acl_compile(const yacls *c, int gen, FILE *fp, int *nrules, const char **l2,
    struct aclerr *ae)
{
	const yacl	*l;
	const yattach	*ap;
	char		 cm[ACL_COMMENT + 1], tag[32];
	int		*band, *att, fam, num, k;
	size_t		 i, j;
	bool		 eth;

	*nrules = 0;
	*l2 = NULL;
	if (c == NULL || (c->acl.n == 0 && (c->attachment_points == NULL ||
	    c->attachment_points->interface.n == 0)))
		return (0);
	if ((band = calloc(2 * (c->acl.n + 1), sizeof(*band))) == NULL)
		return (fault(ae, ENOMEM, NULL, "%s", strerror(errno)));
	att = band + c->acl.n + 1;
	if (bands_of(c, band, ae) != 0 || attached(c, att, ae) != 0 ||
	    tables_compile(c->acl_enh_defined_sets, gen, fp, ae) != 0)
		goto bad;
	comment_of(cm, sizeof(cm), "guard", NULL, NULL);
	fprintf(fp, "add %d set %d skipto %d ip from any to any // %s\n",
	    ACL_GUARD, ACL_STAGE, ACL_PAST, cm);
	(*nrules)++;
	for (i = 0; i < c->acl.n; i++) {
		l = &c->acl.v[i];
		fam = 0;
		if (l->has_type) {
			if (l->type == acl_ident("ipv4-acl-type") ||
			    l->type == acl_ident("mixed-eth-ipv4-acl-type"))
				fam = 4;
			else if (l->type == acl_ident("ipv6-acl-type") ||
			    l->type == acl_ident("mixed-eth-ipv6-acl-type"))
				fam = 6;
			else if (l->type != acl_ident("eth-acl-type") &&
			    l->type != acl_ident("mixed-eth-ipv4-ipv6-acl-type")) {
				(void)fault(ae, EOPNOTSUPP, "acl/type", "acl %s: "
				    "its type is not compiled into ipfw by this "
				    "agent: it names no family ipfw matches",
				    l->name);
				goto bad;
			}
		}
		if ((eth = acl_l2(l))) {
			if (att[i] & ATT_OUT) {
				(void)fault(ae, EOPNOTSUPP,
				    "attachment-points/interface/egress/"
				    "acl-sets/acl-set", "acl %s: an Ethernet "
				    "match in an ACL attached on an interface's "
				    "way out is not compiled into ipfw by this "
				    "agent: ipfw sees the frame after the IP "
				    "pass has decided", l->name);
				goto bad;
			}
			if (*l2 == NULL)
				*l2 = l->name;
		}
		for (j = 0; l->aces != NULL && j < l->aces->ace.n; j++) {
			snprintf(tag, sizeof(tag), "%zu.%zu", i, j + 1);
			comment_of(cm, sizeof(cm), tag, l->name,
			    l->aces->ace.v[j].name);
			if (ace_compile(fp, l->name, fam, att[i], eth,
			    band[i] + (int)j, &l->aces->ace.v[j], cm,
			    c->acl_enh_defined_sets, gen, ae) != 0)
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
			(void)fault(ae, EINVAL, "attachment-points/interface/"
			    "interface-id", "attachment point %s: no interface "
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
					(void)fault(ae, EINVAL,
					    "attachment-points/interface",
					    "attachment point %s: no acl %s",
					    ap->interface_id, name);
					goto bad;
				}
				if (num >= ACL_ATTACH_END) {
					(void)fault(ae, ENOBUFS,
					    "attachment-points/interface",
					    "more attachments than rules %d to "
					    "%d hold", ACL_ATTACH,
					    ACL_ATTACH_END - 1);
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
 * The kernel's rules, ipfw -a -S list's: each number, counters, set,
 * comment (a disabled set's, "# DISABLED", left out) and the generation
 * of the ACLs' tables it names.  -1 where ipfw cannot be read (not
 * loaded, or not there).
 */
static int
kernel_rules(struct work *w, struct krule **out, size_t *np)
{
	struct execres	 res;
	struct krule	*v;
	const char	*p, *nl, *c;
	char		*argv[5], *line;
	size_t		 n, cap;
	uintmax_t	 pkts, bytes;
	long		 num;
	int		 set, off;

	*out = NULL;
	*np = 0;
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"-a";
	argv[2] = (char *)(uintptr_t)"-S";
	argv[3] = (char *)(uintptr_t)"list";
	argv[4] = NULL;
	if (run_exec_max(w, argv, &res, ARC_MAX_JSON) != 0 || res.out == NULL)
		return (-1);
	n = cap = 0;
	v = NULL;
	for (p = res.out; *p != '\0'; p = *nl != '\0' ? nl + 1 : nl) {
		nl = p + strcspn(p, "\n");
		line = wstrndup(w, p, (size_t)(nl - p));
		if (sscanf(line, "%ld %ju %ju set %d %n", &num, &pkts, &bytes,
		    &set, &off) != 4)
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
		v[n].pkts = pkts;
		v[n].bytes = bytes;
		v[n].count = strncmp(line + off, "count ", 6) == 0;
		c = strstr(line + off, "// ");
		v[n].comment = c != NULL ? c + 3 : "";
		if (c != NULL)
			line[c - line] = '\0';
		v[n].gen = strstr(line + off, ACL_TABLE "0-") != NULL ? 0 :
		    strstr(line + off, ACL_TABLE "1-") != NULL ? 1 : -1;
		n++;
	}
	*out = v;
	*np = n;
	return (0);
}

/* Whether the kernel's rules leave the ACLs' numbers and sets to them. */
static int
kernel_free(const struct krule *k, size_t n, struct aclerr *ae)
{

	for (size_t i = 0; i < n; i++) {
		if (k[i].set == ACL_SET || k[i].set == ACL_STAGE) {
			if (strncmp(k[i].comment, ACL_PREFIX,
			    strlen(ACL_PREFIX)) != 0)
				return (fault(ae, EBUSY, NULL, "rule %ld is in "
				    "set %d, which the ACLs keep, and is not an "
				    "ACL's: move it to another set first",
				    k[i].num, k[i].set));
			continue;
		}
		if (k[i].num == ACL_ENTRY || (k[i].num >= ACL_GUARD &&
		    k[i].num < ACL_PAST))
			return (fault(ae, EBUSY, NULL, "rule %ld of set %d is at "
			    "a number the ACLs keep (%d, %d to %d): renumber it "
			    "first", k[i].num, k[i].set, ACL_ENTRY, ACL_GUARD,
			    ACL_PAST - 1));
		if (k[i].gen != -1)
			return (fault(ae, EBUSY, NULL, "rule %ld of set %d names "
			    "a table the ACLs keep (" ACL_TABLE "0-*, " ACL_TABLE
			    "1-*): give it a table of its own first", k[i].num,
			    k[i].set));
	}
	return (0);
}

/*
 * The ACLs' tables the kernel has (ipfw table all list: a "--- table(T),
 * set(N) ---" line, then an entry a line, its key first), into *out.
 * -1 where ipfw cannot be read.
 */
static int
kernel_tables(struct work *w, struct ktable **out, size_t *np)
{
	struct execres	 res;
	struct ktable	*v, *cur;
	const char	*p, *nl;
	char		*argv[5], *line, *e;
	size_t		 n, cap;

	*out = NULL;
	*np = 0;
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"table";
	argv[2] = (char *)(uintptr_t)"all";
	argv[3] = (char *)(uintptr_t)"list";
	argv[4] = NULL;
	if (run_exec_max(w, argv, &res, ARC_MAX_JSON) != 0)
		return (-1);
	n = cap = 0;
	v = cur = NULL;
	for (p = res.out != NULL ? res.out : ""; *p != '\0';
	    p = *nl != '\0' ? nl + 1 : nl) {
		nl = p + strcspn(p, "\n");
		line = wstrndup(w, p, (size_t)(nl - p));
		if (strncmp(line, "--- table(", 10) == 0) {
			cur = NULL;
			if ((e = strchr(line + 10, ')')) == NULL)
				continue;
			*e = '\0';
			if (strncmp(line + 10, ACL_TABLE "0-", 6) != 0 &&
			    strncmp(line + 10, ACL_TABLE "1-", 6) != 0)
				continue;
			if (n == cap) {
				struct ktable	*nv;

				cap = cap == 0 ? 16 : cap * 2;
				nv = wcalloc(w, cap, sizeof(*v));
				if (n > 0)
					memcpy(nv, v, n * sizeof(*v));
				v = nv;
			}
			cur = &v[n++];
			cur->name = line + 10;
			cur->n = 0;
			cur->entry = NULL;
			continue;
		}
		if (cur == NULL || *line == '\0')
			continue;
		line[strcspn(line, " ")] = '\0';
		if ((cur->n & 63) == 0) {
			const char	**ne;

			ne = wcalloc(w, cur->n + 64, sizeof(*ne));
			if (cur->n > 0)
				memcpy(ne, cur->entry, cur->n * sizeof(*ne));
			cur->entry = ne;
		}
		cur->entry[cur->n++] = line;
	}
	*out = v;
	*np = n;
	return (0);
}

/*
 * The generation of the ACLs' tables in use: the one set 29's rules
 * name, else the one whose tables alone are there; -1 neither.
 */
static int
live_gen(const struct krule *k, size_t nk, const struct ktable *t, size_t nt)
{
	bool	have[2] = { false, false };

	for (size_t i = 0; i < nk; i++)
		if (k[i].set == ACL_SET && k[i].gen != -1)
			return (k[i].gen);
	for (size_t i = 0; i < nt; i++)
		have[t[i].name[strlen(ACL_TABLE)] == '1'] = true;
	return (have[0] == have[1] ? -1 : have[1] ? 1 : 0);
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

/* The ACLs' tables of generation gen (-1 both) destroyed, as the kernel
 * has them now; none of them may be named by a rule then. */
static void
tables_drop(struct work *w, int gen)
{
	struct ktable	*t;
	size_t		 nt;

	if (kernel_tables(w, &t, &nt) != 0)
		return;
	for (size_t i = 0; i < nt; i++)
		if (gen == -1 || t[i].name[strlen(ACL_TABLE)] == '0' + gen)
			(void)IPFW(w, NULL, 0, "table", t[i].name, "destroy");
}

/* Whether an integer sysctl of the admin's is set (sysctl(8) where a
 * stand-in is given); 0 where it cannot be read. */
static bool
fw_sysctl(struct work *w, const char *name)
{
	struct execres	 res;
	char		*argv[4];
	size_t		 len;
	int		 v;

	if (strcmp(opts.sysctl_bin, "/sbin/sysctl") == 0) {
		len = sizeof(v);
		return (sysctlbyname(name, &v, &len, NULL, 0) == 0 && v != 0);
	}
	argv[0] = (char *)(uintptr_t)opts.sysctl_bin;
	argv[1] = (char *)(uintptr_t)"-n";
	argv[2] = (char *)(uintptr_t)name;
	argv[3] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL)
		return (false);
	return (strtol(wstrndup(w, res.out, res.outlen), NULL, 10) != 0);
}

/* Whether frames reach ipfw on the layer-2 pass: net.link.ether.ipfw,
 * the admin's to set. */
static bool
ether_ipfw(struct work *w)
{

	return (fw_sysctl(w, "net.link.ether.ipfw"));
}

/*
 * The ACLs c made what the kernel has, all at once (above); none, set
 * 29 deleted and the ACLs' tables destroyed.  -1 and why into ae, the
 * kernel as it was.
 */
static int
acl_apply(struct work *w, const yacls *c, struct aclerr *ae)
{
	char		*err = ae->msg;
	size_t		 errlen = sizeof(ae->msg);
	struct krule	*k;
	struct ktable	*t;
	const char	*l2;
	char		 path[MAXPATHLEN], *buf;
	size_t		 nk, nt, blen;
	FILE		*fp;
	int		 nrules, fd, rc, gen;
	bool		 ours, readable;

	/* The tables' generation: the one not in use. */
	readable = kernel_rules(w, &k, &nk) == 0;
	if (!readable || kernel_tables(w, &t, &nt) != 0) {
		t = NULL;
		nt = 0;
	}
	gen = readable && live_gen(k, nk, t, nt) == 0 ? 1 : 0;
	buf = NULL;
	blen = 0;
	if ((fp = open_memstream(&buf, &blen)) == NULL)
		return (fault(ae, errno, NULL, "open_memstream: %s",
		    strerror(errno)));
	rc = acl_compile(c, gen, fp, &nrules, &l2, ae);
	if (fclose(fp) != 0 && rc == 0)
		rc = fault(ae, errno, NULL, "the rules: %s", strerror(errno));
	if (rc != 0) {
		free(buf);
		return (-1);
	}
	wadopt(w, buf);
	if (l2 != NULL && !ether_ipfw(w))
		return (fault(ae, EIO, "acl/aces/ace/matches/eth", "acl %s: an "
		    "Ethernet match needs the frames on ipfw's layer-2 pass, "
		    "net.link.ether.ipfw=1, which is the admin's to set (this "
		    "agent does not)", l2));
	if (!readable) {
		if (nrules == 0)
			return (0);
		return (fault(ae, EIO, NULL, "ipfw cannot be read (ipfw(4) not "
		    "loaded?): the ACLs would be kept and not enforced"));
	}
	if (kernel_free(k, nk, ae) != 0)
		return (-1);
	/* With tables in sets, set 28's rules would look theirs up in set
	 * 28: the admin's choice, refused. */
	if (nrules > 0 && (strncmp(buf, "table ", 6) == 0 ||
	    strstr(buf, "\ntable ") != NULL) &&
	    fw_sysctl(w, "net.inet.ip.fw.tables_sets"))
		return (fault(ae, EOPNOTSUPP, "defined-sets", "the defined sets "
		    "are not compiled into ipfw by this agent with "
		    "net.inet.ip.fw.tables_sets=1: the ACLs' tables are "
		    "global, the default"));
	/* What fails from here is ipfw's, or the file's. */
	ae->error = EIO;
	ae->sid = 0;
	if (nrules == 0) {
		ours = false;
		for (size_t i = 0; i < nk; i++)
			ours |= k[i].set == ACL_SET || k[i].set == ACL_STAGE;
		if (ours && (IPFW(w, err, errlen, "-f", "delete", "set",
		    "29") != 0 || IPFW(w, err, errlen, "-f", "delete", "set",
		    "28") != 0))
			return (-1);
		if (nt > 0)
			tables_drop(w, -1);
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
	/* The staging set emptied and disabled, what is left of the new
	 * generation's tables destroyed; the tables filled and the rules
	 * loaded into set 28, then swapped in: set 28 holds the old ones,
	 * disabled, and goes, and so do the old generation's tables. */
	(void)IPFW(w, NULL, 0, "-f", "delete", "set", "28");
	tables_drop(w, gen);
	rc = -1;
	if (IPFW(w, err, errlen, "set", "disable", "28") != 0)
		goto out;
	if (IPFW(w, err, errlen, path) != 0) {
		(void)IPFW(w, NULL, 0, "-f", "delete", "set", "28");
		tables_drop(w, gen);
		goto out;
	}
	if (IPFW(w, err, errlen, "set", "swap", "28", "29") != 0) {
		(void)IPFW(w, NULL, 0, "-f", "delete", "set", "28");
		tables_drop(w, gen);
		goto out;
	}
	(void)IPFW(w, NULL, 0, "set", "enable", "29");
	(void)IPFW(w, NULL, 0, "-f", "delete", "set", "28");
	tables_drop(w, 1 - gen);
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
 * An ACE's statistics (acl-aggregate-stats) into a's st: the counters
 * of its rules in set 29, the name map's tag, every family's summed, the
 * layer-2 pass's tagging rule left out (the IP pass's decides).
 */
static int
ace_stats(const struct krule *k, size_t nk, const char *tag, const char *acl,
    const char *ace, cbl_yarena *a,
    const struct ietf_access_control_list_acls_acl_aces_ace_statistics **out)
{
	struct ietf_access_control_list_acls_acl_aces_ace_statistics *st;
	char		 cm[ACL_COMMENT + 1];

	if ((st = cbl_yarena_alloc(a, sizeof(*st))) == NULL)
		return (ENOMEM);
	memset(st, 0, sizeof(*st));
	comment_of(cm, sizeof(cm), tag, acl, ace);
	for (size_t i = 0; i < nk; i++)
		if (k[i].set == ACL_SET && !k[i].count &&
		    strcmp(k[i].comment, cm) == 0) {
			st->matched_packets += k[i].pkts;
			st->matched_octets += k[i].bytes;
		}
	st->has_matched_packets = st->has_matched_octets = true;
	*out = st;
	return (0);
}

/* s copied into a's. */
static const char *
arena_str(cbl_yarena *a, const char *s)
{
	char	*p;
	size_t	 n = strlen(s) + 1;

	if ((p = cbl_yarena_alloc(a, n)) != NULL)
		memcpy(p, s, n);
	return (p);
}

/* A table's entries as a's prefixes, into *v and *n; ENOMEM. */
static int
table_prefixes(const struct ktable *t, cbl_yarena *a, const char *const **v,
    size_t *n)
{
	const char	**p;

	*v = NULL;
	*n = 0;
	if (t->n == 0)
		return (0);
	if ((p = cbl_yarena_alloc(a, t->n * sizeof(*p))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < t->n; i++)
		if ((p[i] = arena_str(a, t->entry[i])) == NULL)
			return (ENOMEM);
	*v = p;
	*n = t->n;
	return (0);
}

/* The kernel's table of that name; NULL: none. */
static const struct ktable *
table_find(const struct ktable *t, size_t nt, const char *name)
{

	for (size_t i = 0; i < nt; i++)
		if (strcmp(t[i].name, name) == 0)
			return (&t[i]);
	return (NULL);
}

/*
 * The defined sets as the kernel has them, into *out: each prefix set
 * whose table of generation gen is there, its prefixes the table's; the
 * other sets running's, compiled into the rules that name them.
 */
static int
sets_installed(const ysets *ds, const struct ktable *t, size_t nt, int gen,
    cbl_yarena *a, const ysets **out)
{
	struct ietf_access_control_list_acls_acl_enh_defined_sets_ipv4_prefix_sets
	    *p4;
	struct ietf_access_control_list_acls_acl_enh_defined_sets_ipv4_prefix_sets_prefix_set
	    *v4;
	struct ietf_access_control_list_acls_acl_enh_defined_sets_ipv6_prefix_sets
	    *p6;
	struct ietf_access_control_list_acls_acl_enh_defined_sets_ipv6_prefix_sets_prefix_set
	    *v6;
	const struct ktable *kt;
	ysets		*r;
	char		 name[64];
	size_t		 n;
	int		 error;

	*out = NULL;
	if ((r = cbl_yarena_alloc(a, sizeof(*r))) == NULL)
		return (ENOMEM);
	*r = *ds;
	r->ipv4_prefix_sets = NULL;
	r->ipv6_prefix_sets = NULL;
	if (ds->ipv4_prefix_sets != NULL && gen != -1) {
		n = ds->ipv4_prefix_sets->prefix_set.n;
		if ((p4 = cbl_yarena_alloc(a, sizeof(*p4))) == NULL ||
		    (v4 = cbl_yarena_alloc(a, (n + 1) * sizeof(*v4))) == NULL)
			return (ENOMEM);
		memset(p4, 0, sizeof(*p4));
		for (size_t i = 0; i < n; i++) {
			table_name(name, sizeof(name), gen, '4', i);
			if ((kt = table_find(t, nt, name)) == NULL)
				continue;
			v4[p4->prefix_set.n] =
			    ds->ipv4_prefix_sets->prefix_set.v[i];
			if ((error = table_prefixes(kt, a,
			    &v4[p4->prefix_set.n].prefix.v,
			    &v4[p4->prefix_set.n].prefix.n)) != 0)
				return (error);
			p4->prefix_set.n++;
		}
		p4->prefix_set.v = v4;
		if (p4->prefix_set.n > 0)
			r->ipv4_prefix_sets = p4;
	}
	if (ds->ipv6_prefix_sets != NULL && gen != -1) {
		n = ds->ipv6_prefix_sets->prefix_set.n;
		if ((p6 = cbl_yarena_alloc(a, sizeof(*p6))) == NULL ||
		    (v6 = cbl_yarena_alloc(a, (n + 1) * sizeof(*v6))) == NULL)
			return (ENOMEM);
		memset(p6, 0, sizeof(*p6));
		for (size_t i = 0; i < n; i++) {
			table_name(name, sizeof(name), gen, '6', i);
			if ((kt = table_find(t, nt, name)) == NULL)
				continue;
			v6[p6->prefix_set.n] =
			    ds->ipv6_prefix_sets->prefix_set.v[i];
			if ((error = table_prefixes(kt, a,
			    &v6[p6->prefix_set.n].prefix.v,
			    &v6[p6->prefix_set.n].prefix.n)) != 0)
				return (error);
			p6->prefix_set.n++;
		}
		p6->prefix_set.v = v6;
		if (p6->prefix_set.n > 0)
			r->ipv6_prefix_sets = p6;
	}
	*out = r;
	return (0);
}

/*
 * Running's acls as the kernel has them, into out: each ACL whose band
 * is whole (every ACE's rule and the return, by the name map), its ACEs
 * with their statistics, each attachment whose call is there, the
 * defined sets where the ACLs are installed (sets_installed()); nothing
 * where ipfw cannot be read.
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
	struct ietf_access_control_list_acls_acl_aces	*as;
	struct krule	*k;
	struct ktable	*t;
	yacls		*r;
	yacl		*v;
	yace		*ev;
	char		 tag[32];
	size_t		 nk, nt, i, j, n, m, nin, nout;
	bool		*whole, have;
	int		 error;

	*out = NULL;
	if (kernel_rules(w, &k, &nk) != 0)
		return (0);
	if (kernel_tables(w, &t, &nt) != 0) {
		t = NULL;
		nt = 0;
	}
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
		if (!(whole[i] = have))
			continue;
		v[n] = c->acl.v[i];
		if (m > 0) {
			if ((as = cbl_yarena_alloc(a, sizeof(*as))) == NULL ||
			    (ev = cbl_yarena_alloc(a, m * sizeof(*ev))) == NULL)
				return (ENOMEM);
			for (j = 0; j < m; j++) {
				ev[j] = c->acl.v[i].aces->ace.v[j];
				snprintf(tag, sizeof(tag), "%zu.%zu", i, j + 1);
				if ((error = ace_stats(k, nk, tag,
				    c->acl.v[i].name, ev[j].name, a,
				    &ev[j].statistics)) != 0)
					return (error);
			}
			as->ace.n = m;
			as->ace.v = ev;
			v[n].aces = as;
		}
		n++;
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
	if (c->acl_enh_defined_sets != NULL &&
	    has_rule(k, nk, "guard", NULL, NULL) &&
	    (error = sets_installed(c->acl_enh_defined_sets, t, nt,
	    live_gen(k, nk, t, nt), a, &r->acl_enh_defined_sets)) != 0)
		return (error);
	if (r->acl.n > 0 || r->attachment_points != NULL ||
	    r->acl_enh_defined_sets != NULL)
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
 * after's acls compiled and made the kernel's, then kept; refused, an
 * errno, why in err and the node at fault in *sid (0: the acls), the
 * kernel and the file as they were.
 */
int
acl_edit(const struct ietf_access_control_list *after, char *err,
    size_t errlen, uint64_t *sid)
{
	struct aclerr	ae;
	struct work	w;
	int		rc;

	memset(&ae, 0, sizeof(ae));
	work_init(&w);
	pthread_mutex_lock(&acl_lock);
	rc = acl_apply(&w, after != NULL ? after->acls : NULL, &ae);
	if (rc == 0 && (rc = kept_write(after, ae.msg, sizeof(ae.msg))) != 0)
		ae.error = EIO;
	pthread_mutex_unlock(&acl_lock);
	work_free(&w);
	snprintf(err, errlen, "%s", ae.msg);
	*sid = ae.sid;
	if (rc == 0) {
		logmsg(LOG_NOTICE, "acls: %zu applied", after != NULL &&
		    after->acls != NULL ? after->acls->acl.n : 0);
		return (0);
	}
	return (ae.error != 0 ? ae.error : EIO);
}

/* At the start: the kept ACLs made the kernel's again. */
void
acl_start(void)
{
	struct ietf_access_control_list	 kept;
	struct work			 w;
	struct aclerr			 ae;
	cbl_yarena			*a;

	if ((a = cbl_yarena_new()) == NULL)
		return;
	memset(&kept, 0, sizeof(kept));
	if (kept_read(&kept, a) == 0 && kept.acls != NULL) {
		work_init(&w);
		pthread_mutex_lock(&acl_lock);
		memset(&ae, 0, sizeof(ae));
		if (acl_apply(&w, kept.acls, &ae) != 0)
			logmsg(LOG_ERR, "acls: the kept ACLs not applied: %s",
			    ae.msg);
		pthread_mutex_unlock(&acl_lock);
		work_free(&w);
	}
	cbl_yarena_free(a);
}
