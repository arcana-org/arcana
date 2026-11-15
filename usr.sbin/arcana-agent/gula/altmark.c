/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: alternate marking (RFC 9341) on the tunnels of an edge's
 * services, its packet loss counted in blocks, without a probe.
 *
 * The colour is the lowest bit of the DSCP.  The standard classes (CS,
 * AF, EF, VA) all have it clear; what has it set is RFC 2474's pools 2
 * and 3, for local and experimental use (and LE, RFC 8622's 1).  So a
 * service's traffic keeps its class: the colour of an even block is the
 * class's own DSCP, an odd block's the class's DSCP with that bit set,
 * and the far end clears it again before anything else reads the DSCP.
 * Traffic that came with the bit set (LE, local use) is carried as its
 * even neighbour: LE arrives as CS0.
 *
 * ipfw(8) does it all, in the SD-WAN rules' own set and band; sdwan.c
 * writes them into the set's file, so that they go and come with the
 * set, its undo and its safe mode as the rest of it.  On the way out of
 * a tunnel, first of all (rule 9, before the IDS's diverts and the
 * classification):
 *
 *	count ... in recv TUN dscp <even>	count ... dscp <odd>
 *		what came out at this end, of each colour
 *	setdscp tablearg ... in recv TUN lookup dscp:0x3e arcam_even
 *		the bit cleared: the class's DSCP again, before anything
 *		else reads it
 *
 * and on the way in, last (rule 11, after every rule of the way out
 * that only counts, marks or sets a FIB, before the first that ends the
 * packet's pass there: the flows' dummynet queues and pipes, the skip to
 * the way out; a packet leaving dummynet is not seen by the rules again,
 * net.inet.ip.fw.one_pass, so nothing can follow those):
 *
 *	setdscp tablearg ... out xmit TUN lookup dscp:0x3e arcamK
 *		the colour: the table maps each class (the DSCP less its
 *		lowest bit) to itself or to itself with the bit, as the
 *		block's colour says
 *	count ... out xmit TUN dscp <even>	count ... dscp <odd>
 *		what went in, of each colour
 *	setdscp tablearg PROTO from any to OUTER out ... arcam_even
 *		the bit cleared on the outer header too, which gre(4),
 *		gif(4), wg(4) and ESP copy from the inner one, of the
 *		tunnel's own protocol alone (gre; IP in IP or IPv6 for gif;
 *		UDP to its port for wg and GENEVE; ESP too when IPsec carries
 *		it), so that the underlay treats both colours alike and the
 *		admin's other traffic to that address keeps its DSCP; none
 *		where the kind is not said (the underlay then sees the
 *		colour)
 *
 * The console's queue and pipe rules of a flow by DSCP come after the
 * colour: it matches each class and its coloured neighbour (dscp 46,47).
 * Each rule has a comment "am K.J what" naming its service and tunnel.  A
 * block is L seconds of the wall clock (CLOCK_REALTIME, NTP's), block n
 * from n*L, its colour n's lowest bit; at its start the agent swaps the
 * colour table with its other (IP_FW_TABLE_XSWAP, one atomic switch of
 * every tunnel of the service), and in its middle (L/2, RFC 9341 §3.2's
 * guard band) reads the counters of the colour before (IP_FW_XGET of
 * the set's rule 9 with its counters, through ipfw's own socket option
 * IP_FW3, not ipfw -S show's text): what they gained since its last
 * block is the block before's.  A read is kept with its block number,
 * where in the block it was made and how late the swap was; it is told
 * as the event sdwan-altmark, and the last AM_BLOCKS of each tunnel are
 * in the sdwan read for the console, which subtracts the far end's
 * count in from this end's count out (RFC 9342's clusters).
 *
 * The ends agree on the block's number by their clocks alone: what is
 * measured is right while they are within L/4 of each other and a
 * packet's delay is less than L/4 (the read made between L/4 and 3L/4
 * of its block, the swap within L/4 of its start; a block outside that
 * is said not valid).  A vnet jail's edge is read on a socket made in
 * the jail's network (the helper), whose firewall is the jail's.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_fw.h>
#include <arpa/inet.h>

#include <errno.h>
#include <jail.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"


#define	AM_BLOCKS	64	/* a tunnel's kept */
#define	AM_EVENT	3000	/* bytes of an event, then another */

/* A block of a tunnel: what went in at this end and came out. */
struct amblock {
	int64_t		n;		/* its number: its start / L */
	uint64_t	out_p, out_b;	/* into the tunnel, this end */
	uint64_t	in_p, in_b;	/* out of it, this end */
	int32_t		read_ms;	/* the read, from its next's start */
	int32_t		flip_ms;	/* the swap into its next, late by */
	bool		valid;
};

struct amtun {
	struct am_tunnel t;
	uint64_t	 base[2][4];	/* a colour's counters at its last read */
	int64_t		 based[2];	/* that read's block; INT64_MIN none */
	struct amblock	 b[AM_BLOCKS];
	int		 first, nb;
};

struct amsvc {
	char		 name[AM_NAME];
	int		 period;
	int		 colour;	/* the colour table's now */
	int64_t		 read_block;	/* the last read's block */
	int32_t		 flip_ms;	/* the last swap's lateness */
	int64_t		 flip_block;
	int		 ntun;
	struct amtun	*tun;
};

struct amedge {
	char		 jail[64];
	int		 set;
	int		 fd;		/* ipfw's socket, -1 none yet */
	bool		 failing;	/* said, not said again */
	int		 nsvc;
	struct amsvc	 svc[AM_SERVICES];
};

static pthread_mutex_t	am_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	am_cond = PTHREAD_COND_INITIALIZER;
static struct amedge	*am_edges[AM_EDGES];
static int		 am_nedges;
static bool		 am_running;

static int64_t
now_ms(void)
{
	struct timespec	ts;

	(void)clock_gettime(CLOCK_REALTIME, &ts);
	return ((int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

/* ---- What the console asks for ---------------------------------------- */

static bool
word_ok(const char *s, size_t max, const char *more)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) > max)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <=
		    'Z') || (s[i] >= '0' && s[i] <= '9') || strchr(more, s[i]) !=
		    NULL))
			return (false);
	return (true);
}

void
altmark_free(struct am_service *v, int n)
{
	int	i;

	for (i = 0; v != NULL && i < n; i++)
		free(v[i].tun);
	free(v);
}

/*
 * The sdwan-rules payload's altmark: each service's name, block length
 * (period, 2 to 3600 seconds) and tunnels, each its id, its interface
 * at this edge and, where said, the far end's outer address, the
 * tunnel's kind, the far end's UDP port and whether IPsec carries it.
 * 0, or -1 and why.
 */
int
altmark_parse(const ucl_object_t *arr, struct am_service **outp, int *np,
    const char **errp)
{
	const ucl_object_t	*s, *t, *v, *x;
	ucl_object_iter_t	 it, tit;
	struct am_service	*out;
	struct am_tunnel	*tu;
	unsigned char		 a[16];
	const char		*id, *ifn, *outer;
	int			 n, k, i, j;

	*outp = NULL;
	*np = 0;
	if (arr == NULL)
		return (0);
	if (ucl_object_type(arr) != UCL_ARRAY || ucl_array_size(arr) >
	    AM_SERVICES) {
		*errp = "altmark is a list of services, 16 at most";
		return (-1);
	}
	if (ucl_array_size(arr) == 0)
		return (0);
	if ((out = calloc(ucl_array_size(arr), sizeof(*out))) == NULL) {
		*errp = strerror(errno);
		return (-1);
	}
	n = 0;
	it = NULL;
	while ((s = ucl_object_iterate(arr, &it, true)) != NULL) {
		v = ucl_object_lookup(s, "service");
		if (ucl_object_type(s) != UCL_OBJECT || v == NULL ||
		    !word_ok(ucl_object_tostring(v), AM_NAME - 1, "_.-")) {
			*errp = "altmark: a service is named by letters, digits "
			    "and _ . -";
			goto bad;
		}
		snprintf(out[n].name, sizeof(out[n].name), "%s",
		    ucl_object_tostring(v));
		v = ucl_object_lookup(s, "period");
		if (v == NULL || ucl_object_type(v) != UCL_INT ||
		    ucl_object_toint(v) < 2 || ucl_object_toint(v) > 3600) {
			*errp = "altmark: a service's period is 2 to 3600 s";
			goto bad;
		}
		out[n].period = (int)ucl_object_toint(v);
		v = ucl_object_lookup(s, "tunnels");
		if (v == NULL || ucl_object_type(v) != UCL_ARRAY ||
		    ucl_array_size(v) == 0 || ucl_array_size(v) > AM_TUNNELS) {
			*errp = "altmark: a service has tunnels, 64 at most";
			goto bad;
		}
		if ((out[n].tun = calloc(ucl_array_size(v), sizeof(*tu))) ==
		    NULL) {
			*errp = strerror(errno);
			goto bad;
		}
		k = 0;
		tit = NULL;
		while ((t = ucl_object_iterate(v, &tit, true)) != NULL) {
			tu = &out[n].tun[k];
			id = ucl_object_tostring(ucl_object_lookup(t, "id"));
			ifn = ucl_object_tostring(ucl_object_lookup(t,
			    "interface"));
			outer = ucl_object_lookup(t, "outer") != NULL ?
			    ucl_object_tostring(ucl_object_lookup(t, "outer")) :
			    NULL;
			if (!word_ok(id, sizeof(tu->id) - 1, "_.-/:,@") ||
			    !word_ok(ifn, IFNAMSIZ - 1, "_.-") ||
			    (ucl_object_lookup(t, "outer") != NULL && (outer ==
			    NULL || (inet_pton(AF_INET, outer, a) != 1 &&
			    inet_pton(AF_INET6, outer, a) != 1)))) {
				*errp = "altmark: a tunnel is its id, its interface "
				    "and the far end's outer address";
				out[n].ntun = k;
				n++;
				goto bad;
			}
			snprintf(tu->id, sizeof(tu->id), "%s", id);
			snprintf(tu->ifname, sizeof(tu->ifname), "%s", ifn);
			if (outer != NULL)
				snprintf(tu->outer, sizeof(tu->outer), "%s",
				    outer);
			/* Its kind, port and IPsec, for the outer rule's
			 * match; a kind not known, no outer rule. */
			if ((x = ucl_object_lookup(t, "kind")) != NULL &&
			    ucl_object_type(x) == UCL_STRING && (strcmp(
			    ucl_object_tostring(x), "gre") == 0 || strcmp(
			    ucl_object_tostring(x), "gif") == 0 || strcmp(
			    ucl_object_tostring(x), "wg") == 0 || strcmp(
			    ucl_object_tostring(x), "geneve") == 0))
				snprintf(tu->kind, sizeof(tu->kind), "%s",
				    ucl_object_tostring(x));
			if ((x = ucl_object_lookup(t, "port")) != NULL) {
				if (ucl_object_type(x) != UCL_INT ||
				    ucl_object_toint(x) < 1 || ucl_object_toint(x) >
				    65535) {
					*errp = "altmark: a tunnel's port is 1 to "
					    "65535";
					out[n].ntun = k;
					n++;
					goto bad;
				}
				tu->port = (int)ucl_object_toint(x);
			}
			tu->ipsec = ucl_object_toboolean(ucl_object_lookup(t,
			    "ipsec"));
			k++;
		}
		out[n].ntun = k;
		n++;
	}
	/* An interface counted twice would count twice. */
	for (i = 0; i < n; i++)
		for (j = 0; j < out[i].ntun; j++)
			for (k = 0; k < n; k++)
				for (int l = 0; l < out[k].ntun; l++)
					if ((k != i || l != j) && strcmp(
					    out[i].tun[j].ifname,
					    out[k].tun[l].ifname) == 0) {
						*errp = "altmark: an interface is "
						    "one tunnel's";
						goto bad;
					}
	*outp = out;
	*np = n;
	return (0);
bad:
	altmark_free(out, n);
	return (-1);
}

/* ---- The rules ---------------------------------------------------------- */

static void
dscp_list(char *buf, size_t len, int odd)
{
	size_t	at;
	int	d;

	buf[0] = '\0';
	for (d = odd, at = 0; d < 64 && at < len; d += 2)
		at += (size_t)snprintf(buf + at, len - at, "%s%d", d > 1 ? "," :
		    "", d);
}

/* A colour table's entries, a class to itself or to itself odd. */
static void
table_lines(FILE *fp, const char *set, const char *name, int colour)
{
	int	d;

	fprintf(fp, "set %s table %s create type number valtype dscp\n", set,
	    name);
	fprintf(fp, "set %s table %s atomic add", set, name);
	for (d = 0; d < 64; d += 2)
		fprintf(fp, " %d %d", d, d + colour);
	fprintf(fp, "\n");
}

/*
 * The colour tables of v into fp, ipfw's own lines in set set, filled as
 * now's block says (v's colour set to it).
 */
void
altmark_tables(FILE *fp, const char *set, struct am_service *v, int n)
{
	char	tbl[32], alt[40];
	int64_t	t;
	int	i;

	if (n == 0)
		return;
	t = now_ms();
	table_lines(fp, set, AM_EVEN, 0);
	for (i = 0; i < n; i++) {
		v[i].colour = (int)((t / ((int64_t)v[i].period * 1000)) & 1);
		snprintf(tbl, sizeof(tbl), AM_TABLE "%d", i);
		snprintf(alt, sizeof(alt), "%s_alt", tbl);
		table_lines(fp, set, tbl, v[i].colour);
		table_lines(fp, set, alt, !v[i].colour);
	}
}

/*
 * The rules of the way out of each tunnel, first (AM_RULE_IN): what came
 * out of it counted by colour, then the colour cleared.  How many.  The
 * comments are 80 at most: the id as it fits.
 */
int
altmark_rules_in(FILE *fp, const char *set, const struct am_service *v,
    int n)
{
	char	even[160], odd[160];
	int	i, j, nr;

	dscp_list(even, sizeof(even), 0);
	dscp_list(odd, sizeof(odd), 1);
	nr = 0;
	for (i = 0; i < n; i++)
		for (j = 0; j < v[i].ntun; j++) {
			const struct am_tunnel *u = &v[i].tun[j];

			fprintf(fp, "add %d set %s count ip from any to any in "
			    "recv %s dscp %s // am %d.%d in 0 %.50s\n",
			    AM_RULE_IN, set, u->ifname, even, i, j, u->id);
			fprintf(fp, "add %d set %s count ip from any to any in "
			    "recv %s dscp %s // am %d.%d in 1 %.50s\n",
			    AM_RULE_IN, set, u->ifname, odd, i, j, u->id);
			fprintf(fp, "add %d set %s setdscp tablearg ip from any "
			    "to any in recv %s lookup dscp:0x3e %s // am %d.%d "
			    "unmark %.50s\n", AM_RULE_IN, set, u->ifname, AM_EVEN,
			    i, j, u->id);
			nr += 3;
		}
	return (nr);
}

/* The match of tunnel u's outer packets to its far end, by its kind;
 * NULL where the kind is not said. */
static const char *
outer_match(const struct am_tunnel *u, char *buf, size_t len)
{
	const char	*esp = u->ipsec ? " or proto esp" : "";

	if (strcmp(u->kind, "gre") == 0)
		snprintf(buf, len, "ip from any to %s out { proto gre%s }",
		    u->outer, esp);
	else if (strcmp(u->kind, "gif") == 0)
		snprintf(buf, len, "ip from any to %s out { proto ipencap or "
		    "proto ipv6%s }", u->outer, esp);
	else if ((strcmp(u->kind, "wg") == 0 || strcmp(u->kind, "geneve") ==
	    0) && u->port > 0 && !u->ipsec)
		snprintf(buf, len, "udp from any to %s dst-port %d out",
		    u->outer, u->port);
	else if ((strcmp(u->kind, "wg") == 0 || strcmp(u->kind, "geneve") ==
	    0) && u->ipsec)
		snprintf(buf, len, "ip from any to %s out proto esp", u->outer);
	else
		return (NULL);
	return (buf);
}

/*
 * The rules of the way into each tunnel, last (AM_RULE_OUT): the colour,
 * what went in counted by colour, and the colour cleared on the outer
 * header of the tunnel's own packets.  How many.
 */
int
altmark_rules_out(FILE *fp, const char *set, const struct am_service *v,
    int n)
{
	char	even[160], odd[160], tbl[32], om[160];
	int	i, j, nr;

	dscp_list(even, sizeof(even), 0);
	dscp_list(odd, sizeof(odd), 1);
	nr = 0;
	for (i = 0; i < n; i++) {
		snprintf(tbl, sizeof(tbl), AM_TABLE "%d", i);
		for (j = 0; j < v[i].ntun; j++) {
			const struct am_tunnel *u = &v[i].tun[j];

			fprintf(fp, "add %d set %s setdscp tablearg ip from any "
			    "to any out xmit %s lookup dscp:0x3e %s // am %d.%d "
			    "mark %.50s\n", AM_RULE_OUT, set, u->ifname, tbl, i, j,
			    u->id);
			fprintf(fp, "add %d set %s count ip from any to any out "
			    "xmit %s dscp %s // am %d.%d out 0 %.50s\n",
			    AM_RULE_OUT, set, u->ifname, even, i, j, u->id);
			fprintf(fp, "add %d set %s count ip from any to any out "
			    "xmit %s dscp %s // am %d.%d out 1 %.50s\n",
			    AM_RULE_OUT, set, u->ifname, odd, i, j, u->id);
			nr += 3;
			if (u->outer[0] != '\0' && outer_match(u, om, sizeof(om))
			    != NULL) {
				fprintf(fp, "add %d set %s setdscp tablearg %s "
				    "lookup dscp:0x3e %s // am %d.%d outer %.50s\n",
				    AM_RULE_OUT, set, om, AM_EVEN, i, j, u->id);
				nr++;
			}
		}
	}
	return (nr);
}

/*
 * Whether the colour goes before the console's rule line ("number
 * words"): the first rule of the way out, AM_RULE_OUT, that does more
 * than count, mark or set a FIB (a dummynet queue or pipe, the skip to
 * the way out, a verdict), or the first of a later number.
 */
bool
altmark_marks_before(const char *line)
{
	static const char *const go_on[] = { "count", "setdscp", "setfib",
	    "tcp-setmss", "tag", "untag", "setmark" };
	const char	*w;
	size_t		 i, n;
	long		 num;

	num = strtol(line, NULL, 10);
	if (num > AM_RULE_OUT)
		return (true);
	if (num < AM_RULE_OUT)
		return (false);
	w = line + strspn(line, "0123456789 ");
	n = strcspn(w, " ");
	for (i = 0; i < nitems(go_on); i++)
		if (strlen(go_on[i]) == n && strncmp(w, go_on[i], n) == 0)
			return (false);
	return (true);
}

/* ---- ipfw's socket option ------------------------------------------------ */

/* The edge's ipfw socket: the host's, or one made in the jail's network. */
static int
edge_fd(struct amedge *e)
{
	int	jid;

	if (e->fd != -1)
		return (e->fd);
	if (e->jail[0] == '\0')
		e->fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	else if ((jid = jail_getid(e->jail)) > 0)
		e->fd = helper_ipfw_socket(jid);
	else
		errno = ENOENT;
	return (e->fd);
}

static void
edge_fail(struct amedge *e, const char *what)
{

	if (!e->failing)
		logmsg(LOG_WARNING, "alternate marking%s%s: %s: %s",
		    e->jail[0] != '\0' ? " of " : "", e->jail, what,
		    strerror(errno));
	e->failing = true;
	if (e->fd != -1) {
		close(e->fd);
		e->fd = -1;
	}
}

/* The colour table and its other swapped: one atomic switch. */
static int
table_swap(struct amedge *e, int k)
{
	char			 buf[sizeof(ipfw_obj_header) +
				     sizeof(ipfw_obj_ntlv)];
	ipfw_obj_header		*oh = (ipfw_obj_header *)(void *)buf;
	ipfw_obj_ntlv		*second = (ipfw_obj_ntlv *)(oh + 1);
	int			 fd;

	if ((fd = edge_fd(e)) == -1)
		return (-1);
	memset(buf, 0, sizeof(buf));
	oh->opheader.opcode = IP_FW_TABLE_XSWAP;
	oh->opheader.version = IP_FW3_OPVER;
	oh->idx = 1;
	oh->ntlv.head.type = IPFW_TLV_TBL_NAME;
	oh->ntlv.head.length = sizeof(oh->ntlv);
	oh->ntlv.idx = 1;
	oh->ntlv.set = (uint8_t)e->set;
	snprintf(oh->ntlv.name, sizeof(oh->ntlv.name), AM_TABLE "%d", k);
	second->head.type = IPFW_TLV_TBL_NAME;
	second->head.length = sizeof(*second);
	second->idx = 1;
	second->set = (uint8_t)e->set;
	snprintf(second->name, sizeof(second->name), AM_TABLE "%d_alt", k);
	return (setsockopt(fd, IPPROTO_IP, IP_FW3, buf, sizeof(buf)));
}

/* The comment of a rule, its O_NOP's text; NULL none. */
static const char *
rule_comment(const struct ip_fw_rule *r, size_t room)
{
	const ipfw_insn	*cmd;
	size_t		 at, l;

	for (at = 0; at < r->act_ofs && at < r->cmd_len; at += l) {
		cmd = &r->cmd[at];
		if ((l = F_LEN(cmd)) == 0)
			break;
		if (cmd->opcode == O_NOP && l > 1 && (at + l) * sizeof(*cmd) <=
		    room && memchr(cmd + 1, '\0', (l - 1) * sizeof(*cmd)) !=
		    NULL)
			return ((const char *)(cmd + 1));
	}
	return (NULL);
}

/*
 * Service k's counters of the colour, each tunnel's [out p, out b, in
 * p, in b], from the set's rules AM_RULE_IN to AM_RULE_OUT with their
 * counters (IP_FW_XGET).  The tunnels whose rules were seen marked in
 * seen.  0, or -1.
 */
static int
counters_read(struct amedge *e, int k, int colour, uint64_t (*c)[4],
    bool *seen, int ntun)
{
	ipfw_cfg_lheader	*cfg;
	ipfw_obj_ctlv		*ctlv;
	ipfw_obj_tlv		*tlv;
	struct ip_fw_bcounter	*cnt;
	struct ip_fw_rule	*r;
	const char		*cm;
	char			 dir[8], *end;
	socklen_t		 sz;
	size_t			 at, room;
	uint32_t		 i;
	int			 fd, sk, tj, col, tries;

	if ((fd = edge_fd(e)) == -1)
		return (-1);
	sz = 16384;
	cfg = NULL;
	for (tries = 0; tries < 8; tries++) {
		free(cfg);
		if ((cfg = calloc(1, sz)) == NULL)
			return (-1);
		cfg->opheader.opcode = IP_FW_XGET;
		cfg->opheader.version = IP_FW3_OPVER;
		cfg->flags = IPFW_CFG_GET_STATIC | IPFW_CFG_GET_COUNTERS;
		cfg->start_rule = AM_RULE_IN;
		cfg->end_rule = AM_RULE_OUT;
		if (getsockopt(fd, IPPROTO_IP, IP_FW3, cfg, &sz) == 0)
			break;
		if (errno != ENOMEM) {
			free(cfg);
			return (-1);
		}
		sz = cfg->size > sz * 2 ? cfg->size : sz * 2;
	}
	if (tries == 8) {
		free(cfg);
		errno = ENOMEM;
		return (-1);
	}
	memset(c, 0, sizeof(*c) * (size_t)ntun);
	memset(seen, 0, sizeof(*seen) * (size_t)ntun);
	at = sizeof(*cfg);
	ctlv = (ipfw_obj_ctlv *)(void *)((char *)cfg + at);
	if (at + sizeof(*ctlv) <= sz && ctlv->head.type ==
	    IPFW_TLV_TBLNAME_LIST) {
		at += ctlv->head.length;
		ctlv = (ipfw_obj_ctlv *)(void *)((char *)cfg + at);
	}
	if (at + sizeof(*ctlv) > sz || ctlv->head.type != IPFW_TLV_RULE_LIST) {
		free(cfg);
		return (0);
	}
	at += sizeof(*ctlv);
	for (i = 0; i < ctlv->count && at + sizeof(*tlv) <= sz; i++,
	    at += tlv->length) {
		tlv = (ipfw_obj_tlv *)(void *)((char *)cfg + at);
		if (tlv->length < sizeof(*tlv) + sizeof(*cnt) + sizeof(*r) ||
		    at + tlv->length > sz)
			break;
		cnt = (struct ip_fw_bcounter *)(void *)(tlv + 1);
		if (cnt->size < sizeof(*cnt) || sizeof(*tlv) + cnt->size +
		    sizeof(*r) > tlv->length)
			break;
		r = (struct ip_fw_rule *)(void *)((char *)cnt + cnt->size);
		room = tlv->length - sizeof(*tlv) - cnt->size -
		    offsetof(struct ip_fw_rule, cmd);
		if ((r->rulenum != AM_RULE_IN && r->rulenum != AM_RULE_OUT) ||
		    r->set != e->set || (cm = rule_comment(r, room)) == NULL ||
		    strncmp(cm, "am ", 3) != 0)
			continue;
		/* "am K.J out|in C id" */
		sk = (int)strtol(cm + 3, &end, 10);
		if (sk != k || *end != '.')
			continue;
		tj = (int)strtol(end + 1, &end, 10);
		if (tj < 0 || tj >= ntun || sscanf(end, " %7s %d", dir, &col) !=
		    2 || col != colour)
			continue;
		if (strcmp(dir, "out") == 0) {
			c[tj][0] = cnt->pcnt;
			c[tj][1] = cnt->bcnt;
		} else if (strcmp(dir, "in") == 0) {
			c[tj][2] = cnt->pcnt;
			c[tj][3] = cnt->bcnt;
		} else
			continue;
		seen[tj] = true;
	}
	free(cfg);
	return (0);
}

/* ---- The blocks ------------------------------------------------------------ */

/* The event of a service's block: its tunnels' counts, in parts that
 * fit. */
static void
block_tell(const struct amedge *e, const struct amsvc *s, int64_t n)
{
	char		 buf[AM_EVENT + 512], q[300], q2[300];
	const struct amblock *b;
	size_t		 at;
	int		 j, put;

	at = 0;
	put = 0;
	for (j = 0; j < s->ntun; j++) {
		if (s->tun[j].nb == 0)
			continue;
		b = &s->tun[j].b[(s->tun[j].first + s->tun[j].nb - 1) %
		    AM_BLOCKS];
		if (b->n != n)
			continue;
		if (put == 0)
			at = (size_t)snprintf(buf, sizeof(buf), "{\"service\":"
			    "\"%s\",\"block\":%jd,\"start\":%jd,\"period\":%d,"
			    "\"colour\":%d,\"valid\":%s,\"tunnels\":[",
			    json_quote(s->name, q, sizeof(q)), (intmax_t)n,
			    (intmax_t)(n * s->period), s->period, (int)(n & 1),
			    b->valid ? "true" : "false");
		at += (size_t)snprintf(buf + at, sizeof(buf) - at, "%s{\"id\":"
		    "\"%s\",\"interface\":\"%s\",\"out\":%ju,\"in\":%ju}", put >
		    0 ? "," : "", json_quote(s->tun[j].t.id, q, sizeof(q)),
		    json_quote(s->tun[j].t.ifname, q2, sizeof(q2)),
		    (uintmax_t)b->out_p, (uintmax_t)b->in_p);
		put++;
		if (at > AM_EVENT || j == s->ntun - 1) {
			event_add_jail(e->jail[0] != '\0' ? e->jail : NULL,
			    "sdwan-altmark", "%s]}", buf);
			put = 0;
		}
	}
	if (put > 0)
		event_add_jail(e->jail[0] != '\0' ? e->jail : NULL,
		    "sdwan-altmark", "%s]}", buf);
}

/*
 * The read in block n, at off ms into it: the colour of block n-1, each
 * tunnel's gain since that colour's last read (block n-2's) its count
 * of block n-1.
 */
static void
svc_read(struct amedge *e, int k, int64_t n, int64_t off)
{
	struct amsvc	*s = &e->svc[k];
	struct amtun	*u;
	struct amblock	*b;
	uint64_t	 (*c)[4];
	bool		*seen, valid, any;
	int64_t		 L;
	int		 colour, j, q;

	L = (int64_t)s->period * 1000;
	colour = (int)((n - 1) & 1);
	if ((c = calloc((size_t)s->ntun, sizeof(*c))) == NULL ||
	    (seen = calloc((size_t)s->ntun, sizeof(*seen))) == NULL) {
		free(c);
		return;
	}
	if (counters_read(e, k, colour, c, seen, s->ntun) != 0) {
		edge_fail(e, "IP_FW_XGET");
		free(c);
		free(seen);
		return;
	}
	e->failing = false;
	/* Read between L/4 and 3L/4 of its block, swapped into it within
	 * L/4 of its start: the guard band. */
	valid = off >= L / 4 && off <= 3 * L / 4 && s->flip_block == n &&
	    s->flip_ms <= L / 4;
	any = false;
	for (j = 0; j < s->ntun; j++) {
		u = &s->tun[j];
		if (!seen[j])
			continue;
		if (u->based[colour] == n - 2 && c[j][0] >= u->base[colour][0] &&
		    c[j][2] >= u->base[colour][2]) {
			if (u->nb == AM_BLOCKS) {
				u->first = (u->first + 1) % AM_BLOCKS;
				u->nb--;
			}
			b = &u->b[(u->first + u->nb) % AM_BLOCKS];
			u->nb++;
			b->n = n - 1;
			b->out_p = c[j][0] - u->base[colour][0];
			b->out_b = c[j][1] - u->base[colour][1];
			b->in_p = c[j][2] - u->base[colour][2];
			b->in_b = c[j][3] - u->base[colour][3];
			b->read_ms = (int32_t)off;
			b->flip_ms = s->flip_block == n ? s->flip_ms : -1;
			b->valid = valid;
			any = true;
		}
		for (q = 0; q < 4; q++)
			u->base[colour][q] = c[j][q];
		u->based[colour] = n;
	}
	free(c);
	free(seen);
	if (any)
		block_tell(e, s, n - 1);
}

/* What is due now, done; when the next is due, ms. */
static int64_t
due(void)
{
	struct amedge	*e;
	struct amsvc	*s;
	int64_t		 t, L, n, off, next, at;
	int		 i, k, want;

	t = now_ms();
	next = t + 60000;
	for (i = 0; i < am_nedges; i++) {
		e = am_edges[i];
		for (k = 0; k < e->nsvc; k++) {
			s = &e->svc[k];
			L = (int64_t)s->period * 1000;
			n = t / L;
			off = t % L;
			want = (int)(n & 1);
			if (s->colour != want) {
				if (table_swap(e, k) == 0) {
					s->colour = want;
					s->flip_block = n;
					s->flip_ms = (int32_t)off;
					e->failing = false;
				} else
					edge_fail(e, "IP_FW_TABLE_XSWAP");
			}
			if (off >= L / 2 && s->read_block != n) {
				svc_read(e, k, n, off);
				s->read_block = n;
			}
			at = s->read_block != n ? n * L + L / 2 : (n + 1) * L;
			if (at < next)
				next = at;
		}
	}
	return (next);
}

static void *
am_thread(void *arg)
{
	struct timespec	ts;
	int64_t		next;

	(void)arg;
	pthread_mutex_lock(&am_lock);
	for (;;) {
		next = due();
		ts.tv_sec = (time_t)(next / 1000);
		ts.tv_nsec = (long)(next % 1000) * 1000000;
		(void)pthread_cond_timedwait(&am_cond, &am_lock, &ts);
	}
	/* NOTREACHED */
	return (NULL);
}

/*
 * The services jail's edge measures from now: v (n of them, their
 * colour as altmark_load() filled the tables) in ipfw set set; none
 * stops it.  What a tunnel kept goes with it unless it is measured
 * again, by the same service and id.
 */
void
altmark_set(const char *jail, int set, const struct am_service *v, int n)
{
	struct amedge	*e, *old;
	struct amsvc	*s;
	struct amtun	*u;
	pthread_t	 tid;
	int64_t		 t, L, b0;
	int		 i, k, j, oj, ok;

	if (jail == NULL)
		jail = "";
	pthread_mutex_lock(&am_lock);
	old = NULL;
	for (i = 0; i < am_nedges; i++)
		if (strcmp(am_edges[i]->jail, jail) == 0) {
			old = am_edges[i];
			am_edges[i] = am_edges[--am_nedges];
			break;
		}
	e = NULL;
	if (n > 0 && am_nedges < AM_EDGES && (e = calloc(1, sizeof(*e))) !=
	    NULL) {
		snprintf(e->jail, sizeof(e->jail), "%s", jail);
		e->set = set;
		e->fd = -1;
		t = now_ms();
		for (k = 0; k < n && k < AM_SERVICES; k++) {
			s = &e->svc[k];
			snprintf(s->name, sizeof(s->name), "%s", v[k].name);
			s->period = v[k].period;
			s->colour = v[k].colour;
			L = (int64_t)s->period * 1000;
			b0 = t / L;
			s->read_block = INT64_MIN;
			s->flip_block = INT64_MIN;
			if ((s->tun = calloc((size_t)v[k].ntun, sizeof(*u))) ==
			    NULL)
				break;
			s->ntun = v[k].ntun;
			for (j = 0; j < s->ntun; j++) {
				u = &s->tun[j];
				u->t = v[k].tun[j];
				/* The counters begin at 0 now: the colour
				 * before this block's has no packet yet, its
				 * next block (b0 + 1) whole from 0. */
				u->based[(b0 - 1) & 1] = b0;
				u->based[b0 & 1] = INT64_MIN;
				/* The blocks kept of the tunnel before. */
				for (oj = 0, ok = -1; old != NULL && ok < 0 &&
				    oj < AM_SERVICES; oj++)
					for (int l = 0; l < old->svc[oj].ntun;
					    l++)
						if (strcmp(old->svc[oj].name,
						    s->name) == 0 && strcmp(
						    old->svc[oj].tun[l].t.id,
						    u->t.id) == 0) {
							memcpy(u->b,
							    old->svc[oj].tun[l].b,
							    sizeof(u->b));
							u->first =
							    old->svc[oj].tun[l].first;
							u->nb =
							    old->svc[oj].tun[l].nb;
							ok = l;
							break;
						}
			}
			e->nsvc++;
		}
		am_edges[am_nedges++] = e;
	}
	if (old != NULL) {
		if (old->fd != -1)
			close(old->fd);
		for (k = 0; k < old->nsvc; k++)
			free(old->svc[k].tun);
		free(old);
	}
	if (am_nedges > 0 && !am_running) {
		if (pthread_create(&tid, NULL, am_thread, NULL) == 0) {
			(void)pthread_detach(tid);
			am_running = true;
		}
	}
	pthread_cond_signal(&am_cond);
	pthread_mutex_unlock(&am_lock);
}

/* jail's edge's tunnels as measured, each its last blocks, for the sdwan
 * read: an array, empty where none is. */
ucl_object_t *
altmark_json(const char *jail)
{
	const struct amedge	*e;
	const struct amsvc	*s;
	const struct amtun	*u;
	const struct amblock	*b;
	ucl_object_t		*arr, *o, *bs, *bo;
	int64_t			 t;
	int			 i, k, j, q;

	if (jail == NULL)
		jail = "";
	arr = ucl_object_typed_new(UCL_ARRAY);
	pthread_mutex_lock(&am_lock);
	t = now_ms();
	for (i = 0; i < am_nedges; i++) {
		e = am_edges[i];
		if (strcmp(e->jail, jail) != 0)
			continue;
		for (k = 0; k < e->nsvc; k++) {
			s = &e->svc[k];
			for (j = 0; j < s->ntun; j++) {
				u = &s->tun[j];
				o = ucl_object_typed_new(UCL_OBJECT);
				ucl_object_insert_key(o, ucl_object_fromstring(
				    u->t.id), "tunnel", 0, true);
				ucl_object_insert_key(o, ucl_object_fromstring(
				    s->name), "service", 0, true);
				ucl_object_insert_key(o, ucl_object_fromstring(
				    u->t.ifname), "interface", 0, true);
				ucl_object_insert_key(o, ucl_object_fromint(
				    s->period), "period", 0, true);
				ucl_object_insert_key(o, ucl_object_fromint(
				    s->colour), "colour", 0, true);
				ucl_object_insert_key(o, ucl_object_fromint(t /
				    ((int64_t)s->period * 1000)), "block", 0,
				    true);
				bs = ucl_object_typed_new(UCL_ARRAY);
				for (q = 0; q < u->nb; q++) {
					b = &u->b[(u->first + q) % AM_BLOCKS];
					bo = ucl_object_typed_new(UCL_OBJECT);
					ucl_object_insert_key(bo,
					    ucl_object_fromint(b->n), "block", 0,
					    true);
					ucl_object_insert_key(bo,
					    ucl_object_fromint(b->n * s->period),
					    "start", 0, true);
					ucl_object_insert_key(bo,
					    ucl_object_fromint((int)(b->n & 1)),
					    "colour", 0, true);
					ucl_object_insert_key(bo,
					    ucl_object_fromint((int64_t)b->out_p),
					    "out_packets", 0, true);
					ucl_object_insert_key(bo,
					    ucl_object_fromint((int64_t)b->out_b),
					    "out_bytes", 0, true);
					ucl_object_insert_key(bo,
					    ucl_object_fromint((int64_t)b->in_p),
					    "in_packets", 0, true);
					ucl_object_insert_key(bo,
					    ucl_object_fromint((int64_t)b->in_b),
					    "in_bytes", 0, true);
					ucl_object_insert_key(bo,
					    ucl_object_fromint(b->read_ms),
					    "read_ms", 0, true);
					if (b->flip_ms >= 0)
						ucl_object_insert_key(bo,
						    ucl_object_fromint(b->flip_ms),
						    "flip_ms", 0, true);
					ucl_object_insert_key(bo,
					    ucl_object_frombool(b->valid),
					    "valid", 0, true);
					ucl_array_append(bs, bo);
				}
				ucl_object_insert_key(o, bs, "blocks", 0, true);
				ucl_array_append(arr, o);
			}
		}
	}
	pthread_mutex_unlock(&am_lock);
	return (arr);
}
