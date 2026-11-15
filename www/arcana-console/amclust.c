/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Alternate marking's loss (RFC 9341, PLAN-SDN-YANG 5.5.3), of the
 * blocks each edge's agent counted (gula/altmark.c): ipfw's count rules
 * at both ends of each tunnel, a pair a colour, read in the middle of
 * the block after.  The block's number is the same at both ends (the
 * wall clock over the block's length), so a tunnel's way from A to B
 * lost in block n what went into it at A in block n less what came out
 * of it at B in block n.
 *
 * And the clusters of RFC 9342 §5.1, the smallest parts of the
 * monitoring network whose loss is known: its nodes the measurement
 * points (an edge's tunnel interface as the packets go in, and as they
 * come out at the far edge, two nodes, so that no node is both a source
 * and a destination), its arcs each tunnel's each way.  The links of one
 * starting node are grouped, and groups with an ending node in common
 * joined; a cluster's loss in a block is what its input nodes counted
 * less what its output nodes did.  With a tunnel interface of its own a
 * tunnel at each end, as the console makes them, every cluster is one
 * tunnel's one way: the loss is the link's (RFC 9342 Appendix A's
 * two-node cluster); a measurement point that several tunnels share
 * joins their clusters, and the loss is then the cluster's, not known
 * of one link.
 *
 * Pure: the plan's tunnels and what the edges counted in, the view out;
 * altmark.c reads them, the tests feed them (altmark_test.c).
 */

#include <sys/param.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ucl.h>

#include "amclust.h"

#define	AM_SHOWN	32	/* a link's last blocks in the view */

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	(void)ucl_object_delete_key(o, key);
	ucl_object_insert_key(o, v, key, 0, true);
}

static const char *
str(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	if ((v = ucl_object_lookup(o, key)) == NULL || ucl_object_type(v) !=
	    UCL_STRING)
		return (NULL);
	return (ucl_object_tostring(v));
}

static int64_t
num(const ucl_object_t *o, const char *key)
{

	return (ucl_object_toint(ucl_object_lookup(o, key)));
}

/* ---- RFC 9342 §5.1 ------------------------------------------------------ */

static size_t
root(size_t *up, size_t i)
{

	while (up[i] != i)
		i = up[i] = up[up[i]];
	return (i);
}

int
am_partition(size_t n, const char *const *from, const char *const *to,
    int *cluster)
{
	size_t	*up, i, k, a, b;
	int	 nc;

	if (n == 0)
		return (0);
	if ((up = calloc(n, sizeof(*up))) == NULL)
		return (-1);
	for (i = 0; i < n; i++)
		up[i] = i;
	/* Group the links of the same starting node; join the groups that
	 * have an ending node in common. */
	for (i = 0; i < n; i++)
		for (k = i + 1; k < n; k++)
			if (strcmp(from[i], from[k]) == 0 || strcmp(to[i],
			    to[k]) == 0) {
				a = root(up, i);
				b = root(up, k);
				if (a != b)
					up[a > b ? a : b] = a > b ? b : a;
			}
	/* Numbered in the order of their first link. */
	nc = 0;
	for (i = 0; i < n; i++) {
		if (root(up, i) == i)
			cluster[i] = nc++;
		else
			cluster[i] = cluster[root(up, i)];
	}
	free(up);
	return (nc);
}

/* ---- A flow's DSCP after the colour --------------------------------------- */

/*
 * A rule's words in with its "dscp" list matching each class and its
 * coloured neighbour (46: 46,47), into out: for a rule on the way into a
 * tunnel that comes after the colour (a dummynet queue or pipe, which
 * the colour must precede: no rule sees a packet again after dummynet,
 * net.inet.ip.fw.one_pass).  in as it is when it has no dscp.
 */
const char *
am_dscp_widen(const char *in, char *out, size_t len)
{
	const char	*p, *q;
	char		 list[400];
	uint64_t	 set;
	size_t		 at;
	long		 v;
	char		*end;
	int		 d;

	if ((p = strstr(in, " dscp ")) == NULL) {
		snprintf(out, len, "%s", in);
		return (out);
	}
	p += 6;
	set = 0;
	for (q = p; *q >= '0' && *q <= '9'; ) {
		v = strtol(q, &end, 10);
		if (v >= 0 && v < 64)
			set |= (uint64_t)3 << (v & ~1L);
		q = end;
		if (*q != ',')
			break;
		q++;
	}
	if (q == p) {
		snprintf(out, len, "%s", in);
		return (out);
	}
	list[0] = '\0';
	at = 0;
	for (d = 0; d < 64 && at < sizeof(list); d++)
		if ((set & ((uint64_t)1 << d)) != 0)
			at += (size_t)snprintf(list + at, sizeof(list) - at,
			    "%s%d", at > 0 ? "," : "", d);
	snprintf(out, len, "%.*s%s%s", (int)(p - in), in, list, q);
	return (out);
}

/* ---- The view ----------------------------------------------------------- */

/* Edge's record of tunnel id, NULL none. */
static const ucl_object_t *
record_of(const ucl_object_t *states, const char *edge, const char *id)
{
	const ucl_object_t	*r;
	ucl_object_iter_t	 it = NULL;

	if (edge == NULL || id == NULL)
		return (NULL);
	while ((r = ucl_object_iterate(ucl_object_lookup(states, edge), &it,
	    true)) != NULL)
		if (str(r, "tunnel") != NULL && strcmp(str(r, "tunnel"), id) ==
		    0)
			return (r);
	return (NULL);
}

/* Record r's block n, NULL none. */
static const ucl_object_t *
block_of(const ucl_object_t *r, int64_t n)
{
	const ucl_object_t	*b;
	ucl_object_iter_t	 it = NULL;

	while ((b = ucl_object_iterate(ucl_object_lookup(r, "blocks"), &it,
	    true)) != NULL)
		if (num(b, "block") == n)
			return (b);
	return (NULL);
}

static double
ratio(int64_t lost, int64_t out)
{

	return (out > 0 && lost > 0 ? (double)lost * 100.0 / (double)out :
	    0.0);
}

/* A link: a tunnel's one way, its blocks counted at both ends. */
struct amlink {
	const char		*svc, *tunnel, *from, *to;
	const ucl_object_t	*ra, *rb;	/* the from end's, the to end's */
	char			 nin[96], nout[96];	/* its input node, its output */
};

ucl_object_t *
am_view(const ucl_object_t *tuns, const ucl_object_t *states)
{
	const ucl_object_t	*t, *a, *b, *x, *ba, *bb, *r;
	ucl_object_iter_t	 it, bit;
	struct amlink		*l;
	ucl_object_t		*top, *links, *clusters, *o, *bs, *bo, *c, *arr;
	const char		**from, **to;
	int			*cl, nc, k, i, j, m, nshown;
	size_t			 nl, cap;

	top = ucl_object_typed_new(UCL_OBJECT);
	links = ucl_object_typed_new(UCL_ARRAY);
	clusters = ucl_object_typed_new(UCL_ARRAY);
	cap = 2 * (ucl_array_size(tuns) + 1);
	l = calloc(cap, sizeof(*l));
	from = calloc(cap, sizeof(*from));
	to = calloc(cap, sizeof(*to));
	cl = calloc(cap, sizeof(*cl));
	if (l == NULL || from == NULL || to == NULL || cl == NULL)
		goto out;
	nl = 0;
	it = NULL;
	while ((t = ucl_object_iterate(tuns, &it, true)) != NULL) {
		if (ucl_object_toboolean(ucl_object_lookup(t, "control")))
			continue;
		for (k = 0; k < 2 && nl < cap; k++) {
			a = ucl_array_find_index(ucl_object_lookup(t, "ends"),
			    (unsigned int)k);
			b = ucl_array_find_index(ucl_object_lookup(t, "ends"),
			    (unsigned int)!k);
			l[nl].ra = record_of(states, str(a, "edge"), str(t,
			    "id"));
			l[nl].rb = record_of(states, str(b, "edge"), str(t,
			    "id"));
			if (l[nl].ra == NULL && l[nl].rb == NULL)
				continue;
			l[nl].svc = str(t, "swvc") != NULL ? str(t, "swvc") : "";
			l[nl].tunnel = str(t, "id");
			l[nl].from = str(a, "edge");
			l[nl].to = str(b, "edge");
			snprintf(l[nl].nin, sizeof(l[nl].nin), "%s %s in",
			    l[nl].from, str(a, "ifname") != NULL ? str(a,
			    "ifname") : "?");
			snprintf(l[nl].nout, sizeof(l[nl].nout), "%s %s out",
			    l[nl].to, str(b, "ifname") != NULL ? str(b,
			    "ifname") : "?");
			o = ucl_object_typed_new(UCL_OBJECT);
			put(o, "service", ucl_object_fromstring(l[nl].svc));
			put(o, "tunnel", ucl_object_fromstring(l[nl].tunnel));
			put(o, "from", ucl_object_fromstring(l[nl].from));
			put(o, "to", ucl_object_fromstring(l[nl].to));
			if (str(a, "name") != NULL)
				put(o, "from_name", ucl_object_fromstring(str(a,
				    "name")));
			if (str(b, "name") != NULL)
				put(o, "to_name", ucl_object_fromstring(str(b,
				    "name")));
			put(o, "period", ucl_object_fromint(num(l[nl].ra !=
			    NULL ? l[nl].ra : l[nl].rb, "period")));
			/* Its blocks counted at both ends, the last shown. */
			bs = ucl_object_typed_new(UCL_ARRAY);
			nshown = 0;
			bit = NULL;
			while (l[nl].ra != NULL && l[nl].rb != NULL && (ba =
			    ucl_object_iterate(ucl_object_lookup(l[nl].ra,
			    "blocks"), &bit, true)) != NULL)
				if (block_of(l[nl].rb, num(ba, "block")) != NULL)
					nshown++;
			bit = NULL;
			while (l[nl].ra != NULL && l[nl].rb != NULL && (ba =
			    ucl_object_iterate(ucl_object_lookup(l[nl].ra,
			    "blocks"), &bit, true)) != NULL) {
				int64_t	lost;

				if ((bb = block_of(l[nl].rb, num(ba, "block"))) ==
				    NULL || nshown-- > AM_SHOWN)
					continue;
				lost = num(ba, "out") - num(bb, "in");
				bo = ucl_object_typed_new(UCL_OBJECT);
				put(bo, "block", ucl_object_fromint(num(ba,
				    "block")));
				put(bo, "start", ucl_object_fromint(num(ba,
				    "start")));
				put(bo, "out", ucl_object_fromint(num(ba, "out")));
				put(bo, "in", ucl_object_fromint(num(bb, "in")));
				put(bo, "lost", ucl_object_fromint(lost));
				put(bo, "loss", ucl_object_fromdouble(ratio(lost,
				    num(ba, "out"))));
				/* More out than in: a packet across the guard
				 * band, the clocks too far apart. */
				put(bo, "valid", ucl_object_frombool(
				    ucl_object_toboolean(ucl_object_lookup(ba,
				    "valid")) && ucl_object_toboolean(
				    ucl_object_lookup(bb, "valid")) && lost >= 0));
				ucl_array_append(bs, bo);
			}
			put(o, "blocks", bs);
			ucl_array_append(links, o);
			from[nl] = l[nl].nin;
			to[nl] = l[nl].nout;
			nl++;
		}
	}
	/* The clusters of each service's links. */
	for (i = 0; (size_t)i < nl; i++) {
		int	 cn, seen;

		if (i > 0) {
			for (j = 0; j < i; j++)
				if (strcmp(l[j].svc, l[i].svc) == 0)
					break;
			if (j < i)
				continue;	/* its service done */
		}
		{
			const char	**sf, **st;
			int		*ix, ns = 0;

			sf = calloc(nl, sizeof(*sf));
			st = calloc(nl, sizeof(*st));
			ix = calloc(nl, sizeof(*ix));
			if (sf == NULL || st == NULL || ix == NULL) {
				free(sf);
				free(st);
				free(ix);
				break;
			}
			for (j = i; (size_t)j < nl; j++)
				if (strcmp(l[j].svc, l[i].svc) == 0) {
					sf[ns] = from[j];
					st[ns] = to[j];
					ix[ns++] = j;
				}
			nc = am_partition((size_t)ns, sf, st, cl);
			for (cn = 0; cn < nc; cn++) {
				int64_t	 lastn, n, sout, sin, tout, tlost;
				int	 nb;
				bool	 all;

				c = ucl_object_typed_new(UCL_OBJECT);
				put(c, "service", ucl_object_fromstring(l[i].svc));
				put(c, "cluster", ucl_object_fromint(cn + 1));
				arr = ucl_object_typed_new(UCL_ARRAY);
				for (m = 0; m < ns; m++)
					if (cl[m] == cn) {
						o = ucl_object_typed_new(UCL_OBJECT);
						put(o, "tunnel", ucl_object_fromstring(
						    l[ix[m]].tunnel));
						put(o, "from", ucl_object_fromstring(
						    l[ix[m]].from));
						put(o, "to", ucl_object_fromstring(
						    l[ix[m]].to));
						ucl_array_append(arr, o);
					}
				put(c, "links", arr);
				/* Its input and output nodes, each once. */
				for (k = 0; k < 2; k++) {
					arr = ucl_object_typed_new(UCL_ARRAY);
					for (m = 0; m < ns; m++) {
						if (cl[m] != cn)
							continue;
						for (seen = 0, j = 0; j < m; j++)
							if (cl[j] == cn && strcmp(k ==
							    0 ? sf[j] : st[j], k == 0 ?
							    sf[m] : st[m]) == 0)
								seen = 1;
						if (!seen)
							ucl_array_append(arr,
							    ucl_object_fromstring(k ==
							    0 ? sf[m] : st[m]));
					}
					put(c, k == 0 ? "inputs" : "outputs", arr);
				}
				/* Its blocks: each that every node counted;
				 * the last's loss, and all's. */
				lastn = INT64_MIN;
				sout = sin = tout = tlost = 0;
				nb = 0;
				for (m = 0; m < ns; m++) {
					if (cl[m] != cn || l[ix[m]].ra == NULL)
						continue;
					bit = NULL;
					while ((ba = ucl_object_iterate(
					    ucl_object_lookup(l[ix[m]].ra, "blocks"),
					    &bit, true)) != NULL) {
						int64_t	 bo_, bi_;

						n = num(ba, "block");
						all = true;
						bo_ = bi_ = 0;
						for (j = 0; j < ns && all; j++) {
							if (cl[j] != cn)
								continue;
							/* A node counted once,
							 * whatever links share
							 * it. */
							for (seen = 0, k = 0; k < j;
							    k++)
								if (cl[k] == cn &&
								    strcmp(sf[k],
								    sf[j]) == 0)
									seen |= 1;
							for (k = 0; k < j; k++)
								if (cl[k] == cn &&
								    strcmp(st[k],
								    st[j]) == 0)
									seen |= 2;
							if (l[ix[j]].ra == NULL ||
							    l[ix[j]].rb == NULL ||
							    (x = block_of(
							    l[ix[j]].ra, n)) ==
							    NULL || (r = block_of(
							    l[ix[j]].rb, n)) ==
							    NULL) {
								all = false;
								break;
							}
							if (!(seen & 1))
								bo_ += num(x, "out");
							if (!(seen & 2))
								bi_ += num(r, "in");
						}
						/* Once a block, by its first
						 * link. */
						for (j = 0; j < m; j++)
							if (cl[j] == cn &&
							    l[ix[j]].ra != NULL)
								all = false;
						if (!all)
							continue;
						nb++;
						tout += bo_;
						tlost += bo_ - bi_;
						if (n > lastn) {
							lastn = n;
							sout = bo_;
							sin = bi_;
						}
					}
				}
				if (nb > 0) {
					put(c, "block", ucl_object_fromint(lastn));
					put(c, "out", ucl_object_fromint(sout));
					put(c, "in", ucl_object_fromint(sin));
					put(c, "lost", ucl_object_fromint(sout -
					    sin));
					put(c, "loss", ucl_object_fromdouble(ratio(
					    sout - sin, sout)));
					put(c, "blocks", ucl_object_fromint(nb));
					put(c, "out_total", ucl_object_fromint(
					    tout));
					put(c, "lost_total", ucl_object_fromint(
					    tlost));
					put(c, "loss_total", ucl_object_fromdouble(
					    ratio(tlost, tout)));
				}
				ucl_array_append(clusters, c);
			}
			free(sf);
			free(st);
			free(ix);
		}
	}
out:
	free(l);
	free(from);
	free(to);
	free(cl);
	put(top, "links", links);
	put(top, "clusters", clusters);
	return (top);
}
