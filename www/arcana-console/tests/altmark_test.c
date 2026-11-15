/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Alternate marking's loss and clusters (amclust.c, PLAN-SDN-YANG
 * 5.5.3): RFC 9342 §5.1's partition of Appendix A's monitoring network,
 * four clusters as the RFC has them; and the view of three edges'
 * blocks, each tunnel's each way paired by block number, the loss on
 * one tunnel found in its cluster alone, a measurement point two
 * tunnels share counted once and their links one cluster.
 */

#include <atf-c.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ucl.h>

#include "../amclust.h"

static ucl_object_t *
parse(const char *json)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	p = ucl_parser_new(0);
	ATF_REQUIRE(ucl_parser_add_string(p, json, 0));
	o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	ATF_REQUIRE(o != NULL);
	return (o);
}

ATF_TC_WITHOUT_HEAD(appendix_a);
ATF_TC_BODY(appendix_a, tc)
{
	/* Figure 4's links, left to right, as Appendix A lists them. */
	static const char *const from[] = { "R1", "R1", "R1", "R2", "R2",
	    "R3", "R3", "R4", "R4", "R5" };
	static const char *const to[] = { "R2", "R3", "R10", "R4", "R5",
	    "R5", "R9", "R6", "R7", "R8" };
	/* Cluster 1: R1's; 2: R2's and R3's (R5 in common); 3: R4's; 4:
	 * R5-R8. */
	static const int want[] = { 0, 0, 0, 1, 1, 1, 1, 2, 2, 3 };
	int	cl[10], n;

	n = am_partition(10, from, to, cl);
	ATF_REQUIRE_EQ(n, 4);
	for (int i = 0; i < 10; i++)
		ATF_CHECK_EQ_MSG(cl[i], want[i], "%s-%s: cluster %d, not %d",
		    from[i], to[i], cl[i] + 1, want[i] + 1);
	/* Whatever the order of the links: the same partition. */
	{
		static const char *const rf[] = { "R5", "R4", "R4", "R3", "R3",
		    "R2", "R2", "R1", "R1", "R1" };
		static const char *const rt[] = { "R8", "R7", "R6", "R9", "R5",
		    "R5", "R4", "R10", "R3", "R2" };

		n = am_partition(10, rf, rt, cl);
		ATF_REQUIRE_EQ(n, 4);
		ATF_CHECK(cl[1] == cl[2] && cl[3] == cl[4] && cl[4] == cl[5] &&
		    cl[5] == cl[6] && cl[7] == cl[8] && cl[8] == cl[9]);
		ATF_CHECK(cl[0] != cl[1] && cl[0] != cl[3] && cl[0] != cl[7] &&
		    cl[1] != cl[3] && cl[1] != cl[7] && cl[3] != cl[7]);
	}
	ATF_CHECK_EQ(am_partition(0, NULL, NULL, cl), 0);
}

/* Edge e's record of tunnel id over ifname, its blocks n0.. of the
 * counts given (out, in a pair each). */
static void
record(char *buf, size_t len, const char *id, const char *ifname,
    int n0, int nb, const int (*c)[2])
{
	size_t	at;

	at = (size_t)snprintf(buf, len, "{\"tunnel\":\"%s\",\"interface\":"
	    "\"%s\",\"period\":10,\"blocks\":[", id, ifname);
	for (int i = 0; i < nb; i++)
		at += (size_t)snprintf(buf + at, len - at, "%s{\"block\":%d,"
		    "\"start\":%d,\"out\":%d,\"in\":%d,\"valid\":true}", i > 0 ?
		    "," : "", n0 + i, (n0 + i) * 10, c[i][0], c[i][1]);
	snprintf(buf + at, len - at, "]}");
}

static const ucl_object_t *
find(const ucl_object_t *arr, const char *k1, const char *v1, const char *k2,
    const char *v2)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it = NULL;

	while ((o = ucl_object_iterate(arr, &it, true)) != NULL)
		if (strcmp(ucl_object_tostring(ucl_object_lookup(o, k1)), v1) ==
		    0 && (k2 == NULL || strcmp(ucl_object_tostring(
		    ucl_object_lookup(o, k2)), v2) == 0))
			return (o);
	return (NULL);
}

static int64_t
inum(const ucl_object_t *o, const char *key)
{

	return (ucl_object_toint(ucl_object_lookup(o, key)));
}

ATF_TC_WITHOUT_HEAD(three_edges);
ATF_TC_BODY(three_edges, tc)
{
	/* Three edges, a tunnel each pair, gre each end; 3 of 100 lost
	 * from a to b in block 101, nothing else lost.  b's blocks begin
	 * one later than a's: the pairs are by number. */
	static const int ab_a[][2] = { { 100, 0 }, { 100, 0 }, { 50, 0 } };
	static const int ab_b[][2] = { { 0, 97 }, { 0, 50 }, { 0, 0 } };
	static const int z3[][2] = { { 0, 0 }, { 0, 0 }, { 0, 0 } };
	static const int ac[][2] = { { 20, 30 }, { 20, 30 }, { 20, 30 } };
	static const int ca[][2] = { { 30, 20 }, { 30, 20 }, { 30, 20 } };
	char		 s[8][512], json[8192];
	ucl_object_t	*tuns, *states, *v;
	const ucl_object_t *l, *b, *c, *bl;
	ucl_object_iter_t it;
	int		 nc;

	tuns = parse("[{\"id\":\"sw1/a-b\",\"swvc\":\"sw1\",\"ends\":["
	    "{\"edge\":\"a\",\"ifname\":\"gre100\",\"name\":\"edge-a\"},"
	    "{\"edge\":\"b\",\"ifname\":\"gre101\"}]},"
	    "{\"id\":\"sw1/a-c\",\"swvc\":\"sw1\",\"ends\":["
	    "{\"edge\":\"a\",\"ifname\":\"gre102\"},"
	    "{\"edge\":\"c\",\"ifname\":\"gre103\"}]},"
	    "{\"id\":\"sw1/b-c\",\"swvc\":\"sw1\",\"ends\":["
	    "{\"edge\":\"b\",\"ifname\":\"gre104\"},"
	    "{\"edge\":\"c\",\"ifname\":\"gre105\"}]},"
	    "{\"id\":\"sw1/a-b/ctvc\",\"swvc\":\"sw1\",\"control\":true,"
	    "\"ends\":[{\"edge\":\"a\",\"ifname\":\"gre106\"},"
	    "{\"edge\":\"b\",\"ifname\":\"gre107\"}]}]");
	record(s[0], sizeof(s[0]), "sw1/a-b", "gre100", 100, 3, ab_a);
	record(s[1], sizeof(s[1]), "sw1/a-b", "gre101", 101, 3, ab_b);
	record(s[2], sizeof(s[2]), "sw1/a-c", "gre102", 100, 3, ac);
	record(s[3], sizeof(s[3]), "sw1/a-c", "gre103", 100, 3, ca);
	record(s[4], sizeof(s[4]), "sw1/b-c", "gre104", 100, 3, z3);
	record(s[5], sizeof(s[5]), "sw1/b-c", "gre105", 100, 3, z3);
	snprintf(json, sizeof(json), "{\"a\":[%s,%s],\"b\":[%s,%s],\"c\":"
	    "[%s,%s]}", s[0], s[2], s[1], s[4], s[3], s[5]);
	states = parse(json);
	v = am_view(tuns, states);
	/* Six links: each tunnel each way; none of the control tunnel. */
	ATF_REQUIRE_EQ(ucl_array_size(ucl_object_lookup(v, "links")), 6);
	ATF_REQUIRE((l = find(ucl_object_lookup(v, "links"), "tunnel",
	    "sw1/a-b", "from", "a")) != NULL);
	ATF_CHECK_STREQ(ucl_object_tostring(ucl_object_lookup(l, "from_name")),
	    "edge-a");
	ATF_CHECK_EQ(inum(l, "period"), 10);
	/* a's blocks 101 and 102 have b's: 100 in, 97 out; 50, 50. */
	bl = ucl_object_lookup(l, "blocks");
	ATF_REQUIRE_EQ(ucl_array_size(bl), 2);
	b = ucl_array_find_index(bl, 0);
	ATF_CHECK_EQ(inum(b, "block"), 101);
	ATF_CHECK_EQ(inum(b, "start"), 1010);
	ATF_CHECK_EQ(inum(b, "out"), 100);
	ATF_CHECK_EQ(inum(b, "in"), 97);
	ATF_CHECK_EQ(inum(b, "lost"), 3);
	ATF_CHECK(ucl_object_todouble(ucl_object_lookup(b, "loss")) > 2.99 &&
	    ucl_object_todouble(ucl_object_lookup(b, "loss")) < 3.01);
	ATF_CHECK(ucl_object_toboolean(ucl_object_lookup(b, "valid")));
	b = ucl_array_find_index(bl, 1);
	ATF_CHECK_EQ(inum(b, "block"), 102);
	ATF_CHECK_EQ(inum(b, "lost"), 0);
	/* The way back, and the other tunnels: nothing lost. */
	it = NULL;
	while ((l = ucl_object_iterate(ucl_object_lookup(v, "links"), &it,
	    true)) != NULL) {
		const ucl_object_t	*x;
		ucl_object_iter_t	 bit = NULL;

		if (strcmp(ucl_object_tostring(ucl_object_lookup(l, "tunnel")),
		    "sw1/a-b") == 0 && strcmp(ucl_object_tostring(
		    ucl_object_lookup(l, "from")), "a") == 0)
			continue;
		while ((x = ucl_object_iterate(ucl_object_lookup(l, "blocks"),
		    &bit, true)) != NULL)
			ATF_CHECK_EQ(inum(x, "lost"), 0);
	}
	/* The clusters: a tunnel interface each end, so one each way of
	 * each tunnel, six; the loss is a to b's alone. */
	c = ucl_object_lookup(v, "clusters");
	ATF_REQUIRE_EQ(ucl_array_size(c), 6);
	it = NULL;
	nc = 0;
	while ((l = ucl_object_iterate(c, &it, true)) != NULL) {
		const ucl_object_t *lk = ucl_array_find_index(ucl_object_lookup(l,
		    "links"), 0);

		ATF_CHECK_EQ(ucl_array_size(ucl_object_lookup(l, "links")), 1);
		ATF_CHECK_EQ(inum(l, "cluster"), ++nc);
		if (strcmp(ucl_object_tostring(ucl_object_lookup(lk, "tunnel")),
		    "sw1/a-b") == 0 && strcmp(ucl_object_tostring(
		    ucl_object_lookup(lk, "from")), "a") == 0) {
			ATF_CHECK_STREQ(ucl_object_tostring(ucl_array_find_index(
			    ucl_object_lookup(l, "inputs"), 0)), "a gre100 in");
			ATF_CHECK_STREQ(ucl_object_tostring(ucl_array_find_index(
			    ucl_object_lookup(l, "outputs"), 0)), "b gre101 out");
			ATF_CHECK_EQ(inum(l, "block"), 102);
			ATF_CHECK_EQ(inum(l, "lost"), 0);
			ATF_CHECK_EQ(inum(l, "blocks"), 2);
			ATF_CHECK_EQ(inum(l, "lost_total"), 3);
			ATF_CHECK_EQ(inum(l, "out_total"), 150);
		} else
			ATF_CHECK_EQ(inum(l, "lost_total"), 0);
	}
	ucl_object_unref(v);
	ucl_object_unref(states);
	ucl_object_unref(tuns);
}

ATF_TC_WITHOUT_HEAD(shared_point);
ATF_TC_BODY(shared_point, tc)
{
	/* Two tunnels from a over one interface (a wg(4) of two peers):
	 * one input node, counted once; their links one cluster, whose
	 * loss is known, not which link's. */
	static const int out[][2] = { { 100, 0 } };
	static const int inb[][2] = { { 0, 60 } };
	static const int inc[][2] = { { 0, 38 } };
	char		 s[4][512], json[4096];
	ucl_object_t	*tuns, *states, *v;
	const ucl_object_t *c, *cl;

	tuns = parse("[{\"id\":\"t1\",\"swvc\":\"s\",\"ends\":["
	    "{\"edge\":\"a\",\"ifname\":\"wg0\"},{\"edge\":\"b\","
	    "\"ifname\":\"wg0\"}]},{\"id\":\"t2\",\"swvc\":\"s\",\"ends\":["
	    "{\"edge\":\"a\",\"ifname\":\"wg0\"},{\"edge\":\"c\","
	    "\"ifname\":\"wg0\"}]}]");
	record(s[0], sizeof(s[0]), "t1", "wg0", 5, 1, out);
	record(s[1], sizeof(s[1]), "t2", "wg0", 5, 1, out);
	record(s[2], sizeof(s[2]), "t1", "wg0", 5, 1, inb);
	record(s[3], sizeof(s[3]), "t2", "wg0", 5, 1, inc);
	snprintf(json, sizeof(json), "{\"a\":[%s,%s],\"b\":[%s],\"c\":[%s]}",
	    s[0], s[1], s[2], s[3]);
	states = parse(json);
	v = am_view(tuns, states);
	c = ucl_object_lookup(v, "clusters");
	/* a to b and a to c share a's node: one; b to a and c to a share
	 * a's output node: one more, nothing lost. */
	ATF_REQUIRE_EQ(ucl_array_size(c), 2);
	ATF_CHECK_EQ(inum(ucl_array_find_index(c, 1), "lost"), 0);
	cl = ucl_array_find_index(c, 0);
	ATF_CHECK_EQ(ucl_array_size(ucl_object_lookup(cl, "links")), 2);
	ATF_CHECK_EQ(ucl_array_size(ucl_object_lookup(cl, "inputs")), 1);
	ATF_CHECK_EQ(ucl_array_size(ucl_object_lookup(cl, "outputs")), 2);
	ATF_CHECK_EQ(inum(cl, "out"), 100);
	ATF_CHECK_EQ(inum(cl, "in"), 98);
	ATF_CHECK_EQ(inum(cl, "lost"), 2);
	ucl_object_unref(v);
	ucl_object_unref(states);
	ucl_object_unref(tuns);
}

ATF_TC_WITHOUT_HEAD(dscp_widen);
ATF_TC_BODY(dscp_widen, tc)
{
	char	b[300];

	/* A flow's queue by DSCP after the colour: each class and its
	 * coloured neighbour, an odd one with its even one. */
	ATF_CHECK_STREQ(am_dscp_widen("ip from any to any { src-port 5060 or "
	    "dst-port 5060 } dscp 46,10 src-ip table(sw1_zp0)", b, sizeof(b)),
	    "ip from any to any { src-port 5060 or dst-port 5060 } dscp "
	    "10,11,46,47 src-ip table(sw1_zp0)");
	ATF_CHECK_STREQ(am_dscp_widen("ip from any to any dscp 1", b,
	    sizeof(b)), "ip from any to any dscp 0,1");
	ATF_CHECK_STREQ(am_dscp_widen("tcp from any to any dst-port 80", b,
	    sizeof(b)), "tcp from any to any dst-port 80");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, dscp_widen);
	ATF_TP_ADD_TC(tp, appendix_a);
	ATF_TP_ADD_TC(tp, three_edges);
	ATF_TP_ADD_TC(tp, shared_point);
	return (atf_no_error());
}
