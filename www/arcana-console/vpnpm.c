/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The services' performance view (RFC 9375's ietf-network-vpn-pm over
 * RFC 8345's networks), made at each read of the L3NM kept, the plan's
 * tunnels and what the agents' probes measured (arcana-probe's pm,
 * arcana-stamp's sessions, read through the fleet mount), beside
 * sapnet.c's networks in /restconf/data/ietf-network:networks:
 *
 *	arcana:underlay		the network itself (no service): a node
 *				each edge; a termination point each UCS
 *				End Point a tunnel leaves by; a link each
 *				way between two UCS End Points a tunnel
 *				joins (no pm yet: PLAN-SDN-YANG 5.3.3's
 *				probes)
 *	arcana:vpn:<vpn-id>	a service: network-types' service (its
 *				vpn-type, else l3vpn; its vpn-id; its
 *				vpn-service-topology), a node each
 *				vpn-node (pe, its role by its accesses'
 *				profiles) over the underlay's, a
 *				termination point each tunnel interface
 *				over its UCS End Point, and two links a
 *				tunnel, one each way, each over the
 *				underlay's link
 *
 * Every id is an inet:uri, as RFC 9911's pattern wants a scheme:
 * arcana:edge:<edge>, arcana:if:<interface>, arcana:ucs-ep:<id>,
 * arcana:tunnel:<tunnel>,<from UCS EP>,<to UCS EP> and
 * arcana:underlay:<from UCS EP>,<to UCS EP>.  The underlay is over no
 * network: sapnet.c's arcana-physical and arcana-sap, whose ids are the
 * agents' (a host's id, an interface's name), are no URIs.
 *
 * A service link's perf-mon: the percentiles and measurement interval
 * its figures were made with (the source end's target's, else the
 * service's probe settings, else Arcana's 10, 50, 90 and 60 s: RFC
 * 9375's high default is 95, Arcana's 90, so all four are said), one
 * pm entry, pm-type-vpn-tunnel, of the last completed measurement
 * interval, and vpn-tunnel's type (gre, ip-in-ip for gif, geneve;
 * arcana-network-vpn-pm's wireguard and ipsec for wg and uswe).
 *
 * How a link's pair is filled.  Each end of a tunnel has a target of
 * the tunnel's id: by STAMP, its forward direction is the link from it,
 * its backward direction (the reflected packets) the link to it.  So a
 * link from A to B takes its one-way figures from A's forward ones;
 * where A has none (no record of A, a reflector whose clock gave no
 * one-way delay), from B's backward ones of the same interval (the
 * intervals are aligned to the wall clock, so both ends' last completed
 * have one start), arcana-network-vpn-pm's one-way-measured-at saying
 * which.  The one-way loss is the sequence's (a stateful reflector's),
 * the delay and the jitter (IPDV) in microseconds with the percentiles
 * said non-zero.  RFC 9375 has one-way metrics alone: the round trip
 * the link's source end measured, there and back, is the augment's
 * round-trip-pm-statistics, and all an ICMP-measured tunnel has (its
 * pm-source arcana-network-vpn-pm's pm-source-icmp-echo, STAMP's
 * pm-source-stamp, as arcana-stamp's session says the method).
 *
 * Classes of service: RFC 9375's one-way-pm-statistics-per-class, a
 * class-id each class the service measures its tunnels in (arcana-l3nm's
 * probe classes, a session each at the ends), filled the same way; the
 * DSCP each session's probes went by in the augment's dscp, the
 * target's own in pm-attributes'.
 *
 * Read alone, of the hosts the user may read (their pm; the services'
 * nodes and links whatever), where the user may read the L3NM.  Left
 * out, and said in the log, where it is not of the schema.
 */

#include <sys/param.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <ucl.h>

#include "console.h"

#define	NVP		"ietf-network-vpn-pm:"
#define	ARC		"arcana-network-vpn-pm:"
#define	NT		"ietf-network-topology:"
/* The ids, RFC 9911's inet:uri each (a scheme, then anything). */
#define	UNDERLAY	"arcana:underlay"
#define	VPN_NET		"arcana:vpn:"
#define	EDGE		"arcana:edge:"
#define	IFACE		"arcana:if:"
#define	UCS_EP		"arcana:ucs-ep:"
#define	TUNNEL		"arcana:tunnel:"
#define	ULINK		"arcana:underlay:"
#define	US		"ietf-lime-time-types:microseconds"

/* The settings a link's figures were made with. */
struct pmset {
	double		 pct[3];	/* low, intermediate, high */
	long long	 len;		/* measurement interval, seconds */
};

struct vctx {
	vpnpm_get_fn	*get;
	void		*arg;
	ucl_object_t	*probes;	/* sid: arcana-probe's state targets */
	ucl_object_t	*stamp;		/* sid: arcana-stamp's sessions */
};

static void
put(ucl_object_t *o, const char *k, ucl_object_t *v)
{

	ucl_object_replace_key(o, v, k, 0, true);
}

static void
puts_(ucl_object_t *o, const char *k, const char *v)
{

	put(o, k, ucl_object_fromstring(v));
}

static ucl_object_t *
obj(void)
{

	return (ucl_object_typed_new(UCL_OBJECT));
}

static ucl_object_t *
arr(void)
{

	return (ucl_object_typed_new(UCL_ARRAY));
}

/* A member's value as a string, whatever its JSON type; NULL: none. */
static const char *
sval(const ucl_object_t *o, const char *k)
{
	const ucl_object_t	*v;

	if (o == NULL || (v = ucl_object_lookup(o, k)) == NULL ||
	    ucl_object_type(v) == UCL_OBJECT || ucl_object_type(v) ==
	    UCL_ARRAY || ucl_object_type(v) == UCL_NULL)
		return (NULL);
	return (ucl_object_tostring_forced(v));
}

static bool
num(const ucl_object_t *o, const char *k, double *d)
{
	const char	*s;
	char		*e;

	if ((s = sval(o, k)) == NULL || *s == '\0')
		return (false);
	*d = strtod(s, &e);
	return (*e == '\0');
}

/* An identity value with its module: v's own, else mod's. */
static ucl_object_t *
ident(const char *mod, const char *v)
{
	char	buf[160];

	if (strchr(v, ':') != NULL)
		return (ucl_object_fromstring(v));
	snprintf(buf, sizeof(buf), "%s:%s", mod, v);
	return (ucl_object_fromstring(buf));
}

/* An identity's name, its module's prefix taken off. */
static const char *
bare(const char *v)
{
	const char	*c;

	if (v == NULL)
		return ("");
	return ((c = strchr(v, ':')) != NULL ? c + 1 : v);
}

/* ---- What the agents measured ------------------------------------------ */

static ucl_object_t *
fleet_json(struct vctx *x, const char *sid, const char *path)
{
	struct ucl_parser	*p;
	ucl_object_t		*o = NULL;
	char			*json;
	int			 status = 0;

	if ((json = x->get(x->arg, sid, path, &status)) == NULL)
		return (NULL);
	if (status == 200) {
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		if (ucl_parser_add_string(p, json, 0))
			o = ucl_parser_get_object(p);
		ucl_parser_free(p);
	}
	free(json);
	return (o);
}

/* Host sid's list key of top member at path, read once a view; NULL:
 * not read (not the user's, not reached, no such module). */
static const ucl_object_t *
host_list(struct vctx *x, ucl_object_t *cache, const char *sid,
    const char *path, const char *top, const char *list)
{
	const ucl_object_t	*v;
	ucl_object_t		*o, *l;

	if ((v = ucl_object_lookup(cache, sid)) != NULL)
		return (ucl_object_type(v) == UCL_ARRAY ? v : NULL);
	l = NULL;
	if ((o = fleet_json(x, sid, path)) != NULL) {
		v = ucl_object_lookup(ucl_object_lookup(o, top), list);
		l = v != NULL && ucl_object_type(v) == UCL_ARRAY ?
		    ucl_object_copy(v) : arr();
		ucl_object_unref(o);
	}
	put(cache, sid, l != NULL ? l : ucl_object_typed_new(UCL_NULL));
	return (l);
}

/* Whether entry e is of target id in jail (""), class cls (NULL: the
 * target's own), its keys named so. */
static bool
is_of(const ucl_object_t *e, const char *idk, const char *id,
    const char *jail, const char *cls)
{
	const char	*s;

	if ((s = ucl_str(e, idk)) == NULL || strcmp(s, id) != 0)
		return (false);
	s = ucl_str(e, "jail");
	if (strcmp(s != NULL ? s : "", jail) != 0)
		return (false);
	s = ucl_str(e, "class");
	if (cls == NULL)
		return (s == NULL || *s == '\0');
	return (s != NULL && strcmp(s, cls) == 0);
}

/* Edge's target of tunnel id, class cls; and its STAMP session's
 * method (*method, NULL: unknown). */
static const ucl_object_t *
target_at(struct vctx *x, const char *edge, const char *id, const char *cls,
    const char **method)
{
	const ucl_object_t	*l, *e, *found = NULL;
	ucl_object_iter_t	 it = NULL;
	char			 sid[64], jail[64], path[256];

	*method = NULL;
	if (!sdwan_edge_split(edge, sid, sizeof(sid), jail, sizeof(jail)))
		return (NULL);
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/"
	    "host=%s/arcana-probe:probes/state", sid);
	l = host_list(x, x->probes, sid, path, "arcana-probe:state", "target");
	while ((e = ucl_object_iterate(l, &it, true)) != NULL)
		if (is_of(e, "id", id, jail, cls))
			found = e;
	if (found == NULL)
		return (NULL);
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/"
	    "host=%s/arcana-stamp:stamp", sid);
	l = host_list(x, x->stamp, sid, path, "arcana-stamp:stamp", "session");
	it = NULL;
	while ((e = ucl_object_iterate(l, &it, true)) != NULL)
		if (is_of(e, "target", id, jail, cls))
			*method = ucl_str(e, "method");
	return (found);
}

/* Target t's last completed measurement interval; NULL: none yet. */
static const ucl_object_t *
last_complete(const ucl_object_t *t)
{
	const ucl_object_t	*v, *best = NULL;
	ucl_object_iter_t	 it = NULL;
	const char		*s, *b;

	while ((v = ucl_object_iterate(ucl_object_lookup_path(t,
	    "pm.interval"), &it, true)) != NULL) {
		if (!ucl_object_toboolean(ucl_object_lookup(v, "complete")) ||
		    (s = ucl_str(v, "start")) == NULL)
			continue;
		if (best == NULL || ((b = ucl_str(best, "start")) != NULL &&
		    strcmp(s, b) > 0))
			best = v;
	}
	return (best);
}

/* ---- RFC 9375's statistics ---------------------------------------------- */

static void
put_u64(ucl_object_t *o, const char *k, const ucl_object_t *src,
    const char *sk)
{
	const char	*s;

	if ((s = sval(src, sk)) != NULL)
		puts_(o, k, s);
}

/*
 * A delay or jitter statistics container (what "delay" or "jitter"
 * names in RFC 9375's leaves) of st, an interval's figures of one
 * metric (count, min, max, the three percentiles, microseconds); NULL
 * where it counted none.
 */
static ucl_object_t *
stats_of(const ucl_object_t *st, const char *what, const struct pmset *ps)
{
	static const char *const lv[] = { "low", "intermediate", "high" };
	ucl_object_t	*o;
	double		 n;
	char		 k[64], sk[64];

	if (st == NULL || !num(st, "count", &n) || n <= 0)
		return (NULL);
	o = obj();
	puts_(o, "unit-value", US);
	snprintf(k, sizeof(k), "min-%s-value", what);
	put_u64(o, k, st, "min");
	snprintf(k, sizeof(k), "max-%s-value", what);
	put_u64(o, k, st, "max");
	for (size_t i = 0; i < nitems(lv); i++) {
		if (ps->pct[i] <= 0)
			continue;
		snprintf(k, sizeof(k), "%s-%s-percentile", lv[i], what);
		snprintf(sk, sizeof(sk), "%s-percentile", lv[i]);
		put_u64(o, k, st, sk);
	}
	return (o);
}

/* A loss-statistics container of an interval's loss: count and ratio
 * of the members named so; NULL where there are none. */
static ucl_object_t *
loss_of(const ucl_object_t *loss, const char *ck, const char *rk)
{
	ucl_object_t	*o;
	double		 r;
	char		 v[32];

	if (sval(loss, ck) == NULL)
		return (NULL);
	o = obj();
	puts_(o, "packet-loss-count", sval(loss, ck));
	if (num(loss, rk, &r)) {
		snprintf(v, sizeof(v), "%.5f", r);
		puts_(o, "loss-ratio", v);
	}
	return (o);
}

/* One-way statistics into o of interval v's direction dir (forward,
 * backward); false where it has none. */
static bool
one_way(ucl_object_t *o, const ucl_object_t *v, const char *dir,
    const struct pmset *ps)
{
	ucl_object_t	*d, *j, *l;
	char		 ck[32], rk[32];

	if (v == NULL || (d = stats_of(ucl_object_lookup(v, dir), "delay",
	    ps)) == NULL)
		return (false);
	snprintf(ck, sizeof(ck), "%s-count", dir);
	snprintf(rk, sizeof(rk), "%s-ratio", dir);
	if ((l = loss_of(ucl_object_lookup(v, "loss"), ck, rk)) != NULL)
		put(o, "loss-statistics", l);
	put(o, "delay-statistics", d);
	if ((j = stats_of(ucl_object_lookup(ucl_object_lookup(v, "jitter"),
	    dir), "jitter", ps)) != NULL)
		put(o, "jitter-statistics", j);
	return (true);
}

/* The round trip of interval v, arcana-network-vpn-pm's; NULL: none. */
static ucl_object_t *
round_trip(const ucl_object_t *v, const struct pmset *ps)
{
	ucl_object_t	*o, *s;

	if (v == NULL)
		return (NULL);
	o = obj();
	if ((s = loss_of(ucl_object_lookup(v, "loss"), "count", "ratio")) !=
	    NULL)
		put(o, "loss-statistics", s);
	if ((s = stats_of(ucl_object_lookup(v, "round-trip"), "delay", ps)) !=
	    NULL)
		put(o, "delay-statistics", s);
	if ((s = stats_of(ucl_object_lookup_path(v, "jitter.round-trip"),
	    "jitter", ps)) != NULL)
		put(o, "jitter-statistics", s);
	if (ucl_object_lookup(o, "loss-statistics") == NULL &&
	    ucl_object_lookup(o, "delay-statistics") == NULL) {
		ucl_object_unref(o);
		return (NULL);
	}
	return (o);
}

/*
 * What the link from edge src to edge dst of tunnel id has measured of
 * it in class cls (NULL: the target's own) into o (pm-attributes, or a
 * per-class entry): the one-way figures, which end they are of, the
 * DSCP, the round trip; *start and *end the interval's.  False: none
 * measured yet.
 */
static bool
link_fill(struct vctx *x, ucl_object_t *o, const char *id, const char *src,
    const char *dst, const char *cls, const struct pmset *ps,
    const char **start, const char **end, const char **method)
{
	const ucl_object_t	*ts, *td, *a, *b;
	const char		*m2;
	ucl_object_t		*ow, *rt;
	const char		*at = NULL;

	ts = target_at(x, src, id, cls, method);
	td = target_at(x, dst, id, cls, &m2);
	a = ts != NULL ? last_complete(ts) : NULL;
	b = td != NULL ? last_complete(td) : NULL;
	if (a == NULL && b == NULL)
		return (false);
	/* The far end's of the same interval alone. */
	if (a != NULL && b != NULL && (ucl_str(b, "start") == NULL ||
	    strcmp(ucl_str(a, "start"), ucl_str(b, "start")) != 0))
		b = NULL;
	*start = ucl_str(a != NULL ? a : b, "start");
	*end = ucl_str(a != NULL ? a : b, "end");
	ow = obj();
	if (one_way(ow, a, "forward", ps))
		at = "source";
	else if (one_way(ow, b, "backward", ps))
		at = "destination";
	if (at != NULL && cls == NULL)
		put(o, "one-way-pm-statistics", ow);
	else if (at != NULL) {
		/* A per-class entry has the statistics itself. */
		const ucl_object_t	*m;
		ucl_object_iter_t	 mt = NULL;

		while ((m = ucl_object_iterate(ow, &mt, true)) != NULL)
			put(o, ucl_object_key(m), ucl_object_copy(m));
		ucl_object_unref(ow);
	} else
		ucl_object_unref(ow);
	if (at != NULL)
		puts_(o, ARC "one-way-measured-at", at);
	if (ts != NULL && sval(ts, "dscp") != NULL)
		put(o, ARC "dscp", ucl_object_fromint(ucl_object_toint(
		    ucl_object_lookup(ts, "dscp"))));
	else if (td != NULL && sval(td, "dscp") != NULL)
		put(o, ARC "dscp", ucl_object_fromint(ucl_object_toint(
		    ucl_object_lookup(td, "dscp"))));
	if ((rt = round_trip(a, ps)) != NULL)
		put(o, ARC "round-trip-pm-statistics", rt);
	return (true);
}

/* ---- The networks -------------------------------------------------------- */

static ucl_object_t *
ref_node(const char *net, const char *node)
{
	ucl_object_t	*r = obj();

	puts_(r, "network-ref", net);
	puts_(r, "node-ref", node);
	return (r);
}

/* Node id's entry of nodes (an object by id), made where it is not. */
static ucl_object_t *
node_entry(ucl_object_t *nodes, const char *id, const char *below,
    const char *below_node)
{
	ucl_object_t	*n, *a;

	if ((n = __DECONST(ucl_object_t *, ucl_object_lookup(nodes, id))) !=
	    NULL)
		return (n);
	n = obj();
	puts_(n, "node-id", id);
	if (below != NULL) {
		a = arr();
		ucl_array_append(a, ref_node(below, below_node));
		put(n, "supporting-node", a);
	}
	puts_(n, NVP "node-type", NVP "pe");
	put(n, NT "termination-point", obj());	/* by tp-id, made a list */
	put(nodes, id, n);
	return (n);
}

/* Node n's termination point tp, supported by sup's (NULL: none). */
static void
tp_add(ucl_object_t *n, const char *tp, const char *net, const char *node,
    const char *sup)
{
	ucl_object_t	*tps, *e, *a, *r;

	tps = __DECONST(ucl_object_t *, ucl_object_lookup(n, NT
	    "termination-point"));
	if (ucl_object_lookup(tps, tp) != NULL)
		return;
	e = obj();
	puts_(e, "tp-id", tp);
	if (sup != NULL) {
		r = ref_node(net, node);
		puts_(r, "tp-ref", sup);
		a = arr();
		ucl_array_append(a, r);
		put(e, "supporting-termination-point", a);
	}
	put(tps, tp, e);
}

/* The object nodes (by id) as RFC 7951's list, each one's termination
 * points as one too. */
static ucl_object_t *
node_list(ucl_object_t *nodes)
{
	const ucl_object_t	*n, *tp;
	ucl_object_iter_t	 it = NULL, jt;
	ucl_object_t		*l, *c, *tps;

	l = arr();
	while ((n = ucl_object_iterate(nodes, &it, true)) != NULL) {
		c = ucl_object_copy(n);
		tps = arr();
		jt = NULL;
		while ((tp = ucl_object_iterate(ucl_object_lookup(n, NT
		    "termination-point"), &jt, true)) != NULL)
			ucl_array_append(tps, ucl_object_copy(tp));
		if (ucl_array_size(tps) > 0)
			put(c, NT "termination-point", tps);
		else {
			ucl_object_unref(tps);
			(void)ucl_object_delete_key(c, NT "termination-point");
		}
		ucl_array_append(l, c);
	}
	ucl_object_unref(nodes);
	return (l);
}

static ucl_object_t *
link_new(const char *id, const char *sn, const char *stp, const char *dn,
    const char *dtp)
{
	ucl_object_t	*l, *e;

	l = obj();
	puts_(l, "link-id", id);
	e = obj();
	puts_(e, "source-node", sn);
	puts_(e, "source-tp", stp);
	put(l, "source", e);
	e = obj();
	puts_(e, "dest-node", dn);
	puts_(e, "dest-tp", dtp);
	put(l, "destination", e);
	return (l);
}

/* The settings: those the source end's target reported, else the
 * service's (sw, arcana-l3nm's sdwan), else Arcana's defaults. */
static void
pmset_of(struct vctx *x, const ucl_object_t *sw, const char *id,
    const char *src, struct pmset *ps)
{
	static const char *const k[] = { "low-percentile",
	    "intermediate-percentile", "high-percentile" };
	const ucl_object_t	*t, *p;
	const char		*m;
	double			 d;

	ps->pct[0] = 10;
	ps->pct[1] = 50;
	ps->pct[2] = 90;
	ps->len = 60;
	p = ucl_object_lookup(sw, "probe");
	if ((t = target_at(x, src, id, NULL, &m)) != NULL &&
	    ucl_object_lookup(t, "pm") != NULL)
		p = ucl_object_lookup(t, "pm");
	for (size_t i = 0; i < nitems(k); i++)
		if (num(p, k[i], &d) && d >= 0 && d <= 100)
			ps->pct[i] = d;
	if (num(p, "measurement-interval", &d) && d >= 1)
		ps->len = (long long)d;
}

static const char *
tunnel_type(const char *kind)
{

	if (kind == NULL || strcmp(kind, "gre") == 0)
		return ("ietf-vpn-common:gre");
	if (strcmp(kind, "gif") == 0)
		return ("ietf-vpn-common:ip-in-ip");
	if (strcmp(kind, "geneve") == 0)
		return ("ietf-vpn-common:geneve");
	if (strcmp(kind, "wg") == 0)
		return (ARC "wireguard");
	if (strcmp(kind, "uswe") == 0)
		return (ARC "ipsec");
	return ("ietf-vpn-common:gre");
}

/* Service s's link of tunnel t from end es to end ed. */
static ucl_object_t *
svc_link(struct vctx *x, const ucl_object_t *s, const ucl_object_t *t,
    const ucl_object_t *es, const ucl_object_t *ed)
{
	const ucl_object_t	*sw, *c;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*l, *pm, *pa, *e, *a, *cl, *ce;
	struct pmset		 ps;
	const char		*id, *start = NULL, *end = NULL, *method = NULL;
	const char		*cs, *ce2, *cm, *name;
	char			 lid[400], v[32], sn[160], dn[160], stp[64];
	char			 dtp[64];
	bool			 any;

	id = ucl_str(t, "id");
	snprintf(lid, sizeof(lid), TUNNEL "%s,%s,%s", id, ucl_str(es,
	    "ucs_ep"), ucl_str(ed, "ucs_ep"));
	snprintf(sn, sizeof(sn), EDGE "%s", ucl_str(es, "edge"));
	snprintf(dn, sizeof(dn), EDGE "%s", ucl_str(ed, "edge"));
	snprintf(stp, sizeof(stp), IFACE "%s", ucl_str(es, "ifname"));
	snprintf(dtp, sizeof(dtp), IFACE "%s", ucl_str(ed, "ifname"));
	l = link_new(lid, sn, stp, dn, dtp);
	a = arr();
	e = obj();
	puts_(e, "network-ref", UNDERLAY);
	snprintf(lid, sizeof(lid), ULINK "%s,%s", ucl_str(es, "ucs_ep"),
	    ucl_str(ed, "ucs_ep"));
	puts_(e, "link-ref", lid);
	ucl_array_append(a, e);
	put(l, "supporting-link", a);

	sw = ucl_object_lookup(s, "arcana-l3nm:sdwan");
	pmset_of(x, sw, id, ucl_str(es, "edge"), &ps);
	pm = obj();
	snprintf(v, sizeof(v), "%.3f", ps.pct[0]);
	puts_(pm, "low-percentile", v);
	snprintf(v, sizeof(v), "%.3f", ps.pct[1]);
	puts_(pm, "intermediate-percentile", v);
	snprintf(v, sizeof(v), "%.3f", ps.pct[2]);
	puts_(pm, "high-percentile", v);
	put(pm, "measurement-interval", ucl_object_fromint(ps.len));

	pa = obj();
	any = link_fill(x, pa, id, ucl_str(es, "edge"), ucl_str(ed, "edge"),
	    NULL, &ps, &start, &end, &method);
	cl = arr();
	while ((c = ucl_object_iterate(ucl_object_lookup_path(sw,
	    "probe.class"), &it, true)) != NULL) {
		if ((name = ucl_str(c, "name")) == NULL)
			continue;
		ce = obj();
		puts_(ce, "class-id", name);
		cs = ce2 = NULL;
		if (!link_fill(x, ce, id, ucl_str(es, "edge"), ucl_str(ed,
		    "edge"), name, &ps, &cs, &ce2, &cm)) {
			ucl_object_unref(ce);
			continue;
		}
		if (start == NULL) {
			start = cs;
			end = ce2;
		}
		ucl_array_append(cl, ce);
	}
	if (ucl_array_size(cl) > 0) {
		put(pa, "one-way-pm-statistics-per-class", cl);
		any = true;
	} else
		ucl_object_unref(cl);
	if (any) {
		ucl_object_t	*p0 = obj(), *pms = arr(), *ord = obj();
		const ucl_object_t *m;
		ucl_object_iter_t	 mt = NULL;

		/* start-time and end-time first, as the model has them. */
		if (start != NULL)
			puts_(ord, "start-time", start);
		if (end != NULL)
			puts_(ord, "end-time", end);
		if (method != NULL && strcmp(method, "stamp") == 0)
			puts_(ord, "pm-source", NVP "pm-source-stamp");
		else if (method != NULL && strcmp(method, "icmp") == 0)
			puts_(ord, "pm-source", ARC "pm-source-icmp-echo");
		else if (ucl_object_lookup(pa, "one-way-pm-statistics") !=
		    NULL)
			puts_(ord, "pm-source", NVP "pm-source-stamp");
		while ((m = ucl_object_iterate(pa, &mt, true)) != NULL)
			put(ord, ucl_object_key(m), ucl_object_copy(m));
		puts_(p0, "pm-type", NVP "pm-type-vpn-tunnel");
		put(p0, "pm-attributes", ord);
		ucl_array_append(pms, p0);
		put(pm, "pm", pms);
	}
	ucl_object_unref(pa);
	e = obj();
	puts_(e, "vpn-tunnel-type", tunnel_type(ucl_str(t, "kind")));
	a = obj();
	put(a, "vpn-tunnel", e);
	put(pm, "vpn-pm-type", a);
	put(l, NVP "perf-mon", pm);
	return (l);
}

/* RFC 9181's role of service s's node nd, by its accesses' profiles:
 * a hub where one is, a spoke where all are, else any-to-any. */
static const char *
role_of(const ucl_object_t *s, const ucl_object_t *nd)
{
	const ucl_object_t	*na, *p;
	ucl_object_iter_t	 it = NULL, pt;
	const char		*pid, *r;
	size_t			 n = 0, spokes = 0;

	while ((na = ucl_object_iterate(ucl_object_lookup_path(nd,
	    "vpn-network-accesses.vpn-network-access"), &it, true)) != NULL) {
		n++;
		if ((pid = ucl_str(na, "vpn-instance-profile")) == NULL)
			continue;
		pt = NULL;
		while ((p = ucl_object_iterate(ucl_object_lookup_path(s,
		    "vpn-instance-profiles.vpn-instance-profile"), &pt,
		    true)) != NULL) {
			if (ucl_str(p, "profile-id") == NULL || strcmp(ucl_str(
			    p, "profile-id"), pid) != 0)
				continue;
			r = bare(ucl_str(p, "role"));
			if (strcmp(r, "hub-role") == 0)
				return ("ietf-vpn-common:hub-role");
			spokes += strcmp(r, "spoke-role") == 0;
		}
	}
	return (n > 0 && spokes == n ? "ietf-vpn-common:spoke-role" :
	    "ietf-vpn-common:any-to-any-role");
}

/* Service s's network, its tunnels' ends added to the underlay's
 * nodes and links. */
static ucl_object_t *
svc_network(struct vctx *x, const ucl_object_t *s, const ucl_object_t *tuns,
    ucl_object_t *unodes, ucl_object_t *ulinks)
{
	const ucl_object_t	*nd, *t, *es, *ed;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*nw, *ty, *sv, *nodes, *links, *n, *a;
	const char		*vid, *edge;
	char			 nid[200], lid[200], en[160], dn[160], tp[64];
	char			 utp[160], dtp[160];

	if ((vid = ucl_str(s, "vpn-id")) == NULL)
		return (NULL);
	nw = obj();
	snprintf(nid, sizeof(nid), VPN_NET "%s", vid);
	puts_(nw, "network-id", nid);
	sv = obj();
	put(sv, "service-type", ident("ietf-vpn-common", ucl_str(s,
	    "vpn-type") != NULL ? ucl_str(s, "vpn-type") : "l3vpn"));
	puts_(sv, "vpn-id", vid);
	put(sv, "vpn-service-topology", ident("ietf-vpn-common", ucl_str(s,
	    "vpn-service-topology") != NULL ? ucl_str(s,
	    "vpn-service-topology") : "any-to-any"));
	ty = obj();
	put(ty, NVP "service", sv);
	put(nw, "network-types", ty);
	a = arr();
	n = obj();
	puts_(n, "network-ref", UNDERLAY);
	ucl_array_append(a, n);
	put(nw, "supporting-network", a);

	nodes = obj();
	while ((nd = ucl_object_iterate(ucl_object_lookup_path(s,
	    "vpn-nodes.vpn-node"), &it, true)) != NULL) {
		if ((edge = ucl_str(nd, "vpn-node-id")) == NULL)
			continue;
		snprintf(en, sizeof(en), EDGE "%s", edge);
		n = node_entry(nodes, en, UNDERLAY, en);
		puts_(n, NVP "role", role_of(s, nd));
	}
	links = arr();
	it = NULL;
	while ((t = ucl_object_iterate(tuns, &it, true)) != NULL) {
		if (ucl_str(t, "id") == NULL || ucl_str(t, "swvc") == NULL ||
		    strcmp(ucl_str(t, "swvc"), vid) != 0)
			continue;
		for (unsigned k = 0; k < 2; k++) {
			es = ucl_array_find_index(ucl_object_lookup(t, "ends"),
			    k);
			ed = ucl_array_find_index(ucl_object_lookup(t, "ends"),
			    !k);
			if (ucl_str(es, "edge") == NULL || ucl_str(es,
			    "ifname") == NULL || ucl_str(es, "ucs_ep") == NULL ||
			    ucl_str(ed, "edge") == NULL || ucl_str(ed,
			    "ifname") == NULL || ucl_str(ed, "ucs_ep") == NULL)
				break;
			edge = ucl_str(es, "edge");
			snprintf(en, sizeof(en), EDGE "%s", edge);
			snprintf(dn, sizeof(dn), EDGE "%s", ucl_str(ed, "edge"));
			snprintf(utp, sizeof(utp), UCS_EP "%s", ucl_str(es,
			    "ucs_ep"));
			snprintf(dtp, sizeof(dtp), UCS_EP "%s", ucl_str(ed,
			    "ucs_ep"));
			/* The underlay's: the edge, the UCS End Point the
			 * tunnel leaves by, the way to the far one. */
			n = node_entry(unodes, en, NULL, NULL);
			tp_add(n, utp, NULL, NULL, NULL);
			snprintf(lid, sizeof(lid), ULINK "%s,%s", ucl_str(es,
			    "ucs_ep"), ucl_str(ed, "ucs_ep"));
			if (ucl_object_lookup(ulinks, lid) == NULL)
				put(ulinks, lid, link_new(lid, en, utp, dn,
				    dtp));
			/* The service's: the tunnel's interface at the edge. */
			n = node_entry(nodes, en, UNDERLAY, en);
			snprintf(tp, sizeof(tp), IFACE "%s", ucl_str(es,
			    "ifname"));
			tp_add(n, tp, UNDERLAY, en, utp);
			ucl_array_append(links, svc_link(x, s, t, es, ed));
		}
	}
	put(nw, "node", node_list(nodes));
	if (ucl_array_size(links) > 0)
		put(nw, NT "link", links);
	else
		ucl_object_unref(links);
	return (nw);
}

void
vpnpm_networks(const ucl_object_t *y, vpnpm_get_fn *get, void *arg,
    ucl_object_t *list)
{
	struct vctx		 x;
	const ucl_object_t	*s, *l;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*tuns, *unodes, *ulinks, *u, *a, *nw;
	ucl_object_t		*svcs;

	if (y == NULL || ucl_object_lookup_path(y, "vpn-services.vpn-service")
	    == NULL)
		return;
	tuns = sdwan_plan_tunnels(y);
	memset(&x, 0, sizeof(x));
	x.get = get;
	x.arg = arg;
	x.probes = obj();
	x.stamp = obj();
	unodes = obj();
	ulinks = obj();
	svcs = arr();
	while ((s = ucl_object_iterate(ucl_object_lookup_path(y,
	    "vpn-services.vpn-service"), &it, true)) != NULL)
		if ((nw = svc_network(&x, s, tuns, unodes, ulinks)) != NULL)
			ucl_array_append(svcs, nw);
	u = obj();
	puts_(u, "network-id", UNDERLAY);
	put(u, "network-types", obj());
	put(u, "node", node_list(unodes));
	a = arr();
	it = NULL;
	while ((l = ucl_object_iterate(ulinks, &it, true)) != NULL)
		ucl_array_append(a, ucl_object_copy(l));
	ucl_object_unref(ulinks);
	if (ucl_array_size(a) > 0)
		put(u, NT "link", a);
	else
		ucl_object_unref(a);
	ucl_array_append(list, u);
	it = NULL;
	while ((s = ucl_object_iterate(svcs, &it, true)) != NULL)
		ucl_array_append(list, ucl_object_copy(s));
	ucl_object_unref(svcs);
	if (tuns != NULL)
		ucl_object_unref(tuns);
	ucl_object_unref(x.probes);
	ucl_object_unref(x.stamp);
}
