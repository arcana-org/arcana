/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: the probes as YANG, arcana-probe: each edge's targets, links
 * and monitors (probe.c's probe_conf_json()) as configuration, and
 * back as the JSON do_probes_set() and do_monitors_set() take; the
 * sdwan read's targets as state, each sample taken apart from its row.
 * And arcana-stamp's sessions, from the same read: each target that
 * STAMP measures, or may (probe.c's target_json() says its reflector's
 * port), with what STAMP saw of it.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arcana.h>

#include "collect.h"
#include "yjson.h"

static char *
datetime(cbl_yarena *a, int64_t t)
{
	char		buf[32], *p;
	struct tm	tm;
	time_t		tt = (time_t)t;

	if (gmtime_r(&tt, &tm) == NULL || strftime(buf, sizeof(buf),
	    "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
		return (NULL);
	if ((p = cbl_yarena_alloc(a, strlen(buf) + 1)) != NULL)
		memcpy(p, buf, strlen(buf) + 1);
	return (p);
}

static bool
addr_union(cbl_yarena *a, const ucl_object_t *o, const char *key, void *u)
{
	struct arcana_probe_target_address	*s = u;
	const char					*v;

	if ((v = yj_str(a, o, key)) == NULL)
		return (false);
	s->which = strchr(v, ':') != NULL ? 1 : 0;
	s->v.m0 = v;
	return (true);
}

/* A number of o's as a decimal64 of d fraction digits. */
static bool
dec(const ucl_object_t *o, const char *key, int d, int64_t *v)
{
	const ucl_object_t	*e;
	double			 m = d == 6 ? 1000000.0 : 1000.0;

	if ((e = ucl_object_lookup(o, key)) == NULL || (ucl_object_type(e) !=
	    UCL_FLOAT && ucl_object_type(e) != UCL_INT))
		return (false);
	*v = (int64_t)(ucl_object_todouble(e) * m + (ucl_object_todouble(e) <
	    0 ? -0.5 : 0.5));
	return (true);
}

static const char *const states[] = { "unknown", "up", "down", "ended",
    "error" };

/* The thresholds of o's, NULL with none. */
static int
tca_of(cbl_yarena *a, const ucl_object_t *o, const struct arcana_probe_tca **tp)
{
	struct arcana_probe_tca	*t;
	const ucl_object_t	*c;

	*tp = NULL;
	if ((c = ucl_object_lookup(o, "tca")) == NULL)
		return (0);
	if ((t = cbl_yarena_alloc(a, sizeof(*t))) == NULL)
		return (ENOMEM);
	memset(t, 0, sizeof(*t));
	t->has_delay = dec(c, "delay", 3, &t->delay);
	t->has_ipdv = dec(c, "ipdv", 3, &t->ipdv);
	t->has_loss = dec(c, "loss", 6, &t->loss);
	YJ_NUM(c, "damping", t, damping);
	*tp = t;
	return (0);
}

/* The three percentiles of o's (low_percentile...), where it says them,
 * into y's. */
#define	PCT_OF(o, y) do {						\
	(y)->has_low_percentile = dec((o), "low_percentile", 3,		\
	    &(y)->low_percentile);					\
	(y)->has_intermediate_percentile = dec((o),			\
	    "intermediate_percentile", 3, &(y)->intermediate_percentile);	\
	(y)->has_high_percentile = dec((o), "high_percentile", 3,	\
	    &(y)->high_percentile);					\
} while (0)

/* An edge's lists, e's ("targets", "links", "monitors"), into its. */
static int
edge_of(cbl_yarena *a, const ucl_object_t *e,
    struct arcana_probe_probes_jail *out)
{
	struct arcana_probe_target	*t;
	struct arcana_probe_link	*l;
	struct arcana_probe_monitor	*m;
	const ucl_object_t		*o, *list;
	ucl_object_iter_t		 it;
	const char			*s;
	size_t				 n;
	int				 error;

	list = ucl_object_lookup(e, "targets");
	if ((t = cbl_yarena_alloc(a, (yj_count(list) + 1) * sizeof(*t))) ==
	    NULL)
		return (ENOMEM);
	n = 0;
	YJ_EACH(list, it, o) {
		memset(&t[n], 0, sizeof(t[n]));
		if ((t[n].id = yj_str(a, o, "id")) == NULL)
			continue;
		t[n].has_address = addr_union(a, o, "address", &t[n].address);
		/* How it is measured, auto unless said. */
		if ((s = yj_str(a, o, "kind")) != NULL) {
			t[n].has_kind = true;
			t[n].kind = strcmp(s, "stamp") == 0 ?
			    ARCANA_PROBE_TARGET_KIND_STAMP : strcmp(s, "icmp") ==
			    0 ? ARCANA_PROBE_TARGET_KIND_ICMP :
			    ARCANA_PROBE_TARGET_KIND_AUTO;
		}
		t[n].stamp_interface = yj_str(a, o, "stamp_interface");
		t[n].stamp_peer = yj_str(a, o, "stamp_peer");
		YJ_NUM(o, "count", &t[n], count);
		YJ_NUM(o, "report", &t[n], report);
		YJ_NUM(o, "fib", &t[n], fib);
		YJ_NUM(o, "interval", &t[n], interval);
		YJ_NUM(o, "size", &t[n], size);
		YJ_NUM(o, "dscp", &t[n], dscp);
		YJ_NUM(o, "down", &t[n], down);
		YJ_NUM(o, "up", &t[n], up);
		YJ_NUM(o, "timeout", &t[n], timeout);
		YJ_NUM(o, "eval", &t[n], eval);
		YJ_NUM(o, "history", &t[n], history);
		YJ_NUM(o, "measurement_interval", &t[n], measurement_interval);
		PCT_OF(o, &t[n]);
		/* Its classes of service. */
		{
			const ucl_object_t		*cl = ucl_object_lookup(o,
						    "classes"), *c;
			struct arcana_probe_target_class	*cv;
			ucl_object_iter_t		 cit;
			size_t				 nc = 0;

			if ((cv = cbl_yarena_alloc(a, (yj_count(cl) + 1) *
			    sizeof(*cv))) == NULL)
				return (ENOMEM);
			YJ_EACH(cl, cit, c) {
				memset(&cv[nc], 0, sizeof(cv[nc]));
				if ((cv[nc].name = yj_str(a, c, "name")) == NULL)
					continue;
				YJ_NUM(c, "dscp", &cv[nc], dscp);
				nc++;
			}
			t[n].class.n = nc;
			t[n].class.v = cv;
		}
		if ((error = tca_of(a, o, &t[n].tca)) != 0)
			return (error);
		n++;
	}
	out->target.n = n;
	out->target.v = t;
	list = ucl_object_lookup(e, "links");
	if ((l = cbl_yarena_alloc(a, (yj_count(list) + 1) * sizeof(*l))) ==
	    NULL)
		return (ENOMEM);
	n = 0;
	YJ_EACH(list, it, o) {
		memset(&l[n], 0, sizeof(l[n]));
		if ((l[n].id = yj_str(a, o, "id")) == NULL)
			continue;
		l[n].interface = yj_str(a, o, "interface");
		if ((s = yj_str(a, o, "role")) != NULL) {
			l[n].has_role = true;
			l[n].role = strcmp(s, "uni") == 0 ?
			    ARCANA_PROBE_LINK_ROLE_UNI :
			    ARCANA_PROBE_LINK_ROLE_UCS;
		}
		n++;
	}
	out->link.n = n;
	out->link.v = l;
	list = ucl_object_lookup(e, "monitors");
	if ((m = cbl_yarena_alloc(a, (yj_count(list) + 1) * sizeof(*m))) ==
	    NULL)
		return (ENOMEM);
	n = 0;
	YJ_EACH(list, it, o) {
		memset(&m[n], 0, sizeof(m[n]));
		if ((m[n].name = yj_str(a, o, "id")) == NULL)
			continue;
		m[n].interface = yj_str(a, o, "interface");
		m[n].has_address = addr_union(a, o, "address", &m[n].address);
		YJ_NUM(o, "fib", &m[n], fib);
		YJ_NUM(o, "interval", &m[n], interval);
		YJ_NUM(o, "size", &m[n], size);
		YJ_NUM(o, "dscp", &m[n], dscp);
		YJ_NUM(o, "down", &m[n], down);
		YJ_NUM(o, "up", &m[n], up);
		YJ_NUM(o, "timeout", &m[n], timeout);
		YJ_NUM(o, "eval", &m[n], eval);
		YJ_NUM(o, "history", &m[n], history);
		YJ_NUM(o, "measurement_interval", &m[n], measurement_interval);
		PCT_OF(o, &m[n]);
		if ((error = tca_of(a, o, &m[n].tca)) != 0)
			return (error);
		n++;
	}
	out->monitor.n = n;
	out->monitor.v = m;
	return (0);
}

int
yprobe_conf_from_json(const char *json, cbl_yarena *a,
    struct arcana_probe_probes *out)
{
	struct arcana_probe_probes_jail	*j, host;
	const ucl_object_t		*e;
	ucl_object_iter_t		 it;
	ucl_object_t			*top;
	const char			*name;
	size_t				 n = 0;
	int				 error = 0;

	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	if ((j = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "edges")) + 1) * sizeof(*j))) == NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	YJ_EACH(ucl_object_lookup(top, "edges"), it, e) {
		name = yj_str(a, e, "jail");
		if (name == NULL || name[0] == '\0') {
			memset(&host, 0, sizeof(host));
			if ((error = edge_of(a, e, &host)) != 0)
				break;
			out->target.n = host.target.n;
			out->target.v = host.target.v;
			out->link.n = host.link.n;
			out->link.v = host.link.v;
			out->monitor.n = host.monitor.n;
			out->monitor.v = host.monitor.v;
			continue;
		}
		memset(&j[n], 0, sizeof(j[n]));
		j[n].name = name;
		if ((error = edge_of(a, e, &j[n])) != 0)
			break;
		n++;
	}
	out->jail.n = n;
	out->jail.v = j;
	ucl_object_unref(top);
	return (error);
}

/* A decimal64 of d fraction digits as a number of o's. */
static void
put_dec(ucl_object_t *o, const char *key, bool has, int64_t v, int d)
{

	if (has)
		ucl_object_insert_key(o, ucl_object_fromdouble((double)v / (d ==
		    6 ? 1000000.0 : 1000.0)), key, 0, true);
}

#define	PUT_INT(o, key, y, f) do {					\
	if ((y)->has_##f)						\
		ucl_object_insert_key((o), ucl_object_fromint((int64_t)	\
		    (y)->f), (key), 0, true);				\
} while (0)

/* The three percentiles y says, as o's numbers. */
#define	PUT_PCT(o, y) do {						\
	put_dec((o), "low_percentile", (y)->has_low_percentile,		\
	    (y)->low_percentile, 3);					\
	put_dec((o), "intermediate_percentile",				\
	    (y)->has_intermediate_percentile,				\
	    (y)->intermediate_percentile, 3);				\
	put_dec((o), "high_percentile", (y)->has_high_percentile,	\
	    (y)->high_percentile, 3);					\
} while (0)

static void
put_tca(ucl_object_t *o, const struct arcana_probe_tca *t)
{
	ucl_object_t	*c;

	if (t == NULL)
		return;
	c = ucl_object_typed_new(UCL_OBJECT);
	put_dec(c, "delay", t->has_delay, t->delay, 3);
	put_dec(c, "ipdv", t->has_ipdv, t->ipdv, 3);
	put_dec(c, "loss", t->has_loss, t->loss, 6);
	PUT_INT(c, "damping", t, damping);
	ucl_object_insert_key(o, c, "tca", 0, true);
}

static char *
emit(ucl_object_t *top)
{
	char	*json;

	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	return (json);
}

char *
yprobe_edge_json(const char *jail, size_t nt,
    const struct arcana_probe_target *tv, size_t nl,
    const struct arcana_probe_link *lv)
{
	ucl_object_t	*top, *arr, *o;

	top = ucl_object_typed_new(UCL_OBJECT);
	if (jail != NULL && jail[0] != '\0')
		ucl_object_insert_key(top, ucl_object_fromstring(jail), "jail",
		    0, true);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < nt; i++) {
		const struct arcana_probe_target *t = &tv[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(t->id), "id", 0,
		    true);
		if (t->has_address)
			ucl_object_insert_key(o, ucl_object_fromstring(
			    t->address.v.m0), "address", 0, true);
		/* Its kind, auto unless said. */
		if (t->has_kind && t->kind != ARCANA_PROBE_TARGET_KIND_AUTO)
			ucl_object_insert_key(o, ucl_object_fromstring(t->kind ==
			    ARCANA_PROBE_TARGET_KIND_STAMP ? "stamp" : "icmp"),
			    "kind", 0, true);
		/* A plain tunnel's: what its STAMP key comes from. */
		if (t->stamp_interface != NULL)
			ucl_object_insert_key(o, ucl_object_fromstring(
			    t->stamp_interface), "stamp_interface", 0, true);
		if (t->stamp_peer != NULL)
			ucl_object_insert_key(o, ucl_object_fromstring(
			    t->stamp_peer), "stamp_peer", 0, true);
		PUT_INT(o, "count", t, count);
		PUT_INT(o, "report", t, report);
		PUT_INT(o, "fib", t, fib);
		PUT_INT(o, "interval", t, interval);
		PUT_INT(o, "size", t, size);
		PUT_INT(o, "dscp", t, dscp);
		PUT_INT(o, "down", t, down);
		PUT_INT(o, "up", t, up);
		PUT_INT(o, "timeout", t, timeout);
		PUT_INT(o, "eval", t, eval);
		PUT_INT(o, "history", t, history);
		PUT_INT(o, "measurement_interval", t, measurement_interval);
		PUT_PCT(o, t);
		if (t->class.n > 0) {
			ucl_object_t	*cl, *c;

			cl = ucl_object_typed_new(UCL_ARRAY);
			for (size_t k = 0; k < t->class.n; k++) {
				c = ucl_object_typed_new(UCL_OBJECT);
				ucl_object_insert_key(c, ucl_object_fromstring(
				    t->class.v[k].name), "name", 0, true);
				PUT_INT(c, "dscp", &t->class.v[k], dscp);
				ucl_array_append(cl, c);
			}
			ucl_object_insert_key(o, cl, "classes", 0, true);
		}
		put_tca(o, t->tca);
		ucl_array_append(arr, o);
	}
	ucl_object_insert_key(top, arr, "targets", 0, true);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < nl; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(lv[i].id), "id",
		    0, true);
		if (lv[i].interface != NULL)
			ucl_object_insert_key(o, ucl_object_fromstring(
			    lv[i].interface), "interface", 0, true);
		ucl_object_insert_key(o, ucl_object_fromstring(lv[i].has_role &&
		    lv[i].role == ARCANA_PROBE_LINK_ROLE_UNI ? "uni" : "ucs"),
		    "role", 0, true);
		ucl_array_append(arr, o);
	}
	ucl_object_insert_key(top, arr, "links", 0, true);
	return (emit(top));
}

char *
yprobe_monitors_json(const char *jail, size_t n,
    const struct arcana_probe_monitor *v)
{
	ucl_object_t	*top, *arr, *o;

	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, ucl_object_fromstring(jail != NULL ? jail :
	    ""), "jail", 0, true);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < n; i++) {
		const struct arcana_probe_monitor *m = &v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(m->name), "id", 0,
		    true);
		if (m->interface != NULL)
			ucl_object_insert_key(o, ucl_object_fromstring(
			    m->interface), "interface", 0, true);
		if (m->has_address)
			ucl_object_insert_key(o, ucl_object_fromstring(
			    m->address.v.m0), "address", 0, true);
		PUT_INT(o, "fib", m, fib);
		PUT_INT(o, "interval", m, interval);
		PUT_INT(o, "size", m, size);
		PUT_INT(o, "dscp", m, dscp);
		PUT_INT(o, "down", m, down);
		PUT_INT(o, "up", m, up);
		PUT_INT(o, "timeout", m, timeout);
		PUT_INT(o, "eval", m, eval);
		PUT_INT(o, "history", m, history);
		PUT_INT(o, "measurement_interval", m, measurement_interval);
		PUT_PCT(o, m);
		put_tca(o, m->tca);
		ucl_array_append(arr, o);
	}
	ucl_object_insert_key(top, arr, "targets", 0, true);
	return (emit(top));
}

/* The i-th number of a row, as a double. */
static bool
nth(const ucl_object_t *arr, size_t i, double *v)
{
	const ucl_object_t	*e;

	if ((e = ucl_array_find_index(arr, (unsigned)i)) == NULL ||
	    (ucl_object_type(e) != UCL_INT && ucl_object_type(e) != UCL_FLOAT))
		return (false);
	*v = ucl_object_todouble(e);
	return (true);
}

#define	ROW_DEC(arr, i, y, f, m)	do {				\
	double v_;							\
									\
	if (((y)->has_##f = nth((arr), (i), &v_)))			\
		(y)->f = (int64_t)(v_ * (m) + 0.5);			\
} while (0)

/* A target's samples, each a row. */
static int
samples_of(cbl_yarena *a, const ucl_object_t *arr, size_t *np,
    const struct arcana_probe_sample **vp)
{
	struct arcana_probe_sample	*v;
	const ucl_object_t				*e;
	ucl_object_iter_t				 it;
	double						 d;
	size_t						 n = 0;

	if ((v = cbl_yarena_alloc(a, (yj_count(arr) + 1) * sizeof(*v))) ==
	    NULL)
		return (ENOMEM);
	YJ_EACH(arr, it, e) {
		if (ucl_object_type(e) != UCL_ARRAY || !nth(e, 0, &d))
			continue;
		memset(&v[n], 0, sizeof(v[n]));
		v[n].time = datetime(a, (int64_t)d);
		ROW_DEC(e, 1, &v[n], delay, 1000.0);
		ROW_DEC(e, 2, &v[n], ipdv, 1000.0);
		ROW_DEC(e, 3, &v[n], loss, 1000000.0);
		ROW_DEC(e, 4, &v[n], min, 1000.0);
		ROW_DEC(e, 5, &v[n], max, 1000.0);
		if ((v[n].has_sent = nth(e, 6, &d)))
			v[n].sent = (uint32_t)d;
		if ((v[n].has_received = nth(e, 7, &d)))
			v[n].received = (uint32_t)d;
		/* By STAMP: the loss each way (a fraction of those sent, -1
		 * not told), the delay each way and how (1 one way, 0 half
		 * the round trip, -1 not by STAMP). */
		if (nth(e, 8, &d) && d >= 0 && v[n].has_sent) {
			v[n].has_lost_forward = true;
			v[n].lost_forward = (uint32_t)(d * v[n].sent + 0.5);
		}
		if (nth(e, 9, &d) && d >= 0 && v[n].has_sent) {
			v[n].has_lost_backward = true;
			v[n].lost_backward = (uint32_t)(d * v[n].sent + 0.5);
		}
		if (nth(e, 12, &d) && d >= 0) {
			v[n].has_one_way = true;
			v[n].one_way = d > 0 ? ARCANA_PROBE_SAMPLE_ONE_WAY_MEASURED :
			    ARCANA_PROBE_SAMPLE_ONE_WAY_ESTIMATED;
			ROW_DEC(e, 10, &v[n], delay_forward, 1000.0);
			ROW_DEC(e, 11, &v[n], delay_backward, 1000.0);
		}
		if (v[n].time != NULL)
			n++;
	}
	*np = n;
	*vp = v;
	return (0);
}

/* One metric's statistics of an interval's JSON, NULL with none. */
static int
stats_of(cbl_yarena *a, const ucl_object_t *o, const char *key,
    const struct arcana_probe_stats **sp)
{
	struct arcana_probe_stats	*s;
	const ucl_object_t		*e;

	*sp = NULL;
	if ((e = ucl_object_lookup(o, key)) == NULL)
		return (0);
	if ((s = cbl_yarena_alloc(a, sizeof(*s))) == NULL)
		return (ENOMEM);
	memset(s, 0, sizeof(*s));
	YJ_NUM(e, "count", s, count);
	YJ_NUM(e, "min", s, min);
	YJ_NUM(e, "max", s, max);
	YJ_NUM(e, "mean", s, mean);
	YJ_NUM(e, "low", s, low_percentile);
	YJ_NUM(e, "intermediate", s, intermediate_percentile);
	YJ_NUM(e, "high", s, high_percentile);
	*sp = s;
	return (0);
}

/* A count of n as RFC 9375's percentage, 5 fraction digits. */
static int64_t
pct5(int64_t lost, int64_t n)
{

	return (n > 0 ? (lost * 10000000 + n / 2) / n : 0);
}

/* A list of numbers of r's, key, as a leaf-list's. */
static int
u32s_of(cbl_yarena *a, const ucl_object_t *r, const char *key, size_t *np,
    const uint32_t **vp)
{
	const ucl_object_t	*l, *e;
	ucl_object_iter_t	 it;
	uint32_t		*v;
	size_t			 n = 0;

	l = ucl_object_lookup(r, key);
	if ((v = cbl_yarena_alloc(a, (yj_count(l) + 1) * sizeof(*v))) == NULL)
		return (ENOMEM);
	YJ_EACH(l, it, e)
		v[n++] = (uint32_t)ucl_object_toint(e);
	*np = n;
	*vp = v;
	return (0);
}

/* A target's measurement intervals (probe.c's pm_target_json()). */
static int
pm_of(cbl_yarena *a, const ucl_object_t *pm,
    const struct arcana_probe_target_state_pm **out)
{
	struct arcana_probe_target_state_pm	*p;
	struct arcana_probe_interval		*v;
	struct arcana_probe_interval_loss	*l;
	struct arcana_probe_interval_jitter	*j;
	struct arcana_probe_interval_raw	*r;
	const ucl_object_t			*e, *list, *ro;
	ucl_object_iter_t			 it;
	int64_t					 t, sent, lost;
	size_t					 n = 0;
	int					 error = 0;

	*out = NULL;
	if (pm == NULL)
		return (0);
	if ((p = cbl_yarena_alloc(a, sizeof(*p))) == NULL)
		return (ENOMEM);
	memset(p, 0, sizeof(*p));
	YJ_NUM(pm, "length", p, measurement_interval);
	p->has_low_percentile = dec(pm, "low", 3, &p->low_percentile);
	p->has_intermediate_percentile = dec(pm, "intermediate", 3,
	    &p->intermediate_percentile);
	p->has_high_percentile = dec(pm, "high", 3, &p->high_percentile);
	list = ucl_object_lookup(pm, "intervals");
	if ((v = cbl_yarena_alloc(a, (yj_count(list) + 1) * sizeof(*v))) ==
	    NULL)
		return (ENOMEM);
	YJ_EACH(list, it, e) {
		memset(&v[n], 0, sizeof(v[n]));
		if (!yj_num(e, "start", &t) || (v[n].start = datetime(a, t)) ==
		    NULL)
			continue;
		if (yj_num(e, "end", &t))
			v[n].end = datetime(a, t);
		v[n].complete = yj_yes(e, "complete", &v[n].has_complete);
		YJ_NUM(e, "sent", &v[n], sent);
		YJ_NUM(e, "received", &v[n], received);
		YJ_NUM(e, "kept", &v[n], kept);
		/* The loss, a count and a percentage of those sent; each
		 * way, where a stateful reflector told it. */
		if ((l = cbl_yarena_alloc(a, sizeof(*l))) == NULL)
			return (ENOMEM);
		memset(l, 0, sizeof(*l));
		sent = v[n].sent;
		lost = sent - v[n].received;
		l->has_count = l->has_ratio = true;
		l->count = (uint32_t)lost;
		l->ratio = pct5(lost, sent);
		if (yj_num(e, "lost_forward", &lost)) {
			l->has_forward_count = l->has_forward_ratio = true;
			l->forward_count = (uint32_t)lost;
			l->forward_ratio = pct5(lost, sent);
		}
		if (yj_num(e, "lost_backward", &lost)) {
			l->has_backward_count = l->has_backward_ratio = true;
			l->backward_count = (uint32_t)lost;
			l->backward_ratio = pct5(lost, sent);
		}
		v[n].loss = l;
		if ((j = cbl_yarena_alloc(a, sizeof(*j))) == NULL)
			return (ENOMEM);
		memset(j, 0, sizeof(*j));
		if ((error = stats_of(a, e, "rtt", &v[n].round_trip)) != 0 ||
		    (error = stats_of(a, e, "forward", &v[n].forward)) != 0 ||
		    (error = stats_of(a, e, "backward", &v[n].backward)) != 0 ||
		    (error = stats_of(a, e, "jitter_rtt", &j->round_trip)) != 0 ||
		    (error = stats_of(a, e, "jitter_forward", &j->forward)) !=
		    0 || (error = stats_of(a, e, "jitter_backward",
		    &j->backward)) != 0)
			return (error);
		if (j->round_trip != NULL || j->forward != NULL ||
		    j->backward != NULL)
			v[n].jitter = j;
		/* The last completed one's raw samples, when asked. */
		if ((ro = ucl_object_lookup(e, "raw")) != NULL) {
			if ((r = cbl_yarena_alloc(a, sizeof(*r))) == NULL)
				return (ENOMEM);
			memset(r, 0, sizeof(*r));
			if ((error = u32s_of(a, ro, "rtt", &r->round_trip.n,
			    &r->round_trip.v)) != 0 || (error = u32s_of(a, ro,
			    "forward", &r->forward.n, &r->forward.v)) != 0 ||
			    (error = u32s_of(a, ro, "backward", &r->backward.n,
			    &r->backward.v)) != 0 || (error = u32s_of(a, ro,
			    "jitter_rtt", &r->jitter_round_trip.n,
			    &r->jitter_round_trip.v)) != 0 || (error = u32s_of(a,
			    ro, "jitter_forward", &r->jitter_forward.n,
			    &r->jitter_forward.v)) != 0 || (error = u32s_of(a, ro,
			    "jitter_backward", &r->jitter_backward.n,
			    &r->jitter_backward.v)) != 0)
				return (error);
			v[n].raw = r;
		}
		n++;
	}
	p->interval.n = n;
	p->interval.v = v;
	*out = p;
	return (0);
}

int
yprobe_state_from_json(const char *json, cbl_yarena *a,
    struct arcana_probe_probes_state *out)
{
	struct arcana_probe_target_state		*v;
	struct arcana_probe_target_state_now	*nw;
	const ucl_object_t				*e, *o, *list;
	ucl_object_iter_t				 it;
	ucl_object_t					*top;
	const char					*s;
	int64_t						 n;
	size_t						 k = 0, i;
	int						 error;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	out->probing = yj_yes(top, "probing", &out->has_probing);
	if (yj_num(top, "time", &n))
		out->time = datetime(a, n);
	/* SD-WAN's targets, or the admin's monitors (do_monitors()). */
	if ((list = ucl_object_lookup(top, "targets")) == NULL)
		list = ucl_object_lookup(top, "monitors");
	if ((v = cbl_yarena_alloc(a, (yj_count(list) + 1) * sizeof(*v))) ==
	    NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	YJ_EACH(list, it, e) {
		memset(&v[k], 0, sizeof(v[k]));
		if ((v[k].id = yj_str(a, e, "id")) == NULL)
			continue;
		v[k].jail = yj_str(a, e, "jail");
		v[k].class = yj_str(a, e, "class");
		v[k].has_address = addr_union(a, e, "address", &v[k].address);
		if ((s = yj_str(a, e, "family")) != NULL) {
			v[k].has_family = true;
			v[k].family = strcmp(s, "inet6") == 0 ?
			    ARCANA_PROBE_TARGET_STATE_FAMILY_IPV6 :
			    ARCANA_PROBE_TARGET_STATE_FAMILY_IPV4;
		}
		YJ_NUM(e, "fib", &v[k], fib);
		if ((s = yj_str(a, e, "state")) != NULL)
			for (i = 0; i < nitems(states); i++)
				if (strcmp(s, states[i]) == 0) {
					v[k].has_state = true;
					v[k].state = (int)i;
				}
		v[k].error = yj_str(a, e, "error");
		if (yj_num(e, "since", &n))
			v[k].since = datetime(a, n);
		YJ_NUM(e, "interval", &v[k], interval);
		YJ_NUM(e, "size", &v[k], size);
		YJ_NUM(e, "eval", &v[k], eval);
		YJ_NUM(e, "dscp", &v[k], dscp);
		YJ_NUM(e, "sent", &v[k], sent);
		YJ_NUM(e, "received", &v[k], received);
		YJ_NUM(e, "misses", &v[k], misses);
		v[k].has_last_rtt = dec(e, "last_rtt", 3, &v[k].last_rtt);
		if ((o = ucl_object_lookup(e, "now")) != NULL) {
			if ((nw = cbl_yarena_alloc(a, sizeof(*nw))) == NULL) {
				ucl_object_unref(top);
				return (ENOMEM);
			}
			memset(nw, 0, sizeof(*nw));
			YJ_NUM(o, "sent", nw, sent);
			YJ_NUM(o, "recv", nw, received);
			nw->has_delay = dec(o, "delay", 3, &nw->delay);
			nw->has_ipdv = dec(o, "ipdv", 3, &nw->ipdv);
			nw->has_loss = dec(o, "loss", 6, &nw->loss);
			nw->has_age = dec(o, "age", 3, &nw->age);
			v[k].now = nw;
		}
		YJ_NUM(e, "kept", &v[k], kept);
		if ((error = samples_of(a, ucl_object_lookup(e, "samples"),
		    &v[k].sample.n, &v[k].sample.v)) != 0 ||
		    (error = pm_of(a, ucl_object_lookup(e, "pm"), &v[k].pm)) !=
		    0) {
			ucl_object_unref(top);
			return (error);
		}
		k++;
	}
	out->target.n = k;
	out->target.v = v;
	ucl_object_unref(top);
	return (0);
}

/* A name of RFC 8972's Sync Source registry (stamp_sync_name()) as
 * arcana-stamp's clock-source, its enums' order: ntp, ptp, ssu, gnss,
 * local, unknown. */
static int
sync_of(const char *s)
{
	static const char *const n[] = { "ntp", "ptp", "ssu", "gnss",
	    "local" };

	for (size_t i = 0; s != NULL && i < nitems(n); i++)
		if (strcmp(s, n[i]) == 0)
			return ((int)i);
	return ((int)nitems(n));
}

/* A Timestamp Method's name (stamp_tsm_name()): hw, sw, control,
 * unknown. */
static int
tsm_of(const char *s)
{

	if (s == NULL)
		return (3);
	return (strcmp(s, "hw") == 0 ? 0 : strcmp(s, "sw") == 0 ? 1 :
	    strcmp(s, "cp") == 0 ? 2 : 3);
}

/* An address of o's, key, into an inet:ip-address-no-zone union. */
#define	ADDR_OF(a, o, key, y, f)	do {				\
	const char *s_;							\
									\
	if (((y)->has_##f = (s_ = yj_str((a), (o), (key))) != NULL)) {	\
		(y)->f.which = strchr(s_, ':') != NULL ? 1 : 0;		\
		(y)->f.v.m0 = s_;					\
	}								\
} while (0)

/* One target of the probes' read as its session. */
static int
session_of(cbl_yarena *a, const ucl_object_t *e, struct arcana_stamp_session *s)
{
	struct arcana_stamp_session_delay	*d;
	struct arcana_stamp_session_timestamp_info *ti;
	struct arcana_stamp_session_dscp	*ds;
	struct arcana_stamp_session_location	*lo;
	struct arcana_stamp_session_counters	*c;
	const ucl_object_t			*o;
	const char				*v;

	s->target = yj_str(a, e, "id");
	s->jail = yj_str(a, e, "jail");
	s->class = yj_str(a, e, "class");
	if ((v = yj_str(a, e, "kind")) != NULL) {
		s->has_kind = true;
		s->kind = strcmp(v, "stamp") == 0 ?
		    ARCANA_STAMP_SESSION_KIND_STAMP : strcmp(v, "icmp") == 0 ?
		    ARCANA_STAMP_SESSION_KIND_ICMP :
		    ARCANA_STAMP_SESSION_KIND_AUTO;
	}
	if ((v = yj_str(a, e, "method")) != NULL) {
		s->has_method = true;
		s->method = strcmp(v, "stamp") == 0 ?
		    ARCANA_STAMP_SESSION_METHOD_STAMP :
		    ARCANA_STAMP_SESSION_METHOD_ICMP;
	}
	s->reason = yj_str(a, e, "reason");
	ADDR_OF(a, e, "address", s, reflector_address);
	YJ_NUM(e, "reflector_port", s, reflector_udp_port);
	YJ_NUM(e, "fib", s, fib);
	YJ_NUM(e, "ssid", s, ssid);
	s->has_reflector_mode = true;
	v = yj_str(a, e, "reflector");
	s->reflector_mode = v != NULL && strcmp(v, "stateful") == 0 ?
	    ARCANA_STAMP_SESSION_REFLECTOR_MODE_STATEFUL : v != NULL &&
	    strcmp(v, "stateless") == 0 ?
	    ARCANA_STAMP_SESSION_REFLECTOR_MODE_STATELESS :
	    ARCANA_STAMP_SESSION_REFLECTOR_MODE_UNKNOWN;
	s->authenticated = yj_yes(e, "authenticated", &s->has_authenticated);
	s->key_error = yj_str(a, e, "key_error");
	if ((d = cbl_yarena_alloc(a, sizeof(*d))) == NULL ||
	    (ti = cbl_yarena_alloc(a, sizeof(*ti))) == NULL ||
	    (ds = cbl_yarena_alloc(a, sizeof(*ds))) == NULL ||
	    (lo = cbl_yarena_alloc(a, sizeof(*lo))) == NULL ||
	    (c = cbl_yarena_alloc(a, sizeof(*c))) == NULL)
		return (ENOMEM);
	memset(d, 0, sizeof(*d));
	memset(ti, 0, sizeof(*ti));
	memset(ds, 0, sizeof(*ds));
	memset(lo, 0, sizeof(*lo));
	memset(c, 0, sizeof(*c));
	/* The last reply's delay, when by STAMP. */
	if ((v = yj_str(a, e, "one_way")) != NULL) {
		d->has_rtt = dec(e, "last_rtt", 3, &d->rtt);
		d->has_forward = dec(e, "forward_delay", 3, &d->forward);
		d->has_backward = dec(e, "backward_delay", 3, &d->backward);
		d->has_one_way = true;
		d->one_way = strcmp(v, "measured") == 0 ?
		    ARCANA_STAMP_SESSION_DELAY_ONE_WAY_MEASURED :
		    ARCANA_STAMP_SESSION_DELAY_ONE_WAY_ESTIMATED;
		d->has_clock_error = dec(e, "clock_error", 3, &d->clock_error);
		s->delay = d;
	}
	if ((o = ucl_object_lookup(e, "timestamp_info")) != NULL) {
		ti->has_sync_in = ti->has_timestamp_in = true;
		ti->has_sync_out = ti->has_timestamp_out = true;
		ti->sync_in = sync_of(yj_str(a, o, "sync_in"));
		ti->timestamp_in = tsm_of(yj_str(a, o, "timestamp_in"));
		ti->sync_out = sync_of(yj_str(a, o, "sync_out"));
		ti->timestamp_out = tsm_of(yj_str(a, o, "timestamp_out"));
		s->timestamp_info = ti;
	}
	YJ_NUM(e, "dscp", ds, sent);
	YJ_NUM(e, "dscp_forward", ds, forward);
	YJ_NUM(e, "dscp_backward", ds, backward);
	ds->refused = yj_yes(e, "dscp_refused", &ds->has_refused);
	s->dscp = ds;
	if ((v = yj_str(a, e, "nat")) != NULL) {
		ADDR_OF(a, e, "seen_source_addr", lo, source_address);
		YJ_NUM(e, "seen_source_port", lo, source_port);
		ADDR_OF(a, e, "seen_destination_addr", lo, destination_address);
		YJ_NUM(e, "seen_destination_port", lo, destination_port);
		lo->has_nat = true;
		lo->nat = strcmp(v, "source") == 0 ?
		    ARCANA_STAMP_SESSION_LOCATION_NAT_SOURCE : strcmp(v,
		    "destination") == 0 ?
		    ARCANA_STAMP_SESSION_LOCATION_NAT_DESTINATION : strcmp(v,
		    "both") == 0 ? ARCANA_STAMP_SESSION_LOCATION_NAT_BOTH :
		    ARCANA_STAMP_SESSION_LOCATION_NAT_NONE;
		s->location = lo;
	}
	if ((o = ucl_object_lookup(e, "stamp_counters")) != NULL) {
		YJ_NUM(o, "sent", c, sent);
		YJ_NUM(o, "received", c, received);
		YJ_NUM(o, "lost", c, lost);
		YJ_NUM(o, "lost_forward", c, lost_forward);
		YJ_NUM(o, "lost_backward", c, lost_backward);
		YJ_NUM(o, "lost_unknown", c, lost_unknown);
		YJ_NUM(o, "dm_lost_forward", c, dm_lost_forward);
		YJ_NUM(o, "dm_lost_backward", c, dm_lost_backward);
		YJ_NUM(o, "late", c, late);
		YJ_NUM(o, "auth_failed", c, auth_failed);
		YJ_NUM(o, "refused", c, refused);
		YJ_NUM(o, "fallbacks", c, fallbacks);
		s->counters = c;
	}
	return (0);
}

int
ystamp_sessions_from_json(const char *json, cbl_yarena *a,
    struct arcana_stamp_stamp *out)
{
	struct arcana_stamp_session	*v;
	const ucl_object_t		*e, *list;
	ucl_object_iter_t		 it;
	ucl_object_t			*top;
	size_t				 k = 0;
	int				 error = 0;

	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	list = ucl_object_lookup(top, "targets");
	if ((v = cbl_yarena_alloc(a, (yj_count(list) + 1) * sizeof(*v))) ==
	    NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	/* A target STAMP measures, or may (auto fallen back): one with
	 * the reflector's port said (probe.c's target_json()). */
	YJ_EACH(list, it, e) {
		if (ucl_object_lookup(e, "reflector_port") == NULL ||
		    yj_str(a, e, "id") == NULL)
			continue;
		memset(&v[k], 0, sizeof(v[k]));
		if ((error = session_of(a, e, &v[k])) != 0)
			break;
		k++;
	}
	out->session.n = k;
	out->session.v = v;
	ucl_object_unref(top);
	return (error);
}
