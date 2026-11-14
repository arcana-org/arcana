/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula, the prober as its readers see it: the snapshot the engine
 * publishes (snap_publish(), probe_engine.c says when), every target a
 * copy taken whole at once, its samples and intervals the rows of that
 * moment (shared, never written again: probe_pm.c), its STAMP sender's
 * counts then.  A reader takes the snapshot (snap_get()) under snap_mtx,
 * a pointer and a count, and reads it at leisure, the engine publishing
 * the next meanwhile; the last to let one go frees it.  So a read never
 * holds up the probes, and never sees a target half changed, nor a
 * table half swapped.
 *
 * What is read here: arcana-probe's state (do_probes_read(), the YANG
 * side gula/yprobe.c), the monitors (do_monitors()), a target's state
 * and last sample for the steering (invidia/sdwan.c), the FIBs and the
 * STAMP keys stampd needs (gula/stampd.c), the configuration as
 * arcana-probe has it (probe_conf_json()), and each edge's interfaces'
 * counters and FIBs' routes (probe_edges_json()).
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <ucl.h>

#include "agent.h"
#include "stamp.h"
#include "probe_int.h"

static const char *const pm_names[] = { "rtt", "forward", "backward",
    "jitter_rtt", "jitter_forward", "jitter_backward" };

static pthread_mutex_t	 snap_mtx = PTHREAD_MUTEX_INITIALIZER;
static struct snap	*snap;		/* the last published, or none */

/* ---- The snapshot --------------------------------------------------- */

static void
view_rows(struct rowsview *v, struct rows *r)
{

	v->s = rows_snap(r);
	v->lo = r->lo;
	v->hi = r->hi;
	v->esz = r->esz;
	v->per = r->per;
}

/* A target as the readers see it: nothing in its copy the engine's. */
static void
view_make(struct tview *v, struct target *t)
{

	memcpy(&v->t, t, sizeof(*t));
	v->has_st = t->ss != NULL;
	if (v->has_st)
		stamp_sender_stats(t->ss, &v->st);
	else
		memset(&v->st, 0, sizeof(v->st));
	v->t.ss = NULL;
	view_rows(&v->samp, &t->samp);
	view_rows(&v->raw, &t->pm_raw);
	view_rows(&v->last, &t->pm_last);
	view_rows(&v->done, &t->pm_done);
	memset(&v->t.samp, 0, sizeof(v->t.samp));
	memset(&v->t.pm_raw, 0, sizeof(v->t.pm_raw));
	memset(&v->t.pm_last, 0, sizeof(v->t.pm_last));
	memset(&v->t.pm_done, 0, sizeof(v->t.pm_done));
	explicit_bzero(&v->t.was, sizeof(v->t.was));
}

/*
 * The table (n targets of v) published for the readers, the one before
 * let go; probing, whether the prober runs.  By the table's owner: the
 * engine, or before it runs the asker under req_mtx.
 */
void
snap_publish(struct target *v, int n, bool probing)
{
	struct snap	*s, *old;

	if ((s = malloc(sizeof(*s) + (size_t)n * sizeof(s->v[0]))) == NULL)
		return;
	atomic_init(&s->ref, 1);
	s->probing = probing;
	s->n = n;
	for (int i = 0; i < n; i++)
		view_make(&s->v[i], &v[i]);
	pthread_mutex_lock(&snap_mtx);
	old = snap;
	snap = s;
	pthread_mutex_unlock(&snap_mtx);
	snap_put(old);
}

/* The last snapshot, held until snap_put(); NULL before the first. */
struct snap *
snap_get(void)
{
	struct snap	*s;

	pthread_mutex_lock(&snap_mtx);
	if ((s = snap) != NULL)
		atomic_fetch_add(&s->ref, 1);
	pthread_mutex_unlock(&snap_mtx);
	return (s);
}

void
snap_put(struct snap *s)
{

	if (s == NULL || atomic_fetch_sub(&s->ref, 1) != 1)
		return;
	for (int i = 0; i < s->n; i++) {
		rowsnap_put(s->v[i].samp.s);
		rowsnap_put(s->v[i].raw.s);
		rowsnap_put(s->v[i].last.s);
		rowsnap_put(s->v[i].done.s);
		explicit_bzero(&s->v[i].t.key, sizeof(s->v[i].t.key));
	}
	free(s);
}

/* ---- Measurement intervals as JSON ---------------------------------- */

static void
pm_put_stats(ucl_object_t *o, const char *key, const struct target *t,
    const struct pm_stats *s)
{
	static const char *const pn[] = { "low", "intermediate", "high" };
	ucl_object_t	*c;

	if (s->n == 0)
		return;
	c = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(c, ucl_object_fromint(s->n), "count", 0, false);
	ucl_object_insert_key(c, ucl_object_fromint((int64_t)s->min), "min", 0,
	    false);
	ucl_object_insert_key(c, ucl_object_fromint((int64_t)s->max), "max", 0,
	    false);
	ucl_object_insert_key(c, ucl_object_fromint((int64_t)s->mean), "mean",
	    0, false);
	for (int i = 0; i < 3; i++)
		if (t->pct[i] > 0)
			ucl_object_insert_key(c, ucl_object_fromint((int64_t)
			    s->p[i]), pn[i], 0, false);
	ucl_object_insert_key(o, c, key, 0, false);
}

/* An interval as JSON; with raw, its raw samples too. */
static ucl_object_t *
pm_json(const struct target *t, const struct pm *p, bool complete,
    const struct rowsrc *raw)
{
	const struct pm_raw	*r;
	ucl_object_t		*o, *ro, *l;
	uint64_t		 i;
	int			 m;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromint(p->start), "start", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(p->end), "end", 0, false);
	ucl_object_insert_key(o, ucl_object_frombool(complete), "complete", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(p->sent), "sent", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(p->recv), "received", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(p->kept), "kept", 0, false);
	if (p->lost_fwd >= 0) {
		ucl_object_insert_key(o, ucl_object_fromint(p->lost_fwd),
		    "lost_forward", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(p->lost_back),
		    "lost_backward", 0, false);
	}
	for (m = 0; m < PM_NM; m++)
		pm_put_stats(o, pm_names[m], t, &p->st[m]);
	if (raw != NULL) {
		ro = ucl_object_typed_new(UCL_OBJECT);
		for (m = 0; m < PM_NM; m++) {
			l = ucl_object_typed_new(UCL_ARRAY);
			for (i = raw->lo; i < raw->hi; i++) {
				r = rowsrc_at(raw, i);
				if (r->v[m] >= 0)
					ucl_array_append(l, ucl_object_fromint(
					    r->v[m]));
			}
			ucl_object_insert_key(ro, l, pm_names[m], 0, false);
		}
		ucl_object_insert_key(o, ro, "raw", 0, false);
	}
	return (o);
}

/* Its measurement intervals as JSON: the percentiles, the length, the
 * completed ones ended after the time after (the last always, with its
 * raw samples when raw), the running one after them. */
static ucl_object_t *
pm_target_json(const struct tview *v, uint64_t after, bool raw)
{
	const struct target	*t = &v->t;
	const struct pm		*p;
	struct rowsrc		 done, last, run;
	ucl_object_t		*o, *arr;
	struct pm		 now;
	uint64_t		 k;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromdouble(t->pct[0]), "low", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromdouble(t->pct[1]),
	    "intermediate", 0, false);
	ucl_object_insert_key(o, ucl_object_fromdouble(t->pct[2]), "high", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(t->pm_len), "length", 0,
	    false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	rowsview_src(&v->done, &done);
	rowsview_src(&v->last, &last);
	for (k = done.lo; k < done.hi; k++) {
		p = rowsrc_at(&done, k);
		if ((uint64_t)p->end <= after && k != done.hi - 1)
			continue;
		ucl_array_append(arr, pm_json(t, p, true, raw && k ==
		    done.hi - 1 ? &last : NULL));
	}
	if (t->pm_start != 0) {
		rowsview_src(&v->raw, &run);
		pm_now(t, v->has_st ? &v->st : NULL, &run, &now);
		ucl_array_append(arr, pm_json(t, &now, false, NULL));
	}
	ucl_object_insert_key(o, arr, "intervals", 0, false);
	return (o);
}

/* ---- A target as JSON ----------------------------------------------- */

/* An address and its port as o's key_addr and key_port. */
static void
loc_put(ucl_object_t *o, const char *key, const struct sockaddr_storage *ss)
{
	char	a[INET6_ADDRSTRLEN], k[48];

	if (ss->ss_family == 0)
		return;
	snprintf(k, sizeof(k), "%s_addr", key);
	ucl_object_insert_key(o, ucl_object_fromstring(stamp_sa_ntop((const
	    struct sockaddr *)ss, a, sizeof(a))), k, 0, true);
	snprintf(k, sizeof(k), "%s_port", key);
	ucl_object_insert_key(o, ucl_object_fromint(stamp_sa_port((const struct
	    sockaddr *)ss)), k, 0, true);
}

/* A target as JSON: what it is, its state, the sample in progress and
 * those kept after the time after, its measurement intervals (with raw,
 * the last completed one's raw samples). */
static ucl_object_t *
target_json(const struct tview *v, double now, uint64_t after, bool raw)
{
	const struct target	*t = &v->t;
	const struct sample	*sm;
	struct rowsrc		 samp;
	ucl_object_t		*o, *s, *row, *cur;
	uint64_t		 k, from;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(t->id), "id", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromstring(t->address),
	    "address", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(t->af == AF_INET ?
	    "inet" : "inet6"), "family", 0, false);
	if (t->cls[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromstring(t->cls), "class",
		    0, false);
	if (t->jail[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromstring(t->jail),
		    "jail", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->fib), "fib", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromstring(state_names[
	    t->state]), "state", 0, false);
	if (t->error[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromstring(t->error),
		    "error", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->since), "since",
	    0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->interval),
	    "interval", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->size), "size", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(t->eval), "eval", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(t->dscp), "dscp", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)t->sent),
	    "sent", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)
	    t->received), "received", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->misses), "misses",
	    0, false);
	ucl_object_insert_key(o, ucl_object_fromdouble(t->last_rtt),
	    "last_rtt", 0, false);
	/* How it is measured: its kind, and now STAMP to Arcana's far end
	 * or an echo; of STAMP, arcana-stamp's session (gula/yprobe.c). */
	ucl_object_insert_key(o, ucl_object_fromstring(kind_names[t->kind]),
	    "kind", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(t->by_stamp ? "stamp" :
	    "icmp"), "method", 0, false);
	if (t->arcana) {
		struct stamp_sender_stats	st;
		uint64_t			af = t->auth_failed;
		uint64_t			fl = t->fwd_lost, bl = t->back_lost;
		uint64_t			dmf = t->dm_fwd_lost;
		uint64_t			dmb = t->dm_back_lost;
		bool				dm = t->dm_told;

		memset(&st, 0, sizeof(st));
		if (v->has_st) {
			st = v->st;
			ucl_object_insert_key(o, ucl_object_fromstring(
			    stamp_mode_name(st.mode)), "reflector", 0, false);
			af += st.auth_failed;
			/* What the sender has that no window took yet. */
			fl += st.fwd_lost - t->tk_fwd;
			bl += st.back_lost - t->tk_back;
			if (st.dm_told) {
				dmf += st.dm_fwd_lost - t->tk_dmf;
				dmb += st.dm_back_lost - t->tk_dmb;
				dm = true;
			}
		}
		if (t->stamp_why[0] != '\0')
			ucl_object_insert_key(o, ucl_object_fromstring(
			    t->stamp_why), "reason", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(opts.stamp_port),
		    "reflector_port", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(t->keyed ?
		    (int64_t)t->key.ssid : (int64_t)t->ssid), "ssid", 0, false);
		/* Its counts all along, every sender's. */
		cur = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)
		    (t->st_sent + st.sent)), "sent", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)
		    (t->st_recv + st.received)), "received", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)
		    (t->st_lost + st.lost)), "lost", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)fl),
		    "lost_forward", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)bl),
		    "lost_backward", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)
		    (t->st_unknown + st.unknown_lost)), "lost_unknown", 0, false);
		if (dm) {
			ucl_object_insert_key(cur, ucl_object_fromint((int64_t)
			    dmf), "dm_lost_forward", 0, false);
			ucl_object_insert_key(cur, ucl_object_fromint((int64_t)
			    dmb), "dm_lost_backward", 0, false);
		}
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)
		    (t->st_late + st.late)), "late", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)af),
		    "auth_failed", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)
		    t->refused), "refused", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)
		    t->fallbacks), "fallbacks", 0, false);
		ucl_object_insert_key(o, cur, "stamp_counters", 0, false);
		/* A plain tunnel's: authenticated, its replies that were
		 * not, why there is no key yet. */
		ucl_object_insert_key(o, ucl_object_frombool(t->keyed),
		    "authenticated", 0, false);
		if (t->stamp_peer[0] != '\0') {
			ucl_object_insert_key(o, ucl_object_fromint((int64_t)af),
			    "auth_failed", 0, false);
			if (!t->keyed && t->key_err[0] != '\0')
				ucl_object_insert_key(o, ucl_object_fromstring(
				    t->key_err), "key_error", 0, false);
		}
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)fl),
		    "forward_lost", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)bl),
		    "backward_lost", 0, false);
		/* The last reply's delay each way: one way, or half its
		 * round trip ("estimated"); the reflector's clock. */
		if (t->by_stamp && t->has_delay) {
			ucl_object_insert_key(o, ucl_object_fromdouble(
			    t->last_dfwd), "forward_delay", 0, false);
			ucl_object_insert_key(o, ucl_object_fromdouble(
			    t->last_dback), "backward_delay", 0, false);
			ucl_object_insert_key(o, ucl_object_fromstring(
			    t->last_owd ? "measured" : "estimated"), "one_way",
			    0, false);
			ucl_object_insert_key(o, ucl_object_fromdouble(
			    t->last_err), "clock_error", 0, false);
		}
		/* The DSCP each way as the last reply saw it: the probe's
		 * at the reflector, the reply's here. */
		if (t->by_stamp && t->has_cos) {
			ucl_object_insert_key(o, ucl_object_fromint(
			    t->dscp_fwd), "dscp_forward", 0, false);
			ucl_object_insert_key(o, ucl_object_frombool(
			    t->dscp_refused), "dscp_refused", 0, false);
		}
		if (t->by_stamp && t->has_rtos)
			ucl_object_insert_key(o, ucl_object_fromint(
			    t->dscp_back), "dscp_backward", 0, false);
		/* The far end's view of the probe's addresses, a NAT. */
		if (t->has_loc) {
			char	ap[96];

			ucl_object_insert_key(o, ucl_object_fromstring(
			    addr_port(&t->loc.src, ap, sizeof(ap))),
			    "seen_source", 0, true);
			ucl_object_insert_key(o, ucl_object_fromstring(
			    addr_port(&t->loc.dst, ap, sizeof(ap))),
			    "seen_destination", 0, true);
			/* The same apart, arcana-stamp's location. */
			loc_put(o, "seen_source", &t->loc.src);
			loc_put(o, "seen_destination", &t->loc.dst);
			ucl_object_insert_key(o, ucl_object_fromstring(
			    t->nat == 0 ? "none" : t->nat == STAMP_NAT_SRC ?
			    "source" : t->nat == STAMP_NAT_DST ? "destination" :
			    "both"), "nat", 0, false);
		}
		/* The loss each way by the counters, all along. */
		if (dm) {
			ucl_object_insert_key(o, ucl_object_fromint((int64_t)
			    dmf), "dm_forward_lost", 0, false);
			ucl_object_insert_key(o, ucl_object_fromint((int64_t)
			    dmb), "dm_backward_lost", 0, false);
		}
		if (t->has_ti) {
			cur = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(cur, ucl_object_fromstring(
			    stamp_sync_name(t->ti.sync_in)), "sync_in", 0, true);
			ucl_object_insert_key(cur, ucl_object_fromstring(
			    stamp_tsm_name(t->ti.ts_in)), "timestamp_in", 0,
			    true);
			ucl_object_insert_key(cur, ucl_object_fromstring(
			    stamp_sync_name(t->ti.sync_out)), "sync_out", 0,
			    true);
			ucl_object_insert_key(cur, ucl_object_fromstring(
			    stamp_tsm_name(t->ti.ts_out)), "timestamp_out", 0,
			    true);
			ucl_object_insert_key(o, cur, "timestamp_info", 0,
			    false);
		}
	}
	/* The interval in progress, so far. */
	cur = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(cur, ucl_object_fromint(t->w_sent), "sent",
	    0, false);
	ucl_object_insert_key(cur, ucl_object_fromint(t->w_recv), "recv",
	    0, false);
	ucl_object_insert_key(cur, ucl_object_fromdouble(t->w_recv > 0 ?
	    t->w_sum / t->w_recv / 2 : 0), "delay", 0, false);
	ucl_object_insert_key(cur, ucl_object_fromdouble(t->w_ipdv_n >
	    0 ? t->w_ipdv_sum / t->w_ipdv_n : 0), "ipdv", 0, false);
	ucl_object_insert_key(cur, ucl_object_fromdouble(t->w_sent > 0 ?
	    (double)(t->w_sent - t->w_recv) / t->w_sent : 0), "loss", 0,
	    false);
	ucl_object_insert_key(cur, ucl_object_fromdouble(now -
	    t->win_start), "age", 0, false);
	ucl_object_insert_key(o, cur, "now", 0, false);
	/* The samples, the oldest first: t, delay, ipdv, loss, min,
	 * max, sent, received, the loss forward and backward (-1 not
	 * told: not by a stateful reflector), and the delay forward and
	 * backward with how (1 one way, 0 half the round trip, -1 not by
	 * STAMP: -1 each); the last report * eval ms are the report's. */
	s = ucl_object_typed_new(UCL_ARRAY);
	rowsview_src(&v->samp, &samp);
	from = samp.hi - samp.lo > 3600 ? samp.hi - 3600 : samp.lo;
	for (k = from; k < samp.hi; k++) {
		sm = rowsrc_at(&samp, k);
		if ((uint64_t)sm->t <= after)
			continue;
		row = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(row, ucl_object_fromint((int64_t)
		    sm->t));
		ucl_array_append(row, ucl_object_fromdouble(sm->delay));
		ucl_array_append(row, ucl_object_fromdouble(sm->ipdv));
		ucl_array_append(row, ucl_object_fromdouble(sm->loss));
		ucl_array_append(row, ucl_object_fromdouble(sm->min));
		ucl_array_append(row, ucl_object_fromdouble(sm->max));
		ucl_array_append(row, ucl_object_fromint(sm->sent));
		ucl_array_append(row, ucl_object_fromint(sm->recv));
		ucl_array_append(row, ucl_object_fromdouble(sm->fwd));
		ucl_array_append(row, ucl_object_fromdouble(sm->back));
		ucl_array_append(row, ucl_object_fromdouble(sm->dfwd));
		ucl_array_append(row, ucl_object_fromdouble(sm->dback));
		ucl_array_append(row, ucl_object_fromint(sm->owd));
		ucl_array_append(s, row);
	}
	ucl_object_insert_key(o, s, "samples", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)(samp.hi -
	    samp.lo)), "kept", 0, false);
	ucl_object_insert_key(o, pm_target_json(v, after, raw), "pm", 0,
	    false);
	if (t->ifname[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromstring(t->ifname),
		    "interface", 0, false);
	if (t->tca[0] > 0 || t->tca[1] > 0 || t->tca[2] > 0) {
		cur = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(cur, ucl_object_fromdouble(t->tca[0]),
		    "delay", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromdouble(t->tca[1]),
		    "ipdv", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromdouble(t->tca[2]),
		    "loss", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint(t->damping),
		    "damping", 0, false);
		ucl_object_insert_key(o, cur, "tca", 0, false);
	}
	ucl_object_insert_key(o, ucl_object_fromint(t->history), "history", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(t->down), "down", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(t->up), "up", 0, false);
	return (o);
}

static int
json_reply(struct work *w, ucl_object_t *top, struct json_rsp *rsp)
{
	unsigned char	*json;

	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	rsp->has_ok = true;
	if (json == NULL) {
		rsp->ok = false;
		rsp->error = "no memory";
		return (0);
	}
	rsp->json = wadopt(w, (char *)json);
	rsp->ok = true;
	return (0);
}

/* The SD-WAN targets, or the monitors (mon), of the snapshot as JSON
 * {key: [...], "time", "probing"}. */
static int
targets_read(struct work *w, bool mon, const char *key, uint64_t after,
    bool raw, struct json_rsp *rsp)
{
	struct snap	*s;
	ucl_object_t	*top, *arr;
	double		 now;
	int		 i;

	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	now = now_s();
	s = snap_get();
	for (i = 0; s != NULL && i < s->n; i++)
		if (is_monitor(&s->v[i].t) == mon)
			ucl_array_append(arr, target_json(&s->v[i], now, after,
			    raw));
	ucl_object_insert_key(top, arr, key, 0, false);
	ucl_object_insert_key(top, ucl_object_fromint(time(NULL)), "time", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_frombool(s != NULL &&
	    s->probing), "probing", 0, false);
	snap_put(s);
	return (json_reply(w, top, rsp));
}

/*
 * What the probes have seen, as JSON, arcana-probe's state: the SD-WAN
 * targets (with after, only the samples and the measurement intervals
 * after that time; with raw, each one's last completed interval's raw
 * samples), when, and whether the prober runs.  The admin's monitors
 * are read apart (do_monitors()).
 */
int
do_probes_read(struct work *w, uint64_t after, bool raw, struct json_rsp *rsp)
{

	return (targets_read(w, false, "targets", after, raw, rsp));
}

/* What the monitors have seen, as JSON, the host's and the jails'. */
int
do_monitors(struct work *w, uint64_t after, struct json_rsp *rsp)
{

	return (targets_read(w, true, "monitors", after, false, rsp));
}

/*
 * The SD-WAN edge as it is, as JSON, arcana-sdwan's state: the rules
 * and the steering, the services' instances, the record, the keys and
 * the faults.
 */
int
do_sdwan_state(struct work *w, struct json_rsp *rsp)
{
	ucl_object_t	*top;

	top = ucl_object_typed_new(UCL_OBJECT);
	sdwan_json(w, top);
	sdwan_bird_json(w, top);
	sdwan_dhcp_json(w, top);
	sdwan_dns_json(w, top);
	sdwan_proxy_json(w, top);
	sdwan_ids_json(w, top);
	record_json(top);
	sa_keys_json(w, top);
	faults_json(top);
	return (json_reply(w, top, rsp));
}

/* ---- The steering's and stampd's ------------------------------------ */

/* A target's state by its edge (jail, "" the host) and id; PROBE_NONE
 * when it is none. */
int
probe_state_of(const char *jail, const char *id)
{
	const struct target	*t;
	struct snap		*s;
	int			 i, st;

	st = PROBE_NONE;
	s = snap_get();
	for (i = 0; s != NULL && i < s->n; i++) {
		t = &s->v[i].t;
		if (!is_monitor(t) && t->cls[0] == '\0' && strcmp(t->jail,
		    jail) == 0 && strcmp(t->id, id) == 0) {
			st = t->state;
			break;
		}
	}
	snap_put(s);
	return (st);
}

/* A target's last sample's delay, delay variation and loss; false when
 * it is none or has none. */
bool
probe_sample_of(const char *jail, const char *id, double *delay,
    double *ipdv, double *loss)
{
	const struct target	*t;
	const struct sample	*sm;
	struct rowsrc		 src;
	struct snap		*s;
	bool			 ok = false;
	int			 i;

	s = snap_get();
	for (i = 0; s != NULL && i < s->n; i++) {
		t = &s->v[i].t;
		if (is_monitor(t) || t->cls[0] != '\0' || strcmp(t->jail, jail) !=
		    0 || strcmp(t->id, id) != 0)
			continue;
		rowsview_src(&s->v[i].samp, &src);
		if (src.hi > src.lo) {
			sm = rowsrc_at(&src, src.hi - 1);
			*delay = sm->delay;
			*ipdv = sm->ipdv;
			*loss = sm->loss;
			ok = true;
		}
		break;
	}
	snap_put(s);
	return (ok);
}

/* The STAMP keys of the host's plain tunnels' targets, each once, in
 * the targets' order, into v (max of them), and with names the name of
 * the first target of each into names[] (PROBE_NAME_MAX each): the
 * reflector's copies, stampd's key file (gula/stampd.c), of one
 * snapshot, so a set the engine had at once.  The caller zeroes them. */
int
probe_stamp_keys(struct stamp_key *v, char (*names)[PROBE_NAME_MAX],
    int max)
{
	const struct target	*t;
	struct snap		*s;
	int			 i, k, n;

	n = 0;
	s = snap_get();
	for (i = 0; s != NULL && i < s->n && n < max; i++) {
		t = &s->v[i].t;
		if (t->jail[0] != '\0' || !t->keyed)
			continue;
		for (k = 0; k < n && memcmp(&v[k], &t->key, sizeof(v[k])) != 0;
		    k++)
			;
		if (k < n)
			continue;
		if (names != NULL)
			(void)target_name(t, names[n], PROBE_NAME_MAX);
		v[n++] = t->key;
	}
	snap_put(s);
	return (n);
}

/* The FIBs the host's targets are probed in, each once, into v (max
 * of them): stampd answers there (gula/stampd.c). */
int
probe_fibs(int *v, int max)
{
	const struct target	*t;
	struct snap		*s;
	int			 i, k, n;

	n = 0;
	s = snap_get();
	for (i = 0; s != NULL && i < s->n && n < max; i++) {
		t = &s->v[i].t;
		if (t->jail[0] != '\0')
			continue;
		for (k = 0; k < n && v[k] != t->fib; k++)
			;
		if (k == n)
			v[n++] = t->fib;
	}
	snap_put(s);
	return (n);
}

/* ---- The configuration as arcana-probe has it ----------------------- */

/* A target's settings, as targets_parse takes them back. */
ucl_object_t *
target_conf(const struct target *t)
{
	ucl_object_t	*o, *tc;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(t->id), "id", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(t->address), "address",
	    0, false);
	if (t->ifname[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromstring(t->ifname),
		    "interface", 0, false);
	if (t->kind != KIND_AUTO)
		ucl_object_insert_key(o, ucl_object_fromstring(
		    kind_names[t->kind]), "kind", 0, false);
	if (t->underlay)
		ucl_object_insert_key(o, ucl_object_frombool(true), "underlay",
		    0, false);
	if (t->stamp_peer[0] != '\0') {
		ucl_object_insert_key(o, ucl_object_fromstring(t->stamp_if),
		    "stamp_interface", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(t->stamp_peer),
		    "stamp_peer", 0, false);
	}
	ucl_object_insert_key(o, ucl_object_fromint(t->fib), "fib", 0, false);
	if (!is_monitor(t)) {
		ucl_object_insert_key(o, ucl_object_fromint(t->count), "count",
		    0, false);
		ucl_object_insert_key(o, ucl_object_fromint(t->report),
		    "report", 0, false);
	}
	ucl_object_insert_key(o, ucl_object_fromint(t->interval), "interval",
	    0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->size), "size", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->dscp), "dscp", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->down), "down", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->up), "up", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->timeout), "timeout", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(t->eval), "eval", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->history), "history", 0,
	    false);
	if (t->pm_len != PM_LEN)
		ucl_object_insert_key(o, ucl_object_fromint(t->pm_len),
		    "measurement_interval", 0, false);
	/* Its measurement intervals' percentiles, where not the defaults. */
	{
		static const char *const pk[] = { "low_percentile",
		    "intermediate_percentile", "high_percentile" };
		static const double pd[] = { 10, 50, 90 };

		for (int k = 0; k < 3; k++)
			if (t->pct[k] != pd[k])
				ucl_object_insert_key(o, ucl_object_fromdouble(
				    t->pct[k]), pk[k], 0, false);
	}
	if (t->tca[0] > 0 || t->tca[1] > 0 || t->tca[2] > 0) {
		tc = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(tc, ucl_object_fromdouble(t->tca[0]),
		    "delay", 0, false);
		ucl_object_insert_key(tc, ucl_object_fromdouble(t->tca[1]),
		    "ipdv", 0, false);
		ucl_object_insert_key(tc, ucl_object_fromdouble(t->tca[2]),
		    "loss", 0, false);
		ucl_object_insert_key(tc, ucl_object_fromint(t->damping),
		    "damping", 0, false);
		ucl_object_insert_key(o, tc, "tca", 0, false);
	}
	return (o);
}

/*
 * The configuration of the probes as arcana-probe has it: each edge
 * (the host's first, "" its jail) with its SD-WAN targets, the links it
 * watches and the admin's monitors, as JSON
 * {"edges": [{"jail", "targets", "links", "monitors"}]}; malloc'd, NULL
 * for no memory.
 */
char *
probe_conf_json(void)
{
	ucl_object_t		*top, *edges, *e, *l;
	const ucl_object_t	*o;
	const struct target	*t;
	ucl_object_iter_t	 it;
	struct link		*links;
	struct snap		*s;
	const char		*jail, *key;
	char			*json;
	int			 k, nt, nlinks;

	if ((links = calloc(LINKS_MAX, sizeof(*links))) == NULL)
		return (NULL);
	top = ucl_object_typed_new(UCL_OBJECT);
	edges = ucl_object_typed_new(UCL_OBJECT);
	/* The host's, always. */
	e = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(edges, e, "", 0, true);
	s = snap_get();
	nt = s != NULL ? s->n : 0;
	nlinks = links_copy(links, LINKS_MAX);
	for (k = 0; k < nt + nlinks; k++) {
		t = k < nt ? &s->v[k].t : NULL;
		/* A target's place left empty is none; a class's session is
		 * its target's classes. */
		if (t != NULL && (t->id[0] == '\0' || t->cls[0] != '\0'))
			continue;
		jail = t != NULL ? t->jail : links[k - nt].jail;
		if ((o = ucl_object_lookup(edges, jail)) == NULL) {
			e = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(edges, e, jail, 0, true);
		} else
			e = (ucl_object_t *)(uintptr_t)o;
		key = t == NULL ? "links" : is_monitor(t) ? "monitors" :
		    "targets";
		if ((o = ucl_object_lookup(e, key)) == NULL) {
			l = ucl_object_typed_new(UCL_ARRAY);
			ucl_object_insert_key(e, l, key, 0, true);
		} else
			l = (ucl_object_t *)(uintptr_t)o;
		if (t != NULL) {
			ucl_object_t	*tc, *cl = NULL, *c;

			tc = target_conf(t);
			for (int j = k + 1; j < nt && s->v[j].t.cls[0] != '\0';
			    j++) {
				if (cl == NULL)
					cl = ucl_object_typed_new(UCL_ARRAY);
				c = ucl_object_typed_new(UCL_OBJECT);
				ucl_object_insert_key(c, ucl_object_fromstring(
				    s->v[j].t.cls), "name", 0, false);
				ucl_object_insert_key(c, ucl_object_fromint(
				    s->v[j].t.dscp), "dscp", 0, false);
				ucl_array_append(cl, c);
			}
			if (cl != NULL)
				ucl_object_insert_key(tc, cl, "classes", 0, false);
			ucl_array_append(l, tc);
		} else {
			o = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key((ucl_object_t *)(uintptr_t)o,
			    ucl_object_fromstring(links[k - nt].id), "id", 0,
			    false);
			ucl_object_insert_key((ucl_object_t *)(uintptr_t)o,
			    ucl_object_fromstring(links[k - nt].ifname),
			    "interface", 0, false);
			ucl_object_insert_key((ucl_object_t *)(uintptr_t)o,
			    ucl_object_fromstring(links[k - nt].role), "role", 0,
			    false);
			ucl_array_append(l, (ucl_object_t *)(uintptr_t)o);
		}
	}
	snap_put(s);
	free(links);
	l = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((o = ucl_object_iterate(edges, &it, true)) != NULL) {
		e = ucl_object_copy(o);
		ucl_object_insert_key(e, ucl_object_fromstring(ucl_object_key(o)),
		    "jail", 0, true);
		ucl_array_append(l, e);
	}
	ucl_object_unref(edges);
	ucl_object_insert_key(top, l, "edges", 0, false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	return (json);
}

/* ---- Each edge's interfaces and routing tables ---------------------- */

/* Word w added to the comma-separated set at key k of o, once. */
static void
set_add(ucl_object_t *o, const char *k, const char *w)
{
	const ucl_object_t	*v;
	const char		*s, *p;
	char			 buf[4096];
	size_t			 n = strlen(w);

	if (w[0] == '\0')
		return;
	if ((v = ucl_object_lookup(o, k)) == NULL) {
		ucl_object_insert_key(o, ucl_object_fromstring(w), k, 0, true);
		return;
	}
	s = ucl_object_tostring(v);
	for (p = s; p != NULL; p = (p = strchr(p, ',')) != NULL ? p + 1 :
	    NULL)
		if (strncmp(p, w, n) == 0 && (p[n] == ',' || p[n] == '\0'))
			return;
	if ((size_t)snprintf(buf, sizeof(buf), "%s,%s", s, w) >= sizeof(buf))
		return;
	ucl_object_replace_key(o, ucl_object_fromstring(buf), k, 0, true);
}

/*
 * The routes each edge's FIBs had when last dumped, and when: a FIB
 * with a full BGP table is a long walk for netlink(4), and the base
 * counts them no cheaper (no sysctl nor netlink message tells a
 * table's size), so a count is told again for --routes-cache seconds.
 * One edge's FIBs are dumped by one reader at a time, under rtc_lock:
 * another waits for that dump and takes what it found.  ok false, a
 * FIB the kernel has not.
 */
struct rtc {
	char		 jail[64];
	unsigned int	 fib, n4, n6;
	bool		 ok;
	double		 at;
};

static pthread_mutex_t	 rtc_lock = PTHREAD_MUTEX_INITIALIZER;
static struct rtc	*rtc;
static size_t		 nrtc, rtc_cap;

static struct rtc *
rtc_find(const char *jail, unsigned int fib)
{
	struct rtc	*r;

	for (size_t i = 0; i < nrtc; i++)
		if (rtc[i].fib == fib && strcmp(rtc[i].jail, jail) == 0)
			return (&rtc[i]);
	if (nrtc == rtc_cap) {
		if ((r = reallocarray(rtc, rtc_cap + 16, sizeof(*r))) == NULL)
			return (NULL);
		rtc = r;
		rtc_cap += 16;
	}
	r = &rtc[nrtc++];
	memset(r, 0, sizeof(*r));
	strlcpy(r->jail, jail, sizeof(r->jail));
	r->fib = fib;
	r->at = -1;
	return (r);
}

/*
 * Edge jail's (w's) FIBs fibs, a comma-separated list, appended to l as
 * {"fib", "ipv4", "ipv6"}: dumped again those older than the window.
 */
static void
fib_counts(struct work *w, const char *jail, const char *fibs,
    ucl_object_t *l)
{
	struct rtc	*r;
	const char	*p, *txt, *line, *nl;
	char		*e, stale[512];
	unsigned long	 fib;
	unsigned int	 f, n4, n6;
	double		 now;
	size_t		 i, len;
	ucl_object_t	*o;

	pthread_mutex_lock(&rtc_lock);
	now = now_s();
	/* An edge or FIB no longer asked about for long, forgotten. */
	for (i = 0; i < nrtc; )
		if (rtc[i].at < 0 || now - rtc[i].at > opts.routes_cache_s +
		    600)
			rtc[i] = rtc[--nrtc];
		else
			i++;
	stale[0] = '\0';
	len = 0;
	for (p = fibs; *p != '\0'; p = *e == ',' ? e + 1 : e) {
		fib = strtoul(p, &e, 10);
		if (e == p || (*e != ',' && *e != '\0') || fib > 65535)
			break;
		if ((r = rtc_find(jail, (unsigned int)fib)) == NULL)
			continue;
		if (r->at >= 0 && now - r->at < opts.routes_cache_s)
			continue;
		len += (size_t)snprintf(stale + len, sizeof(stale) - len,
		    "%s%lu", len > 0 ? "," : "", fib);
		if (len >= sizeof(stale))
			break;
	}
	if (len > 0 && len < sizeof(stale)) {
		logmsg(LOG_DEBUG, "probe: routes dumped: edge \"%s\" FIBs %s",
		    jail, stale);
		if ((txt = fib_routes_text(w, stale)) != NULL) {
			/* Each asked for, none until the dump tells it. */
			for (p = stale; *p != '\0'; p = *e == ',' ? e + 1 : e) {
				fib = strtoul(p, &e, 10);
				if ((r = rtc_find(jail, (unsigned int)fib)) !=
				    NULL) {
					r->ok = false;
					r->at = now;
				}
			}
			for (line = txt; *line != '\0'; line = nl + 1) {
				if ((nl = strchr(line, '\n')) == NULL)
					break;
				if (sscanf(line, "%u %u %u", &f, &n4, &n6) != 3 ||
				    (r = rtc_find(jail, f)) == NULL)
					continue;
				r->n4 = n4;
				r->n6 = n6;
				r->ok = true;
			}
		}
	}
	/* As asked, each the kernel has (the last count, when the dump
	 * failed). */
	for (p = fibs; *p != '\0'; p = *e == ',' ? e + 1 : e) {
		fib = strtoul(p, &e, 10);
		if (e == p || (*e != ',' && *e != '\0') || fib > 65535)
			break;
		if ((r = rtc_find(jail, (unsigned int)fib)) == NULL || !r->ok)
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromint(r->fib), "fib", 0,
		    true);
		ucl_object_insert_key(o, ucl_object_fromint(r->n4), "ipv4", 0,
		    true);
		ucl_object_insert_key(o, ucl_object_fromint(r->n6), "ipv6", 0,
		    true);
		ucl_array_append(l, o);
	}
	pthread_mutex_unlock(&rtc_lock);
}

/*
 * Each edge's interfaces and routing tables as the kernel counts them
 * now (PLAN-SDN-YANG 5.3.2, RFC 9375's termination point statistics
 * and entry summary): the interfaces its targets are measured over
 * (their interface) and its links watch, from their if_data; the FIBs
 * its targets go by, and FIB 0, their routes as netlink(4) dumps them
 * (fib_counts(): a dump told again for --routes-cache seconds).
 * A vnet jail's read in its own network by the helper, one question
 * for its interfaces and one for its FIBs.  As JSON {"edges": [{"jail",
 * "time", "interfaces": [{"name", "ibytes", ...}], "fibs": [{"fib",
 * "ipv4", "ipv6"}]}]}, the host's first; malloc'd, NULL for no memory.
 */
char *
probe_edges_json(void)
{
	static const char *const cn[] = { "ibytes", "ipackets", "imcasts",
	    "iqdrops", "ierrors", "noproto", "obytes", "opackets", "omcasts",
	    "oqdrops", "oerrors" };
	ucl_object_t		*want, *top, *arr, *e, *l, *o;
	const ucl_object_t	*w, *v;
	const struct target	*t;
	ucl_object_iter_t	 it;
	struct link		*links;
	struct snap		*s;
	struct work		 jw;
	const char		*jail, *txt, *err, *line, *nl;
	char			 name[IFNAMSIZ], fb[16], *json;
	uintmax_t		 c[nitems(cn)];
	int			 k, nt, nlinks;

	if ((links = calloc(LINKS_MAX, sizeof(*links))) == NULL)
		return (NULL);
	/* What each edge has: its interfaces and FIBs, as words. */
	want = ucl_object_typed_new(UCL_OBJECT);
	e = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(e, ucl_object_fromstring("0"), "fibs", 0, true);
	ucl_object_insert_key(want, e, "", 0, true);
	s = snap_get();
	nt = s != NULL ? s->n : 0;
	nlinks = links_copy(links, LINKS_MAX);
	for (k = 0; k < nt + nlinks; k++) {
		t = k < nt ? &s->v[k].t : NULL;
		if (t != NULL && t->id[0] == '\0')
			continue;
		jail = t != NULL ? t->jail : links[k - nt].jail;
		if ((w = ucl_object_lookup(want, jail)) == NULL) {
			e = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(want, e, jail, 0, true);
		} else
			e = __DECONST(ucl_object_t *, w);
		if (t != NULL) {
			set_add(e, "ifs", t->ifname);
			snprintf(fb, sizeof(fb), "%d", t->fib);
			set_add(e, "fibs", fb);
		} else
			set_add(e, "ifs", links[k - nt].ifname);
	}
	snap_put(s);
	free(links);
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((w = ucl_object_iterate(want, &it, true)) != NULL) {
		jail = ucl_object_key(w);
		work_init(&jw);
		err = NULL;
		if (jail[0] != '\0' && scope_enter(&jw, jail, &err) != 0) {
			/* A jail not running: its network not there. */
			work_free(&jw);
			continue;
		}
		e = ucl_object_typed_new(UCL_OBJECT);
		if (jail[0] != '\0')
			ucl_object_insert_key(e, ucl_object_fromstring(jail),
			    "jail", 0, true);
		ucl_object_insert_key(e, ucl_object_fromint((int64_t)time(
		    NULL)), "time", 0, true);
		l = ucl_object_typed_new(UCL_ARRAY);
		if ((v = ucl_object_lookup(w, "ifs")) != NULL && (txt =
		    if_counters_text(&jw, ucl_object_tostring(v))) != NULL)
			for (line = txt; *line != '\0'; line = nl + 1) {
				if ((nl = strchr(line, '\n')) == NULL)
					break;
				if (sscanf(line, "%15s %ju %ju %ju %ju %ju %ju %ju "
				    "%ju %ju %ju %ju", name, &c[0], &c[1], &c[2],
				    &c[3], &c[4], &c[5], &c[6], &c[7], &c[8], &c[9],
				    &c[10]) != 12)
					continue;
				o = ucl_object_typed_new(UCL_OBJECT);
				ucl_object_insert_key(o, ucl_object_fromstring(
				    name), "name", 0, true);
				for (size_t i = 0; i < nitems(cn); i++)
					ucl_object_insert_key(o, ucl_object_fromint(
					    (int64_t)c[i]), cn[i], 0, true);
				ucl_array_append(l, o);
			}
		ucl_object_insert_key(e, l, "interfaces", 0, true);
		l = ucl_object_typed_new(UCL_ARRAY);
		if ((v = ucl_object_lookup(w, "fibs")) != NULL)
			fib_counts(&jw, jail, ucl_object_tostring(v), l);
		ucl_object_insert_key(e, l, "fibs", 0, true);
		work_free(&jw);
		ucl_array_append(arr, e);
	}
	ucl_object_unref(want);
	ucl_object_insert_key(top, arr, "edges", 0, false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	return (json);
}
