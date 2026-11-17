/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula, what the prober makes of its answers: so many misses in a row
 * and a target is down, so many answers and it is up again, each an
 * event (sdwan-tunnel, monitor) and SD-WAN's fault (tunnel, underlay);
 * of each eval interval a sample: the one-way delay, half the mean
 * round trip (MEF 105 §7.2.4); the delay variation, the mean difference
 * between one round trip and the next; the loss; the least and the
 * most; and its thresholds crossed (Mplify 119 §11.4's TCA): a fault
 * for SD-WAN's, an event for a monitor's.  Each target's measurement
 * intervals (PLAN-SDN-YANG 5.2, RFC 9375's perf-mon) are aligned to the
 * wall clock and end by the monotonic one: their raw samples (a uniform
 * sample beyond PM_RAW_MAX), the least, the most, the mean and three
 * percentiles of each metric, the last PM_KEPT kept.  Everything here
 * runs on the engine's thread (probe_engine.c), on its targets.
 *
 * The samples, the raw samples and the intervals kept are rows: chunks
 * of ROWS each, which the snapshots (probe_view.c) share with the engine
 * by their count of holders.  A row is added at the end, the oldest let
 * go a chunk at a time, and a row a snapshot may see is never written
 * again: a raw sample put in the place of another (the uniform sample)
 * goes into a copy of its chunk when one is shared.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>

#include <math.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "agent.h"
#include "stamp.h"
#include "probe_int.h"

#define	PM_RAW_MAX	4096	/* raw samples an interval keeps, a target */
#define	PM_KEPT		60	/* completed measurement intervals kept */
#define	SAMP_ROWS	256	/* samples a chunk */
#define	RAW_ROWS	256	/* raw samples a chunk */
#define	DONE_ROWS	16	/* intervals a chunk */

/* ---- Rows ----------------------------------------------------------- */

static struct rchunk *
chunk_new(const struct rows *r)
{
	struct rchunk	*c;

	if ((c = malloc(sizeof(*c) + r->esz * (size_t)r->per)) == NULL)
		return (NULL);
	atomic_init(&c->ref, 1);
	return (c);
}

static void
chunk_put(struct rchunk *c)
{

	if (atomic_fetch_sub(&c->ref, 1) == 1)
		free(c);
}

/* None, of esz bytes each, per a chunk. */
void
rows_init(struct rows *r, size_t esz, int per)
{

	memset(r, 0, sizeof(*r));
	r->esz = esz;
	r->per = per;
}

/* The snapshot of them made last let go: they changed under it. */
static void
rows_stale(struct rows *r)
{

	rowsnap_put(r->snap);
	r->snap = NULL;
}

void
rows_clear(struct rows *r)
{
	size_t	esz = r->esz;
	int	per = r->per, i;

	rows_stale(r);
	for (i = 0; i < r->nc; i++)
		chunk_put(r->c[i]);
	free(r->c);
	rows_init(r, esz, per);
}

/* A row added at the end, for the caller to fill; NULL for no memory. */
void *
rows_push(struct rows *r)
{
	struct rchunk	**v, *c;
	uint64_t	  i;
	int		  cap;

	if (r->hi - r->base == (uint64_t)r->nc * (uint64_t)r->per) {
		if (r->nc == r->cap) {
			cap = r->cap == 0 ? 8 : r->cap * 2;
			if ((v = reallocarray(r->c, (size_t)cap,
			    sizeof(*v))) == NULL)
				return (NULL);
			r->c = v;
			r->cap = cap;
		}
		if ((c = chunk_new(r)) == NULL)
			return (NULL);
		r->c[r->nc++] = c;
		rows_stale(r);
	}
	i = r->hi++ - r->base;
	return (r->c[i / (uint64_t)r->per]->v + (i % (uint64_t)r->per) *
	    r->esz);
}

/* Row i (lo to hi), to write: its chunk copied first when a snapshot
 * has it.  NULL for no memory. */
void *
rows_at(struct rows *r, uint64_t i)
{
	struct rchunk	*c, *n;
	uint64_t	 k;

	i -= r->base;
	k = i / (uint64_t)r->per;
	c = r->c[k];
	/* Held by the engine's own snapshot alone: not shared. */
	if (atomic_load(&c->ref) > 1 && r->snap != NULL &&
	    atomic_load(&r->snap->ref) == 1)
		rows_stale(r);
	if (atomic_load(&c->ref) > 1) {
		if ((n = chunk_new(r)) == NULL)
			return (NULL);
		memcpy(n->v, c->v, r->esz * (size_t)r->per);
		r->c[k] = n;
		chunk_put(c);
		rows_stale(r);
	}
	return (r->c[k]->v + (i % (uint64_t)r->per) * r->esz);
}

/* The last keep rows kept, those before let go. */
void
rows_trim(struct rows *r, uint64_t keep)
{
	int	n;

	if (r->hi - r->lo > keep)
		r->lo = r->hi - keep;
	for (n = 0; n < r->nc && r->lo - r->base >= (uint64_t)r->per; n++)
		r->base += (uint64_t)r->per;
	if (n == 0)
		return;
	for (int i = 0; i < n; i++)
		chunk_put(r->c[i]);
	memmove(r->c, r->c + n, (size_t)(r->nc - n) * sizeof(*r->c));
	r->nc -= n;
	rows_stale(r);
}

/* Their chunks now, held for the caller (rowsnap_put()); NULL for none
 * (or no memory: the caller sees none). */
struct rowsnap *
rows_snap(struct rows *r)
{
	struct rowsnap	*s;

	if (r->nc == 0)
		return (NULL);
	if (r->snap == NULL) {
		if ((s = malloc(sizeof(*s) + (size_t)r->nc *
		    sizeof(s->c[0]))) == NULL)
			return (NULL);
		atomic_init(&s->ref, 1);
		s->nc = r->nc;
		s->base = r->base;
		for (int i = 0; i < r->nc; i++) {
			s->c[i] = r->c[i];
			atomic_fetch_add(&r->c[i]->ref, 1);
		}
		r->snap = s;
	}
	atomic_fetch_add(&r->snap->ref, 1);
	return (r->snap);
}

void
rowsnap_put(struct rowsnap *s)
{

	if (s == NULL || atomic_fetch_sub(&s->ref, 1) != 1)
		return;
	for (int i = 0; i < s->nc; i++)
		chunk_put(s->c[i]);
	free(s);
}

void
rows_src(const struct rows *r, struct rowsrc *src)
{

	src->c = r->c;
	src->base = r->base;
	src->lo = r->lo;
	src->hi = r->hi;
	src->esz = r->esz;
	src->per = r->per;
}

void
rowsview_src(const struct rowsview *v, struct rowsrc *src)
{

	src->c = v->s != NULL ? v->s->c : NULL;
	src->base = v->s != NULL ? v->s->base : 0;
	src->lo = v->s != NULL ? v->lo : 0;
	src->hi = v->s != NULL ? v->hi : 0;
	src->esz = v->esz;
	src->per = v->per;
}

/* Row i, lo to hi. */
const void *
rowsrc_at(const struct rowsrc *src, uint64_t i)
{

	i -= src->base;
	return (src->c[i / (uint64_t)src->per]->v + (i %
	    (uint64_t)src->per) * src->esz);
}

/* A target's rows, none yet. */
void
target_rows(struct target *t)
{

	rows_init(&t->samp, sizeof(struct sample), SAMP_ROWS);
	rows_init(&t->pm_raw, sizeof(struct pm_raw), RAW_ROWS);
	rows_init(&t->pm_last, sizeof(struct pm_raw), RAW_ROWS);
	rows_init(&t->pm_done, sizeof(struct pm), DONE_ROWS);
}

void
target_rows_free(struct target *t)
{

	rows_clear(&t->samp);
	rows_clear(&t->pm_raw);
	rows_clear(&t->pm_last);
	rows_clear(&t->pm_done);
}

/* ---- State ---------------------------------------------------------- */

void
state_set(struct target *t, int state)
{
	char	id[TNAME_MAX * 6], qa[6 * 64], qj[6 * 64], qi[6 * IFNAMSIZ];

	if (t->state == state)
		return;
	t->state = state;
	t->since = time(NULL);
	/* A class's session: its state its own, no event, fault nor
	 * steering (the target's DSCP's state is the target's). */
	if (t->cls[0] != '\0')
		return;
	engine_changed();
	if (state != ST_UP && state != ST_DOWN)
		return;
	/* An underlay path is no tunnel: its fault alone, no event. */
	if (t->underlay) {
		logmsg(state == ST_UP ? LOG_NOTICE : LOG_WARNING, "sdwan: "
		    "underlay %s (%s) is %s", target_name(t, id, sizeof(id)),
		    t->address, state_names[state]);
		if (state == ST_DOWN)
			fault_set("underlay", "Major", id, "probe", "no answer "
			    "from %s in FIB %d after %d probes", t->address,
			    t->fib, t->misses);
		else
			fault_clear("underlay", id, "%s answers again",
			    t->address);
		return;
	}
	/* Its id, address, jail and interface as JSON strings. */
	event_add(is_monitor(t) ? "monitor" : "sdwan-tunnel", "{\"id\":\"%s\","
	    "\"address\":\"%s\",\"state\":\"%s\",\"misses\":%d%s%s%s%s%s%s}",
	    json_quote(t->id, id, sizeof(id)), json_quote(t->address, qa,
	    sizeof(qa)), state_names[state], t->misses, t->jail[0] != '\0' ?
	    ",\"jail\":\"" : "", json_quote(t->jail, qj, sizeof(qj)),
	    t->jail[0] != '\0' ? "\"" : "", t->ifname[0] != '\0' ?
	    ",\"interface\":\"" : "", json_quote(t->ifname, qi, sizeof(qi)),
	    t->ifname[0] != '\0' ? "\"" : "");
	logmsg(state == ST_UP ? LOG_NOTICE : LOG_WARNING, "%s: %s (%s) is "
	    "%s", is_monitor(t) ? "monitor" : "sdwan", target_name(t, id,
	    sizeof(id)), t->address, state_names[state]);
	/* A monitor is the admin's own: an event, not SD-WAN's fault. */
	if (is_monitor(t))
		return;
	if (state == ST_DOWN)
		fault_set("tunnel", "Major", id, "probe", "no answer from %s "
		    "after %d probes", t->address, t->misses);
	else
		fault_clear("tunnel", id, "%s answers again", t->address);
}

/* A monitor's metric over its threshold, or under it again: an event. */
static void
monitor_tca(const struct target *t, const char *metric, double v, bool over)
{
	char	name[TNAME_MAX], qn[6 * TNAME_MAX], qi[6 * IFNAMSIZ];

	target_name(t, name, sizeof(name));
	event_add("monitor-threshold", "{\"id\":\"%s\",\"metric\":\"%s\","
	    "\"value\":%.6g,\"threshold\":%.6g,\"over\":%s%s%s%s}",
	    json_quote(name, qn, sizeof(qn)), metric, v,
	    t->tca[strcmp(metric, "delay") == 0 ? 0 : strcmp(metric, "ipdv") ==
	    0 ? 1 : 2], over ? "true" : "false", t->ifname[0] != '\0' ?
	    ",\"interface\":\"" : "", json_quote(t->ifname, qi, sizeof(qi)),
	    t->ifname[0] != '\0' ? "\"" : "");
	logmsg(over ? LOG_WARNING : LOG_NOTICE, "monitor: %s: %s %.3g %s the "
	    "threshold", name, metric, v, over ? "over" : "under");
}

/* The sample against the thresholds: an alert set or cleared. */
static void
tca_check(struct target *t, const struct sample *s)
{
	static const char *const names[] = { "delay", "ipdv", "loss" };
	static const char *const units[] = { " ms", " ms", "" };
	double		v[3];
	char		obj[TOBJ_MAX], name[TNAME_MAX];
	int		i;

	v[0] = s->delay;
	v[1] = s->ipdv;
	v[2] = s->loss;
	for (i = 0; i < 3; i++) {
		snprintf(obj, sizeof(obj), "%s/%s", target_name(t, name,
		    sizeof(name)), names[i]);
		/* No threshold now: over it no more, its alert cleared. */
		if (t->tca[i] <= 0) {
			if (t->tca_on[i] && !is_monitor(t))
				fault_clear("tca", obj, "%s: no threshold now",
				    names[i]);
			t->tca_on[i] = false;
			t->tca_over[i] = t->tca_under[i] = 0;
			continue;
		}
		if (v[i] > t->tca[i]) {
			t->tca_under[i] = 0;
			if (!t->tca_on[i] && ++t->tca_over[i] >= t->damping) {
				t->tca_on[i] = true;
				if (is_monitor(t))
					monitor_tca(t, names[i], v[i], true);
				else
					fault_set("tca", "Minor", obj, "probe",
					    "%s %.3g%s over the threshold %.3g%s",
					    names[i], v[i], units[i], t->tca[i],
					    units[i]);
			}
		} else {
			t->tca_over[i] = 0;
			if (t->tca_on[i] && ++t->tca_under[i] >= t->damping) {
				t->tca_on[i] = false;
				if (is_monitor(t))
					monitor_tca(t, names[i], v[i], false);
				else
					fault_clear("tca", obj, "%s %.3g%s, under "
					    "the threshold %.3g%s again", names[i],
					    v[i], units[i], t->tca[i], units[i]);
			}
		}
	}
}

/* ---- Measurement intervals (PLAN-SDN-YANG 5.2) ---------------------- */

/* Milliseconds as whole microseconds, 0 to INT32_MAX. */
static int32_t
pm_us(double ms)
{
	double	v = ms * 1000 + 0.5;

	return (v < 0 ? 0 : v > INT32_MAX ? INT32_MAX : (int32_t)v);
}

/* Its sender's counts, false when it has none. */
static bool
sender_stats(const struct target *t, struct stamp_sender_stats *st)
{

	if (t->ss == NULL)
		return (false);
	stamp_sender_stats(t->ss, st);
	return (true);
}

/* The loss each way the target's STAMP has told, all along: its
 * senders' given up, and st's (its sender's now, NULL none). */
void
pm_lost(const struct target *t, const struct stamp_sender_stats *st,
    uint64_t *fwd, uint64_t *back)
{

	*fwd = t->fwd_lost;
	*back = t->back_lost;
	if (st != NULL) {
		*fwd += st->fwd_lost - t->tk_fwd;
		*back += st->back_lost - t->tk_back;
	}
}

/*
 * A new interval from the wall clock's boundary at or before now, its
 * name; it ends after what is left of it by the monotonic clock, so a
 * step of the wall clock neither holds it open nor ends it early.  The
 * counts from 0.
 */
static void
pm_begin(struct target *t)
{
	struct stamp_sender_stats	st;
	time_t				now = time(NULL);

	t->pm_start = now - now % t->pm_len;
	t->pm_due = now_s() + (double)(t->pm_start + t->pm_len - now);
	t->pm_sent = t->pm_recv = t->pm_seen = 0;
	rows_clear(&t->pm_raw);
	memset(t->pm_acc, 0, sizeof(t->pm_acc));
	pm_lost(t, sender_stats(t, &st) ? &st : NULL, &t->pm_fwd0,
	    &t->pm_back0);
}

/* The intervals forgotten: another length or other percentiles. */
void
pm_forget(struct target *t)
{

	rows_clear(&t->pm_done);
	rows_clear(&t->pm_last);
	t->pm_start = 0;
}

/* An answer's metrics: the round trip, and by STAMP (sm) the delay
 * each way when it was measured one way; each one's IPDV against the
 * answer before. */
void
pm_hit(struct target *t, double rtt_ms, const struct stamp_sample *sm)
{
	struct pm_raw	 r, *p;
	struct pm_acc	*a;
	uint32_t	 j;
	int		 i;

	r.v[PM_RTT] = pm_us(rtt_ms);
	r.v[PM_FWD] = r.v[PM_BACK] = -1;
	if (sm != NULL && sm->owd) {
		r.v[PM_FWD] = pm_us(sm->fwd * 1000);
		r.v[PM_BACK] = pm_us(sm->back * 1000);
	}
	for (i = 0; i < 3; i++) {
		r.v[PM_JRTT + i] = -1;
		if (r.v[i] < 0)
			continue;
		if (t->pm_prev[i] >= 0)
			r.v[PM_JRTT + i] = r.v[i] > t->pm_prev[i] ? r.v[i] -
			    t->pm_prev[i] : t->pm_prev[i] - r.v[i];
		t->pm_prev[i] = r.v[i];
	}
	for (i = 0; i < PM_NM; i++) {
		if (r.v[i] < 0)
			continue;
		a = &t->pm_acc[i];
		if (a->n == 0 || (uint32_t)r.v[i] < a->min)
			a->min = (uint32_t)r.v[i];
		if (a->n == 0 || (uint32_t)r.v[i] > a->max)
			a->max = (uint32_t)r.v[i];
		a->sum += (uint32_t)r.v[i];
		a->n++;
	}
	/* Kept: all of them up to PM_RAW_MAX, then each in its place with
	 * a chance that keeps a uniform sample (reservoir sampling). */
	t->pm_seen++;
	if (t->pm_raw.hi - t->pm_raw.lo < PM_RAW_MAX) {
		if ((p = rows_push(&t->pm_raw)) != NULL)
			*p = r;
	} else if ((j = arc4random_uniform(t->pm_seen)) < PM_RAW_MAX &&
	    (p = rows_at(&t->pm_raw, t->pm_raw.lo + j)) != NULL)
		*p = r;
}

static int
pm_cmp(const void *a, const void *b)
{
	int32_t	x = *(const int32_t *)a, y = *(const int32_t *)b;

	return (x < y ? -1 : x > y);
}

/* A percentile of n sorted values, the nearest rank: the least that p
 * percent of them are less than or equal to. */
static uint64_t
pm_rank(const int32_t *v, int n, double p)
{
	int	k;

	k = (int)ceil(p * n / 100.0 - 1e-9);
	if (k < 1)
		k = 1;
	if (k > n)
		k = n;
	return ((uint64_t)v[k - 1]);
}

/* The figures of raw samples (src's) and of every value (acc). */
static void
pm_figures(const struct target *t, const struct rowsrc *src,
    const struct pm_acc *acc, struct pm_stats *st)
{
	const struct pm_raw	*r;
	int32_t			*v;
	uint64_t		 i;
	int			 k, m, n;

	memset(st, 0, PM_NM * sizeof(*st));
	n = (int)(src->hi - src->lo);
	v = n > 0 ? calloc((size_t)n, sizeof(*v)) : NULL;
	for (m = 0; m < PM_NM; m++) {
		if (acc[m].n == 0)
			continue;
		st[m].n = acc[m].n;
		st[m].min = acc[m].min;
		st[m].max = acc[m].max;
		st[m].mean = (acc[m].sum + acc[m].n / 2) / acc[m].n;
		if (v == NULL)
			continue;
		for (i = src->lo, k = 0; i < src->hi; i++) {
			r = rowsrc_at(src, i);
			if (r->v[m] >= 0)
				v[k++] = r->v[m];
		}
		if (k == 0)
			continue;
		qsort(v, (size_t)k, sizeof(*v), pm_cmp);
		for (i = 0; i < 3; i++)
			if (t->pct[i] > 0)
				st[m].p[i] = pm_rank(v, k, t->pct[i]);
	}
	free(v);
}

/* The running interval as it would end now, into p: its raw samples
 * src's, its sender's counts st's (NULL, none). */
void
pm_now(const struct target *t, const struct stamp_sender_stats *st,
    const struct rowsrc *src, struct pm *p)
{
	uint64_t	f, b;

	p->start = t->pm_start;
	p->end = t->pm_start + t->pm_len;
	p->sent = t->pm_sent;
	p->recv = t->pm_recv;
	p->kept = (uint32_t)(src->hi - src->lo);
	p->lost_fwd = p->lost_back = -1;
	/* The loss each way, a stateful reflector's to tell. */
	if (t->by_stamp && st != NULL && st->mode == STAMP_MODE_STATEFUL) {
		pm_lost(t, st, &f, &b);
		p->lost_fwd = (int64_t)(f - t->pm_fwd0);
		p->lost_back = (int64_t)(b - t->pm_back0);
	}
	pm_figures(t, src, t->pm_acc, p->st);
}

/* The running interval ended: its figures kept, its raw samples the
 * last completed one's, a new one begun at the boundary of now. */
static void
pm_end(struct target *t)
{
	struct stamp_sender_stats	 st;
	struct rowsrc			 src;
	struct pm			 done, *p;

	rows_src(&t->pm_raw, &src);
	pm_now(t, sender_stats(t, &st) ? &st : NULL, &src, &done);
	if ((p = rows_push(&t->pm_done)) == NULL) {
		pm_begin(t);
		return;
	}
	*p = done;
	rows_trim(&t->pm_done, PM_KEPT);
	rows_clear(&t->pm_last);
	t->pm_last = t->pm_raw;
	rows_init(&t->pm_raw, sizeof(struct pm_raw), RAW_ROWS);
	pm_begin(t);
}

/* Its intervals' clock: begun, or ended when it is due. */
void
pm_timers(struct target *t, double now)
{

	if (t->pm_start == 0)
		pm_begin(t);
	else if (now >= t->pm_due)
		pm_end(t);
}

/* ---- Eval intervals ------------------------------------------------- */

/* Its samples none: another number of them kept. */
void
samples_reset(struct target *t)
{

	rows_clear(&t->samp);
}

/*
 * A sample into the archive (archive.c), the target's series by its
 * name: an interval that sent nothing is none; delays and loss as the
 * sample has them, those not told (-1) left out there.
 */
static void
archive_sample(const struct target *t, const struct sample *s)
{
	char	name[TNAME_MAX];
	double	v[11];

	if (s->sent == 0)
		return;
	v[0] = s->recv > 0 ? s->delay : -1;
	v[1] = s->recv > 1 ? s->ipdv : -1;
	v[2] = s->loss;
	v[3] = s->recv > 0 ? s->min : -1;
	v[4] = s->recv > 0 ? s->max : -1;
	v[5] = s->fwd;
	v[6] = s->back;
	v[7] = s->dfwd;
	v[8] = s->dback;
	v[9] = s->sent;
	v[10] = s->recv;
	archive_add(ARC_PROBE, target_name(t, name, sizeof(name)),
	    (time_t)s->t, v, nitems(v));
}

void
window_end(struct target *t, double now)
{
	struct sample	*s;

	if (t->history <= 0)
		goto reset;
	if ((s = rows_push(&t->samp)) == NULL)
		goto reset;
	rows_trim(&t->samp, (uint64_t)t->history);
	s->t = (double)time(NULL);
	s->sent = t->w_sent;
	s->recv = t->w_recv;
	s->delay = t->w_recv > 0 ? t->w_sum / t->w_recv / 2 : 0;
	s->ipdv = t->w_ipdv_n > 0 ? t->w_ipdv_sum / t->w_ipdv_n : 0;
	s->loss = t->w_sent > 0 ? (double)(t->w_sent - t->w_recv) / t->w_sent :
	    0;
	s->min = t->w_recv > 0 ? t->w_min / 2 : 0;
	s->max = t->w_recv > 0 ? t->w_max / 2 : 0;
	s->fwd = s->back = -1;
	/* The delay each way: one way when every STAMP reply of the
	 * interval had it so, else half the round trip, an estimate. */
	s->dfwd = s->dback = -1;
	s->owd = -1;
	if (t->w_owd_n > 0 && t->w_est_n == 0) {
		s->dfwd = t->w_dfwd / t->w_owd_n;
		s->dback = t->w_dback / t->w_owd_n;
		s->owd = 1;
	} else if (t->w_owd_n + t->w_est_n > 0) {
		s->dfwd = s->dback = s->delay;
		s->owd = 0;
	}
	/* The loss each way, a stateful reflector's to tell. */
	if (t->by_stamp && t->ss != NULL)
		stamp_window(t, s);
	if (t->w_sent > 0 && t->cls[0] == '\0')
		tca_check(t, s);
	archive_sample(t, s);
reset:
	t->w_sent = t->w_recv = t->w_ipdv_n = 0;
	t->w_sum = t->w_ipdv_sum = 0;
	t->w_owd_n = t->w_est_n = 0;
	t->w_dfwd = t->w_dback = 0;
	t->w_min = t->w_max = 0;
	t->win_start = now;
}

void
miss(struct target *t)
{

	t->w_sent++;
	t->pm_sent++;
	t->hits = 0;
	if (++t->misses >= t->down && t->state != ST_DOWN)
		state_set(t, ST_DOWN);
}

void
hit(struct target *t, double rtt_ms)
{

	t->w_sent++;
	t->w_recv++;
	t->pm_sent++;
	t->pm_recv++;
	t->received++;
	t->last_rtt = rtt_ms;
	t->w_sum += rtt_ms;
	if (t->w_recv == 1 || rtt_ms < t->w_min)
		t->w_min = rtt_ms;
	if (t->w_recv == 1 || rtt_ms > t->w_max)
		t->w_max = rtt_ms;
	if (t->w_has_prev) {
		t->w_ipdv_sum += rtt_ms > t->w_prev ? rtt_ms - t->w_prev :
		    t->w_prev - rtt_ms;
		t->w_ipdv_n++;
	}
	t->w_prev = rtt_ms;
	t->w_has_prev = true;
	t->misses = 0;
	if (++t->hits >= t->up && t->state != ST_UP)
		state_set(t, ST_UP);
}
