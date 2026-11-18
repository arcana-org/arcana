/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A host's long run (PLAN-SDN-YANG 5.6.3): what its agent archived on
 * its disk, a class at a time (the host, its interfaces, disks, jails,
 * FEC relays, and the targets it probes), drawn over the hour, six
 * hours, the day, the week or all the class keeps, under the
 * utilization of the last hour on the host's Monitoring tab.  Read
 * from arcana-history's read-archive, each series given as many
 * points as its plot is wide: the agent merges its own into longer
 * ones, so a week is as light as an hour.  A class of many series (an
 * interface each, a target each) is a table of them first, each with
 * its means over the range, and the one picked is drawn.  What the
 * agent did not sample, or kept nothing of, is a gap in the line,
 * never drawn across.  The plots are the utilization's (usage.c).
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "app.h"

#define	ARCH_EVERY	60000	/* ms between two reads while shown */
#define	ARCH_PTS_MIN	60	/* points a series is asked for, at least */
#define	ARCH_PTS_MAX	2000	/* and at most */
#define	ARCH_NAME	256

/* How a figure is drawn and told. */
enum { U_PCT, U_LOAD, U_BYTES, U_RATE, U_BPS, U_MS, U_LOSS, U_COUNT };

struct aplot {
	const char	*label;
	int		 unit;
	const char	*f[3];		/* its fields, the first filled */
	const char	*n[3];		/* and their names in the key */
};

struct acol {
	const char	*title;
	const char	*f;		/* the field it is the mean of */
	int		 unit;
};

static const struct aplot p_host[] = {
	{ "CPU", U_PCT, { "cpu" }, { "busy" } },
	{ "Load", U_LOAD, { "load" }, { "1 min" } },
	{ "Memory", U_BYTES, { "memory", "swap" }, { "in use", "swap" } },
	{ "Network", U_RATE, { "received", "sent" }, { "in", "out" } },
	{ "Disks", U_BPS, { "read", "written" }, { "read", "written" } },
};
static const struct aplot p_if[] = {
	{ "Network", U_RATE, { "received", "sent" }, { "in", "out" } },
};
static const struct aplot p_disk[] = {
	{ "Disk", U_BPS, { "read", "written" }, { "read", "written" } },
};
static const struct aplot p_jail[] = {
	{ "Jail CPU", U_PCT, { "cpu" }, { "of one CPU" } },
	{ "Jail memory", U_BYTES, { "memory" }, { "in use" } },
};
static const struct aplot p_relay[] = {
	{ "FEC relay", U_RATE, { "plain", "added" }, { "carried",
	    "added by FEC" } },
};
static const struct aplot p_probe[] = {
	{ "Delay", U_MS, { "delay", "min", "max" }, { "mean", "least",
	    "most" } },
	{ "Delay each way", U_MS, { "delay-forward", "delay-backward" },
	    { "forward", "backward" } },
	{ "Delay variation", U_MS, { "ipdv" }, { "IPDV" } },
	{ "Loss", U_LOSS, { "loss", "lost-forward", "lost-backward" },
	    { "both", "forward", "backward" } },
};

static const struct aclass {
	const char		*name;
	const char		*title;		/* the class's button */
	const char		*one;		/* a series of it */
	int			 keep;		/* days kept unless set */
	const struct aplot	*plots;
	int			 nplots;
	struct acol		 cols[4];	/* the series' table */
	const char		*none;		/* why there may be none */
} classes[] = {
	{ "host", "Host", "host", 30, p_host, nitems(p_host),
	    { { NULL, NULL, 0 } },
	    "The agent archives the host's figures as it samples them." },
	{ "interface", "Interfaces", "Interface", 7, p_if, nitems(p_if),
	    { { "In", "received", U_RATE }, { "Out", "sent", U_RATE } },
	    "An interface is archived once the sampler tells it apart." },
	{ "disk", "Disks", "Disk", 7, p_disk, nitems(p_disk),
	    { { "Read", "read", U_BPS }, { "Written", "written", U_BPS } },
	    "A disk is archived once the sampler tells it apart." },
	{ "jail", "Jails", "Jail", 7, p_jail, nitems(p_jail),
	    { { "CPU", "cpu", U_PCT }, { "Memory", "memory", U_BYTES } },
	    "A jail is archived once the kernel accounts for it: "
	    "kern.racct.enable=1 in /boot/loader.conf, and a reboot." },
	{ "relay", "FEC relays", "FEC relay", 7, p_relay, nitems(p_relay),
	    { { "Carried", "plain", U_RATE }, { "Added", "added", U_RATE } },
	    "A FEC relay is archived from its reports in syslog." },
	{ "probe", "Probes", "Target", 7, p_probe, nitems(p_probe),
	    { { "Delay", "delay", U_MS }, { "IPDV", "ipdv", U_MS },
	    { "Loss", "loss", U_LOSS }, { "Sent", "sent", U_COUNT } },
	    "A target is archived as the agent measures it: a tunnel's "
	    "probe, an SD-WAN path's STAMP." },
};

static const struct {
	int		 secs;		/* 0: all the class keeps */
	const char	*title, *long_;
} ranges[] = {
	{ 3600, "1 h", "the last hour" }, { 6 * 3600, "6 h",
	    "the last six hours" }, { 86400, "1 d", "the last day" },
	{ 7 * 86400, "7 d", "the last week" }, { 0, NULL, NULL },
};

/* A read on its way: for which host, and for what was shown then. */
struct areq {
	char		 sid[9];
	unsigned int	 gen;
};

static struct {
	char		 sid[9];
	int		 cls;		/* classes[] */
	int		 range;		/* s; 0 all the class keeps */
	char		 name[ARCH_NAME];	/* the series drawn; "" none */
	unsigned int	 gen;		/* what is shown: a reply to another
					   is dropped */
	ucl_object_t	*state;		/* history/state/archive */
	ucl_object_t	*list;		/* the series, a mean each, as rows */
	ucl_object_t	*pts;		/* the series drawn, read */
	bool		 lstate, llist, lpts;
	bool		 have_list, have_pts;	/* read for gen */
	double		 fetched, asked;
	time_t		 from, to;	/* of pts */
	int		 points;	/* asked for */
	char		 error[200];
} ar = { .range = 86400 };

static void	arch_read(const struct server *);

static const struct aclass *
cur_class(void)
{

	return (&classes[ar.cls]);
}

/* How many days the class keeps: as its state says, or its default. */
static int
keep_days(void)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((o = ucl_object_iterate(jget(ar.state, "class"), &it, true)) !=
	    NULL)
		if (jstr(o, "name") != NULL && strcmp(jstr(o, "name"),
		    cur_class()->name) == 0 && jint(o, "retention", 0) > 0)
			return ((int)jint(o, "retention", 0));
	return (cur_class()->keep);
}

static int
range_secs(void)
{

	return (ar.range > 0 ? ar.range : keep_days() * 86400);
}

/* The range as words: "the last day", "the 30 days kept". */
static void
range_words(char *buf, size_t len)
{
	size_t	i;

	for (i = 0; i < nitems(ranges) && ranges[i].secs != ar.range; i++)
		;
	if (ar.range > 0 && i < nitems(ranges))
		snprintf(buf, len, "%s", ranges[i].long_);
	else
		snprintf(buf, len, "the %d day%s kept", keep_days(),
		    keep_days() == 1 ? "" : "s");
}

static void
iso(char *buf, size_t len, time_t t)
{
	struct tm	tm;

	gmtime_r(&t, &tm);
	strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* A figure as it is shown. */
static void
fmt_unit(char *buf, size_t len, double v, int unit)
{

	if (isnan(v)) {
		snprintf(buf, len, "–");
		return;
	}
	switch (unit) {
	case U_PCT:
		snprintf(buf, len, v < 10 ? "%.1f%%" : "%.0f%%", v);
		break;
	case U_LOAD:
		snprintf(buf, len, "%.2f", v);
		break;
	case U_BYTES:
		fmt_size(buf, len, v);
		break;
	case U_RATE:
		fmt_rate(buf, len, v);
		break;
	case U_BPS:
		fmt_size(buf, len, v);
		strlcat(buf, "/s", len);
		break;
	case U_MS:
		snprintf(buf, len, v < 10 ? "%.2f ms" : "%.1f ms", v);
		break;
	case U_LOSS:
		snprintf(buf, len, "%.2f%%", v);
		break;
	default:
		snprintf(buf, len, "%.0f", v);
		break;
	}
}

/* A value of a point: a number, or as RFC 7951 has 64-bit ones, text. */
static double
num(const ucl_object_t *o)
{
	const char	*s;
	char		*end;
	double		 d;

	if (o == NULL)
		return (-1);
	if (ucl_object_type(o) == UCL_STRING) {
		s = ucl_object_tostring(o);
		d = strtod(s, &end);
		return (s[0] != '\0' && *end == '\0' ? d : -1);
	}
	return (ucl_object_todouble_safe(o, &d) ? d : -1);
}

/* Field name's place among a read's fields, -1 none; its scale. */
static int
field(const ucl_object_t *r, const char *name, double *scale)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	int			 k;

	if (name == NULL)
		return (-1);
	k = 0;
	it = NULL;
	while ((o = ucl_object_iterate(jget(r, "field"), &it, true)) != NULL) {
		if (strcmp(ucl_object_tostring_forced(o), name) == 0) {
			*scale = num(ucl_array_find_index(jget(r, "scale"),
			    (unsigned int)k));
			if (*scale <= 0)
				*scale = 1;
			return (k);
		}
		k++;
	}
	return (-1);
}

/* Value k of a point in the unit it is drawn in; NaN not told. */
static double
value(const ucl_object_t *p, int k, double scale, int unit)
{
	double	v;

	if (k < 0 || (v = num(ucl_array_find_index(jget(p, "value"),
	    (unsigned int)k))) < 0)
		return (NAN);
	v /= scale;
	return (unit == U_LOSS ? v * 100 : v);
}

/* The series of a read named name, or its first. */
static const ucl_object_t *
series(const ucl_object_t *r, const char *name)
{
	const ucl_object_t	*o, *first;
	ucl_object_iter_t	 it;

	first = NULL;
	it = NULL;
	while ((o = ucl_object_iterate(jget(r, "series"), &it, true)) != NULL) {
		if (first == NULL)
			first = o;
		if (name[0] != '\0' && jstr(o, "name") != NULL && strcmp(jstr(o,
		    "name"), name) == 0)
			return (o);
	}
	return (name[0] == '\0' ? first : NULL);
}

static struct server *
server(const char *sid)
{
	int	i;

	for (i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, sid) == 0)
			return (&app.servers[i]);
	return (NULL);
}

static struct areq *
req(void)
{
	struct areq	*r;

	if ((r = calloc(1, sizeof(*r))) == NULL)
		abort();
	snprintf(r->sid, sizeof(r->sid), "%s", ar.sid);
	r->gen = ar.gen;
	return (r);
}

/* Is the reply for what is shown?  Freed either way. */
static bool
current(struct areq *r)
{
	bool	ok;

	ok = strcmp(r->sid, ar.sid) == 0 && r->gen == ar.gen;
	free(r);
	return (ok);
}

static void
failed(const char *err)
{

	snprintf(ar.error, sizeof(ar.error), "%s", err != NULL ? err :
	    "no answer");
}

/* What the archive holds is the host's, whatever is shown of it. */
static void
state_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct areq	*r = arg;
	bool		 ok;

	ok = strcmp(r->sid, ar.sid) == 0;
	free(r);
	if (!ok)
		return;
	ar.lstate = false;
	if (status != 200 || o == NULL)
		return;
	if (ar.state != NULL)
		ucl_object_unref(ar.state);
	ar.state = ucl_object_ref(o);
}

/* How many points a series is given: as many as its plot is wide. */
static int
points_wanted(void)
{
	int	w;

	if ((w = arc_el_w(".arch .uplots figure.uplot svg")) <= 0 && (w =
	    arc_el_w("section.arch")) > 0)
		w = arc_narrow() ? w : w / 2;
	if (w <= 0)
		w = 600;
	return (w < ARCH_PTS_MIN ? ARCH_PTS_MIN : w > ARCH_PTS_MAX ?
	    ARCH_PTS_MAX : w);
}

static void
pts_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	if (!current(arg))
		return;
	ar.lpts = false;
	ar.have_pts = true;
	if (status != 200 || o == NULL) {
		failed(err);
		return;
	}
	ar.error[0] = '\0';
	ar.fetched = arc_now();
	if (ar.pts != NULL)
		ucl_object_unref(ar.pts);
	ar.pts = ucl_object_ref(o);
}

/* The series drawn, read with its points. */
static void
pts_read(const struct server *s)
{
	struct html	 b;
	char		 from[32], to[32], *q;

	ar.to = time(NULL);
	ar.from = ar.to - range_secs();
	ar.points = points_wanted();
	iso(from, sizeof(from), ar.from);
	iso(to, sizeof(to), ar.to);
	memset(&b, 0, sizeof(b));
	h_strf(&b, "{\"class\":\"%s\",\"from\":\"%s\",\"to\":\"%s\","
	    "\"points\":%d", cur_class()->name, from, to, ar.points);
	if (ar.cls != 0 && ar.name[0] != '\0') {
		q = json_quote(ar.name);
		h_strf(&b, ",\"name\":%s", q);
		free(q);
	}
	h_raw(&b, "}");
	q = h_take(&b);
	ar.lpts = true;
	host_yread(s, "arcana-history:history/read-archive", q, NULL, false,
	    pts_cb, req());
	free(q);
}

/*
 * The series of a class over the range, a point each (the agent's
 * merged into one, or two where the range is not of its buckets): as
 * rows of the series' table, the name and each column's mean.
 */
static void
list_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	const struct aclass	*c = cur_class();
	const ucl_object_t	*sr, *p;
	ucl_object_iter_t	 it, pit;
	ucl_object_t		*rows, *row;
	struct server		*s;
	double			 scale, v, sum[4];
	char			 key[8];
	int			 k, f[4], n[4];
	bool			 found;

	if (!current(arg))
		return;
	ar.llist = false;
	ar.have_list = true;
	if (status != 200 || o == NULL) {
		failed(err);
		return;
	}
	ar.error[0] = '\0';
	ar.fetched = arc_now();
	rows = ucl_object_typed_new(UCL_ARRAY);
	found = false;
	it = NULL;
	while ((sr = ucl_object_iterate(jget(o, "series"), &it, true)) !=
	    NULL) {
		if (jstr(sr, "name") == NULL)
			continue;
		row = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(row, ucl_object_fromstring(jstr(sr,
		    "name")), "name", 0, true);
		for (k = 0; k < 4 && c->cols[k].title != NULL; k++) {
			f[k] = field(o, c->cols[k].f, &scale);
			sum[k] = 0;
			n[k] = 0;
			pit = NULL;
			while ((p = ucl_object_iterate(jget(sr, "point"), &pit,
			    true)) != NULL) {
				v = value(p, f[k], scale, c->cols[k].unit);
				if (isnan(v))
					continue;
				sum[k] += v;
				n[k]++;
			}
			snprintf(key, sizeof(key), "f%d", k);
			if (n[k] > 0)
				ucl_object_insert_key(row,
				    ucl_object_fromdouble(c->cols[k].unit ==
				    U_COUNT ? sum[k] : sum[k] / n[k]), key, 0,
				    true);
		}
		if (strcmp(jstr(sr, "name"), ar.name) == 0)
			found = true;
		ucl_array_append(rows, row);
	}
	if (ar.list != NULL)
		ucl_object_unref(ar.list);
	ar.list = rows;
	/* None picked yet, or the one picked has nothing in this range:
	 * the first drawn. */
	if (!found) {
		ar.name[0] = '\0';
		if ((row = (ucl_object_t *)ucl_array_find_index(rows, 0)) !=
		    NULL)
			snprintf(ar.name, sizeof(ar.name), "%s", jstr(row,
			    "name"));
	}
	if (ar.name[0] == '\0') {
		if (ar.pts != NULL)
			ucl_object_unref(ar.pts);
		ar.pts = NULL;
		ar.have_pts = true;
		return;
	}
	if ((s = server(ar.sid)) != NULL)
		pts_read(s);
}

static void
list_read(const struct server *s)
{
	char	from[32], to[32], in[160];
	time_t	t;

	t = time(NULL);
	iso(from, sizeof(from), t - range_secs());
	iso(to, sizeof(to), t);
	snprintf(in, sizeof(in), "{\"class\":\"%s\",\"from\":\"%s\",\"to\":"
	    "\"%s\",\"points\":1}", cur_class()->name, from, to);
	ar.llist = true;
	host_yread(s, "arcana-history:history/read-archive", in, NULL, false,
	    list_cb, req());
}

/* All of it read again: what the archive holds, the class's series or
 * the host's points. */
static void
arch_read(const struct server *s)
{

	ar.asked = arc_now();
	ar.lstate = true;
	host_yread(s, "arcana-history:history/state/archive", NULL, NULL,
	    false, state_cb, req());
	if (ar.cls == 0)
		pts_read(s);
	else
		list_read(s);
}

/* Something else to show: what was read for the rest is let go. */
static void
renew(void)
{

	ar.gen++;
	ar.have_list = ar.have_pts = false;
	ar.lpts = ar.llist = false;
	ar.error[0] = '\0';
	if (ar.list != NULL)
		ucl_object_unref(ar.list);
	ar.list = NULL;
	if (ar.pts != NULL)
		ucl_object_unref(ar.pts);
	ar.pts = NULL;
}

/* The host's Monitoring tab opened: read at once. */
void
arch_open(struct server *s)
{

	if (strcmp(ar.sid, s->id) != 0) {
		snprintf(ar.sid, sizeof(ar.sid), "%s", s->id);
		ar.name[0] = '\0';
		renew();
		if (ar.state != NULL)
			ucl_object_unref(ar.state);
		ar.state = NULL;
		ar.fetched = 0;
	}
	arch_read(s);
}

void
arch_tick(double now)
{
	struct server	*s;
	int		 w;

	if (app.node != NODE_HOST || app.tab != TAB_MONITORING ||
	    !app.visible || (s = cur_server()) == NULL ||
	    strcmp(s->id, ar.sid) != 0)
		return;
	/* A read nobody answered is given up after a while. */
	if ((ar.lstate || ar.llist || ar.lpts) && now - ar.asked > 30000)
		ar.lstate = ar.llist = ar.lpts = false;
	if (ar.lstate || ar.llist || ar.lpts)
		return;
	/* Read again as the archive grows, and when the plots came out
	 * of another width than the points were asked for. */
	w = points_wanted();
	if (now - ar.asked >= ARCH_EVERY || (ar.have_pts && ar.pts != NULL &&
	    abs(w - ar.points) > ar.points / 4))
		arch_read(s);
}

/* The class's plots of the series read: a line a field, broken where a
 * point is missing or a figure was not told. */
static void
plots(struct html *h, const ucl_object_t *sr)
{
	const struct aclass	*c = cur_class();
	const struct aplot	*pl;
	const ucl_object_t	*p;
	ucl_object_iter_t	 it;
	static const char *const colour[] = { "var(--c1)", "var(--c2)",
	    "var(--violet)" };
	char			 label[ARCH_NAME + 32], top_s[64], a[32], b[32];
	double			*t, *v[3], scale[3], step, prev, top, peak, sum;
	int			 n, np, k, j, f[3], cnt, npl;

	step = num(jget(ar.pts, "step"));
	np = (int)ucl_array_size(jget(sr, "point"));
	if ((t = calloc(2 * (size_t)np + 1, sizeof(*t))) == NULL)
		abort();
	for (j = 0; j < 3; j++)
		if ((v[j] = calloc(2 * (size_t)np + 1, sizeof(*v[j]))) == NULL)
			abort();
	h_fmt(h, "<div class=\"uplots arch-plots\" data-points=\"%d\" "
	    "data-asked=\"%d\" data-step=\"%.0f\" data-from=\"%lld\" "
	    "data-to=\"%lld\">", np, ar.points, step, (long long)ar.from,
	    (long long)ar.to);
	for (npl = 0; npl < c->nplots; npl++) {
		pl = &c->plots[npl];
		for (j = 0; j < 3; j++)
			f[j] = field(ar.pts, pl->f[j], &scale[j]);
		/* The points, a NaN between two that are more than a
		 * bucket apart: the agent kept nothing between. */
		n = 0;
		prev = 0;
		it = NULL;
		while ((p = ucl_object_iterate(jget(sr, "point"), &it, true)) !=
		    NULL) {
			double	tp = (double)rc_time(jstr(p, "time"));

			if (n > 0 && step > 0 && tp - prev > 1.5 * step) {
				t[n] = prev + step;
				for (j = 0; j < 3; j++)
					v[j][n] = NAN;
				n++;
			}
			t[n] = tp;
			for (j = 0; j < 3; j++)
				v[j][n] = value(p, f[j], scale[j], pl->unit);
			n++;
			prev = tp;
		}
		/* The top: round, a share's at least 100%. */
		peak = 0;
		for (j = 0; j < 3; j++)
			for (k = 0; k < n; k++)
				if (f[j] >= 0 && !isnan(v[j][k]) &&
				    v[j][k] > peak)
					peak = v[j][k];
		top = pl->unit == U_PCT && peak <= 100 ? 100 :
		    uplot_ceiling(peak);
		sum = 0;
		for (cnt = 0, k = 0; k < n; k++)
			if (!isnan(v[0][k])) {
				sum += v[0][k];
				cnt++;
			}
		fmt_unit(a, sizeof(a), cnt > 0 ? sum / cnt : NAN, pl->unit);
		fmt_unit(b, sizeof(b), cnt > 0 ? peak : NAN, pl->unit);
		snprintf(top_s, sizeof(top_s), "avg %s · peak %s", a, b);
		if (ar.cls == 0)
			snprintf(label, sizeof(label), "%s", pl->label);
		else
			snprintf(label, sizeof(label), "%s · %s", pl->label,
			    jstr(sr, "name") != NULL ? jstr(sr, "name") : "");
		uplot_open(h, label, top_s);
		for (j = 0; j < 3; j++)
			if (f[j] >= 0)
				uplot_line(h, t, v[j], n, (double)ar.to,
				    (double)(ar.to - ar.from), top, colour[j],
				    j == 0, j == 2 || (j == 1 && (pl->f[2] !=
				    NULL || pl->unit == U_BYTES)));
		h_raw(h, "</svg><div class=\"ukeys\">");
		for (j = 0; j < 3; j++) {
			if (f[j] < 0)
				continue;
			sum = 0;
			for (cnt = 0, k = 0; k < n; k++)
				if (!isnan(v[j][k])) {
					sum += v[j][k];
					cnt++;
				}
			fmt_unit(a, sizeof(a), cnt > 0 ? sum / cnt : NAN,
			    pl->unit);
			uplot_key(h, colour[j], pl->n[j], a);
		}
		h_raw(h, "</div></figure>");
	}
	h_raw(h, "</div>");
	free(t);
	for (j = 0; j < 3; j++)
		free(v[j]);
}

/* The series of the class over the range, to pick the one drawn. */
static void
series_table(struct html *h)
{
	const struct aclass	*c = cur_class();
	struct tcol		 tc[5];
	const ucl_object_t	**rows, *v;
	char			 buf[48], key[8], id[24];
	int			 k, nc, i;

	/* Each class its own order: its columns are its own. */
	snprintf(id, sizeof(id), "arch-s-%s", c->name);

	tc[0] = (struct tcol){ c->one, "name", false };
	for (nc = 1; nc < 5 && c->cols[nc - 1].title != NULL; nc++) {
		tc[nc].title = c->cols[nc - 1].title;
		tc[nc].key = nc == 1 ? "f0" : nc == 2 ? "f1" : nc == 3 ? "f2" :
		    "f3";
		tc[nc].num = true;
	}
	h_raw(h, "<table class=\"net arch-series\">");
	tbl_head(h, id, tc, nc, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows(id, ar.list, tc, nc, app.filter);
	for (i = 0; rows[i] != NULL; i++) {
		h_fmt(h, "<tr class=\"pick%s\" data-act=\"arch-series\" "
		    "title=\"Draw it\"", strcmp(jstr(rows[i], "name"),
		    ar.name) == 0 ? " on" : "");
		h_attr(h, "data-arg", jstr(rows[i], "name"));
		h_raw(h, "><td><b>");
		h_txt(h, jstr(rows[i], "name"));
		h_raw(h, "</b></td>");
		for (k = 1; k < nc; k++) {
			snprintf(key, sizeof(key), "f%d", k - 1);
			v = jget(rows[i], key);
			fmt_unit(buf, sizeof(buf), v != NULL ?
			    ucl_object_todouble(v) : NAN, c->cols[k - 1].unit);
			h_raw(h, "<td class=\"num\">");
			h_txt(h, buf);
			h_raw(h, "</td>");
		}
		h_raw(h, "</tr>");
	}
	if (i == 0)
		h_fmt(h, "<tr><td colspan=\"%d\" class=\"dim\">%s</td></tr>",
		    nc, ucl_array_size(ar.list) > 0 ? "None of them has what "
		    "is filtered for." : "None.");
	free(rows);
	h_raw(h, "</tbody></table>");
}

/* What the archive holds, a class a row: picked, it is shown. */
static void
classes_table(struct html *h)
{
	static const struct tcol tc[] = { { "Class", "name", false },
	    { "Point every", "step", true }, { "Kept", "retention", true },
	    { "Days on disk", "files", true }, { "Size", "bytes", true },
	    { "Oldest day", "oldest", false }, { "State", "full", false } };
	const ucl_object_t	**rows;
	char			 buf[48];
	int			 i;

	h_raw(h, "<h4>What the agent keeps</h4><table class=\"net "
	    "arch-classes\">");
	tbl_head(h, "arch-classes", tc, nitems(tc), 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("arch-classes", jget(ar.state, "class"), tc,
	    nitems(tc), app.filter);
	for (i = 0; rows[i] != NULL; i++) {
		const char	*name = jstr(rows[i], "name");

		if (name == NULL)
			continue;
		h_fmt(h, "<tr class=\"pick%s\" data-act=\"arch-class\" "
		    "title=\"Show it\"", strcmp(name, cur_class()->name) == 0 ?
		    " on" : "");
		h_attr(h, "data-arg", name);
		h_raw(h, "><td><b>");
		h_txt(h, name);
		h_fmt(h, "</b></td><td class=\"num\">%lld s</td><td class=\""
		    "num\">%lld d</td><td class=\"num\">%lld</td>",
		    (long long)jint(rows[i], "step", 60), (long long)jint(
		    rows[i], "retention", 0), (long long)jint(rows[i], "files",
		    0));
		fmt_size(buf, sizeof(buf), jnum(rows[i], "bytes", 0));
		h_raw(h, "<td class=\"num\">");
		h_txt(h, buf);
		h_raw(h, "</td><td>");
		if (jstr(rows[i], "oldest") != NULL)
			h_fmt(h, "%.10s", jstr(rows[i], "oldest"));
		else
			h_raw(h, "–");
		h_raw(h, "</td><td>");
		if (jbool(rows[i], "full"))
			h_raw(h, "<span class=\"chip st-down\" title=\"The "
			    "budget is reached with today's files alone: no "
			    "more until tomorrow (UTC)\">full</span>");
		else
			h_raw(h, "<span class=\"dim\">kept</span>");
		h_raw(h, "</td></tr>");
	}
	if (i == 0)
		h_raw(h, "<tr><td colspan=\"7\" class=\"dim\">Nothing.</td>"
		    "</tr>");
	free(rows);
	h_raw(h, "</tbody></table>");
	if (jget(ar.state, "budget") != NULL) {
		char	b2[32];

		fmt_size(buf, sizeof(buf), jnum(ar.state, "bytes", 0));
		fmt_size(b2, sizeof(b2), jnum(ar.state, "budget", 0));
		h_raw(h, "<p class=\"dim arch-budget\">");
		h_txt(h, buf);
		h_raw(h, " of its budget of ");
		h_txt(h, b2);
		h_raw(h, ": over it, the oldest day of any class goes first. "
		    "A file a class a day (UTC) in the agent's archive "
		    "directory, beside history.conf.</p>");
	}
}

/*
 * A host's long run, on its Monitoring tab: the classes, the ranges,
 * the series of the class to pick from, the plots of the one picked,
 * and what the archive holds.
 */
void
arch_view(struct html *h, struct server *s)
{
	const struct aclass	*c;
	const ucl_object_t	*sr;
	char			 words[48], when[2][32], buf[64];
	size_t			 i;
	bool			 got;

	if (strcmp(ar.sid, s->id) != 0)
		return;
	c = cur_class();
	h_raw(h, "<section class=\"transport arch\"><h3>Long run</h3>"
	    "<div class=\"toolbar\"><nav class=\"sub arch-classes-nav\">");
	for (i = 0; i < nitems(classes); i++) {
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"arch-"
		    "class\"", (int)i == ar.cls ? " on" : "");
		h_attr(h, "data-arg", classes[i].name);
		h_raw(h, ">");
		h_txt(h, classes[i].title);
		h_raw(h, "</button>");
	}
	h_raw(h, "</nav><nav class=\"sub arch-ranges\">");
	for (i = 0; i < nitems(ranges); i++) {
		if (ranges[i].secs == 0)
			snprintf(buf, sizeof(buf), "all %d d", keep_days());
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"arch-"
		    "range\" data-arg=\"%d\"", ranges[i].secs == ar.range ?
		    " on" : "", ranges[i].secs);
		if (ranges[i].secs == 0)
			h_raw(h, " title=\"All the class keeps: its "
			    "retention\"");
		h_raw(h, ">");
		h_txt(h, ranges[i].secs == 0 ? buf : ranges[i].title);
		h_raw(h, "</button>");
	}
	h_raw(h, "</nav><input class=\"filter\" id=\"filter\" data-input="
	    "\"filter\" placeholder=\"Filter\" autocomplete=\"off\" "
	    "spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, ">");
	fresh(h, ar.fetched, ar.lstate || ar.llist || ar.lpts, ar.error);
	h_raw(h, "</div>");
	if (ar.error[0] != '\0') {
		h_raw(h, "<p class=\"error arch-error\">");
		h_txt(h, ar.error);
		h_raw(h, "</p>");
	}
	range_words(words, sizeof(words));
	got = ar.cls == 0 ? ar.have_pts : ar.have_list;
	if (!got && ar.error[0] == '\0')
		h_raw(h, "<div class=\"loader\"></div>");
	if (got && ar.cls != 0 && ucl_array_size(ar.list) > 0)
		series_table(h);
	sr = ar.pts != NULL ? series(ar.pts, ar.cls == 0 ? "" : ar.name) :
	    NULL;
	if (got && sr != NULL && ucl_array_size(jget(sr, "point")) > 0) {
		plots(h, sr);
		iso(when[0], sizeof(when[0]), ar.from);
		iso(when[1], sizeof(when[1]), ar.to);
		h_raw(h, "<p class=\"dim arch-span\">");
		h_txt(h, words);
		snprintf(buf, sizeof(buf), ", a point every %.0f s",
		    num(jget(ar.pts, "step")));
		h_txt(h, buf);
		h_raw(h, ", from ");
		h_txt(h, when[0]);
		h_raw(h, " to ");
		h_txt(h, when[1]);
		h_raw(h, ": the agent's own points merged into as many as a "
		    "plot is wide. A gap is a time it kept nothing of.</p>");
	} else if (got && (ar.cls == 0 || ar.have_pts) && ar.error[0] ==
	    '\0') {
		h_raw(h, "<div class=\"empty arch-empty\"><p>Nothing "
		    "archived of ");
		h_txt(h, ar.cls == 0 ? "the host" : c->title);
		h_raw(h, " in ");
		h_txt(h, words);
		h_raw(h, ".</p><p class=\"dim\">");
		h_txt(h, c->none);
		h_raw(h, " A point is written once the next one begins.</p>"
		    "</div>");
	} else if (got && !ar.have_pts && ar.error[0] == '\0')
		h_raw(h, "<div class=\"loader\"></div>");
	if (ar.state != NULL)
		classes_table(h);
	h_raw(h, "</section>");
}

bool
arch_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	size_t		 i;

	(void)value;
	if (strncmp(act, "arch-", 5) != 0)
		return (false);
	if ((s = server(ar.sid)) == NULL)
		return (true);
	if (strcmp(act, "arch-class") == 0) {
		for (i = 0; i < nitems(classes) && strcmp(classes[i].name,
		    arg) != 0; i++)
			;
		if (i == nitems(classes) || (int)i == ar.cls)
			return (true);
		ar.cls = (int)i;
		ar.name[0] = '\0';
		app.filter[0] = '\0';
	} else if (strcmp(act, "arch-range") == 0) {
		for (i = 0; i < nitems(ranges) && ranges[i].secs != atoi(arg);
		    i++)
			;
		if (i == nitems(ranges) || ranges[i].secs == ar.range)
			return (true);
		ar.range = ranges[i].secs;
	} else if (strcmp(act, "arch-series") == 0) {
		if (strcmp(arg, ar.name) == 0)
			return (true);
		snprintf(ar.name, sizeof(ar.name), "%s", arg);
		/* The list stays: only the one drawn is read. */
		ar.gen++;
		ar.have_pts = false;
		ar.lpts = ar.llist = false;
		if (ar.pts != NULL)
			ucl_object_unref(ar.pts);
		ar.pts = NULL;
		pts_read(s);
		return (true);
	} else
		return (true);
	renew();
	arch_read(s);
	return (true);
}
