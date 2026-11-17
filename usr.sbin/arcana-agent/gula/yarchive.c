/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: the archive (archive.c) as arcana-history has it: its settings
 * (the archive container, configuration), what it holds (the state's
 * archive) and read-archive's points, made from archive.c's own
 * structs into the module's.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "agent.h"
#include "collect.h"

/* A time as yang:date-and-time, in a. */
static const char *
datetime(cbl_yarena *a, time_t t)
{
	struct tm	 tm;
	char		 buf[32], *p;

	if (gmtime_r(&t, &tm) == NULL || strftime(buf, sizeof(buf),
	    "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
		return (NULL);
	if ((p = cbl_yarena_alloc(a, strlen(buf) + 1)) != NULL)
		memcpy(p, buf, strlen(buf) + 1);
	return (p);
}

/* The settings: enabled and the budget always, a class where its step
 * or retention is set. */
const struct arcana_history_history_archive *
yarchive_conf(cbl_yarena *a)
{
	struct arcana_history_history_archive		*o;
	struct arcana_history_history_archive_class	*v;
	struct arc_conf					 cf;
	size_t						 n;
	int						 c;

	archive_conf_get(&cf);
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL || (v =
	    cbl_yarena_alloc(a, ARC_CLASSES * sizeof(*v))) == NULL)
		return (NULL);
	memset(o, 0, sizeof(*o));
	o->has_enabled = o->has_budget = true;
	o->enabled = cf.on;
	o->budget = cf.budget;
	for (c = 0, n = 0; c < ARC_CLASSES; c++) {
		if (cf.step[c] == 0 && cf.keep[c] == 0)
			continue;
		memset(&v[n], 0, sizeof(v[n]));
		v[n].name = (enum arcana_history_history_archive_class_name)c;
		if ((v[n].has_step = cf.step[c] != 0))
			v[n].step = cf.step[c];
		if ((v[n].has_retention = cf.keep[c] != 0))
			v[n].retention = cf.keep[c];
		n++;
	}
	o->class.n = n;
	o->class.v = v;
	return (o);
}

/*
 * The settings an edit gives (NULL: the defaults) in force: NULL, or
 * what is wrong with them, nothing changed then.
 */
const char *
yarchive_set(const struct arcana_history_history_archive *h)
{
	struct arc_conf	cf;
	size_t		i;

	memset(&cf, 0, sizeof(cf));
	cf.on = h == NULL || !h->has_enabled || h->enabled;
	cf.budget = h != NULL && h->has_budget ? h->budget : ARC_BUDGET;
	for (i = 0; h != NULL && i < h->class.n; i++) {
		const struct arcana_history_history_archive_class *k =
		    &h->class.v[i];

		if ((unsigned int)k->name >= ARC_CLASSES)
			return ("an archive class is host, interface, disk, "
			    "jail, relay or probe");
		if (k->has_step)
			cf.step[k->name] = k->step;
		if (k->has_retention) {
			if (k->retention == 0)
				return ("an archive class's retention is 1 to "
				    "3660 days");
			cf.keep[k->name] = k->retention;
		}
	}
	return (archive_conf_set(&cf));
}

const struct arcana_history_history_state_archive *
yarchive_state(cbl_yarena *a)
{
	struct arcana_history_history_state_archive		*o;
	struct arcana_history_history_state_archive_class	*v;
	struct arc_state					 st;
	int							 c;

	archive_state(&st);
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL || (v =
	    cbl_yarena_alloc(a, ARC_CLASSES * sizeof(*v))) == NULL)
		return (NULL);
	memset(o, 0, sizeof(*o));
	o->has_bytes = o->has_budget = true;
	o->bytes = st.bytes;
	o->budget = st.budget;
	for (c = 0; c < ARC_CLASSES; c++) {
		memset(&v[c], 0, sizeof(v[c]));
		v[c].name = (enum arcana_history_history_state_archive_class_name)c;
		v[c].has_bytes = v[c].has_files = v[c].has_series = true;
		v[c].bytes = st.c[c].bytes;
		v[c].files = st.c[c].files;
		v[c].series = st.c[c].series;
		if (st.c[c].oldest != -1)
			v[c].oldest = datetime(a, (time_t)st.c[c].oldest *
			    86400);
		v[c].has_step = v[c].has_retention = v[c].has_full = true;
		v[c].step = (uint16_t)st.c[c].step;
		v[c].retention = (uint16_t)st.c[c].keep;
		v[c].full = st.c[c].full;
	}
	o->class.n = ARC_CLASSES;
	o->class.v = v;
	return (o);
}

/* read-archive's output, in a: the fields, their scales, each series'
 * points.  0, or an errno with why. */
int
yarchive_read(int c, const char *name, time_t from, time_t to,
    unsigned int points, cbl_yarena *a,
    struct arcana_history_history_read_archive_output *out,
    const char **why)
{
	struct arcana_history_history_read_archive_output_series	*sv;
	struct arcana_history_history_read_archive_output_series_point	*pv;
	struct arc_read							 r;
	int64_t								*vals;
	char								*nm;
	size_t								 i, k;
	int								 error;

	memset(out, 0, sizeof(*out));
	if ((error = archive_read(c, name, from, to, points, &r, why)) != 0)
		return (error);
	error = ENOMEM;
	*why = "out of memory";
	out->has_step = true;
	out->step = r.step;
	out->field.n = r.ncols;
	out->field.v = r.fields;
	out->scale.n = r.ncols;
	out->scale.v = r.scale;
	if ((sv = cbl_yarena_alloc(a, (r.ns + 1) * sizeof(*sv))) == NULL)
		goto out;
	for (i = 0; i < r.ns; i++) {
		memset(&sv[i], 0, sizeof(sv[i]));
		if ((nm = cbl_yarena_alloc(a, strlen(r.s[i].name) + 1)) ==
		    NULL || (pv = cbl_yarena_alloc(a, (r.s[i].npoints + 1) *
		    sizeof(*pv))) == NULL || (vals = cbl_yarena_alloc(a,
		    (r.s[i].npoints * r.ncols + 1) * sizeof(*vals))) == NULL)
			goto out;
		memcpy(nm, r.s[i].name, strlen(r.s[i].name) + 1);
		sv[i].name = nm;
		memcpy(vals, r.s[i].v, r.s[i].npoints * r.ncols *
		    sizeof(*vals));
		for (k = 0; k < r.s[i].npoints; k++) {
			memset(&pv[k], 0, sizeof(pv[k]));
			if ((pv[k].time = datetime(a, (time_t)r.s[i].t[k])) ==
			    NULL)
				goto out;
			pv[k].value.n = r.ncols;
			pv[k].value.v = vals + k * r.ncols;
		}
		sv[i].point.n = r.s[i].npoints;
		sv[i].point.v = pv;
	}
	out->series.n = r.ns;
	out->series.v = sv;
	error = 0;
	*why = NULL;
out:
	archive_read_free(&r);
	return (error);
}
