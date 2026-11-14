/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: the agent's faults (faults.c) as RFC 8632's alarms.  An alarm
 * is the faults of one object and kind, the list's key (resource,
 * alarm-type-id, alarm-type-qualifier): its object the resource, as a
 * string; its kind arcana-alarms' alarm type, no qualifier.  Each
 * fault of it is a raise and a clearing, its status changes in their
 * order (alarm-history); the alarm is as its last fault is (cleared or
 * not, its severity Warning, Minor, Major or Critical, its text), made
 * when its first was raised.  The inventory is every kind the agent
 * raises, with the severities it raises it with; the summary counts
 * the alarms by severity, each once.  An alarm on a shelf of the
 * control's (gula/faults.c) is a shelved alarm, in neither the list nor
 * the summary; the control itself, running's, goes to and comes from
 * faults.c as RFC 7951's JSON, its alarm types named.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "collect.h"
#include "yjson.h"

typedef struct ietf_alarms_alarms_alarm_list_alarm yalarm;

/* Each kind of fault, as faults.c's callers raise it. */
static const struct kind {
	const char	*name;
	int		 sev[2];	/* 0 ends */
	const char	*descr;
} kinds[] = {
	{ "tunnel", { 5, 0 }, "an SD-WAN tunnel's far end did not answer" },
	{ "underlay", { 5, 0 }, "an SD-WAN underlay path's far end did not "
	    "answer" },
	{ "stamp-unauthenticated", { 3, 0 }, "a plain tunnel's authenticated "
	    "STAMP fell back to ICMP echo" },
	{ "tca", { 4, 0 }, "a probe's metric crossed its threshold" },
	{ "bfd", { 5, 0 }, "a BFD session went down" },
	{ "bgp-neighbor", { 4, 5 }, "a BGP session left Established" },
	{ "ospf-neighbor", { 5, 0 }, "an OSPF neighbour left Full" },
	{ "bird-instance", { 6, 0 }, "BIRD does not answer" },
	{ "interface", { 5, 0 }, "an SD-WAN interface has no link" },
	{ "ids", { 3, 6 }, "a Suricata instance that prevents is not running" },
	{ "key-rotation", { 5, 0 }, "manual IPsec keys were not rotated" },
	{ "storage", { 5, 0 }, "a pool or file system is too full" },
	{ "cpu", { 5, 0 }, "the CPU has been too busy" },
	{ "memory", { 5, 0 }, "the memory has been too full" },
	{ "crash", { 5, 0 }, "a process died of a signal that dumps core" },
	{ "mail", { 4, 5 }, "smtpd stopped, or too much queued" },
	{ "undo", { 6, 0 }, "a confirmed commit could not be undone" },
	{ "nacm-rules", { 4, 5 }, "the access rules have a path rule whose "
	    "path does not compile" },
	{ "alarm-list-full", { 5, 0 }, "every place of the alarm list is an "
	    "open alarm: new ones are refused" },
};

/* An identity's SID, by its module and name; 0: none. */
static uint64_t
ident_sid(const char *mod, const char *name)
{
	const struct cbl_yident	*id;
	uint32_t		 i;

	for (i = 0; i < ymodel_schema.nident; i++) {
		id = &ymodel_schema.ident[i];
		if (strcmp(id->name, name) == 0 &&
		    strcmp(id->module->name, mod) == 0)
			return (id->sid);
	}
	return (0);
}

/* A severity's value (RFC 8632's enumeration), by faults.c's word. */
static int
severity(const char *s)
{

	if (s == NULL)
		return (2);
	if (strcasecmp(s, "Warning") == 0)
		return (3);
	if (strcasecmp(s, "Minor") == 0)
		return (4);
	if (strcasecmp(s, "Major") == 0)
		return (5);
	if (strcasecmp(s, "Critical") == 0)
		return (6);
	return (2);		/* indeterminate */
}

static const char *
datetime(cbl_yarena *a, int64_t t)
{
	char		 buf[32];
	struct tm	 tm;
	time_t		 tt = (time_t)t;
	char		*p;

	if (gmtime_r(&tt, &tm) == NULL)
		return (NULL);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
	if ((p = cbl_yarena_alloc(a, strlen(buf) + 1)) != NULL)
		memcpy(p, buf, strlen(buf) + 1);
	return (p);
}

/* The alarm inventory: every kind, as the agent raises it. */
static int
inventory(cbl_yarena *a, struct ietf_alarms_alarms *al)
{
	struct ietf_alarms_alarms_alarm_inventory		*inv;
	struct ietf_alarms_alarms_alarm_inventory_alarm_type	*t;
	enum ietf_alarms_alarms_alarm_inventory_alarm_type_severity_level *sv;
	size_t							 i, k;

	if ((inv = cbl_yarena_alloc(a, sizeof(*inv))) == NULL ||
	    (t = cbl_yarena_alloc(a, nitems(kinds) * sizeof(*t))) == NULL)
		return (ENOMEM);
	for (i = 0; i < nitems(kinds); i++) {
		t[i].alarm_type_id = ident_sid("arcana-alarms", kinds[i].name);
		t[i].alarm_type_qualifier = "";
		t[i].has_will_clear = true;
		t[i].will_clear = true;
		for (k = 0; k < 2 && kinds[i].sev[k] != 0; k++)
			;
		if ((sv = cbl_yarena_alloc(a, k * sizeof(*sv))) == NULL)
			return (ENOMEM);
		for (k = 0; k < 2 && kinds[i].sev[k] != 0; k++)
			sv[k] = kinds[i].sev[k];
		t[i].severity_level.n = k;
		t[i].severity_level.v = sv;
		t[i].description = kinds[i].descr;
	}
	inv->alarm_type.n = nitems(kinds);
	inv->alarm_type.v = t;
	al->alarm_inventory = inv;
	return (0);
}

/* A fault of the faults' JSON: what an alarm is made of. */
struct rec {
	const char	*type, *object, *text, *shelf;
	int64_t		 t, cl;		/* raised; cleared, 0 not */
	int		 sev;
	bool		 compressed;
	int		 next;		/* the next of its alarm's, -1 none */
};

/* A fault's status changes into sc (from k): raised, and cleared when
 * it was; compressed, or cleared within the second it was raised (the
 * change's time its key), the clearing alone.  The next k. */
static size_t
changes(cbl_yarena *a, const struct rec *r,
    struct ietf_alarms_alarms_alarm_list_alarm_status_change *sc, size_t k)
{

	if (r->cl == 0 || (!r->compressed && r->cl != r->t)) {
		sc[k].time = datetime(a, r->t);
		sc[k].has_perceived_severity = true;
		sc[k].perceived_severity.which = 1;
		sc[k].perceived_severity.v.m1 = r->sev;
		sc[k++].alarm_text = r->text;
	}
	if (r->cl != 0) {
		sc[k].time = datetime(a, r->cl);
		sc[k].has_perceived_severity = true;
		sc[k].perceived_severity.which = 0;
		sc[k].perceived_severity.v.m0 =
		    IETF_ALARMS_ALARMS_ALARM_LIST_ALARM_STATUS_CHANGE_PERCEIVED_SEVERITY_M0_CLEARED;
		sc[k++].alarm_text = r->text;
	}
	return (k);
}

/* An alarm's history: each fault of it, from first (its others by
 * next), in order; at most max changes (-1 any), the latest kept. */
static int
history(cbl_yarena *a, const struct rec *recs, int first, yalarm *v,
    int64_t max)
{
	struct ietf_alarms_alarms_alarm_list_alarm_status_change *sc;
	size_t	n;
	int	i;

	for (n = 0, i = first; i != -1; i = recs[i].next)
		n += 2;
	if ((sc = cbl_yarena_alloc(a, n * sizeof(*sc))) == NULL)
		return (ENOMEM);
	for (n = 0, i = first; i != -1; i = recs[i].next)
		n = changes(a, &recs[i], sc, n);
	v->status_change.n = n;
	v->status_change.v = sc;
	/* max-alarm-status-changes. */
	if (max >= 0 && v->status_change.n > (size_t)max) {
		v->status_change.v += v->status_change.n - (size_t)max;
		v->status_change.n = (size_t)max;
	}
	return (0);
}

/* An alarm of the list as a shelved one, on shelf. */
static int
shelved(cbl_yarena *a, const yalarm *v, const char *shelf,
    struct ietf_alarms_alarms_shelved_alarms_shelved_alarm *s)
{
	struct ietf_alarms_alarms_shelved_alarms_shelved_alarm_status_change *sc;
	size_t	i;

	memset(s, 0, sizeof(*s));
	s->resource.which = 2;
	s->resource.v.m2 = v->resource.v.m2;
	s->alarm_type_id = v->alarm_type_id;
	s->alarm_type_qualifier = v->alarm_type_qualifier;
	s->shelf_name = shelf;
	s->has_is_cleared = true;
	s->is_cleared = v->is_cleared;
	s->last_raised = v->last_raised;
	s->last_changed = v->last_changed;
	s->has_perceived_severity = true;
	s->perceived_severity = (int)v->perceived_severity;
	s->alarm_text = v->alarm_text;
	if (v->status_change.n == 0)
		return (0);
	if ((sc = cbl_yarena_alloc(a, v->status_change.n * sizeof(*sc))) ==
	    NULL)
		return (ENOMEM);
	for (i = 0; i < v->status_change.n; i++) {
		sc[i].time = v->status_change.v[i].time;
		sc[i].has_perceived_severity = true;
		sc[i].perceived_severity.which =
		    v->status_change.v[i].perceived_severity.which;
		if (sc[i].perceived_severity.which == 0)
			sc[i].perceived_severity.v.m0 =
			    IETF_ALARMS_ALARMS_SHELVED_ALARMS_SHELVED_ALARM_STATUS_CHANGE_PERCEIVED_SEVERITY_M0_CLEARED;
		else
			sc[i].perceived_severity.v.m1 = (int)
			    v->status_change.v[i].perceived_severity.v.m1;
		sc[i].alarm_text = v->status_change.v[i].alarm_text;
	}
	s->status_change.n = v->status_change.n;
	s->status_change.v = sc;
	return (0);
}

/*
 * The faults' JSON (faults_json(): the faults, the shelves' count, the
 * history's length) as ietf-alarms' state: the faults of one object and
 * kind one alarm; those of no shelf the alarm list and the summary, the
 * others the shelved alarms.
 */
int
yalarms_from_json(const char *json, cbl_yarena *a, struct ietf_alarms *out)
{
	struct ietf_alarms_alarms			*al;
	struct ietf_alarms_alarms_alarm_list		*list;
	struct ietf_alarms_alarms_shelved_alarms	*shl;
	struct ietf_alarms_alarms_shelved_alarms_shelved_alarm *sv2;
	struct ietf_alarms_alarms_summary		*sum;
	struct ietf_alarms_alarms_summary_alarm_summary	*sv;
	const ucl_object_t				*arr, *e;
	ucl_object_iter_t				 it;
	ucl_object_t					*top;
	yalarm						*v, x;
	struct rec					*recs, *r;
	const char					*last, *slast, *sh;
	int64_t						 t, cl, lastt, slastt, max;
	int64_t						 nsh;
	size_t						 n, ns, i, nr;
	int						*first, *tail;
	bool						 has;
	int						 sev, error, g, ng;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	error = ENOMEM;
	arr = ucl_object_lookup(top, "faults");
	if (!yj_num(top, "max_changes", &max))
		max = -1;
	if (!yj_num(top, "shelves", &nsh))
		nsh = 0;
	if ((al = cbl_yarena_alloc(a, sizeof(*al))) == NULL ||
	    (list = cbl_yarena_alloc(a, sizeof(*list))) == NULL ||
	    (shl = cbl_yarena_alloc(a, sizeof(*shl))) == NULL ||
	    (sum = cbl_yarena_alloc(a, sizeof(*sum))) == NULL ||
	    (sv = cbl_yarena_alloc(a, 5 * sizeof(*sv))) == NULL ||
	    (v = cbl_yarena_alloc(a, (yj_count(arr) + 1) * sizeof(*v))) ==
	    NULL || (sv2 = cbl_yarena_alloc(a, (yj_count(arr) + 1) *
	    sizeof(*sv2))) == NULL || (recs = cbl_yarena_alloc(a,
	    (yj_count(arr) + 1) * sizeof(*recs))) == NULL || (first =
	    cbl_yarena_alloc(a, (yj_count(arr) + 1) * sizeof(*first))) ==
	    NULL || (tail = cbl_yarena_alloc(a, (yj_count(arr) + 1) *
	    sizeof(*tail))) == NULL)
		goto out;
	if ((error = inventory(a, al)) != 0)
		goto out;
	/* The summary: each severity, those cleared and not; the shelved
	 * not in it. */
	for (i = 0; i < 5; i++) {
		sv[i].severity = (int)i + 2;
		sv[i].has_total = sv[i].has_not_cleared = sv[i].has_cleared =
		    true;
	}
	/* The faults, the oldest first, each with the next of its alarm's
	 * (its object and kind): an alarm's first and last by first[] and
	 * tail[], in the order each alarm was first raised. */
	nr = 0;
	ng = 0;
	YJ_EACH(arr, it, e) {
		if (nr == yj_count(arr))
			break;
		r = &recs[nr];
		memset(r, 0, sizeof(*r));
		if ((r->type = yj_str(a, e, "type")) == NULL ||
		    (r->object = yj_str(a, e, "object")) == NULL ||
		    !yj_num(e, "t", &r->t))
			continue;
		if (yj_yes(e, "cleared", &has) && !yj_num(e, "cleared_at",
		    &r->cl))
			r->cl = r->t;
		/* Its severity when raised: "was" keeps it once cleared. */
		r->sev = severity(yj_str(a, e, "was"));
		if ((r->text = yj_str(a, e, "description")) == NULL)
			r->text = "";
		r->shelf = yj_str(a, e, "shelf");
		r->compressed = yj_yes(e, "compressed", &has);
		r->next = -1;
		for (g = 0; g < ng && (strcmp(recs[first[g]].type, r->type) !=
		    0 || strcmp(recs[first[g]].object, r->object) != 0); g++)
			;
		if (g == ng) {
			first[ng] = tail[ng] = (int)nr;
			ng++;
		} else {
			recs[tail[g]].next = (int)nr;
			tail[g] = (int)nr;
		}
		nr++;
	}
	n = ns = 0;
	lastt = slastt = 0;
	last = slast = NULL;
	for (g = 0; g < ng; g++) {
		/* As its last fault is; made when its first was raised. */
		r = &recs[tail[g]];
		t = r->t;
		cl = r->cl;
		sev = r->sev;
		memset(&x, 0, sizeof(x));
		x.resource.which = 2;	/* its string member */
		x.resource.v.m2 = r->object;
		x.alarm_type_id = ident_sid("arcana-alarms", r->type);
		x.alarm_type_qualifier = "";
		x.time_created = datetime(a, recs[first[g]].t);
		x.last_raised = datetime(a, t);
		x.has_is_cleared = true;
		x.is_cleared = cl != 0;
		x.last_changed = cl != 0 ? datetime(a, cl) : x.last_raised;
		x.has_perceived_severity = true;
		x.perceived_severity = sev;
		x.alarm_text = r->text;
		if ((error = history(a, recs, first[g], &x, max)) != 0)
			goto out;
		/* A shelf is of an object and kind: every fault's the same. */
		if ((sh = r->shelf) != NULL) {
			if ((error = shelved(a, &x, sh, &sv2[ns])) != 0)
				goto out;
			ns++;
			if ((cl != 0 ? cl : t) >= slastt) {
				slastt = cl != 0 ? cl : t;
				slast = x.last_changed;
			}
			continue;
		}
		v[n] = x;
		sv[sev - 2].total++;
		if (x.is_cleared)
			sv[sev - 2].cleared++;
		else
			sv[sev - 2].not_cleared++;
		if ((cl != 0 ? cl : t) >= lastt) {
			lastt = cl != 0 ? cl : t;
			last = x.last_changed;
		}
		n++;
	}
	list->has_number_of_alarms = true;
	list->number_of_alarms = (uint32_t)n;
	list->last_changed = last;
	list->alarm.n = n;
	list->alarm.v = n > 0 ? v : NULL;
	shl->has_number_of_shelved_alarms = true;
	shl->number_of_shelved_alarms = (uint32_t)ns;
	shl->shelved_alarms_last_changed = slast;
	shl->shelved_alarm.n = ns;
	shl->shelved_alarm.v = ns > 0 ? sv2 : NULL;
	sum->alarm_summary.n = 5;
	sum->alarm_summary.v = sv;
	/* A hint that shelves are configured; there whenever one shelves
	 * an alarm (RFC 8632). */
	sum->shelves_active = nsh > 0 || ns > 0;
	al->alarm_list = list;
	al->shelved_alarms = shl;
	al->summary = sum;
	out->alarms = al;
	error = 0;
out:
	ucl_object_unref(top);
	return (error);
}

/* s copied into the arena; NULL as it is. */
static const char *
copy(cbl_yarena *a, const char *s)
{
	char	*p;

	if (s == NULL || (p = cbl_yarena_alloc(a, strlen(s) + 1)) == NULL)
		return (NULL);
	memcpy(p, s, strlen(s) + 1);
	return (p);
}

/* An identity by its SID: "module:name"; NULL none. */
static const char *
ident_name(cbl_yarena *a, uint64_t sid)
{
	const struct cbl_yident	*id;
	char			*p;
	size_t			 len;
	uint32_t		 i;

	for (i = 0; i < ymodel_schema.nident; i++) {
		id = &ymodel_schema.ident[i];
		if (id->sid != sid)
			continue;
		len = strlen(id->module->name) + strlen(id->name) + 2;
		if ((p = cbl_yarena_alloc(a, len)) != NULL)
			snprintf(p, len, "%s:%s", id->module->name, id->name);
		return (p);
	}
	return (NULL);
}

static const char *const notify_names[] = { "all-state-changes",
    "raise-and-clear", "severity-level" };
static const char *const level_names[] = { "indeterminate", "warning",
    "minor", "major", "critical" };

/* A resource-match's string, whichever member it came as. */
static const char *
match_str(const struct ietf_alarms_alarms_control_alarm_shelving_shelf_resource
    *r)
{

	return (r->which == 0 ? r->v.m0 : r->which == 1 ? r->v.m1 : r->v.m2);
}

/*
 * ietf-alarms' control, c, as RFC 7951's JSON (faults_control()), the
 * alarm types by name; NULL with none, or a type no identity is.  The
 * caller frees it.
 */
char *
yalarms_control_json(const struct ietf_alarms_alarms_control *c,
    cbl_yarena *a)
{
	const struct ietf_alarms_alarms_control_alarm_shelving_shelf *s;
	ucl_object_t	*top, *arr, *o, *res, *tys, *ty;
	const char	*id;
	char		*json;
	size_t		 i, k;

	if (c == NULL)
		return (NULL);
	top = ucl_object_typed_new(UCL_OBJECT);
	if (c->has_max_alarm_status_changes)
		ucl_object_insert_key(top, c->max_alarm_status_changes.which == 0 ?
		    ucl_object_fromint(c->max_alarm_status_changes.v.m0) :
		    ucl_object_fromstring("infinite"),
		    "max-alarm-status-changes", 0, false);
	if (c->has_notify_status_changes && (size_t)c->notify_status_changes <
	    nitems(notify_names))
		ucl_object_insert_key(top, ucl_object_fromstring(
		    notify_names[c->notify_status_changes]),
		    "notify-status-changes", 0, false);
	if (c->has_notify_severity_level && c->notify_severity_level >= 2 &&
	    c->notify_severity_level <= 6)
		ucl_object_insert_key(top, ucl_object_fromstring(
		    level_names[c->notify_severity_level - 2]),
		    "notify-severity-level", 0, false);
	if (c->alarm_shelving != NULL) {
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < c->alarm_shelving->shelf.n; i++) {
			s = &c->alarm_shelving->shelf.v[i];
			o = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(o, ucl_object_fromstring(s->name),
			    "name", 0, false);
			res = ucl_object_typed_new(UCL_ARRAY);
			for (k = 0; k < s->resource.n; k++)
				ucl_array_append(res, ucl_object_fromstring(
				    match_str(&s->resource.v[k])));
			ucl_object_insert_key(o, res, "resource", 0, false);
			tys = ucl_object_typed_new(UCL_ARRAY);
			for (k = 0; k < s->alarm_type.n; k++) {
				if ((id = ident_name(a,
				    s->alarm_type.v[k].alarm_type_id)) == NULL) {
					ucl_object_unref(o);
					ucl_object_unref(tys);
					ucl_object_unref(arr);
					ucl_object_unref(top);
					return (NULL);
				}
				ty = ucl_object_typed_new(UCL_OBJECT);
				ucl_object_insert_key(ty, ucl_object_fromstring(id),
				    "alarm-type-id", 0, false);
				ucl_object_insert_key(ty, ucl_object_fromstring(
				    s->alarm_type.v[k].alarm_type_qualifier_match),
				    "alarm-type-qualifier-match", 0, false);
				ucl_array_append(tys, ty);
			}
			ucl_object_insert_key(o, tys, "alarm-type", 0, false);
			if (s->description != NULL)
				ucl_object_insert_key(o, ucl_object_fromstring(
				    s->description), "description", 0, false);
			ucl_array_append(arr, o);
		}
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, arr, "shelf", 0, false);
		ucl_object_insert_key(top, o, "alarm-shelving", 0, false);
	}
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	return (json);
}

/* The control as kept (faults_control_json()) as ietf-alarms'; *out
 * NULL with none. */
int
yalarms_control_from_json(const char *json, cbl_yarena *a,
    const struct ietf_alarms_alarms_control **out)
{
	struct ietf_alarms_alarms_control			*c;
	struct ietf_alarms_alarms_control_alarm_shelving		*sh;
	struct ietf_alarms_alarms_control_alarm_shelving_shelf		*sv = NULL;
	struct ietf_alarms_alarms_control_alarm_shelving_shelf_resource	*rv;
	struct ietf_alarms_alarms_control_alarm_shelving_shelf_alarm_type *tv;
	const ucl_object_t	*o, *s, *r, *t;
	ucl_object_iter_t	 it, rit;
	ucl_object_t		*top;
	const char		*w, *id, *colon;
	char			 mod[64];
	int64_t			 m;
	size_t			 n, i, k;
	int			 error = ENOMEM;

	*out = NULL;
	if (json == NULL || json[0] == '\0')
		return (0);
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	if ((c = cbl_yarena_alloc(a, sizeof(*c))) == NULL)
		goto out;
	if ((o = ucl_object_lookup(top, "max-alarm-status-changes")) != NULL) {
		c->has_max_alarm_status_changes = true;
		if (yj_num(top, "max-alarm-status-changes", &m)) {
			c->max_alarm_status_changes.which = 0;
			c->max_alarm_status_changes.v.m0 = (uint16_t)m;
		} else {
			c->max_alarm_status_changes.which = 1;
			c->max_alarm_status_changes.v.m1 =
			    IETF_ALARMS_ALARMS_CONTROL_MAX_ALARM_STATUS_CHANGES_M1_INFINITE;
		}
	}
	if ((w = yj_str(a, top, "notify-status-changes")) != NULL)
		for (i = 0; i < nitems(notify_names); i++)
			if (strcmp(w, notify_names[i]) == 0) {
				c->has_notify_status_changes = true;
				c->notify_status_changes = (int)i;
			}
	if ((w = yj_str(a, top, "notify-severity-level")) != NULL)
		for (i = 0; i < nitems(level_names); i++)
			if (strcmp(w, level_names[i]) == 0) {
				c->has_notify_severity_level = true;
				c->notify_severity_level = (int)i + 2;
			}
	if ((s = ucl_object_lookup(top, "alarm-shelving")) != NULL) {
		if ((sh = cbl_yarena_alloc(a, sizeof(*sh))) == NULL)
			goto out;
		n = yj_count(ucl_object_lookup(s, "shelf"));
		if (n > 0 && (sv = cbl_yarena_alloc(a, n * sizeof(*sv))) == NULL)
			goto out;
		i = 0;
		/* Only what yj_count() sized: an array's members (faults.c
		 * keeps no other). */
		YJ_EACH(ucl_object_lookup(s, "shelf"), it, o) {
			if (i == n)
				break;
			sv[i].name = yj_str(a, o, "name");
			sv[i].description = yj_str(a, o, "description");
			r = ucl_object_lookup(o, "resource");
			rv = NULL;
			if (yj_count(r) > 0 && (rv = cbl_yarena_alloc(a,
			    yj_count(r) * sizeof(*rv))) == NULL)
				goto out;
			k = 0;
			YJ_EACH(r, rit, t) {
				if (k == yj_count(r))
					break;
				rv[k].which = 2;
				rv[k].v.m2 = copy(a, ucl_object_tostring(t));
				k++;
			}
			sv[i].resource.n = k;
			sv[i].resource.v = k > 0 ? rv : NULL;
			r = ucl_object_lookup(o, "alarm-type");
			tv = NULL;
			if (yj_count(r) > 0 && (tv = cbl_yarena_alloc(a,
			    yj_count(r) * sizeof(*tv))) == NULL)
				goto out;
			k = 0;
			YJ_EACH(r, rit, t) {
				if (k == yj_count(r))
					break;
				/* "module:name", a module's identity. */
				if ((id = yj_str(a, t, "alarm-type-id")) == NULL ||
				    (colon = strchr(id, ':')) == NULL ||
				    (size_t)(colon - id) >= sizeof(mod))
					continue;
				snprintf(mod, sizeof(mod), "%.*s", (int)(colon - id),
				    id);
				tv[k].alarm_type_id = ident_sid(mod, colon + 1);
				tv[k].alarm_type_qualifier_match = yj_str(a, t,
				    "alarm-type-qualifier-match");
				if (tv[k].alarm_type_qualifier_match == NULL)
					tv[k].alarm_type_qualifier_match = "";
				k++;
			}
			sv[i].alarm_type.n = k;
			sv[i].alarm_type.v = k > 0 ? tv : NULL;
			i++;
		}
		sh->shelf.n = i;
		sh->shelf.v = i > 0 ? sv : NULL;
		c->alarm_shelving = sh;
	}
	*out = c;
	error = 0;
out:
	ucl_object_unref(top);
	return (error);
}
