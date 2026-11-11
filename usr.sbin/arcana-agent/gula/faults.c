/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Faults (Mplify 119 §11.3): each with the time it was seen or
 * cleared, a type (Table 4: interface-down, bfd, bgp-neighbor, cpu,
 * memory, storage; and ours: tunnel, underlay (a UCS End Point's path
 * outside the tunnels), stamp-unauthenticated (a plain tunnel's
 * authenticated STAMP fallen back to ICMP), bird-instance,
 * ospf-neighbor, tca;
 * luxuria/birdwatch.c's for the host's BIRD; crash, kmsg.c's,
 * a program the kernel saw die of a signal), a severity
 * (Warning, Minor, Major, Critical; Cleared when it is), what it is
 * of, who saw it and a line of description (Table 5).  One open fault
 * of a type and object at a time; set and cleared are events
 * (sdwan-fault, R71) besides.  Kept 24 hours (D5), on disk too.
 *
 * Their control is ietf-alarms' (RFC 8632, PLAN-SDN-YANG 5.4.2), the
 * running configuration (invidia/yserve.c), kept beside the faults
 * (alarm-control.json, RFC 7951's JSON of the control) for the next
 * start: its shelves, in order, a fault the first's that matches (its
 * resources, any of them, and its alarm types, any of them, both; none
 * of either any), shelved: kept, its state followed, but no event; the
 * events told as notify-status-changes says (a raise under
 * notify-severity-level not told; a clearing always); its history at
 * most max-alarm-status-changes long (gula/yalarms.c).  A resource and
 * an alarm type qualifier match by the XML Schema regular expression
 * RFC 8632 says, taken as POSIX's extended one (regex(3)) of the whole
 * string; an alarm type matches its own identity, and ietf-alarms'
 * alarm-type-id and arcana-alarms' arcana-fault every fault's.
 */

#include <sys/param.h>

#include <pthread.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <ucl.h>

#include "agent.h"

#define	FAULTS_FILE	"sdwan-faults.json"
#define	FAULTS_MAX	2048
#define	FAULTS_KEEP	(24 * 3600)

struct fault {
	time_t	t, cleared_at;
	char	type[24];
	char	severity[12];
	char	object[128];
	char	by[12];
	char	descr[200];
	bool	cleared;
	bool	compressed;	/* its history the clearing alone */
};

#define	CONTROL_FILE	"alarm-control.json"

/* A shelf: its resources' expressions and its alarm types, each an
 * arcana-alarms name ("" any fault's; none, another module's, no
 * fault's) and its qualifier's expression. */
struct shelf {
	char		*name;
	regex_t		*res;
	size_t		 nres;
	struct shtype {
		char	 type[24];
		bool	 none;
		regex_t	 q;
	}		*ty;
	size_t		 nty;
};

/* notify-status-changes: all-state-changes, raise-and-clear (the same
 * here: a fault's line said anew is no event), severity-level. */
enum { NOTIFY_ALL, NOTIFY_RAISE_CLEAR, NOTIFY_LEVEL };

static pthread_mutex_t	lock = PTHREAD_MUTEX_INITIALIZER;
static struct fault	*faults;
static int		 nfaults;
/* The control, under the lock: as kept, and made of it. */
static char		*control;
static struct shelf	*shelves;
static size_t		 nshelves;
static int		 notify_how, notify_level;
static int		 max_changes = -1;	/* -1: infinite */

/* A string as JSON's: quotes and backslashes escaped. */
static const char *
jq(const char *s, char *buf, size_t len)
{
	size_t	i, n;

	for (i = 0, n = 0; s != NULL && s[i] != '\0' && n + 2 < len; i++) {
		if (s[i] == '"' || s[i] == '\\')
			buf[n++] = '\\';
		buf[n++] = s[i] < 0x20 ? ' ' : s[i];
	}
	buf[n] = '\0';
	return (buf);
}

static int	rank(const char *);

/* s matches re whole. */
static bool
whole(const regex_t *re, const char *s)
{
	regmatch_t	m;

	return (regexec(re, s, 1, &m, 0) == 0 && m.rm_so == 0 &&
	    s[m.rm_eo] == '\0');
}

/* With the lock held: the shelf f is on, the first that matches it;
 * NULL, none. */
static const char *
shelf_of(const struct fault *f)
{
	const struct shelf	*s;
	size_t			 i, k;

	for (i = 0; i < nshelves; i++) {
		s = &shelves[i];
		for (k = 0; k < s->nres && !whole(&s->res[k], f->object); k++)
			;
		if (s->nres > 0 && k == s->nres)
			continue;
		/* A fault's qualifier is "". */
		for (k = 0; k < s->nty; k++)
			if (!s->ty[k].none && (s->ty[k].type[0] == '\0' ||
			    strcmp(s->ty[k].type, f->type) == 0) &&
			    whole(&s->ty[k].q, ""))
				break;
		if (s->nty > 0 && k == s->nty)
			continue;
		return (s->name);
	}
	return (NULL);
}

/* With the lock held: whether a fault's change of severity sev is told
 * (notify-status-changes); a clearing (NULL) always is. */
static bool
told(const char *sev)
{

	return (sev == NULL || notify_how != NOTIFY_LEVEL ||
	    rank(sev) >= notify_level);
}

/* The day's faults as JSON, the oldest first; with shelf, a shelved
 * one's shelf. */
static ucl_object_t *
faults_array(time_t since, bool shelf)
{
	ucl_object_t	*arr, *o;
	const char	*sh;
	int		 i;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < nfaults; i++) {
		if (faults[i].t < since && (!faults[i].cleared ||
		    faults[i].cleared_at < since))
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromint(faults[i].t), "t", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(faults[i].type),
		    "type", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(faults[i].cleared ?
		    "Cleared" : faults[i].severity), "severity", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(faults[i].severity),
		    "was", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(faults[i].object),
		    "object", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(faults[i].by), "by",
		    0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(faults[i].descr),
		    "description", 0, false);
		ucl_object_insert_key(o, ucl_object_frombool(faults[i].cleared),
		    "cleared", 0, false);
		if (faults[i].cleared)
			ucl_object_insert_key(o, ucl_object_fromint(
			    faults[i].cleared_at), "cleared_at", 0, false);
		if (faults[i].compressed)
			ucl_object_insert_key(o, ucl_object_frombool(true),
			    "compressed", 0, false);
		if (shelf && (sh = shelf_of(&faults[i])) != NULL)
			ucl_object_insert_key(o, ucl_object_fromstring(sh),
			    "shelf", 0, false);
		ucl_array_append(arr, o);
	}
	return (arr);
}

/* With the lock held: the old ones dropped, the rest written down. */
static void
faults_keep(void)
{
	ucl_object_t	*arr;
	unsigned char	*json;
	const char	*e;
	time_t		 since;
	int		 i, k;

	since = time(NULL) - FAULTS_KEEP;
	for (i = k = 0; i < nfaults; i++)
		if (faults[i].t >= since || (faults[i].cleared &&
		    faults[i].cleared_at >= since) || !faults[i].cleared)
			faults[k++] = faults[i];
	nfaults = k;
	arr = faults_array(0, false);
	json = ucl_object_emit(arr, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(arr);
	if (json != NULL) {
		e = NULL;
		if (sdwan_conf_write(FAULTS_FILE, (const char *)json, &e) != 0)
			logmsg(LOG_WARNING, "faults: %s: %s", FAULTS_FILE, e);
		free(json);
	}
}

static int
fault_find(const char *type, const char *object)
{
	int	i;

	for (i = 0; i < nfaults; i++)
		if (!faults[i].cleared && strcmp(faults[i].type, type) == 0 &&
		    strcmp(faults[i].object, object) == 0)
			return (i);
	return (-1);
}

/* A fault seen: once, until it is cleared. */
void
fault_set(const char *type, const char *severity, const char *object,
    const char *by, const char *fmt, ...)
{
	struct fault	*f;
	va_list		 ap;
	char		 qo[300], qd[500], descr[200];
	bool		 tell;

	pthread_mutex_lock(&lock);
	if (fault_find(type, object) >= 0) {
		pthread_mutex_unlock(&lock);
		return;
	}
	if (faults == NULL && (faults = calloc(FAULTS_MAX, sizeof(*faults))) ==
	    NULL) {
		pthread_mutex_unlock(&lock);
		return;
	}
	if (nfaults == FAULTS_MAX) {
		memmove(faults, faults + 1, sizeof(*faults) * (FAULTS_MAX - 1));
		nfaults--;
	}
	f = &faults[nfaults++];
	memset(f, 0, sizeof(*f));
	f->t = time(NULL);
	snprintf(f->type, sizeof(f->type), "%s", type);
	snprintf(f->severity, sizeof(f->severity), "%s", severity);
	snprintf(f->object, sizeof(f->object), "%s", object);
	snprintf(f->by, sizeof(f->by), "%s", by);
	va_start(ap, fmt);
	vsnprintf(f->descr, sizeof(f->descr), fmt, ap);
	va_end(ap);
	faults_keep();
	/* Shelved, or under the level told: no event (RFC 8632's
	 * notification). */
	tell = shelf_of(f) == NULL && told(severity);
	snprintf(descr, sizeof(descr), "%s", f->descr);
	pthread_mutex_unlock(&lock);
	yang_changed(YANG_ALARMS);
	if (tell)
		event_add("sdwan-fault", "{\"type\":\"%s\",\"severity\":\"%s\","
		    "\"object\":\"%s\",\"by\":\"%s\",\"description\":\"%s\","
		    "\"state\":\"set\"}", type, severity, jq(object, qo,
		    sizeof(qo)), by, jq(descr, qd, sizeof(qd)));
	logmsg(LOG_WARNING, "fault %s (%s) %s: %s%s", type, severity, object,
	    descr, tell ? "" : " (not told: shelved, or under the level)");
}

/* A fault cleared, if one of the type and object is open. */
void
fault_clear(const char *type, const char *object, const char *fmt, ...)
{
	struct fault	*f;
	va_list		 ap;
	char		 qo[300], qd[500], descr[200];
	int		 i;
	bool		 tell;

	pthread_mutex_lock(&lock);
	if ((i = fault_find(type, object)) < 0) {
		pthread_mutex_unlock(&lock);
		return;
	}
	f = &faults[i];
	f->cleared = true;
	f->cleared_at = time(NULL);
	va_start(ap, fmt);
	vsnprintf(descr, sizeof(descr), fmt, ap);
	va_end(ap);
	snprintf(f->descr, sizeof(f->descr), "%s", descr);
	faults_keep();
	tell = shelf_of(f) == NULL;
	pthread_mutex_unlock(&lock);
	yang_changed(YANG_ALARMS);
	if (tell)
		event_add("sdwan-fault", "{\"type\":\"%s\",\"severity\":"
		    "\"Cleared\",\"object\":\"%s\",\"description\":\"%s\","
		    "\"state\":\"cleared\"}", type, jq(object, qo, sizeof(qo)),
		    jq(descr, qd, sizeof(qd)));
	logmsg(LOG_NOTICE, "fault %s %s cleared: %s", type, object, descr);
}

/* Every open fault one saw (by) cleared, each with the line why. */
void
fault_clear_by(const char *by, const char *why)
{
	char	type[24], object[128];
	int	i;

	for (;;) {
		pthread_mutex_lock(&lock);
		for (i = 0; i < nfaults; i++)
			if (!faults[i].cleared && strcmp(faults[i].by, by) == 0)
				break;
		if (i == nfaults) {
			pthread_mutex_unlock(&lock);
			return;
		}
		snprintf(type, sizeof(type), "%s", faults[i].type);
		snprintf(object, sizeof(object), "%s", faults[i].object);
		pthread_mutex_unlock(&lock);
		fault_clear(type, object, "%s: %s", object, why);
	}
}

/*
 * An open fault's line said anew, as what it is of goes on (a program
 * that crashes again): no event, the fault being the same one.  false
 * when none of the type and object is open.
 */
bool
fault_update(const char *type, const char *object, const char *fmt, ...)
{
	va_list	ap;
	int	i;

	pthread_mutex_lock(&lock);
	if ((i = fault_find(type, object)) < 0) {
		pthread_mutex_unlock(&lock);
		return (false);
	}
	va_start(ap, fmt);
	vsnprintf(faults[i].descr, sizeof(faults[i].descr), fmt, ap);
	va_end(ap);
	faults_keep();
	pthread_mutex_unlock(&lock);
	yang_changed(YANG_ALARMS);
	return (true);
}

/* A severity's rank, by its word: Warning 3 to Critical 6 (RFC 8632). */
static int
rank(const char *s)
{
	static const char *const words[] = { "Warning", "Minor", "Major",
	    "Critical" };

	for (size_t i = 0; i < nitems(words); i++)
		if (strcasecmp(s, words[i]) == 0)
			return ((int)i + 3);
	return (2);
}

/*
 * The faults that match taken away, of the alarm list's or the shelved
 * ones' (shelved): cleared or not (clearance 1, 2; 0 either), last
 * changed before before (0: any time), of a severity below (-1), at (0)
 * or above (1) sev (sev 0: any).  How many.
 */
int
faults_purge(bool shelved, int clearance, time_t before, int sevop, int sev)
{
	struct fault	*f;
	time_t		 last;
	int		 i, k, r;

	pthread_mutex_lock(&lock);
	for (i = k = 0; i < nfaults; i++) {
		f = &faults[i];
		last = f->cleared ? f->cleared_at : f->t;
		r = rank(f->severity);
		if ((shelf_of(f) != NULL) == shelved && (clearance == 0 ||
		    (clearance == 1) == f->cleared) &&
		    (before == 0 || last < before) && (sev == 0 ||
		    (sevop < 0 ? r < sev : sevop > 0 ? r > sev : r == sev)))
			continue;
		faults[k++] = *f;
	}
	r = nfaults - k;
	nfaults = k;
	if (r > 0)
		faults_keep();
	pthread_mutex_unlock(&lock);
	if (r > 0)
		yang_changed(YANG_ALARMS);
	return (r);
}

/* The cleared faults of object and type (NULL: any), of the alarm
 * list's or the shelved ones' (shelved), left with their last status
 * change alone.  How many. */
int
faults_compress(bool shelved, const char *object, const char *type)
{
	struct fault	*f;
	int		 i, n = 0;

	pthread_mutex_lock(&lock);
	for (i = 0; i < nfaults; i++) {
		f = &faults[i];
		if (!f->cleared || f->compressed || (shelf_of(f) != NULL) !=
		    shelved || (object != NULL &&
		    strcmp(f->object, object) != 0) || (type != NULL &&
		    strcmp(f->type, type) != 0))
			continue;
		f->compressed = true;
		n++;
	}
	if (n > 0)
		faults_keep();
	pthread_mutex_unlock(&lock);
	if (n > 0)
		yang_changed(YANG_ALARMS);
	return (n);
}

/* The day's faults into the sdwan reply. */
void
faults_json(ucl_object_t *top)
{

	pthread_mutex_lock(&lock);
	ucl_object_insert_key(top, faults_array(time(NULL) - FAULTS_KEEP, true),
	    "faults", 0, false);
	/* The control's, for ietf-alarms (gula/yalarms.c). */
	ucl_object_insert_key(top, ucl_object_fromint((int64_t)nshelves),
	    "shelves", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint(max_changes),
	    "max_changes", 0, false);
	pthread_mutex_unlock(&lock);
}

static void
shelves_free(struct shelf *v, size_t n)
{
	size_t	i, k;

	for (i = 0; i < n; i++) {
		free(v[i].name);
		for (k = 0; k < v[i].nres; k++)
			regfree(&v[i].res[k]);
		for (k = 0; k < v[i].nty; k++)
			regfree(&v[i].ty[k].q);
		free(v[i].res);
		free(v[i].ty);
	}
	free(v);
}

/* re, an XML Schema regular expression, compiled as an extended one;
 * false and why in err. */
static bool
re_make(regex_t *re, const char *s, char *err, size_t len)
{
	char	m[128];
	int	rc;

	/* The empty expression, which regcomp(3) refuses: "" alone. */
	if ((rc = regcomp(re, s[0] != '\0' ? s : "^$", REG_EXTENDED)) == 0)
		return (true);
	regerror(rc, re, m, sizeof(m));
	snprintf(err, len, "'%s' is not a regular expression: %s", s, m);
	return (false);
}

/* The severities' names, RFC 8632's: their rank, 2 to 6; 0 none. */
static int
level(const char *s)
{
	static const char *const words[] = { "indeterminate", "warning",
	    "minor", "major", "critical" };

	for (size_t i = 0; s != NULL && i < nitems(words); i++)
		if (strcmp(s, words[i]) == 0)
			return ((int)i + 2);
	return (0);
}

/*
 * The control as RFC 7951's JSON of ietf-alarms' control (NULL or "":
 * none, the defaults): each shelf's expressions compiled, checked, and
 * unless check, made the faults' and kept for the next start.  -1 and
 * why in err when it is not one.
 */
int
faults_control(const char *json, bool check, char *err, size_t len)
{
	struct ucl_parser	*p;
	ucl_object_t		*top = NULL;
	const ucl_object_t	*o, *s, *v;
	ucl_object_iter_t	 it, vit;
	struct shelf		*nv = NULL;
	const char		*how, *e, *id, *q;
	size_t			 n = 0;
	int			 nhow = NOTIFY_ALL, nlevel = 0, nmax = -1;

	if (json != NULL && json[0] != '\0') {
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		top = ucl_parser_add_string(p, json, 0) ?
		    ucl_parser_get_object(p) : NULL;
		ucl_parser_free(p);
		if (top == NULL) {
			snprintf(err, len, "the alarms' control is not JSON");
			return (-1);
		}
	}
	if ((o = ucl_object_lookup(top, "max-alarm-status-changes")) != NULL &&
	    ucl_object_type(o) == UCL_INT)
		nmax = (int)ucl_object_toint(o);
	how = ucl_object_tostring(ucl_object_lookup(top,
	    "notify-status-changes"));
	if (how != NULL && strcmp(how, "raise-and-clear") == 0)
		nhow = NOTIFY_RAISE_CLEAR;
	else if (how != NULL && strcmp(how, "severity-level") == 0) {
		nhow = NOTIFY_LEVEL;
		/* The model's must: a level with it. */
		if ((nlevel = level(ucl_object_tostring(ucl_object_lookup(top,
		    "notify-severity-level")))) == 0) {
			snprintf(err, len, "notify-status-changes severity-level "
			    "needs notify-severity-level");
			goto bad;
		}
	}
	s = ucl_object_lookup_path(top, "alarm-shelving.shelf");
	if (s != NULL && ucl_array_size(s) > 0 && (nv = calloc(
	    ucl_array_size(s), sizeof(*nv))) == NULL) {
		snprintf(err, len, "no memory");
		goto bad;
	}
	it = NULL;
	while ((o = ucl_object_iterate(s, &it, true)) != NULL) {
		struct shelf	*sh = &nv[n++];

		if ((sh->name = strdup(ucl_object_tostring(ucl_object_lookup(o,
		    "name")) != NULL ? ucl_object_tostring(ucl_object_lookup(o,
		    "name")) : "")) == NULL) {
			snprintf(err, len, "no memory");
			goto bad;
		}
		v = ucl_object_lookup(o, "resource");
		if (v != NULL && ucl_array_size(v) > 0 && (sh->res = calloc(
		    ucl_array_size(v), sizeof(*sh->res))) == NULL) {
			snprintf(err, len, "no memory");
			goto bad;
		}
		vit = NULL;
		while ((v = ucl_object_iterate(ucl_object_lookup(o,
		    "resource"), &vit, true)) != NULL) {
			if ((e = ucl_object_tostring(v)) == NULL || !re_make(
			    &sh->res[sh->nres], e, err, len)) {
				if (e == NULL)
					snprintf(err, len, "a resource is a string");
				goto bad;
			}
			sh->nres++;
		}
		v = ucl_object_lookup(o, "alarm-type");
		if (v != NULL && ucl_array_size(v) > 0 && (sh->ty = calloc(
		    ucl_array_size(v), sizeof(*sh->ty))) == NULL) {
			snprintf(err, len, "no memory");
			goto bad;
		}
		vit = NULL;
		while ((v = ucl_object_iterate(ucl_object_lookup(o,
		    "alarm-type"), &vit, true)) != NULL) {
			struct shtype	*t = &sh->ty[sh->nty];

			id = ucl_object_tostring(ucl_object_lookup(v,
			    "alarm-type-id"));
			q = ucl_object_tostring(ucl_object_lookup(v,
			    "alarm-type-qualifier-match"));
			if (!re_make(&t->q, q != NULL ? q : "", err, len))
				goto bad;
			sh->nty++;
			/* The bases match every fault; another module's
			 * identity none. */
			if (id == NULL || strcmp(id, "ietf-alarms:alarm-type-id") ==
			    0 || strcmp(id, "arcana-alarms:arcana-fault") == 0)
				t->type[0] = '\0';
			else if (strncmp(id, "arcana-alarms:", 14) == 0)
				snprintf(t->type, sizeof(t->type), "%s", id + 14);
			else
				t->none = true;
		}
	}
	if (check) {
		shelves_free(nv, n);
		ucl_object_unref(top);
		return (0);
	}
	pthread_mutex_lock(&lock);
	shelves_free(shelves, nshelves);
	shelves = nv;
	nshelves = n;
	notify_how = nhow;
	notify_level = nlevel;
	max_changes = nmax;
	free(control);
	control = json != NULL && json[0] != '\0' ? strdup(json) : NULL;
	e = NULL;
	if (sdwan_conf_write(CONTROL_FILE, control != NULL ? control : "",
	    &e) != 0)
		logmsg(LOG_WARNING, "faults: %s: %s", CONTROL_FILE, e);
	pthread_mutex_unlock(&lock);
	ucl_object_unref(top);
	yang_changed(YANG_ALARMS);
	return (0);
bad:
	shelves_free(nv, n);
	if (top != NULL)
		ucl_object_unref(top);
	return (-1);
}

/* The control as kept, RFC 7951's JSON; NULL none.  The caller frees
 * it. */
char *
faults_control_json(void)
{
	char	*s;

	pthread_mutex_lock(&lock);
	s = control != NULL ? strdup(control) : NULL;
	pthread_mutex_unlock(&lock);
	return (s);
}

/* At the start: the control and the day's faults read back. */
void
faults_start(void)
{
	struct ucl_parser	*p;
	ucl_object_t		*arr;
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	char			*json, err[256];
	struct fault		*f;

	/* The control first, running's as kept. */
	if ((json = sdwan_kept_read(CONTROL_FILE)) != NULL) {
		if (json[0] != '\0' && faults_control(json, false, err,
		    sizeof(err)) != 0)
			logmsg(LOG_WARNING, "faults: %s: %s", CONTROL_FILE, err);
		free(json);
	}
	if ((json = sdwan_kept_read(FAULTS_FILE)) == NULL)
		return;
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	arr = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	free(json);
	if (arr == NULL)
		return;
	pthread_mutex_lock(&lock);
	if (faults == NULL)
		faults = calloc(FAULTS_MAX, sizeof(*faults));
	it = NULL;
	while (faults != NULL && nfaults < FAULTS_MAX && (o =
	    ucl_object_iterate(arr, &it, true)) != NULL) {
		f = &faults[nfaults];
		memset(f, 0, sizeof(*f));
		f->t = (time_t)ucl_object_toint(ucl_object_lookup(o, "t"));
#define	STR(field, key) snprintf(f->field, sizeof(f->field), "%s", \
	ucl_object_tostring(ucl_object_lookup(o, key)) != NULL ? \
	ucl_object_tostring(ucl_object_lookup(o, key)) : "")
		STR(type, "type");
		STR(severity, "was");
		STR(object, "object");
		STR(by, "by");
		STR(descr, "description");
#undef STR
		f->cleared = ucl_object_toboolean(ucl_object_lookup(o,
		    "cleared"));
		f->cleared_at = (time_t)ucl_object_toint(ucl_object_lookup(o,
		    "cleared_at"));
		f->compressed = ucl_object_toboolean(ucl_object_lookup(o,
		    "compressed"));
		if (f->type[0] != '\0')
			nfaults++;
	}
	pthread_mutex_unlock(&lock);
	ucl_object_unref(arr);
}
