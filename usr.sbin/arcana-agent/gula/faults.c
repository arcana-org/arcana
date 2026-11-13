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
 * of a type and object at a time, the object whole (FAULT_OBJECT_MAX
 * at most, a longer one refused); set and cleared are events
 * (sdwan-fault, R71) besides.  Kept 24 hours (D5), on disk too: a
 * change marks them, and a writer of their own writes them out of
 * every lock, the changes of a second together, and at the stop
 * (faults_save()).
 *
 * At most FAULTS_MAX are kept: a new one takes the place of the oldest
 * cleared; when every one is open, it is refused, said once a minute,
 * and the list's last place holds alarm-list-full (Major), which says
 * how many were refused, until a clearing makes room.
 *
 * Who raises faults says, at its start once it sees what it watches and
 * whenever that changes, what it still watches and how each is
 * (fault_reconcile()): every open fault of its own that is of nothing
 * it watches, or whose cause it says is gone, is cleared, so that one
 * of a target, a link, a file system or a session gone, or one an
 * agent before it raised, is not open for ever; what is still open of
 * the objects it watches is told back, for it to go on from (a
 * threshold crossed before a restart is cleared when the figure is
 * back under it).  Two owners of one name keep apart by the objects'
 * prefixes: one names its own, the other "!" before each of those it
 * leaves alone (sdbird.c beside birdwatch.c, both "bird").
 * faults_open() tells an owner its open faults, for
 * one whose objects are the faults themselves (kmsg.c's crashes).
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
 * alarm-type-id and arcana-alarms' arcana-fault every fault's.  A
 * control of other types than the model's (a shelf list that is no
 * array) is refused whole, and a kept one that is starts with none.
 */

#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	FAULTS_FILE	"sdwan-faults.json"
#define	FAULTS_MAX	2048
#define	FAULTS_KEEP	(24 * 3600)
#define	FAULTS_SYNC_MS	1000	/* a change on disk within, after it */
#define	FULL_SAY_S	60	/* the list full: logged once in so long */
#define	FULL_TYPE	"alarm-list-full"
#define	FULL_OBJECT	"faults"

struct fault {
	time_t	t, cleared_at;
	time_t	changed;	/* raised, or its line said anew */
	char	type[24];
	char	severity[12];
	char	*object;	/* whole, FAULT_OBJECT_MAX at most */
	char	by[16];
	char	descr[200];
	bool	cleared;
	bool	compressed;	/* its history the clearing alone */
};

/* A change, told after the lock: its event and its line. */
struct told {
	char	 type[24];
	char	 severity[12];
	char	 by[16];
	char	*object;
	char	 descr[200];
	bool	 set;
	bool	 tell;
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
/* Changed since written: the writer's to write (wcv), one at a time
 * (wlock, taken before lock). */
static pthread_mutex_t	wlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	wcv = PTHREAD_COND_INITIALIZER;
static bool		 dirty;
/* Refused while every one was open: how many, since when; when said. */
static uint64_t		 refused;
static time_t		 refused_since, full_said;
/* The control, under the lock: as kept, and made of it. */
static char		*control;
static struct shelf	*shelves;
static size_t		 nshelves;
static int		 notify_how, notify_level;
static int		 max_changes = -1;	/* -1: infinite */

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
		if (faults[i].changed != faults[i].t)
			ucl_object_insert_key(o, ucl_object_fromint(
			    faults[i].changed), "changed", 0, false);
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

/* With the lock held: changed, to be written by the writer soon. */
static void
mark(void)
{

	dirty = true;
	pthread_cond_signal(&wcv);
}

/* With the lock held: the old cleared ones dropped, the rest as JSON
 * to write; NULL with no change, or no memory. */
static char *
faults_text(void)
{
	ucl_object_t	*arr;
	char		*json;
	time_t		 since;
	int		 i, k;

	if (!dirty)
		return (NULL);
	since = time(NULL) - FAULTS_KEEP;
	for (i = k = 0; i < nfaults; i++)
		if (faults[i].t >= since || (faults[i].cleared &&
		    faults[i].cleared_at >= since) || !faults[i].cleared)
			faults[k++] = faults[i];
		else
			free(faults[i].object);
	nfaults = k;
	arr = faults_array(0, false);
	json = (char *)ucl_object_emit(arr, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(arr);
	if (json != NULL)
		dirty = false;
	return (json);
}

/* The faults written, if they changed: out of every lock but the
 * writers' own, so a set or a clear never waits for the disk. */
void
faults_save(void)
{
	const char	*e;
	char		*json;

	pthread_mutex_lock(&wlock);
	pthread_mutex_lock(&lock);
	json = faults_text();
	pthread_mutex_unlock(&lock);
	if (json != NULL) {
		e = NULL;
		if (sdwan_conf_write(FAULTS_FILE, json, &e) != 0)
			logmsg(LOG_WARNING, "faults: %s: %s", FAULTS_FILE, e);
		free(json);
	}
	pthread_mutex_unlock(&wlock);
}

/* The writer: woken by a change, it waits for those of the next
 * moment, then writes them all. */
static void *
writer(void *arg __unused)
{
	struct timespec	ts = { FAULTS_SYNC_MS / 1000,
			    (FAULTS_SYNC_MS % 1000) * 1000000L };

	for (;;) {
		pthread_mutex_lock(&lock);
		while (!dirty)
			pthread_cond_wait(&wcv, &lock);
		pthread_mutex_unlock(&lock);
		(void)nanosleep(&ts, NULL);
		faults_save();
	}
	return (NULL);
}

/* With the lock held: the open fault of type and object, or -1. */
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

/* An object a fault can be of: a string, whole within the bound. */
static bool
object_ok(const char *type, const char *object)
{

	if (object != NULL && object[0] != '\0' && strlen(object) <
	    FAULT_OBJECT_MAX)
		return (true);
	logmsg(LOG_WARNING, "fault %s of %.64s%s: refused, its object %s",
	    type, object != NULL ? object : "", object != NULL &&
	    strlen(object) > 64 ? "..." : "", object == NULL || object[0] ==
	    '\0' ? "is none" : "is longer than a fault's object may be");
	return (false);
}

/*
 * With the lock held: a place for a new fault, zeroed: one free, or
 * the oldest cleared one's (dropped); the list's last place for the
 * full alarm alone (last).  NULL when every one is open.
 */
static struct fault *
fault_place(bool last)
{
	struct fault	*f;
	int		 i, old;

	if (faults == NULL && (faults = calloc(FAULTS_MAX, sizeof(*faults))) ==
	    NULL)
		return (NULL);
	if (nfaults >= (last ? FAULTS_MAX : FAULTS_MAX - 1)) {
		for (i = 0, old = -1; i < nfaults; i++)
			if (faults[i].cleared && (old == -1 ||
			    faults[i].cleared_at < faults[old].cleared_at))
				old = i;
		if (old == -1)
			return (NULL);
		free(faults[old].object);
		memmove(&faults[old], &faults[old + 1], sizeof(*faults) *
		    (size_t)(nfaults - old - 1));
		nfaults--;
	}
	f = &faults[nfaults++];
	memset(f, 0, sizeof(*f));
	return (f);
}

/* With the lock held: f made what to tell of it after the lock. */
static void
tell_of(const struct fault *f, bool set, bool tell, struct told *tl)
{

	memset(tl, 0, sizeof(*tl));
	snprintf(tl->type, sizeof(tl->type), "%s", f->type);
	snprintf(tl->severity, sizeof(tl->severity), "%s", f->severity);
	snprintf(tl->by, sizeof(tl->by), "%s", f->by);
	snprintf(tl->descr, sizeof(tl->descr), "%s", f->descr);
	tl->object = strdup(f->object);
	tl->set = set;
	tl->tell = tell;
}

/* What a change tells, after the lock: its event (sdwan-fault), unless
 * shelved, and its line. */
static void
say(struct told *tl)
{
	char	*qo, qd[1300], qt[64], qs[32], qb[48];
	size_t	 len;

	if (tl->object == NULL)
		return;
	len = strlen(tl->object) * 6 + 1;
	if (tl->tell && (qo = malloc(len)) != NULL) {
		json_quote(tl->object, qo, len);
		json_quote(tl->descr, qd, sizeof(qd));
		json_quote(tl->type, qt, sizeof(qt));
		if (tl->set)
			event_add("sdwan-fault", "{\"type\":\"%s\",\"severity\":"
			    "\"%s\",\"object\":\"%s\",\"by\":\"%s\","
			    "\"description\":\"%s\",\"state\":\"set\"}", qt,
			    json_quote(tl->severity, qs, sizeof(qs)), qo,
			    json_quote(tl->by, qb, sizeof(qb)), qd);
		else
			event_add("sdwan-fault", "{\"type\":\"%s\",\"severity\":"
			    "\"Cleared\",\"object\":\"%s\",\"description\":"
			    "\"%s\",\"state\":\"cleared\"}", qt, qo, qd);
		free(qo);
	}
	if (tl->set)
		logmsg(LOG_WARNING, "fault %s (%s) %s: %s%s", tl->type,
		    tl->severity, tl->object, tl->descr, tl->tell ? "" :
		    " (not told: shelved, or under the level)");
	else
		logmsg(LOG_NOTICE, "fault %s %s cleared: %s", tl->type,
		    tl->object, tl->descr);
	free(tl->object);
	tl->object = NULL;
}

/* With the lock held: f cleared, with the line why; what to tell of it
 * into tl. */
static void
clear_one(struct fault *f, const char *why, struct told *tl)
{

	f->cleared = true;
	f->cleared_at = time(NULL);
	snprintf(f->descr, sizeof(f->descr), "%s", why);
	tell_of(f, false, shelf_of(f) == NULL, tl);
}

/* With the lock held: the list full, a fault of type and object
 * refused: counted, said once a minute; the full alarm raised in the
 * last place, or its line said anew, into tl (its object NULL when
 * there is nothing to tell). */
static void
full(const char *type, const char *object, struct told *tl)
{
	struct fault	*f;
	time_t		 now;
	int		 i;

	memset(tl, 0, sizeof(*tl));
	now = time(NULL);
	if (refused++ == 0)
		refused_since = now;
	if (full_said == 0 || now - full_said >= FULL_SAY_S) {
		full_said = now;
		logmsg(LOG_ERR, "faults: all %d places are open faults: %s of "
		    "%s refused (%ju refused since %jd)", FAULTS_MAX - 1, type,
		    object, (uintmax_t)refused, (intmax_t)refused_since);
	}
	if ((i = fault_find(FULL_TYPE, FULL_OBJECT)) >= 0) {
		f = &faults[i];
		snprintf(f->descr, sizeof(f->descr), "every place of the alarm "
		    "list is an open alarm: %ju new ones refused since %jd, "
		    "the last %s of %.80s", (uintmax_t)refused,
		    (intmax_t)refused_since, type, object);
		f->changed = now;
		mark();
		return;
	}
	if ((f = fault_place(true)) == NULL)
		return;
	f->t = f->changed = now;
	snprintf(f->type, sizeof(f->type), "%s", FULL_TYPE);
	snprintf(f->severity, sizeof(f->severity), "Major");
	snprintf(f->by, sizeof(f->by), "faults");
	if ((f->object = strdup(FULL_OBJECT)) == NULL) {
		nfaults--;
		return;
	}
	snprintf(f->descr, sizeof(f->descr), "every place of the alarm list "
	    "is an open alarm: new ones refused, the first %s of %.80s", type,
	    object);
	mark();
	tell_of(f, true, shelf_of(f) == NULL && told(f->severity), tl);
}

/* With the lock held, after a clearing or a purge: room again, so the
 * full alarm, if it is open, cleared into tl (its object NULL when it
 * is not). */
static void
room(struct told *tl)
{
	int	i;
	char	why[200];

	memset(tl, 0, sizeof(*tl));
	if ((i = fault_find(FULL_TYPE, FULL_OBJECT)) < 0)
		return;
	snprintf(why, sizeof(why), "room in the alarm list again: %ju "
	    "refused while it was full", (uintmax_t)refused);
	refused = 0;
	clear_one(&faults[i], why, tl);
}

/* A fault seen: once, until it is cleared. */
void
fault_set(const char *type, const char *severity, const char *object,
    const char *by, const char *fmt, ...)
{
	struct fault	*f;
	struct told	 tl;
	va_list		 ap;
	char		 descr[200];

	if (!object_ok(type, object))
		return;
	va_start(ap, fmt);
	vsnprintf(descr, sizeof(descr), fmt, ap);
	va_end(ap);
	pthread_mutex_lock(&lock);
	if (fault_find(type, object) >= 0) {
		pthread_mutex_unlock(&lock);
		return;
	}
	if ((f = fault_place(false)) == NULL || (f->object = strdup(object)) ==
	    NULL) {
		if (f != NULL)
			nfaults--;
		full(type, object, &tl);
		pthread_mutex_unlock(&lock);
		if (tl.object != NULL) {
			yang_changed(YANG_ALARMS);
			say(&tl);
		}
		return;
	}
	f->t = f->changed = time(NULL);
	snprintf(f->type, sizeof(f->type), "%s", type);
	snprintf(f->severity, sizeof(f->severity), "%s", severity);
	snprintf(f->by, sizeof(f->by), "%s", by);
	snprintf(f->descr, sizeof(f->descr), "%s", descr);
	mark();
	/* Shelved, or under the level told: no event (RFC 8632's
	 * notification). */
	tell_of(f, true, shelf_of(f) == NULL && told(severity), &tl);
	pthread_mutex_unlock(&lock);
	yang_changed(YANG_ALARMS);
	say(&tl);
}

/* A fault cleared, if one of the type and object is open. */
void
fault_clear(const char *type, const char *object, const char *fmt, ...)
{
	struct told	 tl, tr;
	va_list		 ap;
	char		 descr[200];
	int		 i;

	if (object == NULL)
		return;
	va_start(ap, fmt);
	vsnprintf(descr, sizeof(descr), fmt, ap);
	va_end(ap);
	pthread_mutex_lock(&lock);
	if ((i = fault_find(type, object)) < 0) {
		pthread_mutex_unlock(&lock);
		return;
	}
	clear_one(&faults[i], descr, &tl);
	room(&tr);
	mark();
	pthread_mutex_unlock(&lock);
	yang_changed(YANG_ALARMS);
	say(&tl);
	say(&tr);
}

/*
 * object begins with one of scope's (NULL ends them; scope NULL: any),
 * and with none of those written "!<prefix>" (another owner's of the
 * same by); only such: any but those.
 */
static bool
in_scope(const char *const *scope, const char *object)
{
	bool	any, in;

	if (scope == NULL)
		return (true);
	any = in = false;
	for (; *scope != NULL; scope++) {
		if ((*scope)[0] == '!') {
			if (strncmp(object, *scope + 1, strlen(*scope + 1)) == 0)
				return (false);
			continue;
		}
		any = true;
		if (strncmp(object, *scope, strlen(*scope)) == 0)
			in = true;
	}
	return (!any || in);
}

/*
 * What an owner (by) watches now, of type (NULL: of every type, each
 * live object's its own) and of the objects that begin as scope says
 * (NULL: all of its): v, n of them, each of an object and whether its
 * cause is gone (well), with the line why (reason; NULL, why's).  Every
 * open fault of the owner's there that is of no object of v, or of
 * one well, cleared, its line "object: why"; each of v told whether a
 * fault of it is still open.  How many were cleared.
 */
int
fault_reconcile(const char *by, const char *type, const char *const *scope,
    struct fault_live *v, size_t n, const char *why)
{
	struct told	*tl, *nt, tr;
	struct fault	*f;
	const char	*ty;
	char		 line[200];
	size_t		 k, ntl, cap;
	int		 i;

	for (k = 0; k < n; k++)
		v[k].open = false;
	tl = NULL;
	ntl = cap = 0;
	memset(&tr, 0, sizeof(tr));
	pthread_mutex_lock(&lock);
	for (i = 0; i < nfaults; i++) {
		f = &faults[i];
		if (f->cleared || strcmp(f->by, by) != 0 || (type != NULL &&
		    strcmp(f->type, type) != 0) || !in_scope(scope, f->object))
			continue;
		for (k = 0; k < n; k++) {
			ty = v[k].type != NULL ? v[k].type : type;
			if (ty != NULL && strcmp(ty, f->type) == 0 &&
			    strcmp(v[k].object, f->object) == 0)
				break;
		}
		if (k < n && !v[k].well) {
			v[k].open = true;
			continue;
		}
		if (ntl == cap) {
			cap = cap == 0 ? 16 : cap * 2;
			if ((nt = reallocarray(tl, cap, sizeof(*tl))) == NULL)
				break;
			tl = nt;
		}
		if (k < n && v[k].reason != NULL)
			snprintf(line, sizeof(line), "%s", v[k].reason);
		else
			snprintf(line, sizeof(line), "%s: %s", f->object, why);
		clear_one(f, line, &tl[ntl++]);
	}
	if (ntl > 0) {
		room(&tr);
		mark();
	}
	pthread_mutex_unlock(&lock);
	if (ntl > 0)
		yang_changed(YANG_ALARMS);
	for (k = 0; k < ntl; k++)
		say(&tl[k]);
	say(&tr);
	free(tl);
	return ((int)ntl);
}

/*
 * An owner's (by) open faults of type (NULL: any), each told to fn with
 * its object and when it was last raised or said anew, out of the
 * lock.  How many.
 */
int
faults_open(const char *by, const char *type,
    void (*fn)(const char *, time_t, void *), void *arg)
{
	struct { char *object; time_t changed; } *v, *nv;
	size_t	n, cap, k;
	int	i;

	v = NULL;
	n = cap = 0;
	pthread_mutex_lock(&lock);
	for (i = 0; i < nfaults; i++) {
		if (faults[i].cleared || strcmp(faults[i].by, by) != 0 ||
		    (type != NULL && strcmp(faults[i].type, type) != 0))
			continue;
		if (n == cap) {
			cap = cap == 0 ? 16 : cap * 2;
			if ((nv = reallocarray(v, cap, sizeof(*v))) == NULL)
				break;
			v = nv;
		}
		if ((v[n].object = strdup(faults[i].object)) == NULL)
			break;
		v[n++].changed = faults[i].changed;
	}
	pthread_mutex_unlock(&lock);
	for (k = 0; k < n; k++) {
		fn(v[k].object, v[k].changed, arg);
		free(v[k].object);
	}
	free(v);
	return ((int)n);
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

	if (object == NULL)
		return (false);
	pthread_mutex_lock(&lock);
	if ((i = fault_find(type, object)) < 0) {
		pthread_mutex_unlock(&lock);
		return (false);
	}
	va_start(ap, fmt);
	vsnprintf(faults[i].descr, sizeof(faults[i].descr), fmt, ap);
	va_end(ap);
	faults[i].changed = time(NULL);
	mark();
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
	struct told	 tr;
	time_t		 last;
	int		 i, k, r;

	memset(&tr, 0, sizeof(tr));
	pthread_mutex_lock(&lock);
	for (i = k = 0; i < nfaults; i++) {
		f = &faults[i];
		last = f->cleared ? f->cleared_at : f->t;
		r = rank(f->severity);
		if ((shelf_of(f) != NULL) == shelved && (clearance == 0 ||
		    (clearance == 1) == f->cleared) &&
		    (before == 0 || last < before) && (sev == 0 ||
		    (sevop < 0 ? r < sev : sevop > 0 ? r > sev : r == sev))) {
			free(f->object);
			continue;
		}
		faults[k++] = *f;
	}
	r = nfaults - k;
	nfaults = k;
	if (r > 0) {
		room(&tr);
		mark();
	}
	pthread_mutex_unlock(&lock);
	if (r > 0)
		yang_changed(YANG_ALARMS);
	say(&tr);
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
		mark();
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
	/* Refused while the list was full, since the last room. */
	if (refused > 0)
		ucl_object_insert_key(top, ucl_object_fromint((int64_t)refused),
		    "refused", 0, false);
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

/* o's key, when it is there, of type t (an array, an object, a
 * string); false and why in err when it is of another. */
static bool
typed(const ucl_object_t *o, const char *key, ucl_type_t t,
    const ucl_object_t **vp, char *err, size_t len)
{
	static const char *const tn[] = { [UCL_OBJECT] = "an object",
	    [UCL_ARRAY] = "an array", [UCL_STRING] = "a string" };

	*vp = ucl_object_lookup(o, key);
	if (*vp == NULL || ucl_object_type(*vp) == t)
		return (true);
	snprintf(err, len, "%s is %s", key, tn[t]);
	return (false);
}

/*
 * The control as RFC 7951's JSON of ietf-alarms' control (NULL or "":
 * none, the defaults): each shelf's expressions compiled, checked, and
 * unless check, made the faults' and kept for the next start.  Of the
 * model's types, each list an array: -1 and why in err when it is not
 * one, nothing taken.
 */
int
faults_control(const char *json, bool check, char *err, size_t len)
{
	struct ucl_parser	*p;
	ucl_object_t		*top = NULL;
	const ucl_object_t	*o, *s, *v, *w, *sh;
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
		if (top == NULL || ucl_object_type(top) != UCL_OBJECT) {
			snprintf(err, len, "the alarms' control is not a JSON "
			    "object");
			goto bad;
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
	/* Each list an array of objects, each name, resource and qualifier
	 * a string: what is sized by an array's length walks it alone. */
	if (!typed(top, "alarm-shelving", UCL_OBJECT, &sh, err, len) ||
	    (sh != NULL && !typed(sh, "shelf", UCL_ARRAY, &s, err, len)))
		goto bad;
	if (sh == NULL)
		s = NULL;
	if (s != NULL && ucl_array_size(s) > 0 && (nv = calloc(
	    ucl_array_size(s), sizeof(*nv))) == NULL) {
		snprintf(err, len, "no memory");
		goto bad;
	}
	it = NULL;
	while ((o = ucl_object_iterate(s, &it, true)) != NULL) {
		struct shelf	*shf;

		if (ucl_object_type(o) != UCL_OBJECT) {
			snprintf(err, len, "a shelf is an object");
			goto bad;
		}
		if (!typed(o, "name", UCL_STRING, &w, err, len) ||
		    !typed(o, "resource", UCL_ARRAY, &v, err, len) ||
		    !typed(o, "alarm-type", UCL_ARRAY, &w, err, len))
			goto bad;
		shf = &nv[n++];
		if ((shf->name = strdup(ucl_object_tostring(ucl_object_lookup(o,
		    "name")) != NULL ? ucl_object_tostring(ucl_object_lookup(o,
		    "name")) : "")) == NULL) {
			snprintf(err, len, "no memory");
			goto bad;
		}
		if (v != NULL && ucl_array_size(v) > 0 && (shf->res = calloc(
		    ucl_array_size(v), sizeof(*shf->res))) == NULL) {
			snprintf(err, len, "no memory");
			goto bad;
		}
		vit = NULL;
		while ((w = ucl_object_iterate(v, &vit, true)) != NULL) {
			if (ucl_object_type(w) != UCL_STRING) {
				snprintf(err, len, "a resource is a string");
				goto bad;
			}
			if (!re_make(&shf->res[shf->nres], ucl_object_tostring(w),
			    err, len))
				goto bad;
			shf->nres++;
		}
		v = ucl_object_lookup(o, "alarm-type");
		if (v != NULL && ucl_array_size(v) > 0 && (shf->ty = calloc(
		    ucl_array_size(v), sizeof(*shf->ty))) == NULL) {
			snprintf(err, len, "no memory");
			goto bad;
		}
		vit = NULL;
		while ((w = ucl_object_iterate(v, &vit, true)) != NULL) {
			struct shtype	*t = &shf->ty[shf->nty];
			const ucl_object_t	*x;

			if (ucl_object_type(w) != UCL_OBJECT ||
			    !typed(w, "alarm-type-id", UCL_STRING, &x, err,
			    len) || !typed(w, "alarm-type-qualifier-match",
			    UCL_STRING, &x, err, len)) {
				if (ucl_object_type(w) != UCL_OBJECT)
					snprintf(err, len, "an alarm type is an "
					    "object");
				goto bad;
			}
			id = ucl_object_tostring(ucl_object_lookup(w,
			    "alarm-type-id"));
			q = ucl_object_tostring(ucl_object_lookup(w,
			    "alarm-type-qualifier-match"));
			if (!re_make(&t->q, q != NULL ? q : "", err, len))
				goto bad;
			shf->nty++;
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
		if (top != NULL)
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
	if (top != NULL)
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

/* At the start: the control and the day's faults read back, and their
 * writer. */
void
faults_start(void)
{
	struct ucl_parser	*p;
	ucl_object_t		*arr;
	const ucl_object_t	*o, *ob;
	ucl_object_iter_t	 it;
	pthread_t		 tid;
	char			*json, err[256];
	struct fault		*f;
	int			 error;

	/* The control first, running's as kept; one that is not the
	 * model's, none (said). */
	if ((json = sdwan_kept_read(CONTROL_FILE)) != NULL) {
		if (json[0] != '\0' && faults_control(json, false, err,
		    sizeof(err)) != 0)
			logmsg(LOG_WARNING, "faults: %s: %s: no shelves, the "
			    "control's defaults", CONTROL_FILE, err);
		free(json);
	}
	if ((error = pthread_create(&tid, NULL, writer, NULL)) != 0)
		logmsg(LOG_ERR, "faults: no writer: %s; written at the stop "
		    "alone", strerror(error));
	else
		(void)pthread_detach(tid);
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
	while (faults != NULL && nfaults < FAULTS_MAX && ucl_object_type(arr) ==
	    UCL_ARRAY && (o = ucl_object_iterate(arr, &it, true)) != NULL) {
		f = &faults[nfaults];
		memset(f, 0, sizeof(*f));
		ob = ucl_object_lookup(o, "object");
		if (ucl_object_type(o) != UCL_OBJECT || ob == NULL ||
		    ucl_object_type(ob) != UCL_STRING ||
		    strlen(ucl_object_tostring(ob)) >= FAULT_OBJECT_MAX ||
		    (f->object = strdup(ucl_object_tostring(ob))) == NULL)
			continue;
		f->t = (time_t)ucl_object_toint(ucl_object_lookup(o, "t"));
		f->changed = ucl_object_lookup(o, "changed") != NULL ?
		    (time_t)ucl_object_toint(ucl_object_lookup(o, "changed")) :
		    f->t;
#define	STR(field, key) snprintf(f->field, sizeof(f->field), "%s", \
	ucl_object_tostring(ucl_object_lookup(o, key)) != NULL ? \
	ucl_object_tostring(ucl_object_lookup(o, key)) : "")
		STR(type, "type");
		STR(severity, "was");
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
		else
			free(f->object);
	}
	pthread_mutex_unlock(&lock);
	ucl_object_unref(arr);
}
