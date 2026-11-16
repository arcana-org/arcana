/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What the page is told rather than asks for: RESTCONF's event streams
 * and YANG-Push subscriptions (RFC 8040 section 6, RFC 8650; the
 * console's rcstream.c) as Server-Sent Events, all on one EventSource
 * (bridge.js; the console's page stream), HTTP/2 giving it one stream
 * of the console's few, each of these a source of it:
 *
 * - the fleet's stream, /restconf/streams/fleet/json, while the console
 *   is shown: every host's arcana-events, each a sign that what the page
 *   shows of its host changed: its jails read again a moment later (a
 *   burst of them one read), its tabs as live.c says, its Log tab's
 *   events added (logs.c).  A host the console lost or heard again, a
 *   record left out, the stream itself lost and back: what is shown of
 *   that host (of every host) read again.  The browser comes back by
 *   itself with Last-Event-ID, the console replaying what came between
 *   and taking the subscriptions again.
 * - arcana-host's stats, a periodic subscription of the operational
 *   datastore every REFRESH_MS: every host's (established under the
 *   fleet) on the fleet and devices views, the host's own on its page;
 *   each push-update the sample a GET would have read.
 * - arcana-jobs, an on-change subscription of every host's, while a job
 *   of the page's runs or a Jobs tab is shown: a change of a host's
 *   jobs has its running jobs and its Jobs tab read then, not every
 *   second.
 *
 * - a job's program followed while it runs, "out-<host>.<job>.<step>"
 *   (the console's rcstream.c, the agent's exec-follow): what it wrote,
 *   from its start, kept in app.follow for the step's pane (graph.c);
 *   one at a time, its open the sign to start over.
 *
 * What nothing tells is still read now and then (SSE_SAFE_MS), and what
 * a stream would tell is read as before, on a timer, while that stream
 * is not up: closed, refused, or not yet open.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <emscripten/emscripten.h>

#include "app.h"

enum { SS_FLEET = 1, SS_STATS, SS_JOBS, SS_OUT, SS_N };

#define	SSE_RETRY_MS	5000	/* a stream refused or closed: again then */
#define	SSE_SAFE_MS	180000	/* what a stream tells, read so often anyway */
#define	SSE_SOON_MS	1000	/* an event's read waits for others */
#define	SSE_HOSTS	128
#define	FOLLOW_MAX	(512 * 1024)	/* of a followed program's output */

static struct {
	bool	 open;		/* its EventSource asked for */
	bool	 up;		/* said open, and not down since */
	bool	 was_up;	/* up before: an open again is a return */
	bool	 asking;	/* establish-subscription on its way */
	int	 gen;		/* a reply to an older ask is dropped */
	char	 sid[9];	/* whose: "" every host's */
	double	 retry;
} ss[SS_N];

/* Each host's: when its events asked for a read, when it was read. */
static struct {
	char	 sid[9];
	double	 due[SD_N];
	double	 read[SD_N];
} hd[SSE_HOSTS];
static int	nhd;
static char	fleet_ids[SSE_HOSTS * 9];	/* the hosts the stream hears */

static int
hd_find(const char *sid)
{
	int	i;

	for (i = 0; i < nhd; i++)
		if (strcmp(hd[i].sid, sid) == 0)
			return (i);
	if (nhd == SSE_HOSTS)
		return (-1);
	memset(&hd[nhd], 0, sizeof(hd[nhd]));
	snprintf(hd[nhd].sid, sizeof(hd[nhd].sid), "%s", sid);
	return (nhd++);
}

static struct server *
host_of(const char *sid)
{

	for (int i = 0; sid != NULL && i < app.nservers; i++)
		if (strcmp(app.servers[i].id, sid) == 0)
			return (&app.servers[i]);
	return (NULL);
}

/* What of host sid (NULL: every host) is read again soon. */
static void
due(const char *sid, int what)
{
	int	i;

	for (i = 0; i < app.nservers; i++) {
		int	k;

		if (sid != NULL && strcmp(app.servers[i].id, sid) != 0)
			continue;
		if ((k = hd_find(app.servers[i].id)) != -1 &&
		    hd[k].due[what] == 0)
			hd[k].due[what] = arc_now();
	}
}

/* Everything shown of sid (NULL: every host) read again. */
static void
lost(const char *sid)
{

	for (int w = 0; w < SD_N; w++)
		due(sid, w);
	live_lost(sid);
	logs_lost(sid);
}

bool
sse_fleet_up(void)
{

	return (ss[SS_FLEET].up);
}

bool
sse_jobs_up(void)
{

	return (ss[SS_JOBS].up);
}

/* Do host s's stats come by its subscription? */
static bool
stats_pushed(const struct server *s)
{

	return (ss[SS_STATS].up && (ss[SS_STATS].sid[0] == '\0' ||
	    strcmp(ss[SS_STATS].sid, s->id) == 0));
}

/*
 * Is what of host s to be read now?  When an event asked, a moment on;
 * else every ms, while it is periodic or its stream is not up, and now
 * and then while it is.
 */
bool
sse_due(const struct server *s, int what, double now, double every,
    bool periodic)
{
	bool	up;
	int	k;

	if ((k = hd_find(s->id)) == -1)
		return (false);
	up = what == SD_JAILS ? ss[SS_FLEET].up : what == SD_STATS ?
	    stats_pushed(s) : ss[SS_JOBS].up;
	if (hd[k].due[what] != 0 && now - hd[k].due[what] >= SSE_SOON_MS)
		;
	else if (now - hd[k].read[what] < (periodic || !up ? every :
	    SSE_SAFE_MS))
		return (false);
	hd[k].due[what] = 0;
	hd[k].read[what] = now;
	return (true);
}

/* What of host s was read by other means: not again at once. */
void
sse_read(const struct server *s, int what)
{
	int	k;

	if ((k = hd_find(s->id)) != -1)
		hd[k].read[what] = arc_now();
}

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

/*
 * arcana-events' event as the page's other parts had it from the
 * console's socket: {n, t, kind, jail, data}, data the kind's container
 * with the names it had there.
 */
ucl_object_t *
event_of_yang(const ucl_object_t *y)
{
	static const char *const names[] = {
	    "interface", "interface-name",	/* route, neighbor */
	    "link-address", "lladdr", "prefix-length", "prefixlen",
	    "sequence", "seq", NULL };
	const ucl_object_t	*v, *c;
	ucl_object_iter_t	 it = NULL, jt;
	ucl_object_t		*e, *d;
	const char		*k, *kind;
	bool			 rn;

	e = ucl_object_typed_new(UCL_OBJECT);
	put(e, "n", ucl_object_fromint(jint(y, "number", 0)));
	put(e, "t", ucl_object_fromint(rc_time(jstr(y, "time"))));
	kind = jstr(y, "kind") != NULL ? jstr(y, "kind") : "";
	if (strchr(kind, ':') != NULL)
		kind = strchr(kind, ':') + 1;
	put(e, "kind", ucl_object_fromstring(kind));
	if (jstr(y, "jail") != NULL)
		put(e, "jail", ucl_object_fromstring(jstr(y, "jail")));
	d = ucl_object_typed_new(UCL_OBJECT);
	while ((c = ucl_object_iterate(y, &it, true)) != NULL) {
		if (ucl_object_type(c) != UCL_OBJECT)
			continue;
		/* A route's and a neighbour's interface by its old name. */
		rn = strcmp(ucl_object_key(c), "route") == 0 ||
		    strcmp(ucl_object_key(c), "neighbor") == 0;
		jt = NULL;
		while ((v = ucl_object_iterate(c, &jt, true)) != NULL) {
			k = ucl_object_key(v);
			for (int i = 0; names[i] != NULL; i += 2)
				if (strcmp(k, names[i]) == 0 && (rn ||
				    i != 0)) {
					k = names[i + 1];
					break;
				}
			put(d, k, ucl_object_copy(v));
		}
	}
	put(e, "data", d);
	return (e);
}

/* An event of host sid's, told. */
static void
event(const char *sid, const ucl_object_t *e)
{
	const char	*kind = jstr(e, "kind"), *f;

	if (kind == NULL)
		return;
	f = jstr(e, "data.file");
	if (strcmp(kind, "jail-state") == 0 || strcmp(kind, "job") == 0 ||
	    (strcmp(kind, "conf") == 0 && f != NULL && strstr(f,
	    "jail.conf") != NULL))
		due(sid, SD_JAILS);
	if (strcmp(kind, "job") == 0)
		jobs_changed(sid);
	ecmp_event(sid, kind, jstr(e, "jail") != NULL);
	live_event(sid, e);
	logs_event(sid, e);
}

/* A push of a subscription's of host sid. */
static void
pushed(int id, const char *sid, const ucl_object_t *n)
{
	const ucl_object_t	*pu, *st;
	struct server		*s;

	if ((s = host_of(sid)) == NULL)
		return;
	pu = jget(n, "ietf-yang-push:push-update");
	if (id == SS_JOBS) {
		if (pu != NULL || jget(n, "ietf-yang-push:push-change-update")
		    != NULL)
			jobs_changed(sid);
		return;
	}
	if ((st = jget(pu, "datastore-contents.arcana-host:host.stats")) ==
	    NULL && (st = jget(pu, "datastore-contents.arcana-host:stats")) ==
	    NULL)
		return;
	stats_take(s, st);
	sse_read(s, SD_STATS);
}

/* "host <id>: ..." of an error event's message, or its host member. */
static bool
host_named(const ucl_object_t *o, char *sid, size_t len)
{
	const char	*m;

	if ((m = jstr(o, "host")) != NULL) {
		snprintf(sid, len, "%s", m);
		return (true);
	}
	if ((m = jstr(o, "ietf-restconf:errors.error.0.error-message")) ==
	    NULL || strncmp(m, "host ", 5) != 0)
		return (false);
	snprintf(sid, len, "%.*s", (int)strcspn(m + 5, ":"), m + 5);
	return (true);
}

static void
sse_closed(int id, double now)
{

	arc_sse_close(id);
	ss[id].open = ss[id].up = false;
	ss[id].retry = now + SSE_RETRY_MS;
	ss[id].gen++;
}

/* What the followed program wrote, added; its last FOLLOW_MAX kept. */
static void
follow_add(const char *t)
{
	size_t	n, drop;

	if (t == NULL || (n = strlen(t)) == 0)
		return;
	if ((app.follow.text = realloc(app.follow.text, app.follow.len + n +
	    1)) == NULL)
		abort();
	memcpy(app.follow.text + app.follow.len, t, n + 1);
	app.follow.len += n;
	if (app.follow.len > FOLLOW_MAX) {
		drop = app.follow.len - FOLLOW_MAX;
		memmove(app.follow.text, app.follow.text + drop,
		    app.follow.len - drop + 1);
		app.follow.len -= drop;
	}
}

/* Follow step step of job job on host sid; step -1: follow none. */
void
sse_follow(const char *sid, long long job, int step)
{

	/* Closed even when it ended by itself: the bridge still names it. */
	arc_sse_close(SS_OUT);
	ss[SS_OUT].open = ss[SS_OUT].up = false;
	free(app.follow.text);
	app.follow.text = NULL;
	app.follow.len = 0;
	app.follow.up = app.follow.done = false;
	app.follow.err[0] = '\0';
	app.follow.step = -1;
	if (sid == NULL || step < 0 || job <= 0)
		return;
	snprintf(app.follow.sid, sizeof(app.follow.sid), "%s", sid);
	app.follow.job = job;
	app.follow.step = step;
	snprintf(ss[SS_OUT].sid, sizeof(ss[SS_OUT].sid), "%s", sid);
	ss[SS_OUT].open = true;
	{
		char	url[160];

		snprintf(url, sizeof(url), "/restconf/streams/out/%s/%lld/%d",
		    sid, job, step);
		arc_sse_open(SS_OUT, url);
	}
}

/* What the followed program's source said. */
static void
follow_event(const char *ev, const char *data)
{
	ucl_object_t	*o;
	const char	*m;

	if (strcmp(ev, "open") == 0) {
		/* Taken (again): sent from the program's start. */
		free(app.follow.text);
		app.follow.text = NULL;
		app.follow.len = 0;
		app.follow.up = true;
	} else if (strcmp(ev, "message") == 0 && (o = json_parse(data)) !=
	    NULL) {
		follow_add(jstr(o, "text"));
		ucl_object_unref(o);
	} else if (strcmp(ev, "error") == 0 && (o = json_parse(data)) !=
	    NULL) {
		if (jget(o, "done") != NULL)
			app.follow.done = true;
		else if ((m = jstr(o, "ietf-restconf:errors.error.0."
		    "error-message")) != NULL)
			snprintf(app.follow.err, sizeof(app.follow.err), "%s", m);
		ucl_object_unref(o);
	} else if (strcmp(ev, "down") == 0 && strcmp(data, "closed") == 0) {
		ss[SS_OUT].open = false;
		if (!app.follow.done && app.follow.err[0] == '\0')
			snprintf(app.follow.err, sizeof(app.follow.err),
			    "the console did not take it");
	}
}

/* What an EventSource said (bridge.js). */
EMSCRIPTEN_KEEPALIVE void
arc_on_sse(int id, char *ev, char *data)
{
	const ucl_object_t	*n, *h;
	ucl_object_t		*o, *e;
	char			 sid[16];

	if (id <= 0 || id >= SS_N || !ss[id].open)
		goto out;
	if (id == SS_OUT) {
		follow_event(ev, data);
		render();
		goto out;
	}
	if (strcmp(ev, "open") == 0) {
		ss[id].up = true;
		/* Back: what came meanwhile may have gone past. */
		if (id == SS_FLEET && ss[id].was_up)
			lost(NULL);
		ss[id].was_up = true;
	} else if (strcmp(ev, "down") == 0) {
		ss[id].up = false;
		/* Given up, or ended: opened (established) again a while on;
		 * else the stream comes back with it. */
		if (strcmp(data, "closed") == 0)
			sse_closed(id, arc_now());
	} else if (strcmp(ev, "lost") == 0) {
		if (id == SS_FLEET)
			lost(NULL);
		else
			due(NULL, id == SS_STATS ? SD_STATS : SD_JOBS);
	} else if (strcmp(ev, "error") == 0 || strcmp(ev, "info") == 0) {
		if ((o = json_parse(data)) != NULL) {
			if (host_named(o, sid, sizeof(sid)))
				lost(sid);
			ucl_object_unref(o);
		}
	} else if (strcmp(ev, "message") == 0 && (o = json_parse(data)) !=
	    NULL) {
		n = jget(o, "ietf-restconf:notification");
		/* The fleet's: in its host's entry. */
		if ((h = jget(n, "arcana-fleet:fleet.host.0")) != NULL &&
		    jstr(h, "id") != NULL) {
			snprintf(sid, sizeof(sid), "%s", jstr(h, "id"));
			n = h;
		} else
			snprintf(sid, sizeof(sid), "%s", ss[id].sid);
		if (id == SS_FLEET && jget(n, "arcana-events:event") != NULL) {
			e = event_of_yang(jget(n, "arcana-events:event"));
			event(sid, e);
			ucl_object_unref(e);
		} else if (id != SS_FLEET)
			pushed(id, sid, n);
		ucl_object_unref(o);
	}
	render();
out:
	free(ev);
	free(data);
}

static void
established(int status, const ucl_object_t *o, const char *err, void *arg)
{
	int		 id = (int)((intptr_t)arg & 0xff);
	int		 gen = (int)((intptr_t)arg >> 8);
	const char	*uri, *p;

	if (id <= 0 || id >= SS_N || gen != (ss[id].gen & 0xffffff))
		return;
	ss[id].asking = false;
	uri = jstr(o, "ietf-restconf-subscribed-notifications:uri");
	if (status != 200 || uri == NULL || (p = strstr(uri, "/restconf/")) ==
	    NULL) {
		ss[id].retry = arc_now() + 6 * SSE_RETRY_MS;
		return;
	}
	ss[id].open = true;
	arc_sse_open(id, p);
}

/* Subscription id of host sid ("" every host's) wanted, or none (NULL). */
static void
subscribe(int id, const char *sid, double now)
{
	char	url[300], in[400];

	if (ss[id].open || ss[id].asking) {
		if (sid != NULL && strcmp(ss[id].sid, sid) == 0)
			return;
		if (ss[id].open)
			arc_sse_close(id);
		ss[id].open = ss[id].up = ss[id].asking = false;
		ss[id].gen++;
		ss[id].retry = 0;
	}
	if (sid == NULL || now < ss[id].retry)
		return;
	snprintf(ss[id].sid, sizeof(ss[id].sid), "%s", sid);
	if (sid[0] == '\0')
		snprintf(url, sizeof(url), "/restconf/data/arcana-fleet:fleet/"
		    "ietf-subscribed-notifications:establish-subscription");
	else
		rc_h(url, sizeof(url), sid, "ietf-subscribed-notifications:"
		    "establish-subscription");
	/* Its period, centiseconds: today's pace; a burst of changes one. */
	if (id == SS_STATS)
		snprintf(in, sizeof(in), "{\"ietf-yang-push:datastore\":"
		    "\"ietf-datastores:operational\",\"ietf-yang-push:"
		    "datastore-xpath-filter\":\"/arcana-host:host/stats\","
		    "\"ietf-yang-push:periodic\":{\"period\":%d}}",
		    REFRESH_MS / 10);
	else
		snprintf(in, sizeof(in), "{\"ietf-yang-push:datastore\":"
		    "\"ietf-datastores:operational\",\"ietf-yang-push:"
		    "datastore-xpath-filter\":\"/arcana-jobs:jobs\","
		    "\"ietf-yang-push:on-change\":{\"dampening-period\":"
		    "20}}");
	ss[id].asking = true;
	rc_read(url, in, NULL, established, (void *)(intptr_t)(id |
	    ((ss[id].gen & 0xffffff) << 8)));
}

/* Is a job of the page's running? */
static bool
jobs_running(void)
{

	for (int i = 0; i < app.nops; i++)
		if (app.ops[i].job > 0 && app.ops[i].state == OP_RUNNING)
			return (true);
	return (false);
}

/* Once a second, from main.c's tick: the streams the page wants. */
void
sse_tick(double now)
{
	struct server	*s;
	char		 ids[sizeof(fleet_ids)];
	size_t		 n = 0;
	bool		 on, host;

	on = app.screen == SCREEN_CONSOLE && app.visible && app.online &&
	    app.nservers > 0;
	ids[0] = '\0';
	for (int i = 0; i < app.nservers && n + 10 < sizeof(ids); i++)
		n += (size_t)snprintf(ids + n, sizeof(ids) - n, "%s,",
		    app.servers[i].id);
	/* The fleet's: opened again when the hosts are not those it hears. */
	if (ss[SS_FLEET].open && (!on || strcmp(ids, fleet_ids) != 0)) {
		arc_sse_close(SS_FLEET);
		ss[SS_FLEET].open = ss[SS_FLEET].up = false;
		if (!on)
			ss[SS_FLEET].was_up = true;
	}
	if (on && !ss[SS_FLEET].open && now >= ss[SS_FLEET].retry) {
		snprintf(fleet_ids, sizeof(fleet_ids), "%s", ids);
		ss[SS_FLEET].open = true;
		arc_sse_open(SS_FLEET, "/restconf/streams/fleet/json");
	}
	s = cur_server();
	host = s != NULL && (app.node == NODE_HOST || app.node == NODE_JAIL);
	subscribe(SS_STATS, !on ? NULL : app.node == NODE_FLEET || app.node ==
	    NODE_DEVICES ? "" : host ? s->id : NULL, now);
	subscribe(SS_JOBS, on && (jobs_running() || (host && app.node ==
	    NODE_HOST && app.tab == TAB_JOBS)) ? "" : NULL, now);
}
