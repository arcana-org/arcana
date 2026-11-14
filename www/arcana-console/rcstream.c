/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * RESTCONF's event streams (RFC 8040 section 6): a host's NETCONF
 * stream, every event its agent tells, as Server-Sent Events at
 * /restconf/streams/<id>/json, each record RFC 8040's notification JSON
 * on a data line, its event time its id: a client that comes back with
 * Last-Event-ID is sent what the agent kept since that time first (RFC
 * 8639's replay), the last one it had among them again.
 *
 * Each client is a thread of its own: it subscribes to the host's
 * stream (cblink's YANG family, SUBSCRIBE, RFC 8639's
 * establish-subscription) on a connection nothing else uses, and puts
 * what it hears in a buffer; a timer of the worker's passes the buffers
 * on to the replies, which only the worker may write to.  A comment line
 * every so often keeps the connection from being taken for idle.  The
 * host's stream ending ends the reply, with an error event saying why;
 * the client going stops the thread.
 *
 * The fleet's stream, /restconf/streams/fleet/json: every host's this
 * user may read, on one thread and one reply, each record its
 * notification nested in its host's entry of arcana-fleet (RFC 8528's
 * mount point; RFC 7950 section 7.16.2's notification in a list).  A
 * host whose stream ends is said in an error event naming it, and
 * subscribed again, a second on, then twice as long each time up to a
 * minute (as watch.c does), at its address then, with the replay from
 * its last record's event time: what came meanwhile is not lost, and
 * the records of that very time it had are not told again (each
 * stream keeps those, by a hash).  Heard again, it is said in an info
 * event naming it.  A host removed is said in an error event and not
 * asked again; the reply ends with the last of them.
 *
 * A subscription of one's own (RFC 8650, RESTCONF's transport of RFC
 * 8639 and RFC 8641): establish-subscription POSTed under a host's
 * entry, a stream or the operational datastore, periodic or on-change,
 * filtered by XPath, answers with its id and the URI whose GET is its
 * stream, /restconf/subscriptions/<id>; the same client takes it within
 * a minute, once.  POSTed under arcana-fleet:fleet itself, it is every
 * host's this user may read (its XPath each host's, below its mount),
 * on one reply as the fleet's stream is: each record in its host's
 * entry, a host lost said and subscribed again.
 *
 * A page's stream, /restconf/streams/page/json?fleet=1&sub=<id>,<id>:
 * the console's page holds one EventSource, not one a stream (every tab
 * shares the browser's one HTTP/2 connection, and the streams held on
 * it are few), and so one reply and one thread carry its sources: the
 * fleet's stream ("fleet") and the subscriptions it established
 * ("sub-<id>"), each judged as its own GET would be.  Each event is
 * named by its source: a record "fleet", "sub-<id>"; a host lost or
 * heard again "<name>.error", "<name>.info"; a source taken
 * "<name>.open", one that ended by itself "<name>.end", saying why.  A
 * record's and an open's id is every source's of the reply with its
 * last record's event time, "fleet@<time>;sub-<id>@<time>" (a source
 * without one by its name alone), so a client back with Last-Event-ID
 * has each source again from its own time, the subscriptions it names
 * taken again (a page stream's are given back to be taken, as when
 * just established, when its reply goes).  Its first line, a comment,
 * and its first event, "page" ({"stream": <id>, "sources": [...]}),
 * name the stream: a source wanted later, or one given up, is said to
 * it by POST /restconf/streams/page/<id> ({"add": <name>} or {"end":
 * <name>}), by the session that opened it alone.  The lost events, the
 * keep-alives and the error the reply ends with are the reply's.
 *
 * Records left out, the client being slow, are said in a lost event:
 * a page then reads again what it shows.
 *
 * A stream is bound to the session (or the bearer token) that opened
 * it (auth.c's sbind), judged each time the worker passes records on:
 * the session ended, timed out or its user gone, the reply ends; a host
 * its principal may no longer read, the reply ends saying so, and the
 * client, coming back, hears what it may then.  RCS_WHO streams of one
 * principal at once (a token's from one address), RCS_MAX of all; each
 * lasts RCS_LIFE_S at most, then ends, and EventSource comes back by
 * itself, from its last event's id.  A subscription is taken by the
 * session that made it alone: its user, their id and the key's (or the
 * token's id), never a name a user gives.
 */

#include <sys/param.h>
#include <sys/queue.h>

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <cblink.h>
#include <cbl_schema.h>

#include "console.h"
#include "restconf.h"
#include "ymodel.h"

#define	RCS_MAX		128		/* at once, of every client */
#define	RCS_WHO		8		/* ... of one principal (a token's,
					 * of one address) */
#define	RCS_LIFE_S	3600		/* a stream lasts, then is made again */
#define	RCS_OUT_MAX	(4 * 1024 * 1024)	/* not yet passed on */
#define	RCS_TICK_MS	200
#define	RCS_WAKE_MS	250		/* how soon a stop is seen */
#define	RCS_KEEP_S	15		/* a comment line, so often */
#define	SUBS_MAX	64		/* established, not yet taken */
#define	SUB_WAIT_S	60		/* how long one waits to be taken */
#define	RCH_BACKOFF_S	60		/* subscribe again at most so far apart */
#define	RCH_SEEN	64		/* records of one event time remembered */
#define	PAGE_SRC_MAX	8		/* sources of a page's stream */
#define	PAGE_SRC_WHO	32		/* ... of one principal's pages */
#define	PAGE_SRC_ALL	256		/* ... of every page */
#define	PAGE_ID_LEN	32		/* a page's stream's id, hex */

/* An establish-subscription's input, as the POST said it. */
struct rcsub {
	uint32_t	 id;		/* 0: the slot is free */
	char		 sid[9];
	char		 who[256];	/* whose (session_owner()), alone
					 * may take it */
	time_t		 made;
	bool		 fleet;		/* every host's: sid "" */
	bool		 datastore;	/* else the NETCONF stream */
	bool		 onchange;
	uint32_t	 period, damp;	/* centiseconds */
	char		*xpath, *replay, *stop, *anchor;
};

static struct rcsub	subs[SUBS_MAX];

struct rcs;
struct rcsrc;

/* A host a stream hears, its connection the thread's alone. */
struct rch {
	struct rcsrc		*src;
	char			 sid[9];
	char			*uri;
	char			*peer;
	cbl_conn		*conn;	/* NULL: not connected, or let go */
	cbl_tls			*tls;
	cbl_stream		*s;
	bool			 closed;	/* its stream ended */
	char			 why[200];	/* why */
	bool			 gone;		/* removed: not asked again */
	bool			 lost;		/* said lost, not yet back */
	unsigned		 backoff;	/* s */
	uint64_t		 retry;		/* ms, subscribe again then */
	char			 last[40];	/* its last record's event time */
	uint64_t		 seen[RCH_SEEN];	/* the records of that time */
	size_t			 nseen;
};

/* A source of a stream: a host's NETCONF stream, the fleet's, or a
 * subscription, and the hosts it hears.  A page's stream has several,
 * each by its name; another's one, its name "". */
struct rcsrc {
	TAILQ_ENTRY(rcsrc)	 link;
	struct rcs		*rs;
	char			 name[24];	/* "fleet", "sub-<id>"; "" */
	struct rch		*h;
	size_t			 nh;
	bool			 fleet;	/* records nested in their hosts */
	bool			 opened;	/* its hosts asked, by the thread */
	atomic_bool		 end;	/* given up by the page */
	struct rcsub		 sub;	/* its input: id 0, the NETCONF stream;
					 * a subscription's its id kept */
	char			 since[40];	/* replay from, or "" */
	char			 last[40];	/* its last record's event time
						 * (the lock's) */
	char			 why[200];	/* why it ended */
};

TAILQ_HEAD(rcsrcs, rcsrc);

struct rcs {
	LIST_ENTRY(rcs)		 list;
	struct http_request	*req;	/* NULL once the client went */
	struct rcsrcs		 src;	/* the thread's; changed under lock */
	struct rcsrcs		 add;	/* for the thread to take (lock) */
	size_t			 nsrc;	/* of both (lock) */
	bool			 page;	/* a page's: its sources named */
	char			 pid[PAGE_ID_LEN + 1];	/* a page's: its id */
	char			 owner[256];	/* a page's: session_owner() */
	pthread_t		 thread;
	atomic_bool		 stop;
	atomic_bool		 ended;	/* the thread is done */
	pthread_mutex_t		 lock;
	struct buf		*out;
	bool			 lost;
	char			 why[200];	/* why the stream ended */
	time_t			 said;	/* when the reply had a line last */
	struct sbind		 b;	/* whose: the session that opened it */
	uint64_t		 hgen;	/* sbind_gen() when its hosts were
					 * judged last */
};

static LIST_HEAD(, rcs)	streams = LIST_HEAD_INITIALIZER(streams);
static int		nstreams;
static struct timer	*ticker;

/* A notification as RFC 8040's JSON (section 6.4): its event time, the
 * notification qualified by its module, in host's entry of the fleet
 * when host is not NULL; malloc'd, or NULL.  Its event time in when. */
static char *
notif_json(const cbl_msg *msg, const char *host, char *when, size_t wlen)
{
	const struct cbl_ynode	*n;
	struct cbl_ynotif	 nt;
	struct cbl_ybuf		 b = { NULL, 0, 0 };
	cbl_yarena		*a;
	void			*data;
	char			*json = NULL;

	if ((a = cbl_yarena_new()) == NULL)
		return (NULL);
	if (cbl_msg_ynotif(msg, &nt, a) != 0)
		goto out;
	snprintf(when, wlen, "%s", nt.event_time);
	if ((n = cbl_yschema_node(&ymodel_schema, nt.sid)) == NULL ||
	    (data = cbl_yarena_alloc(a, n->size)) == NULL ||
	    cbl_ydecode(n, nt.content, nt.len, data, a, 0, NULL, 0) != 0 ||
	    cbl_yjson(n, data, &b) != 0) {
		if (asprintf(&json, "{\"ietf-restconf:notification\":{"
		    "\"eventTime\":\"%s\",\"sid\":\"%ju\"}}", nt.event_time,
		    (uintmax_t)nt.sid) == -1)
			json = NULL;
	} else if (host != NULL ? asprintf(&json,
	    "{\"ietf-restconf:notification\":{\"eventTime\":\"%s\","
	    "\"arcana-fleet:fleet\":{\"host\":[{\"id\":\"%s\",\"%s:%s\":"
	    "%.*s}]}}}", nt.event_time, host, n->module->name, n->name,
	    (int)b.len, (const char *)b.p) == -1 : asprintf(&json,
	    "{\"ietf-restconf:notification\":{\"eventTime\":\"%s\","
	    "\"%s:%s\":%.*s}}", nt.event_time, n->module->name, n->name,
	    (int)b.len, (const char *)b.p) == -1)
		json = NULL;
out:
	cbl_ybuf_free(&b);
	cbl_yarena_free(a);
	return (json);
}

static uint64_t
mono_ms(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000);
}

/* FNV-1a of a record. */
static uint64_t
rec_hash(const char *p)
{
	uint64_t	h = 0xcbf29ce484222325ULL;

	for (; *p != '\0'; p++)
		h = (h ^ (unsigned char)*p) * 0x100000001b3ULL;
	return (h);
}

/*
 * Whether h told json of event time when already: a replay from its
 * last record's second has those of that second again, their event
 * time the second alone (the agent keeps no finer), so a record is
 * known by what follows its event time.  Remembered if not.
 */
static bool
rch_seen(struct rch *h, const char *when, const char *json)
{
	const char	*p;
	char		 sec[sizeof(h->last)];
	uint64_t	 k;

	/* RFC 3339's to the second, UTC: 2026-01-02T03:04:05Z. */
	if (strlen(when) < 19 || (p = strstr(json, "\"eventTime\":\"")) ==
	    NULL || (p = strchr(p + 13, '"')) == NULL)
		return (false);
	snprintf(sec, sizeof(sec), "%.19sZ", when);
	k = rec_hash(p);
	if (strcmp(sec, h->last) == 0) {
		for (size_t i = 0; i < h->nseen; i++)
			if (h->seen[i] == k)
				return (true);
	} else {
		strlcpy(h->last, sec, sizeof(h->last));
		h->nseen = 0;
	}
	if (h->nseen < RCH_SEEN)
		h->seen[h->nseen++] = k;
	return (false);
}

/*
 * A page's stream's id of now: each of its sources, its last record's
 * event time after an @ where it has one, ';' between them.  Under the
 * lock.
 */
static void
rcs_id(const struct rcs *rs, char *buf, size_t len)
{
	const struct rcsrc	*src;
	size_t			 n = 0;

	buf[0] = '\0';
	TAILQ_FOREACH(src, &rs->src, link) {
		if (atomic_load(&src->end))
			continue;
		n += (size_t)snprintf(buf + n, n < len ? len - n : 0, "%s%s%s%s",
		    n > 0 ? ";" : "", src->name, src->last[0] != '\0' ? "@" : "",
		    src->last);
		if (n >= len) {
			buf[0] = '\0';
			return;
		}
	}
}

/* An event of src's ("open", "end", "error", "info"; named by src on a
 * page's stream), with an id when id. */
static void
src_say(struct rcsrc *src, const char *event, const char *data, bool id)
{
	struct rcs	*rs = src->rs;
	char		 ids[PAGE_SRC_MAX * 72];

	pthread_mutex_lock(&rs->lock);
	if (src->name[0] == '\0')
		buf_appendf(rs->out, "event: %s\ndata: %s\n\n", event, data);
	else {
		ids[0] = '\0';
		if (id)
			rcs_id(rs, ids, sizeof(ids));
		buf_appendf(rs->out, "event: %s.%s\n%s%s%sdata: %s\n\n",
		    src->name, event, ids[0] != '\0' ? "id: " : "", ids,
		    ids[0] != '\0' ? "\n" : "", data);
	}
	pthread_mutex_unlock(&rs->lock);
}

/* An event of the fleet's reply, about host h. */
static void
rch_say(struct rch *h, const char *event, const char *data)
{

	src_say(h->src, event, data, false);
}

static void
rcs_open(cbl_stream *s, cbl_msg *accept, int error, void *arg)
{
	struct rch	*h = arg;
	char		 text[300];

	(void)s;
	if (error != 0) {
		snprintf(h->why, sizeof(h->why), "the host refused: %s",
		    accept != NULL && cbl_msg_err_str(accept) != NULL ?
		    cbl_msg_err_str(accept) : strerror(error));
		h->closed = true;
		return;
	}
	h->backoff = 0;
	/* Back after it was said lost: said so, naming it. */
	if (h->lost && !atomic_load(&h->src->rs->stop)) {
		h->lost = false;
		snprintf(text, sizeof(text), "{\"host\":\"%s\",\"message\":"
		    "\"host %s: heard again, from %s\"}", h->sid, h->sid,
		    h->last[0] != '\0' ? h->last : "now");
		rch_say(h, "info", text);
	}
}

static void
rcs_data(cbl_stream *s, cbl_msg *data, void *arg)
{
	struct rch	*h = arg;
	struct rcsrc	*src = h->src;
	struct rcs	*rs = src->rs;
	char		*json, when[64], ids[PAGE_SRC_MAX * 72];
	bool		 timed;

	(void)s;
	when[0] = '\0';
	if ((json = notif_json(data, src->fleet ? h->sid : NULL, when,
	    sizeof(when))) == NULL)
		return;
	if (rch_seen(h, when, json)) {
		free(json);
		return;
	}
	/* Its event time its id, where it has one; on a page's stream,
	 * every source's. */
	timed = when[0] != '\0' && strlen(when) < sizeof(src->last) &&
	    when[strspn(when, "0123456789-:.TZ+")] == '\0';
	pthread_mutex_lock(&rs->lock);
	if (rs->out->offset + strlen(json) > RCS_OUT_MAX)
		rs->lost = true;
	else if (rs->page) {
		if (timed)
			strlcpy(src->last, when, sizeof(src->last));
		rcs_id(rs, ids, sizeof(ids));
		buf_appendf(rs->out, "event: %s\n%s%s%sdata: %s\n\n", src->name,
		    ids[0] != '\0' ? "id: " : "", ids, ids[0] != '\0' ? "\n" :
		    "", json);
	} else if (timed)
		buf_appendf(rs->out, "id: %s\ndata: %s\n\n", when, json);
	else
		buf_appendf(rs->out, "data: %s\n\n", json);
	pthread_mutex_unlock(&rs->lock);
	free(json);
}

static void
rcs_close(cbl_stream *s, int code, const char *text, void *arg)
{
	struct rch	*h = arg;

	(void)s;
	(void)code;
	h->closed = true;
	snprintf(h->why, sizeof(h->why), "%s", text != NULL && text[0] !=
	    '\0' ? text : "the host ended the stream");
}

static const struct cbl_stream_cbs rcs_cbs = {
	.on_open = rcs_open,
	.on_data = rcs_data,
	.on_close = rcs_close,
};

/* establish-subscription's input node, in the tables. */
static const struct cbl_ynode *
est_input(void)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*rpc;

	for (uint32_t i = 0; i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		if (strcmp(m->name, "ietf-subscribed-notifications") != 0)
			continue;
		for (uint32_t k = 0; k < m->ntop; k++) {
			rpc = m->top[k];
			if (strcmp(rpc->name, "establish-subscription") != 0)
				continue;
			for (uint32_t c = 0; c < rpc->nchild; c++)
				if (rpc->child[c]->kind == CBL_YN_INPUT)
					return (rpc->child[c]);
		}
	}
	return (NULL);
}

#define	SN(x)	IETF_SUBSCRIBED_NOTIFICATIONS_ESTABLISH_SUBSCRIPTION_INPUT_##x

/* establish-subscription's input of source src: the NETCONF stream,
 * from since when it is not NULL, or what a POST said. */
static void
sub_input(const struct rcsrc *src, const char *since,
    struct ietf_subscribed_notifications_establish_subscription_input *in,
    struct ietf_subscribed_notifications_establish_subscription_input_yp_periodic
    *per,
    struct ietf_subscribed_notifications_establish_subscription_input_yp_on_change
    *oc)
{
	const struct cbl_yident	*id;
	const struct rcsub	*sb = &src->sub;

	memset(in, 0, sizeof(*in));
	memset(per, 0, sizeof(*per));
	memset(oc, 0, sizeof(*oc));
	if (!sb->datastore) {
		in->target = SN(TARGET_STREAM);
		in->stream = "NETCONF";
		if (sb->xpath != NULL) {
			in->stream_filter = SN(STREAM_FILTER_WITHIN_SUBSCRIPTION);
			in->filter_spec = SN(FILTER_SPEC_STREAM_XPATH_FILTER);
			in->stream_xpath_filter = sb->xpath;
		}
		in->replay_start_time = sb->replay != NULL ? sb->replay :
		    since;
	} else {
		in->target = SN(TARGET_DATASTORE);
		for (uint32_t i = 0; i < ymodel_schema.nident; i++) {
			id = &ymodel_schema.ident[i];
			if (strcmp(id->name, "operational") == 0 &&
			    strcmp(id->module->name, "ietf-datastores") == 0) {
				in->has_yp_datastore = true;
				in->yp_datastore = id->sid;
			}
		}
		if (sb->xpath != NULL) {
			in->yp_selection_filter =
			    SN(YP_SELECTION_FILTER_WITHIN_SUBSCRIPTION);
			in->yp_filter_spec =
			    SN(YP_FILTER_SPEC_DATASTORE_XPATH_FILTER);
			in->yp_datastore_xpath_filter = sb->xpath;
		}
		if (sb->onchange) {
			oc->has_dampening_period = true;
			oc->dampening_period = sb->damp;
			in->yp_update_trigger = SN(YP_UPDATE_TRIGGER_ON_CHANGE);
			in->yp_on_change = oc;
		} else {
			per->has_period = true;
			per->period = sb->period;
			per->anchor_time = sb->anchor;
			in->yp_update_trigger = SN(YP_UPDATE_TRIGGER_PERIODIC);
			in->yp_periodic = per;
		}
	}
	in->stop_time = sb->stop;
}

#undef SN

static void
sub_clear(struct rcsub *sb)
{

	free(sb->xpath);
	free(sb->replay);
	free(sb->stop);
	free(sb->anchor);
	memset(sb, 0, sizeof(*sb));
}

/* Host h's stream opened on a connection of its own; false, why in h. */
static bool
rch_open(struct rch *h)
{
	struct ietf_subscribed_notifications_establish_subscription_input in;
	struct ietf_subscribed_notifications_establish_subscription_input_yp_periodic
				 per;
	struct ietf_subscribed_notifications_establish_subscription_input_yp_on_change
				 oc;
	const struct cbl_ynode	*inode;
	const char		*msg;
	cbl_msg			*m;
	struct tm		 tm;
	time_t			 t;

	if ((msg = hosts_connect(h->uri, h->peer, &h->conn,
	    &h->tls)) != NULL) {
		h->conn = NULL;
		snprintf(h->why, sizeof(h->why), "the host does not answer: %s",
		    msg);
		return (false);
	}
	/* Again: from its last record, or from when it was first heard. */
	sub_input(h->src, h->last[0] != '\0' ? h->last : h->src->since[0] !=
	    '\0' ? h->src->since : NULL, &in, &per, &oc);
	if ((inode = est_input()) == NULL || cbl_msg_new(cbl_conn_ctx(h->conn),
	    CBL_YANG_FAMILY, CBL_YCMD_SUBSCRIBE, 0, &m) != 0 ||
	    cbl_msg_put_ynode(m, inode, &in) != 0 || cbl_stream_open(h->conn, m,
	    CBL_SF_PUSH, &rcs_cbs, h, &h->s) != 0) {
		snprintf(h->why, sizeof(h->why), "the host's stream could not "
		    "be opened");
		hosts_release(h->uri, h->peer, h->conn, h->tls, false);
		h->conn = NULL;
		return (false);
	}
	/* Heard from now on: subscribed again, from now at least. */
	if (h->last[0] == '\0' && h->src->since[0] == '\0') {
		t = time(NULL);
		if (gmtime_r(&t, &tm) != NULL)
			strftime(h->last, sizeof(h->last),
			    "%Y-%m-%dT%H:%M:%SZ", &tm);
	}
	return (true);
}

/* Host h's address now, as the stream subscribes again; false: it was
 * removed, said so, and is not asked again. */
static bool
rch_reach(struct rch *h)
{
	char	*uri, *peer, *why, text[260];

	if (servers_reach(h->sid, &uri, &peer)) {
		free(h->uri);
		free(h->peer);
		h->uri = uri;
		h->peer = peer;
		return (true);
	}
	h->gone = true;
	snprintf(text, sizeof(text), "host %s: removed, not heard again",
	    h->sid);
	if ((why = restconf_errors(404, text)) != NULL) {
		rch_say(h, "error", why);
		free(why);
	}
	return (false);
}

/* Host h let go, its stream closed first while it is open and its
 * connection whole; in the fleet's, said in an error event naming it
 * the first time, and subscribed again a while on. */
static void
rch_done(struct rch *h, bool broken)
{
	struct rcsrc	*src = h->src;
	char		*why, text[260];

	if (h->conn != NULL) {
		/* A connection with a stream on it is no one else's. */
		if (!h->closed && !broken)
			(void)cbl_stream_close(h->s, 0, NULL);
		hosts_release(h->uri, h->peer, h->conn, h->tls, false);
		h->conn = NULL;
	}
	h->closed = true;
	if (!src->fleet || atomic_load(&src->rs->stop) ||
	    atomic_load(&src->end))
		return;
	h->backoff = h->backoff == 0 ? 1 : MIN(h->backoff * 2, RCH_BACKOFF_S);
	h->retry = mono_ms() + (uint64_t)h->backoff * 1000;
	if (h->lost)
		return;
	h->lost = true;
	snprintf(text, sizeof(text), "host %s: %s; subscribed again a while "
	    "on", h->sid, h->why);
	if ((why = restconf_errors(502, text)) == NULL)
		return;
	rch_say(h, "error", why);
	free(why);
}

/* A source of the n hosts sv, the fleet's (records nested in their
 * hosts) or one host's, of sb's input (NULL: the NETCONF stream; its
 * strings the source's then), from since when it is not NULL. */
static struct rcsrc *
src_new(struct rcs *rs, const char *name, const struct server *const *sv,
    size_t n, bool fleet, struct rcsub *sb, const char *since)
{
	struct rcsrc	*src;

	src = xcalloc(1, sizeof(*src));
	src->rs = rs;
	strlcpy(src->name, name, sizeof(src->name));
	src->h = xcalloc(n, sizeof(*src->h));
	src->nh = n;
	src->fleet = fleet;
	for (size_t i = 0; i < n; i++) {
		src->h[i].src = src;
		strlcpy(src->h[i].sid, sv[i]->id, sizeof(src->h[i].sid));
		src->h[i].uri = xstrdup(sv[i]->uri);
		src->h[i].peer = sv[i]->peer_name != NULL ?
		    xstrdup(sv[i]->peer_name) : NULL;
	}
	if (sb != NULL) {
		src->sub = *sb;
		memset(sb, 0, sizeof(*sb));
	}
	if (since != NULL) {
		strlcpy(src->since, since, sizeof(src->since));
		strlcpy(src->last, since, sizeof(src->last));
	}
	atomic_init(&src->end, false);
	return (src);
}

static void
src_free(struct rcsrc *src)
{

	sub_clear(&src->sub);
	for (size_t i = 0; i < src->nh; i++) {
		free(src->h[i].uri);
		free(src->h[i].peer);
	}
	free(src->h);
	free(src);
}

/* In the thread: the sources added since it looked, each said open and
 * its hosts asked. */
static void
rcs_take(struct rcs *rs)
{
	struct rcsrc	*src;

	pthread_mutex_lock(&rs->lock);
	TAILQ_CONCAT(&rs->src, &rs->add, link);
	pthread_mutex_unlock(&rs->lock);
	TAILQ_FOREACH(src, &rs->src, link) {
		if (src->opened)
			continue;
		src->opened = true;
		if (rs->page)
			src_say(src, "open", "{}", true);
		for (size_t i = 0; i < src->nh && !atomic_load(&rs->stop); i++)
			if (!rch_open(&src->h[i]))
				rch_done(&src->h[i], true);
	}
}

/* In the thread: src let go, its hosts' streams closed; on a page's,
 * said ended, why, unless the page gave it up. */
static void
src_drop(struct rcs *rs, struct rcsrc *src)
{
	char	*why;

	for (size_t i = 0; i < src->nh; i++)
		if (src->h[i].conn != NULL)
			rch_done(&src->h[i], false);
	if (rs->page && !atomic_load(&src->end) && (why = restconf_errors(502,
	    src->why)) != NULL) {
		src_say(src, "end", why, false);
		free(why);
	}
	pthread_mutex_lock(&rs->lock);
	TAILQ_REMOVE(&rs->src, src, link);
	rs->nsrc--;
	pthread_mutex_unlock(&rs->lock);
	src_free(src);
}

static void *
rcs_run(void *arg)
{
	struct rcs	*rs = arg;
	struct rcsrc	*src, *next;
	struct pollfd	*pfd = NULL;
	struct rch	*h, **at = NULL;
	size_t		 i, n, cap = 0, want;
	uint64_t	 now;
	int		 error, ev, ms, wait;
	bool		 live;

	while (!atomic_load(&rs->stop)) {
		rcs_take(rs);
		want = 0;
		TAILQ_FOREACH(src, &rs->src, link)
			want += src->nh;
		if (want > cap) {
			cap = want;
			pfd = xrealloc(pfd, cap * sizeof(*pfd));
			at = xrealloc(at, cap * sizeof(*at));
		}
		wait = RCS_WAKE_MS;
		now = mono_ms();
		n = 0;
		TAILQ_FOREACH_SAFE(src, &rs->src, link, next) {
			if (atomic_load(&src->end)) {
				src_drop(rs, src);
				continue;
			}
			for (i = 0; i < src->nh; i++) {
				h = &src->h[i];
				/* The fleet's: a host lost is asked again, in
				 * time. */
				if (h->conn == NULL && src->fleet && !h->gone) {
					if (now < h->retry) {
						if (h->retry - now < (uint64_t)wait)
							wait = (int)(h->retry - now);
						continue;
					}
					if (!rch_reach(h))
						continue;
					h->closed = false;
					h->why[0] = '\0';
					if (!rch_open(h))
						rch_done(h, true);
					if (h->conn == NULL)
						continue;
				}
				if (h->conn == NULL)
					continue;
				if (h->closed) {
					rch_done(h, false);
					continue;
				}
				ev = 0;
				ms = -1;
				(void)cbl_conn_interest(h->conn, &ev, &ms);
				if (ms >= 0 && ms < wait)
					wait = ms;
				pfd[n].fd = cbl_conn_fd(h->conn);
				pfd[n].events = ((ev & CBL_EV_READ) != 0 ?
				    POLLIN : 0) | ((ev & CBL_EV_WRITE) != 0 ?
				    POLLOUT : 0);
				pfd[n].revents = 0;
				at[n++] = h;
			}
			/* Every host of it let go: it ended, why. */
			live = false;
			for (i = 0; i < src->nh && !live; i++)
				if (src->h[i].conn != NULL || (src->fleet &&
				    !src->h[i].gone))
					live = true;
			if (live)
				continue;
			snprintf(src->why, sizeof(src->why), "%s", src->fleet ?
			    "every host was removed" : src->nh > 0 ?
			    src->h[0].why : "no host to hear");
			if (!rs->page) {
				strlcpy(rs->why, src->why, sizeof(rs->why));
				goto out;
			}
			src_drop(rs, src);
		}
		if (n == 0) {
			(void)poll(NULL, 0, wait);
			continue;
		}
		if (poll(pfd, n, wait) == -1)
			continue;
		for (i = 0; i < n; i++) {
			h = at[i];
			ev = ((pfd[i].revents & (POLLIN | POLLHUP | POLLERR)) !=
			    0 ? CBL_EV_READ : 0) | ((pfd[i].revents & POLLOUT) !=
			    0 ? CBL_EV_WRITE : 0);
			if ((error = cbl_conn_process(h->conn, ev)) != 0) {
				snprintf(h->why, sizeof(h->why), "the host stopped "
				    "answering: %s", strerror(error));
				rch_done(h, true);
			}
		}
	}
out:
	TAILQ_FOREACH(src, &rs->src, link)
		for (i = 0; i < src->nh; i++)
			if (src->h[i].conn != NULL)
				rch_done(&src->h[i], false);
	free(pfd);
	free(at);
	atomic_store(&rs->ended, true);
	return (NULL);
}

/*
 * A subscription's input given back, to be taken again as one just
 * established is (a page's stream's, its reply gone: its client, back,
 * names it in its Last-Event-ID); dropped when no slot is free.
 */
static void
sub_back(struct rcsub *sb)
{
	time_t	now = time(NULL);

	for (int i = 0; i < SUBS_MAX; i++)
		if (subs[i].id == 0 || now - subs[i].made > SUB_WAIT_S) {
			sub_clear(&subs[i]);
			subs[i] = *sb;
			subs[i].made = now;
			memset(sb, 0, sizeof(*sb));
			return;
		}
	sub_clear(sb);
}

static void
rcs_clear(struct rcs *rs)
{
	struct rcsrc	*src;

	while ((src = TAILQ_FIRST(&rs->src)) != NULL) {
		TAILQ_REMOVE(&rs->src, src, link);
		src_free(src);
	}
	while ((src = TAILQ_FIRST(&rs->add)) != NULL) {
		TAILQ_REMOVE(&rs->add, src, link);
		src_free(src);
	}
	pthread_mutex_destroy(&rs->lock);
	buf_free(rs->out);
	free(rs);
}

static void
rcs_free(struct rcs *rs)
{
	struct rcsrc	*src;

	(void)pthread_join(rs->thread, NULL);
	LIST_REMOVE(rs, list);
	nstreams--;
	/* A page's subscriptions, to be taken again. */
	if (rs->page) {
		TAILQ_CONCAT(&rs->src, &rs->add, link);
		TAILQ_FOREACH(src, &rs->src, link)
			if (src->sub.id != 0 && !atomic_load(&src->end))
				sub_back(&src->sub);
	}
	rcs_clear(rs);
}

static void
put(struct http_request *req, const char *s)
{

	http_stream_put(req, s, strlen(s));
}

/*
 * Is rs's still to be told: its session good, each host of each source
 * its own still to read (judged again when who may do what changed),
 * and its time not over?  Why not into why.
 */
static bool
rcs_ok(struct rcs *rs, time_t t, char *why, size_t len)
{
	struct rcsrcs	*l[2] = { &rs->src, &rs->add };
	struct rcsrc	*src;
	bool		 ok = true;

	if (!sbind_ok(&rs->b)) {
		snprintf(why, len, "the session ended: sign in again");
		return (false);
	}
	if (t - rs->b.born >= RCS_LIFE_S) {
		snprintf(why, len, "the stream's time is over: open it again");
		return (false);
	}
	if (rs->hgen == sbind_gen())
		return (true);
	rs->hgen = sbind_gen();
	pthread_mutex_lock(&rs->lock);
	for (int k = 0; k < 2 && ok; k++)
		TAILQ_FOREACH(src, l[k], link)
			for (size_t i = 0; i < src->nh && ok; i++)
				if (!src->h[i].gone && !principal_may(
				    &rs->b.who, src->h[i].sid, ROLE_VIEWER)) {
					snprintf(why, len, "host %s is not one "
					    "to read any more", src->h[i].sid);
					ok = false;
				}
	pthread_mutex_unlock(&rs->lock);
	return (ok);
}

/* In the worker: what each thread heard, to its reply. */
static void
rcs_tick(void *arg, uint64_t now)
{
	struct rcs	*rs, *next;
	struct buf	*b;
	char		*why, no[200];
	time_t		 t;
	bool		 lost;

	(void)arg;
	(void)now;
	t = time(NULL);
	LIST_FOREACH_SAFE(rs, &streams, list, next) {
		/* No longer its principal's: nothing more passed on, the
		 * reply ended, saying why. */
		if (rs->req != NULL && !atomic_load(&rs->stop) && !rcs_ok(rs, t,
		    no, sizeof(no))) {
			atomic_store(&rs->stop, true);
			if ((why = restconf_errors(403, no)) != NULL) {
				put(rs->req, "event: error\ndata: ");
				put(rs->req, why);
				put(rs->req, "\n\n");
				free(why);
			}
			http_stream_end(rs->req);
			rs->req->hdlr_extra = NULL;
			rs->req = NULL;
		}
		pthread_mutex_lock(&rs->lock);
		b = rs->out;
		rs->out = buf_alloc(512);
		lost = rs->lost;
		rs->lost = false;
		pthread_mutex_unlock(&rs->lock);
		if (rs->req != NULL) {
			if (lost)
				put(rs->req, "event: lost\ndata: {\"message\":"
				    "\"some records were left out, the client "
				    "being slow\"}\n\n");
			if (b->offset > 0) {
				http_stream_put(rs->req, b->data, b->offset);
				rs->said = t;
			} else if (t - rs->said >= RCS_KEEP_S) {
				put(rs->req, ": keep-alive\n\n");
				rs->said = t;
			}
		}
		buf_free(b);
		if (!atomic_load(&rs->ended))
			continue;
		/* The host's side ended: so does the reply, saying why. */
		if (rs->req != NULL) {
			if (!atomic_load(&rs->stop) && (why = restconf_errors(
			    502, rs->why)) != NULL) {
				put(rs->req, "event: error\ndata: ");
				put(rs->req, why);
				put(rs->req, "\n\n");
				free(why);
			}
			http_stream_end(rs->req);
			rs->req->hdlr_extra = NULL;
			rs->req = NULL;
		}
		rcs_free(rs);
	}
}

/* The route's on_free: the client went, the thread is stopped. */
void
api_restconf_stream_free(struct http_request *req)
{
	struct rcs	*rs;

	if ((rs = req->hdlr_extra) == NULL)
		return;
	req->hdlr_extra = NULL;
	rs->req = NULL;
	atomic_store(&rs->stop, true);
}

/* A stream for req, its sources to be added, or NULL: too many are open,
 * said so. */
static struct rcs *
rcs_new(struct http_request *req)
{
	struct rcs	*rs, *o;
	struct sbind	 b;
	int		 mine;

	sbind_make(req, &b);
	mine = 0;
	LIST_FOREACH(o, &streams, list)
		if (o->req != NULL && o->b.who.kind == b.who.kind && strcmp(
		    o->b.who.name, b.who.name) == 0 && (b.who.kind == P_USER ||
		    strcmp(o->b.addr, b.addr) == 0))
			mine++;
	if (nstreams >= RCS_MAX || mine >= RCS_WHO) {
		(void)restconf_error(req, 503, "too many streams are open: "
		    "try again");
		return (NULL);
	}
	rs = xcalloc(1, sizeof(*rs));
	rs->b = b;
	rs->hgen = sbind_gen();
	TAILQ_INIT(&rs->src);
	TAILQ_INIT(&rs->add);
	rs->out = buf_alloc(512);
	rs->said = time(NULL);
	atomic_init(&rs->stop, false);
	atomic_init(&rs->ended, false);
	pthread_mutex_init(&rs->lock, NULL);
	return (rs);
}

/* src to rs's sources, for its thread to take. */
static void
rcs_add(struct rcs *rs, struct rcsrc *src)
{

	pthread_mutex_lock(&rs->lock);
	TAILQ_INSERT_TAIL(&rs->add, src, link);
	rs->nsrc++;
	pthread_mutex_unlock(&rs->lock);
}

/* rs's thread started, the reply to req begun with first, a comment;
 * false: no thread for it, rs let go, said so. */
static bool
rcs_go(struct http_request *req, struct rcs *rs, const char *first)
{

	if (hosts_thread(&rs->thread, rcs_run, rs) != 0) {
		rcs_clear(rs);
		(void)restconf_error(req, 503, "no thread for it");
		return (false);
	}
	LIST_INSERT_HEAD(&streams, rs, list);
	nstreams++;
	rs->req = req;
	req->hdlr_extra = rs;
	http_response_header(req, "content-type", "text/event-stream");
	http_response_header(req, "cache-control", "no-store");
	http_response_header(req, "x-content-type-options", "nosniff");
	http_stream(req, 200);
	/* A first line at once: the client knows it is open. */
	put(req, first);
	if (ticker == NULL)
		ticker = timer_add(rcs_tick, RCS_TICK_MS, NULL, 0);
	return (true);
}

/* The stream of the n hosts sv to req, the fleet's (records nested in
 * their hosts) or one host's, of sb's input (NULL: the NETCONF stream),
 * from since when it is not NULL; the reply begun. */
static int
rcs_start(struct http_request *req, const struct server *const *sv,
    size_t n, bool fleet, struct rcsub *sb, const char *since)
{
	struct rcs	*rs;
	bool		 sub = sb != NULL;

	if ((rs = rcs_new(req)) == NULL)
		return (WEB_OK);
	rcs_add(rs, src_new(rs, "", sv, n, fleet, sb, since));
	(void)rcs_go(req, rs, sub ? ": the subscription\n\n" : fleet ?
	    ": the fleet's stream\n\n" : ": the host's NETCONF stream\n\n");
	return (WEB_OK);
}

/* Back after a cut: what came meanwhile first.  An id is an event time,
 * RFC 3339's characters alone; NULL: none. */
static const char *
last_event(struct http_request *req)
{
	const char	*leid;

	if (!http_request_header(req, "last-event-id", &leid) || leid[0] ==
	    '\0' || strlen(leid) >= 40 || leid[strspn(leid,
	    "0123456789-:.TZ+")] != '\0')
		return (NULL);
	return (leid);
}

/* GET /restconf/streams/<id>/json: the host's NETCONF stream as events. */
int
api_restconf_stream(struct http_request *req)
{
	const struct server	*s;
	char			 sid[16];

	if (!guard(req, false))
		return (WEB_OK);
	if (!capture(req, 3, sid, sizeof(sid)) || (s = server_find(sid)) ==
	    NULL)
		return (restconf_error(req, 404, "no such host"));
	if (!host_allowed(req, sid, false, false))
		return (WEB_OK);
	return (rcs_start(req, &s, 1, false, NULL, last_event(req)));
}

/* The hosts of every host's this user may read, into *svp (malloc'd);
 * how many. */
static size_t
fleet_hosts(struct http_request *req, const struct server ***svp)
{
	const struct server	*s, **sv;
	size_t			 n = 0;

	for (int i = 0; server_at(i) != NULL; i++)
		n++;
	sv = xcalloc(n + 1, sizeof(*sv));
	n = 0;
	for (int i = 0; (s = server_at(i)) != NULL; i++)
		if (host_role_ok(req, s->id, false, false))
			sv[n++] = s;
	*svp = sv;
	return (n);
}

/* The fleet's stream of every host's this user may read, of sb's input
 * (NULL: the NETCONF stream). */
static int
fleet_start(struct http_request *req, struct rcsub *sb)
{
	const struct server	**sv;
	size_t			  n;
	int			  rv;

	n = fleet_hosts(req, &sv);
	rv = n == 0 ? restconf_error(req, 404, "no host to hear") :
	    rcs_start(req, sv, n, true, sb, sb == NULL ? last_event(req) :
	    NULL);
	free(sv);
	return (rv);
}

/* GET /restconf/streams/fleet/json: every host's this user may read. */
int
api_restconf_fleet_stream(struct http_request *req)
{

	if (!guard(req, false))
		return (WEB_OK);
	return (fleet_start(req, NULL));
}

/* A string member of o, a copy; NULL when there is none. */
static char *
str_of(const ucl_object_t *o, const char *key, bool *bad)
{
	const ucl_object_t	*v;

	if ((v = ucl_object_lookup(o, key)) == NULL)
		return (NULL);
	if (ucl_object_type(v) != UCL_STRING || strlen(ucl_object_tostring(v))
	    > 1024) {
		*bad = true;
		return (NULL);
	}
	return (xstrdup(ucl_object_tostring(v)));
}

/* A number member of o, lo to hi (a string, as RFC 7951 has uint32's
 * sometimes); false when it is not one. */
static bool
num_of(const ucl_object_t *o, const char *key, int64_t lo, int64_t hi,
    uint32_t *out)
{
	const ucl_object_t	*v;
	char			*end;
	int64_t			 n;

	if ((v = ucl_object_lookup(o, key)) == NULL)
		return (false);
	if (ucl_object_type(v) == UCL_INT)
		n = ucl_object_toint(v);
	else if (ucl_object_type(v) == UCL_STRING) {
		n = strtoll(ucl_object_tostring(v), &end, 10);
		if (*end != '\0' || end == ucl_object_tostring(v))
			return (false);
	} else
		return (false);
	if (n < lo || n > hi)
		return (false);
	*out = (uint32_t)n;
	return (true);
}

/*
 * POST .../host=<id>/ietf-subscribed-notifications:establish-subscription
 * (RFC 8650 section 3.2): the input kept for its stream, its id and URI
 * answered.  sid NULL: POSTed under arcana-fleet:fleet, every host's.
 */
int
restconf_establish(struct http_request *req, const char *sid)
{
	const ucl_object_t	*in, *p;
	const struct server	*s = NULL;
	struct rcsub		 sb, *slot;
	ucl_object_t		*body, *top, *out;
	const char		*v;
	char			 uri[512];
	time_t			 now;
	bool			 bad = false;

	if (!guard(req, false))
		return (WEB_OK);
	if (sid != NULL && (s = server_find(sid)) == NULL)
		return (restconf_error(req, 404, "no such host"));
	if (sid != NULL && !host_allowed(req, sid, false, false))
		return (WEB_OK);
	if ((body = read_json(req)) == NULL || (in = ucl_object_lookup(body,
	    "ietf-subscribed-notifications:input")) == NULL ||
	    ucl_object_type(in) != UCL_OBJECT) {
		if (body != NULL)
			ucl_object_unref(body);
		return (restconf_error(req, 400, "the body is {\"ietf-"
		    "subscribed-notifications:input\": {...}}"));
	}
	memset(&sb, 0, sizeof(sb));
	sb.fleet = sid == NULL;
	if (sid != NULL)
		strlcpy(sb.sid, s->id, sizeof(sb.sid));
	(void)session_owner(req, sb.who, sizeof(sb.who));
	sb.stop = str_of(in, "stop-time", &bad);
	if ((v = ucl_object_tostring(ucl_object_lookup(in, "stream"))) != NULL) {
		/* A stream: the agent's one, NETCONF. */
		if (strcmp(v, "NETCONF") != 0)
			bad = true;
		sb.xpath = str_of(in, "stream-xpath-filter", &bad);
		sb.replay = str_of(in, "replay-start-time", &bad);
	} else if ((v = ucl_object_tostring(ucl_object_lookup(in,
	    "ietf-yang-push:datastore"))) != NULL) {
		if (strcmp(v, "ietf-datastores:operational") != 0)
			bad = true;
		sb.datastore = true;
		sb.xpath = str_of(in, "ietf-yang-push:datastore-xpath-filter",
		    &bad);
		if ((p = ucl_object_lookup(in, "ietf-yang-push:periodic")) !=
		    NULL) {
			if (!num_of(p, "period", 10, UINT32_MAX, &sb.period))
				bad = true;
			sb.anchor = str_of(p, "anchor-time", &bad);
		} else if ((p = ucl_object_lookup(in,
		    "ietf-yang-push:on-change")) != NULL) {
			sb.onchange = true;
			if (ucl_object_lookup(p, "dampening-period") != NULL &&
			    !num_of(p, "dampening-period", 0, UINT32_MAX,
			    &sb.damp))
				bad = true;
		} else
			bad = true;
	} else
		bad = true;
	ucl_object_unref(body);
	if (bad) {
		sub_clear(&sb);
		return (restconf_error(req, 400, "a subscription is of the "
		    "NETCONF stream, or of ietf-datastores:operational, "
		    "periodic (its period, centiseconds, 10 at least) or "
		    "on-change; its filter an XPath"));
	}
	/* A slot: a free one, or one whose time to be taken is past. */
	now = time(NULL);
	slot = NULL;
	for (int i = 0; i < SUBS_MAX && slot == NULL; i++)
		if (subs[i].id == 0 || now - subs[i].made > SUB_WAIT_S)
			slot = &subs[i];
	if (slot == NULL) {
		sub_clear(&sb);
		return (restconf_error(req, 503, "too many subscriptions wait "
		    "to be taken"));
	}
	sub_clear(slot);
	*slot = sb;
	slot->made = now;
	do
		slot->id = arc4random() & 0x7fffffff;
	while (slot->id == 0);
	snprintf(uri, sizeof(uri), "%s/restconf/subscriptions/%u",
	    cfg.origin != NULL ? cfg.origin : "", slot->id);
	out = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(out, ucl_object_fromint(slot->id), "id", 0,
	    false);
	ucl_object_insert_key(out, ucl_object_fromstring(uri),
	    "ietf-restconf-subscribed-notifications:uri", 0, false);
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, out, "ietf-subscribed-notifications:output",
	    0, false);
	return (restconf_reply(req, top));
}

/* Subscription id, made by who, not yet taken and its time to be taken
 * not past; NULL. */
static struct rcsub *
sub_find(unsigned long id, const char *who)
{

	for (int i = 0; i < SUBS_MAX; i++)
		if (subs[i].id != 0 && subs[i].id == id && who[0] != '\0' &&
		    strcmp(subs[i].who, who) == 0 && time(NULL) -
		    subs[i].made <= SUB_WAIT_S)
			return (&subs[i]);
	return (NULL);
}

/* GET /restconf/subscriptions/<id>: an established subscription's stream,
 * to whoever made it, once. */
int
api_restconf_subscription(struct http_request *req)
{
	const struct server	*s;
	struct rcsub		*sb;
	char			 num[16], *end, who[256];
	unsigned long		 id;

	if (!guard(req, false))
		return (WEB_OK);
	if (!capture(req, 3, num, sizeof(num)) || (id = strtoul(num, &end,
	    10)) == 0 || *end != '\0')
		return (restconf_error(req, 404, "no such subscription"));
	(void)session_owner(req, who, sizeof(who));
	if ((sb = sub_find(id, who)) == NULL)
		return (restconf_error(req, 404, "no such subscription"));
	if (sb->fleet) {
		sb->id = 0;
		return (fleet_start(req, sb));
	}
	if ((s = server_find(sb->sid)) == NULL)
		return (restconf_error(req, 404, "no such subscription"));
	if (!host_allowed(req, sb->sid, false, false))
		return (WEB_OK);
	sb->id = 0;
	return (rcs_start(req, &s, 1, false, sb, NULL));
}

/* ---- A page's stream ------------------------------------------------- */

/* A source a page's stream is asked for: its name, replayed from since
 * ("" from now). */
struct pagesrc {
	char	name[24];
	char	since[40];
};

/* Is name one of a page's sources: "fleet", or "sub-<id>" (its id into
 * idp)? */
static bool
page_name(const char *name, unsigned long *idp)
{
	char		*end;
	unsigned long	 id;

	if (strcmp(name, "fleet") == 0) {
		*idp = 0;
		return (true);
	}
	if (strncmp(name, "sub-", 4) != 0 || name[4] < '1' || name[4] > '9' ||
	    strlen(name + 4) > 10 || name[4 + strspn(name + 4,
	    "0123456789")] != '\0')
		return (false);
	id = strtoul(name + 4, &end, 10);
	if (id == 0 || id > 0x7fffffff)
		return (false);
	*idp = id;
	return (true);
}

/* name, from since, to the n of l (max long), once: named twice, from
 * the time one of them has. */
static void
page_want(struct pagesrc *l, size_t *n, size_t max, const char *name,
    const char *since)
{

	for (size_t i = 0; i < *n; i++)
		if (strcmp(l[i].name, name) == 0) {
			if (l[i].since[0] == '\0')
				strlcpy(l[i].since, since, sizeof(l[i].since));
			return;
		}
	if (*n == max)
		return;
	strlcpy(l[*n].name, name, sizeof(l[*n].name));
	strlcpy(l[*n].since, since, sizeof(l[*n].since));
	(*n)++;
}

/*
 * The sources a client back names in its Last-Event-ID, each with its
 * last record's event time, "fleet@<time>;sub-<id>" (rcs_id()), to the
 * n of l; what is not one is passed over.
 */
static void
page_last(struct http_request *req, struct pagesrc *l, size_t *n,
    size_t max)
{
	const char	*leid, *p, *at, *e;
	char		 name[24], since[40];
	unsigned long	 id;
	size_t		 k;

	if (!http_request_header(req, "last-event-id", &leid) ||
	    strlen(leid) >= PAGE_SRC_MAX * 72)
		return;
	for (p = leid; *p != '\0'; p = *e == ';' ? e + 1 : e) {
		e = p + strcspn(p, ";");
		at = memchr(p, '@', (size_t)(e - p));
		k = (size_t)((at != NULL ? at : e) - p);
		if (k >= sizeof(name))
			continue;
		memcpy(name, p, k);
		name[k] = '\0';
		since[0] = '\0';
		if (at != NULL) {
			k = (size_t)(e - at - 1);
			if (k >= sizeof(since))
				continue;
			memcpy(since, at + 1, k);
			since[k] = '\0';
			if (since[strspn(since, "0123456789-:.TZ+")] != '\0')
				continue;
		}
		if (page_name(name, &id))
			page_want(l, n, max, name, since);
	}
}

/* Is a source of rs's named name, and not given up?  Under the lock. */
static bool
page_has(struct rcs *rs, const char *name)
{
	struct rcsrcs	*l[2] = { &rs->src, &rs->add };
	struct rcsrc	*src;

	for (int k = 0; k < 2; k++)
		TAILQ_FOREACH(src, l[k], link)
			if (strcmp(src->name, name) == 0 &&
			    !atomic_load(&src->end))
				return (true);
	return (false);
}

/*
 * Source name ("fleet", "sub-<id>") of req's to page stream rs, from
 * since ("": from now): the fleet's stream of every host it may read, or
 * a subscription it established, judged as the fleet's stream's GET and
 * the subscription's are.  0, or the status it is refused with, why into
 * why.
 */
static int
page_add(struct http_request *req, struct rcs *rs, const char *name,
    const char *since, char *why, size_t len)
{
	const struct server	**sv, *s;
	struct rcsub		 *sb;
	struct rcsrc		 *src;
	char			  who[256];
	struct rcs		 *o;
	unsigned long		  id;
	size_t			  n, k, mine, all;
	bool			  have;

	if (!page_name(name, &id)) {
		snprintf(why, len, "a source is fleet or sub-<id>");
		return (400);
	}
	pthread_mutex_lock(&rs->lock);
	have = page_has(rs, name);
	n = rs->nsrc;
	pthread_mutex_unlock(&rs->lock);
	if (have)
		return (0);
	if (n >= PAGE_SRC_MAX) {
		snprintf(why, len, "a page's stream has %d sources at most",
		    PAGE_SRC_MAX);
		return (503);
	}
	/* Each source is the hosts' streams of its own, as a stream of one
	 * source was: counted as those were, of one principal and of all. */
	mine = all = 0;
	LIST_FOREACH(o, &streams, list) {
		if (!o->page || o->req == NULL)
			continue;
		pthread_mutex_lock(&o->lock);
		k = o->nsrc;
		pthread_mutex_unlock(&o->lock);
		all += k;
		if (o->b.who.kind == rs->b.who.kind && strcmp(o->b.who.name,
		    rs->b.who.name) == 0 && (rs->b.who.kind == P_USER ||
		    strcmp(o->b.addr, rs->b.addr) == 0))
			mine += k;
	}
	/* rs itself is on the list only once its reply began. */
	if (rs->req == NULL) {
		all += n;
		mine += n;
	}
	if (mine >= PAGE_SRC_WHO || all >= PAGE_SRC_ALL) {
		snprintf(why, len, "too many sources are heard: try again");
		return (503);
	}
	(void)session_owner(req, who, sizeof(who));
	if (id == 0) {
		if ((n = fleet_hosts(req, &sv)) == 0) {
			free(sv);
			snprintf(why, len, "no host to hear");
			return (404);
		}
		src = src_new(rs, name, sv, n, true, NULL, since[0] != '\0' ?
		    since : NULL);
		free(sv);
	} else if ((sb = sub_find(id, who)) == NULL) {
		snprintf(why, len, "no such subscription");
		return (404);
	} else if (sb->fleet) {
		sb->id = 0;
		if ((n = fleet_hosts(req, &sv)) == 0) {
			free(sv);
			snprintf(why, len, "no host to hear");
			return (404);
		}
		src = src_new(rs, name, sv, n, true, sb, NULL);
		free(sv);
		src->sub.id = (uint32_t)id;
	} else {
		/* As host_allowed() judges a read: no such host to one who
		 * may not read it. */
		if ((s = server_find(sb->sid)) == NULL ||
		    !host_role_ok(req, sb->sid, false, false)) {
			snprintf(why, len, "no such server");
			return (404);
		}
		sb->id = 0;
		src = src_new(rs, name, &s, 1, false, sb, since[0] != '\0' ?
		    since : NULL);
		src->sub.id = (uint32_t)id;
	}
	rcs_add(rs, src);
	return (0);
}

/*
 * GET /restconf/streams/page/json?fleet=1&sub=<id>,<id>: the page's one
 * stream, of the fleet's and of the subscriptions named, and of those
 * its Last-Event-ID names; one refused said ended, why, the rest heard.
 */
int
api_restconf_page_stream(struct http_request *req)
{
	struct pagesrc	 l[PAGE_SRC_MAX * 2];
	struct rcs	*rs;
	struct rcsrc	*src;
	struct buf	*said, *page;
	uint8_t		 raw[PAGE_ID_LEN / 2];
	const char	*v, *p;
	char		 name[24], why[200], first[80], *err;
	unsigned long	 id;
	size_t		 n = 0, k;
	int		 st;

	if (!guard(req, false))
		return (WEB_OK);
	if (http_argument_get_string(req, "fleet", &v) && strcmp(v, "1") == 0)
		page_want(l, &n, nitems(l), "fleet", "");
	if (http_argument_get_string(req, "sub", &v))
		for (p = v; *p != '\0'; p += k + (p[k] == ',' ? 1 : 0)) {
			k = strcspn(p, ",");
			if (snprintf(name, sizeof(name), "sub-%.*s", (int)k, p) >=
			    (int)sizeof(name) || !page_name(name, &id))
				return (restconf_error(req, 400, "sub is a list "
				    "of subscriptions' ids"));
			page_want(l, &n, nitems(l), name, "");
		}
	page_last(req, l, &n, nitems(l));
	if ((rs = rcs_new(req)) == NULL)
		return (WEB_OK);
	rs->page = true;
	arc4random_buf(raw, sizeof(raw));
	for (size_t i = 0; i < sizeof(raw); i++)
		snprintf(rs->pid + 2 * i, 3, "%02x", raw[i]);
	(void)session_owner(req, rs->owner, sizeof(rs->owner));
	said = buf_alloc(256);
	for (size_t i = 0; i < n; i++) {
		if ((st = page_add(req, rs, l[i].name, l[i].since, why,
		    sizeof(why))) == 0 || (err = restconf_errors(st, why)) ==
		    NULL)
			continue;
		buf_appendf(said, "event: %s.end\ndata: %s\n\n", l[i].name, err);
		free(err);
	}
	page = buf_alloc(256);
	buf_appendf(page, "event: page\ndata: {\"stream\":\"%s\",\"sources\":[",
	    rs->pid);
	TAILQ_FOREACH(src, &rs->add, link)
		buf_appendf(page, "%s\"%s\"", src == TAILQ_FIRST(&rs->add) ? "" :
		    ",", src->name);
	buf_appendf(page, "]}\n\n");
	snprintf(first, sizeof(first), ": the page's stream %s\n\n", rs->pid);
	if (rcs_go(req, rs, first)) {
		http_stream_put(req, said->data, said->offset);
		http_stream_put(req, page->data, page->offset);
	}
	buf_free(said);
	buf_free(page);
	return (WEB_OK);
}

/* The page's stream pid, its reply not gone, opened by req's session
 * (or bearer token), its owner who; NULL. */
static struct rcs *
page_find(struct http_request *req, const char *pid, const char *who)
{
	struct rcs	*rs;
	struct sbind	 b;

	if (strlen(pid) != PAGE_ID_LEN || who[0] == '\0')
		return (NULL);
	sbind_make(req, &b);
	LIST_FOREACH(rs, &streams, list)
		if (rs->page && rs->req != NULL && !atomic_load(&rs->stop) &&
		    timingsafe_bcmp(rs->pid, pid, PAGE_ID_LEN) == 0 &&
		    strcmp(rs->owner, who) == 0 && memcmp(rs->b.hash, b.hash,
		    sizeof(b.hash)) == 0 && strcmp(rs->b.tok, b.tok) == 0)
			return (rs);
	return (NULL);
}

/* Source name of rs's given up: one not yet taken let go here, one taken
 * by its thread; false when it has none of that name. */
static bool
page_end(struct rcs *rs, const char *name)
{
	struct rcsrc	*src, *drop = NULL;
	bool		 found = false;

	pthread_mutex_lock(&rs->lock);
	TAILQ_FOREACH(src, &rs->add, link)
		if (strcmp(src->name, name) == 0) {
			TAILQ_REMOVE(&rs->add, src, link);
			rs->nsrc--;
			drop = src;
			found = true;
			break;
		}
	if (!found)
		TAILQ_FOREACH(src, &rs->src, link)
			if (strcmp(src->name, name) == 0 &&
			    !atomic_load(&src->end)) {
				atomic_store(&src->end, true);
				found = true;
				break;
			}
	pthread_mutex_unlock(&rs->lock);
	if (drop != NULL)
		src_free(drop);
	return (found);
}

/*
 * POST /restconf/streams/page/<id>: a source added to the page's stream
 * of that id ({"add": "<name>"}), or one given up ({"end": "<name>"}),
 * by the session (or token) that opened it alone; to any other, there is
 * no such stream.
 */
int
api_restconf_page_change(struct http_request *req)
{
	ucl_object_t	*body;
	struct rcs	*rs;
	const char	*add, *end;
	char		 pid[PAGE_ID_LEN + 8], who[256], why[200], name[24];
	bool		 adding;
	int		 st;

	if (!guard(req, true))
		return (WEB_OK);
	(void)session_owner(req, who, sizeof(who));
	if (!capture(req, 4, pid, sizeof(pid)) || (rs = page_find(req, pid,
	    who)) == NULL)
		return (restconf_error(req, 404, "no such stream"));
	if ((body = read_json(req)) == NULL)
		return (restconf_error(req, 400, "the body is {\"add\": "
		    "<source>} or {\"end\": <source>}"));
	add = ucl_object_tostring(ucl_object_lookup(body, "add"));
	end = ucl_object_tostring(ucl_object_lookup(body, "end"));
	if ((add == NULL) == (end == NULL) || strlen(add != NULL ? add :
	    end) >= sizeof(name)) {
		ucl_object_unref(body);
		return (restconf_error(req, 400, "the body is {\"add\": "
		    "<source>} or {\"end\": <source>}"));
	}
	strlcpy(name, add != NULL ? add : end, sizeof(name));
	adding = add != NULL;
	ucl_object_unref(body);
	if (adding) {
		if ((st = page_add(req, rs, name, "", why, sizeof(why))) != 0)
			return (restconf_error(req, st, why));
	} else if (!page_end(rs, name))
		return (restconf_error(req, 404, "no such source"));
	http_response(req, 204, NULL, 0);
	return (WEB_OK);
}
