/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Requests: every one gets an id and a callback; bridge.js answers with
 * arc_on_http() or arc_on_webauthn().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <emscripten/emscripten.h>

#include "app.h"

#define	MAX_PENDING	256

struct inflight {
	int		 id;
	api_cb		*cb;
	/* A GET of a host's: kept for the tab it was made for (export.c). */
	char		 url[300];
	int		 node, tab;
	int		 op;		/* the task it is, or 0 */
	bool		 awaited;	/* op: the task that awaited it; else a quiet poll */
	/* A read of the host shown, for a callback with no context of its
	 * own: the shown host's generation then (api_gen()), its id. */
	unsigned int	 gen;
	char		 sid[9];
	void		 (*wcb)(bool, const char *, void *);
	void		*arg;
};

static struct inflight	pend[MAX_PENDING];
static int		lastid;
static bool		reads;		/* the next request only reads */
static bool		keep;		/* ... is answered whatever is shown */
static unsigned int	gen;		/* of the host shown */
static char		gen_sid[9];

/*
 * The generation of the host the page shows: another each time it
 * shows another.  A read made for the page as it is shown, its callback
 * holding nothing of its own (arg NULL), is taken at one; its reply,
 * come at another with that host no longer shown, is dropped: it would
 * fill the page of the host shown now with the other's.
 */
unsigned int
api_gen(void)
{
	const struct server	*s;
	const char		*id;

	id = (s = cur_server()) != NULL ? s->id : "";
	if (strcmp(id, gen_sid) != 0) {
		snprintf(gen_sid, sizeof(gen_sid), "%s", id);
		gen++;
	}
	return (gen);
}

/* A read of sid's taken at generation g that no one waits for now. */
bool
api_stale(unsigned int g, const char *sid)
{
	const struct server	*s;

	return (sid[0] != '\0' && g != api_gen() && ((s = cur_server()) ==
	    NULL || strcmp(s->id, sid) != 0));
}

/* The next request answered whatever host is shown by then. */
void
api_keep(void)
{

	keep = true;
}

/* The host a URL of the console's names: /api/servers/<id>/, host=<id>. */
static void
url_host(const char *url, char *sid, size_t len)
{
	const char	*p;

	sid[0] = '\0';
	if ((p = strstr(url, "/servers/")) != NULL)
		p += 9;
	else if ((p = strstr(url, "host=")) != NULL)
		p += 5;
	else
		return;
	snprintf(sid, len, "%.*s", (int)strcspn(p, "/?&"), p);
}

static struct inflight *
slot(void)
{
	int	i;

	for (i = 0; i < MAX_PENDING; i++)
		if (pend[i].id == 0) {
			pend[i].id = ++lastid;
			return (&pend[i]);
		}
	return (NULL);
}

static struct inflight *
lookup(int id)
{
	int	i;

	for (i = 0; i < MAX_PENDING; i++)
		if (pend[i].id == id)
			return (&pend[i]);
	return (NULL);
}

/*
 * Send a request.  cb gets the HTTP status (0: no answer), the parsed
 * JSON reply and the error message, if any.
 */
int
api(const char *method, const char *url, const char *body, api_cb *cb,
    void *arg)
{

	return (api_hdr(method, url, body, NULL, cb, arg));
}

/* The next request, though a POST, only reads (an action's read). */
void
api_reads(void)
{

	reads = true;
}

/* The same with headers of the caller's own, "Name: value" a line. */
int
api_hdr(const char *method, const char *url, const char *body,
    const char *hdrs, api_cb *cb, void *arg)
{
	struct inflight	*p;
	bool		 rd, k;
	int		 id;

	rd = reads || strcmp(method, "GET") == 0;
	reads = false;
	k = keep;
	keep = false;

	/* Not sent is not "no answer": the console is not to blame. */
	if ((p = slot()) == NULL) {
		cb(429, NULL, "too many requests in flight here; try again",
		    arg);
		return (0);
	}
	p->cb = cb;
	p->arg = arg;
	id = p->id;
	p->url[0] = '\0';
	/* A read for the page as shown: of the host shown, the callback
	 * keeping nothing of its own. */
	p->sid[0] = '\0';
	if (rd && arg == NULL && !k) {
		url_host(url, p->sid, sizeof(p->sid));
		if (cur_server() == NULL || strcmp(cur_server()->id, p->sid) !=
		    0)
			p->sid[0] = '\0';
		p->gen = api_gen();
	}
	if (rd && strlen(url) < sizeof(p->url)) {
		snprintf(p->url, sizeof(p->url), "%s", url);
		export_where(&p->node, &p->tab);
	}
	/*
	 * A task is made just before the request that does it: the first
	 * request after is its, said in its graph while it waits.
	 */
	p->op = 0;
	p->awaited = false;
	if (app.nops > 0 && app.ops[0].await) {
		snprintf(app.ops[0].method, sizeof(app.ops[0].method), "%s",
		    method);
		snprintf(app.ops[0].url, sizeof(app.ops[0].url), "%s", url);
		app.ops[0].await = false;
		/* Bound to it: given up with it, and ended by its answer
		 * when its callback does not end it. */
		p->op = app.ops[0].id;
		p->awaited = true;
		app.ops[0].req = id;
	} else if (!rd && strncmp(url, "/api/auth/",
	    10) != 0 && strcmp(url, "/api/health") != 0) {
		/* A change no part made a task for: one of its own. */
		p->op = op_auto(method, url, id);
		p->awaited = true;
	} else if (app.quiet && rd)
		/* The page's own poll: a task too, shown apart from what
		 * was asked for, so that every exchange can be seen. */
		p->op = op_quiet_begin(method, url);
	/* A change: the control that asked for it busy until answered. */
	if (!rd)
		arc_busy(id);
	/* The tick's reads wait behind the rest; the health check not. */
	arc_http(id, method, url, body, hdrs, !(rd && app.polling) ||
	    strcmp(url, "/api/health") == 0);
	return (id);
}

/* The entity-tag of the answer being handled, NULL: none. */
static const char	*cur_etag;

const char *
api_etag(void)
{

	return (cur_etag);
}

EMSCRIPTEN_KEEPALIVE void
arc_on_http(int id, int status, char *text, char *etag)
{
	struct inflight	 p, *pp;
	ucl_object_t	*o;
	const char	*err;
	char		 why[320], rcwhy[600];

	if ((pp = lookup(id)) == NULL) {
		free(text);
		free(etag);
		return;
	}
	p = *pp;
	memset(pp, 0, sizeof(*pp));
	o = status != 0 && text[0] != '\0' ? json_parse(text) : NULL;
	/* The console's reason: error.message, RESTCONF's (rc.c), or an
	 * error as a text. */
	err = NULL;
	if (status == 0)
		err = text;
	else if (status >= 400 && (err = jstr(o, "error.message")) == NULL &&
	    (err = rc_error(o, rcwhy, sizeof(rcwhy))) == NULL)
		err = jstr(o, "error");
	/* None: a change's 204, RESTCONF's. */
	if (status >= 200 && status < 300 && o == NULL && status != 204)
		err = "the console sent something that is not JSON";
	/*
	 * Every answer means the console is up; a 401 means log in: the
	 * page loads itself again, nothing of the session kept in it, its
	 * sign-in page saying why.
	 */
	if (status != 0)
		app.api = LINK_UP;
	if (status == 401 && app.screen == SCREEN_CONSOLE) {
		plugins_signed_out();
		arc_start_over(1);
		app.screen = SCREEN_LOGIN;
	}
	/*
	 * An error without a reason of ours did not come from the console's
	 * own handlers: a proxy in front of it, or its server.  Say what
	 * came, so that it can be looked for.
	 */
	if (err == NULL && status >= 400) {
		snprintf(why, sizeof(why), "HTTP %d without a reason%s%.120s",
		    status, text != NULL && text[0] != '\0' && o == NULL ?
		    "; it said: " : " (not from the console's own code: a "
		    "proxy in front of it, or its server)", text != NULL &&
		    o == NULL ? text : "");
		err = why;
	}
	if (status == 200 && p.url[0] != '\0')
		export_note(p.url, p.node, p.tab, o);
	if (p.op != 0 && !p.awaited)
		op_quiet_end(p.op, status);
	cur_etag = etag;
	/* Read for a host shown no more: not the page's now. */
	if (p.sid[0] == '\0' || !api_stale(p.gen, p.sid))
		p.cb(status, o, err, p.arg);
	cur_etag = NULL;
	if (p.awaited)
		op_answered(p.op, id, status, o, err);
	if (o != NULL)
		ucl_object_unref(o);
	free(text);
	free(etag);
	render();
}

void
webauthn(bool create, const char *options, void (*cb)(bool, const char *,
    void *), void *arg)
{
	struct inflight	*p;

	if ((p = slot()) == NULL) {
		cb(false, "busy", arg);
		return;
	}
	p->wcb = cb;
	p->arg = arg;
	arc_webauthn(p->id, create ? 1 : 0, options);
}

EMSCRIPTEN_KEEPALIVE void
arc_on_webauthn(int id, int ok, char *result)
{
	struct inflight	 p, *pp;

	if ((pp = lookup(id)) == NULL) {
		free(result);
		return;
	}
	p = *pp;
	memset(pp, 0, sizeof(*pp));
	p.wcb(ok != 0, result, p.arg);
	free(result);
	render();
}
