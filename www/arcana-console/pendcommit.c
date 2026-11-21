/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The confirmed commits waiting to be kept, a host each (RFC 6241
 * section 8.4): one made through the console's RESTCONF carries persist
 * (restconf.c), and the console keeps it here from the commit to its
 * confirm, its cancel-commit or its timeout, with who made it.  A page
 * that reloads has forgotten its token, which the host would undo at
 * the timeout: hosts/host=<id>/pending-commit says the commit waits (who
 * made it, when, its timeout, the seconds left, whether the reader may
 * keep it), never its persist-id, which is the commit's alone; its maker
 * or a console owner keeps it (keep-commit: the commit that confirms,
 * over a connection of its own) or undoes it (undo-commit:
 * cancel-commit), the console giving the persist-id for them.  Kept in
 * memory: a console that restarts knows none, and the host undoes it at
 * the timeout.
 */

#include <sys/param.h>

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <ucl.h>

#include "console.h"
#include "restconf.h"

struct pendc {
	char	sid[9];
	char	user[USER_NAME_LEN];
	char	token[256];		/* the persist-id: never said */
	time_t	made;
	time_t	deadline;
	uint32_t timeout;
	bool	used;
};

#define	PENDC_MAX	1024

static struct pendc	pendcs[PENDC_MAX];
static pthread_mutex_t	pendc_lock = PTHREAD_MUTEX_INITIALIZER;

/* With the lock held: host sid's, its timeout not past; NULL, none. */
static struct pendc *
find(const char *sid, time_t now)
{

	for (size_t i = 0; i < nitems(pendcs); i++) {
		if (!pendcs[i].used || strcmp(pendcs[i].sid, sid) != 0)
			continue;
		if (pendcs[i].deadline <= now) {
			explicit_bzero(&pendcs[i], sizeof(pendcs[i]));
			return (NULL);
		}
		return (&pendcs[i]);
	}
	return (NULL);
}

/*
 * A commit host sid took, as its input said (restconf.c, after the host
 * answered it): confirmed with persist, one waiting now (or again, a
 * follow-up confirmed commit with persist-id moving its timeout); one
 * that confirms, or a plain one, none.  user: who made it, the host's
 * NACM name of them.
 */
void
pendc_commit(const char *sid, const char *user, bool confirmed,
    const char *persist, const char *persist_id, uint32_t timeout)
{
	struct pendc	*p;
	time_t		 now = time(NULL);

	pthread_mutex_lock(&pendc_lock);
	p = find(sid, now);
	if (!confirmed || persist == NULL || persist[0] == '\0' ||
	    strlen(persist) >= sizeof(p->token)) {
		if (p != NULL)
			explicit_bzero(p, sizeof(*p));
		pthread_mutex_unlock(&pendc_lock);
		return;
	}
	/* A follow-up of the one waiting keeps its maker. */
	if (p != NULL && (persist_id == NULL || strcmp(persist_id, p->token) !=
	    0))
		explicit_bzero(p, sizeof(*p));
	if (p == NULL || !p->used) {
		for (size_t i = 0; p == NULL && i < nitems(pendcs); i++)
			if (!pendcs[i].used || pendcs[i].deadline <= now)
				p = &pendcs[i];
		if (p == NULL) {
			pthread_mutex_unlock(&pendc_lock);
			return;
		}
		memset(p, 0, sizeof(*p));
		p->used = true;
		(void)strlcpy(p->sid, sid, sizeof(p->sid));
		(void)strlcpy(p->user, user != NULL ? user : "",
		    sizeof(p->user));
		p->made = now;
	}
	(void)strlcpy(p->token, persist, sizeof(p->token));
	p->timeout = timeout > 0 ? timeout : 600;
	p->deadline = now + (time_t)p->timeout;
	pthread_mutex_unlock(&pendc_lock);
}

/* A cancel-commit host sid took: none waits. */
void
pendc_cancel(const char *sid)
{
	struct pendc	*p;

	pthread_mutex_lock(&pendc_lock);
	if ((p = find(sid, time(NULL))) != NULL)
		explicit_bzero(p, sizeof(*p));
	pthread_mutex_unlock(&pendc_lock);
}

/* Host sid's one waiting, copied (its token too); false: none. */
static bool
pendc_get(const char *sid, struct pendc *out)
{
	struct pendc	*p;

	pthread_mutex_lock(&pendc_lock);
	if ((p = find(sid, time(NULL))) != NULL)
		*out = *p;
	pthread_mutex_unlock(&pendc_lock);
	return (p != NULL);
}

/* Whether req's principal may keep or undo p: its maker, or an owner of
 * the console. */
static bool
may_settle(struct http_request *req, const struct pendc *p)
{
	struct principal	who;
	char			name[USER_NAME_LEN];

	if (req_console(req) == CROLE_OWNER)
		return (true);
	req_principal(req, &who);
	if (principal_nacm(&who, name, sizeof(name)) == NULL || name[0] == '\0')
		return (false);
	return (strcmp(name, p->user) == 0);
}

static ucl_object_t *
doc_of(struct http_request *req, const struct pendc *p, bool has)
{
	ucl_object_t	*o;
	time_t		 now = time(NULL);

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_frombool(has), "waiting", 0,
	    false);
	if (!has)
		return (o);
	ucl_object_insert_key(o, ucl_object_fromstring(p->user[0] != '\0' ?
	    p->user : NACM_CONSOLE), "user", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)p->made), "made",
	    0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)p->timeout),
	    "timeout", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)p->deadline),
	    "deadline", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(p->deadline > now ?
	    (int64_t)(p->deadline - now) : 0), "left", 0, false);
	ucl_object_insert_key(o, ucl_object_frombool(may_settle(req, p)),
	    "yours", 0, false);
	return (o);
}

/* keep-commit's and undo-commit's task: the host asked as the request's
 * principal. */
struct settle {
	struct task	 task;		/* first */
	bool		 keep;
	char		 sid[9];
	char		*uri, *peer, *name;
	char		 token[256];
	char		*json;
	int		 status;
};

static int
settle_run(struct task *t)
{
	struct settle	*st = (struct settle *)t;
	ucl_object_t	*body, *in;
	char		 path[160];

	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/"
	    "host=%s/ietf-netconf:%s", st->sid, st->keep ? "commit" :
	    "cancel-commit");
	in = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(in, ucl_object_fromstring(st->token),
	    "persist-id", 0, false);
	body = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(body, in, "ietf-netconf:input", 0, false);
	hosts_need(ROLE_OPERATOR);
	st->json = hosts_restconf(st->sid, st->uri, st->peer, st->name,
	    HTTP_METHOD_POST, path, body, &st->status);
	explicit_bzero(st->token, sizeof(st->token));
	return (WEB_OK);
}

static void
settle_free(struct settle *st)
{

	explicit_bzero(st->token, sizeof(st->token));
	free(st->uri);
	free(st->peer);
	free(st->name);
	free(st->json);
	free(st);
}

/* The host's refusal of a keep or an undo: its error-message, with the
 * status it came with. */
static int
refused(struct http_request *req, const struct settle *st)
{
	struct ucl_parser	*pr;
	ucl_object_t		*top = NULL;
	const ucl_object_t	*e;
	const char		*msg = "the host was not reached";
	int			 rc;

	if (st->json != NULL) {
		pr = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		if (ucl_parser_add_string(pr, st->json, 0))
			top = ucl_parser_get_object(pr);
		ucl_parser_free(pr);
		e = ucl_object_lookup(top, "ietf-restconf:errors");
		e = ucl_array_head(ucl_object_lookup(e, "error"));
		if ((e = ucl_object_lookup(e, "error-message")) != NULL &&
		    ucl_object_tostring(e) != NULL)
			msg = ucl_object_tostring(e);
	}
	rc = restconf_error(req, st->status != 0 ? st->status : 502, msg);
	ucl_object_unref(top);
	return (rc);
}

/*
 * GET hosts/host=<id>/pending-commit: the confirmed commit waiting on
 * the host, a viewer's to read; POST keep-commit or undo-commit settles
 * it, its maker's or a console owner's: the host's answer, its
 * ietf-restconf:errors where it refused.
 */
int
api_pending_commit(struct http_request *req)
{
	const struct server	*s;
	struct settle		*st;
	struct pendc		 p;
	ucl_object_t		*o;
	char			 id[17];
	bool			 has;

	if ((st = req->hdlr_extra) != NULL) {
		if (task_state(&st->task) != TASK_STATE_FINISHED) {
			http_request_sleep(req);
			return (WEB_RETRY);
		}
		if (st->status != 200 && st->status != 204)
			return (refused(req, st));
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(st->keep ?
		    "kept" : "undone"), "state", 0, false);
		return (cyang_output(req, o));
	}
	if (!server_capture(req, id, sizeof(id)) ||
	    (s = server_find(id)) == NULL)
		return (reply_error(req, 404, "not_found", "no such host"));
	if (req->method == HTTP_METHOD_GET) {
		if (!guard(req, false) || !host_allowed(req, id, false, false))
			return (WEB_OK);
		has = pendc_get(id, &p);
		o = doc_of(req, &p, has);
		explicit_bzero(&p, sizeof(p));
		return (reply_json(req, 200, o));
	}
	if (!guard(req, true) || !host_allowed(req, id, true, false))
		return (WEB_OK);
	if (!pendc_get(id, &p))
		return (reply_error(req, 404, "not_found", "no confirmed "
		    "commit waits on the host"));
	if (!may_settle(req, &p)) {
		char	who[USER_NAME_LEN];

		(void)strlcpy(who, p.user, sizeof(who));
		explicit_bzero(&p, sizeof(p));
		return (reply_error(req, 403, "forbidden", "only %s, who made "
		    "it, or an owner of the console keeps or undoes it", who));
	}
	st = xcalloc(1, sizeof(*st));
	st->keep = strstr(req->path, "/keep-commit") != NULL;
	(void)strlcpy(st->sid, id, sizeof(st->sid));
	(void)strlcpy(st->token, p.token, sizeof(st->token));
	explicit_bzero(&p, sizeof(p));
	st->uri = xstrdup(s->uri);
	st->peer = s->peer_name != NULL ? xstrdup(s->peer_name) : NULL;
	st->name = xstrdup(s->name);
	req->hdlr_extra = st;
	task_create(&st->task, settle_run);
	task_bind_request(&st->task, req);
	task_run(&st->task);
	return (WEB_RETRY);
}

void
api_pending_commit_free(struct http_request *req)
{
	struct settle	*st = req->hdlr_extra;

	if (st == NULL || !task_finished(&st->task))
		return;
	task_destroy(&st->task);
	settle_free(st);
	req->hdlr_extra = NULL;
}
