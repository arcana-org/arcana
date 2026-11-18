/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The services as the console stores them: RFC 9182's L3VPN network
 * model (L3NM, ietf-l3vpn-ntw, with RFC 9181's ietf-vpn-common), a
 * datastore of the console's own, served by RESTCONF beside the fleet:
 *
 *	/restconf/data/ietf-l3vpn-ntw:l3vpn-ntw[/<api-path>]
 *
 * GET, POST, PUT, PATCH (plain and YANG Patch) and DELETE, as restconf.c
 * makes them of a host's candidate, here of the tree kept, then checked
 * as RFC 7950 says and kept whole: l3nm.json in the data directory, RFC
 * 7951's JSON, saved through the cluster as every store is.  It is read
 * at each request, so a change another node of the cluster made is
 * what the next one sees.  Who may: the console's operators and owners,
 * as arcana-console's sdwan (users.c).
 *
 * The SD-WAN document arcana-console's sdwan/document serves (sdwan.c)
 * is a view of it, one
 * source of truth: read, the L3NM exported (l3nm_mef.c); written, the
 * document imported into the L3NM kept and run as RESTCONF's PUT of it,
 * checked as one.  The document's version is the datastore's, kept
 * beside the L3NM in l3nm.json: one more at each change, made either
 * way, with its time.  A console that kept sdwan.json before has it
 * imported once, at start (in a cluster, which takes no write while it
 * starts, at its first use), and kept as sdwan-mef.json.
 */

#include <sys/param.h>
#include <sys/file.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <cbl_data.h>
#include <ucl.h>

#include "console.h"
#include "restconf.h"
#include "ymodel.h"
#include "ytrans.h"

#define	L3NM_FILE	"l3nm.json"
#define	L3NM_PATH	"/restconf/data/ietf-l3vpn-ntw:l3vpn-ntw"
#define	L3NM_MEMBER	"ietf-l3vpn-ntw:l3vpn-ntw"
#define	L3NM_URI	"console:l3nm"	/* its entity-tags' */
#define	MEF_FILE	"sdwan.json"	/* the document, before */
#define	MEF_BACKUP	"sdwan-mef.json"
#define	MEF_LOCK	"l3nm.lock"

static pthread_mutex_t	l3nm_lock = PTHREAD_MUTEX_INITIALIZER;

/* Whether path is below the L3NM's top-level node. */
bool
l3nm_path(const char *path)
{
	size_t	n = sizeof(L3NM_PATH) - 1;

	return (strncmp(path, L3NM_PATH, n) == 0 && (path[n] == '\0' ||
	    path[n] == '/'));
}

/* A module of the console's own datastore, which no agent has: not
 * ietf-vpn-common, whose identities the agents' SAPs use too. */
bool
l3nm_module(const struct cbl_ymodule *m)
{

	return (strcmp(m->name, "ietf-l3vpn-ntw") == 0 || strcmp(m->name,
	    "arcana-l3nm") == 0 || strcmp(m->name, "ietf-vn") == 0 ||
	    strcmp(m->name, "arcana-sdwan-underlay") == 0 || strcmp(m->name,
	    "arcana-console") == 0);
}

static const struct cbl_ynode *
l3nm_top(void)
{
	const struct cbl_ymodule	*m;

	for (uint32_t i = 0; i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		if (strcmp(m->name, "ietf-l3vpn-ntw") != 0)
			continue;
		for (uint32_t k = 0; k < m->ntop; k++)
			if (strcmp(m->top[k]->name, "l3vpn-ntw") == 0)
				return (m->top[k]);
	}
	return (NULL);
}

/* The tree kept, its strings in a; NULL and why: it cannot be read. */
static cbl_dtree *
l3nm_load(cbl_yarena *a, char *why, size_t len)
{
	const struct cbl_ynode	*n;
	const ucl_object_t	*v;
	ucl_object_t		*o;
	cbl_dtree		*t;

	if ((n = l3nm_top()) == NULL || (t = cbl_dtree_new(&ymodel_schema)) ==
	    NULL) {
		snprintf(why, len, "out of memory");
		return (NULL);
	}
	o = store_load(L3NM_FILE);
	if ((v = ucl_object_lookup(o, L3NM_MEMBER)) != NULL &&
	    yjson_member(t, n, v, a, why, len) != 0) {
		thread_log(LOG_ERR, "%s: %s", L3NM_FILE, why);
		cbl_dtree_free(t);
		t = NULL;
	}
	ucl_object_unref(o);
	return (t);
}

/* Tree t as RFC 7951's JSON, {"ietf-l3vpn-ntw:l3vpn-ntw": ...}; NULL
 * when it cannot be made. */
static ucl_object_t *
tree_json(const cbl_dtree *t)
{
	struct cbl_ybuf		 b = { NULL, 0, 0 };
	struct ucl_parser	*p;
	ucl_object_t		*o = NULL;

	if (cbl_dtree_json(t, &b) == 0) {
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		if (ucl_parser_add_chunk(p, b.p != NULL ? b.p :
		    (const unsigned char *)"{}", b.p != NULL ? b.len : 2))
			o = ucl_parser_get_object(p);
		ucl_parser_free(p);
	}
	cbl_ybuf_free(&b);
	return (o);
}

/*
 * Tree t kept, as RFC 7951's JSON, its version one more than the kept
 * one's and than floor, with who made it (who, NULL the console's own
 * change), for the audit.  Where tell says, each Security Function
 * Policy whose values it changes a SAN (MEF 138 R31, sen.c): here,
 * where every way the services change meets (the SD-WAN document's
 * PUT, RESTCONF's writes of the L3NM, a SAP's attachment merged), the
 * document before and after compared, who did it and from where in
 * the words of the request the thread runs for.
 */
static int
l3nm_save(const cbl_dtree *t, int64_t floor, const struct principal *who,
    bool tell)
{
	ucl_object_t	*o, *kept, *before, *after;
	int64_t		 v;
	int		 rc;
	char		 words[256], from[80];

	if ((o = tree_json(t)) == NULL)
		return (-1);
	kept = store_load(L3NM_FILE);
	v = ucl_object_toint(ucl_object_lookup(kept, "version"));
	before = tell ? mef_export(ucl_object_lookup(kept, L3NM_MEMBER)) : NULL;
	ucl_object_unref(kept);
	ucl_object_insert_key(o, ucl_object_fromint(MAX(v, floor) + 1),
	    "version", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(time(NULL)), "changed", 0,
	    false);
	if (who != NULL)
		ucl_object_insert_key(o, principal_record(who), "author", 0,
		    false);
	rc = store_save(L3NM_FILE, o);
	if (rc == 0 && tell) {
		after = mef_export(ucl_object_lookup(o, L3NM_MEMBER));
		web_acting_words(words, sizeof(words), from, sizeof(from));
		san_changes(before, after, from, words[0] != '\0' ? words :
		    "the console");
		ucl_object_unref(after);
	}
	if (before != NULL)
		ucl_object_unref(before);
	ucl_object_unref(o);
	return (rc);
}

/* ---- Who may change what ----------------------------------------------- */

#define	ISSUED_SKEW	300	/* s an identity's issued may be from now */

static const ucl_object_t *
entry_by(const ucl_object_t *list, const char *key, const char *v)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;

	while (v != NULL && (e = ucl_object_iterate(list, &it, true)) != NULL)
		if (ucl_str(e, key) != NULL && strcmp(ucl_str(e, key), v) == 0)
			return (e);
	return (NULL);
}

static bool
same(const ucl_object_t *a, const ucl_object_t *b)
{

	if (a == NULL || b == NULL)
		return (a == b);
	return (ucl_object_compare(a, b) == 0);
}

/* o without key, a copy, to compare the rest of it (none: empty). */
static ucl_object_t *
without(const ucl_object_t *o, const char *key)
{
	ucl_object_t	*c;

	if (o == NULL)
		return (ucl_object_typed_new(UCL_OBJECT));
	c = ucl_object_copy(o);
	(void)ucl_object_delete_key(c, key);
	return (c);
}

/* A service's nodes, the edges they are. */
static const ucl_object_t *
nodes_of(const ucl_object_t *svc)
{

	return (ucl_object_lookup(ucl_object_lookup(svc, "vpn-nodes"),
	    "vpn-node"));
}

static void
mark(ucl_object_t *edges, const char *edge)
{

	if (edge != NULL && edge[0] != '\0')
		ucl_object_replace_key(edges, ucl_object_frombool(true), edge, 0,
		    true);
}

/* Every node of svc marked. */
static void
mark_nodes(ucl_object_t *edges, const ucl_object_t *svc)
{
	const ucl_object_t	*n;
	ucl_object_iter_t	 it = NULL;

	while ((n = ucl_object_iterate(nodes_of(svc), &it, true)) != NULL)
		mark(edges, ucl_str(n, "vpn-node-id") != NULL ? ucl_str(n,
		    "vpn-node-id") : ucl_str(n, "ne-id"));
}

/* Every edge of y, of its services and of its SD-WAN document. */
static void
mark_all(ucl_object_t *edges, const ucl_object_t *y, const ucl_object_t *doc)
{
	const ucl_object_t	*s;
	ucl_object_iter_t	 it = NULL;

	while ((s = ucl_object_iterate(ucl_object_lookup(ucl_object_lookup(y,
	    "vpn-services"), "vpn-service"), &it, true)) != NULL)
		mark_nodes(edges, s);
	it = NULL;
	while ((s = ucl_object_iterate(ucl_object_lookup(doc, "edges"), &it,
	    true)) != NULL)
		mark(edges, ucl_str(s, "server"));
}

/*
 * The services' vpn-service list of was and of now, each service a
 * change on every edge it has when more than its nodes changed, else on
 * each node that changed alone.
 */
static void
mark_services(ucl_object_t *edges, const ucl_object_t *was,
    const ucl_object_t *now)
{
	const ucl_object_t	*pair[2] = { was, now }, *s, *o, *n, *m;
	ucl_object_t		*a, *b;
	ucl_object_iter_t	 it, nit;
	int			 k;

	for (k = 0; k < 2; k++) {
		it = NULL;
		while ((s = ucl_object_iterate(ucl_object_lookup(
		    ucl_object_lookup(pair[k], "vpn-services"), "vpn-service"),
		    &it, true)) != NULL) {
			o = entry_by(ucl_object_lookup(ucl_object_lookup(
			    pair[1 - k], "vpn-services"), "vpn-service"),
			    "vpn-id", ucl_str(s, "vpn-id"));
			if (same(s, o))
				continue;
			a = without(s, "vpn-nodes");
			b = o != NULL ? without(o, "vpn-nodes") : NULL;
			if (b == NULL || ucl_object_compare(a, b) != 0) {
				mark_nodes(edges, s);
				if (o != NULL)
					mark_nodes(edges, o);
			} else {
				nit = NULL;
				while ((n = ucl_object_iterate(nodes_of(s), &nit,
				    true)) != NULL) {
					m = entry_by(nodes_of(o), "vpn-node-id",
					    ucl_str(n, "vpn-node-id"));
					if (!same(n, m))
						mark(edges, ucl_str(n,
						    "vpn-node-id"));
				}
			}
			ucl_object_unref(a);
			if (b != NULL)
				ucl_object_unref(b);
		}
	}
}

/*
 * The SD-WAN document's own of was and now (dw, dn, their exports): an
 * edge's entry its edge's, an underlay every edge that has an end point
 * on it, anything else every edge; its services are mark_services()'s.
 */
static void
mark_document(ucl_object_t *edges, const ucl_object_t *dw,
    const ucl_object_t *dn, bool *allp)
{
	const ucl_object_t	*pair[2] = { dw, dn }, *e, *o, *u, *ue;
	ucl_object_iter_t	 it, eit, uit;
	ucl_object_t		*a, *b;
	int			 k;

	for (k = 0; k < 2; k++) {
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(pair[k],
		    "edges"), &it, true)) != NULL) {
			o = entry_by(ucl_object_lookup(pair[1 - k], "edges"),
			    "server", ucl_str(e, "server"));
			if (!same(e, o))
				mark(edges, ucl_str(e, "server"));
		}
		it = NULL;
		while ((u = ucl_object_iterate(ucl_object_lookup(pair[k], "ucs"),
		    &it, true)) != NULL) {
			if (same(u, entry_by(ucl_object_lookup(pair[1 - k],
			    "ucs"), "id", ucl_str(u, "id"))))
				continue;
			eit = NULL;
			while ((e = ucl_object_iterate(ucl_object_lookup(pair[k],
			    "edges"), &eit, true)) != NULL) {
				uit = NULL;
				while ((ue = ucl_object_iterate(ucl_object_lookup(e,
				    "ucs_end_points"), &uit, true)) != NULL)
					if (ucl_str(ue, "ucs") != NULL && strcmp(
					    ucl_str(ue, "ucs"), ucl_str(u, "id")) ==
					    0)
						mark(edges, ucl_str(e, "server"));
			}
		}
	}
	/* The rest of the document: lists, settings, every edge's. */
	a = without(dw, "edges");
	b = without(dn, "edges");
	(void)ucl_object_delete_key(a, "ucs");
	(void)ucl_object_delete_key(b, "ucs");
	(void)ucl_object_delete_key(a, "swvcs");
	(void)ucl_object_delete_key(b, "swvcs");
	if (ucl_object_compare(a, b) != 0)
		*allp = true;
	ucl_object_unref(a);
	ucl_object_unref(b);
}

/*
 * The identities of now's document: one made or changed has an issued
 * of now (ISSUED_SKEW either way) or none, which the console makes, so
 * that no client can have it run out at once; a remote's reauth an hour
 * to a year.  NULL, or what is wrong.
 */
static const char *
identities_ok(const ucl_object_t *dw, const ucl_object_t *dn, char *why,
    size_t len)
{
	const ucl_object_t	*sw, *ep, *r, *id, *ow, *oe, *oi, *v;
	ucl_object_iter_t	 it, eit, iit;
	time_t			 now;
	int64_t			 t;

	now = time(NULL);
	it = NULL;
	while ((sw = ucl_object_iterate(ucl_object_lookup(dn, "swvcs"), &it,
	    true)) != NULL) {
		ow = entry_by(ucl_object_lookup(dw, "swvcs"), "id", ucl_str(sw,
		    "id"));
		eit = NULL;
		while ((ep = ucl_object_iterate(ucl_object_lookup(sw,
		    "end_points"), &eit, true)) != NULL) {
			if ((r = ucl_object_lookup(ep, "remote")) == NULL)
				continue;
			if ((v = ucl_object_lookup(r, "reauth")) != NULL &&
			    (ucl_object_type(v) != UCL_INT || ucl_object_toint(v) <
			    3600 || ucl_object_toint(v) > 366 * 86400)) {
				snprintf(why, len, "end point %s: its remote's "
				    "reauth is an hour to a year", ucl_str(ep,
				    "id"));
				return (why);
			}
			oe = entry_by(ucl_object_lookup(ow, "end_points"), "id",
			    ucl_str(ep, "id"));
			iit = NULL;
			while ((id = ucl_object_iterate(ucl_object_lookup(r,
			    "identities"), &iit, true)) != NULL) {
				if ((v = ucl_object_lookup(id, "issued")) == NULL)
					continue;
				oi = entry_by(ucl_object_lookup(ucl_object_lookup(
				    oe, "remote"), "identities"), "name",
				    ucl_str(id, "name"));
				if (oi != NULL && same(ucl_object_lookup(oi,
				    "issued"), v) && same(ucl_object_lookup(oi,
				    "public_key"), ucl_object_lookup(id,
				    "public_key")))
					continue;
				t = ucl_object_toint(v);
				if (t < now - ISSUED_SKEW || t > now + ISSUED_SKEW) {
					snprintf(why, len, "identity %s: issued is "
					    "when the console issues it, not a "
					    "time a client says", ucl_str(id,
					    "name"));
					return (why);
				}
			}
		}
	}
	return (NULL);
}

/*
 * May p change the L3NM kept from was to now (l3vpn-ntw's values)?
 * Each change at any depth is mapped to the edges it changes (a
 * service's, an end point's, a policy's or a zone's to every edge of
 * its service; a vpn-node's or a site-network-access's to its edge; an
 * edge's entry or an underlay's to theirs; anything else to every
 * edge), and p is to be an operator of each.  The console's own change
 * (p NULL, or the console) is not judged.  Why not into why.
 */
static bool
touch_ok(const struct principal *p, const ucl_object_t *was,
    const ucl_object_t *now, char *why, size_t len)
{
	ucl_object_t		*edges, *dw, *dn, *a, *b;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	char			 who[96], sid[64], jail[64];
	bool			 all, ok;

	if (p == NULL || p->kind == P_CONSOLE)
		return (true);
	if (p->kind == P_NONE) {
		snprintf(why, len, "changed for no one");
		return (false);
	}
	dw = mef_export(was);
	dn = mef_export(now);
	if (identities_ok(dw, dn, why, len) != NULL) {
		ucl_object_unref(dw);
		ucl_object_unref(dn);
		return (false);
	}
	edges = ucl_object_typed_new(UCL_OBJECT);
	all = false;
	mark_services(edges, was, now);
	mark_document(edges, dw, dn, &all);
	/* L3NM's own beside the services and the SD-WAN: every edge's. */
	a = without(was, "vpn-services");
	b = without(now, "vpn-services");
	(void)ucl_object_delete_key(a, "arcana-l3nm:sdwan");
	(void)ucl_object_delete_key(b, "arcana-l3nm:sdwan");
	if (ucl_object_compare(a, b) != 0)
		all = true;
	ucl_object_unref(a);
	ucl_object_unref(b);
	if (all) {
		mark_all(edges, was, dw);
		mark_all(edges, now, dn);
	}
	ok = true;
	it = NULL;
	while (ok && (e = ucl_object_iterate(edges, &it, true)) != NULL) {
		if (!sdwan_edge_split(ucl_object_key(e), sid, sizeof(sid), jail,
		    sizeof(jail)))
			snprintf(sid, sizeof(sid), "%s", ucl_object_key(e));
		if (!principal_may_now(p, sid, ROLE_OPERATOR)) {
			snprintf(why, len, "edge %s: host %s, which the change "
			    "reaches, is not yours to change (%s)",
			    ucl_object_key(e), sid, principal_who(p, who,
			    sizeof(who)));
			ok = false;
		}
	}
	ucl_object_unref(edges);
	ucl_object_unref(dw);
	ucl_object_unref(dn);
	return (ok);
}

/* Whom this thread changes the L3NM for; NULL for the console. */
static const struct principal *
writer(struct principal *p)
{

	hosts_acting(p);
	return (p->kind == P_CONSOLE ? NULL : p);
}

/* /restconf/data's: the L3NM kept, its top-level node into top, where
 * the user may read it. */
void
l3nm_into(struct http_request *req, ucl_object_t *top)
{
	ucl_object_t		*o;
	const ucl_object_t	*v;
	char			 why[300];

	if (req_may_path(req, L3NM_PATH, false, NULL, why, sizeof(why)) != 0)
		return;
	pthread_mutex_lock(&l3nm_lock);
	o = store_load(L3NM_FILE);
	pthread_mutex_unlock(&l3nm_lock);
	if ((v = ucl_object_lookup(o, L3NM_MEMBER)) != NULL)
		ucl_object_insert_key(top, ucl_object_copy(v), L3NM_MEMBER, 0,
		    false);
	ucl_object_unref(o);
}

static int
reply(struct http_request *req, struct rcreq *r, int status, char *json)
{

	http_response_header(req, "content-type", "application/yang-data+json");
	http_response_header(req, "cache-control", "no-store");
	http_response_header(req, "x-content-type-options", "nosniff");
	restconf_headers(req, r, L3NM_URI, status);
	http_response(req, status, json, strlen(json));
	free(json);
	return (WEB_OK);
}

int
api_l3nm(struct http_request *req)
{
	struct rcreq		*r;
	struct principal	 p;
	ucl_object_t		*body = NULL, *was, *now;
	cbl_dtree		*t;
	cbl_yarena		*a;
	const char		*why = NULL, *ctype = NULL;
	char			 err[256], refused[400], *json = NULL;
	bool			 changed;
	int			 st, status;

	if (!guard(req, req->method != HTTP_METHOD_GET))
		return (WEB_OK);
	if (req->method != HTTP_METHOD_GET && req->method !=
	    HTTP_METHOD_DELETE) {
		body = read_json(req);
		if (body == NULL && req->http_body != NULL &&
		    req->http_body->length > 0)
			return (restconf_error_tag(req, 400,
			    "malformed-message", "the body is not JSON"));
	}
	(void)http_request_header(req, "content-type", &ctype);
	if ((r = restconf_parse_own(req->path, req->query_string, &why)) ==
	    NULL) {
		ucl_object_unref(body);
		return (restconf_error(req, 400, why));
	}
	if ((st = restconf_prepare(r, req->method, ctype, body, &why)) == 0)
		st = restconf_precondition(req, r, L3NM_URI);
	if (st != 0) {
		(void)restconf_refuse(req, r, L3NM_URI, st, why);
		restconf_free(r);
		return (WEB_OK);
	}
	if ((a = cbl_yarena_new()) == NULL) {
		restconf_free(r);
		return (restconf_error(req, 500, "out of memory"));
	}
	pthread_mutex_lock(&l3nm_lock);
	if ((t = l3nm_load(a, err, sizeof(err))) == NULL) {
		pthread_mutex_unlock(&l3nm_lock);
		cbl_yarena_free(a);
		restconf_free(r);
		return (restconf_error(req, 500, "the services kept could not "
		    "be read"));
	}
	restconf_run_own(r, t, a, &changed, &json, &status);
	/* Each edge the change reaches, at any depth, the writer's to
	 * change (touch_ok()). */
	if (changed) {
		was = store_load(L3NM_FILE);
		now = tree_json(t);
		if (now == NULL || !touch_ok(writer(&p), ucl_object_lookup(was,
		    L3NM_MEMBER), ucl_object_lookup(now, L3NM_MEMBER), refused,
		    sizeof(refused))) {
			free(json);
			json = restconf_errors(now == NULL ? 500 : 403, now ==
			    NULL ? "out of memory" : refused);
			status = now == NULL ? 500 : 403;
			changed = false;
		}
		if (was != NULL)
			ucl_object_unref(was);
		if (now != NULL)
			ucl_object_unref(now);
	}
	if (changed && l3nm_save(t, 0, writer(&p), true) != 0) {
		free(json);
		json = restconf_errors(500, "the services could not be kept");
		status = 500;
		changed = false;
	}
	if (changed)
		restconf_own_changed(L3NM_URI);
	pthread_mutex_unlock(&l3nm_lock);
	cbl_dtree_free(t);
	cbl_yarena_free(a);
	if (changed)
		audit_add("policies-changed", "Administer", "the services as "
		    "L3NM", "a change of RFC 9182's model, checked first",
		    "the console (the Policy Administration Point)",
		    session_who(req), "%s %s", req->method == HTTP_METHOD_POST ?
		    "POST" : req->method == HTTP_METHOD_PUT ? "PUT" :
		    req->method == HTTP_METHOD_PATCH ? "PATCH" : "DELETE",
		    req->path);
	if (json == NULL)
		json = restconf_errors(500, "out of memory");
	st = reply(req, r, status, json);
	restconf_free(r);
	return (st);
}

/* ---- The SD-WAN document, a view of it -------------------------------- */

/* The first error's message of restconf_errors()'s JSON, into why. */
static void
error_of(const char *json, char *why, size_t len)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	const ucl_object_t	*e;
	const char		*m, *at;

	snprintf(why, len, "the services as L3NM were refused");
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
	if (json != NULL && ucl_parser_add_string(p, json, 0) &&
	    (o = ucl_parser_get_object(p)) != NULL) {
		e = ucl_array_find_index(ucl_object_lookup_path(o,
		    "ietf-restconf:errors.error"), 0);
		m = ucl_str(e, "error-message");
		at = ucl_str(e, "error-path");
		if (m != NULL)
			snprintf(why, len, "as L3NM: %s%s%s", at != NULL ? at :
			    "", at != NULL ? ": " : "", m);
		ucl_object_unref(o);
	}
	ucl_parser_free(p);
}

/*
 * Document doc imported into the L3NM kept, run as a PUT of it, for who
 * (NULL: the console's own), each edge it changes theirs (touch_ok()):
 * 0, or the HTTP status and why.  expect, unless -1, the version it was
 * made from; floor, the least the version kept is before it; tell,
 * whether its changes of the function policies are SANs (not for the
 * import of a document kept before).  Under the lock.
 */
static int
put_doc(const ucl_object_t *doc, int64_t expect, int64_t floor,
    const struct principal *who, bool tell, char *why, size_t len)
{
	struct rcreq	*r;
	ucl_object_t	*o, *y, *body, *now;
	cbl_dtree	*t;
	cbl_yarena	*a;
	const char	*w = NULL;
	char		 err[256], *json = NULL;
	int64_t		 have;
	bool		 changed;
	int		 status;

	o = store_load(L3NM_FILE);
	have = ucl_object_toint(ucl_object_lookup(o, "version"));
	if (expect != -1 && expect != have) {
		ucl_object_unref(o);
		snprintf(why, len, "it was changed since: version %jd, not %jd",
		    (intmax_t)have, (intmax_t)expect);
		return (409);
	}
	y = ucl_object_lookup(o, L3NM_MEMBER) != NULL ? ucl_object_copy(
	    ucl_object_lookup(o, L3NM_MEMBER)) : ucl_object_typed_new(
	    UCL_OBJECT);
	mef_import(doc, y);
	body = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(body, y, L3NM_MEMBER, 0, false);
	if ((r = restconf_parse_own(L3NM_PATH, NULL, &w)) == NULL) {
		ucl_object_unref(o);
		ucl_object_unref(body);
		snprintf(why, len, "%s", w != NULL ? w : "out of memory");
		return (500);
	}
	if ((status = restconf_prepare(r, HTTP_METHOD_PUT,
	    "application/yang-data+json", body, &w)) != 0) {
		snprintf(why, len, "as L3NM: %s", w != NULL ? w : "refused");
		ucl_object_unref(o);
		restconf_free(r);
		return (status >= 500 ? 500 : 400);
	}
	t = NULL;
	if ((a = cbl_yarena_new()) == NULL || (t = l3nm_load(a, err,
	    sizeof(err))) == NULL) {
		if (a != NULL)
			cbl_yarena_free(a);
		ucl_object_unref(o);
		restconf_free(r);
		snprintf(why, len, "the services kept could not be read");
		return (500);
	}
	restconf_run_own(r, t, a, &changed, &json, &status);
	/* Judged as kept, both sides RESTCONF's own JSON of it. */
	now = status < 300 ? tree_json(t) : NULL;
	if (status >= 300) {
		error_of(json, why, len);
		status = status >= 500 ? 500 : 400;
	} else if (now == NULL) {
		snprintf(why, len, "out of memory");
		status = 500;
	} else if (!touch_ok(who, ucl_object_lookup(o, L3NM_MEMBER),
	    ucl_object_lookup(now, L3NM_MEMBER), why, len))
		status = 403;
	else if (l3nm_save(t, floor, who, tell) != 0) {
		snprintf(why, len, "the services could not be kept");
		status = 500;
	} else {
		restconf_own_changed(L3NM_URI);
		status = 0;
	}
	if (now != NULL)
		ucl_object_unref(now);
	ucl_object_unref(o);
	free(json);
	cbl_dtree_free(t);
	cbl_yarena_free(a);
	restconf_free(r);
	return (status);
}

/*
 * The document a console kept before, imported once, its version kept,
 * then kept as MEF_BACKUP and taken away.  When the L3NM has an SD-WAN
 * already (another node of the cluster imported it), kept and taken
 * away alone.
 */
void
l3nm_sdwan_migrate(void)
{
	ucl_object_t	*old, *o;
	char		 path[MAXPATHLEN], why[300];
	int		 fd, rc;
	bool		 done;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, MEF_FILE);
	if (access(path, F_OK) == -1)
		return;
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, MEF_LOCK);
	if ((fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600)) == -1)
		return;
	(void)flock(fd, LOCK_EX);
	pthread_mutex_lock(&l3nm_lock);
	if ((old = store_load(MEF_FILE)) == NULL) {
		pthread_mutex_unlock(&l3nm_lock);
		close(fd);
		return;
	}
	o = store_load(L3NM_FILE);
	done = mef_has_sdwan(ucl_object_lookup(o, L3NM_MEMBER));
	ucl_object_unref(o);
	rc = done ? 0 : put_doc(old, -1, ucl_object_toint(ucl_object_lookup(
	    old, "version")) - 1, NULL, false, why, sizeof(why));
	if (rc == 0 && store_save(MEF_BACKUP, old) == 0 &&
	    store_remove(MEF_FILE) == 0)
		thread_log(LOG_NOTICE, "%s: %s as L3NM, kept as %s", MEF_FILE,
		    done ? "imported before" : "imported", MEF_BACKUP);
	else if (rc != 0 && !cluster_on())
		thread_log(LOG_ERR, "%s: not imported as L3NM: %s", MEF_FILE,
		    why);
	pthread_mutex_unlock(&l3nm_lock);
	ucl_object_unref(old);
	close(fd);
}

/* The SD-WAN document: the L3NM kept, exported, with its version. */
ucl_object_t *
l3nm_sdwan(void)
{
	ucl_object_t		*o, *doc;
	const ucl_object_t	*v;

	l3nm_sdwan_migrate();
	pthread_mutex_lock(&l3nm_lock);
	o = store_load(L3NM_FILE);
	pthread_mutex_unlock(&l3nm_lock);
	doc = mef_export(ucl_object_lookup(o, L3NM_MEMBER));
	ucl_object_insert_key(doc, ucl_object_fromint(ucl_object_toint(
	    ucl_object_lookup(o, "version"))), "version", 0, false);
	if ((v = ucl_object_lookup(o, "changed")) != NULL)
		ucl_object_insert_key(doc, ucl_object_copy(v), "changed", 0,
		    false);
	ucl_object_unref(o);
	return (doc);
}

/* The L3NM kept, its l3vpn-ntw (an empty one where none is). */
ucl_object_t *
l3nm_kept(void)
{
	ucl_object_t		*o, *y;
	const ucl_object_t	*v;

	l3nm_sdwan_migrate();
	pthread_mutex_lock(&l3nm_lock);
	o = store_load(L3NM_FILE);
	pthread_mutex_unlock(&l3nm_lock);
	y = (v = ucl_object_lookup(o, L3NM_MEMBER)) != NULL ?
	    ucl_object_copy(v) : ucl_object_typed_new(UCL_OBJECT);
	ucl_object_unref(o);
	return (y);
}

/* y, an l3vpn-ntw's value, merged into the L3NM kept as RESTCONF's
 * PATCH of it, for whom this thread acts for, each edge it changes
 * theirs: 0, or the HTTP status and why. */
int
l3nm_merge(const ucl_object_t *y, char *why, size_t len)
{
	struct rcreq		*r;
	struct principal	 p;
	ucl_object_t		*body, *was, *now;
	cbl_dtree		*t;
	cbl_yarena		*a;
	const char		*w = NULL;
	char			 err[256], *json = NULL;
	bool			 changed;
	int			 status;

	body = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(body, ucl_object_copy(y), L3NM_MEMBER, 0, false);
	if ((r = restconf_parse_own(L3NM_PATH, NULL, &w)) == NULL) {
		ucl_object_unref(body);
		snprintf(why, len, "%s", w != NULL ? w : "out of memory");
		return (500);
	}
	if ((status = restconf_prepare(r, HTTP_METHOD_PATCH,
	    "application/yang-data+json", body, &w)) != 0) {
		snprintf(why, len, "as L3NM: %s", w != NULL ? w : "refused");
		restconf_free(r);
		return (status >= 500 ? 500 : 400);
	}
	l3nm_sdwan_migrate();
	pthread_mutex_lock(&l3nm_lock);
	t = NULL;
	if ((a = cbl_yarena_new()) == NULL || (t = l3nm_load(a, err,
	    sizeof(err))) == NULL) {
		pthread_mutex_unlock(&l3nm_lock);
		if (a != NULL)
			cbl_yarena_free(a);
		restconf_free(r);
		snprintf(why, len, "the services kept could not be read");
		return (500);
	}
	restconf_run_own(r, t, a, &changed, &json, &status);
	was = now = NULL;
	if (status < 300 && changed) {
		was = store_load(L3NM_FILE);
		now = tree_json(t);
	}
	if (status >= 300) {
		error_of(json, why, len);
		status = status >= 500 ? 500 : 400;
	} else if (changed && (now == NULL || !touch_ok(writer(&p),
	    ucl_object_lookup(was, L3NM_MEMBER), ucl_object_lookup(now,
	    L3NM_MEMBER), why, len))) {
		if (now == NULL)
			snprintf(why, len, "out of memory");
		status = now == NULL ? 500 : 403;
	} else if (changed && l3nm_save(t, 0, writer(&p), true) != 0) {
		snprintf(why, len, "the services could not be kept");
		status = 500;
	} else {
		if (changed)
			restconf_own_changed(L3NM_URI);
		status = 0;
	}
	pthread_mutex_unlock(&l3nm_lock);
	if (was != NULL)
		ucl_object_unref(was);
	if (now != NULL)
		ucl_object_unref(now);
	free(json);
	cbl_dtree_free(t);
	cbl_yarena_free(a);
	restconf_free(r);
	return (status);
}

/*
 * Document doc kept, as L3NM, for whom this thread acts for, each edge
 * it changes theirs: 0, or the HTTP status and why (409: not made from
 * version expect, unless that is -1; 403: an edge not theirs).
 */
int
l3nm_sdwan_put(const ucl_object_t *doc, int64_t expect, char *why,
    size_t len)
{
	struct principal	p;
	int			rc;

	l3nm_sdwan_migrate();
	pthread_mutex_lock(&l3nm_lock);
	rc = put_doc(doc, expect, 0, writer(&p), true, why, len);
	pthread_mutex_unlock(&l3nm_lock);
	return (rc);
}
