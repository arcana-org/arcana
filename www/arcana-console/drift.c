/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A host's configuration drift: what it has otherwise than its running
 * configuration says (RFC 8342 section 5.3: intended against
 * operational).  Running and the operational datastore are read a
 * top-level node at a time (one answer of them all went past a
 * message's bound), the state taken out of the latter, and the edit
 * that would make the one the other (cbl_dtree_diff()) is the drift: a
 * node running has that is not in effect, one that differs, and one the
 * host has that running does not, said with its origin (with-origin,
 * section 5.3.4): set by hand since (unknown), learned (DHCP, SLAAC, a
 * neighbour), or the kernel's (system).  A node too large for a message alone is a
 * row of its own (too-large), the rest compared all the same.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_data.h>
#include <cbl_schema.h>
#include <ucl.h>

#include "console.h"
#include "ymodel.h"
#include "ytrans.h"

/* The state taken out of n and below: what running never has. */
static void
prune_state(cbl_dnode *n)
{
	cbl_dnode	*c, *next;

	for (c = cbl_dnode_first(n); c != NULL; c = next) {
		next = cbl_dnode_next(c);
		if ((cbl_dnode_schema(c)->flags & CBL_YNF_CONFIG) == 0)
			(void)cbl_dnode_remove(c);
		else
			prune_state(c);
	}
}

/* The node of tree t that c (of another tree of the schema) is. */
static const cbl_dnode *
same(const cbl_dtree *t, const cbl_dnode *c)
{
	const struct cbl_ynode	*sn = cbl_dnode_schema(c);
	const cbl_dnode		*p, *pr, *k;
	const void		*keys[16];

	p = cbl_dnode_parent(c);
	pr = p == NULL || cbl_dnode_schema(p) == NULL ? cbl_dtree_root(t) :
	    same(t, p);
	if (pr == NULL)
		return (NULL);
	switch (sn->kind) {
	case CBL_YN_LIST:
		if (sn->nkeys == 0 || sn->nkeys > nitems(keys))
			return (NULL);
		for (uint16_t i = 0; i < sn->nkeys; i++) {
			if ((k = cbl_dnode_child(c, sn->child[sn->keys[i]])) ==
			    NULL)
				return (NULL);
			keys[i] = cbl_dnode_value(k);
		}
		return (cbl_dnode_entry(pr, sn, keys));
	case CBL_YN_LEAFLIST:
		return (cbl_dnode_llentry(pr, sn, cbl_dnode_value(c)));
	default:
		return (cbl_dnode_child(pr, sn));
	}
}

/* n's origin: its annotation, or the nearest above it; "" none. */
static const char *
origin_of(const cbl_dnode *n)
{
	static const struct cbl_yannot	*an;
	const void			*v;

	if (an == NULL) {
		for (uint32_t i = 0; an == NULL && i < ymodel_schema.nmod; i++)
			if (strcmp(ymodel_schema.mod[i]->name, "ietf-origin") ==
			    0)
				an = cbl_ymodule_annot(ymodel_schema.mod[i],
				    "origin");
		if (an == NULL)
			return ("");
	}
	for (; n != NULL && cbl_dnode_schema(n) != NULL; n = cbl_dnode_parent(n))
		if ((v = cbl_dnode_meta(n, an)) != NULL) {
			const struct cbl_yident *id = cbl_yschema_ident(
			    &ymodel_schema, *(const uint64_t *)v);

			return (id != NULL ? id->name : "");
		}
	return ("");
}

/* The node of t that c is, as RFC 7951's JSON with the nodes above it;
 * NULL where t has it not. */
static ucl_object_t *
value_of(const cbl_dtree *t, const cbl_dnode *c)
{
	struct cbl_ybuf		 b = { NULL, 0, 0 };
	struct ucl_parser	*p;
	const cbl_dnode		*n;
	cbl_dtree		*sel;
	ucl_object_t		*o = NULL;
	char			*json;

	if ((n = same(t, c)) == NULL ||
	    (sel = cbl_dtree_select(t, &n, 1)) == NULL)
		return (NULL);
	if (cbl_dtree_json(sel, &b) == 0 && (json = strndup((const char *)
	    b.p, b.len)) != NULL) {
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		if (ucl_parser_add_string(p, json, 0))
			o = ucl_parser_get_object(p);
		ucl_parser_free(p);
		free(json);
	}
	cbl_ybuf_free(&b);
	cbl_dtree_free(sel);
	return (o);
}

static ucl_object_t *
row(const char *kind, const cbl_dnode *c, const char *origin,
    ucl_object_t *value, ucl_object_t *was)
{
	struct cbl_ybuf	 b = { NULL, 0, 0 };
	ucl_object_t	*r;

	r = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(r, ucl_object_fromstring(kind), "kind", 0, false);
	if (cbl_dnode_apipath(c, &b) == 0)
		ucl_object_insert_key(r, ucl_object_fromstring_common(
		    (const char *)b.p, b.len, UCL_STRING_RAW), "path", 0, false);
	cbl_ybuf_free(&b);
	if (origin != NULL && origin[0] != '\0')
		ucl_object_insert_key(r, ucl_object_fromstring(origin),
		    "origin", 0, false);
	if (value != NULL)
		ucl_object_insert_key(r, value, "value", 0, false);
	if (was != NULL)
		ucl_object_insert_key(r, was, "was", 0, false);
	return (r);
}

/*
 * The rows of diff d below n: what the edit from the operational
 * configuration (op) to running (run) creates is running's and not in
 * effect; what it merges differs; what it removes the host has beyond
 * running, with its origin.
 */
static void
rows(ucl_object_t *arr, const cbl_dnode *n, const cbl_dtree *op,
    const cbl_dtree *run, int depth)
{
	const cbl_dnode	*c, *o;

	if (depth > 64)
		return;
	for (c = cbl_dnode_first(n); c != NULL; c = cbl_dnode_next(c)) {
		switch (cbl_dnode_op(c)) {
		case CBL_DOP_CREATE:
			ucl_array_append(arr, row("unapplied", c, NULL,
			    value_of(run, c), NULL));
			break;
		case CBL_DOP_MERGE:
		case CBL_DOP_REPLACE:
			o = same(op, c);
			ucl_array_append(arr, row("differs", c, origin_of(o),
			    value_of(run, c), value_of(op, c)));
			break;
		case CBL_DOP_REMOVE:
		case CBL_DOP_DELETE:
			o = same(op, c);
			ucl_array_append(arr, row("extra", c, origin_of(o),
			    value_of(op, c), NULL));
			break;
		default:
			rows(arr, c, op, run, depth + 1);
		}
	}
}

/*
 * Top-level node t of datastore ds into *tp, alone: a request of its
 * own, as a whole host's GET asks (restconf.c's host_ask()), since the
 * host's answer of them all went past a message's bound.  What the host
 * has not of it is an empty tree; 1 where the user may not read it or
 * the host has no such model (the node left out), 0, or an errno.
 */
static int
node_get(cbl_conn *conn, const struct cbl_ynode *t, int ds, bool origin,
    cbl_dtree **tp, ucl_object_t **warnings, char *err, size_t errlen)
{
	uint64_t	errsid;
	int		error;

	error = ytrans_get_tree_warn(conn, &t, 1, ds, origin, tp, warnings,
	    err, errlen, &errsid);
	if (error == ENOENT) {
		err[0] = '\0';
		if ((*tp = cbl_dtree_new(&ymodel_schema)) == NULL)
			return (ENOMEM);
		return (0);
	}
	if (error == EACCES || error == EPERM || error == EOPNOTSUPP) {
		err[0] = '\0';
		return (1);
	}
	return (error);
}

/* A row of a node too large for a message alone: its path and why. */
static ucl_object_t *
too_large(const char *module, const struct cbl_ynode *t)
{
	ucl_object_t	*r;
	char		 path[256], why[256];

	snprintf(path, sizeof(path), "/%s:%s", module, t->name);
	snprintf(why, sizeof(why), "the host's %s:%s alone is larger than a "
	    "message from the host (%d MiB): not compared", module, t->name,
	    CBLINK_MAX_FRAME / (1024 * 1024));
	r = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(r, ucl_object_fromstring("too-large"), "kind",
	    0, false);
	ucl_object_insert_key(r, ucl_object_fromstring(path), "path", 0,
	    false);
	ucl_object_insert_key(r, ucl_object_fromstring(why), "error", 0,
	    false);
	return (r);
}

/*
 * The drift of top-level node t (of module) into arr: the operational
 * configuration and running, each asked alone.  A node either is too
 * large for is a row saying so; 0, or an errno of the connection.
 */
static int
node_drift(cbl_conn *conn, const char *module, const struct cbl_ynode *t,
    ucl_object_t *arr, ucl_object_t **warnings, char *err, size_t errlen)
{
	cbl_dtree	*op = NULL, *run = NULL, *d;
	int		 error;

	if ((error = node_get(conn, t, CBL_YDS_OPERATIONAL, true, &op,
	    warnings, err, errlen)) == 0)
		error = node_get(conn, t, CBL_YDS_RUNNING, false, &run,
		    warnings, err, errlen);
	if (error == EMSGSIZE) {
		ucl_array_append(arr, too_large(module, t));
		err[0] = '\0';
		error = 0;
		goto out;
	}
	if (error != 0) {
		/* Left out: not the user's to read, or no such model. */
		if (error == 1)
			error = 0;
		goto out;
	}
	prune_state(cbl_dtree_root(op));
	if ((d = cbl_dtree_diff(op, run)) == NULL) {
		error = errno != 0 ? errno : ENOMEM;
		snprintf(err, errlen, "%s", strerror(error));
		goto out;
	}
	rows(arr, cbl_dtree_root(d), op, run, 0);
	cbl_dtree_free(d);
out:
	cbl_dtree_free(op);
	cbl_dtree_free(run);
	return (error);
}

int
drift_read(cbl_conn *conn, ucl_object_t **out, ucl_object_t **warnings,
    char *err, size_t errlen)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*t;
	ucl_object_t			*arr;
	int				 error = 0;

	*out = NULL;
	*warnings = NULL;
	arr = ucl_object_typed_new(UCL_ARRAY);
	/* The top-level nodes that are configuration: what running has;
	 * none of the console's own datastore, nor the SAP network, which
	 * an agent has as state alone (RFC 9408, its running none).  Each
	 * asked alone. */
	for (uint32_t i = 0; error == 0 && i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		if (l3nm_module(m) || strcmp(m->name, "ietf-network") == 0)
			continue;
		for (uint32_t k = 0; error == 0 && k < m->ntop; k++) {
			t = m->top[k];
			if ((t->kind == CBL_YN_CONTAINER || t->kind ==
			    CBL_YN_LIST) && (t->flags & CBL_YNF_CONFIG) != 0)
				error = node_drift(conn, m->name, t, arr,
				    warnings, err, errlen);
		}
	}
	if (error != 0) {
		ucl_object_unref(arr);
		if (*warnings != NULL)
			ucl_object_unref(*warnings);
		*warnings = NULL;
		return (error);
	}
	*out = arr;
	return (0);
}
