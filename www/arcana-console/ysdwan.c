/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * An SD-WAN edge through arcana-sdwan (PLAN-SDN-YANG 3.1.12), for the
 * console and arcanactl.  What the console's apply makes for an edge
 * (sdwan_edge.c), the JSON the sdwan-rules, -steer, -bird, -dhcp,
 * -dns, -proxy and -ids operations took, is put in the candidate as
 * the module has it, running's sdwan with that part of that edge in
 * place of its own, by an EDIT of RFC 7951's JSON (yjsonin.c); the
 * caller commits.  The sdwan read's JSON, which the SD-WAN and
 * Security pages and the apply read, is made of the module's state
 * and arcana-probe's, in the operation's shape.
 */

#include <sys/param.h>

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

#include "ymodel.h"
#include "yqueue.h"
#include "yjsonin.h"
#include "ysdwan.h"

#define	SEC_PREFIX	"sec-"

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	(void)ucl_object_delete_key(o, key);
	ucl_object_insert_key(o, v, key, 0, true);
}

static void
put_str(ucl_object_t *o, const char *key, const char *s)
{

	if (s != NULL)
		put(o, key, ucl_object_fromstring(s));
}

static const char *
str(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	v = ucl_object_lookup(o, key);
	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : NULL);
}

static ucl_object_t *
parse(const char *json)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	return (o);
}

/* A jail's name as the agent takes one: letters, digits and _ . -. */
static bool
jail_ok(const char *s)
{

	if (s[0] == '\0' || s[0] == '.' || s[0] == '-' || strstr(s, "..") !=
	    NULL || strlen(s) > 63)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("_.-", *s) == NULL)
			return (false);
	return (true);
}

static bool
is_sec(const char *name)
{

	return (name != NULL && strncmp(name, SEC_PREFIX, strlen(SEC_PREFIX))
	    == 0);
}

/* ---- The operations' JSON as the module's --------------------------- */

/* A value of o's copied into m under key, where o has it. */
static void
copy(ucl_object_t *m, const char *key, const ucl_object_t *o,
    const char *from)
{
	const ucl_object_t	*v;

	if ((v = ucl_object_lookup(o, from)) != NULL && ucl_object_type(v) !=
	    UCL_NULL)
		put(m, key, ucl_object_copy(v));
}

/* The IDS' form: a JSON object made its text; text as it is. */
static void
spec_put(ucl_object_t *m, const ucl_object_t *o)
{
	const ucl_object_t	*v;
	unsigned char		*t;

	if ((v = ucl_object_lookup(o, "spec")) == NULL)
		return;
	if (ucl_object_type(v) == UCL_STRING)
		put_str(m, "spec", ucl_object_tostring(v));
	else if (ucl_object_type(v) == UCL_OBJECT && (t = ucl_object_emit(v,
	    UCL_EMIT_JSON_COMPACT)) != NULL) {
		put_str(m, "spec", (const char *)t);
		free(t);
	}
}

/*
 * A form (spec) as arcana-sdwan's container of its kind says it, from
 * what the console made of the document: each member named as a node of
 * n (a _ where the node has a -), its value of the node's kind (a
 * number, a flag, a text); a list's entries, one object alone an entry,
 * those without their keys or twice left out, a list keyed by its index
 * alone numbering its entries; a leaf-list's values each once, a pair
 * [as, value] (a community as the document writes it) made as:value;
 * a presence container said true there; what the module has not left
 * out (the document's own words, as a PDNS entry's encryption).
 */
#define	FORM_DEPTH	16

static void	put_list(ucl_object_t *, const char *, ucl_object_t *);

static const ucl_object_t *
form_member(const ucl_object_t *o, const char *name)
{
	const ucl_object_t	*v;
	char			 alt[64], *c;

	if ((v = ucl_object_lookup(o, name)) != NULL || strchr(name, '-') ==
	    NULL)
		return (v);
	snprintf(alt, sizeof(alt), "%s", name);
	for (c = alt; *c != '\0'; c++)
		if (*c == '-')
			*c = '_';
	return (ucl_object_lookup(o, alt));
}

/* A scalar as leaf n's kind has it in RFC 7951's JSON; NULL: none. */
static ucl_object_t *
form_scalar(const struct cbl_ynode *n, const ucl_object_t *v)
{
	char	 buf[48];
	int	 k = n->type->kind;

	if (ucl_object_type(v) == UCL_ARRAY && ucl_array_size(v) == 2 &&
	    ucl_object_type(ucl_array_find_index(v, 0)) == UCL_INT &&
	    ucl_object_type(ucl_array_find_index(v, 1)) == UCL_INT) {
		snprintf(buf, sizeof(buf), "%jd:%jd", (intmax_t)
		    ucl_object_toint(ucl_array_find_index(v, 0)), (intmax_t)
		    ucl_object_toint(ucl_array_find_index(v, 1)));
		return (ucl_object_fromstring(buf));
	}
	if (ucl_object_type(v) == UCL_OBJECT || ucl_object_type(v) ==
	    UCL_ARRAY || ucl_object_type(v) == UCL_NULL)
		return (NULL);
	if (k == CBL_YT_BOOLEAN)
		return (ucl_object_type(v) == UCL_BOOLEAN ? ucl_object_copy(v) :
		    NULL);
	if ((k == CBL_YT_INT8 || k == CBL_YT_INT16 || k == CBL_YT_INT32 ||
	    k == CBL_YT_UINT8 || k == CBL_YT_UINT16 || k == CBL_YT_UINT32) &&
	    ucl_object_type(v) == UCL_INT)
		return (ucl_object_copy(v));
	return (ucl_object_fromstring(ucl_object_tostring_forced(v)));
}

static ucl_object_t	*form_object(const struct cbl_ynode *,
			    const ucl_object_t *, int);

/* A list's entries: each with its keys, once; one object alone an
 * entry, a word alone the entry of a list keyed by one leaf. */
static ucl_object_t *
form_list(const struct cbl_ynode *n, const ucl_object_t *v, int depth)
{
	const struct cbl_ynode	*kn;
	const ucl_object_t	*e, *kv;
	ucl_object_iter_t	 it;
	ucl_object_t		*arr, *seen, *o, *all, *w;
	char			 key[512];
	int			 i;
	bool			 index, ok;

	arr = ucl_object_typed_new(UCL_ARRAY);
	if (n->nkeys == 0)
		return (arr);
	all = ucl_object_typed_new(UCL_ARRAY);
	if (ucl_object_type(v) == UCL_OBJECT)
		ucl_array_append(all, ucl_object_copy(v));
	it = NULL;
	while (ucl_object_type(v) == UCL_ARRAY && (e = ucl_object_iterate(v,
	    &it, true)) != NULL) {
		if (ucl_object_type(e) == UCL_OBJECT)
			ucl_array_append(all, ucl_object_copy(e));
		else if (n->nkeys == 1 && ucl_object_type(e) != UCL_ARRAY &&
		    ucl_object_type(e) != UCL_NULL) {
			w = ucl_object_typed_new(UCL_OBJECT);
			put(w, n->child[n->keys[0]]->name, ucl_object_copy(e));
			ucl_array_append(all, w);
		}
	}
	seen = ucl_object_typed_new(UCL_OBJECT);
	index = n->nkeys == 1 && strcmp(n->child[n->keys[0]]->name, "index") ==
	    0;
	i = 0;
	it = NULL;
	while ((e = ucl_object_iterate(all, &it, true)) != NULL) {
		if ((o = form_object(n, e, depth + 1)) == NULL)
			continue;
		if (index && ucl_object_lookup(o, "index") == NULL)
			put(o, "index", ucl_object_fromint(i));
		i++;
		key[0] = '\0';
		ok = true;
		for (uint16_t k = 0; ok && k < n->nkeys; k++) {
			kn = n->child[n->keys[k]];
			if ((kv = ucl_object_lookup(o, kn->name)) == NULL)
				ok = false;
			else
				snprintf(key + strlen(key), sizeof(key) -
				    strlen(key), "%s\x1f",
				    ucl_object_tostring_forced(kv));
		}
		if (!ok || ucl_object_lookup(seen, key) != NULL) {
			ucl_object_unref(o);
			continue;
		}
		ucl_object_insert_key(seen, ucl_object_frombool(true), key, 0,
		    true);
		ucl_array_append(arr, o);
	}
	ucl_object_unref(seen);
	ucl_object_unref(all);
	return (arr);
}

/* Container or list entry n's members of o; NULL past the depth. */
static ucl_object_t *
form_object(const struct cbl_ynode *n, const ucl_object_t *o, int depth)
{
	const struct cbl_ynode	*c;
	const ucl_object_t	*v, *e;
	ucl_object_iter_t	 it;
	ucl_object_t		*m, *x, *arr, *seen;

	if (depth > FORM_DEPTH)
		return (NULL);
	m = ucl_object_typed_new(UCL_OBJECT);
	for (uint32_t i = 0; i < n->nchild; i++) {
		c = n->child[i];
		if ((c->flags & CBL_YNF_CONFIG) == 0 || (v = form_member(o,
		    c->name)) == NULL)
			continue;
		switch (c->kind) {
		case CBL_YN_LEAF:
			if ((x = form_scalar(c, v)) != NULL)
				put(m, c->name, x);
			break;
		case CBL_YN_LEAFLIST:
			arr = ucl_object_typed_new(UCL_ARRAY);
			seen = ucl_object_typed_new(UCL_OBJECT);
			it = NULL;
			while (ucl_object_type(v) == UCL_ARRAY && (e =
			    ucl_object_iterate(v, &it, true)) != NULL) {
				if ((x = form_scalar(c, e)) == NULL)
					continue;
				if (ucl_object_lookup(seen,
				    ucl_object_tostring_forced(x)) != NULL) {
					ucl_object_unref(x);
					continue;
				}
				ucl_object_insert_key(seen, ucl_object_frombool(
				    true), ucl_object_tostring_forced(x), 0, true);
				ucl_array_append(arr, x);
			}
			ucl_object_unref(seen);
			put_list(m, c->name, arr);
			break;
		case CBL_YN_CONTAINER:
			if (ucl_object_type(v) == UCL_BOOLEAN &&
			    ucl_object_toboolean(v) && (c->flags &
			    CBL_YNF_PRESENCE) != 0)
				put(m, c->name, ucl_object_typed_new(UCL_OBJECT));
			else if (ucl_object_type(v) == UCL_OBJECT && (x =
			    form_object(c, v, depth + 1)) != NULL) {
				if (x->len > 0 || (c->flags & CBL_YNF_PRESENCE) != 0)
					put(m, c->name, x);
				else
					ucl_object_unref(x);
			}
			break;
		case CBL_YN_LIST:
			put_list(m, c->name, form_list(c, v, depth));
			break;
		default:
			break;
		}
	}
	return (m);
}

/* in's form, of instances of kind (the list key names), into m. */
static void
form_put(ucl_object_t *m, const char *key, const ucl_object_t *in)
{
	const struct cbl_ynode	*n;
	const ucl_object_t	*v;
	ucl_object_t		*f;

	if ((v = ucl_object_lookup(in, "spec")) == NULL || (n = yq_child(
	    yq_child(yq_top("arcana-sdwan", "sdwan"), key), "spec")) == NULL)
		return;
	if (ucl_object_type(v) == UCL_STRING) {
		/* Text: as an object, where it is one. */
		if ((v = parse(ucl_object_tostring(v))) == NULL)
			return;
		f = form_object(n, v, 0);
		ucl_object_unref((ucl_object_t *)(uintptr_t)v);
	} else if (ucl_object_type(v) == UCL_OBJECT)
		f = form_object(n, v, 0);
	else
		return;
	if (f != NULL)
		put(m, "spec", f);
}

/* An object of names to texts as a list of name and text. */
static ucl_object_t *
named(const ucl_object_t *o)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	ucl_object_t		*arr, *e;

	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while (o != NULL && ucl_object_type(o) == UCL_OBJECT && (v =
	    ucl_object_iterate(o, &it, true)) != NULL) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put_str(e, "name", ucl_object_key(v));
		put_str(e, "text", ucl_object_tostring_forced(v));
		ucl_array_append(arr, e);
	}
	return (arr);
}

/* A list put where it has entries, taken away where it has none. */
static void
put_list(ucl_object_t *m, const char *key, ucl_object_t *arr)
{

	if (ucl_array_size(arr) > 0)
		put(m, key, arr);
	else {
		(void)ucl_object_delete_key(m, key);
		ucl_object_unref(arr);
	}
}

/*
 * What is not as it should be is passed on as it is, for the module to
 * refuse: a missing key, a word where a number goes.  An entry whose
 * keys came already is left out: a table's prefix, a table and prefix
 * of the steering, a candidate's id, a route's destination, once.
 */

/* Whether arr has an entry whose key members are o's, all strings. */
static bool
seen(const ucl_object_t *arr, const ucl_object_t *o, const char *k1,
    const char *k2)
{
	const ucl_object_t	*x, *a, *b;
	ucl_object_iter_t	 it;

	if ((a = ucl_object_lookup(o, k1)) == NULL || (k2 != NULL &&
	    ucl_object_lookup(o, k2) == NULL))
		return (false);
	it = NULL;
	while ((x = ucl_object_iterate(arr, &it, true)) != NULL) {
		if ((b = ucl_object_lookup(x, k1)) == NULL || strcmp(
		    ucl_object_tostring_forced(a), ucl_object_tostring_forced(b))
		    != 0)
			continue;
		if (k2 == NULL)
			return (true);
		if ((b = ucl_object_lookup(x, k2)) != NULL && strcmp(
		    ucl_object_tostring_forced(ucl_object_lookup(o, k2)),
		    ucl_object_tostring_forced(b)) == 0)
			return (true);
	}
	return (false);
}

/* The rules: set, tables (their entries one a prefix), objects, and the
 * rules in their order. */
static ucl_object_t *
rules_of(const ucl_object_t *in)
{
	const ucl_object_t	*t, *e, *p, *q;
	ucl_object_iter_t	 it, eit;
	ucl_object_t		*m, *tabs, *tab, *ents, *ent, *arr, *r;
	uint32_t		 idx;

	m = ucl_object_typed_new(UCL_OBJECT);
	copy(m, "set", in, "set");
	tabs = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((t = ucl_object_iterate(ucl_object_lookup(in, "tables"), &it,
	    true)) != NULL) {
		tab = ucl_object_typed_new(UCL_OBJECT);
		copy(tab, "name", t, "name");
		copy(tab, "valtype", t, "valtype");
		ents = ucl_object_typed_new(UCL_ARRAY);
		eit = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(t, "entries"),
		    &eit, true)) != NULL) {
			if (ucl_object_type(e) == UCL_ARRAY) {
				p = ucl_array_find_index(e, 0);
				q = ucl_array_find_index(e, 1);
			} else {
				p = ucl_object_lookup(e, "prefix");
				q = ucl_object_lookup(e, "value");
			}
			ent = ucl_object_typed_new(UCL_OBJECT);
			if (p != NULL)
				put_str(ent, "prefix",
				    ucl_object_tostring_forced(p));
			if (q != NULL)
				put_str(ent, "value",
				    ucl_object_tostring_forced(q));
			if (seen(ents, ent, "prefix", NULL))
				ucl_object_unref(ent);
			else
				ucl_array_append(ents, ent);
		}
		put_list(tab, "entry", ents);
		ucl_array_append(tabs, tab);
	}
	put_list(m, "table", tabs);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((t = ucl_object_iterate(ucl_object_lookup(in, "objects"), &it,
	    true)) != NULL)
		ucl_array_append(arr, ucl_object_copy(t));
	put_list(m, "object", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	idx = 0;
	it = NULL;
	while ((t = ucl_object_iterate(ucl_object_lookup(in, "rules"), &it,
	    true)) != NULL) {
		const char	*s;
		char		*end;
		unsigned long	 num;

		r = ucl_object_typed_new(UCL_OBJECT);
		if (ucl_object_type(t) == UCL_STRING) {
			/* "number words"; without a number, the words. */
			s = ucl_object_tostring(t);
			num = strtoul(s, &end, 10);
			if (end != s)
				put(r, "number", ucl_object_fromint((int64_t)
				    num));
			put_str(r, "text", end + strspn(end, " "));
		} else {
			copy(r, "number", t, ucl_object_lookup(t, "number") !=
			    NULL ? "number" : "num");
			copy(r, "text", t, "text");
		}
		put(r, "index", ucl_object_fromint(idx++));
		ucl_array_append(arr, r);
	}
	put_list(m, "rule", arr);
	/* The services measured by alternate marking, their tunnels. */
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((t = ucl_object_iterate(ucl_object_lookup(in, "altmark"), &it,
	    true)) != NULL) {
		ucl_object_t	*ts, *u;

		r = ucl_object_typed_new(UCL_OBJECT);
		copy(r, "service", t, "service");
		copy(r, "period", t, "period");
		ts = ucl_object_typed_new(UCL_ARRAY);
		eit = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(t, "tunnels"),
		    &eit, true)) != NULL) {
			u = ucl_object_typed_new(UCL_OBJECT);
			copy(u, "id", e, "id");
			copy(u, "interface", e, "interface");
			copy(u, "outer", e, "outer");
			copy(u, "kind", e, "kind");
			copy(u, "port", e, "port");
			copy(u, "ipsec", e, "ipsec");
			ucl_array_append(ts, u);
		}
		put_list(r, "tunnel", ts);
		ucl_array_append(arr, r);
	}
	put_list(m, "alt-marking", arr);
	/* The services whose flows are recorded, their tunnels. */
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((t = ucl_object_iterate(ucl_object_lookup(in, "flowexp"), &it,
	    true)) != NULL) {
		ucl_object_t	*ts, *u;

		r = ucl_object_typed_new(UCL_OBJECT);
		copy(r, "service", t, "service");
		copy(r, "collector", t, "collector");
		copy(r, "port", t, "port");
		copy(r, "sampling", t, "sampling");
		copy(r, "active-timeout", t, "active_timeout");
		copy(r, "inactive-timeout", t, "inactive_timeout");
		ts = ucl_object_typed_new(UCL_ARRAY);
		eit = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(t, "tunnels"),
		    &eit, true)) != NULL) {
			u = ucl_object_typed_new(UCL_OBJECT);
			copy(u, "id", e, "id");
			copy(u, "interface", e, "interface");
			ucl_array_append(ts, u);
		}
		put_list(r, "tunnel", ts);
		ucl_array_append(arr, r);
	}
	put_list(m, "flow-export", arr);
	return (m);
}

/* Candidates: each an id and the address it goes via, in order. */
static ucl_object_t *
candidates_of(const ucl_object_t *cands)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it;
	ucl_object_t		*cs, *cand;

	cs = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((c = ucl_object_iterate(cands, &it, true)) != NULL) {
		cand = ucl_object_typed_new(UCL_OBJECT);
		copy(cand, "id", c, "id");
		copy(cand, "via", c, "via");
		if (seen(cs, cand, "id", NULL))
			ucl_object_unref(cand);
		else
			ucl_array_append(cs, cand);
	}
	return (cs);
}

/* The steering: each table and prefix's candidates, in order, and the
 * breakout's routes. */
static ucl_object_t *
steer_of(const ucl_object_t *in)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*m, *arr, *ent;

	m = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, "entries"), &it,
	    true)) != NULL) {
		ent = ucl_object_typed_new(UCL_OBJECT);
		copy(ent, "table", e, "table");
		copy(ent, "prefix", e, "prefix");
		if (seen(arr, ent, "table", "prefix")) {
			ucl_object_unref(ent);
			continue;
		}
		put_list(ent, "candidate", candidates_of(ucl_object_lookup(e,
		    "candidates")));
		ucl_array_append(arr, ent);
	}
	put_list(m, "entry", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, "routes"), &it,
	    true)) != NULL) {
		ent = ucl_object_typed_new(UCL_OBJECT);
		copy(ent, "fib", e, "fib");
		copy(ent, "destination", e, "destination");
		if (seen(arr, ent, "fib", "destination")) {
			ucl_object_unref(ent);
			continue;
		}
		put_list(ent, "candidate", candidates_of(ucl_object_lookup(e,
		    "candidates")));
		ucl_array_append(arr, ent);
	}
	put_list(m, "route", arr);
	return (m);
}

/* An instance of a kind: BIRD's, dnsmasq's, unbound's alike; Squid's
 * with its mode and lists; Suricata's. */
static ucl_object_t *
instance_of(const char *kind, const ucl_object_t *in)
{
	ucl_object_t	*m, *arr;
	const ucl_object_t *v;
	ucl_object_iter_t it;

	m = ucl_object_typed_new(UCL_OBJECT);
	copy(m, "name", in, "name");
	if (strcmp(kind, "ids") == 0) {
		arr = ucl_object_typed_new(UCL_ARRAY);
		it = NULL;
		while ((v = ucl_object_iterate(ucl_object_lookup(in,
		    "interfaces"), &it, true)) != NULL)
			ucl_array_append(arr, ucl_object_copy(v));
		put_list(m, "interface", arr);
		copy(m, "conf", in, "conf");
		copy(m, "rules", in, "rules");
		copy(m, "divert", in, "divert");
		copy(m, "host", in, "host");
		spec_put(m, in);
		copy(m, "capture", in, "capture");
		copy(m, "offload", in, "offload");
		put_list(m, "lua", named(ucl_object_lookup(in, "lua")));
		arr = ucl_object_typed_new(UCL_ARRAY);
		it = NULL;
		while ((v = ucl_object_iterate(ucl_object_lookup(in, "plugins"),
		    &it, true)) != NULL)
			ucl_array_append(arr, ucl_object_copy(v));
		put_list(m, "plugin", arr);
		copy(m, "stopped", in, "stopped");
		copy(m, "thresholds", in, "thresholds");
		return (m);
	}
	copy(m, "fib", in, "fib");
	copy(m, "host", in, "host");
	form_put(m, strcmp(kind, "bird") == 0 ? "bird-instance" : strcmp(kind,
	    "dhcp") == 0 ? "dhcp-instance" : strcmp(kind, "dns") == 0 ?
	    "dns-instance" : "proxy-instance", in);
	if (strcmp(kind, "proxy") == 0) {
		copy(m, "mode", in, "mode");
		put_list(m, "named-list", named(ucl_object_lookup(in, "lists")));
		copy(m, "stopped", in, "stopped");
	}
	return (m);
}

/*
 * The instances of in, with those of was kept that are not of its group
 * (group -1: none kept), in the agent's order: SD-WAN's, then the
 * Security section's.
 */
static ucl_object_t *
instances_of(const char *kind, const ucl_object_t *in,
    const ucl_object_t *was, int group)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	ucl_object_t		*arr;

	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while (group == 1 && (v = ucl_object_iterate(was, &it, true)) != NULL)
		if (!is_sec(str(v, "name")))
			ucl_array_append(arr, ucl_object_copy(v));
	it = NULL;
	while ((v = ucl_object_iterate(ucl_object_lookup(in, "instances"), &it,
	    true)) != NULL)
		ucl_array_append(arr, instance_of(kind, v));
	it = NULL;
	while (group == 0 && (v = ucl_object_iterate(was, &it, true)) != NULL)
		if (is_sec(str(v, "name")))
			ucl_array_append(arr, ucl_object_copy(v));
	return (arr);
}

/*
 * A number of o's that its leaf (an unsigned integer up to max) cannot
 * hold, said in err: cblink's parser would take it modulo the type's
 * size, not refuse it.
 */
static bool
num_bad(const ucl_object_t *o, const char *key, int64_t max, char *err,
    size_t errlen)
{
	const ucl_object_t	*v;

	if ((v = ucl_object_lookup(o, key)) == NULL || ucl_object_type(v) !=
	    UCL_INT || (ucl_object_toint(v) >= 0 && ucl_object_toint(v) <= max))
		return (false);
	snprintf(err, errlen, "%s: '%jd' is not a value of it", key,
	    (intmax_t)ucl_object_toint(v));
	return (true);
}

/* An instance's texts and flags of the kinds their leaves have: the
 * module's would take a number for a text. */
static bool
kind_bad(const ucl_object_t *o, char *err, size_t errlen)
{
	static const char *const texts[] = { "name", "host", "conf", "rules",
	    "thresholds", "mode", "capture" };
	static const char *const flags[] = { "stopped", "offload" };
	const ucl_object_t	*v;

	for (size_t i = 0; i < nitems(texts); i++)
		if ((v = ucl_object_lookup(o, texts[i])) != NULL &&
		    ucl_object_type(v) != UCL_STRING) {
			snprintf(err, errlen, "%s is a text", texts[i]);
			return (true);
		}
	for (size_t i = 0; i < nitems(flags); i++)
		if ((v = ucl_object_lookup(o, flags[i])) != NULL &&
		    ucl_object_type(v) != UCL_BOOLEAN) {
			snprintf(err, errlen, "%s is true or false", flags[i]);
			return (true);
		}
	return (false);
}

/* in's numbers within their leaves' types, for part k (ysdwan_edit()). */
static bool
nums_bad(size_t k, const ucl_object_t *in, char *err, size_t errlen)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;

	if (k == 0) {
		if (num_bad(in, "set", UINT8_MAX, err, errlen))
			return (true);
		it = NULL;
		while ((v = ucl_object_iterate(ucl_object_lookup(in, "rules"),
		    &it, true)) != NULL) {
			if (num_bad(v, "number", UINT16_MAX, err, errlen))
				return (true);
			if (ucl_object_type(v) == UCL_STRING && strtoul(
			    ucl_object_tostring(v), NULL, 10) > UINT16_MAX) {
				snprintf(err, errlen, "number: '%s' is not a "
				    "rule's", ucl_object_tostring(v));
				return (true);
			}
		}
		return (false);
	}
	it = NULL;
	while ((v = ucl_object_iterate(ucl_object_lookup(in, k == 1 ?
	    "routes" : "instances"), &it, true)) != NULL) {
		if (num_bad(v, "fib", UINT16_MAX, err, errlen) || num_bad(v,
		    "divert", UINT16_MAX, err, errlen))
			return (true);
		if (k > 1 && kind_bad(v, err, errlen))
			return (true);
	}
	return (false);
}

/* arcana-sdwan's sdwan as running has it, RFC 7951's JSON. */
static ucl_object_t *
running(cbl_conn *conn, const struct cbl_ynode *n, char *err, size_t errlen,
    int *errorp)
{
	struct cbl_ybuf		 b = { NULL, 0, 0 };
	struct arcana_sdwan	 d;
	ucl_object_t		*top, *v;
	cbl_yarena		*a;
	cbl_msg			*req, *rep = NULL;
	char			*text;
	bool			 first = true;
	int			 error;

	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_GET, 0, &req)) != 0 || (error = cbl_msg_put_yget(req,
	    &n->sid, 1)) != 0 || (error = cbl_msg_set_datastore(req,
	    CBL_YDS_RUNNING)) != 0) {
		snprintf(err, errlen, "%s", strerror(error));
		*errorp = error;
		return (NULL);
	}
	if ((error = cbl_request(conn, req, &rep, -1)) != 0) {
		snprintf(err, errlen, "%s", rep != NULL && cbl_msg_err_str(rep) !=
		    NULL ? cbl_msg_err_str(rep) : strerror(error));
		cbl_msg_free(rep);
		*errorp = error;
		return (NULL);
	}
	if ((a = cbl_yarena_new()) == NULL)
		error = ENOMEM;
	else {
		memset(&d, 0, sizeof(d));
		if ((error = cbl_msg_ydecode_member(rep, n, &d, a, 0, err,
		    errlen)) == ENOENT)
			error = 0;
		if (error == 0)
			error = cbl_yjson_members(n->module, &d, &b, &first);
	}
	cbl_yarena_free(a);
	cbl_msg_free(rep);
	if (error != 0) {
		cbl_ybuf_free(&b);
		*errorp = error;
		return (NULL);
	}
	if (asprintf(&text, "{%.*s}", (int)b.len, b.p != NULL ? (const char *)
	    b.p : "") == -1) {
		cbl_ybuf_free(&b);
		*errorp = ENOMEM;
		return (NULL);
	}
	cbl_ybuf_free(&b);
	top = parse(text);
	free(text);
	/* None yet: an empty one. */
	if (top == NULL || (v = (ucl_object_t *)(uintptr_t)ucl_object_lookup(
	    top, "arcana-sdwan:sdwan")) == NULL) {
		if (top != NULL)
			ucl_object_unref(top);
		return (ucl_object_typed_new(UCL_OBJECT));
	}
	v = ucl_object_ref(v);
	ucl_object_unref(top);
	return (v);
}

/* Whether an edge that is a jail has anything left: rules (more than
 * their set), steering or BIRD. */
static bool
edge_empty(const ucl_object_t *e)
{
	const ucl_object_t	*r, *s;

	r = ucl_object_lookup(e, "rules");
	s = ucl_object_lookup(e, "steer");
	return ((r == NULL || (ucl_object_lookup(r, "table") == NULL &&
	    ucl_object_lookup(r, "object") == NULL && ucl_object_lookup(r,
	    "rule") == NULL)) && (s == NULL || (ucl_object_lookup(s, "entry") ==
	    NULL && ucl_object_lookup(s, "route") == NULL)) &&
	    ucl_object_lookup(e, "bird-instance") == NULL);
}

static const char *const kinds[] = { "rules", "steer", "bird", "dhcp", "dns",
    "proxy", "ids" };

int
ysdwan_edit(cbl_conn *conn, const char *kind, const char *json, bool *same,
    char *err, size_t errlen, uint64_t *errsid, char *tag, size_t taglen)
{
	const struct cbl_ynode	*n;
	const ucl_object_t	*v, *w;
	ucl_object_iter_t	 it;
	ucl_object_t		*in, *sd, *was, *e, *keep, *jails;
	const char		*jail, *key;
	size_t			 k;
	int			 error = 0, group;

	err[0] = tag[0] = '\0';
	*errsid = 0;
	for (k = 0; k < nitems(kinds) && strcmp(kinds[k], kind) != 0; k++)
		;
	if (k == nitems(kinds)) {
		snprintf(err, errlen, "%s: not a part of an SD-WAN edge", kind);
		return (EINVAL);
	}
	if ((n = yq_top("arcana-sdwan", "sdwan")) == NULL) {
		snprintf(err, errlen, "arcana-sdwan is not in the tables");
		return (ENOENT);
	}
	if ((in = parse(json)) == NULL || ucl_object_type(in) != UCL_OBJECT) {
		if (in != NULL)
			ucl_object_unref(in);
		snprintf(err, errlen, "the %s are a JSON object", kind);
		return (EINVAL);
	}
	jail = str(in, "jail") != NULL && str(in, "jail")[0] != '\0' ?
	    str(in, "jail") : NULL;
	if (jail != NULL && !jail_ok(jail)) {
		ucl_object_unref(in);
		snprintf(err, errlen, "invalid jail name");
		return (EINVAL);
	}
	if (jail != NULL && k > 2) {
		ucl_object_unref(in);
		snprintf(err, errlen, "an edge that is a vnet jail has no %s: "
		    "the host's own edge has", kind);
		return (EINVAL);
	}
	if (nums_bad(k, in, err, errlen)) {
		ucl_object_unref(in);
		return (EINVAL);
	}
	group = str(in, "group") != NULL && strcmp(str(in, "group"),
	    "security") == 0 ? 1 : 0;
	/* The proxies and the IDS of a group: the Security section's named
	 * sec-, SD-WAN's not; the module keeps both in one list. */
	it = NULL;
	while (k >= 5 && (v = ucl_object_iterate(ucl_object_lookup(in,
	    "instances"), &it, true)) != NULL)
		if (str(v, "name") != NULL && is_sec(str(v, "name")) !=
		    (group == 1)) {
			snprintf(err, errlen, "instance %s: the Security "
			    "section's are named " SEC_PREFIX ", SD-WAN's not",
			    str(v, "name"));
			ucl_object_unref(in);
			return (EINVAL);
		}
	if ((sd = running(conn, n, err, errlen, &error)) == NULL) {
		ucl_object_unref(in);
		return (error);
	}
	was = ucl_object_copy(sd);
	/* The edge: the host's, or the jail's entry, made where it is
	 * none. */
	e = sd;
	keep = NULL;
	if (jail != NULL) {
		keep = ucl_object_typed_new(UCL_ARRAY);
		e = NULL;
		it = NULL;
		while ((v = ucl_object_iterate(ucl_object_lookup(sd, "jail"),
		    &it, true)) != NULL) {
			if (e == NULL && (w = ucl_object_lookup(v, "name")) !=
			    NULL && strcmp(ucl_object_tostring(w), jail) == 0)
				e = ucl_object_copy(v);
			else
				ucl_array_append(keep, ucl_object_copy(v));
		}
		if (e == NULL) {
			e = ucl_object_typed_new(UCL_OBJECT);
			put_str(e, "name", jail);
		}
	}
	switch (k) {
	case 0:
		put(e, "rules", rules_of(in));
		break;
	case 1:
		put(e, "steer", steer_of(in));
		break;
	default:
		key = k == 2 ? "bird-instance" : k == 3 ? "dhcp-instance" :
		    k == 4 ? "dns-instance" : k == 5 ? "proxy-instance" :
		    "ids-instance";
		put_list(e, key, instances_of(kind, in, ucl_object_lookup(e,
		    key), k >= 5 ? group : -1));
		break;
	}
	if (jail != NULL) {
		/* The jail's entry, gone when nothing is left of it. */
		if (!edge_empty(e))
			ucl_array_append(keep, e);
		else
			ucl_object_unref(e);
		jails = keep;
		put_list(sd, "jail", jails);
	}
	/* The same as running has: nothing to edit, the part to be set
	 * again (ysdwan_apply()). */
	*same = ucl_object_compare(was, sd) == 0;
	if (!*same)
		error = yjson_edit(conn, n, sd, CBL_YDS_CANDIDATE, NULL, 0, err,
		    errlen, errsid, tag, taglen);
	ucl_object_unref(was);
	ucl_object_unref(sd);
	ucl_object_unref(in);
	return (error);
}

int
ysdwan_apply(cbl_conn *conn, const char *kind, const char *json, char *err,
    size_t errlen)
{
	struct arcana_sdwan_sdwan_apply_input	 in;
	const struct cbl_ynode			*n, *act;
	ucl_object_t				*o;
	cbl_yarena				*a;
	size_t					 k;
	int					 error;

	err[0] = '\0';
	for (k = 0; k < nitems(kinds) && strcmp(kinds[k], kind) != 0; k++)
		;
	if (k == nitems(kinds) || (n = yq_top("arcana-sdwan", "sdwan")) ==
	    NULL || (act = yq_child(n, "apply")) == NULL) {
		snprintf(err, errlen, "arcana-sdwan has no apply of %s", kind);
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&in, 0, sizeof(in));
	in.has_part = true;
	in.part = (enum arcana_sdwan_sdwan_apply_input_part)k;
	o = parse(json);
	if (o != NULL && str(o, "jail") != NULL && str(o, "jail")[0] != '\0') {
		char	*j;

		if ((j = cbl_yarena_alloc(a, strlen(str(o, "jail")) + 1)) != NULL)
			memcpy(j, str(o, "jail"), strlen(str(o, "jail")) + 1);
		in.jail = j;
	}
	if (o != NULL && str(o, "group") != NULL && strcmp(str(o, "group"),
	    "security") == 0) {
		in.has_security = true;
		in.security = true;
	}
	if (o != NULL)
		ucl_object_unref(o);
	error = yq_call(conn, n, NULL, act, &in, NULL, a, err, errlen);
	cbl_yarena_free(a);
	return (error);
}

/* ---- The sdwan read's JSON ------------------------------------------- */

#define	PUT_INT(o, key, y, f) do {					\
	if ((y)->has_##f)						\
		put((o), (key), ucl_object_fromint((int64_t)(y)->f));	\
} while (0)

#define	PUT_YES(o, key, y, f) do {					\
	if ((y)->has_##f)						\
		put((o), (key), ucl_object_frombool((y)->f));		\
} while (0)

/* A decimal64 of d fraction digits as the number it was. */
static ucl_object_t *
dec(int64_t v, int d)
{

	return (ucl_object_fromdouble((double)v / (d == 6 ? 1000000.0 :
	    1000.0)));
}

/* A date-and-time as seconds since the Epoch; 0 for none. */
static int64_t
epoch(const char *s)
{
	struct tm	 tm;
	const char	*end;

	if (s == NULL)
		return (0);
	memset(&tm, 0, sizeof(tm));
	if ((end = strptime(s, "%Y-%m-%dT%H:%M:%S", &tm)) == NULL)
		return (0);
	return ((int64_t)timegm(&tm));
}

static void
put_time(ucl_object_t *o, const char *key, const char *s)
{

	if (s != NULL)
		put(o, key, ucl_object_fromint(epoch(s)));
}

/* An instance's BMP station (PLAN-SDN-YANG 5.6.2), as the agent's
 * sdwan read has it. */
static ucl_object_t *
bmp_json(const struct arcana_sdwan_sdwan_state_bird_bmp *b)
{
	ucl_object_t	*o, *arr, *e;

	o = ucl_object_typed_new(UCL_OBJECT);
	if (b->has_port)
		put(o, "port", ucl_object_fromint(b->port));
	put(o, "listening", ucl_object_frombool(b->listening));
	put(o, "connected", ucl_object_frombool(b->connected));
	put_time(o, "since", b->since);
	put_str(o, "sys_name", b->sys_name);
	put_str(o, "sys_descr", b->sys_descr);
	put(o, "messages", ucl_object_fromint((int64_t)b->messages));
	put_str(o, "error", b->error);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t k = 0; k < b->peer.n; k++) {
		const struct arcana_sdwan_sdwan_state_bird_bmp_peer *p =
		    &b->peer.v[k];

		e = ucl_object_typed_new(UCL_OBJECT);
		put_str(e, "address", p->address.v.m0);
		if (p->distinguisher != 0)
			put(e, "distinguisher", ucl_object_fromint((int64_t)
			    p->distinguisher));
		put(e, "as", ucl_object_fromint(p->as));
		put_str(e, "bgp_id", p->bgp_id);
		if (p->has_local)
			put_str(e, "local", p->local.v.m0);
		put(e, "up", ucl_object_frombool(p->up));
		put_time(e, "since", p->since);
		if (p->has_down_reason)
			put(e, "down_reason", ucl_object_fromint(p->down_reason));
		put(e, "announced", ucl_object_fromint((int64_t)p->announced));
		put(e, "withdrawn", ucl_object_fromint((int64_t)p->withdrawn));
		put(e, "announced_post", ucl_object_fromint((int64_t)
		    p->announced_post));
		put(e, "withdrawn_post", ucl_object_fromint((int64_t)
		    p->withdrawn_post));
		put_time(e, "last", p->last);
		ucl_array_append(arr, e);
	}
	put(o, "peers", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t k = 0; k < b->update.n; k++) {
		const struct arcana_sdwan_sdwan_state_bird_bmp_update *u =
		    &b->update.v[k];

		e = ucl_object_typed_new(UCL_OBJECT);
		put_time(e, "t", u->time);
		if (u->has_peer)
			put_str(e, "peer", u->peer.v.m0);
		put_str(e, "policy", u->policy ? "post" : "pre");
		put_str(e, "action", u->action ? "withdraw" : "announce");
		if (u->has_prefix)
			put_str(e, "prefix", u->prefix.v.m0);
		if (u->has_next_hop)
			put_str(e, "next_hop", u->next_hop.v.m0);
		put_str(e, "as_path", u->as_path);
		ucl_array_append(arr, e);
	}
	put(o, "updates", arr);
	return (o);
}

static ucl_object_t *
strs(size_t n, const char *const *v)
{
	ucl_object_t	*arr;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < n; i++)
		ucl_array_append(arr, ucl_object_fromstring(v[i]));
	return (arr);
}

static const char *
far(bool has, int s)
{
	static const char *const names[] = { "up", "down", "unknown",
	    "not probed" };

	return (has && s >= 0 && s < (int)nitems(names) ? names[s] :
	    "unknown");
}

/* A target's settings as its edge's configuration has them. */
static const struct arcana_probe_target *
target_conf(const struct arcana_probe_probes *p, const char *jail,
    const char *id)
{
	size_t		 n = 0;
	const struct arcana_probe_target *v = NULL;

	if (p == NULL)
		return (NULL);
	if (jail == NULL) {
		n = p->target.n;
		v = p->target.v;
	} else
		for (size_t i = 0; i < p->jail.n; i++)
			if (strcmp(p->jail.v[i].name, jail) == 0) {
				n = p->jail.v[i].target.n;
				v = p->jail.v[i].target.v;
			}
	for (size_t i = 0; i < n; i++)
		if (strcmp(v[i].id, id) == 0)
			return (&v[i]);
	return (NULL);
}

/* What a target's or a monitor's configuration says of its probing. */
struct probe_conf {
	const struct arcana_probe_tca	*tca;
	bool				 has_history;
	uint32_t			 history;
	bool				 has_down;
	uint8_t				 down;
	bool				 has_up;
	uint8_t				 up;
	const char			*interface;
};

#define	PROBE_CONF(pc, c) do {						\
	(pc)->tca = (c)->tca;						\
	(pc)->has_history = (c)->has_history;				\
	(pc)->history = (c)->history;					\
	(pc)->has_down = (c)->has_down;					\
	(pc)->down = (c)->down;						\
	(pc)->has_up = (c)->has_up;					\
	(pc)->up = (c)->up;						\
} while (0)

/* One metric's statistics of an interval, as probe.c's (microseconds). */
static void
pm_stats(ucl_object_t *o, const char *key, const struct arcana_probe_stats *s)
{
	ucl_object_t	*c;

	if (s == NULL)
		return;
	c = ucl_object_typed_new(UCL_OBJECT);
	PUT_INT(c, "count", s, count);
	PUT_INT(c, "min", s, min);
	PUT_INT(c, "max", s, max);
	PUT_INT(c, "mean", s, mean);
	PUT_INT(c, "low", s, low_percentile);
	PUT_INT(c, "intermediate", s, intermediate_percentile);
	PUT_INT(c, "high", s, high_percentile);
	put(o, key, c);
}

/* A target's measurement intervals as probe.c's pm_target_json() put
 * them, with the loss as a percentage too (RFC 9375's). */
static ucl_object_t *
pm_obj(const struct arcana_probe_target_state_pm *p)
{
	const struct arcana_probe_interval	*v;
	ucl_object_t				*o, *arr, *e;

	o = ucl_object_typed_new(UCL_OBJECT);
	PUT_INT(o, "length", p, measurement_interval);
	put(o, "low", dec(p->low_percentile, 3));
	put(o, "intermediate", dec(p->intermediate_percentile, 3));
	put(o, "high", dec(p->high_percentile, 3));
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < p->interval.n; i++) {
		v = &p->interval.v[i];
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "start", ucl_object_fromint(epoch(v->start)));
		put(e, "end", ucl_object_fromint(epoch(v->end)));
		put(e, "complete", ucl_object_frombool(v->complete));
		PUT_INT(e, "sent", v, sent);
		PUT_INT(e, "received", v, received);
		PUT_INT(e, "kept", v, kept);
		if (v->loss != NULL) {
			PUT_INT(e, "lost", v->loss, count);
			if (v->loss->has_ratio)
				put(e, "loss_pct", ucl_object_fromdouble((double)
				    v->loss->ratio / 100000.0));
			PUT_INT(e, "lost_forward", v->loss, forward_count);
			PUT_INT(e, "lost_backward", v->loss, backward_count);
		}
		pm_stats(e, "rtt", v->round_trip);
		pm_stats(e, "forward", v->forward);
		pm_stats(e, "backward", v->backward);
		if (v->jitter != NULL) {
			pm_stats(e, "jitter_rtt", v->jitter->round_trip);
			pm_stats(e, "jitter_forward", v->jitter->forward);
			pm_stats(e, "jitter_backward", v->jitter->backward);
		}
		ucl_array_append(arr, e);
	}
	put(o, "intervals", arr);
	return (o);
}

/*
 * A target as probe.c's target_json() put it, the settings of its
 * configuration, c (NULL: none, the prober's own).
 */
static ucl_object_t *
target_obj(const struct arcana_probe_target_state *t,
    const struct probe_conf *c)
{
	static const char *const states[] = { "unknown", "up", "down",
	    "ended", "error" };
	ucl_object_t				*o, *now, *arr, *row;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "id", t->id);
	if (t->has_address)
		put_str(o, "address", t->address.v.m0);
	put_str(o, "family", t->has_family && t->family ==
	    ARCANA_PROBE_TARGET_STATE_FAMILY_IPV6 ? "inet6" : "inet");
	put_str(o, "jail", t->jail);
	put_str(o, "class", t->class);
	PUT_INT(o, "fib", t, fib);
	put_str(o, "state", t->has_state && t->state < nitems(states) ?
	    states[t->state] : "unknown");
	put_str(o, "error", t->error);
	put_time(o, "since", t->since);
	PUT_INT(o, "interval", t, interval);
	PUT_INT(o, "size", t, size);
	PUT_INT(o, "eval", t, eval);
	PUT_INT(o, "dscp", t, dscp);
	PUT_INT(o, "sent", t, sent);
	PUT_INT(o, "received", t, received);
	PUT_INT(o, "misses", t, misses);
	put(o, "last_rtt", dec(t->has_last_rtt ? t->last_rtt : 0, 3));
	if (t->now != NULL) {
		now = ucl_object_typed_new(UCL_OBJECT);
		put(now, "sent", ucl_object_fromint(t->now->sent));
		put(now, "recv", ucl_object_fromint(t->now->received));
		put(now, "delay", dec(t->now->delay, 3));
		put(now, "ipdv", dec(t->now->ipdv, 3));
		put(now, "loss", dec(t->now->loss, 6));
		put(now, "age", dec(t->now->age, 3));
		put(o, "now", now);
	}
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < t->sample.n; i++) {
		const struct arcana_probe_sample	*s = &t->sample.v[i];
		int64_t					 at = epoch(s->time);

		row = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(row, ucl_object_fromint(at));
		ucl_array_append(row, dec(s->delay, 3));
		ucl_array_append(row, dec(s->ipdv, 3));
		ucl_array_append(row, dec(s->loss, 6));
		ucl_array_append(row, dec(s->min, 3));
		ucl_array_append(row, dec(s->max, 3));
		ucl_array_append(row, ucl_object_fromint(s->sent));
		ucl_array_append(row, ucl_object_fromint(s->received));
		/* By STAMP, as probe.c's rows: the loss each way, a
		 * fraction of those sent (-1 not told), the delay each way
		 * and how (1 one way, 0 half the round trip, -1 not by
		 * STAMP: -1 each). */
		ucl_array_append(row, ucl_object_fromdouble(s->has_lost_forward &&
		    s->sent > 0 ? (double)s->lost_forward / s->sent : -1));
		ucl_array_append(row, ucl_object_fromdouble(s->has_lost_backward &&
		    s->sent > 0 ? (double)s->lost_backward / s->sent : -1));
		ucl_array_append(row, s->has_one_way ? dec(s->delay_forward, 3) :
		    ucl_object_fromdouble(-1));
		ucl_array_append(row, s->has_one_way ? dec(s->delay_backward, 3) :
		    ucl_object_fromdouble(-1));
		ucl_array_append(row, ucl_object_fromint(!s->has_one_way ? -1 :
		    s->one_way == ARCANA_PROBE_SAMPLE_ONE_WAY_MEASURED ? 1 : 0));
		ucl_array_append(arr, row);
	}
	put(o, "samples", arr);
	PUT_INT(o, "kept", t, kept);
	if (t->pm != NULL)
		put(o, "pm", pm_obj(t->pm));
	if (c != NULL)
		put_str(o, "interface", c->interface);
	/* The settings its edge's configuration has, the prober's own
	 * where it says none. */
	if (c != NULL && c->tca != NULL && ((c->tca->has_delay &&
	    c->tca->delay > 0) || (c->tca->has_ipdv && c->tca->ipdv > 0) ||
	    (c->tca->has_loss && c->tca->loss > 0))) {
		now = ucl_object_typed_new(UCL_OBJECT);
		put(now, "delay", dec(c->tca->delay, 3));
		put(now, "ipdv", dec(c->tca->ipdv, 3));
		put(now, "loss", dec(c->tca->loss, 6));
		put(now, "damping", ucl_object_fromint(c->tca->damping));
		put(o, "tca", now);
	}
	put(o, "history", ucl_object_fromint(c != NULL && c->has_history ?
	    c->history : 3600));
	put(o, "down", ucl_object_fromint(c != NULL && c->has_down ? c->down :
	    3));
	put(o, "up", ucl_object_fromint(c != NULL && c->has_up ? c->up : 3));
	return (o);
}

static ucl_object_t *
target_json(const struct arcana_probe_probes *p,
    const struct arcana_probe_target_state *t)
{
	const struct arcana_probe_target	*c;
	struct probe_conf			 pc;

	memset(&pc, 0, sizeof(pc));
	if ((c = target_conf(p, t->jail, t->id)) == NULL)
		return (target_obj(t, NULL));
	PROBE_CONF(&pc, c);
	return (target_obj(t, &pc));
}

/* A monitor's settings as its edge's configuration has them. */
static const struct arcana_probe_monitor *
monitor_conf(const struct arcana_probe_probes *p, const char *jail,
    const char *id)
{
	size_t		 n = 0;
	const struct arcana_probe_monitor *v = NULL;

	if (p == NULL)
		return (NULL);
	if (jail == NULL) {
		n = p->monitor.n;
		v = p->monitor.v;
	} else
		for (size_t i = 0; i < p->jail.n; i++)
			if (strcmp(p->jail.v[i].name, jail) == 0) {
				n = p->jail.v[i].monitor.n;
				v = p->jail.v[i].monitor.v;
			}
	for (size_t i = 0; i < n; i++)
		if (strcmp(v[i].name, id) == 0)
			return (&v[i]);
	return (NULL);
}

int
ysdwan_monitors(cbl_conn *conn, bool has_after, uint64_t after,
    ucl_object_t **data, char *err, size_t errlen)
{
	struct arcana_probe_probes_read_input	 in;
	struct arcana_probe_probes_read_output	 rd;
	const struct arcana_probe_monitor	*m;
	const struct cbl_ynode			*np, *act;
	struct arcana_probe			 pr;
	struct probe_conf			 pc;
	ucl_object_t				*top, *arr;
	struct tm				 tm;
	time_t					 t;
	cbl_yarena				*a;
	char					 when[32];
	int					 error;

	*data = NULL;
	err[0] = '\0';
	if ((np = yq_top("arcana-probe", "probes")) == NULL || (act =
	    yq_child(np, "read")) == NULL) {
		snprintf(err, errlen, "arcana-probe is not in the tables");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&pr, 0, sizeof(pr));
	memset(&in, 0, sizeof(in));
	memset(&rd, 0, sizeof(rd));
	in.has_monitors = true;
	in.monitors = true;
	t = (time_t)after;
	if (has_after && gmtime_r(&t, &tm) != NULL && strftime(when,
	    sizeof(when), "%Y-%m-%dT%H:%M:%SZ", &tm) > 0)
		in.after = when;
	if ((error = yq_get(conn, np, CBL_YDS_RUNNING, &pr, a, err,
	    errlen)) == 0 && (error = yq_call(conn, np, NULL, act, &in, &rd, a,
	    err, errlen)) == 0) {
		/* As probe.c's do_monitors() put them. */
		top = ucl_object_typed_new(UCL_OBJECT);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < rd.target.n; i++) {
			m = monitor_conf(pr.probes, rd.target.v[i].jail,
			    rd.target.v[i].id);
			memset(&pc, 0, sizeof(pc));
			if (m != NULL) {
				PROBE_CONF(&pc, m);
				pc.interface = m->interface;
			}
			ucl_array_append(arr, target_obj(&rd.target.v[i],
			    m != NULL ? &pc : NULL));
		}
		put(top, "monitors", arr);
		put(top, "time", ucl_object_fromint(rd.time != NULL ?
		    epoch(rd.time) : time(NULL)));
		put(top, "probing", ucl_object_frombool(rd.probing));
		*data = top;
	}
	cbl_yarena_free(a);
	return (error);
}

/* An edge's rules and steering, as edge_json() put them. */
static void
edge_json(ucl_object_t *o, const struct arcana_sdwan_rules *r, bool steered,
    size_t ns, const struct arcana_sdwan_steer *sv, size_t nr,
    const struct arcana_sdwan_steered_route *rv)
{
	ucl_object_t	*ro, *arr, *e, *cs, *c, *tabs;

	ro = ucl_object_typed_new(UCL_OBJECT);
	put(ro, "set", ucl_object_fromint(r != NULL ? r->set : 0));
	put(ro, "rules", ucl_object_fromint(r != NULL ? r->rules : 0));
	tabs = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; r != NULL && i < r->table.n; i++)
		ucl_array_append(tabs, ucl_object_fromstring(
		    r->table.v[i].name));
	put(ro, "tables", tabs);
	put(ro, "objects", ucl_object_fromint(r != NULL ? r->objects : 0));
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; r != NULL && i < r->counter.n; i++) {
		c = ucl_object_typed_new(UCL_OBJECT);
		put(c, "rule", ucl_object_fromint(r->counter.v[i].rule));
		put(c, "pkts", ucl_object_fromint((int64_t)
		    r->counter.v[i].packets));
		put(c, "bytes", ucl_object_fromint((int64_t)
		    r->counter.v[i].octets));
		put_str(c, "text", r->counter.v[i].text);
		ucl_array_append(arr, c);
	}
	put(ro, "counters", arr);
	put(o, "rules", ro);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < ns; i++) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put_str(e, "table", sv[i].table);
		put_str(e, "prefix", sv[i].prefix);
		put(e, "chosen", ucl_object_fromint(sv[i].chosen));
		cs = ucl_object_typed_new(UCL_ARRAY);
		for (size_t k = 0; k < sv[i].candidate.n; k++) {
			const struct arcana_sdwan_steer_candidate *v =
			    &sv[i].candidate.v[k];

			c = ucl_object_typed_new(UCL_OBJECT);
			put_str(c, "id", v->id);
			put_str(c, "via", v->has_via ? v->via.v.m0 : "");
			put_str(c, "state", far(v->has_state, (int)v->state));
			if (v->has_bfd)
				put_str(c, "bfd", far(true, (int)v->bfd));
			ucl_array_append(cs, c);
		}
		put(e, "candidates", cs);
		ucl_array_append(arr, e);
	}
	put(o, "steer", arr);
	put(o, "steered", ucl_object_frombool(steered));
	if (nr == 0)
		return;
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < nr; i++) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "fib", ucl_object_fromint(rv[i].fib));
		put_str(e, "destination", rv[i].destination);
		put(e, "chosen", ucl_object_fromint(rv[i].chosen));
		cs = ucl_object_typed_new(UCL_ARRAY);
		for (size_t k = 0; k < rv[i].candidate.n; k++) {
			const struct arcana_sdwan_steered_route_candidate *v =
			    &rv[i].candidate.v[k];

			c = ucl_object_typed_new(UCL_OBJECT);
			put_str(c, "id", v->id);
			put_str(c, "via", v->has_via ? v->via.v.m0 : "");
			put_str(c, "state", far(v->has_state, (int)v->state));
			ucl_array_append(cs, c);
		}
		put(e, "candidates", cs);
		ucl_array_append(arr, e);
	}
	put(o, "routes", arr);
}

/* An edge's tunnels measured by alternate marking, their last blocks,
 * as the agent's sdwan read had them (gula/altmark.c); none, nothing. */
static void
altmark_json(ucl_object_t *o, size_t n, const struct arcana_sdwan_altmark_tunnel
    *v)
{
	ucl_object_t	*arr, *t, *bs, *b;

	if (n == 0)
		return;
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < n; i++) {
		t = ucl_object_typed_new(UCL_OBJECT);
		put_str(t, "tunnel", v[i].tunnel);
		put_str(t, "service", v[i].service);
		put_str(t, "interface", v[i].interface);
		put(t, "period", ucl_object_fromint(v[i].period));
		put(t, "colour", ucl_object_fromint(v[i].colour));
		put(t, "block", ucl_object_fromint((int64_t)v[i].current));
		bs = ucl_object_typed_new(UCL_ARRAY);
		for (size_t k = 0; k < v[i].block.n; k++) {
			const struct arcana_sdwan_altmark_tunnel_block *x =
			    &v[i].block.v[k];

			b = ucl_object_typed_new(UCL_OBJECT);
			put(b, "block", ucl_object_fromint((int64_t)x->number));
			put_time(b, "start", x->start);
			put(b, "colour", ucl_object_fromint(x->colour));
			put(b, "out_packets", ucl_object_fromint((int64_t)
			    x->out_packets));
			put(b, "out_bytes", ucl_object_fromint((int64_t)
			    x->out_octets));
			put(b, "in_packets", ucl_object_fromint((int64_t)
			    x->in_packets));
			put(b, "in_bytes", ucl_object_fromint((int64_t)
			    x->in_octets));
			put(b, "read_ms", ucl_object_fromint(x->read_offset));
			if (x->has_swap_delay)
				put(b, "flip_ms", ucl_object_fromint(
				    x->swap_delay));
			put(b, "valid", ucl_object_frombool(x->valid));
			ucl_array_append(bs, b);
		}
		put(t, "blocks", bs);
		ucl_array_append(arr, t);
	}
	put(o, "altmark", arr);
}

/* A JSON text the agent read, parsed again; NULL where it is none. */
static ucl_object_t *
reparse(const char *s)
{

	return (s != NULL ? parse(s) : NULL);
}

static void
file_json(ucl_object_t *o, const char *path, bool has_size, uint64_t size,
    const char *at)
{

	put_str(o, "path", path);
	if (has_size)
		put(o, "size", ucl_object_fromint((int64_t)size));
	put_time(o, "at", at);
}

static ucl_object_t *
ids_json(const struct arcana_sdwan_sdwan_state_ids *d)
{
	ucl_object_t	*o, *arr, *a, *s, *f;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "name", d->name);
	put(o, "interfaces", strs(d->interface.n, d->interface.v));
	put_str(o, "mode", d->has_mode && d->mode ==
	    ARCANA_SDWAN_SDWAN_STATE_IDS_MODE_PREVENT ? "prevent" : "detect");
	PUT_INT(o, "divert", d, divert);
	put(o, "running", ucl_object_frombool(d->running));
	if (d->has_stopped && d->stopped)
		put(o, "stopped", ucl_object_frombool(true));
	put(o, "alerts_seen", ucl_object_fromint((int64_t)d->alerts_seen));
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < d->alert.n; i++) {
		const struct arcana_sdwan_sdwan_state_ids_alert *v =
		    &d->alert.v[i];

		a = ucl_object_typed_new(UCL_OBJECT);
		put_str(a, "name", d->name);
		put_str(a, "time", v->time != NULL ? v->time : "");
		put_str(a, "src", v->source != NULL ? v->source : "");
		put(a, "sport", ucl_object_fromint(v->source_port));
		put_str(a, "dst", v->destination != NULL ? v->destination : "");
		put(a, "dport", ucl_object_fromint(v->destination_port));
		put_str(a, "proto", v->proto != NULL ? v->proto : "");
		put_str(a, "iface", v->interface != NULL ? v->interface : "");
		put(a, "sid", ucl_object_fromint(v->signature_id));
		put(a, "rev", ucl_object_fromint(v->rev));
		put_str(a, "signature", v->name != NULL ? v->name : "");
		put_str(a, "category", v->category != NULL ? v->category : "");
		put(a, "severity", ucl_object_fromint(v->severity));
		put_str(a, "action", v->action != NULL ? v->action : "");
		ucl_array_append(arr, a);
	}
	put(o, "alerts", arr);
	if (d->stats != NULL) {
		s = ucl_object_typed_new(UCL_OBJECT);
		put(s, "fields", strs(d->stats->field.n, d->stats->field.v));
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < d->stats->series.n; i++) {
			a = ucl_object_typed_new(UCL_ARRAY);
			for (size_t k = 0; k < d->stats->series.v[i].value.n;
			    k++)
				ucl_array_append(a, ucl_object_fromint(
				    d->stats->series.v[i].value.v[k]));
			ucl_array_append(arr, a);
		}
		put(s, "series", arr);
		if ((f = reparse(d->stats->flows)) != NULL)
			put(s, "flows", f);
		put(o, "stats", s);
	}
	put_str(o, "capture", !d->has_capture ? "pcap" : d->capture ==
	    ARCANA_SDWAN_SDWAN_STATE_IDS_CAPTURE_NETMAP ? "netmap" :
	    d->capture == ARCANA_SDWAN_SDWAN_STATE_IDS_CAPTURE_DIVERT ?
	    "divert" : "pcap");
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < d->pcap.n; i++) {
		a = ucl_object_typed_new(UCL_OBJECT);
		file_json(a, d->pcap.v[i].path, d->pcap.v[i].has_size,
		    d->pcap.v[i].size, d->pcap.v[i].at);
		PUT_INT(a, "from", &d->pcap.v[i], from);
		ucl_array_append(arr, a);
	}
	put(o, "pcaps", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < d->replay_capture.n; i++) {
		a = ucl_object_typed_new(UCL_OBJECT);
		file_json(a, d->replay_capture.v[i].path,
		    d->replay_capture.v[i].has_size,
		    d->replay_capture.v[i].size, d->replay_capture.v[i].at);
		ucl_array_append(arr, a);
	}
	put(o, "captures", arr);
	if ((f = reparse(d->replay)) != NULL)
		put(o, "replay", f);
	s = ucl_object_typed_new(UCL_OBJECT);
	for (size_t i = 0; i < d->offload.n; i++)
		put(s, d->offload.v[i].interface, strs(
		    d->offload.v[i].capability.n, d->offload.v[i].capability.v));
	put(o, "offload", s);
	put_str(o, "group", is_sec(d->name) ? "security" : "sdwan");
	return (o);
}

/* A form of the Security section's, a sec- IDS instance's spec, into
 * arr. */
static void
security_spec(ucl_object_t *arr, const char *name, const char *spec)
{
	ucl_object_t	*s;

	if (is_sec(name) && (s = reparse(spec)) != NULL)
		ucl_array_append(arr, s);
}

/* The Security section's URL filter as its page has the form, a sec-
 * proxy instance's: its spec, each address it listens on a word, its
 * name and whether it is stopped. */
static void
security_proxy(ucl_object_t *arr,
    const struct arcana_sdwan_sdwan_proxy_instance *p)
{
	struct cbl_ybuf		 b = { NULL, 0, 0 };
	const struct cbl_ynode	*n;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*s, *l;
	char			*text;

	if (!is_sec(p->name) || p->spec == NULL || (n = yq_child(yq_child(
	    yq_top("arcana-sdwan", "sdwan"), "proxy-instance"), "spec")) ==
	    NULL || cbl_yjson(n, p->spec, &b) != 0 || asprintf(&text, "%.*s",
	    (int)b.len, (const char *)b.p) == -1) {
		cbl_ybuf_free(&b);
		return;
	}
	cbl_ybuf_free(&b);
	s = parse(text);
	free(text);
	if (s == NULL)
		return;
	l = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(s, "listen"), &it,
	    true)) != NULL)
		if (str(e, "address") != NULL)
			ucl_array_append(l, ucl_object_fromstring(str(e,
			    "address")));
	put(s, "listen", l);
	put_str(s, "name", p->name);
	if (p->has_stopped && p->stopped)
		put(s, "stopped", ucl_object_frombool(true));
	ucl_array_append(arr, s);
}

static void
clamav_json(ucl_object_t *top, const struct arcana_sdwan_sdwan_state_clamav *c)
{
	ucl_object_t	*o, *arr, *d;

	if (c == NULL)
		return;
	o = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < c->database.n; i++) {
		d = ucl_object_typed_new(UCL_OBJECT);
		put_str(d, "name", c->database.v[i].name);
		put_str(d, "file", c->database.v[i].file);
		put_str(d, "built", c->database.v[i].built);
		PUT_INT(d, "version", &c->database.v[i], version);
		PUT_INT(d, "signatures", &c->database.v[i], signatures);
		ucl_array_append(arr, d);
	}
	put(o, "databases", arr);
	put(o, "freshclam", ucl_object_frombool(c->freshclam));
	put(o, "conf", ucl_object_frombool(c->conf));
	put(o, "mirrors", strs(c->mirror.n, c->mirror.v));
	if (c->log.n > 0)
		put(o, "log", strs(c->log.n, c->log.v));
	put(top, "clamav", o);
}

/* The sdwan read, all of it, from the two modules' data. */
static ucl_object_t *
read_json(const struct arcana_sdwan_sdwan *sd,
    const struct arcana_probe_probes *pr,
    const struct arcana_probe_probes_read_output *rd)
{
	const struct arcana_sdwan_sdwan_state	*st;
	ucl_object_t				*top, *arr, *o, *c;

	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < rd->target.n; i++)
		ucl_array_append(arr, target_json(pr, &rd->target.v[i]));
	put(top, "targets", arr);
	put(top, "time", ucl_object_fromint(rd->time != NULL ? epoch(rd->time) :
	    time(NULL)));
	put(top, "probing", ucl_object_frombool(rd->probing));
	st = sd != NULL ? sd->state : NULL;
	if (st == NULL) {
		static const struct arcana_sdwan_sdwan_state none;

		st = &none;
	}
	edge_json(top, st->rules, st->steered, st->steer.n, st->steer.v,
	    st->route.n, st->route.v);
	altmark_json(top, st->alt_marking.n, st->alt_marking.v);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < st->edge.n; i++) {
		const struct arcana_sdwan_sdwan_state_edge *e = &st->edge.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "jail", e->jail);
		if (e->error != NULL)
			put_str(o, "error", e->error);
		else {
			edge_json(o, e->rules, e->steered, e->steer.n,
			    e->steer.v, e->route.n, e->route.v);
			altmark_json(o, e->alt_marking.n, e->alt_marking.v);
		}
		ucl_array_append(arr, o);
	}
	put(top, "edges", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < st->bird.n; i++) {
		const struct arcana_sdwan_sdwan_state_bird *b = &st->bird.v[i];
		ucl_object_t	*ps;

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", b->name);
		put(o, "fib", ucl_object_fromint(b->fib));
		put_str(o, "jail", b->jail);
		put(o, "running", ucl_object_frombool(b->running));
		ps = ucl_object_typed_new(UCL_ARRAY);
		for (size_t k = 0; k < b->protocol.n; k++) {
			c = ucl_object_typed_new(UCL_OBJECT);
			put_str(c, "name", b->protocol.v[k].name);
			put_str(c, "proto", b->protocol.v[k].proto);
			put_str(c, "state", b->protocol.v[k].state);
			put_str(c, "info", b->protocol.v[k].info);
			ucl_array_append(ps, c);
		}
		put(o, "protocols", ps);
		ps = ucl_object_typed_new(UCL_ARRAY);
		for (size_t k = 0; k < b->bfd.n; k++) {
			c = ucl_object_typed_new(UCL_OBJECT);
			put_str(c, "address", b->bfd.v[k].address);
			put_str(c, "interface", b->bfd.v[k].interface);
			put_str(c, "state", far(b->bfd.v[k].has_state,
			    (int)b->bfd.v[k].state));
			put_str(c, "since", b->bfd.v[k].since);
			ucl_array_append(ps, c);
		}
		put(o, "bfd", ps);
		if (b->bmp != NULL)
			put(o, "bmp", bmp_json(b->bmp));
		ucl_array_append(arr, o);
	}
	put(top, "bird", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < st->dhcp.n; i++) {
		const struct arcana_sdwan_sdwan_state_dhcp *d = &st->dhcp.v[i];
		ucl_object_t	*ls;

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", d->name);
		put(o, "fib", ucl_object_fromint(d->fib));
		put(o, "running", ucl_object_frombool(d->running));
		ls = ucl_object_typed_new(UCL_ARRAY);
		for (size_t k = 0; k < d->lease.n; k++) {
			c = ucl_object_typed_new(UCL_OBJECT);
			put_time(c, "expires", d->lease.v[k].expires);
			put_str(c, "id", d->lease.v[k].id);
			if (d->lease.v[k].has_address)
				put_str(c, "address", d->lease.v[k].address.v.m0);
			put_str(c, "name", d->lease.v[k].hostname);
			ucl_array_append(ls, c);
		}
		put(o, "leases", ls);
		ucl_array_append(arr, o);
	}
	put(top, "dhcp", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < st->dns.n; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", st->dns.v[i].name);
		put(o, "fib", ucl_object_fromint(st->dns.v[i].fib));
		put(o, "running", ucl_object_frombool(st->dns.v[i].running));
		put_str(o, "tls_cert", st->dns.v[i].tls_cert);
		ucl_array_append(arr, o);
	}
	put(top, "dns", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < st->proxy.n; i++) {
		const struct arcana_sdwan_sdwan_state_proxy *p = &st->proxy.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", p->name);
		put(o, "fib", ucl_object_fromint(p->fib));
		put_str(o, "mode", p->mode);
		put(o, "running", ucl_object_frombool(p->running));
		PUT_YES(o, "icap", p, icap);
		put_str(o, "ca", p->ca);
		put_str(o, "group", is_sec(p->name) ? "security" : "sdwan");
		ucl_array_append(arr, o);
	}
	put(top, "proxy", arr);
	/* The Security section's forms, from the configuration. */
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; sd != NULL && i < sd->proxy_instance.n; i++)
		security_proxy(arr, &sd->proxy_instance.v[i]);
	put(top, "security_proxy", arr);
	clamav_json(top, st->clamav);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < st->ids.n; i++)
		ucl_array_append(arr, ids_json(&st->ids.v[i]));
	put(top, "ids", arr);
	if (st->ids_build != NULL) {
		const struct arcana_sdwan_sdwan_state_ids_build *b =
		    st->ids_build;

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "version", b->version);
		PUT_YES(o, "lua", b, lua);
		PUT_YES(o, "profiling", b, profiling);
		PUT_YES(o, "profiling_rules", b, profiling_rules);
		PUT_YES(o, "profiling_locks", b, profiling_locks);
		PUT_YES(o, "hyperscan", b, hyperscan);
		PUT_YES(o, "netmap", b, netmap);
		PUT_YES(o, "ipfw", b, ipfw);
		PUT_YES(o, "plugins", b, plugins);
		put(top, "ids_build", o);
	}
	if (st->ids_host != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "ncpu", ucl_object_fromint(st->ids_host->ncpu));
		put(o, "ndomains", ucl_object_fromint(st->ids_host->ndomains));
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < st->ids_host->irq.n; i++) {
			c = ucl_object_typed_new(UCL_OBJECT);
			put(c, "irq", ucl_object_fromint(
			    st->ids_host->irq.v[i].irq));
			put_str(c, "name", st->ids_host->irq.v[i].name);
			put_str(c, "cpus", st->ids_host->irq.v[i].cpus);
			ucl_array_append(arr, c);
		}
		put(o, "irqs", arr);
		put(top, "ids_host", o);
	}
	if (st->ids_ruleset != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "path", st->ids_ruleset->path);
		put_time(o, "at", st->ids_ruleset->at);
		PUT_INT(o, "size", st->ids_ruleset, size);
		put(top, "ids_ruleset", o);
	}
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; sd != NULL && i < sd->ids_instance.n; i++)
		security_spec(arr, sd->ids_instance.v[i].name,
		    sd->ids_instance.v[i].spec);
	put(top, "security_ids", arr);
	o = ucl_object_typed_new(UCL_OBJECT);
	if (st->record != NULL) {
		put(o, "count", ucl_object_fromint((int64_t)st->record->count));
		put(o, "seq", ucl_object_fromint((int64_t)
		    st->record->sequence));
		put(o, "untold", ucl_object_fromint((int64_t)
		    st->record->untold));
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < st->record->last.n; i++) {
			const struct arcana_sdwan_sdwan_state_record_last *l =
			    &st->record->last.v[i];

			c = ucl_object_typed_new(UCL_OBJECT);
			put_time(c, "t", l->time);
			put(c, "seq", ucl_object_fromint((int64_t)l->sequence));
			put(c, "rule", ucl_object_fromint(l->rule));
			put_str(c, "action", l->action);
			put_str(c, "src", l->source);
			put_str(c, "dst", l->destination);
			put_str(c, "iface", l->interface);
			put_str(c, "comment", l->comment);
			ucl_array_append(arr, c);
		}
		put(o, "last", arr);
	}
	put(top, "record", o);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < st->key.n; i++) {
		const struct arcana_sdwan_sdwan_state_key *k = &st->key.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "interface", k->interface);
		put_str(o, "public", k->public);
		put_str(o, "next", k->next);
		put_time(o, "keyed_at", k->keyed_at);
		PUT_INT(o, "lifetime", k, lifetime);
		PUT_INT(o, "spi_in", k, spi_in);
		PUT_INT(o, "spi_out", k, spi_out);
		PUT_YES(o, "pending", k, pending);
		ucl_array_append(arr, o);
	}
	put(top, "keys", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < st->fault.n; i++) {
		const struct arcana_sdwan_sdwan_state_fault *f = &st->fault.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_time(o, "t", f->time);
		put_str(o, "type", f->type);
		put_str(o, "severity", f->severity);
		put_str(o, "was", f->was);
		put_str(o, "object", f->object);
		put_str(o, "by", f->by);
		put_str(o, "description", f->description);
		put(o, "cleared", ucl_object_frombool(f->cleared));
		put_time(o, "cleared_at", f->cleared_at);
		if (f->has_compressed && f->compressed)
			put(o, "compressed", ucl_object_frombool(true));
		ucl_array_append(arr, o);
	}
	put(top, "faults", arr);
	return (top);
}

/* ---- arcana-steer: why each choice, and the console's pins ---------- */

static const char *const steer_reasons[] = { "preference", "first-up",
    "failover", "override", "none" };

/* The read's entries of key (steer, routes) of an edge: the host's in
 * top, a jail's in its entry of edges; NULL none. */
static ucl_object_t *
steer_entries(ucl_object_t *top, const char *jail, const char *key)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	if (jail == NULL || jail[0] == '\0')
		return ((ucl_object_t *)(uintptr_t)ucl_object_lookup(top, key));
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(top, "edges"), &it,
	    true)) != NULL)
		if (str(e, "jail") != NULL && strcmp(str(e, "jail"), jail) == 0)
			return ((ucl_object_t *)(uintptr_t)ucl_object_lookup(e,
			    key));
	return (NULL);
}

/* The why of a choice into its entry. */
static void
steer_put(ucl_object_t *e, bool has_reason, int reason,
    const char *from, const char *since, bool has_changes, uint32_t changes)
{

	if (has_reason && reason >= 0 && (size_t)reason < nitems(steer_reasons))
		put_str(e, "reason", steer_reasons[reason]);
	if (from != NULL)
		put_str(e, "from", from);
	if (since != NULL)
		put(e, "since", ucl_object_fromint(epoch(since)));
	if (has_changes)
		put(e, "changes", ucl_object_fromint(changes));
}

/*
 * arcana-steer's why of each choice, into the read's steer entries and
 * steered routes (reason, from, since, changes, pinned); an
 * agent without the module is read as before.
 */
static void
steer_why(cbl_conn *conn, ucl_object_t *top, cbl_yarena *a)
{
	const struct arcana_steer_steering_state	*st;
	const struct cbl_ynode				*n;
	struct arcana_steer				 d;
	ucl_object_t					*arr, *e;
	ucl_object_iter_t				 it;
	char						 err[128];

	if ((n = yq_top("arcana-steer", "steering")) == NULL)
		return;
	memset(&d, 0, sizeof(d));
	if (yq_get(conn, n, CBL_YDS_OPERATIONAL, &d, a, err, sizeof(err)) !=
	    0 || d.steering == NULL || (st = d.steering->state) == NULL)
		return;
	for (size_t i = 0; i < st->policy.n; i++) {
		const struct arcana_steer_policy_state *p = &st->policy.v[i];

		arr = steer_entries(top, p->jail, "steer");
		it = NULL;
		while (arr != NULL && (e = (ucl_object_t *)(uintptr_t)
		    ucl_object_iterate(arr, &it, true)) != NULL) {
			if (str(e, "table") == NULL || str(e, "prefix") == NULL ||
			    strcmp(str(e, "table"), p->table) != 0 || strcmp(str(e,
			    "prefix"), p->prefix) != 0)
				continue;
			steer_put(e, p->has_reason, (int)p->reason,
			    p->from, p->since, p->has_changes, p->changes);
			if (p->pinned != NULL)
				put_str(e, "pinned", p->pinned);
			break;
		}
	}
	for (size_t i = 0; i < st->route.n; i++) {
		const struct arcana_steer_route_state *r = &st->route.v[i];

		arr = steer_entries(top, r->jail, "routes");
		it = NULL;
		while (arr != NULL && (e = (ucl_object_t *)(uintptr_t)
		    ucl_object_iterate(arr, &it, true)) != NULL) {
			if (str(e, "destination") == NULL || strcmp(str(e,
			    "destination"), r->destination) != 0 ||
			    ucl_object_toint(ucl_object_lookup(e, "fib")) !=
			    r->fib)
				continue;
			steer_put(e, r->has_reason, (int)r->reason,
			    r->from, r->since, r->has_changes, r->changes);
			break;
		}
	}
}


/* ---- arcana-stamp: what STAMP sees of each target ------------------ */

static const char *const stamp_kinds[] = { "auto", "stamp", "icmp" };
static const char *const stamp_modes[] = { "unknown", "stateless",
    "stateful" };
static const char *const stamp_clocks[] = { "ntp", "ptp", "ssu", "gnss",
    "local", "unknown" };
static const char *const stamp_tsms[] = { "hw", "sw", "control",
    "unknown" };
static const char *const stamp_nats[] = { "none", "source", "destination",
    "both" };

#define	PUT_NAME(o, key, y, f, names) do {				\
	if ((y)->has_##f && (size_t)(y)->f < nitems(names))		\
		put_str((o), (key), (names)[(y)->f]);			\
} while (0)

/* A session of arcana-stamp's as the read's JSON: the target's
 * "stamp". */
static ucl_object_t *
stamp_obj(const struct arcana_stamp_session *s)
{
	const struct arcana_stamp_session_counters	*c;
	ucl_object_t					*o, *co;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "target", s->target);
	put_str(o, "jail", s->jail);
	put_str(o, "class", s->class);
	PUT_NAME(o, "kind", s, kind, stamp_kinds);
	if (s->has_method)
		put_str(o, "method", s->method ==
		    ARCANA_STAMP_SESSION_METHOD_STAMP ? "stamp" : "icmp");
	put_str(o, "reason", s->reason);
	if (s->has_reflector_address)
		put_str(o, "reflector", s->reflector_address.v.m0);
	PUT_INT(o, "port", s, reflector_udp_port);
	PUT_INT(o, "fib", s, fib);
	PUT_INT(o, "ssid", s, ssid);
	PUT_NAME(o, "mode", s, reflector_mode, stamp_modes);
	PUT_YES(o, "authenticated", s, authenticated);
	put_str(o, "key_error", s->key_error);
	if (s->delay != NULL) {
		if (s->delay->has_rtt)
			put(o, "rtt", dec(s->delay->rtt, 3));
		if (s->delay->has_forward)
			put(o, "delay_forward", dec(s->delay->forward, 3));
		if (s->delay->has_backward)
			put(o, "delay_backward", dec(s->delay->backward, 3));
		if (s->delay->has_one_way)
			put_str(o, "one_way", s->delay->one_way ==
			    ARCANA_STAMP_SESSION_DELAY_ONE_WAY_MEASURED ?
			    "measured" : "estimated");
		if (s->delay->has_clock_error)
			put(o, "clock_error", dec(s->delay->clock_error, 3));
	}
	if (s->timestamp_info != NULL) {
		PUT_NAME(o, "sync_in", s->timestamp_info, sync_in, stamp_clocks);
		PUT_NAME(o, "timestamp_in", s->timestamp_info, timestamp_in,
		    stamp_tsms);
		PUT_NAME(o, "sync_out", s->timestamp_info, sync_out,
		    stamp_clocks);
		PUT_NAME(o, "timestamp_out", s->timestamp_info, timestamp_out,
		    stamp_tsms);
	}
	if (s->dscp != NULL) {
		PUT_INT(o, "dscp_sent", s->dscp, sent);
		PUT_INT(o, "dscp_forward", s->dscp, forward);
		PUT_INT(o, "dscp_backward", s->dscp, backward);
		PUT_YES(o, "dscp_refused", s->dscp, refused);
	}
	if (s->location != NULL) {
		PUT_NAME(o, "nat", s->location, nat, stamp_nats);
		if (s->location->has_source_address)
			put_str(o, "seen_source",
			    s->location->source_address.v.m0);
		PUT_INT(o, "seen_source_port", s->location, source_port);
		if (s->location->has_destination_address)
			put_str(o, "seen_destination",
			    s->location->destination_address.v.m0);
		PUT_INT(o, "seen_destination_port", s->location,
		    destination_port);
	}
	if ((c = s->counters) != NULL) {
		co = ucl_object_typed_new(UCL_OBJECT);
		PUT_INT(co, "sent", c, sent);
		PUT_INT(co, "received", c, received);
		PUT_INT(co, "lost", c, lost);
		PUT_INT(co, "lost_forward", c, lost_forward);
		PUT_INT(co, "lost_backward", c, lost_backward);
		PUT_INT(co, "lost_unknown", c, lost_unknown);
		PUT_INT(co, "dm_lost_forward", c, dm_lost_forward);
		PUT_INT(co, "dm_lost_backward", c, dm_lost_backward);
		PUT_INT(co, "late", c, late);
		PUT_INT(co, "auth_failed", c, auth_failed);
		PUT_INT(co, "refused", c, refused);
		PUT_INT(co, "fallbacks", c, fallbacks);
		put(o, "counters", co);
	}
	return (o);
}

/* arcana-stamp's state, into d (a's); false when the agent has none. */
static bool
stamp_get(cbl_conn *conn, struct arcana_stamp *d, cbl_yarena *a, char *err,
    size_t errlen)
{
	const struct cbl_ynode	*n;

	memset(d, 0, sizeof(*d));
	if ((n = yq_top("arcana-stamp", "stamp")) == NULL) {
		snprintf(err, errlen, "arcana-stamp is not in the tables");
		return (false);
	}
	return (yq_get(conn, n, CBL_YDS_OPERATIONAL, d, a, err, errlen) ==
	    0 && d->stamp != NULL);
}

/*
 * arcana-stamp's sessions into the read's targets, each its "stamp"
 * (a target measured by ICMP alone has none); an agent without the
 * module is read as before.
 */
static void
stamp_facts(cbl_conn *conn, ucl_object_t *top, cbl_yarena *a)
{
	const struct arcana_stamp_session	*s;
	struct arcana_stamp			 d;
	ucl_object_t				*e;
	ucl_object_iter_t			 it;
	char					 err[128];

	if (!stamp_get(conn, &d, a, err, sizeof(err)))
		return;
	for (size_t i = 0; i < d.stamp->session.n; i++) {
		s = &d.stamp->session.v[i];
		it = NULL;
		while ((e = (ucl_object_t *)(uintptr_t)ucl_object_iterate(
		    ucl_object_lookup(top, "targets"), &it, true)) != NULL) {
			if (str(e, "id") == NULL || s->target == NULL ||
			    strcmp(str(e, "id"), s->target) != 0 ||
			    (str(e, "jail") != NULL) != (s->jail != NULL) ||
			    (s->jail != NULL && strcmp(str(e, "jail"),
			    s->jail) != 0) || (str(e, "class") != NULL) !=
			    (s->class != NULL) || (s->class != NULL &&
			    strcmp(str(e, "class"), s->class) != 0))
				continue;
			put(e, "stamp", stamp_obj(s));
			break;
		}
	}
}

int
ysdwan_stamp(cbl_conn *conn, ucl_object_t **data, char *err, size_t errlen)
{
	const struct arcana_stamp_stamp_sender		*sn;
	const struct arcana_stamp_stamp_reflector	*rf;
	struct arcana_stamp				 d;
	ucl_object_t					*top, *o, *arr;
	cbl_yarena					*a;

	*data = NULL;
	err[0] = '\0';
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if (!stamp_get(conn, &d, a, err, errlen)) {
		cbl_yarena_free(a);
		return (err[0] != '\0' ? EIO : ENOENT);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	if ((sn = d.stamp->sender) != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		PUT_INT(o, "port", sn, port);
		PUT_NAME(o, "clock_source", sn, clock_source, stamp_clocks);
		if (sn->has_clock_error)
			put(o, "clock_error", dec(sn->clock_error, 3));
		PUT_YES(o, "clock_synchronised", sn, clock_synchronised);
		put_str(o, "clock_set", sn->clock_set);
		put(top, "sender", o);
	}
	if ((rf = d.stamp->reflector) != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		PUT_YES(o, "installed", rf, installed);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < rf->fib.n; i++)
			ucl_array_append(arr, ucl_object_fromint(rf->fib.v[i]));
		put(o, "fibs", arr);
		put_str(o, "key_file", rf->key_file);
		PUT_INT(o, "keys", rf, keys);
		put_str(o, "status", rf->status);
		put(top, "reflector", o);
	}
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < d.stamp->session.n; i++)
		ucl_array_append(arr, stamp_obj(&d.stamp->session.v[i]));
	put(top, "sessions", arr);
	*data = top;
	cbl_yarena_free(a);
	return (0);
}

int
ysdwan_read(cbl_conn *conn, bool has_after, uint64_t after,
    ucl_object_t **data, char *err, size_t errlen)
{
	struct arcana_probe_probes_read_input	 in;
	struct arcana_probe_probes_read_output	 rd;
	const struct cbl_ynode			*ns, *np, *act;
	struct arcana_sdwan			 sd;
	struct arcana_probe			 pr;
	struct tm				 tm;
	time_t					 t;
	cbl_yarena				*a;
	char					 when[32];
	int					 error;

	*data = NULL;
	err[0] = '\0';
	if ((ns = yq_top("arcana-sdwan", "sdwan")) == NULL || (np =
	    yq_top("arcana-probe", "probes")) == NULL || (act = yq_child(np,
	    "read")) == NULL) {
		snprintf(err, errlen, "arcana-sdwan is not in the tables");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&sd, 0, sizeof(sd));
	memset(&pr, 0, sizeof(pr));
	memset(&in, 0, sizeof(in));
	memset(&rd, 0, sizeof(rd));
	/* The targets as they are, the samples after the time alone, by
	 * the probes' read; their settings, running's. */
	t = (time_t)after;
	if (has_after && gmtime_r(&t, &tm) != NULL && strftime(when,
	    sizeof(when), "%Y-%m-%dT%H:%M:%SZ", &tm) > 0)
		in.after = when;
	if ((error = yq_get(conn, np, CBL_YDS_RUNNING, &pr, a, err,
	    errlen)) == 0 && (error = yq_call(conn, np, NULL, act, &in, &rd, a,
	    err, errlen)) == 0 && (error = yq_get(conn, ns,
	    CBL_YDS_OPERATIONAL, &sd, a, err, errlen)) == 0) {
		*data = read_json(sd.sdwan, pr.probes, &rd);
		steer_why(conn, *data, a);
		stamp_facts(conn, *data, a);
	}
	cbl_yarena_free(a);
	return (error);
}
