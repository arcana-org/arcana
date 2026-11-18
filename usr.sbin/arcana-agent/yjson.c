/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * An operation's JSON object read back into a YANG module's structs:
 * what the converters of the operations that answer in JSON share
 * (ystorage.c, ysystem.c); and a container's whole by the schema's
 * tables, a form's members named as its nodes (ysd.c).
 */

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "yjson.h"

/* json parsed; NULL: not JSON. */
ucl_object_t *
yj_parse(const char *json)
{
	struct ucl_parser *p;
	ucl_object_t *top = NULL;

	if (json == NULL || (p = ucl_parser_new(UCL_PARSER_NO_TIME)) == NULL)
		return (NULL);
	if (ucl_parser_add_string(p, json, 0))
		top = ucl_parser_get_object(p);
	ucl_parser_free(p);
	return (top);
}

/* A string of o's, the arena's; NULL: none. */
const char *
yj_str(cbl_yarena *a, const ucl_object_t *o, const char *key)
{
	const ucl_object_t *v = ucl_object_lookup(o, key);
	const char *t;
	size_t len;
	char *p;

	if (v == NULL || ucl_object_type(v) != UCL_STRING ||
	    (t = ucl_object_tostring(v)) == NULL)
		return (NULL);
	len = strlen(t) + 1;
	if ((p = cbl_yarena_alloc(a, len)) != NULL)
		memcpy(p, t, len);
	return (p);
}

/* A number of o's; false: none. */
bool
yj_num(const ucl_object_t *o, const char *key, int64_t *v)
{
	const ucl_object_t *x = ucl_object_lookup(o, key);

	if (x == NULL || (ucl_object_type(x) != UCL_INT &&
	    ucl_object_type(x) != UCL_FLOAT))
		return (false);
	*v = ucl_object_toint(x);
	return (true);
}

/* A number of o's, a float or an integer, in hundredths; false: none. */
bool
yj_hundredths(const ucl_object_t *o, const char *key, int64_t *v)
{
	const ucl_object_t *x = ucl_object_lookup(o, key);
	double d;

	if (x == NULL || (ucl_object_type(x) != UCL_INT &&
	    ucl_object_type(x) != UCL_FLOAT))
		return (false);
	d = ucl_object_todouble(x) * 100;
	*v = (int64_t)(d + (d < 0 ? -0.5 : 0.5));
	return (true);
}

/* true, "yes", "on": true; false, "no", "off": false; else none. */
bool
yj_yes(const ucl_object_t *o, const char *key, bool *has)
{
	const ucl_object_t *x = ucl_object_lookup(o, key);
	const char *t;

	*has = false;
	if (x == NULL)
		return (false);
	if (ucl_object_type(x) == UCL_BOOLEAN) {
		*has = true;
		return (ucl_object_toboolean(x));
	}
	if ((t = ucl_object_tostring(x)) == NULL)
		return (false);
	if (strcmp(t, "yes") == 0 || strcmp(t, "on") == 0) {
		*has = true;
		return (true);
	}
	if (strcmp(t, "no") == 0 || strcmp(t, "off") == 0)
		*has = true;
	return (false);
}

size_t
yj_count(const ucl_object_t *arr)
{

	return (arr != NULL && ucl_object_type(arr) == UCL_ARRAY ?
	    arr->len : 0);
}

/* An array of strings, the arena's. */
int
yj_strs(cbl_yarena *a, const ucl_object_t *arr, size_t *n,
    const char *const **v)
{
	const ucl_object_t *e;
	ucl_object_iter_t it;
	const char **p;
	size_t k = 0;

	*n = 0;
	*v = NULL;
	if (yj_count(arr) == 0)
		return (0);
	if ((p = cbl_yarena_alloc(a, yj_count(arr) * sizeof(*p))) == NULL)
		return (ENOMEM);
	YJ_EACH(arr, it, e) {
		const char *t;
		size_t len;
		char *c;

		if ((t = ucl_object_tostring(e)) == NULL)
			continue;
		len = strlen(t) + 1;
		if ((c = cbl_yarena_alloc(a, len)) == NULL)
			return (ENOMEM);
		memcpy(c, t, len);
		p[k++] = c;
	}
	*n = k;
	*v = p;
	return (0);
}

/* ---- A container's tree, by the schema's tables ----------------------- */

#define	YJ_AT(p, off)	((void *)((char *)(p) + (off)))
#define	YJ_DEPTH	16

struct yj_arr {
	size_t		 n;
	const void	*v;
};

/* The child of n a member names: its name, or its name with a _ for
 * each - (the setters' spelling of some). */
static const struct cbl_ynode *
yj_child(const struct cbl_ynode *n, const char *key)
{
	const char	*c;
	size_t		 i;

	for (uint32_t k = 0; key != NULL && k < n->nchild; k++) {
		c = n->child[k]->name;
		for (i = 0; c[i] != '\0' && (c[i] == key[i] || (c[i] == '-' &&
		    key[i] == '_')); i++)
			;
		if (c[i] == '\0' && key[i] == '\0')
			return (n->child[k]);
	}
	return (NULL);
}

/* A scalar of JSON as leaf or leaf-list n's value into out: 0, or what
 * does not parse. */
static int
yj_value(const struct cbl_ynode *n, const ucl_object_t *v, void *out,
    cbl_yarena *a)
{
	const char	*t;
	size_t		 len;
	char		*s;

	switch (ucl_object_type(v)) {
	case UCL_STRING:
	case UCL_INT:
	case UCL_FLOAT:
		t = ucl_object_tostring_forced(v);
		break;
	case UCL_BOOLEAN:
		t = ucl_object_toboolean(v) ? "true" : "false";
		break;
	default:
		return (EINVAL);
	}
	/* The parser keeps a string as it is: the arena's copy. */
	len = strlen(t) + 1;
	if ((s = cbl_yarena_alloc(a, len)) == NULL)
		return (ENOMEM);
	memcpy(s, t, len);
	return (cbl_yvalue_parse(n, n->type, s, out, a));
}

static int	yj_fill(const struct cbl_ynode *, const ucl_object_t *, void *,
		    cbl_yarena *, int);

/* Member c of p's struct from v. */
static int
yj_member(const struct cbl_ynode *c, const ucl_object_t *v, void *p,
    cbl_yarena *a, int depth)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct yj_arr		*arr;
	size_t			 cnt, k;
	char			*q;
	void			*s;
	int			 error;

	switch (c->kind) {
	case CBL_YN_CONTAINER:
		if (ucl_object_type(v) != UCL_OBJECT)
			return (0);
		if ((s = cbl_yarena_alloc(a, c->size)) == NULL)
			return (ENOMEM);
		if ((error = yj_fill(c, v, s, a, depth + 1)) != 0)
			return (error);
		*(void **)YJ_AT(p, c->off) = s;
		return (0);
	case CBL_YN_LIST:
	case CBL_YN_LEAFLIST:
		if ((cnt = yj_count(v)) == 0)
			return (0);
		arr = YJ_AT(p, c->off);
		if ((q = cbl_yarena_alloc(a, cnt * (c->kind == CBL_YN_LIST ?
		    c->size : c->type->csize))) == NULL)
			return (ENOMEM);
		k = 0;
		YJ_EACH(v, it, e) {
			if (c->kind == CBL_YN_LIST) {
				if (ucl_object_type(e) != UCL_OBJECT)
					continue;
				if ((error = yj_fill(c, e, q + k * c->size, a,
				    depth + 1)) != 0)
					return (error);
				k++;
			} else if ((error = yj_value(c, e, q + k *
			    c->type->csize, a)) == 0)
				k++;
			else if (error == ENOMEM)
				return (error);
		}
		arr->n = k;
		arr->v = q;
		return (0);
	case CBL_YN_LEAF:
		if ((error = yj_value(c, v, YJ_AT(p, c->off), a)) != 0)
			return (error == ENOMEM ? error : 0);
		if (c->hoff != CBL_YOFF_NONE)
			*(bool *)YJ_AT(p, c->hoff) = true;
		return (0);
	default:
		return (0);
	}
}

/* n's children in its struct p, from the members of o. */
static int
yj_fill(const struct cbl_ynode *n, const ucl_object_t *o, void *p,
    cbl_yarena *a, int depth)
{
	const struct cbl_ynode	*c;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	int			 error;

	if (depth > YJ_DEPTH)
		return (0);
	YJ_EACH(o, it, v) {
		if ((c = yj_child(n, ucl_object_key(v))) == NULL ||
		    c->choice != NULL || (c->flags & CBL_YNF_CONFIG) == 0)
			continue;
		if ((error = yj_member(c, v, p, a, depth)) != 0)
			return (error);
	}
	return (0);
}

/* JSON object o as the struct of container n, allocated in a; what is
 * not of the node, or not of its type, left out; NULL when o is no
 * object, or there is no memory for it. */
void *
yj_tree(const struct cbl_ynode *n, const ucl_object_t *o, cbl_yarena *a)
{
	void	*p;

	if (n == NULL || o == NULL || ucl_object_type(o) != UCL_OBJECT ||
	    (p = cbl_yarena_alloc(a, n->size)) == NULL)
		return (NULL);
	if (yj_fill(n, o, p, a, 0) != 0)
		return (NULL);
	return (p);
}

/* Container n's struct p as RFC 7951's JSON object; NULL where p is. */
ucl_object_t *
yj_untree(const struct cbl_ynode *n, const void *p)
{
	struct cbl_ybuf	 b = { NULL, 0, 0 };
	ucl_object_t	*o;
	char		*text;

	if (n == NULL || p == NULL || cbl_yjson(n, p, &b) != 0 ||
	    (text = malloc(b.len + 1)) == NULL) {
		cbl_ybuf_free(&b);
		return (NULL);
	}
	memcpy(text, b.p, b.len);
	text[b.len] = '\0';
	cbl_ybuf_free(&b);
	o = yj_parse(text);
	free(text);
	return (o);
}

/* A module's node by its path of names ("sdwan", "bird-instance", ...,
 * NULL), in tables s; NULL: none. */
const struct cbl_ynode *
yj_node(const struct cbl_yschema *s, const char *module, ...)
{
	const struct cbl_ynode	*n = NULL, *c;
	const char		*name;
	va_list			 ap;

	for (uint32_t i = 0; i < s->nmod && n == NULL; i++) {
		if (strcmp(s->mod[i]->name, module) != 0)
			continue;
		va_start(ap, module);
		name = va_arg(ap, const char *);
		for (uint32_t k = 0; name != NULL && k < s->mod[i]->ntop; k++)
			if (strcmp(s->mod[i]->top[k]->name, name) == 0)
				n = s->mod[i]->top[k];
		while (n != NULL && (name = va_arg(ap, const char *)) != NULL) {
			c = NULL;
			for (uint32_t k = 0; k < n->nchild; k++)
				if (strcmp(n->child[k]->name, name) == 0)
					c = n->child[k];
			n = c;
		}
		va_end(ap);
	}
	return (n);
}
