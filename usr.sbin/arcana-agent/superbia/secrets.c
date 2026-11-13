/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Superbia's secrets: what in a text, a command line or a name says it
 * holds a password, a key or a token, and the text with each such value
 * shown as <hidden>.  One place for every reader: a trace's argv
 * (exec.c), a job's title and its steps' details (jobs.c), a bundle's
 * files (bundle.c), and the reads open to every role, given masked to
 * a principal below the clearance a secret needs (clearance(),
 * ynacm.c).
 *
 * A value is hidden when
 * - it is NAME=value (+= and -= too), NAME saying it is a secret
 *   (secret_name()): an rc.conf line, a sysrc argument, --token=...;
 * - it follows a word that announces one: password, pass (carp(4)),
 *   psk, authkey, -k (speederv2), a dash option whose name says it is
 *   one (--password x); or key, secret, token, bearer, words of prose
 *   as often, when what follows looks like one (quoted, or eight
 *   characters and more with a digit);
 * - it is a URL's password (scheme://user:<hidden>@host) or a query's
 *   parameter whose name says it is one (?oinkcode=<hidden>);
 * - it is a long hexadecimal number, 0x and 16 digits or more
 *   (setkey(8)'s manual keys);
 * - it is authorized_keys' command="..." or environment="...", whole.
 * A quoted value of a NAME="..." that is no secret by its name is
 * looked into, word by word (ifconfig_em0="... pass <hidden> ...");
 * OpenSMTPD's inline table (table name { ... }) is hidden whole.  The
 * marker is the trace's, MASK_MARK.  ucl_mask() does it to every
 * string of a reply's JSON.
 */

#include <sys/param.h>

#include <ctype.h>
#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

#include "agent.h"

/*
 * Does the variable name, n bytes of it, say it holds a secret: a
 * password, a key, a token (rc.conf's, a form's)?
 */
bool
secret_name(const char *s, size_t n)
{
	static const char *const says[] = { "pass", "secret", "key", "token",
	    "psk", "cred", "oink" };
	char	name[128];
	size_t	i;

	(void)snprintf(name, sizeof(name), "%.*s", (int)n, s);
	for (i = 0; i < nitems(says); i++)
		if (strcasestr(name, says[i]) != NULL)
			return (true);
	return (false);
}

/*
 * Is a NAME=value (or += and -=) whose NAME says it holds a secret
 * (sysrc of a password, a key, a token)?  *keep is how much of it is
 * shown, the name and its = sign.
 */
bool
secret_assign(const char *a, size_t *keep)
{
	const char	*eq;
	size_t		 n, i;

	if ((eq = strchr(a, '=')) == NULL || eq == a)
		return (false);
	n = (size_t)(eq - a);
	*keep = n + 1;
	if (a[n - 1] == '+' || a[n - 1] == '-')
		n--;
	for (i = 0; i < n; i++)
		if (!isalnum((unsigned char)a[i]) && a[i] != '_' && a[i] != '.' &&
		    a[i] != '-')
			return (false);
	return (secret_name(a, n));
}

/* What a token says of the one after it. */
#define	NEXT_NONE	0
#define	NEXT_HIDE	1	/* -k <hidden>, password <hidden> */
#define	NEXT_EQUALS	2	/* PrivateKey = <hidden>, only past an = */
#define	NEXT_WEAK	3	/* key <hidden>, if it looks like one */

/*
 * A word that says the next one is a secret: NEXT_HIDE where it always
 * is (password, pass, psk, authkey, -k, a dash option whose name says
 * so), NEXT_WEAK where the word is as often prose (key, secret, token,
 * bearer); NEXT_NONE.
 */
static int
announces(const char *t, size_t n)
{
	static const char *const strong[] = { "password", "passwd", "pass",
	    "psk", "authkey", "-k" };
	static const char *const weak[] = { "secret", "key", "token",
	    "bearer" };
	size_t	i, k;

	for (i = 0; i < nitems(strong); i++)
		if (strlen(strong[i]) == n && strncasecmp(t, strong[i], n) == 0)
			return (NEXT_HIDE);
	for (i = 0; i < nitems(weak); i++)
		if (strlen(weak[i]) == n && strncasecmp(t, weak[i], n) == 0)
			return (NEXT_WEAK);
	/* An option: -password, --auth-token, no value of its own. */
	if (n > 2 && t[0] == '-' && memchr(t, '=', n) == NULL) {
		for (k = 1; k < n; k++)
			if (!isalnum((unsigned char)t[k]) && t[k] != '-' &&
			    t[k] != '_')
				return (NEXT_NONE);
		return (secret_name(t, n) ? NEXT_HIDE : NEXT_NONE);
	}
	return (NEXT_NONE);
}

/* Does a token after a weak word look like a secret: quoted, or eight
 * characters or more with a digit among them? */
static bool
looks_secret(const char *t, size_t n)
{
	size_t	i;

	if (n > 2 && (t[0] == '"' || t[0] == '\''))
		return (true);
	if (n < 8)
		return (false);
	for (i = 0; i < n; i++)
		if (isdigit((unsigned char)t[i]))
			return (true);
	return (false);
}

/* Does argument a say the next one is a secret (-k, --password)? */
bool
secret_word(const char *a)
{

	return (announces(a, strlen(a)) == NEXT_HIDE);
}

/* The quote a token's text closes with, from its opening one; its end
 * when there is none. */
static size_t
quoted(const char *t, size_t n)
{
	size_t	i;

	for (i = 1; i < n; i++) {
		if (t[0] == '"' && t[i] == '\\' && i + 1 < n)
			i++;
		else if (t[i] == t[0])
			return (i);
	}
	return (n);
}

/* A token hidden: its quotes and what follows them (";", ",") kept. */
static void
put_hidden(FILE *f, const char *t, size_t n)
{
	size_t	q, e;

	if (n > 0 && (t[0] == '"' || t[0] == '\'')) {
		q = quoted(t, n);
		(void)fprintf(f, "%c%s", t[0], MASK_MARK);
		(void)fwrite(t + q, 1, n - q, f);
		return;
	}
	for (e = n; e > 0 && strchr(";,}", t[e - 1]) != NULL; e--)
		;
	(void)fputs(MASK_MARK, f);
	(void)fwrite(t + e, 1, n - e, f);
}

static void	mask_words(FILE *, const char *, size_t, bool *);

/* A URL's password and a query's secret parameters, hidden. */
static bool
put_url(FILE *f, const char *t, size_t n)
{
	const char	*s, *at, *colon, *slash, *q, *p, *e, *eq;
	bool		 hid;

	if ((s = memmem(t, n, "://", 3)) == NULL)
		return (false);
	hid = false;
	s += 3;
	slash = memchr(s, '/', (size_t)(t + n - s));
	if (slash == NULL)
		slash = t + n;
	at = memchr(s, '@', (size_t)(slash - s));
	colon = at != NULL ? memchr(s, ':', (size_t)(at - s)) : NULL;
	if (colon != NULL) {
		(void)fwrite(t, 1, (size_t)(colon + 1 - t), f);
		(void)fputs(MASK_MARK, f);
		p = at;
		hid = true;
	} else
		p = t;
	if ((q = memchr(p, '?', (size_t)(t + n - p))) == NULL) {
		(void)fwrite(p, 1, (size_t)(t + n - p), f);
		return (hid);
	}
	(void)fwrite(p, 1, (size_t)(q + 1 - p), f);
	for (p = q + 1; p < t + n; p = e) {
		e = p + strcspn(p, "&#\"' \t");
		if (e > t + n)
			e = t + n;
		eq = memchr(p, '=', (size_t)(e - p));
		if (eq != NULL && secret_name(p, (size_t)(eq - p))) {
			(void)fwrite(p, 1, (size_t)(eq + 1 - p), f);
			(void)fputs(MASK_MARK, f);
			hid = true;
		} else
			(void)fwrite(p, 1, (size_t)(e - p), f);
		if (e < t + n && *e == '&') {
			(void)fputc('&', f);
			e++;
		} else {
			(void)fwrite(e, 1, (size_t)(t + n - e), f);
			break;
		}
	}
	return (hid);
}

/* Is a value empty: nothing, "" or ''? */
static bool
empty(const char *v, size_t n)
{

	return (n == 0 || (n == 2 && (v[0] == '"' || v[0] == '\'') &&
	    v[1] == v[0]));
}

/* One token, *next what it says of the one after. */
static void
put_token(FILE *f, const char *t, size_t n, int *next, bool *hid)
{
	const char	*eq;
	char		 buf[256];
	size_t		 keep, q, k;

	*next = announces(t, n);
	if (*next == NEXT_NONE && strspn(t, "abcdefghijklmnopqrstuvwxyz"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") >= n && secret_name(t, n))
		*next = NEXT_EQUALS;
	if ((eq = memchr(t, '=', n)) != NULL && eq > t && eq[-1] != '!' &&
	    t[0] != '"' && t[0] != '\'') {
		keep = 0;
		k = (size_t)(eq + 1 - t);
		(void)snprintf(buf, sizeof(buf), "%.*s", (int)k, t);
		/* authorized_keys' command="..." and environment="...":
		 * what a forced command is given, a token as often as not. */
		if (strcasecmp(buf, "command=") == 0 || strcasecmp(buf,
		    "environment=") == 0)
			keep = k;
		if (k < sizeof(buf) && (keep > 0 || secret_assign(buf, &keep))) {
			(void)fwrite(t, 1, keep, f);
			if (empty(t + keep, n - keep))
				(void)fwrite(t + keep, 1, n - keep, f);
			else {
				put_hidden(f, t + keep, n - keep);
				*hid = true;
			}
			*next = NEXT_NONE;
			return;
		}
		if (k < n && (t[k] == '"' || t[k] == '\'')) {
			/* NAME="words": each looked at. */
			(void)fwrite(t, 1, k + 1, f);
			q = k + quoted(t + k, n - k);
			mask_words(f, t + k + 1, q - k - 1, hid);
			(void)fwrite(t + q, 1, n - q, f);
			*next = NEXT_NONE;
			return;
		}
	}
	if (n > 2 && (t[0] == '"' || t[0] == '\'')) {
		q = quoted(t, n);
		(void)fputc(t[0], f);
		mask_words(f, t + 1, q - 1, hid);
		(void)fwrite(t + q, 1, n - q, f);
		return;
	}
	if (put_url(f, t, n)) {
		*hid = true;
		return;
	}
	if (n >= 18 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X') &&
	    strspn(t + 2, "0123456789abcdefABCDEF") >= 16) {
		put_hidden(f, t, n);
		*hid = true;
		return;
	}
	(void)fwrite(t, 1, n, f);
}

/* Words of s, n bytes, separators kept as they are; a quoted part is
 * of one line. */
static void
mask_words(FILE *f, const char *s, size_t n, bool *hid)
{
	const char	*p, *e, *end, *le, *c;
	size_t		 q;
	int		 hide, next, table;

	hide = NEXT_NONE;
	table = 0;
	end = s + n;
	for (p = s; p < end; p = e) {
		if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
			(void)fputc(*p, f);
			e = p + 1;
			/* A line's end ends what a word announced. */
			if (*p == '\n')
				hide = NEXT_NONE;
			continue;
		}
		if ((le = memchr(p, '\n', (size_t)(end - p))) == NULL)
			le = end;
		/* A token: up to a blank, a quoted part whole. */
		for (e = p; e < le && *e != ' ' && *e != '\t' && *e != '\r';
		    e++)
			if (*e == '"' || *e == '\'') {
				q = quoted(e, (size_t)(le - e));
				if ((e += q) >= le) {
					e = le;
					break;
				}
			}
		if (hide == NEXT_EQUALS) {
			hide = NEXT_NONE;
			if (e - p == 1 && *p == '=') {
				/* "PrivateKey = <hidden>": past its = sign. */
				(void)fputc('=', f);
				hide = NEXT_HIDE;
				continue;
			}
		} else if (hide == NEXT_HIDE || hide == NEXT_WEAK) {
			if (!empty(p, (size_t)(e - p)) && strncmp(p, "--", 2) !=
			    0 && (hide == NEXT_HIDE || looks_secret(p, (size_t)(e -
			    p)))) {
				hide = NEXT_NONE;
				put_hidden(f, p, (size_t)(e - p));
				*hid = true;
				continue;
			}
		}
		/* OpenSMTPD's inline table, "table name { ... }": its
		 * contents, credentials as often as not. */
		if (table == 2 && *p == '{' && (c = memchr(p, '}', (size_t)(end -
		    p))) != NULL) {
			(void)fprintf(f, "{ %s }", MASK_MARK);
			*hid = true;
			e = c + 1;
			table = 0;
			continue;
		}
		table = table == 1 ? 2 : e - p == 5 && strncmp(p, "table", 5) ==
		    0 ? 1 : 0;
		put_token(f, p, (size_t)(e - p), &next, hid);
		hide = next;
	}
}

/*
 * o, a reply's JSON, with each string's secrets masked (text_mask()),
 * in place.
 */
void
ucl_mask(ucl_object_t *o)
{
	ucl_object_iter_t	 it;
	ucl_object_t		*c, *old;
	char			**keys, **m, *t;
	size_t			 i, k, cap;
	bool			 hid;

	if (o == NULL)
		return;
	if (ucl_object_type(o) == UCL_ARRAY) {
		for (i = 0; i < ucl_array_size(o); i++) {
			c = __DECONST(ucl_object_t *, ucl_array_find_index(o,
			    i));
			if (ucl_object_type(c) != UCL_STRING) {
				ucl_mask(c);
				continue;
			}
			t = text_mask(ucl_object_tostring(c), &hid);
			if (t != NULL && hid && (old = ucl_array_replace_index(
			    o, ucl_object_fromstring(t), (unsigned)i)) != NULL)
				ucl_object_unref(old);
			free(t);
		}
		return;
	}
	if (ucl_object_type(o) != UCL_OBJECT)
		return;
	/* Replaced once the walk is done. */
	keys = m = NULL;
	k = cap = 0;
	it = NULL;
	while ((c = __DECONST(ucl_object_t *, ucl_object_iterate(o, &it,
	    true))) != NULL) {
		if (ucl_object_type(c) != UCL_STRING) {
			ucl_mask(c);
			continue;
		}
		if ((t = text_mask(ucl_object_tostring(c), &hid)) == NULL)
			err(1, "malloc");
		if (!hid) {
			free(t);
			continue;
		}
		if (k == cap) {
			cap = cap == 0 ? 8 : cap * 2;
			keys = reallocf(keys, cap * sizeof(*keys));
			m = reallocf(m, cap * sizeof(*m));
			if (keys == NULL || m == NULL)
				err(1, "malloc");
		}
		if ((keys[k] = strdup(ucl_object_key(c))) == NULL)
			err(1, "malloc");
		m[k++] = t;
	}
	for (i = 0; i < k; i++) {
		(void)ucl_object_replace_key(o, ucl_object_fromstring(m[i]),
		    keys[i], 0, true);
		free(keys[i]);
		free(m[i]);
	}
	free(keys);
	free(m);
}

/*
 * s with each secret's value as MASK_MARK (above); *hidp, when not
 * NULL, says whether there was one.  Allocated; NULL when out of memory.
 */
char *
text_mask(const char *s, bool *hidp)
{
	FILE	*f;
	char	*out;
	size_t	 len;
	bool	 hid;

	hid = false;
	if ((f = open_memstream(&out, &len)) == NULL)
		return (NULL);
	mask_words(f, s, strlen(s), &hid);
	if (fclose(f) != 0) {
		free(out);
		return (NULL);
	}
	if (hidp != NULL)
		*hidp = hid;
	return (out);
}

/* text_mask() in w's, s itself where nothing was hidden; NULL as NULL. */
const char *
wmask(struct work *w, const char *s)
{
	char	*m;
	bool	 hid;

	if (s == NULL || (m = text_mask(s, &hid)) == NULL)
		return (s);
	if (!hid) {
		free(m);
		return (s);
	}
	return (wadopt(w, m));
}

/*
 * A reply's JSON with each string's secrets masked (ucl_mask()), w's;
 * NULL when it is no JSON.
 */
const char *
wjson_mask(struct work *w, const char *json)
{
	struct ucl_parser	*p;
	ucl_object_t		*top;
	unsigned char		*out;

	if ((p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS)) == NULL)
		return (NULL);
	if (!ucl_parser_add_string(p, json, 0) || (top =
	    ucl_parser_get_object(p)) == NULL) {
		ucl_parser_free(p);
		return (NULL);
	}
	ucl_parser_free(p);
	ucl_mask(top);
	out = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	return (out != NULL ? wadopt(w, out) : NULL);
}

/*
 * A URL whose path may be a secret (a rule source's code in it): its
 * scheme and host alone, the rest MASK_MARK; s itself when it has no
 * path.  w's.
 */
const char *
wurl(struct work *w, const char *s)
{
	const char	*h, *p;

	if ((h = strstr(s, "://")) == NULL)
		return (wmask(w, s));
	h += 3;
	h += strcspn(h, "/?#");
	if (*h == '\0' || ((*h == '/') && h[1] == '\0'))
		return (wmask(w, s));
	/* user:password@ before the host, masked by text_mask(). */
	p = wmask(w, wstrndup(w, s, (size_t)(h - s)));
	return (wfmt(w, "%s/%s", p, MASK_MARK));
}

/*
 * Does a text hold a secret by what it says (text_mask() would hide
 * something)?  Such a file is withheld from a bundle unless secrets are
 * asked for, as a secret's place is: its text is no use with the
 * secret masked.
 */
bool
text_secret(const char *text)
{
	char	*m;
	bool	 hid;

	if ((m = text_mask(text, &hid)) == NULL)
		return (true);
	free(m);
	return (hid);
}

/*
 * s, words separated by spaces, with each secret's value hidden: a
 * job's title.  Allocated; NULL when out of memory.
 */
char *
mask_secrets(const char *s)
{

	return (text_mask(s, NULL));
}
