/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Building markup.  h_raw() takes literal markup from this program;
 * anything that came from the network goes through h_txt(), h_attr()
 * or h_fmt()'s %s, which escape it.  h_rawf() is h_fmt() for this
 * program's own markup alone (make check-html holds its arguments to
 * literals), h_strf() for what is not markup at all.
 */

#include <sys/types.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static void	grow(struct html *, size_t);

static void
grow(struct html *h, size_t n)
{

	if (h->len + n + 1 <= h->cap)
		return;
	while (h->len + n + 1 > h->cap)
		h->cap = h->cap == 0 ? 8192 : h->cap * 2;
	if ((h->s = realloc(h->s, h->cap)) == NULL)
		abort();
}

void
h_raw(struct html *h, const char *s)
{
	size_t	n;

	n = strlen(s);
	grow(h, n);
	memcpy(h->s + h->len, s, n + 1);
	h->len += n;
}

/*
 * Text that must fit a box drawn for it: at most max characters, the
 * last an ellipsis when there were more.
 */
void
h_fit(struct html *h, const char *s, int max)
{
	char		 cut[256];
	const char	*p;
	int		 n;

	if (s == NULL)
		return;
	for (n = 0, p = s; *p != '\0'; p++)
		if (((unsigned char)*p & 0xc0) != 0x80)
			n++;
	if (n <= max) {
		h_txt(h, s);
		return;
	}
	for (n = 0, p = s; *p != '\0'; p++) {
		if (((unsigned char)*p & 0xc0) != 0x80 && ++n == max)
			break;
	}
	snprintf(cut, sizeof(cut), "%.*s", (int)(p - s), s);
	h_txt(h, cut);
	h_raw(h, "…");
}

void
h_txt(struct html *h, const char *s)
{
	char	c[2];

	if (s == NULL)
		return;
	c[1] = '\0';
	for (; *s != '\0'; s++) {
		switch (*s) {
		case '&':
			h_raw(h, "&amp;");
			break;
		case '<':
			h_raw(h, "&lt;");
			break;
		case '>':
			h_raw(h, "&gt;");
			break;
		case '"':
			h_raw(h, "&quot;");
			break;
		case '\'':
			h_raw(h, "&#39;");
			break;
		default:
			c[0] = *s;
			h_raw(h, c);
			break;
		}
	}
}

/*
 * The conversion at f, its argument taken from ap: a %s escaped as
 * h_txt() does unless raw, the rest as printf(3) writes them.  -Wformat
 * checked the arguments at the call.
 */
static const char *
conv(struct html *h, const char *f, va_list *ap, bool raw)
{
	char		 spec[64], *s;
	const char	*p;
	size_t		 n;
	int		 lng, star, r;

	n = 0;
	spec[n++] = '%';
	lng = 0;
	for (p = f + 1; *p != '\0' && n < sizeof(spec) - 16; p++) {
		if (*p == '*') {
			/* A width or a precision given: written in. */
			star = va_arg(*ap, int);
			if (spec[n - 1] == '.' && star < 0)
				n--;	/* a negative precision is none */
			else
				n += snprintf(spec + n, sizeof(spec) - n, "%d",
				    star);
			continue;
		}
		if (strchr("-+ #0123456789.", *p) != NULL) {
			spec[n++] = *p;
			continue;
		}
		if (*p == 'h' || *p == 'L')
			continue;
		if (*p == 'l' || *p == 'q') {
			lng++;
			spec[n++] = 'l';
			continue;
		}
		if (*p == 'j' || *p == 'z' || *p == 't') {
			lng = *p;
			spec[n++] = *p;
			continue;
		}
		break;
	}
	spec[n++] = *p;
	spec[n] = '\0';
	switch (*p) {
	case 's':
		r = asprintf(&s, spec, va_arg(*ap, const char *));
		break;
	case 'c':
		r = asprintf(&s, spec, va_arg(*ap, int));
		break;
	case 'd':
	case 'i':
		if (lng == 'j')
			r = asprintf(&s, spec, va_arg(*ap, intmax_t));
		else if (lng == 'z')
			r = asprintf(&s, spec, va_arg(*ap, ssize_t));
		else if (lng == 't')
			r = asprintf(&s, spec, va_arg(*ap, ptrdiff_t));
		else if (lng >= 2)
			r = asprintf(&s, spec, va_arg(*ap, long long));
		else if (lng == 1)
			r = asprintf(&s, spec, va_arg(*ap, long));
		else
			r = asprintf(&s, spec, va_arg(*ap, int));
		break;
	case 'o':
	case 'u':
	case 'x':
	case 'X':
		if (lng == 'j')
			r = asprintf(&s, spec, va_arg(*ap, uintmax_t));
		else if (lng == 'z')
			r = asprintf(&s, spec, va_arg(*ap, size_t));
		else if (lng == 't')
			r = asprintf(&s, spec, va_arg(*ap, ptrdiff_t));
		else if (lng >= 2)
			r = asprintf(&s, spec, va_arg(*ap,
			    unsigned long long));
		else if (lng == 1)
			r = asprintf(&s, spec, va_arg(*ap, unsigned long));
		else
			r = asprintf(&s, spec, va_arg(*ap, unsigned int));
		break;
	case 'a':
	case 'A':
	case 'e':
	case 'E':
	case 'f':
	case 'F':
	case 'g':
	case 'G':
		r = asprintf(&s, spec, va_arg(*ap, double));
		break;
	case 'p':
		r = asprintf(&s, spec, va_arg(*ap, void *));
		break;
	case '%':
		r = asprintf(&s, "%%");
		break;
	default:
		/* %n, or what this program does not write. */
		abort();
	}
	if (r == -1)
		abort();
	if (*p == 's' && !raw)
		h_txt(h, s);
	else
		h_raw(h, s);
	free(s);
	return (p + 1);
}

static void
vfmt(struct html *h, const char *fmt, va_list ap, bool raw)
{
	va_list		 aq;
	const char	*p;
	size_t		 n;

	va_copy(aq, ap);
	while (*fmt != '\0') {
		if ((p = strchr(fmt, '%')) == NULL) {
			h_raw(h, fmt);
			break;
		}
		if ((n = (size_t)(p - fmt)) > 0) {
			grow(h, n);
			memcpy(h->s + h->len, fmt, n);
			h->len += n;
			h->s[h->len] = '\0';
		}
		fmt = conv(h, p, &aq, raw);
	}
	va_end(aq);
}

/*
 * Markup: the format is this program's, each %s an argument escaped
 * (as text, or a quoted attribute's value alike).
 */
void
h_fmt(struct html *h, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vfmt(h, fmt, ap, false);
	va_end(ap);
}

/*
 * Markup whose %s are this program's markup too: literals, or what
 * make check-html allows them to be (tools/check-html.awk).
 */
void
h_rawf(struct html *h, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vfmt(h, fmt, ap, true);
	va_end(ap);
}

/*
 * Not markup: JSON, a configuration file, a line kept in a struct html,
 * never drawn as markup.  A string from the network goes into JSON by
 * h_json().
 */
void
h_strf(struct html *h, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vfmt(h, fmt, ap, true);
	va_end(ap);
}

/*
 * s in a URL: every byte but the unreserved (RFC 3986 section 2.3)
 * percent-encoded, as rc_key() does in a buffer; safe in an attribute.
 */
void
h_url(struct html *h, const char *s)
{
	static const char	hex[] = "0123456789ABCDEF";
	char			e[4];

	for (; s != NULL && *s != '\0'; s++) {
		if ((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
		    (*s >= '0' && *s <= '9') || strchr("-._~", *s) != NULL) {
			e[0] = *s;
			e[1] = '\0';
		} else {
			e[0] = '%';
			e[1] = hex[(unsigned char)*s >> 4];
			e[2] = hex[(unsigned char)*s & 15];
			e[3] = '\0';
		}
		h_raw(h, e);
	}
}

/* s as a JSON string, quoted. */
void
h_json(struct html *h, const char *s)
{
	char	*q;

	q = json_quote(s);
	h_raw(h, q);
	free(q);
}

/*
 * s where a class name is built from it: as it is when it is a plain
 * word, def otherwise.
 */
const char *
h_word(const char *s, const char *def)
{
	const char	*p;

	if (s == NULL || *s == '\0')
		return (def);
	for (p = s; *p != '\0'; p++)
		if ((*p < 'a' || *p > 'z') && *p != '-')
			return (def);
	return (s);
}

/* name="value", value escaped. */
void
h_attr(struct html *h, const char *name, const char *value)
{

	h_raw(h, " ");
	h_raw(h, name);
	h_raw(h, "=\"");
	h_txt(h, value != NULL ? value : "");
	h_raw(h, "\"");
}

char *
h_take(struct html *h)
{
	char	*s;

	grow(h, 0);
	s = h->s;
	memset(h, 0, sizeof(*h));
	return (s);
}

void
h_reset(struct html *h)
{

	h->len = 0;
	if (h->s != NULL)
		h->s[0] = '\0';
}
