/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Text fit to be shown: valid UTF-8 with no control character, C0, DEL
 * or C1 (U+0080 to U+009F, which a terminal takes as ESC and the like),
 * a tab and a newline aside unless it is a name (a host's, a jail's, an
 * interface's description: one line).  What is not fit is escaped as
 * vis(3) VIS_CSTYLE | VIS_OCTAL would: vis(3) leaves a byte that is no
 * UTF-8 as it is, and is of the locale; this is of neither.  No
 * allocation, nothing else of the agent's: the collectors' tests link it.
 */

#include <sys/types.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "textfit.h"

/* The length of the UTF-8 character s begins with, whole and the
 * shortest form; 0 when it is none.  *cp its code point. */
static size_t
utf8_char(const unsigned char *s, unsigned int *cp)
{
	unsigned int	c;
	size_t		n, i;

	if (s[0] < 0x80) {
		*cp = s[0];
		return (1);
	}
	if (s[0] >= 0xc2 && s[0] <= 0xdf) {
		n = 2;
		c = s[0] & 0x1fU;
	} else if (s[0] >= 0xe0 && s[0] <= 0xef) {
		n = 3;
		c = s[0] & 0x0fU;
	} else if (s[0] >= 0xf0 && s[0] <= 0xf4) {
		n = 4;
		c = s[0] & 0x07U;
	} else
		return (0);
	for (i = 1; i < n; i++) {
		if ((s[i] & 0xc0) != 0x80)
			return (0);
		c = c << 6 | (s[i] & 0x3fU);
	}
	/* Overlong, a surrogate, beyond U+10FFFF. */
	if ((n == 3 && (c < 0x800 || (c >= 0xd800 && c <= 0xdfff))) ||
	    (n == 4 && (c < 0x10000 || c > 0x10ffff)))
		return (0);
	*cp = c;
	return (n);
}

static bool
control(unsigned int c, bool name)
{

	return ((c < 0x20 && (name || (c != '\t' && c != '\n'))) ||
	    (c >= 0x7f && c < 0xa0));
}

bool
text_fit(const char *s, bool name)
{
	const unsigned char	*p;
	unsigned int		 c;
	size_t			 n;

	for (p = (const unsigned char *)s; *p != '\0'; p += n)
		if ((n = utf8_char(p, &c)) == 0 || control(c, name))
			return (false);
	return (true);
}

/* s escaped into out, 4 * strlen(s) + 1 bytes; out. */
char *
text_vis(char *out, const char *s, bool name)
{
	const unsigned char	*p;
	unsigned int		 c;
	size_t			 n, i;
	char			*o;

	o = out;
	for (p = (const unsigned char *)s; *p != '\0'; p += n) {
		if ((n = utf8_char(p, &c)) == 0) {
			o += sprintf(o, "\\%03o", *p);
			n = 1;
		} else if (c == '\\')
			o = stpcpy(o, "\\\\");
		else if (c == '\n' && name)
			o = stpcpy(o, "\\n");
		else if (c == '\t' && name)
			o = stpcpy(o, "\\t");
		else if (control(c, name))
			for (i = 0; i < n; i++)
				o += sprintf(o, "\\%03o", p[i]);
		else {
			memcpy(o, p, n);
			o += n;
		}
	}
	*o = '\0';
	return (out);
}
