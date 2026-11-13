/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * mask: secrets.c's masking alone, for agent_test.sh.  The standard
 * input whole, printed as text_mask() makes it; with -u, each line a
 * URL as wurl() makes it; with -s, "secret" or "none" by text_secret().
 */

#include <sys/param.h>

#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "agent.h"

struct opts	opts;

/* work.c's, as much as secrets.c takes: nothing freed, a run's life. */
void *
wadopt(struct work *w, void *p)
{

	(void)w;
	return (p);
}

char *
wstrndup(struct work *w, const char *s, size_t n)
{
	char	*p;

	(void)w;
	if ((p = strndup(s, n)) == NULL)
		err(1, "strndup");
	return (p);
}

char *
wfmt(struct work *w, const char *fmt, ...)
{
	va_list	 ap;
	char	*p;

	(void)w;
	va_start(ap, fmt);
	if (vasprintf(&p, fmt, ap) == -1)
		err(1, "vasprintf");
	va_end(ap);
	return (p);
}

int
main(int argc, char **argv)
{
	char	*buf, *m, *line;
	size_t	 len, cap;
	ssize_t	 n;
	int	 ch;
	bool	 url, secret;

	url = secret = false;
	while ((ch = getopt(argc, argv, "su")) != -1)
		switch (ch) {
		case 's':
			secret = true;
			break;
		case 'u':
			url = true;
			break;
		default:
			errx(2, "usage: mask [-s | -u] < text");
		}
	cap = 4096;
	len = 0;
	if ((buf = malloc(cap)) == NULL)
		err(1, "malloc");
	while ((n = read(STDIN_FILENO, buf + len, cap - len - 1)) > 0)
		if ((len += (size_t)n) == cap - 1 && (buf = realloc(buf,
		    cap *= 2)) == NULL)
			err(1, "realloc");
	buf[len] = '\0';
	if (secret) {
		printf("%s\n", text_secret(buf) ? "secret" : "none");
		return (0);
	}
	if (url) {
		while ((line = strsep(&buf, "\n")) != NULL)
			if (line[0] != '\0')
				printf("%s\n", wurl(NULL, line));
		return (0);
	}
	if ((m = text_mask(buf, NULL)) == NULL)
		err(1, "text_mask");
	fputs(m, stdout);
	return (0);
}
