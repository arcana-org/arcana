/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * kmsg: the kernel's line for a program that died of a signal, as the
 * event and the fault kmsg.c makes of it, for agent_test.sh.  Each
 * line of the standard input is "<seconds> <the kernel's line>", or
 * "sweep <seconds>"; "open <seconds> <object>", a crash fault an agent
 * before left open, last said then, and "adopt", the start's taking
 * them up; or "find <was> grew|wrapped <tail> <buffer>", where the tail
 * of the last read (which ended at was) ends in the buffer read now ("|"
 * a line's end in both).  What the events and faults are told is printed in
 * their place, one line each, and where the tail ends as "found <at>"
 * or "found none".
 */

#include <sys/param.h>

#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"

struct opts	opts;

/* The faults open, as faults.c keeps them: a type and an object; and
 * when each was last said. */
static char	open_faults[16][160];
static time_t	open_at[16];
static int	nopen;

static int
find(const char *type, const char *object)
{
	char	key[160];
	int	i;

	snprintf(key, sizeof(key), "%s %s", type, object);
	for (i = 0; i < nopen; i++)
		if (strcmp(open_faults[i], key) == 0)
			return (i);
	return (-1);
}

void
event_add(const char *kind, const char *fmt, ...)
{
	va_list	ap;

	printf("event %s ", kind);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

void
fault_set(const char *type, const char *severity, const char *object,
    const char *by, const char *fmt, ...)
{
	va_list	ap;

	if (find(type, object) >= 0) {
		printf("set again %s %s\n", type, object);
		return;
	}
	if (nopen < 16) {
		open_at[nopen] = 0;
		snprintf(open_faults[nopen++], sizeof(open_faults[0]), "%s %s",
		    type, object);
	}
	printf("set %s %s %s %s: ", type, severity, object, by);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

bool
fault_update(const char *type, const char *object, const char *fmt, ...)
{
	va_list	ap;

	if (find(type, object) < 0)
		return (false);
	printf("update %s %s: ", type, object);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	return (true);
}

void
fault_clear(const char *type, const char *object, const char *fmt, ...)
{
	va_list	ap;
	int	i;

	if ((i = find(type, object)) < 0) {
		printf("clear of none %s %s\n", type, object);
		return;
	}
	memmove(open_faults[i], open_faults[i + 1], sizeof(open_faults[0]) *
	    (size_t)(nopen - i - 1));
	memmove(&open_at[i], &open_at[i + 1], sizeof(open_at[0]) *
	    (size_t)(nopen - i - 1));
	nopen--;
	printf("clear %s %s: ", type, object);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

/* The open crash faults, as faults.c tells an owner its own. */
int
faults_open(const char *by __unused, const char *type,
    void (*fn)(const char *, time_t, void *), void *arg)
{
	size_t	tl = strlen(type);
	int	i, n;

	for (i = n = 0; i < nopen; i++)
		if (strncmp(open_faults[i], type, tl) == 0 &&
		    open_faults[i][tl] == ' ') {
			fn(open_faults[i] + tl + 1, open_at[i], arg);
			n++;
		}
	return (n);
}

/* What an event's strings are put in with: quotes and backslashes
 * escaped, as the test's lines have them. */
const char *
json_quote(const char *s, char *buf, size_t len)
{
	size_t	n;

	for (n = 0; *s != '\0' && n + 3 < len; s++) {
		if (*s == '"' || *s == '\\')
			buf[n++] = '\\';
		buf[n++] = *s;
	}
	buf[n] = '\0';
	return (buf);
}

void
logmsg(int level __unused, const char *fmt __unused, ...)
{
}

/* "|" as a line's end. */
static void
lines(char *s)
{

	for (; *s != '\0'; s++)
		if (*s == '|')
			*s = '\n';
}

char *
wstrdup(struct work *w __unused, const char *s)
{

	return (strdup(s));
}

void *
wcalloc(struct work *w __unused, size_t n, size_t size)
{

	return (calloc(n, size));
}

int
main(void)
{
	char	*line, *p;
	size_t	 cap;
	ssize_t	 len;
	long	 t;

	line = NULL;
	cap = 0;
	while ((len = getline(&line, &cap, stdin)) > 0) {
		if (line[len - 1] == '\n')
			line[len - 1] = '\0';
		if (strncmp(line, "sweep ", 6) == 0) {
			kmsg_crash_sweep((time_t)strtol(line + 6, NULL, 10));
			continue;
		}
		if (strcmp(line, "adopt") == 0) {
			kmsg_crash_adopt();
			continue;
		}
		if (strncmp(line, "open ", 5) == 0) {
			t = strtol(line + 5, &p, 10);
			if (*p != ' ' || nopen == 16)
				errx(1, "not a line of the test: %s", line);
			open_at[nopen] = (time_t)t;
			snprintf(open_faults[nopen++], sizeof(open_faults[0]),
			    "crash %s", p + 1);
			continue;
		}
		if (strncmp(line, "find ", 5) == 0) {
			char		*tail, *buf, *grew;
			const char	*at;

			t = strtol(line + 5, &p, 10);
			if (*p != ' ' || strsep(&p, " ") == NULL ||
			    (grew = strsep(&p, " ")) == NULL ||
			    (tail = strsep(&p, " ")) == NULL || (buf = p) == NULL)
				errx(1, "not a line of the test: %s", line);
			lines(tail);
			lines(buf);
			at = kmsg_find(buf, strlen(buf), tail, strlen(tail),
			    (size_t)t, strcmp(grew, "grew") == 0);
			if (at == NULL)
				printf("found none\n");
			else
				printf("found %td\n", at - buf);
			continue;
		}
		if (strncmp(line, "core ", 5) == 0) {
			char	*comm;
			int	 uid;

			p = line + 5;
			if ((comm = strsep(&p, " ")) == NULL || p == NULL)
				errx(1, "not a line of the test: %s", line);
			t = strtol(p, NULL, 10);
			if (kmsg_core_dumped(comm, (int)t, &uid))
				printf("core of %s %ld: uid %d\n", comm, t, uid);
			else
				printf("no core of %s %ld\n", comm, t);
			continue;
		}
		t = strtol(line, &p, 10);
		if (p == line || *p != ' ')
			errx(1, "not a line of the test: %s", line);
		if (!kmsg_crash_line(p + 1, (time_t)t))
			printf("not a crash: %s\n", p + 1);
	}
	free(line);
	return (0);
}
