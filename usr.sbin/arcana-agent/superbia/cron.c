/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * cron(8), of the host or of a running jail (the read's jail, the job's):
 * every entry of the system crontab (/etc/crontab), of the files of the
 * cron.d directories cron reads (/etc/cron.d, /usr/local/etc/cron.d,
 * those whose names start with a dot left out as cron leaves them) and
 * of each user's crontab, as crontab -l -u prints it for each user
 * /var/cron/tabs has one of; with its schedule, user, command, file and
 * the comment line above it (arcana-cron's read).
 *
 * Arcana writes two places alone.  Its own file, /usr/local/etc/cron.d/
 * arcana, which cron reads by itself (it looks at the cron.d
 * directories' and files' times each minute): its entries are in the
 * system format, a user field after the schedule.  And a user's
 * crontab, between Arcana's markers, by crontab(1) alone (crontab -u
 * user -, the crontab whole on its standard input, the lines outside
 * the markers as they were); never /var/cron/tabs' files themselves.
 * The admin's /etc/crontab, the other cron.d files and a crontab's
 * lines outside the markers are read and never written.  A jail's are
 * read and written beneath its root, never through a link out of it
 * (scope.c), its users' crontabs by its own crontab(1), through
 * jexec(8); its users are its own passwd(5)'s.
 *
 * Each entry's next three runs are worked out from its fields in the
 * time zone cron has there: /etc/localtime, a jail's beneath its root
 * (its links followed as the jail sees them).  The agent cannot change
 * its own time zone (TZ is the process's, its threads share it), so the
 * helper does it (cron_next_helper()): the zone's file on its standard
 * input, the schedules its words.  The variables a file sets (SHELL=,
 * MAILTO=) are read with its entries; Arcana sets its own at the top of
 * its file, or just after its first marker in a crontab, before its
 * entries, so that they are the environment of each of them.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	CRON_SYSTAB	"/etc/crontab"
#define	CRON_FILE	"/usr/local/etc/cron.d/arcana"
#define	CRON_TABS	"/var/cron/tabs"
#define	CRON_TEXT_MAX	(256 * 1024)
#define	CRON_LINE_MAX	1000
#define	CRON_NOTE_MAX	200

/* The directories cron(8) reads besides /etc/crontab, in its order. */
static const char *const cron_dirs[] = { "/etc/cron.d",
    "/usr/local/etc/cron.d" };

/* Arcana's markers in a user's crontab: its entries between them. */
#define	CRON_BEGIN	"# BEGIN arcana"
#define	CRON_BEGIN_LINE	CRON_BEGIN ": entries of Arcana's, written by " \
			"crontab(1); changed from Arcana"
#define	CRON_END	"# END arcana"

/* What Arcana's file begins with. */
#define	CRON_HEAD	"# Arcana's cron entries: cron(8) reads this file " \
			"by itself.\n# Written by arcana-agent; changed " \
			"from Arcana, not here.\n"

/* The special strings a schedule may be (crontab(5)). */
static const char *const cron_at[] = { "@reboot", "@yearly", "@annually",
    "@monthly", "@weekly", "@daily", "@midnight", "@hourly",
    "@every_minute", "@every_second" };

static const char *const cron_months[] = { "jan", "feb", "mar", "apr",
    "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec" };
static const char *const cron_days[] = { "sun", "mon", "tue", "wed",
    "thu", "fri", "sat" };

/* An entry's line taken apart. */
struct centry {
	const char	*schedule;	/* its time fields, a space between */
	const char	*user;		/* the system format's, or NULL */
	const char	*command;
};

/* A file where it is: the host's (under -r's root), or a jail's own
 * path, which scope.c opens beneath the jail's root. */
static const char *
rooted(struct work *w, const char *path)
{

	if (w->jail != NULL)
		return (path);
	return (opts.root != NULL ? wfmt(w, "%s%s", opts.root, path) : path);
}

/* The file Arcana's entries are in, for a safe change. */
const char *
cron_path(struct work *w)
{

	return (rooted(w, CRON_FILE));
}

static void
put_s(ucl_object_t *o, const char *k, const char *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(v), k, 0, true);
}

/* A user's name as passwd(5) and crontab(1) take it. */
static bool
cron_user_ok(const char *u)
{

	return (u != NULL && u[0] != '\0' && u[0] != '-' && strlen(u) <= 32 &&
	    strspn(u, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "0123456789._-") == strlen(u));
}

/* One line of printable characters (a tab too), n bytes at most. */
static bool
cron_one_line(const char *s, size_t n)
{
	const unsigned char	*p;

	if (s == NULL || strlen(s) > n)
		return (false);
	for (p = (const unsigned char *)s; *p != '\0'; p++)
		if ((*p < 0x20 && *p != '\t') || *p == 0x7f)
			return (false);
	return (true);
}

/* A number of a field, or a name of it (a month's, a day's). */
static bool
cron_value(const char *s, size_t len, int lo, int hi,
    const char *const *names, size_t nnames, bool *named)
{
	size_t	i;
	int	v;

	*named = false;
	if (len == 0)
		return (false);
	if (isdigit((unsigned char)s[0])) {
		v = 0;
		for (i = 0; i < len; i++) {
			if (!isdigit((unsigned char)s[i]) || i > 3)
				return (false);
			v = v * 10 + (s[i] - '0');
		}
		return (v >= lo && v <= hi);
	}
	for (i = 0; i < nnames; i++)
		if (len == 3 && strncasecmp(s, names[i], 3) == 0) {
			*named = true;
			return (true);
		}
	return (false);
}

/*
 * A time field of crontab(5): items between commas, each * or a value
 * or a range of two, with a /step after * or a range; a name (a month's
 * or a day's) alone, never in a range or with a step.
 */
static bool
cron_field(const char *f, int lo, int hi, const char *const *names,
    size_t nnames)
{
	const char	*item, *end, *slash, *dash;
	size_t		 len;
	bool		 named, named2;

	for (item = f; ; item = end + 1) {
		end = strchr(item, ',');
		len = end != NULL ? (size_t)(end - item) : strlen(item);
		if (len == 0)
			return (false);
		slash = memchr(item, '/', len);
		if (slash != NULL) {
			bool	n2;

			if (!cron_value(slash + 1, len - (size_t)(slash + 1 -
			    item), 1, hi > 0 ? hi : 1, NULL, 0, &n2) || n2)
				return (false);
			len = (size_t)(slash - item);
		}
		if (len == 1 && item[0] == '*')
			;
		else if ((dash = memchr(item, '-', len)) != NULL) {
			if (!cron_value(item, (size_t)(dash - item), lo, hi,
			    names, nnames, &named) || !cron_value(dash + 1,
			    len - (size_t)(dash + 1 - item), lo, hi, names,
			    nnames, &named2) || named || named2)
				return (false);
		} else if (!cron_value(item, len, lo, hi, names, nnames,
		    &named) || (named && slash != NULL))
			return (false);
		if (end == NULL)
			return (true);
	}
}

/* A schedule: five time fields, or one of the special strings. */
static bool
cron_schedule_ok(char *const *f, size_t n)
{
	size_t	i;

	if (n == 1 && f[0][0] == '@') {
		for (i = 0; i < nitems(cron_at); i++)
			if (strcmp(f[0], cron_at[i]) == 0)
				return (true);
		/* @ and seconds: that long after the last run ended. */
		return (f[0][1] != '\0' && strlen(f[0]) <= 10 &&
		    strspn(f[0] + 1, "0123456789") == strlen(f[0] + 1));
	}
	return (n == 5 && cron_field(f[0], 0, 59, NULL, 0) &&
	    cron_field(f[1], 0, 23, NULL, 0) &&
	    cron_field(f[2], 1, 31, NULL, 0) &&
	    cron_field(f[3], 1, 12, cron_months, nitems(cron_months)) &&
	    cron_field(f[4], 0, 7, cron_days, nitems(cron_days)));
}

/*
 * A line taken apart: its schedule's words, then (sys, the system
 * format) the user, then the command, the rest of it as it is.  -1 when
 * it is no entry.
 */
static int
cron_split(struct work *w, const char *line, bool sys, struct centry *e)
{
	const char	*p, *q, *words[6];
	size_t		 lens[6], n, k, want;
	char		*s;

	p = line + strspn(line, " \t");
	want = p[0] == '@' ? 1 : 5;
	for (n = 0; n < want + (sys ? 1 : 0); n++) {
		q = p + strcspn(p, " \t");
		if (q == p)
			return (-1);
		words[n] = p;
		lens[n] = (size_t)(q - p);
		p = q + strspn(q, " \t");
	}
	if (*p == '\0')
		return (-1);
	/* The schedule, a space between its words. */
	for (k = 0, s = NULL; k < want; k++)
		s = wfmt(w, "%s%s%.*s", s != NULL ? s : "", k > 0 ? " " : "",
		    (int)lens[k], words[k]);
	e->schedule = s;
	e->user = sys ? wstrndup(w, words[want], lens[want]) : NULL;
	/* The command, its trailing blanks off. */
	k = strlen(p);
	while (k > 0 && (p[k - 1] == ' ' || p[k - 1] == '\t' || p[k - 1] ==
	    '\r'))
		k--;
	e->command = wstrndup(w, p, k);
	return (0);
}

/* Is the line an entry, a comment, a variable's or blank? */
enum { CL_BLANK, CL_COMMENT, CL_VAR, CL_ENTRY, CL_OTHER };

static int
cron_kind(const char *line)
{
	const char	*p;

	p = line + strspn(line, " \t");
	if (*p == '\0' || *p == '\r')
		return (CL_BLANK);
	if (*p == '#')
		return (CL_COMMENT);
	if (*p == '@' || *p == '*' || isdigit((unsigned char)*p))
		return (CL_ENTRY);
	if (strchr(p, '=') != NULL)
		return (CL_VAR);
	return (CL_OTHER);
}

/* A comment's text, its # and the blank after it off. */
static const char *
cron_note(struct work *w, const char *line)
{
	const char	*p;
	size_t		 k;

	p = line + strspn(line, " \t") + 1;
	p += strspn(p, " \t");
	k = strlen(p);
	while (k > 0 && (p[k - 1] == ' ' || p[k - 1] == '\t' || p[k - 1] ==
	    '\r'))
		k--;
	return (wstrndup(w, p, k));
}

/* Is a comment line one of Arcana's own (its file's head, its
 * markers), which says nothing of the entry below it? */
static bool
cron_ours(const char *line)
{
	const char	*p;

	p = line + strspn(line, " \t");
	return (strncmp(p, CRON_BEGIN, strlen(CRON_BEGIN)) == 0 ||
	    strncmp(p, CRON_END, strlen(CRON_END)) == 0 ||
	    strncmp(p, "# Arcana's cron entries:", 24) == 0 ||
	    strncmp(p, "# Written by arcana-agent;", 26) == 0);
}

/*
 * text's entries onto list: of source, in file, run as user (a
 * crontab's owner) or each line's own (sys); Arcana's those of its file
 * (all) or between its markers.
 */
/*
 * A variable's line taken apart as cron(8) reads it (load_env()): its
 * name, blanks and =, its value, either quoted to keep its blanks.
 * false when it is none.
 */
static bool
cron_var(struct work *w, const char *line, const char **namep,
    const char **valuep)
{
	const char	*p, *q;
	size_t		 k;

	p = line + strspn(line, " \t");
	if (*p == '"' || *p == '\'') {
		if ((q = strchr(p + 1, *p)) == NULL)
			return (false);
		*namep = wstrndup(w, p + 1, (size_t)(q - p - 1));
		p = q + 1;
	} else {
		q = p + strcspn(p, "= \t");
		*namep = wstrndup(w, p, (size_t)(q - p));
		p = q;
	}
	p += strspn(p, " \t");
	if (*p != '=' || (*namep)[0] == '\0')
		return (false);
	p++;
	p += strspn(p, " \t");
	k = strlen(p);
	while (k > 0 && (p[k - 1] == ' ' || p[k - 1] == '\t' || p[k - 1] ==
	    '\r'))
		k--;
	if (k >= 2 && (p[0] == '"' || p[0] == '\'') && p[k - 1] == p[0]) {
		p++;
		k -= 2;
	}
	*valuep = wstrndup(w, p, k);
	return (true);
}

static void
cron_entries(struct work *w, ucl_object_t *list, ucl_object_t *vars,
    const char *text, const char *source, const char *file,
    const char *user, bool sys, bool all)
{
	const char	*vname, *vvalue;
	struct centry	 e;
	ucl_object_t	*o;
	const char	*note, *p, *nl;
	char		*line;
	uint32_t	 n;
	bool		 inside;

	note = NULL;
	inside = false;
	for (p = text, n = 1; *p != '\0'; p = nl != NULL ? nl + 1 :
	    p + strlen(p), n++) {
		nl = strchr(p, '\n');
		line = wstrndup(w, p, nl != NULL ? (size_t)(nl - p) :
		    strlen(p));
		switch (cron_kind(line)) {
		case CL_COMMENT:
			if (strncmp(line + strspn(line, " \t"), CRON_BEGIN,
			    strlen(CRON_BEGIN)) == 0)
				inside = true;
			else if (strncmp(line + strspn(line, " \t"), CRON_END,
			    strlen(CRON_END)) == 0)
				inside = false;
			note = cron_ours(line) ? NULL : cron_note(w, line);
			continue;
		case CL_ENTRY:
			break;
		case CL_VAR:
			note = NULL;
			if (vars == NULL || !cron_var(w, line, &vname, &vvalue))
				continue;
			o = ucl_object_typed_new(UCL_OBJECT);
			put_s(o, "source", source);
			put_s(o, "file", file);
			ucl_object_insert_key(o, ucl_object_fromint(n), "line",
			    0, false);
			if (!sys)
				put_s(o, "user", user);
			put_s(o, "name", wtext(w, vname));
			put_s(o, "value", wtext(w, vvalue));
			ucl_object_insert_key(o, ucl_object_frombool(all ||
			    inside), "arcana", 0, false);
			ucl_array_append(vars, o);
			continue;
		default:
			note = NULL;
			continue;
		}
		if (cron_split(w, line, sys, &e) != 0) {
			note = NULL;
			continue;
		}
		o = ucl_object_typed_new(UCL_OBJECT);
		put_s(o, "source", source);
		put_s(o, "file", file);
		ucl_object_insert_key(o, ucl_object_fromint(n), "line", 0,
		    false);
		put_s(o, "schedule", wtext(w, e.schedule));
		put_s(o, "user", wtext(w, sys ? e.user : user));
		put_s(o, "command", wtext(w, e.command));
		if (note != NULL && note[0] != '\0')
			put_s(o, "comment", wtext(w, note));
		ucl_object_insert_key(o, ucl_object_frombool(all || inside),
		    "arcana", 0, false);
		ucl_array_append(list, o);
		note = NULL;
	}
}

/* A file of the host's or the jail's, whole; NULL with errno. */
static char *
cron_slurp(struct work *w, const char *path)
{
	char	*buf;
	size_t	 n;

	if ((buf = scope_slurp(w, rooted(w, path), &n)) != NULL &&
	    n > CRON_TEXT_MAX)
		buf[CRON_TEXT_MAX] = '\0';
	return (buf);
}

static int
cron_cmp(const void *a, const void *b)
{

	return (strcmp(*(const char *const *)a, *(const char *const *)b));
}

/*
 * The names in a directory of the host's or the jail's, sorted: regular
 * files whose names do not start with a dot (as cron reads cron.d);
 * NULL with errno for none.
 */
static char **
cron_names(struct work *w, const char *dir, size_t *np)
{
	struct dirent	 *dp;
	struct stat	  sb;
	DIR		 *d;
	char		**v;
	size_t		  n, cap;
	int		  fd;

	*np = 0;
	if ((fd = scope_dirfd(w, rooted(w, dir))) == -1)
		return (NULL);
	if ((d = fdopendir(fd)) == NULL) {
		close(fd);
		return (NULL);
	}
	v = NULL;
	n = cap = 0;
	while ((dp = readdir(d)) != NULL) {
		if (dp->d_name[0] == '.' || fstatat(dirfd(d), dp->d_name, &sb,
		    AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(sb.st_mode))
			continue;
		v = wgrow(w, v, n, &cap, sizeof(*v));
		v[n++] = wstrdup(w, dp->d_name);
	}
	closedir(d);
	if (v == NULL)
		v = wcalloc(w, 1, sizeof(*v));
	qsort(v, n, sizeof(*v), cron_cmp);
	*np = n;
	return (v);
}

/*
 * A user's crontab as crontab -l -u prints it (crontab(1) leaves out
 * the head it wrote), of the host or by the jail's own crontab(1):
 * *textp, "" and *hadp false when the user has none.  -1 and *errp.
 */
static int
cron_tab_read(struct work *w, const char *user, const char **textp,
    bool *hadp, const char **errp)
{
	struct execres	 res;
	char		*argv[5];

	*textp = "";
	*hadp = false;
	argv[0] = (char *)(uintptr_t)opts.crontab_bin;
	argv[1] = (char *)(uintptr_t)"-l";
	argv[2] = (char *)(uintptr_t)"-u";
	argv[3] = (char *)(uintptr_t)user;
	argv[4] = NULL;
	if (run_read_max(w, scope_jexec(w, argv), &res, CRON_TEXT_MAX) == 0 &&
	    res.status == 0) {
		*textp = res.out != NULL ? res.out : "";
		*hadp = true;
		return (0);
	}
	if (res.err != NULL && strstr(res.err, "no crontab for") != NULL)
		return (0);
	*errp = wtext(w, exec_error(w, &res, wfmt(w, "crontab -l -u %s%s%s",
	    user, w->jail != NULL ? " in " : "", w->jail != NULL ? w->jail :
	    "")));
	return (-1);
}

/*
 * A user's crontab made text by crontab(1), the jail's own in a jail;
 * text NULL, or nothing but blank lines, has it removed (crontab -r
 * -f).  -1 and *errp.
 */
static int
cron_tab_write(struct work *w, const char *user, const char *text,
    const char **errp)
{
	struct execres	 res;
	const char	*p;
	char		*argv[6];
	int		 rc;

	for (p = text; p != NULL && *p != '\0' && strchr(" \t\r\n", *p) !=
	    NULL; p++)
		;
	argv[0] = (char *)(uintptr_t)opts.crontab_bin;
	argv[1] = (char *)(uintptr_t)"-u";
	argv[2] = (char *)(uintptr_t)user;
	if (p == NULL || *p == '\0') {
		argv[3] = (char *)(uintptr_t)"-r";
		argv[4] = (char *)(uintptr_t)"-f";
		argv[5] = NULL;
		if (run_exec(w, scope_jexec(w, argv), &res) == 0 &&
		    res.status == 0)
			return (0);
		/* None to remove: as asked. */
		if (res.err != NULL && strstr(res.err, "no crontab for") !=
		    NULL)
			return (0);
		*errp = wtext(w, exec_error(w, &res, wfmt(w, "crontab -u %s "
		    "-r", user)));
		return (-1);
	}
	argv[3] = (char *)(uintptr_t)"-";
	argv[4] = NULL;
	exec_set_stdin(text, strlen(text));
	rc = run_exec(w, scope_jexec(w, argv), &res);
	exec_set_stdin(NULL, 0);
	if (rc == 0 && res.status == 0)
		return (0);
	*errp = wtext(w, exec_error(w, &res, wfmt(w, "crontab -u %s -%s%s",
	    user, w->jail != NULL ? " in " : "", w->jail != NULL ? w->jail :
	    "")));
	return (-1);
}

/* rc.conf's cron, of the host or the jail: its own service(8) asked
 * there, through jexec. */
static ucl_object_t *
cron_daemon(struct work *w)
{
	struct execres	 res;
	ucl_object_t	*o;
	char		*argv[4];
	bool		 running, enabled;

	if (w->jail == NULL)
		service_state(w, "cron", &running, &enabled);
	else {
		argv[0] = (char *)(uintptr_t)opts.service_bin;
		argv[1] = (char *)(uintptr_t)"cron";
		argv[2] = (char *)(uintptr_t)"onestatus";
		argv[3] = NULL;
		running = run_read(w, scope_jexec(w, argv), &res) == 0 &&
		    res.status == 0;
		argv[2] = (char *)(uintptr_t)"enabled";
		enabled = run_read(w, scope_jexec(w, argv), &res) == 0 &&
		    res.status == 0;
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_frombool(enabled), "enabled", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_frombool(running), "running", 0,
	    false);
	/* sysrc, run with -j in a jail (scope_argv()). */
	put_s(o, "flags", rc_get(w, "cron_flags"));
	return (o);
}

/* ---- When each entry runs next ---- */

#define	CRON_NEXT	3		/* runs worked out of each entry */
#define	CRON_NEXT_DAYS	3660		/* days looked at: ten years */
#define	CRON_TZ_MAX	(256 * 1024)	/* of a time zone's file */

/* A schedule as the times it matches. */
struct cbits {
	uint64_t	min;		/* 0-59 */
	uint32_t	hour;		/* 0-23 */
	uint32_t	dom;		/* 1-31 */
	uint32_t	mon;		/* 1-12 */
	uint32_t	dow;		/* 0-6, Sunday 0 (7 is 0 too) */
	bool		domstar;	/* the day of the month's field is *... */
	bool		dowstar;	/* the day of the week's */
};

/* What the @ strings are as five fields; NULL, ones of no time. */
static const char *const cron_at_fields[][2] = {
	{ "@yearly", "0 0 1 1 *" }, { "@annually", "0 0 1 1 *" },
	{ "@monthly", "0 0 1 * *" }, { "@weekly", "0 0 * * 0" },
	{ "@daily", "0 0 * * *" }, { "@midnight", "0 0 * * *" },
	{ "@hourly", "0 * * * *" }, { "@every_minute", "*/1 * * * *" },
};

/* A value of a field: a number, or a name (a month's 1-12, a day's
 * 0-6). -1 for none. */
static int
cron_num(const char *s, size_t len, const char *const *names, size_t nnames,
    int base)
{
	size_t	i;
	int	v;

	if (len == 0 || len > 4)
		return (-1);
	if (isdigit((unsigned char)s[0])) {
		for (i = 0, v = 0; i < len; i++) {
			if (!isdigit((unsigned char)s[i]))
				return (-1);
			v = v * 10 + (s[i] - '0');
		}
		return (v);
	}
	for (i = 0; i < nnames; i++)
		if (len == 3 && strncasecmp(s, names[i], 3) == 0)
			return ((int)i + base);
	return (-1);
}

/* A field's items as bits lo to hi: *, a value, a-b, each a /step
 * (a value with one, from it to hi); false when it is none. */
static bool
cron_bits(const char *f, size_t flen, int lo, int hi,
    const char *const *names, size_t nnames, int base, uint64_t *bits)
{
	const char	*item, *end, *fend, *slash, *dash;
	size_t		 len;
	int		 a, b, step, v;

	*bits = 0;
	fend = f + flen;
	for (item = f; item < fend; item = end + 1) {
		end = memchr(item, ',', (size_t)(fend - item));
		if (end == NULL)
			end = fend;
		len = (size_t)(end - item);
		step = 1;
		if ((slash = memchr(item, '/', len)) != NULL) {
			if ((step = cron_num(slash + 1, (size_t)(end - slash -
			    1), NULL, 0, 0)) <= 0)
				return (false);
			len = (size_t)(slash - item);
		}
		if (len == 1 && item[0] == '*') {
			a = lo;
			b = hi;
		} else if ((dash = memchr(item, '-', len)) != NULL) {
			a = cron_num(item, (size_t)(dash - item), names,
			    nnames, base);
			b = cron_num(dash + 1, len - (size_t)(dash + 1 - item),
			    names, nnames, base);
		} else {
			a = cron_num(item, len, names, nnames, base);
			b = slash != NULL ? hi : a;
		}
		if (a < lo || b > hi || a > b)
			return (false);
		for (v = a; v <= b; v += step)
			*bits |= UINT64_C(1) << v;
		if (end == fend)
			break;
	}
	return (true);
}

/* A schedule's fields as bits; false for none of a time (@reboot). */
static bool
cron_parse(const char *sched, struct cbits *cb)
{
	const char	*f[5], *p;
	size_t		 len[5], i;
	uint64_t	 b;

	memset(cb, 0, sizeof(*cb));
	p = sched + strspn(sched, " \t");
	if (*p == '@') {
		for (i = 0; i < nitems(cron_at_fields); i++)
			if (strcmp(p, cron_at_fields[i][0]) == 0)
				return (cron_parse(cron_at_fields[i][1], cb));
		return (false);
	}
	for (i = 0; i < 5; i++) {
		f[i] = p;
		len[i] = strcspn(p, " \t");
		if (len[i] == 0)
			return (false);
		p += len[i];
		p += strspn(p, " \t");
	}
	if (*p != '\0')
		return (false);
	if (!cron_bits(f[0], len[0], 0, 59, NULL, 0, 0, &cb->min))
		return (false);
	if (!cron_bits(f[1], len[1], 0, 23, NULL, 0, 0, &b))
		return (false);
	cb->hour = (uint32_t)b;
	if (!cron_bits(f[2], len[2], 1, 31, NULL, 0, 0, &b))
		return (false);
	cb->dom = (uint32_t)b;
	if (!cron_bits(f[3], len[3], 1, 12, cron_months, nitems(cron_months),
	    1, &b))
		return (false);
	cb->mon = (uint32_t)b;
	if (!cron_bits(f[4], len[4], 0, 7, cron_days, nitems(cron_days), 0,
	    &b))
		return (false);
	cb->dow = (uint32_t)(b | (b >> 7)) & 0x7f;
	/* cron(8)'s rule: a day field that starts with * leaves it to the
	 * other; both given, either day will do. */
	cb->domstar = f[2][0] == '*';
	cb->dowstar = f[4][0] == '*';
	return (true);
}

/* The next runs after now, in this process's time zone: up to max of
 * them in out, how many returned. */
static int
cron_next(const struct cbits *cb, time_t now, time_t *out, int max)
{
	struct tm	 cur, day, t;
	time_t		 tt;
	int		 d, h, m, n;
	bool		 domok, dowok;

	if (localtime_r(&now, &cur) == NULL)
		return (0);
	n = 0;
	for (d = 0; d < CRON_NEXT_DAYS && n < max; d++) {
		memset(&day, 0, sizeof(day));
		day.tm_year = cur.tm_year;
		day.tm_mon = cur.tm_mon;
		day.tm_mday = cur.tm_mday + d;
		day.tm_hour = 12;
		day.tm_isdst = -1;
		if (mktime(&day) == -1)
			continue;
		if ((cb->mon & (UINT32_C(1) << (day.tm_mon + 1))) == 0)
			continue;
		domok = (cb->dom & (UINT32_C(1) << day.tm_mday)) != 0;
		dowok = (cb->dow & (UINT32_C(1) << day.tm_wday)) != 0;
		if (cb->domstar || cb->dowstar ? !(domok && dowok) :
		    !(domok || dowok))
			continue;
		for (h = 0; h < 24 && n < max; h++) {
			if ((cb->hour & (UINT32_C(1) << h)) == 0)
				continue;
			for (m = 0; m < 60 && n < max; m++) {
				if ((cb->min & (UINT64_C(1) << m)) == 0)
					continue;
				t = day;
				t.tm_hour = h;
				t.tm_min = m;
				t.tm_sec = 0;
				t.tm_isdst = -1;
				if ((tt = mktime(&t)) == -1 || tt <= now)
					continue;
				/* An hour the clock skips: no such time. */
				if (t.tm_hour != h || t.tm_min != m)
					continue;
				if (n > 0 && tt <= out[n - 1])
					continue;
				out[n++] = tt;
			}
		}
	}
	return (n);
}

/* A time as RFC 3339 has it, in this process's time zone, its offset
 * after it. */
static void
cron_fmt(time_t tt, char *buf, size_t len)
{
	struct tm	tm;
	long		off;
	size_t		k;

	buf[0] = '\0';
	if (localtime_r(&tt, &tm) == NULL || (k = strftime(buf, len,
	    "%Y-%m-%dT%H:%M:%S", &tm)) == 0)
		return;
	off = tm.tm_gmtoff;
	snprintf(buf + k, len - k, "%c%02ld:%02ld", off < 0 ? '-' : '+',
	    labs(off) / 3600, labs(off) % 3600 / 60);
}

/*
 * The helper's cron-next (scope_helper(), of the host's alone): the time
 * zone's file on its standard input (none: UTC, as cron has it with no
 * /etc/localtime), the schedules its words.  It prints "zone ABBR
 * +hh:mm", then for each schedule its index and its next runs, a space
 * between them.  The file is written to a file of its own for TZ, this
 * process's alone, and taken away again.
 */
int
cron_next_helper(int argc, char **argv)
{
	struct cbits	 cb;
	struct tm	 tm;
	time_t		 now, t[CRON_NEXT];
	char		*buf, path[PATH_MAX], when[40], abbr[16];
	size_t		 len;
	ssize_t		 r;
	int		 fd, i, k, n;

	if ((buf = malloc(CRON_TZ_MAX)) == NULL)
		return (1);
	for (len = 0; len < CRON_TZ_MAX && (r = read(STDIN_FILENO, buf + len,
	    CRON_TZ_MAX - len)) > 0; len += (size_t)r)
		;
	path[0] = '\0';
	if (len > 0) {
		snprintf(path, sizeof(path), "%s/arcana-tz.XXXXXX", tmp_dir());
		if ((fd = mkstemp(path)) == -1 || write(fd, buf, len) !=
		    (ssize_t)len) {
			fprintf(stderr, "%s: %s\n", path, strerror(errno));
			if (fd != -1) {
				close(fd);
				unlink(path);
			}
			return (1);
		}
		close(fd);
		setenv("TZ", path, 1);
	} else
		setenv("TZ", "UTC0", 1);
	free(buf);
	tzset();
	now = time(NULL);
	if (localtime_r(&now, &tm) != NULL) {
		if (strftime(abbr, sizeof(abbr), "%Z", &tm) == 0)
			snprintf(abbr, sizeof(abbr), "UTC");
		cron_fmt(now, when, sizeof(when));
		printf("zone %s %s\n", abbr, strlen(when) > 19 ? when + 19 :
		    "+00:00");
	}
	for (i = 1; i < argc; i++) {
		n = cron_parse(argv[i], &cb) ? cron_next(&cb, now, t,
		    CRON_NEXT) : 0;
		printf("%d", i - 1);
		for (k = 0; k < n; k++) {
			cron_fmt(t[k], when, sizeof(when));
			printf(" %s", when);
		}
		printf("\n");
	}
	if (path[0] != '\0')
		unlink(path);
	return (fflush(stdout) == 0 ? 0 : 1);
}

/*
 * Each entry of list given its next runs (next_run) and top the time
 * zone they are in, by the helper: the zone's file opened here, the
 * host's or beneath the jail's root (its links as the jail sees them),
 * its standard input.  What goes wrong is said in unread.
 */
static void
cron_next_runs(struct work *w, ucl_object_t *top, ucl_object_t *list,
    ucl_object_t *unread)
{
	struct execres		 res;
	const ucl_object_t	*e;
	ucl_object_t		*o, *a;
	const char		**words, *sched;
	char			**argv, *out, *line, *v;
	size_t			 n, i, k, nw;
	int			 fd;

	n = ucl_array_size(list);
	if (n == 0)
		return;
	/* The schedules, each once. */
	words = wcalloc(w, n, sizeof(*words));
	nw = 0;
	for (i = 0; i < n; i++) {
		e = ucl_array_find_index(list, (unsigned)i);
		if ((sched = ucl_object_tostring(ucl_object_lookup(e,
		    "schedule"))) == NULL)
			continue;
		for (k = 0; k < nw && strcmp(words[k], sched) != 0; k++)
			;
		if (k == nw)
			words[nw++] = sched;
	}
	argv = wcalloc(w, nw + 5, sizeof(*argv));
	argv[0] = (char *)(uintptr_t)opts.helper_bin;
	argv[1] = (char *)(uintptr_t)"--scope-helper";
	argv[2] = (char *)(uintptr_t)"0";
	argv[3] = (char *)(uintptr_t)"cron-next";
	for (k = 0; k < nw; k++)
		argv[4 + k] = (char *)(uintptr_t)words[k];
	argv[4 + nw] = NULL;
	errno = 0;
	fd = scope_open_read(w, rooted(w, "/etc/localtime"));
	if (fd == -1 && errno != ENOENT) {
		ucl_array_append(unread, ucl_object_fromstring(wfmt(w,
		    "/etc/localtime: %s: the next runs not worked out",
		    strerror(errno))));
		return;
	}
	exec_set_fds(fd, -1);
	if (run_read(w, argv, &res) != 0 || res.status != 0) {
		if (fd != -1)
			close(fd);
		ucl_array_append(unread, ucl_object_fromstring(wtext(w,
		    exec_error(w, &res, "the next runs (cron-next)"))));
		return;
	}
	if (fd != -1)
		close(fd);
	out = wstrndup(w, res.out != NULL ? res.out : "", res.outlen);
	while ((line = strsep(&out, "\n")) != NULL) {
		if (strncmp(line, "zone ", 5) == 0) {
			put_s(top, "timezone", wtext(w, line + 5));
			continue;
		}
		if ((v = strchr(line, ' ')) == NULL)
			continue;
		*v++ = '\0';
		k = strtoul(line, NULL, 10);
		if (k >= nw)
			continue;
		/* Each entry of that schedule. */
		for (i = 0; i < n; i++) {
			e = ucl_array_find_index(list, (unsigned)i);
			sched = ucl_object_tostring(ucl_object_lookup(e,
			    "schedule"));
			if (sched == NULL || strcmp(sched, words[k]) != 0)
				continue;
			a = ucl_object_typed_new(UCL_ARRAY);
			{
				char	*vv = wstrdup(w, v), *t;

				while ((t = strsep(&vv, " ")) != NULL)
					if (t[0] != '\0')
						ucl_array_append(a,
						    ucl_object_fromstring(t));
			}
			o = (ucl_object_t *)(uintptr_t)e;
			ucl_object_insert_key(o, a, "next_run", 0, false);
		}
	}
}

/* The read: arcana-cron's, of the host or of the jail w works in. */
void
do_cron(struct work *w, struct json_rsp *rsp)
{
	ucl_object_t	*top, *list, *unread, *vars;
	const char	*tab, *path;
	char		*text, **names, *json;
	size_t		 i, k, n;
	bool		 had;

	rsp->has_ok = true;
	rsp->ok = false;
	top = ucl_object_typed_new(UCL_OBJECT);
	list = ucl_object_typed_new(UCL_ARRAY);
	unread = ucl_object_typed_new(UCL_ARRAY);
	vars = ucl_object_typed_new(UCL_ARRAY);
	put_s(top, "jail", w->jail);
	ucl_object_insert_key(top, cron_daemon(w), "daemon", 0, false);
	/* The system crontab. */
	if ((text = cron_slurp(w, CRON_SYSTAB)) != NULL)
		cron_entries(w, list, vars, text, "system", CRON_SYSTAB, NULL,
		    true, false);
	else if (errno != ENOENT)
		ucl_array_append(unread, ucl_object_fromstring(wfmt(w, "%s: %s",
		    CRON_SYSTAB, strerror(errno))));
	/* The cron.d directories', Arcana's file among them. */
	for (i = 0; i < nitems(cron_dirs); i++) {
		if ((names = cron_names(w, cron_dirs[i], &n)) == NULL) {
			if (errno != ENOENT)
				ucl_array_append(unread, ucl_object_fromstring(
				    wfmt(w, "%s: %s", cron_dirs[i],
				    strerror(errno))));
			continue;
		}
		for (k = 0; k < n; k++) {
			path = wfmt(w, "%s/%s", cron_dirs[i], names[k]);
			if ((text = cron_slurp(w, path)) == NULL) {
				ucl_array_append(unread, ucl_object_fromstring(
				    wfmt(w, "%s: %s", path, strerror(errno))));
				continue;
			}
			cron_entries(w, list, vars, text, "cron-d", path, NULL,
			    true, strcmp(path, CRON_FILE) == 0);
		}
	}
	/* The users' crontabs, each by crontab -l -u. */
	if ((names = cron_names(w, CRON_TABS, &n)) == NULL && errno != ENOENT)
		ucl_array_append(unread, ucl_object_fromstring(wfmt(w, "%s: %s",
		    CRON_TABS, strerror(errno))));
	for (k = 0; names != NULL && k < n; k++) {
		const char	*e = NULL;

		if (!cron_user_ok(names[k]))
			continue;
		if (cron_tab_read(w, names[k], &tab, &had, &e) != 0) {
			ucl_array_append(unread, ucl_object_fromstring(e));
			continue;
		}
		if (had)
			cron_entries(w, list, vars, tab, "user", wfmt(w,
			    "%s/%s", CRON_TABS, names[k]), names[k], false,
			    false);
	}
	cron_next_runs(w, top, list, unread);
	ucl_object_insert_key(top, list, "entry", 0, false);
	ucl_object_insert_key(top, vars, "variable", 0, false);
	if (ucl_array_size(unread) > 0)
		ucl_object_insert_key(top, unread, "unread", 0, false);
	else
		ucl_object_unref(unread);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL) {
		rsp->error = "out of memory";
		return;
	}
	rsp->json = wstrdup(w, json);
	free(json);
	rsp->ok = true;
}

/* ---- The cron job: an entry of Arcana's added, deleted, replaced ---- */

/* A line of an entry as a job gives it: the schedule's fields, then
 * (sys) a user, then a command; NULL, or what is wrong. */
static const char *
cron_line_check(const char *line, bool sys)
{
	char		*copy, *p, *f[6];
	size_t		 n, want;
	const char	*why;

	if (line == NULL || line[0] == '\0')
		return ("a cron entry is a line: its schedule, then the user "
		    "and the command (a crontab's, the command)");
	if (!cron_one_line(line, CRON_LINE_MAX))
		return ("a cron entry is one line of printable characters, "
		    "1000 at most");
	if ((copy = strdup(line)) == NULL)
		return ("out of memory");
	p = copy + strspn(copy, " \t");
	want = *p == '@' ? 1 : 5;
	for (n = 0; n < want + (sys ? 1 : 0); n++) {
		f[n] = p;
		p += strcspn(p, " \t");
		if (*p == '\0') {
			n++;
			break;
		}
		*p++ = '\0';
		p += strspn(p, " \t");
	}
	why = NULL;
	if (!cron_schedule_ok(f, n < want ? n : want))
		why = "a cron entry's schedule is five fields (minute 0-59, "
		    "hour 0-23, day of the month 1-31, month 1-12 or jan-dec, "
		    "day of the week 0-7 or sun-sat; each *, a value, a range "
		    "a-b, a list, a /step), or @reboot, @yearly, @annually, "
		    "@monthly, @weekly, @daily, @midnight, @hourly, "
		    "@every_minute, @every_second, or @ and seconds";
	else if (sys && (n < want + 1 || !cron_user_ok(f[want])))
		why = "an entry of Arcana's file names the user it runs as "
		    "after its schedule, then its command";
	else if (*p == '\0' || n < want + (sys ? 1 : 0))
		why = "a cron entry runs a command, after its schedule";
	free(copy);
	return (why);
}

/* Is the verb a variable's (setvar, unsetvar)? */
static bool
cron_isvar(const struct arc_job_spec *sp)
{

	return (strcmp(sp->verb, "setvar") == 0 || strcmp(sp->verb,
	    "unsetvar") == 0);
}

/* A variable's name as a job gives it: letters, digits and _, not a
 * digit first; LOGNAME and USER cron sets itself. */
static bool
cron_varname_ok(const char *s, size_t len)
{
	size_t	i;

	if (len == 0 || len > 64 || isdigit((unsigned char)s[0]))
		return (false);
	for (i = 0; i < len; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '_')
			return (false);
	return (!(len == 7 && strncmp(s, "LOGNAME", 7) == 0) && !(len == 4 &&
	    strncmp(s, "USER", 4) == 0));
}

/* Must a value be quoted to be read back as it is: none, blanks at an
 * end, a quote first? */
static bool
cron_quoted(const char *v)
{
	size_t	k = strlen(v);

	return (k == 0 || strchr(" \t\"'", v[0]) != NULL || v[k - 1] == ' ' ||
	    v[k - 1] == '\t');
}

/* setvar's NAME=value, unsetvar's NAME: NULL, or what is wrong. */
static const char *
cron_var_check(const char *text, bool set)
{
	const char	*eq;

	if (text == NULL)
		return ("a cron variable is NAME=value to set, NAME to unset");
	eq = strchr(text, '=');
	if (!cron_varname_ok(text, eq != NULL ? (size_t)(eq - text) :
	    strlen(text)))
		return ("a cron variable's name is letters, digits and _, 64 at "
		    "most, not a digit first; LOGNAME and USER are cron's own");
	if (!set)
		return (eq == NULL ? NULL : "a cron unsetvar takes the "
		    "variable's name alone");
	if (eq == NULL)
		return ("a cron setvar is NAME=value (MAILTO= and nothing after "
		    "it: no mail)");
	if (!cron_one_line(eq + 1, CRON_LINE_MAX))
		return ("a cron variable's value is one line of printable "
		    "characters, 1000 at most");
	if (cron_quoted(eq + 1) && strchr(eq + 1, '"') != NULL)
		return ("a cron variable's value with blanks at an end, or a "
		    "quote first, is written in double quotes: it cannot hold "
		    "one");
	return (NULL);
}

const char *
cron_check(const struct arc_job_spec *sp)
{
	const char	*why;
	bool		 sys;

	if (sp->verb == NULL || (strcmp(sp->verb, "add") != 0 &&
	    strcmp(sp->verb, "delete") != 0 && strcmp(sp->verb, "replace") !=
	    0 && !cron_isvar(sp)))
		return ("a cron job's verb is add, delete, replace, setvar or "
		    "unsetvar");
	if (sp->jail != NULL && sp->jail[0] != '\0' && !valid_jail(sp->jail))
		return ("invalid jail name");
	sys = sp->user == NULL || sp->user[0] == '\0';
	if (!sys && !cron_user_ok(sp->user))
		return ("a crontab's user is a name of passwd(5): letters, "
		    "digits, ., _ and -");
	if (cron_isvar(sp)) {
		if ((why = cron_var_check(sp->text, strcmp(sp->verb,
		    "setvar") == 0)) != NULL)
			return (why);
		if (sp->names.n != 0 || (sp->description != NULL &&
		    sp->description[0] != '\0'))
			return ("a cron setvar or unsetvar takes its variable as "
			    "text, and no args nor comment");
		return (NULL);
	}
	if ((why = cron_line_check(sp->text, sys)) != NULL)
		return (why);
	if (strcmp(sp->verb, "replace") == 0) {
		if (sp->names.n != 1)
			return ("a cron replace names the line it replaces, as "
			    "its one arg");
		if ((why = cron_line_check(sp->names.v[0], sys)) != NULL)
			return (why);
	} else if (sp->names.n != 0)
		return ("a cron add or delete takes its line as text, and no "
		    "args");
	if (sp->description != NULL && (strcmp(sp->verb, "delete") == 0 ||
	    !cron_one_line(sp->description, CRON_NOTE_MAX) ||
	    strchr(sp->description, '\n') != NULL))
		return ("a cron entry's comment is one line, 200 characters at "
		    "most, given to add and replace");
	return (NULL);
}

char *
cron_title(const struct arc_job_spec *sp)
{
	char	*t;

	if (asprintf(&t, "cron %s: %s%s%s", sp->verb, sp->text,
	    sp->user != NULL && sp->user[0] != '\0' ? ", crontab of " : "",
	    sp->user != NULL && sp->user[0] != '\0' ? sp->user : "") == -1)
		return (NULL);
	return (t);
}

/* Does passwd(5) of the host, or the jail's own, have user? */
static bool
cron_user_there(struct work *w, const char *user)
{
	const char	*p, *nl;
	char		*text;
	size_t		 len;

	if ((text = cron_slurp(w, "/etc/passwd")) == NULL)
		return (false);
	len = strlen(user);
	for (p = text; *p != '\0'; p = nl != NULL ? nl + 1 : p + strlen(p)) {
		nl = strchr(p, '\n');
		if (strncmp(p, user, len) == 0 && p[len] == ':')
			return (true);
	}
	return (false);
}

/* Two lines of an entry the same: the same words, whatever blanks are
 * between them. */
static bool
cron_same(const char *a, const char *b)
{

	for (;;) {
		a += strspn(a, " \t\r");
		b += strspn(b, " \t\r");
		if (*a == '\0' || *b == '\0')
			return (*a == *b);
		while (*a != '\0' && *a == *b && strchr(" \t\r", *a) == NULL) {
			a++;
			b++;
		}
		if ((*a == '\0' || strchr(" \t\r", *a) != NULL) && (*b ==
		    '\0' || strchr(" \t\r", *b) != NULL))
			continue;
		return (false);
	}
}

/* Lines of a text: v[0 .. n-1], each without its newline. */
struct clines {
	char	**v;
	size_t	  n, cap;
};

static void
cl_add(struct work *w, struct clines *l, const char *s)
{

	l->v = wgrow(w, l->v, l->n, &l->cap, sizeof(*l->v));
	l->v[l->n++] = wstrdup(w, s);
}

static void
cl_split(struct work *w, struct clines *l, const char *text)
{
	const char	*p, *nl;

	memset(l, 0, sizeof(*l));
	for (p = text; p != NULL && *p != '\0'; p = nl != NULL ? nl + 1 :
	    p + strlen(p)) {
		nl = strchr(p, '\n');
		cl_add(w, l, wstrndup(w, p, nl != NULL ? (size_t)(nl - p) :
		    strlen(p)));
	}
}

static char *
cl_join(struct work *w, const struct clines *l)
{
	char	*s;
	size_t	 i, len;

	for (i = 0, len = 1; i < l->n; i++)
		len += strlen(l->v[i]) + 1;
	s = wmalloc(w, len);
	s[0] = '\0';
	for (i = 0, len = 0; i < l->n; i++) {
		memcpy(s + len, l->v[i], strlen(l->v[i]));
		len += strlen(l->v[i]);
		s[len++] = '\n';
	}
	s[len] = '\0';
	return (s);
}

/* Lines from at, n of them, out; the rest after them moved up. */
static void
cl_cut(struct clines *l, size_t at, size_t n)
{

	memmove(&l->v[at], &l->v[at + n], (l->n - at - n) * sizeof(*l->v));
	l->n -= n;
}

/* A line put at at, those from it moved down. */
static void
cl_put(struct work *w, struct clines *l, size_t at, const char *s)
{

	cl_add(w, l, s);
	memmove(&l->v[at + 1], &l->v[at], (l->n - 1 - at) * sizeof(*l->v));
	l->v[at] = wstrdup(w, s);
}

/* The entry's line in l from lo to hi (not hi), or -1. */
static ssize_t
cl_find(const struct clines *l, size_t lo, size_t hi, const char *line)
{
	size_t	i;

	for (i = lo; i < hi; i++)
		if (cron_kind(l->v[i]) == CL_ENTRY && cron_same(l->v[i], line))
			return ((ssize_t)i);
	return (-1);
}

/* Is l's line i a variable named name (len bytes)? */
static bool
cl_isvar(struct work *w, const struct clines *l, size_t i, const char *name,
    size_t len)
{
	const char	*n, *v;

	return (cron_kind(l->v[i]) == CL_VAR && cron_var(w, l->v[i], &n, &v) &&
	    strlen(n) == len && strncmp(n, name, len) == 0);
}

/* Is the variable set in l's lines lo to hi? */
static bool
cl_hasvar(struct work *w, const struct clines *l, size_t lo, size_t hi,
    const char *name, size_t len)
{
	size_t	i;

	for (i = lo; i < hi; i++)
		if (cl_isvar(w, l, i, name, len))
			return (true);
	return (false);
}

/*
 * A variable set or unset in l's lines lo to hi (Arcana's): its lines
 * there taken away, and set, written at the top of them, after the
 * variables already there, so that it is the environment of each entry
 * below.  *hip moved.  0, or -1 and *errp.
 */
static int
cron_var_edit(struct work *w, const struct arc_job_spec *sp,
    struct clines *l, size_t lo, size_t *hip, const char *where,
    const char **errp)
{
	const char	*eq;
	size_t		 hi = *hip, i, len;
	bool		 had;

	eq = strchr(sp->text, '=');
	len = eq != NULL ? (size_t)(eq - sp->text) : strlen(sp->text);
	had = false;
	for (i = lo; i < hi; ) {
		if (cl_isvar(w, l, i, sp->text, len)) {
			cl_cut(l, i, 1);
			hi--;
			had = true;
		} else
			i++;
	}
	if (strcmp(sp->verb, "unsetvar") == 0) {
		if (!had) {
			*errp = wfmt(w, "%s sets no %.*s", where, (int)len,
			    sp->text);
			return (-1);
		}
		*hip = hi;
		return (0);
	}
	for (i = lo; i < hi && cron_kind(l->v[i]) == CL_VAR; i++)
		;
	cl_put(w, l, i, cron_quoted(eq + 1) ? wfmt(w, "%.*s=\"%s\"", (int)len,
	    sp->text, eq + 1) : sp->text);
	*hip = hi + 1;
	return (0);
}

/*
 * The change made in l's lines lo to hi (Arcana's), at end of them a new
 * entry: an add, a delete (the comment just above taken too), a replace
 * (the old's comment with it, the new's in its place).  *hip moved.
 * 0, or -1 and *errp.
 */
static int
cron_edit(struct work *w, const struct arc_job_spec *sp, struct clines *l,
    size_t lo, size_t *hip, const char *where, const char **errp)
{
	const char	*line;
	ssize_t		 at;
	size_t		 hi = *hip, i;

	if (cron_isvar(sp))
		return (cron_var_edit(w, sp, l, lo, hip, where, errp));
	line = sp->text + strspn(sp->text, " \t");
	if (strcmp(sp->verb, "add") == 0) {
		if (cl_find(l, lo, hi, line) >= 0) {
			*errp = wfmt(w, "%s has that entry already", where);
			return (-1);
		}
		i = hi;
		if (sp->description != NULL && sp->description[0] != '\0')
			cl_put(w, l, i++, wfmt(w, "# %s", sp->description));
		cl_put(w, l, i++, line);
		*hip = i;
		return (0);
	}
	if ((at = cl_find(l, lo, hi, strcmp(sp->verb, "replace") == 0 ?
	    sp->names.v[0] : line)) < 0) {
		*errp = wfmt(w, "%s has no entry %s", where, strcmp(sp->verb,
		    "replace") == 0 ? sp->names.v[0] : line);
		return (-1);
	}
	if (strcmp(sp->verb, "replace") == 0 && strcmp(sp->names.v[0],
	    line) != 0 && cl_find(l, lo, hi, line) >= 0) {
		*errp = wfmt(w, "%s has that entry already", where);
		return (-1);
	}
	/* Its comment with it: the line just above, one of the entry's. */
	if ((size_t)at > lo && cron_kind(l->v[at - 1]) == CL_COMMENT &&
	    !cron_ours(l->v[at - 1])) {
		cl_cut(l, (size_t)at - 1, 2);
		at--;
		hi -= 2;
	} else {
		cl_cut(l, (size_t)at, 1);
		hi--;
	}
	if (strcmp(sp->verb, "replace") == 0) {
		i = (size_t)at;
		if (sp->description != NULL && sp->description[0] != '\0') {
			cl_put(w, l, i++, wfmt(w, "# %s", sp->description));
			hi++;
		}
		cl_put(w, l, i, line);
		hi++;
	}
	*hip = hi;
	return (0);
}

/* The line's user, of the system format: the word after its schedule. */
static const char *
cron_line_user(struct work *w, const char *line)
{
	struct centry	e;

	if (cron_split(w, line, true, &e) != 0)
		return (NULL);
	return (e.user);
}

/* Arcana's file changed: written whole beneath the jail's root where it
 * works in one, its directory made where it is not. */
static int
cron_file_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	struct clines	 l;
	const char	*path, *user, *text;
	size_t		 lo, hi;
	int		 step;

	user = cron_isvar(sp) ? "" : cron_line_user(w, sp->text);
	if (!cron_isvar(sp) && (user == NULL || !cron_user_there(w, user))) {
		*errp = wfmt(w, "no user %s%s%s: an entry runs as a user of "
		    "passwd(5)", user != NULL ? user : "", w->jail != NULL ?
		    " in the jail " : "", w->jail != NULL ? w->jail : "");
		return (-1);
	}
	path = rooted(w, CRON_FILE);
	errno = 0;
	if ((text = cron_slurp(w, CRON_FILE)) == NULL && errno != ENOENT) {
		*errp = wfmt(w, "%s%s%s: %s", CRON_FILE, w->jail != NULL ?
		    " in " : "", w->jail != NULL ? w->jail : "",
		    strerror(errno));
		return (-1);
	}
	cl_split(w, &l, text != NULL && text[0] != '\0' ? text : CRON_HEAD);
	/* Its head left first. */
	for (lo = 0; lo < l.n && cron_kind(l.v[lo]) == CL_COMMENT &&
	    cron_ours(l.v[lo]); lo++)
		;
	hi = l.n;
	if (cron_edit(w, sp, &l, lo, &hi, "Arcana's cron file", errp) != 0)
		return (-1);
	text = cl_join(w, &l);
	step = step_begin(w, STEP_FILE, "write", "%s%s%s", CRON_FILE,
	    w->jail != NULL ? " in " : "", w->jail != NULL ? w->jail : "");
	if (work_dry(w, step))
		return (0);
	if (scope_mkdirs(w, rooted(w, "/usr/local/etc/cron.d")) != 0 ||
	    scope_replace(w, path, text, strlen(text), 0644, NULL) != 0) {
		*errp = wfmt(w, "%s%s%s: %s", CRON_FILE, w->jail != NULL ?
		    " in " : "", w->jail != NULL ? w->jail : "",
		    strerror(errno));
		step_end(w, step, false, "%s", strerror(errno));
		return (-1);
	}
	step_end(w, step, true, NULL);
	return (0);
}

/* A user's crontab changed between Arcana's markers, by crontab(1). */
static int
cron_tab_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	struct clines	 l;
	const char	*text, *line;
	ssize_t		 b, e;
	size_t		 i, hi;
	bool		 had;

	if (!cron_user_there(w, sp->user)) {
		*errp = wfmt(w, "no user %s%s%s: a crontab is a user's of "
		    "passwd(5)", sp->user, w->jail != NULL ? " in the jail " :
		    "", w->jail != NULL ? w->jail : "");
		return (-1);
	}
	if (cron_tab_read(w, sp->user, &text, &had, errp) != 0)
		return (-1);
	cl_split(w, &l, text);
	b = e = -1;
	for (i = 0; i < l.n; i++) {
		line = l.v[i] + strspn(l.v[i], " \t");
		if (b < 0 && strncmp(line, CRON_BEGIN, strlen(CRON_BEGIN)) == 0)
			b = (ssize_t)i;
		else if (b >= 0 && e < 0 && strncmp(line, CRON_END,
		    strlen(CRON_END)) == 0)
			e = (ssize_t)i;
	}
	if (b >= 0 && e < 0) {
		*errp = wfmt(w, "%s's crontab has Arcana's first marker and "
		    "not its last: crontab -e -u %s to mend it", sp->user,
		    sp->user);
		return (-1);
	}
	/* Not Arcana's: the user's own, outside the markers. */
	if (strcmp(sp->verb, "unsetvar") == 0 && (b < 0 || !cl_hasvar(w, &l,
	    (size_t)b, (size_t)e, sp->text, strlen(sp->text))) &&
	    cl_hasvar(w, &l, 0, l.n, sp->text, strlen(sp->text))) {
		*errp = wfmt(w, "%s of %s's crontab is not Arcana's: it is "
		    "outside Arcana's markers, the user's own (crontab -e -u "
		    "%s)", sp->text, sp->user, sp->user);
		return (-1);
	}
	if (strcmp(sp->verb, "add") != 0 && !cron_isvar(sp)) {
		line = strcmp(sp->verb, "replace") == 0 ? sp->names.v[0] :
		    sp->text;
		if ((b < 0 || cl_find(&l, (size_t)b, (size_t)e, line) < 0) &&
		    (cl_find(&l, 0, b >= 0 ? (size_t)b : l.n, line) >= 0 ||
		    (e >= 0 && cl_find(&l, (size_t)e, l.n, line) >= 0))) {
			*errp = wfmt(w, "that entry of %s's crontab is not "
			    "Arcana's: it is outside Arcana's markers, the "
			    "user's own (crontab -e -u %s)", sp->user,
			    sp->user);
			return (-1);
		}
	}
	if (b < 0) {
		/* Arcana's markers, at the end. */
		if (l.n > 0 && cron_kind(l.v[l.n - 1]) != CL_BLANK)
			cl_add(w, &l, "");
		b = (ssize_t)l.n;
		cl_add(w, &l, CRON_BEGIN_LINE);
		cl_add(w, &l, CRON_END);
		e = b + 1;
	}
	hi = (size_t)e;
	if (cron_edit(w, sp, &l, (size_t)b + 1, &hi, wfmt(w, "%s's crontab",
	    sp->user), errp) != 0)
		return (-1);
	/* Nothing of Arcana's left: its markers too. */
	if (hi == (size_t)b + 1) {
		cl_cut(&l, (size_t)b, 2);
		if (b > 0 && (size_t)b == l.n && cron_kind(l.v[b - 1]) ==
		    CL_BLANK)
			cl_cut(&l, (size_t)b - 1, 1);
	}
	return (cron_tab_write(w, sp->user, cl_join(w, &l), errp));
}

int
do_cron_job(struct work *w, const struct arc_job_spec *sp, const char **errp)
{

	if ((*errp = cron_check(sp)) != NULL)
		return (-1);
	if (sp->user == NULL || sp->user[0] == '\0')
		return (cron_file_job(w, sp, errp));
	return (cron_tab_job(w, sp, errp));
}

/*
 * For a safe change of a user's crontab: as it is, to be put back
 * (cron_undo()); Arcana's file is a file of the job's undo.  0, or -1
 * and *errp.
 */
int
cron_snap(struct work *w, const struct arc_job_spec *sp,
    struct cron_was *was, const char **errp)
{
	const char	*text;

	memset(was, 0, sizeof(*was));
	if (cron_tab_read(w, sp->user, &text, &was->had, errp) != 0)
		return (-1);
	was->text = wstrdup(w, text);
	was->taken = true;
	return (0);
}

/* The user's crontab as it was: written again by crontab(1), or
 * removed where there was none. */
int
cron_undo(struct work *w, const struct arc_job_spec *sp,
    const struct cron_was *was, const char **errp)
{

	if (!was->taken)
		return (0);
	return (cron_tab_write(w, sp->user, was->had ? was->text : NULL,
	    errp));
}
