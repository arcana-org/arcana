/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A host's crashes: the cores its kernel dumped (core(5)), where
 * kern.corefile says and where else one lies, the host's and each
 * running jail's beneath its root, with the jail they are of
 * (arcana-crashes' read, through the fleet mount).  A core's backtrace
 * read when asked, as lldb(1) reads it with its program, a jail's with
 * the jail's own (the read's backtrace and jail); a core in
 * kern.corefile's directory taken away by the crash job, a jail's
 * beneath the jail's root.  The Process crash alert is of the same
 * crashes: the kernel's line for each.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	struct res	 r;		/* the list */
	struct res	 bt;		/* a core's backtrace */
	char		 core[200];	/* whose: the core */
	char		 jail[64];	/* and its jail, "" the host's */
} cr;

/* arcana-crashes' read as the page draws it: by its names. */
static ucl_object_t *
cr_conv(const ucl_object_t *o)
{
	static const char *const names[] = { "core-file=cores",
	    "other=others", "note=notes", NULL };

	return (jflat(o, names));
}

static void
cr_load(const char *sid)
{

	res_yread(&cr.r, sid, "arcana-crashes:crashes/read", "{}", cr_conv);
}

/* Read the host's cores; again asks though they are here already. */
void
refresh_crashes(struct server *s, bool again)
{

	if (!app.online)
		return;
	if (again || strcmp(cr.r.sid, s->id) != 0)
		cr_load(s->id);
}

/* The backtrace's read, as it is. */
static ucl_object_t *
bt_conv(const ucl_object_t *o)
{

	return (ucl_object_copy(o));
}

/* A core's backtrace, of the host's or of a jail's. */
static void
bt_load(const char *sid)
{
	char	*qc, *qj, *in;

	qc = json_quote(cr.core);
	qj = json_quote(cr.jail);
	if (asprintf(&in, "{\"backtrace\":%s%s%s}", qc, cr.jail[0] != '\0' ?
	    ",\"jail\":" : "", cr.jail[0] != '\0' ? qj : "") == -1)
		abort();
	free(qc);
	free(qj);
	res_yread(&cr.bt, sid, "arcana-crashes:crashes/read", in, bt_conv);
	free(in);
}

static void
size(char *buf, size_t len, int64_t n)
{
	static const char *const units[] = { "B", "KiB", "MiB", "GiB" };
	double	v;
	int	u;

	v = (double)n;
	for (u = 0; v >= 1024 && u < 3; u++)
		v /= 1024;
	snprintf(buf, len, u == 0 ? "%.0f %s" : "%.1f %s", v, units[u]);
}

/* Is the core in kern.corefile's directory, the host's or beneath its
 * jail's root: the one place the crash job takes a core from. */
static bool
in_coredir(const ucl_object_t *c)
{
	const char	*dir, *where;
	size_t		 n, w;

	if ((dir = jstr(cr.r.o, "directory")) == NULL || (where = jstr(c,
	    "directory")) == NULL)
		return (false);
	if (jstr(c, "jail") == NULL)
		return (strcmp(where, dir) == 0);
	n = strlen(dir);
	w = strlen(where);
	return (w > n && strcmp(where + w - n, dir) == 0);
}

void
view_crashes(struct html *h, struct server *s)
{
	static const struct tcol cols[] = {
		{ "Core", "name", false }, { "Program", "program", false },
		{ "Pid", "pid", true }, { "Jail", "jail", false },
		{ "Size", "size", true }, { "Written", "time", false },
		{ "Directory", "directory", false },
	};
	const ucl_object_t	**rows, *o;
	ucl_object_iter_t	 it;
	const char		*j;
	char			 buf[32];
	int			 r, shown;

	h_raw(h, "<div class=\"toolbar\"><input class=\"filter\" id=\"filter\" "
	    "data-input=\"filter\" placeholder=\"Filter rows\" autocomplete="
	    "\"off\" spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, "><button class=\"ghost small\" data-act=\"crash-reload\">"
	    "Read again</button></div>");
	if (!res_shown(h, &cr.r, s->id, cr_load, "crash-reload"))
		return;
	h_raw(h, "<p class=\"dim\">The cores the kernel dumped where <code>"
	    "kern.corefile</code> (");
	h_txt(h, jstr(cr.r.o, "corefile") != NULL ? jstr(cr.r.o, "corefile") :
	    "?");
	h_raw(h, ") puts them, and in <code>/</code>, <code>/tmp</code>, "
	    "<code>/var/tmp</code> and the home directories; each running "
	    "jail's beneath its root. A backtrace is read by lldb with the "
	    "core's program, a jail's with the jail's own; only a core the "
	    "kernel said it dumped is read.</p>");
	it = NULL;
	while ((o = ucl_object_iterate(jget(cr.r.o, "notes"), &it, true)) !=
	    NULL) {
		h_raw(h, "<div class=\"notice info\">");
		h_txt(h, ucl_object_tostring_forced(o));
		h_raw(h, "</div>");
	}
	if (ucl_array_size(jget(cr.r.o, "cores")) == 0) {
		h_raw(h, "<div class=\"empty\"><h2>No cores</h2><p>No program "
		    "of the host or its jails has dumped one where they are "
		    "looked for.</p></div>");
		return;
	}
	h_raw(h, "<table class=\"net crashes\">");
	tbl_head(h, "crashes", cols, 7, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("crashes", jget(cr.r.o, "cores"), cols, 7, app.filter);
	shown = 0;
	for (r = 0; (o = rows[r]) != NULL; r++) {
		j = jstr(o, "jail") != NULL ? jstr(o, "jail") : "";
		shown++;
		h_raw(h, "<tr");
		h_attr(h, "data-core", jstr(o, "name"));
		h_attr(h, "data-jail", j);
		h_raw(h, "><td><b>");
		h_txt(h, jstr(o, "name"));
		h_raw(h, "</b></td><td>");
		h_txt(h, jstr(o, "program"));
		h_raw(h, "</td><td>");
		if (jget(o, "pid") != NULL)
			h_fmt(h, "%lld", (long long)jint(o, "pid", 0));
		h_raw(h, "</td><td>");
		if (j[0] != '\0')
			h_txt(h, j);
		else
			h_raw(h, "<span class=\"dim\">the host</span>");
		h_raw(h, "</td><td>");
		size(buf, sizeof(buf), jint(o, "size", 0));
		h_txt(h, buf);
		h_raw(h, "</td><td class=\"dim\">");
		h_txt(h, jstr(o, "time"));
		h_raw(h, "</td><td class=\"dim\"><code>");
		h_txt(h, jstr(o, "directory"));
		h_raw(h, "</code></td><td class=\"acts\"><button class=\"ghost "
		    "small\" data-act=\"crash-bt\"");
		h_attr(h, "data-arg", jstr(o, "name"));
		h_attr(h, "data-value", j);
		h_raw(h, ">Backtrace</button>");
		if (in_coredir(o)) {
			h_raw(h, "<button class=\"ghost small danger\" data-act="
			    "\"crash-delete\"");
			h_attr(h, "data-arg", jstr(o, "name"));
			h_attr(h, "data-value", j);
			h_raw(h, ">Delete</button>");
		}
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	if (shown == 0)
		h_raw(h, "<p class=\"dim\">No core of that name.</p>");
	it = NULL;
	if (ucl_array_size(jget(cr.r.o, "others")) > 0) {
		h_raw(h, "<details class=\"cr-others\"><summary>Other files in "
		    "the cores' directory</summary><ul>");
		while ((o = ucl_object_iterate(jget(cr.r.o, "others"), &it,
		    true)) != NULL) {
			h_raw(h, "<li><code>");
			h_txt(h, ucl_object_tostring_forced(o));
			h_raw(h, "</code></li>");
		}
		h_raw(h, "</ul></details>");
	}

	/* The backtrace asked for. */
	if (cr.core[0] == '\0')
		return;
	h_raw(h, "<section class=\"cr-bt\"><h4>Backtrace of ");
	h_txt(h, cr.core);
	if (cr.jail[0] != '\0') {
		h_raw(h, " <small class=\"dim\">in jail ");
		h_txt(h, cr.jail);
		h_raw(h, "</small>");
	}
	h_raw(h, " <button class=\"icon\" data-act=\"crash-bt-close\" title=\""
	    "Close\">×</button></h4>");
	if (cr.bt.o == NULL || strcmp(cr.bt.sid, s->id) != 0) {
		h_raw(h, "<div class=\"loader\"></div></section>");
		return;
	}
	if (cr.bt.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, cr.bt.error);
		h_raw(h, "</div></section>");
		return;
	}
	if (jstr(cr.bt.o, "program") != NULL) {
		h_raw(h, "<p class=\"dim\">Read with <code>");
		h_txt(h, jstr(cr.bt.o, "program"));
		h_raw(h, "</code>");
		if (jbool(cr.bt.o, "truncated"))
			h_raw(h, "; cut at 512 KiB");
		h_raw(h, ".</p>");
	}
	h_raw(h, "<pre class=\"mono crbt\">");
	h_txt(h, jstr(cr.bt.o, "backtrace"));
	h_raw(h, "</pre></section>");
}

/* A core taken away: a crash job, the list read again after it. */
static void
cr_delete(struct server *s, const char *core, const char *jail)
{
	char	*qc, *qj, *json, title[300];

	qc = json_quote(core);
	qj = json_quote(jail);
	if (asprintf(&json, "{\"kind\":\"crash\",\"verb\":\"delete\","
	    "\"args\":[%s]%s%s}", qc, jail[0] != '\0' ? ",\"jail\":" : "",
	    jail[0] != '\0' ? qj : "") == -1)
		abort();
	free(qc);
	free(qj);
	snprintf(title, sizeof(title), "core %s deleted%s%s", core, jail[0] !=
	    '\0' ? " in " : "", jail);
	job_send_host(s, json, title, JOB_CRASHES, core);
}

/* A core's name as the list has one: no path. */
static bool
core_ok(const char *s)
{

	return (s[0] != '\0' && s[0] != '.' && strlen(s) < 200 &&
	    strchr(s, '/') == NULL);
}

bool
crashes_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		 body[600];

	/* crash-, not cr-: cron_action is asked first and takes every cr-. */
	if (strncmp(act, "crash-", 6) != 0 && strcmp(act, "do-crash-delete") !=
	    0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "crash-reload") == 0) {
		cr_load(s->id);
	} else if (strcmp(act, "crash-bt") == 0 && core_ok(arg)) {
		snprintf(cr.core, sizeof(cr.core), "%s", arg);
		snprintf(cr.jail, sizeof(cr.jail), "%s", value);
		res_drop(&cr.bt);
		bt_load(s->id);
	} else if (strcmp(act, "crash-bt-close") == 0) {
		cr.core[0] = '\0';
		res_drop(&cr.bt);
	} else if (strcmp(act, "crash-delete") == 0 && core_ok(arg)) {
		snprintf(body, sizeof(body), "%s is deleted from %s%s%s. It "
		    "cannot be read again: read its backtrace first if it is "
		    "wanted.", arg, value[0] != '\0' ? "the jail " : "",
		    value[0] != '\0' ? value : s->name, value[0] != '\0' ?
		    "'s cores" : "");
		confirm("Delete the core", body, "Delete", true, NULL,
		    "do-crash-delete", arg, value);
	} else if (strcmp(act, "do-crash-delete") == 0 && core_ok(arg)) {
		if (strcmp(cr.core, arg) == 0 && strcmp(cr.jail, value) == 0) {
			cr.core[0] = '\0';
			res_drop(&cr.bt);
		}
		cr_delete(s, arg, value);
	}
	return (true);
}
