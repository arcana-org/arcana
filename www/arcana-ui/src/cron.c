/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The System tab's cron: cron(8) of the host, or of the running jail
 * picked in the tab (sysview.c's Where), as arcana-cron's read has it
 * through the fleet mount.  Every entry of /etc/crontab, of the cron.d
 * files and of the users' crontabs, in a table that sorts and filters
 * (tbl.c), the admin's read alone; Arcana's own (its file,
 * /usr/local/etc/cron.d/arcana, and its part of a user's crontab
 * between its markers) edited and deleted here, and new ones added,
 * each a cron job of the place picked; each entry's next runs, in the
 * time zone of the host or the jail.  The variables each file sets
 * (SHELL=, MAILTO=), Arcana's set and unset by the cron job too; cron
 * itself started, stopped and enabled by the service-action job of the
 * place picked (enabled on the host by a commit, as the Services tab
 * does); and cron's log beside them, arcana-log's read of the place's
 * log directory.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	struct res	 r;		/* arcana-cron's read */
	struct res	 log;		/* cron's log, arcana-log's read */
	char		 where[256];	/* of which: "" the host, or a jail */
	char		 filter[64];
	char		 vfilter[64];	/* the variables' */
	int		 edit;		/* the entry edited, -2 a new one,
					 * -1 none */
	int		 vedit;		/* the variable edited, likewise */
} cr = { .edit = -1, .vedit = -1 };

#define	CR_LOG_LINES	200

static const struct tcol	cr_cols[] = {
	{ "Schedule", "schedule", false },
	{ "Next run", "next", false },
	{ "User", "user", false },
	{ "Command", "command", false },
	{ "Comment", "comment", false },
	{ "File", "file", false },
};

static const struct tcol	cr_vcols[] = {
	{ "Name", "name", false },
	{ "Value", "value", false },
	{ "File", "file", false },
};

void
cron_refresh(void)
{

	res_drop(&cr.r);
	res_drop(&cr.log);
}

/* list of the read, each its index, i; an entry its first next run as
 * next, to sort by. */
static ucl_object_t *
cr_indexed(const ucl_object_t *list)
{
	const ucl_object_t	*e, *n;
	ucl_object_t		*l, *c;
	ucl_object_iter_t	 it = NULL;
	int			 i;

	l = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; (e = ucl_object_iterate(list, &it, true)) != NULL; i++) {
		c = ucl_object_copy(e);
		ucl_object_insert_key(c, ucl_object_fromint(i), "i", 0, false);
		if ((n = ucl_array_find_index(jget(e, "next-run"), 0)) != NULL)
			ucl_object_insert_key(c, ucl_object_fromstring(
			    ucl_object_tostring(n)), "next", 0, false);
		ucl_array_append(l, c);
	}
	return (l);
}

/* The read as the tables draw it. */
static ucl_object_t *
cr_conv(const ucl_object_t *o)
{
	ucl_object_t	*r;

	r = ucl_object_copy(o);
	ucl_object_delete_key(r, "entry");
	ucl_object_delete_key(r, "variable");
	ucl_object_insert_key(r, cr_indexed(jget(o, "entry")), "entry", 0,
	    false);
	ucl_object_insert_key(r, cr_indexed(jget(o, "variable")), "variable",
	    0, false);
	return (r);
}

/* arcana-log's read as it came. */
static ucl_object_t *
cr_logconv(const ucl_object_t *o)
{

	return (o != NULL ? ucl_object_copy(o) : ucl_object_typed_new(
	    UCL_OBJECT));
}

/* cron's log, of the place picked: its last lines. */
static void
cr_log_load(const char *sid)
{
	struct server	*s = cur_server();
	struct html	 b;
	char		*q;

	memset(&b, 0, sizeof(b));
	h_strf(&b, "{\"name\":\"cron\",\"lines\":%d", CR_LOG_LINES);
	if (s != NULL && sysview_jail(s)[0] != '\0') {
		q = json_quote(sysview_jail(s));
		h_strf(&b, ",\"jail\":%s", q);
		free(q);
	}
	h_raw(&b, "}");
	res_yread(&cr.log, sid, "arcana-log:logs/read", b.s, cr_logconv);
	free(b.s);
}

/* A next run as the table shows it: its date and time, the host's. */
static void
cr_when(struct html *h, const char *t)
{
	char	buf[24];

	/* 2026-11-21T03:00:00+01:00: the date, the hour and minute. */
	if (t == NULL || strlen(t) < 16) {
		h_txt(h, t != NULL ? t : "");
		return;
	}
	snprintf(buf, sizeof(buf), "%.10s %.5s", t, t + 11);
	h_txt(h, buf);
}

static void
cr_load(const char *sid)
{
	struct server	*s = cur_server();
	char		*q, *in;

	if (s == NULL || sysview_jail(s)[0] == '\0') {
		res_yread(&cr.r, sid, "arcana-cron:cron/read", "{}", cr_conv);
		return;
	}
	q = json_quote(sysview_jail(s));
	if (asprintf(&in, "{\"jail\":%s}", q) == -1)
		abort();
	free(q);
	res_yread(&cr.r, sid, "arcana-cron:cron/read", in, cr_conv);
	free(in);
}

/* The entry of index i, of the read. */
static const ucl_object_t *
cr_entry(int i)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;

	while ((e = ucl_object_iterate(jget(cr.r.o, "entry"), &it, true)) !=
	    NULL)
		if (jint(e, "i", -1) == i)
			return (e);
	return (NULL);
}

/* The variable of index i, of the read. */
static const ucl_object_t *
cr_var(int i)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;

	while ((e = ucl_object_iterate(jget(cr.r.o, "variable"), &it,
	    true)) != NULL)
		if (jint(e, "i", -1) == i)
			return (e);
	return (NULL);
}

/* An entry's line as its job names it: a crontab's has no user. */
static char *
cr_line(const ucl_object_t *e)
{
	char	*s;

	if (asprintf(&s, "%s%s%s %s", jstr(e, "schedule"), strcmp(jstr(e,
	    "source"), "user") == 0 ? "" : " ", strcmp(jstr(e, "source"),
	    "user") == 0 ? "" : jstr(e, "user"), jstr(e, "command")) == -1)
		abort();
	return (s);
}

/* A cron job of the place picked, its title saying where. */
static void
cr_send(struct server *s, char *json, const char *what)
{
	char	title[200];

	if (sysview_jail(s)[0] == '\0') {
		job_send(s, json, what, JOB_SYSTEM, s->name);
		return;
	}
	snprintf(title, sizeof(title), "%s: %s", sysview_jail(s), what);
	job_send(s, json, title, JOB_SYSTEM, sysview_jail(s));
}

/* A job's extra: the jail, the crontab's user, the comment. */
static char *
cr_extra(struct server *s, const char *tab, const char *note)
{
	struct html	 b;
	char		*q;

	memset(&b, 0, sizeof(b));
	if (sysview_jail(s)[0] != '\0') {
		q = json_quote(sysview_jail(s));
		h_strf(&b, ",\"jail\":%s", q);
		free(q);
	}
	if (tab != NULL && tab[0] != '\0') {
		q = json_quote(tab);
		h_strf(&b, ",\"user\":%s", q);
		free(q);
	}
	if (note != NULL && note[0] != '\0') {
		q = json_quote(note);
		h_strf(&b, ",\"description\":%s", q);
		free(q);
	}
	return (b.s);
}

/* The form of an entry: a new one, or e's. */
static void
cr_form(struct html *h, const ucl_object_t *e)
{
	bool	tab = e != NULL && strcmp(jstr(e, "source"), "user") == 0;
	char	*line;

	h_raw(h, "<form class=\"secform cronform\" data-form=\"cr-entry\"><h4>");
	h_raw(h, e != NULL ? "The entry, changed" : "A new entry");
	h_raw(h, "</h4>");
	if (e != NULL) {
		line = cr_line(e);
		h_raw(h, "<input type=\"hidden\" name=\"old\"");
		h_attr(h, "value", line);
		h_raw(h, ">");
		free(line);
	}
	h_raw(h, "<label>Schedule <input name=\"schedule\" required "
	    "spellcheck=\"false\" autocomplete=\"off\" placeholder=\"*/5 * * * "
	    "* or @daily\"");
	if (e != NULL)
		h_attr(h, "value", jstr(e, "schedule"));
	h_raw(h, "><small class=\"help\">minute, hour, day of the month, "
	    "month, day of the week (each *, a value, a-b, a list, /step); or "
	    "@reboot, @hourly, @daily, @weekly, @monthly, @yearly</small>"
	    "</label><label>User <input name=\"user\" required "
	    "spellcheck=\"false\" autocomplete=\"off\" placeholder=\"root\"");
	h_attr(h, "value", e != NULL ? jstr(e, "user") : "root");
	if (e != NULL && tab)
		h_raw(h, " readonly");
	h_raw(h, "><small class=\"help\">who it runs as, one of passwd(5)'s"
	    "</small></label><label class=\"wide\">Command <input name="
	    "\"command\" required spellcheck=\"false\" autocomplete=\"off\" "
	    "class=\"mono\" placeholder=\"/usr/local/bin/backup.sh\"");
	if (e != NULL)
		h_attr(h, "value", jstr(e, "command"));
	h_raw(h, "></label><label class=\"wide\">Comment <input name="
	    "\"comment\" autocomplete=\"off\" placeholder=\"what it is for, "
	    "the line above it\"");
	if (e != NULL && jstr(e, "comment") != NULL)
		h_attr(h, "value", jstr(e, "comment"));
	h_raw(h, "></label>");
	if (e == NULL)
		h_raw(h, "<label class=\"check\"><input type=\"checkbox\" name="
		    "\"tab\"> In the user's own crontab, by crontab(1), between "
		    "Arcana's markers; else Arcana's file, "
		    "/usr/local/etc/cron.d/arcana</label>");
	else if (tab)
		h_raw(h, "<input type=\"hidden\" name=\"tab\" value=\"on\">");
	h_raw(h, "<div class=\"actions\"><button type=\"button\" class=\"ghost\" "
	    "data-act=\"cr-cancel\">Cancel</button><button type=\"submit\" "
	    "class=\"primary\">");
	h_raw(h, e != NULL ? "Save" : "Add");
	h_raw(h, "</button></div></form>");
}

/* The form of a variable of Arcana's: a new one, or e's value. */
static void
cr_vform(struct html *h, const ucl_object_t *e)
{
	bool	tab = e != NULL && jstr(e, "user") != NULL;

	h_raw(h, "<form class=\"secform cronform\" data-form=\"cr-var\"><h4>");
	h_raw(h, e != NULL ? "The variable, changed" : "A new variable");
	h_raw(h, "</h4><label>Name <input name=\"name\" required "
	    "spellcheck=\"false\" autocomplete=\"off\" class=\"mono\" "
	    "pattern=\"[A-Za-z_][A-Za-z0-9_]*\" placeholder=\"MAILTO\"");
	if (e != NULL) {
		h_attr(h, "value", jstr(e, "name"));
		h_raw(h, " readonly");
	}
	h_raw(h, "><small class=\"help\">SHELL, MAILTO, PATH, HOME and the "
	    "like; cron(8) sets LOGNAME and USER itself, and has no CRON_TZ"
	    "</small></label><label class=\"wide\">Value <input name=\"value\" "
	    "spellcheck=\"false\" autocomplete=\"off\" class=\"mono\" "
	    "placeholder=\"root (empty MAILTO: no mail)\"");
	if (e != NULL)
		h_attr(h, "value", jstr(e, "value") != NULL ? jstr(e, "value") :
		    "");
	h_raw(h, "></label>");
	if (e == NULL)
		h_raw(h, "<label class=\"check\"><input type=\"checkbox\" "
		    "name=\"tab\"> In a user's own crontab, between Arcana's "
		    "markers; else Arcana's file</label><label>User <input "
		    "name=\"user\" spellcheck=\"false\" autocomplete=\"off\" "
		    "placeholder=\"the crontab's, when in one\"></label>");
	else if (tab) {
		h_raw(h, "<input type=\"hidden\" name=\"tab\" value=\"on\">"
		    "<input type=\"hidden\" name=\"user\"");
		h_attr(h, "value", jstr(e, "user"));
		h_raw(h, ">");
	}
	h_raw(h, "<p class=\"help\">Set at the top of Arcana's part, before its "
	    "entries: each of them runs with it.</p><div class=\"actions\">"
	    "<button type=\"button\" class=\"ghost\" data-act=\"cr-vcancel\">"
	    "Cancel</button><button type=\"submit\" class=\"primary\">");
	h_raw(h, e != NULL ? "Save" : "Set");
	h_raw(h, "</button></div></form>");
}

/* The variables each file sets, Arcana's changed here. */
static void
cr_vars(struct html *h)
{
	const ucl_object_t	**rows, *e;
	int			  n;

	h_raw(h, "<h4 class=\"secsub\">Variables</h4><p class=\"dim\">What "
	    "a file sets for its entries below it (crontab(5)). Arcana's are "
	    "at the top of its file, or of its part of a user's crontab."
	    "</p><div class=\"toolbar\"><button class=\"ghost small\" "
	    "data-act=\"cr-vnew\">+ variable</button><input class=\"filter\" "
	    "data-input=\"cr-vfilter\" placeholder=\"Filter variables\" "
	    "autocomplete=\"off\" spellcheck=\"false\"");
	h_attr(h, "value", cr.vfilter);
	h_raw(h, "></div>");
	if (cr.vedit == -2)
		cr_vform(h, NULL);
	h_raw(h, "<table class=\"net cronvars\">");
	tbl_head(h, "cronvars", cr_vcols, (int)nitems(cr_vcols), 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("cronvars", jget(cr.r.o, "variable"), cr_vcols,
	    (int)nitems(cr_vcols), cr.vfilter);
	for (n = 0; (e = rows[n]) != NULL; n++) {
		h_raw(h, "<tr");
		h_fmt(h, " data-i=\"%d\"", (int)jint(e, "i", -1));
		h_raw(h, jbool(e, "arcana") ? " class=\"ours\"" : "");
		h_raw(h, "><td class=\"mono\">");
		h_txt(h, jstr(e, "name"));
		h_raw(h, "</td><td class=\"mono\">");
		if (jstr(e, "value") != NULL && jstr(e, "value")[0] != '\0')
			h_txt(h, jstr(e, "value"));
		else
			h_raw(h, "<span class=\"dim\">empty</span>");
		h_raw(h, "</td><td><span class=\"mono\">");
		h_txt(h, jstr(e, "file"));
		h_fmt(h, "</span>:%d", (int)jint(e, "line", 0));
		if (jstr(e, "user") != NULL)
			h_raw(h, " <span class=\"chip\">crontab</span>");
		h_raw(h, "</td><td class=\"acts\">");
		if (jbool(e, "arcana"))
			h_fmt(h, "<button class=\"ghost small\" data-act=\""
			    "cr-vedit\" data-arg=\"%d\">Edit</button><button "
			    "class=\"icon\" data-act=\"cr-vdel\" data-arg=\"%d\" "
			    "title=\"Unset this variable\">×</button>",
			    (int)jint(e, "i", -1), (int)jint(e, "i", -1));
		else
			h_raw(h, "<span class=\"chip\" title=\"The admin's: "
			    "changed in its file, or by crontab -e as its "
			    "user\">admin's</span>");
		h_raw(h, "</td></tr>");
		if (cr.vedit >= 0 && cr.vedit == (int)jint(e, "i", -1)) {
			h_raw(h, "<tr><td colspan=\"4\">");
			cr_vform(h, e);
			h_raw(h, "</td></tr>");
		}
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"4\" class=\"dim\">No variables."
		    "</td></tr>");
	free(rows);
	h_raw(h, "</tbody></table>");
}

/* cron's log, its last lines, read beside the entries. */
static void
cr_log(struct html *h, struct server *s)
{
	const ucl_object_t	*l;
	ucl_object_iter_t	 it = NULL;
	int			 n;

	h_fmt(h, "<h4 class=\"secsub\">cron's log</h4><p class=\"dim\">The "
	    "last %d lines of <code>/var/log/cron</code>%s, as syslogd(8) "
	    "wrote them: what ran, and when. <button class=\"ghost small\" "
	    "data-act=\"cr-log-retry\">Read again</button></p>", CR_LOG_LINES,
	    sysview_jail(s)[0] != '\0' ? " of the jail" : "");
	if (!res_shown(h, &cr.log, s->id, cr_log_load, "cr-log-retry") ||
	    cr.log.o == NULL || cr.log.error[0] != '\0')
		return;
	h_raw(h, "<pre class=\"cronlog mono\">");
	for (n = 0; (l = ucl_object_iterate(jget(cr.log.o, "line"), &it,
	    true)) != NULL; n++) {
		if (jstr(l, "time") != NULL) {
			h_txt(h, jstr(l, "time"));
			h_raw(h, " ");
		}
		if (jstr(l, "tag") != NULL) {
			h_txt(h, jstr(l, "tag"));
			if (jget(l, "pid") != NULL) {
				h_raw(h, "[");
				h_txt(h, ucl_object_tostring_forced(jget(l,
				    "pid")));
				h_raw(h, "]");
			}
			h_raw(h, ": ");
		}
		h_txt(h, jstr(l, "text") != NULL ? jstr(l, "text") : "");
		h_raw(h, "\n");
	}
	if (n == 0)
		h_raw(h, "<span class=\"dim\">Nothing in it.</span>");
	h_raw(h, "</pre>");
}

/*
 * The section: cron's daemon, the entries in their table, a form to add
 * one or edit one of Arcana's.
 */
void
view_cron(struct html *h, struct server *s)
{
	const ucl_object_t	**rows, *e, *d, *u;
	ucl_object_iter_t	  it;
	const char		 *src;
	int			  n;

	/* Another place picked: its own read. */
	if (strcmp(cr.where, sysview_jail(s)) != 0) {
		snprintf(cr.where, sizeof(cr.where), "%s", sysview_jail(s));
		res_drop(&cr.r);
		res_drop(&cr.log);
		cr.edit = cr.vedit = -1;
	}
	h_raw(h, "<h3 class=\"secsub\" id=\"cron\">cron(8)</h3><p class=\"dim\">"
	    "Commands run on a schedule: /etc/crontab and the cron.d files "
	    "(a user field each), and each user's crontab. Arcana's own are "
	    "its file, <code>/usr/local/etc/cron.d/arcana</code>, which cron "
	    "reads by itself, and its part of a user's crontab between its "
	    "markers, written by crontab(1); the rest is the admin's, read "
	    "here.</p>");
	if (!res_shown(h, &cr.r, s->id, cr_load, "cr-retry") || cr.r.o == NULL)
		return;
	d = jget(cr.r.o, "daemon");
	h_raw(h, "<div class=\"toolbar\"><span class=\"chip ");
	h_raw(h, jbool(d, "running") ? "st-up\">running" : "st-down\">not "
	    "running");
	h_raw(h, "</span><span class=\"chip\">");
	h_raw(h, jbool(d, "enabled") ? "cron_enable YES" : "cron_enable NO");
	h_raw(h, "</span>");
	if (jstr(d, "flags") != NULL) {
		h_raw(h, "<span class=\"chip mono\">cron_flags ");
		h_txt(h, jstr(d, "flags"));
		h_raw(h, "</span>");
	}
	/* cron itself, by service(8) there. */
	if (jbool(d, "running"))
		h_raw(h, "<button class=\"ghost small\" data-act=\"cr-svc\" "
		    "data-arg=\"restart\" title=\"service cron restart\">"
		    "Restart</button><button class=\"ghost small\" data-act=\""
		    "cr-svc\" data-arg=\"stop\" title=\"service cron stop: no "
		    "entry runs until it starts again\">Stop</button>");
	else
		h_raw(h, "<button class=\"ghost small\" data-act=\"cr-svc\" "
		    "data-arg=\"start\" title=\"service cron start\">Start"
		    "</button>");
	if (jbool(d, "enabled"))
		h_raw(h, "<button class=\"ghost small\" data-act=\"cr-svc\" "
		    "data-arg=\"disable\" title=\"cron_enable NO: not started "
		    "at boot\">Disable</button>");
	else
		h_raw(h, "<button class=\"ghost small\" data-act=\"cr-svc\" "
		    "data-arg=\"enable\" title=\"cron_enable YES: started at "
		    "boot\">Enable</button>");
	h_raw(h, "<button class=\"ghost small\" data-act=\"cr-new\" title=\"An "
	    "entry of Arcana's: in its file, or a user's crontab\">+ entry"
	    "</button><input class=\"filter\" data-input=\"cr-filter\" "
	    "placeholder=\"Filter entries\" autocomplete=\"off\" "
	    "spellcheck=\"false\"");
	h_attr(h, "value", cr.filter);
	h_raw(h, "></div>");
	it = NULL;
	while ((u = ucl_object_iterate(jget(cr.r.o, "unread"), &it, true)) !=
	    NULL) {
		h_raw(h, "<p class=\"notice bad\">Not read: ");
		h_txt(h, ucl_object_tostring(u));
		h_raw(h, "</p>");
	}
	if (cr.edit == -2)
		cr_form(h, NULL);
	h_raw(h, "<table class=\"net cron\">");
	tbl_head(h, "cron", cr_cols, (int)nitems(cr_cols), 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("cron", jget(cr.r.o, "entry"), cr_cols,
	    (int)nitems(cr_cols), cr.filter);
	for (n = 0; (e = rows[n]) != NULL; n++) {
		src = jstr(e, "source") != NULL ? jstr(e, "source") : "";
		h_raw(h, "<tr");
		h_fmt(h, " data-i=\"%d\"", (int)jint(e, "i", -1));
		h_raw(h, jbool(e, "arcana") ? " class=\"ours\"" : "");
		h_raw(h, "><td class=\"mono\">");
		h_txt(h, jstr(e, "schedule"));
		h_raw(h, "</td><td class=\"mono next\">");
		{
			const ucl_object_t	*t;
			ucl_object_iter_t	 ti = NULL;
			int			 k;

			for (k = 0; (t = ucl_object_iterate(jget(e,
			    "next-run"), &ti, true)) != NULL; k++) {
				h_raw(h, k == 0 ? "<span" : "<br><small "
				    "class=\"dim\"");
				h_attr(h, "title", ucl_object_tostring(t));
				h_raw(h, ">");
				cr_when(h, ucl_object_tostring(t));
				h_raw(h, k == 0 ? "</span>" : "</small>");
			}
			if (k == 0)
				h_raw(h, "<span class=\"dim\">—</span>");
		}
		h_raw(h, "</td><td>");
		h_txt(h, jstr(e, "user"));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(e, "command"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(e, "comment") != NULL ? jstr(e, "comment") : "");
		h_raw(h, "</td><td><span class=\"mono\">");
		h_txt(h, jstr(e, "file"));
		h_fmt(h, "</span>:%d", (int)jint(e, "line", 0));
		if (strcmp(src, "user") == 0)
			h_raw(h, " <span class=\"chip\">crontab</span>");
		h_raw(h, "</td><td class=\"acts\">");
		if (jbool(e, "arcana")) {
			h_fmt(h, "<button class=\"ghost small\" data-act=\""
			    "cr-edit\" data-arg=\"%d\">Edit</button><button "
			    "class=\"icon\" data-act=\"cr-del\" data-arg=\"%d\" "
			    "title=\"Delete this entry\">×</button>",
			    (int)jint(e, "i", -1), (int)jint(e, "i", -1));
		} else
			h_raw(h, "<span class=\"chip\" title=\"The admin's: "
			    "changed in its file, or by crontab -e as its "
			    "user\">admin's</span>");
		h_raw(h, "</td></tr>");
		if (cr.edit >= 0 && cr.edit == (int)jint(e, "i", -1)) {
			h_raw(h, "<tr><td colspan=\"7\">");
			cr_form(h, e);
			h_raw(h, "</td></tr>");
		}
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"7\" class=\"dim\">No entries.</td>"
		    "</tr>");
	free(rows);
	h_raw(h, "</tbody></table>");
	if (jstr(cr.r.o, "timezone") != NULL) {
		h_raw(h, "<p class=\"dim small\">Next runs in ");
		h_txt(h, jstr(cr.r.o, "timezone"));
		h_raw(h, sysview_jail(s)[0] != '\0' ? ", the jail's time zone "
		    "(its /etc/localtime)." : ", the host's time zone "
		    "(/etc/localtime).");
		h_raw(h, "</p>");
	}
	cr_vars(h);
	cr_log(h, s);
}

/* A variable set: setvar of Arcana's file, or a user's crontab. */
static bool
cr_vsubmit(const ucl_object_t *f)
{
	struct server	*s;
	const char	*name, *value, *user;
	char		*text, *extra, what[300];
	bool		 tab;

	if ((s = cur_server()) == NULL)
		return (true);
	name = jstr(f, "name") != NULL ? jstr(f, "name") : "";
	value = jstr(f, "value") != NULL ? jstr(f, "value") : "";
	user = jstr(f, "user") != NULL ? jstr(f, "user") : "";
	tab = jbool(f, "tab") || (jstr(f, "tab") != NULL && strcmp(jstr(f,
	    "tab"), "on") == 0);
	if (name[0] == '\0') {
		toast(true, "A variable has a name");
		return (true);
	}
	if (tab && user[0] == '\0') {
		toast(true, "In a user's crontab: whose");
		return (true);
	}
	if (asprintf(&text, "%s=%s", name, value) == -1)
		abort();
	extra = cr_extra(s, tab ? user : NULL, NULL);
	snprintf(what, sizeof(what), "cron variable set: %s%s%s", text,
	    tab ? ", crontab of " : "", tab ? user : "");
	cr_send(s, job_json("cron", "setvar", NULL, 0, text, extra), what);
	free(extra);
	free(text);
	cr.vedit = -1;
	render();
	return (true);
}

bool
cron_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*sched, *user, *cmd, *note, *old, *w[1];
	char		*line, *extra, what[300];
	bool		 tab;

	if (strcmp(form, "cr-var") == 0)
		return (cr_vsubmit(f));
	if (strcmp(form, "cr-entry") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	sched = jstr(f, "schedule") != NULL ? jstr(f, "schedule") : "";
	user = jstr(f, "user") != NULL ? jstr(f, "user") : "";
	cmd = jstr(f, "command") != NULL ? jstr(f, "command") : "";
	note = jstr(f, "comment");
	old = jstr(f, "old");
	tab = jbool(f, "tab") || (jstr(f, "tab") != NULL && strcmp(jstr(f,
	    "tab"), "on") == 0);
	if (sched[0] == '\0' || user[0] == '\0' || cmd[0] == '\0') {
		toast(true, "An entry has a schedule, a user and a command");
		return (true);
	}
	/* A crontab's line has no user: whose crontab it is says it. */
	if (asprintf(&line, "%s %s%s%s", sched, tab ? "" : user, tab ? "" : " ",
	    cmd) == -1)
		abort();
	extra = cr_extra(s, tab ? user : NULL, note);
	if (old != NULL && old[0] != '\0') {
		w[0] = old;
		snprintf(what, sizeof(what), "cron entry replaced: %s", line);
		cr_send(s, job_json("cron", "replace", w, 1, line, extra), what);
	} else {
		snprintf(what, sizeof(what), "cron entry added: %s", line);
		cr_send(s, job_json("cron", "add", NULL, 0, line, extra), what);
	}
	free(extra);
	free(line);
	cr.edit = -1;
	render();
	return (true);
}

bool
cron_action(const char *act, const char *arg, const char *value)
{
	struct server		*s;
	const ucl_object_t	*e;
	char			*line, *extra, what[300];

	if (strcmp(act, "input:cr-filter") == 0) {
		snprintf(cr.filter, sizeof(cr.filter), "%s", value != NULL ?
		    value : "");
		render();
		return (true);
	}
	if (strcmp(act, "input:cr-vfilter") == 0) {
		snprintf(cr.vfilter, sizeof(cr.vfilter), "%s", value != NULL ?
		    value : "");
		render();
		return (true);
	}
	if (strncmp(act, "cr-", 3) != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "cr-retry") == 0) {
		res_drop(&cr.r);
		render();
		return (true);
	}
	if (strcmp(act, "cr-log-retry") == 0) {
		res_drop(&cr.log);
		render();
		return (true);
	}
	/* cron itself: the service-action job of the place picked; on the
	 * host, enabled by a commit, as the Services tab does it. */
	if (strcmp(act, "cr-svc") == 0 && arg != NULL && (strcmp(arg,
	    "start") == 0 || strcmp(arg, "stop") == 0 || strcmp(arg,
	    "restart") == 0 || strcmp(arg, "enable") == 0 || strcmp(arg,
	    "disable") == 0)) {
		char	*q, *json;

		if (sysview_jail(s)[0] == '\0' && (strcmp(arg, "enable") ==
		    0 || strcmp(arg, "disable") == 0)) {
			service_enable(s, "cron", strcmp(arg, "enable") == 0);
			res_drop(&cr.r);
			return (true);
		}
		q = json_quote(sysview_jail(s));
		if (asprintf(&json, "{\"kind\":\"service-action\",\"service\":"
		    "\"cron\",\"action\":\"%s\"%s%s}", arg, sysview_jail(s)[0] !=
		    '\0' ? ",\"jail\":" : "", sysview_jail(s)[0] != '\0' ? q :
		    "") == -1)
			abort();
		free(q);
		snprintf(what, sizeof(what), "service cron %s", arg);
		cr_send(s, json, what);
		return (true);
	}
	if (strcmp(act, "cr-vnew") == 0 || strcmp(act, "cr-vcancel") == 0 ||
	    strcmp(act, "cr-vedit") == 0) {
		cr.vedit = strcmp(act, "cr-vnew") == 0 ? -2 : strcmp(act,
		    "cr-vedit") == 0 && arg != NULL ? atoi(arg) : -1;
		render();
		return (true);
	}
	if ((strcmp(act, "cr-vdel") == 0 || strcmp(act, "cr-vdel-yes") == 0) &&
	    arg != NULL && (e = cr_var(atoi(arg))) != NULL && jbool(e,
	    "arcana")) {
		if (strcmp(act, "cr-vdel") == 0) {
			confirm("Unset this cron variable?", jstr(e, "name"),
			    "Unset", true, NULL, "cr-vdel-yes", arg, "");
			return (true);
		}
		extra = cr_extra(s, jstr(e, "user"), NULL);
		snprintf(what, sizeof(what), "cron variable unset: %s",
		    jstr(e, "name"));
		cr_send(s, job_json("cron", "unsetvar", NULL, 0, jstr(e,
		    "name"), extra), what);
		free(extra);
		return (true);
	}
	if (strcmp(act, "cr-new") == 0 || strcmp(act, "cr-cancel") == 0 ||
	    strcmp(act, "cr-edit") == 0) {
		cr.edit = strcmp(act, "cr-new") == 0 ? -2 : strcmp(act,
		    "cr-edit") == 0 && arg != NULL ? atoi(arg) : -1;
		render();
		return (true);
	}
	if ((strcmp(act, "cr-del") == 0 || strcmp(act, "cr-del-yes") == 0) &&
	    arg != NULL && (e = cr_entry(atoi(arg))) != NULL &&
	    jbool(e, "arcana")) {
		line = cr_line(e);
		if (strcmp(act, "cr-del") == 0) {
			confirm("Delete this cron entry?", line, "Delete", true,
			    NULL, "cr-del-yes", arg, "");
			free(line);
			return (true);
		}
		extra = cr_extra(s, strcmp(jstr(e, "source"), "user") == 0 ?
		    jstr(e, "user") : NULL, NULL);
		snprintf(what, sizeof(what), "cron entry deleted: %s", line);
		cr_send(s, job_json("cron", "delete", NULL, 0, line, extra),
		    what);
		free(extra);
		free(line);
		return (true);
	}
	return (true);
}
