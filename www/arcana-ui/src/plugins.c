/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Console plugins, the page's side (the console's is cplug.c there):
 * the list read after sign-in and again with the health, handed to
 * bridge.js, which loads each enabled plugin's files with the integrity
 * listed: the themes and guide packs of its data, checked and applied
 * by the page's own code, and a trusted plugin's scripts, given
 * window.Arcana.  Here: Settings' Plugins tab, data and trusted plugins
 * apart, the themes of plugins in Look, the entries plugins add to the
 * account menu, the screen of a plugin's the address names
 * (#/p/<plugin>/<screen>[/rest]), and what the page saw of each plugin
 * (loaded, or why not).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	ucl_object_t	*o;		/* arcana-console's plugins */
	char		*text;		/* as handed to the page */
	bool		 loading;
	double		 fetched;	/* 0: to be read */
	char		 error[300];
	char		 busy[48];	/* being enabled or disabled */
	ucl_object_t	*page;		/* by id: "loaded", or the error */
	ucl_object_t	*data;		/* by id: {themes, packs} applied */
	ucl_object_t	*menu;		/* [{plugin, label, screen}] */
	char		 screen[160];	/* <plugin>/<screen>[/rest], or "" */
	char		*servers;	/* the hosts as last told the plugins */
} pl;

static const struct tcol pcols[] = {
	{ "Plugin", "name", false }, { "Version", "version", false },
	{ "Author", "author", false }, { "Provides", NULL, false },
	{ "Enabled", "enabled", false }, { "State", NULL, false },
};

/* The list to the page, which loads what is new in it. */
static void
give(void)
{
	char	*t;

	if (pl.o == NULL)
		return;
	t = (char *)ucl_object_emit(pl.o, UCL_EMIT_JSON_COMPACT);
	free(pl.text);
	pl.text = t;
	arc_plugins_set(pl.text, app.version, app.user, app.console_role);
}

static void
list_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*m, *a, *p;

	pl.loading = false;
	pl.busy[0] = '\0';
	if (status != 200 || o == NULL) {
		snprintf(pl.error, sizeof(pl.error), "%s", err != NULL ? err :
		    "no answer");
		return;
	}
	pl.error[0] = '\0';
	/* arcana-console's plugins as bridge.js takes them: {dir, plugins:
	 * [{id, ..., provides, files}]}. */
	m = ucl_object_typed_new(UCL_OBJECT);
	if (jstr(o, "directory") != NULL)
		ucl_object_insert_key(m, ucl_object_fromstring(jstr(o,
		    "directory")), "dir", 0, false);
	a = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(jget(o, "plugin"), &it, true)) !=
	    NULL) {
		p = ucl_object_copy(e);
		if (jget(p, "provides") == NULL)
			ucl_object_insert_key(p, ucl_object_typed_new(
			    UCL_ARRAY), "provides", 0, false);
		if (jget(e, "file") != NULL) {
			ucl_object_insert_key(p, ucl_object_copy(jget(e,
			    "file")), "files", 0, false);
			ucl_object_delete_key(p, "file");
		}
		ucl_array_append(a, p);
	}
	ucl_object_insert_key(m, a, "plugins", 0, false);
	if (pl.o != NULL)
		ucl_object_unref(pl.o);
	pl.o = m;
	pl.fetched = arc_now();
	give();
}

static void
list_load(void)
{

	if (pl.loading || !app.online)
		return;
	pl.loading = true;
	rc_get(RC_C "plugins", NULL, list_cb, NULL);
}

/* One enabled or not (204): the list read again. */
static void
enabled_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	if (status < 200 || status > 299) {
		list_cb(status, o, err, arg);
		return;
	}
	pl.loading = false;
	list_load();
}

/*
 * Signed in: read once at once, then with the health while the page is
 * looked at; the page loads only what is new, so a read that changed
 * nothing costs it a comparison.
 */
void
plugins_tick(double now)
{

	if (!app.servers_loaded)
		return;
	if (pl.fetched == 0 || (app.visible && now - pl.fetched > HEALTH_MS))
		list_load();
}

/* The page is looked at again: the list is read at the next tick. */
void
plugins_poke(void)
{

	if (pl.fetched != 0)
		pl.fetched = 1;
}

/* What a plugin said to the page, kept by its id. */
static void
page_set(const char *id, const char *what)
{

	if (pl.page == NULL)
		pl.page = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_replace_key(pl.page, ucl_object_fromstring(what), id, 0,
	    true);
}

static const char *
page_get(const char *id)
{

	return (pl.page != NULL ? jstr(pl.page, id) : NULL);
}

/* A plugin with code, its scripts or styles: a trusted one. */
static bool
trusted(const ucl_object_t *p)
{
	const ucl_object_t	*f;
	ucl_object_iter_t	 it;
	const char		*k;

	it = NULL;
	while ((f = ucl_object_iterate(jget(p, "files"), &it, true)) != NULL)
		if ((k = jstr(f, "kind")) != NULL && (strcmp(k, "script") ==
		    0 || strcmp(k, "style") == 0))
			return (true);
	return (false);
}

static const ucl_object_t *
plugin_of(const char *id)
{
	const ucl_object_t	*p;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((p = ucl_object_iterate(jget(pl.o, "plugins"), &it, true)) !=
	    NULL)
		if (jstr(p, "id") != NULL && strcmp(jstr(p, "id"), id) == 0)
			return (p);
	return (NULL);
}

/* The data bridge.js applied of plugin id, as it told it; "" none. */
static void
data_set(const char *id, const char *json)
{
	ucl_object_t	*o;

	if (pl.data == NULL)
		pl.data = ucl_object_typed_new(UCL_OBJECT);
	if (json[0] == '\0' || (o = json_parse(json)) == NULL) {
		ucl_object_delete_key(pl.data, id);
		return;
	}
	ucl_object_replace_key(pl.data, o, id, 0, true);
}

/* The themes of plugins' data, for Look beside the stylesheet's. */
void
plugins_themes(struct html *h)
{
	const ucl_object_t	*d, *t;
	ucl_object_iter_t	 it, jt;

	it = NULL;
	while ((d = ucl_object_iterate(pl.data, &it, true)) != NULL) {
		jt = NULL;
		while ((t = ucl_object_iterate(jget(d, "themes"), &jt, true)) !=
		    NULL) {
			if (jstr(t, "key") == NULL || jstr(t, "name") == NULL)
				continue;
			h_fmt(h, "<button type=\"button\" class=\"theme "
			    "t-plugin%s\" data-act=\"theme\"",
			    strcmp(app.theme, jstr(t, "key")) == 0 ? " on" : "");
			h_attr(h, "data-arg", jstr(t, "key"));
			h_raw(h, "><i></i>");
			h_txt(h, jstr(t, "name"));
			h_raw(h, "</button>");
		}
	}
}

/* The guide packs of plugins' data: a picture and a line of each, as
 * text. */
static void
packs_shown(struct html *h)
{
	const ucl_object_t	*d, *g;
	ucl_object_iter_t	 it, jt;
	bool			 any;

	any = false;
	it = NULL;
	while ((d = ucl_object_iterate(pl.data, &it, true)) != NULL) {
		jt = NULL;
		while ((g = ucl_object_iterate(jget(d, "packs"), &jt, true)) !=
		    NULL) {
			if (jstr(g, "id") == NULL || jstr(g, "name") == NULL)
				continue;
			if (!any)
				h_raw(h, "<h3 class=\"set-sub\">Guide packs</h3>"
				    "<p class=\"dim\">For a guide that takes "
				    "them (Game mode's): what each shows and "
				    "the first thing it says.</p><div "
				    "class=\"cplug-packs\">");
			any = true;
			h_raw(h, "<figure class=\"cplug-pack\"");
			h_attr(h, "data-pack", jstr(g, "id"));
			h_raw(h, ">");
			if (jstr(g, "picture") != NULL &&
			    strncmp(jstr(g, "picture"), "/plugins/", 9) == 0) {
				h_raw(h, "<img alt=\"\" loading=\"lazy\"");
				h_attr(h, "src", jstr(g, "picture"));
				h_raw(h, ">");
			}
			h_raw(h, "<figcaption><b>");
			h_txt(h, jstr(g, "name"));
			h_raw(h, "</b>");
			if (jstr(g, "line") != NULL && jstr(g, "line")[0] !=
			    '\0') {
				h_raw(h, " <q>");
				h_txt(h, jstr(g, "line"));
				h_raw(h, "</q>");
			}
			h_raw(h, "</figcaption></figure>");
		}
	}
	if (any)
		h_raw(h, "</div>");
}

static bool
word_ok(const char *s, bool upper)
{

	if (*s == '\0')
		return (false);
	for (; *s != '\0'; s++)
		if (!((*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9') ||
		    *s == '-' || (upper && ((*s >= 'A' && *s <= 'Z') ||
		    *s == '_'))))
			return (false);
	return (true);
}

/* A plugin's screen, as the address names it after #/p/. */
void
plugins_open(const char *spec)
{
	const char	*s;
	char		 id[48], name[48];
	size_t		 n;

	n = strcspn(spec, "/");
	snprintf(id, sizeof(id), "%.*s", (int)n, spec);
	s = spec[n] == '/' ? spec + n + 1 : spec + n;
	snprintf(name, sizeof(name), "%.*s", (int)strcspn(s, "/"), s);
	if (!word_ok(id, false) || !word_ok(name, true)) {
		toast(true, "No plugin's screen is #/p/%s", spec);
		pl.screen[0] = '\0';
		return;
	}
	snprintf(pl.screen, sizeof(pl.screen), "%s", spec);
}

/* Back to the console's own pages, as they were. */
void
plugins_close(void)
{

	pl.screen[0] = '\0';
}

/* The address of the plugin's screen shown, if one is. */
bool
plugins_loc(char *buf, size_t len)
{

	if (pl.screen[0] == '\0')
		return (false);
	snprintf(buf, len, "#/p/%s", pl.screen);
	return (true);
}

/* After each drawing: the page shows the plugin's screen, or none. */
void
plugins_render(void)
{

	arc_plug_screen(app.screen == SCREEN_CONSOLE ? pl.screen : "");
}

/* The hosts changed: told to the plugins, by id and name. */
void
plugins_servers(void)
{
	ucl_object_t	*a, *o;
	char		*t;
	int		 i;

	a = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < app.nservers; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(
		    app.servers[i].id), "id", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(
		    app.servers[i].name), "name", 0, false);
		ucl_object_insert_key(o, ucl_object_frombool(
		    app.servers[i].local), "local", 0, false);
		ucl_array_append(a, o);
	}
	t = (char *)ucl_object_emit(a, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(a);
	if (pl.servers != NULL && strcmp(pl.servers, t) == 0) {
		free(t);
		return;
	}
	free(pl.servers);
	pl.servers = t;
	arc_plug_event("servers", t);
}

/* Signed out: the plugins told, their screen put away; read again at
 * the next sign-in. */
void
plugins_signed_out(void)
{

	pl.screen[0] = '\0';
	pl.fetched = 0;
	arc_plug_event("signed-out", "{}");
}

/* The entries plugins add to the account menu. */
void
plugins_menu(struct html *h)
{
	const ucl_object_t	*m;
	ucl_object_iter_t	 it;
	char			 arg[100];

	it = NULL;
	while ((m = ucl_object_iterate(pl.menu, &it, true)) != NULL) {
		snprintf(arg, sizeof(arg), "%s/%s", jstr(m, "plugin"), jstr(m,
		    "screen"));
		h_raw(h, "<button class=\"ghost\" data-act=\"plugin-open\"");
		h_attr(h, "data-arg", arg);
		h_raw(h, ">");
		h_txt(h, jstr(m, "label"));
		h_raw(h, "</button>");
	}
}

/* A plugin's entries for the menu, as it registered them: kept valid. */
static void
menu_set(const char *id, const char *json)
{
	ucl_object_t		*in, *keep, *e;
	const ucl_object_t	*m;
	ucl_object_iter_t	 it;
	const char		*label, *screen;

	keep = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((m = ucl_object_iterate(pl.menu, &it, true)) != NULL)
		if (strcmp(jstr(m, "plugin"), id) != 0)
			ucl_array_append(keep, ucl_object_ref(
			    (ucl_object_t *)(uintptr_t)m));
	in = json_parse(json);
	it = NULL;
	while ((m = ucl_object_iterate(in, &it, true)) != NULL) {
		label = jstr(m, "label");
		screen = jstr(m, "screen");
		if (label == NULL || screen == NULL || !word_ok(screen, true) ||
		    strlen(label) > 64 || strlen(screen) > 40)
			continue;
		e = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(e, ucl_object_fromstring(id), "plugin", 0,
		    false);
		ucl_object_insert_key(e, ucl_object_fromstring(label), "label",
		    0, false);
		ucl_object_insert_key(e, ucl_object_fromstring(screen),
		    "screen", 0, false);
		ucl_array_append(keep, e);
	}
	if (in != NULL)
		ucl_object_unref(in);
	if (pl.menu != NULL)
		ucl_object_unref(pl.menu);
	pl.menu = keep;
}

bool
plugins_action(const char *act, const char *arg, const char *value)
{
	char	body[48], url[200];

	if (strcmp(act, "plugin-open") == 0) {
		plugins_open(arg);
	} else if (strcmp(act, "plugin-exit") == 0) {
		/* ctx.exit(): its screen, if it is the one shown. */
		if (strncmp(pl.screen, arg, strlen(arg)) == 0 &&
		    (pl.screen[strlen(arg)] == '\0' ||
		    pl.screen[strlen(arg)] == '/'))
			pl.screen[0] = '\0';
	} else if (strcmp(act, "plugin-missing") == 0) {
		if (strcmp(pl.screen, arg) == 0) {
			pl.screen[0] = '\0';
			toast(true, "No plugin's screen is #/p/%s", arg);
		}
	} else if (strcmp(act, "plugin-loaded") == 0) {
		if (page_get(arg) == NULL)
			page_set(arg, "loaded");
	} else if (strcmp(act, "plugin-error") == 0) {
		/* The first error is the one to read; a toast says it. */
		if (page_get(arg) == NULL || strcmp(page_get(arg), "loaded") ==
		    0)
			toast(true, "Plugin %s: %s", arg, value);
		page_set(arg, value);
	} else if (strcmp(act, "plugin-data") == 0) {
		data_set(arg, value);
	} else if (strcmp(act, "plugin-unloaded") == 0) {
		/* A plugin of data alone, disabled: gone from the page. */
		if (pl.page != NULL)
			ucl_object_delete_key(pl.page, arg);
		data_set(arg, "");
	} else if (strcmp(act, "plugin-menu") == 0) {
		menu_set(arg, value);
	} else if (strcmp(act, "plugin-toast") == 0) {
		toast(arg[0] != '\0', "%s", value);
	} else if (strcmp(act, "plugin-enable") == 0 && strcmp(value, "1") ==
	    0 && plugin_of(arg) != NULL && trusted(plugin_of(arg))) {
		/* Code that runs as everyone: asked first. */
		confirm("Enable a trusted plugin?", "Its scripts will run in "
		    "this page as every user who opens it, with that user's "
		    "session: they can read and do whatever that user can, on "
		    "the console and on every host. Enable it only if you trust "
		    "whoever wrote it and whoever installed it.", "Enable", true,
		    "", "plugin-enable-trusted", arg, "1");
	} else if (strcmp(act, "plugin-enable") == 0 ||
	    strcmp(act, "plugin-enable-trusted") == 0) {
		/* A console owner's alone; the reply is the list. */
		if (pl.busy[0] != '\0' || !word_ok(arg, false) || strlen(arg) >
		    40)
			return (true);
		snprintf(pl.busy, sizeof(pl.busy), "%s", arg);
		rc_c(url, sizeof(url), "plugins/plugin=%s/enabled",
		    rc_key(arg));
		snprintf(body, sizeof(body), "{\"arcana-console:enabled\":%s}",
		    strcmp(value, "1") == 0 ? "true" : "false");
		pl.loading = true;
		rc_edit("PUT", url, body, enabled_cb, NULL);
	} else
		return (false);
	return (true);
}

/* What the page made of a plugin: running (applied, for data), failed,
 * or put away at the next reload. */
static void
state_cell(struct html *h, const ucl_object_t *p, bool code)
{
	const char	*id, *page;
	bool		 on;

	id = jstr(p, "id");
	page = page_get(id);
	on = jbool(p, "enabled");
	if (jstr(p, "error") != NULL) {
		h_raw(h, "<span class=\"err\">");
		h_txt(h, jstr(p, "error"));
		h_raw(h, "</span>");
	} else if (page != NULL && strcmp(page, "loaded") != 0) {
		h_raw(h, "<span class=\"err\">In this page: ");
		h_txt(h, page);
		h_raw(h, "</span>");
	} else if (page != NULL && on)
		h_fmt(h, "<span class=\"chip st-up\">%s</span>", code ?
		    "running here" : "in use here");
	else if (page != NULL)
		h_raw(h, "<span class=\"chip warn\">running here until this "
		    "page is reloaded</span>");
	else if (on)
		h_raw(h, "<span class=\"dim\">loading…</span>");
	else
		h_raw(h, "<span class=\"dim\">off</span>");
}

/* The plugins of one kind, data or trusted (code), in a table of their
 * own; their number. */
static int
plug_table(struct html *h, const char *tid, bool code, bool owner)
{
	const ucl_object_t	**rows, *p, *w;
	ucl_object_iter_t	  it;
	int			  r, n, k;

	rows = tbl_rows(tid, jget(pl.o, "plugins"), pcols, nitems(pcols),
	    app.filter);
	for (r = k = 0; (p = rows[r]) != NULL; r++) {
		if (trusted(p) != code)
			continue;
		if (k++ == 0) {
			h_fmt(h, "<table class=\"net cplugs%s\">", code ?
			    " trusted" : "");
			tbl_head(h, tid, pcols, nitems(pcols), owner ? 1 : 0);
			h_raw(h, "<tbody>");
		}
		h_raw(h, "<tr");
		h_attr(h, "data-plugin", jstr(p, "id"));
		h_raw(h, "><td><b>");
		h_txt(h, jstr(p, "name") != NULL ? jstr(p, "name") :
		    jstr(p, "id"));
		h_raw(h, "</b> <small class=\"dim mono\">");
		h_txt(h, jstr(p, "id"));
		h_raw(h, "</small>");
		if (jstr(p, "description") != NULL) {
			h_raw(h, "<br><small class=\"dim\">");
			h_txt(h, jstr(p, "description"));
			h_raw(h, "</small>");
		}
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(p, "version") != NULL ? jstr(p, "version") : "");
		h_raw(h, "</td><td>");
		h_txt(h, jstr(p, "author") != NULL ? jstr(p, "author") : "");
		h_raw(h, "</td><td>");
		n = 0;
		it = NULL;
		while ((w = ucl_object_iterate(jget(p, "provides"), &it,
		    true)) != NULL) {
			h_raw(h, "<span class=\"chip\">");
			h_txt(h, ucl_object_tostring_forced(w));
			h_raw(h, "</span> ");
			n++;
		}
		h_rawf(h, "%s</td><td>%s</td><td>", n == 0 ?
		    "<span class=\"dim\">—</span>" : "", jbool(p, "enabled") ?
		    "yes" : "no");
		state_cell(h, p, code);
		h_raw(h, "</td>");
		if (owner) {
			h_raw(h, "<td>");
			if (jstr(p, "error") == NULL || jbool(p, "enabled")) {
				h_fmt(h, "<button class=\"ghost small\" "
				    "data-act=\"plugin-enable\" "
				    "data-value=\"%s\"%s",
				    jbool(p, "enabled") ? "0" : "1",
				    pl.busy[0] != '\0' ? " disabled" : "");
				h_attr(h, "data-arg", jstr(p, "id"));
				h_fmt(h, ">%s</button>", jbool(p, "enabled") ?
				    "Disable" : "Enable");
			}
			h_raw(h, "</td>");
		}
		h_raw(h, "</tr>");
	}
	free(rows);
	if (k > 0)
		h_raw(h, "</tbody></table>");
	return (k);
}

void
set_plugins(struct html *h)
{
	const ucl_object_t	*p;
	ucl_object_iter_t	 it;
	bool			 owner;

	if (pl.o == NULL)
		list_load();
	owner = !app.by_token && strcmp(app.console_role, "owner") == 0;
	h_raw(h, "<p class=\"dim\">Extensions of this page that the console "
	    "host's administrator installed, each enabled by a console owner "
	    "for every signed-in page. Themes and guide packs are data: this "
	    "page reads and applies them itself, and puts them away at once "
	    "when they are disabled. A trusted plugin brings code.</p>");
	if (owner && jstr(pl.o, "dir") != NULL) {
		h_raw(h, "<p class=\"dim\">Installed under <code>");
		h_txt(h, jstr(pl.o, "dir"));
		h_raw(h, "</code>, a directory each (web.conf's "
		    "<code>plugins_dir</code>).</p>");
	}
	if (pl.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, pl.error);
		h_raw(h, "</div>");
	}
	if (pl.o == NULL) {
		h_raw(h, "<p class=\"dim\">Reading…</p>");
		return;
	}
	if (ucl_array_size(jget(pl.o, "plugins")) == 0) {
		h_raw(h, "<div class=\"empty\"><p>No console plugin is "
		    "installed.</p></div>");
		return;
	}
	h_raw(h, "<div class=\"toolbar\"><input class=\"filter\" id=\"filter\" "
	    "data-input=\"filter\" placeholder=\"Filter\" autocomplete=\"off\" "
	    "spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, "></div>");
	(void)plug_table(h, "cplugs", false, owner);
	packs_shown(h);
	it = NULL;
	while ((p = ucl_object_iterate(jget(pl.o, "plugins"), &it, true)) !=
	    NULL)
		if (trusted(p)) {
			h_raw(h, "<h3 class=\"set-sub\">Trusted plugins</h3>"
			    "<div class=\"notice warn cplug-warn\"><b>These "
			    "run code.</b> A trusted plugin's scripts run in "
			    "this page as every user who opens it, with that "
			    "user's session: they can read and do whatever "
			    "that user can, on the console and on every host. "
			    "Enabling one asks first; disabled, it is gone from "
			    "a page once that page is reloaded.</div>");
			(void)plug_table(h, "cplugs-t", true, owner);
			break;
		}
	if (!owner)
		h_raw(h, "<p class=\"dim\">A console owner enables and "
		    "disables them.</p>");
}
