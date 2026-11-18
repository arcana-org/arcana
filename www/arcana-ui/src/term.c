/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A host's Terminal tab: login(1) on the host, or in one of its running
 * jails, in xterm.js (vendor/xterm), over the console's /api/terminal
 * socket (the console's terminal.c).  The page draws the picker and the
 * buttons; the terminal itself is the bridge's (js/bridge.js, arcTerm),
 * drawn into an element the page leaves alone across its patches
 * (data-keep), named by the host so that another host's tab is another
 * element, and the one before is hung up.  What it says (connecting,
 * logged in, ended and why, the connection dropped) it writes there
 * itself.  Leaving the tab hangs it up.
 *
 * A mapped login: where the host's admins mapped the signed-in user to
 * an account of the host's or of the jail picked (arcana-console's
 * terminal-login), the tab says before Connect whom they will be logged
 * in as, without a password; the password prompt instead, where the
 * host allows it (terminal-prompt), when they tick it.  The host's
 * admins keep the mappings and the switch here, told that a mapping
 * gives that account's full rights.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	char	sid[9];
	char	jail[256];	/* "" the host */
	bool	prompt;		/* the password prompt, though mapped */
} tm;

static void	term_maps(struct html *, struct server *,
		    const ucl_object_t *);

/* The account the signed-in user is logged in as on host entry e, in
 * jail ("" the host), or NULL: no mapped login. */
static const char *
my_account(const ucl_object_t *e, const char *jail)
{
	const ucl_object_t	*m;
	ucl_object_iter_t	 it = NULL;

	if (app.user[0] == '\0')
		return (NULL);
	while ((m = ucl_object_iterate(jget(e, "terminal-login"), &it,
	    true)) != NULL)
		if (jstr(m, "user") != NULL && strcmp(jstr(m, "user"),
		    app.user) == 0 && jstr(m, "jail") != NULL && strcmp(jstr(m,
		    "jail"), jail[0] != '\0' ? jail : ".") == 0)
			return (jstr(m, "account"));
	return (NULL);
}

/* Does host entry e have no password prompt? */
static bool
prompt_never(const ucl_object_t *e)
{

	return (jstr(e, "terminal-prompt") != NULL && strcmp(jstr(e,
	    "terminal-prompt"), "never") == 0);
}

void
view_terminal(struct html *h, struct server *s)
{
	const ucl_object_t	*o, *e;
	ucl_object_iter_t	 it;
	const char		*acct;
	bool			 found, never;

	if (strcmp(tm.sid, s->id) != 0) {
		snprintf(tm.sid, sizeof(tm.sid), "%s", s->id);
		tm.jail[0] = '\0';
	}
	h_raw(h, "<section class=\"termpage\"><div class=\"toolbar\">"
	    "<label>On <select id=\"term-jail\" data-input=\"term-jail\" "
	    "title=\"The host, or one of its running jails: its own login, "
	    "its own accounts\"><option value=\"\"");
	h_raw(h, tm.jail[0] == '\0' ? " selected>" : ">");
	h_txt(h, s->name);
	h_raw(h, " (the host)</option>");
	found = tm.jail[0] == '\0';
	it = NULL;
	while (s->list != NULL && (o = ucl_object_iterate(jget(s->list,
	    "jails"), &it, true)) != NULL) {
		if (jstr(o, "name") == NULL || jstr(o, "state") == NULL ||
		    strcmp(jstr(o, "state"), "running") != 0)
			continue;
		h_raw(h, "<option");
		h_attr(h, "value", jstr(o, "name"));
		if (strcmp(tm.jail, jstr(o, "name")) == 0) {
			h_raw(h, " selected");
			found = true;
		}
		h_raw(h, ">jail ");
		h_txt(h, jstr(o, "name"));
		h_raw(h, "</option>");
	}
	if (!found)
		tm.jail[0] = '\0';
	e = host_entry(s->id);
	acct = e != NULL ? my_account(e, tm.jail) : NULL;
	never = e != NULL && prompt_never(e);
	h_raw(h, "</select></label>");
	if (acct != NULL && !never)
		h_fmt(h, "<label class=\"toggle\"><input type=\"checkbox\" "
		    "data-input=\"term-prompt\" id=\"term-prompt\"%s><span>"
		    "The password prompt instead</span></label>", tm.prompt ?
		    " checked" : "");
	h_fmt(h, "<button data-act=\"term-open\" id=\"term-open\"%s title="
	    "\"%s\">Connect</button><button ", acct == NULL && never ?
	    " disabled" : "", acct != NULL && !tm.prompt ? "A new session, "
	    "logged in as the mapped account" : "A new session: login asks "
	    "for an account's name and password");
	h_raw(h, "class=\"ghost\" data-act=\"term-close\" id=\"term-close\" "
	    "title=\"Hang up: the session's processes get SIGHUP\">"
	    "Disconnect</button></div>");
	if (acct != NULL && !(tm.prompt && !never)) {
		h_raw(h, "<p class=\"termas\" id=\"term-as\">You will be "
		    "logged in as <b>");
		h_txt(h, acct);
		h_raw(h, "</b>");
		h_raw(h, tm.jail[0] != '\0' ? " in the jail" : " on the host");
		h_raw(h, ", without a password (a mapped login: login -f, as "
		    "the host's own terminal-users allows it).</p>");
	} else if (acct == NULL && never)
		h_raw(h, "<p class=\"termas\" id=\"term-as\">This host allows "
		    "no password prompt, and no mapped login of yours is "
		    "there: its admins map one.</p>");
	h_raw(h, "<p class=\"dim termnote\">login(1) of "
	    "the host, or of the jail, on a pseudo-terminal of its own, as on "
	    "its console: log in with an account of its own, whose password "
	    "the host checks (PAM); root only as its own rules allow. "
	    "Operators and admins of the host may open one (operators only "
	    "where the hosts' default for actions is permit: with deny, the "
	    "host's admin adds a rule by hand); each is in the "
	    "audit trail, and one nobody types in for 30 minutes is hung up."
	    "</p>");
	/* The bridge's from here on; another host's is another. */
	h_fmt(h, "<div class=\"termwrap\" id=\"term-wrap-%s\" data-keep "
	    "data-state=\"idle\"><div class=\"termstat\">Not connected: "
	    "Connect opens a session.</div><div class=\"termbox\"></div>"
	    "</div>", s->id);
	if (e != NULL && jstr(e, "role") != NULL && strcmp(jstr(e, "role"),
	    "admin") == 0)
		term_maps(h, s, e);
	h_raw(h, "</section>");
}

/*
 * The host's mapped logins and its password prompt, for its admins: a
 * table of them (sorted and filtered as every table), one taken out by
 * its button, one added by the form; each written by its own path.
 */
static void
term_maps(struct html *h, struct server *s, const ucl_object_t *e)
{
	static const struct tcol	cols[] = {
		{ "Where", "jail", false }, { "Console user", "user", false },
		{ "Account", "account", false }, { "Mapped by", "author",
		false }, { "When", "changed", false },
	};
	const ucl_object_t		**rows, *r, *o;
	ucl_object_iter_t		  it;
	int				  n;

	h_raw(h, "<section class=\"transport termmaps\">");
	box_head(h, "termmaps", "h3");
	h_raw(h, "Mapped logins</h3>");
	if (box_shut("termmaps")) {
		h_raw(h, "</section>");
		return;
	}
	h_raw(h, "<p class=\"warn\" id=\"term-maps-warn\">A mapped login "
	    "logs a console user in as an account of the host's, or of a "
	    "jail's, <b>without its password</b>: it grants that account's "
	    "full rights, sudo and wheel included. The host's own "
	    "/usr/local/etc/arcana/terminal-users (root's, 0600) must allow "
	    "it too; these only choose among what it allows. Each change is "
	    "in the audit trail.</p>");
	h_fmt(h, "<form data-form=\"term-switch\" class=\"toolbar\"><label>"
	    "Password prompt <select name=\"prompt\" id=\"term-switch\">"
	    "<option value=\"allowed\"%s>allowed</option><option value=\""
	    "never\"%s>never: mapped logins alone</option></select></label>"
	    "<button class=\"ghost small\">Save</button></form>",
	    prompt_never(e) ? "" : " selected", prompt_never(e) ?
	    " selected" : "");
	h_raw(h, "<div class=\"toolbar\"><input class=\"filter\" id=\""
	    "filter\" data-input=\"filter\" placeholder=\"Filter\" "
	    "autocomplete=\"off\" spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, "></div><table class=\"net termmap\">");
	tbl_head(h, "term-maps", cols, 5, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("term-maps", jget(e, "terminal-login"), cols, 5,
	    app.filter);
	for (n = 0; (r = rows[n]) != NULL; n++) {
		h_raw(h, "<tr><td>");
		h_txt(h, jstr(r, "jail") != NULL && strcmp(jstr(r, "jail"),
		    ".") != 0 ? jstr(r, "jail") : "the host");
		h_raw(h, "</td><td>");
		h_txt(h, jstr(r, "user"));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(r, "account"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(r, "author") != NULL ? jstr(r, "author") : "");
		h_raw(h, "</td><td>");
		h_txt(h, jstr(r, "changed") != NULL ? jstr(r, "changed") : "");
		h_raw(h, "</td><td class=\"acts\"><button class=\"ghost small\" "
		    "data-act=\"term-unmap\" title=\"Take the mapped login "
		    "out: an open one is hung up\"");
		h_attr(h, "data-arg", jstr(r, "jail"));
		h_attr(h, "data-value", jstr(r, "user"));
		h_raw(h, ">Remove</button></td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table><form data-form=\"term-map\" class=\""
	    "toolbar\"><label>On <select name=\"jail\"><option value=\".\">"
	    "the host</option>");
	it = NULL;
	while (s->list != NULL && (o = ucl_object_iterate(jget(s->list,
	    "jails"), &it, true)) != NULL) {
		if (jstr(o, "name") == NULL)
			continue;
		h_raw(h, "<option");
		h_attr(h, "value", jstr(o, "name"));
		h_raw(h, ">jail ");
		h_txt(h, jstr(o, "name"));
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label><label>Console user <input name=\"user\" "
	    "autocomplete=\"off\" spellcheck=\"false\" required></label>"
	    "<label>Account <input name=\"account\" class=\"mono\" "
	    "pattern=\"[a-z_][a-z0-9_\\-]{0,31}\" autocomplete=\"off\" "
	    "spellcheck=\"false\" required></label><button class=\"small\" "
	    "title=\"Grants that account's full rights, without its "
	    "password\">Map</button></form></section>");
}

static void
term_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)o;
	(void)arg;
	/* Refused (another changed the host since: its ETag) or not, the
	 * tab reads the host again. */
	if (status < 200 || status > 299)
		toast(true, "The mapped logins were not saved: %s", err != NULL ?
		    err : "the console refused");
	else
		toast(false, "Mapped logins saved");
	refresh_servers();
}

/* An account's name as the host takes it: [a-z_][a-z0-9_-]{0,31}. */
static bool
account_ok(const char *a)
{
	size_t	n;

	return (a != NULL && (n = strlen(a)) > 0 && n <= 32 && ((a[0] >= 'a' &&
	    a[0] <= 'z') || a[0] == '_') && strspn(a,
	    "abcdefghijklmnopqrstuvwxyz0123456789_-") == n);
}

/*
 * The switch, or one mapped login, written by its own path, never the
 * host's whole entry: a tab that read it long ago brings back nothing
 * another took out since.
 */
static void
term_write(const char *method, const char *path, ucl_object_t *body)
{
	unsigned char	*json;

	json = body != NULL ? ucl_object_emit(body, UCL_EMIT_JSON_COMPACT) :
	    NULL;
	rc_edit(method, path, (const char *)json, term_cb, NULL);
	free(json);
	if (body != NULL)
		ucl_object_unref(body);
}

bool
term_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	ucl_object_t	*top, *a, *r;
	const char	*jail, *user, *acct, *v;
	char		 url[400];

	if (strcmp(form, "term-switch") != 0 && strcmp(form, "term-map") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(form, "term-switch") == 0) {
		v = jstr(f, "prompt");
		top = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(top, ucl_object_fromstring(v != NULL &&
		    strcmp(v, "never") == 0 ? "never" : "allowed"),
		    "arcana-console:terminal-prompt", 0, false);
		term_write("PUT", rc_c(url, sizeof(url),
		    "hosts/host=%s/terminal-prompt", rc_key(s->id)), top);
		return (true);
	}
	jail = jstr(f, "jail") != NULL ? jstr(f, "jail") : ".";
	user = jstr(f, "user");
	acct = jstr(f, "account");
	if (user == NULL || user[0] == '\0' || !account_ok(acct)) {
		toast(true, "A mapped login is a console user and an account: a "
		    "lowercase letter or _, then lowercase letters, digits, _ "
		    "and -, 32 at most");
		return (true);
	}
	/* One per user and place: the one there before replaced. */
	r = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(r, ucl_object_fromstring(jail), "jail", 0, true);
	ucl_object_insert_key(r, ucl_object_fromstring(user), "user", 0, true);
	ucl_object_insert_key(r, ucl_object_fromstring(acct), "account", 0,
	    true);
	a = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(a, r);
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, a, "arcana-console:terminal-login", 0,
	    false);
	term_write("PUT", rc_c(url, sizeof(url), "hosts/host=%s/"
	    "terminal-login=%s,%s", rc_key(s->id), rc_key(jail), rc_key(user)),
	    top);
	return (true);
}

/* A mapped login taken out of host s by its own path: jail's, user's. */
static void
term_unmap(struct server *s, const char *jail, const char *user)
{
	char	url[400];

	if (jail == NULL || user == NULL)
		return;
	term_write("DELETE", rc_c(url, sizeof(url), "hosts/host=%s/"
	    "terminal-login=%s,%s", rc_key(s->id), rc_key(jail), rc_key(user)),
	    NULL);
}

bool
term_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	size_t		 n;

	(void)arg;
	if (strcmp(act, "term-open") != 0 && strcmp(act, "term-close") != 0 &&
	    strcmp(act, "input:term-jail") != 0 && strcmp(act,
	    "input:term-prompt") != 0 && strcmp(act, "term-unmap") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "input:term-prompt") == 0) {
		tm.prompt = value != NULL && (strcmp(value, "true") == 0 ||
		    strcmp(value, "on") == 0 || strcmp(value, "1") == 0);
		return (true);
	}
	if (strcmp(act, "term-unmap") == 0) {
		term_unmap(s, arg, value);
		return (true);
	}
	if (strcmp(act, "input:term-jail") == 0) {
		n = value != NULL ? strlen(value) : 0;
		if (n < sizeof(tm.jail) && (n == 0 || (value[0] != '.' &&
		    value[strspn(value, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
		    "KLMNOPQRSTUVWXYZ0123456789_.-")] == '\0')))
			snprintf(tm.jail, sizeof(tm.jail), "%s", n > 0 ? value :
			    "");
		return (true);
	}
	if (strcmp(act, "term-open") == 0)
		arc_term_open(s->id, tm.jail, tm.prompt);
	else
		arc_term_close();
	return (true);
}
