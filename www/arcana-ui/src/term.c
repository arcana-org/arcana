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
 */

#include <stdio.h>
#include <string.h>

#include "app.h"

static struct {
	char	sid[9];
	char	jail[256];	/* "" the host */
} tm;

void
view_terminal(struct html *h, struct server *s)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	bool			 found;

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
	h_raw(h, "</select></label><button data-act=\"term-open\" "
	    "id=\"term-open\" title=\"A new session: login asks for an "
	    "account's name and password\">Connect</button><button "
	    "class=\"ghost\" data-act=\"term-close\" id=\"term-close\" "
	    "title=\"Hang up: the session's processes get SIGHUP\">"
	    "Disconnect</button></div><p class=\"dim termnote\">login(1) of "
	    "the host, or of the jail, on a pseudo-terminal of its own, as on "
	    "its console: log in with an account of its own, whose password "
	    "the host checks (PAM); root only as its own rules allow. "
	    "Operators and admins of the host may open one; each is in the "
	    "audit trail, and one nobody types in for 30 minutes is hung up."
	    "</p>");
	/* The bridge's from here on; another host's is another. */
	h_fmt(h, "<div class=\"termwrap\" id=\"term-wrap-%s\" data-keep "
	    "data-state=\"idle\"><div class=\"termstat\">Not connected: "
	    "Connect opens a session.</div><div class=\"termbox\"></div>"
	    "</div></section>", s->id);
}

bool
term_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	size_t		 n;

	(void)arg;
	if (strcmp(act, "term-open") != 0 && strcmp(act, "term-close") != 0 &&
	    strcmp(act, "input:term-jail") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
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
		arc_term_open(s->id, tm.jail);
	else
		arc_term_close();
	return (true);
}
