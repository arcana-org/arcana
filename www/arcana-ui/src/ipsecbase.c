/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * In a host's network tab, a section of the base system's: its IPsec
 * without IKE, whether or not strongSwan is there.  RFC 9061's IKE-less
 * lists (ietf-i2nsf-ikeless, the agent's ikeless.c), each sent by the
 * agent over PF_KEY (pfkey(4)) in its own process: the kernel's SAD and
 * SPD as the host's operational datastore tells them, every SA and
 * policy; those of the lists' controller, Arcana (an SD-WAN tunnel's
 * SAs, derived by the agent, among them), by their names, each edited
 * by the form its model makes (yform.c) or taken out of the candidate
 * and committed confirmed (ycommit.c); the rest, setkey's, an IKE
 * daemon's, an interface's, by the kernel's names, read only.  And
 * ipsec.conf, setkey(8)'s commands, which rc.d/ipsec (ipsec_enable)
 * loads at boot, with the kernel's SPD read beside it.  IKE is the
 * strongSwan plugin's (ipsec.c).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	IKL_MOD		"ietf-i2nsf-ikeless"
#define	IKL_TOP		"ietf-i2nsf-ikeless:ipsec-ikeless"

static void	ikl_saved(struct ycommit *, int);

/* The lists as the host's kernel has them, and running's names. */
static struct {
	char		 sid[9];
	ucl_object_t	*oper;		/* the operational datastore's */
	ucl_object_t	*run;		/* running's */
	bool		 loading;
	bool		 stale;		/* read again once the form is shut */
	char		 error[300];
	struct ycommit	 yc;
} ikl = { .yc = { .act = "ikl-yc", .saved = "Saved: the kernel has it, "
    "and running keeps it.", .undone = "Undone: the SAD and SPD are as "
    "they were.", .done = ikl_saved } };

static void
ikl_run_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*sid = arg;

	(void)err;
	if (strcmp(sid, ikl.sid) == 0) {
		if (ikl.run != NULL)
			ucl_object_unref(ikl.run);
		ikl.run = status == 200 && o != NULL ? ucl_object_copy(o) :
		    NULL;
	}
	free(sid);
}

static void
ikl_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*sid = arg;
	char	 url[300];

	if (strcmp(sid, ikl.sid) != 0) {
		free(sid);
		return;
	}
	ikl.loading = false;
	if (ikl.oper != NULL)
		ucl_object_unref(ikl.oper);
	ikl.oper = NULL;
	if (status == 200 && o != NULL)
		ikl.oper = ucl_object_copy(o);
	else if (status == 404)
		ikl.oper = ucl_object_typed_new(UCL_OBJECT);
	else
		snprintf(ikl.error, sizeof(ikl.error), "%s", rc_why(o, err));
	rc_get(rc_ds(url, sizeof(url), "running", sid, IKL_TOP), NULL,
	    ikl_run_cb, sid);
}

static void
ikl_load(struct server *s)
{
	char	url[300];

	if (ikl.loading)
		return;
	if (strcmp(ikl.sid, s->id) != 0) {
		if (ikl.oper != NULL)
			ucl_object_unref(ikl.oper);
		if (ikl.run != NULL)
			ucl_object_unref(ikl.run);
		ikl.oper = ikl.run = NULL;
	}
	snprintf(ikl.sid, sizeof(ikl.sid), "%s", s->id);
	ikl.error[0] = '\0';
	ikl.loading = true;
	ikl.stale = false;
	rc_get(rc_ds(url, sizeof(url), "operational", s->id, IKL_TOP), NULL,
	    ikl_cb, strdup(s->id));
}

static void
ikl_saved(struct ycommit *yc, int how)
{
	struct server	*s;

	(void)how;
	if ((s = cur_server()) != NULL && strcmp(s->id, yc->sid) == 0)
		ikl_load(s);
}

/* Whether running has an entry of list (sad-entry, spd-entry) named
 * name: the controller's, Arcana's. */
static bool
ikl_ours(const char *list, const char *name)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	char			 key[64];

	snprintf(key, sizeof(key), "%s.%s", strcmp(list, "sad-entry") == 0 ?
	    "sad" : "spd", list);
	while (name != NULL && (e = ucl_object_iterate(jget(ikl.run, key), &it,
	    true)) != NULL)
		if (jstr(e, "name") != NULL && strcmp(jstr(e, "name"), name) ==
		    0)
			return (true);
	return (false);
}

/* The two ends of an SA or a policy: its tunnel's, else its selector's. */
static void
ikl_ends(struct html *h, const ucl_object_t *cfg, const char *tunnel)
{
	const ucl_object_t	*t = jget(cfg, tunnel);

	if (jstr(t, "local") != NULL) {
		h_txt(h, jstr(t, "local"));
		h_raw(h, " &rarr; ");
		h_txt(h, jstr(t, "remote") != NULL ? jstr(t, "remote") : "?");
		return;
	}
	t = jget(cfg, "traffic-selector");
	h_txt(h, jstr(t, "local-prefix") != NULL ? jstr(t, "local-prefix") :
	    "?");
	h_raw(h, " &rarr; ");
	h_txt(h, jstr(t, "remote-prefix") != NULL ? jstr(t, "remote-prefix") :
	    "?");
}

/* Its buttons: Edit and Remove for the controller's, a chip for the rest. */
static void
ikl_acts(struct html *h, const char *list, const char *name)
{
	char	arg[600];

	h_raw(h, "</td><td class=\"acts\">");
	if (!ikl_ours(list, name)) {
		h_raw(h, "<span class=\"chip\" title=\"Not Arcana's: "
		    "setkey's (ipsec.conf), an IKE daemon's or an ipsec(4) "
		    "interface's. Read only: no edit "
		    "here changes it\">kernel's</span>");
		return;
	}
	snprintf(arg, sizeof(arg), IKL_MOD "|/" IKL_TOP "/%s/%s|%s",
	    strcmp(list, "sad-entry") == 0 ? "sad" : "spd", list, name);
	/* A key with / or , cannot be named in a request's own path, which
	 * the form reads the entry by (the console's restconf.c): taken out
	 * by a YANG Patch, whose target is encoded, it can be. */
	if (strpbrk(name, "/,") != NULL)
		h_raw(h, "<button class=\"ghost small\" disabled title=\"Its "
		    "name has a / or a comma, which a request's path cannot "
		    "carry: edit it by Remove and + again, or from the "
		    "controller\">Edit</button>");
	else {
		h_raw(h, "<button class=\"ghost small\" data-act=\""
		    "ikl-edit\"");
		h_attr(h, "data-arg", arg);
		h_raw(h, ">Edit</button>");
	}
	h_raw(h, "<button class=\"ghost small\" data-act=\"ikl-del\"");
	snprintf(arg, sizeof(arg), "%s|%s", list, name);
	h_attr(h, "data-arg", arg);
	h_raw(h, ">Remove</button>");
}

static void
view_ikeless(struct html *h, struct server *s)
{
	static const struct tcol	sacols[] = {
		{ "Name", "name", false },
		{ "SPI", "ipsec-sa-config.spi", true },
		{ "reqid", "reqid", true },
		{ "Mode", "ipsec-sa-config.mode", false },
		{ "Packets", "ipsec-sa-state.sa-lifetime-current.packets", true },
	}, spcols[] = {
		{ "Name", "name", false },
		{ "Direction", "direction", false },
		{ "reqid", "reqid", true },
		{ "Action", "ipsec-policy-config.processing-info.action",
		    false },
	};
	const ucl_object_t	**rows, *r, *c;
	ucl_object_t		*list;
	int			 i;

	h_raw(h, "<section class=\"pane ipsec-ikeless\"><h4><span>SAD and "
	    "SPD <small>RFC 9061's IKE-less lists, by PF_KEY</small></span>"
	    "<span class=\"pane-actions\"><button class=\"ghost small\" "
	    "data-act=\"ikl-new\" data-arg=\"" IKL_MOD "|/" IKL_TOP
	    "/sad/sad-entry\" title=\"A security association: its SPI, "
	    "ends, algorithms and keys, put in by SADB_ADD\">+ SA</button>"
	    "<button class=\"ghost small\" data-act=\"ikl-new\" data-arg="
	    "\"" IKL_MOD "|/" IKL_TOP "/spd/spd-entry\" title=\"A security "
	    "policy: a selector, a direction, and what is done with its "
	    "traffic, put in by SADB_X_SPDADD\">+ policy</button><button "
	    "class=\"ghost small\" data-act=\"ikl-reload\">Refresh</button>"
	    "</span></h4><p class=\"dim\">The kernel's SAs and policies, "
	    "every one: Arcana's by the names they were given, the rest "
	    "(setkey's, an IKE daemon's, an interface's) by the kernel's, "
	    "read only. A selector's local prefix is its packets' source. "
	    "Packets and idle lifetimes are the agent's, read every 10 "
	    "seconds; the rest the kernel's.</p>");
	if (strcmp(ikl.sid, s->id) != 0 || (ikl.oper == NULL && !ikl.loading &&
	    ikl.error[0] == '\0') || (ikl.stale && app.modal != MODAL_YFORM)) {
		ikl_load(s);
		if (ikl.oper == NULL) {
			h_raw(h, "<div class=\"loader\"></div></section>");
			return;
		}
	}
	if (ikl.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, ikl.error);
		h_raw(h, "</div>");
	}
	ycommit_note(h, &ikl.yc);
	if (ikl.oper == NULL) {
		h_raw(h, "</section>");
		return;
	}
	h_raw(h, "<h5>Security associations</h5>");
	list = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(ikl.oper,
	    "sad.sad-entry"));
	if (list == NULL || ucl_array_size(list) == 0)
		h_raw(h, "<div class=\"empty\"><p>No SAs: <b>+ SA</b> puts "
		    "one in.</p></div>");
	else {
		h_raw(h, "<table class=\"net ikl-sad\">");
		tbl_head(h, "ikl-sad", sacols, 5, 2);
		h_raw(h, "<tbody>");
		rows = tbl_rows("ikl-sad", list, sacols, 5, app.filter);
		for (i = 0; (r = rows[i]) != NULL; i++) {
			c = jget(r, "ipsec-sa-config");
			h_raw(h, "<tr><td class=\"mono\">");
			h_txt(h, jstr(r, "name"));
			h_fmt(h, "</td><td class=\"mono\">%#x</td><td>%d</td>"
			    "<td>", (unsigned)jint(c, "spi", 0),
			    (int)jint(r, "reqid", 0));
			h_txt(h, jstr(c, "mode") != NULL ? jstr(c, "mode") :
			    "transport");
			h_fmt(h, "</td><td>%lld</td><td class=\"mono\">",
			    (long long)jint(jget(jget(r, "ipsec-sa-state"),
			    "sa-lifetime-current"), "packets", 0));
			ikl_ends(h, c, "tunnel");
			ikl_acts(h, "sad-entry", jstr(r, "name"));
			h_raw(h, "</td></tr>");
		}
		free(rows);
		h_raw(h, "</tbody></table>");
	}
	if (list != NULL)
		ucl_object_unref(list);
	h_raw(h, "<h5>Security policies</h5>");
	list = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(ikl.oper,
	    "spd.spd-entry"));
	if (list == NULL || ucl_array_size(list) == 0)
		h_raw(h, "<div class=\"empty\"><p>No policies: <b>+ policy"
		    "</b> puts one in.</p></div>");
	else {
		h_raw(h, "<table class=\"net ikl-spd\">");
		tbl_head(h, "ikl-spd", spcols, 4, 2);
		h_raw(h, "<tbody>");
		rows = tbl_rows("ikl-spd", list, spcols, 4, app.filter);
		for (i = 0; (r = rows[i]) != NULL; i++) {
			c = jget(r, "ipsec-policy-config");
			h_raw(h, "<tr><td class=\"mono\">");
			h_txt(h, jstr(r, "name"));
			h_raw(h, "</td><td>");
			h_txt(h, jstr(r, "direction"));
			h_fmt(h, "</td><td>%d</td><td>", (int)jint(r, "reqid",
			    0));
			h_txt(h, jstr(jget(c, "processing-info"), "action") !=
			    NULL ? jstr(jget(c, "processing-info"), "action") :
			    "discard");
			h_raw(h, "</td><td class=\"mono\">");
			ikl_ends(h, c, "nothing");
			ikl_acts(h, "spd-entry", jstr(r, "name"));
			h_raw(h, "</td></tr>");
		}
		free(rows);
		h_raw(h, "</tbody></table>");
	}
	if (list != NULL)
		ucl_object_unref(list);
	h_raw(h, "</section>");
}

void
ipsecbase_tick(double now)
{

	ycommit_tick(&ikl.yc, now);
}

void
view_ipsecbase(struct html *h, struct server *s)
{

	h_raw(h, "<section class=\"pane ipsec-base\"><h4><span>IPsec <small>"
	    "the base system's: PF_KEY, ipsec(4), setkey(8)</small></span>"
	    "</h4><p class=\"dim\">The kernel's IPsec, with nothing "
	    "installed: an <code>ipsec</code>(4) interface made with a reqid "
	    "(the Interfaces' <b>+ interface</b>) carries what the SAs of "
	    "its reqid take; Arcana's agent sends them by PF_KEY (<code>"
	    "pfkey</code>(4)) itself, as <code>setkey</code>(8) would: the "
	    "SAD and SPD below, an SD-WAN tunnel's SAs among them, derived "
	    "by the agent from a key pair of its own and the far end's "
	    "public half.  <code>ipsec.conf</code> below is "
	    "setkey's own, loaded at boot by <code>rc.d/ipsec</code> "
	    "(<code>ipsec_enable</code>).  IKE, keys agreed by a daemon, is "
	    "the strongSwan plugin's section.</p></section>");
	view_ikeless(h, s);
	view_setkey(h, s);
}

bool
ipsecbase_action(const char *act, const char *arg, const char *value)
{

	struct server	*s;
	char		 url[300], list[16], *body;
	const char	*name;

	(void)value;
	if (strncmp(act, "ikl-", 4) == 0) {
		if ((s = cur_server()) == NULL)
			return (true);
		if (ycommit_action(&ikl.yc, act))
			return (true);
		if (strcmp(act, "ikl-reload") == 0)
			ikl_load(s);
		else if (strcmp(act, "ikl-new") == 0 ||
		    strcmp(act, "ikl-edit") == 0) {
			/* The form's; the lists read again once it is shut. */
			ikl.stale = true;
			return (yform_action(strcmp(act, "ikl-new") == 0 ?
			    "yf-new" : "yf-edit", arg, value));
		} else if (strcmp(act, "ikl-del") == 0 && arg != NULL &&
		    (name = strchr(arg, '|')) != NULL && (size_t)(name - arg) <
		    sizeof(list)) {
			snprintf(list, sizeof(list), "%.*s", (int)(name - arg),
			    arg);
			/* A YANG Patch: its target %-encoded, so a name of
			 * RFC 9061's kind (out/trans/a/b) is named whole. */
			rc_ds(url, sizeof(url), "candidate", s->id, IKL_TOP);
			if (asprintf(&body, "{\"ietf-yang-patch:yang-patch\":"
			    "{\"patch-id\":\"ikeless\",\"edit\":[{\"edit-id\":"
			    "\"1\",\"operation\":\"remove\",\"target\":"
			    "\"/%s/%s=%s\"}]}}", strcmp(list, "sad-entry") == 0 ?
			    "sad" : "spd", strcmp(list, "sad-entry") == 0 ?
			    "sad-entry" : "spd-entry", rc_key(name + 1)) == -1)
				abort();
			if (!ycommit_save(&ikl.yc, s->id, "PATCH", url, body))
				toast(true, "A change of the SAD or SPD is on "
				    "its way already");
			free(body);
		}
		return (true);
	}
	return (false);
}
