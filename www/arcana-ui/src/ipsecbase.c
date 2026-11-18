/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * In a host's network tab, a section of the base system's: its IPsec
 * without IKE, whether or not strongSwan is there.  The security
 * associations of an ipsec(4) interface keyed by hand or by a key
 * agreement of the two hosts' own, and the security policies of a
 * selector on them, each sent by the agent over PF_KEY (pfkey(4)) in
 * its own process; and ipsec.conf, setkey(8)'s commands, which
 * rc.d/ipsec (ipsec_enable) loads at boot, with the kernel's SPD read
 * beside it.  IKE is the strongSwan plugin's (ipsec.c).
 *
 * And RFC 9061's IKE-less lists (ietf-i2nsf-ikeless, the agent's
 * ikeless.c): the kernel's SAD and SPD as the host's operational
 * datastore tells them, every SA and policy; those of the lists'
 * controller, Arcana, by their names, each edited by the form its
 * model makes (yform.c) or taken out of the candidate and committed
 * confirmed (ycommit.c); the rest, setkey's, an IKE daemon's, an
 * interface's, the manual SAs' above, by the kernel's names, read
 * only.
 */

#include <stdarg.h>
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
		    "setkey's (ipsec.conf), an IKE daemon's, an ipsec(4) "
		    "interface's or the manual SAs' above. Read only: no edit "
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

static void
sa_job(struct server *s, const char *title, const char *fmt, ...)
{
	va_list	 ap;
	char	*json;

	va_start(ap, fmt);
	if (vasprintf(&json, fmt, ap) == -1)
		abort();
	va_end(ap);
	/* The system's read has the SPD and ipsec.conf: read again after. */
	job_send(s, json, title, JOB_SYSTEM, s->name);
}

void
view_ipsecbase(struct html *h, struct server *s)
{

	h_raw(h, "<section class=\"pane ipsec-base\"><h4><span>IPsec <small>"
	    "the base system's: PF_KEY, ipsec(4), setkey(8)</small></span>"
	    "<span class=\"pane-actions\"><button class=\"ghost small\" "
	    "data-act=\"ipsec-sa-add\" title=\"Security associations keyed by "
	    "hand or by a key agreement of the two hosts' own, and the "
	    "policies of a selector on them, for an ipsec(4) interface: no "
	    "IKE\">+ manual SAs</button></span></h4><p class=\"dim\">The "
	    "kernel's IPsec, with nothing installed: an <code>ipsec</code>"
	    "(4) interface made with a reqid (the Interfaces' <b>+ interface"
	    "</b>) carries what its SAs and policies take; Arcana's agent "
	    "sends them by PF_KEY (<code>pfkey</code>(4)) itself, as "
	    "<code>setkey</code>(8) would, and keeps their words to put "
	    "them back at its start.  <code>ipsec.conf</code> below is "
	    "setkey's own, loaded at boot by <code>rc.d/ipsec</code> "
	    "(<code>ipsec_enable</code>).  IKE, keys agreed by a daemon, is "
	    "the strongSwan plugin's section.</p></section>");
	view_ikeless(h, s);
	view_setkey(h, s);
}

/* Manually keyed SAs of an ipsec(4) interface: a verb, its words. */
bool
ipsecbase_modal(struct html *h)
{

	if (app.modal != MODAL_IPSEC_SA)
		return (false);
	h_raw(h, "<form data-form=\"ipsec-sa\"><h2>Manually keyed security "
	    "associations</h2><p>For an ipsec(4) interface made with a reqid, "
	    "without IKE, by PF_KEY: the SAs set from keys given here "
	    "(<b>set</b>), or derived on both hosts from a key pair each "
	    "host makes (<b>key</b>) and the other's public half (<b>derive"
	    "</b>), the public halves shown by the host's SD-WAN read; a "
	    "rotation derives from the next pair (<b>key next</b>, <b>derive "
	    "&hellip; next</b>) and <b>commit</b> makes it the pair; <b>clear"
	    "</b> takes the SAs out.  <b>policy</b> puts in the two policies "
	    "of a selector on the SAs, as setkey's spdadd would, and "
	    "<b>unpolicy</b> takes them out (without a selector, all of "
	    "Arcana's on them).  In safe mode the host puts back what was in "
	    "when the console does not confirm the job: derived SAs come "
	    "back from their words, ones set by hand cannot, so a safe job "
	    "over those is refused.</p>"
	    "<div class=\"two\"><label>Verb<select name=\"verb\">"
	    "<option value=\"key\">key: a pair of this interface's</option>"
	    "<option value=\"derive\">derive: the SAs from the pair and "
	    "the peer's public half</option>"
	    "<option value=\"set\">set: the SAs from keys given</option>"
	    "<option value=\"commit\">commit: the next pair the pair</option>"
	    "<option value=\"clear\">clear: the SAs out</option>"
	    "<option value=\"policy\">policy: a selector's policies in"
	    "</option><option value=\"unpolicy\">unpolicy: policies out"
	    "</option></select>"
	    "</label><label>Interface<input name=\"interface\" spellcheck=\""
	    "false\" autocomplete=\"off\" placeholder=\"ipsec0\" autofocus>"
	    "</label></div>"
	    "<div class=\"two\"><label>reqid<input name=\"reqid\" inputmode="
	    "\"numeric\" placeholder=\"100\"><small>The interface's; not "
	    "for key.</small></label><label>This host's outer address<input "
	    "name=\"local\" spellcheck=\"false\" autocomplete=\"off\" "
	    "placeholder=\"192.0.2.1\"></label></div>"
	    "<label>The peer's outer address<input name=\"remote\" "
	    "spellcheck=\"false\" autocomplete=\"off\" placeholder=\""
	    "192.0.2.2\"></label>"
	    "<label>Words<input name=\"words\" spellcheck=\"false\" "
	    "autocomplete=\"off\" placeholder=\"peer &lt;base64&gt; enc "
	    "aes-gcm-16 epoch 1 lifetime 3600\"><small>As arcanactl takes "
	    "them: for derive, <code>peer</code>, <code>enc</code> (aes-cbc "
	    "with <code>auth</code>, or aes-gcm-16), <code>epoch</code>, "
	    "<code>install</code> both, in or out, <code>encap</code>, "
	    "<code>esn</code>, <code>lifetime</code>, <code>next</code>; for "
	    "set, <code>spi-in</code>, <code>spi-out</code>, <code>key-in"
	    "</code>, <code>key-out</code>, <code>akey-in</code>, <code>"
	    "akey-out</code> in hex; for policy and unpolicy, <code>src"
	    "</code> and <code>dst</code> prefixes, <code>proto</code>, "
	    "<code>sport</code>, <code>dport</code>; for key, <code>next"
	    "</code> at most.</small></label>"
	    "<label class=\"toggle\"><input type=\"checkbox\" name=\"safe\" "
	    "checked><span>Safe mode <em>undone by the host unless the "
	    "console confirms it</em></span></label>");
	return (true);
}

bool
ipsecbase_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*verb, *v, *p, *e;
	char		 title[160], reqid[32], *words, *qw, *qi, *ql, *qr, *q;
	size_t		 len;
	bool		 iskey;

	if (strcmp(form, "ipsec-sa") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	verb = jstr(f, "verb") != NULL ? jstr(f, "verb") : "derive";
	iskey = strcmp(verb, "key") == 0;
	v = jstr(f, "interface");
	if (v == NULL || strncmp(v, "ipsec", 5) != 0 || v[5] == '\0' ||
	    v[5 + strspn(v + 5, "0123456789")] != '\0') {
		snprintf(app.modal_error, sizeof(app.modal_error), "The "
		    "interface is an ipsec(4) one, ipsec0");
		return (true);
	}
	qi = json_quote(v);
	reqid[0] = '\0';
	ql = qr = NULL;
	if (!iskey) {
		v = jstr(f, "reqid");
		if (v == NULL || v[0] == '\0' || strlen(v) > 5 || v[strspn(v,
		    "0123456789")] != '\0' || atoi(v) < 1 || atoi(v) > 16383 ||
		    jstr(f, "local") == NULL || jstr(f, "local")[0] == '\0' ||
		    jstr(f, "remote") == NULL || jstr(f, "remote")[0] == '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "But for key, the reqid (1 to 16383) and the two "
			    "outer addresses are needed");
			free(qi);
			return (true);
		}
		snprintf(reqid, sizeof(reqid), ",\"reqid\":%d", atoi(v));
		ql = json_quote(jstr(f, "local"));
		qr = json_quote(jstr(f, "remote"));
	}
	/* The words, each a string of the args list. */
	words = strdup("");
	len = 0;
	for (p = jstr(f, "words") != NULL ? jstr(f, "words") : ""; *p != '\0';
	    p = e) {
		p += strspn(p, " \t\n,");
		e = p + strcspn(p, " \t\n,");
		if (e == p)
			break;
		{
			char	*word = strndup(p, (size_t)(e - p));

			q = json_quote(word);
			free(word);
		}
		if (asprintf(&qw, "%s%s%s", words, len > 0 ? "," : "", q) == -1)
			abort();
		free(q);
		free(words);
		words = qw;
		len++;
	}
	snprintf(title, sizeof(title), "ipsec sa %s %s", verb, jstr(f,
	    "interface"));
	if (iskey)
		sa_job(s, title, "{\"kind\":\"ipsec-sa\",\"verb\":\"key\","
		    "\"interface\":%s,\"args\":[%s],\"safe\":%s}", qi, words,
		    jbool(f, "safe") ? "true" : "false");
	else {
		q = json_quote(verb);
		sa_job(s, title, "{\"kind\":\"ipsec-sa\",\"verb\":%s,"
		    "\"interface\":%s%s,\"tunnel_local\":%s,\"tunnel_remote\":%s,"
		    "\"args\":[%s],\"safe\":%s}", q, qi, reqid, ql, qr, words,
		    jbool(f, "safe") ? "true" : "false");
		free(q);
	}
	free(qi);
	free(ql);
	free(qr);
	free(words);
	app.modal = MODAL_NONE;
	return (true);
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
	if (strcmp(act, "ipsec-sa-add") != 0)
		return (false);
	app.modal = MODAL_IPSEC_SA;
	app.modal_error[0] = '\0';
	return (true);
}
