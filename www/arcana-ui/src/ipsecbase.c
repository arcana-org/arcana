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
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

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

	(void)arg;
	(void)value;
	if (strcmp(act, "ipsec-sa-add") != 0)
		return (false);
	app.modal = MODAL_IPSEC_SA;
	app.modal_error[0] = '\0';
	return (true);
}
