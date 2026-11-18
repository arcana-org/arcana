/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The Security page's SSL inspection tab: SSLproxy (security/sslproxy,
 * a plugin), run by Arcana's rc script arcana_sslproxy, the clients'
 * TLS sent to it by ipfw fwd rules (set 27, rule 7) that keep the
 * destination for its NAT engine ipfw.  As arcana-sslproxy's read has
 * it: whether it is installed, enabled and running, the edge's CA (an
 * intermediate of the tenant fleet's root, its key made on the host and
 * never read out), the form the configuration was rendered from, the
 * rules loaded and the file.  The CA is issued by the console
 * (arcana-console's inspection-ca); the rest are sslproxy jobs.  Where
 * an SD-WAN service's MBSF is what SSLproxy serves (MEF 138's function
 * policy bound to zones, the form the console's), the binding is shown
 * in place of the form: the service, the policy, its table, each zone's
 * clients and interfaces, changed in SD-WAN alone.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "app.h"

/* The form's protocols, their usual port and SSLproxy's port. */
static const struct {
	const char	*proto;
	int		 port, listen;
	bool		 on;		/* in a new form */
} protos[] = {
	{ "https", 443, 8443, true }, { "http", 80, 8080, false },
	{ "smtps", 465, 8465, false }, { "pop3s", 995, 8995, false },
	{ "imaps", 993, 8993, false },
};

static struct {
	struct res	 r;		/* arcana-sslproxy's read */
	bool		 issuing;	/* inspection-ca under way */
} si;

void
sslinspect_refresh(void)
{

	res_drop(&si.r);
}

static ucl_object_t *
si_conv(const ucl_object_t *o)
{
	static const char *const names[] = { "rule=rules", NULL };
	static const char *const nums[] = { "not_after", "number", "set",
	    "rules_expected", "connect_log_size", "fib", NULL };
	ucl_object_t	*f, *r;

	f = jflat(o, names);
	r = net_plain(f, nums);
	ucl_object_unref(f);
	return (r);
}

static void
si_load(const char *sid)
{

	res_yread(&si.r, sid, "arcana-sslproxy:sslproxy/read", "{}", si_conv);
}

static void
day(char *buf, size_t len, int64_t t)
{
	struct tm	tm;
	time_t		tt;

	tt = (time_t)t;
	gmtime_r(&tt, &tm);
	strftime(buf, len, "%Y-%m-%d", &tm);
}

/* A certificate's lines of the CA's list. */
static void
cert_rows(struct html *h, const char *what, const ucl_object_t *c)
{
	char	d[16];

	h_raw(h, "<dt>");
	h_txt(h, what);
	h_raw(h, "</dt><dd>");
	h_txt(h, jstr(c, "subject") != NULL ? jstr(c, "subject") : "");
	if (jint(c, "not_after", 0) > 0) {
		day(d, sizeof(d), jint(c, "not_after", 0));
		h_fmt(h, " <span class=\"dim\">until %s</span>", d);
	}
	h_raw(h, "</dd>");
}

/* The spec's listener of a protocol, or NULL. */
static const ucl_object_t *
listener(const ucl_object_t *spec, const char *proto)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((e = ucl_object_iterate(jget(spec, "listeners"), &it, true)) !=
	    NULL)
		if (jstr(e, "proto") != NULL && strcmp(jstr(e, "proto"), proto)
		    == 0)
			return (e);
	return (NULL);
}

static void
check(struct html *h, const char *name, bool on, const char *label,
    const char *help)
{

	h_fmt(h, "<label class=\"check\"><input type=\"checkbox\" name=\"%s\"%s>"
	    " ", name, on ? " checked" : "");
	h_txt(h, label);
	if (help != NULL) {
		h_raw(h, " <small class=\"help\">");
		h_txt(h, help);
		h_raw(h, "</small>");
	}
	h_raw(h, "</label>");
}

/* The words of a list, joined, as an input's value. */
static void
joined_value(struct html *h, const ucl_object_t *arr)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct html		 b;
	bool			 first;

	memset(&b, 0, sizeof(b));
	first = true;
	it = NULL;
	while ((e = ucl_object_iterate(arr, &it, true)) != NULL)
		if (ucl_object_type(e) == UCL_STRING) {
			h_strf(&b, "%s%s", first ? "" : ", ",
			    ucl_object_tostring(e));
			first = false;
		}
	h_attr(h, "value", b.s != NULL ? b.s : "");
	free(b.s);
}

static void
si_form(struct html *h, const ucl_object_t *o)
{
	const ucl_object_t	*l;
	ucl_object_t		*spec;
	struct ucl_parser	*p;
	size_t			 i;

	spec = NULL;
	if (jstr(o, "spec") != NULL) {
		p = ucl_parser_new(UCL_PARSER_NO_TIME);
		if (ucl_parser_add_string(p, jstr(o, "spec"), 0))
			spec = ucl_parser_get_object(p);
		ucl_parser_free(p);
	}
	h_raw(h, "<form class=\"secform\" data-form=\"ssl-conf\"><h4>What is "
	    "inspected</h4><table class=\"ssl-listeners\"><thead><tr><th>"
	    "Protocol</th><th>Its port</th><th>SSLproxy listens at (loopback)"
	    "</th></tr></thead><tbody>");
	for (i = 0; i < nitems(protos); i++) {
		l = listener(spec, protos[i].proto);
		h_fmt(h, "<tr><td><label class=\"check\"><input type=\"checkbox\" "
		    "name=\"p_%s\"%s> %s</label></td><td><input name=\"port_%s\" "
		    "type=\"number\" min=\"1\" max=\"65535\" value=\"%lld\"></td>"
		    "<td><input name=\"listen_%s\" type=\"number\" min=\"1024\" "
		    "max=\"65535\" value=\"%lld\"></td></tr>", protos[i].proto,
		    (spec == NULL ? protos[i].on : l != NULL) ? " checked" : "",
		    protos[i].proto, protos[i].proto, (long long)jint(l, "port",
		    protos[i].port), protos[i].proto, (long long)jint(l, "listen",
		    protos[i].listen));
	}
	h_raw(h, "</tbody></table><label>Interfaces <input name=\"interfaces\" "
	    "required spellcheck=\"false\" placeholder=\"em1, vlan20\"");
	joined_value(h, jget(spec, "interfaces"));
	h_raw(h, "><small class=\"help\">where the clients' traffic comes in: "
	    "each fwd rule is \"in recv\" one of them</small></label>"
	    "<label>Clients <input name=\"clients\" spellcheck=\"false\" "
	    "placeholder=\"192.0.2.0/24, 2001:db8::/64\"");
	joined_value(h, jget(spec, "clients"));
	h_raw(h, "><small class=\"help\">the prefixes inspected; empty, "
	    "every client on those interfaces</small></label>");
	check(h, "ipv6", spec == NULL || jbool(spec, "ipv6") ||
	    jget(spec, "ipv6") == NULL, "IPv6 too", "fwd ::1 beside 127.0.0.1");
	check(h, "connect_log", spec == NULL || jbool(spec, "connect_log") ||
	    jget(spec, "connect_log") == NULL, "Connect log",
	    "a line a connection, /var/log/sslproxy/connect.log");
	check(h, "content_log", jbool(spec, "content_log"), "Content log",
	    "what was opened, written whole: off unless troubleshooting");
	check(h, "ssh_log", jbool(spec, "ssh_log"), "SSH logged",
	    "port 22 relayed by a tcp proxyspec: a connect-log line a session, "
	    "never opened");
	check(h, "passthrough", spec == NULL || jbool(spec, "passthrough") ||
	    jget(spec, "passthrough") == NULL, "Pass what cannot be opened",
	    "client certificates: passed through, not dropped (Passthrough)");
	if (jstr(o, "conf") != NULL && !jbool(o, "ours"))
		check(h, "replace", false, "Replace the admin's sslproxy.conf",
		    "the form did not write it: its own lines would go");
	h_raw(h, "<div class=\"actions\"><button class=\"primary\" type=\""
	    "submit\">Save</button></div></form>");
	if (spec != NULL)
		ucl_object_unref(spec);
}

/* The words of a list, joined. */
static void
joined_text(struct html *h, const ucl_object_t *arr)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	bool			 first;

	first = true;
	it = NULL;
	while ((e = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (!first)
			h_raw(h, ", ");
		h_txt(h, ucl_object_tostring_forced(e));
		first = false;
	}
}

/* An SD-WAN service's MBSF the form was compiled from: its zones. */
static void
si_bound(struct html *h, const ucl_object_t *b)
{
	const ucl_object_t	*z;
	ucl_object_iter_t	 it;

	h_raw(h, "<div class=\"ssl-bound\"><p>Bound by SD-WAN: service <b>");
	h_txt(h, jstr(b, "service") != NULL ? jstr(b, "service") : "");
	h_raw(h, "</b>, its MBSF <b>");
	h_txt(h, jstr(b, "policy") != NULL ? jstr(b, "policy") : "");
	h_fmt(h, "</b> (MEF 138's middlebox), SSLproxy run in routing table "
	    "%lld (<code>setfib</code>). Its zones' TLS is opened here; the "
	    "function policy and its zones are changed in SD-WAN, Security."
	    "</p><table class=\"ssl-zones\"><thead><tr><th>Zone</th><th>"
	    "Clients</th><th>Interfaces (the UNIs)</th></tr></thead><tbody>",
	    (long long)jint(b, "fib", 0));
	it = NULL;
	while ((z = ucl_object_iterate(jget(b, "zone"), &it, true)) != NULL) {
		h_raw(h, "<tr><td>");
		h_txt(h, jstr(z, "name") != NULL ? jstr(z, "name") : "");
		h_raw(h, "</td><td>");
		joined_text(h, jget(z, "clients"));
		h_raw(h, "</td><td>");
		joined_text(h, jget(z, "interfaces"));
		h_raw(h, "</td></tr>");
	}
	h_raw(h, "</tbody></table></div>");
}

void
view_sslinspect(struct html *h, struct server *s)
{
	const ucl_object_t	*o, *ca, *c, *e;
	ucl_object_iter_t	 it;
	int64_t			 n;

	if (!res_shown(h, &si.r, s->id, si_load, "ssl-retry"))
		return;
	o = si.r.o;
	if (jget(o, "installed") != NULL && !jbool(o, "installed")) {
		h_raw(h, "<div class=\"notice warn sec-missing\"><span>SSLproxy "
		    "is not installed on this host: TLS is inspected by it, "
		    "transparently (ipfw fwd), the clients setting no proxy."
		    "</span><button class=\"primary small\" data-act=\""
		    "sec-install\" data-arg=\"sslproxy\">Install sslproxy</button>"
		    "</div>");
		return;
	}
	h_raw(h, "<div class=\"sslview\"><p class=\"dim\">TLS opened by "
	    "<code>sslproxy(1)</code> in split mode, its NAT engine "
	    "<code>ipfw</code>: the clients' traffic reaches it by "
	    "<code>ipfw fwd</code> rules, set 27 at rule 7, which keep the "
	    "destination; run by <code>rc.subr(8)</code> as "
	    "<code>arcana_sslproxy</code>.</p><dl class=\"kv\"><dt>SSLproxy"
	    "</dt><dd>");
	h_txt(h, jstr(o, "version") != NULL ? jstr(o, "version") : "installed");
	h_raw(h, "</dd><dt>Service</dt><dd>");
	h_fmt(h, "<span class=\"chip %s\">%s</span> <span class=\"chip %s\">"
	    "%s</span>", jbool(o, "running") ? "st-up" : "st-down",
	    jbool(o, "running") ? "running" : "not running", jbool(o,
	    "enabled") ? "st-up" : "", jbool(o, "enabled") ? "enabled" :
	    "not enabled");
	h_raw(h, " ");
	if (!jbool(o, "enabled"))
		h_raw(h, "<button class=\"ghost small\" data-act=\"ssl-job\" "
		    "data-arg=\"enable\">Enable</button>");
	else
		h_raw(h, "<button class=\"ghost small\" data-act=\"ssl-job\" "
		    "data-arg=\"disable\">Disable</button>");
	if (jbool(o, "running"))
		h_raw(h, "<button class=\"ghost small\" data-act=\"ssl-job\" "
		    "data-arg=\"restart\">Restart</button><button class=\"ghost "
		    "small\" data-act=\"ssl-job\" data-arg=\"stop\">Stop</button>");
	else if (jstr(o, "conf") != NULL)
		h_raw(h, "<button class=\"ghost small\" data-act=\"ssl-job\" "
		    "data-arg=\"start\">Start</button>");
	h_raw(h, "</dd>");
	if (jstr(o, "connect_log") != NULL) {
		h_raw(h, "<dt>Connect log</dt><dd><code>");
		h_txt(h, jstr(o, "connect_log"));
		h_fmt(h, "</code> <span class=\"dim\">%lld bytes</span></dd>",
		    (long long)jint(o, "connect_log_size", 0));
	}
	h_raw(h, "</dl>");

	/* The edge's CA. */
	ca = jget(o, "ca");
	h_raw(h, "<h3 class=\"secsub\">The edge's CA</h3><dl class=\"kv ssl-ca\">");
	if ((c = jget(ca, "certificate")) != NULL)
		cert_rows(h, "Intermediate", c);
	else
		h_raw(h, "<dt>Intermediate</dt><dd class=\"dim\">none yet: "
		    "issue it from the fleet's root</dd>");
	if ((c = jget(ca, "root")) != NULL) {
		cert_rows(h, "Root", c);
		h_raw(h, "<dt>For the clients</dt><dd><a class=\"ghost small "
		    "ssl-root\" download=\"arcana-inspection-root.crt\" href=\""
		    "data:application/x-x509-ca-cert;charset=utf-8,");
		h_url(h, jstr(c, "pem") != NULL ? jstr(c, "pem") : "");
		h_raw(h, "\" title=\"The root every client of the fleet trusts "
		    "once, for every edge\">Download the root (PEM)</a></dd>");
	}
	if (jbool(ca, "pending"))
		h_raw(h, "<dt>Waiting</dt><dd class=\"dim\">a new key waits for "
		    "its certificate</dd>");
	h_raw(h, "</dl><p class=\"dim\">The key is made on this host and never "
	    "leaves it; the console signs its request with the tenant fleet's "
	    "root, whose key stays on the console.</p>");
	h_fmt(h, "<button class=\"%s small\" data-act=\"ssl-issue\"%s>%s</button>",
	    jget(ca, "certificate") != NULL ? "ghost" : "primary", si.issuing ?
	    " disabled" : "", jget(ca, "certificate") != NULL ?
	    "Renew from the fleet's root" : "Issue from the fleet's root");

	/* The form, or the SD-WAN's binding the console compiled it from. */
	h_raw(h, "<h3 class=\"secsub\">Configuration</h3>");
	if (jget(o, "bound") != NULL)
		si_bound(h, jget(o, "bound"));
	else
		si_form(h, o);

	/* The rules. */
	h_raw(h, "<h3 class=\"secsub\">ipfw fwd rules</h3>");
	if (jstr(o, "rules_error") != NULL) {
		h_raw(h, "<div class=\"notice warn\">");
		h_txt(h, jstr(o, "rules_error"));
		h_raw(h, "</div>");
	}
	n = 0;
	it = NULL;
	while ((e = ucl_object_iterate(jget(o, "rules"), &it, true)) != NULL)
		n++;
	h_fmt(h, "<p class=\"dim\">%lld loaded in set 27, of %lld the form "
	    "makes", (long long)n, (long long)jint(o, "rules_expected", 0));
	if (jstr(o, "rules_file") != NULL) {
		h_raw(h, " (<code>");
		h_txt(h, jstr(o, "rules_file"));
		h_raw(h, "</code>)");
	}
	h_raw(h, ".</p>");
	if (n > 0) {
		h_raw(h, "<table class=\"ssl-rules\"><thead><tr><th>Rule</th><th>"
		    "As ipfw lists it</th></tr></thead><tbody>");
		it = NULL;
		while ((e = ucl_object_iterate(jget(o, "rules"), &it, true)) !=
		    NULL) {
			h_fmt(h, "<tr><td>%05lld</td><td><code>",
			    (long long)jint(e, "number", 0));
			h_txt(h, jstr(e, "text") != NULL ? jstr(e, "text") : "");
			h_raw(h, "</code></td></tr>");
		}
		h_raw(h, "</tbody></table>");
	}
	if (jstr(o, "conf") != NULL) {
		h_raw(h, "<details class=\"ssl-conf\"><summary>sslproxy.conf");
		if (jstr(o, "conf_path") != NULL) {
			h_raw(h, " <code>");
			h_txt(h, jstr(o, "conf_path"));
			h_raw(h, "</code>");
		}
		h_raw(h, "</summary><pre>");
		h_txt(h, jstr(o, "conf"));
		h_raw(h, "</pre></details>");
	}
	h_raw(h, "</div>");
}

static void
issue_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	si.issuing = false;
	if (status == 200 && jstr(o, "error") == NULL)
		toast(false, "The edge's CA issued");
	else
		toast(true, "%s", jstr(o, "error") != NULL ? jstr(o, "error") :
		    err != NULL ? err : "not issued");
	res_drop(&si.r);
	render();
}

/* A word list of a field, as JSON strings into o under key. */
static void
put_words(ucl_object_t *o, const char *key, const char *s)
{
	ucl_object_t	*arr;
	char		*copy, *p, *w;

	arr = ucl_object_typed_new(UCL_ARRAY);
	if (s != NULL) {
		if ((copy = strdup(s)) == NULL)
			abort();
		for (p = copy; (w = strsep(&p, ", \t\r\n")) != NULL; )
			if (w[0] != '\0')
				ucl_array_append(arr, ucl_object_fromstring(w));
		free(copy);
	}
	ucl_object_insert_key(o, arr, key, 0, false);
}

bool
sslinspect_form(const char *form, const ucl_object_t *f)
{
	ucl_object_t	*spec, *ls, *l;
	char		 k[32], *text, *json;
	const char	*v;
	size_t		 i;

	if (strcmp(form, "ssl-conf") != 0)
		return (false);
	spec = ucl_object_typed_new(UCL_OBJECT);
	ls = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < nitems(protos); i++) {
		snprintf(k, sizeof(k), "p_%s", protos[i].proto);
		if (!jbool(f, k))
			continue;
		l = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(l, ucl_object_fromstring(protos[i].proto),
		    "proto", 0, false);
		snprintf(k, sizeof(k), "port_%s", protos[i].proto);
		v = jstr(f, k);
		ucl_object_insert_key(l, ucl_object_fromint(v != NULL && v[0] !=
		    '\0' ? strtol(v, NULL, 10) : protos[i].port), "port", 0,
		    false);
		snprintf(k, sizeof(k), "listen_%s", protos[i].proto);
		v = jstr(f, k);
		ucl_object_insert_key(l, ucl_object_fromint(v != NULL && v[0] !=
		    '\0' ? strtol(v, NULL, 10) : protos[i].listen), "listen", 0,
		    false);
		ucl_array_append(ls, l);
	}
	ucl_object_insert_key(spec, ls, "listeners", 0, false);
	put_words(spec, "clients", jstr(f, "clients"));
	put_words(spec, "interfaces", jstr(f, "interfaces"));
	ucl_object_insert_key(spec, ucl_object_frombool(jbool(f, "ipv6")),
	    "ipv6", 0, false);
	ucl_object_insert_key(spec, ucl_object_frombool(jbool(f,
	    "connect_log")), "connect_log", 0, false);
	ucl_object_insert_key(spec, ucl_object_frombool(jbool(f,
	    "content_log")), "content_log", 0, false);
	ucl_object_insert_key(spec, ucl_object_frombool(jbool(f, "ssh_log")),
	    "ssh_log", 0, false);
	ucl_object_insert_key(spec, ucl_object_frombool(jbool(f,
	    "passthrough")), "passthrough", 0, false);
	text = (char *)ucl_object_emit(spec, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(spec);
	if (text == NULL)
		abort();
	json = job_json("sslproxy", "conf", NULL, 0, text, jbool(f, "replace") ?
	    ",\"force\":true" : NULL);
	free(text);
	sec_job(json, "SSL inspection: sslproxy.conf and its fwd rules");
	return (true);
}

bool
sslinspect_action(const char *act, const char *arg, const char *value)
{
	char		 url[256], title[64], *json;
	const char	*sid;

	(void)value;
	if (strncmp(act, "ssl-", 4) != 0)
		return (false);
	sid = sec_host_id();
	if (strcmp(act, "ssl-retry") == 0) {
		res_drop(&si.r);
		return (true);
	}
	if (strcmp(act, "ssl-job") == 0 && arg != NULL && (strcmp(arg,
	    "enable") == 0 || strcmp(arg, "disable") == 0 || strcmp(arg,
	    "start") == 0 || strcmp(arg, "stop") == 0 || strcmp(arg,
	    "restart") == 0)) {
		json = job_json("sslproxy", arg, NULL, 0, NULL, NULL);
		snprintf(title, sizeof(title), "SSL inspection: %s", arg);
		sec_job(json, title);
		return (true);
	}
	if (strcmp(act, "ssl-issue") == 0 && sid[0] != '\0' && !si.issuing) {
		const ucl_object_t	*ca = jget(si.r.o, "ca");

		si.issuing = true;
		rc_verb(rc_c(url, sizeof(url), "hosts/host=%s/inspection-ca",
		    rc_key(sid)), jget(ca, "certificate") != NULL ?
		    "{\"renew\":true}" : NULL, NULL, issue_cb, NULL);
		render();
		return (true);
	}
	return (true);
}
