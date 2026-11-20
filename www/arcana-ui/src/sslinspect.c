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
 * clients and interfaces, changed in SD-WAN alone.  Each jail may run
 * one of its own: picked here (the host, or a running jail), its read,
 * jobs, CA and Install (pkg -j) the jail's; a vnet jail's rules are its
 * own ipfw's, a jail of the host's network's the host's, sent to the
 * jail's address.  What is never opened (phase 3): Arcana's categories
 * ticked, the admin's hosts, destinations, ports and clients, the
 * console's prefix lists' clients written into the form when saved;
 * the binding shows the MBSF's.
 */

#include <stdbool.h>
#include <stdint.h>
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
	bool		 picked;	/* where, chosen by hand: jail */
	char		 jail[64];	/* "" the host */
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

/* The Security page's host. */
static struct server *
si_server(void)
{
	int	i;

	for (i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, sec_host_id()) == 0)
			return (&app.servers[i]);
	return (NULL);
}

/* Where SSLproxy is looked for: the place picked in the tab, else the
 * host where it has it, else a running jail that has, else the host. */
static const char *
si_where(const struct server *s)
{
	const char	*at;

	if (si.picked || s == NULL)
		return (si.jail);
	at = plugin_anywhere(s, "sslproxy");
	return (at != NULL ? at : "");
}

static void
si_load(const char *sid)
{
	struct server	*s;
	char		 in[160], *q;

	/* Another host: its own choice. */
	if (strcmp(sid, si.r.sid) != 0)
		si.picked = false;
	snprintf(in, sizeof(in), "{}");
	if ((s = si_server()) != NULL && si_where(s)[0] != '\0') {
		q = json_quote(si_where(s));
		snprintf(in, sizeof(in), "{\"jail\":%s}", q);
		free(q);
	}
	res_yread(&si.r, sid, "arcana-sslproxy:sslproxy/read", in, si_conv);
}

/* A job's extra: the jail it is done in, when SSLproxy is a jail's. */
static const char *
si_extra(const char *more)
{
	static char	 extra[160];
	char		*q;

	if (si_where(si_server())[0] == '\0')
		return (more);
	q = json_quote(si_where(si_server()));
	snprintf(extra, sizeof(extra), ",\"jail\":%s%s", q, more != NULL ?
	    more : "");
	free(q);
	return (extra);
}

/* A job's title, with the jail it is done in. */
static void
si_title(char *buf, size_t len, const char *what)
{
	const char	*j;

	j = si_where(si_server());
	snprintf(buf, len, "%s%s%s", what, j[0] != '\0' ? " in jail " : "", j);
}

/* The picker: the host, or any running jail of it. */
static void
si_pick(struct html *h, const struct server *s)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	h_raw(h, "<div class=\"toolbar\"><label class=\"secpick\">Where "
	    "<select data-input=\"ssl-where\"><option value=\"\"");
	if (si_where(s)[0] == '\0')
		h_raw(h, " selected");
	h_raw(h, ">the host</option>");
	it = NULL;
	while (s != NULL && s->list != NULL && (e = ucl_object_iterate(jget(
	    s->list, "jails"), &it, true)) != NULL) {
		if (jstr(e, "name") == NULL || jstr(e, "state") == NULL ||
		    strcmp(jstr(e, "state"), "running") != 0)
			continue;
		h_raw(h, "<option");
		h_attr(h, "value", jstr(e, "name"));
		if (strcmp(si_where(s), jstr(e, "name")) == 0)
			h_raw(h, " selected");
		h_raw(h, ">jail ");
		h_txt(h, jstr(e, "name"));
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label><small class=\"help\">SSLproxy on the "
	    "host, or a jail's own: a vnet jail's rules in its own ipfw, a "
	    "jail of the host's network's in the host's, sent to the jail's "
	    "address</small></div>");
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
		if (ucl_object_type(e) == UCL_STRING || ucl_object_type(e) ==
		    UCL_INT) {
			h_strf(&b, "%s%s", first ? "" : ", ",
			    ucl_object_tostring_forced(e));
			first = false;
		}
	h_attr(h, "value", b.s != NULL ? b.s : "");
	free(b.s);
}

/* Arcana's do-not-decrypt categories, as the agent has them (luxuria/
 * sslproxy.c's cats[]): the form's name, what it is. */
static const struct {
	const char	*name, *what;
} si_cats[] = {
	{ "os-updates", "The operating systems' updates (FreeBSD, Windows, "
	    "Apple)" },
	{ "pinned", "Services that pin their certificate (Apple push, "
	    "Google's FCM, Signal, WhatsApp)" },
};

/* Whether a list of categories has one; absent, none (opt-in). */
static bool
si_cat_on(const ucl_object_t *v, const char *name)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((e = ucl_object_iterate(v, &it, true)) != NULL)
		if (strcmp(ucl_object_tostring_forced(e), name) == 0)
			return (true);
	return (false);
}

/* SSLproxy's limit of a *.name host, said where it is entered and
 * where a bound MBSF has one (the agent's sslproxy.conf says it too). */
#define	SI_WILD	"SSLproxy matches *.example.org as a substring: " \
	"example.org and its subdomains pass, and so would a name such as " \
	"www.example.org.attacker.example; use a zone opened by Squid for an " \
	"exact wildcard"

/*
 * What is never opened (docs/notes/ssl-inspection.md, phase 3), the
 * tab's form's: Arcana's categories (opt-in), hosts by name or *.name
 * (SSLproxy's Pass filter rules, by SNI and CN, *.name a substring),
 * destinations, ports and clients (skipped by the fwd rules), the
 * console's prefix lists' clients added.
 */
static void
si_pass_fields(struct html *h, const ucl_object_t *spec)
{
	size_t	i;

	h_raw(h, "<fieldset class=\"ssl-pass\"><legend>Never opened</legend>"
	    "<p class=\"dim\">Passed through as it is: Arcana's categories "
	    "ticked (exact names, no third party's feed), then your own. "
	    "Hosts by the TLS name and the verified certificate's CN "
	    "(SSLproxy's <code>Pass</code> filter rules), a name exactly, "
	    "<code>*.example.org</code> the domain and the names beneath it; "
	    "destinations, ports and clients skipped by the <code>ipfw</code> "
	    "rules before the fwd, never reaching SSLproxy.</p>");
	for (i = 0; i < nitems(si_cats); i++) {
		char	name[32];

		snprintf(name, sizeof(name), "cat_%s", si_cats[i].name);
		check(h, name, si_cat_on(jget(spec, "pass_categories"),
		    si_cats[i].name), si_cats[i].what, NULL);
	}
	h_raw(h, "<label>Hosts <input name=\"pass\" spellcheck=\"false\" "
	    "placeholder=\"bank.example, *.health.example\"");
	joined_value(h, jget(spec, "pass"));
	h_raw(h, "><small class=\"help\">a bank, a doctor, an app that pins its "
	    "certificate: 64 at most</small><small class=\"help ssl-wild\">"
	    SI_WILD "</small></label><label>Destinations <input "
	    "name=\"pass_destinations\" spellcheck=\"false\" placeholder=\""
	    "198.51.100.0/24, 2001:db8:5::/48\"");
	joined_value(h, jget(spec, "pass_destinations"));
	h_raw(h, "><small class=\"help\">prefixes whose TLS is never opened"
	    "</small></label><label>Ports <input name=\"pass_ports\" "
	    "spellcheck=\"false\" placeholder=\"8443\"");
	joined_value(h, jget(spec, "pass_ports"));
	h_raw(h, "><small class=\"help\">destination ports never opened"
	    "</small></label><label>Clients <input name=\"pass_clients\" "
	    "spellcheck=\"false\" placeholder=\"192.0.2.7/32\"");
	joined_value(h, jget(spec, "pass_clients"));
	h_raw(h, "><small class=\"help\">clients whose TLS is never opened"
	    "</small></label>");
	pfxlist_select(h, "And the clients of the console's lists", "pass_pfx",
	    "their prefixes added to the clients never opened when saved",
	    true);
	h_raw(h, "</fieldset>");
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
	pfxlist_select(h, "And the clients of the console's lists", "clients_pfx",
	    "their prefixes added to the clients when saved", true);
	si_pass_fields(h, spec);
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

/* A row of the MBSF's never-opened list, where it has the key. */
static void
pass_row(struct html *h, const ucl_object_t *m, const char *key,
    const char *what)
{

	if (jget(m, key) == NULL)
		return;
	h_raw(h, "<dt>");
	h_txt(h, what);
	h_raw(h, "</dt><dd>");
	joined_text(h, jget(m, key));
	h_raw(h, "</dd>");
}

/* Whether a list of hosts has a *.name one. */
static bool
si_wild(const ucl_object_t *v)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((e = ucl_object_iterate(v, &it, true)) != NULL)
		if (strncmp(ucl_object_tostring_forced(e), "*.", 2) == 0)
			return (true);
	return (false);
}

/* What the bound MBSF never opens (phase 3), as the console compiled
 * it: Arcana's categories, its hosts, destinations, ports, clients; a
 * *.name host's limit under SSLproxy said. */
static void
si_bound_pass(struct html *h, const char *text)
{
	struct ucl_parser	*p;
	ucl_object_t		*spec;
	const ucl_object_t	*m;
	size_t			 i;
	bool			 first;

	if (text == NULL)
		return;
	p = ucl_parser_new(UCL_PARSER_NO_TIME);
	spec = ucl_parser_add_string(p, text, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	if (spec == NULL)
		return;
	m = jget(spec, "mbsf");
	h_raw(h, "<dl class=\"kv ssl-bound-pass\"><dt>Never opened</dt><dd>");
	first = true;
	for (i = 0; i < nitems(si_cats); i++)
		if (si_cat_on(jget(m, "pass-categories"), si_cats[i].name)) {
			if (!first)
				h_raw(h, "; ");
			h_txt(h, si_cats[i].what);
			first = false;
		}
	if (first)
		h_raw(h, "none of Arcana's categories");
	h_raw(h, "</dd>");
	pass_row(h, m, "pass-through", "Hosts");
	pass_row(h, m, "pass-destinations", "Destinations");
	pass_row(h, m, "pass-ports", "Ports");
	pass_row(h, m, "pass-clients", "Clients");
	h_raw(h, "</dl>");
	if (si_wild(jget(m, "pass-through")))
		h_raw(h, "<p class=\"dim ssl-wild\">" SI_WILD ".</p>");
	ucl_object_unref(spec);
}

/* An SD-WAN service's MBSF the form was compiled from: its zones. */
static void
si_bound(struct html *h, const ucl_object_t *b, const char *spec)
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
	h_raw(h, "</tbody></table>");
	si_bound_pass(h, spec);
	h_raw(h, "</div>");
}

/* Are IPv6 clients sent by fwd: the form's IPv6 too (on unless unticked),
 * or an SD-WAN binding's, which always is. */
static bool
si_ipv6(const ucl_object_t *o)
{
	struct ucl_parser	*p;
	ucl_object_t		*spec;
	bool			 v;

	if (jget(o, "bound") != NULL)
		return (true);
	if (jstr(o, "spec") == NULL)
		return (false);
	p = ucl_parser_new(UCL_PARSER_NO_TIME);
	spec = ucl_parser_add_string(p, jstr(o, "spec"), 0) ?
	    ucl_parser_get_object(p) : NULL;
	ucl_parser_free(p);
	if (spec == NULL)
		return (false);
	v = jget(spec, "ipv6") == NULL || jbool(spec, "ipv6");
	ucl_object_unref(spec);
	return (v);
}

void
view_sslinspect(struct html *h, struct server *s)
{
	const ucl_object_t	*o, *ca, *c, *e;
	ucl_object_iter_t	 it;
	const char		*jail;
	int64_t			 n;
	bool			 shared;

	si_pick(h, s);
	if (!res_shown(h, &si.r, s->id, si_load, "ssl-retry"))
		return;
	o = si.r.o;
	jail = jstr(o, "jail");
	/* A jail of the host's network: the host's ipfw fwds to it. */
	shared = jail != NULL && !jbool(o, "vnet");
	if (jget(o, "installed") != NULL && !jbool(o, "installed")) {
		h_raw(h, "<div class=\"notice warn sec-missing\"><span>SSLproxy "
		    "is not installed ");
		if (jail != NULL) {
			h_raw(h, "in jail ");
			h_txt(h, jail);
			h_raw(h, ": a plugin, the port security/sslproxy, "
			    "installed there with pkg -j.");
		} else
			h_raw(h, "on this host: TLS is inspected by it, "
			    "transparently (ipfw fwd), the clients setting no "
			    "proxy.");
		h_raw(h, "</span><button class=\"primary small\" data-act=\""
		    "ssl-install\">Install sslproxy</button></div>");
		return;
	}
	h_raw(h, "<div class=\"sslview\">");
	if (jail != NULL) {
		h_raw(h, "<p><span class=\"chip\">in jail ");
		h_txt(h, jail);
		h_raw(h, "</span> ");
		h_raw(h, shared ? "of the host's network: SSLproxy listens at "
		    "the jail's address, the host's <code>ipfw fwd</code> sends "
		    "the clients there" : "with a network of its own (vnet): its "
		    "own <code>ipfw</code> has the rules, SSLproxy at its "
		    "loopback");
		h_raw(h, "</p>");
	}
	h_raw(h, "<p class=\"dim\">TLS opened by "
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
	h_fmt(h, "</dl><p class=\"dim\">The key is made for %s and never "
	    "leaves it; the console signs its request with the tenant fleet's "
	    "root, whose key stays on the console.</p>", jail != NULL ?
	    "the jail, beneath its root," : "this host");
	h_fmt(h, "<button class=\"%s small\" data-act=\"ssl-issue\"%s>%s</button>",
	    jget(ca, "certificate") != NULL ? "ghost" : "primary", si.issuing ?
	    " disabled" : "", jget(ca, "certificate") != NULL ?
	    "Renew from the fleet's root" : "Issue from the fleet's root");

	/* The form, or the SD-WAN's binding the console compiled it from. */
	h_raw(h, "<h3 class=\"secsub\">Configuration</h3>");
	if (jget(o, "bound") != NULL)
		si_bound(h, jget(o, "bound"), jstr(o, "spec"));
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
	/* IPv6 fwd rules where net.inet6.ip6.redirect is 0, on a kernel
	 * before FreeBSD main fb9969ca61ca: said, never refused. */
	if (si_ipv6(o) && jget(o, "ip6_redirect") != NULL && !jbool(o,
	    "ip6_redirect"))
		(void)kernel_fwd6_note(h, s, "the IPv6 fwd rules that send the "
		    "clients to SSLproxy");
	h_fmt(h, "<p class=\"dim\">%lld loaded in set 27 of %s, of %lld the "
	    "form makes", (long long)n, jail == NULL ? "the host's ipfw" :
	    shared ? "the host's ipfw (the jail's, tagged @jail)" : "the "
	    "jail's own ipfw", (long long)jint(o, "rules_expected", 0));
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

/* The words of a field and the prefixes of the console's lists picked
 * beside it (a select of several, by commas), each once, under key. */
static void
put_listed(ucl_object_t *o, const char *key, const char *s,
    const char *lists)
{
	const ucl_object_t	*e, *had;
	ucl_object_iter_t	 it, hit;
	ucl_object_t		*more;
	char			*joined;
	bool			 seen;

	put_words(o, key, s);
	if ((joined = pfxlist_joined(lists, ", ")) == NULL)
		return;
	more = ucl_object_typed_new(UCL_OBJECT);
	put_words(more, key, joined);
	free(joined);
	it = NULL;
	while ((e = ucl_object_iterate(jget(more, key), &it, true)) != NULL) {
		seen = false;
		hit = NULL;
		while ((had = ucl_object_iterate(jget(o, key), &hit, true)) !=
		    NULL)
			if (strcmp(ucl_object_tostring(had),
			    ucl_object_tostring(e)) == 0)
				seen = true;
		if (!seen)
			ucl_array_append((ucl_object_t *)(uintptr_t)jget(o, key),
			    ucl_object_copy(e));
	}
	ucl_object_unref(more);
}

bool
sslinspect_form(const char *form, const ucl_object_t *f)
{
	ucl_object_t	*spec, *ls, *l;
	char		 k[32], *text, *json, title[128];
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
	put_listed(spec, "clients", jstr(f, "clients"), jstr(f, "clients_pfx"));
	put_words(spec, "interfaces", jstr(f, "interfaces"));
	/* Never opened: the words given, ports as numbers, the categories
	 * ticked (none: unsaid). */
	put_words(spec, "pass", jstr(f, "pass"));
	put_words(spec, "pass_destinations", jstr(f, "pass_destinations"));
	put_listed(spec, "pass_clients", jstr(f, "pass_clients"), jstr(f,
	    "pass_pfx"));
	put_words(spec, "pass_ports", jstr(f, "pass_ports"));
	{
		ucl_object_t		*ports, *cats;
		const ucl_object_t	*e;
		ucl_object_iter_t	 it;

		ports = ucl_object_typed_new(UCL_ARRAY);
		it = NULL;
		while ((e = ucl_object_iterate(jget(spec, "pass_ports"), &it,
		    true)) != NULL)
			ucl_array_append(ports, strspn(ucl_object_tostring(e),
			    "0123456789") == strlen(ucl_object_tostring(e)) ?
			    ucl_object_fromint(strtol(ucl_object_tostring(e),
			    NULL, 10)) : ucl_object_fromstring(
			    ucl_object_tostring(e)));
		ucl_object_replace_key(spec, ports, "pass_ports", 0, false);
		cats = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < nitems(si_cats); i++) {
			snprintf(k, sizeof(k), "cat_%s", si_cats[i].name);
			if (jbool(f, k))
				ucl_array_append(cats, ucl_object_fromstring(
				    si_cats[i].name));
		}
		if (ucl_array_size(cats) == 0)
			ucl_object_unref(cats);
		else
			ucl_object_insert_key(spec, cats, "pass_categories", 0,
			    false);
	}
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
	json = job_json("sslproxy", "conf", NULL, 0, text, si_extra(jbool(f,
	    "replace") ? ",\"force\":true" : NULL));
	free(text);
	si_title(title, sizeof(title), "SSL inspection: sslproxy.conf and its "
	    "fwd rules");
	sec_job(json, title);
	return (true);
}

bool
sslinspect_action(const char *act, const char *arg, const char *value)
{
	char		 url[256], title[96], body[160], *json, *q;
	const char	*sid, *jail;

	if (strcmp(act, "input:ssl-where") == 0) {
		si.picked = true;
		snprintf(si.jail, sizeof(si.jail), "%s", value != NULL ? value :
		    "");
		res_drop(&si.r);
		render();
		return (true);
	}
	if (strncmp(act, "ssl-", 4) != 0)
		return (false);
	sid = sec_host_id();
	jail = si_where(si_server());
	if (strcmp(act, "ssl-install") == 0 && si_server() != NULL) {
		/* Where the tab looks: the host, or the jail by pkg -j. */
		q = json_quote(jail);
		if (asprintf(&json, "{\"kind\":\"pkg-install\",\"packages\":"
		    "[\"sslproxy\"]%s%s}", jail[0] != '\0' ? ",\"jail\":" : "",
		    jail[0] != '\0' ? q : "") == -1)
			abort();
		free(q);
		si_title(title, sizeof(title), "pkg install sslproxy");
		job_send_host(si_server(), json, title, JOB_SECURITY, jail);
		return (true);
	}
	if (strcmp(act, "ssl-retry") == 0) {
		res_drop(&si.r);
		return (true);
	}
	if (strcmp(act, "ssl-job") == 0 && arg != NULL && (strcmp(arg,
	    "enable") == 0 || strcmp(arg, "disable") == 0 || strcmp(arg,
	    "start") == 0 || strcmp(arg, "stop") == 0 || strcmp(arg,
	    "restart") == 0)) {
		json = job_json("sslproxy", arg, NULL, 0, NULL, si_extra(NULL));
		snprintf(body, sizeof(body), "SSL inspection: %s", arg);
		si_title(title, sizeof(title), body);
		sec_job(json, title);
		return (true);
	}
	if (strcmp(act, "ssl-issue") == 0 && sid[0] != '\0' && !si.issuing) {
		const ucl_object_t	*ca = jget(si.r.o, "ca");

		si.issuing = true;
		/* A jail's: its own intermediate, its key made for it. */
		q = json_quote(jail);
		snprintf(body, sizeof(body), "{%s%s%s%s}", jail[0] != '\0' ?
		    "\"jail\":" : "", jail[0] != '\0' ? q : "", jail[0] != '\0'
		    && jget(ca, "certificate") != NULL ? "," : "", jget(ca,
		    "certificate") != NULL ? "\"renew\":true" : "");
		free(q);
		rc_verb(rc_c(url, sizeof(url), "hosts/host=%s/inspection-ca",
		    rc_key(sid)), strcmp(body, "{}") != 0 ? body : NULL, NULL,
		    issue_cb, NULL);
		render();
		return (true);
	}
	return (true);
}
