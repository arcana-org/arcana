/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Luxuria: SSL inspection by SSLproxy (security/sslproxy), a plugin
 * the host has installed, run by Arcana's own rc script,
 * arcana_sslproxy (share/rc.d): the port has none.  The clients' TLS
 * reaches it by ipfw(8) fwd rules, which keep the destination, so that
 * its NAT engine ipfw reads it with getsockname(2): no NAT, no divert.
 *
 * The configuration (--sslproxy-conf) is rendered here from the form
 * the console sends (job kind sslproxy, verb conf), checked by
 * sslproxy -Q before it replaces the file, the form kept beside the
 * CA (--sslproxy-dir: spec.json).  An admin's own file is not replaced
 * unless that is asked for (force).  Split mode alone (Divert no): what
 * is opened is logged and encrypted again, handed to no program.  SSH
 * is relayed by a tcp proxyspec, never opened, a connect-log line a
 * session.
 *
 * The rules: one a protocol, family and interface, "fwd 127.0.0.1,<p>
 * tcp from <clients> to not me <port> in recv <if>" (::1 and me6 for
 * IPv6), with "// sslproxy:<proto>", written to fwd.rules as an ipfw
 * file of set 26 at rule 7 (before the ACLs' entry, 8, and the
 * SD-WAN's rules, 9 to 99).  Loaded as the ACLs are (invidia/acl.c):
 * set 26 emptied and disabled, the file loaded, swapped with set 27,
 * set 26 emptied; taken away by deleting set 27.  The admin's rules are
 * never touched: a rule of set 26 or 27 that is not SSL inspection's
 * (its comment), or one of another set at rule 7, refuses the change
 * and nothing is loaded.  The rules are loaded once SSLproxy is
 * started, and taken away before it is stopped; the rc script does the
 * same at boot.
 *
 * Bound (docs/notes/ssl-inspection.md, phase 2): the console compiles
 * an SD-WAN service's MBSF (MEF 138's middlebox, a function policy bound
 * to zones) into the form, "bound" naming the service, the policy and
 * its routing table, "zones" each a zone's clients (its prefixes at this
 * edge) and interfaces (the service's UNIs here), "except" the other
 * zones' prefixes where the zone is Default (a skipto past the rest),
 * "mbsf" the policy: its pass-through hosts as Pass rules (by SNI), the
 * oldest TLS version let through (MinSSLProto), a server's certificate
 * not trusted refused or not (VerifyPeer), and cleartext HTTP blocked by
 * an ipfw reset rule that logs (logdst rtsock), its comment the one the
 * console makes a Security Event Notification of (security <service>
 * <policy> unencrypted).  SSLproxy is then run in the service's table
 * (arcana_sslproxy_fib, rc.subr's setfib); the form is not the tab's.
 *
 * A restart of ipfw(8) empties set 27 under a running SSLproxy: the
 * agent looks every --sslproxy-watch seconds and loads the rules again
 * when the service is enabled and runs, its rules file is not empty and
 * set 27 holds none of them.
 *
 * The CA: the edge's key is made here (EC P-256, ca.key, 0600) and
 * never read out; a new one waits as ca.key.next while the one in use
 * serves.  The console signs its request with the tenant fleet's root
 * as an intermediate and sends it back (install-ca): taken only when it
 * is a CA's and the waiting key's, and when the chain given issued it;
 * written as ca.crt (CACert) with the root as chain.crt (CAChain).
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <ucl.h>

#include "agent.h"

/* The rules changed by one at a time: a job, or the watch. */
static pthread_mutex_t	fw_lock = PTHREAD_MUTEX_INITIALIZER;

#define	SERVICE		"arcana_sslproxy"	/* Arcana's rc script */
#define	MARK		"# Written by arcana-agent"
#define	TAG		"sslproxy:"		/* the rules' comments */
#define	FW_RULE		7		/* the rules' number */
#define	FW_SET		27		/* their set */
#define	FW_STAGE	26		/* where they are loaded first */
#define	LOG_DIR		"/var/log/sslproxy"
#define	SPEC_MAX	65536
#define	LISTENERS_MAX	8
#define	CLIENTS_MAX	32
#define	IFACES_MAX	8
#define	PEM_MAX		65536
#define	SSH_LISTEN	8022
#define	ZONES_MAX	16
#define	PASSES_MAX	64
#define	COMMENT_MAX	80		/* ipfw(8)'s, for a rule's comment */

/* The protocols the form takes: SSLproxy's type, the usual port. */
static const struct {
	const char	*name;
	const char	*type;
	int		 port;
} protos[] = {
	{ "https", "https", 443 }, { "http", "http", 80 },
	{ "smtps", "smtps", 465 }, { "pop3s", "pop3s", 995 },
	{ "imaps", "ssl", 993 },
};

struct listener {
	const char	*proto;		/* the form's name */
	const char	*type;		/* SSLproxy's */
	int		 port;		/* the clients' destination */
	int		 listen;	/* SSLproxy's, on the loopback */
};

/* Clients of the rules: a family each. */
struct clients {
	const char	*v4[CLIENTS_MAX], *v6[CLIENTS_MAX];
	size_t		 n4, n6;
};

/* A zone of the rules: the tab's form is one, unnamed. */
struct zone {
	const char	*name;
	struct clients	 c;		/* none: any */
	struct clients	 x;		/* skipped first: the other zones' */
	const char	*ifs[IFACES_MAX];
	size_t		 nifs;
};

/* The form, checked. */
struct form {
	struct listener	 l[LISTENERS_MAX + 1];	/* and SSH's */
	size_t		 nl;
	struct zone	 z[ZONES_MAX];
	size_t		 nz;
	bool		 ipv6, connect_log, content_log, ssh_log, passthrough;
	/* Bound: an SD-WAN service's MBSF. */
	bool		 bound;
	const char	*service, *policy;
	int		 fib;
	const char	*pass[PASSES_MAX];	/* hosts never opened */
	size_t		 npass;
	int		 tlsmin;		/* tls_names' index, -1 none */
	bool		 verify, plain_block;
};

/* SSLproxy's names of the versions, MEF 138's order (Table 9). */
static const char *const tls_mef[] = { "ssl3", "tls1.0", "tls1.1",
    "tls1.2", "tls1.3" };
static const char *const tls_names[] = { "ssl3", "tls10", "tls11",
    "tls12", "tls13" };

static const char *
bin(struct work *w)
{
	const char	*p;

	return ((p = tool(w, "sslproxy")) != NULL ? p : opts.sslproxy_bin);
}

static const char *
dir_file(struct work *w, const char *name)
{

	return (wfmt(w, "%s/%s", opts.sslproxy_dir, name));
}

/* ---- The form ---------------------------------------------------- */

static ucl_object_t *
spec_of(const char *text)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	if (text == NULL || strlen(text) > SPEC_MAX)
		return (NULL);
	p = ucl_parser_new(UCL_PARSER_NO_TIME | UCL_PARSER_DISABLE_MACRO);
	o = ucl_parser_add_string(p, text, 0) ? ucl_parser_get_object(p) : NULL;
	ucl_parser_free(p);
	if (o != NULL && ucl_object_type(o) != UCL_OBJECT) {
		ucl_object_unref(o);
		return (NULL);
	}
	return (o);
}

static bool
flag(const ucl_object_t *o, const char *key, bool dflt)
{
	const ucl_object_t	*v;

	if ((v = ucl_object_lookup(o, key)) == NULL ||
	    ucl_object_type(v) != UCL_BOOLEAN)
		return (dflt);
	return (ucl_object_toboolean(v));
}

static int
num(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;
	int64_t			 n;

	if ((v = ucl_object_lookup(o, key)) == NULL)
		return (-1);
	if (ucl_object_type(v) == UCL_INT)
		n = ucl_object_toint(v);
	else if (ucl_object_type(v) == UCL_STRING && ucl_object_tostring(v)[0] !=
	    '\0' && strspn(ucl_object_tostring(v), "0123456789") ==
	    strlen(ucl_object_tostring(v)) && strlen(ucl_object_tostring(v)) <
	    6)
		n = strtol(ucl_object_tostring(v), NULL, 10);
	else
		return (-1);
	return (n < 0 || n > 65535 ? -1 : (int)n);
}

/* A prefix, an address with or without its length: 4 or 6, 0 for none. */
static int
prefix_family(const char *s)
{
	char		 a[INET6_ADDRSTRLEN + 8], *slash;
	struct in6_addr	 a6;
	struct in_addr	 a4;
	const char	*e;
	long		 len;
	int		 fam;

	if (strlen(s) >= sizeof(a))
		return (0);
	snprintf(a, sizeof(a), "%s", s);
	len = -1;
	if ((slash = strchr(a, '/')) != NULL) {
		*slash++ = '\0';
		e = slash;
		if (*e == '\0' || strspn(e, "0123456789") != strlen(e) ||
		    strlen(e) > 3)
			return (0);
		len = strtol(e, NULL, 10);
	}
	if (inet_pton(AF_INET, a, &a4) == 1)
		fam = 4;
	else if (inet_pton(AF_INET6, a, &a6) == 1)
		fam = 6;
	else
		return (0);
	if (len > (fam == 4 ? 32 : 128))
		return (0);
	return (fam);
}

/* An interface's name as ifconfig(8) has it. */
static bool
ifname_ok(const char *s)
{
	size_t	i, n;

	n = strlen(s);
	if (n == 0 || n >= 16 || !isalpha((unsigned char)s[0]))
		return (false);
	for (i = 0; i < n; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '.' && s[i] !=
		    '_' && s[i] != '-')
			return (false);
	return (true);
}

/* The words of a list or of a string, at commas and spaces. */
static const char **
words_of(struct work *w, const ucl_object_t *o, const char *key, size_t *np)
{
	const ucl_object_t	*v, *e;
	ucl_object_iter_t	 it;
	const char		**out;
	char			*s, *p, *word;
	size_t			 n, cap;

	*np = 0;
	cap = 64;
	out = wcalloc(w, cap, sizeof(*out));
	n = 0;
	if ((v = ucl_object_lookup(o, key)) == NULL)
		return (out);
	if (ucl_object_type(v) == UCL_STRING) {
		s = wstrdup(w, ucl_object_tostring(v));
		for (p = s; (word = strsep(&p, ", \t\r\n")) != NULL; )
			if (word[0] != '\0' && n < cap)
				out[n++] = word;
	} else if (ucl_object_type(v) == UCL_ARRAY) {
		it = NULL;
		while ((e = ucl_object_iterate(v, &it, true)) != NULL && n < cap)
			if (ucl_object_type(e) == UCL_STRING &&
			    ucl_object_tostring(e)[0] != '\0')
				out[n++] = ucl_object_tostring(e);
	}
	*np = n;
	return (out);
}

/* An id of the console's, as a rule's comment takes it: letters,
 * digits, ., _ and -, 64 at most. */
static bool
word_ok(const char *s)
{
	size_t	i, n;

	n = strlen(s);
	if (n == 0 || n > 64)
		return (false);
	for (i = 0; i < n; i++)
		if (!isalnum((unsigned char)s[i]) && strchr("._-", s[i]) == NULL)
			return (false);
	return (true);
}

/* A host's name, *. before it for the names beneath. */
static bool
host_ok(const char *s)
{
	size_t	i, n;

	if (strncmp(s, "*.", 2) == 0)
		s += 2;
	n = strlen(s);
	if (n == 0 || n > 253 || s[0] == '.' || s[0] == '-')
		return (false);
	for (i = 0; i < n; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '.' && s[i] != '-')
			return (false);
	return (true);
}

/* The prefixes of o's key into c, by family; NULL, or what is wrong. */
static const char *
clients_of(struct work *w, const ucl_object_t *o, const char *key,
    const struct form *f, struct clients *c, const char *what)
{
	const char	**v;
	size_t		  i, n;

	v = words_of(w, o, key, &n);
	if (n > CLIENTS_MAX)
		return (wfmt(w, "%s%s: 32 prefixes at most", what, key));
	for (i = 0; i < n; i++)
		switch (prefix_family(v[i])) {
		case 4:
			c->v4[c->n4++] = v[i];
			break;
		case 6:
			if (!f->ipv6)
				return (wfmt(w, "%s%s: an IPv6 prefix with ipv6 "
				    "off", what, key));
			c->v6[c->n6++] = v[i];
			break;
		default:
			return (wfmt(w, "%s%s: %s is not an address or a "
			    "prefix", what, key, wvis(w, v[i])));
		}
	return (NULL);
}

/*
 * A zone of the rules, o its clients, except and interfaces (the tab's
 * form has no except); a bound one has clients, its prefixes here.
 */
static const char *
zone_of(struct work *w, const ucl_object_t *o, const struct form *f,
    struct zone *z, const char *what, bool bound)
{
	const char	**v, *e;
	size_t		  i, n;

	if ((e = clients_of(w, o, "clients", f, &z->c, what)) != NULL)
		return (e);
	if (bound && z->c.n4 + z->c.n6 == 0)
		return (wfmt(w, "%sclients: its prefixes here, one at least",
		    what));
	if (!bound && ucl_object_lookup(o, "except") != NULL)
		return ("except is a bound form's zones'");
	if ((e = clients_of(w, o, "except", f, &z->x, what)) != NULL)
		return (e);
	v = words_of(w, o, "interfaces", &n);
	if (n == 0)
		return (wfmt(w, "%sinterfaces: one at least, where the clients' "
		    "traffic comes in (in recv)", what));
	if (n > IFACES_MAX)
		return (wfmt(w, "%sinterfaces: 8 at most", what));
	for (i = 0; i < n; i++) {
		if (!ifname_ok(v[i]))
			return (wfmt(w, "%sinterfaces: %s is not an interface's "
			    "name", what, wvis(w, v[i])));
		z->ifs[z->nifs++] = v[i];
	}
	return (NULL);
}

/* A word of a list of an MBSF's, by MEF 138's names. */
static bool
listed(const ucl_object_t *m, const char *list, const char *word)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(m, list), &it, true))
	    != NULL)
		if (ucl_object_type(e) == UCL_STRING && strcmp(
		    ucl_object_tostring(e), word) == 0)
			return (true);
	return (false);
}

/* allow or block, dflt when not said; -1 for another word. */
static int
allow_block(const ucl_object_t *m, const char *key, int dflt)
{
	const char	*v;

	if ((v = ucl_object_tostring(ucl_object_lookup(m, key))) == NULL)
		return (dflt);
	return (strcmp(v, "allow") == 0 ? 1 : strcmp(v, "block") == 0 ? 0 :
	    -1);
}

/*
 * The MBSF of a bound form (MEF 138 Table 9): the oldest version let
 * through, above every one blocked and those on no list where its
 * No-match blocks; its pass-through hosts; a server's certificate not
 * trusted, and cleartext HTTP, each allowed or blocked.
 */
static const char *
mbsf_of(struct work *w, const ucl_object_t *m, struct form *f)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	int			 i, min, nm, isc, un;

	if (m == NULL || ucl_object_type(m) != UCL_OBJECT)
		return ("mbsf: the MBSF the zones are bound to, an object");
	if ((nm = allow_block(m, "no-match", 1)) < 0 || (isc = allow_block(m,
	    "invalid-server-certificate", 0)) < 0 || (un = allow_block(m,
	    "unencrypted", 1)) < 0)
		return ("mbsf: no-match, invalid-server-certificate and "
		    "unencrypted are allow or block");
	min = 0;
	for (i = 0; i < (int)nitems(tls_mef); i++) {
		if (listed(m, "block", tls_mef[i]))
			min = i + 1;
		else if (!listed(m, "allow", tls_mef[i]) && nm == 0 && i + 1 >
		    min)
			min = i + 1;
	}
	if (min == (int)nitems(tls_mef))
		return ("mbsf: every TLS version is blocked");
	f->tlsmin = min > 0 ? min : -1;
	f->verify = isc == 0;
	f->plain_block = un == 0;
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(m, "pass-through"),
	    &it, true)) != NULL) {
		if (f->npass == PASSES_MAX)
			return ("mbsf: pass-through, 64 hosts at most");
		if (ucl_object_type(e) != UCL_STRING || !host_ok(
		    ucl_object_tostring(e)))
			return (wfmt(w, "mbsf: pass-through: %s is not a host",
			    wvis(w, ucl_object_tostring_forced(e))));
		f->pass[f->npass++] = ucl_object_tostring(e);
	}
	return (NULL);
}

/* The form o into f; NULL, or what is wrong with it. */
static const char *
form_of(struct work *w, const ucl_object_t *o, struct form *f)
{
	const ucl_object_t	*ls, *e, *b, *zs;
	ucl_object_iter_t	 it;
	const char		*p, *err;
	size_t			 i, j;

	memset(f, 0, sizeof(*f));
	f->ipv6 = flag(o, "ipv6", true);
	f->connect_log = flag(o, "connect_log", true);
	f->content_log = flag(o, "content_log", false);
	f->ssh_log = flag(o, "ssh_log", false);
	f->passthrough = flag(o, "passthrough", true);
	if ((ls = ucl_object_lookup(o, "listeners")) == NULL ||
	    ucl_object_type(ls) != UCL_ARRAY || ucl_array_size(ls) == 0)
		return ("listeners: one protocol at least, each {proto, port, "
		    "listen}");
	if (ucl_array_size(ls) > LISTENERS_MAX)
		return ("listeners: 8 at most");
	it = NULL;
	while ((e = ucl_object_iterate(ls, &it, true)) != NULL) {
		struct listener	*l = &f->l[f->nl];

		if (ucl_object_type(e) != UCL_OBJECT || (p = ucl_object_tostring(
		    ucl_object_lookup(e, "proto"))) == NULL)
			return ("listeners: each {proto, port, listen}");
		for (i = 0; i < nitems(protos); i++)
			if (strcmp(p, protos[i].name) == 0)
				break;
		if (i == nitems(protos))
			return (wfmt(w, "listeners: %s is not one of https, http, "
			    "smtps, pop3s, imaps", wvis(w, p)));
		l->proto = protos[i].name;
		l->type = protos[i].type;
		l->port = ucl_object_lookup(e, "port") != NULL ? num(e, "port") :
		    protos[i].port;
		l->listen = num(e, "listen");
		if (l->port < 1)
			return (wfmt(w, "listeners: %s's port is 1 to 65535",
			    l->proto));
		if (l->listen < 1024)
			return (wfmt(w, "listeners: %s's listen port, where "
			    "SSLproxy listens on the loopback, is 1024 to 65535",
			    l->proto));
		f->nl++;
	}
	if (f->ssh_log) {
		f->l[f->nl].proto = "ssh";
		f->l[f->nl].type = "tcp";
		f->l[f->nl].port = 22;
		f->l[f->nl].listen = SSH_LISTEN;
		f->nl++;
	}
	for (i = 0; i < f->nl; i++)
		for (j = i + 1; j < f->nl; j++) {
			if (f->l[i].listen == f->l[j].listen)
				return (wfmt(w, "listeners: %s and %s both listen "
				    "at %d", f->l[i].proto, f->l[j].proto,
				    f->l[i].listen));
			if (f->l[i].port == f->l[j].port)
				return (wfmt(w, "listeners: %s and %s both take "
				    "port %d", f->l[i].proto, f->l[j].proto,
				    f->l[i].port));
		}
	if ((b = ucl_object_lookup(o, "bound")) == NULL) {
		if (ucl_object_lookup(o, "zones") != NULL ||
		    ucl_object_lookup(o, "mbsf") != NULL)
			return ("zones and mbsf are a bound form's (an SD-WAN "
			    "service's MBSF, from the console)");
		f->nz = 1;
		return (zone_of(w, o, f, &f->z[0], "", false));
	}
	if (ucl_object_type(b) != UCL_OBJECT || (f->service = ucl_object_tostring(
	    ucl_object_lookup(b, "service"))) == NULL || (f->policy =
	    ucl_object_tostring(ucl_object_lookup(b, "policy"))) == NULL ||
	    !word_ok(f->service) || !word_ok(f->policy) || (f->fib = num(b,
	    "fib")) < 0)
		return ("bound: the service, its MBSF's id (letters, digits, ., "
		    "_ and -) and its routing table (fib)");
	f->bound = true;
	if (ucl_object_lookup(o, "clients") != NULL ||
	    ucl_object_lookup(o, "interfaces") != NULL)
		return ("a bound form's clients and interfaces are its zones'");
	if ((zs = ucl_object_lookup(o, "zones")) == NULL || ucl_object_type(zs)
	    != UCL_ARRAY || ucl_array_size(zs) == 0)
		return ("zones: one at least, each {name, clients, interfaces}");
	if (ucl_array_size(zs) > ZONES_MAX)
		return ("zones: 16 at most");
	it = NULL;
	while ((e = ucl_object_iterate(zs, &it, true)) != NULL) {
		if (ucl_object_type(e) != UCL_OBJECT || (p = ucl_object_tostring(
		    ucl_object_lookup(e, "name"))) == NULL || !word_ok(p))
			return ("zones: each {name, clients, interfaces}, its name "
			    "letters, digits, ., _ and -");
		if ((err = zone_of(w, e, f, &f->z[f->nz], wfmt(w, "zone %s: ",
		    p), true)) != NULL)
			return (err);
		f->z[f->nz++].name = p;
	}
	return (mbsf_of(w, ucl_object_lookup(o, "mbsf"), f));
}

/* sslproxy.conf(5), from the form. */
static char *
conf_render(struct work *w, const struct form *f)
{
	char	*out;
	size_t	 len, i;
	FILE	*fp;

	out = NULL;
	if ((fp = open_memstream(&out, &len)) == NULL)
		return (NULL);
	fprintf(fp, MARK " from the SSL inspection form (Security,\n"
	    "# SSL inspection): a change here is replaced at its next save.\n"
	    "# The clients' traffic comes by ipfw fwd rules (%s).\n",
	    dir_file(w, "fwd.rules"));
	fprintf(fp, "CACert %s\nCAKey %s\nCAChain %s\n", dir_file(w, "ca.crt"),
	    dir_file(w, "ca.key"), dir_file(w, "chain.crt"));
	/* Split: opened, logged and encrypted again, given to no program. */
	fprintf(fp, "Divert no\n");
	fprintf(fp, "Passthrough %s\n", f->passthrough ? "yes" : "no");
	if (f->bound)
		fprintf(fp, "# SD-WAN service %s's MBSF %s (MEF 138), in routing "
		    "table %d.\n", f->service, f->policy, f->fib);
	/* A server's certificate not trusted: refused unless the MBSF lets
	 * it through. */
	fprintf(fp, "VerifyPeer %s\nAllowWrongHost no\n", !f->bound ||
	    f->verify ? "yes" : "no");
	if (f->tlsmin > 0)
		fprintf(fp, "MinSSLProto %s\n", tls_names[f->tlsmin]);
	/* Never opened: by the TLS name, a *. one's names beneath it as a
	 * substring (SSLproxy has no suffix match). */
	for (i = 0; i < f->npass; i++)
		if (strncmp(f->pass[i], "*.", 2) == 0)
			fprintf(fp, "Pass to sni %s*\n", f->pass[i] + 1);
		else
			fprintf(fp, "Pass to sni %s\n", f->pass[i]);
	fprintf(fp, "ConnIdleTimeout 120\nExpiredConnCheckPeriod 10\n");
	if (f->connect_log)
		fprintf(fp, "ConnectLog " LOG_DIR "/connect.log\n");
	if (f->content_log)
		fprintf(fp, "ContentLogDir " LOG_DIR "/content\n");
	for (i = 0; i < f->nl; i++) {
		fprintf(fp, "ProxySpec %s 127.0.0.1 %d ipfw\n", f->l[i].type,
		    f->l[i].listen);
		if (f->ipv6)
			fprintf(fp, "ProxySpec %s ::1 %d ipfw\n", f->l[i].type,
			    f->l[i].listen);
	}
	if (fclose(fp) != 0) {
		free(out);
		return (NULL);
	}
	return (wadopt(w, out));
}

/* Whether a list has a prefix of length 0, which ipfw writes "any":
 * of either family, unless the rule says which. */
static bool
zero_len(const char *const *v, size_t n)
{
	size_t	i, l;

	for (i = 0; i < n; i++)
		if ((l = strlen(v[i])) > 2 && strcmp(v[i] + l - 2, "/0") == 0)
			return (true);
	return (false);
}

/* The clients of a family as ipfw takes them: "any", or a list. */
static const char *
sources(struct work *w, const char *const *v, size_t n)
{
	char	*s;
	size_t	 i;

	if (n == 0)
		return ("any");
	s = wstrdup(w, v[0]);
	for (i = 1; i < n; i++)
		s = wfmt(w, "%s,%s", s, v[i]);
	return (s);
}

/*
 * The fwd rules, an ipfw file of set 26, and how many: a zone at a
 * time, each family its clients have (none named: any, of both) and
 * interface, the other zones' prefixes skipped first (a Default
 * zone's), a protocol's rule each, then cleartext HTTP reset where a
 * bound MBSF blocks it.  The reset logs, its comment the one the
 * console makes a SEN of while ipfw's 80 characters hold it.
 */
static char *
rules_render(struct work *w, const struct form *f, int *np)
{
	const struct zone	*z;
	const char		*src, *cm;
	char			*out;
	size_t			 len, i, k, zi, nx;
	int			 fam, n;
	bool			 any, famq;
	FILE			*fp;

	out = NULL;
	n = 0;
	if ((fp = open_memstream(&out, &len)) == NULL)
		return (NULL);
	cm = f->bound ? wfmt(w, "security %s %s unencrypted " TAG "http",
	    f->service, f->policy) : NULL;
	if (cm != NULL && strlen(cm) > COMMENT_MAX)
		cm = TAG "http";
	for (zi = 0; zi < f->nz; zi++) {
		z = &f->z[zi];
		for (fam = 4; fam <= 6; fam += 2) {
			if (fam == 6 && !f->ipv6)
				continue;
			/* Clients of one family named: the other's none. */
			any = z->c.n4 == 0 && z->c.n6 == 0;
			if (!any && (fam == 4 ? z->c.n4 : z->c.n6) == 0)
				continue;
			src = any ? "any" : sources(w, fam == 4 ? z->c.v4 :
			    z->c.v6, fam == 4 ? z->c.n4 : z->c.n6);
			/* The family said where the clients are any. */
			famq = any || zero_len(fam == 4 ? z->c.v4 : z->c.v6,
			    fam == 4 ? z->c.n4 : z->c.n6);
			nx = fam == 4 ? z->x.n4 : z->x.n6;
			for (k = 0; k < z->nifs; k++) {
				if (nx > 0) {
					fprintf(fp, "add %d set %d skipto %d tcp from "
					    "%s to not %s in recv %s // " TAG
					    "except\n", FW_RULE, FW_STAGE, FW_RULE +
					    1, sources(w, fam == 4 ? z->x.v4 :
					    z->x.v6, nx), fam == 4 ? "me" : "me6",
					    z->ifs[k]);
					n++;
				}
				for (i = 0; i < f->nl; i++) {
					fprintf(fp, "add %d set %d fwd %s,%d tcp from "
					    "%s to not %s %d in recv %s%s // " TAG
					    "%s\n", FW_RULE, FW_STAGE, fam == 4 ?
					    "127.0.0.1" : "::1", f->l[i].listen,
					    src, fam == 4 ? "me" : "me6",
					    f->l[i].port, z->ifs[k], famq ? (fam ==
					    4 ? " ip4" : " ip6") : "",
					    f->l[i].proto);
					n++;
				}
				if (f->plain_block) {
					fprintf(fp, "add %d set %d %s log logdst "
					    "rtsock logamount 1000 tcp from %s to "
					    "not %s 80 in recv %s%s // %s\n",
					    FW_RULE, FW_STAGE, fam == 4 ? "reset" :
					    "reset6", src, fam == 4 ? "me" : "me6",
					    z->ifs[k], famq ? (fam == 4 ? " ip4" :
					    " ip6") : "", cm);
					n++;
				}
			}
		}
	}
	if (fclose(fp) != 0) {
		free(out);
		return (NULL);
	}
	*np = n;
	return (wadopt(w, out));
}

/* ---- ipfw -------------------------------------------------------- */

struct krule {
	long		 num;
	int		 set;
	const char	*text;		/* the rule, without the counters */
	bool		 ours;		/* its comment is SSL inspection's */
};

/* ipfw -a -S list read; -1 where ipfw cannot be. */
static int
kernel_rules(struct work *w, struct krule **out, size_t *np)
{
	struct execres	 res;
	struct krule	*v;
	const char	*p, *nl, *c;
	char		*argv[5], *line;
	size_t		 n, cap;
	uintmax_t	 pkts, bytes;
	long		 num;
	int		 set, off;

	*out = NULL;
	*np = 0;
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"-a";
	argv[2] = (char *)(uintptr_t)"-S";
	argv[3] = (char *)(uintptr_t)"list";
	argv[4] = NULL;
	if (run_read_max(w, argv, &res, ARC_MAX_JSON) != 0)
		return (-1);
	n = cap = 0;
	v = NULL;
	for (p = res.out != NULL ? res.out : ""; *p != '\0';
	    p = *nl != '\0' ? nl + 1 : nl) {
		nl = p + strcspn(p, "\n");
		line = wstrndup(w, p, (size_t)(nl - p));
		if (sscanf(line, "%ld %ju %ju set %d %n", &num, &pkts, &bytes,
		    &set, &off) != 4)
			continue;
		if (n == cap) {
			struct krule	*nv;

			cap = cap == 0 ? 64 : cap * 2;
			nv = wcalloc(w, cap, sizeof(*v));
			if (n > 0)
				memcpy(nv, v, n * sizeof(*v));
			v = nv;
		}
		v[n].num = num;
		v[n].set = set;
		v[n].text = line + off;
		/* Its comment has the tag: an SEN's starts otherwise. */
		v[n].ours = (c = strstr(line + off, "// ")) != NULL &&
		    strstr(c, TAG) != NULL;
		n++;
	}
	*out = v;
	*np = n;
	return (0);
}

/* Whether the kernel's rules leave set 26, 27 and rule 7 to us; NULL,
 * or why not. */
static const char *
kernel_free(struct work *w, const struct krule *k, size_t n, bool *any)
{
	size_t	i;

	*any = false;
	for (i = 0; i < n; i++) {
		if (k[i].set == FW_SET || k[i].set == FW_STAGE) {
			if (!k[i].ours)
				return (wfmt(w, "rule %ld is in ipfw set %d, which "
				    "SSL inspection keeps, and is not its own: "
				    "move it to another set first", k[i].num,
				    k[i].set));
			*any = true;
			continue;
		}
		if (k[i].num == FW_RULE)
			return (wfmt(w, "rule %d of ipfw set %d is at the number "
			    "SSL inspection keeps (%d): renumber it first",
			    FW_RULE, k[i].set, FW_RULE));
	}
	return (NULL);
}

static int
ipfw(struct work *w, const char **errp, const char *a, const char *b,
    const char *c, const char *d)
{
	struct execres	 res;
	char		*argv[7];
	int		 n;

	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[n++] = (char *)(uintptr_t)"-q";
	argv[n++] = (char *)(uintptr_t)a;
	if (b != NULL)
		argv[n++] = (char *)(uintptr_t)b;
	if (c != NULL)
		argv[n++] = (char *)(uintptr_t)c;
	if (d != NULL)
		argv[n++] = (char *)(uintptr_t)d;
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		if (errp != NULL)
			*errp = wtext(w, exec_error(w, &res, "ipfw"));
		return (-1);
	}
	return (0);
}

#define	SET(n)		__XSTRING(n)

/* The fwd file loaded into set 27, by set 26; 0, or -1 with why. */
static int
rules_load(struct work *w, const char **errp)
{
	struct krule	*k;
	const char	*path, *e;
	size_t		 nk, len;
	bool		 any;
	int		 step, rc;

	path = dir_file(w, "fwd.rules");
	if (scope_slurp(w, path, &len) == NULL || len == 0)
		return (0);
	step = step_begin(w, STEP_EXEC, "ipfw fwd", "the fwd rules loaded into "
	    "set " SET(FW_SET) " at rule " SET(FW_RULE));
	if (kernel_rules(w, &k, &nk) != 0) {
		*errp = "ipfw cannot be read (ipfw(4) not loaded?): no fwd rule "
		    "sends the clients to SSLproxy";
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	if ((e = kernel_free(w, k, nk, &any)) != NULL) {
		*errp = e;
		step_end(w, step, false, "%s", e);
		return (-1);
	}
	(void)ipfw(w, NULL, "-f", "delete", "set", SET(FW_STAGE));
	rc = -1;
	if (ipfw(w, errp, "set", "disable", SET(FW_STAGE), NULL) != 0)
		goto out;
	if (ipfw(w, errp, path, NULL, NULL, NULL) != 0) {
		(void)ipfw(w, NULL, "-f", "delete", "set", SET(FW_STAGE));
		goto out;
	}
	if (ipfw(w, errp, "set", "swap", SET(FW_STAGE), SET(FW_SET)) != 0) {
		(void)ipfw(w, NULL, "-f", "delete", "set", SET(FW_STAGE));
		goto out;
	}
	(void)ipfw(w, NULL, "set", "enable", SET(FW_SET), NULL);
	(void)ipfw(w, NULL, "-f", "delete", "set", SET(FW_STAGE));
	rc = 0;
out:
	if (rc == 0)
		step_end(w, step, true, NULL);
	else
		step_end(w, step, false, "%s", *errp);
	return (rc);
}

/* Set 27 taken away, where it holds SSL inspection's rules alone. */
static int
rules_unload(struct work *w, const char **errp)
{
	struct krule	*k;
	size_t		 nk, i;
	bool		 any;

	if (kernel_rules(w, &k, &nk) != 0)
		return (0);
	any = false;
	for (i = 0; i < nk; i++) {
		if (k[i].set != FW_SET && k[i].set != FW_STAGE)
			continue;
		if (!k[i].ours) {
			*errp = wfmt(w, "rule %ld is in ipfw set %d, which SSL "
			    "inspection keeps, and is not its own: the set is "
			    "left alone, move it to another set first",
			    k[i].num, k[i].set);
			return (-1);
		}
		any = true;
	}
	if (!any)
		return (0);
	if (ipfw(w, errp, "-f", "delete", "set", SET(FW_SET)) != 0)
		return (-1);
	(void)ipfw(w, NULL, "-f", "delete", "set", SET(FW_STAGE));
	return (0);
}

/* ---- The service ------------------------------------------------- */

/* "service arcana_sslproxy one<verb>"; 0, or -1 with why when asked. */
static int
svc(struct work *w, const char *verb, const char **errp)
{
	struct execres	 res;
	char		*argv[4];

	argv[0] = (char *)(uintptr_t)opts.service_bin;
	argv[1] = (char *)(uintptr_t)SERVICE;
	argv[2] = wfmt(w, "one%s", verb);
	argv[3] = NULL;
	if ((strcmp(verb, "status") == 0 ? run_read(w, argv, &res) :
	    run_exec(w, argv, &res)) != 0) {
		if (errp != NULL)
			*errp = wtext(w, exec_error(w, &res, wfmt(w, "service "
			    SERVICE " one%s", verb)));
		return (-1);
	}
	return (0);
}

static bool
running(struct work *w)
{

	return (svc(w, "status", NULL) == 0);
}

/* rc.subr's checkyesno. */
static bool
yes(const char *v)
{

	return (v != NULL && (strcasecmp(v, "yes") == 0 || strcasecmp(v,
	    "true") == 0 || strcasecmp(v, "on") == 0 || strcmp(v, "1") == 0));
}

/* Started (or started again, unless again is false and it runs),
 * then its rules loaded. */
static int
start(struct work *w, bool again, const char **errp)
{
	int	rc;

	pthread_mutex_lock(&fw_lock);
	rc = 0;
	if (!running(w))
		rc = svc(w, "start", errp);
	else if (again)
		rc = svc(w, "restart", errp);
	if (rc == 0)
		rc = rules_load(w, errp);
	pthread_mutex_unlock(&fw_lock);
	return (rc);
}

/* Its rules taken away, then stopped. */
static int
stop(struct work *w, const char **errp)
{
	int	rc;

	pthread_mutex_lock(&fw_lock);
	if ((rc = rules_unload(w, errp)) == 0 && running(w))
		rc = svc(w, "stop", errp);
	pthread_mutex_unlock(&fw_lock);
	return (rc);
}

/*
 * The watch: set 27 emptied under a running SSLproxy (ipfw(8)
 * restarted, or flushed) has its rules loaded again, where the service
 * is enabled, the rules file is not empty and the sets are free.  Said
 * once a change, not every turn.
 */
static void *
watch(void *arg __unused)
{
	struct work	 w;
	struct krule	*k;
	struct stat	 sb;
	const char	*e, *path;
	size_t		 nk, i;
	bool		 ours, any, warned;

	warned = false;
	for (;;) {
		sleep((unsigned int)opts.sslproxy_watch_s);
		work_init(&w);
		w.nice = true;
		path = dir_file(&w, "fwd.rules");
		pthread_mutex_lock(&fw_lock);
		if (stat(path, &sb) == 0 && sb.st_size > 0 && kernel_rules(&w,
		    &k, &nk) == 0) {
			ours = false;
			for (i = 0; i < nk; i++)
				if (k[i].set == FW_SET && k[i].ours)
					ours = true;
			if (!ours && kernel_free(&w, k, nk, &any) == NULL &&
			    yes(rc_get(&w, SERVICE "_enable")) && running(&w)) {
				if (rules_load(&w, &e) == 0) {
					logmsg(LOG_NOTICE, "sslproxy: ipfw set %d "
					    "held none of its fwd rules while "
					    "SSLproxy runs (ipfw restarted?): "
					    "loaded again", FW_SET);
					warned = false;
				} else if (!warned) {
					logmsg(LOG_WARNING, "sslproxy: the fwd "
					    "rules not loaded again: %s", e);
					warned = true;
				}
			}
		}
		pthread_mutex_unlock(&fw_lock);
		work_free(&w);
	}
	return (NULL);
}

void
sslproxy_watch_start(void)
{
	pthread_t	tid;
	int		error;

	if (opts.sslproxy_watch_s <= 0)
		return;
	if ((error = pthread_create(&tid, NULL, watch, NULL)) != 0) {
		logmsg(LOG_ERR, "sslproxy watch: %s", strerror(error));
		return;
	}
	(void)pthread_detach(tid);
}

/* ---- The CA ------------------------------------------------------ */

static X509 *
pem_cert(const char *pem)
{
	BIO	*b;
	X509	*x;

	if (pem == NULL || (b = BIO_new_mem_buf(pem, -1)) == NULL)
		return (NULL);
	x = PEM_read_bio_X509(b, NULL, NULL, NULL);
	BIO_free(b);
	return (x);
}

/* A name on one line, RFC 2253's. */
static const char *
name_line(struct work *w, const X509_NAME *n)
{
	BIO	*b;
	char	*p;
	long	 len;
	const char *s;

	if ((b = BIO_new(BIO_s_mem())) == NULL)
		return ("");
	(void)X509_NAME_print_ex(b, n, 0, XN_FLAG_RFC2253);
	len = BIO_get_mem_data(b, &p);
	s = wfmt(w, "%.*s", (int)len, p);
	BIO_free(b);
	return (s);
}

static int64_t
not_after(const X509 *x)
{
	struct tm	tm;

	if (ASN1_TIME_to_tm(X509_get0_notAfter(x), &tm) != 1)
		return (0);
	return ((int64_t)timegm(&tm));
}

/* A certificate as the read says it, into o under key. */
static void
cert_json(struct work *w, ucl_object_t *o, const char *key, X509 *x,
    const char *pem)
{
	ucl_object_t	*c;

	c = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(c, ucl_object_fromstring(name_line(w,
	    X509_get_subject_name(x))), "subject", 0, false);
	ucl_object_insert_key(c, ucl_object_fromstring(name_line(w,
	    X509_get_issuer_name(x))), "issuer", 0, false);
	ucl_object_insert_key(c, ucl_object_fromint(not_after(x)), "not_after",
	    0, false);
	ucl_object_insert_key(c, ucl_object_fromstring(pem), "pem", 0, false);
	ucl_object_insert_key(o, c, key, 0, false);
}

/* The PEM of the last certificate of a chain's text. */
static const char *
last_pem(struct work *w, const char *text)
{
	const char	*p, *q, *last;

	last = NULL;
	for (p = text; p != NULL && (q = strstr(p, "-----BEGIN CERTIFICATE-----"))
	    != NULL; p = q + 1)
		last = q;
	return (last != NULL ? wstrdup(w, last) : NULL);
}

static EVP_PKEY *
key_read(struct work *w, const char *path)
{
	EVP_PKEY	*k;
	BIO		*b;
	char		*pem;

	if ((pem = scope_slurp(w, path, NULL)) == NULL || (b =
	    BIO_new_mem_buf(pem, -1)) == NULL)
		return (NULL);
	k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
	BIO_free(b);
	explicit_bzero(pem, strlen(pem));
	return (k);
}

/* The CA's directory, root's alone. */
static int
dir_make(struct work *w, const char **errp)
{

	if (scope_mkdirs(w, opts.sslproxy_dir) != 0 || chmod(opts.sslproxy_dir,
	    0700) != 0) {
		*errp = wfmt(w, "%s: %s", opts.sslproxy_dir, strerror(errno));
		return (-1);
	}
	return (0);
}

/*
 * The key a request is made for: a new one when renew is asked or none
 * is there, as ca.key.next; else the one that waits, else the one in
 * use.  The request (ca.csr) into *csrp.  0, or -1 with why.
 */
int
sslproxy_csr(struct work *w, bool renew, const char **csrp, const char **errp)
{
	EVP_PKEY	*key;
	X509_REQ	*rq;
	X509_NAME	*nm;
	BIO		*b;
	char		*p, host[MAXHOSTNAMELEN], *pem;
	const char	*kpath, *cn;
	long		 len;
	bool		 ok;
	int		 step;

	if (dir_make(w, errp) != 0)
		return (-1);
	kpath = dir_file(w, "ca.key.next");
	step = step_begin(w, STEP_LIB, "csr", "the edge's CA key and its "
	    "request");
	if (renew || (access(kpath, F_OK) != 0 && access(dir_file(w, "ca.key"),
	    F_OK) != 0)) {
		if ((key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256")) ==
		    NULL || (b = BIO_new(BIO_s_mem())) == NULL) {
			EVP_PKEY_free(key);
			*errp = "cannot make a key";
			step_end(w, step, false, "%s", *errp);
			return (-1);
		}
		ok = PEM_write_bio_PrivateKey(b, key, NULL, NULL, 0, NULL,
		    NULL) == 1;
		len = BIO_get_mem_data(b, &p);
		pem = wfmt(w, "%.*s", (int)len, p);
		BIO_free(b);
		if (!ok || scope_replace(w, kpath, pem, strlen(pem), 0600, NULL)
		    != 0) {
			explicit_bzero(pem, strlen(pem));
			EVP_PKEY_free(key);
			*errp = wfmt(w, "%s: %s", kpath, strerror(errno));
			step_end(w, step, false, "%s", *errp);
			return (-1);
		}
		explicit_bzero(pem, strlen(pem));
	} else if ((key = key_read(w, access(kpath, F_OK) == 0 ? kpath :
	    dir_file(w, "ca.key"))) == NULL) {
		*errp = "the edge's CA key cannot be read";
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	if (gethostname(host, sizeof(host)) != 0)
		snprintf(host, sizeof(host), "edge");
	cn = wfmt(w, "Arcana SSL inspection on %.*s", 32, host);
	rq = X509_REQ_new();
	nm = rq != NULL ? X509_REQ_get_subject_name(rq) : NULL;
	ok = rq != NULL && X509_REQ_set_version(rq, 0) == 1 &&
	    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_UTF8,
	    (const unsigned char *)cn, -1, -1, 0) == 1 &&
	    X509_REQ_set_pubkey(rq, key) == 1 &&
	    X509_REQ_sign(rq, key, EVP_sha256()) > 0;
	EVP_PKEY_free(key);
	b = ok ? BIO_new(BIO_s_mem()) : NULL;
	if (b == NULL || PEM_write_bio_X509_REQ(b, rq) != 1) {
		BIO_free(b);
		X509_REQ_free(rq);
		*errp = "cannot make the request";
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	X509_REQ_free(rq);
	len = BIO_get_mem_data(b, &p);
	*csrp = wfmt(w, "%.*s", (int)len, p);
	BIO_free(b);
	(void)scope_replace(w, dir_file(w, "ca.csr"), *csrp, strlen(*csrp),
	    0644, NULL);
	step_end(w, step, true, NULL);
	return (0);
}

/*
 * The intermediate for the waiting key (or the one in use) and the
 * chain above it: checked, written, the waiting key made the one in
 * use, SSLproxy restarted where it runs.  0, or -1 with why.
 */
int
sslproxy_install(struct work *w, const char *certpem, const char *chainpem,
    const char **subjectp, int64_t *notafterp, const char **errp)
{
	X509		*x, *up;
	EVP_PKEY	*key;
	const char	*next, *kpath;
	bool		 waits;
	int		 step, rc;

	if (certpem == NULL || chainpem == NULL || strlen(certpem) > PEM_MAX ||
	    strlen(chainpem) > PEM_MAX) {
		*errp = "a certificate and its chain, PEM, 64 KB at most";
		return (-1);
	}
	next = dir_file(w, "ca.key.next");
	waits = access(next, F_OK) == 0;
	kpath = waits ? next : dir_file(w, "ca.key");
	x = pem_cert(certpem);
	up = pem_cert(chainpem);
	key = key_read(w, kpath);
	step = step_begin(w, STEP_FILE, "ca.crt", "the edge's CA certificate "
	    "checked and written");
	rc = -1;
	if (x == NULL || up == NULL)
		*errp = "the certificate or its chain does not read as PEM";
	else if (key == NULL)
		*errp = "no key of the edge's CA: csr first";
	else if (X509_check_ca(x) == 0)
		*errp = "the certificate is not a CA's: SSLproxy would forge "
		    "certificates no client takes";
	else if (X509_check_private_key(x, key) != 1)
		*errp = "the certificate is not of the edge's key";
	else if (X509_check_issued(up, x) != X509_V_OK ||
	    X509_verify(x, X509_get0_pubkey(up)) != 1)
		*errp = "the chain's first certificate did not issue it";
	else if (scope_replace(w, dir_file(w, "chain.crt"), chainpem,
	    strlen(chainpem), 0644, NULL) != 0 || scope_replace(w,
	    dir_file(w, "ca.crt"), certpem, strlen(certpem), 0644, NULL) != 0)
		*errp = wfmt(w, "%s: %s", opts.sslproxy_dir, strerror(errno));
	else if (waits && rename(next, dir_file(w, "ca.key")) != 0)
		*errp = wfmt(w, "%s: %s", next, strerror(errno));
	else {
		*subjectp = name_line(w, X509_get_subject_name(x));
		*notafterp = not_after(x);
		rc = 0;
	}
	X509_free(x);
	X509_free(up);
	EVP_PKEY_free(key);
	if (rc != 0) {
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	(void)scope_unlink(w, dir_file(w, "ca.csr"));
	step_end(w, step, true, NULL);
	/* A running SSLproxy reads its CA as it starts. */
	if (running(w) && svc(w, "restart", errp) != 0)
		return (-1);
	return (0);
}

/* ---- The read ---------------------------------------------------- */

static void
put_str(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(v), key, 0, true);
}

static void
put_bool(ucl_object_t *o, const char *key, bool v)
{

	ucl_object_insert_key(o, ucl_object_frombool(v), key, 0, true);
}

static bool
installed(struct work *w)
{

	return (access(bin(w), X_OK) == 0);
}

/* What sslproxy -V says first. */
static const char *
version(struct work *w)
{
	struct execres	 res;
	const char	*t;
	char		*argv[3];

	argv[0] = (char *)(uintptr_t)bin(w);
	argv[1] = (char *)(uintptr_t)"-V";
	argv[2] = NULL;
	if (run_read(w, argv, &res) != 0)
		return (NULL);
	t = res.out != NULL && res.out[0] != '\0' ? res.out : res.err;
	if (t == NULL || t[0] == '\0')
		return (NULL);
	return (wfmt(w, "%.*s", (int)strcspn(t, "\r\n"), t));
}

static void
ca_json(struct work *w, ucl_object_t *top)
{
	ucl_object_t	*ca;
	const char	*pem, *root;
	X509		*x;

	ca = ucl_object_typed_new(UCL_OBJECT);
	put_bool(ca, "key", access(dir_file(w, "ca.key"), F_OK) == 0);
	put_bool(ca, "pending", access(dir_file(w, "ca.key.next"), F_OK) == 0);
	put_str(ca, "csr", scope_slurp(w, dir_file(w, "ca.csr"), NULL));
	if ((pem = scope_slurp(w, dir_file(w, "ca.crt"), NULL)) != NULL &&
	    (x = pem_cert(pem)) != NULL) {
		cert_json(w, ca, "certificate", x, pem);
		X509_free(x);
	}
	if ((pem = scope_slurp(w, dir_file(w, "chain.crt"), NULL)) != NULL &&
	    (root = last_pem(w, pem)) != NULL && (x = pem_cert(root)) != NULL) {
		cert_json(w, ca, "root", x, root);
		X509_free(x);
	}
	ucl_object_insert_key(top, ca, "ca", 0, false);
}

/* The words of a list, as a list of the read's. */
static ucl_object_t *
words_json(struct work *w, const ucl_object_t *o, const char *key)
{
	ucl_object_t	*arr;
	const char	**v;
	size_t		  i, n;

	arr = ucl_object_typed_new(UCL_ARRAY);
	v = words_of(w, o, key, &n);
	for (i = 0; i < n; i++)
		ucl_array_append(arr, ucl_object_fromstring(v[i]));
	return (arr);
}

/* A bound form's service, MBSF, table and zones, as the read says. */
static void
bound_json(struct work *w, ucl_object_t *top, const char *text)
{
	const ucl_object_t	*b, *z;
	ucl_object_iter_t	 it;
	ucl_object_t		*spec, *o, *zs, *zo;

	if ((spec = spec_of(text)) == NULL)
		return;
	if ((b = ucl_object_lookup(spec, "bound")) != NULL && ucl_object_type(b)
	    == UCL_OBJECT) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "service", ucl_object_tostring(ucl_object_lookup(b,
		    "service")));
		put_str(o, "policy", ucl_object_tostring(ucl_object_lookup(b,
		    "policy")));
		if (num(b, "fib") >= 0)
			ucl_object_insert_key(o, ucl_object_fromint(num(b, "fib")),
			    "fib", 0, false);
		zs = ucl_object_typed_new(UCL_ARRAY);
		it = NULL;
		while ((z = ucl_object_iterate(ucl_object_lookup(spec, "zones"),
		    &it, true)) != NULL) {
			zo = ucl_object_typed_new(UCL_OBJECT);
			put_str(zo, "name", ucl_object_tostring(ucl_object_lookup(z,
			    "name")));
			ucl_object_insert_key(zo, words_json(w, z, "clients"),
			    "clients", 0, false);
			ucl_object_insert_key(zo, words_json(w, z, "interfaces"),
			    "interfaces", 0, false);
			ucl_array_append(zs, zo);
		}
		ucl_object_insert_key(o, zs, "zone", 0, false);
		ucl_object_insert_key(top, o, "bound", 0, false);
	}
	ucl_object_unref(spec);
}

static void
rules_json(struct work *w, ucl_object_t *top)
{
	ucl_object_t	*arr, *o;
	struct krule	*k;
	const char	*file, *p, *e;
	size_t		 nk, i;
	bool		 any;
	int		 n;

	file = dir_file(w, "fwd.rules");
	put_str(top, "rules_file", file);
	n = 0;
	if ((p = scope_slurp(w, file, NULL)) != NULL)
		for (; *p != '\0'; p++)
			n += *p == '\n';
	ucl_object_insert_key(top, ucl_object_fromint(n), "rules_expected", 0,
	    false);
	if (kernel_rules(w, &k, &nk) != 0) {
		put_str(top, "rules_error", "ipfw cannot be read (ipfw(4) not "
		    "loaded?)");
		return;
	}
	if ((e = kernel_free(w, k, nk, &any)) != NULL)
		put_str(top, "rules_error", e);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < nk; i++) {
		if (k[i].set != FW_SET || !k[i].ours)
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromint(k[i].num), "number",
		    0, false);
		ucl_object_insert_key(o, ucl_object_fromint(k[i].set), "set", 0,
		    false);
		put_str(o, "text", k[i].text);
		ucl_array_append(arr, o);
	}
	ucl_object_insert_key(top, arr, "rules", 0, false);
}

void
do_sslproxy(struct work *w, struct json_rsp *rsp)
{
	ucl_object_t	*top;
	struct stat	 sb;
	const char	*conf, *log, *spec;
	char		*json;

	rsp->has_ok = true;
	rsp->ok = false;
	top = ucl_object_typed_new(UCL_OBJECT);
	put_bool(top, "installed", installed(w));
	if (installed(w))
		put_str(top, "version", version(w));
	put_bool(top, "enabled", yes(rc_get(w, SERVICE "_enable")));
	put_bool(top, "running", running(w));
	put_str(top, "conf_path", opts.sslproxy_conf);
	if ((conf = scope_slurp(w, opts.sslproxy_conf, NULL)) != NULL) {
		put_bool(top, "ours", strncmp(conf, MARK, strlen(MARK)) == 0);
		put_str(top, "conf", conf);
		/* The connect log the file names. */
		if ((log = strstr(conf, "\nConnectLog ")) != NULL) {
			log += strlen("\nConnectLog ");
			log = wfmt(w, "%.*s", (int)strcspn(log, " \t\r\n"), log);
			put_str(top, "connect_log", log);
			if (stat(log, &sb) == 0)
				ucl_object_insert_key(top, ucl_object_fromint(
				    sb.st_size), "connect_log_size", 0, false);
		}
	} else
		put_bool(top, "ours", false);
	put_str(top, "spec", (spec = scope_slurp(w, dir_file(w, "spec.json"),
	    NULL)));
	bound_json(w, top, spec);
	ca_json(w, top);
	rules_json(w, top);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL) {
		rsp->error = "out of memory";
		return;
	}
	rsp->json = wstrdup(w, json);
	free(json);
	rsp->ok = true;
}

/* ---- The job ----------------------------------------------------- */

const char *
sslproxy_check(const struct arc_job_spec *sp)
{
	static _Thread_local char	 errbuf[300];
	struct work			 cw;
	struct form			 f;
	ucl_object_t			*o;
	const char			*e;

	if (sp->jail != NULL && sp->jail[0] != '\0')
		return ("SSL inspection is the host's: no jail");
	if (sp->safe)
		return ("SSL inspection is not undone: not in safe mode");
	if (sp->verb == NULL)
		return ("an sslproxy job has a verb: conf, enable, disable, "
		    "start, stop, restart");
	if (strcmp(sp->verb, "conf") == 0) {
		if (sp->names.n != 0 || (o = spec_of(sp->text)) == NULL)
			return ("conf takes the form as JSON, an object, 64 KB "
			    "at most");
		work_init(&cw);
		e = form_of(&cw, o, &f);
		if (e != NULL) {
			snprintf(errbuf, sizeof(errbuf), "%s", e);
			e = errbuf;
		}
		work_free(&cw);
		ucl_object_unref(o);
		return (e);
	}
	if (strcmp(sp->verb, "enable") == 0 || strcmp(sp->verb, "disable") ==
	    0 || strcmp(sp->verb, "start") == 0 || strcmp(sp->verb, "stop") ==
	    0 || strcmp(sp->verb, "restart") == 0)
		return (sp->names.n == 0 && sp->text == NULL ? NULL : "enable, "
		    "disable, start, stop and restart take nothing more");
	return ("an sslproxy job is conf, enable, disable, start, stop or "
	    "restart");
}

char *
sslproxy_title(const struct arc_job_spec *sp)
{
	char	*t;

	if (asprintf(&t, "SSL inspection: %s", sp->verb) == -1)
		return (NULL);
	return (t);
}

/* The rendered file checked by sslproxy -Q, then put in its place. */
static int
conf_put(struct work *w, const char *conf, const char **errp)
{
	struct execres	 res;
	const char	*path, *base;
	char		*argv[5];
	int		 step;

	path = wfmt(w, "%s.arcana-new", opts.sslproxy_conf);
	if (scope_replace(w, path, conf, strlen(conf), 0644, NULL) != 0) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		return (-1);
	}
	step = step_begin(w, STEP_EXEC, "sslproxy -Q", "the configuration "
	    "checked");
	argv[0] = (char *)(uintptr_t)bin(w);
	argv[1] = (char *)(uintptr_t)"-Q";
	argv[2] = (char *)(uintptr_t)"-f";
	argv[3] = (char *)(uintptr_t)path;
	argv[4] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		(void)scope_unlink(w, path);
		*errp = wfmt(w, "sslproxy does not take it: %s", exec_error(w,
		    &res, "sslproxy -Q"));
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	step_end(w, step, true, NULL);
	base = strrchr(opts.sslproxy_conf, '/') != NULL ?
	    strrchr(opts.sslproxy_conf, '/') + 1 : opts.sslproxy_conf;
	if (scope_replace(w, opts.sslproxy_conf, conf, strlen(conf), 0644,
	    wfmt(w, "%s.arcana-old", base)) != 0) {
		*errp = wfmt(w, "%s: %s", opts.sslproxy_conf, strerror(errno));
		(void)scope_unlink(w, path);
		return (-1);
	}
	(void)scope_unlink(w, path);
	return (0);
}

/* The rc script's variables where the agent's files are not its
 * defaults (a test's, or an agent told otherwise). */
static int
vars_set(struct work *w, const struct form *f, const char **errp)
{
	const char	*fwd;

	/* A bound form's service's table, rc.subr's setfib; else none. */
	if (f->bound && f->fib > 0) {
		if (rc_set(w, SERVICE "_fib", "=", wfmt(w, "%d", f->fib), errp)
		    != 0)
			return (-1);
	} else if (rc_get(w, SERVICE "_fib") != NULL)
		rc_unset(w, SERVICE "_fib");

	fwd = dir_file(w, "fwd.rules");
	if (strcmp(opts.sslproxy_conf, "/usr/local/etc/sslproxy.conf") != 0 &&
	    rc_set(w, SERVICE "_config", "=", opts.sslproxy_conf, errp) != 0)
		return (-1);
	if (strcmp(fwd, "/usr/local/etc/sslproxy/arcana/fwd.rules") != 0 &&
	    rc_set(w, SERVICE "_fwd", "=", fwd, errp) != 0)
		return (-1);
	return (0);
}

static int
conf_job(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct form	 f;
	ucl_object_t	*o;
	const char	*conf, *rules, *cur;
	char		*text;
	int		 n, rc;

	if ((o = spec_of(sp->text)) == NULL) {
		*errp = "conf takes the form as JSON";
		return (-1);
	}
	rc = -1;
	if ((*errp = form_of(w, o, &f)) != NULL)
		goto out;
	if (access(dir_file(w, "ca.crt"), F_OK) != 0 || access(dir_file(w,
	    "ca.key"), F_OK) != 0) {
		*errp = "the edge's CA is not installed: issue it from the "
		    "fleet's root first (SSL inspection, the CA)";
		goto out;
	}
	if ((conf = conf_render(w, &f)) == NULL || (rules = rules_render(w,
	    &f, &n)) == NULL) {
		*errp = "out of memory";
		goto out;
	}
	/* The admin's own file is not replaced by the form unless that is
	 * asked for (force). */
	if ((cur = scope_slurp(w, opts.sslproxy_conf, NULL)) != NULL &&
	    strncmp(cur, MARK, strlen(MARK)) != 0 && !sp->force) {
		*errp = wfmt(w, "%s is not Arcana's (its form did not write it): "
		    "its own lines would be replaced; replace it with the form on "
		    "purpose", opts.sslproxy_conf);
		goto out;
	}
	if (dir_make(w, errp) != 0 || conf_put(w, conf, errp) != 0)
		goto out;
	if (scope_replace(w, dir_file(w, "fwd.rules"), rules, strlen(rules),
	    0600, NULL) != 0) {
		*errp = wfmt(w, "%s: %s", dir_file(w, "fwd.rules"),
		    strerror(errno));
		goto out;
	}
	text = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
	if (text != NULL) {
		(void)scope_replace(w, dir_file(w, "spec.json"), text,
		    strlen(text), 0600, NULL);
		free(text);
	}
	if (vars_set(w, &f, errp) != 0)
		goto out;
	/* Taken where it runs: started again, the new rules in. */
	rc = running(w) ? start(w, true, errp) : 0;
out:
	ucl_object_unref(o);
	return (rc);
}

int
do_sslproxy_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{

	if ((*errp = sslproxy_check(sp)) != NULL)
		return (-1);
	if (strcmp(sp->verb, "conf") == 0)
		return (conf_job(w, sp, errp));
	if (strcmp(sp->verb, "enable") == 0)
		return (rc_set(w, SERVICE "_enable", "=", "YES", errp) != 0 ? -1 :
		    start(w, false, errp));
	if (strcmp(sp->verb, "disable") == 0)
		return (stop(w, errp) != 0 ? -1 : rc_set(w, SERVICE "_enable",
		    "=", "NO", errp));
	if (strcmp(sp->verb, "stop") == 0)
		return (stop(w, errp));
	/* start, restart. */
	if (access(opts.sslproxy_conf, F_OK) != 0) {
		*errp = wfmt(w, "%s is not there: save the form first",
		    opts.sslproxy_conf);
		return (-1);
	}
	return (start(w, true, errp));
}
