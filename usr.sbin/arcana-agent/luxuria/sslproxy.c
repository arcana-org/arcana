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
 * "mbsf" the policy: its pass-through hosts as Pass rules (below), the
 * oldest TLS version let through (MinSSLProto), a server's certificate
 * not trusted refused or not (VerifyPeer), and cleartext HTTP blocked by
 * an ipfw reset rule that logs (logdst rtsock), its comment the one the
 * console makes a Security Event Notification of (security <service>
 * <policy> unencrypted).  SSLproxy is then run in the service's table
 * (arcana_sslproxy_fib, rc.subr's setfib); the form is not the tab's.
 *
 * What is never opened (phase 3), the tab's form's or the MBSF's: hosts
 * as SSLproxy's filter rules (Pass to sni; Pass to cn where VerifyPeer
 * checks the certificate), a name exactly and a *.name as its apex
 * exactly and .name* (pass_lines()), which SSLproxy matches as a
 * substring, said where the admin sees it; Arcana's categories where
 * the form names them (cats[], opt-in: the operating systems' updates,
 * services that pin their certificate; no third party's feed), then
 * the admin's; the destinations (prefixes), ports and clients
 * (prefixes, the console's prefix lists among them, written out before
 * they come) by "skipto 8" rules ahead of each zone's fwd, so that
 * SSLproxy never sees them.
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
 *
 * A jail's own SSLproxy, one a jail beside the host's: the jail's
 * sslproxy (pkg -j), its files beneath the jail's root (opened from the
 * root's descriptor, never through a link out of it: invidia/scope.c),
 * the CA's key made for it and written there alone, the rc script
 * copied into the jail's /usr/local/etc/rc.d and run there (service by
 * jexec), its rc.conf the jail's (sysrc -j).  The rules follow its
 * network.  A vnet jail's are its own ipfw's, run in it (jexec): set 27
 * at rule 7 there, staged and refused as the host's, the fwd to its own
 * loopback, loaded by the rc script at the jail's start too.  A jail of
 * the host's network listens at its own address (ip4.addr, ip6.addr;
 * the loopback where it inherits the host's), which the host's ipfw
 * fwds to: a local address, so the connection keeps its destination,
 * which getsockname(2) in the jail says (the accepted socket's local
 * address is the packet's, the jail's own being only where it was
 * looked up), as SSLproxy's NAT engine ipfw asks.  Those rules are the
 * host's set 27 beside the host's own, each comment tagged
 * "@<jail>", rendered by the agent and kept on the host
 * (jails/<jail>.fwd), never read from the jail; while the jail's
 * SSLproxy is started they are jails/<jail>.rules, which the host's set
 * 27 is loaded from (and the host's rc script, and the watch, where the
 * jail runs and its SSLproxy does).  A deny rule of the jail's listen
 * ports keeps clients from reaching SSLproxy at its address but by the
 * fwd.
 */

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
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
#define	PORTS_MAX	16
#define	COMMENT_MAX	80		/* ipfw(8)'s, for a rule's comment */
#define	JAILS		"jails"		/* the host's: jails' rules */
#define	JAIL_RC		"/usr/local/etc/rc.d/" SERVICE	/* in a jail */
#define	FILES_MAX	65		/* set 27's files: the host's, jails' */

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
	int		 tlsmin;		/* tls_names' index, -1 none */
	bool		 verify, plain_block;
	/* Never opened (phase 3): by name, destination, port or client. */
	const char	*pass[PASSES_MAX];	/* the admin's hosts */
	size_t		 npass;
	struct clients	 pdst, pcli;	/* destinations, clients */
	int		 pports[PORTS_MAX];
	size_t		 npports;
	unsigned	 cats;		/* categories', a bit each */
};

/*
 * Arcana's do-not-decrypt categories (docs/notes/ssl-inspection.md,
 * phase 3), opt-in: off unless the form names them, small and fixed,
 * no third party's feed, exact names alone.  SSLproxy 0.10's filter
 * rules match a name exactly or, with a trailing *, any name that
 * contains the rest: no anchored suffix, no regex, so a pattern would
 * pass a name made to contain it (www.bank.evil.example for .bank*)
 * and inspection with it.  The operating systems' update hosts (their
 * payloads signed, their clients often pinning; FreeBSD's in both
 * cases, as a client may send the URL's), and the endpoints of
 * services known to pin their certificate, which inspection breaks
 * rather than sees.  Banks and clinics are no category: an edge cannot
 * name them, the admin does.
 */
static const char *const cat_updates[] = { "pkg.FreeBSD.org",
    "pkg.freebsd.org", "update.FreeBSD.org", "update.freebsd.org",
    "download.FreeBSD.org", "download.freebsd.org",
    "update.microsoft.com", "download.windowsupdate.com",
    "fe3.delivery.mp.microsoft.com", "swscan.apple.com",
    "swdist.apple.com", "swcdn.apple.com", "mesu.apple.com",
    "updates.cdn-apple.com", NULL };
static const char *const cat_pinned[] = { "api.push.apple.com",
    "mtalk.google.com", "chat.signal.org", "storage.signal.org",
    "g.whatsapp.net", NULL };
static const struct {
	const char		*name, *what;
	const char *const	*hosts;
} cats[] = {
	{ "os-updates", "the operating systems' updates", cat_updates },
	{ "pinned", "services that pin their certificate", cat_pinned },
};

/* The categories a list names, a bit each (absent or empty: none);
 * -1 for a word that is not one. */
static int
cats_of(const ucl_object_t *v)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*s;
	unsigned		 bits;
	size_t			 i;

	bits = 0;
	it = NULL;
	while ((e = ucl_object_iterate(v, &it, true)) != NULL) {
		if ((s = ucl_object_tostring(e)) == NULL)
			return (-1);
		for (i = 0; i < nitems(cats); i++)
			if (strcmp(s, cats[i].name) == 0)
				break;
		if (i == nitems(cats))
			return (-1);
		bits |= 1u << i;
	}
	return ((int)bits);
}

/*
 * The hosts of the categories a list names (cats_of()), each once, into
 * out (max of them); how many, or -1 for a word that is no category.
 * Squid's MBSF (sdconf.c) splices them as SSLproxy passes them.
 */
int
sslproxy_category_hosts(const ucl_object_t *v, const char **out, size_t max)
{
	size_t	i, j, n;
	int	bits;

	if ((bits = cats_of(v)) < 0)
		return (-1);
	n = 0;
	for (i = 0; i < nitems(cats); i++)
		for (j = 0; (bits & (1 << i)) != 0 && cats[i].hosts[j] != NULL;
		    j++)
			if (n < max)
				out[n++] = cats[i].hosts[j];
	return ((int)n);
}

/* SSLproxy's names of the versions, MEF 138's order (Table 9). */
static const char *const tls_mef[] = { "ssl3", "tls1.0", "tls1.1",
    "tls1.2", "tls1.3" };
static const char *const tls_names[] = { "ssl3", "tls10", "tls11",
    "tls12", "tls13" };

/*
 * Where SSLproxy runs: the host, a vnet jail (its own ipfw and
 * loopback) or a jail of the host's network (the host's ipfw, the
 * jail's address); the address it listens at, of each family, NULL
 * where the jail has none.
 */
struct place {
	bool		 jailed, vnet;
	const char	*a4, *a6;
};

/* The work's scope, kept while w works on the host. */
struct was {
	const char	*jail, *jroot;
	int		 jid;
};

static void
to_host(struct work *w, struct was *s)
{

	s->jail = w->jail;
	s->jroot = w->jroot;
	s->jid = w->jid;
	w->jail = NULL;
	w->jroot = NULL;
	w->jid = 0;
}

static void
back_to(struct work *w, const struct was *s)
{

	w->jail = s->jail;
	w->jroot = s->jroot;
	w->jid = s->jid;
}

/* A parameter of the jail named, as jailparam_export(3) says it; NULL
 * where it has none (a kernel without INET6 has no ip6.addr). */
static const char *
jail_param(struct work *w, const char *jail, const char *name)
{
	struct jailparam	 jp[2];
	const char		*v;
	char			*s;

	memset(jp, 0, sizeof(jp));
	v = NULL;
	if (jailparam_init(&jp[0], "name") == 0 && jailparam_import(&jp[0],
	    jail) == 0 && jailparam_init(&jp[1], name) == 0 &&
	    jailparam_get(jp, 2, 0) >= 0 && (s = jailparam_export(&jp[1])) !=
	    NULL) {
		v = wstrdup(w, s);
		free(s);
	}
	jailparam_free(jp, 2);
	return (v);
}

/* The first address of a jail's list of one family, or NULL. */
static const char *
first_addr(struct work *w, const char *jail, const char *param,
    const char *mode, const char *loopback)
{
	const char	*v;

	if ((v = jail_param(w, jail, param)) != NULL && v[0] != '\0')
		return (wstrndup(w, v, strcspn(v, ", ")));
	/* None of its own: the host's, the loopback among them. */
	if ((v = jail_param(w, jail, mode)) != NULL && strcmp(v, "inherit") ==
	    0)
		return (loopback);
	return (NULL);
}

/* The place of w's scope; 0, or -1 with why where the jail is gone. */
static int
place_of(struct work *w, struct place *pl, const char **errp)
{
	struct jinfo	ji;

	memset(pl, 0, sizeof(*pl));
	pl->a4 = "127.0.0.1";
	pl->a6 = "::1";
	if (w->jail == NULL)
		return (0);
	pl->jailed = true;
	if (jail_named(w, w->jail, &ji) < 0) {
		*errp = wfmt(w, "the jail %s is not running", w->jail);
		return (-1);
	}
	if ((pl->vnet = ji.vnet))
		return (0);
	pl->a4 = first_addr(w, w->jail, "ip4.addr", "ip4", "127.0.0.1");
	pl->a6 = first_addr(w, w->jail, "ip6.addr", "ip6", "::1");
	return (0);
}

/* sslproxy(1): the host's (or the tools directory's), or the jail's
 * own, run there. */
static const char *
bin(struct work *w)
{
	const char	*p;

	if (w->jail != NULL)
		return (opts.sslproxy_bin);
	return ((p = tool(w, "sslproxy")) != NULL ? p : opts.sslproxy_bin);
}

static const char *
dir_file(struct work *w, const char *name)
{

	return (wfmt(w, "%s/%s", opts.sslproxy_dir, name));
}

/* A jail's file of the host's (jails/<jail><ext>), by its name. */
static const char *
jail_file(struct work *w, const char *jail, const char *ext)
{

	return (wfmt(w, "%s/" JAILS "/%s%s", opts.sslproxy_dir, jail, ext));
}

/* Whether a file is there, of the host or beneath w's jail's root, a
 * link not followed. */
static bool
there(struct work *w, const char *path)
{
	struct stat	 sb;
	const char	*base;
	int		 dfd, rc;

	if ((dfd = scope_open_dir(w, path, &base)) == -1)
		return (false);
	rc = fstatat(dfd, base, &sb, AT_SYMLINK_NOFOLLOW);
	close(dfd);
	return (rc == 0);
}

/* A file's size, as there() finds it; -1 for none. */
static off_t
size_of(struct work *w, const char *path)
{
	struct stat	 sb;
	const char	*base;
	int		 dfd, rc;

	if ((dfd = scope_open_dir(w, path, &base)) == -1)
		return (-1);
	rc = fstatat(dfd, base, &sb, AT_SYMLINK_NOFOLLOW);
	close(dfd);
	return (rc == 0 && S_ISREG(sb.st_mode) ? sb.st_size : -1);
}

/* Whether a program is there to run, beneath w's jail's root alone. */
static bool
runnable(struct work *w, const char *path)
{
	const char	*base;
	int		 dfd, rc;

	if (w->jail == NULL)
		return (access(path, X_OK) == 0);
	if ((dfd = scope_open_dir(w, path, &base)) == -1)
		return (false);
	rc = faccessat(dfd, base, X_OK, AT_RESOLVE_BENEATH);
	close(dfd);
	return (rc == 0);
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

/* The names of what is never opened, the tab's and an MBSF's. */
static const char *const pass_tab[] = { "pass", "pass_destinations",
    "pass_ports", "pass_clients", "pass_categories" };
static const char *const pass_mbsf[] = { "pass-through", "pass-destinations",
    "pass-ports", "pass-clients", "pass-categories" };

/* A port, a number or its digits; -1 for anything else. */
static int
port_of(const ucl_object_t *e)
{
	const char	*s;

	if (ucl_object_type(e) == UCL_INT)
		return (ucl_object_toint(e) > 0 && ucl_object_toint(e) < 65536 ?
		    (int)ucl_object_toint(e) : -1);
	if (ucl_object_type(e) != UCL_STRING || (s = ucl_object_tostring(e))[0]
	    == '\0' || strlen(s) > 5 || strspn(s, "0123456789") != strlen(s) ||
	    strtol(s, NULL, 10) < 1 || strtol(s, NULL, 10) > 65535)
		return (-1);
	return ((int)strtol(s, NULL, 10));
}

/*
 * What is never opened (phase 3), of the tab's form or of a bound
 * form's MBSF (o): hosts by the TLS name and the certificate's CN,
 * destinations (prefixes) and ports, clients by prefix (the console's
 * prefix lists among them, written out by the console or the page),
 * and Arcana's categories (opt-in).  Hosts are names, or *.name for a
 * domain and the names beneath it, which SSLproxy can only match as a
 * substring (pass_lines()); a * alone (every site) or anywhere else is
 * refused.  NULL, or what is wrong.
 */
static const char *
pass_of(struct work *w, const ucl_object_t *o, struct form *f,
    const char *what, bool mbsf)
{
	const char *const	*k = mbsf ? pass_mbsf : pass_tab;
	const ucl_object_t	*v, *e;
	ucl_object_iter_t	 it;
	const char		**hs, *err;
	size_t			 i, n;
	int			 c, p;

	v = ucl_object_lookup(o, k[0]);
	if (ucl_object_type(v) == UCL_ARRAY && ucl_array_size(v) > PASSES_MAX)
		return (wfmt(w, "%s%s: 64 hosts at most", what, k[0]));
	hs = words_of(w, o, k[0], &n);
	if (n > PASSES_MAX)
		return (wfmt(w, "%s%s: 64 hosts at most", what, k[0]));
	for (i = 0; i < n; i++) {
		if (strcmp(hs[i], "*") == 0)
			return (wfmt(w, "%s%s: a * alone would pass every site: "
			    "turn inspection off instead", what, k[0]));
		if (!host_ok(hs[i]))
			return (wfmt(w, "%s%s: %s is not a host", what, k[0],
			    wvis(w, hs[i])));
		f->pass[f->npass++] = hs[i];
	}
	if ((err = clients_of(w, o, k[1], f, &f->pdst, what)) != NULL ||
	    (err = clients_of(w, o, k[3], f, &f->pcli, what)) != NULL)
		return (err);
	v = ucl_object_lookup(o, k[2]);
	if (v != NULL && ucl_object_type(v) != UCL_ARRAY)
		return (wfmt(w, "%s%s: a list of ports", what, k[2]));
	it = NULL;
	while ((e = ucl_object_iterate(v, &it, true)) != NULL) {
		if (f->npports == PORTS_MAX)
			return (wfmt(w, "%s%s: 16 ports at most", what, k[2]));
		if ((p = port_of(e)) < 1)
			return (wfmt(w, "%s%s: %s is not a port", what, k[2],
			    wvis(w, ucl_object_tostring_forced(e))));
		f->pports[f->npports++] = p;
	}
	v = ucl_object_lookup(o, k[4]);
	if ((v != NULL && ucl_object_type(v) != UCL_ARRAY) || (c = cats_of(v))
	    < 0)
		return (wfmt(w, "%s%s: of os-updates and pinned", what,
		    k[4]));
	f->cats = (unsigned)c;
	return (NULL);
}

/*
 * The MBSF of a bound form (MEF 138 Table 9): the oldest version let
 * through, above every one blocked and those on no list where its
 * No-match blocks; a server's certificate not trusted, and cleartext
 * HTTP, each allowed or blocked; what it never opens (pass_of()).
 */
static const char *
mbsf_of(struct work *w, const ucl_object_t *m, struct form *f)
{
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
	return (pass_of(w, m, f, "mbsf: ", true));
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
		if ((err = zone_of(w, o, f, &f->z[0], "", false)) != NULL)
			return (err);
		return (pass_of(w, o, f, "", false));
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
	for (i = 0; i < nitems(pass_tab); i++)
		if (ucl_object_lookup(o, pass_tab[i]) != NULL)
			return ("a bound form's do-not-decrypt list is its MBSF's "
			    "(pass-through, pass-destinations, pass-ports, "
			    "pass-clients, pass-categories)");
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

/* What a place cannot listen at for the form; NULL where it can. */
static const char *
place_refuses(struct work *w, const struct place *pl, const struct form *f)
{

	if (pl->a4 == NULL)
		return (wfmt(w, "the jail %s has no IPv4 address of its own "
		    "(ip4.addr): SSLproxy listens at the jail's address, which "
		    "the host's ipfw fwds the clients to", w->jail));
	if (f->ipv6 && pl->a6 == NULL)
		return (wfmt(w, "the jail %s has no IPv6 address of its own "
		    "(ip6.addr), where SSLproxy would listen for the IPv6 "
		    "clients: give it one, or turn IPv6 off", w->jail));
	return (NULL);
}

/*
 * A host never opened: SSLproxy's filter rules (FilterRule's one-line
 * form), by SNI, and by the certificate's CN where the peer's
 * certificate is verified (cn): else the CN is the server's to choose,
 * a way past inspection.  A name exactly; a *.name as its apex exactly
 * and .name*, which SSLproxy 0.10 matches as a substring (a trailing *;
 * a leading one is no pattern, and there is no suffix match): the
 * names beneath it, and any name containing .name too
 * (www.example.org.attacker.example), the leading dot keeping
 * evilexample.org out.
 */
static void
pass_lines(FILE *fp, const char *h, bool cn)
{
	const char	*apex;

	apex = strncmp(h, "*.", 2) == 0 ? h + 2 : NULL;
	fprintf(fp, "Pass to sni %s\n", apex != NULL ? apex : h);
	if (apex != NULL)
		fprintf(fp, "Pass to sni .%s*\n", apex);
	if (!cn)
		return;
	fprintf(fp, "Pass to cn %s\n", apex != NULL ? apex : h);
	if (apex != NULL)
		fprintf(fp, "Pass to cn .%s*\n", apex);
}

/* sslproxy.conf(5), from the form. */
static char *
conf_render(struct work *w, const struct form *f, const struct place *pl)
{
	char	*out;
	size_t	 len, i, j;
	bool	 cn;
	FILE	*fp;

	out = NULL;
	if ((fp = open_memstream(&out, &len)) == NULL)
		return (NULL);
	fprintf(fp, MARK " from the SSL inspection form (Security,\n"
	    "# SSL inspection): a change here is replaced at its next save.\n");
	if (pl->jailed && !pl->vnet)
		fprintf(fp, "# The clients' traffic comes by the host's ipfw fwd "
		    "rules, to %s.\n", pl->a4);
	else
		fprintf(fp, "# The clients' traffic comes by ipfw fwd rules "
		    "(%s).\n", dir_file(w, "fwd.rules"));
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
	/* Never opened, by name: the TLS name, and the server
	 * certificate's CN (a client without SNI) where VerifyPeer checks
	 * it; Arcana's categories named, then the admin's hosts, a *.name
	 * one said to be a substring; the destinations, ports and clients
	 * by the fwd rules, which skip them. */
	cn = !f->bound || f->verify;
	if (f->cats != 0 || f->npass > 0)
		fprintf(fp, "# Never opened (filter rules, Pass): by the TLS "
		    "name%s.\n", cn ? " and the verified certificate's "
		    "CN" : " alone (VerifyPeer no: a CN is the server's to say)");
	for (i = 0; i < nitems(cats); i++) {
		if ((f->cats & (1u << i)) == 0)
			continue;
		fprintf(fp, "# Arcana's category %s: %s\n", cats[i].name,
		    cats[i].what);
		for (j = 0; cats[i].hosts[j] != NULL; j++)
			pass_lines(fp, cats[i].hosts[j], cn);
	}
	if (f->npass > 0)
		fprintf(fp, "# %s\n", f->bound ? "The MBSF's pass-through" :
		    "The form's");
	for (i = 0; i < f->npass; i++) {
		if (strncmp(f->pass[i], "*.", 2) == 0)
			fprintf(fp, "# %s: SSLproxy matches it as a substring: %s "
			    "and its subdomains pass, and so would a name such as "
			    "www.%s.attacker.example; a zone opened by Squid has "
			    "an exact wildcard.\n", f->pass[i], f->pass[i] + 2,
			    f->pass[i] + 2);
		pass_lines(fp, f->pass[i], cn);
	}
	fprintf(fp, "ConnIdleTimeout 120\nExpiredConnCheckPeriod 10\n");
	if (f->connect_log)
		fprintf(fp, "ConnectLog " LOG_DIR "/connect.log\n");
	if (f->content_log)
		fprintf(fp, "ContentLogDir " LOG_DIR "/content\n");
	for (i = 0; i < f->nl; i++) {
		fprintf(fp, "ProxySpec %s %s %d ipfw\n", f->l[i].type, pl->a4,
		    f->l[i].listen);
		if (f->ipv6)
			fprintf(fp, "ProxySpec %s %s %d ipfw\n", f->l[i].type,
			    pl->a6, f->l[i].listen);
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
 * console makes a SEN of while ipfw's 80 characters hold it.  A jail
 * of the host's network: the fwd to its address, each comment's tag
 * followed by @<jail> (the host's set 27 has the host's and the jails'
 * rules), and its listen ports denied but by the fwd.
 */
static char *
rules_render(struct work *w, const struct form *f, const struct place *pl,
    int *np)
{
	const struct zone	*z;
	const char		*src, *cm, *sfx, *to, *lports, *pports;
	char			*out;
	size_t			 len, i, k, zi, nx, pc, pd;
	int			 fam, n;
	bool			 any, famq;
	FILE			*fp;

	out = NULL;
	n = 0;
	/* The ports opened (SSH's relay is not), and those never. */
	lports = pports = "";
	for (i = 0; i < f->nl; i++)
		if (strcmp(f->l[i].type, "tcp") != 0)
			lports = wfmt(w, "%s%s%d", lports, *lports != '\0' ? "," :
			    "", f->l[i].port);
	for (i = 0; i < f->npports; i++)
		pports = wfmt(w, "%s%s%d", pports, i > 0 ? "," : "",
		    f->pports[i]);
	if ((fp = open_memstream(&out, &len)) == NULL)
		return (NULL);
	sfx = pl->jailed && !pl->vnet ? wfmt(w, "@%s", w->jail) : "";
	cm = f->bound ? wfmt(w, "security %s %s unencrypted " TAG "http%s",
	    f->service, f->policy, sfx) : NULL;
	if (cm != NULL && strlen(cm) > COMMENT_MAX)
		cm = wfmt(w, TAG "http%s", sfx);
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
			to = fam == 4 ? pl->a4 : pl->a6;
			for (k = 0; k < z->nifs; k++) {
				/* Never opened: those clients, destinations
				 * and ports skip the fwd (and the reset of
				 * cleartext HTTP where they are its). */
				pc = fam == 4 ? f->pcli.n4 : f->pcli.n6;
				pd = fam == 4 ? f->pdst.n4 : f->pdst.n6;
				if (pc > 0) {
					fprintf(fp, "add %d set %d skipto %d tcp from "
					    "%s to not %s %s in recv %s // " TAG
					    "pass%s\n", FW_RULE, FW_STAGE, FW_RULE +
					    1, sources(w, fam == 4 ? f->pcli.v4 :
					    f->pcli.v6, pc), fam == 4 ? "me" : "me6",
					    lports, z->ifs[k], sfx);
					n++;
				}
				if (pd > 0) {
					fprintf(fp, "add %d set %d skipto %d tcp from "
					    "%s to %s %s in recv %s // " TAG
					    "pass%s\n", FW_RULE, FW_STAGE, FW_RULE +
					    1, src, sources(w, fam == 4 ?
					    f->pdst.v4 : f->pdst.v6, pd), lports,
					    z->ifs[k], sfx);
					n++;
				}
				if (f->npports > 0) {
					fprintf(fp, "add %d set %d skipto %d tcp from "
					    "%s to not %s %s in recv %s%s // " TAG
					    "pass%s\n", FW_RULE, FW_STAGE, FW_RULE +
					    1, src, fam == 4 ? "me" : "me6", pports,
					    z->ifs[k], famq ? (fam == 4 ? " ip4" :
					    " ip6") : "", sfx);
					n++;
				}
				if (nx > 0) {
					fprintf(fp, "add %d set %d skipto %d tcp from "
					    "%s to not %s in recv %s // " TAG
					    "except%s\n", FW_RULE, FW_STAGE, FW_RULE +
					    1, sources(w, fam == 4 ? z->x.v4 :
					    z->x.v6, nx), fam == 4 ? "me" : "me6",
					    z->ifs[k], sfx);
					n++;
				}
				for (i = 0; i < f->nl; i++) {
					fprintf(fp, "add %d set %d fwd %s,%d tcp from "
					    "%s to not %s %d in recv %s%s // " TAG
					    "%s%s\n", FW_RULE, FW_STAGE, to,
					    f->l[i].listen, src, fam == 4 ? "me" :
					    "me6", f->l[i].port, z->ifs[k], famq ?
					    (fam == 4 ? " ip4" : " ip6") : "",
					    f->l[i].proto, sfx);
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
	/* SSLproxy at a jail's address: reached by the fwd alone (a fwd
	 * keeps the packet's destination, which this does not match). */
	for (fam = 4; *sfx != '\0' && fam <= 6; fam += 2) {
		to = fam == 4 ? pl->a4 : pl->a6;
		if ((fam == 6 && !f->ipv6) || strcmp(to, fam == 4 ?
		    "127.0.0.1" : "::1") == 0)
			continue;
		for (i = 0; i < f->nl; i++) {
			fprintf(fp, "add %d set %d deny tcp from any to %s %d in "
			    "// " TAG "direct%s\n", FW_RULE, FW_STAGE, to,
			    f->l[i].listen, sfx);
			n++;
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
	const char	*jail;		/* ours of a jail's ("@<jail>"), or "" */
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
		/* Its comment has the tag: an SEN's starts otherwise.  A
		 * jail's: the tag's word ends in @<jail>. */
		v[n].ours = (c = strstr(line + off, "// ")) != NULL &&
		    (c = strstr(c, TAG)) != NULL;
		v[n].jail = "";
		if (v[n].ours) {
			c = wstrndup(w, c, strcspn(c, " \t"));
			if ((c = strchr(c, '@')) != NULL)
				v[n].jail = c + 1;
		}
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

/*
 * The fwd files loaded into set 27, by set 26, by the ipfw of w's scope
 * (the host's, or a vnet jail's, run there, its files as it sees them);
 * 0, or -1 with why.
 */
static int
rules_load(struct work *w, const char *const *files, size_t nf,
    const char **errp)
{
	struct krule	*k;
	const char	*e;
	size_t		 nk, i;
	bool		 any;
	int		 step, rc;

	if (nf == 0)
		return (0);
	step = step_begin(w, STEP_EXEC, "ipfw fwd", "the fwd rules loaded into "
	    "set " SET(FW_SET) " at rule " SET(FW_RULE) "%s%s", w->jail != NULL ?
	    " of the jail " : "", w->jail != NULL ? w->jail : "");
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
	for (i = 0; i < nf; i++)
		if (ipfw(w, errp, files[i], NULL, NULL, NULL) != 0) {
			(void)ipfw(w, NULL, "-f", "delete", "set",
			    SET(FW_STAGE));
			goto out;
		}
	if (ipfw(w, errp, "set", "swap", SET(FW_STAGE), SET(FW_SET)) != 0) {
		(void)ipfw(w, NULL, "-f", "delete", "set", SET(FW_STAGE));
		goto out;
	}
	(void)ipfw(w, NULL, "set", "enable", SET(FW_SET), NULL);
	(void)ipfw(w, NULL, "-f", "delete", "set", SET(FW_STAGE));
	rc = 0;
	/* A vnet jail's reset of cleartext HTTP logs to its own routing
	 * socket: the record listens there too. */
	if (w->jail != NULL)
		(void)record_jail_sync(w->jail, w->jid, false);
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
	/* A vnet jail's: its routing socket no longer listened on, unless
	 * another of its rules logs there. */
	if (w->jail != NULL)
		(void)record_jail_sync(w->jail, w->jid, true);
	return (0);
}

/* ---- The service ------------------------------------------------- */

/* "service arcana_sslproxy one<verb>", of the host or run in w's jail;
 * 0, or -1 with why when asked. */
static int
svc(struct work *w, const char *verb, const char **errp)
{
	struct execres	 res;
	char		*argv[4];

	argv[0] = (char *)(uintptr_t)opts.service_bin;
	argv[1] = (char *)(uintptr_t)SERVICE;
	argv[2] = wfmt(w, "one%s", verb);
	argv[3] = NULL;
	if ((strcmp(verb, "status") == 0 ? run_read(w, scope_jexec(w, argv),
	    &res) : run_exec(w, scope_jexec(w, argv), &res)) != 0 ||
	    res.status != 0) {
		if (errp != NULL)
			*errp = wtext(w, exec_error(w, &res, wfmt(w, "service "
			    SERVICE " one%s%s%s", verb, w->jail != NULL ?
			    " in the jail " : "", w->jail != NULL ? w->jail :
			    "")));
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

/* A file's lines (its rules), of the work's scope; 0 for none. */
static size_t
lines(struct work *w, const char *path)
{
	const char	*p;
	size_t		 n;

	n = 0;
	if ((p = scope_slurp(w, path, NULL)) != NULL)
		for (; *p != '\0'; p++)
			n += *p == '\n';
	return (n);
}

/*
 * The files of the host's set 27, w on the host: its own SSLproxy's
 * rules (with_host), and the started ones of each jail of the host's
 * network (jails/<jail>.rules) that runs and whose SSLproxy runs, but
 * skip's.  How many into files.
 */
static size_t
host_files(struct work *w, bool with_host, const char *skip,
    const char **files, size_t max)
{
	struct jinfo	 ji;
	struct dirent	*de;
	const char	*path;
	char		*name;
	size_t		 n, l;
	bool		 up;
	DIR		*d;

	n = 0;
	if (with_host && size_of(w, dir_file(w, "fwd.rules")) > 0)
		files[n++] = dir_file(w, "fwd.rules");
	if ((d = opendir(dir_file(w, JAILS))) == NULL)
		return (n);
	while ((de = readdir(d)) != NULL && n < max) {
		l = strlen(de->d_name);
		if (l <= 6 || strcmp(de->d_name + l - 6, ".rules") != 0)
			continue;
		name = wstrndup(w, de->d_name, l - 6);
		path = jail_file(w, name, ".rules");
		if (!valid_jail(name) || (skip != NULL && strcmp(name, skip) ==
		    0) || size_of(w, path) <= 0)
			continue;
		/* Gone, or another network now: not the host's to send to. */
		if (jail_named(w, name, &ji) < 0 || ji.vnet)
			continue;
		w->jail = ji.name;
		w->jid = ji.jid;
		w->jroot = ji.path;
		up = running(w);
		w->jail = w->jroot = NULL;
		w->jid = 0;
		if (up)
			files[n++] = path;
	}
	closedir(d);
	return (n);
}

/* The host's set 27 loaded from host_files(), or taken away where they
 * are none; w on the host.  0, or -1 with why. */
static int
host_load(struct work *w, bool with_host, const char *skip,
    const char **errp)
{
	const char	*files[FILES_MAX];
	size_t		 n;

	if ((n = host_files(w, with_host, skip, files, nitems(files))) == 0)
		return (rules_unload(w, errp));
	return (rules_load(w, files, n, errp));
}

/*
 * The rules where p's are, its own SSLproxy up (its rules in) or not:
 * a vnet jail's in its own ipfw; the host's and a jail's of the host's
 * network in the host's set 27, with the others' there.  0, or -1 with
 * why.
 */
static int
rules_set(struct work *w, const struct place *p, bool up, const char **errp)
{
	struct was	 s;
	const char	*file;
	int		 rc;

	if (p->vnet) {
		file = dir_file(w, "fwd.rules");
		if (!up)
			return (rules_unload(w, errp));
		return (rules_load(w, &file, size_of(w, file) > 0 ? 1 : 0,
		    errp));
	}
	if (!p->jailed)
		return (host_load(w, up, NULL, errp));
	/* A jail's: started, its rules are jails/<jail>.rules, the copy of
	 * what its form made; stopped, none. */
	to_host(w, &s);
	rc = 0;
	if (up) {
		const char	*text;
		size_t		 len;

		if ((text = scope_slurp(w, jail_file(w, s.jail, ".fwd"), &len))
		    == NULL) {
			text = "";
			len = 0;
		}
		if (w->dry)
			(void)work_dry(w, step_begin(w, STEP_FILE, "write",
			    "%s", jail_file(w, s.jail, ".rules")));
		else if (file_replace(jail_file(w, s.jail, ".rules"), text,
		    len, 0600) != 0) {
			*errp = wfmt(w, "%s: %s", jail_file(w, s.jail,
			    ".rules"), strerror(errno));
			rc = -1;
		}
	}
	if (rc == 0)
		rc = host_load(w, running(w), up ? NULL : s.jail, errp);
	if (rc == 0 && !up && !w->dry)
		(void)unlink(jail_file(w, s.jail, ".rules"));
	back_to(w, &s);
	return (rc);
}

/* Started (or started again, unless again is false and it runs),
 * then its rules loaded. */
static int
start(struct work *w, const struct place *p, bool again, const char **errp)
{
	int	rc;

	pthread_mutex_lock(&fw_lock);
	rc = 0;
	if (!running(w))
		rc = svc(w, "start", errp);
	else if (again)
		rc = svc(w, "restart", errp);
	if (rc == 0)
		rc = rules_set(w, p, true, errp);
	pthread_mutex_unlock(&fw_lock);
	return (rc);
}

/* Its rules taken away, then stopped. */
static int
stop(struct work *w, const struct place *p, const char **errp)
{
	int	rc;

	pthread_mutex_lock(&fw_lock);
	if ((rc = rules_set(w, p, false, errp)) == 0 && running(w))
		rc = svc(w, "stop", errp);
	pthread_mutex_unlock(&fw_lock);
	return (rc);
}

/* Said once a change, not every turn: the host's, and the jails'. */
static bool	warned_host, warned_jail;

/*
 * The host's set 27 against what it should hold: the host's rules while
 * its SSLproxy runs, and each started jail's of the host's network
 * while it and its SSLproxy run.  Loaded again where the count differs
 * (ipfw restarted, a jail stopped or started by its own rc), where the
 * sets are free.
 */
static void
watch_host(struct work *w)
{
	const char	*files[FILES_MAX], *e;
	struct krule	*k;
	size_t		 nf, nk, i, want, have;
	bool		 any, mine;
	DIR		*d;

	mine = size_of(w, dir_file(w, "fwd.rules")) > 0;
	if (!mine) {
		/* Nothing of the host's, and no jail's: nothing to ask. */
		if ((d = opendir(dir_file(w, JAILS))) == NULL)
			return;
		closedir(d);
	}
	nf = host_files(w, mine && running(w), NULL, files, nitems(files));
	for (want = 0, i = 0; i < nf; i++)
		want += lines(w, files[i]);
	if (kernel_rules(w, &k, &nk) != 0)
		return;
	for (have = 0, i = 0; i < nk; i++)
		have += k[i].set == FW_SET && k[i].ours;
	if (want == have || kernel_free(w, k, nk, &any) != NULL)
		return;
	if ((nf == 0 ? rules_unload(w, &e) : rules_load(w, files, nf, &e)) ==
	    0) {
		if (have == 0)
			logmsg(LOG_NOTICE, "sslproxy: ipfw set %d held none of "
			    "its fwd rules while SSLproxy runs (ipfw "
			    "restarted?): loaded again", FW_SET);
		else
			logmsg(LOG_NOTICE, "sslproxy: ipfw set %d held %zu of "
			    "SSL inspection's rules, %zu wanted (a jail's "
			    "SSLproxy started or stopped?): loaded again",
			    FW_SET, have, want);
		warned_host = false;
	} else if (!warned_host) {
		logmsg(LOG_WARNING, "sslproxy: the fwd rules not loaded again: "
		    "%s", e);
		warned_host = true;
	}
}

/* Each vnet jail's set 27, in its own ipfw: loaded again where it holds
 * none of the rules of its running SSLproxy (the jail's ipfw restarted). */
static void
watch_vnets(struct work *w)
{
	struct jinfo	*list;
	struct krule	*k;
	const char	*file, *e;
	size_t		 n, j, nk, i;
	bool		 ours, any, logs;

	if (jails_running(w, &list, &n, &e) != 0)
		return;
	for (j = 0; j < n; j++) {
		if (!list[j].vnet || list[j].dying || list[j].path == NULL ||
		    list[j].name == NULL)
			continue;
		w->jail = list[j].name;
		w->jid = list[j].jid;
		w->jroot = list[j].path;
		file = dir_file(w, "fwd.rules");
		if (size_of(w, file) > 0 && kernel_rules(w, &k, &nk) == 0) {
			for (ours = logs = false, i = 0; i < nk; i++) {
				ours |= k[i].set == FW_SET && k[i].ours;
				logs |= k[i].set == FW_SET && strstr(k[i].text,
				    " logdst ") != NULL && strstr(k[i].text,
				    "rtsock") != NULL;
			}
			/* Its reset of cleartext HTTP logged where the
			 * record listens (the jail's rc loaded it). */
			if (logs)
				(void)record_jail_sync(list[j].name,
				    list[j].jid, false);
			if (!ours && kernel_free(w, k, nk, &any) == NULL &&
			    running(w)) {
				if (rules_load(w, &file, 1, &e) == 0) {
					logmsg(LOG_NOTICE, "sslproxy: the jail "
					    "%s's ipfw set %d held none of its "
					    "fwd rules while SSLproxy runs there: "
					    "loaded again", list[j].name, FW_SET);
					warned_jail = false;
				} else if (!warned_jail) {
					logmsg(LOG_WARNING, "sslproxy: the jail "
					    "%s's fwd rules not loaded again: %s",
					    list[j].name, e);
					warned_jail = true;
				}
			}
		}
		w->jail = w->jroot = NULL;
		w->jid = 0;
	}
}

/*
 * Whether the vnet jail jid's kept rules (its fwd.rules, beneath its
 * root) log to its routing socket: a bound MBSF's reset of cleartext
 * HTTP, which the record listens for there (gula/record.c).
 */
bool
sslproxy_jail_rtsock(int jid)
{
	struct work	 w;
	const char	*e;
	char		 name[MAXHOSTNAMELEN], vnet[16], *text;
	bool		 logs;

	if (jail_jid_name(jid, name, sizeof(name), vnet, sizeof(vnet)) != 0 ||
	    strcmp(vnet, "new") != 0)
		return (false);
	work_init(&w);
	e = NULL;
	logs = scope_enter(&w, name, &e) == 0 && (text = scope_slurp(&w,
	    dir_file(&w, "fwd.rules"), NULL)) != NULL && strstr(text,
	    " log logdst rtsock ") != NULL;
	work_free(&w);
	return (logs);
}

/*
 * The watch: the rules loaded again where ipfw(8) lost them (restarted,
 * or flushed) under a running SSLproxy, the host's and its jails', and
 * a jail's taken away from the host's set where it stopped.
 */
static void *
watch(void *arg __unused)
{
	struct work	w;

	for (;;) {
		sleep((unsigned int)opts.sslproxy_watch_s);
		work_init(&w);
		w.nice = true;
		pthread_mutex_lock(&fw_lock);
		watch_host(&w);
		watch_vnets(&w);
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

/* The CA's directory, root's alone (of the host, or beneath the
 * jail's root, a link on the way not followed). */
static int
dir_make(struct work *w, const char **errp)
{
	const char	*base;
	int		 dfd, rc, e;

	rc = -1;
	if (scope_mkdirs(w, opts.sslproxy_dir) == 0 && (dfd = scope_open_dir(w,
	    opts.sslproxy_dir, &base)) != -1) {
		rc = fchmodat(dfd, base, 0700, AT_SYMLINK_NOFOLLOW);
		e = errno;
		close(dfd);
		errno = e;
	}
	if (rc != 0) {
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
	if (renew || (!there(w, kpath) && !there(w, dir_file(w, "ca.key")))) {
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
	} else if ((key = key_read(w, there(w, kpath) ? kpath :
	    dir_file(w, "ca.key"))) == NULL) {
		*errp = "the edge's CA key cannot be read";
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	if (gethostname(host, sizeof(host)) != 0)
		snprintf(host, sizeof(host), "edge");
	/* A jail's: its own request, named for the edge and the jail. */
	cn = w->jail != NULL ? wfmt(w, "Arcana SSL inspection on %.*s/%.*s",
	    20, host, 16, w->jail) : wfmt(w, "Arcana SSL inspection on %.*s",
	    32, host);
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
	waits = there(w, next);
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
	else if (waits && scope_rename(w, next, "ca.key.next", "ca.key") != 0)
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

	return (runnable(w, bin(w)));
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
	if (run_read(w, scope_jexec(w, argv), &res) != 0)
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
	put_bool(ca, "key", there(w, dir_file(w, "ca.key")));
	put_bool(ca, "pending", there(w, dir_file(w, "ca.key.next")));
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

/*
 * The rules of the place's SSLproxy as its ipfw has them: the host's
 * set 27's own (no jail's tag), a vnet jail's set 27 in its ipfw, or
 * the host's of a jail of its network (tagged @<jail>), its file the
 * host's copy.
 */
static void
rules_json(struct work *w, ucl_object_t *top, const struct place *pl)
{
	ucl_object_t	*arr, *o;
	struct krule	*k;
	struct was	 s;
	const char	*file, *e, *jail;
	size_t		 nk, i;
	bool		 any, host;

	host = pl->jailed && !pl->vnet;
	jail = host ? w->jail : "";
	if (host)
		to_host(w, &s);
	file = host ? jail_file(w, jail, ".fwd") : dir_file(w, "fwd.rules");
	put_str(top, "rules_file", file);
	ucl_object_insert_key(top, ucl_object_fromint((int64_t)lines(w, file)),
	    "rules_expected", 0, false);
	if (kernel_rules(w, &k, &nk) != 0) {
		put_str(top, "rules_error", "ipfw cannot be read (ipfw(4) not "
		    "loaded?)");
		goto out;
	}
	if ((e = kernel_free(w, k, nk, &any)) != NULL)
		put_str(top, "rules_error", e);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < nk; i++) {
		if (k[i].set != FW_SET || !k[i].ours || (!pl->vnet &&
		    strcmp(k[i].jail, jail) != 0))
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
out:
	if (host)
		back_to(w, &s);
}

/*
 * net.inet6.ip6.redirect of the network whose ipfw has the fwd rules:
 * the host's, or a vnet jail's own.  With 0, forwarded IPv6 takes
 * ip6_tryforward(), where a kernel before FreeBSD main fb9969ca61ca
 * loses an fwd rule's next hop: the console says so beside the rules.
 */
static void
redirect_json(struct work *w, ucl_object_t *top, const struct place *pl)
{
	struct was	 s;
	long		 r;
	bool		 host;

	host = pl->jailed && !pl->vnet;
	if (host)
		to_host(w, &s);
	r = sysctl_int_here(w, "net.inet6.ip6.redirect");
	if (host)
		back_to(w, &s);
	if (r >= 0)
		put_bool(top, "ip6_redirect", r != 0);
}

void
do_sslproxy(struct work *w, struct json_rsp *rsp)
{
	ucl_object_t	*top;
	struct place	 pl;
	const char	*conf, *log, *spec, *e;
	char		*json;
	off_t		 size;

	rsp->has_ok = true;
	rsp->ok = false;
	if (place_of(w, &pl, &e) != 0) {
		rsp->error = e;
		return;
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	if (pl.jailed) {
		put_str(top, "jail", w->jail);
		put_bool(top, "vnet", pl.vnet);
	}
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
			if ((size = size_of(w, log)) >= 0)
				ucl_object_insert_key(top, ucl_object_fromint(
				    size), "connect_log_size", 0, false);
		}
	} else
		put_bool(top, "ours", false);
	put_str(top, "spec", (spec = scope_slurp(w, dir_file(w, "spec.json"),
	    NULL)));
	bound_json(w, top, spec);
	ca_json(w, top);
	rules_json(w, top, &pl);
	redirect_json(w, top, &pl);
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

	if (sp->jail != NULL && sp->jail[0] != '\0' && !valid_jail(sp->jail))
		return ("invalid jail name");
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

	if (asprintf(&t, "SSL inspection: %s%s%s", sp->verb, sp->jail != NULL &&
	    sp->jail[0] != '\0' ? " in the jail " : "", sp->jail != NULL ?
	    sp->jail : "") == -1)
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
	if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
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

/*
 * Arcana's rc script in the jail w works in, as the host has it: the
 * port has none, and the jail's service(8) runs what its own rc.d
 * holds.  Written beneath the jail's root (never through a link) where
 * it is not there as the host's.  0, or -1 with why.
 */
static int
script_put(struct work *w, const char **errp)
{
	struct was	 s;
	const char	*text, *cur;
	char		*dirs, *p, *d;
	size_t		 len;

	if (w->jail == NULL)
		return (0);
	to_host(w, &s);
	text = NULL;
	dirs = wstrdup(w, opts.rc_dirs);
	for (p = dirs; text == NULL && (d = strsep(&p, ":")) != NULL; )
		if (*d != '\0')
			text = scope_slurp(w, wfmt(w, "%s/" SERVICE, d), &len);
	back_to(w, &s);
	if (text == NULL) {
		*errp = wfmt(w, "Arcana's rc script " SERVICE " is not on the "
		    "host (%s): it is what the jail is given to run SSLproxy "
		    "by", opts.rc_dirs);
		return (-1);
	}
	if ((cur = scope_slurp(w, JAIL_RC, NULL)) != NULL && strcmp(cur, text)
	    == 0)
		return (0);
	/* A dry run's: the write said, not done. */
	if (w->dry) {
		(void)work_dry(w, step_begin(w, STEP_FILE, "write", JAIL_RC
		    " in the jail %s", w->jail));
		return (0);
	}
	if (scope_mkdirs(w, "/usr/local/etc/rc.d") != 0 || scope_replace(w,
	    JAIL_RC, text, len, 0555, NULL) != 0) {
		*errp = wfmt(w, JAIL_RC " in the jail %s: %s", w->jail,
		    strerror(errno));
		return (-1);
	}
	return (0);
}

/* The rc script's variables where the agent's files are not its
 * defaults (a test's, or an agent told otherwise); a jail of the host's
 * network loads no rules itself (the host's ipfw has them). */
static int
vars_set(struct work *w, const struct form *f, const struct place *pl,
    const char **errp)
{
	const char	*fwd;

	/* A bound form's service's table, rc.subr's setfib; else none. */
	if (f->bound && f->fib > 0) {
		if (rc_set(w, SERVICE "_fib", "=", wfmt(w, "%d", f->fib), errp)
		    != 0)
			return (-1);
	} else if (rc_get(w, SERVICE "_fib") != NULL)
		rc_unset(w, SERVICE "_fib");

	fwd = pl->jailed && !pl->vnet ? "" : dir_file(w, "fwd.rules");
	if (strcmp(opts.sslproxy_conf, "/usr/local/etc/sslproxy.conf") != 0 &&
	    rc_set(w, SERVICE "_config", "=", opts.sslproxy_conf, errp) != 0)
		return (-1);
	if (strcmp(fwd, "/usr/local/etc/sslproxy/arcana/fwd.rules") != 0 &&
	    rc_set(w, SERVICE "_fwd", "=", fwd, errp) != 0)
		return (-1);
	return (0);
}

/*
 * The rules a form makes, where they are kept: the host's and a vnet
 * jail's beside the CA (fwd.rules, which its own ipfw and rc script
 * load), a jail's of the host's network the host's own (jails/<jail>.fwd:
 * never read from the jail, whose root may write there what it likes).
 */
static int
rules_put(struct work *w, const struct place *pl, const char *rules,
    const char **errp)
{
	struct was	 s;
	const char	*path;
	int		 rc;

	if (!pl->jailed || pl->vnet) {
		path = dir_file(w, "fwd.rules");
		if (scope_replace(w, path, rules, strlen(rules), 0600, NULL) !=
		    0) {
			*errp = wfmt(w, "%s: %s", path, strerror(errno));
			return (-1);
		}
		return (0);
	}
	to_host(w, &s);
	path = jail_file(w, s.jail, ".fwd");
	rc = 0;
	if (dir_make(w, errp) != 0)
		rc = -1;
	else if (mkdir(dir_file(w, JAILS), 0700) != 0 && errno != EEXIST) {
		*errp = wfmt(w, "%s: %s", dir_file(w, JAILS), strerror(errno));
		rc = -1;
	} else if (file_replace(path, rules, strlen(rules), 0600) != 0) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		rc = -1;
	}
	back_to(w, &s);
	/* A file of the jail's own would be loaded by nothing. */
	if (rc == 0 && there(w, dir_file(w, "fwd.rules")))
		(void)scope_unlink(w, dir_file(w, "fwd.rules"));
	return (rc);
}

static int
conf_job(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct form	 f;
	struct place	 pl;
	ucl_object_t	*o;
	const char	*conf, *rules, *cur;
	char		*text;
	int		 n, rc;

	if (place_of(w, &pl, errp) != 0)
		return (-1);
	if ((o = spec_of(sp->text)) == NULL) {
		*errp = "conf takes the form as JSON";
		return (-1);
	}
	rc = -1;
	if ((*errp = form_of(w, o, &f)) != NULL ||
	    (*errp = place_refuses(w, &pl, &f)) != NULL)
		goto out;
	if (!there(w, dir_file(w, "ca.crt")) || !there(w, dir_file(w,
	    "ca.key"))) {
		*errp = "the edge's CA is not installed: issue it from the "
		    "fleet's root first (SSL inspection, the CA)";
		goto out;
	}
	if ((conf = conf_render(w, &f, &pl)) == NULL || (rules = rules_render(w,
	    &f, &pl, &n)) == NULL) {
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
	if (script_put(w, errp) != 0 || dir_make(w, errp) != 0 ||
	    conf_put(w, conf, errp) != 0 || rules_put(w, &pl, rules, errp) != 0)
		goto out;
	text = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
	if (text != NULL) {
		(void)scope_replace(w, dir_file(w, "spec.json"), text,
		    strlen(text), 0600, NULL);
		free(text);
	}
	if (vars_set(w, &f, &pl, errp) != 0)
		goto out;
	/* Taken where it runs: started again, the new rules in. */
	rc = running(w) ? start(w, &pl, true, errp) : 0;
out:
	ucl_object_unref(o);
	return (rc);
}

int
do_sslproxy_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	struct place	pl;

	if ((*errp = sslproxy_check(sp)) != NULL)
		return (-1);
	if (place_of(w, &pl, errp) != 0)
		return (-1);
	if (strcmp(sp->verb, "conf") == 0)
		return (conf_job(w, sp, errp));
	if (strcmp(sp->verb, "disable") == 0)
		return (stop(w, &pl, errp) != 0 ? -1 : rc_set(w, SERVICE
		    "_enable", "=", "NO", errp));
	if (strcmp(sp->verb, "stop") == 0)
		return (stop(w, &pl, errp));
	/* A jail's runs Arcana's rc script, as the host has it now. */
	if (script_put(w, errp) != 0)
		return (-1);
	if (strcmp(sp->verb, "enable") == 0)
		return (rc_set(w, SERVICE "_enable", "=", "YES", errp) != 0 ? -1 :
		    start(w, &pl, false, errp));
	/* start, restart. */
	if (!there(w, opts.sslproxy_conf)) {
		*errp = wfmt(w, "%s is not there: save the form first",
		    opts.sslproxy_conf);
		return (-1);
	}
	return (start(w, &pl, true, errp));
}
