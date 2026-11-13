/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Threat feeds: lists of scanners', spammers' and abusers' prefixes,
 * fetched from the internet by the console, once for the fleet (a host
 * may have no way out), and kept on the hosts chosen as ipfw(8) tables
 * of type addr, IPv4 and IPv6 in one, by arcana-firewall's feed-load:
 * the agent fills a scratch table and swaps it in.  No rule is added:
 * the Firewall page offers one, which the admin keeps or not.
 *
 * The generic work is libipfeeds' (the submodule ipfeeds/, ipfeeds(3)):
 * the presets and formats, a feed fetched over HTTP or HTTPS (verified
 * for the URL's name) conditionally (If-Modified-Since), 16 MB and
 * 250 000 entries at most, in a minute, only from an address of the
 * internet, the one resolved and checked connected to, and so at each
 * redirect (3 at most, none from https to http); each entry made an
 * address or prefix with no host bits, once, those another covers left
 * out.  Arcana's is the policy: which feeds, at which interval (an hour
 * at least; the presets' as their sources ask), what reserved space
 * Settings' feeds_allow_private lets a fetch reach, and what no feed
 * may cut off: dropped, with why, is what is no prefix, the whole
 * address space, what covers the console's own addresses, a host's (the
 * address its servers.json URI names) or a user's last sign-in, and
 * private or reserved space unless the feed lists it on purpose.
 *
 * feeds.json, {"feeds": [...]}, is what the operators keep; the
 * fetches and deliveries, feeds-state.json, and each feed's entries
 * feeds/<id>.json.  The work is a thread's of the worker that takes
 * feeds.lock (and of the cluster's leader alone), asked by
 * feeds-asks.json: a fetch now, or a preview, every host's dry run.  A
 * feed failing FEED_FAILS times raises an alarm, by mail and Telegram
 * as Settings say, and its recovery clears it; an update with other
 * entries is an event of the feed's; one of fewer than half the
 * entries delivered last is held back until an owner or the feed's
 * author takes it anyway (feed_run()).  The same as arcana-console's
 * threat-feeds (cyang.c), its view made of feed_json()'s and its
 * changes through feed_put() and feed_remove(), every protection
 * held.
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#include <ipfeeds.h>

#include "console.h"
#include "ynet.h"

#define	FEEDS_FILE	"feeds.json"
#define	FEEDS_STATE	"feeds-state.json"
#define	FEEDS_ASKS	"feeds-asks.json"
#define	FEEDS_LOCK	"feeds.lock"
#define	FEEDS_RUN	"feeds-run.lock"
#define	SIGNINS_FILE	"signins.json"
#define	FEEDS_MAX	32
#define	FEED_MAX_BYTES	(16 * 1024 * 1024)
#define	FEED_MAX	250000
#define	FEED_FLOOR_H	1		/* hours between fetches, at least */
#define	FEED_FAILS	3		/* fetches failed in a row: an alarm */
#define	FEED_DROPPED	500		/* dropped entries kept, with why */
#define	FEED_EVENTS	30
#define	FEED_TIMEOUT	60		/* s a fetch may take */
#define	FEED_HOST_RETRY	300		/* s before a failed delivery again */
#define	FEEDS_TICK	2		/* s between looks at what is asked */
#define	SIGNINS_MAX	64

#define	S(x)	ucl_object_fromstring(x)
#define	I(x)	ucl_object_fromint(x)
#define	B(x)	ucl_object_frombool(x)

/* An address no feed may cut off, and why. */
struct prot {
	struct ipf_prefix p;
	char		 why[96];
	char		 host[9];	/* the host's whose it is, or "" */
};
#define	PROT_MAX	512

static pthread_mutex_t	run_lock = PTHREAD_MUTEX_INITIALIZER;

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_replace_key(o, v, key, 0, true);
}

static const char *
str(const ucl_object_t *o, const char *key)
{

	return (ucl_str(o, key));
}

static size_t
obj_len(const ucl_object_t *o)
{
	ucl_object_iter_t	 it = NULL;
	size_t			 n = 0;

	while (o != NULL && ucl_object_iterate(o, &it, true) != NULL)
		n++;
	return (n);
}

static int64_t
num(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	return ((v = ucl_object_lookup(o, key)) != NULL ? ucl_object_toint(v) :
	    0);
}

/* ---- What is protected ------------------------------------------- */

static void
prot_add(struct prot *v, size_t *np, int af, const void *addr,
    const char *fmt, ...) __printflike(5, 6);

static void
prot_add(struct prot *v, size_t *np, int af, const void *addr,
    const char *fmt, ...)
{
	va_list	ap;

	if (*np >= PROT_MAX)
		return;
	memset(&v[*np], 0, sizeof(v[*np]));
	v[*np].p.af = af;
	v[*np].p.len = af == AF_INET ? 32 : 128;
	memcpy(v[*np].p.addr, addr, af == AF_INET ? 4 : 16);
	va_start(ap, fmt);
	vsnprintf(v[*np].why, sizeof(v[*np].why), fmt, ap);
	va_end(ap);
	(*np)++;
}

/* A name's or an address's addresses, each protected for why; sid's, a
 * host's, or NULL. */
static void
prot_resolve(struct prot *v, size_t *np, const char *host, const char *why,
    const char *sid)
{
	size_t			 first = *np;
	struct addrinfo	 hints, *res, *ai;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, NULL, &hints, &res) != 0)
		return;
	for (ai = res; ai != NULL; ai = ai->ai_next)
		if (ai->ai_family == AF_INET)
			prot_add(v, np, AF_INET, &((struct sockaddr_in *)(void *)
			    ai->ai_addr)->sin_addr, "%s", why);
		else if (ai->ai_family == AF_INET6)
			prot_add(v, np, AF_INET6, &((struct sockaddr_in6 *)
			    (void *)ai->ai_addr)->sin6_addr, "%s", why);
	freeaddrinfo(res);
	for (; sid != NULL && first < *np; first++)
		snprintf(v[first].host, sizeof(v[first].host), "%s", sid);
}

/*
 * What no feed may cut off: the console's own addresses, each host's
 * (the address its URI names, resolved), each user's last sign-in.
 */
static size_t
protected(struct prot *v)
{
	struct ifaddrs		*ifa, *i;
	struct hostref		 refs[256];
	ucl_object_t		*si;
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;
	char			 host[256], why[96];
	const char		*p, *e;
	size_t			 n;
	int			 k, nr;

	n = 0;
	if (getifaddrs(&ifa) == 0) {
		for (i = ifa; i != NULL; i = i->ifa_next) {
			if (i->ifa_addr == NULL)
				continue;
			if (i->ifa_addr->sa_family == AF_INET)
				prot_add(v, &n, AF_INET, &((struct sockaddr_in *)
				    (void *)i->ifa_addr)->sin_addr, "the "
				    "console's, on %s", i->ifa_name);
			else if (i->ifa_addr->sa_family == AF_INET6)
				prot_add(v, &n, AF_INET6, &((struct sockaddr_in6
				    *)(void *)i->ifa_addr)->sin6_addr, "the "
				    "console's, on %s", i->ifa_name);
		}
		freeifaddrs(ifa);
	}
	nr = host_refs_get(refs, (int)nitems(refs));
	for (k = 0; k < nr; k++) {
		/* tcp://host:port, sctp://[v6]:port. */
		if ((p = strstr(refs[k].uri, "://")) == NULL)
			continue;
		p += 3;
		if (*p == '[') {
			p++;
			e = strchr(p, ']');
		} else
			e = strrchr(p, ':');
		if (e == NULL || (size_t)(e - p) >= sizeof(host))
			continue;
		snprintf(host, sizeof(host), "%.*s", (int)(e - p), p);
		snprintf(why, sizeof(why), "host %s's, which the console "
		    "reaches", refs[k].name);
		prot_resolve(v, &n, host, why, refs[k].id);
	}
	if ((si = store_load(SIGNINS_FILE)) != NULL) {
		it = NULL;
		while ((u = ucl_object_iterate(si, &it, true)) != NULL) {
			if (str(u, "addr") == NULL)
				continue;
			snprintf(why, sizeof(why), "%s's last sign-in",
			    ucl_object_key(u));
			prot_resolve(v, &n, str(u, "addr"), why, NULL);
		}
		ucl_object_unref(si);
	}
	return (n);
}

/* A user signed in from the request's address: kept, for protected(). */
void
feeds_signin(struct http_request *req, const char *user)
{
	ucl_object_t		*si, *o;
	const ucl_object_t	*u, *old;
	ucl_object_iter_t	 it;
	char			 addr[INET6_ADDRSTRLEN + 8];
	struct ipf_prefix	 p;

	if (user == NULL || user[0] == '\0' || web_peer(req, addr,
	    sizeof(addr)) == NULL || ipf_prefix_parse(addr, &p) != 0)
		return;
	if ((si = store_load(SIGNINS_FILE)) == NULL || ucl_object_type(si) !=
	    UCL_OBJECT) {
		if (si != NULL)
			ucl_object_unref(si);
		si = ucl_object_typed_new(UCL_OBJECT);
	}
	if ((u = ucl_object_lookup(si, user)) != NULL && str(u, "addr") !=
	    NULL && strcmp(str(u, "addr"), addr) == 0) {
		ucl_object_unref(si);
		return;
	}
	/* The oldest goes when there are too many. */
	if (ucl_object_lookup(si, user) == NULL && ucl_object_type(si) ==
	    UCL_OBJECT) {
		size_t	 cnt = 0;

		old = NULL;
		it = NULL;
		while ((u = ucl_object_iterate(si, &it, true)) != NULL) {
			cnt++;
			if (old == NULL || num(u, "at") < num(old, "at"))
				old = u;
		}
		if (cnt >= SIGNINS_MAX && old != NULL)
			(void)ucl_object_delete_key(si, ucl_object_key(old));
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "addr", S(addr));
	put(o, "at", I(time(NULL)));
	put(si, user, o);
	(void)store_save(SIGNINS_FILE, si);
	ucl_object_unref(si);
}

/* ---- Parsing a feed ---------------------------------------------- */

#define	PROTECTED	"covers a protected address: the console, a host, or a " \
			"sign-in"

/*
 * An entry dropped, and why; one that covers a protected address with
 * which, and whose (detail; host, a host's id), which feed_json() gives
 * only to whom may see it.
 */
static void
dropped_add(ucl_object_t *dropped, size_t *ndropped, const char *entry,
    const char *why, const char *detail, const char *host)
{
	ucl_object_t	*o;

	(*ndropped)++;
	if (ucl_array_size(dropped) >= FEED_DROPPED)
		return;
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "entry", S(entry));
	put(o, "reason", S(why));
	if (detail != NULL)
		put(o, "detail", S(detail));
	if (host != NULL && host[0] != '\0')
		put(o, "host", S(host));
	ucl_array_append(dropped, o);
}

/* What ipf_parse() drops, kept as feed_json() tells it. */
struct drops {
	const struct prot	*pv;
	ucl_object_t		*dropped;
	size_t			 n;
};

static void
drop_kept(void *arg, enum ipf_drop why, size_t line,
    const struct ipf_prefix *x, size_t which)
{
	struct drops	*d = arg;
	char		 s[IPF_PREFIX_STRLEN], a[IPF_PREFIX_STRLEN], w[200];

	switch (why) {
	case IPF_DROP_SYNTAX:
		/* Its line, not its words: a source is not to be read
		 * through the console. */
		snprintf(s, sizeof(s), "line %zu", line);
		dropped_add(d->dropped, &d->n, s, "not an address or prefix",
		    NULL, NULL);
		break;
	case IPF_DROP_ALL:
		dropped_add(d->dropped, &d->n, ipf_prefix_format(x, s,
		    sizeof(s)), "the whole address space", NULL, NULL);
		break;
	case IPF_DROP_PROTECTED:
		snprintf(w, sizeof(w), "covers %s, %s", ipf_prefix_addr(
		    &d->pv[which].p, a, sizeof(a)), d->pv[which].why);
		dropped_add(d->dropped, &d->n, ipf_prefix_format(x, s,
		    sizeof(s)), PROTECTED, w, d->pv[which].host);
		break;
	default:
		dropped_add(d->dropped, &d->n, ipf_prefix_format(x, s,
		    sizeof(s)), "private or reserved space, which this feed "
		    "does not list on purpose", NULL, NULL);
		break;
	}
}

/*
 * A feed's text made its entries (ipf_parse(3)): each made canonical,
 * once, those another covers left out (counted in *covered); those
 * dropped with why, the first FEED_DROPPED of them, all counted in
 * *ndropped.  NULL and err when it has more than FEED_MAX or none at
 * all.
 */
static ucl_object_t *
feed_parse(const char *text, size_t len, const char *format, bool keep_bogons,
    const struct prot *pv, size_t np, ucl_object_t *dropped, size_t *ndropped,
    size_t *covered, char *err, size_t errlen)
{
	struct ipf_prefix	*prot;
	struct ipf_parse	 ps;
	struct ipf_list		 l;
	struct drops		 d;
	ucl_object_t		*out;
	char			 s[IPF_PREFIX_STRLEN];
	size_t			 i;

	*ndropped = *covered = 0;
	memset(&ps, 0, sizeof(ps));
	if (ipf_format_parse(format, &ps.format) != 0) {
		snprintf(err, errlen, "no such format: %s", format);
		return (NULL);
	}
	if ((prot = calloc(np > 0 ? np : 1, sizeof(*prot))) == NULL) {
		snprintf(err, errlen, "out of memory");
		return (NULL);
	}
	for (i = 0; i < np; i++)
		prot[i] = pv[i].p;
	d.pv = pv;
	d.dropped = dropped;
	d.n = 0;
	ps.keep_reserved = keep_bogons;
	ps.protect = prot;
	ps.nprotect = np;
	ps.max = FEED_MAX;
	ps.drop = drop_kept;
	ps.arg = &d;
	ipf_list_init(&l);
	if (ipf_parse(&ps, text, len, &l, err, errlen) != 0) {
		free(prot);
		ipf_list_free(&l);
		return (NULL);
	}
	free(prot);
	*ndropped = d.n;
	*covered = ipf_list_aggregate(&l);
	out = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < l.n; i++)
		ucl_array_append(out, S(ipf_prefix_format(&l.v[i], s,
		    sizeof(s))));
	ipf_list_free(&l);
	return (out);
}

/* ---- What is kept --------------------------------------------------- */

static int
lock_take(void)
{
	char	path[MAXPATHLEN];
	int	fd;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, FEEDS_LOCK);
	if ((fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600)) == -1)
		return (-1);
	(void)flock(fd, LOCK_EX);
	(void)cluster_lock(FEEDS_LOCK);
	return (fd);
}

static void
lock_give(int fd)
{

	if (fd != -1) {
		cluster_unlock(FEEDS_LOCK);
		close(fd);
	}
}

static ucl_object_t *
doc_load(const char *name, const char *key, int type)
{
	ucl_object_t	*o;

	if ((o = store_load(name)) == NULL || ucl_object_type(o) !=
	    UCL_OBJECT) {
		if (o != NULL)
			ucl_object_unref(o);
		o = ucl_object_typed_new(UCL_OBJECT);
	}
	if (key != NULL && ucl_object_lookup(o, key) == NULL)
		put(o, key, ucl_object_typed_new(type));
	return (o);
}

static const ucl_object_t *
feed_by(const ucl_object_t *doc, const char *id)
{
	const ucl_object_t	*f;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((f = ucl_object_iterate(ucl_object_lookup(doc, "feeds"), &it,
	    true)) != NULL)
		if (str(f, "id") != NULL && strcmp(str(f, "id"), id) == 0)
			return (f);
	return (NULL);
}

static bool
id_ok(const char *s)
{
	size_t	n;

	n = s != NULL ? strlen(s) : 0;
	return (n > 0 && n <= 24 && strspn(s, "abcdefghijklmnopqrstuvwxyz"
	    "0123456789-") == n && s[0] != '-');
}

/* An ipfw table's name: letters, digits, _ . -, not all digits. */
static bool
table_ok(const char *s)
{
	size_t	n;

	n = s != NULL ? strlen(s) : 0;
	return (n <= 48 && ipf_ipfw_table_ok(s));
}

static void
table_default(const char *id, char *out, size_t len)
{
	size_t	i;

	snprintf(out, len, "feed_%s", id);
	for (i = 0; out[i] != '\0'; i++)
		if (out[i] == '-')
			out[i] = '_';
}

static int64_t
interval_of(const ucl_object_t *f)
{
	int64_t	h;

	h = num(f, "interval");
	return (h < FEED_FLOOR_H ? FEED_FLOOR_H : h);
}

/* A feed's entries, as kept: {"entries": [...], "sha256"}. */
static ucl_object_t *
entries_load(const char *id)
{
	char	name[64];

	snprintf(name, sizeof(name), "feeds/%s.json", id);
	return (store_load(name));
}

static void
sha_hex(const char *data, size_t len, char *out)
{
	unsigned char	md[32];
	unsigned int	n;
	int		i;

	out[0] = '\0';
	if (EVP_Digest(data, len, md, &n, EVP_sha256(), NULL) != 1)
		return;
	for (i = 0; i < 32; i++)
		snprintf(out + i * 2, 3, "%02x", md[i]);
}

/* The entries, a line each, to send; malloc'd. */
static char *
entries_text(const ucl_object_t *entries, size_t *lenp)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	FILE			*fp;
	char			*buf;
	size_t			 len;

	if ((fp = open_memstream(&buf, &len)) == NULL)
		return (NULL);
	it = NULL;
	while ((e = ucl_object_iterate(entries, &it, true)) != NULL)
		fprintf(fp, "%s\n", ucl_object_tostring(e));
	if (fclose(fp) != 0)
		return (NULL);
	if (lenp != NULL)
		*lenp = len;
	return (buf);
}

/* ---- Fetching ------------------------------------------------------ */

/*
 * Where a feed may come from: an address of the internet.  What
 * resolves to loopback, private, shared, link-local (a cloud's metadata
 * at 169.254.169.254), multicast or reserved space is refused, unless
 * Settings' feeds_allow_private lets its prefix through: the console is
 * not to be aimed at what only it can reach.  The prefixes let through
 * into allow, f made to fetch as the console does.
 */
static void
fetch_init(struct ipf_fetch *f, struct ipf_list *allow, char *ua, size_t len)
{
	char	*w;

	ipf_list_init(allow);
	w = settings_peek("feeds_allow_private");
	(void)ipf_list_words(allow, w);
	free(w);
	snprintf(ua, len, "arcana-console/%s", ARCW_VERSION);
	memset(f, 0, sizeof(*f));
	f->user_agent = ua;
	f->max_bytes = FEED_MAX_BYTES;
	f->timeout = FEED_TIMEOUT;
	f->redirects = 3;
	f->allow = allow->v;
	f->nallow = allow->n;
	f->allow_hint = "Settings' feeds_allow_private lets a prefix through";
}

/* May a feed be fetched from the URL now?  Why not in err. */
static bool
url_allowed(const char *url, char *err, size_t errlen)
{
	struct ipf_fetch	f;
	struct ipf_list		allow;
	char			ua[64];
	int			rc;

	fetch_init(&f, &allow, ua, sizeof(ua));
	rc = ipf_url_check(&f, url, err, errlen);
	ipf_list_free(&allow);
	return (rc == 0);
}

/*
 * The feed's text (ipf_fetch(3)): 0 and *bodyp (malloc'd), 1 when not
 * modified since ims, -1 and err.
 */
static int
fetch_url(const char *url, time_t ims, char **bodyp, size_t *lenp,
    time_t *lmp, char *err, size_t errlen)
{
	struct ipf_fetch	f;
	struct ipf_list		allow;
	char			ua[64];
	int			rc;

	fetch_init(&f, &allow, ua, sizeof(ua));
	f.if_modified_since = ims;
	rc = ipf_fetch(&f, url, bodyp, lenp, err, errlen);
	*lmp = f.last_modified;
	ipf_list_free(&allow);
	return (rc);
}

/*
 * Another part's URL (SD-WAN's lists) held to what a feed's is: may it
 * be fetched now?  Why not in err.
 */
bool
feeds_url_ok(const char *url, char *err, size_t errlen)
{

	return (url_allowed(url, err, errlen));
}

/*
 * Another part's document fetched as a feed is (ipf_fetch(3)): what
 * resolves to private space refused but for feeds_allow_private, each
 * redirect's target held to the same, at most max bytes within timeout
 * seconds.  0 and *bodyp (malloc'd, NUL-terminated), -1 and err.
 */
int
feeds_get(const char *url, size_t max, int timeout, char **bodyp,
    size_t *lenp, char *err, size_t errlen)
{
	struct ipf_fetch	f;
	struct ipf_list		allow;
	char			ua[64];
	int			rc;

	fetch_init(&f, &allow, ua, sizeof(ua));
	f.max_bytes = max;
	f.timeout = timeout;
	rc = ipf_fetch(&f, url, bodyp, lenp, err, errlen);
	ipf_list_free(&allow);
	return (rc == 0 ? 0 : -1);
}

/* ---- Delivery ------------------------------------------------------ */

/* A table on a host: loaded (dry, a preview), what came back in o. */
static bool
host_load(const char *sid, const char *table, const char *id,
    const char *text, bool dry, ucl_object_t *o)
{
	cbl_conn	*conn;
	cbl_tls		*tls;
	ucl_object_t	*out;
	const char	*e;
	char		 uri[256], peer[256], name[128], err[300];
	int		 error;

	if (!host_ref(sid, uri, sizeof(uri), peer, sizeof(peer), name,
	    sizeof(name))) {
		put(o, "error", S("no such host"));
		return (false);
	}
	put(o, "name", S(name));
	if ((e = hosts_connect(uri, peer, &conn, &tls)) != NULL) {
		put(o, "error", S(e));
		return (false);
	}
	out = NULL;
	err[0] = '\0';
	error = ynet_feed_load(conn, table, id, text, dry, &out, err,
	    sizeof(err));
	hosts_release(uri, peer, conn, tls, error == 0 || error == EIO);
	if (error != 0) {
		put(o, "error", S(err[0] != '\0' ? err : strerror(error)));
		return (false);
	}
	put(o, "count", I(num(out, "count")));
	put(o, "added", I(num(out, "added")));
	put(o, "removed", I(num(out, "removed")));
	put(o, "set", I(num(out, "set")));
	if (num(out, "left_out") > 0)
		put(o, "left_out", I(num(out, "left_out")));
	ucl_object_unref(out);
	return (true);
}

static bool
host_drop(const char *sid, const char *table, char *err, size_t errlen)
{
	cbl_conn	*conn;
	cbl_tls		*tls;
	const char	*e;
	char		 uri[256], peer[256], name[128];
	bool		 gone;
	int		 error;

	/* A host that is no more has nothing to drop. */
	if (!host_ref(sid, uri, sizeof(uri), peer, sizeof(peer), name,
	    sizeof(name)))
		return (true);
	if ((e = hosts_connect(uri, peer, &conn, &tls)) != NULL) {
		snprintf(err, errlen, "%s", e);
		return (false);
	}
	error = ynet_feed_drop(conn, table, &gone, err, errlen);
	hosts_release(uri, peer, conn, tls, error == 0 || error == EIO);
	return (error == 0);
}

/* ---- The work ------------------------------------------------------ */

static void
event_add(ucl_object_t *st, ucl_object_t *ev)
{
	ucl_object_t	*evs, *nv;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	size_t		 skip;

	evs = (ucl_object_t *)(uintptr_t)ucl_object_lookup(st, "events");
	nv = ucl_object_typed_new(UCL_ARRAY);
	skip = evs != NULL && ucl_array_size(evs) >= FEED_EVENTS ?
	    ucl_array_size(evs) - FEED_EVENTS + 1 : 0;
	it = NULL;
	while ((e = ucl_object_iterate(evs, &it, true)) != NULL)
		if (skip > 0)
			skip--;
		else
			ucl_array_append(nv, ucl_object_ref(e));
	ucl_array_append(nv, ev);
	put(st, "events", nv);
}

/* The alarm raised or cleared, and said where Settings say. */
static void
alarm_set(ucl_object_t *st, const ucl_object_t *f, bool raise,
    const char *why)
{
	ucl_object_t	*a;
	char		 subj[200], text[600], err[300];

	if (raise == (ucl_object_lookup(st, "alarm") != NULL))
		return;
	if (raise) {
		a = ucl_object_typed_new(UCL_OBJECT);
		put(a, "since", I(time(NULL)));
		put(a, "text", S(why));
		put(st, "alarm", a);
		snprintf(subj, sizeof(subj), "Arcana: threat feed %s is failing",
		    str(f, "name"));
		snprintf(text, sizeof(text), "The threat feed %s (%s) could "
		    "not be fetched %d times in a row: %s\nThe hosts keep its "
		    "last entries.", str(f, "name"), str(f, "url"), FEED_FAILS,
		    why);
		thread_log(LOG_WARNING, "feed %s: alarm raised: %s", str(f,
		    "id"), why);
	} else {
		(void)ucl_object_delete_key(st, "alarm");
		snprintf(subj, sizeof(subj), "Arcana: threat feed %s is back",
		    str(f, "name"));
		snprintf(text, sizeof(text), "The threat feed %s (%s) was "
		    "fetched again.", str(f, "name"), str(f, "url"));
		thread_log(LOG_NOTICE, "feed %s: alarm cleared", str(f, "id"));
	}
	(void)alert_send("all", subj, text, err, sizeof(err));
}

#define	RUN_FETCH	0	/* fetched when modified since the last */
#define	RUN_PREVIEW	1	/* fetched whole, each host's dry run */
#define	RUN_KEPT	2	/* the kept entries, to the hosts that lack them */

/*
 * Whom feed f is delivered for: who last saved it (author), held at
 * each delivery to the hosts they may operate now; one saved before
 * feeds kept it, the built-in owner; an author that cannot be read, no
 * one, to whom nothing is delivered.
 */
static void
feed_author(const ucl_object_t *f, struct principal *p)
{

	if (ucl_object_lookup(f, "author") != NULL) {
		(void)principal_of_record(ucl_object_lookup(f, "author"), p);
		return;
	}
	memset(p, 0, sizeof(*p));
	p->kind = P_USER;
	p->need = ROLE_VIEWER;
	snprintf(p->name, sizeof(p->name), "%s", ADMIN_USER);
}

/*
 * One feed fetched, its entries kept when they changed and sent to each
 * of its hosts that has not them and its author may operate still (one
 * that it may not is skipped, logged and said in the feed's state); a
 * preview keeps nothing but what it says.  A list of fewer than
 * IPF_SHRINK_PERCENT of the entries delivered last (ipf_list_shrunk(): a
 * source that serves an empty list, or half of it, as whole) is held
 * back, both counts in the state's "held", the last list kept and on
 * the hosts, fetched whole again next time, until "take" (an owner or
 * the feed's author, feeds_yang_ask()) lets the next one through.  st
 * is the feed's state, changed.
 */
static void
feed_run(const ucl_object_t *f, ucl_object_t *st, int how)
{
	struct principal	 author;
	struct prot	*pv;
	ucl_object_t	*entries, *dropped, *kept, *hosts, *h, *o, *ev;
	const ucl_object_t	*sid, *was, *hw;
	ucl_object_iter_t	 it;
	char		*body, *text, err[300], sha[65], name[64], table[64];
	const char	*id;
	size_t		 blen, tlen, ndropped, covered, np;
	time_t		 lm, now;
	int		 rc;
	bool		 changed, dry, held;

	dry = how == RUN_PREVIEW;
	id = str(f, "id");
	now = time(NULL);
	snprintf(table, sizeof(table), "%s", str(f, "table"));
	if ((pv = calloc(PROT_MAX, sizeof(*pv))) == NULL)
		return;
	np = protected(pv);
	kept = entries_load(id);
	body = NULL;
	if (how == RUN_KEPT)
		rc = 1;
	else {
		put(st, "tried_at", I(now));
		rc = fetch_url(str(f, "url"), dry || kept == NULL ? 0 :
		    (time_t)num(st, "last_modified"), &body, &blen, &lm, err,
		    sizeof(err));
	}
	if (rc < 0) {
		free(pv);
		if (kept != NULL)
			ucl_object_unref(kept);
		if (dry) {
			o = ucl_object_typed_new(UCL_OBJECT);
			put(o, "at", I(now));
			put(o, "error", S(err));
			put(st, "preview", o);
			return;
		}
		put(st, "error", S(err));
		put(st, "failures", I(num(st, "failures") + 1));
		thread_log(LOG_WARNING, "feed %s not fetched from %s: %s", id,
		    str(f, "url"), err);
		if (num(st, "failures") >= FEED_FAILS)
			alarm_set(st, f, true, err);
		return;
	}
	if (!dry && how != RUN_KEPT) {
		(void)ucl_object_delete_key(st, "error");
		put(st, "failures", I(0));
		alarm_set(st, f, false, NULL);
	}
	changed = false;
	entries = NULL;
	if (rc == 0) {
		dropped = ucl_object_typed_new(UCL_ARRAY);
		entries = feed_parse(body, blen, str(f, "format"), ucl_flag(f,
		    "bogons"), pv, np, dropped, &ndropped, &covered, err,
		    sizeof(err));
		free(body);
		if (entries == NULL) {
			ucl_object_unref(dropped);
			free(pv);
			if (kept != NULL)
				ucl_object_unref(kept);
			if (dry) {
				o = ucl_object_typed_new(UCL_OBJECT);
				put(o, "at", I(now));
				put(o, "error", S(err));
				put(st, "preview", o);
				return;
			}
			put(st, "error", S(err));
			put(st, "failures", I(num(st, "failures") + 1));
			if (num(st, "failures") >= FEED_FAILS)
				alarm_set(st, f, true, err);
			return;
		}
		if ((text = entries_text(entries, &tlen)) == NULL) {
			ucl_object_unref(entries);
			ucl_object_unref(dropped);
			free(pv);
			if (kept != NULL)
				ucl_object_unref(kept);
			return;
		}
		sha_hex(text, tlen, sha);
		free(text);
		if (dry) {
			o = ucl_object_typed_new(UCL_OBJECT);
			put(o, "at", I(now));
			put(o, "count", I((int64_t)ucl_array_size(entries)));
			put(o, "dropped_count", I((int64_t)ndropped));
			put(o, "covered", I((int64_t)covered));
			put(o, "dropped", dropped);
			put(st, "preview", o);
		} else {
			changed = kept == NULL || str(kept, "sha256") == NULL ||
			    strcmp(str(kept, "sha256"), sha) != 0;
			put(st, "fetched_at", I(now));
			if (lm > 0)
				put(st, "last_modified", I(lm));
			put(st, "dropped", dropped);
			put(st, "dropped_count", I((int64_t)ndropped));
			put(st, "covered", I((int64_t)covered));
			held = changed && kept != NULL && !ucl_flag(st, "take") &&
			    ipf_list_shrunk(ucl_array_size(ucl_object_lookup(kept,
			    "entries")), ucl_array_size(entries),
			    IPF_SHRINK_PERCENT);
			if (held) {
				int64_t	 before;

				before = (int64_t)ucl_array_size(
				    ucl_object_lookup(kept, "entries"));
				snprintf(err, sizeof(err), "%u entries fetched, "
				    "%jd delivered last: fewer than %d%%, not "
				    "delivered; the last list stays on the hosts "
				    "until it is taken anyway", ucl_array_size(
				    entries), (intmax_t)before,
				    IPF_SHRINK_PERCENT);
				if (str(ucl_object_lookup(st, "held"), "text") ==
				    NULL || strcmp(str(ucl_object_lookup(st,
				    "held"), "text"), err) != 0)
					thread_log(LOG_WARNING, "feed %s: %s", id,
					    err);
				o = ucl_object_typed_new(UCL_OBJECT);
				put(o, "at", I(now));
				put(o, "count", I((int64_t)ucl_array_size(
				    entries)));
				put(o, "was", I(before));
				put(o, "text", S(err));
				put(st, "held", o);
				/* Fetched whole again: a 304 would keep it. */
				(void)ucl_object_delete_key(st, "last_modified");
				ucl_object_unref(entries);
				entries = ucl_object_lookup(kept, "entries") !=
				    NULL ? ucl_object_ref(ucl_object_lookup(kept,
				    "entries")) : NULL;
				snprintf(sha, sizeof(sha), "%s", str(kept,
				    "sha256") != NULL ? str(kept, "sha256") : "");
				changed = false;
			} else {
				(void)ucl_object_delete_key(st, "held");
				(void)ucl_object_delete_key(st, "take");
			}
			if (changed) {
				int64_t	 before;

				before = kept != NULL ? (int64_t)ucl_array_size(
				    ucl_object_lookup(kept, "entries")) : 0;
				o = ucl_object_typed_new(UCL_OBJECT);
				put(o, "entries", ucl_object_ref(entries));
				put(o, "sha256", S(sha));
				snprintf(name, sizeof(name), "feeds/%s.json", id);
				(void)store_save(name, o);
				ucl_object_unref(o);
				put(st, "sha256", S(sha));
				put(st, "count", I((int64_t)ucl_array_size(
				    entries)));
				put(st, "changed_at", I(now));
				ev = ucl_object_typed_new(UCL_OBJECT);
				put(ev, "at", I(now));
				put(ev, "count", I((int64_t)ucl_array_size(
				    entries)));
				put(ev, "was", I(before));
				event_add(st, ev);
				thread_log(LOG_INFO, "feed %s: %u entries, %jd "
				    "before", id, ucl_array_size(entries),
				    (intmax_t)before);
			}
		}
	} else {
		/* Not modified: the kept entries, to the hosts that lack
		 * them. */
		if (how != RUN_KEPT)
			put(st, "fetched_at", I(now));
		if (kept != NULL && ucl_object_lookup(kept, "entries") != NULL)
			entries = ucl_object_ref(ucl_object_lookup(kept,
			    "entries"));
		snprintf(sha, sizeof(sha), "%s", kept != NULL && str(kept,
		    "sha256") != NULL ? str(kept, "sha256") : "");
	}
	free(pv);
	if (kept != NULL)
		ucl_object_unref(kept);
	if (entries == NULL)
		return;
	/* Each host: those that have them already are left alone. */
	if ((text = entries_text(entries, NULL)) == NULL) {
		ucl_object_unref(entries);
		return;
	}
	ucl_object_unref(entries);
	hosts = dry ? (ucl_object_t *)(uintptr_t)ucl_object_lookup(
	    ucl_object_lookup(st, "preview"), "hosts") :
	    (ucl_object_t *)(uintptr_t)ucl_object_lookup(st, "hosts");
	if (hosts == NULL) {
		hosts = ucl_object_typed_new(UCL_OBJECT);
		put(dry ? (ucl_object_t *)(uintptr_t)ucl_object_lookup(st,
		    "preview") : st, "hosts", hosts);
	}
	feed_author(f, &author);
	it = NULL;
	while ((sid = ucl_object_iterate(ucl_object_lookup(f, "hosts"), &it,
	    true)) != NULL) {
		const char	*s = ucl_object_tostring(sid);

		was = ucl_object_lookup(ucl_object_lookup(st, "hosts"), s);
		/* Its author's to operate now, or not delivered: a role
		 * taken away, a user removed (another of the name is not
		 * them), the feed saved again by one who may. */
		if (!principal_may_now(&author, s, ROLE_OPERATOR)) {
			char	who[96];

			h = ucl_object_typed_new(UCL_OBJECT);
			put(h, "tried_at", I(now));
			put(h, "table", S(table));
			snprintf(err, sizeof(err), "skipped: %s may not operate "
			    "it now; saved again by one who may, it is "
			    "delivered", principal_who(&author, who,
			    sizeof(who)));
			put(h, "error", S(err));
			if (!dry && was != NULL && str(was, "sha256") != NULL)
				put(h, "sha256", S(str(was, "sha256")));
			if (was == NULL || str(was, "error") == NULL || strcmp(
			    str(was, "error"), err) != 0)
				thread_log(LOG_NOTICE, "feed %s: not delivered to "
				    "%s: %s", id, s, err);
			put(hosts, s, h);
			continue;
		}
		if (!dry && was != NULL && str(was, "sha256") != NULL &&
		    strcmp(str(was, "sha256"), sha) == 0 && str(was, "table") !=
		    NULL && strcmp(str(was, "table"), table) == 0 && str(was,
		    "error") == NULL)
			continue;
		if (!dry && was != NULL && str(was, "error") != NULL && now -
		    num(was, "tried_at") < FEED_HOST_RETRY && !changed &&
		    how == RUN_KEPT)
			continue;
		/* Its table renamed: the old one given up first. */
		if (!dry && was != NULL && str(was, "sha256") != NULL && str(was,
		    "table") != NULL && strcmp(str(was, "table"), table) != 0 &&
		    !host_drop(s, str(was, "table"), err, sizeof(err)))
			thread_log(LOG_WARNING, "feed %s: table %s on %s not given "
			    "up: %s", id, str(was, "table"), s, err);
		h = ucl_object_typed_new(UCL_OBJECT);
		put(h, "tried_at", I(now));
		put(h, "table", S(table));
		if (host_load(s, table, id, text, dry, h)) {
			put(h, "at", I(now));
			if (!dry)
				put(h, "sha256", S(sha));
		} else if (!dry && was != NULL && str(was, "sha256") != NULL) {
			/* What it has still. */
			put(h, "sha256", S(str(was, "sha256")));
			if ((hw = ucl_object_lookup(was, "at")) != NULL)
				put(h, "at", I(ucl_object_toint(hw)));
			if ((hw = ucl_object_lookup(was, "count")) != NULL &&
			    ucl_object_lookup(h, "count") == NULL)
				put(h, "count", I(ucl_object_toint(hw)));
		}
		put(hosts, s, h);
	}
	free(text);
}

/*
 * The tables of hosts a feed is no longer for, or of a feed disabled or
 * gone, given up on those hosts: only what the feed itself made (the
 * agent refuses any other table).
 */
static void
feed_unload(const ucl_object_t *f, ucl_object_t *st)
{
	ucl_object_t		*hosts, *gone;
	const ucl_object_t	*h, *sid;
	ucl_object_iter_t	 it, sit;
	char			 err[300];
	bool			 want;

	if ((hosts = (ucl_object_t *)(uintptr_t)ucl_object_lookup(st,
	    "hosts")) == NULL)
		return;
	gone = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((h = ucl_object_iterate(hosts, &it, true)) != NULL) {
		want = false;
		sit = NULL;
		while (f != NULL && ucl_flag(f, "enabled") && (sid =
		    ucl_object_iterate(ucl_object_lookup(f, "hosts"), &sit,
		    true)) != NULL)
			if (strcmp(ucl_object_tostring(sid), ucl_object_key(h)) ==
			    0 && str(h, "table") != NULL && strcmp(str(h,
			    "table"), str(f, "table")) == 0)
				want = true;
		if (want)
			continue;
		/* Never loaded there: nothing to give up. */
		if (str(h, "sha256") == NULL) {
			ucl_array_append(gone, S(ucl_object_key(h)));
			continue;
		}
		if (time(NULL) - num(h, "drop_tried") < FEED_HOST_RETRY)
			continue;
		err[0] = '\0';
		if (host_drop(ucl_object_key(h), str(h, "table") != NULL ?
		    str(h, "table") : "", err, sizeof(err)))
			ucl_array_append(gone, S(ucl_object_key(h)));
		else {
			put((ucl_object_t *)(uintptr_t)h, "drop_tried", I(time(
			    NULL)));
			put((ucl_object_t *)(uintptr_t)h, "drop_error", S(err));
		}
	}
	it = NULL;
	while ((h = ucl_object_iterate(gone, &it, true)) != NULL)
		(void)ucl_object_delete_key(hosts, ucl_object_tostring(h));
	ucl_object_unref(gone);
}

/* The asks taken: {id: "fetch" | "preview"}, emptied. */
static ucl_object_t *
asks_take(void)
{
	ucl_object_t	*a;
	int		 fd;

	/* Looked at without the lock, as a rule there is nothing. */
	if ((a = store_load(FEEDS_ASKS)) == NULL || obj_len(a) == 0)
		return (a);
	ucl_object_unref(a);
	fd = lock_take();
	a = store_load(FEEDS_ASKS);
	if (a != NULL && ucl_object_type(a) == UCL_OBJECT && obj_len(a) > 0) {
		ucl_object_t	*empty = ucl_object_typed_new(UCL_OBJECT);

		(void)store_save(FEEDS_ASKS, empty);
		ucl_object_unref(empty);
	}
	lock_give(fd);
	return (a);
}

static void
ask(const char *id, const char *what)
{
	ucl_object_t	*a;
	int		 fd;

	fd = lock_take();
	a = doc_load(FEEDS_ASKS, NULL, UCL_OBJECT);
	put(a, id, S(what));
	(void)store_save(FEEDS_ASKS, a);
	ucl_object_unref(a);
	lock_give(fd);
}

/* One look: what is asked, what is due, what is to be given up. */
static void
feeds_tick(bool due)
{
	ucl_object_t		*doc, *state, *asks, *st;
	const ucl_object_t	*f, *s, *a;
	ucl_object_iter_t	 it;
	ucl_object_t		*gone;
	char			 name[64];
	int			 fd;
	time_t			 now;
	bool			 any;

	asks = asks_take();
	if (!due && obj_len(asks) == 0) {
		if (asks != NULL)
			ucl_object_unref(asks);
		return;
	}
	pthread_mutex_lock(&run_lock);
	host_refs();
	fd = lock_take();
	doc = doc_load(FEEDS_FILE, "feeds", UCL_ARRAY);
	state = doc_load(FEEDS_STATE, NULL, UCL_OBJECT);
	lock_give(fd);
	now = time(NULL);
	any = false;
	it = NULL;
	while ((f = ucl_object_iterate(ucl_object_lookup(doc, "feeds"), &it,
	    true)) != NULL) {
		const char	*id = str(f, "id");

		if (id == NULL)
			continue;
		if ((st = (ucl_object_t *)(uintptr_t)ucl_object_lookup(state,
		    id)) == NULL) {
			st = ucl_object_typed_new(UCL_OBJECT);
			put(state, id, st);
		}
		a = asks != NULL ? ucl_object_lookup(asks, id) : NULL;
		if (a != NULL && strcmp(ucl_object_tostring(a), "preview") ==
		    0) {
			feed_run(f, st, RUN_PREVIEW);
			any = true;
			continue;
		}
		/* A list held back taken anyway: fetched now, let through. */
		if (a != NULL && strcmp(ucl_object_tostring(a), "take") == 0 &&
		    ucl_flag(f, "enabled")) {
			put(st, "take", B(true));
			feed_run(f, st, RUN_FETCH);
			any = true;
			feed_unload(f, st);
			continue;
		}
		if (!ucl_flag(f, "enabled") || (a != NULL && strcmp(
		    ucl_object_tostring(a), "fetch") != 0)) {
			feed_unload(f, st);
			any = true;
			continue;
		}
		if (a != NULL || now - num(st, "tried_at") >= interval_of(f) *
		    3600 || (num(st, "failures") > 0 && now - num(st,
		    "tried_at") >= FEED_FLOOR_H * 3600)) {
			feed_run(f, st, RUN_FETCH);
			any = true;
		} else if (due) {
			/* Hosts that lack the entries, or failed. */
			const ucl_object_t	*sid, *h;
			ucl_object_iter_t	 sit;
			bool			 lack = false;

			sit = NULL;
			while ((sid = ucl_object_iterate(ucl_object_lookup(f,
			    "hosts"), &sit, true)) != NULL) {
				h = ucl_object_lookup(ucl_object_lookup(st,
				    "hosts"), ucl_object_tostring(sid));
				if (str(st, "sha256") != NULL && (h == NULL ||
				    str(h, "sha256") == NULL || strcmp(str(h,
				    "sha256"), str(st, "sha256")) != 0 || str(h,
				    "error") != NULL) && (h == NULL || now -
				    num(h, "tried_at") >= FEED_HOST_RETRY))
					lack = true;
			}
			if (lack) {
				feed_run(f, st, RUN_KEPT);
				any = true;
			}
		}
		feed_unload(f, st);
	}
	/* The state of a feed that is gone, once its tables are. */
	gone = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((s = ucl_object_iterate(state, &it, true)) != NULL) {
		if (feed_by(doc, ucl_object_key(s)) != NULL)
			continue;
		feed_unload(NULL, (ucl_object_t *)(uintptr_t)s);
		any = true;
		if (obj_len(ucl_object_lookup(s, "hosts")) == 0)
			ucl_array_append(gone, S(ucl_object_key(s)));
	}
	it = NULL;
	while ((s = ucl_object_iterate(gone, &it, true)) != NULL) {
		(void)ucl_object_delete_key(state, ucl_object_tostring(s));
		snprintf(name, sizeof(name), "feeds/%s.json",
		    ucl_object_tostring(s));
		(void)store_remove(name);
	}
	ucl_object_unref(gone);
	if (any) {
		fd = lock_take();
		(void)store_save(FEEDS_STATE, state);
		lock_give(fd);
		cyang_changed("threat-feeds");
	}
	ucl_object_unref(doc);
	ucl_object_unref(state);
	if (asks != NULL)
		ucl_object_unref(asks);
	pthread_mutex_unlock(&run_lock);
}

/*
 * The console itself: the feeds are the fleet's, each host they go to
 * chosen by one who may change it (feeds_yang_set()), and what goes is
 * a table the agent swaps in, no rule.
 */
static void *
feeds_main(void *arg __unused)
{
	unsigned int	n;

	hosts_act_console();
	for (n = 0;; n++) {
		sleep(FEEDS_TICK);
		/* Of a cluster, the leader's alone. */
		if (cluster_leads())
			feeds_tick(n % (60 / FEEDS_TICK) == 0);
	}
	return (NULL);
}

/* At the worker's start: the one that takes the lock does the work. */
void
feeds_init(void)
{
	pthread_t	tid;
	char		path[MAXPATHLEN];
	int		fd;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, FEEDS_RUN);
	if ((fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600)) == -1)
		return;
	if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
		close(fd);
		return;
	}
	if (pthread_create(&tid, NULL, feeds_main, NULL) == 0)
		(void)pthread_detach(tid);
}

/* ---- The API -------------------------------------------------------- */

static ucl_object_t *
presets_json(void)
{
	const struct ipf_preset	*presets;
	ucl_object_t		*arr, *o;
	size_t			 i, n;

	presets = ipf_presets(&n);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < n; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "id", S(presets[i].id));
		put(o, "name", S(presets[i].name));
		put(o, "url", S(presets[i].url));
		put(o, "format", S(ipf_format_name(presets[i].format)));
		put(o, "what", S(presets[i].description));
		put(o, "terms", S(presets[i].terms));
		put(o, "terms_url", S(presets[i].terms_url));
		put(o, "interval", I(presets[i].interval));
		put(o, "bogons", B(presets[i].reserved));
		ucl_array_append(arr, o);
	}
	return (arr);
}

/*
 * What a feed dropped, as the request's user may see it.  The console's
 * owners see it all.  To anyone else an entry dropped as it covers a
 * protected address is listed only when it is a host's that the user
 * may read, with which address; any other (the console's, another
 * host's, a sign-in's) is only counted, in *hiddenp, as a feed of
 * chosen addresses would otherwise tell which of them are protected.
 */
static ucl_object_t *
dropped_for(struct http_request *req, const ucl_object_t *dropped,
    int64_t *hiddenp)
{
	ucl_object_t		*out, *o;
	const ucl_object_t	*d;
	ucl_object_iter_t	 it;
	bool			 owner;

	*hiddenp = 0;
	owner = user_console(session_user(req)) == CROLE_OWNER;
	out = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((d = ucl_object_iterate(dropped, &it, true)) != NULL) {
		/* A host's, to one who may read it alone, an owner too; the
		 * console's own and a sign-in's, to an owner. */
		if (str(d, "detail") != NULL && (str(d, "host") == NULL ? !owner :
		    !host_role_ok(req, str(d, "host"), false, false))) {
			(*hiddenp)++;
			continue;
		}
		o = ucl_object_copy(d);
		(void)ucl_object_delete_key(o, "host");
		ucl_array_append(out, o);
	}
	return (out);
}

static bool	is_owner(struct http_request *);

/*
 * Every per-host part of a feed as the request's user may see it: of a
 * list of host ids, or an object keyed by them (what each host was sent,
 * its name and errors), those the user may read, an owner's too; the
 * rest only counted in *hiddenp.
 */
static ucl_object_t *
hosts_for(struct http_request *req, const ucl_object_t *o, int64_t *hiddenp)
{
	ucl_object_t		*out;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*sid;
	bool			 arr;

	*hiddenp = 0;
	arr = ucl_object_type(o) == UCL_ARRAY;
	out = ucl_object_typed_new(arr ? UCL_ARRAY : UCL_OBJECT);
	it = NULL;
	while ((e = ucl_object_iterate(o, &it, true)) != NULL) {
		sid = arr ? ucl_object_tostring_forced(e) : ucl_object_key(e);
		if (sid == NULL || server_find(sid) == NULL || !host_role_ok(req,
		    sid, false, false)) {
			(*hiddenp)++;
			continue;
		}
		if (arr)
			ucl_array_append(out, S(sid));
		else
			put(out, sid, ucl_object_copy(e));
	}
	return (out);
}

/* A feed and what its state says, for a page: whole with full. */
static ucl_object_t *
feed_json(struct http_request *req, const ucl_object_t *f,
    const ucl_object_t *st, bool full)
{
	static const char *const keys[] = { "fetched_at", "tried_at",
	    "changed_at", "count", "dropped_count", "covered", "failures" };
	ucl_object_t		*o, *ents, *sample;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	int64_t			 hidden;
	size_t			 i;

	o = ucl_object_copy(f);
	/* Its hosts, those the user may read; the others counted. */
	put(o, "hosts", hosts_for(req, ucl_object_lookup(f, "hosts"),
	    &hidden));
	if (hidden > 0)
		put(o, "hosts_hidden", I(hidden));
	for (i = 0; i < nitems(keys); i++)
		if (ucl_object_lookup(st, keys[i]) != NULL)
			put(o, keys[i], I(num(st, keys[i])));
	if (str(st, "error") != NULL)
		put(o, "error", S(str(st, "error")));
	if (ucl_object_lookup(st, "alarm") != NULL)
		put(o, "alarm", ucl_object_copy(ucl_object_lookup(st, "alarm")));
	if (ucl_object_lookup(st, "held") != NULL)
		put(o, "held", ucl_object_copy(ucl_object_lookup(st, "held")));
	put(o, "delivered", hosts_for(req, ucl_object_lookup(st, "hosts"),
	    &hidden));
	if (hidden > 0)
		put(o, "delivered_hidden", I(hidden));
	if (!full)
		return (o);
	put(o, "dropped", dropped_for(req, ucl_object_lookup(st, "dropped"),
	    &hidden));
	if (hidden > 0)
		put(o, "protected_hidden", I(hidden));
	put(o, "events", ucl_object_lookup(st, "events") != NULL ?
	    ucl_object_copy(ucl_object_lookup(st, "events")) :
	    ucl_object_typed_new(UCL_ARRAY));
	if (ucl_object_lookup(st, "preview") != NULL) {
		ucl_object_t	*pv;

		pv = ucl_object_copy(ucl_object_lookup(st, "preview"));
		put(pv, "dropped", dropped_for(req, ucl_object_lookup(pv,
		    "dropped"), &hidden));
		if (hidden > 0)
			put(pv, "protected_hidden", I(hidden));
		put(pv, "hosts", hosts_for(req, ucl_object_lookup(pv, "hosts"),
		    &hidden));
		if (hidden > 0)
			put(pv, "hosts_hidden", I(hidden));
		put(o, "preview", pv);
	}
	/* The first entries, to see what it holds. */
	sample = ucl_object_typed_new(UCL_ARRAY);
	if ((ents = entries_load(str(f, "id"))) != NULL) {
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(ents,
		    "entries"), &it, true)) != NULL && ucl_array_size(sample) <
		    200)
			ucl_array_append(sample, ucl_object_ref(e));
		ucl_object_unref(ents);
	}
	put(o, "sample", sample);
	return (o);
}

/* A feed as it is to be kept, from body and what a preset says. */
static ucl_object_t *
feed_check(struct http_request *req, const char *id, const ucl_object_t *body,
    const ucl_object_t *doc, char *err, size_t errlen)
{
	const struct ipf_preset	*pr;
	const ucl_object_t	*v, *e, *g;
	ucl_object_iter_t	 it, git;
	ucl_object_t		*f, *hosts;
	const char		*url, *fmt, *name, *table;
	char			 tdef[64];
	enum ipf_format		 fv;
	int64_t			 h;
	size_t			 i;

	pr = ipf_preset_find(str(body, "preset") != NULL ? str(body, "preset") :
	    id);
	if (str(body, "preset") != NULL && pr == NULL) {
		snprintf(err, errlen, "no such preset");
		return (NULL);
	}
	url = str(body, "url") != NULL ? str(body, "url") : pr != NULL ?
	    pr->url : NULL;
	if (url == NULL || strlen(url) > 500 || (strncmp(url, "https://", 8) !=
	    0 && strncmp(url, "http://", 7) != 0)) {
		snprintf(err, errlen, "a feed's url is https (or http)");
		return (NULL);
	}
	for (i = 0; url[i] != '\0'; i++)
		if (isspace((unsigned char)url[i]) || iscntrl((unsigned char)
		    url[i])) {
			snprintf(err, errlen, "a url has no spaces");
			return (NULL);
		}
	/* A preset's own source is the internet's; checked at each fetch,
	 * as every other. */
	if ((pr == NULL || strcmp(url, pr->url) != 0) && !url_allowed(url, err,
	    errlen))
		return (NULL);
	fmt = str(body, "format") != NULL ? str(body, "format") : pr != NULL ?
	    ipf_format_name(pr->format) : "plain";
	if (ipf_format_parse(fmt, &fv) != 0) {
		snprintf(err, errlen, "a format is plain, spamhaus-json or "
		    "dshield");
		return (NULL);
	}
	name = str(body, "name") != NULL ? str(body, "name") : pr != NULL ?
	    pr->name : id;
	if (strlen(name) == 0 || strlen(name) > 80) {
		snprintf(err, errlen, "a name is 80 characters at most");
		return (NULL);
	}
	for (i = 0; name[i] != '\0'; i++)
		if (iscntrl((unsigned char)name[i])) {
			snprintf(err, errlen, "a name has no control characters");
			return (NULL);
		}
	table_default(id, tdef, sizeof(tdef));
	table = str(body, "table") != NULL && str(body, "table")[0] != '\0' ?
	    str(body, "table") : tdef;
	if (!table_ok(table)) {
		snprintf(err, errlen, "an ipfw table's name is letters, digits, "
		    "_ . and -, 48 at most, not digits alone");
		return (NULL);
	}
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(doc, "feeds"), &it,
	    true)) != NULL)
		if (strcmp(str(e, "id"), id) != 0 && str(e, "table") != NULL &&
		    strcmp(str(e, "table"), table) == 0) {
			snprintf(err, errlen, "feed %s fills table %s already",
			    str(e, "id"), table);
			return (NULL);
		}
	h = (v = ucl_object_lookup(body, "interval")) != NULL ?
	    ucl_object_toint(v) : pr != NULL ? pr->interval : 6;
	if ((v != NULL && ucl_object_type(v) != UCL_INT) || h < FEED_FLOOR_H ||
	    h > 24 * 30) {
		snprintf(err, errlen, "the interval is hours, %d to 720",
		    FEED_FLOOR_H);
		return (NULL);
	}
	hosts = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((g = ucl_object_iterate(ucl_object_lookup(body, "hosts"), &it,
	    true)) != NULL) {
		const char	*sid = ucl_object_tostring_forced(g);

		if (server_find(sid) == NULL || !host_role_ok(req, sid, true,
		    false)) {
			ucl_object_unref(hosts);
			snprintf(err, errlen, "host %s is not one you may change",
			    sid);
			return (NULL);
		}
		git = NULL;
		for (e = NULL; (e = ucl_object_iterate(hosts, &git, true)) !=
		    NULL;)
			if (strcmp(ucl_object_tostring(e), sid) == 0)
				break;
		if (e == NULL)
			ucl_array_append(hosts, S(sid));
	}
	f = ucl_object_typed_new(UCL_OBJECT);
	put(f, "id", S(id));
	put(f, "name", S(name));
	put(f, "url", S(url));
	put(f, "format", S(fmt));
	put(f, "interval", I(h));
	put(f, "enabled", B(ucl_flag(body, "enabled")));
	put(f, "table", S(table));
	put(f, "bogons", B(ucl_object_lookup(body, "bogons") != NULL ?
	    ucl_flag(body, "bogons") : pr != NULL && pr->reserved));
	if (pr != NULL)
		put(f, "preset", S(pr->id));
	put(f, "hosts", hosts);
	return (f);
}

/*
 * May the request's user change every host the feed is on and every one
 * it was sent to, whose tables a change replaces or gives up?  NULL, or
 * the first that the user may not, by its name.
 */
static const char *
hosts_denied(struct http_request *req, const ucl_object_t *f,
    const ucl_object_t *st)
{
	const struct server	*sv;
	const ucl_object_t	*h;
	ucl_object_iter_t	 it;
	const char		*sid;

	it = NULL;
	while ((h = ucl_object_iterate(ucl_object_lookup(f, "hosts"), &it,
	    true)) != NULL) {
		sid = ucl_object_tostring_forced(h);
		if ((sv = server_find(sid)) != NULL && !host_role_ok(req, sid,
		    true, false))
			return (sv->name);
	}
	it = NULL;
	while ((h = ucl_object_iterate(ucl_object_lookup(st, "hosts"), &it,
	    true)) != NULL) {
		sid = ucl_object_key(h);
		if ((sv = server_find(sid)) != NULL && !host_role_ok(req, sid,
		    true, false))
			return (sv->name);
	}
	return (NULL);
}

/*
 * Is the feed fetched from a URL of one's own, not its preset's?  Only a
 * console owner makes one, changes one or previews one: what such a
 * feed drops, counted even, tells of the addresses no feed may cut off.
 */
static bool
feed_custom(const ucl_object_t *f)
{
	const struct ipf_preset	*pr;

	return ((pr = ipf_preset_find(str(f, "preset"))) == NULL || str(f, "url") ==
	    NULL || strcmp(str(f, "url"), pr->url) != 0);
}

static bool
is_owner(struct http_request *req)
{

	return (user_console(session_user(req)) == CROLE_OWNER);
}

/* Does b say what a does of key? */
static bool
same_key(const ucl_object_t *a, const ucl_object_t *b, const char *key)
{
	const ucl_object_t	*x, *y;

	x = ucl_object_lookup(a, key);
	y = ucl_object_lookup(b, key);
	if (x == NULL || y == NULL)
		return (x == y);
	return (strcmp(ucl_object_tostring_forced(x),
	    ucl_object_tostring_forced(y)) == 0);
}

/* Is the request's principal who last saved f (its "author")? */
static bool
is_author(struct http_request *req, const ucl_object_t *f)
{
	struct principal	 p;
	const ucl_object_t	*a;
	ucl_object_t		*r;
	bool			 same;

	if ((a = ucl_object_lookup(f, "author")) == NULL)
		return (false);
	req_principal(req, &p);
	r = principal_record(&p);
	same = same_key(r, a, "kind") && same_key(r, a, "name") &&
	    same_key(r, a, "id") && same_key(r, a, "write");
	ucl_object_unref(r);
	return (same);
}

/* The feed's hosts_denied(), as kept. */
static const char *
feed_denied(struct http_request *req, const char *id)
{
	ucl_object_t		*doc, *state;
	const ucl_object_t	*f;
	static __thread char	 name[128];
	const char		*who;
	int			 fd;

	fd = lock_take();
	doc = doc_load(FEEDS_FILE, "feeds", UCL_ARRAY);
	state = doc_load(FEEDS_STATE, NULL, UCL_OBJECT);
	lock_give(fd);
	f = feed_by(doc, id);
	who = hosts_denied(req, f, ucl_object_lookup(state, id));
	if (who != NULL)
		snprintf(name, sizeof(name), "%s", who);
	ucl_object_unref(doc);
	ucl_object_unref(state);
	return (who != NULL ? name : NULL);
}

/*
 * Feed id kept as body says, as the request's user may: every host it
 * is on and was sent to the user's to change, its hosts too, a URL of
 * one's own an owner's (an operator enables, disables or chooses the
 * hosts of such a feed), the URL an address of the internet; fetched at
 * once when enabled.  Dry, checked alone.  The feed kept into *keptp
 * when asked.  0, or the HTTP status and why.
 */
static int
feed_put(struct http_request *req, const char *id, const ucl_object_t *body,
    bool dry, ucl_object_t **keptp, char *err, size_t errlen)
{
	ucl_object_t		*doc, *f, *arr;
	const ucl_object_t	*e, *was;
	ucl_object_iter_t	 it;
	const char		*who;
	int			 fd;

	if (!id_ok(id)) {
		snprintf(err, errlen, "a feed is named by lower-case letters, "
		    "digits and -, 24 at most");
		return (400);
	}
	/* What changes the feed changes its hosts' tables: each of them,
	 * those it was sent to too, the user's to change. */
	if ((who = feed_denied(req, id)) != NULL) {
		snprintf(err, errlen, "host %s is not one you may change, and "
		    "the feed's table is on it", who);
		return (403);
	}
	if (body == NULL || ucl_object_type(body) != UCL_OBJECT) {
		snprintf(err, errlen, "a feed, as {\"name\", \"url\", "
		    "\"format\", \"interval\", \"enabled\", \"hosts\", "
		    "\"table\"}, or {\"preset\"}");
		return (400);
	}
	fd = lock_take();
	doc = doc_load(FEEDS_FILE, "feeds", UCL_ARRAY);
	was = feed_by(doc, id);
	if (was == NULL && ucl_array_size(ucl_object_lookup(doc, "feeds")) >=
	    FEEDS_MAX) {
		lock_give(fd);
		ucl_object_unref(doc);
		snprintf(err, errlen, "%d feeds at most", FEEDS_MAX);
		return (400);
	}
	if ((f = feed_check(req, id, body, doc, err, errlen)) == NULL) {
		lock_give(fd);
		ucl_object_unref(doc);
		return (400);
	}
	/* A URL of one's own: a console owner's to set and to change; an
	 * operator enables such a feed, disables it, chooses its hosts. */
	if (!is_owner(req) && feed_custom(f)) {
		static const char *const keys[] = { "name", "url", "format",
		    "bogons", "table", "interval" };
		size_t	 k;
		bool	 same = was != NULL && feed_custom(was);

		for (k = 0; same && k < nitems(keys); k++)
			same = same_key(was, f, keys[k]);
		if (!same) {
			lock_give(fd);
			ucl_object_unref(doc);
			ucl_object_unref(f);
			snprintf(err, errlen, "a feed from a URL of one's own is "
			    "made and changed by a console owner alone: an "
			    "operator uses the presets, and enables, disables or "
			    "chooses the hosts of such a feed");
			return (403);
		}
	}
	if (dry) {
		lock_give(fd);
		ucl_object_unref(doc);
		ucl_object_unref(f);
		return (0);
	}
	/* Who saved it: delivered for them, as they may at each delivery
	 * (feed_run()). */
	{
		struct principal	p;

		req_principal(req, &p);
		put(f, "author", principal_record(&p));
	}
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(doc, "feeds"), &it,
	    true)) != NULL)
		ucl_array_append(arr, strcmp(str(e, "id"), id) == 0 ?
		    ucl_object_ref(f) : ucl_object_ref(e));
	if (was == NULL)
		ucl_array_append(arr, ucl_object_ref(f));
	put(doc, "feeds", arr);
	if (store_save(FEEDS_FILE, doc) != 0) {
		lock_give(fd);
		ucl_object_unref(doc);
		ucl_object_unref(f);
		snprintf(err, errlen, "the feeds could not be written");
		return (500);
	}
	lock_give(fd);
	audit_add(was == NULL ? "feed-added" : "feed-changed", "Administer",
	    id, FEEDS_FILE, "the console", session_user(req), "threat feed %s "
	    "%s: %s, every %jd h, %s, "
	    "table %s on %u hosts", id, was == NULL ? "added" : "changed",
	    str(f, "url"), (intmax_t)num(f, "interval"), ucl_flag(f, "enabled") ?
	    "enabled" : "disabled", str(f, "table"), ucl_array_size(
	    ucl_object_lookup(f, "hosts")));
	ask(id, ucl_flag(f, "enabled") ? "fetch" : "unload");
	ucl_object_unref(doc);
	cyang_changed("threat-feeds");
	if (keptp != NULL)
		*keptp = f;
	else
		ucl_object_unref(f);
	return (0);
}

/* Feed id taken away, its tables given up, as the request's user may;
 * dry, checked alone.  0, or the HTTP status and why. */
static int
feed_remove(struct http_request *req, const char *id, bool dry, char *err,
    size_t errlen)
{
	ucl_object_t		*doc, *arr;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*who;
	int			 fd;

	if ((who = feed_denied(req, id)) != NULL) {
		snprintf(err, errlen, "host %s is not one you may change, and "
		    "the feed's table is on it", who);
		return (403);
	}
	if (dry)
		return (0);
	fd = lock_take();
	doc = doc_load(FEEDS_FILE, "feeds", UCL_ARRAY);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(doc, "feeds"),
	    &it, true)) != NULL)
		if (strcmp(str(e, "id"), id) != 0)
			ucl_array_append(arr, ucl_object_ref(e));
	put(doc, "feeds", arr);
	(void)store_save(FEEDS_FILE, doc);
	lock_give(fd);
	ucl_object_unref(doc);
	audit_add("feed-removed", "Administer", id, FEEDS_FILE,
	    "the console", session_user(req), "threat feed %s removed; "
	    "its tables given up", id);
	ask(id, "unload");
	cyang_changed("threat-feeds");
	return (0);
}

/*
 * Feed id fetched now or previewed (verb), as the request's user may: a
 * feed from a URL of one's own previewed by an owner alone.  0, or the
 * HTTP status and why.
 */
int
feeds_yang_ask(struct http_request *req, const char *id, const char *verb,
    char *err, size_t errlen)
{
	ucl_object_t		*doc;
	const ucl_object_t	*e;
	const char		*who;
	int			 fd;
	bool			 custom, author;

	if (!id_ok(id)) {
		snprintf(err, errlen, "no such feed");
		return (404);
	}
	if ((who = feed_denied(req, id)) != NULL) {
		snprintf(err, errlen, "host %s is not one you may change, and "
		    "the feed's table is on it", who);
		return (403);
	}
	fd = lock_take();
	doc = doc_load(FEEDS_FILE, "feeds", UCL_ARRAY);
	lock_give(fd);
	e = feed_by(doc, id);
	custom = e != NULL && feed_custom(e);
	author = e != NULL && is_author(req, e);
	ucl_object_unref(doc);
	if (e == NULL) {
		snprintf(err, errlen, "no such feed");
		return (404);
	}
	if (strcmp(verb, "preview") == 0 && custom && !is_owner(req)) {
		snprintf(err, errlen, "a feed from a URL of one's own is "
		    "previewed by a console owner alone");
		return (403);
	}
	if (strcmp(verb, "take") == 0 && !author && !is_owner(req)) {
		snprintf(err, errlen, "a list held back is taken anyway by a "
		    "console owner or the feed's author (who last saved it)");
		return (403);
	}
	ask(id, verb);
	return (0);
}

/* ---- arcana-console's threat feeds (cyang.c) ------------------------- */

/* Of o, the numbers named copied into to under their leaves' names. */
static void
numbers(ucl_object_t *to, const ucl_object_t *o, const char *const *keys)
{

	for (; keys[0] != NULL; keys += 2)
		if (ucl_object_lookup(o, keys[0]) != NULL)
			put(to, keys[1], I(num(o, keys[0])));
}

/* Of o, the times (seconds since the epoch) named copied into to. */
static void
times(ucl_object_t *to, const ucl_object_t *o, const char *const *keys)
{

	for (; keys[0] != NULL; keys += 2)
		if (ucl_object_lookup(o, keys[0]) != NULL)
			put(to, keys[1], yang_time((double)num(o, keys[0])));
}

/* feed_json()'s hosts, {id: what it was sent}, as feed-host entries. */
static ucl_object_t *
yhosts(const ucl_object_t *hosts)
{
	static const char *const nums[] = { "count", "count", "added",
	    "added", "removed", "removed", "set", "set", "left_out",
	    "left-out", NULL };
	static const char *const ts[] = { "at", "at", "tried_at", "tried-at",
	    NULL };
	ucl_object_t		*arr, *x;
	const ucl_object_t	*h;
	ucl_object_iter_t	 it = NULL;

	arr = ucl_object_typed_new(UCL_ARRAY);
	while ((h = ucl_object_iterate(hosts, &it, true)) != NULL) {
		x = ucl_object_typed_new(UCL_OBJECT);
		put(x, "host", S(ucl_object_key(h)));
		if (str(h, "name") != NULL)
			put(x, "name", S(str(h, "name")));
		if (str(h, "table") != NULL)
			put(x, "table", S(str(h, "table")));
		times(x, h, ts);
		numbers(x, h, nums);
		if (str(h, "error") != NULL)
			put(x, "error", S(str(h, "error")));
		ucl_array_append(arr, x);
	}
	return (arr);
}

/* feed_json()'s dropped entries and hidden count into to. */
static void
ydropped(ucl_object_t *to, const ucl_object_t *o)
{
	ucl_object_t		*arr, *x;
	const ucl_object_t	*d;
	ucl_object_iter_t	 it = NULL;
	int64_t			 i = 0;

	arr = ucl_object_typed_new(UCL_ARRAY);
	while ((d = ucl_object_iterate(ucl_object_lookup(o, "dropped"), &it,
	    true)) != NULL) {
		x = ucl_object_typed_new(UCL_OBJECT);
		put(x, "index", I(i++));
		if (str(d, "entry") != NULL)
			put(x, "entry", S(str(d, "entry")));
		if (str(d, "reason") != NULL)
			put(x, "reason", S(str(d, "reason")));
		if (str(d, "detail") != NULL)
			put(x, "detail", S(str(d, "detail")));
		ucl_array_append(arr, x);
	}
	put(to, "dropped", arr);
	if (ucl_object_lookup(o, "protected_hidden") != NULL)
		put(to, "protected-hidden", I(num(o, "protected_hidden")));
}

/*
 * A feed as arcana-console has it, from feed_json()'s whole view, so
 * that what the reader may not see of a host is left out here as there.
 */
static ucl_object_t *
feed_yang(const ucl_object_t *j)
{
	static const char *const cfg_s[] = { "id", "name", "url", "format",
	    "table", "preset", NULL };
	static const char *const nums[] = { "interval", "interval",
	    "hosts_hidden", "hosts-hidden", "count", "count", "dropped_count",
	    "dropped-count", "covered", "covered", "failures", "failures",
	    "delivered_hidden", "delivered-hidden", NULL };
	static const char *const ts[] = { "fetched_at", "fetched-at",
	    "tried_at", "tried-at", "changed_at", "changed-at", NULL };
	static const char *const pnums[] = { "count", "count",
	    "dropped_count", "dropped-count", "covered", "covered",
	    "hosts_hidden", "hosts-hidden", NULL };
	ucl_object_t		*o, *x, *arr;
	const ucl_object_t	*v, *e;
	ucl_object_iter_t	 it;
	int64_t			 i;
	size_t			 k;

	o = ucl_object_typed_new(UCL_OBJECT);
	for (k = 0; cfg_s[k] != NULL; k++)
		if (str(j, cfg_s[k]) != NULL)
			put(o, cfg_s[k], S(str(j, cfg_s[k])));
	put(o, "enabled", B(ucl_flag(j, "enabled")));
	if (ucl_object_lookup(j, "bogons") != NULL)
		put(o, "bogons", B(ucl_flag(j, "bogons")));
	if (ucl_array_size(ucl_object_lookup(j, "hosts")) > 0)
		put(o, "host", ucl_object_copy(ucl_object_lookup(j, "hosts")));
	numbers(o, j, nums);
	times(o, j, ts);
	if (str(j, "error") != NULL)
		put(o, "error", S(str(j, "error")));
	if ((v = ucl_object_lookup(j, "alarm")) != NULL) {
		x = ucl_object_typed_new(UCL_OBJECT);
		if (ucl_object_lookup(v, "since") != NULL)
			put(x, "since", yang_time((double)num(v, "since")));
		if (str(v, "text") != NULL)
			put(x, "text", S(str(v, "text")));
		put(o, "alarm", x);
	}
	if ((v = ucl_object_lookup(j, "held")) != NULL) {
		x = ucl_object_typed_new(UCL_OBJECT);
		if (ucl_object_lookup(v, "at") != NULL)
			put(x, "at", yang_time((double)num(v, "at")));
		put(x, "count", I(num(v, "count")));
		put(x, "was", I(num(v, "was")));
		if (str(v, "text") != NULL)
			put(x, "text", S(str(v, "text")));
		put(o, "held", x);
	}
	put(o, "delivered", yhosts(ucl_object_lookup(j, "delivered")));
	x = ucl_object_typed_new(UCL_OBJECT);
	ydropped(x, j);
	put(o, "last-fetch", x);
	arr = ucl_object_typed_new(UCL_ARRAY);
	i = 0;
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(j, "events"), &it,
	    true)) != NULL) {
		x = ucl_object_typed_new(UCL_OBJECT);
		put(x, "index", I(i++));
		if (ucl_object_lookup(e, "at") != NULL)
			put(x, "at", yang_time((double)num(e, "at")));
		put(x, "count", I(num(e, "count")));
		put(x, "was", I(num(e, "was")));
		ucl_array_append(arr, x);
	}
	put(o, "event", arr);
	if ((v = ucl_object_lookup(j, "preview")) != NULL) {
		x = ucl_object_typed_new(UCL_OBJECT);
		if (ucl_object_lookup(v, "at") != NULL)
			put(x, "at", yang_time((double)num(v, "at")));
		if (str(v, "error") != NULL)
			put(x, "error", S(str(v, "error")));
		numbers(x, v, pnums);
		ydropped(x, v);
		put(x, "host", yhosts(ucl_object_lookup(v, "hosts")));
		put(o, "last-preview", x);
	}
	if (ucl_array_size(ucl_object_lookup(j, "sample")) > 0)
		put(o, "sample", ucl_object_copy(ucl_object_lookup(j,
		    "sample")));
	return (o);
}

/* arcana-console:threat-feeds's value, as the request may see it. */
ucl_object_t *
feeds_yang(struct http_request *req)
{
	ucl_object_t		*doc, *state, *out, *arr, *j, *p;
	const ucl_object_t	*f, *e;
	ucl_object_iter_t	 it;
	int			 fd;

	fd = lock_take();
	doc = doc_load(FEEDS_FILE, "feeds", UCL_ARRAY);
	state = doc_load(FEEDS_STATE, NULL, UCL_OBJECT);
	lock_give(fd);
	out = ucl_object_typed_new(UCL_OBJECT);
	put(out, "floor", I(FEED_FLOOR_H));
	put(out, "max-entries", I(FEED_MAX));
	arr = presets_json();
	it = NULL;
	while ((e = ucl_object_iterate(arr, &it, true)) != NULL) {
		p = (ucl_object_t *)(uintptr_t)e;
		put(p, "terms-url", ucl_object_copy(ucl_object_lookup(p,
		    "terms_url")));
		(void)ucl_object_delete_key(p, "terms_url");
	}
	put(out, "preset", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((f = ucl_object_iterate(ucl_object_lookup(doc, "feeds"), &it,
	    true)) != NULL) {
		j = feed_json(req, f, ucl_object_lookup(state, str(f, "id")),
		    true);
		ucl_array_append(arr, feed_yang(j));
		ucl_object_unref(j);
	}
	put(out, "feed", arr);
	ucl_object_unref(doc);
	ucl_object_unref(state);
	return (out);
}

/* A feed's entry y as feed_put() takes it. */
static ucl_object_t *
feed_body(const ucl_object_t *y)
{
	static const char *const keys[] = { "name", "url", "format",
	    "table", "preset", NULL };
	ucl_object_t		*b;
	const ucl_object_t	*v;
	size_t			 k;

	b = ucl_object_typed_new(UCL_OBJECT);
	for (k = 0; keys[k] != NULL; k++)
		if (str(y, keys[k]) != NULL)
			put(b, keys[k], S(str(y, keys[k])));
	if ((v = ucl_object_lookup(y, "interval")) != NULL)
		put(b, "interval", I(ucl_object_toint(v)));
	put(b, "enabled", B(ucl_flag(y, "enabled")));
	if (ucl_object_lookup(y, "bogons") != NULL)
		put(b, "bogons", B(ucl_flag(y, "bogons")));
	put(b, "hosts", (v = ucl_object_lookup(y, "host")) != NULL ?
	    ucl_object_copy(v) : ucl_object_typed_new(UCL_ARRAY));
	return (b);
}

/*
 * The feeds changed from was to now, through feed_put() and
 * feed_remove(), every protection of theirs: every change checked
 * before any is kept.  0, or the HTTP status and why.
 */
int
feeds_yang_set(struct http_request *req, const ucl_object_t *was,
    const ucl_object_t *now, char *why, size_t len)
{
	const ucl_object_t	*f, *o;
	ucl_object_iter_t	 it;
	ucl_object_t		*b;
	const char		*id;
	char			 w[300];
	int			 rc, pass;

	for (pass = 0; pass < 2; pass++) {
		it = NULL;
		while ((o = ucl_object_iterate(ucl_object_lookup(was, "feed"),
		    &it, true)) != NULL) {
			id = str(o, "id");
			if (cyang_entry(ucl_object_lookup(now, "feed"), "id",
			    id) == NULL && (rc = feed_remove(req, id, pass == 0,
			    w, sizeof(w))) != 0) {
				snprintf(why, len, "feed %s: %s", id, w);
				return (rc);
			}
		}
		it = NULL;
		while ((f = ucl_object_iterate(ucl_object_lookup(now, "feed"),
		    &it, true)) != NULL) {
			id = str(f, "id");
			o = cyang_entry(ucl_object_lookup(was, "feed"), "id", id);
			b = feed_body(f);
			/* By what feed_put() is given: a default left out or
			 * said is the same. */
			if (o != NULL) {
				ucl_object_t	*a = feed_body(o);
				bool		 same = cyang_same(a, b);

				ucl_object_unref(a);
				if (same) {
					ucl_object_unref(b);
					continue;
				}
			}
			rc = feed_put(req, id, b, pass == 0, NULL, w, sizeof(w));
			ucl_object_unref(b);
			if (rc != 0) {
				snprintf(why, len, "feed %s: %s", id, w);
				return (rc);
			}
		}
	}
	return (0);
}
