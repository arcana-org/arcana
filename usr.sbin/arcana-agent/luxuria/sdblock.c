/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What the daemons of the SD-WAN services at this edge blocked, as
 * their own logs tell it: an event each, sdwan-block, which the
 * console makes a Security Event Notification of (MEF 138 R24), as it
 * does of ipfw's denies (record.c) and of Suricata's alerts (sdids.c).
 *
 *	unbound	its log file beside the agent's kept files (sddns.c), a
 *		jail edge's beneath the jail's root, opened through no
 *		link out of it; each
 *		local zone it answered (log-local-actions: DNF) and each
 *		RPZ trigger it applied (rpz-log, named by the zone: PDNS's
 *		CNAME and NS entries); both written where a zone's DNF or
 *		PDNS tells a list's matches (dns_conf_render()).
 *	Squid	its access log, in the arcana format (SQUID_LOGFORMAT): a
 *		request refused (TCP_DENIED) or a TLS connection ended at
 *		its name (terminate), each a zone's DNF with a * inside,
 *		MBSF's HTTP refused, or URLF's.
 *	c-icap	its server log, each virus found (virus_scan's "VIRUS
 *		DETECTED"): an MD+R list's hash, by the signature's name
 *		(clamav_sigs_render()), or a signature of ClamAV's own.
 *
 * Each line is matched back to the form the daemon was rendered from
 * (sdconf.c): the zone by the client's address, the function policy,
 * and the list the entry is on, or the No-match; told only where the
 * policy tells that list's matches (R20, R21), so the event is the
 * SEN's (the service, the policy, the list, the source, the target).
 * A thread reads each log every second from where it stopped, a log
 * turned over read from its start; one new to it from its end, so
 * what was there before is not told again.  BLOCKS_SECOND events a
 * second at most for each log.  unbound's own log, which nothing turns
 * over, is cut once it is read and longer than LOG_CUT.
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
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	LOGS_MAX	(3 * 64)
#define	BLOCKS_SECOND	20	/* events a second, at most, per log */
#define	LINE_MAX_LOG	(16 * 1024)
#define	LOG_CUT		(1024 * 1024)	/* unbound's, cut when longer */

struct watched {
	int		 kind;		/* SDB_* */
	char		 name[40];	/* the instance */
	char		 jail[64];	/* its edge's, "" the host's */
	char		 jroot[256];
	char		 path[MAXPATHLEN];	/* a jail's as it sees it */
	off_t		 off;		/* how far it is read */
	ucl_object_t	*spec;		/* the form it was rendered from */
};

static pthread_mutex_t	lock = PTHREAD_MUTEX_INITIALIZER;
static struct watched	logs[LOGS_MAX];
static int		nlogs;
static bool		reading;

static const char *const daemons[] = { "unbound", "squid", "c-icap" };

static const char *
sstr(const ucl_object_t *o, const char *k)
{
	const ucl_object_t	*v;

	v = ucl_object_lookup(o, k);
	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : NULL);
}

/* Whether address a is in prefix p (an address alone its own). */
static bool
in_prefix(const char *a, const char *p)
{
	uint8_t		 x[16], y[16];
	char		 buf[64], *sl;
	int		 af, len, i, bits;

	snprintf(buf, sizeof(buf), "%s", p);
	len = -1;
	if ((sl = strchr(buf, '/')) != NULL) {
		*sl = '\0';
		len = atoi(sl + 1);
	}
	af = strchr(buf, ':') != NULL ? AF_INET6 : AF_INET;
	if ((strchr(a, ':') != NULL) != (af == AF_INET6) || inet_pton(af, a,
	    x) != 1 || inet_pton(af, buf, y) != 1)
		return (false);
	bits = af == AF_INET6 ? 128 : 32;
	if (len < 0 || len > bits)
		len = bits;
	for (i = 0; i < len / 8; i++)
		if (x[i] != y[i])
			return (false);
	if (len % 8 != 0 && ((x[i] ^ y[i]) & (0xff << (8 - len % 8))) != 0)
		return (false);
	return (true);
}

/* The zone of the form a client's address is in: the one whose prefix
 * is the longest, else Default; NULL for none. */
static const ucl_object_t *
zone_of(const ucl_object_t *spec, const char *src)
{
	const ucl_object_t	*z, *e, *best, *def;
	ucl_object_iter_t	 zit, it;
	const char		*p, *sl;
	int			 len, blen;

	best = def = NULL;
	blen = -1;
	zit = NULL;
	while ((z = ucl_object_iterate(ucl_object_lookup(spec, "zones"), &zit,
	    true)) != NULL) {
		if (ucl_object_toboolean(ucl_object_lookup(z, "default")))
			def = z;
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(z, "prefixes"),
		    &it, true)) != NULL) {
			p = ucl_object_tostring_forced(e);
			if (!in_prefix(src, p))
				continue;
			len = (sl = strchr(p, '/')) != NULL ? atoi(sl + 1) : 128;
			if (len > blen) {
				blen = len;
				best = z;
			}
		}
	}
	return (best != NULL ? best : def);
}

/* The zone of the form by its name. */
static const ucl_object_t *
zone_named(const ucl_object_t *spec, const char *name)
{
	const ucl_object_t	*z;
	ucl_object_iter_t	 zit;

	zit = NULL;
	while ((z = ucl_object_iterate(ucl_object_lookup(spec, "zones"), &zit,
	    true)) != NULL)
		if (sstr(z, "name") != NULL && strcmp(sstr(z, "name"), name) == 0)
			return (z);
	return (NULL);
}

/* An event of what was blocked. */
static void
tell(const struct watched *w, const char *when, const char *src,
    const char *fn, const char *policy, const char *list, const char *target,
    const char *action, const char *detail)
{
	ucl_object_t	*o;
	char		*json;

	o = ucl_object_typed_new(UCL_OBJECT);
#define	PUT(k, v)	ucl_object_insert_key(o, ucl_object_fromstring((v) != \
	NULL ? (v) : ""), (k), 0, false)
	PUT("name", w->name);
	PUT("daemon", daemons[w->kind]);
	PUT("time", when);
	PUT("src", src);
	PUT("function", fn);
	PUT("service", sstr(w->spec, "service"));
	PUT("policy", policy);
	PUT("list", list);
	PUT("target", target);
	PUT("action", action);
	PUT("detail", detail);
#undef PUT
	if ((json = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT)) != NULL)
		event_add("sdwan-block", "%s", json);
	free(json);
	ucl_object_unref(o);
}

/* A name without its last dot, as the form has it ("." stays). */
static void
undot(char *s)
{
	size_t	n;

	n = strlen(s);
	if (n > 1 && s[n - 1] == '.')
		s[n - 1] = '\0';
}

/* An address without its @port, as unbound writes the client. */
static void
unport(char *s)
{
	char	*at;

	if ((at = strrchr(s, '@')) != NULL)
		*at = '\0';
}

/*
 * One line of unbound's: "[t] unbound[pid:tid] info: " and a local
 * zone's "zone type client@port qname qtype qclass", or an RPZ's "rpz:
 * applied [zone] [trigger ]owner action client@port qname qtype
 * qclass".  The rest are not told.
 */
static bool
unbound_line(const struct watched *w, char *line)
{
	const ucl_object_t	*z, *f;
	char			*p, *t[8], when[32], own[300], suf[80];
	const char		*entry, *list;
	int			 n, k;

	if (sscanf(line, "[%31[0-9]]", when) != 1 || (p = strstr(line,
	    "] info: ")) == NULL)
		return (false);
	p += 8;
	p[strcspn(p, "\n")] = '\0';
	if (strncmp(p, "rpz: applied [", 14) == 0) {
		char	zn[48];

		if (sscanf(p + 14, "%47[^]]", zn) != 1 || (p = strchr(p + 14,
		    ']')) == NULL)
			return (false);
		for (p++, n = 0; n < 8 && (t[n] = strsep(&p, " ")) != NULL; )
			if (t[n][0] != '\0')
				n++;
		if (n == 7) {		/* a trigger named: nsdname, nsip */
			t[0] = t[1];
			t[1] = t[2];
			t[2] = t[3];
			t[3] = t[4];
		} else if (n != 6)
			return (false);
		if ((z = zone_named(w->spec, zn)) == NULL || (f =
		    ucl_object_lookup(z, "pdns")) == NULL)
			return (false);
		/* The owner, its zone's origin taken away. */
		snprintf(own, sizeof(own), "%s", t[0]);
		undot(own);
		snprintf(suf, sizeof(suf), ".%s.rpz", zn);
		if (strlen(own) > strlen(suf) && strcasecmp(own + strlen(own) -
		    strlen(suf), suf) == 0)
			own[strlen(own) - strlen(suf)] = '\0';
		if ((k = sdwan_pdns_list(f, own, &entry)) < 0 ||
		    !sdwan_notifies(f, sdwan_list_name(k)))
			return (false);
		unport(t[2]);
		undot(t[3]);
		tell(w, when, t[2], "pdns", sstr(f, "id"), sdwan_list_name(k),
		    t[3], t[1], entry);
		return (true);
	}
	for (n = 0; n < 8 && (t[n] = strsep(&p, " ")) != NULL; )
		if (t[n][0] != '\0')
			n++;
	if (n != 6 || strchr(t[0], '/') != NULL)
		return (false);
	unport(t[2]);
	if ((z = zone_of(w->spec, t[2])) == NULL || (f = ucl_object_lookup(z,
	    "dnf")) == NULL)
		return (false);
	undot(t[0]);
	undot(t[3]);
	if (strcmp(t[0], ".") == 0) {
		/* The zone's No-match, which unbound has as the root. */
		if (strcmp(sstr(f, "no-match") != NULL ? sstr(f, "no-match") : "",
		    "block") != 0)
			return (false);
		list = "no-match";
		entry = "";
	} else {
		if ((k = sdwan_dnf_list(f, t[0])) < 0)
			return (false);
		list = sdwan_list_name(k);
		entry = t[0];
	}
	if (!sdwan_notifies(f, list))
		return (false);
	tell(w, when, t[2], "dnf", sstr(f, "id"), list, t[3], t[1], entry);
	return (true);
}

/*
 * One line of Squid's, SQUID_LOGFORMAT's: "time client status/code
 * method URL sni bumpmode".  A request refused or a connection ended
 * at its TLS name, matched by its zone's: a DNF's name with a * inside
 * (refused first), MBSF's HTTP, then the URLF's entries.
 */
static bool
squid_line(const struct watched *w, char *line)
{
	const ucl_object_t	*z, *f;
	char			*p, *t[8], host[256], *path;
	const char		*entry, *list, *fn, *u, *v;
	int			 n, k;
	bool			 tls;

	line[strcspn(line, "\n")] = '\0';
	p = line;
	for (n = 0; n < 8 && (t[n] = strsep(&p, " ")) != NULL; )
		if (t[n][0] != '\0')
			n++;
	if (n != 7 || (strstr(t[2], "DENIED") == NULL && strcmp(t[6],
	    "terminate") != 0))
		return (false);
	/* The host: the TLS name, else the URL's (a CONNECT's host:port). */
	tls = strcmp(t[3], "CONNECT") == 0 || strcmp(t[6], "terminate") == 0;
	u = t[4];
	if (strncmp(u, "http://", 7) == 0)
		u += 7;
	else if (strncmp(u, "https://", 8) == 0)
		u += 8;
	snprintf(host, sizeof(host), "%.*s", (int)strcspn(u, "/:"), u);
	if (strcmp(t[5], "-") != 0)
		snprintf(host, sizeof(host), "%s", t[5]);
	path = tls ? NULL : strchr(u, '/');
	if ((z = zone_of(w->spec, t[1])) == NULL)
		return (false);
	entry = "";
	list = NULL;
	fn = NULL;
	f = NULL;
	if (ucl_object_lookup(z, "dnf") != NULL && sdwan_dnf_wild(
	    ucl_object_lookup(z, "dnf"), host, &entry)) {
		fn = "dnf";
		list = "block";
		v = sstr(z, "dnf_id");
		if (v == NULL)
			v = "";
		tell(w, t[0], t[1], fn, v, list, tls ? host : t[4], t[6][0] != '-' ?
		    t[6] : t[2], entry);
		return (true);
	}
	if ((f = ucl_object_lookup(z, "mbsf")) != NULL && !tls && strcmp(
	    sstr(f, "unencrypted") != NULL ? sstr(f, "unencrypted") : "",
	    "block") == 0) {
		fn = "mbsf";
		list = "unencrypted";
	} else if ((f = ucl_object_lookup(z, "urlf")) != NULL) {
		fn = "urlf";
		if ((k = sdwan_urlf_list(f, host, path != NULL ? path : "/", &entry)
		    ) < 0 && tls)
			k = sdwan_urlf_list(f, host, NULL, &entry);
		if (k == 2)
			return (false);		/* let through: not this one */
		if (k >= 0)
			list = sdwan_list_name(k);
		else if (strcmp(sstr(f, "no-match") != NULL ? sstr(f, "no-match")
		    : "", "block") == 0)
			list = "no-match";
		else
			list = "block";	/* a named list's, a file of its own */
	} else if ((f = ucl_object_lookup(z, "mbsf")) != NULL) {
		fn = "mbsf";
		list = "";
	} else
		return (false);
	if (list[0] != '\0' && strcmp(list, "unencrypted") != 0 &&
	    !sdwan_notifies(f, list))
		return (false);
	tell(w, t[0], t[1], fn, sstr(f, "id"), list, tls ? host : t[4],
	    t[6][0] != '-' ? t[6] : t[2], entry);
	return (true);
}

/*
 * One line of c-icap's: "..., VIRUS DETECTED: name , http client ip:
 * client, http user: user, http url: URL".  A hash of an MD+R list's
 * by its signature's name; another, ClamAV's own, the client's zone's
 * MD+R's.
 */
static bool
icap_line(const struct watched *w, char *line)
{
	const ucl_object_t	*z, *f;
	char			*p, virus[200], src[64], url[2048];
	const char		*policy, *list;
	int			 k;

	if ((p = strstr(line, "VIRUS DETECTED: ")) == NULL)
		return (false);
	line[strcspn(line, "\n")] = '\0';
	virus[0] = src[0] = url[0] = '\0';
	if (sscanf(p + 16, "%199[^ ,]", virus) != 1)
		return (false);
	if ((p = strstr(line, "http client ip: ")) != NULL)
		(void)sscanf(p + 16, "%63[^ ,]", src);
	if ((p = strstr(line, "http url: ")) != NULL)
		(void)sscanf(p + 10, "%2047s", url);
	if (sdwan_mdr_sig(w->spec, virus, &policy, &k)) {
		list = sdwan_list_name(k);
		f = NULL;
		/* The policy, by its ID, for what it tells. */
		{
			ucl_object_iter_t	zit = NULL;

			while ((z = ucl_object_iterate(ucl_object_lookup(w->spec,
			    "zones"), &zit, true)) != NULL)
				if ((f = ucl_object_lookup(z, "mdr")) != NULL &&
				    sstr(f, "id") != NULL && strcmp(sstr(f, "id"),
				    policy) == 0)
					break;
		}
		if (f == NULL || !sdwan_notifies(f, list))
			return (false);
	} else {
		if ((z = zone_of(w->spec, src)) == NULL || (f = ucl_object_lookup(
		    z, "mdr")) == NULL)
			return (false);
		policy = sstr(f, "id");
		list = "malware";
	}
	tell(w, "", src, "mdr", policy, list, url, virus, virus);
	return (true);
}

/*
 * A log opened to read, and to be cut: the host's by its path, a jail's
 * beneath the jail's root, through no link (its root user may put one
 * anywhere), a regular file only.  -1 with errno for none.
 */
static int
log_open(const struct watched *w)
{
	struct stat	 st;
	const char	*rel;
	int		 root, fd, e, rw;

	/* unbound's is cut once read (read_log()); the others only read. */
	rw = w->kind == SDB_UNBOUND ? O_RDWR : O_RDONLY;
	if (w->jail[0] == '\0')
		return (open(w->path, rw | O_NONBLOCK | O_CLOEXEC));
	if ((root = open(w->jroot, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) == -1)
		return (-1);
	rel = w->path + strspn(w->path, "/");
	fd = openat(root, rel, rw | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC |
	    O_RESOLVE_BENEATH);
	e = errno;
	close(root);
	if (fd != -1 && (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))) {
		close(fd);
		fd = -1;
		e = EINVAL;
	}
	errno = e;
	return (fd);
}

/* What a log has had written since it was last read. */
static void
read_log(struct watched *w)
{
	struct stat	 st;
	FILE		*fp;
	char		*line;
	size_t		 cap;
	ssize_t		 n;
	int		 told, fd;

	if ((fd = log_open(w)) == -1)
		return;
	if ((fp = fdopen(fd, "r")) == NULL) {
		close(fd);
		return;
	}
	if (fstat(fileno(fp), &st) != 0) {
		fclose(fp);
		return;
	}
	if (st.st_size < w->off)	/* turned over, or made anew */
		w->off = 0;
	if (st.st_size == w->off || fseeko(fp, w->off, SEEK_SET) != 0) {
		fclose(fp);
		return;
	}
	line = NULL;
	cap = 0;
	told = 0;
	while ((n = getline(&line, &cap, fp)) > 0) {
		if (line[n - 1] != '\n')	/* half written: next time */
			break;
		w->off += n;
		if (n > LINE_MAX_LOG || told >= BLOCKS_SECOND)
			continue;
		switch (w->kind) {
		case SDB_UNBOUND:
			told += unbound_line(w, line);
			break;
		case SDB_SQUID:
			told += squid_line(w, line);
			break;
		case SDB_ICAP:
			told += icap_line(w, line);
			break;
		}
	}
	free(line);
	/* unbound's own, which nothing turns over: cut, all of it read. */
	if (w->kind == SDB_UNBOUND && w->off > LOG_CUT && w->off == st.st_size &&
	    ftruncate(fileno(fp), 0) == 0)
		w->off = 0;
	fclose(fp);
}

static void *
reader(void *arg __unused)
{
	int	i;

	for (;;) {
		sleep(1);
		pthread_mutex_lock(&lock);
		for (i = 0; i < nlogs; i++)
			read_log(&logs[i]);
		pthread_mutex_unlock(&lock);
	}
	return (NULL);
}

/*
 * The logs of a kind read from now on: those of the n instances, each
 * its name, its log and its form; those of the kind before not any
 * more.  One read before goes on from where it was; a new one from its
 * end.  The host's: those of a jail's edge are left as they are.
 */
void
sdblock_watch(int kind, int n, const char *const *names,
    const char *const *paths, const ucl_object_t *const *specs)
{

	sdblock_watch_jail(kind, NULL, NULL, n, names, paths, specs);
}

/* The same of an edge, the jail's (jail NULL or "": the host's), its
 * logs' paths as the jail sees them, beneath jroot. */
void
sdblock_watch_jail(int kind, const char *jail, const char *jroot, int n,
    const char *const *names, const char *const *paths,
    const ucl_object_t *const *specs)
{
	struct watched	*nl;
	struct stat	 st;
	int		 i, k, m, fd;

	if (jail == NULL)
		jail = "";
	/* Not on the stack: a request's thread has little of it. */
	if ((nl = calloc(LOGS_MAX, sizeof(*nl))) == NULL)
		return;
	pthread_mutex_lock(&lock);
	m = 0;
	for (i = 0; i < nlogs; i++)
		if (logs[i].kind != kind || strcmp(logs[i].jail, jail) != 0)
			nl[m++] = logs[i];
	for (k = 0; k < n && m < LOGS_MAX; k++) {
		memset(&nl[m], 0, sizeof(nl[m]));
		nl[m].kind = kind;
		snprintf(nl[m].name, sizeof(nl[m].name), "%s", names[k]);
		snprintf(nl[m].jail, sizeof(nl[m].jail), "%s", jail);
		snprintf(nl[m].jroot, sizeof(nl[m].jroot), "%s", jail[0] != '\0' &&
		    jroot != NULL ? jroot : "");
		snprintf(nl[m].path, sizeof(nl[m].path), "%s", paths[k]);
		nl[m].spec = ucl_object_copy(specs[k]);
		nl[m].off = 0;
		if ((fd = log_open(&nl[m])) != -1) {
			if (fstat(fd, &st) == 0)
				nl[m].off = st.st_size;
			close(fd);
		}
		for (i = 0; i < nlogs; i++)
			if (logs[i].kind == kind && strcmp(logs[i].jail, jail) ==
			    0 && strcmp(logs[i].path, paths[k]) == 0)
				nl[m].off = logs[i].off;
		m++;
	}
	for (i = 0; i < nlogs; i++)
		if (logs[i].kind == kind && strcmp(logs[i].jail, jail) == 0)
			ucl_object_unref(logs[i].spec);
	memcpy(logs, nl, sizeof(*nl) * (size_t)m);
	nlogs = m;
	free(nl);
	if (!reading && nlogs > 0) {
		pthread_t	tid;

		if (pthread_create(&tid, NULL, reader, NULL) == 0) {
			pthread_detach(tid);
			reading = true;
		}
	}
	pthread_mutex_unlock(&lock);
}
