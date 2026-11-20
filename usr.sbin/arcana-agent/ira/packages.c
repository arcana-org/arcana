/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Packages of the host or of a running jail, through pkg(8): "pkg -j
 * <jail>" runs inside the jail.  What has a newer version comes from
 * "pkg version -vRl '<'" (one line per package: name-version, '<',
 * "needs updating (remote has <version>)"), and upgrades are
 * "pkg upgrade -y [names]".  Every run is a step in the trace, so the
 * upgrade's output reaches the console.
 *
 * Before pkg reaches for a repository (pkg update, upgrade, install),
 * the repository is asked whether it answers from where pkg will run:
 * its meta.conf fetched once by the helper attached to the jail
 * (repo_reach_helper()), the URL as pkg -vv has it, an SRV record
 * followed as pkg follows one, given up after REPO_REACH_SEC.  pkg's
 * own FETCH_TIMEOUT covers no transfer that stalls once connected: a
 * jail whose only family has no way out held a job for hours.  When it
 * does not answer, the job fails at once saying what was tried and what
 * the jail has to reach it with; a job may say not to ask.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <arpa/nameser.h>
#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <poll.h>
#include <resolv.h>
#include <signal.h>
#include <stdio.h>
#include <fetch.h>		/* after stdio.h: FILE */
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"

/* A repository as pkg -vv says it. */
struct pkgrepo {
	const char	*name;
	const char	*url;		/* or NULL */
	bool		 enabled;
	bool		 srv;		/* mirror_type SRV */
	uint8_t		 ip;		/* its ip_version: 4, 6, or 0 */
	long		 priority;
};

/* What pkg -vv says that reaching a repository takes. */
struct pkgconf {
	struct pkgrepo	*repos;
	size_t		 nrepos;
	uint8_t		 ip;		/* IP_VERSION */
	const char	*env;		/* PKG_ENV's, NAME=value lines */
};

static int	pkg_run(struct work *, const char *, bool, uint8_t,
		    const char *const *, size_t, struct execres *);
static int	pkg_read(struct work *, const char *, const char *const *,
		    size_t, struct execres *);
static void	parse_versions(struct work *, const struct execres *,
		    struct package **, size_t *);
static bool	valid_pkg(const char *);
static const char *check_jail(struct work *, const char *);

/*
 * "pkg [-4 | -6] [-o IGNORE_OSVERSION=yes] [-j jail] args...": with
 * anyos, also packages built for a newer FreeBSD than this one; ip 4
 * or 6, the repository reached over that only.
 */
static int
pkg_exec(struct work *w, const char *jail, bool anyos, uint8_t ip,
    const char *const *args, size_t n, struct execres *res, bool reads)
{
	char	**argv;
	size_t	 i, k;
	int	 rc;

	argv = wcalloc(w, n + 8, sizeof(*argv));
	k = 0;
	argv[k++] = (char *)(uintptr_t)opts.pkg_bin;
	if (ip == 4 || ip == 6)
		argv[k++] = (char *)(uintptr_t)(ip == 4 ? "-4" : "-6");
	if (anyos) {
		argv[k++] = (char *)(uintptr_t)"-o";
		argv[k++] = (char *)(uintptr_t)"IGNORE_OSVERSION=yes";
	}
	if (jail != NULL && *jail != '\0') {
		argv[k++] = (char *)(uintptr_t)"-j";
		argv[k++] = (char *)(uintptr_t)jail;
	}
	for (i = 0; i < n; i++)
		argv[k++] = (char *)(uintptr_t)args[i];
	argv[k] = NULL;
	/* Watched: a pkg that hangs (a stalled fetch) is stopped, its
	 * child in the jail with it. */
	pkg_watch(true);
	rc = reads ? run_read(w, argv, res) : run_exec(w, argv, res);
	pkg_watch(false);
	pkg_stalled(w, res, jail, ip, NULL);
	return (rc);
}

static int
pkg_run(struct work *w, const char *jail, bool anyos, uint8_t ip,
    const char *const *args, size_t n, struct execres *res)
{

	return (pkg_exec(w, jail, anyos, ip, args, n, res, false));
}

/* What only reads pkg's database or configuration (pkg -vv, query,
 * audit): a dry run runs it too, as a job's would be. */
static int
pkg_read(struct work *w, const char *jail, const char *const *args,
    size_t n, struct execres *res)
{

	return (pkg_exec(w, jail, false, 0, args, n, res, true));
}

/*
 * What pkg prints as it begins to install, upgrade or remove a package
 * ("[1/2] Upgrading pimd from 3.1.0 to 3.2.0...", "[1/2] Extracting
 * pimd-3.2.0: ..."); "[1/2] Fetching" is not one.  From then on its
 * silence is a package's script at work.
 */
static const char *const pkg_busy_marks[] = { "] Installing ",
    "] Upgrading ", "] Downgrading ", "] Reinstalling ", "] Deinstalling ",
    "] Deleting ", "] Extracting ", NULL };

/*
 * The pkg this thread runs next watched, or no longer: stopped once
 * silent for --pkg-idle while it fetches (a stalled download), only
 * once silent PKG_BUSY_TIMES as long once it installs, its waiting said
 * in the trace before (exec_set_busy()).
 */
void
pkg_watch(bool on)
{

	exec_set_watch(on ? opts.pkg_idle_s : 0);
	exec_set_busy(on ? pkg_busy_marks : NULL, on ? opts.pkg_idle_s *
	    PKG_BUSY_TIMES : 0, "pkg waits on a package's script (an rc stop "
	    "of a service, or a question)");
}

/*
 * A watched pkg stopped for its silence: which silence it was, in
 * res->note.  While it installed, a package's script waited; else
 * whether the repository answers now says it.
 */
void
pkg_stalled(struct work *w, struct execres *res, const char *jail,
    uint8_t ip, const char *repo)
{

	if (res->stalled == 0)
		return;
	if (res->waited != NULL)
		res->note = wtext(w, wfmt(w, "it had begun installing and a "
		    "package's script waited (an rc stop of a service that "
		    "would not stop, or a question); it printed last: "
		    "\"%s\"; that package may be left half installed",
		    res->waited));
	else
		res->note = pkg_stall_note(w, jail, ip, repo);
}

/* pkg's line when a package could not be fetched. */
#define	PKG_FETCH_FAILED	"An error occurred while fetching package"
#define	PKG_FETCH_LINES		6	/* of pkg's before it, at most */

/*
 * A fetch that failed: pkg says only PKG_FETCH_FAILED last, the URL and
 * libfetch's or curl's reason on the lines of standard error before it
 * ("pkg: https://...: Not Found"), which are kept: the last of pkg's
 * own ("pkg: ") and those that name a URL, up to that line.  NULL when
 * pkg said no such thing.
 */
static const char *
pkg_fetch_error(struct work *w, const struct execres *res, const char *prog)
{
	const char	*why, *v[PKG_FETCH_LINES];
	char		*copy, *it, *line;
	bool		 inerr;
	size_t		 n, i;

	inerr = res->err != NULL && strstr(res->err, PKG_FETCH_FAILED) != NULL;
	if (!inerr && (res->out == NULL || strstr(res->out, PKG_FETCH_FAILED) ==
	    NULL))
		return (NULL);
	n = 0;
	copy = wstrndup(w, res->err != NULL ? res->err : "", res->errlen);
	for (it = copy; (line = strsep(&it, "\n")) != NULL; ) {
		line[strcspn(line, "\r")] = '\0';
		if (strncmp(line, "pkg: ", 5) == 0)
			line += 5;
		else if (strncmp(line, "pkg-static: ", 12) == 0)
			line += 12;
		else if (strstr(line, "://") == NULL &&
		    strstr(line, PKG_FETCH_FAILED) == NULL)
			continue;
		if (line[0] == '\0')
			continue;
		if (n == PKG_FETCH_LINES) {
			memmove(v, v + 1, (n - 1) * sizeof(*v));
			n--;
		}
		v[n++] = line;
		if (strstr(line, PKG_FETCH_FAILED) != NULL)
			break;
	}
	if (!inerr) {
		if (n == PKG_FETCH_LINES) {
			memmove(v, v + 1, (n - 1) * sizeof(*v));
			n--;
		}
		v[n++] = PKG_FETCH_FAILED;
	}
	why = NULL;
	for (i = 0; i < n; i++)
		why = why == NULL ? wfmt(w, "%.300s", v[i]) : wfmt(w,
		    "%s; %.300s", why, v[i]);
	return (wtext(w, wfmt(w, "%s exited with status %d: %s", prog,
	    res->status, why)));
}

/*
 * Why pkg failed, as the job says it: a repository it could not read
 * (pkg_repo_error()); killed or stopped, as exec_error() says; a fetch
 * that failed, with pkg's lines of it; else its last line.
 */
const char *
pkg_error(struct work *w, const struct execres *res, const char *prog)
{
	const char	*e;

	if ((e = pkg_repo_error(w, res, prog)) != NULL)
		return (e);
	if (!res->timedout && !res->cancelled && res->stalled == 0 &&
	    (e = pkg_fetch_error(w, res, prog)) != NULL)
		return (e);
	return (wtext(w, exec_error(w, res, prog)));
}

/*
 * What pkg said of repositories it could not update or open, its lines
 * of "pkg:" joined, or NULL when it said none: pkg upgrade and install
 * exit 0 then, with nothing to do, as if every package were up to date.
 * A repository of packages for a newer FreeBSD (pkg's "wrong OS
 * version") is said to need IGNORE_OSVERSION, for the console to ask
 * whether to go on past it.
 */
const char *
pkg_repo_error(struct work *w, const struct execres *res, const char *prog)
{
	const char	*text[] = { res->err, res->out };
	char		*copy, *it, *line, *why;
	bool		 failed;
	size_t		 i;

	failed = false;
	why = NULL;
	for (i = 0; i < nitems(text); i++) {
		if (text[i] == NULL)
			continue;
		if (strstr(text[i], "Error updating repositories") != NULL ||
		    strstr(text[i], "cannot be opened") != NULL)
			failed = true;
		copy = wstrdup(w, text[i]);
		for (it = copy; (line = strsep(&it, "\n")) != NULL;) {
			if (strncmp(line, "pkg: ", 5) != 0)
				continue;
			why = why == NULL ? wstrdup(w, line + 5) :
			    wfmt(w, "%s; %s", why, line + 5);
		}
	}
	if (!failed)
		return (NULL);
	if (why != NULL && strstr(why, "wrong OS version") != NULL)
		return (wtext(w, wfmt(w, "%s: a repository has packages for a "
		    "newer FreeBSD than this one, refused unless "
		    "IGNORE_OSVERSION=yes: %s", prog, why)));
	return (wtext(w, wfmt(w, "%s: the repositories could not be read%s%s",
	    prog, why != NULL ? ": " : "", why != NULL ? why : "")));
}

/* "  key   : value," of a repository, the value unquoted; NULL else. */
static char *
repo_value(char *line, const char *key)
{
	char	*p, *e;
	size_t	 len;

	p = line + strspn(line, " \t");
	len = strlen(key);
	if (strncmp(p, key, len) != 0 || (p[len] != ' ' && p[len] != ':'))
		return (NULL);
	p += len + strspn(p + len, " \t");
	if (*p != ':')
		return (NULL);
	p++;
	p += strspn(p, " \t");
	e = p + strlen(p);
	while (e > p && (e[-1] == ',' || e[-1] == ' ' || e[-1] == '\r'))
		*--e = '\0';
	if (*p == '"' && e > p + 1 && e[-1] == '"') {
		e[-1] = '\0';
		p++;
	}
	return (p);
}

/* Is name one of PKG_ENV's that reaching a repository takes? */
static bool
env_wanted(const char *name)
{
	size_t	len;

	len = strlen(name);
	return ((len > 6 && (strcmp(name + len - 6, "_PROXY") == 0 ||
	    strcmp(name + len - 6, "_proxy") == 0)) ||
	    strcmp(name, "NO_PROXY") == 0 || strcmp(name, "no_proxy") == 0 ||
	    strcmp(name, "HTTP_PROXY_AUTH") == 0 ||
	    strcmp(name, "FETCH_BIND_ADDRESS") == 0);
}

/*
 * What pkg is configured with there (pkg -vv): its repositories under
 * "Repositories:", each "  NAME: {" with its settings deeper, enabled
 * or not; IP_VERSION; PKG_ENV's proxies.  No repository when pkg did
 * not say.
 */
static void
pkg_conf(struct work *w, const char *jail, struct pkgconf *c)
{
	static const char *const vv[] = { "-vv" };
	struct execres	 res;
	struct pkgrepo	*r;
	char		*copy, *it, *line, *end, *v, *eq;
	bool		 in, inenv;
	size_t		 n;

	memset(c, 0, sizeof(*c));
	c->env = "";
	if (pkg_read(w, jail, vv, 1, &res) != 0 || res.out == NULL)
		return;
	r = wcalloc(w, 65, sizeof(*r));
	n = 0;
	in = inenv = false;
	copy = wstrndup(w, res.out, res.outlen);
	for (it = copy; (line = strsep(&it, "\n")) != NULL; ) {
		if (strcmp(line, "Repositories:") == 0) {
			in = true;
			continue;
		}
		if (strncmp(line, "PKG_ENV {", 9) == 0) {
			inenv = true;
			continue;
		}
		if (inenv) {
			/* "    NAME = "value";" */
			if (line[0] != ' ') {
				inenv = false;
				continue;
			}
			v = line + strspn(line, " \t");
			if ((eq = strstr(v, " = ")) == NULL)
				continue;
			*eq = '\0';
			eq += 3;
			end = eq + strlen(eq);
			while (end > eq && (end[-1] == ';' || end[-1] == ' '))
				*--end = '\0';
			if (*eq == '"' && end > eq + 1 && end[-1] == '"') {
				end[-1] = '\0';
				eq++;
			}
			if (env_wanted(v) && strchr(eq, '\n') == NULL)
				c->env = wfmt(w, "%s%s=%s\n", c->env, v, eq);
			continue;
		}
		if (!in) {
			if (strncmp(line, "IP_VERSION = ", 13) == 0)
				c->ip = (uint8_t)atoi(line + 13);
			continue;
		}
		if (line[0] != ' ') {
			in = false;
			continue;
		}
		/* Two spaces, the name, ": {"; its settings deeper. */
		if (line[1] == ' ' && line[2] != ' ' && line[2] != '\0' &&
		    (end = strstr(line + 2, ": {")) != NULL) {
			if (n >= 64)
				break;
			*end = '\0';
			r[n].name = line + 2;
			r[n].enabled = true;
			n++;
			continue;
		}
		if (n == 0)
			continue;
		if ((v = repo_value(line, "url")) != NULL)
			r[n - 1].url = v;
		else if ((v = repo_value(line, "enabled")) != NULL)
			r[n - 1].enabled = strcmp(v, "yes") == 0 ||
			    strcmp(v, "true") == 0;
		else if ((v = repo_value(line, "mirror_type")) != NULL)
			r[n - 1].srv = strcasecmp(v, "srv") == 0;
		else if ((v = repo_value(line, "ip_version")) != NULL)
			r[n - 1].ip = (uint8_t)atoi(v);
		else if ((v = repo_value(line, "priority")) != NULL)
			r[n - 1].priority = strtol(v, NULL, 10);
	}
	c->repos = r;
	c->nrepos = n;
}

/*
 * The repositories pkg is configured with there (pkg -vv), enabled or
 * not, by name.  *np 0 when pkg did not say.
 */
static void
pkg_repos(struct work *w, const char *jail, const char ***vp, size_t *np)
{
	struct pkgconf	 c;
	const char	**v;
	size_t		 i;

	pkg_conf(w, jail, &c);
	v = wcalloc(w, c.nrepos + 1, sizeof(*v));
	for (i = 0; i < c.nrepos; i++)
		v[i] = c.repos[i].name;
	*vp = v;
	*np = c.nrepos;
}

/*
 * The SRV record pkg follows for a repository's host (mirror_type SRV):
 * _<scheme>._tcp.<host>, the target of the lowest priority and, of
 * those, the heaviest weight.  False when there is none.
 */
static bool
srv_target(const char *scheme, const char *host, char *target, size_t tlen,
    int *portp)
{
	u_char		 ans[4096];
	char		 zone[MAXHOSTNAMELEN + 32], name[MAXDNAME];
	ns_msg		 msg;
	ns_rr		 rr;
	const u_char	*d;
	int		 len, i, n, best_pri, best_w, pri, wt;
	bool		 found;

	snprintf(zone, sizeof(zone), "_%s._tcp.%s", scheme, host);
	if ((len = res_query(zone, ns_c_in, ns_t_srv, ans, sizeof(ans))) <= 0 ||
	    ns_initparse(ans, len, &msg) == -1)
		return (false);
	n = ns_msg_count(msg, ns_s_an);
	found = false;
	best_pri = best_w = 0;
	for (i = 0; i < n; i++) {
		if (ns_parserr(&msg, ns_s_an, i, &rr) == -1 ||
		    ns_rr_type(rr) != ns_t_srv || ns_rr_rdlen(rr) < 7)
			continue;
		d = ns_rr_rdata(rr);
		pri = ns_get16(d);
		wt = ns_get16(d + 2);
		if (found && (pri > best_pri || (pri == best_pri &&
		    wt <= best_w)))
			continue;
		if (dn_expand(ns_msg_base(msg), ns_msg_end(msg), d + 6, name,
		    sizeof(name)) < 0)
			continue;
		found = true;
		best_pri = pri;
		best_w = wt;
		*portp = ns_get16(d + 4);
		strlcpy(target, name, tlen);
	}
	return (found);
}

/*
 * One fetch of u over the family flags names ("4", "6"): 'o' it
 * answered (an HTTP error is an answer), 'r' its name has no address of
 * that family, 'c' nothing reached it; what came, or why not, in why.
 */
static char
fetch_once(struct url *u, const char *flags, char *why, size_t len)
{
	struct url_stat	 us;
	FILE		*f;
	char		 buf[4096];
	size_t		 got;

	if ((f = fetchXGet(u, &us, flags)) != NULL) {
		got = fread(buf, 1, sizeof(buf), f);
		fclose(f);
		snprintf(why, len, "%zu bytes of meta.conf", got);
		return ('o');
	}
	snprintf(why, len, "%s", fetchLastErrString);
	switch (fetchLastErrCode) {
	case FETCH_RESOLV:
		return ('r');
	case FETCH_DOWN:
	case FETCH_NETWORK:
	case FETCH_TIMEOUT:
	case FETCH_ABORT:
		return ('c');
	default:
		snprintf(why, len, "it answered: %s", fetchLastErrString);
		return ('o');
	}
}

/*
 * u fetched over IPv6 and IPv4 at once, each by a child of its own, as
 * pkg's libcurl races them (RFC 8305): one family that has no way out
 * does not hide the other.  The first that answers is said; when none
 * does within secs, what each said.
 */
static void
fetch_both(struct url *u, int secs)
{
	static const char *const fam[2] = { "6", "4" };
	struct pollfd	 pfd[2];
	pid_t		 pid[2];
	char		 res[2], why[2][256], buf[258];
	time_t		 deadline;
	ssize_t		 n;
	int		 p[2], i, left, won, status;

	won = -1;
	for (i = 0; i < 2; i++) {
		res[i] = 0;
		snprintf(why[i], sizeof(why[i]), "nothing in %d seconds", secs);
		pfd[i].fd = -1;
		pfd[i].events = POLLIN;
		pid[i] = -1;
		if (pipe(p) == -1)
			continue;
		if ((pid[i] = fork()) == 0) {
			close(p[0]);
			res[i] = fetch_once(u, fam[i], why[i], sizeof(why[i]));
			dprintf(p[1], "%c%s", res[i], why[i]);
			_exit(0);
		}
		close(p[1]);
		if (pid[i] == -1)
			close(p[0]);
		else
			pfd[i].fd = p[0];
	}
	deadline = time(NULL) + secs + 1;
	while ((pfd[0].fd != -1 || pfd[1].fd != -1) && won == -1 &&
	    (left = (int)(deadline - time(NULL))) > 0) {
		if (poll(pfd, 2, left * 1000) <= 0)
			continue;
		for (i = 0; i < 2; i++) {
			if (pfd[i].fd == -1 || pfd[i].revents == 0)
				continue;
			if ((n = read(pfd[i].fd, buf, sizeof(buf) - 1)) > 0) {
				buf[n] = '\0';
				res[i] = buf[0];
				strlcpy(why[i], buf + 1, sizeof(why[i]));
				if (res[i] == 'o')
					won = i;
			}
			close(pfd[i].fd);
			pfd[i].fd = -1;
		}
	}
	for (i = 0; i < 2; i++) {
		if (pfd[i].fd != -1)
			close(pfd[i].fd);
		if (pid[i] > 0) {
			(void)kill(pid[i], SIGKILL);
			while (waitpid(pid[i], &status, 0) == -1 && errno == EINTR)
				;
		}
	}
	if (won != -1)
		printf("ok over IPv%s: %s\n", fam[won], why[won]);
	else if (res[0] == 'r' && res[1] == 'r')
		printf("fail resolve %s\n", why[1]);
	else
		printf("fail connect IPv6: %s; IPv4: %s\n", why[0], why[1]);
}

/*
 * The helper's side ("repo-reach url srv|plain ip secs", attached to the
 * jail or on the host): what there is to reach anything with, its
 * addresses that are neither loopback nor link-local of each family;
 * the URL's host by its SRV record when pkg follows one; then
 * <url>/meta.conf fetched (over each family at once unless one is
 * named: fetch_both()), with PKG_ENV's proxies read on standard input,
 * the certificate taken as it is (whether the repository answers is
 * asked, not whether it is trusted: pkg checks its signatures).  A line each, flushed, so that what was said before a
 * fetch that never ends reaches the daemon, which stops it:
 *
 *	addrs <IPv4> <IPv6>
 *	srv <target>:<port> | srv none
 *	url <what was fetched>
 *	ok <what came> | fail resolve|connect|other <why>
 */
int
repo_reach_helper(int argc, char **argv)
{
	struct ifaddrs		*ifa, *i;
	struct url		*u;
	const struct sockaddr_in6 *s6;
	char			 line[2048], target[MAXHOSTNAMELEN], *doc, *eq,
				 one[256], c;
	const char		*url;
	size_t			 len;
	int			 n4, n6, port, secs;

	if (argc != 5)
		return (2);
	n4 = n6 = 0;
	if (getifaddrs(&ifa) == 0) {
		for (i = ifa; i != NULL; i = i->ifa_next) {
			if (i->ifa_addr == NULL)
				continue;
			if (i->ifa_addr->sa_family == AF_INET &&
			    (ntohl(((const struct sockaddr_in *)(const void *)
			    i->ifa_addr)->sin_addr.s_addr) >> 24) != 127)
				n4++;
			s6 = (const struct sockaddr_in6 *)(const void *)
			    i->ifa_addr;
			if (i->ifa_addr->sa_family == AF_INET6 &&
			    !IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr) &&
			    !IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr))
				n6++;
		}
		freeifaddrs(ifa);
	}
	printf("addrs %d %d\n", n4, n6);
	fflush(stdout);
	while (fgets(line, sizeof(line), stdin) != NULL) {
		line[strcspn(line, "\n")] = '\0';
		if ((eq = strchr(line, '=')) == NULL)
			continue;
		*eq = '\0';
		if (env_wanted(line))
			(void)setenv(line, eq + 1, 1);
	}
	(void)setenv("SSL_NO_VERIFY_PEER", "1", 1);
	(void)setenv("SSL_NO_VERIFY_HOSTNAME", "1", 1);
	url = strncmp(argv[1], "pkg+", 4) == 0 ? argv[1] + 4 : argv[1];
	if ((u = fetchParseURL(url)) == NULL) {
		printf("fail other %s is not a URL fetch(3) takes\n", url);
		return (0);
	}
	if (strcmp(argv[2], "srv") == 0) {
		if (srv_target(u->scheme, u->host, target, sizeof(target),
		    &port)) {
			printf("srv %s:%d\n", target, port);
			strlcpy(u->host, target, sizeof(u->host));
			u->port = port;
		} else
			printf("srv none\n");
	}
	len = strlen(u->doc);
	while (len > 0 && u->doc[len - 1] == '/')
		len--;
	if (asprintf(&doc, "%.*s/meta.conf", (int)len, u->doc) == -1)
		return (1);
	free(u->doc);
	u->doc = doc;
	if (u->port > 0)
		printf("url %s://%s%s%s:%d%s\n", u->scheme, strchr(u->host,
		    ':') != NULL ? "[" : "", u->host, strchr(u->host, ':') !=
		    NULL ? "]" : "", u->port, u->doc);
	else
		printf("url %s://%s%s%s%s\n", u->scheme, strchr(u->host, ':') !=
		    NULL ? "[" : "", u->host, strchr(u->host, ':') != NULL ?
		    "]" : "", u->doc);
	fflush(stdout);
	secs = atoi(argv[4]);
	if (secs <= 0)
		secs = REPO_REACH_SEC;
	fetchTimeout = secs;
	if (strcmp(argv[3], "4") == 0 || strcmp(argv[3], "6") == 0) {
		c = fetch_once(u, argv[3], one, sizeof(one));
		printf("%s %s\n", c == 'o' ? "ok" : c == 'r' ? "fail resolve" :
		    "fail connect", one);
	} else
		fetch_both(u, secs);
	fetchFreeURL(u);
	return (0);
}

/*
 * What pkg will reach there, asked of the helper: the repository named,
 * or the enabled one first by priority; over ip (4, 6), else as the
 * repository or pkg is configured.  NULL when it answers, or when there
 * is nothing to ask (a file:// repository, none enabled, a helper that
 * could not say): pkg tells of those itself.  Otherwise what was tried
 * and what failed, and the likely cause, by what the jail (or host) has
 * of each family.
 */
static const char *
reach(struct work *w, const char *jail, uint8_t ip, const char *repo)
{
	struct pkgconf		 c;
	const struct pkgrepo	*r;
	struct execres		 res;
	char			*argv[9], *copy, *it, *line;
	const char		*fetched, *srv, *why, *where, *cause, *tried;
	size_t			 i;
	int			 jid, n4, n6, step;
	bool			 ok, fail, resolve, have;

	pkg_conf(w, jail, &c);
	r = NULL;
	for (i = 0; i < c.nrepos; i++) {
		if (repo != NULL && repo[0] != '\0') {
			if (strcmp(c.repos[i].name, repo) == 0)
				r = &c.repos[i];
			continue;
		}
		if (c.repos[i].enabled && (r == NULL || c.repos[i].priority >
		    r->priority))
			r = &c.repos[i];
	}
	if (r == NULL || r->url == NULL || (strncmp(r->url, "http", 4) != 0 &&
	    strncmp(r->url, "pkg+http", 8) != 0))
		return (NULL);
	jid = 0;
	if (jail != NULL && jail[0] != '\0' && (jid = jail_lookup(w,
	    jail)) < 0)
		return (NULL);
	if (ip != 4 && ip != 6)
		ip = r->ip == 4 || r->ip == 6 ? r->ip : c.ip == 4 || c.ip == 6 ?
		    c.ip : 0;
	argv[0] = (char *)(uintptr_t)opts.helper_bin;
	argv[1] = (char *)(uintptr_t)"--scope-helper";
	argv[2] = wfmt(w, "%d", jid);
	argv[3] = (char *)(uintptr_t)"repo-reach";
	argv[4] = (char *)(uintptr_t)r->url;
	argv[5] = (char *)(uintptr_t)(r->srv ? "srv" : "plain");
	argv[6] = wfmt(w, "%u", (unsigned int)ip);
	argv[7] = wfmt(w, "%d", opts.repo_reach_s);
	argv[8] = NULL;
	step = step_begin(w, STEP_DAEMON, "arcana-agent", "does the "
	    "repository %s answer from %s%s?", r->name, jail != NULL &&
	    jail[0] != '\0' ? "jail " : "this host", jail != NULL ? jail :
	    "");
	/* A dry run's: the check named, the repository not asked. */
	if (w->dry) {
		step_end(w, step, true, "does the repository %s answer from "
		    "%s%s? not asked: a dry run (it would fetch %s/meta.conf)",
		    r->name, jail != NULL && jail[0] != '\0' ? "jail " :
		    "this host", jail != NULL ? jail : "", r->url);
		return (NULL);
	}
	if (c.env[0] != '\0')
		exec_set_stdin(c.env, strlen(c.env));
	/* Its own deadline, a little past the fetch's. */
	exec_set_limit(opts.repo_reach_s + 2);
	(void)run_read(w, argv, &res);
	n4 = n6 = -1;
	fetched = srv = why = NULL;
	ok = fail = resolve = false;
	copy = wstrdup(w, res.out != NULL ? res.out : "");
	for (it = copy; (line = strsep(&it, "\n")) != NULL; ) {
		if (strncmp(line, "addrs ", 6) == 0)
			(void)sscanf(line + 6, "%d %d", &n4, &n6);
		else if (strncmp(line, "srv ", 4) == 0)
			srv = line + 4;
		else if (strncmp(line, "url ", 4) == 0)
			fetched = line + 4;
		else if (strncmp(line, "ok", 2) == 0)
			ok = true;
		else if (strncmp(line, "fail ", 5) == 0) {
			fail = true;
			resolve = strncmp(line + 5, "resolve ", 8) == 0;
			why = strchr(line + 5, ' ') != NULL ? strchr(line + 5,
			    ' ') + 1 : "";
		}
	}
	/* Answered; or the helper could not tell, which is no reason to
	 * hold pkg back. */
	if (ok || (!fail && !res.timedout)) {
		step_end(w, step, true, ok ? "it answers" : "not known: the "
		    "helper said nothing of it");
		return (NULL);
	}
	where = jail != NULL && jail[0] != '\0' ? wfmt(w, "jail %s", jail) :
	    "this host";
	have = jail != NULL && jail[0] != '\0';
	tried = wfmt(w, "%s%s%s", fetched != NULL ? fetched : r->url,
	    srv == NULL ? "" : strcmp(srv, "none") == 0 ? " (the host itself: "
	    "no SRV record for it)" : " (its host by SRV record)", ip == 4 ?
	    " over IPv4 (pkg -4)" : ip == 6 ? " over IPv6 (pkg -6)" : "");
	if (resolve)
		why = wfmt(w, "its name did not resolve (%s)", why);
	else if (fail)
		why = wfmt(w, "it failed (%s)", why);
	else
		why = wfmt(w, "nothing came in %d seconds", opts.repo_reach_s);
	if (n4 == 0 && n6 == 0)
		cause = wfmt(w, "%s has no address but loopback and "
		    "link-local: nothing reaches out of it", have ? "the jail" :
		    "this host");
	else if (n4 == 0 && n6 > 0)
		cause = wfmt(w, "%s has IPv6 addresses only: likely nothing "
		    "routes IPv6 out of it (the host's IPv6 way out), or the "
		    "mirror's IPv6 is down", have ? "the jail" : "this host");
	else if (n6 == 0 && n4 > 0)
		cause = wfmt(w, "%s has IPv4 addresses only: likely nothing "
		    "routes IPv4 out of it (the host's IPv4 way out, its NAT), "
		    "or the mirror's IPv4 is down", have ? "the jail" :
		    "this host");
	else if (ip == 4 || ip == 6)
		cause = wfmt(w, "pkg is held to IPv%u: likely nothing routes "
		    "IPv%u out of %s", (unsigned int)ip, (unsigned int)ip,
		    have ? "the jail" : "this host");
	else if (resolve)
		cause = wfmt(w, "%s's resolver (its resolv.conf) answers no "
		    "name, or reaches no server", have ? "the jail" :
		    "this host");
	else
		cause = "likely no route out, a firewall, or a mirror that is "
		    "down";
	step_end(w, step, false, "%s: %s", tried, why);
	return (wfmt(w, "the repository %s does not answer from %s: "
	    "fetching %s, %s; %s", r->name, where, tried, why, cause));
}

/*
 * Before pkg reaches for the repository there: NULL when it answers (or
 * cannot be asked), else why pkg is not started.
 */
const char *
pkg_reach(struct work *w, const char *jail, uint8_t ip, const char *repo)
{
	const char	*e;

	if ((e = reach(w, jail, ip, repo)) == NULL)
		return (NULL);
	return (wtext(w, wfmt(w, "%s.  pkg was not started (a job may say "
	    "not to check the repository first)", e)));
}

/*
 * After pkg was stopped for its silence: whether the repository answers
 * from there now, as what the stall's message says of its cause.
 */
static _Thread_local bool	in_note;

const char *
pkg_stall_note(struct work *w, const char *jail, uint8_t ip,
    const char *repo)
{
	const char	*e;

	if (in_note)
		return (NULL);
	in_note = true;
	e = reach(w, jail, ip, repo);
	in_note = false;
	if (e != NULL)
		return (wtext(w, wfmt(w, "asked after: %s", e)));
	return (wtext(w, "the repository answers from there when asked "
	    "after, so the stall was elsewhere: a mirror that stopped part "
	    "way, or a question pkg waits on"));
}

/* Is repo one of pkg's repositories there?  NULL, or why not. */
const char *
pkg_repo_check(struct work *w, const char *jail, const char *repo)
{
	const char	**v;
	const char	*p;
	size_t		 n, i;

	if (repo == NULL || repo[0] == '\0')
		return (NULL);
	for (p = repo; *p != '\0'; p++)
		if (!isalnum((unsigned char)*p) && strchr("-_.", *p) == NULL)
			return (wfmt(w, "'%s' is not a repository's name", repo));
	pkg_repos(w, jail, &v, &n);
	for (i = 0; i < n; i++)
		if (strcmp(v[i], repo) == 0)
			return (NULL);
	return (wfmt(w, "pkg has no repository %s%s%s", repo, jail != NULL &&
	    jail[0] != '\0' ? " in jail " : "", jail != NULL ? jail : ""));
}

/* The lines of "pkg version -vRl '<'" as packages. */
static void
parse_versions(struct work *w, const struct execres *res,
    struct package **outp, size_t *np)
{
	struct package	*v;
	char			*copy, *it, *line, *nv, *dash, *p, *e;
	size_t			 n, cap;

	v = NULL;
	n = cap = 0;
	copy = wstrndup(w, res->out, res->outlen);
	for (it = copy; (line = strsep(&it, "\n")) != NULL; ) {
		if ((nv = strsep(&line, " \t")) == NULL || *nv == '\0' ||
		    (dash = strrchr(nv, '-')) == NULL)
			continue;
		/*
		 * A package's line has the comparison after its name,
		 * "<"; what else pkg says, each repository's "FreeBSD-ports
		 * repository is up to date." among it, is no package.
		 */
		if (line != NULL)
			line += strspn(line, " \t");
		if (line == NULL || strchr("<=>?!", line[0]) == NULL ||
		    (line[1] != '\0' && line[1] != ' ' && line[1] != '\t'))
			continue;
		v = wgrow(w, v, n, &cap, sizeof(*v));
		memset(&v[n], 0, sizeof(v[n]));
		v[n].name = wtext(w, wstrndup(w, nv, (size_t)(dash - nv)));
		v[n].installed = wtext(w, dash + 1);
		if (line != NULL && (p = strstr(line, "remote has ")) != NULL) {
			p += 11;
			if ((e = strchr(p, ')')) != NULL)
				*e = '\0';
			v[n].available = wtext(w, p);
		}
		n++;
	}
	*outp = v;
	*np = n;
}

/* Package names as pkg(8) takes them. */
static bool
valid_pkg(const char *s)
{

	if (*s == '\0' || *s == '-' || strlen(s) > 128)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("_.+-", *s) == NULL)
			return (false);
	return (true);
}

/* A jail named in a request must be running for pkg -j. */
static const char *
check_jail(struct work *w, const char *jail)
{

	if (jail == NULL || *jail == '\0')
		return (NULL);
	if (jail_lookup(w, jail) < 0)
		return (wfmt(w, "jail '%s' is not running; pkg -j needs it",
		    jail));
	return (NULL);
}

/*
 * The packages installed, from the host's own database: name, version,
 * whether it came automatically, its size, origin and comment, a line
 * each with tabs between (pkg query).
 */
static int
installed(struct work *w, const char *jail, struct pkg_read *rsp)
{
	static const char *const query[] = { "query",
	    "%n\t%v\t%a\t%sb\t%o\t%c" };
	struct package	*v;
	struct execres		 res;
	char			*copy, *it, *line, *f[6];
	size_t			 n, i, cap;

	if (pkg_run(w, jail, false, 0, query, 2, &res) != 0) {
		rsp->error = wtext(w, exec_error(w, &res, "pkg query"));
		return (0);
	}
	v = NULL;
	n = cap = 0;
	copy = wstrndup(w, res.out != NULL ? res.out : "", res.outlen);
	for (it = copy; (line = strsep(&it, "\n")) != NULL; ) {
		for (i = 0; i < 6 && (f[i] = strsep(&line, "\t")) != NULL; i++)
			;
		if (i < 5 || f[0][0] == '\0')
			continue;
		v = wgrow(w, v, n, &cap, sizeof(*v));
		memset(&v[n], 0, sizeof(v[n]));
		v[n].name = wtext(w, f[0]);
		v[n].installed = wtext(w, f[1]);
		v[n].has_automatic = true;
		v[n].automatic = strcmp(f[2], "1") == 0;
		v[n].has_size = true;
		v[n].size = strtoull(f[3], NULL, 10);
		v[n].origin = wtext(w, f[4]);
		v[n].comment = i > 5 ? wtext(w, f[5]) : NULL;
		n++;
	}
	rsp->packages = v;
	rsp->npackages = n;
	rsp->ok = true;
	return (0);
}

int
do_packages(struct work *w, const char *jail, bool refresh, bool inst,
    uint8_t ip, bool anyos, bool nocheck, struct pkg_read *rsp)
{
	static const char *const update[] = { "update", "-q" };
	static const char *const version[] = { "version", "-vRl", "<" };
	struct package	*v;
	struct execres		 res;
	const char		*e;
	size_t			 n;

	memset(rsp, 0, sizeof(*rsp));
	if ((e = check_jail(w, jail)) != NULL) {
		rsp->error = e;
		return (0);
	}
	/* The repositories an upgrade or an install may be held to. */
	{
		const char	**rv;

		pkg_repos(w, jail, &rv, &rsp->nrepos);
		rsp->repos = rv;
	}
	/* A jail's base: pkgbase when FreeBSD-runtime is a package of it. */
	if (jail != NULL && *jail != '\0') {
		static const char *const runtime[] = { "info", "-q",
		    "FreeBSD-runtime" };

		rsp->has_pkgbase = true;
		rsp->pkgbase = pkg_run(w, jail, false, 0, runtime, 3, &res) == 0;
	}
	if (inst)
		return (installed(w, jail, rsp));
	/* pkg update reaches for the repositories: only when they answer. */
	if (refresh && !nocheck && (e = pkg_reach(w, jail, ip, NULL)) != NULL) {
		rsp->error = e;
		return (0);
	}
	/* A repository for a newer FreeBSD is named as such, for the
	 * console to ask whether to read past it. */
	if (refresh && pkg_run(w, jail, anyos, ip, update, 2, &res) != 0) {
		rsp->error = (e = pkg_repo_error(w, &res, "pkg update")) != NULL ? e :
		    wtext(w, exec_error(w, &res, "pkg update"));
		return (0);
	}
	/* pkg version exits 0 with matches and 1 without, as grep does;
	 * a repository it could not read is an error whatever it exits. */
	if (pkg_run(w, jail, anyos, ip, version, 3, &res) != 0 && ((e =
	    pkg_repo_error(w, &res, "pkg version")) != NULL || res.status != 1)) {
		rsp->error = e != NULL ? e : wtext(w, exec_error(w, &res,
		    "pkg version"));
		return (0);
	}
	parse_versions(w, &res, &v, &n);
	rsp->packages = v;
	rsp->npackages = n;
	rsp->ok = true;
	return (0);
}

/*
 * The running jails whose base is pkgbase (FreeBSD-runtime one of their
 * packages, pkg -j info), for the host's read: a plain pkg upgrade of
 * every jail moves their FreeBSD base too, which the page says before
 * it.  None when the jails cannot be listed.
 */
void
pkg_pkgbase_jails(struct work *w, const char *const **vp, size_t *np)
{
	static const char *const runtime[] = { "info", "-q",
	    "FreeBSD-runtime" };
	struct execres	 res;
	struct jinfo	*list;
	const char	**v, *e;
	size_t		 n, i, k;

	*vp = NULL;
	*np = 0;
	list = NULL;
	n = 0;
	if (jails_running(w, &list, &n, &e) != 0 || n == 0)
		return;
	v = wcalloc(w, n + 1, sizeof(*v));
	for (i = k = 0; i < n; i++)
		if (!list[i].dying && list[i].name != NULL &&
		    pkg_run(w, list[i].name, false, 0, runtime, 3, &res) == 0)
			v[k++] = list[i].name;
	*vp = v;
	*np = k;
}

/*
 * Every running jail's packages upgraded, one jail after the other: one
 * without pkg (never bootstrapped, pkg -N says) left out and said so,
 * one that fails not stopping the rest; what each did is a step of the
 * trace, and the error, when there is one, names each that failed.
 */
static int
upgrade_every_jail(struct work *w, const struct pkg_upgrade *rq,
    struct pkg_upgraded *rsp)
{
	struct pkg_upgrade		 one;
	struct pkg_upgraded		 r;
	struct execres			 res;
	struct jinfo			*list;
	const char			*e, *failed, *skipped;
	static const char *const	 bootstrapped[] = { "-N" };
	size_t				 n, i, done;

	memset(rsp, 0, sizeof(*rsp));
	list = NULL;
	n = 0;
	if (jails_running(w, &list, &n, &e) != 0) {
		rsp->error = e != NULL ? e : "the jails could not be listed";
		return (0);
	}
	failed = skipped = NULL;
	done = 0;
	rsp->has_upgraded = true;
	rsp->upgraded = 0;
	for (i = 0; i < n; i++) {
		if (list[i].dying || list[i].name == NULL)
			continue;
		if (pkg_read(w, list[i].name, bootstrapped, 1, &res) != 0) {
			skipped = skipped == NULL ? list[i].name : wfmt(w,
			    "%s, %s", skipped, list[i].name);
			continue;
		}
		one = *rq;
		one.jail = list[i].name;
		memset(&r, 0, sizeof(r));
		(void)do_pkg_upgrade(w, &one, &r);
		if (!r.ok)
			failed = wfmt(w, "%s%s%s: %s", failed != NULL ? failed :
			    "", failed != NULL ? "; " : "", list[i].name,
			    r.error != NULL ? r.error : "failed");
		else
			rsp->upgraded += r.upgraded;
		done++;
	}
	if (skipped != NULL)
		logmsg(LOG_INFO, "pkg upgrade of every jail: without pkg, "
		    "left out: %s", skipped);
	if (failed != NULL)
		rsp->error = wfmt(w, "pkg upgrade failed in %s", failed);
	else if (done == 0)
		rsp->error = skipped != NULL ? wfmt(w, "no running jail has pkg "
		    "(%s have none)", skipped) : "no jail is running";
	else
		rsp->ok = true;
	return (0);
}

int
do_pkg_upgrade(struct work *w, const struct pkg_upgrade *rq,
    struct pkg_upgraded *rsp)
{
	/* -U: from the catalogue pkg has, the repository not asked again
	 * (pkg upgrade read it just now, or could not). */
	const char		*version[] = { "version", "-U", "-vRl", "<",
				    NULL, NULL, NULL };
	struct package	*v;
	struct execres		 res;
	const char		**args, *e, *p;
	size_t			 n, i, nv;

	if (rq->jail != NULL && strcmp(rq->jail, "*") == 0)
		return (upgrade_every_jail(w, rq, rsp));
	memset(rsp, 0, sizeof(*rsp));
	if ((e = check_jail(w, rq->jail)) != NULL ||
	    (e = pkg_repo_check(w, rq->jail, rq->pkg_repo)) != NULL ||
	    (!rq->no_repo_check && (e = pkg_reach(w, rq->jail, rq->pkg_ip,
	    rq->pkg_repo)) != NULL)) {
		rsp->error = e;
		return (0);
	}
	nv = 4;
	if (rq->pkg_repo != NULL && rq->pkg_repo[0] != '\0') {
		/* What that repository has newer: pkg version -R -r. */
		version[2] = "-vR";
		version[3] = "-r";
		version[4] = rq->pkg_repo;
		version[5] = "-l";
		version[6] = "<";
		nv = 7;
	}
	for (i = 0; i < rq->names.n; i++)
		if (rq->names.v[i] == NULL || !valid_pkg(rq->names.v[i])) {
			rsp->error = wfmt(w, "'%s' is not a package name",
			    rq->names.v[i] != NULL ? rq->names.v[i] : "");
			return (0);
		}
	args = wcalloc(w, rq->names.n + 6, sizeof(*args));
	n = 0;
	args[n++] = "upgrade";
	/* From that repository alone. */
	if (rq->pkg_repo != NULL && rq->pkg_repo[0] != '\0') {
		args[n++] = "-r";
		args[n++] = rq->pkg_repo;
	}
	args[n++] = rq->dry_run ? "-n" : "-y";
	for (i = 0; i < rq->names.n; i++)
		args[n++] = rq->names.v[i];
	/* pkg upgrade -n exits 1 when it would change nothing. */
	if (pkg_run(w, rq->jail, rq->ignore_osversion, rq->pkg_ip, args, n,
	    &res) != 0 &&
	    !(rq->dry_run && res.status == 1)) {
		/* A repository it could not read is said as such, the newer
		 * FreeBSD's named, whatever pkg exited; a fetch that failed
		 * with what pkg said of it. */
		rsp->error = pkg_error(w, &res, "pkg upgrade");
	} else if ((e = pkg_repo_error(w, &res, "pkg upgrade")) != NULL) {
		rsp->error = e;
	} else {
		rsp->ok = true;
		rsp->has_upgraded = true;
		rsp->upgraded = 0;
		for (p = res.out; (p = strstr(p, "Upgrading ")) != NULL; p += 10)
			rsp->upgraded++;
	}
	/* What is still pending, for the reply. */
	if (pkg_exec(w, rq->jail, false, rq->pkg_ip, version, nv, &res,
	    true) == 0 || res.status == 1) {
		parse_versions(w, &res, &v, &n);
		rsp->packages = v;
		rsp->npackages = n;
	}
	return (0);
}

/*
 * pkg clean -y: the cached packages no longer needed, or no longer in
 * the repository, deleted; with all, the whole cache (-a).
 */
/* pkg install -y of the packages named, there or in a running jail. */
int
do_pkg_install(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	struct execres	 res;
	const char	**args, *e;
	size_t		 i, n;

	if ((e = check_jail(w, sp->jail)) != NULL ||
	    (e = pkg_repo_check(w, sp->jail, sp->pkg_repo)) != NULL ||
	    (!sp->no_repo_check && (e = pkg_reach(w, sp->jail, sp->has_pkg_ip ?
	    sp->pkg_ip : 0, sp->pkg_repo)) != NULL)) {
		*errp = e;
		return (-1);
	}
	args = wcalloc(w, sp->names.n + 5, sizeof(*args));
	n = 0;
	args[n++] = "install";
	if (sp->pkg_repo != NULL && sp->pkg_repo[0] != '\0') {
		args[n++] = "-r";
		args[n++] = sp->pkg_repo;
	}
	args[n++] = "-y";
	for (i = 0; i < sp->names.n; i++) {
		if (sp->names.v[i] == NULL || !valid_pkg(sp->names.v[i])) {
			*errp = wfmt(w, "'%s' is not a package name",
			    sp->names.v[i] != NULL ? sp->names.v[i] : "");
			return (-1);
		}
		args[n++] = sp->names.v[i];
	}
	if (pkg_run(w, sp->jail, sp->force, sp->has_pkg_ip ? sp->pkg_ip : 0,
	    args, n, &res) != 0) {
		*errp = pkg_error(w, &res, "pkg install");
		return (-1);
	}
	if ((e = pkg_repo_error(w, &res, "pkg install")) != NULL) {
		*errp = e;
		return (-1);
	}
	return (0);
}

int
do_pkg_clean(struct work *w, const char *jail, bool all, const char **errp)
{
	static const char *const some[] = { "clean", "-y" };
	static const char *const every[] = { "clean", "-ay" };
	struct execres	res;
	const char	*e;

	if ((e = check_jail(w, jail)) != NULL) {
		*errp = e;
		return (-1);
	}
	if (pkg_run(w, jail, false, 0, all ? every : some, 2, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "pkg clean"));
		return (-1);
	}
	return (0);
}


/* pkg's words when its vulnerability database was never fetched. */
#define	PKG_NO_VULNXML	"does not exist"

/* A package of rsp's by name, or NULL. */
static struct package *
listed_pkg(struct pkg_read *rsp, const char *name, size_t len)
{
	size_t	i;

	for (i = 0; i < rsp->npackages; i++)
		if (strlen(rsp->packages[i].name) == len &&
		    strncmp(rsp->packages[i].name, name, len) == 0)
			return (&rsp->packages[i]);
	return (NULL);
}

/* An id more of p's, once. */
static void
vuln_add(struct work *w, struct package *p, const char *id)
{
	const char	**v;
	size_t		  i;

	for (i = 0; i < p->nvulns; i++)
		if (strcmp(p->vulns[i], id) == 0)
			return;
	v = wcalloc(w, p->nvulns + 1, sizeof(*v));
	if (p->nvulns > 0)
		memcpy(v, p->vulns, p->nvulns * sizeof(*v));
	v[p->nvulns++] = wtext(w, id);
	p->vulns = v;
}

/*
 * The vulnerabilities of rsp's packages, there or in a running jail, as
 * pkg audit reads them from the database fetched before (VuXML's,
 * /var/db/pkg/vuln.xml): never fetched here, that is a job the admin
 * asks for (pkg audit -F, do_pkg_audit_fetch()).  pkg says, of each
 * vulnerable package, "name-version is vulnerable:", then each issue:
 * its line, its "CVE: id" lines, its "WWW: .../<vuxml id>.html"; an
 * issue with no CVE is named by its VuXML id.  pkg exits 1 when one is
 * vulnerable.  rsp->audit_error: the database not fetched, or what pkg
 * said when it could not read it.
 */
void
pkg_audit(struct work *w, const char *jail, struct pkg_read *rsp)
{
	static const char *const audit[] = { "audit" };
	struct execres	 res;
	struct package	*p;
	char		*copy, *it, *line, *t, *e;
	const char	*sp;
	bool		 any, cve;

	if (pkg_read(w, jail, audit, 1, &res) != 0 && res.status != 1) {
		rsp->audit_error = wtext(w, exec_error(w, &res, "pkg audit"));
		return;
	}
	if (res.err != NULL && memmem(res.err, res.errlen, PKG_NO_VULNXML,
	    strlen(PKG_NO_VULNXML)) != NULL) {
		rsp->audit_error = "the vulnerability database is not fetched "
		    "(pkg audit -F): fetch it to know which packages are "
		    "vulnerable";
		return;
	}
	p = NULL;
	any = cve = false;
	copy = wstrndup(w, res.out != NULL ? res.out : "", res.outlen);
	for (it = copy; (line = strsep(&it, "\n")) != NULL; ) {
		sp = line + strspn(line, " \t");
		if (line[0] != ' ' && (t = strstr(line, " is vulnerable:")) !=
		    NULL) {
			*t = '\0';
			any = true;
			p = (e = strrchr(line, '-')) != NULL ? listed_pkg(rsp,
			    line, (size_t)(e - line)) : NULL;
			if (p != NULL)
				p->vulnerable = true;
			cve = false;
		} else if (p != NULL && strncmp(sp, "CVE: ", 5) == 0) {
			vuln_add(w, p, sp + 5);
			cve = true;
		} else if (p != NULL && strncmp(sp, "WWW: ", 5) == 0) {
			/* The issue ends: one without a CVE by its VuXML id. */
			if (!cve && (t = strrchr(sp, '/')) != NULL) {
				t = wstrdup(w, t + 1);
				if ((e = strstr(t, ".html")) != NULL)
					*e = '\0';
				if (*t != '\0')
					vuln_add(w, p, t);
			}
			cve = false;
		}
	}
	/* Exited 1 with nothing vulnerable said: it failed. */
	if (res.status == 1 && !any)
		rsp->audit_error = wtext(w, exec_error(w, &res, "pkg audit"));
}

/*
 * pkg audit -F: the vulnerability database fetched there, or in a
 * running jail (the jail's own), as the admin asked.  pkg audits the
 * packages after, and exits 1 when one is vulnerable: fetched still.
 */
int
do_pkg_audit_fetch(struct work *w, const char *jail, const char **errp)
{
	static const char *const fetch[] = { "audit", "-F" };
	struct execres	 res;
	const char	*e;

	if ((e = check_jail(w, jail)) != NULL) {
		*errp = e;
		return (-1);
	}
	if (pkg_run(w, jail, false, 0, fetch, 2, &res) != 0 &&
	    !(res.status == 1 && res.out != NULL && memmem(res.out,
	    res.outlen, " is vulnerable:", 15) != NULL)) {
		*errp = wtext(w, exec_error(w, &res, "pkg audit -F"));
		return (-1);
	}
	return (0);
}
