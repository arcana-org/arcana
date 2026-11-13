/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the threat feeds' tables.  The console fetches a feed, a list
 * of scanners', spammers' or abusers' prefixes, and sends it whole; it
 * becomes an ipfw(8) table of type addr, IPv4 and IPv6 in one, kept in
 * a file beside the kept rules (feeds/<table>) and filled into a scratch
 * table of the same set that is then swapped in (ipfw table T swap S),
 * so that a lookup sees the old entries or the new ones, never half.
 * The prefixes, the table's name and the script that loads it (under
 * the lock ipfeeds(8)'s loads of the table take) are libipfeeds'
 * (ipfeeds(3)); what a feed's table is, where it is kept and when it is
 * filled, Arcana's.
 *
 * The file is the mark of a table a feed made: no other is replaced or
 * destroyed, but an empty one of type addr that a rule made by naming
 * it.  The kernel forgets the tables at a reboot, and Apply makes set
 * 1's anew and swaps them in: the agent fills them again from the files
 * when it starts and before Apply's swap.  An entry covering the address
 * the request came from, the console's, is left out.  The host's alone:
 * a vnet jail's firewall is not fed.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <ucl.h>
#include <unistd.h>

#include <ipfeeds.h>

#include "agent.h"
#include "collect.h"

#define	FEED_MAX	250000		/* entries of a table */
#define	FEED_TEXT_MAX	(8 * 1024 * 1024)

static pthread_mutex_t	feeds_lock = PTHREAD_MUTEX_INITIALIZER;

/* A table's name a feed may give: one ipfw takes (letters, digits, _ .
 * -, not digits alone), 48 at most. */
bool
feed_name_ok(const char *s)
{

	return (s != NULL && strlen(s) <= 48 && ipf_ipfw_table_ok(s));
}

/* Where the feeds' files are: feeds/ beside Arcana's own kept rules
 * (not /etc's, where config-files system moves them). */
static const char *
feeds_dir(struct work *w)
{
	const char	*s, *r = cf_ipfw_home();

	if ((s = strrchr(r, '/')) == NULL)
		return ("feeds");
	return (wfmt(w, "%.*s/feeds", (int)(s - r), r));
}

/*
 * The entries of a text, one a line (what follows # left out), made
 * canonical, sorted, each once, none another covers, into l (its memory
 * w's); those covering the address of af and a (none: af 0) left out
 * and counted.  -1 and why when one is no prefix or there are too many.
 */
static int
entries_of(struct work *w, const char *text, int af, const uint8_t *a,
    struct ipf_list *l, size_t *leftp, const char **errp)
{
	struct ipf_prefix	 peer;
	struct ipf_parse	 ps;
	char			 err[256];
	int			 rc;

	*leftp = 0;
	memset(&ps, 0, sizeof(ps));
	ps.format = IPF_FORMAT_PLAIN;
	ps.strict = true;
	ps.keep_reserved = true;
	ps.max = FEED_MAX;
	if (af == AF_INET || af == AF_INET6) {
		memset(&peer, 0, sizeof(peer));
		peer.af = af;
		peer.len = af == AF_INET ? 32 : 128;
		memcpy(peer.addr, a, af == AF_INET ? 4 : 16);
		ps.protect = &peer;
		ps.nprotect = 1;
	}
	ipf_list_init(l);
	rc = ipf_parse(&ps, text, strlen(text), l, err, sizeof(err));
	(void)wadopt(w, l->v);
	if (rc != 0) {
		*errp = wtext(w, wstrdup(w, err));
		return (-1);
	}
	*leftp = ps.dropped[IPF_DROP_PROTECTED];
	(void)ipf_list_aggregate(l);
	return (0);
}

/* A feed's file: its feed, when, and its entries, as written. */
struct feedfile {
	const char	*feed;
	time_t		 updated;
	const char	*body;		/* the entries, a line each */
	size_t		 count;
};

static bool
file_of(struct work *w, const char *name, struct feedfile *ff)
{
	struct stat	 sb;
	char		*text, *p;
	const char	*path;
	ssize_t		 r;
	int		 fd;

	memset(ff, 0, sizeof(*ff));
	path = wfmt(w, "%s/%s", feeds_dir(w), name);
	if ((fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) == -1)
		return (false);
	if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_size >
	    FEED_TEXT_MAX) {
		close(fd);
		return (false);
	}
	text = wcalloc(w, (size_t)sb.st_size + 1, 1);
	r = read(fd, text, (size_t)sb.st_size);
	close(fd);
	if (r != sb.st_size)
		return (false);
	/* "# arcana feed <feed>" and "# updated <seconds>" first. */
	p = text;
	while (*p == '#') {
		char	*nl = p + strcspn(p, "\n");

		if (*nl != '\0')
			*nl++ = '\0';
		if (strncmp(p, "# arcana feed ", 14) == 0)
			ff->feed = p + 14;
		else if (strncmp(p, "# updated ", 10) == 0)
			ff->updated = (time_t)strtoll(p + 10, NULL, 10);
		p = nl;
	}
	if (ff->feed == NULL)
		return (false);
	ff->body = p;
	for (; *p != '\0'; p++)
		if (*p == '\n')
			ff->count++;
	return (true);
}

/* A table of the kernel's, as table all info tells it. */
struct ktable {
	const char	*name;
	int		 set;
	const char	*type;
	long		 items;
};

static size_t
ktables(struct work *w, struct ktable **tp)
{
	struct execres	 res;
	struct ktable	*t;
	char		*argv[5], *text, *p, *line, *s;
	size_t		 n, cap;

	*tp = NULL;
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"table";
	argv[2] = (char *)(uintptr_t)"all";
	argv[3] = (char *)(uintptr_t)"info";
	argv[4] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL)
		return (0);
	text = wstrndup(w, res.out, res.outlen);
	cap = 16;
	t = wcalloc(w, cap, sizeof(*t));
	n = 0;
	for (p = text; (line = strsep(&p, "\n")) != NULL; ) {
		if (strncmp(line, "--- table(", 10) == 0) {
			if (n == cap) {
				struct ktable	*nt;

				nt = wcalloc(w, cap * 2, sizeof(*t));
				memcpy(nt, t, n * sizeof(*t));
				t = nt;
				cap *= 2;
			}
			line += 10;
			s = strstr(line, "), set(");
			line[strcspn(line, ")")] = '\0';
			t[n].name = line;
			t[n].set = s != NULL ? (int)strtol(s + 7, NULL, 10) : 0;
			t[n].items = -1;
			n++;
		} else if (n > 0 && (s = strstr(line, " type: ")) != NULL) {
			s += 7;
			s[strcspn(s, ", ")] = '\0';
			t[n - 1].type = s;
		} else if (n > 0 && (s = strstr(line, "items: ")) != NULL)
			t[n - 1].items = strtol(s + 7, NULL, 10);
	}
	*tp = t;
	return (n);
}

static const struct ktable *
ktable(const struct ktable *t, size_t n, const char *name, int set)
{
	size_t	i;

	for (i = 0; i < n; i++)
		if (strcmp(t[i].name, name) == 0 && (set < 0 || t[i].set == set))
			return (&t[i]);
	return (NULL);
}

static long
tables_sets(struct work *w)
{
	struct execres	 res;
	char		*argv[4];
	int		 v;
	size_t		 len;

	if (strcmp(opts.sysctl_bin, "/sbin/sysctl") == 0) {
		len = sizeof(v);
		return (sysctlbyname("net.inet.ip.fw.tables_sets", &v, &len,
		    NULL, 0) == 0 ? v : 0);
	}
	argv[0] = (char *)(uintptr_t)opts.sysctl_bin;
	argv[1] = (char *)(uintptr_t)"-n";
	argv[2] = (char *)(uintptr_t)"net.inet.ip.fw.tables_sets";
	argv[3] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL)
		return (0);
	return (strtol(wstrndup(w, res.out, res.outlen), NULL, 10));
}

/*
 * The set a feed's table is in: with tables_sets=1 that of the first
 * rule of the kernel's that names it, else 0.
 */
static int
table_set(struct work *w, const char *name)
{
	struct execres	 res;
	char		*argv[4], *text, *p, *line, *t, *want;
	int		 set;

	if (tables_sets(w) != 1)
		return (0);
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"-S";
	argv[2] = (char *)(uintptr_t)"list";
	argv[3] = NULL;
	if (run_exec_max(w, argv, &res, 16 * 1024 * 1024) != 0 ||
	    res.out == NULL)
		return (0);
	want = wfmt(w, "table(%s)", name);
	text = wstrndup(w, res.out, res.outlen);
	for (p = text; (line = strsep(&p, "\n")) != NULL; ) {
		if ((t = strstr(line, " set ")) == NULL || strstr(line, want) ==
		    NULL)
			continue;
		set = (int)strtol(t + 5, NULL, 10);
		if (set >= 0 && set < 31)
			return (set);
	}
	return (0);
}

/* ipfw with the words, in set when set >= 0; 0 or -1 and why. */
static int
fw(struct work *w, const char **errp, int set, ...)
{
	struct execres	 res;
	va_list		 ap;
	char		*argv[16];
	const char	*a;
	int		 n;

	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[n++] = (char *)(uintptr_t)"-q";
	if (set >= 0) {
		argv[n++] = (char *)(uintptr_t)"set";
		argv[n++] = wfmt(w, "%d", set);
	}
	va_start(ap, set);
	while ((a = va_arg(ap, const char *)) != NULL && n < 15)
		argv[n++] = (char *)(uintptr_t)a;
	va_end(ap);
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		if (errp != NULL)
			*errp = wtext(w, exec_error(w, &res, "ipfw"));
		return (-1);
	}
	return (0);
}

/*
 * The table filled whole with the list l, in set
 * (-1: tables_sets is 0 and a table is in every set), by libipfeeds'
 * sh(1) script (ipf_ipfw_script()) run whole: under the lock of the
 * table's loads, which ipfeeds(8)'s take too (lockf(1) on
 * /var/run/ipfeeds.<table>.lock, --root's own under it), a scratch
 * table filled by one ipfw run and swapped in, the table made when there
 * is none, the scratch destroyed.  A scratch there already is the
 * script's to destroy only when it is the feed's: its load file left
 * beside the feeds' by a fill cut short, or empty of type addr, as the
 * main table is checked; any other is the host's own, and the feed is
 * refused before the script runs.  The script's file is closed when it
 * runs: the agent holds no lock of its.
 */
static int
fill(struct work *w, const char *name, int set, const struct ipf_list *l,
    const char **errp)
{
	struct execres	 res;
	struct ktable	*kt;
	const struct ktable *t;
	struct stat	 sb;
	FILE		*fp;
	char		*buf, *argv[3];
	const char	*scratch, *path, *lockdir;
	size_t		 len, nk;
	int		 fd, rc;

	scratch = wfmt(w, "%s_load", name);
	path = wfmt(w, "%s/.%s.load", feeds_dir(w), name);
	nk = ktables(w, &kt);
	if ((t = ktable(kt, nk, scratch, set)) != NULL && lstat(path, &sb) ==
	    -1 && (t->items != 0 || (t->type != NULL && strcmp(t->type,
	    "addr") != 0))) {
		*errp = wfmt(w, "table %s, the feed's scratch, is the host's "
		    "own: it is not destroyed. Give the feed another table, or "
		    "move that one", scratch);
		return (-1);
	}
	lockdir = opts.root != NULL ? wfmt(w, "%s/var/run", opts.root) : NULL;
	if ((fp = open_memstream(&buf, &len)) == NULL) {
		*errp = "out of memory";
		return (-1);
	}
	rc = ipf_ipfw_script(fp, opts.ipfw_bin, name, set, l, lockdir);
	if (fclose(fp) != 0 || rc != 0) {
		free(buf);
		*errp = rc != 0 ? wfmt(w, "table %s: no script of libipfeeds' "
		    "loads it", name) : "out of memory";
		return (-1);
	}
	wadopt(w, buf);
	if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	    O_NOFOLLOW, 0600)) == -1 || write(fd, buf, len) != (ssize_t)len) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		if (fd != -1)
			close(fd);
		return (-1);
	}
	close(fd);
	argv[0] = (char *)(uintptr_t)"/bin/sh";
	argv[1] = (char *)(uintptr_t)path;
	argv[2] = NULL;
	rc = run_exec(w, argv, &res);
	(void)unlink(path);
	if (rc != 0) {
		*errp = wtext(w, exec_error(w, &res, "ipfw"));
		return (-1);
	}
	return (0);
}

int
feed_load(struct work *w, const struct feed_req *rq, struct feed_rsp *rs,
    const char **errp)
{
	struct feedfile		 ff;
	struct ipf_list		 v, old;
	struct ktable		*kt;
	const struct ktable	*t;
	const char		*dir, *path, *tmp;
	struct stat		 sb;
	FILE			*fp;
	char			*buf, p[IPF_PREFIX_STRLEN];
	size_t			 n, left, i, len, nk, add, rem;
	int			 set, fd, step;
	bool			 had;

	memset(rs, 0, sizeof(*rs));
	if (w->jail != NULL) {
		*errp = "a vnet jail's firewall is not fed: the host's alone";
		return (-1);
	}
	if (!feed_name_ok(rq->name)) {
		*errp = "a feed's table is named by letters, digits, _ . and -, "
		    "48 at most";
		return (-1);
	}
	if (rq->feed == NULL || rq->feed[0] == '\0' || strlen(rq->feed) > 64 ||
	    strchr(rq->feed, '\n') != NULL) {
		*errp = "the feed's name, of a line, is needed";
		return (-1);
	}
	if (rq->entries == NULL || strlen(rq->entries) > FEED_TEXT_MAX) {
		*errp = "the entries, 8 MB at most, are needed";
		return (-1);
	}
	if (entries_of(w, rq->entries, rq->peer_af, rq->peer, &v, &left,
	    errp) != 0)
		return (-1);
	n = v.n;
	rs->left_out = (uint32_t)left;
	pthread_mutex_lock(&feeds_lock);
	had = file_of(w, rq->name, &ff);
	ipf_list_init(&old);
	if (had && entries_of(w, ff.body, 0, NULL, &old, &i, errp) != 0) {
		had = false;
		ipf_list_init(&old);
	}
	ipf_list_diff(&old, &v, &add, &rem);
	rs->added = (uint32_t)add;
	rs->removed = (uint32_t)rem;
	rs->count = (uint32_t)n;
	/* A table there that no feed made, with entries: the host's own. */
	nk = ktables(w, &kt);
	set = table_set(w, rq->name);
	if ((t = ktable(kt, nk, rq->name, tables_sets(w) == 1 ? set : -1)) !=
	    NULL) {
		if (!had && (t->items != 0 || (t->type != NULL && strcmp(t->type,
		    "addr") != 0))) {
			pthread_mutex_unlock(&feeds_lock);
			*errp = wfmt(w, "table %s is the host's own, not a feed's: "
			    "it is not replaced. Give the feed another table",
			    rq->name);
			return (-1);
		}
	}
	rs->set = (uint8_t)set;
	if (rq->dry_run) {
		pthread_mutex_unlock(&feeds_lock);
		step = step_begin(w, STEP_DAEMON, "feed", "%s", rq->name);
		step_end(w, step, true, "would have %zu entries: %u added, %u "
		    "removed", n, rs->added, rs->removed);
		return (0);
	}
	/* The file first, so that a restart fills the table again. */
	dir = feeds_dir(w);
	if (stat(dir, &sb) != 0 && mkdir(dir, 0700) != 0) {
		pthread_mutex_unlock(&feeds_lock);
		*errp = wfmt(w, "%s: %s", dir, strerror(errno));
		return (-1);
	}
	if ((fp = open_memstream(&buf, &len)) == NULL) {
		pthread_mutex_unlock(&feeds_lock);
		*errp = "out of memory";
		return (-1);
	}
	fprintf(fp, "# arcana feed %s\n# updated %jd\n", rq->feed,
	    (intmax_t)time(NULL));
	for (i = 0; i < n; i++)
		fprintf(fp, "%s\n", ipf_prefix_format(&v.v[i], p, sizeof(p)));
	(void)fclose(fp);
	wadopt(w, buf);
	path = wfmt(w, "%s/%s", dir, rq->name);
	tmp = wfmt(w, "%s/.%s.tmp", dir, rq->name);
	step = step_begin(w, STEP_FILE, "write", "%s", path);
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	    O_NOFOLLOW, 0600)) == -1 || write(fd, buf, len) != (ssize_t)len ||
	    fsync(fd) != 0 || close(fd) != 0 || rename(tmp, path) != 0) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		step_end(w, step, false, "%s", *errp);
		(void)unlink(tmp);
		pthread_mutex_unlock(&feeds_lock);
		return (-1);
	}
	step_end(w, step, true, NULL);
	step = step_begin(w, STEP_DAEMON, "feed", "table %s, set %d", rq->name,
	    set);
	if (fill(w, rq->name, tables_sets(w) == 1 ? set : -1, &v, errp) != 0) {
		step_end(w, step, false, "%s", *errp);
		/* The file says what the table is to be; the next load or
		 * start makes it so. */
		pthread_mutex_unlock(&feeds_lock);
		return (-1);
	}
	step_end(w, step, true, "%zu entries: %u added, %u removed", n,
	    rs->added, rs->removed);
	pthread_mutex_unlock(&feeds_lock);
	return (0);
}

int
feed_drop(struct work *w, const char *name, bool *destroyedp,
    const char **errp)
{
	struct feedfile		 ff;
	struct ktable		*kt;
	const struct ktable	*t;
	const char		*e;
	size_t			 nk;
	int			 set;

	*destroyedp = false;
	if (w->jail != NULL) {
		*errp = "a vnet jail's firewall is not fed: the host's alone";
		return (-1);
	}
	if (!feed_name_ok(name)) {
		*errp = "not a feed's table";
		return (-1);
	}
	pthread_mutex_lock(&feeds_lock);
	if (!file_of(w, name, &ff)) {
		pthread_mutex_unlock(&feeds_lock);
		*errp = wfmt(w, "table %s is no feed's: it is left as it is",
		    name);
		return (-1);
	}
	nk = ktables(w, &kt);
	set = tables_sets(w) == 1 ? table_set(w, name) : -1;
	if ((t = ktable(kt, nk, name, set)) != NULL) {
		e = NULL;
		if (fw(w, &e, set, "table", name, "destroy", NULL) == 0)
			*destroyedp = true;
		else if (fw(w, errp, set, "table", name, "flush", NULL) != 0) {
			pthread_mutex_unlock(&feeds_lock);
			return (-1);
		}
	} else
		*destroyedp = true;
	if (unlink(wfmt(w, "%s/%s", feeds_dir(w), name)) != 0 && errno !=
	    ENOENT) {
		pthread_mutex_unlock(&feeds_lock);
		*errp = wfmt(w, "%s/%s: %s", feeds_dir(w), name,
		    strerror(errno));
		return (-1);
	}
	pthread_mutex_unlock(&feeds_lock);
	return (0);
}

/* The feeds' tables, by their files: each name in v, at most max. */
static size_t
feeds_names(struct work *w, const char **v, size_t max)
{
	struct dirent	*de;
	DIR		*d;
	size_t		 n;

	if ((d = opendir(feeds_dir(w))) == NULL)
		return (0);
	n = 0;
	while ((de = readdir(d)) != NULL && n < max)
		if (de->d_name[0] != '.' && feed_name_ok(de->d_name))
			v[n++] = wstrdup(w, de->d_name);
	closedir(d);
	return (n);
}

/* The tables read (do_ipfw()'s "tables"), the feeds' marked. */
void
feeds_mark(struct work *w, ucl_object_t *tables)
{
	struct feedfile		 ff;
	const ucl_object_t	*t;
	ucl_object_iter_t	 it;

	if (w->jail != NULL)
		return;
	it = NULL;
	while ((t = ucl_object_iterate(tables, &it, true)) != NULL) {
		const char	*name;

		name = ucl_object_tostring(ucl_object_lookup(t, "name"));
		if (name == NULL || !feed_name_ok(name) || !file_of(w, name,
		    &ff))
			continue;
		ucl_object_insert_key((ucl_object_t *)(uintptr_t)t,
		    ucl_object_fromstring(ff.feed), "feed", 0, false);
		ucl_object_insert_key((ucl_object_t *)(uintptr_t)t,
		    ucl_object_fromint(ff.updated), "updated", 0, false);
	}
}

/*
 * The feeds' tables of set 0 made again in set 1 before Apply swaps the
 * sets (tables_sets=1, which moves a table with its set): Apply's load
 * made them empty there, where a kept rule names one, or not at all.  A
 * feed's table in another set is not Apply's.
 */
int
feeds_fill_set1(struct work *w)
{
	struct feedfile		 ff;
	struct ipf_list		 l;
	struct ktable		*kt;
	const struct ktable	*t0;
	const char		*names[256], *e;
	size_t			 n, i, nk, left;
	int			 step;

	if (w->jail != NULL || tables_sets(w) != 1)
		return (0);
	pthread_mutex_lock(&feeds_lock);
	n = feeds_names(w, names, nitems(names));
	nk = ktables(w, &kt);
	for (i = 0; i < n; i++) {
		t0 = ktable(kt, nk, names[i], 0);
		if ((t0 == NULL && ktable(kt, nk, names[i], -1) != NULL) ||
		    !file_of(w, names[i], &ff))
			continue;
		step = step_begin(w, STEP_DAEMON, "feed", "table %s into set 1",
		    names[i]);
		e = NULL;
		if (entries_of(w, ff.body, 0, NULL, &l, &left, &e) != 0 ||
		    fill(w, names[i], 1, &l, &e) != 0) {
			step_end(w, step, false, "%s", e);
			continue;
		}
		step_end(w, step, true, "%zu entries", ff.count);
	}
	pthread_mutex_unlock(&feeds_lock);
	return (0);
}

/*
 * At the start: each feed's table the kernel has not as its file says
 * (a reboot empties them, a rule names one and makes it empty) filled
 * again.
 */
void
feeds_start(void)
{
	struct feedfile		 ff;
	struct ipf_list		 l;
	struct work		 w;
	struct ktable		*kt;
	const struct ktable	*t;
	const char		*names[256], *e;
	size_t			 n, i, nk, left;
	int			 set, ts;

	if (!kmod_loaded("ipfw") && strcmp(opts.ipfw_bin, "/sbin/ipfw") == 0)
		return;
	work_init(&w);
	pthread_mutex_lock(&feeds_lock);
	n = feeds_names(&w, names, nitems(names));
	nk = n > 0 ? ktables(&w, &kt) : 0;
	ts = n > 0 ? (int)tables_sets(&w) : 0;
	for (i = 0; i < n; i++) {
		if (!file_of(&w, names[i], &ff))
			continue;
		set = ts == 1 ? table_set(&w, names[i]) : -1;
		t = ktable(kt, nk, names[i], set);
		if (t != NULL && t->items == (long)ff.count)
			continue;
		e = NULL;
		if (entries_of(&w, ff.body, 0, NULL, &l, &left, &e) != 0 ||
		    fill(&w, names[i], set, &l, &e) != 0)
			logmsg(LOG_WARNING, "feed table %s not filled: %s",
			    names[i], e);
		else
			logmsg(LOG_INFO, "feed table %s filled: %zu entries",
			    names[i], ff.count);
	}
	pthread_mutex_unlock(&feeds_lock);
	work_free(&w);
}
