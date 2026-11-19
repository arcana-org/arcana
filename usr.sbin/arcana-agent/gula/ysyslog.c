/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: ietf-syslog (RFC 9742) served.  Running is what syslogd(8)
 * reads, syslog.conf and the files it includes, and newsyslog.conf
 * (ylog.c); a commit of the candidate writes Arcana's lines in files
 * of its own, SYSLOG_ARCANA and NEWSYSLOG_ARCANA (ylog.c's rules), and
 * leaves the user's files as they are but for what the user accepts:
 *
 *	syslog-include		syslog.conf or newsyslog.conf does not
 *				include Arcana's file: included, once, at
 *				its end
 *	syslog-conf-conflict	a line of the user's writes to an action
 *				the commit changes or takes away, or turns
 *				over a log whose rotation it changes:
 *				commented out where it is
 *
 * Unaccepted, the request is refused with that error-app-tag and says
 * what it would do.  syslogd has no check of its files of its own: what
 * was written is read back first, as running is, and must be what was
 * asked.  A log file new to syslogd is made (0600, as syslogd -C), for
 * syslogd writes to none that is not there.  syslogd, where it runs, is
 * told to read them again (service syslogd onereload, SIGHUP); failing,
 * every file is put back as it was and syslogd told again.
 *
 * Each running jail's syslogd the same, in arcana-syslog: the jail's
 * root a mount point (RFC 8528) where ietf-syslog is the jail's files,
 * read and written beneath its root and never through a link out of it
 * (scope.c), its syslogd told by its own service(8) through jexec(8).
 * The jails a commit changes are put back together when one fails.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <cblink.h>

#include "agent.h"
#include "collect.h"

/* ---- A jail's files, as ylog.c reaches them ------------------------- */

static int
io_open(void *arg, const char *path)
{

	return (scope_open_read(arg, path));
}

static int
io_opendir(void *arg, const char *dir)
{

	return (scope_dirfd(arg, dir));
}

static int
io_lstat(void *arg, const char *path, struct stat *sb)
{
	const char	*base;
	int		 dfd, rc, e;

	if ((dfd = scope_open_dir(arg, path, &base)) == -1)
		return (-1);
	rc = fstatat(dfd, base, sb, AT_SYMLINK_NOFOLLOW);
	e = errno;
	close(dfd);
	errno = e;
	return (rc);
}

static int
io_replace(void *arg, const char *path, const char *text, size_t len)
{

	return (scope_replace(arg, path, text, len, 0, NULL));
}

/* How ylog.c reaches w's files: NULL for the host's, by their paths. */
static const struct ysyslog_io *
io_of(struct work *w, struct ysyslog_io *io)
{

	if (w->jail == NULL)
		return (NULL);
	io->open = io_open;
	io->opendir = io_opendir;
	io->lstat = io_lstat;
	io->replace = io_replace;
	io->arg = w;
	return (io);
}

int
ietf_syslog_syslog_get(cbl_req *req, struct ietf_syslog *data, cbl_yarena *a)
{
	struct yunread	*u;
	char		 conf[MAXPATHLEN], ns[MAXPATHLEN];
	size_t		 nu, i;
	int		 error;

	(void)req;
	snprintf(conf, sizeof(conf), "%s%s", opts.root != NULL ? opts.root :
	    "", SYSLOG_CONF);
	snprintf(ns, sizeof(ns), "%s%s", opts.root != NULL ? opts.root : "",
	    NEWSYSLOG_CONF);
	if ((error = ysyslog_read(NULL, opts.root, conf, ns, a, data, &u,
	    &nu)) != 0)
		return (error);
	for (i = 0; i < nu; i++)
		logmsg(LOG_INFO, "syslog.conf: %s: %s", u[i].var, u[i].why);
	return (0);
}

/* A refusal with its app-tag, text its words, for req. */
static int
refuse(cbl_req *req, const char *tag, const char *text)
{

	(void)cbl_req_set_yapptag(req, tag);
	(void)cbl_req_set_yerr(req, text, 0);
	return (EEXIST);
}

/* ---- The files as they were, to be put back -------------------------- */

/*
 * The host's by rcarcana.c's rca; a jail's here, beneath its root: the
 * text and mode each had, or that it was not there.
 */
struct kept {
	const char	*path;
	char		*text;
	size_t		 len;
	mode_t		 mode;
	bool		 there;
};

struct keep {
	struct work	*w;
	struct rca	 x;
	struct kept	 v[64];
	size_t		 n;
};

static int
keep_one(struct keep *k, const char *path)
{
	struct kept	*f;
	struct stat	 sb;
	char		*t;

	if (k->w->jail == NULL)
		return (rca_keep(&k->x, path));
	for (size_t i = 0; i < k->n; i++)
		if (strcmp(k->v[i].path, path) == 0)
			return (0);
	if (k->n == nitems(k->v))
		return (E2BIG);
	f = &k->v[k->n];
	memset(f, 0, sizeof(*f));
	f->path = wstrdup(k->w, path);
	if ((t = scope_slurp(k->w, path, &f->len)) != NULL) {
		if ((f->text = malloc(f->len + 1)) == NULL)
			return (ENOMEM);
		memcpy(f->text, t, f->len + 1);
		f->there = true;
		f->mode = io_lstat(k->w, path, &sb) == 0 ? sb.st_mode & 07777 :
		    0644;
	} else if (errno != ENOENT)
		return (errno);
	k->n++;
	return (0);
}

/* Every file kept put back, the last first; 0, or the first error. */
static int
keep_undo(struct keep *k)
{
	char	why[256];
	int	error = 0, e;

	if (k->w->jail == NULL)
		return (rca_undo(&k->x));
	for (size_t i = k->n; i-- > 0; ) {
		struct kept *f = &k->v[i];

		e = 0;
		if (!f->there) {
			if (scope_unlink(k->w, f->path) == -1 && errno != ENOENT)
				e = errno;
		} else if (scope_replace(k->w, f->path, f->text, f->len,
		    f->mode, NULL) == -1)
			e = errno;
		if (e == 0)
			continue;
		(void)snprintf(why, sizeof(why), "in the jail %s: %s: %s",
		    k->w->jail, f->there ? "not put back as it was" : "not "
		    "taken away, as it was not there", strerror(e));
		undo_report(f->path, e, why);
		if (error == 0)
			error = e;
	}
	return (error);
}

static void
keep_close(struct keep *k)
{

	if (k->w != NULL && k->w->jail == NULL)
		rca_close(&k->x);
	for (size_t i = 0; i < k->n; i++)
		free(k->v[i].text);
	k->n = 0;
}

/* ---- Writing, the host's by its paths, a jail's beneath its root ----- */

/* text as the whole of path, its directory made where it is not. */
static int
put(struct work *w, const char *path, const char *text)
{
	char	 dir[MAXPATHLEN], *slash;
	FILE	*fp;
	int	 error = 0;

	(void)snprintf(dir, sizeof(dir), "%s", path);
	if ((slash = strrchr(dir, '/')) != NULL)
		slash[slash == dir ? 1 : 0] = '\0';
	if (w->jail != NULL)
		return (scope_mkdirs(w, dir) == -1 || scope_replace(w, path,
		    text, strlen(text), 0644, NULL) == -1 ? errno : 0);
	if (slash != NULL && slash != dir)
		(void)mkdir_mode(dir, 0755);
	if ((fp = fopen(path, "we")) == NULL)
		return (errno);
	if (fputs(text, fp) == EOF)
		error = errno != 0 ? errno : EIO;
	(void)fchmod(fileno(fp), 0644);
	if (fclose(fp) == EOF && error == 0)
		error = errno;
	return (error);
}

/* line at the end of path, on a line of its own. */
static int
append(struct work *w, const char *path, const char *line)
{
	struct stat	 sb;
	FILE		*fp;
	char		*t, *text;
	size_t		 len = 0;
	int		 c = '\n', error = 0;

	if (w->jail != NULL) {
		if ((t = scope_slurp(w, path, &len)) == NULL && errno != ENOENT)
			return (errno);
		text = wfmt(w, "%s%s%s", t != NULL ? t : "", len > 0 &&
		    t[len - 1] != '\n' ? "\n" : "", line);
		return (scope_replace(w, path, text, strlen(text), t != NULL ?
		    0 : 0644, NULL) == -1 ? errno : 0);
	}
	if ((fp = fopen(path, "a+e")) == NULL)
		return (errno);
	if (fstat(fileno(fp), &sb) == 0 && sb.st_size > 0 &&
	    fseeko(fp, -1, SEEK_END) == 0)
		c = fgetc(fp);
	if ((c != '\n' && fputc('\n', fp) == EOF) || fputs(line, fp) == EOF)
		error = errno != 0 ? errno : EIO;
	if (fclose(fp) == EOF && error == 0)
		error = errno;
	return (error);
}

/* A log file made, empty, 0600 (syslogd -C's), where it is not. */
static int
create(struct work *w, const char *path)
{
	int	fd;

	if ((fd = w->jail != NULL ? scope_open(w, path, O_WRONLY | O_CREAT |
	    O_EXCL, 0600) : open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
	    0600)) == -1)
		return (errno);
	close(fd);
	return (0);
}

/* syslogd made to read its files again, where it runs (*running): the
 * host's, or the jail's by its own service(8). */
static int
syslogd_again(struct work *w, bool *running, const char **errp)
{
	struct execres	 res;
	char		*argv[4];

	argv[0] = (char *)(uintptr_t)opts.service_bin;
	argv[1] = (char *)(uintptr_t)"syslogd";
	argv[2] = (char *)(uintptr_t)"onestatus";
	argv[3] = NULL;
	if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
		*running = false;
		return (0);
	}
	*running = true;
	argv[2] = (char *)(uintptr_t)"onereload";
	if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "service syslogd "
		    "onereload"));
		return (-1);
	}
	return (0);
}

/*
 * after committed to w's files, the host's (under root) or a jail's;
 * every file it changes kept in k first, for the caller to put back.
 * *running: syslogd runs there.  0, or the error, said for req.
 */
static int
commit(cbl_req *req, struct work *w, const char *root,
    const struct ietf_syslog *after, struct keep *k, bool *running)
{
	struct ysyslog_plan	 pl;
	struct ysyslog_io	 iob;
	const struct ysyslog_io	*io = io_of(w, &iob);
	cbl_yarena		*a;
	const char		*e = NULL, *in;
	char			 err[1024], conf[MAXPATHLEN], rot[MAXPATHLEN];
	char			 sconf[MAXPATHLEN], nconf[MAXPATHLEN], said[1200];
	size_t			 rl = strlen(root), off = 0;
	bool			 inc, rinc;
	int			 error;

	*running = false;
	err[0] = '\0';
	in = w->jail != NULL ? wfmt(w, "in the jail %s: ", w->jail) : "";
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if ((error = ysyslog_plan(io, root[0] != '\0' ? root : NULL, after, a,
	    &pl, err, sizeof(err))) != 0 || !pl.changed) {
		if (error != 0) {
			(void)snprintf(said, sizeof(said), "%s%s", in, err);
			(void)cbl_req_set_yerr(req, said, 0);
		}
		cbl_yarena_free(a);
		return (error);
	}
	(void)snprintf(conf, sizeof(conf), "%s%s", root, SYSLOG_ARCANA);
	(void)snprintf(rot, sizeof(rot), "%s%s", root, NEWSYSLOG_ARCANA);
	(void)snprintf(sconf, sizeof(sconf), "%s%s", root, SYSLOG_CONF);
	(void)snprintf(nconf, sizeof(nconf), "%s%s", root, NEWSYSLOG_CONF);
	inc = pl.conf != NULL && !pl.included;
	rinc = pl.rot != NULL && !pl.rot_included;
	if ((inc || rinc) && !cbl_req_yaccepts(req, "syslog-include")) {
		(void)snprintf(said, sizeof(said), "%sArcana keeps what it "
		    "writes of syslog.conf in %s and of newsyslog.conf in %s, "
		    "read where they include them: accept syslog-include to "
		    "have %s%s%s include them, once", in, SYSLOG_ARCANA,
		    NEWSYSLOG_ARCANA, inc ? SYSLOG_CONF : "", inc && rinc ?
		    " and " : "", rinc ? NEWSYSLOG_CONF : "");
		cbl_yarena_free(a);
		return (refuse(req, "syslog-include", said));
	}
	if (pl.ntake > 0 && !cbl_req_yaccepts(req, "syslog-conf-conflict")) {
		for (size_t i = 0; i < pl.ntake && off < sizeof(err); i++)
			off += (size_t)snprintf(err + off, sizeof(err) - off,
			    "%s%s:%d", i > 0 ? ", " : "", pl.take[i].path + rl,
			    pl.take[i].line);
		(void)snprintf(said, sizeof(said), "%syour lines write what "
		    "Arcana would change: %s; accept syslog-conf-conflict to "
		    "have it in Arcana's files alone, those commented out", in,
		    err);
		cbl_yarena_free(a);
		return (refuse(req, "syslog-conf-conflict", said));
	}
	/* Every file kept as it is first, for keep_undo(). */
	error = 0;
	if (pl.conf != NULL)
		error = keep_one(k, conf);
	if (error == 0 && pl.rot != NULL)
		error = keep_one(k, rot);
	if (error == 0 && inc)
		error = keep_one(k, sconf);
	if (error == 0 && rinc)
		error = keep_one(k, nconf);
	for (size_t i = 0; error == 0 && i < pl.ntake; i++)
		error = keep_one(k, pl.take[i].path);
	for (size_t i = 0; error == 0 && i < pl.ncreate; i++)
		error = keep_one(k, pl.create[i]);
	if (error != 0) {
		(void)snprintf(said, sizeof(said), "%sthe files as they are "
		    "could not be kept to be put back: %s", in,
		    strerror(error));
		(void)cbl_req_set_yerr(req, said, 0);
		cbl_yarena_free(a);
		return (error);
	}
	if ((error = ysyslog_take(io, &pl)) != 0)
		(void)snprintf(err, sizeof(err), "taking your lines: %s",
		    strerror(error));
	else if (inc && (error = append(w, sconf, "include\t\t\t\t\t\t"
	    "/usr/local/etc/syslog.d\n")) != 0)
		(void)snprintf(err, sizeof(err), "%s: %s", SYSLOG_CONF,
		    strerror(error));
	else if (rinc && (error = append(w, nconf, "<include> "
	    "/usr/local/etc/newsyslog.conf.d/[!.]*.conf\n")) != 0)
		(void)snprintf(err, sizeof(err), "%s: %s", NEWSYSLOG_CONF,
		    strerror(error));
	else if ((pl.conf != NULL && (error = put(w, conf, pl.conf)) != 0) ||
	    (pl.rot != NULL && (error = put(w, rot, pl.rot)) != 0))
		(void)snprintf(err, sizeof(err), "Arcana's files: %s",
		    strerror(error));
	for (size_t i = 0; error == 0 && i < pl.ncreate; i++)
		if ((error = create(w, pl.create[i])) != 0)
			(void)snprintf(err, sizeof(err), "%s: %s",
			    pl.create[i] + rl, strerror(error));
	if (error == 0)
		error = ysyslog_check(io, root[0] != '\0' ? root : NULL, after,
		    err, sizeof(err));
	if (error == 0 && syslogd_again(w, running, &e) != 0) {
		(void)snprintf(err, sizeof(err), "%s", e != NULL ? e :
		    "service syslogd onereload failed");
		error = EIO;
	}
	if (error != 0) {
		(void)snprintf(said, sizeof(said), "%s%s", in, err);
		(void)cbl_req_set_yerr(req, said, 0);
	}
	cbl_yarena_free(a);
	return (error);
}

int
ietf_syslog_syslog_edit(cbl_req *req, const struct ietf_syslog *before,
    const struct ietf_syslog *after)
{
	struct work	 w;
	struct keep	*k;
	const char	*e = NULL;
	bool		 running = false;
	int		 error;

	/* Running is read again: the files as they are now. */
	(void)before;
	if ((k = calloc(1, sizeof(*k))) == NULL)
		return (ENOMEM);
	work_init(&w);
	k->w = &w;
	error = commit(req, &w, opts.root != NULL ? opts.root : "", after, k,
	    &running);
	if (error != 0 && k->x.nwas + k->n > 0) {
		(void)keep_undo(k);
		if (running)
			(void)syslogd_again(&w, &running, &e);
		logmsg(LOG_WARNING, "syslog: the files as they were");
	} else if (error == 0 && !running && k->x.nwas > 0)
		(void)cbl_req_ywarn(req, ynode_named("ietf-syslog",
		    "syslog")->sid, "syslogd-stopped", "syslogd is not "
		    "running: it reads the files when it starts");
	keep_close(k);
	free(k);
	work_free(&w);
	return (error);
}

/* ---- The jails' syslogd: arcana-syslog ------------------------------- */

typedef struct arcana_syslog_jail_syslog_jail		yjail;
typedef struct arcana_syslog_jail_syslog_jail_root	yjroot;

/* The mount point of a jail's root. */
static const struct cbl_ynode *
jail_root(void)
{
	static const struct cbl_ynode *n;
	const struct cbl_ynode *c;

	if (n != NULL)
		return (n);
	c = ynode_named("arcana-syslog", "jail-syslog");
	for (int depth = 0; c != NULL && depth < 2; depth++) {
		const char *want = depth == 0 ? "jail" : "root";
		const struct cbl_ynode *f = NULL;

		for (uint32_t i = 0; i < c->nchild && f == NULL; i++)
			if (strcmp(c->child[i]->name, want) == 0)
				f = c->child[i];
		c = f;
	}
	return (n = c);
}

static const struct cbl_ymodule *
syslog_module(void)
{

	return (ynode_named("ietf-syslog", "syslog")->module);
}

static char *
astr(cbl_yarena *a, const char *s)
{
	size_t	 len = strlen(s) + 1;
	char	*p;

	if ((p = cbl_yarena_alloc(a, len)) != NULL)
		memcpy(p, s, len);
	return (p);
}

/*
 * Each running jail with its root: its syslog as its files have it, read
 * beneath its root, and the YANG library that says the shared schema
 * (RFC 8528 section 3), the host's own.
 */
int
arcana_syslog_jail_syslog_get(cbl_req *req, struct arcana_syslog *data,
    cbl_yarena *a)
{
	struct arcana_syslog_jail_syslog	*js;
	struct ysyslog_io			 iob;
	struct ietf_yang_library		*yl;
	struct ietf_syslog			*sl;
	struct yunread				*u;
	struct jinfo				*list;
	struct work				 w, jw;
	const struct cbl_ynode			*mp = jail_root();
	const char				*e;
	yjail					*v;
	yjroot					*r;
	size_t					 n, k = 0, nu;
	int					 error = 0;

	(void)req;
	if (mp == NULL)
		return (0);
	work_init(&w);
	if (jails_running(&w, &list, &n, &e) != 0 || n == 0) {
		work_free(&w);
		return (0);
	}
	if ((js = cbl_yarena_alloc(a, sizeof(*js))) == NULL ||
	    (v = cbl_yarena_alloc(a, n * sizeof(*v))) == NULL) {
		work_free(&w);
		return (ENOMEM);
	}
	memset(js, 0, sizeof(*js));
	memset(v, 0, n * sizeof(*v));
	for (size_t i = 0; error == 0 && i < n; i++) {
		if (list[i].dying || list[i].name == NULL)
			continue;
		work_init(&jw);
		if (scope_enter_jail(&jw, list[i].name, &e, false) != 0) {
			work_free(&jw);
			continue;
		}
		if ((r = cbl_yarena_alloc(a, sizeof(*r))) == NULL ||
		    (v[k].name = astr(a, list[i].name)) == NULL ||
		    (sl = cbl_ymount_data(mp, r, syslog_module(), a)) ==
		    NULL || (yl = cbl_ymount_data(mp, r, ynode_named(
		    "ietf-yang-library", "yang-library")->module, a)) ==
		    NULL)
			error = ENOMEM;
		else if ((error = ysyslog_read(io_of(&jw, &iob), NULL,
		    SYSLOG_CONF, NEWSYSLOG_CONF, a, sl, &u, &nu)) == 0 &&
		    (error = ietf_yang_library_yang_library_get(NULL, yl,
		    a)) == 0) {
			v[k].root = r;
			k++;
		}
		work_free(&jw);
	}
	work_free(&w);
	if (error != 0)
		return (error);
	js->jail.n = k;
	js->jail.v = v;
	data->jail_syslog = js;
	return (0);
}

/* A jail's syslog in its root; NULL: none there. */
static const struct ietf_syslog *
syslog_of(const yjail *j)
{

	return (j != NULL && j->root != NULL ? cbl_ymount_find(jail_root(),
	    j->root, syslog_module()) : NULL);
}

/* Whether x and y are one syslog, by their YANG-CBOR. */
static bool
same(const struct ietf_syslog *x, const struct ietf_syslog *y)
{
	struct cbl_ybuf	bx = { 0 }, by = { 0 };
	bool		is;

	if (x == NULL || y == NULL || x->syslog == NULL || y->syslog == NULL)
		return ((x == NULL || x->syslog == NULL) == (y == NULL ||
		    y->syslog == NULL));
	is = ietf_syslog_syslog_encode(x->syslog, &bx) == 0 &&
	    ietf_syslog_syslog_encode(y->syslog, &by) == 0 && bx.len ==
	    by.len && memcmp(bx.p, by.p, bx.len) == 0;
	cbl_ybuf_free(&bx);
	cbl_ybuf_free(&by);
	return (is);
}

/* What the root of a jail has but its syslog and the YANG library:
 * a module's name, or NULL. */
static const char *
other_in(const yjail *j)
{
	const struct cbl_ymodule *yl = ynode_named("ietf-yang-library",
	    "yang-library")->module;

	for (size_t i = 0; j->root != NULL && i < j->root->mounted.n; i++)
		if (j->root->mounted.v[i].data != NULL &&
		    j->root->mounted.v[i].module != syslog_module() &&
		    j->root->mounted.v[i].module != yl)
			return (j->root->mounted.v[i].module->name);
	return (NULL);
}

/*
 * A commit of the jails' syslogd: each jail whose syslog changed
 * committed in it, as the host's is; one failing, every jail done before
 * it put back too, and its syslogd told again.  A jail left out of the
 * edit, or with no syslog in its root, is left as it is.
 */
int
arcana_syslog_jail_syslog_edit(cbl_req *req, const struct arcana_syslog *before,
    const struct arcana_syslog *after)
{
	const struct arcana_syslog_jail_syslog	*ja, *jb;
	const struct ietf_syslog		*sa;
	struct work				*w;
	struct keep				*k = NULL;
	const char				*e, *other;
	char					 err[512];
	bool					*running;
	size_t					 n, done = 0;
	int					 error = 0;

	ja = after != NULL ? after->jail_syslog : NULL;
	jb = before != NULL ? before->jail_syslog : NULL;
	if (ja == NULL || (n = ja->jail.n) == 0)
		return (0);
	if ((w = calloc(n, sizeof(*w))) == NULL ||
	    (k = calloc(n, sizeof(*k))) == NULL ||
	    (running = calloc(n, sizeof(*running))) == NULL) {
		free(w);
		free(k);
		return (ENOMEM);
	}
	for (size_t i = 0; error == 0 && i < n; i++) {
		const yjail *j = &ja->jail.v[i], *was = NULL;

		for (size_t m = 0; jb != NULL && m < jb->jail.n; m++)
			if (strcmp(jb->jail.v[m].name, j->name) == 0)
				was = &jb->jail.v[m];
		if ((sa = syslog_of(j)) == NULL || same(syslog_of(was), sa))
			continue;
		if ((other = other_in(j)) != NULL) {
			(void)snprintf(err, sizeof(err), "the jail %s: its root "
			    "has its syslog alone (ietf-syslog), not %s",
			    j->name, other);
			(void)cbl_req_set_yerr(req, err, 0);
			error = EINVAL;
			break;
		}
		work_init(&w[done]);
		k[done].w = &w[done];
		e = NULL;
		if (!valid_jail(j->name) || scope_enter_jail(&w[done], j->name,
		    &e, false) != 0) {
			(void)cbl_req_set_yerr(req, e != NULL ? e : "invalid "
			    "jail name", 0);
			work_free(&w[done]);
			error = ENOENT;
			break;
		}
		error = commit(req, &w[done], "", sa, &k[done],
		    &running[done]);
		done++;
	}
	for (size_t i = done; i-- > 0; ) {
		if (error != 0 && k[i].n > 0) {
			(void)keep_undo(&k[i]);
			if (running[i])
				(void)syslogd_again(&w[i], &running[i], &e);
			logmsg(LOG_WARNING, "syslog: the jail %s's files as they "
			    "were", w[i].jail);
		} else if (error == 0 && !running[i] && k[i].n > 0) {
			(void)snprintf(err, sizeof(err), "syslogd is not running "
			    "in the jail %s: it reads the files when it starts",
			    w[i].jail);
			(void)cbl_req_ywarn(req, ynode_named("arcana-syslog",
			    "jail-syslog")->sid, "syslogd-stopped", err);
		}
		keep_close(&k[i]);
		work_free(&w[i]);
	}
	free(running);
	free(k);
	free(w);
	return (error);
}
