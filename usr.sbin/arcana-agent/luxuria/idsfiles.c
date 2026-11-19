/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Luxuria: Suricata's files, to and from the console.  A capture comes
 * in as a stream (suricata-pcap-put), in parts, to the captures
 * directory of an instance's replay directory, where the suricata
 * job's verb pcap replays it; a file of the packets of its alerts
 * (pcap-log) goes out as one (suricata-pcap-get).  And what its
 * profiling wrote, Suricata built with --enable-profiling: packets'
 * ticks per protocol and per stage (packet_stats.log), its rules'
 * (rule_perf.log), read back for the suricata-rules read.  An instance
 * in a jail has them beneath the jail's root, each opened there by a
 * descriptor beneath it (never by a link out of it), their paths as
 * the jail has them.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"
#include "ystream.h"

#define	XF_MAX		4			/* at once, each way */
/* Sent at once: half the window a stream has unless its opener says
 * more, the message about it counted too. */
#define	XF_CHUNK	(128 * 1024)
#define	XF_ROOM		(XF_CHUNK + 4096)
#define	CAPTURE_MAX	(1024LL * 1024 * 1024)	/* a capture, at most */
#define	CAPTURES_KEPT	8
#define	TAIL_MAX	(2 * 1024 * 1024)	/* of a profiling file */
#define	PROF_ROWS	3000

static pthread_mutex_t	xf_lock = PTHREAD_MUTEX_INITIALIZER;
static int		nputs, ngets;

/* The value of key= among the names; NULL when it is not there. */
static const char *
word(const char *const *v, size_t n, const char *key)
{
	size_t	i, k;

	k = strlen(key);
	for (i = 0; i < n; i++)
		if (v[i] != NULL && strncmp(v[i], key, k) == 0 && v[i][k] == '=')
			return (v[i] + k + 1);
	return (NULL);
}

/* Each name one of keys. */
static bool
words_ok(const char *const *v, size_t n, const char *const *keys,
    size_t nkeys)
{
	size_t	i, k;

	for (i = 0; i < n; i++) {
		for (k = 0; k < nkeys; k++)
			if (v[i] != NULL && strncmp(v[i], keys[k],
			    strlen(keys[k])) == 0 && v[i][strlen(keys[k])] == '=')
				break;
		if (k == nkeys)
			return (false);
	}
	return (true);
}

/* A file's name alone: letters, digits, ., _ and -, not a dot first. */
static bool
base_ok(const char *s)
{
	size_t	n;

	return (s != NULL && (n = strlen(s)) > 0 && n <= 128 && s[0] != '.' &&
	    strspn(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "0123456789._-") == n);
}

static bool
capture_name_ok(const char *s)
{
	size_t	n;

	return (base_ok(s) && (n = strlen(s)) > 4 && (strcmp(s + n - 5,
	    ".pcap") == 0 || (n > 7 && strcmp(s + n - 7, ".pcapng") == 0) ||
	    strcmp(s + n - 4, ".cap") == 0));
}

/* A directory of w's scope read: a jail's beneath its root. */
static DIR *
dir_open(struct work *w, const char *dir)
{
	DIR	*d;
	int	 fd;

	if ((fd = scope_dirfd(w, dir)) == -1)
		return (NULL);
	if ((d = fdopendir(fd)) == NULL)
		close(fd);
	return (d);
}

/* Its replay directory's captures, made when it has none, in w's
 * scope: opened, its path in *pathp; -1 for none. */
static int
captures_dir(struct work *w, const char *inst, const char **pathp)
{
	const char	*rd;

	rd = suricata_inst_file(w, inst, "replay.d");
	*pathp = wfmt(w, "%s/captures", rd);
	if (w->jail != NULL) {
		if (scope_mkdirs(w, *pathp) != 0)
			return (-1);
	} else if ((mkdir_mode(rd, 0750) == -1 && errno != EEXIST) ||
	    (mkdir_mode(*pathp, 0750) == -1 && errno != EEXIST))
		return (-1);
	return (scope_dirfd(w, *pathp));
}

/* The instance there is, in w's scope: its configuration. */
static bool
inst_there(struct work *w, const char *inst)
{

	return (scope_access(w, suricata_inst_file(w, inst, "yaml"), false));
}

/*
 * The captures an instance's replay keeps (its directory dfd):
 * CAPTURES_KEPT, the oldest let go, and a part nobody finished a day
 * ago.
 */
static void
captures_prune(int dfd)
{
	struct {
		char	name[160];
		time_t	at;
	}		 v[64];
	struct dirent	*de;
	struct stat	 sb;
	size_t		 n, i, old, len;
	DIR		*d;
	int		 fd;

	if ((fd = dup(dfd)) == -1)
		return;
	if ((d = fdopendir(fd)) == NULL) {
		close(fd);
		return;
	}
	n = 0;
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.' || fstatat(dfd, de->d_name, &sb,
		    AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(sb.st_mode))
			continue;
		len = strlen(de->d_name);
		if (len > 5 && strcmp(de->d_name + len - 5, ".part") == 0) {
			if (sb.st_mtime < time(NULL) - 86400)
				(void)unlinkat(dfd, de->d_name, 0);
			continue;
		}
		if (n < nitems(v) && len < sizeof(v[n].name)) {
			snprintf(v[n].name, sizeof(v[n].name), "%s", de->d_name);
			v[n++].at = sb.st_mtime;
		}
	}
	closedir(d);
	while (n > CAPTURES_KEPT) {
		for (old = 0, i = 1; i < n; i++)
			if (v[i].at < v[old].at)
				old = i;
		(void)unlinkat(dfd, v[old].name, 0);
		v[old] = v[--n];
	}
}

/* The captures uploaded for its replay, for the sdwan read, in w's
 * scope: a jail's paths as the jail has them. */
ucl_object_t *
suricata_captures_json(struct work *w, const char *inst)
{
	ucl_object_t	*arr, *o;
	struct dirent	*de;
	struct stat	 sb;
	const char	*dir, *p;
	DIR		*d;

	arr = ucl_object_typed_new(UCL_ARRAY);
	dir = wfmt(w, "%s/captures", suricata_inst_file(w, inst, "replay.d"));
	if ((d = dir_open(w, dir)) == NULL)
		return (arr);
	while ((de = readdir(d)) != NULL) {
		if (!capture_name_ok(de->d_name) || fstatat(dirfd(d),
		    de->d_name, &sb, AT_SYMLINK_NOFOLLOW) != 0 ||
		    !S_ISREG(sb.st_mode))
			continue;
		p = wfmt(w, "%s/%s", dir, de->d_name);
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(p), "path", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)
		    sb.st_size), "size", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)
		    sb.st_mtime), "at", 0, false);
		ucl_array_append(arr, o);
	}
	closedir(d);
	return (arr);
}

/* ---- A capture in: suricata-pcap-put --------------------------------- */

/* A capture coming: its part and its name in the captures directory
 * dfd (a jail's beneath its root), its path as its place has it. */
struct put {
	int		 fd, dfd;
	bool		 last, failed;
	int64_t		 offset, written;
	char		 part[NAME_MAX + 1], name[NAME_MAX + 1];
	char		 path[MAXPATHLEN];
};

static void
put_free(struct put *p)
{

	if (p->fd != -1)
		close(p->fd);
	if (p->dfd != -1)
		close(p->dfd);
	free(p);
	pthread_mutex_lock(&xf_lock);
	nputs--;
	pthread_mutex_unlock(&xf_lock);
}

static void
put_data(cbl_stream *s, const struct arcana_stream_chunk *d, void *arg)
{
	struct put	*p = arg;
	size_t		 off;
	ssize_t		 n;

	if (p->failed)
		return;
	if (p->offset + p->written + (int64_t)d->data.len > CAPTURE_MAX) {
		p->failed = true;
		(void)cbl_stream_close(s, EFBIG, "a capture is 1 GiB at most");
		return;
	}
	for (off = 0; off < d->data.len; off += (size_t)n)
		if ((n = write(p->fd, (const unsigned char *)d->data.p +
		    off, d->data.len - off)) <= 0) {
			if (n == -1 && errno == EINTR) {
				n = 0;
				continue;
			}
			p->failed = true;
			(void)cbl_stream_close(s, EIO, n == -1 ? strerror(errno) :
			    "nothing written");
			return;
		}
	p->written += (int64_t)d->data.len;
}

/* All was sent: the part kept, or, the last, the capture whole. */
static void
put_hclose(cbl_stream *s, void *arg)
{
	struct put	*p = arg;
	int		 fd;

	if (p->failed)
		return;
	fd = p->fd;
	p->fd = -1;
	if (fsync(fd) == -1 || close(fd) == -1) {
		p->failed = true;
		(void)cbl_stream_close(s, EIO, strerror(errno));
		return;
	}
	if (p->last) {
		if (renameat(p->dfd, p->part, p->dfd, p->name) == -1) {
			p->failed = true;
			(void)cbl_stream_close(s, EIO, strerror(errno));
			return;
		}
		captures_prune(p->dfd);
		logmsg(LOG_INFO, "suricata: a capture came for replay, %s, "
		    "%jd bytes", p->path, (intmax_t)(p->offset + p->written));
	}
	/* Nothing after: the stream may end at once. */
	(void)cbl_stream_close(s, 0, NULL);
}

/* The stream ended: a part left unfinished goes. */
static void
put_close(cbl_stream *s __unused, int code __unused,
    const char *text __unused, void *arg)
{
	struct put	*p = arg;

	if (p->fd != -1 || p->failed)
		(void)unlinkat(p->dfd, p->part, 0);
	put_free(p);
}

static const struct ys_cbs put_cbs = {
	.on_data = put_data,
	.on_hclose = put_hclose,
	.on_close = put_close,
};

/* A capture's stream opened, w where its instance runs. */
static int
put_open(struct work *w, cbl_req *req, const struct arcana_stream_open *rq,
    cbl_stream *s)
{
	static const char *const keys[] = { "instance", "file", "offset",
	    "last" };
	struct arcana_stream_opened		 rsp;
	struct put				*p;
	struct stat				 sb;
	const char				*inst, *file, *off, *last, *e;
	const char				*dir;
	char					*end, json[MAXPATHLEN + 32];
	char					 why[96];
	long long				 o;

	inst = word(rq->name.v, rq->name.n, "instance");
	file = word(rq->name.v, rq->name.n, "file");
	off = word(rq->name.v, rq->name.n, "offset");
	last = word(rq->name.v, rq->name.n, "last");
	o = 0;
	if (!words_ok(rq->name.v, rq->name.n, keys, nitems(keys)) ||
	    inst == NULL || !suricata_name_ok(inst) || !capture_name_ok(file) ||
	    (off != NULL && ((o = strtoll(off, &end, 10)) < 0 || *end != '\0' ||
	    off[0] == '\0' || o > CAPTURE_MAX)) || (last != NULL &&
	    strcmp(last, "1") != 0)) {
		(void)cbl_req_set_err(req, "a capture is sent by instance=, "
		    "file= (a .pcap, .pcapng or .cap, its name alone), offset= "
		    "and last=1", NULL, 0, -1);
		return (EINVAL);
	}
	/* Where it runs: a jail's captures beneath its root. */
	e = NULL;
	if (suricata_inst_in(w, inst, &e) != 0) {
		(void)cbl_req_set_err(req, e, NULL, 0, -1);
		return (ENOENT);
	}
	if (!inst_there(w, inst)) {
		(void)cbl_req_set_err(req, "there is no such instance here",
		    NULL, 0, -1);
		return (ENOENT);
	}
	pthread_mutex_lock(&xf_lock);
	if (nputs >= XF_MAX) {
		pthread_mutex_unlock(&xf_lock);
		(void)cbl_req_set_err(req, "four captures at most come at once",
		    NULL, 0, -1);
		return (EBUSY);
	}
	nputs++;
	pthread_mutex_unlock(&xf_lock);
	if ((p = calloc(1, sizeof(*p))) == NULL) {
		pthread_mutex_lock(&xf_lock);
		nputs--;
		pthread_mutex_unlock(&xf_lock);
		return (ENOMEM);
	}
	p->fd = -1;
	p->offset = o;
	p->last = last != NULL;
	if ((p->dfd = captures_dir(w, inst, &dir)) == -1) {
		(void)cbl_req_set_err(req, strerror(errno), NULL, 0, -1);
		put_free(p);
		return (EIO);
	}
	snprintf(p->path, sizeof(p->path), "%s/%s", dir, file);
	snprintf(p->name, sizeof(p->name), "%s", file);
	snprintf(p->part, sizeof(p->part), "%s.part", file);
	/* The first part makes it; the next one goes on where the one
	 * before ended, or is refused. */
	p->fd = openat(p->dfd, p->part, O_WRONLY | O_CLOEXEC | O_NOFOLLOW |
	    (o == 0 ? O_CREAT | O_TRUNC : O_APPEND), 0640);
	if (p->fd == -1 || fstat(p->fd, &sb) == -1 || !S_ISREG(sb.st_mode) ||
	    sb.st_size != o) {
		if (p->fd != -1)
			snprintf(why, sizeof(why), "the part before ended at %jd, "
			    "not %lld", (intmax_t)sb.st_size, o);
		(void)cbl_req_set_err(req, p->fd == -1 && o > 0 ? "no part of "
		    "it came before" : p->fd == -1 ? strerror(errno) : why,
		    NULL, 0, -1);
		put_free(p);
		return (EINVAL);
	}
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = true;
	snprintf(json, sizeof(json), "{\"path\":\"%s\"}", p->path);
	rsp.json = json;
	if (ys_accept(s, &rsp, &put_cbs, p) != 0) {
		(void)unlinkat(p->dfd, p->part, 0);
		put_free(p);
		return (ECONNREFUSED);
	}
	return (0);
}

int
pcap_put_open(cbl_req *req, const struct arcana_stream_open *rq,
    cbl_stream *s)
{
	struct work	w;
	int		rc;

	work_init(&w);
	rc = put_open(&w, req, rq, s);
	work_free(&w);
	return (rc);
}

/* ---- A pcap-log file out: suricata-pcap-get -------------------------- */

struct get {
	cbl_stream	*s;
	int		 fd;
	pthread_mutex_t	 lock;
	pthread_cond_t	 wake;
	bool		 closed;
	int		 refs;		/* the thread's, the stream's */
};

static void
get_unref(struct get *g)
{
	bool	last;

	pthread_mutex_lock(&g->lock);
	last = --g->refs == 0;
	pthread_mutex_unlock(&g->lock);
	if (!last)
		return;
	if (g->fd != -1)
		close(g->fd);
	pthread_mutex_destroy(&g->lock);
	pthread_cond_destroy(&g->wake);
	free(g);
	pthread_mutex_lock(&xf_lock);
	ngets--;
	pthread_mutex_unlock(&xf_lock);
}

static void
get_closed(cbl_stream *s __unused, int code __unused,
    const char *text __unused, void *arg)
{
	struct get	*g = arg;

	pthread_mutex_lock(&g->lock);
	g->closed = true;
	pthread_cond_signal(&g->wake);
	pthread_mutex_unlock(&g->lock);
	get_unref(g);
}

static void
get_writable(cbl_stream *s __unused, size_t credit __unused, void *arg)
{
	struct get	*g = arg;

	pthread_mutex_lock(&g->lock);
	pthread_cond_signal(&g->wake);
	pthread_mutex_unlock(&g->lock);
}

/* Its thread: the file read and sent as there is room. */
static void *
get_run(void *arg)
{
	struct get		*g = arg;
	unsigned char		*buf;
	ssize_t			 n;
	int			 error;

	error = 0;
	n = 0;
	if ((buf = malloc(XF_CHUNK)) == NULL)
		error = ENOMEM;
	while (error == 0 && (n = read(g->fd, buf, XF_CHUNK)) > 0) {
		while ((error = ys_send(g->s, buf, (size_t)n)) == EAGAIN) {
			pthread_mutex_lock(&g->lock);
			while (!g->closed && cbl_stream_credit(g->s) < XF_ROOM)
				pthread_cond_wait(&g->wake, &g->lock);
			error = g->closed ? EPIPE : 0;
			pthread_mutex_unlock(&g->lock);
			if (error != 0)
				break;
		}
	}
	if (error == 0 && n == -1)
		error = errno;
	free(buf);
	if (error == 0)
		(void)cbl_stream_half_close(g->s);
	else if (error != EPIPE)
		(void)cbl_stream_close(g->s, error, strerror(error));
	cbl_stream_rele(g->s);
	get_unref(g);
	return (NULL);
}

static const struct ys_cbs get_cbs = {
	.on_writable = get_writable,
	.on_close = get_closed,
};

/* A pcap-log file's stream opened, w where its instance runs. */
static int
get_open(struct work *w, cbl_req *req, const struct arcana_stream_open *rq,
    cbl_stream *s)
{
	static const char *const keys[] = { "instance", "file" };
	struct arcana_stream_opened		 rsp;
	struct get				*g;
	struct stat				 sb;
	pthread_t				 tid;
	const char				*inst, *file, *e;
	char					 p[MAXPATHLEN];
	char					 json[MAXPATHLEN + 64];

	inst = word(rq->name.v, rq->name.n, "instance");
	file = word(rq->name.v, rq->name.n, "file");
	/* Its pcap-log's files alone: log.pcap, and its rotations. */
	if (!words_ok(rq->name.v, rq->name.n, keys, nitems(keys)) ||
	    inst == NULL || !suricata_name_ok(inst) || !base_ok(file) ||
	    strncmp(file, "log.pcap", 8) != 0) {
		(void)cbl_req_set_err(req, "a file of pcap-log is asked by "
		    "instance= and file= (log.pcap or a rotation of it, its "
		    "name alone)", NULL, 0, -1);
		return (EINVAL);
	}
	/* Where it runs: a jail's files beneath its root. */
	e = NULL;
	if (suricata_inst_in(w, inst, &e) != 0) {
		(void)cbl_req_set_err(req, e, NULL, 0, -1);
		return (ENOENT);
	}
	snprintf(p, sizeof(p), "%s/%s", suricata_inst_file(w, inst, "d"), file);
	pthread_mutex_lock(&xf_lock);
	if (ngets >= XF_MAX) {
		pthread_mutex_unlock(&xf_lock);
		(void)cbl_req_set_err(req, "four files at most go at once",
		    NULL, 0, -1);
		return (EBUSY);
	}
	ngets++;
	pthread_mutex_unlock(&xf_lock);
	if ((g = calloc(1, sizeof(*g))) == NULL) {
		pthread_mutex_lock(&xf_lock);
		ngets--;
		pthread_mutex_unlock(&xf_lock);
		return (ENOMEM);
	}
	g->s = s;
	g->refs = 2;
	pthread_mutex_init(&g->lock, NULL);
	pthread_cond_init(&g->wake, NULL);
	if ((g->fd = scope_open(w, p, O_RDONLY, 0)) == -1 ||
	    fstat(g->fd, &sb) == -1 || !S_ISREG(sb.st_mode)) {
		(void)cbl_req_set_err(req, g->fd == -1 && errno == ENOENT ?
		    "the instance has no such file: Suricata may have let it "
		    "go (its pcap-log's files at most)" : "not a file of its "
		    "pcap-log", NULL, 0, -1);
		g->refs = 1;
		get_unref(g);
		return (ENOENT);
	}
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = true;
	snprintf(json, sizeof(json), "{\"path\":\"%s\",\"size\":%jd}", p,
	    (intmax_t)sb.st_size);
	rsp.json = json;
	if (ys_accept(s, &rsp, &get_cbs, g) != 0) {
		g->refs = 1;
		get_unref(g);
		return (ECONNREFUSED);
	}
	cbl_stream_ref(s);
	if (pthread_create(&tid, NULL, get_run, g) != 0) {
		(void)cbl_stream_close(s, EAGAIN, "no thread for it");
		cbl_stream_rele(s);
		get_unref(g);
		return (0);
	}
	(void)pthread_detach(tid);
	return (0);
}

int
pcap_get_open(cbl_req *req, const struct arcana_stream_open *rq,
    cbl_stream *s)
{
	struct work	w;
	int		rc;

	work_init(&w);
	rc = get_open(&w, req, rq, s);
	work_free(&w);
	return (rc);
}

/* ---- Profiling: what Suricata wrote of it, read back ----------------- */

/* A file's last TAIL_MAX bytes at most, as text; NULL for none. */
static char *
tail_of(struct work *w, const char *path, time_t *atp)
{
	struct stat	 sb;
	char		*buf;
	off_t		 from;
	ssize_t		 n;
	size_t		 got;
	int		 fd;

	if ((fd = scope_open(w, path, O_RDONLY, 0)) == -1)
		return (NULL);
	if (fstat(fd, &sb) == -1 || !S_ISREG(sb.st_mode)) {
		close(fd);
		return (NULL);
	}
	from = sb.st_size > TAIL_MAX ? sb.st_size - TAIL_MAX : 0;
	buf = wcalloc(w, (size_t)(sb.st_size - from) + 1, 1);
	got = 0;
	while (got < (size_t)(sb.st_size - from) && (n = pread(fd, buf + got,
	    (size_t)(sb.st_size - from) - got, from + (off_t)got)) > 0)
		got += (size_t)n;
	close(fd);
	buf[got] = '\0';
	*atp = sb.st_mtime;
	return (buf);
}

/* A number Suricata wrote, or -1. */
static int64_t
num(const char *s)
{
	char	*end;
	long long v;

	v = strtoll(s, &end, 10);
	return (end == s || *end != '\0' ? -1 : (int64_t)v);
}

/*
 * packet_stats.log's last dump ("Packet profile dump:"): each table's
 * head (its first column the stage: Thread Module, App Layer, Flow
 * Worker, Logger, Detection phase; none for the packets themselves)
 * and its rows, ticks per IP version and protocol.
 */
static ucl_object_t *
packets_json(char *text)
{
	ucl_object_t	*top, *secs, *sec, *rows, *r;
	char		*p, *line, *t[16], *ipv, title[64];
	size_t		 total;
	int		 nt, k, i;

	if ((p = text) == NULL)
		return (NULL);
	while ((line = strstr(p, "Packet profile dump:")) != NULL)
		p = line + 20;
	if (p == text)
		return (NULL);
	top = ucl_object_typed_new(UCL_OBJECT);
	secs = ucl_object_typed_new(UCL_ARRAY);
	sec = rows = NULL;
	total = 0;
	while ((line = strsep(&p, "\n")) != NULL && total < PROF_ROWS) {
		/* A table's head: what is before "IP ver" its title. */
		if ((ipv = strstr(line, "IP ver")) != NULL) {
			while (ipv > line && isspace((unsigned char)ipv[-1]))
				ipv--;
			line += strspn(line, " \t");
			snprintf(title, sizeof(title), "%.*s", (int)MAX(0,
			    ipv - line), line);
			sec = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(sec, ucl_object_fromstring(
			    title[0] != '\0' ? title : "Packets"), "title", 0,
			    false);
			rows = ucl_object_typed_new(UCL_ARRAY);
			ucl_object_insert_key(sec, rows, "rows", 0, false);
			ucl_array_append(secs, sec);
			continue;
		}
		if (rows == NULL)
			continue;
		for (nt = 0; nt < (int)nitems(t) && (t[nt] = strsep(&line,
		    " \t")) != NULL;)
			if (t[nt][0] != '\0')
				nt++;
		for (k = 0; k < nt; k++)
			if (strcmp(t[k], "IPv4") == 0 || strcmp(t[k], "IPv6") == 0)
				break;
		/* The version, protocol, cnt, min, max and avg at least. */
		if (k == nt || nt - k < 6 || num(t[k + 1]) < 0 || num(t[k +
		    2]) < 0)
			continue;
		r = ucl_object_typed_new(UCL_OBJECT);
		title[0] = '\0';
		for (i = 0; i < k; i++)
			snprintf(title + strlen(title), sizeof(title) -
			    strlen(title), "%s%s", i > 0 ? " " : "", t[i]);
		ucl_object_insert_key(r, ucl_object_fromstring(title), "name", 0,
		    false);
		ucl_object_insert_key(r, ucl_object_fromstring(t[k]), "ip", 0,
		    false);
		ucl_object_insert_key(r, ucl_object_fromint(num(t[k + 1])),
		    "proto", 0, false);
		ucl_object_insert_key(r, ucl_object_fromint(num(t[k + 2])),
		    "cnt", 0, false);
		ucl_object_insert_key(r, ucl_object_fromint(num(t[k + 3])),
		    "min", 0, false);
		ucl_object_insert_key(r, ucl_object_fromint(num(t[k + 4])),
		    "max", 0, false);
		ucl_object_insert_key(r, ucl_object_fromint(num(t[k + 5])),
		    "avg", 0, false);
		/* The total as Suricata says it (12.3m), and the share. */
		if (nt - k >= 7)
			ucl_object_insert_key(r, ucl_object_fromstring(t[k + 6]),
			    "tot", 0, false);
		if (nt - k >= 8)
			ucl_object_insert_key(r, ucl_object_fromdouble(strtod(
			    t[k + 7], NULL)), "pct", 0, false);
		ucl_array_append(rows, r);
		total++;
	}
	ucl_object_insert_key(top, secs, "sections", 0, false);
	return (top);
}

/* rule_perf.log, JSON a line: the last dump. */
static ucl_object_t *
rules_json(char *text)
{
	struct ucl_parser	*pr;
	ucl_object_t		*o;
	char			*line, *last;

	last = NULL;
	while ((line = strsep(&text, "\n")) != NULL)
		if (line[0] == '{')
			last = line;
	if (last == NULL)
		return (NULL);
	pr = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = ucl_parser_add_string(pr, last, 0) ? ucl_parser_get_object(pr) :
	    NULL;
	ucl_parser_free(pr);
	return (o);
}

/* A text file's last lines, 32 KiB at most. */
static ucl_object_t *
text_json(const char *text)
{
	size_t		 n;
	const char	*p;

	n = strlen(text);
	p = n > 32768 ? text + n - 32768 : text;
	if (p != text && strchr(p, '\n') != NULL)
		p = strchr(p, '\n') + 1;
	return (ucl_object_fromstring(p));
}

/* What the profiling wrote into a directory; NULL when nothing. */
static ucl_object_t *
dir_json(struct work *w, const char *dir)
{
	static const struct {
		const char	*file, *key;
	} texts[] = {
		{ "keyword_perf.log", "keywords" },
		{ "prefilter_perf.log", "prefilter" },
		{ "rule_group_perf.log", "rulegroups" },
		{ "lock_stats.log", "locks" },
	};
	ucl_object_t	*top, *o;
	char		*t;
	time_t		 at;
	size_t		 i;
	int		 n;

	n = 0;
	top = ucl_object_typed_new(UCL_OBJECT);
	if ((t = tail_of(w, wfmt(w, "%s/packet_stats.log", dir), &at)) !=
	    NULL && (o = packets_json(t)) != NULL) {
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)at), "at", 0,
		    false);
		ucl_object_insert_key(top, o, "packets", 0, false);
		n++;
	}
	if ((t = tail_of(w, wfmt(w, "%s/rule_perf.log", dir), &at)) != NULL &&
	    (o = rules_json(t)) != NULL) {
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)at), "at", 0,
		    false);
		ucl_object_insert_key(top, o, "rules", 0, false);
		n++;
	}
	for (i = 0; i < nitems(texts); i++) {
		if ((t = tail_of(w, wfmt(w, "%s/%s", dir, texts[i].file), &at)) ==
		    NULL || t[0] == '\0')
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, text_json(t), "text", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)at), "at", 0,
		    false);
		ucl_object_insert_key(top, o, texts[i].key, 0, false);
		n++;
	}
	if (n == 0) {
		ucl_object_unref(top);
		return (NULL);
	}
	return (top);
}

/*
 * instance=NAME profiling=1: whether its Suricata profiles, and what
 * its profiling wrote, running (its log directory, written as it stops)
 * and of its last replay.
 */
void
suricata_profiling(struct work *w, const char *inst,
    struct json_rsp *rsp)
{
	ucl_object_t	*top, *b, *o;
	const char	*e;
	char		*json;

	rsp->has_ok = true;
	rsp->ok = false;
	if (inst == NULL || !suricata_name_ok(inst)) {
		rsp->error = "profiling is read by instance= and profiling=1";
		return;
	}
	/* Where it runs: a jail's, its Suricata and files there. */
	e = NULL;
	if (suricata_inst_in(w, inst, &e) != 0) {
		rsp->error = e;
		return;
	}
	if (!inst_there(w, inst)) {
		rsp->error = wfmt(w, "there is no instance %s here", inst);
		(void)scope_enter_jail(w, NULL, NULL, false);
		return;
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	b = ucl_object_typed_new(UCL_OBJECT);
	if ((o = suricata_build_json(w)) != NULL) {
		ucl_object_insert_key(b, ucl_object_frombool(
		    ucl_object_toboolean(ucl_object_lookup(o, "profiling"))),
		    "packets", 0, false);
		ucl_object_insert_key(b, ucl_object_frombool(
		    ucl_object_toboolean(ucl_object_lookup(o, "profiling")) ||
		    ucl_object_toboolean(ucl_object_lookup(o,
		    "profiling_rules"))), "rules", 0, false);
		ucl_object_insert_key(b, ucl_object_frombool(
		    ucl_object_toboolean(ucl_object_lookup(o,
		    "profiling_locks"))), "locks", 0, false);
		ucl_object_unref(o);
	}
	ucl_object_insert_key(top, b, "build", 0, false);
	if ((o = dir_json(w, suricata_inst_file(w, inst, "d"))) != NULL)
		ucl_object_insert_key(top, o, "running", 0, false);
	if ((o = dir_json(w, suricata_inst_file(w, inst, "replay.d"))) != NULL)
		ucl_object_insert_key(top, o, "replay", 0, false);
	(void)scope_enter_jail(w, NULL, NULL, false);
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
