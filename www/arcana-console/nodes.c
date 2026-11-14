/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The consoles of a cluster, web.conf's cluster block:
 *
 *	cluster {
 *		self = "a";
 *		listen = "tcp://[::]:4311";
 *		nodes {
 *			a { uri = "tcp://a.console.example:4311";
 *			    origin = "https://a.console.example"; }
 *			b { ... }
 *			c { ... }
 *		}
 *	}
 *
 * Each node serves the arcana-cluster family (share/arcana/cluster.yaml)
 * on its listener, by TLS with a certificate of the console's CA that
 * says urn:arcana:role:console and the node's host, and asks the others
 * by the same.  craft.c decides, as Raft has it: who leads, which
 * writes are committed.  This is its I/O: the term, the vote and the
 * log kept in <datadir>/cluster before anything is said, by a thread of
 * their own (a slow disk holds no lock and no loop while it writes), the
 * messages and the replies craft made with them sent once they are kept;
 * messages sent by a thread for each other node; committed writes applied
 * to the data directory, each a whole document, on every node alike.
 *
 * store_save() of a node is cluster_save(): the leader numbers the
 * document and answers once a majority holds it and it is written here;
 * a follower sends it to the leader and waits for the same.  Reads are
 * each node's own files.  The first node named, the seed, starts from
 * the documents it has; the others are sent them.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "console.h"
#include "craft.h"
#include "cluster.h"

#define	CL_DIR		"cluster"
#define	CL_TICK_MS	50
#define	CL_WAIT_MS	5000	/* a write waits for its commit at most */
#define	CL_DEFER_MS	10000	/* a follower's write, at the leader */
#define	CL_FRAME	(32 * 1024 * 1024)
#define	CL_BATCH_BYTES	(8 * 1024 * 1024)
#define	CL_SNAP_PART	(4 * 1024 * 1024)
#define	CL_LOG_MAX	1024	/* writes kept before the log is cut */
#define	CL_LOG_KEEP	256	/* and those kept after */
#define	CL_QUEUE	16
#define	CL_PENDING	64
#define	CL_LOCKS	64
#define	CL_LOCK_TTL_MS	30000	/* a lock held this long, unless renewed */
#define	CL_LOCK_TTL_MAX	600000	/* a holder's asking, at most */
#define	ROLE_CONSOLE	"URI:urn:arcana:role:console"

/* A reply to a node's request, sent with the messages of its batch. */
enum { R_NONE, R_VOTE, R_APPEND, R_SNAP };

struct batch_msg {
	int			 to;
	struct craft_msg	 m;	/* its entries its own */
};

/*
 * What one turn of craft has to be kept (log records to append, or the
 * log whole; the term, the vote and the base) and then said (messages,
 * a reply): written by the writer thread, batch after batch in order,
 * and only then sent.
 */
struct batch {
	struct batch		*next;
	struct buf		*log;
	bool			 whole;
	bool			 state;
	char			 line[256];
	size_t			 linelen;
	struct batch_msg	*out;
	size_t			 nout;
	size_t			 outcap;
	cbl_req			*req;
	int			 rkind;
	struct craft_msg	 r;
};

struct node {
	char		 name[CRAFT_NAME_MAX];
	char		 uri[256];
	char		 host[256];
	char		 origin[256];
};

struct peer {
	int			 idx;
	pthread_t		 thread;
	pthread_cond_t		 cv;
	struct craft_msg	 q[CL_QUEUE];
	int			 nq;
	cbl_conn		*conn;
	cbl_tls			*tls;
	struct acl_client	 cl;
	bool			 up;
	char			 why[256];	/* the last failure said */
};

struct pending {
	cbl_req		*req;
	uint64_t	 term;
	uint64_t	 seq;
	uint64_t	 since;
	char		 name[256];
};

static struct {
	bool			 on;
	bool			 started;	/* the worker's start is over */
	pthread_mutex_t		 mu;
	pthread_cond_t		 cv;	/* applied, or the leader known */
	struct craft		 c;
	struct node		 nodes[CRAFT_NODES_MAX];
	int			 nn;
	int			 self;
	char			 listen[256];
	struct peer		 peers[CRAFT_NODES_MAX];
	cbl_ctx			*ctx;
	cbl_loop		*loop;
	cbl_listener		*ls;
	char			 dir[MAXPATHLEN];
	char			 cert[MAXPATHLEN];
	char			 key[MAXPATHLEN];
	struct pending		 pend[CL_PENDING];
	uint64_t		 gen;
	/* What was written since the worker last read it again. */
	char			 changed[32][256];
	int			 nchanged;
	bool			 changed_all;
	/* A snapshot being received. */
	bool			 staging;
	/* A follower's own writes, to the leader. */
	pthread_mutex_t		 wmu;
	cbl_conn		*wconn;
	cbl_tls			*wtls;
	struct acl_client	 wcl;
	int			 wnode;
	/* The locks, as the log gave them: the leader grants by this. */
	struct {
		char		 name[256];
		char		 holder[128];
		uint64_t	 until;		/* by this node's clock */
		uint64_t	 token;		/* the write that gave it */
	}			 locks[CL_LOCKS];
	/* The locks this node's holders hold, till when for sure. */
	struct {
		char		 name[256];
		char		 holder[128];
		uint64_t	 token;
		uint64_t	 ttl;
		uint64_t	 until;
	}			 held[CL_LOCKS];
	/* The batches to keep, the first being written. */
	pthread_cond_t		 wcv;
	struct batch		*wq;
	struct batch		**wqtail;
	/* Applied, and what this node's own write waited for in vain: a
	 * reply says this node is behind while it is (any thread). */
	_Atomic uint64_t	 applied_pub;
	_Atomic uint64_t	 behind;
} cl = {
	.mu = PTHREAD_MUTEX_INITIALIZER,
	.cv = PTHREAD_COND_INITIALIZER,
	.wmu = PTHREAD_MUTEX_INITIALIZER,
	.wcv = PTHREAD_COND_INITIALIZER,
	.wqtail = &cl.wq,
	.wnode = -1,
};

static uint64_t
now_ms(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000);
}

bool
cluster_on(void)
{

	return (cl.on);
}

/* Does this node run what runs once in the cluster (the schedulers)? */
bool
cluster_leads(void)
{
	bool	leads;

	if (!cl.on)
		return (true);
	pthread_mutex_lock(&cl.mu);
	/* The leader on its lease: cut off, it leads nothing, and the
	 * one elected instead runs them; and once it knows every write
	 * committed before its term. */
	leads = craft_lease(&cl.c) && craft_ready(&cl.c);
	pthread_mutex_unlock(&cl.mu);
	return (leads);
}

/* This node's name in its cluster; NULL when it is in none. */
const char *
cluster_self(void)
{

	return (cl.on ? cl.nodes[cl.self].name : NULL);
}

/*
 * Has this node not yet applied a write of its own that the cluster
 * committed (its wait for it ran out)?  What it reads may be older than
 * what it said it changed: its replies say so.  Any thread.
 */
bool
cluster_behind(void)
{

	return (cl.on && atomic_load(&cl.behind) > atomic_load(
	    &cl.applied_pub));
}

/* How many committed writes this node applied: a cache compares it. */
uint64_t
cluster_gen(void)
{
	uint64_t	g;

	pthread_mutex_lock(&cl.mu);
	g = cl.gen;
	pthread_mutex_unlock(&cl.mu);
	return (g);
}

static int
node_of(const char *name)
{
	int	i;

	for (i = 0; i < cl.nn; i++)
		if (name != NULL && strcmp(cl.nodes[i].name, name) == 0)
			return (i);
	return (-1);
}

/* ---- web.conf ----------------------------------------------------- */

/* The host of a cblink URI: tcp://host:port, tcp://[v6]:port. */
static bool
uri_host(const char *uri, char *host, size_t len)
{
	const char	*p, *e;

	if ((p = strstr(uri, "://")) == NULL)
		return (false);
	p += 3;
	if (*p == '[') {
		if ((e = strchr(++p, ']')) == NULL)
			return (false);
	} else if ((e = strrchr(p, ':')) == NULL)
		e = p + strcspn(p, "/");
	if (e == p || (size_t)(e - p) >= len)
		return (false);
	snprintf(host, len, "%.*s", (int)(e - p), p);
	return (true);
}

int
cluster_config(const ucl_object_t *top, const char *path)
{
	const ucl_object_t	*c, *ns, *n, *o;
	ucl_object_iter_t	 it;
	struct node		*nd;
	const char		*self;

	if ((c = ucl_object_lookup(top, "cluster")) == NULL)
		return (0);
	if ((o = ucl_object_lookup(c, "self")) == NULL ||
	    (self = ucl_object_tostring(o)) == NULL ||
	    (o = ucl_object_lookup(c, "listen")) == NULL ||
	    ucl_object_tostring(o) == NULL ||
	    (ns = ucl_object_lookup(c, "nodes")) == NULL) {
		log_msg(LOG_ERR, "%s: cluster needs self, listen and nodes",
		    path);
		return (-1);
	}
	strlcpy(cl.listen, ucl_object_tostring(o), sizeof(cl.listen));
	it = NULL;
	while ((n = ucl_object_iterate(ns, &it, true)) != NULL) {
		if (cl.nn == CRAFT_NODES_MAX) {
			log_msg(LOG_ERR, "%s: %d nodes at most", path,
			    CRAFT_NODES_MAX);
			return (-1);
		}
		nd = &cl.nodes[cl.nn];
		if (strlcpy(nd->name, ucl_object_key(n), sizeof(nd->name)) >=
		    sizeof(nd->name) || (o = ucl_object_lookup(n, "uri")) ==
		    NULL || strlcpy(nd->uri, ucl_object_tostring(o),
		    sizeof(nd->uri)) >= sizeof(nd->uri) || (strncmp(nd->uri,
		    "unix:", 5) != 0 && !uri_host(nd->uri, nd->host,
		    sizeof(nd->host)))) {
			log_msg(LOG_ERR, "%s: cluster node %s: a uri, "
			    "tcp://host:port", path, ucl_object_key(n));
			return (-1);
		}
		if ((o = ucl_object_lookup(n, "origin")) != NULL)
			strlcpy(nd->origin, ucl_object_tostring(o),
			    sizeof(nd->origin));
		cl.nn++;
	}
	if ((cl.self = node_of(self)) == -1) {
		log_msg(LOG_ERR, "%s: cluster self %s is not one of its nodes",
		    path, self);
		return (-1);
	}
	cl.on = true;
	return (0);
}

/* ---- What is kept --------------------------------------------------- */

/* The directory path is in, fsync'ed: a file made or renamed in it is
 * kept with it. */
static int
dir_sync(const char *path)
{
	char	dir[MAXPATHLEN], *p;
	int	fd, rc;

	strlcpy(dir, path, sizeof(dir));
	if ((p = strrchr(dir, '/')) != NULL)
		*p = '\0';
	if ((fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) == -1)
		return (-1);
	rc = fsync(fd);
	(void)close(fd);
	return (rc);
}

static int
write_all(int fd, const void *p, size_t len)
{
	const uint8_t	*b = p;
	ssize_t		 n;

	while (len > 0) {
		if ((n = write(fd, b, len)) == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		b += n;
		len -= (size_t)n;
	}
	return (0);
}

static int
write_file(const char *path, const void *p, size_t len, mode_t mode)
{
	char	tmp[MAXPATHLEN];
	int	fd;

	snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path);
	if ((fd = mkstemp(tmp)) == -1)
		return (-1);
	if ((len > 0 && write_all(fd, p, len) == -1) || fchmod(fd, mode) ==
	    -1 || fsync(fd) == -1) {
		log_msg(LOG_ERR, "writing %s: %s", path, strerror(errno));
		(void)close(fd);
		unlink(tmp);
		return (-1);
	}
	if (close(fd) == -1 || rename(tmp, path) == -1) {
		log_msg(LOG_ERR, "writing %s: %s", path, strerror(errno));
		unlink(tmp);
		return (-1);
	}
	/* The rename kept too, before anything is said of it. */
	if (dir_sync(path) == -1) {
		log_msg(LOG_ERR, "writing %s: its directory: %s", path,
		    strerror(errno));
		return (-1);
	}
	return (0);
}

/* The term, the vote and the log's base, as the state file has them. */
static size_t
state_line(char *buf, size_t len)
{
	int	n;

	n = snprintf(buf, len, "%ju %s %ju %ju\n", (uintmax_t)cl.c.term,
	    cl.c.voted_for[0] != '\0' ? cl.c.voted_for : "-",
	    (uintmax_t)cl.c.base_term, (uintmax_t)cl.c.base_seq);
	return (n > 0 && (size_t)n < len ? (size_t)n : 0);
}

static void
state_write(const char *line, size_t len)
{
	char	path[MAXPATHLEN];

	snprintf(path, sizeof(path), "%s/state", cl.dir);
	if (write_file(path, line, len, 0600) == -1)
		fatalx("cluster: cannot keep its state");
}

struct rec {
	uint64_t	term;
	uint64_t	seq;
	uint32_t	nlen;
	uint32_t	blen;
	uint32_t	gone;
	uint32_t	pad;
};

static void
rec_put(struct buf *b, const struct craft_entry *e)
{
	struct rec	r;

	memset(&r, 0, sizeof(r));
	r.term = e->term;
	r.seq = e->seq;
	r.nlen = (uint32_t)strlen(e->name);
	r.blen = (uint32_t)e->len;
	r.gone = e->gone;
	buf_append(b, &r, sizeof(r));
	buf_append(b, e->name, r.nlen);
	if (r.blen > 0)
		buf_append(b, e->body, r.blen);
}

/* What craft says to keep, into the batch that says what came of it: the
 * log whole when it was cut, else what was added to it; with the lock. */
static void
persist(struct batch *b)
{
	size_t	i;

	if (cl.c.log_truncated) {
		if (b->log != NULL)
			buf_reset(b->log);
		else
			b->log = buf_alloc(4096);
		b->whole = true;
		for (i = 0; i < cl.c.nlog; i++)
			rec_put(b->log, &cl.c.log[i]);
		cl.c.state_dirty = true;	/* the base with it */
	} else if (cl.c.log_dirty_from != 0) {
		if (b->log == NULL)
			b->log = buf_alloc(4096);
		for (i = cl.c.log_dirty_from - cl.c.base_seq - 1; i <
		    cl.c.nlog; i++)
			rec_put(b->log, &cl.c.log[i]);
	}
	if (cl.c.state_dirty) {
		b->state = true;
		if ((b->linelen = state_line(b->line, sizeof(b->line))) == 0)
			fatalx("cluster: its state does not fit");
	}
	cl.c.state_dirty = false;
	cl.c.log_truncated = false;
	cl.c.log_dirty_from = 0;
}

/* A batch's log and state on the disk, fsync'ed (the writer thread's,
 * without the lock). */
static void
batch_write(struct batch *b)
{
	char	path[MAXPATHLEN], tmp[MAXPATHLEN];
	int	fd;
	bool	made;

	snprintf(path, sizeof(path), "%s/log", cl.dir);
	if (b->log != NULL && b->whole) {
		snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path);
		if ((fd = mkstemp(tmp)) == -1)
			fatalx("cluster: mkstemp %s: %s", tmp, strerror(errno));
		if (write_all(fd, b->log->data, b->log->offset) == -1 ||
		    fsync(fd) == -1 || close(fd) == -1 || rename(tmp, path) ==
		    -1 || dir_sync(path) == -1)
			fatalx("cluster: its log: %s", strerror(errno));
	} else if (b->log != NULL) {
		made = access(path, F_OK) == -1;
		if ((fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC,
		    0600)) == -1)
			fatalx("cluster: %s: %s", path, strerror(errno));
		if (write_all(fd, b->log->data, b->log->offset) == -1 ||
		    fsync(fd) == -1 || close(fd) == -1 || (made &&
		    dir_sync(path) == -1))
			fatalx("cluster: its log: %s", strerror(errno));
	}
	if (b->state)
		state_write(b->line, b->linelen);
}

static void
batch_free(struct batch *b)
{
	size_t	i, k;

	for (i = 0; i < b->nout; i++) {
		for (k = 0; k < b->out[i].m.nentries; k++) {
			free(b->out[i].m.entries[k].name);
			free(b->out[i].m.entries[k].body);
		}
		free(b->out[i].m.entries);
	}
	free(b->out);
	if (b->log != NULL)
		buf_free(b->log);
	free(b);
}

static void
restore(void)
{
	char		 path[MAXPATHLEN], vote[CRAFT_NAME_MAX];
	struct rec	 r;
	uintmax_t	 term, bt, bs;
	FILE		*fp;
	char		*name;
	uint8_t		*body;

	snprintf(path, sizeof(path), "%s/state", cl.dir);
	if ((fp = fopen(path, "r")) == NULL) {
		/* None yet: the seed starts from the documents it has,
		 * the base the others are sent; they wait for it. */
		if (cl.self == 0) {
			char	line[256];

			craft_restore(&cl.c, 1, "", 1, 1);
			state_write(line, state_line(line, sizeof(line)));
		}
		return;
	}
	if (fscanf(fp, "%ju %63s %ju %ju", &term, vote, &bt, &bs) != 4)
		fatalx("cluster: %s does not read", path);
	fclose(fp);
	craft_restore(&cl.c, term, strcmp(vote, "-") == 0 ? "" : vote, bt,
	    bs);
	snprintf(path, sizeof(path), "%s/log", cl.dir);
	if ((fp = fopen(path, "r")) == NULL)
		return;
	while (fread(&r, sizeof(r), 1, fp) == 1) {
		name = calloc(1, (size_t)r.nlen + 1);
		body = r.blen > 0 ? malloc(r.blen) : NULL;
		if (name == NULL || (r.blen > 0 && body == NULL) ||
		    fread(name, 1, r.nlen, fp) != r.nlen || (r.blen > 0 &&
		    fread(body, 1, r.blen, fp) != r.blen)) {
			free(name);
			free(body);
			break;		/* cut short: what came before stands */
		}
		if (r.seq > cl.c.base_seq)
			(void)craft_restore_entry(&cl.c, r.term, r.seq, name,
			    body, r.blen, r.gone != 0);
		free(name);
		free(body);
	}
	fclose(fp);
}

/* ---- The documents ---------------------------------------------------- */

/* A document's name: in the data directory, not in cluster/. */
static bool
doc_name_ok(const char *n)
{
	size_t	i;

	if (n == NULL || n[0] == '\0' || n[0] == '/' || n[0] == '.' ||
	    strlen(n) > 255 || strstr(n, "..") != NULL || strstr(n, "//") !=
	    NULL || strncmp(n, CL_DIR "/", sizeof(CL_DIR)) == 0)
		return (false);
	for (i = 0; n[i] != '\0'; i++)
		if (!(n[i] >= 'a' && n[i] <= 'z') && !(n[i] >= 'A' && n[i] <=
		    'Z') && !(n[i] >= '0' && n[i] <= '9') && n[i] != '.' &&
		    n[i] != '-' && n[i] != '_' && n[i] != '/')
			return (false);
	return (true);
}

/* One the cluster keeps: a JSON document, at the top, in runs/, in
 * sessions/ or in plugin-store/. */
static bool
replicated(const char *n)
{
	size_t	len;

	len = strlen(n);
	return (doc_name_ok(n) && len > 5 && strcmp(n + len - 5, ".json") ==
	    0 && (strchr(n, '/') == NULL || (strncmp(n, "runs/", 5) == 0 &&
	    strchr(n + 5, '/') == NULL) || (strncmp(n, SESSIONS_DIR "/",
	    sizeof(SESSIONS_DIR)) == 0 && strchr(n + sizeof(SESSIONS_DIR),
	    '/') == NULL) || (strncmp(n, "plugin-store/", 13) == 0 &&
	    strchr(n + 13, '/') == NULL)));
}

/* A document the worker reads again: what it keeps of it is stale. */
static void
changed(const char *name)
{
	int	i;

	if (name == NULL) {
		cl.changed_all = true;
		return;
	}
	for (i = 0; i < cl.nchanged; i++)
		if (strcmp(cl.changed[i], name) == 0)
			return;
	if (cl.nchanged == (int)nitems(cl.changed))
		cl.changed_all = true;
	else
		strlcpy(cl.changed[cl.nchanged++], name,
		    sizeof(cl.changed[0]));
}

/* Each document written since the last call, or NULL for every one. */
void
cluster_changes(void (*fn)(const char *))
{
	char	names[32][256];
	int	i, n;
	bool	all;

	pthread_mutex_lock(&cl.mu);
	all = cl.changed_all;
	n = cl.nchanged;
	memcpy(names, cl.changed, sizeof(names));
	cl.nchanged = 0;
	cl.changed_all = false;
	pthread_mutex_unlock(&cl.mu);
	if (all) {
		fn(NULL);
		return;
	}
	for (i = 0; i < n; i++)
		fn(names[i]);
}

/*
 * A lock as a write of the log: its name with LOCK_PREFIX, its body the
 * holder and how long it holds it; gone when let go.  Every node applies
 * it to its table, each by its own clock (a node's monotonic clock means
 * nothing to another), so that a new leader knows the locks the one
 * before granted, and grants none twice.  Its token is the write that
 * gave it to its holder, kept while the holder renews it.
 */
#define	LOCK_PREFIX	"\001lock\001"

/* The table's place of name, or a free one; -1 for none. */
static int
lock_slot(const char *name)
{
	uint64_t	now;
	int		i, free_i;

	now = now_ms();
	free_i = -1;
	for (i = 0; i < CL_LOCKS; i++) {
		if (strcmp(cl.locks[i].name, name) == 0)
			return (i);
		if (free_i == -1 && (cl.locks[i].name[0] == '\0' ||
		    cl.locks[i].until <= now))
			free_i = i;
	}
	return (free_i);
}

/* Held, and not run out, by holder (or by anyone, for NULL)? */
static bool
lock_live(int i, const char *holder)
{

	return (strcmp(cl.locks[i].name, "") != 0 && cl.locks[i].until >
	    now_ms() && (holder == NULL || strcmp(cl.locks[i].holder, holder) ==
	    0));
}

/* Lock i given to holder for ttl, by the write seq when it is not its
 * already. */
static void
lock_set(int i, const char *name, const char *holder, uint64_t ttl,
    uint64_t seq)
{

	if (strcmp(cl.locks[i].name, name) != 0 || !lock_live(i, holder)) {
		strlcpy(cl.locks[i].name, name, sizeof(cl.locks[i].name));
		strlcpy(cl.locks[i].holder, holder, sizeof(cl.locks[i].holder));
		cl.locks[i].token = seq;
	}
	cl.locks[i].until = now_ms() + ttl;
}

static void
lock_apply(const struct craft_entry *e)
{
	const char	*name = e->name + strlen(LOCK_PREFIX);
	char		 holder[128], *nl;
	uint64_t	 ttl;
	int		 i;

	snprintf(holder, sizeof(holder), "%.*s", (int)(e->len > sizeof(holder)
	    - 1 ? sizeof(holder) - 1 : e->len), (const char *)e->body);
	if ((nl = strchr(holder, '\n')) == NULL)
		return;
	*nl = '\0';
	ttl = strtoull(nl + 1, NULL, 10);
	/* Let go by its holder: another's, granted since, stays. */
	if (e->gone) {
		for (i = 0; i < CL_LOCKS; i++)
			if (strcmp(cl.locks[i].name, name) == 0 &&
			    strcmp(cl.locks[i].holder, holder) == 0)
				cl.locks[i].name[0] = '\0';
		return;
	}
	if ((i = lock_slot(name)) != -1)
		lock_set(i, name, holder, ttl, e->seq);
}

/* ---- The tokens ------------------------------------------------------- */

/*
 * The setup token and the enrolment tokens, kept by the cluster as its
 * log gives them, not by the node that made one: each change a write of
 * the log named TOKEN_PREFIX and its kind, its body lines of key=value,
 * an empty line, and (a setup alone) the document it writes.  The leader
 * proposes each, whoever asked, with its own clock's time in it (time=),
 * and every node applies them alike in order, to cl.tok and to
 * TOKENS_DOC, which the documents sent to a node carry.  A write that
 * spends a token holds only when the token is there, unspent, and (an
 * enrolment token) in time by that write's own time: of two committed,
 * the first wins and the second changes nothing, on every node.  What is
 * kept of a token is the SHA-256 of its secret, compared in constant
 * time, never the secret.  The first owner is itself such a write: the
 * console's credentials.json or users.json as it is to be, written only
 * by the write that spends the setup token, after which no setup token
 * is taken again.
 */
#define	TOKEN_PREFIX	"\001token\001"
#define	TOKENS_DOC	"cluster-tokens.json"
#define	TOK_HEAD_MAX	2048	/* a token write's lines */
#define	TOK_OUTCOMES	64	/* what came of the token writes, the last */

enum tok_kind { TK_SETUP_TOKEN, TK_SETUP, TK_ENROL_TOKEN, TK_ENROL, TK_N };
static const char *const tok_kinds[TK_N] = { "setup-token", "setup",
    "enrol-token", "enrol" };

/* The keys of a token write's lines, as bits. */
#define	TF_HASH		0x01
#define	TF_TIME		0x02
#define	TF_NODE		0x04
#define	TF_NAME		0x08
#define	TF_HOST		0x10
#define	TF_PORT		0x20
#define	TF_TTL		0x40
#define	TF_DOC		0x80
static const struct {
	const char	*key;
	int		 bit;
} tok_keys[] = {
	{ "hash", TF_HASH }, { "time", TF_TIME }, { "node", TF_NODE },
	{ "name", TF_NAME }, { "host", TF_HOST }, { "port", TF_PORT },
	{ "ttl", TF_TTL }, { "doc", TF_DOC },
};
/* What each kind says, every one of them. */
static const int tok_need[TK_N] = {
	[TK_SETUP_TOKEN] = TF_HASH | TF_TIME | TF_NODE,
	[TK_SETUP] = TF_HASH | TF_TIME | TF_DOC,
	[TK_ENROL_TOKEN] = TF_HASH | TF_TIME | TF_NAME | TF_HOST | TF_PORT |
	    TF_TTL,
	[TK_ENROL] = TF_HASH | TF_TIME,
};
/* The documents a setup may write: the first owner's. */
static const char *const tok_docs[] = { "credentials.json", "users.json" };

/* A token write, its body read. */
struct tok_entry {
	enum tok_kind	 kind;
	uint8_t		 hash[32];	/* SHA-256 of the token's secret */
	int64_t		 time;		/* the leader's clock as it proposed it */
	char		 node[CRAFT_NAME_MAX];	/* setup-token: whose it is */
	char		 name[65];	/* enrol-token: the server's name */
	char		 host[256];	/* its host */
	int		 port;
	int64_t		 ttl;		/* seconds it lasts */
	char		 doc[32];	/* setup: what it writes */
	const uint8_t	*doc_body;
	size_t		 doc_len;
};

struct tok_outcome {
	uint64_t		 seq;	/* the write; 0 a free place */
	bool			 ok;
	char			 why[96];
	struct cluster_enrol	 en;	/* enrol-token, enrol: the token */
};

/* The tokens, as the log made them: the leader and the others alike. */
static struct {
	uint64_t		 seq;		/* the last token write applied */
	uint64_t		 set_up;	/* the setup that spent it; 0 none */
	bool			 setup_live;
	uint8_t			 setup_hash[32];
	char			 setup_node[CRAFT_NAME_MAX];
	struct {
		bool		 used;
		uint8_t		 hash[32];
		struct cluster_enrol en;
	}			 enrol[CLUSTER_ENROL_MAX];
} tok;
static struct tok_outcome tok_out[TOK_OUTCOMES];

static void
hex_put(char *out, const uint8_t *p, size_t n)
{
	size_t	i;

	for (i = 0; i < n; i++)
		snprintf(out + 2 * i, 3, "%02x", p[i]);
}

/* n bytes of exactly 2n small hexadecimal digits; false else. */
static bool
hex_get(uint8_t *p, size_t n, const char *s, size_t len)
{
	size_t	i;
	int	hi, lo;

	if (s == NULL || len != 2 * n)
		return (false);
	for (i = 0; i < n; i++) {
		hi = s[2 * i] >= '0' && s[2 * i] <= '9' ? s[2 * i] - '0' :
		    s[2 * i] >= 'a' && s[2 * i] <= 'f' ? s[2 * i] - 'a' + 10 : -1;
		lo = s[2 * i + 1] >= '0' && s[2 * i + 1] <= '9' ? s[2 * i + 1] -
		    '0' : s[2 * i + 1] >= 'a' && s[2 * i + 1] <= 'f' ?
		    s[2 * i + 1] - 'a' + 10 : -1;
		if (hi == -1 || lo == -1)
			return (false);
		p[i] = (uint8_t)(hi << 4 | lo);
	}
	return (true);
}

/* Of len bytes, each one of the set (and printable)? */
static bool
chars_of(const char *s, size_t len, const char *set)
{
	size_t	i;

	for (i = 0; i < len; i++)
		if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] > 0x7e ||
		    (set != NULL && !(s[i] >= 'a' && s[i] <= 'z') && !(s[i] >=
		    'A' && s[i] <= 'Z') && !(s[i] >= '0' && s[i] <= '9') &&
		    strchr(set, s[i]) == NULL))
			return (false);
	return (true);
}

/* A decimal number of v's text, lo to hi; false else. */
static bool
num_get(const char *v, size_t len, int64_t lo, int64_t hi, int64_t *out)
{
	char		 buf[24], *end;
	long long	 n;

	if (len == 0 || len >= sizeof(buf) || !chars_of(v, len, "") ||
	    strspn(v, "0123456789") < len)
		return (false);
	memcpy(buf, v, len);
	buf[len] = '\0';
	errno = 0;
	n = strtoll(buf, &end, 10);
	if (errno != 0 || *end != '\0' || n < lo || n > hi)
		return (false);
	*out = n;
	return (true);
}

/*
 * A token write of name and body read into t, as a node reads whatever a
 * peer sent it: every key known to its kind and said once, every value
 * of its form and size, a setup's document a JSON object.  0, or -1.
 */
static int
tok_parse(const char *name, const uint8_t *body, size_t len,
    struct tok_entry *t)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	const char		*s, *end, *eol, *eq, *v;
	size_t			 vl, i;
	int64_t			 n;
	int			 k, seen, bit;
	bool			 ok;

	memset(t, 0, sizeof(*t));
	if (strncmp(name, TOKEN_PREFIX, strlen(TOKEN_PREFIX)) != 0)
		return (-1);
	name += strlen(TOKEN_PREFIX);
	for (k = 0; k < TK_N && strcmp(name, tok_kinds[k]) != 0; k++)
		;
	if (k == TK_N || body == NULL || len < 1)
		return (-1);
	t->kind = (enum tok_kind)k;
	s = (const char *)body;
	end = s + MIN(len, TOK_HEAD_MAX);
	seen = 0;
	for (;;) {
		if ((eol = memchr(s, '\n', (size_t)(end - s))) == NULL)
			return (-1);
		if (eol == s)
			break;		/* the empty line: the lines end */
		if ((eq = memchr(s, '=', (size_t)(eol - s))) == NULL)
			return (-1);
		v = eq + 1;
		vl = (size_t)(eol - v);
		for (i = 0, bit = 0; i < nitems(tok_keys); i++)
			if ((size_t)(eq - s) == strlen(tok_keys[i].key) &&
			    memcmp(s, tok_keys[i].key, (size_t)(eq - s)) == 0)
				bit = tok_keys[i].bit;
		if (bit == 0 || (seen & bit) != 0 || (tok_need[t->kind] & bit) ==
		    0)
			return (-1);
		seen |= bit;
		switch (bit) {
		case TF_HASH:
			ok = hex_get(t->hash, sizeof(t->hash), v, vl);
			break;
		case TF_TIME:
			ok = num_get(v, vl, 0, INT64_MAX / 2, &t->time);
			break;
		case TF_NODE:
			ok = vl > 0 && vl < sizeof(t->node) && chars_of(v, vl,
			    "._-");
			if (ok)
				memcpy(t->node, v, vl);
			break;
		case TF_NAME:
			ok = vl > 0 && vl < sizeof(t->name) && chars_of(v, vl,
			    NULL);
			if (ok)
				memcpy(t->name, v, vl);
			break;
		case TF_HOST:
			ok = vl > 0 && vl < sizeof(t->host) && chars_of(v, vl,
			    ".:-");
			if (ok)
				memcpy(t->host, v, vl);
			break;
		case TF_PORT:
			ok = num_get(v, vl, 1, 65535, &n);
			t->port = (int)n;
			break;
		case TF_TTL:
			ok = num_get(v, vl, 1, CLUSTER_ENROL_TTL_MAX, &t->ttl);
			break;
		case TF_DOC:
			for (i = 0, ok = false; i < nitems(tok_docs) && !ok; i++)
				ok = vl == strlen(tok_docs[i]) && memcmp(v,
				    tok_docs[i], vl) == 0;
			if (ok)
				memcpy(t->doc, v, vl);
			break;
		default:
			ok = false;
		}
		if (!ok)
			return (-1);
		s = eol + 1;
	}
	if (seen != tok_need[t->kind])
		return (-1);
	t->doc_body = (const uint8_t *)(s + 1);
	t->doc_len = len - (size_t)(s + 1 - (const char *)body);
	if (t->kind != TK_SETUP)
		return (t->doc_len == 0 ? 0 : -1);
	if (t->doc_len == 0 || t->doc_len > ACL_MAX_DOC)
		return (-1);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO);
	o = NULL;
	if (ucl_parser_add_chunk_full(p, t->doc_body, t->doc_len, 0,
	    UCL_DUPLICATE_APPEND, UCL_PARSE_UCL))
		o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	ok = o != NULL && ucl_object_type(o) == UCL_OBJECT;
	ucl_object_unref(o);
	return (ok ? 0 : -1);
}

/* t's body, as tok_parse() reads it, into b. */
static void
tok_body(const struct tok_entry *t, struct buf *b)
{
	char	hex[65];

	hex_put(hex, t->hash, sizeof(t->hash));
	buf_appendf(b, "hash=%s\ntime=%jd\n", hex, (intmax_t)t->time);
	switch (t->kind) {
	case TK_SETUP_TOKEN:
		buf_appendf(b, "node=%s\n", t->node);
		break;
	case TK_SETUP:
		buf_appendf(b, "doc=%s\n", t->doc);
		break;
	case TK_ENROL_TOKEN:
		buf_appendf(b, "name=%s\nhost=%s\nport=%d\nttl=%jd\n", t->name,
		    t->host, t->port, (intmax_t)t->ttl);
		break;
	default:
		break;
	}
	buf_append(b, "\n", 1);
	if (t->kind == TK_SETUP)
		buf_append(b, t->doc_body, t->doc_len);
}

/* The tokens as TOKENS_DOC has them, the snapshot's of the leader's or
 * this node's own; what does not read is not a token. */
static void
tok_load(void)
{
	const ucl_object_t	*o, *e;
	ucl_object_iter_t	 it;
	ucl_object_t		*top;
	const char		*s;
	int			 i;

	memset(&tok, 0, sizeof(tok));
	if ((top = store_load(TOKENS_DOC)) == NULL)
		return;
	if ((o = ucl_object_lookup(top, "seq")) != NULL)
		tok.seq = (uint64_t)ucl_object_toint(o);
	if ((o = ucl_object_lookup(top, "set_up")) != NULL)
		tok.set_up = (uint64_t)ucl_object_toint(o);
	if ((o = ucl_object_lookup(top, "setup")) != NULL &&
	    (s = ucl_str(o, "hash")) != NULL && hex_get(tok.setup_hash,
	    sizeof(tok.setup_hash), s, strlen(s)) && (s = ucl_str(o,
	    "node")) != NULL && strlen(s) < sizeof(tok.setup_node)) {
		strlcpy(tok.setup_node, s, sizeof(tok.setup_node));
		tok.setup_live = tok.set_up == 0;
	}
	it = NULL;
	i = 0;
	while ((e = ucl_object_iterate(ucl_object_lookup(top, "enrol"), &it,
	    true)) != NULL && i < CLUSTER_ENROL_MAX) {
		if ((s = ucl_str(e, "hash")) == NULL || !hex_get(
		    tok.enrol[i].hash, 32, s, strlen(s)) || ucl_str(e,
		    "name") == NULL || ucl_str(e, "host") == NULL)
			continue;
		strlcpy(tok.enrol[i].en.name, ucl_str(e, "name"),
		    sizeof(tok.enrol[i].en.name));
		strlcpy(tok.enrol[i].en.host, ucl_str(e, "host"),
		    sizeof(tok.enrol[i].en.host));
		tok.enrol[i].en.port = (int)ucl_object_toint(ucl_object_lookup(e,
		    "port"));
		tok.enrol[i].en.expires = ucl_object_toint(ucl_object_lookup(e,
		    "expires"));
		tok.enrol[i].used = true;
		i++;
	}
	ucl_object_unref(top);
}

/* The tokens into TOKENS_DOC, with the write that made them so. */
static void
tok_save(void)
{
	ucl_object_t	*top, *o, *a;
	unsigned char	*json;
	char		 hex[65];
	int		 i;

	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, ucl_object_fromint((int64_t)tok.seq),
	    "seq", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint((int64_t)tok.set_up),
	    "set_up", 0, false);
	if (tok.setup_live) {
		o = ucl_object_typed_new(UCL_OBJECT);
		hex_put(hex, tok.setup_hash, sizeof(tok.setup_hash));
		ucl_object_insert_key(o, ucl_object_fromstring(hex), "hash", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(tok.setup_node),
		    "node", 0, false);
		ucl_object_insert_key(top, o, "setup", 0, false);
	}
	a = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < CLUSTER_ENROL_MAX; i++) {
		if (!tok.enrol[i].used)
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		hex_put(hex, tok.enrol[i].hash, 32);
		ucl_object_insert_key(o, ucl_object_fromstring(hex), "hash", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(
		    tok.enrol[i].en.name), "name", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(
		    tok.enrol[i].en.host), "host", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(tok.enrol[i].en.port),
		    "port", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(
		    tok.enrol[i].en.expires), "expires", 0, false);
		ucl_array_append(a, o);
	}
	ucl_object_insert_key(top, a, "enrol", 0, false);
	if ((json = ucl_object_emit(top, UCL_EMIT_JSON)) == NULL ||
	    store_write(TOKENS_DOC, json, strlen((char *)json)) == -1)
		log_msg(LOG_ERR, "cluster: %s could not be written", TOKENS_DOC);
	free(json);
	ucl_object_unref(top);
}

/* The enrolment token of hash, its place; -1 for none.  Each one looked
 * at, each compared in constant time. */
static int
tok_enrol_find(const uint8_t *hash)
{
	int	i, found;

	found = -1;
	for (i = 0; i < CLUSTER_ENROL_MAX; i++)
		if (tok.enrol[i].used && timingsafe_bcmp(tok.enrol[i].hash, hash,
		    32) == 0)
			found = i;
	return (found);
}

/*
 * A token write committed, applied: the tokens changed as it says, when
 * it holds, on every node alike (by what the log says alone, the time
 * the leader put in it among that), and what came of it kept for whoever
 * waits for it here.  One applied before a restart (TOKENS_DOC has it)
 * changes nothing again.
 */
static void
tok_apply(const struct craft_entry *e)
{
	struct tok_entry	 t;
	struct tok_outcome	*out;
	const char		*why;
	int			 i, k;

	if (e->seq <= tok.seq)
		return;
	out = &tok_out[e->seq % TOK_OUTCOMES];
	memset(out, 0, sizeof(*out));
	out->seq = e->seq;
	why = NULL;
	if (e->gone || tok_parse(e->name, e->body, e->len, &t) == -1) {
		log_msg(LOG_ERR, "cluster: a token write that does not read, "
		    "at %ju: nothing done", (uintmax_t)e->seq);
		why = "not a token write";
		goto done;
	}
	/* The enrolment tokens run out by the leader's clock, as each
	 * write says it. */
	for (i = 0; i < CLUSTER_ENROL_MAX; i++)
		if (tok.enrol[i].used && tok.enrol[i].en.expires < t.time) {
			explicit_bzero(&tok.enrol[i], sizeof(tok.enrol[i]));
			tok.enrol[i].used = false;
		}
	switch (t.kind) {
	case TK_SETUP_TOKEN:
		if (tok.set_up != 0) {
			why = "this console is set up already";
			break;
		}
		tok.setup_live = true;
		memcpy(tok.setup_hash, t.hash, sizeof(tok.setup_hash));
		strlcpy(tok.setup_node, t.node, sizeof(tok.setup_node));
		break;
	case TK_SETUP:
		if (tok.set_up != 0) {
			why = "this console is set up already: sign in";
			break;
		}
		if (!tok.setup_live || timingsafe_bcmp(tok.setup_hash, t.hash,
		    sizeof(t.hash)) != 0) {
			why = "not the setup token";
			break;
		}
		/* Spent by this write, which makes the first owner. */
		if (store_write(t.doc, t.doc_body, t.doc_len) == -1)
			log_msg(LOG_ERR, "cluster: %s could not be written",
			    t.doc);
		cl.gen++;
		changed(t.doc);
		tok.set_up = e->seq;
		tok.setup_live = false;
		explicit_bzero(tok.setup_hash, sizeof(tok.setup_hash));
		break;
	case TK_ENROL_TOKEN:
		/* A free place, else the one that runs out first. */
		for (i = 0, k = 0; i < CLUSTER_ENROL_MAX; i++) {
			if (!tok.enrol[i].used) {
				k = i;
				break;
			}
			if (tok.enrol[i].en.expires < tok.enrol[k].en.expires)
				k = i;
		}
		memset(&tok.enrol[k], 0, sizeof(tok.enrol[k]));
		tok.enrol[k].used = true;
		memcpy(tok.enrol[k].hash, t.hash, sizeof(t.hash));
		strlcpy(tok.enrol[k].en.name, t.name,
		    sizeof(tok.enrol[k].en.name));
		strlcpy(tok.enrol[k].en.host, t.host,
		    sizeof(tok.enrol[k].en.host));
		tok.enrol[k].en.port = t.port;
		tok.enrol[k].en.expires = t.time + t.ttl;
		out->en = tok.enrol[k].en;
		break;
	case TK_ENROL:
		/* Not there: never made, spent, or run out. */
		if ((k = tok_enrol_find(t.hash)) == -1) {
			why = "unknown or expired token";
			break;
		}
		out->en = tok.enrol[k].en;
		explicit_bzero(&tok.enrol[k], sizeof(tok.enrol[k]));
		tok.enrol[k].used = false;
		break;
	default:
		why = "not a token write";
		break;
	}
done:
	out->ok = why == NULL;
	if (why != NULL)
		strlcpy(out->why, why, sizeof(out->why));
	tok.seq = e->seq;
	tok_save();
}

static void
apply_one(const struct craft_entry *e)
{
	char	path[MAXPATHLEN];

	if (strncmp(e->name, TOKEN_PREFIX, strlen(TOKEN_PREFIX)) == 0) {
		tok_apply(e);
		return;
	}
	/* The token writes' alone: none of a document's own. */
	if (strcmp(e->name, TOKENS_DOC) == 0)
		return;
	if (strncmp(e->name, LOCK_PREFIX, strlen(LOCK_PREFIX)) == 0) {
		/* The leader's own writes were in its table as it granted
		 * them: applied again late, an old grant would take a newer
		 * holder's place.  The followers', and a new leader's, from
		 * the log. */
		if (cl.c.role != CRAFT_LEADER || e->term != cl.c.term)
			lock_apply(e);
		return;
	}
	if (e->name[0] == '\0' || !doc_name_ok(e->name))
		return;
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, e->name);
	if (e->gone) {
		if (unlink(path) == -1 && errno != ENOENT)
			log_msg(LOG_ERR, "cluster: %s: %s", path,
			    strerror(errno));
	} else if (store_write(e->name, e->body, e->len) == -1)
		log_msg(LOG_ERR, "cluster: %s could not be written", path);
	cl.gen++;
	changed(e->name);
}

/* The applied write at seq of term? */
static bool
applied_as(uint64_t seq, uint64_t term)
{

	return (craft_applied_as(&cl.c, seq, term));
}

static void
pending_end(struct pending *p, bool ok, const char *why)
{
	struct acl_write_rsp	 rsp;
	struct acl_doc		 d;

	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = ok;
	rsp.error = why;
	if (ok) {
		memset(&d, 0, sizeof(d));
		d.name = p->name;
		d.has_term = d.has_seq = true;
		d.term = p->term;
		d.seq = p->seq;
		rsp.has_term = true;
		rsp.term = p->term;
		rsp.doc.n = 1;
		rsp.doc.v = &d;
	}
	(void)acl_write_reply(p->req, &rsp);
	(void)cbl_req_complete(p->req, 0);
	p->req = NULL;
}

static void	msg_copy(const struct craft_msg *, struct craft_msg *);
static void	batch_send(struct batch *);
static void	batch_reply(struct batch *);

/* A batch kept, or sent at once when there is nothing to keep and none
 * before it is still being kept; with the lock. */
static void
batch_queue(struct batch *b)
{

	if (cl.wq == NULL && b->log == NULL && !b->state) {
		batch_send(b);
		batch_reply(b);
		batch_free(b);
		return;
	}
	b->next = NULL;
	*cl.wqtail = b;
	cl.wqtail = &b->next;
	pthread_cond_signal(&cl.wcv);
}

/*
 * The writer thread: each batch kept on the disk, the lock not held, then
 * what it says sent.  A vote granted, a write acknowledged, a term taken
 * are said only once they are kept (Raft's Figure 2: before responding
 * to RPCs).
 */
static void *
writer_run(void *arg __unused)
{
	struct batch	*b;

	for (;;) {
		pthread_mutex_lock(&cl.mu);
		while (cl.wq == NULL)
			pthread_cond_wait(&cl.wcv, &cl.mu);
		b = cl.wq;
		pthread_mutex_unlock(&cl.mu);
		batch_write(b);
		pthread_mutex_lock(&cl.mu);
		if ((cl.wq = b->next) == NULL)
			cl.wqtail = &cl.wq;
		batch_send(b);
		pthread_mutex_unlock(&cl.mu);
		batch_reply(b);
		batch_free(b);
	}
	return (NULL);
}

/*
 * After craft has changed: what it says to keep put in a batch with what
 * it says to send, kept first and then sent (the writer thread's), and
 * what is committed applied.  The reply of kind rkind to node from's
 * request req is sent with the batch.  With the lock.
 */
static void
pump(cbl_req *req, int rkind, const char *from)
{
	const struct craft_entry *e;
	struct batch		*b;
	struct batch_msg	*no;
	size_t			 i, cap;
	int			 to, k, want;
	bool			 got;

	if ((b = calloc(1, sizeof(*b))) == NULL)
		fatalx("cluster: out of memory");
	persist(b);
	b->req = req;
	b->rkind = rkind;
	b->r.term = cl.c.term;
	want = rkind == R_VOTE ? CRAFT_VOTE_REPLY : rkind == R_APPEND ?
	    CRAFT_APPEND_REPLY : -1;
	got = false;
	for (i = 0; i < cl.c.nout; i++) {
		if (!got && want != -1 && (int)cl.c.out[i].type == want &&
		    strcmp(cl.c.out[i].to, from) == 0) {
			b->r = cl.c.out[i];
			b->r.entries = NULL;
			b->r.nentries = 0;
			got = true;
			continue;
		}
		if ((to = node_of(cl.c.out[i].to)) < 0 || to == cl.self)
			continue;
		if (b->nout == b->outcap) {
			cap = b->outcap == 0 ? 8 : b->outcap * 2;
			if ((no = realloc(b->out, cap * sizeof(*no))) == NULL)
				fatalx("cluster: out of memory");
			b->out = no;
			b->outcap = cap;
		}
		b->out[b->nout].to = to;
		msg_copy(&cl.c.out[i], &b->out[b->nout].m);
		b->nout++;
	}
	craft_out_clear(&cl.c);
	while ((e = craft_next_apply(&cl.c)) != NULL)
		apply_one(e);
	atomic_store(&cl.applied_pub, cl.c.applied);
	/* The leader's answers to the followers' writes. */
	for (k = 0; k < CL_PENDING; k++) {
		if (cl.pend[k].req == NULL || cl.pend[k].seq > cl.c.applied)
			continue;
		if (applied_as(cl.pend[k].seq, cl.pend[k].term))
			pending_end(&cl.pend[k], true, NULL);
		else
			pending_end(&cl.pend[k], false, "a new leader took "
			    "its place before it was written: write it again");
	}
	if (cl.c.nlog > CL_LOG_MAX) {
		craft_compact(&cl.c, CL_LOG_KEEP);
		persist(b);
	}
	batch_queue(b);
	pthread_cond_broadcast(&cl.cv);
}

/* ---- To the others ---------------------------------------------------- */

static void
msg_free(struct craft_msg *m)
{
	size_t	i;

	for (i = 0; i < m->nentries; i++) {
		free(m->entries[i].name);
		free(m->entries[i].body);
	}
	free(m->entries);
	m->entries = NULL;
	m->nentries = 0;
}

/* A message of craft's with its entries copied (they are the log's, and
 * the log changes): CL_BATCH_BYTES of them at most. */
static void
msg_copy(const struct craft_msg *m, struct craft_msg *c)
{
	size_t	i, bytes;

	*c = *m;
	c->entries = NULL;
	c->nentries = 0;
	if (m->nentries == 0 || (c->entries = calloc(m->nentries,
	    sizeof(*c->entries))) == NULL)
		return;
	for (i = 0, bytes = 0; i < m->nentries && (i == 0 || bytes +
	    m->entries[i].len <= CL_BATCH_BYTES); i++) {
		c->entries[i] = m->entries[i];
		c->entries[i].name = strdup(m->entries[i].name);
		c->entries[i].body = NULL;
		if (m->entries[i].len > 0 && (c->entries[i].body =
		    malloc(m->entries[i].len)) != NULL)
			memcpy(c->entries[i].body, m->entries[i].body,
			    m->entries[i].len);
		c->nentries = i + 1;
		bytes += m->entries[i].len;
	}
}

/* A message, copied, queued to the node's thread, which takes it; with
 * the lock. */
static void
send_out(int to, struct craft_msg c)
{
	struct peer		*p = &cl.peers[to];
	int			 k;

	/* An append makes the one before it moot. */
	if (c.type == CRAFT_APPEND)
		for (k = 0; k < p->nq; k++)
			if (p->q[k].type == CRAFT_APPEND) {
				msg_free(&p->q[k]);
				p->q[k] = c;
				pthread_cond_signal(&p->cv);
				return;
			}
	if (p->nq == CL_QUEUE) {
		msg_free(&p->q[0]);
		memmove(&p->q[0], &p->q[1], (CL_QUEUE - 1) * sizeof(p->q[0]));
		p->nq--;
	}
	p->q[p->nq++] = c;
	pthread_cond_signal(&p->cv);
}

/* A batch's messages to the nodes' threads, which take them; with the
 * lock. */
static void
batch_send(struct batch *b)
{
	size_t	i;

	for (i = 0; i < b->nout; i++) {
		send_out(b->out[i].to, b->out[i].m);
		b->out[i].m.entries = NULL;
		b->out[i].m.nentries = 0;
	}
	b->nout = 0;
}

/* The reply a batch carries, to the request it answers. */
static void
batch_reply(struct batch *b)
{
	struct acl_vote_rsp	 vr;
	struct acl_append_rsp	 ar;
	struct acl_snapshot_rsp	 sr;

	if (b->req == NULL)
		return;
	switch (b->rkind) {
	case R_VOTE:
		memset(&vr, 0, sizeof(vr));
		vr.has_term = vr.has_granted = true;
		vr.term = b->r.term;
		vr.granted = b->r.granted;
		(void)acl_vote_reply(b->req, &vr);
		break;
	case R_APPEND:
		memset(&ar, 0, sizeof(ar));
		ar.has_term = ar.has_ok = ar.has_last_term = ar.has_last_seq =
		    ar.has_sent_ms = true;
		ar.term = b->r.term;
		ar.ok = b->r.ok;
		ar.last_term = b->r.last_term;
		ar.last_seq = b->r.last_seq;
		ar.sent_ms = b->r.sent_ms;
		(void)acl_append_reply(b->req, &ar);
		break;
	case R_SNAP:
		memset(&sr, 0, sizeof(sr));
		sr.has_term = sr.has_ok = true;
		sr.term = b->r.term;
		sr.ok = true;
		(void)acl_snapshot_reply(b->req, &sr);
		break;
	}
	(void)cbl_req_complete(b->req, 0);
	b->req = NULL;
}

/* A failure to reach a node, logged when it is not the last one said. */
static void
peer_fail(struct peer *p, const char *what, int error)
{
	char	why[256];

	snprintf(why, sizeof(why), "%s: %s", what, error != 0 ?
	    strerror(error) : "refused");
	if (strcmp(why, p->why) != 0)
		log_msg(LOG_NOTICE, "cluster: %s: %s", cl.nodes[p->idx].name,
		    why);
	strlcpy(p->why, why, sizeof(p->why));
}

static void
peer_close(struct peer *p)
{

	if (p->conn == NULL)
		return;
	acl_client_fini(&p->cl);
	cbl_conn_free(p->conn);
	cbl_tls_free(p->tls);
	p->conn = NULL;
	p->tls = NULL;
}

/* A connection to node i, as a console of its cluster. */
static int
dial(int i, cbl_conn **connp, cbl_tls **tlsp, struct acl_client *c)
{
	const struct node	*n = &cl.nodes[i];
	cbl_conn		*conn;
	cbl_tls			*tls;

	*connp = NULL;
	*tlsp = NULL;
	tls = NULL;
	if (cbl_conn_new(cl.ctx, n->uri, 0, &conn) != 0)
		return (-1);
	if (strncmp(n->uri, "unix:", 5) != 0) {
		if (cbl_tls_new(&tls) != 0 || cbl_tls_set_cert(tls, cl.cert,
		    cl.key) != 0 || cbl_tls_set_ca(tls, cfg.tls_ca, NULL) !=
		    0 || cbl_tls_set_peer_name(tls, n->host) != 0) {
			cbl_conn_free(conn);
			cbl_tls_free(tls);
			return (-1);
		}
		(void)cbl_conn_set_tls(conn, tls);
	}
	if (cbl_conn_connect(conn) != 0 || acl_client_init(c, conn) != 0) {
		cbl_conn_free(conn);
		cbl_tls_free(tls);
		return (-1);
	}
	*connp = conn;
	*tlsp = tls;
	return (0);
}

static void
docs_of(const struct craft_msg *m, struct acl_doc *d)
{
	size_t	i;

	for (i = 0; i < m->nentries; i++) {
		memset(&d[i], 0, sizeof(d[i]));
		d[i].name = m->entries[i].name;
		d[i].has_term = d[i].has_seq = true;
		d[i].term = m->entries[i].term;
		d[i].seq = m->entries[i].seq;
		d[i].body.p = m->entries[i].body;
		d[i].body.len = m->entries[i].len;
		d[i].gone = m->entries[i].gone;
	}
}

/* The documents, as they are applied, read under the lock. */
struct snapdoc {
	char	 name[256];
	char	*body;
	size_t	 len;
};

static void
snap_read_dir(const char *sub, struct snapdoc **v, size_t *n, size_t *cap)
{
	DIR		*d;
	struct dirent	*e;
	char		 path[MAXPATHLEN], name[256];
	struct snapdoc	*nv;
	FILE		*fp;
	long		 len;

	snprintf(path, sizeof(path), "%s%s%s", cfg.datadir, sub[0] != '\0' ?
	    "/" : "", sub);
	if ((d = opendir(path)) == NULL)
		return;
	while ((e = readdir(d)) != NULL) {
		snprintf(name, sizeof(name), "%s%s%s", sub, sub[0] != '\0' ?
		    "/" : "", e->d_name);
		if (e->d_type != DT_REG || !replicated(name))
			continue;
		if (*n == *cap) {
			*cap = *cap == 0 ? 64 : *cap * 2;
			if ((nv = realloc(*v, *cap * sizeof(**v))) == NULL)
				break;
			*v = nv;
		}
		snprintf(path, sizeof(path), "%s/%s", cfg.datadir, name);
		if ((fp = fopen(path, "r")) == NULL)
			continue;
		if (fseek(fp, 0, SEEK_END) != 0 || (len = ftell(fp)) < 0 ||
		    len > ACL_MAX_DOC || fseek(fp, 0, SEEK_SET) != 0) {
			fclose(fp);
			continue;
		}
		strlcpy((*v)[*n].name, name, sizeof((*v)[*n].name));
		(*v)[*n].len = (size_t)len;
		if (((*v)[*n].body = malloc((size_t)len + 1)) == NULL ||
		    fread((*v)[*n].body, 1, (size_t)len, fp) != (size_t)len) {
			free((*v)[*n].body);
			fclose(fp);
			continue;
		}
		fclose(fp);
		(*n)++;
	}
	closedir(d);
}

static uint64_t
applied_term(void)
{
	const struct craft_entry *e;

	if (cl.c.applied == cl.c.base_seq)
		return (cl.c.base_term);
	return ((e = craft_entry_at(&cl.c, cl.c.applied)) != NULL ? e->term :
	    0);
}

/* Every document to node p, as they are applied now, in parts. */
static int
send_snapshot(struct peer *p, uint64_t *seqp)
{
	struct acl_snapshot_req	 rq;
	struct acl_snapshot_rsp	*rsp;
	struct snapdoc		*v = NULL;
	struct acl_doc		*d;
	size_t			 n = 0, cap = 0, i, j, bytes;
	uint64_t		 term, last_term, last_seq;
	int			 rc = 0, err;

	pthread_mutex_lock(&cl.mu);
	snap_read_dir("", &v, &n, &cap);
	snap_read_dir("runs", &v, &n, &cap);
	snap_read_dir(SESSIONS_DIR, &v, &n, &cap);
	snap_read_dir("plugin-store", &v, &n, &cap);
	term = cl.c.term;
	last_seq = cl.c.applied;
	last_term = applied_term();
	pthread_mutex_unlock(&cl.mu);
	if ((d = calloc(n + 1, sizeof(*d))) == NULL) {
		rc = -1;
		goto out;
	}
	i = 0;
	do {
		memset(&rq, 0, sizeof(rq));
		rq.node = cl.nodes[cl.self].name;
		rq.has_term = rq.has_last_term = rq.has_last_seq = true;
		rq.term = term;
		rq.last_term = last_term;
		rq.last_seq = last_seq;
		rq.first = i == 0;
		for (j = 0, bytes = 0; i + j < n && (j == 0 || bytes +
		    v[i + j].len <= CL_SNAP_PART); j++) {
			memset(&d[j], 0, sizeof(d[j]));
			d[j].name = v[i + j].name;
			d[j].body.p = v[i + j].body;
			d[j].body.len = v[i + j].len;
			bytes += v[i + j].len;
		}
		rq.doc.n = j;
		rq.doc.v = d;
		i += j;
		rq.last = i >= n;
		rsp = NULL;
		if ((err = acl_snapshot(&p->cl, &rq, &rsp)) != 0)
			peer_fail(p, "documents", err);
		if (err != 0 || rsp == NULL || !rsp->ok) {
			if (rsp != NULL && rsp->error != NULL)
				log_msg(LOG_NOTICE, "cluster: %s refused the "
				    "documents: %s", cl.nodes[p->idx].name,
				    rsp->error);
			acl_snapshot_rsp_free(rsp);
			rc = -1;
			break;
		}
		acl_snapshot_rsp_free(rsp);
	} while (i < n);
	*seqp = last_seq;
out:
	for (i = 0; i < n; i++)
		free(v[i].body);
	free(v);
	free(d);
	return (rc);
}

static void *
peer_run(void *arg)
{
	struct peer		*p = arg;
	struct craft_msg	 m, r;
	struct acl_doc		*d;
	uint64_t		 seq;
	int			 rc, err;

	for (;;) {
		pthread_mutex_lock(&cl.mu);
		while (p->nq == 0)
			pthread_cond_wait(&p->cv, &cl.mu);
		m = p->q[0];
		memmove(&p->q[0], &p->q[1], (size_t)(p->nq - 1) *
		    sizeof(p->q[0]));
		p->nq--;
		pthread_mutex_unlock(&cl.mu);
		if (p->conn == NULL && dial(p->idx, &p->conn, &p->tls,
		    &p->cl) != 0) {
			peer_fail(p, "cannot connect", 0);
			msg_free(&m);
			usleep(300000);
			continue;
		}
		memset(&r, 0, sizeof(r));
		strlcpy(r.from, cl.nodes[p->idx].name, sizeof(r.from));
		strlcpy(r.to, cl.nodes[cl.self].name, sizeof(r.to));
		rc = -1;
		if (m.type == CRAFT_VOTE) {
			struct acl_vote_req	 rq;
			struct acl_vote_rsp	*rsp = NULL;

			memset(&rq, 0, sizeof(rq));
			rq.node = cl.nodes[cl.self].name;
			rq.has_term = rq.has_last_term = rq.has_last_seq = true;
			rq.term = m.term;
			rq.last_term = m.last_term;
			rq.last_seq = m.last_seq;
			rq.pre_vote = m.pre;
			if ((err = acl_vote(&p->cl, &rq, &rsp)) != 0)
				peer_fail(p, "vote", err);
			if (err == 0 && rsp != NULL) {
				r.type = CRAFT_VOTE_REPLY;
				r.pre = m.pre;
				r.term = rsp->term;
				r.granted = rsp->granted;
				rc = 0;
			}
			acl_vote_rsp_free(rsp);
		} else if (m.type == CRAFT_APPEND) {
			struct acl_append_req	 rq;
			struct acl_append_rsp	*rsp = NULL;

			if ((d = calloc(m.nentries + 1, sizeof(*d))) != NULL) {
				docs_of(&m, d);
				memset(&rq, 0, sizeof(rq));
				rq.node = cl.nodes[cl.self].name;
				rq.has_term = rq.has_prev_term =
				    rq.has_prev_seq = rq.has_commit_seq =
				    rq.has_sent_ms = true;
				rq.term = m.term;
				rq.prev_term = m.prev_term;
				rq.prev_seq = m.prev_seq;
				rq.commit_seq = m.commit;
				rq.sent_ms = m.sent_ms;
				if (cl.nodes[cl.self].origin[0] != '\0')
					rq.origin = cl.nodes[cl.self].origin;
				rq.doc.n = m.nentries;
				rq.doc.v = d;
				if ((err = acl_append(&p->cl, &rq, &rsp)) != 0)
					peer_fail(p, "append", err);
				if (err == 0 && rsp != NULL) {
					r.type = CRAFT_APPEND_REPLY;
					r.term = rsp->term;
					r.ok = rsp->ok;
					r.last_term = rsp->last_term;
					r.last_seq = rsp->last_seq;
					r.sent_ms = rsp->has_sent_ms ?
					    rsp->sent_ms : 0;
					rc = 0;
				}
				acl_append_rsp_free(rsp);
				free(d);
			}
		} else if (m.type == CRAFT_SNAPSHOT_NEEDED) {
			if (send_snapshot(p, &seq) == 0) {
				pthread_mutex_lock(&cl.mu);
				craft_snapshot_done(&cl.c, cl.nodes[p->idx].name,
				    seq);
				pump(NULL, R_NONE, NULL);
				pthread_mutex_unlock(&cl.mu);
				msg_free(&m);
				continue;
			}
		}
		msg_free(&m);
		if (rc != 0) {
			peer_close(p);
			continue;
		}
		pthread_mutex_lock(&cl.mu);
		craft_recv(&cl.c, &r);
		pump(NULL, R_NONE, NULL);
		pthread_mutex_unlock(&cl.mu);
	}
	return (NULL);
}

/* ---- From the others ---------------------------------------------------- */

/* Is the peer node n: a console of this CA, under the node's host? */
static bool
peer_ok(cbl_req *req, const char *node, int *ip)
{
	const cbl_peer	*p = cbl_req_peer(req);
	const char	*san;
	char		 dns[300], ip6[300];
	size_t		 i, ns;
	bool		 role, host;
	int		 n;

	if ((n = node_of(node)) == -1 || n == cl.self)
		return (false);
	*ip = n;
	if (cbl_peer_transport(p) == CBL_TR_UNIX)
		return (true);	/* the socket's mode guards it */
	snprintf(dns, sizeof(dns), "DNS:%s", cl.nodes[n].host);
	snprintf(ip6, sizeof(ip6), "IP:%s", cl.nodes[n].host);
	role = host = false;
	ns = cbl_peer_san_count(p);
	for (i = 0; i < ns; i++) {
		if ((san = cbl_peer_san(p, i)) == NULL)
			continue;
		if (strcmp(san, ROLE_CONSOLE) == 0)
			role = true;
		else if (strcasecmp(san, dns) == 0 || strcmp(san, ip6) == 0)
			host = true;
	}
	return (role && host);
}

/* A vote asked: answered once what it changed (the term, the vote) is
 * kept. */
int
acl_vote_doit(cbl_req *req, const struct acl_vote_req *rq, void *arg __unused)
{
	struct craft_msg	 m;
	int			 n;

	if (!peer_ok(req, rq->node, &n))
		return (EACCES);
	if (cbl_req_defer(req) != 0)
		return (EIO);
	memset(&m, 0, sizeof(m));
	m.type = CRAFT_VOTE;
	strlcpy(m.from, rq->node, sizeof(m.from));
	strlcpy(m.to, cl.nodes[cl.self].name, sizeof(m.to));
	m.term = rq->term;
	m.last_term = rq->last_term;
	m.last_seq = rq->last_seq;
	m.pre = rq->pre_vote;
	pthread_mutex_lock(&cl.mu);
	craft_recv(&cl.c, &m);
	pump(req, R_VOTE, rq->node);
	pthread_mutex_unlock(&cl.mu);
	return (0);
}

/* The leader's writes: acknowledged once they are kept. */
int
acl_append_doit(cbl_req *req, const struct acl_append_req *rq,
    void *arg __unused)
{
	struct craft_msg	 m;
	struct craft_entry	*e;
	size_t			 i;
	int			 n;

	if (!peer_ok(req, rq->node, &n))
		return (EACCES);
	for (i = 0; i < rq->doc.n; i++)
		if (!rq->doc.v[i].has_term || !rq->doc.v[i].has_seq)
			return (EINVAL);
	if ((e = calloc(rq->doc.n + 1, sizeof(*e))) == NULL)
		return (ENOMEM);
	if (cbl_req_defer(req) != 0) {
		free(e);
		return (EIO);
	}
	for (i = 0; i < rq->doc.n; i++) {
		e[i].term = rq->doc.v[i].term;
		e[i].seq = rq->doc.v[i].seq;
		e[i].name = (char *)(uintptr_t)rq->doc.v[i].name;
		e[i].body = (uint8_t *)(uintptr_t)rq->doc.v[i].body.p;
		e[i].len = rq->doc.v[i].body.len;
		e[i].gone = rq->doc.v[i].gone;
	}
	memset(&m, 0, sizeof(m));
	m.type = CRAFT_APPEND;
	strlcpy(m.from, rq->node, sizeof(m.from));
	strlcpy(m.to, cl.nodes[cl.self].name, sizeof(m.to));
	m.term = rq->term;
	m.prev_term = rq->prev_term;
	m.prev_seq = rq->prev_seq;
	m.commit = rq->commit_seq;
	m.sent_ms = rq->has_sent_ms ? rq->sent_ms : 0;
	m.entries = e;
	m.nentries = rq->doc.n;
	pthread_mutex_lock(&cl.mu);
	craft_recv(&cl.c, &m);
	pump(req, R_APPEND, rq->node);
	pthread_mutex_unlock(&cl.mu);
	free(e);
	return (0);
}

static int
mkdirs_for(const char *path)
{
	char	buf[MAXPATHLEN], *p;

	strlcpy(buf, path, sizeof(buf));
	for (p = buf + 1; (p = strchr(p, '/')) != NULL; p++) {
		*p = '\0';
		if (mkdir(buf, 0700) == -1 && errno != EEXIST)
			return (-1);
		*p = '/';
	}
	return (0);
}

static int
snap_reply(cbl_req *req, bool ok, const char *why)
{
	struct acl_snapshot_rsp	rsp;

	memset(&rsp, 0, sizeof(rsp));
	rsp.has_term = rsp.has_ok = true;
	pthread_mutex_lock(&cl.mu);
	rsp.term = cl.c.term;
	pthread_mutex_unlock(&cl.mu);
	rsp.ok = ok;
	rsp.error = why;
	return (acl_snapshot_reply(req, &rsp));
}

/* The documents the leader has, in parts; the last makes them these. */
int
acl_snapshot_doit(cbl_req *req, const struct acl_snapshot_req *rq,
    void *arg __unused)
{
	char		 stage[MAXPATHLEN], path[MAXPATHLEN], name[256];
	DIR		*d;
	struct dirent	*e;
	size_t		 i;
	int		 n, k;
	const char	*subs[] = { "", "runs", SESSIONS_DIR, "plugin-store" };

	if (!peer_ok(req, rq->node, &n))
		return (EACCES);
	snprintf(stage, sizeof(stage), "%s/snap", cl.dir);
	if (rq->first) {
		/* Whatever was staged before is not this one. */
		for (k = (int)nitems(subs) - 1; k >= 0; k--) {
			snprintf(path, sizeof(path), "%s%s%s", stage,
			    subs[k][0] != '\0' ? "/" : "", subs[k]);
			if ((d = opendir(path)) == NULL)
				continue;
			while ((e = readdir(d)) != NULL)
				if (e->d_type == DT_REG) {
					snprintf(name, sizeof(name), "%s/%s",
					    path, e->d_name);
					unlink(name);
				}
			closedir(d);
			rmdir(path);
		}
		if (mkdir(stage, 0700) == -1 && errno != EEXIST)
			return (snap_reply(req, false, strerror(errno)));
		cl.staging = true;
	}
	if (!cl.staging)
		return (snap_reply(req, false, "no first part"));
	for (i = 0; i < rq->doc.n; i++) {
		if (!replicated(rq->doc.v[i].name))
			return (snap_reply(req, false, "not a document"));
		snprintf(path, sizeof(path), "%s/%s", stage,
		    rq->doc.v[i].name);
		if (mkdirs_for(path) == -1 || write_file(path,
		    rq->doc.v[i].body.p, rq->doc.v[i].body.len, 0600) == -1)
			return (snap_reply(req, false, "cannot stage it"));
	}
	if (!rq->last)
		return (snap_reply(req, true, NULL));
	cl.staging = false;
	if (cbl_req_defer(req) != 0)
		return (EIO);
	pthread_mutex_lock(&cl.mu);
	if (rq->term < cl.c.term) {
		pthread_mutex_unlock(&cl.mu);
		(void)snap_reply(req, false, "an old leader's");
		(void)cbl_req_complete(req, 0);
		return (0);
	}
	/* Applied as far already: its documents never go back, and the
	 * leader is told it has them. */
	if (!craft_snapshot_wanted(&cl.c, rq->term, rq->last_seq)) {
		craft_install_snapshot(&cl.c, rq->term, rq->last_term,
		    rq->last_seq, rq->node);
		pump(req, R_SNAP, rq->node);
		pthread_mutex_unlock(&cl.mu);
		return (0);
	}
	/* What is here and not there goes; what is there is put here. */
	for (k = 0; k < (int)nitems(subs); k++) {
		snprintf(path, sizeof(path), "%s%s%s", cfg.datadir,
		    subs[k][0] != '\0' ? "/" : "", subs[k]);
		if ((d = opendir(path)) == NULL)
			continue;
		while ((e = readdir(d)) != NULL) {
			snprintf(name, sizeof(name), "%s%s%s", subs[k],
			    subs[k][0] != '\0' ? "/" : "", e->d_name);
			if (e->d_type != DT_REG || !replicated(name))
				continue;
			snprintf(path, sizeof(path), "%s/%s", stage, name);
			if (access(path, F_OK) == -1) {
				snprintf(path, sizeof(path), "%s/%s",
				    cfg.datadir, name);
				unlink(path);
			}
		}
		closedir(d);
	}
	for (k = 0; k < (int)nitems(subs); k++) {
		snprintf(path, sizeof(path), "%s%s%s", stage, subs[k][0] !=
		    '\0' ? "/" : "", subs[k]);
		if ((d = opendir(path)) == NULL)
			continue;
		while ((e = readdir(d)) != NULL) {
			char	to[MAXPATHLEN];

			snprintf(name, sizeof(name), "%s%s%s", subs[k],
			    subs[k][0] != '\0' ? "/" : "", e->d_name);
			if (e->d_type != DT_REG || !replicated(name))
				continue;
			snprintf(path, sizeof(path), "%s/%s", stage, name);
			snprintf(to, sizeof(to), "%s/%s", cfg.datadir, name);
			if (mkdirs_for(to) == -1 || rename(path, to) == -1)
				log_msg(LOG_ERR, "cluster: %s: %s", to,
				    strerror(errno));
		}
		closedir(d);
	}
	/* The renames kept before the base that says they were made. */
	for (k = 0; k < (int)nitems(subs); k++) {
		snprintf(path, sizeof(path), "%s%s%s/.", cfg.datadir,
		    subs[k][0] != '\0' ? "/" : "", subs[k]);
		(void)dir_sync(path);
	}
	craft_install_snapshot(&cl.c, rq->term, rq->last_term, rq->last_seq,
	    rq->node);
	tok_load();
	cl.gen++;
	changed(NULL);
	/* Answered once its base and log are kept. */
	pump(req, R_SNAP, rq->node);
	pthread_mutex_unlock(&cl.mu);
	log_msg(LOG_NOTICE, "cluster: the documents of %s as of %ju taken",
	    rq->node, (uintmax_t)rq->last_seq);
	return (0);
}

static int	tok_propose(struct tok_entry *, uint64_t *, uint64_t *);

/*
 * A follower's token write, at the leader: read as any peer's word, and
 * proposed as the leader's own, with the leader's time in it (whatever the
 * follower's said); answered once it is applied here.  The setup token is
 * the leader's to make alone.
 */
static int
tok_write_doit(cbl_req *req, int from, const struct acl_doc *d)
{
	struct acl_write_rsp	 rsp;
	struct tok_entry	 t;
	uint64_t		 term, seq;
	int			 k;

	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	if (d->gone || tok_parse(d->name, d->body.p, d->body.len, &t) == -1 ||
	    t.kind == TK_SETUP_TOKEN) {
		log_msg(LOG_NOTICE, "cluster: a token write from %s refused: "
		    "not one a node asks for", cl.nodes[from].name);
		rsp.error = "not a token write a node asks for";
		return (acl_write_reply(req, &rsp));
	}
	pthread_mutex_lock(&cl.mu);
	for (k = 0; k < CL_PENDING && cl.pend[k].req != NULL; k++)
		;
	if (k == CL_PENDING || cl.c.role != CRAFT_LEADER) {
		pthread_mutex_unlock(&cl.mu);
		rsp.error = k == CL_PENDING ? "too many writes at once" :
		    "not the leader";
		return (acl_write_reply(req, &rsp));
	}
	if (cbl_req_defer(req) != 0) {
		pthread_mutex_unlock(&cl.mu);
		return (EIO);
	}
	if (tok_propose(&t, &term, &seq) != 0) {
		pthread_mutex_unlock(&cl.mu);
		rsp.error = "cannot propose it";
		(void)acl_write_reply(req, &rsp);
		(void)cbl_req_complete(req, 0);
		return (0);
	}
	cl.pend[k].req = req;
	cl.pend[k].term = term;
	cl.pend[k].seq = seq;
	cl.pend[k].since = now_ms();
	snprintf(cl.pend[k].name, sizeof(cl.pend[k].name), "%s",
	    tok_kinds[t.kind]);
	pthread_mutex_unlock(&cl.mu);
	return (0);
}

/* A follower's write, at the leader: answered once it is written. */
int
acl_write_doit(cbl_req *req, const struct acl_write_req *rq,
    void *arg __unused)
{
	struct acl_write_rsp	 rsp;
	const struct acl_doc	*d;
	uint64_t		 term, seq;
	int			 n, k;

	if (!peer_ok(req, rq->node, &n))
		return (EACCES);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	if (rq->doc.n == 1 && rq->doc.v[0].name != NULL &&
	    strncmp(rq->doc.v[0].name, TOKEN_PREFIX, strlen(TOKEN_PREFIX)) == 0)
		return (tok_write_doit(req, n, &rq->doc.v[0]));
	if (rq->doc.n != 1 || !replicated(rq->doc.v[0].name) ||
	    strcmp(rq->doc.v[0].name, TOKENS_DOC) == 0) {
		rsp.error = "one document of the data directory";
		return (acl_write_reply(req, &rsp));
	}
	d = &rq->doc.v[0];
	pthread_mutex_lock(&cl.mu);
	for (k = 0; k < CL_PENDING && cl.pend[k].req != NULL; k++)
		;
	if (k == CL_PENDING || craft_propose(&cl.c, d->name, d->body.p,
	    d->body.len, d->gone, &term, &seq) != 0) {
		pthread_mutex_unlock(&cl.mu);
		rsp.error = k == CL_PENDING ? "too many writes at once" :
		    "not the leader";
		return (acl_write_reply(req, &rsp));
	}
	if (cbl_req_defer(req) != 0) {
		pump(NULL, R_NONE, NULL);
		pthread_mutex_unlock(&cl.mu);
		return (EIO);
	}
	cl.pend[k].req = req;
	cl.pend[k].term = term;
	cl.pend[k].seq = seq;
	cl.pend[k].since = now_ms();
	strlcpy(cl.pend[k].name, d->name, sizeof(cl.pend[k].name));
	pump(NULL, R_NONE, NULL);
	pthread_mutex_unlock(&cl.mu);
	return (0);
}

/* The lock written to the log (given or renewed for ttl, so the others
 * know it, or let go): the write's term and place, which the holder
 * waits to see applied as it was proposed.  With the lock. */
static int
lock_write(const char *name, const char *holder, uint64_t ttl, bool gone,
    uint64_t *termp, uint64_t *seqp)
{
	char		lname[256 + sizeof(LOCK_PREFIX)], body[160];
	uint64_t	term, seq;

	snprintf(lname, sizeof(lname), "%s%s", LOCK_PREFIX, name);
	snprintf(body, sizeof(body), "%s\n%ju", holder, (uintmax_t)ttl);
	if (craft_propose(&cl.c, lname, (const uint8_t *)body, strlen(body),
	    gone, &term, &seq) != 0)
		return (-1);
	if (termp != NULL)
		*termp = term;
	if (seqp != NULL)
		*seqp = seq;
	pump(NULL, R_NONE, NULL);
	return (0);
}

/*
 * The leader's lock name given to holder for ttl ms, or renewed for it:
 * true, the write that says so (its term and place) and the lock's token
 * out.  With the lock.
 */
static bool
lock_try(const char *name, const char *holder, uint64_t ttl,
    uint64_t *termp, uint64_t *seqp, uint64_t *tokenp, const char **why)
{
	int	i;

	*why = NULL;
	if (cl.c.role != CRAFT_LEADER) {
		*why = "not the leader";
		return (false);
	}
	/* On its lease alone: a leader cut off grants nothing, so that
	 * the one elected instead and it never grant the same lock. */
	if (!craft_lease(&cl.c)) {
		*why = "the leader has not heard from a majority";
		return (false);
	}
	/* And once it knows the locks the leaders before it gave. */
	if (!craft_ready(&cl.c)) {
		*why = "the leader has not committed a write of its term yet";
		return (false);
	}
	if ((i = lock_slot(name)) == -1) {
		*why = "too many locks held";
		return (false);
	}
	if (strcmp(cl.locks[i].name, name) == 0 && lock_live(i, NULL) &&
	    !lock_live(i, holder)) {
		*why = "held";
		return (false);
	}
	if (lock_write(name, holder, ttl, false, termp, seqp) == -1) {
		*why = "cannot propose it";
		return (false);
	}
	/* Its place again: what was applied meanwhile may have moved it. */
	if ((i = lock_slot(name)) == -1) {
		*why = "too many locks held";
		return (false);
	}
	lock_set(i, name, holder, ttl, *seqp);
	*tokenp = cl.locks[i].token;
	return (true);
}

static void
lock_drop(const char *name, const char *holder)
{
	int	i;

	for (i = 0; i < CL_LOCKS; i++)
		if (strcmp(cl.locks[i].name, name) == 0 &&
		    strcmp(cl.locks[i].holder, holder) == 0) {
			cl.locks[i].name[0] = '\0';
			if (cl.c.role == CRAFT_LEADER)
				(void)lock_write(name, holder, 0, true, NULL,
				    NULL);
		}
}

int
acl_lock_doit(cbl_req *req, const struct acl_lock_req *rq, void *arg __unused)
{
	struct acl_lock_rsp	 rsp;
	const char		*why;
	uint64_t		 ttl, term, seq, token;
	int			 n;
	bool			 ok;

	if (!peer_ok(req, rq->node, &n))
		return (EACCES);
	ttl = rq->has_ttl_ms && rq->ttl_ms > 0 && rq->ttl_ms <=
	    CL_LOCK_TTL_MAX ? rq->ttl_ms : 10000;
	term = seq = token = 0;
	pthread_mutex_lock(&cl.mu);
	ok = lock_try(rq->lock, rq->holder, ttl, &term, &seq, &token, &why);
	pthread_mutex_unlock(&cl.mu);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = ok;
	rsp.error = why;
	rsp.has_term = rsp.has_lock_seq = rsp.has_token = ok;
	rsp.term = term;
	rsp.lock_seq = seq;
	rsp.token = token;
	return (acl_lock_reply(req, &rsp));
}

int
acl_unlock_doit(cbl_req *req, const struct acl_unlock_req *rq,
    void *arg __unused)
{
	struct acl_unlock_rsp	rsp;
	int			n;

	if (!peer_ok(req, rq->node, &n))
		return (EACCES);
	pthread_mutex_lock(&cl.mu);
	lock_drop(rq->lock, rq->holder);
	pthread_mutex_unlock(&cl.mu);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = true;
	return (acl_unlock_reply(req, &rsp));
}

/* ---- The clock ---------------------------------------------------------- */

static void
tick(cbl_timer *t __unused, void *arg __unused)
{
	uint64_t	now;
	int		k;

	now = now_ms();
	pthread_mutex_lock(&cl.mu);
	craft_tick(&cl.c, now);
	pump(NULL, R_NONE, NULL);
	for (k = 0; k < CL_PENDING; k++)
		if (cl.pend[k].req != NULL && (now - cl.pend[k].since >
		    CL_DEFER_MS || cbl_req_cancelled(cl.pend[k].req)))
			pending_end(&cl.pend[k], false, "not committed in time: "
			    "the cluster has no majority here");
	pthread_mutex_unlock(&cl.mu);
}

static void *
loop_run(void *arg __unused)
{

	(void)cbl_loop_run(cl.loop);
	return (NULL);
}

/* ---- This node's writes ------------------------------------------------- */

/* Wait, with the lock held, until applied reaches seq or the deadline. */
static bool
wait_applied(uint64_t seq, uint64_t deadline) __no_lock_analysis
{
	struct timespec	ts;
	uint64_t	now;

	while (cl.c.applied < seq) {
		if ((now = now_ms()) >= deadline)
			return (false);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_nsec += (long)((deadline - now) % 1000) * 1000000 + 0;
		ts.tv_sec += (time_t)((deadline - now) / 1000) + ts.tv_nsec /
		    1000000000;
		ts.tv_nsec %= 1000000000;
		(void)pthread_cond_timedwait(&cl.cv, &cl.mu, &ts);
	}
	return (true);
}

/* The connection of this node's own asks to the leader; with wmu. */
static bool
leader_client(int leader, char *err, size_t errlen)
{

	if (cl.wconn != NULL && cl.wnode != leader) {
		acl_client_fini(&cl.wcl);
		cbl_conn_free(cl.wconn);
		cbl_tls_free(cl.wtls);
		cl.wconn = NULL;
		cl.wtls = NULL;
	}
	if (cl.wconn == NULL) {
		if (dial(leader, &cl.wconn, &cl.wtls, &cl.wcl) != 0) {
			snprintf(err, errlen, "the leader, %s, does not answer",
			    cl.nodes[leader].name);
			return (false);
		}
		cl.wnode = leader;
	}
	return (true);
}

static void
leader_drop(void)
{

	if (cl.wconn == NULL)
		return;
	acl_client_fini(&cl.wcl);
	cbl_conn_free(cl.wconn);
	cbl_tls_free(cl.wtls);
	cl.wconn = NULL;
	cl.wtls = NULL;
}

/* A follower's write, sent to the leader; its sequence, or 0. */
static uint64_t
write_to(int leader, const char *name, const void *body, size_t len,
    bool gone, char *err, size_t errlen)
{
	struct acl_write_req	 rq;
	struct acl_write_rsp	*rsp = NULL;
	struct acl_doc		 d;
	uint64_t		 seq = 0;

	pthread_mutex_lock(&cl.wmu);
	if (!leader_client(leader, err, errlen)) {
		pthread_mutex_unlock(&cl.wmu);
		return (0);
	}
	memset(&d, 0, sizeof(d));
	d.name = name;
	d.body.p = body;
	d.body.len = len;
	d.gone = gone;
	memset(&rq, 0, sizeof(rq));
	rq.node = cl.nodes[cl.self].name;
	rq.doc.n = 1;
	rq.doc.v = &d;
	if (acl_write(&cl.wcl, &rq, &rsp) != 0 || rsp == NULL) {
		leader_drop();
		snprintf(err, errlen, "the leader, %s, did not answer",
		    cl.nodes[leader].name);
	} else if (!rsp->ok || rsp->doc.n != 1 || !rsp->doc.v[0].has_seq)
		snprintf(err, errlen, "%s", rsp->error != NULL ? rsp->error :
		    "the leader did not take it");
	else
		seq = rsp->doc.v[0].seq;
	acl_write_rsp_free(rsp);
	pthread_mutex_unlock(&cl.wmu);
	return (seq);
}

/*
 * A document written through the cluster: 0 once a majority holds it and
 * it is written here too, -1 if it could not be within CL_WAIT_MS.  A
 * follower's write the leader committed is 0 even when this node has not
 * written it within CL_WAIT_MS: then cluster_behind() says so, and every
 * reply of this node with it, until it has.
 */
int
cluster_save(const char *name, const void *body, size_t len, bool gone)
{
	char		 err[256];
	uint64_t	 deadline, term, seq;
	int		 leader;

	if (!replicated(name))
		return (store_write(name, body, len));
	/* The token writes' alone (tok_apply()). */
	if (strcmp(name, TOKENS_DOC) == 0)
		return (-1);
	/*
	 * While the worker starts, no majority can be waited for (the
	 * loop is not running yet): what is written then is the
	 * defaults each node makes alike, in memory; the next change
	 * writes them.
	 */
	/* Not started: nothing would be written, which must not pass for
	 * written. */
	if (!cl.started)
		return (-1);
	deadline = now_ms() + CL_WAIT_MS;
	err[0] = '\0';
	pthread_mutex_lock(&cl.mu);
	for (;;) {
		if (cl.c.role == CRAFT_LEADER) {
			if (craft_propose(&cl.c, name, body, len, gone, &term,
			    &seq) != 0) {
				snprintf(err, sizeof(err), "cannot propose it");
				break;
			}
			pump(NULL, R_NONE, NULL);
			if (!wait_applied(seq, deadline)) {
				snprintf(err, sizeof(err), "not committed in "
				    "time: the cluster has no majority here");
				break;
			}
			if (!applied_as(seq, term)) {
				snprintf(err, sizeof(err), "a new leader took "
				    "its place before it was written");
				break;
			}
			pthread_mutex_unlock(&cl.mu);
			return (0);
		}
		if ((leader = node_of(cl.c.leader)) >= 0 && leader !=
		    cl.self) {
			pthread_mutex_unlock(&cl.mu);
			seq = write_to(leader, name, body, len, gone, err,
			    sizeof(err));
			pthread_mutex_lock(&cl.mu);
			if (seq != 0) {
				/*
				 * Committed: here once the leader says so.  Not
				 * here in time, it is the cluster's all the same
				 * (accepted), and until it is here too this
				 * node's replies say it is behind.
				 */
				if (!wait_applied(seq, deadline)) {
					if (atomic_load(&cl.behind) < seq)
						atomic_store(&cl.behind, seq);
					pthread_mutex_unlock(&cl.mu);
					log_msg(LOG_NOTICE, "cluster: %s accepted "
					    "as %ju, not yet written here", name,
					    (uintmax_t)seq);
					return (0);
				}
				pthread_mutex_unlock(&cl.mu);
				return (0);
			}
		}
		if (now_ms() >= deadline || !wait_applied(cl.c.applied + 1,
		    MIN(deadline, now_ms() + 200))) {
			if (now_ms() >= deadline) {
				if (err[0] == '\0')
					snprintf(err, sizeof(err), "no leader: "
					    "the cluster has no majority here");
				break;
			}
		}
	}
	pthread_mutex_unlock(&cl.mu);
	log_msg(LOG_ERR, "cluster: %s not written: %s", name, err);
	return (-1);
}

/* ---- This node's token writes ------------------------------------------ */

/* The token write t proposed by the leader, its time the leader's clock's
 * now, whoever asked: its term and place.  With the lock. */
static int
tok_propose(struct tok_entry *t, uint64_t *termp, uint64_t *seqp)
{
	struct buf	*b;
	char		 name[64];
	int		 rc;

	t->time = (int64_t)time(NULL);
	snprintf(name, sizeof(name), "%s%s", TOKEN_PREFIX, tok_kinds[t->kind]);
	b = buf_alloc(256 + t->doc_len);
	tok_body(t, b);
	rc = craft_propose(&cl.c, name, (const uint8_t *)b->data, b->offset,
	    false, termp, seqp);
	buf_free(b);
	if (rc == 0)
		pump(NULL, R_NONE, NULL);
	return (rc);
}

/* What came of the token write seq, applied here: 1 it held, 0 it did not
 * (why), -1 not known here (the documents sent instead).  With the lock. */
static int
tok_outcome(uint64_t seq, struct tok_outcome *o, char *why, size_t len)
{
	const struct tok_outcome	*out = &tok_out[seq % TOK_OUTCOMES];

	if (out->seq != seq) {
		snprintf(why, len, "this node took the cluster's documents "
		    "instead of the write: what came of it is not known here");
		return (-1);
	}
	if (o != NULL)
		*o = *out;
	if (!out->ok)
		snprintf(why, len, "%s", out->why);
	return (out->ok ? 1 : 0);
}

/*
 * A token write t through the cluster, from this node: proposed by the
 * leader (this one, or sent it), and once it is applied here, what came
 * of it into *o: 1 it held, 0 it did not (why), -1 it is not known whether
 * it did (why: no majority, no leader, not applied here in time).  A write
 * sent to the leader is sent once: asked again after no answer, a spend
 * could be refused that the first one made.
 */
static int
tok_write(struct tok_entry *t, struct tok_outcome *o, char *why, size_t len)
{
	struct buf	*b;
	char		 name[64];
	uint64_t	 deadline, term, seq;
	int		 leader, rc;

	why[0] = '\0';
	if (!cl.started) {
		snprintf(why, len, "the console is still starting");
		return (-1);
	}
	snprintf(name, sizeof(name), "%s%s", TOKEN_PREFIX, tok_kinds[t->kind]);
	deadline = now_ms() + CL_WAIT_MS;
	rc = -1;
	pthread_mutex_lock(&cl.mu);
	for (;;) {
		if (cl.c.role == CRAFT_LEADER) {
			if (tok_propose(t, &term, &seq) != 0)
				snprintf(why, len, "cannot propose it");
			else if (!wait_applied(seq, deadline))
				snprintf(why, len, "not committed in time: the "
				    "cluster has no majority here");
			else if (!applied_as(seq, term))
				snprintf(why, len, "a new leader took its place "
				    "before it was written");
			else
				rc = tok_outcome(seq, o, why, len);
			break;
		}
		if ((leader = node_of(cl.c.leader)) >= 0 && leader != cl.self) {
			pthread_mutex_unlock(&cl.mu);
			b = buf_alloc(256 + t->doc_len);
			tok_body(t, b);
			seq = write_to(leader, name, b->data, b->offset, false, why,
			    len);
			buf_free(b);
			pthread_mutex_lock(&cl.mu);
			if (seq == 0)
				break;
			/* Committed: what came of it is known once it is
			 * applied here, as on every node. */
			if (!wait_applied(seq, now_ms() + CL_WAIT_MS))
				snprintf(why, len, "the cluster took it, and this "
				    "node has not applied it yet: what came of it "
				    "is not known here");
			else
				rc = tok_outcome(seq, o, why, len);
			break;
		}
		if (now_ms() >= deadline) {
			snprintf(why, len, "no leader: the cluster has no "
			    "majority here");
			break;
		}
		(void)wait_applied(cl.c.applied + 1, MIN(deadline, now_ms() +
		    200));
	}
	pthread_mutex_unlock(&cl.mu);
	if (rc == -1)
		log_msg(LOG_ERR, "cluster: a %s write: %s", tok_kinds[t->kind],
		    why);
	return (rc);
}

/*
 * The cluster's setup token as the log has it: CLUSTER_SETUP_DONE once a
 * setup spent one; CLUSTER_SETUP_TOKEN while one is there, its hash and
 * the node whose setup-token has its text out; CLUSTER_SETUP_NONE before
 * the leader made one, the leader's name out ("" while there is none).
 */
int
cluster_setup_state(uint8_t *hash, char *node, size_t len)
{
	int	st;

	pthread_mutex_lock(&cl.mu);
	if (tok.set_up != 0) {
		st = CLUSTER_SETUP_DONE;
		snprintf(node, len, "%s", "");
	} else if (tok.setup_live) {
		st = CLUSTER_SETUP_TOKEN;
		memcpy(hash, tok.setup_hash, sizeof(tok.setup_hash));
		snprintf(node, len, "%s", tok.setup_node);
	} else {
		st = CLUSTER_SETUP_NONE;
		snprintf(node, len, "%s", cl.c.role == CRAFT_LEADER ?
		    cl.nodes[cl.self].name : cl.c.leader);
	}
	pthread_mutex_unlock(&cl.mu);
	return (st);
}

/* The setup token of hash this leader made, through the log: 0 once
 * committed and applied here, -1 (why) else.  The leader's alone. */
int
cluster_setup_make(const uint8_t *hash, char *why, size_t len)
{
	struct tok_entry	t;

	pthread_mutex_lock(&cl.mu);
	if (cl.c.role != CRAFT_LEADER) {
		pthread_mutex_unlock(&cl.mu);
		snprintf(why, len, "not the leader");
		return (-1);
	}
	pthread_mutex_unlock(&cl.mu);
	memset(&t, 0, sizeof(t));
	t.kind = TK_SETUP_TOKEN;
	memcpy(t.hash, hash, sizeof(t.hash));
	strlcpy(t.node, cl.nodes[cl.self].name, sizeof(t.node));
	return (tok_write(&t, NULL, why, len) == 1 ? 0 : -1);
}

/*
 * The console set up by the setup token of hash: the document doc (the
 * first owner's credentials.json or users.json) written on every node by
 * the write that spends the token.  1 this one was the first, 0 it was
 * not (why: set up already, not the token), -1 not known (why).
 */
int
cluster_setup_spend(const uint8_t *hash, const char *doc, const void *body,
    size_t blen, char *why, size_t len)
{
	struct tok_entry	t;

	memset(&t, 0, sizeof(t));
	t.kind = TK_SETUP;
	memcpy(t.hash, hash, sizeof(t.hash));
	strlcpy(t.doc, doc, sizeof(t.doc));
	t.doc_body = body;
	t.doc_len = blen;
	return (tok_write(&t, NULL, why, len));
}

/*
 * An enrolment token of hash for name, its host and port, lasting ttl s
 * from the time the leader puts in its write: 0 once it is the cluster's
 * and applied here, when it expires out (by the leader's clock); -1, why.
 */
int
cluster_enrol_make(const uint8_t *hash, const char *name, const char *host,
    int port, int ttl, int64_t *expires, char *why, size_t len)
{
	struct tok_entry	t;
	struct tok_outcome	o;

	memset(&t, 0, sizeof(t));
	t.kind = TK_ENROL_TOKEN;
	memcpy(t.hash, hash, sizeof(t.hash));
	if (strlcpy(t.name, name, sizeof(t.name)) >= sizeof(t.name) ||
	    strlcpy(t.host, host, sizeof(t.host)) >= sizeof(t.host)) {
		snprintf(why, len, "too long");
		return (-1);
	}
	t.port = port;
	t.ttl = ttl;
	if (tok_write(&t, &o, why, len) != 1)
		return (-1);
	*expires = o.en.expires;
	return (0);
}

/* Is the enrolment token of hash the cluster's, unspent?  It into *en.
 * Whether it is in time is the spend's to say, by the leader's clock. */
bool
cluster_enrol_find(const uint8_t *hash, struct cluster_enrol *en)
{
	int	i;

	pthread_mutex_lock(&cl.mu);
	if ((i = tok_enrol_find(hash)) != -1)
		*en = tok.enrol[i].en;
	pthread_mutex_unlock(&cl.mu);
	return (i != -1);
}

/* The enrolment token of hash spent through the log: 1 by this write, the
 * token into *en; 0 not (why: spent, run out, never made); -1 not known. */
int
cluster_enrol_spend(const uint8_t *hash, struct cluster_enrol *en,
    char *why, size_t len)
{
	struct tok_entry	t;
	struct tok_outcome	o;
	int			rc;

	memset(&t, 0, sizeof(t));
	t.kind = TK_ENROL;
	memcpy(t.hash, hash, sizeof(t.hash));
	if ((rc = tok_write(&t, &o, why, len)) == 1)
		*en = o.en;
	return (rc);
}

/* ---- Locks of the cluster ------------------------------------------------ */

#define	CL_LOCK_WAIT_MS	10000

static void
holder_of(char *buf, size_t len)
{

	snprintf(buf, len, "%s/%lx", cl.nodes[cl.self].name, (unsigned long)
	    (uintptr_t)pthread_self());
}

/* The lock holder holds by this node's word, kept till until (by this
 * node's clock); with the lock. */
static void
held_set(const char *name, const char *holder, uint64_t token, uint64_t ttl,
    uint64_t until)
{
	int	i, free_i;

	free_i = -1;
	for (i = 0; i < CL_LOCKS; i++) {
		if (strcmp(cl.held[i].name, name) == 0 &&
		    strcmp(cl.held[i].holder, holder) == 0)
			break;
		if (free_i == -1 && cl.held[i].name[0] == '\0')
			free_i = i;
	}
	if (i == CL_LOCKS && (i = free_i) == -1)
		return;
	strlcpy(cl.held[i].name, name, sizeof(cl.held[i].name));
	strlcpy(cl.held[i].holder, holder, sizeof(cl.held[i].holder));
	cl.held[i].token = token;
	cl.held[i].ttl = ttl;
	cl.held[i].until = until;
}

static int
held_find(const char *name, const char *holder)
{
	int	i;

	for (i = 0; i < CL_LOCKS; i++)
		if (strcmp(cl.held[i].name, name) == 0 &&
		    strcmp(cl.held[i].holder, holder) == 0)
			return (i);
	return (-1);
}

/*
 * The cluster's lock name taken by holder for ttl ms (or renewed), asked
 * until wait ms have gone (once for 0): held once the write that gave it
 * is applied here as the leader proposed it, which makes every write the
 * leader had committed before it written here too.  A leader that loses
 * its place before the write is committed gave nothing: its holder asks
 * again.  The lock's fencing token into *tokenp, the write that gave it
 * to holder; the holder is sure of it until ttl from when it asked, less
 * what the clocks may drift.
 */
bool
cluster_lock_as(const char *name, const char *holder, uint64_t ttl,
    uint64_t wait, uint64_t *tokenp)
{
	struct acl_lock_req	 rq;
	struct acl_lock_rsp	*rsp;
	char			 err[256];
	const char		*why;
	uint64_t		 deadline, asked, term, seq, token;
	int			 leader;
	bool			 got, held;

	*tokenp = 0;
	if (!cl.on || !cl.started)
		return (true);
	if (ttl > CL_LOCK_TTL_MAX)
		ttl = CL_LOCK_TTL_MAX;
	deadline = now_ms() + wait;
	do {
		asked = now_ms();
		got = false;
		term = seq = token = 0;
		pthread_mutex_lock(&cl.mu);
		if (cl.c.role == CRAFT_LEADER) {
			got = lock_try(name, holder, ttl, &term, &seq, &token,
			    &why);
			pthread_mutex_unlock(&cl.mu);
		} else {
			leader = node_of(cl.c.leader);
			pthread_mutex_unlock(&cl.mu);
			if (leader >= 0 && leader != cl.self) {
				pthread_mutex_lock(&cl.wmu);
				if (leader_client(leader, err, sizeof(err))) {
					memset(&rq, 0, sizeof(rq));
					rq.node = cl.nodes[cl.self].name;
					rq.lock = name;
					rq.holder = holder;
					rq.has_ttl_ms = true;
					rq.ttl_ms = (uint32_t)ttl;
					rsp = NULL;
					if (acl_lock(&cl.wcl, &rq, &rsp) != 0 ||
					    rsp == NULL)
						leader_drop();
					else if (rsp->ok && rsp->has_term &&
					    rsp->has_lock_seq && rsp->has_token) {
						got = true;
						term = rsp->term;
						seq = rsp->lock_seq;
						token = rsp->token;
					}
					acl_lock_rsp_free(rsp);
				}
				pthread_mutex_unlock(&cl.wmu);
			}
		}
		if (got) {
			pthread_mutex_lock(&cl.mu);
			held = wait_applied(seq, MAX(deadline, now_ms() +
			    CL_WAIT_MS)) && applied_as(seq, term);
			if (held)
				held_set(name, holder, token, ttl, asked + ttl -
				    CRAFT_DRIFT_MS);
			pthread_mutex_unlock(&cl.mu);
			if (held) {
				*tokenp = token;
				return (true);
			}
			log_msg(LOG_NOTICE, "cluster: the lock %s given by a "
			    "leader that lost its place before it was written",
			    name);
		}
		if (now_ms() >= deadline)
			break;
		usleep(50000);
	} while (now_ms() < deadline);
	if (wait > 0)
		log_msg(LOG_ERR, "cluster: the lock %s not had in time", name);
	return (false);
}

/*
 * Is the lock holder took (its token) still held, right before what it
 * guards is done?  Renewed when half its time has gone; false when it
 * ran out or another holds it now.
 */
bool
cluster_lock_held(const char *name, const char *holder, uint64_t token)
{
	uint64_t	now, ttl, t;
	int		i;
	bool		fresh;

	if (!cl.on || !cl.started)
		return (true);
	now = now_ms();
	pthread_mutex_lock(&cl.mu);
	if ((i = held_find(name, holder)) == -1 || cl.held[i].token != token) {
		pthread_mutex_unlock(&cl.mu);
		return (false);
	}
	ttl = cl.held[i].ttl;
	fresh = cl.held[i].until > now && cl.held[i].until - now > ttl / 2;
	pthread_mutex_unlock(&cl.mu);
	if (fresh)
		return (true);
	return (cluster_lock_as(name, holder, ttl, 0, &t) && t == token);
}

void
cluster_unlock_as(const char *name, const char *holder)
{
	struct acl_unlock_req	 rq;
	struct acl_unlock_rsp	*rsp;
	char			 err[256];
	int			 leader, i;

	if (!cl.on || !cl.started)
		return;
	pthread_mutex_lock(&cl.mu);
	if ((i = held_find(name, holder)) != -1)
		cl.held[i].name[0] = '\0';
	if (cl.c.role == CRAFT_LEADER) {
		lock_drop(name, holder);
		pthread_mutex_unlock(&cl.mu);
		return;
	}
	leader = node_of(cl.c.leader);
	pthread_mutex_unlock(&cl.mu);
	if (leader < 0 || leader == cl.self)
		return;		/* it runs out by itself */
	pthread_mutex_lock(&cl.wmu);
	if (leader_client(leader, err, sizeof(err))) {
		memset(&rq, 0, sizeof(rq));
		rq.node = cl.nodes[cl.self].name;
		rq.lock = name;
		rq.holder = holder;
		rsp = NULL;
		if (acl_unlock(&cl.wcl, &rq, &rsp) != 0)
			leader_drop();
		acl_unlock_rsp_free(rsp);
	}
	pthread_mutex_unlock(&cl.wmu);
}

/*
 * What is read, changed and written again by one node of the cluster at
 * a time (labels, templates, prefix lists): the cluster's lock name, by
 * this thread, besides the caller's flock(2) of its own node; taken,
 * every write the leader had committed is written here first, so that
 * what is read is the newest.  False when it was not had within
 * CL_LOCK_WAIT_MS: the write that follows then fails for want of a
 * majority anyway.
 */
bool
cluster_lock(const char *name)
{
	char		holder[128];
	uint64_t	token;

	if (!cl.on || !cl.started)
		return (true);
	holder_of(holder, sizeof(holder));
	return (cluster_lock_as(name, holder, CL_LOCK_TTL_MS, CL_LOCK_WAIT_MS,
	    &token));
}

void
cluster_unlock(const char *name)
{
	char	holder[128];

	if (!cl.on || !cl.started)
		return;
	holder_of(holder, sizeof(holder));
	cluster_unlock_as(name, holder);
}

/* ---- Start ---------------------------------------------------------------- */

/* cbl_user_f: a node's request, made for whoever it says or for none. */
static int
peer_user(const cbl_peer *p, const char *said, char *name, size_t len,
    bool *recovery, void *arg)
{

	(void)p;
	(void)recovery;
	(void)arg;
	(void)snprintf(name, len, "%s", said != NULL ? said : "");
	return (0);
}

int
cluster_init(void)
{
	const char	*peers[CRAFT_NODES_MAX];
	char		 err[256];
	cbl_tls		*tls;
	cbl_timer	*t;
	pthread_t	 tid;
	int		 i, np, error;
	bool		 unix_;

	if (!cl.on)
		return (0);
	snprintf(cl.dir, sizeof(cl.dir), "%s/%s", cfg.datadir, CL_DIR);
	if (mkdir(cl.dir, 0700) == -1 && errno != EEXIST) {
		log_msg(LOG_ERR, "%s: %s", cl.dir, strerror(errno));
		return (-1);
	}
	unix_ = strncmp(cl.listen, "unix:", 5) == 0;
	snprintf(cl.cert, sizeof(cl.cert), "%s/node.pem", cl.dir);
	snprintf(cl.key, sizeof(cl.key), "%s/node.key", cl.dir);
	if (!unix_ && pki_node_cert(cl.nodes[cl.self].host, cl.cert, cl.key,
	    err, sizeof(err)) == -1) {
		log_msg(LOG_ERR, "cluster: %s", err);
		return (-1);
	}
	np = 0;
	for (i = 0; i < cl.nn; i++)
		if (i != cl.self)
			peers[np++] = cl.nodes[i].name;
	craft_init(&cl.c, cl.nodes[cl.self].name, peers, np, now_ms(),
	    (uint32_t)arc4random());
	restore();
	tok_load();
	if ((error = cbl_ctx_new(&cl.ctx)) != 0 ||
	    (error = cbl_loop_new(cl.ctx, &cl.loop)) != 0) {
		log_msg(LOG_ERR, "cluster: cblink: %s", strerror(error));
		return (-1);
	}
	(void)cbl_ctx_set_limit(cl.ctx, CBL_LIM_MAX_FRAME, CL_FRAME);
	(void)cbl_ctx_set_limit(cl.ctx, CBL_LIM_MAX_ATTRS, ACL_MAX_DOCS * 8 +
	    64);
	(void)cbl_ctx_set_limit(cl.ctx, CBL_LIM_REQUEST_MS, 5000);
	/* A node's request says the user it was made for; this family has
	 * no access rules of users, so whoever it names is let through. */
	(void)cbl_ctx_set_user(cl.ctx, peer_user, NULL);
	if ((error = acl_register(cl.ctx, NULL, NULL)) != 0) {
		log_msg(LOG_ERR, "cluster: its family: %s", strerror(error));
		return (-1);
	}
	if ((error = cbl_listener_new(cl.ctx, cl.listen, unix_ ?
	    CBL_LF_UNIX_TRUSTED : 0, &cl.ls)) != 0) {
		log_msg(LOG_ERR, "cluster: %s: %s", cl.listen,
		    strerror(error));
		return (-1);
	}
	if (unix_)
		error = cbl_listener_set_unix_perm(cl.ls, 0600, (uid_t)-1,
		    (gid_t)-1);
	else if (cbl_tls_new(&tls) != 0 || cbl_tls_set_cert(tls, cl.cert,
	    cl.key) != 0 || cbl_tls_set_ca(tls, cfg.tls_ca, NULL) != 0)
		error = EINVAL;
	else
		error = cbl_listener_set_tls(cl.ls, tls);
	if (error != 0 || (error = cbl_listener_start(cl.ls, cl.loop)) != 0) {
		log_msg(LOG_ERR, "cluster: %s: %s", cl.listen,
		    cbl_listener_errstr(cl.ls));
		return (-1);
	}
	if (cbl_loop_timer(cl.loop, CL_TICK_MS, CBL_TF_REPEAT, tick, NULL,
	    &t) != 0) {
		log_msg(LOG_ERR, "cluster: its clock");
		return (-1);
	}
	for (i = 0; i < cl.nn; i++) {
		if (i == cl.self)
			continue;
		cl.peers[i].idx = i;
		pthread_cond_init(&cl.peers[i].cv, NULL);
		if (pthread_create(&cl.peers[i].thread, NULL, peer_run,
		    &cl.peers[i]) != 0) {
			log_msg(LOG_ERR, "cluster: pthread_create");
			return (-1);
		}
		(void)pthread_detach(cl.peers[i].thread);
	}
	if (pthread_create(&tid, NULL, writer_run, NULL) != 0)
		return (-1);
	(void)pthread_detach(tid);
	if (pthread_create(&tid, NULL, loop_run, NULL) != 0)
		return (-1);
	(void)pthread_detach(tid);
	log_msg(LOG_NOTICE, "cluster: node %s of %d, on %s",
	    cl.nodes[cl.self].name, cl.nn, cl.listen);
	return (0);
}

/*
 * One of the nodes' web origins: a browser signed in on a.console.example
 * is one of b.console.example's too (the relying party ID is a name they
 * share, console.example).
 */
bool
cluster_origin(const char *o)
{
	int	i;

	for (i = 0; cl.on && o != NULL && i < cl.nn; i++)
		if (cl.nodes[i].origin[0] != '\0' && strcmp(o,
		    cl.nodes[i].origin) == 0)
			return (true);
	return (false);
}

/* The worker has started: writes go to the cluster from now on. */
void
cluster_started(void)
{

	cl.started = true;
}

/* The cluster as this node knows it, for arcana-console's cluster. */
void
cluster_status(ucl_object_t *o)
{
	ucl_object_t	*arr, *n;
	int		 i;

	ucl_object_insert_key(o, ucl_object_frombool(cl.on), "on", 0, false);
	if (!cl.on)
		return;
	pthread_mutex_lock(&cl.mu);
	ucl_object_insert_key(o, ucl_object_fromstring(cl.nodes[cl.self].name),
	    "self", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(cl.c.role ==
	    CRAFT_LEADER ? "leader" : cl.c.role == CRAFT_CANDIDATE ?
	    "candidate" : "follower"), "role", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(cl.c.leader), "leader",
	    0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)cl.c.term),
	    "term", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)cl.c.commit),
	    "commit", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)cl.c.applied),
	    "applied", 0, false);
	/* A write of this node's own the cluster committed, not yet
	 * written here. */
	if (atomic_load(&cl.behind) > cl.c.applied)
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)
		    atomic_load(&cl.behind)), "behind", 0, false);
	ucl_object_insert_key(o, ucl_object_frombool(craft_lease(&cl.c)),
	    "lease", 0, false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < cl.nn; i++) {
		n = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(n, ucl_object_fromstring(
		    cl.nodes[i].name), "name", 0, false);
		ucl_object_insert_key(n, ucl_object_fromstring(
		    cl.nodes[i].origin), "origin", 0, false);
		if (i != cl.self && cl.c.role == CRAFT_LEADER) {
			int	k;

			for (k = 0; k < cl.c.npeers; k++)
				if (strcmp(cl.c.peers[k].name,
				    cl.nodes[i].name) == 0)
					ucl_object_insert_key(n,
					    ucl_object_fromint((int64_t)
					    cl.c.peers[k].match), "match", 0,
					    false);
		}
		ucl_array_append(arr, n);
	}
	ucl_object_insert_key(o, arr, "nodes", 0, false);
	pthread_mutex_unlock(&cl.mu);
}

/* GET arcana-console's cluster: the nodes, who leads, how far each has
 * come. */
int
api_cluster(struct http_request *req)
{
	ucl_object_t	*o;

	if (!guard(req, false))
		return (WEB_OK);
	o = ucl_object_typed_new(UCL_OBJECT);
	cluster_status(o);
	return (reply_json(req, 200, o));
}
