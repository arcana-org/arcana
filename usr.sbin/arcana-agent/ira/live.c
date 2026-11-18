/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Ira: a job's program followed while it runs.  What a job's program
 * writes, standard output and standard error as they come (each read
 * from its own pipe: what one writes just after the other may come
 * first), is kept beside the capture run_exec_max() makes (exec.c), a
 * live copy of the step's, while the program runs; whoever follows the
 * step (arcana-stream's exec-follow, job= and step=) is sent it from
 * its start, then each new piece as it comes, and the stream is
 * half-closed when the program has exited and all of it was sent.
 *
 * A program run with keys in its words or its input keeps no output
 * (exec.c), and has no live copy.  What a request runs for its own
 * peer is told to it in its reply; jobs alone are followed, their
 * trace read by other threads anyway.  The copy is let go once the
 * program has exited and no one follows: the step's output is in its
 * trace from then on, and a follow of it is refused saying so.
 *
 * A read of the job while the program runs (gula/trace.c's step_fill())
 * carries the last LIVE_TAIL bytes of the copy as the step's output so
 * far, kept apart from the copy's max: the job's view shows where it is
 * without following it.
 *
 * Each follower has a thread of its own, sending as there is room (as
 * a pcap-log file goes out, luxuria/idsfiles.c); the program's thread
 * only adds to the copy and wakes them.
 */

#include <sys/param.h>

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"
#include "ystream.h"

#define	LIVE_FOLLOWERS	16		/* streams at once, all steps' */
#define	LIVE_CHUNK	(16 * 1024)	/* what a data message carries */
#define	LIVE_ROOM	(LIVE_CHUNK + 4096)
/* What a read of the running job carries of the step: its last bytes. */
#define	LIVE_TAIL	(16 * 1024)

struct live {
	pthread_mutex_t	 lock;
	pthread_cond_t	 wake;
	char		*buf;		/* NULL once let go */
	size_t		 len;
	size_t		 cap;
	size_t		 max;
	bool		 truncated;
	bool		 done;		/* the program has exited */
	int		 nfollow;
	atomic_int	 refs;
	/*
	 * The last LIVE_TAIL bytes, kept past max too: a ring, put bytes
	 * written in all, for a read of the job while it runs
	 * (live_tail()).
	 */
	char		 tail[LIVE_TAIL];
	uint64_t	 put;
};

struct follow {
	struct live	*l;
	cbl_stream	*s;
	bool		 closed;	/* l's lock */
	int		 refs;		/* the thread's, the stream's (l's lock) */
};

static pthread_mutex_t	live_lock = PTHREAD_MUTEX_INITIALIZER;
static int		nfollowers;

struct live *
live_new(void)
{
	struct live	*l;

	if ((l = calloc(1, sizeof(*l))) == NULL)
		return (NULL);
	pthread_mutex_init(&l->lock, NULL);
	pthread_cond_init(&l->wake, NULL);
	/* What a step keeps of both outputs, at most. */
	l->max = 2 * ARC_MAX_OUTPUT;
	atomic_init(&l->refs, 1);
	return (l);
}

void
live_ref(struct live *l)
{

	atomic_fetch_add(&l->refs, 1);
}

void
live_rele(struct live *l)
{

	if (l == NULL || atomic_fetch_sub(&l->refs, 1) != 1)
		return;
	free(l->buf);
	pthread_mutex_destroy(&l->lock);
	pthread_cond_destroy(&l->wake);
	free(l);
}

/* len bytes at p added to l's ring of its last.  l's lock held. */
static void
tail_put(struct live *l, const char *p, size_t len)
{
	size_t	at, n;

	if (len > LIVE_TAIL) {
		l->put += len - LIVE_TAIL;
		p += len - LIVE_TAIL;
		len = LIVE_TAIL;
	}
	while (len > 0) {
		at = (size_t)(l->put % LIVE_TAIL);
		n = MIN(len, LIVE_TAIL - at);
		memcpy(l->tail + at, p, n);
		l->put += n;
		p += n;
		len -= n;
	}
}

/*
 * What the program has written so far, its last LIVE_TAIL bytes at
 * most, from w's pool; *lenp 0 when nothing yet.  *cutp whether more
 * came before them.
 */
const char *
live_tail(struct work *w, struct live *l, size_t *lenp, bool *cutp)
{
	char	*buf;
	size_t	 n, at;

	pthread_mutex_lock(&l->lock);
	n = (size_t)MIN(l->put, (uint64_t)LIVE_TAIL);
	buf = wmalloc(w, n + 1);
	at = (size_t)((l->put - n) % LIVE_TAIL);
	if (at + n <= LIVE_TAIL)
		memcpy(buf, l->tail + at, n);
	else {
		memcpy(buf, l->tail + at, LIVE_TAIL - at);
		memcpy(buf + LIVE_TAIL - at, l->tail, n - (LIVE_TAIL - at));
	}
	buf[n] = '\0';
	*cutp = l->put > n;
	pthread_mutex_unlock(&l->lock);
	*lenp = n;
	return (buf);
}

/* The program wrote len bytes at p: kept, its followers woken. */
void
live_put(struct live *l, const char *p, size_t len)
{
	size_t	 cap;
	char	*nb;

	if (l == NULL || len == 0)
		return;
	pthread_mutex_lock(&l->lock);
	tail_put(l, p, len);
	if (l->len + len > l->max) {
		len = l->max - l->len;
		l->truncated = true;
	}
	if (len > 0 && l->len + len > l->cap) {
		cap = MAX(l->cap * 2, 8192);
		while (cap < l->len + len)
			cap *= 2;
		cap = MIN(cap, l->max);
		/* Out of memory: the copy kept as far as it is, cut. */
		if ((nb = realloc(l->buf, cap)) == NULL) {
			l->max = l->len;
			l->truncated = true;
			len = 0;
		} else {
			l->buf = nb;
			l->cap = cap;
		}
	}
	if (len > 0) {
		memcpy(l->buf + l->len, p, len);
		l->len += len;
		pthread_cond_broadcast(&l->wake);
	}
	pthread_mutex_unlock(&l->lock);
}

/* The program has exited: its followers sent the rest; the copy let go
 * now when no one follows. */
void
live_end(struct live *l)
{

	if (l == NULL)
		return;
	pthread_mutex_lock(&l->lock);
	l->done = true;
	if (l->nfollow == 0) {
		free(l->buf);
		l->buf = NULL;
		l->len = l->cap = 0;
	}
	pthread_cond_broadcast(&l->wake);
	pthread_mutex_unlock(&l->lock);
}

/* A follower more of l, false when the program has exited and the copy
 * was let go; *running whether it still runs. */
static bool
follow_begin(struct live *l, bool *running)
{
	bool	ok;

	pthread_mutex_lock(&l->lock);
	if ((ok = l->buf != NULL || !l->done))
		l->nfollow++;
	*running = !l->done;
	pthread_mutex_unlock(&l->lock);
	return (ok);
}

/* A follower of l less: the copy let go with the last once the program
 * has exited.  l's lock held. */
static void
follow_end(struct live *l)
{

	if (--l->nfollow == 0 && l->done) {
		free(l->buf);
		l->buf = NULL;
		l->len = l->cap = 0;
	}
}

static void
follow_unref(struct follow *f)
{
	struct live	*l = f->l;
	bool		 last;

	pthread_mutex_lock(&l->lock);
	if ((last = --f->refs == 0))
		follow_end(l);
	pthread_mutex_unlock(&l->lock);
	if (!last)
		return;
	live_rele(l);
	free(f);
	pthread_mutex_lock(&live_lock);
	nfollowers--;
	pthread_mutex_unlock(&live_lock);
}

static void
follow_closed(cbl_stream *s __unused, int code __unused,
    const char *text __unused, void *arg)
{
	struct follow	*f = arg;

	pthread_mutex_lock(&f->l->lock);
	f->closed = true;
	pthread_cond_broadcast(&f->l->wake);
	pthread_mutex_unlock(&f->l->lock);
	follow_unref(f);
}

static void
follow_writable(cbl_stream *s __unused, size_t credit __unused, void *arg)
{
	struct follow	*f = arg;

	pthread_mutex_lock(&f->l->lock);
	pthread_cond_broadcast(&f->l->wake);
	pthread_mutex_unlock(&f->l->lock);
}

/* Its thread: what the copy holds sent from its start, then as it
 * grows, as there is room; half-closed once the program has exited and
 * all of it went. */
static void *
follow_run(void *arg)
{
	struct follow	*f = arg;
	struct live	*l = f->l;
	char		*buf;
	size_t		 off, n;
	int		 error;

	error = 0;
	off = 0;
	if ((buf = malloc(LIVE_CHUNK)) == NULL)
		error = ENOMEM;
	while (error == 0) {
		pthread_mutex_lock(&l->lock);
		while (!f->closed && off == l->len && !l->done)
			pthread_cond_wait(&l->wake, &l->lock);
		if (f->closed)
			error = EPIPE;
		else if (off == l->len) {
			pthread_mutex_unlock(&l->lock);
			break;
		}
		n = error == 0 ? MIN(l->len - off, LIVE_CHUNK) : 0;
		if (n > 0)
			memcpy(buf, l->buf + off, n);
		pthread_mutex_unlock(&l->lock);
		if (error != 0)
			break;
		while ((error = ys_send(f->s, buf, n)) == EAGAIN) {
			pthread_mutex_lock(&l->lock);
			while (!f->closed && cbl_stream_credit(f->s) < LIVE_ROOM)
				pthread_cond_wait(&l->wake, &l->lock);
			error = f->closed ? EPIPE : 0;
			pthread_mutex_unlock(&l->lock);
			if (error != 0)
				break;
		}
		if (error == 0)
			off += n;
	}
	free(buf);
	if (error == 0)
		(void)cbl_stream_half_close(f->s);
	else if (error != EPIPE)
		(void)cbl_stream_close(f->s, error, strerror(error));
	cbl_stream_rele(f->s);
	follow_unref(f);
	return (NULL);
}

static const struct ys_cbs follow_cbs = {
	.on_writable = follow_writable,
	.on_close = follow_closed,
};

/* The value of key= among the names, a number up to max; -1 when it is
 * not there or not one. */
static int64_t
number_word(const struct arcana_stream_open *rq, const char *key,
    int64_t max)
{
	const char	*v, *err;
	size_t		 i, k;
	int64_t		 n;

	k = strlen(key);
	for (i = 0; i < rq->name.n; i++) {
		v = rq->name.v[i];
		if (v == NULL || strncmp(v, key, k) != 0 || v[k] != '=')
			continue;
		n = strtonum(v + k + 1, 0, max, &err);
		return (err == NULL ? n : -1);
	}
	return (-1);
}

/*
 * arcana-stream's exec-follow: job= and step=, a program's step of a
 * job, its output as it comes.
 */
int
exec_follow_open(cbl_req *req, const struct arcana_stream_open *rq,
    cbl_stream *s)
{
	struct arcana_stream_opened	 rsp;
	struct follow			*f;
	struct live			*l;
	pthread_t			 tid;
	const char			*why;
	char				 json[96];
	int64_t				 job, step;
	bool				 running;

	job = number_word(rq, "job", INT64_MAX);
	step = number_word(rq, "step", TRACE_MAX - 1);
	if (job < 0 || step < 0 || rq->name.n != 2) {
		(void)cbl_req_set_err(req, "a job's step is followed by job= "
		    "and step=, its numbers", NULL, 0, -1);
		return (EINVAL);
	}
	if ((l = jobs_live((uint64_t)job, (int)step, &why)) == NULL) {
		(void)cbl_req_set_err(req, why, NULL, 0, -1);
		return (ENOENT);
	}
	if (!follow_begin(l, &running)) {
		live_rele(l);
		(void)cbl_req_set_err(req, "the program has exited: its output "
		    "is in the job's trace", NULL, 0, -1);
		return (ENOENT);
	}
	pthread_mutex_lock(&live_lock);
	if (nfollowers >= LIVE_FOLLOWERS) {
		pthread_mutex_unlock(&live_lock);
		pthread_mutex_lock(&l->lock);
		follow_end(l);
		pthread_mutex_unlock(&l->lock);
		live_rele(l);
		(void)cbl_req_set_err(req, "sixteen programs at most are "
		    "followed at once", NULL, 0, -1);
		return (EBUSY);
	}
	nfollowers++;
	pthread_mutex_unlock(&live_lock);
	if ((f = calloc(1, sizeof(*f))) == NULL) {
		pthread_mutex_lock(&live_lock);
		nfollowers--;
		pthread_mutex_unlock(&live_lock);
		pthread_mutex_lock(&l->lock);
		follow_end(l);
		pthread_mutex_unlock(&l->lock);
		live_rele(l);
		(void)cbl_req_set_err(req, "out of memory", NULL, 0, -1);
		return (ENOMEM);
	}
	f->l = l;
	f->s = s;
	f->refs = 2;
	snprintf(json, sizeof(json), "{\"job\":%" PRId64 ",\"step\":%" PRId64
	    ",\"running\":%s}", job, step, running ? "true" : "false");
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = true;
	rsp.json = json;
	if (ys_accept(s, &rsp, &follow_cbs, f) != 0) {
		f->refs = 1;
		follow_unref(f);
		return (ECONNREFUSED);
	}
	cbl_stream_ref(s);
	if (pthread_create(&tid, NULL, follow_run, f) != 0) {
		(void)cbl_stream_close(s, EAGAIN, "no thread for it");
		cbl_stream_rele(s);
		follow_unref(f);
		return (0);
	}
	(void)pthread_detach(tid);
	return (0);
}
