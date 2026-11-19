/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula, the prober's engine: one thread for every target, which polls
 * their sockets (poll(2)), sends each probe when it is due and keeps
 * the time of each eval and measurement interval.  It owns the table:
 * once it runs, only it reads or writes a target.
 *
 * What changes the table is handed to it: a new list of an edge's
 * targets (engine_swap(), probe.c's targets_swap() applied between two
 * rounds of its poll), the asker waiting until it is done.  Before the
 * thread runs (probe_start() reading the kept files), the asker applies
 * its change itself, under req_mtx, which keeps the askers one at a
 * time.  What the readers see is the snapshot (probe_view.c) the engine
 * publishes: at once on a change of the table or of a target's state,
 * else every PUB_S while there are targets; a reader takes it whole and
 * never holds up the engine, which never waits for a reader.
 *
 * What would hold the engine up is done off its thread by the worker,
 * one thread beside it: a plain tunnel's STAMP key derived (a file read
 * and an X25519, probe_stamp.c) and a jail's echo socket made (the
 * helper's fork and exec, probe_icmp.c; one a jail, a FIB and a family,
 * its targets waiting for the same answer), each answer handed back to
 * the engine, which takes it as its target asked for it (its serial, a
 * key's generation, a jail's socket's) and passes over one of a target
 * gone.  The faults and events it raises go through faults.c's and
 * events.c's own writers.  A socket wakes it, and so does its own pipe,
 * written by an asker or the worker.
 *
 * The steering made again when a target's state changed (invidia/
 * sdwan.c's sdwan_probe_changed(), ipfw run, at each edge) is the
 * worker's too, before any job: the engine publishes the snapshot the
 * steering reads, then counts the changes for the worker (steer_due).
 * BFD's reader (luxuria/sdbird.c) counts its sessions' changes there
 * too (probe_steer_due()), each after it has published them (its
 * table, which the steering asks), so a burst of both is one run.
 * The changes are applied in their order: one worker, one steering at a
 * time, each reading the snapshot as it is when it begins, which has
 * every change it was counted for (published before), so the tables
 * never go back to an older state than one they had.  A burst is one
 * run: the changes counted while the worker is busy (a steering, a
 * socket made) are taken together by the next, on the states they end
 * in; the steering being made of the states and the pins alone, that is
 * what the changes one after the other would end in, the tables in
 * between, never in use but for the time of a swap, not made, and no
 * ipfw run at all where the burst ends where it began (a flap: no
 * choice changed).  What one run does not see is a choice that was and
 * went within it: not told as steer-changed, not counted in its changes.
 *
 * Its own count, for -d: the probes sent LATE_S or more after they were
 * due, said each second it grew.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"
#include "stamp.h"
#include "probe_int.h"

#define	OPEN_RETRY	1.0	/* s: a socket not made tried again, at first */
#define	OPEN_RETRY_MAX	60.0
#define	PUB_S		0.1	/* s: the snapshot published, at most */
#define	LATE_S		0.01	/* s: a probe later than this is late */
/* Each target's STAMP socket, the FIBs' echo sockets and the jails'
 * (probe_icmp.c's FSOCKS_MAX and JSOCKS_MAX), the pipe. */
#define	POLL_MAX	(TARGETS_MAX + 4 * (16 + TARGETS_MAX) + 1)

/* The engine's: the table, its state. */
static struct target	*targets;
static int		 ntargets;
static unsigned		 changed;	/* state changes not yet steered */
static bool		 dirty;		/* a key or a method did: published at once */
static bool		 started, watching;
static double		 published = -1;
static uint64_t		 late, sends, late_said;
static double		 late_at;

/* What is handed to the engine, the askers waiting for it. */
struct req {
	struct req	*next;
	struct target	*new;
	int		 n;
	const char	*jail, *owner;
	bool		 ok, done;
};

static pthread_mutex_t	 req_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	 req_cv = PTHREAD_COND_INITIALIZER;
static struct req	*reqs, **reqs_end = &reqs;
static bool		 running;
static int		 wake[2] = { -1, -1 };

/* The worker's: what it is asked, and what it answers; the steering
 * due, for how many changes of a state. */
enum { JOB_KEY, JOB_JAIL };
struct job {
	struct job		*next;
	int			 kind;
	uint64_t		 serial;
	uint32_t		 gen;
	char			 jail[64];
	int			 af, fib, fd;
	char			 ifname[IFNAMSIZ];
	char			 peer[PUB_B64 + 1];
	int			 cls;
	bool			 ok, lacks;
	struct stamp_key	 key;
	char			 err[160];
};

static pthread_mutex_t	 wk_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	 wk_cv = PTHREAD_COND_INITIALIZER;
static struct job	*jobs, **jobs_end = &jobs;
static struct job	*answers, **answers_end = &answers;
static unsigned		 steer_due;
static bool		 worker_up;

double
now_s(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((double)ts.tv_sec + (double)ts.tv_nsec / 1e9);
}

/* Its echo socket's next try, the wait doubling from OPEN_RETRY. */
void
open_later(struct target *t, double now)
{

	t->open_wait = t->open_wait <= 0 ? OPEN_RETRY : t->open_wait * 2;
	if (t->open_wait > OPEN_RETRY_MAX)
		t->open_wait = OPEN_RETRY_MAX;
	t->open_at = now + t->open_wait;
}

/* A target's state changed: the steering looks again. */
void
engine_changed(void)
{

	changed++;
}

/* A target's key changed, or how it is measured: the readers' copy
 * (stampd's, the alarms' reader's) made at once. */
void
engine_dirty(void)
{

	dirty = true;
}

static void
engine_wake(void)
{

	if (wake[1] != -1)
		(void)write(wake[1], "", 1);
}

/* ---- The worker ----------------------------------------------------- */

static void
job_do(struct job *j)
{

	if (j->kind == JOB_KEY)
		j->ok = stamp_key_derive(j->ifname, j->peer, j->cls, &j->key,
		    j->err, sizeof(j->err)) == 0;
	else
		j->fd = jail_socket(j->jail, j->af, j->fib, j->err,
		    sizeof(j->err), &j->lacks);
}

static void
job_answer(struct job *j)
{

	pthread_mutex_lock(&wk_mtx);
	j->next = NULL;
	*answers_end = j;
	answers_end = &j->next;
	pthread_mutex_unlock(&wk_mtx);
	engine_wake();
}

/* The steering made again, for n changes of a state. */
static void
steer_run(unsigned n)
{

	logmsg(LOG_DEBUG, "probe: steering made again: %u state change%s, "
	    "one run", n, n == 1 ? "" : "s");
	sdwan_probe_changed();
}

static void *
worker(void *arg __unused)
{
	struct job	*j;
	unsigned	 n;

	for (;;) {
		pthread_mutex_lock(&wk_mtx);
		while (jobs == NULL && steer_due == 0)
			pthread_cond_wait(&wk_cv, &wk_mtx);
		/* The steering first: a failover waits for no socket. */
		if ((n = steer_due) > 0) {
			steer_due = 0;
			pthread_mutex_unlock(&wk_mtx);
			steer_run(n);
			continue;
		}
		j = jobs;
		if ((jobs = j->next) == NULL)
			jobs_end = &jobs;
		pthread_mutex_unlock(&wk_mtx);
		job_do(j);
		job_answer(j);
	}
	return (NULL);
}

/* A job for the worker (done here, the worker not running). */
static void
job_post(struct job *j)
{

	j->next = NULL;
	if (!worker_up) {
		job_do(j);
		job_answer(j);
		return;
	}
	pthread_mutex_lock(&wk_mtx);
	*jobs_end = j;
	jobs_end = &j->next;
	pthread_cond_signal(&wk_cv);
	pthread_mutex_unlock(&wk_mtx);
}

/* The steering asked of the worker for n changes, with those it has
 * not begun on yet (done here, the worker not running). */
static void
engine_steer(unsigned n)
{

	if (!worker_up) {
		steer_run(n);
		return;
	}
	pthread_mutex_lock(&wk_mtx);
	steer_due += n;
	pthread_cond_signal(&wk_cv);
	pthread_mutex_unlock(&wk_mtx);
}

/* n changes of a state said elsewhere (BFD's sessions, luxuria/
 * sdbird.c), each published before: counted with the targets' for the
 * worker's next steering. */
void
probe_steer_due(unsigned n)
{

	if (n > 0)
		engine_steer(n);
}

/* A plain tunnel's key asked of the worker: its STAMP waits for it. */
void
engine_key(struct target *t)
{
	struct job	*j;

	t->key_pending = true;
	t->key_failed = false;
	t->key_gen++;
	if ((j = calloc(1, sizeof(*j))) == NULL) {
		stamp_key_told(t, false, NULL, strerror(errno));
		return;
	}
	j->kind = JOB_KEY;
	j->serial = t->serial;
	j->gen = t->key_gen;
	snprintf(j->ifname, sizeof(j->ifname), "%s", t->stamp_if);
	snprintf(j->peer, sizeof(j->peer), "%s", t->stamp_peer);
	j->cls = t->cls_idx;
	job_post(j);
}

/* A jail's echo socket of FIB fib and family af asked of the worker,
 * its answer gen; false, not asked (errno why). */
static bool
engine_jail(const char *jail, int fib, int af, uint32_t gen)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (false);
	j->kind = JOB_JAIL;
	j->gen = gen;
	snprintf(j->jail, sizeof(j->jail), "%s", jail);
	j->af = af;
	j->fib = fib;
	job_post(j);
	return (true);
}

/* Whether t waits for the jail's socket of FIB fib and family af. */
static bool
waits_for(const struct target *t, const char *jail, int fib, int af)
{

	return (t->id[0] != '\0' && t->opening && t->sock == -1 && t->af ==
	    af && t->fib == fib && strcmp(t->jail, jail) == 0);
}

/* The worker's answer j, a jail's socket: to each target that waits for
 * it, or why there is none. */
static void
jail_answer(struct job *j, double now)
{
	struct target	*t;
	int		 i, fd, waiting;

	waiting = 0;
	for (i = 0; i < ntargets; i++)
		if (waits_for(&targets[i], j->jail, j->fib, j->af))
			waiting++;
	if ((fd = jsock_made(j->jail, j->fib, j->af, j->gen, j->fd,
	    j->lacks, waiting > 0, now, j->err)) == -2)
		return;
	for (i = 0; i < ntargets; i++) {
		t = &targets[i];
		if (!waits_for(t, j->jail, j->fib, j->af))
			continue;
		t->opening = false;
		if (fd == -1) {
			snprintf(t->error, sizeof(t->error), "%s", j->err);
			open_later(t, now);
			state_set(t, ST_ERROR);
		} else {
			t->sock = fd;
			t->error[0] = '\0';
			t->open_wait = 0;
		}
	}
}

static struct target *
by_serial(uint64_t serial)
{

	for (int i = 0; i < ntargets; i++)
		if (targets[i].serial == serial && targets[i].id[0] != '\0')
			return (&targets[i]);
	return (NULL);
}

/* The worker's answers, each to the target that asked, if it still
 * waits for it. */
static void
engine_answers(double now)
{
	struct target	*t;
	struct job	*j, *next;

	pthread_mutex_lock(&wk_mtx);
	j = answers;
	answers = NULL;
	answers_end = &answers;
	pthread_mutex_unlock(&wk_mtx);
	for (; j != NULL; j = next) {
		next = j->next;
		if (j->kind == JOB_KEY) {
			t = by_serial(j->serial);
			if (t != NULL && t->key_pending && t->key_gen == j->gen)
				stamp_key_told(t, j->ok, &j->key, j->err);
		} else
			jail_answer(j, now);
		explicit_bzero(&j->key, sizeof(j->key));
		free(j);
	}
}

/* ---- What is handed to the engine ----------------------------------- */

static bool
apply_swap(struct req *r)
{
	bool	ok;

	ok = targets_swap(&targets, &ntargets, r->new, r->n, r->jail,
	    r->owner);
	if (ok) {
		icmp_table(targets, ntargets);
		/* Those gone: their faults cleared; the rest's taken up. */
		if (watching)
			probe_reconcile(targets, ntargets);
	}
	snap_publish(targets, ntargets, started);
	published = now_s();
	return (ok);
}

/*
 * An edge's new targets (n of them, jail's, owner's) in the place of its
 * old ones, as targets_swap() says; false, nothing changed, when there
 * would be more than TARGETS_MAX.  Applied by the engine, once it runs,
 * between two rounds; the asker waits.
 */
bool
engine_swap(struct target *new, int n, const char *jail, const char *owner)
{
	struct req	r;

	memset(&r, 0, sizeof(r));
	r.new = new;
	r.n = n;
	r.jail = jail;
	r.owner = owner;
	pthread_mutex_lock(&req_mtx);
	if (!running)
		r.ok = apply_swap(&r);
	else {
		*reqs_end = &r;
		reqs_end = &r.next;
		engine_wake();
		while (!r.done)
			pthread_cond_wait(&req_cv, &req_mtx);
	}
	pthread_mutex_unlock(&req_mtx);
	if (!r.ok)
		return (false);
	/* The links' faults as they are; their FIBs stampd's
	 * (gula/stampd.c). */
	links_reconcile();
	stampd_nudge();
	return (true);
}

static void
engine_requests(void)
{
	struct req	*r, *next;
	bool		 ok;

	pthread_mutex_lock(&req_mtx);
	r = reqs;
	reqs = NULL;
	reqs_end = &reqs;
	pthread_mutex_unlock(&req_mtx);
	for (; r != NULL; r = next) {
		next = r->next;
		ok = apply_swap(r);
		pthread_mutex_lock(&req_mtx);
		r->ok = ok;
		r->done = true;
		pthread_cond_broadcast(&req_cv);
		pthread_mutex_unlock(&req_mtx);
	}
}

/* At the start, the readers told the prober runs: none yet. */
void
engine_begin(void)
{

	pthread_mutex_lock(&req_mtx);
	started = true;
	snap_publish(targets, ntargets, started);
	pthread_mutex_unlock(&req_mtx);
}

/* The kept targets all read: the faults held to them from now on. */
void
engine_watch(void)
{

	pthread_mutex_lock(&req_mtx);
	watching = true;
	probe_reconcile(targets, ntargets);
	snap_publish(targets, ntargets, started);
	pthread_mutex_unlock(&req_mtx);
}

/* ---- The thread ----------------------------------------------------- */

/* Probes in the air too long are lost; an eval interval over is kept. */
static void
target_timers(struct target *t, double now)
{
	struct stamp_sample	sm;
	int			i;

	for (i = 0; i < OUT_MAX; i++)
		if (t->out[i].live && now - t->out[i].sent > t->timeout /
		    1000.0) {
			t->out[i].live = false;
			miss(t);
		}
	/* A fallen-back target's tries lost: nothing to count. */
	while (t->ss != NULL && stamp_sender_expire(t->ss, now, &sm) == 1)
		if (t->by_stamp)
			stamp_lost(t, now);
	if (now - t->win_start >= t->eval / 1000.0)
		window_end(t, now);
	pm_timers(t, now);
	if (t->next_send < 0 && t->state != ST_ENDED && t->state != ST_ERROR) {
		bool	air = t->by_stamp && t->ss != NULL &&
			    stamp_sender_next(t->ss) > 0;

		for (i = 0; i < OUT_MAX; i++)
			air = air || t->out[i].live;
		if (!air)
			state_set(t, ST_ENDED);
	}
}

/* The target's next probe: STAMP to Arcana's far end, else an echo. */
static void
target_send(struct target *t, double now)
{

	if (t->by_stamp && stamp_send_one(t, true) == -1)
		return;
	/* Not by STAMP, or no longer: an echo. */
	if (!t->by_stamp)
		icmp_send(t);
	/* Fallen back: STAMP tried now and then, a plain tunnel's under its
	 * key derived anew each time (a pair made again at this end). */
	if (t->arcana && !t->by_stamp && now >= t->stamp_retry) {
		t->stamp_retry = now + STAMP_RETRY;
		stamp_rekey(t);
		if (stamp_send_one(t, false) == -1)
			t->try_wait = true;
	}
	if (t->count > 0 && t->sent >= (uint64_t)t->count)
		t->next_send = -1;
	else
		t->next_send = now + t->interval / 1000.0;
}

static void *
prober(void *arg __unused)
{
	struct pollfd	*pfd;
	struct target	*t;
	double		 now, wait, d;
	uint32_t	 gen;
	unsigned	 moved;
	char		 jail[64];
	int		 i, j, n, ms, fib, af, *pt, *pk;
	bool		 held;
	char		 c[64];

	/* Each target's STAMP socket, the FIBs' and the jails' echo
	 * sockets, the pipe; whose each is, by its index (-1 an echo
	 * socket, its family in pk; -2 the pipe). */
	pfd = calloc(POLL_MAX, sizeof(*pfd));
	pt = calloc(POLL_MAX, sizeof(*pt));
	pk = calloc(POLL_MAX, sizeof(*pk));
	if (pfd == NULL || pt == NULL || pk == NULL) {
		logmsg(LOG_ERR, "sdwan probes: no memory");
		return (NULL);
	}
	for (;;) {
		engine_requests();
		now = now_s();
		engine_answers(now);
		/* A jail's sockets kept for every FIB's replies, each asked
		 * of the worker as it is due. */
		while (jsock_ask(now, jail, sizeof(jail), &fib, &af, &gen))
			if (!engine_jail(jail, fib, af, gen))
				(void)jsock_made(jail, fib, af, gen, -1, false,
				    false, now, strerror(errno));
		wait = 0.2;
		n = 0;
		for (i = 0; i < ntargets; i++) {
			t = &targets[i];
			/* An echo socket it needs and has not: tried when it
			 * is due; a jail's its jail's, FIB's and family's, made
			 * by the worker for the first that needs it, the rest
			 * waiting for the same. */
			if (t->kind != KIND_STAMP && t->sock == -1) {
				if (t->opening)
					continue;
				if (now < t->open_at) {
					if ((d = t->open_at - now) < wait)
						wait = d;
					continue;
				}
				if (t->jail[0] != '\0') {
					switch (jsock_want(t, &gen)) {
					case JS_HAVE:
						break;
					case JS_ASK:
						if (!engine_jail(t->jail,
						    t->fib, t->af, gen)) {
							snprintf(t->error,
							    sizeof(t->error),
							    "%s", strerror(
							    errno));
							(void)jsock_made(t->jail,
							    t->fib, t->af, gen,
							    -1, false, false,
							    now, NULL);
							open_later(t, now);
							state_set(t, ST_ERROR);
							continue;
						}
						/* FALLTHROUGH */
					case JS_WAIT:
						t->opening = true;
						continue;
					default:
						open_later(t, now);
						state_set(t, ST_ERROR);
						continue;
					}
				} else if (!target_open(t)) {
					open_later(t, now);
					state_set(t, ST_ERROR);
					continue;
				}
				t->open_wait = 0;
			}
			if (t->state == ST_ERROR)
				state_set(t, ST_UNKNOWN);
			/* A fallen-back target's STAMP try, its key told. */
			if (t->try_wait && !t->key_pending) {
				t->try_wait = false;
				if (stamp_send_one(t, false) == -1)
					t->try_wait = true;
			}
			/* By STAMP, its key asked for: its probe waits. */
			if (!(t->by_stamp && t->key_pending) && t->next_send >=
			    0 && t->next_send <= now) {
				sends++;
				if (now - t->next_send >= LATE_S)
					late++;
				target_send(t, now);
			}
			target_timers(t, now);
			held = t->by_stamp && t->key_pending;
			if (!held && t->next_send >= 0 && (d = t->next_send -
			    now) < wait)
				wait = d;
			if ((d = t->win_start + t->eval / 1000.0 - now) < wait)
				wait = d;
			if (t->pm_start != 0 && (d = t->pm_due - now) < wait)
				wait = d;
			if (t->usock != -1) {
				pfd[n].fd = t->usock;
				pfd[n].events = POLLIN;
				pfd[n].revents = 0;
				pt[n++] = i;
			}
		}
		j = icmp_pollfds(&pfd[n], &pk[n], POLL_MAX - 1 - n);
		for (; j > 0; j--)
			pt[n++] = -1;
		pfd[n].fd = wake[0];
		pfd[n].events = POLLIN;
		pfd[n].revents = 0;
		pt[n++] = -2;
		moved = changed;
		changed = 0;
		/* The readers' copy: at once when a state changed, which the
		 * steering is about to ask, else every PUB_S. */
		if (moved || dirty || (ntargets > 0 && now - published >=
		    PUB_S)) {
			snap_publish(targets, ntargets, started);
			published = now;
			dirty = false;
		}
		if (ntargets > 0 && (d = published + PUB_S - now) < wait)
			wait = d;
		/* A tunnel down or up: the steering made again by the
		 * worker, as it asks the states back from what was just
		 * published. */
		if (moved > 0)
			engine_steer(moved);
		if (late != late_said && now - late_at >= 1) {
			logmsg(LOG_DEBUG, "probe: engine: %ju of %ju probes sent "
			    "%.0f ms or more late", (uintmax_t)late,
			    (uintmax_t)sends, LATE_S * 1000);
			late_said = late;
			late_at = now;
		}
		ms = wait > 0 ? (int)(wait * 1000) : 0;
		if (poll(pfd, (nfds_t)n, ms < 1 ? 1 : ms) <= 0)
			continue;
		now = now_s();
		for (j = 0; j < n; j++) {
			if (!(pfd[j].revents & POLLIN))
				continue;
			if (pt[j] == -2) {
				while (read(pfd[j].fd, c, sizeof(c)) > 0)
					;
				continue;
			}
			if (pt[j] == -1) {
				icmp_recv_sock(pfd[j].fd, pk[j], targets,
				    ntargets, now);
				continue;
			}
			t = &targets[pt[j]];
			if (t->usock == pfd[j].fd)
				stamp_recv_all(t);
		}
	}
	return (NULL);
}

/* The engine's thread and its worker: from now on the table is its. */
void
engine_start(void)
{
	pthread_t	tid;
	int		error;

	if (pipe2(wake, O_CLOEXEC | O_NONBLOCK) == -1) {
		logmsg(LOG_ERR, "sdwan probes: no pipe: %s", strerror(errno));
		wake[0] = wake[1] = -1;
	}
	if ((error = pthread_create(&tid, NULL, worker, NULL)) == 0) {
		(void)pthread_detach(tid);
		worker_up = true;
	} else
		logmsg(LOG_WARNING, "sdwan probes: no worker, its work done "
		    "by the prober: %s", strerror(error));
	pthread_mutex_lock(&req_mtx);
	if ((error = pthread_create(&tid, NULL, prober, NULL)) == 0) {
		(void)pthread_detach(tid);
		running = true;
	} else
		logmsg(LOG_ERR, "sdwan probes: no thread: %s", strerror(error));
	pthread_mutex_unlock(&req_mtx);
}
