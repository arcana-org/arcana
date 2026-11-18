/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Per-request state: the allocation pool that the reply points into.
 * The trace of what the request did is Gula's (gula/trace.c).
 *
 * Out of memory, a request's alone.  What a request allocates is its
 * work's (wmalloc() and the rest), and the places that allocate so do
 * not look for NULL: a malloc(3) that fails is served from the reserve
 * instead, a region mapped before memory ran out for this alone, and
 * the work is marked (work_oom()).  The request goes on as far as its
 * next program, which is not run (run_exec() fails it as one that could
 * not start: the operation's own error path), or its end, where it
 * fails, "out of memory": a model's handler (yserve.c's guard), a job
 * (jobs.c's run(): a safe change undone, as any failed one).  The
 * daemon serves the others meanwhile, and the request's blocks of the
 * reserve go back with its work.  The reserve spent too, the daemon
 * ends, as it did before there was one.
 */

#include <sys/param.h>
#include <sys/mman.h>

#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <vis.h>

#include "agent.h"

#define	RESERVE_SIZE	(8 * 1024 * 1024)
#define	RESERVE_ALIGN	16

/*
 * A block of the reserve: a free one on the list, by address, or one
 * given out, its header before what the work was given.
 */
struct rblk {
	size_t		 size;		/* the header's with it */
	struct rblk	*next;
};

#define	RHDR	roundup2(sizeof(struct rblk), RESERVE_ALIGN)

static pthread_once_t	 reserve_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t	 reserve_lock = PTHREAD_MUTEX_INITIALIZER;
static char		*reserve_base;
static struct rblk	*reserve_free;

/* A work of this thread has run out of memory (work_oom_seen()). */
static _Thread_local bool	oom_here;

/* Mapped with the first work, before memory runs out; not touched. */
static void
reserve_map(void)
{
	void	*p;

	p = mmap(NULL, RESERVE_SIZE, PROT_READ | PROT_WRITE, MAP_ANON |
	    MAP_PRIVATE | MAP_NOCORE, -1, 0);
	if (p == MAP_FAILED) {
		logmsg(LOG_WARNING, "no reserve for out of memory: %s; a "
		    "request that runs out ends the daemon", strerror(errno));
		return;
	}
	reserve_base = p;
	reserve_free = p;
	reserve_free->size = RESERVE_SIZE;
	reserve_free->next = NULL;
}

static bool
in_reserve(const void *p)
{

	return (reserve_base != NULL && (const char *)p >= reserve_base &&
	    (const char *)p < reserve_base + RESERVE_SIZE);
}

/* n bytes of the reserve, the first free block that has them; NULL. */
static void *
reserve_alloc(size_t n)
{
	struct rblk	**pp, *b, *nb;
	size_t		  need;

	if (n > RESERVE_SIZE - RHDR)
		return (NULL);
	need = roundup2(n, RESERVE_ALIGN) + RHDR;
	pthread_mutex_lock(&reserve_lock);
	for (pp = &reserve_free; (b = *pp) != NULL; pp = &b->next)
		if (b->size >= need)
			break;
	if (b == NULL) {
		pthread_mutex_unlock(&reserve_lock);
		return (NULL);
	}
	if (b->size - need >= RHDR + RESERVE_ALIGN) {
		/* Its tail given; the rest stays free where it is. */
		b->size -= need;
		nb = (struct rblk *)(void *)((char *)b + b->size);
		nb->size = need;
		b = nb;
	} else
		*pp = b->next;
	pthread_mutex_unlock(&reserve_lock);
	return ((char *)b + RHDR);
}

/* A block of the reserve back, one with its neighbours where they touch. */
static void
reserve_release(void *p)
{
	struct rblk	**pp, *b, *prev;

	b = (struct rblk *)(void *)((char *)p - RHDR);
	pthread_mutex_lock(&reserve_lock);
	prev = NULL;
	for (pp = &reserve_free; *pp != NULL && *pp < b; pp = &(*pp)->next)
		prev = *pp;
	b->next = *pp;
	*pp = b;
	if (b->next != NULL && (char *)b + b->size == (char *)b->next) {
		b->size += b->next->size;
		b->next = b->next->next;
	}
	if (prev != NULL && (char *)prev + prev->size == (char *)b) {
		prev->size += b->size;
		prev->next = b->next;
	}
	pthread_mutex_unlock(&reserve_lock);
}

/* What a work was given back where it came from. */
static void
pool_release(void *p)
{

	if (in_reserve(p))
		reserve_release(p);
	else
		free(p);
}

/* n bytes from the reserve, the work out of memory; or the end. */
static void *
pool_reserve(struct work *w, size_t n)
{
	void	*p;

	work_oom(w);
	if ((p = reserve_alloc(n)) == NULL) {
		logmsg(LOG_CRIT, "out of memory, its reserve spent too: "
		    "arcana-agent ends");
		errx(1, "out of memory, its reserve spent too");
	}
	return (p);
}

/*
 * w has run out of memory: a malloc(3) for it failed, its own or its
 * caller's.  Said once; the request fails at its end.
 */
void
work_oom(struct work *w)
{

	if (!w->oom)
		logmsg(LOG_ERR, "out of memory: the request or job fails, "
		    "the daemon goes on");
	w->oom = true;
	oom_here = true;
}

/* Has a work of this thread run out of memory since work_oom_clear()? */
bool
work_oom_seen(void)
{

	return (oom_here);
}

void
work_oom_clear(void)
{

	oom_here = false;
}

/*
 * --alloc-fault's file, a test's: with "request N" in it, the next
 * request's work (ywork()), with "job N" the next job's change
 * (run_kind()), has its Nth allocation from now fail as though memory
 * had run out.  The file is taken away: that one fails alone.
 */
void
work_fault(struct work *w, const char *kind)
{
	static pthread_mutex_t	 lock = PTHREAD_MUTEX_INITIALIZER;
	FILE			*f;
	char			 what[16];
	unsigned long		 n;

	if (opts.alloc_fault == NULL)
		return;
	pthread_mutex_lock(&lock);
	if ((f = fopen(opts.alloc_fault, "r")) != NULL) {
		if (fscanf(f, "%15s %lu", what, &n) == 2 && n > 0 &&
		    strcmp(what, kind) == 0) {
			w->fault_at = w->nalloc + n;
			(void)unlink(opts.alloc_fault);
		}
		fclose(f);
	}
	pthread_mutex_unlock(&lock);
}

void
work_init(struct work *w)
{

	(void)pthread_once(&reserve_once, reserve_map);
	memset(w, 0, sizeof(*w));
	pthread_mutex_init(&w->lock, NULL);
}

void
work_free(struct work *w)
{
	size_t	i;
	int	k;

	for (k = 0; k < w->nsteps; k++)
		live_rele(w->steps[k].live);
	for (i = 0; i < w->nptrs; i++)
		pool_release(w->ptrs[i]);
	if (w->ptrs != NULL)
		pool_release(w->ptrs);
	w->ptrs = NULL;
	w->nptrs = w->capptrs = 0;
	pthread_mutex_destroy(&w->lock);
}

/* Take ownership of p, a malloc(3)ed pointer; it goes with the request. */
void *
wadopt(struct work *w, void *p)
{
	void	**v;
	size_t	  cap;

	if (p == NULL)
		return (NULL);
	if (w->nptrs == w->capptrs) {
		cap = w->capptrs == 0 ? 64 : w->capptrs * 2;
		if ((v = malloc(cap * sizeof(*v))) == NULL)
			v = pool_reserve(w, cap * sizeof(*v));
		if (w->nptrs > 0)
			memcpy(v, w->ptrs, w->nptrs * sizeof(*v));
		if (w->ptrs != NULL)
			pool_release(w->ptrs);
		w->ptrs = v;
		w->capptrs = cap;
	}
	w->ptrs[w->nptrs++] = p;
	return (p);
}

void *
wmalloc(struct work *w, size_t n)
{
	void	*p;

	if (n == 0)
		n = 1;
	/* The allocation --alloc-fault names fails as malloc(3) would. */
	if (++w->nalloc == w->fault_at || (p = malloc(n)) == NULL)
		p = pool_reserve(w, n);
	return (wadopt(w, p));
}

void *
wcalloc(struct work *w, size_t nmemb, size_t size)
{
	void	*p;

	if (size != 0 && nmemb > SIZE_MAX / size)
		errx(1, "wcalloc: overflow");
	p = wmalloc(w, nmemb * size);
	memset(p, 0, nmemb * size);
	return (p);
}

/*
 * v, an array of w's pool with room for *capp elements of size, made
 * room in for one past n: a new one twice as large, the n copied, when
 * it is full; the old one stays in the pool.
 */
void *
wgrow(struct work *w, void *v, size_t n, size_t *capp, size_t size)
{
	void	*nv;

	if (n < *capp)
		return (v);
	*capp = *capp == 0 ? 16 : *capp * 2;
	nv = wcalloc(w, *capp, size);
	if (n > 0)
		memcpy(nv, v, n * size);
	return (nv);
}

char *
wstrndup(struct work *w, const char *s, size_t n)
{
	char	*p;

	p = wmalloc(w, n + 1);
	memcpy(p, s, n);
	p[n] = '\0';
	return (p);
}

char *
wstrdup(struct work *w, const char *s)
{

	return (s == NULL ? NULL : wstrndup(w, s, strlen(s)));
}

char *
wvfmt(struct work *w, const char *fmt, va_list ap)
{
	va_list	 aq;
	char	*p;
	int	 n;

	va_copy(aq, ap);
	n = vsnprintf(NULL, 0, fmt, aq);
	va_end(aq);
	/* Past INT_MAX: as out of memory. */
	if (n < 0) {
		work_oom(w);
		return (wstrdup(w, ""));
	}
	p = wmalloc(w, (size_t)n + 1);
	(void)vsnprintf(p, (size_t)n + 1, fmt, ap);
	return (p);
}

char *
wfmt(struct work *w, const char *fmt, ...)
{
	va_list	 ap;
	char	*p;

	va_start(ap, fmt);
	p = wvfmt(w, fmt, ap);
	va_end(ap);
	return (p);
}

/* s with unprintable characters as C escapes, for display. */
char *
wvis(struct work *w, const char *s)
{
	char	*p;

	if (s == NULL)
		return (NULL);
	p = wmalloc(w, strlen(s) * 4 + 1);
	(void)strvis(p, s, VIS_CSTYLE | VIS_OCTAL | VIS_TAB | VIS_NL);
	return (p);
}

/*
 * s, made fit for a CBOR text string: valid UTF-8 without control
 * characters is returned as is, anything else escaped.
 */
const char *
wtext(struct work *w, const char *s)
{

	if (s == NULL)
		return (NULL);
	return (text_fit(s, false) ? s : text_vis(wmalloc(w, strlen(s) * 4 +
	    1), s, false));
}

/* The same for a name (a host's, a jail's): one line, no tab either. */
const char *
wname(struct work *w, const char *s)
{

	if (s == NULL)
		return (NULL);
	return (text_fit(s, true) ? s : text_vis(wmalloc(w, strlen(s) * 4 + 1),
	    s, true));
}
