/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Ira: every jail's coming and going, told by the kernel (kqueue(2)'s
 * EVFILT_JAIL): a jail made is a child of the host's or of another
 * jail, NOTE_JAIL_CHILD with its number; each is then watched for
 * NOTE_JAIL_REMOVE, and for children of its own: a jail in a jail, a
 * logical network element in another, is told as
 * one of the host's is.  Each is an event, jail-state, with the jail's
 * name and "running" or "stopped", as it happens: nothing has to look
 * again to see it.
 *
 * The services that run in jails and follow them (jail_follow(): the
 * Security section's Suricata and Squid in a jail, a jail edge's SD-WAN
 * services) are told here too.  A jail made is told before it is
 * whole: jail(8) moves its vnet interfaces in (vnet.interface,
 * exec.created) and runs its rc after jail_set(2) has made it, which is
 * when NOTE_JAIL_CHILD comes.  So a jail a follower wants is settled
 * first: the interfaces its instances there need are looked for inside
 * it (ifconfig -j JID -l), every SETTLE_EVERY ms, SETTLE_MAX seconds at
 * most, and then its kept lists applied again, whether they came or
 * not; an apply that fails is tried again APPLY_TRIES times, a while
 * later each time.  Each running at the agent's start is told as made,
 * so that an instance kept while its jail was not running starts when
 * the jail came between its apply and this watch.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/jail.h>
#include <sys/queue.h>

#include <net/if.h>

#include <ctype.h>
#include <errno.h>
#include <jail.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

struct wj {
	LIST_ENTRY(wj)	 list;
	int		 jid;
	char		*name;
};

static LIST_HEAD(, wj)	jails = LIST_HEAD_INITIALIZER(jails);

_Static_assert(JAIL_IFNAMSIZ == IFNAMSIZ, "JAIL_IFNAMSIZ is IFNAMSIZ");

#define	FOLLOWERS_MAX	4
#define	DUE_MAX		32
#define	SETTLE_EVERY	500	/* ms, a jail made looked into again */
#define	SETTLE_MAX	30	/* s, a jail made waited for, at most */
#define	APPLY_TRIES	4	/* its apply, at most */
#define	APPLY_AGAIN	3	/* s, before the second; doubled each time */

/* A jail made that a follower wants, until it is applied again. */
struct due {
	const struct jail_follower *f;
	char		 jail[MAXHOSTNAMELEN];
	int		 jid;
	char		 ifs[JAIL_IFS_MAX][IFNAMSIZ];
	int		 nifs;
	int64_t		 made;		/* ms, monotonic */
	int64_t		 at;		/* ms, when it is looked at next */
	int		 tries;
	bool		 waited;	/* told it did not settle */
};

static pthread_mutex_t	follow_lock = PTHREAD_MUTEX_INITIALIZER;
static const struct jail_follower *followers[FOLLOWERS_MAX];
static int		nfollowers;
static struct due	dues[DUE_MAX];
static int		ndues;
static bool		settling;	/* settler() runs */

static int64_t
mono_ms(void)
{
	struct timespec	ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

void
jail_follow(const struct jail_follower *f)
{

	pthread_mutex_lock(&follow_lock);
	if (nfollowers < FOLLOWERS_MAX)
		followers[nfollowers++] = f;
	pthread_mutex_unlock(&follow_lock);
}

/* An interface of the list in the jail's (names separated by blanks). */
static bool
listed(const char *list, size_t len, const char *ifn)
{
	size_t	n, i, k;

	n = strlen(ifn);
	for (i = 0; i < len; i = k) {
		while (i < len && isspace((unsigned char)list[i]))
			i++;
		for (k = i; k < len && !isspace((unsigned char)list[k]); k++)
			;
		if (k - i == n && memcmp(list + i, ifn, n) == 0)
			return (true);
	}
	return (false);
}

/* One of the list besides the loopback and the pseudo-interfaces
 * Suricata's any leaves out. */
static bool
listed_other(const char *list, size_t len)
{
	static const char *const skip[] = { "lo", "pflog", "pfsync", "enc" };
	size_t	i, k, j, n;

	for (i = 0; i < len; i = k) {
		while (i < len && isspace((unsigned char)list[i]))
			i++;
		for (k = i; k < len && !isspace((unsigned char)list[k]); k++)
			;
		if (k == i)
			continue;
		for (j = 0; j < nitems(skip); j++) {
			n = strlen(skip[j]);
			if (k - i > n && memcmp(list + i, skip[j], n) == 0 &&
			    isdigit((unsigned char)list[i + n]))
				break;
		}
		if (j == nitems(skip))
			return (true);
	}
	return (false);
}

/*
 * Has the jail settled: shares it the host's network, or has its own
 * every interface d names (none named: one up besides the loopback)?
 * NULL when it has; else what it lacks, *gone true when the jail is not
 * the one made any more.
 */
static const char *
settled(struct work *w, const struct due *d, bool *gone)
{
	struct jinfo	 ji;
	struct execres	 res;
	char		*argv[6];
	int		 i, k;

	*gone = false;
	if (jail_named(w, d->jail, &ji) != d->jid) {
		*gone = true;
		return ("gone");
	}
	if (!ji.vnet)
		return (NULL);
	k = 0;
	argv[k++] = (char *)(uintptr_t)opts.ifconfig_bin;
	argv[k++] = (char *)(uintptr_t)"-j";
	argv[k++] = wfmt(w, "%d", d->jid);
	argv[k++] = (char *)(uintptr_t)"-l";
	if (d->nifs == 0)
		argv[k++] = (char *)(uintptr_t)"-u";
	argv[k] = NULL;
	if (run_read(w, argv, &res) != 0 || res.out == NULL)
		return (wfmt(w, "its interfaces not read: %s", exec_error(w,
		    &res, "ifconfig")));
	if (d->nifs == 0)
		return (listed_other(res.out, res.outlen) ? NULL :
		    "an interface up besides the loopback");
	for (i = 0; i < d->nifs; i++)
		if (!listed(res.out, res.outlen, d->ifs[i]))
			return (wfmt(w, "its interface %s", d->ifs[i]));
	return (NULL);
}

/*
 * The jails made that followers want: each looked into until it has
 * settled (or SETTLE_MAX has gone), then its follower's lists applied
 * again; one at a time, the thread gone when none is left.
 */
static void *
settler(void *arg __unused)
{
	struct work	 w;
	struct due	 d;
	const char	*lack, *e;
	int64_t		 now;
	bool		 gone;
	int		 i;

	for (;;) {
		pthread_mutex_lock(&follow_lock);
		if (ndues == 0) {
			settling = false;
			pthread_mutex_unlock(&follow_lock);
			return (NULL);
		}
		now = mono_ms();
		for (i = 0; i < ndues && dues[i].at > now; i++)
			;
		if (i == ndues) {
			pthread_mutex_unlock(&follow_lock);
			(void)usleep(SETTLE_EVERY * 1000);
			continue;
		}
		d = dues[i];
		pthread_mutex_unlock(&follow_lock);
		work_init(&w);
		w.nice = true;
		gone = false;
		lack = d.tries == 0 ? settled(&w, &d, &gone) : NULL;
		if (lack != NULL && !gone && now - d.made < SETTLE_MAX * 1000) {
			d.at = now + SETTLE_EVERY;
			goto keep;
		}
		if (gone) {
			work_free(&w);
			goto drop;
		}
		if (lack != NULL)
			logmsg(LOG_NOTICE, "%s: the jail %s did not settle in %d "
			    "s (it lacks %s): applied again as it is", d.f->what,
			    d.jail, SETTLE_MAX, lack);
		e = NULL;
		if (d.f->apply(&w, d.jail, &e) == 0) {
			logmsg(LOG_INFO, "%s: started again in the jail %s, which "
			    "came back", d.f->what, d.jail);
			work_free(&w);
			goto drop;
		}
		d.tries++;
		logmsg(LOG_WARNING, "%s: the jail %s came back: %s%s", d.f->what,
		    d.jail, e != NULL ? e : "not applied", d.tries < APPLY_TRIES ?
		    "; tried again later" : "; not tried again until it comes "
		    "back again");
		if (d.tries >= APPLY_TRIES) {
			work_free(&w);
			goto drop;
		}
		d.at = now + ((int64_t)APPLY_AGAIN * 1000 << (d.tries - 1));
keep:
		work_free(&w);
		pthread_mutex_lock(&follow_lock);
		/* Still the one taken: not replaced or dropped meanwhile. */
		for (i = 0; i < ndues; i++)
			if (dues[i].f == d.f && dues[i].jid == d.jid &&
			    strcmp(dues[i].jail, d.jail) == 0) {
				dues[i].at = d.at;
				dues[i].tries = d.tries;
				break;
			}
		pthread_mutex_unlock(&follow_lock);
		continue;
drop:
		pthread_mutex_lock(&follow_lock);
		for (i = 0; i < ndues; i++)
			if (dues[i].f == d.f && dues[i].jid == d.jid &&
			    strcmp(dues[i].jail, d.jail) == 0) {
				dues[i] = dues[--ndues];
				break;
			}
		pthread_mutex_unlock(&follow_lock);
	}
}

/* A jail made, or running at the start: each follower that wants it
 * given it, settled first. */
static void
came(const char *name, int jid)
{
	char		 ifs[JAIL_IFS_MAX][IFNAMSIZ];
	pthread_t	 tid;
	struct due	*d;
	int		 i, k, n;

	pthread_mutex_lock(&follow_lock);
	for (i = 0; i < nfollowers; i++) {
		if ((n = followers[i]->wants(name, jid, ifs, JAIL_IFS_MAX)) < 0)
			continue;
		/* The same jail again: made anew, its wait begun again. */
		for (k = 0; k < ndues; k++)
			if (dues[k].f == followers[i] && strcmp(dues[k].jail,
			    name) == 0)
				break;
		if (k == ndues) {
			if (ndues == DUE_MAX) {
				logmsg(LOG_WARNING, "%s: the jail %s came back, "
				    "and %d others wait: not started again",
				    followers[i]->what, name, DUE_MAX);
				continue;
			}
			ndues++;
		}
		d = &dues[k];
		memset(d, 0, sizeof(*d));
		d->f = followers[i];
		snprintf(d->jail, sizeof(d->jail), "%s", name);
		d->jid = jid;
		d->nifs = n > JAIL_IFS_MAX ? JAIL_IFS_MAX : n;
		memcpy(d->ifs, ifs, sizeof(ifs[0]) * (size_t)d->nifs);
		d->made = d->at = mono_ms();
	}
	if (ndues > 0 && !settling && pthread_create(&tid, NULL, settler,
	    NULL) == 0) {
		(void)pthread_detach(tid);
		settling = true;
	}
	pthread_mutex_unlock(&follow_lock);
}

/* A jail removed: what its followers ran there gone, its wait ended. */
static void
went(const char *name, int jid)
{
	int	i;

	pthread_mutex_lock(&follow_lock);
	for (i = 0; i < nfollowers; i++)
		followers[i]->gone(name, jid);
	for (i = 0; i < ndues; )
		if (dues[i].jid == jid && strcmp(dues[i].jail, name) == 0)
			dues[i] = dues[--ndues];
		else
			i++;
	pthread_mutex_unlock(&follow_lock);
}

static void
told(const char *name, int jid, const char *state)
{
	ucl_object_t	*o;
	char		*json;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(name), "jail", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(state), "state", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(jid), "jid", 0, false);
	if ((json = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT)) != NULL)
		event_add("jail-state", "%s", json);
	free(json);
	ucl_object_unref(o);
}

/* jid watched for its removal; said running when it is new. */
static void
watch(int kq, int jid, bool tell)
{
	struct kevent	 ev;
	struct wj	*w;
	char		*name;

	LIST_FOREACH(w, &jails, list)
		if (w->jid == jid)
			return;
	if ((name = jail_getname(jid)) == NULL)
		return;
	if ((w = calloc(1, sizeof(*w))) == NULL) {
		free(name);
		return;
	}
	w->jid = jid;
	w->name = name;
	EV_SET(&ev, jid, EVFILT_JAIL, EV_ADD, NOTE_JAIL_REMOVE |
	    NOTE_JAIL_CHILD, 0, w);
	if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
		/* Gone already. */
		free(w->name);
		free(w);
		return;
	}
	LIST_INSERT_HEAD(&jails, w, list);
	if (tell)
		told(w->name, jid, "running");
	came(w->name, jid);
}

static void
watch_all(int kq, bool tell)
{
	int	jid;

	jid = 0;
	while ((jid = jail_next(jid)) > 0)
		watch(kq, jid, tell);
}

static void *
watcher(void *arg __unused)
{
	struct kevent	 ev;
	struct wj	*w;
	int		 kq;

	if ((kq = kqueue()) == -1) {
		logmsg(LOG_NOTICE, "no events of the jails: kqueue: %s",
		    strerror(errno));
		return (NULL);
	}
	EV_SET(&ev, 0, EVFILT_JAIL, EV_ADD, NOTE_JAIL_CHILD, 0, NULL);
	if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
		logmsg(LOG_NOTICE, "no events of the jails: EVFILT_JAIL: %s",
		    strerror(errno));
		close(kq);
		return (NULL);
	}
	watch_all(kq, false);
	for (;;) {
		if (kevent(kq, NULL, 0, &ev, 1, NULL) == -1) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (ev.filter != EVFILT_JAIL)
			continue;
		/* Made, the host's child or a jail's: which one, unless
		 * several were. */
		if ((ev.fflags & NOTE_JAIL_CHILD) != 0) {
			if (ev.data != 0 && (ev.fflags & NOTE_JAIL_MULTI) == 0)
				watch(kq, (int)ev.data, true);
			else
				watch_all(kq, true);
		}
		if ((w = ev.udata) == NULL ||
		    (ev.fflags & NOTE_JAIL_REMOVE) == 0)
			continue;
		told(w->name, w->jid, "stopped");
		/* What the services that follow it ran there. */
		went(w->name, w->jid);
		/* Its logical network element's helper, killed with it. */
		lne_gone(w->jid);
		/* Its BMP stations' listeners, which would hold it dying. */
		bmp_jail_gone(w->jid);
		LIST_REMOVE(w, list);
		free(w->name);
		free(w);
	}
	close(kq);
	return (NULL);
}

void
jail_watch_start(void)
{
	pthread_t	tid;
	int		error;

	if ((error = pthread_create(&tid, NULL, watcher, NULL)) != 0) {
		logmsg(LOG_WARNING, "no events of the jails: pthread_create: "
		    "%s", strerror(error));
		return;
	}
	(void)pthread_detach(tid);
}
