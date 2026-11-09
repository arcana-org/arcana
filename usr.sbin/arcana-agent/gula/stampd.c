/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula, the far end of a measurement: stampd(8), the STAMP
 * Session-Reflector (RFC 8762, RFC 8972's SSID) of the submodule
 * stamp/.  The agent reflects nothing itself.  It says in rc.conf where
 * stampd answers, the base's way: stampd_enable and stampd_fibs, the
 * FIBs of the host's probe targets (probe_fibs(), gula/probe.c) and of
 * its steered routes (sdwan_fibs(), invidia/sdwan.c), written as a
 * commit writes rc.conf (rca_*: Arcana's file or the admin's, by
 * config-files), and has "service stampd reload" start the instances
 * of FIBs added (one a FIB, rc.subr's stampd_fib), stop those of FIBs
 * gone and tell the others.  No service, no setting: what Arcana set
 * taken out, stampd stopped; what the admin set left alone.
 *
 * Looked at again a moment after the probes or the routes change
 * (stampd_nudge()), the changes of that moment together, and every
 * RECHECK_S seconds: a write refused before (rc-conf-files not yet
 * accepted, a value of the admin's in the way) is tried again, and
 * said once, not each time.  Nothing is written while stampd's rc
 * script is not in the host's rc.d directories (its package not
 * installed).  A jail's edges are not looked at: an agent in a vnet
 * jail runs its own.
 */

#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"
#include "collect.h"
#include "varconf.h"

#define	STAMPD		"stampd"
#define	FIBS_MAX	64
#define	RECHECK_S	60
#define	SETTLE_MS	500	/* after a nudge, for those that follow it */

static pthread_mutex_t	 mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	 cv = PTHREAD_COND_INITIALIZER;
static bool		 nudged;
static char		 applied[FIBS_MAX * 4];	/* the FIBs written last */
static bool		 known;
static char		 said[512];		/* the last thing said */

/* The FIBs of the services changed: looked at again, soon. */
void
stampd_nudge(void)
{

	pthread_mutex_lock(&mtx);
	nudged = true;
	pthread_cond_signal(&cv);
	pthread_mutex_unlock(&mtx);
}

/* A warning or a notice, said when it differs from the one before. */
static void
tell(int pri, const char *fmt, ...) __printflike(2, 3);

static void
tell(int pri, const char *fmt, ...)
{
	char	buf[sizeof(said)];
	va_list	ap;

	va_start(ap, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (strcmp(buf, said) == 0)
		return;
	(void)strlcpy(said, buf, sizeof(said));
	logmsg(pri, "%s", buf);
}

static int
cmp_int(const void *a, const void *b)
{
	int	x = *(const int *)a, y = *(const int *)b;

	return ((x > y) - (x < y));
}

/* The FIBs the host's services use, ascending, as words into buf;
 * how many. */
static int
wanted(char *buf, size_t len)
{
	int	v[FIBS_MAX], got[FIBS_MAX], n, ng, i, k, pass;
	size_t	off;

	n = 0;
	for (pass = 0; pass < 2; pass++) {
		ng = pass == 0 ? probe_fibs(got, FIBS_MAX) :
		    sdwan_fibs(got, FIBS_MAX);
		for (i = 0; i < ng && n < FIBS_MAX; i++) {
			for (k = 0; k < n && v[k] != got[i]; k++)
				;
			if (k == n && got[i] >= 0)
				v[n++] = got[i];
		}
	}
	qsort(v, (size_t)n, sizeof(v[0]), cmp_int);
	buf[0] = '\0';
	for (i = 0, off = 0; i < n && off < len; i++)
		off += (size_t)snprintf(buf + off, len - off, "%s%d", i > 0 ?
		    " " : "", v[i]);
	return (n);
}

/* Whether stampd's rc script is in one of the host's rc.d directories. */
static bool
installed(void)
{
	char	*dirs, *p, *d, path[MAXPATHLEN];
	bool	 there = false;

	if ((dirs = strdup(opts.rc_dirs)) == NULL)
		return (false);
	for (p = dirs; !there && (d = strsep(&p, ":")) != NULL; ) {
		if (*d == '\0')
			continue;
		(void)snprintf(path, sizeof(path), "%s/" STAMPD, d);
		there = access(path, X_OK) == 0;
	}
	free(dirs);
	return (there);
}

static bool
yes(const char *v)
{

	return (v != NULL && (strcasecmp(v, "YES") == 0 || strcasecmp(v,
	    "TRUE") == 0 || strcasecmp(v, "ON") == 0 || strcmp(v, "1") == 0));
}

/* "service stampd verb": 0, or -1 with why in err. */
static int
service(struct work *w, const char *verb, char *err, size_t errlen)
{
	struct execres	 res;
	char		*argv[4];

	argv[0] = (char *)(uintptr_t)opts.service_bin;
	argv[1] = (char *)(uintptr_t)STAMPD;
	argv[2] = (char *)(uintptr_t)verb;
	argv[3] = NULL;
	if (run_exec(w, argv, &res) == 0 && res.status == 0)
		return (0);
	(void)snprintf(err, errlen, "%s", exec_error(w, &res, wfmt(w,
	    "service " STAMPD " %s", verb)));
	return (-1);
}

/* rc.conf made to say what want says (n FIBs), and stampd told.  Under
 * change_lock. */
static void
apply(struct work *w, const char *want, int n)
{
	struct rca	 x;
	const char	*en, *fb;
	char		 err[1024];
	bool		 ours;

	if (rca_open(&x, STAMPD, err, sizeof(err)) != 0) {
		tell(LOG_WARNING, "stampd: rc.conf: %s", err);
		return;
	}
	en = rca_get(&x, STAMPD "_enable");
	fb = rca_get(&x, STAMPD "_fibs");
	/* Arcana's own: in its file, or in the ledger's values. */
	ours = vc_get(x.f, STAMPD "_enable") != NULL ||
	    vc_get(x.f, STAMPD "_fibs") != NULL;
	if (n == 0 && !ours) {
		/* Nothing of Arcana's: the admin's stampd, if any, theirs. */
		(void)strlcpy(applied, want, sizeof(applied));
		known = true;
		rca_close(&x);
		return;
	}
	if (n > 0 && yes(en) && fb != NULL && strcmp(fb, want) == 0) {
		(void)strlcpy(applied, want, sizeof(applied));
		known = true;
		rca_close(&x);
		return;
	}
	err[0] = '\0';
	if (n == 0) {
		(void)rca_drop(&x, STAMPD "_enable");
		(void)rca_drop(&x, STAMPD "_fibs");
		if (rca_write(&x, NULL, err, sizeof(err)) != 0) {
			rca_undo(&x);
			tell(LOG_WARNING, "stampd: no service uses a FIB, but its "
			    "settings are still in %s: %s", rca_where(&x), err);
			rca_close(&x);
			return;
		}
		/* No longer enabled: onestop, as rc.subr has it. */
		if (service(w, "onestop", err, sizeof(err)) != 0)
			logmsg(LOG_WARNING, "stampd: %s", err);
		tell(LOG_INFO, "stampd: no service uses a FIB: stampd_enable "
		    "and stampd_fibs taken out of %s, stampd stopped",
		    rca_where(&x));
	} else {
		if (rca_set(&x, STAMPD "_enable", "YES", err, sizeof(err)) != 0 ||
		    rca_set(&x, STAMPD "_fibs", want, err, sizeof(err)) != 0 ||
		    rca_write(&x, NULL, err, sizeof(err)) != 0) {
			rca_undo(&x);
			tell(LOG_WARNING, "stampd: not set to answer in FIB%s %s: "
			    "%s", n > 1 ? "s" : "", want, err);
			rca_close(&x);
			return;
		}
		if (service(w, "reload", err, sizeof(err)) != 0) {
			/* Written: rc(8) starts it at boot; said, and tried
			 * again with the next change. */
			tell(LOG_WARNING, "stampd: stampd_fibs=\"%s\" in %s, but "
			    "%s", want, rca_where(&x), err);
			rca_close(&x);
			return;
		}
		tell(LOG_INFO, "stampd: answering in FIB%s %s (stampd_fibs in "
		    "%s)", n > 1 ? "s" : "", want, rca_where(&x));
	}
	(void)strlcpy(applied, want, sizeof(applied));
	known = true;
	rca_close(&x);
}

static void *
watch(void *arg __unused)
{
	struct work	 w;
	struct timespec	 ts, settle = { 0, SETTLE_MS * 1000000L };
	char		 want[sizeof(applied)];
	int		 n;

	for (;;) {
		pthread_mutex_lock(&mtx);
		if (!nudged) {
			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_sec += RECHECK_S;
			(void)pthread_cond_timedwait(&cv, &mtx, &ts);
		}
		nudged = false;
		pthread_mutex_unlock(&mtx);
		(void)nanosleep(&settle, NULL);
		n = wanted(want, sizeof(want));
		if (known && strcmp(want, applied) == 0)
			continue;
		if (!installed()) {
			if (n > 0)
				tell(LOG_WARNING, "stampd: not installed (no rc "
				    "script in %s): FIB%s %s not reflected",
				    opts.rc_dirs, n > 1 ? "s" : "", want);
			continue;
		}
		pthread_mutex_lock(&change_lock);
		if (!change_note("stampd: FIBs %s", n > 0 ? want : "none")) {
			pthread_mutex_unlock(&change_lock);
			continue;
		}
		work_init(&w);
		apply(&w, want, n);
		work_free(&w);
		(void)change_note(NULL);
		pthread_mutex_unlock(&change_lock);
	}
	return (NULL);
}

/* At the start, once the probes and the steering are back: looked at
 * once, then on each change. */
void
stampd_start(void)
{
	pthread_t	tid;
	int		error;

	stampd_nudge();
	if ((error = pthread_create(&tid, NULL, watch, NULL)) != 0)
		logmsg(LOG_ERR, "stampd: no thread: %s", strerror(error));
	else
		(void)pthread_detach(tid);
}
