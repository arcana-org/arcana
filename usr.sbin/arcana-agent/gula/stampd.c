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
 * FIBs of the host's probe targets (probe_fibs(), gula/probe_view.c) and of
 * its steered routes (sdwan_fibs(), invidia/sdwan.c), written as a
 * commit writes rc.conf (rca_*: Arcana's file or the admin's, by
 * config-files), and has "service stampd reload" start the instances
 * of FIBs added (one a FIB, rc.subr's stampd_fib), stop those of FIBs
 * gone and tell the others.  stampd_fibs is a word list: Arcana's FIBs
 * added to the admin's, its own alone taken out.  No service, no
 * setting: what Arcana set taken out, stampd stopped; what the admin
 * set left alone.
 *
 * Looked at again a moment after the probes or the routes change
 * (stampd_nudge()), the changes of that moment together, and every
 * RECHECK_S seconds: a write refused before (rc-conf-files not yet
 * accepted, a value of the admin's in the way) is tried again, and
 * said once, not each time.  Nothing is written while stampd's rc
 * script is not in the host's rc.d directories (its package not
 * installed).  A jail's edges are not looked at: an agent in a vnet
 * jail runs its own.
 *
 * The reflector's keys (PLAN-SDN-YANG 5.1.7): the plain tunnels' STAMP
 * keys, each derived by the prober from the tunnel's pair and the far
 * end's public half (probe_stamp_keys(), gula/probe_view.c), written to
 * stampd's key file (--stampd-keys, stampd.keys beside stampd.conf),
 * root's alone, 0600, in place, as stampd(8) wants it: it keeps the
 * file open from its start and reads it again on SIGHUP.  The lines
 * after Arcana's marker are Arcana's, rewritten; those before it, an
 * admin's, kept.  A file made while stampd runs is one it never
 * opened: then it is restarted rather than told.  The keys are never
 * logged; what is compared from one look to the next is their digest.
 * stampd takes STAMP_KEYS_SSID_MAX keys an SSID, the admin's counted,
 * and refuses a whole file with more (keeping the keys it had, said in
 * its own log alone): of the tunnels whose derived SSIDs are the same,
 * the first in the targets' order are written, each other logged and a
 * fault of its (stamp-unauthenticated, Warning, "reflector:<target>");
 * a file stampd would refuse still (libstamp's parser says so: the
 * admin's lines) is not written, and a reload that fails after the keys
 * changed is not taken: both a fault of the file's, "reflector:<file>",
 * tried again at every look.  The faults are held to what is so at
 * each look (fault_reconcile()).
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "agent.h"
#include "collect.h"
#include "stamp.h"
#include "varconf.h"

#define	STAMPD		"stampd"
#define	FIBS_MAX	64
#define	RECHECK_S	60
#define	SETTLE_MS	500	/* after a nudge, for those that follow it */
#define	STAMPD_KEYS	"/usr/local/etc/stampd.keys"	/* main.c's */
#define	KEYS_MAX	256	/* as many as the prober has targets */
#define	KEYS_MARK	"# arcana-agent: the lines below are its own, the " \
			"plain tunnels' STAMP keys (rewritten)\n"
#define	OVER_MAX	32	/* targets whose key is not written, said */
#define	FAULT_BY	"stampd"
#define	FAULT_TYPE	"stamp-unauthenticated"
#define	FAULT_SCOPE	"reflector:"

/* A target whose key is not written: its SSID has so many already. */
struct over {
	char	target[PROBE_NAME_MAX];
	int	ssid;
	int	same;
};

static const char *keys_file(void);

static pthread_mutex_t	 mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	 cv = PTHREAD_COND_INITIALIZER;
static bool		 nudged;
/* The FIBs written last: FIBS_MAX words of 5 digits at most, a space
 * after each. */
static char		 applied[FIBS_MAX * 6 + 1];
static bool		 known;
static char		 said[512];		/* the last thing said */
static unsigned char	 kdig[32];		/* the keys written last */
static bool		 kknown;
/* Why stampd does not take its key file, as the agent last saw: a file
 * it would refuse (not written), a reload that failed; "" when it does.
 * While it is said, every look tries again. */
static char		 kfault[512];

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

/*
 * The FIBs the host's services use, ascending, as words into buf (of
 * applied's size, room for FIBS_MAX of them); how many.  Those beyond
 * FIBS_MAX are not reflected, and said.
 */
static int
wanted(char *buf, size_t len)
{
	int	v[FIBS_MAX], got[FIBS_MAX + 1], n, ng, i, k, pass, over;
	size_t	off;

	n = 0;
	over = -1;
	for (pass = 0; pass < 2; pass++) {
		ng = pass == 0 ? probe_fibs(got, FIBS_MAX + 1) :
		    sdwan_fibs(got, FIBS_MAX + 1);
		for (i = 0; i < ng; i++) {
			for (k = 0; k < n && v[k] != got[i]; k++)
				;
			if (k < n || got[i] < 0)
				continue;
			if (n == FIBS_MAX)
				over = got[i];
			else
				v[n++] = got[i];
		}
	}
	if (over >= 0)
		tell(LOG_WARNING, "stampd: more than %d FIBs used: FIB %d and "
		    "those after it not reflected", FIBS_MAX, over);
	qsort(v, (size_t)n, sizeof(v[0]), cmp_int);
	buf[0] = '\0';
	for (i = 0, off = 0; i < n; i++) {
		k = snprintf(buf + off, len - off, "%s%d", i > 0 ? " " : "",
		    v[i]);
		/* Never a number cut short, which would be another FIB. */
		if (k < 0 || (size_t)k >= len - off) {
			buf[off] = '\0';
			n = i;
			break;
		}
		off += (size_t)k;
	}
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

static int
cmp_key(const void *a, const void *b)
{
	const struct stamp_key	*x = a, *y = b;

	if (x->ssid != y->ssid)
		return (x->ssid < y->ssid ? -1 : 1);
	return (memcmp(x->key, y->key, sizeof(x->key)));
}

/* stampd's key file read whole, into a buffer of the caller's to zero
 * and free (*lenp its length); NULL when there is none or it cannot be
 * read. */
static char *
keys_read(size_t *lenp)
{
	struct stat	 st;
	char		*buf;
	size_t		 len = 0;
	ssize_t		 r;
	int		 fd;

	*lenp = 0;
	if ((fd = open(keys_file(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) == -1)
		return (NULL);
	if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode) || st.st_size >
	    1024 * 1024 || (buf = malloc((size_t)st.st_size + 1)) == NULL) {
		close(fd);
		return (NULL);
	}
	while (len < (size_t)st.st_size && (r = pread(fd, buf + len,
	    (size_t)st.st_size - len, (off_t)len)) > 0)
		len += (size_t)r;
	close(fd);
	buf[len] = '\0';
	*lenp = len;
	return (buf);
}

/*
 * The keys as Arcana's lines of stampd's key file, "ssid key" each,
 * sorted, into a buffer of the caller's to zero and free (*lenp its
 * length; NULL with none); their digest into dig.  stampd takes
 * STAMP_KEYS_SSID_MAX keys an SSID, the admin's lines' among them, and
 * refuses a file with more: of the tunnels whose derived SSIDs are the
 * same, the first in the targets' order are written, the others not,
 * each into over (OVER_MAX of them, *nover).
 */
static char *
keys_text(size_t *lenp, unsigned char *dig, struct over *over, int *nover)
{
	struct stamp_key	*k, *ak;
	char			 (*names)[PROBE_NAME_MAX], *text, *m, why[128];
	char			*buf;
	size_t			 off = 0, cap, nak, tl, j;
	unsigned int		 dl = 32;
	int			 n, i, kept, same;

	*lenp = 0;
	*nover = 0;
	memset(dig, 0, 32);
	if ((k = calloc(KEYS_MAX, sizeof(*k))) == NULL)
		return (NULL);
	if ((names = calloc(KEYS_MAX, sizeof(*names))) == NULL) {
		free(k);
		return (NULL);
	}
	n = probe_stamp_keys(k, names, KEYS_MAX);
	/* The admin's: the lines before Arcana's marker (none when they do
	 * not parse: the file's check says why). */
	ak = NULL;
	nak = 0;
	if ((text = keys_read(&tl)) != NULL) {
		if ((m = strstr(text, KEYS_MARK)) != NULL)
			tl = (size_t)(m - text);
		if (stamp_keys_parse(text, tl, &ak, &nak, why, sizeof(why)) != 0)
			nak = 0;
		explicit_bzero(text, strlen(text));
		free(text);
	}
	for (i = kept = 0; i < n; i++) {
		for (j = 0, same = 0; j < nak; j++)
			same += ak[j].ssid == k[i].ssid;
		for (j = 0; j < (size_t)kept; j++)
			same += k[j].ssid == k[i].ssid;
		if (same >= STAMP_KEYS_SSID_MAX) {
			if (*nover < OVER_MAX) {
				(void)strlcpy(over[*nover].target, names[i],
				    sizeof(over[*nover].target));
				over[*nover].ssid = k[i].ssid;
				over[*nover].same = same;
				(*nover)++;
			}
			continue;
		}
		k[kept++] = k[i];
	}
	n = kept;
	if (ak != NULL)
		stamp_keys_free(ak, nak);
	free(names);
	qsort(k, (size_t)n, sizeof(*k), cmp_key);
	cap = (size_t)n * (8 + 2 * STAMP_KEY_MAX + 2) + 1;
	if (n <= 0 || (buf = malloc(cap)) == NULL) {
		explicit_bzero(k, KEYS_MAX * sizeof(*k));
		free(k);
		return (NULL);
	}
	for (i = 0; i < n; i++) {
		off += (size_t)snprintf(buf + off, cap - off, "%d ", k[i].ssid);
		for (j = 0; j < k[i].len; j++)
			off += (size_t)snprintf(buf + off, cap - off, "%02x",
			    k[i].key[j]);
		off += (size_t)snprintf(buf + off, cap - off, "\n");
	}
	explicit_bzero(k, KEYS_MAX * sizeof(*k));
	free(k);
	(void)EVP_Digest(buf, off, dig, &dl, EVP_sha256(), NULL);
	*lenp = off;
	return (buf);
}

/* stampd's key file: --stampd-keys, the default under --root. */
static const char *
keys_file(void)
{
	static char	buf[MAXPATHLEN];

	if (opts.root == NULL || strcmp(opts.stampd_keys, STAMPD_KEYS) != 0)
		return (opts.stampd_keys);
	(void)snprintf(buf, sizeof(buf), "%s%s", opts.root, opts.stampd_keys);
	return (buf);
}

/*
 * stampd's key file made to hold the admin's lines (those before
 * Arcana's marker) and Arcana's (text, len octets; none: the marker and
 * its lines taken out), rewritten in place, root's and 0600; *made when
 * there was no file (one is made only for keys), *changed when it was
 * written.  0, or -1 and why; -2 and why when stampd would refuse the
 * file so made (the admin's lines and Arcana's past its bounds), which
 * is then not written.
 */
static int
keys_write(const char *text, size_t len, bool *made, bool *changed,
    char *err, size_t errlen)
{
	struct stat	 st;
	struct stamp_key *pk;
	char		*old = NULL, *nw = NULL, *m, why[128];
	size_t		 olen = 0, keep, nlen = 0, npk;
	ssize_t		 r;
	const char	*path;
	int		 fd, rc = -1;

	*made = *changed = false;
	path = keys_file();
	if ((fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)) ==
	    -1) {
		if (errno != ENOENT) {
			(void)snprintf(err, errlen, "%s: %s", path,
			    strerror(errno));
			return (-1);
		}
		if (len == 0)
			return (0);
		if ((fd = open(path, O_RDWR | O_CREAT | O_EXCL |
		    O_NOFOLLOW | O_CLOEXEC, 0600)) == -1) {
			(void)snprintf(err, errlen, "%s: %s", path,
			    strerror(errno));
			return (-1);
		}
		*made = true;
	}
	if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode) || st.st_size >
	    1024 * 1024) {
		(void)snprintf(err, errlen, "%s: not a regular file of a size "
		    "stampd reads", path);
		goto out;
	}
	/* stampd's terms: its owner's alone, root's. */
	if ((geteuid() == 0 && (st.st_uid != 0 || st.st_gid != 0) &&
	    fchown(fd, 0, 0) == -1) || ((st.st_mode & 07777) != 0600 &&
	    fchmod(fd, 0600) == -1)) {
		(void)snprintf(err, errlen, "%s: %s", path,
		    strerror(errno));
		goto out;
	}
	if ((old = malloc((size_t)st.st_size + 1)) == NULL)
		goto nomem;
	while (olen < (size_t)st.st_size && (r = pread(fd, old + olen,
	    (size_t)st.st_size - olen, (off_t)olen)) > 0)
		olen += (size_t)r;
	old[olen] = '\0';
	/* The admin's: everything before Arcana's marker. */
	m = strstr(old, KEYS_MARK);
	keep = m != NULL ? (size_t)(m - old) : olen;
	nlen = keep + (len > 0 ? strlen(KEYS_MARK) + len : 0) + 1;
	if ((nw = malloc(nlen)) == NULL)
		goto nomem;
	memcpy(nw, old, keep);
	nlen = keep;
	if (len > 0 && keep > 0 && nw[keep - 1] != '\n')
		nw[nlen++] = '\n';
	if (len > 0) {
		memcpy(nw + nlen, KEYS_MARK, strlen(KEYS_MARK));
		nlen += strlen(KEYS_MARK);
		memcpy(nw + nlen, text, len);
		nlen += len;
	}
	/* Never a file stampd refuses (libstamp's own parser): it would
	 * keep the keys as they were, and say so in its log alone. */
	if (stamp_keys_parse(nw, nlen, &pk, &npk, why, sizeof(why)) != 0) {
		(void)snprintf(err, errlen, "%s: stampd would refuse it (%s), "
		    "so it is not written: stampd keeps the keys it has", path,
		    why);
		rc = -2;
		goto out;
	}
	stamp_keys_free(pk, npk);
	if (nlen == olen && memcmp(nw, old, olen) == 0) {
		rc = 0;
		goto out;
	}
	/* In place: stampd reads it through the descriptor it kept. */
	if (ftruncate(fd, 0) == -1 || pwrite(fd, nw, nlen, 0) != (ssize_t)nlen
	    || fsync(fd) == -1) {
		(void)snprintf(err, errlen, "%s: %s", path,
		    strerror(errno));
		goto out;
	}
	*changed = true;
	rc = 0;
	goto out;
nomem:
	(void)snprintf(err, errlen, "%s", strerror(errno));
out:
	if (old != NULL) {
		explicit_bzero(old, olen);
		free(old);
	}
	if (nw != NULL) {
		explicit_bzero(nw, nlen);
		free(nw);
	}
	close(fd);
	return (rc);
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

/*
 * Does stampd_fibs (fb, as rca_get() has it) say want already?  A word
 * list Arcana only adds to (cf_list_additive()): the admin's FIBs kept,
 * Arcana's after them.  In Arcana's file, theirs merged with want; where
 * Arcana writes into theirs, fb is Arcana's own (the ledger's), or
 * theirs while Arcana wrote none.
 */
static bool
said_already(struct rca *x, const char *fb, const char *want)
{
	const char	*theirs;
	char		*m;
	bool		 same;

	if (x->sys)
		return (cf_same_words(fb, want));
	if ((theirs = rca_user_get(x, STAMPD "_fibs")) == NULL)
		return (cf_same_words(fb, want));
	if ((m = cf_merge(theirs, want, "")) == NULL)
		return (false);
	same = cf_same_words(fb, m);
	free(m);
	return (same);
}

/*
 * rc.conf made to say what want says (n FIBs), and stampd told: want
 * Arcana's FIBs, added to the admin's stampd_fibs (a word list,
 * cf_list_additive()); the FIBs Arcana takes out its own alone.  Under
 * change_lock.
 */
static void
apply(struct work *w, const char *want, int n, const char *keys,
    size_t klen, const unsigned char *dig)
{
	struct rca	 x;
	const char	*en, *fb, *verb;
	char		 err[1024];
	bool		 ours, made = false, kchanged = false;
	int		 rc;

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
		memcpy(kdig, dig, sizeof(kdig));
		kknown = true;
		kfault[0] = '\0';
		rca_close(&x);
		return;
	}
	/* The keys before stampd is told: a new instance reads them. */
	if ((rc = keys_write(n > 0 ? keys : NULL, n > 0 ? klen : 0, &made,
	    &kchanged, err, sizeof(err))) != 0) {
		tell(LOG_WARNING, "stampd: its keys not written: %s", err);
		if (rc == -2)
			(void)strlcpy(kfault, err, sizeof(kfault));
		rca_close(&x);
		return;
	}
	memcpy(kdig, dig, sizeof(kdig));
	kknown = true;
	kfault[0] = '\0';
	/* A file stampd never opened: started again to open it. */
	verb = made ? "restart" : "reload";
	if (n > 0 && yes(en) && fb != NULL && said_already(&x, fb, want)) {
		if (kchanged && service(w, verb, err, sizeof(err)) != 0) {
			tell(LOG_WARNING, "stampd: its keys written to %s, but "
			    "%s", keys_file(), err);
			/* Not taken: said as a fault, and tried again. */
			(void)snprintf(kfault, sizeof(kfault), "%s written, but "
			    "%s", keys_file(), err);
		} else if (kchanged)
			tell(LOG_INFO, "stampd: its keys rewritten in %s, stampd "
			    "told (%s)", keys_file(), verb);
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
		if (service(w, verb, err, sizeof(err)) != 0) {
			/* Written: rc(8) starts it at boot; said, and tried
			 * again with the next change. */
			tell(LOG_WARNING, "stampd: stampd_fibs=\"%s\" in %s, but "
			    "%s", want, rca_where(&x), err);
			if (kchanged)
				(void)snprintf(kfault, sizeof(kfault), "%s "
				    "written, but %s", keys_file(), err);
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

/*
 * The reflector's faults (stamp-unauthenticated, its own, Warning):
 * each target whose key is not written (over, nover of them), its far
 * end's authenticated STAMP to this host failing; the key file while
 * stampd does not take it (kfault).  Every other of its own cleared
 * (fault_reconcile()), so that one of a target gone or of a file
 * mended, or one an agent before raised, does not stay open.
 */
static void
key_faults(const struct over *over, int nover)
{
	static const char *const scope[] = { FAULT_SCOPE, NULL };
	struct fault_live	 v[OVER_MAX + 1];
	char			 obj[OVER_MAX + 1][PROBE_NAME_MAX + 16];
	size_t			 n, k;

	memset(v, 0, sizeof(v));
	for (n = 0; n < (size_t)nover; n++) {
		(void)snprintf(obj[n], sizeof(obj[n]), FAULT_SCOPE "%s",
		    over[n].target);
		v[n].object = obj[n];
	}
	if (kfault[0] != '\0') {
		(void)snprintf(obj[n], sizeof(obj[n]), FAULT_SCOPE "%s",
		    keys_file());
		v[n].object = obj[n];
		n++;
	}
	(void)fault_reconcile(FAULT_BY, FAULT_TYPE, scope, v, n, "stampd has "
	    "its key, or takes its key file, again");
	for (k = 0; k < n; k++) {
		if (v[k].open)
			continue;
		if (k < (size_t)nover) {
			logmsg(LOG_WARNING, "stampd: target %s's STAMP key not "
			    "written: SSID %d has %d keys in %s already, and "
			    "stampd takes %d an SSID", over[k].target,
			    over[k].ssid, over[k].same, keys_file(),
			    STAMP_KEYS_SSID_MAX);
			fault_set(FAULT_TYPE, "Warning", obj[k], FAULT_BY,
			    "the reflector has no key for target %s: SSID %d "
			    "has %d keys already, stampd takes %d; its far "
			    "end's authenticated STAMP fails", over[k].target,
			    over[k].ssid, over[k].same, STAMP_KEYS_SSID_MAX);
		} else
			fault_set(FAULT_TYPE, "Warning", obj[k], FAULT_BY,
			    "stampd does not take its keys: %s", kfault);
	}
}

static void *
watch(void *arg __unused)
{
	struct work	 w;
	struct timespec	 ts, settle = { 0, SETTLE_MS * 1000000L };
	struct over	 over[OVER_MAX];
	char		 want[sizeof(applied)], *keys;
	unsigned char	 dig[32];
	size_t		 klen;
	int		 n, nover;

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
		keys = keys_text(&klen, dig, over, &nover);
		if (known && strcmp(want, applied) == 0 && kknown && memcmp(dig,
		    kdig, sizeof(dig)) == 0 && kfault[0] == '\0')
			goto next;
		if (!installed()) {
			if (n > 0)
				tell(LOG_WARNING, "stampd: not installed (no rc "
				    "script in %s): FIB%s %s not reflected",
				    opts.rc_dirs, n > 1 ? "s" : "", want);
			goto next;
		}
		pthread_mutex_lock(&change_lock);
		if (!change_note("stampd: FIBs %s", n > 0 ? want : "none")) {
			pthread_mutex_unlock(&change_lock);
			goto next;
		}
		work_init(&w);
		apply(&w, want, n, keys, klen, dig);
		work_free(&w);
		(void)change_note(NULL);
		pthread_mutex_unlock(&change_lock);
next:
		/* Each look, the first a full view: what it raised held to
		 * what is so now. */
		key_faults(over, nover);
		if (keys != NULL) {
			explicit_bzero(keys, klen);
			free(keys);
		}
	}
	return (NULL);
}

/*
 * stampd as it is set, arcana-stamp's reflector: its rc script there,
 * the FIBs written last (words), its key file and the plain tunnels'
 * keys kept in it, the last thing said of it.
 */
void
stampd_state(bool *inst, char *fibs, size_t flen, const char **kfile,
    int *nkeys, char *status, size_t slen)
{
	struct stamp_key	*k;

	*inst = installed();
	*kfile = keys_file();
	(void)strlcpy(fibs, known ? applied : "", flen);
	(void)strlcpy(status, said, slen);
	*nkeys = 0;
	if ((k = calloc(KEYS_MAX, sizeof(*k))) != NULL) {
		*nkeys = probe_stamp_keys(k, NULL, KEYS_MAX);
		explicit_bzero(k, KEYS_MAX * sizeof(*k));
		free(k);
	}
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
