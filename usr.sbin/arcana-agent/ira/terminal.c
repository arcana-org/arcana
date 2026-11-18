/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Ira: a terminal to the host, or to one of its jails, for the console's
 * page (arcana-stream's terminal).  What runs on it is login(1), as
 * getty(8) would run it on a line: the person types an account's name
 * and its password, the host's own PAM (/etc/pam.d/login) says yes or
 * no, and they get that account's shell, rights and environment.  The
 * agent picks no user and runs no shell of its own: root logs in only
 * as the host's policy lets it (securetty, PAM).  In a jail it is the
 * jail's own login, run there by jexec(8), and so the jail's accounts:
 * a process that has had threads may not jail_attach(2) itself, an
 * exec'd one may.
 *
 * A session is a pseudo-terminal (posix_openpt(2)), its other end the
 * controlling terminal of a session of its own (setsid(2),
 * TIOCSCTTY) that login leads.  The stream's opening names jail=, rows=,
 * cols= and from= (the address the person comes from, for login -h and
 * utmpx(5)); each chunk from the console is what was typed, or with
 * rows and cols the window's new size (TIOCSWINSZ, which signals the
 * terminal's foreground SIGWINCH); each chunk to it what the terminal
 * wrote, and once, on the host, the account that logged in as utmpx
 * says (a jail's utmpx is the jail's, not read).
 *
 * Each session has a thread of its own, which reads the terminal only
 * as fast as the stream takes it: with no credit it stops reading, the
 * terminal's queue fills, and what writes to it waits, never the
 * agent's loop.  What was typed is kept until the terminal takes it
 * (the terminal is written without blocking, by that thread), up to
 * TERM_IN_MAX.  The stream's end hangs the session up: SIGHUP to the
 * terminal's foreground and to login's group, the terminal closed (the
 * kernel's hangup), SIGKILL TERM_HUP_S later to what is left of login's
 * group, and login reaped.  The session's end, login gone and the
 * terminal closed by all, ends the stream; so does no typing for the
 * idle time (--terminal-idle, TERM_IDLE_S).  TERM_MAX at once.
 *
 * Mapped logins (arcana-stream's terminal-as, its own command, which
 * NACM refuses unless a rule permits it): login -f, no password asked,
 * for the console user the request is for, cbl_req_user(), the very
 * name NACM judged; never a second field, and no ticket or signature
 * beside it: whoever holds the console holds every host anyway (signed
 * agent updates, the authorized_keys ssh.c writes).  Only the console,
 * the socket's group or root on the unix socket asks; a request for no
 * user (the recovery session that names none) or for the console's own
 * user (but root's) is refused.  The host is the authority: the file
 * --terminal-users (/usr/local/etc/arcana/terminal-users), absent and
 * the feature is off, says per scope (host, or jail:<name>, never one
 * for the other) which account which console users may become; what
 * the console maps only chooses among it.  It is opened as sshd's
 * secure_filename() would: every directory from / down by descriptor,
 * none a link nor writable by another than root (a sticky one of
 * root's aside), the file no link, root's, 0600 or stricter.  No job,
 * sysfile, bundle or YANG node writes it.  It is read again while a
 * mapped session lasts, whenever it changed (TERM_RECHECK_S): a session
 * it no longer allows is hung up.  An account of uid 0 (root, toor, any
 * other name, a jail's too) only where its line says +root; a word
 * beginning with + is a flag, never a user.  On the host the checks
 * login -f skips (it never calls pam_acct_mgmt(3)) are made here before
 * the fork: the account there, not locked, not expired, a shell that
 * logs in, nologin(5) unless the class has ignorenologin, the class's
 * times, hosts and ttys; login.access(5) and securetty are not consulted on
 * this path, the file stands for them.  The session is established only
 * once utmpx says login logged in exactly that account (until then what
 * is typed waits): another account, or none within TERM_CONFIRM_S, is
 * hung up.  In a jail the jail's getent(1), run in it by jexec, proves
 * the account there first (not locked, of uid 0 only by +root, a shell
 * that logs in); its utmpx is not read, so the account is never said to
 * be confirmed, and what is typed waits until login wrote anything.  The
 * residual: an account gone from the jail between its getent and login
 * -f gets the jail's login prompt, which is output, so typing reaches
 * it (the jail's own password then decides).  What may wait (the
 * account's checks, a host's by getpwnam_r(3) and its login class too,
 * a jail's getent, login's start, the hangup's reaping) is the
 * session's own thread's, never the connection's: the stream is
 * accepted first and closed on a refusal.
 * Each open, refusal and end is logged to LOG_AUTH: the console user,
 * the account, the scope, the terminal and the address.  The accounts
 * whose password is empty, which login(1) lets anyone in as, are one
 * fault (empty-password, how many and no names; the names to LOG_AUTH),
 * looked for at the start and every TERM_FINDINGS_S in a thread of its
 * own.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <login_cap.h>
#include <paths.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <utmpx.h>

#include "agent.h"
#include "ystream.h"

#define	TERM_MAX	8			/* sessions at once */
#define	TERM_CHUNK	(16 * 1024)		/* what a data message carries */
#define	TERM_ROOM	(TERM_CHUNK + 4096)
#define	TERM_IN_MAX	(1024 * 1024)		/* typed, not yet taken */
#define	TERM_HUP_S	5			/* hung up, then killed */
#define	TERM_UTX_S	2			/* utmpx looked at so often */
#define	TERM_UTX_FOR	600			/* ... for so long at most */
#define	TERM_FROM_MAX	64			/* login -h's host */
#define	TERM_ACCOUNT_MAX 32			/* an account's name */
#define	TERM_CONFIRM_S	10			/* login -f said by utmpx */
#define	TERM_CONFIRM_MS	200			/* ... looked at so often */
#define	TERM_USERS_MAX	(64 * 1024)		/* the host's file */
#define	TERM_PREFLIGHT_S 5			/* a jail's getent */
#define	TERM_RECHECK_S	2			/* the host's file looked at */
#define	TERM_FINDINGS_S	600			/* empty passwords looked for */
#define	LOCKED		"*LOCKED*"		/* pw(8)'s lock */

struct term {
	pthread_mutex_t	 lock;
	cbl_stream	*s;
	int		 master;	/* the terminal's own end */
	int		 wake[2];	/* the thread's: woken to look again */
	pid_t		 pid;		/* login (jexec, in a jail) */
	char		 tty[32];	/* as utmpx has it: pts/N */
	char		 where[MAXHOSTNAMELEN + 8];	/* "the host", "jail x" */
	char		 who[128];	/* whom the stream was for */
	char		 from[TERM_FROM_MAX + 1];
	char		 account[TERM_ACCOUNT_MAX + 1];	/* terminal-as's; "" */
	char		 scope[MAXHOSTNAMELEN + 8];	/* "host", "jail:x" */
	bool		 jailed;
	bool		 confirmed;	/* utmpx said the account */
	/* A mapped login's, until its thread starts login: */
	int		 slave;		/* the terminal's other end, or -1 */
	int		 jid;
	char		 jail[MAXHOSTNAMELEN];
	bool		 root_ok;	/* its line says +root */
	bool		 uid0;		/* the account is uid 0 */
	bool		 output;	/* login wrote something */
	struct stat	 fst;		/* the host's file as last judged */
	/* The lock's: */
	char		*in;		/* typed, not yet written */
	size_t		 inlen, incap;
	bool		 closed;	/* the stream ended */
	bool		 flood;		/* more typed than TERM_IN_MAX */
	bool		 oom;		/* no memory for what was typed */
	time_t		 last_in;	/* CLOCK_MONOTONIC */
	uint64_t	 nin, nout;
	int		 refs;		/* the thread's, the stream's */
};

static pthread_mutex_t	term_lock = PTHREAD_MUTEX_INITIALIZER;
static int		nterms;
/* getutxent(3) keeps its place in the process. */
static pthread_mutex_t	utx_lock = PTHREAD_MUTEX_INITIALIZER;

static time_t
mono(void)
{
	struct timespec	ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec);
}

static int64_t
mono_ms(void)
{
	struct timespec	ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

/* A mapped login's event to the authentication log (LOG_AUTH), and to
 * the agent's own. */
static void __printflike(1, 2)
authlog(const char *fmt, ...)
{
	va_list	ap;
	char	line[1024];

	va_start(ap, fmt);
	(void)vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	logmsg(LOG_AUTH | LOG_NOTICE, "%s", line);
}

/* The thread woken; from any thread, never blocking. */
static void
term_wake(struct term *t)
{
	char	c = 0;

	(void)write(t->wake[1], &c, 1);
}

static void
term_unref(struct term *t)
{
	bool	last;

	pthread_mutex_lock(&t->lock);
	last = --t->refs == 0;
	pthread_mutex_unlock(&t->lock);
	if (!last)
		return;
	close(t->wake[0]);
	close(t->wake[1]);
	free(t->in);
	pthread_mutex_destroy(&t->lock);
	free(t);
	pthread_mutex_lock(&term_lock);
	nterms--;
	pthread_mutex_unlock(&term_lock);
}

/* A chunk from the console: typed bytes, or the window's size. */
static void
term_data(cbl_stream *s __unused, const struct arcana_stream_chunk *c,
    void *arg)
{
	struct term	*t = arg;
	struct winsize	 ws;
	size_t		 cap;
	char		*nb;

	pthread_mutex_lock(&t->lock);
	if (c->has_rows && c->has_cols && t->master != -1) {
		memset(&ws, 0, sizeof(ws));
		ws.ws_row = c->rows;
		ws.ws_col = c->cols;
		(void)ioctl(t->master, TIOCSWINSZ, &ws);
	}
	if (c->data.len > 0) {
		t->last_in = mono();
		t->nin += c->data.len;
		if (t->inlen + c->data.len > TERM_IN_MAX)
			t->flood = true;
		else {
			if (t->inlen + c->data.len > t->incap) {
				cap = MAX(t->incap * 2, 4096);
				while (cap < t->inlen + c->data.len)
					cap *= 2;
				if ((nb = realloc(t->in, cap)) == NULL)
					t->oom = true;
				else {
					t->in = nb;
					t->incap = cap;
				}
			}
			if (!t->oom) {
				memcpy(t->in + t->inlen, c->data.p,
				    c->data.len);
				t->inlen += c->data.len;
			}
		}
	}
	pthread_mutex_unlock(&t->lock);
	term_wake(t);
}

static void
term_writable(cbl_stream *s __unused, size_t credit __unused, void *arg)
{

	term_wake(arg);
}

static void
term_closed(cbl_stream *s __unused, int code __unused,
    const char *text __unused, void *arg)
{
	struct term	*t = arg;

	pthread_mutex_lock(&t->lock);
	t->closed = true;
	pthread_mutex_unlock(&t->lock);
	term_wake(t);
	term_unref(t);
}

static const struct ys_cbs term_cbs = {
	.on_data = term_data,
	.on_writable = term_writable,
	.on_close = term_closed,
};

/* Who logged in on the session's terminal, as utmpx(5) has it (login
 * writes it, its own pid, once PAM said yes); false while no one has. */
static bool
term_login(const struct term *t, char *buf, size_t len)
{
	struct utmpx	*u;
	bool		 found;

	found = false;
	pthread_mutex_lock(&utx_lock);
	if (setutxdb(UTXDB_ACTIVE, NULL) == 0) {
		while ((u = getutxent()) != NULL)
			if (u->ut_type == USER_PROCESS && u->ut_pid == t->pid &&
			    strncmp(u->ut_line, t->tty, sizeof(u->ut_line)) ==
			    0 && u->ut_user[0] != '\0') {
				(void)snprintf(buf, len, "%.*s",
				    (int)sizeof(u->ut_user), u->ut_user);
				found = true;
				break;
			}
		endutxent();
	}
	pthread_mutex_unlock(&utx_lock);
	return (found);
}

static int	term_spawn(struct term *, char *, size_t);
static int	jail_account(int, const char *, const char *, bool, bool *,
		    char *, size_t);
static int	host_account(const char *, bool, const char *, const char *,
		    bool *, char *, size_t);
static bool	term_still(struct term *, char *, size_t);

/* The session hung up and login reaped, its group killed when it does
 * not go; in its own thread (TERM_HUP_S at most), never the
 * connection's. */
static void
term_hangup(struct term *t)
{
	pid_t	fg;
	int	i, status;

	if (t->pid <= 0) {
		/* No login started: the terminal's ends alone. */
		pthread_mutex_lock(&t->lock);
		if (t->master != -1)
			close(t->master);
		t->master = -1;
		pthread_mutex_unlock(&t->lock);
		if (t->slave != -1)
			close(t->slave);
		t->slave = -1;
		return;
	}
	pthread_mutex_lock(&t->lock);
	if (t->master != -1) {
		if ((fg = tcgetpgrp(t->master)) > 1)
			(void)kill(-fg, SIGHUP);
		(void)kill(-t->pid, SIGHUP);
		/* The kernel's hangup: SIGHUP to the session's leader and
		 * its foreground, reads of the terminal at their end. */
		close(t->master);
		t->master = -1;
	}
	pthread_mutex_unlock(&t->lock);
	for (i = 0; i < TERM_HUP_S * 10; i++) {
		if (waitpid(t->pid, &status, WNOHANG) == t->pid)
			return;
		(void)usleep(100000);
	}
	(void)kill(-t->pid, SIGKILL);
	(void)kill(t->pid, SIGKILL);
	while (waitpid(t->pid, &status, 0) == -1 && errno == EINTR)
		;
}

/*
 * Its thread: the terminal read as the stream has room, what was typed
 * written as the terminal takes it, until either end goes or it was
 * idle too long.
 */
static void *
term_run(void *arg)
{
	struct arcana_stream_chunk	 lc;
	struct term			*t = arg;
	struct pollfd			 pfd[2];
	char				*buf, drain[64], login[33];
	char				 bywhy[160];
	const char			*why;
	size_t				 pend;
	ssize_t				 n;
	time_t				 now, start, idle_at;
	int64_t				 utx_at, now_ms;
	time_t				 recheck_at;
	int				 code, error, ms, nfd;
	bool				 said, mapped, held;

	why = "the session ended";
	code = 0;
	pend = 0;
	said = t->jailed;
	/* login -f on the host: nothing typed reaches it until utmpx says
	 * the account logged in, and that soon. */
	mapped = t->account[0] != '\0' && !t->jailed;
	start = mono();
	utx_at = mono_ms();
	login[0] = '\0';
	if ((buf = malloc(TERM_CHUNK)) == NULL) {
		why = strerror(ENOMEM);
		code = ENOMEM;
		goto out;
	}
	/* A mapped login's jail proved, and its login started, here: never
	 * on the connection's thread.  A refusal closes the stream. */
	if (t->pid == 0) {
		if (((error = t->jailed ? jail_account(t->jid, t->jail,
		    t->account, t->root_ok, &t->uid0, bywhy, sizeof(bywhy)) :
		    host_account(t->account, t->root_ok, t->tty, t->from,
		    &t->uid0, bywhy, sizeof(bywhy)))) != 0) {
			authlog("terminal refused: console user %s as %s on %s, "
			    "from %s: %s", t->who, t->account, t->scope,
			    t->from, bywhy);
			why = bywhy;
			code = error;
			goto out;
		}
		if ((error = term_spawn(t, bywhy, sizeof(bywhy))) != 0) {
			why = bywhy;
			code = error;
			goto out;
		}
		authlog("terminal %s on %s: console user %s as %s, from %s: "
		    "login -f, pid %d", t->tty, t->scope, t->who, t->account,
		    t->from, (int)t->pid);
	}
	recheck_at = mono() + TERM_RECHECK_S;
	for (;;) {
		/* The host's file still allowing a mapped login: hung up as
		 * soon as it does not (looked at again when it changed). */
		if (t->account[0] != '\0' && mono() >= recheck_at) {
			recheck_at = mono() + TERM_RECHECK_S;
			if (!term_still(t, bywhy, sizeof(bywhy))) {
				why = bywhy;
				code = EACCES;
				break;
			}
		}
		pthread_mutex_lock(&t->lock);
		if (t->closed) {
			pthread_mutex_unlock(&t->lock);
			why = NULL;
			break;
		}
		if (t->flood) {
			pthread_mutex_unlock(&t->lock);
			why = "more was typed than the terminal takes";
			code = ENOBUFS;
			break;
		}
		/* This terminal alone hung up. */
		if (t->oom) {
			pthread_mutex_unlock(&t->lock);
			why = "out of memory: hung up";
			code = ENOMEM;
			break;
		}
		now = mono();
		idle_at = t->last_in + opts.terminal_idle_s;
		if (now >= idle_at) {
			pthread_mutex_unlock(&t->lock);
			why = "no typing for the idle time: hung up";
			code = ETIMEDOUT;
			break;
		}
		if (mapped && !t->confirmed && now - start >= TERM_CONFIRM_S) {
			pthread_mutex_unlock(&t->lock);
			(void)snprintf(bywhy, sizeof(bywhy), "login(1) did not "
			    "log %s in within %d s: hung up", t->account,
			    TERM_CONFIRM_S);
			why = bywhy;
			code = ETIMEDOUT;
			break;
		}
		/* The host's: until utmpx says the account.  A jail's: until
		 * login wrote anything at all. */
		held = (mapped && !t->confirmed) || (t->jailed &&
		    t->account[0] != '\0' && !t->output);
		/* What was typed, as much as the terminal takes now. */
		if (t->inlen > 0 && !held) {
			n = write(t->master, t->in, t->inlen);
			if (n > 0) {
				memmove(t->in, t->in + n, t->inlen - (size_t)n);
				t->inlen -= (size_t)n;
			}
		}
		nfd = 0;
		pfd[nfd].fd = t->wake[0];
		pfd[nfd++].events = POLLIN;
		pfd[nfd].fd = t->master;
		pfd[nfd++].events = (pend == 0 ? POLLIN : 0) | (t->inlen > 0 &&
		    !held ? POLLOUT : 0);
		pthread_mutex_unlock(&t->lock);

		/* A chunk that waited for room: sent when there is. */
		if (pend > 0) {
			if ((error = ys_send(t->s, buf, pend)) == 0) {
				pthread_mutex_lock(&t->lock);
				t->nout += pend;
				pthread_mutex_unlock(&t->lock);
				pend = 0;
				continue;
			}
			if (error != EAGAIN) {
				why = NULL;
				break;
			}
		}
		/* Who logged in, said once (the host's sessions); a mapped
		 * one is established by it, exactly its account or hung up. */
		now_ms = mono_ms();
		if (!said && now_ms >= utx_at) {
			utx_at = now_ms + (held ? TERM_CONFIRM_MS : TERM_UTX_S *
			    1000);
			if (now - start > TERM_UTX_FOR)
				said = true;
			else if (login[0] != '\0' || term_login(t, login,
			    sizeof(login))) {
				if (mapped && !t->confirmed &&
				    strcmp(login, t->account) != 0) {
					(void)snprintf(bywhy, sizeof(bywhy),
					    "login(1) logged in %s, not %s: hung "
					    "up", login, t->account);
					why = bywhy;
					code = EPERM;
					break;
				}
				if (mapped && !t->confirmed) {
					pthread_mutex_lock(&t->lock);
					t->confirmed = true;
					pthread_mutex_unlock(&t->lock);
					authlog("terminal %s on %s: console user %s "
					    "logged in as %s (confirmed by utmpx), "
					    "from %s", t->tty, t->scope, t->who,
					    t->account, t->from);
					/* What waited is written now. */
					term_wake(t);
				}
				memset(&lc, 0, sizeof(lc));
				lc.login = login;
				if ((error = ys_send_chunk(t->s, &lc)) == 0) {
					said = true;
					logmsg(LOG_NOTICE, "terminal %s on %s: %s "
					    "logged in", t->tty, t->where, login);
				} else if (error != EAGAIN) {
					why = NULL;
					break;
				}
			}
		}
		ms = (int)MIN(idle_at - now, said ? 3600 : TERM_UTX_S) * 1000;
		if (t->account[0] != '\0')
			ms = MIN(ms, TERM_RECHECK_S * 1000);
		if (held)
			ms = MIN(ms, TERM_CONFIRM_MS);
		if (ms < 0)
			ms = 0;
		if (poll(pfd, (nfds_t)nfd, ms) == -1) {
			if (errno == EINTR)
				continue;
			why = strerror(errno);
			code = errno;
			break;
		}
		if ((pfd[0].revents & POLLIN) != 0)
			while (read(t->wake[0], drain, sizeof(drain)) > 0)
				;
		if (pend == 0 && (pfd[1].revents & (POLLIN | POLLHUP |
		    POLLERR)) != 0) {
			n = read(t->master, buf, TERM_CHUNK);
			if (n == 0 || (n == -1 && errno != EAGAIN &&
			    errno != EINTR))
				break;		/* every slave closed: ended */
			if (n > 0) {
				pend = (size_t)n;
				if (!t->output) {
					t->output = true;
					term_wake(t);
				}
			}
		}
	}
out:
	term_hangup(t);
	if (why != NULL)
		(void)cbl_stream_close(t->s, code, why);
	logmsg(LOG_NOTICE, "terminal %s on %s for %s ended: %s; %ju bytes "
	    "typed, %ju written", t->tty, t->where, t->who, why != NULL ? why :
	    "the console ended it", (uintmax_t)t->nin, (uintmax_t)t->nout);
	if (t->account[0] != '\0')
		authlog("terminal %s on %s: console user %s as %s (%s), from "
		    "%s, ended: %s", t->tty, t->scope, t->who, t->account,
		    t->confirmed ? "confirmed" : "not confirmed", t->from,
		    why != NULL ? why : "the console ended it");
	free(buf);
	cbl_stream_rele(t->s);
	term_unref(t);
	return (NULL);
}

/* The value of key= among the names; NULL when it is not there. */
static const char *
word(const struct arcana_stream_open *rq, const char *key)
{
	size_t	i, k;

	k = strlen(key);
	for (i = 0; i < rq->name.n; i++)
		if (rq->name.v[i] != NULL && strncmp(rq->name.v[i], key, k) ==
		    0 && rq->name.v[i][k] == '=')
			return (rq->name.v[i] + k + 1);
	return (NULL);
}

/* Each name one of jail=, rows=, cols=, from= (and account=, for a
 * mapped login), once. */
static bool
words_ok(const struct arcana_stream_open *rq, bool mapped)
{
	static const char *const keys[] = { "jail=", "rows=", "cols=",
	    "from=", "account=" };
	unsigned int	seen;
	size_t		i, k, nk;

	nk = mapped ? nitems(keys) : nitems(keys) - 1;
	seen = 0;
	for (i = 0; i < rq->name.n; i++) {
		for (k = 0; k < nk; k++)
			if (rq->name.v[i] != NULL && strncmp(rq->name.v[i],
			    keys[k], strlen(keys[k])) == 0)
				break;
		if (k == nk || (seen & (1u << k)) != 0)
			return (false);
		seen |= 1u << k;
	}
	return (true);
}

/* login -h's host: an address, or a name, of what a host name has. */
static bool
from_ok(const char *s)
{
	size_t	n;

	return (s != NULL && (n = strlen(s)) > 0 && n <= TERM_FROM_MAX &&
	    s[0] != '-' && strspn(s, "abcdefghijklmnopqrstuvwxyz"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:-_") == n);
}

/* An account's name as a mapped login takes it: [a-z_][a-z0-9_-]{0,31},
 * so never an option of login's. */
static bool
account_ok(const char *s)
{
	size_t	n;

	return (s != NULL && (n = strlen(s)) > 0 && n <= TERM_ACCOUNT_MAX &&
	    ((s[0] >= 'a' && s[0] <= 'z') || s[0] == '_') &&
	    strspn(s, "abcdefghijklmnopqrstuvwxyz0123456789_-") == n);
}

/* A shell that does not log in: nologin(8), false(1). */
static bool
shell_refuses(const char *sh)
{
	const char	*b;

	if (sh == NULL || sh[0] == '\0')
		return (false);		/* login's /bin/sh */
	b = strrchr(sh, '/') != NULL ? strrchr(sh, '/') + 1 : sh;
	return (strcmp(b, "nologin") == 0 || strcmp(b, "false") == 0);
}

/*
 * A directory, or the file, of the host's file's path as StrictModes
 * would have it: root's or the agent's own user's, and no one else may
 * write it.  An agent that is not root (the tests') also takes a
 * sticky directory of root's (/tmp), in which no one may rename or
 * remove what is another's; one that is root, never.
 */
static bool
secure_node(const struct stat *sb, bool dir)
{

	if (sb->st_uid != 0 && sb->st_uid != geteuid())
		return (false);
	if ((sb->st_mode & 022) == 0)
		return (true);
	return (dir && geteuid() != 0 && (sb->st_mode & S_ISTXT) != 0 &&
	    sb->st_uid == 0);
}

/*
 * The host's file opened as sshd's secure_filename() would have it:
 * each directory from / down by the descriptor of the one above
 * (openat, O_NOFOLLOW: no symbolic link anywhere on the way) and each
 * judged by fstat (secure_node()); the file itself a regular file, no
 * link, root's, 0600 or stricter, at most TERM_USERS_MAX.  Its
 * descriptor, and *sb its stat, or -1 with an errno and why.
 */
static int
term_users_open(struct stat *sb, int *errp, char *why, size_t len)
{
	struct stat	 db;
	char		 path[PATH_MAX], *p, *next;
	int		 dfd, fd, error;

	*errp = 0;
	/* --terminal-users none: the feature off, said as such (EPERM, never
	 * EOPNOTSUPP: that is cblink's unknown command, an older agent's). */
	if (strcmp(opts.terminal_users, "none") == 0) {
		(void)snprintf(why, len, "mapped logins are off on this host "
		    "(--terminal-users none)");
		*errp = EPERM;
		return (-1);
	}
	if (strlcpy(path, opts.terminal_users, sizeof(path)) >= sizeof(path) ||
	    path[0] != '/') {
		(void)snprintf(why, len, "%s is no full path",
		    opts.terminal_users);
		*errp = EINVAL;
		return (-1);
	}
	if ((dfd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)) == -1) {
		*errp = errno;
		(void)snprintf(why, len, "/: %s", strerror(errno));
		return (-1);
	}
	error = 0;
	for (p = path + 1; (next = strchr(p, '/')) != NULL; p = next + 1) {
		*next = '\0';
		if (fstat(dfd, &db) != 0 || !secure_node(&db, true)) {
			error = EACCES;
			break;
		}
		if (*p == '\0')
			continue;
		if ((fd = openat(dfd, p, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
		    O_CLOEXEC)) == -1) {
			error = errno == ENOENT ? ENOENT : EACCES;
			break;
		}
		(void)close(dfd);
		dfd = fd;
	}
	if (error == 0 && (fstat(dfd, &db) != 0 || !secure_node(&db, true)))
		error = EACCES;
	if (error == 0 && (fd = openat(dfd, p, O_RDONLY | O_NOFOLLOW |
	    O_NONBLOCK | O_CLOEXEC)) == -1)
		error = errno == ENOENT ? ENOENT : errno == EMLINK ||
		    errno == ELOOP ? ELOOP : EACCES;
	(void)close(dfd);
	if (error == ENOENT) {
		(void)snprintf(why, len, "mapped logins are off on this host: "
		    "there is no %s", opts.terminal_users);
		/* Not EOPNOTSUPP: that is cblink's unknown command. */
		*errp = EPERM;
		return (-1);
	}
	if (error == ELOOP) {
		(void)snprintf(why, len, "%s is refused: it is a symbolic link",
		    opts.terminal_users);
		*errp = EACCES;
		return (-1);
	}
	if (error != 0) {
		(void)snprintf(why, len, "%s is refused: a directory on its "
		    "way is not root's alone (another may write it, or it is a "
		    "symbolic link)", opts.terminal_users);
		*errp = EACCES;
		return (-1);
	}
	if (fstat(fd, sb) != 0 || !S_ISREG(sb->st_mode) || !secure_node(sb,
	    false) || (sb->st_mode & 077) != 0) {
		(void)close(fd);
		(void)snprintf(why, len, "%s is refused: it must be root's, "
		    "mode 0600, in a directory only root writes",
		    opts.terminal_users);
		*errp = EACCES;
		return (-1);
	}
	if (sb->st_size > TERM_USERS_MAX) {
		(void)close(fd);
		(void)snprintf(why, len, "%s is refused: larger than %d bytes",
		    opts.terminal_users, TERM_USERS_MAX);
		*errp = EFBIG;
		return (-1);
	}
	return (fd);
}

/*
 * The host's file, --terminal-users: may console user user become
 * account in scope ("host" or "jail:<name>")?  Its lines,
 *
 *	scope account [+root] console-user ...
 *
 * a # to the line's end a comment, a CR before its LF dropped; a word
 * beginning with + is a flag, never a user, and +root the only one.
 * Opened by term_users_open(); a line that is not one, of more than 64
 * words, or with an unknown flag, refuses it whole.  0,
 * *root_ok whether a line that allows it says +root, *fst the file's
 * stat; else an errno and why.
 */
static int
term_allowed(const char *scope, const char *account, const char *user,
    bool *root_ok, struct stat *fst, char *why, size_t len)
{
	struct stat	 sb;
	char		*buf, *line, *next, *tok[64], *p;
	ssize_t		 n;
	size_t		 lineno, nt, k;
	int		 fd, error;
	bool		 root, found, many;

	*root_ok = false;
	if ((fd = term_users_open(&sb, &error, why, len)) == -1)
		return (error);
	if ((buf = malloc((size_t)sb.st_size + 1)) == NULL) {
		(void)close(fd);
		(void)snprintf(why, len, "out of memory");
		return (ENOMEM);
	}
	n = read(fd, buf, (size_t)sb.st_size);
	(void)close(fd);
	if (n != sb.st_size) {
		free(buf);
		(void)snprintf(why, len, "%s could not be read",
		    opts.terminal_users);
		return (EIO);
	}
	if (fst != NULL)
		*fst = sb;
	buf[n] = '\0';
	found = false;
	error = 0;
	lineno = 0;
	for (line = buf; line != NULL && error == 0; line = next) {
		lineno++;
		if ((next = strchr(line, '\n')) != NULL)
			*next++ = '\0';
		if (line[0] != '\0' && line[strlen(line) - 1] == '\r')
			line[strlen(line) - 1] = '\0';
		if ((p = strchr(line, '#')) != NULL)
			*p = '\0';
		nt = 0;
		many = false;
		while ((p = strsep(&line, " \t")) != NULL)
			if (*p != '\0') {
				if (nt == nitems(tok))
					many = true;
				else
					tok[nt++] = p;
			}
		if (nt == 0)
			continue;
		root = false;
		for (k = 2; k < nt; k++)
			if (tok[k][0] == '+') {
				if (strcmp(tok[k], "+root") != 0)
					break;
				root = true;
			}
		if (nt < 3 || k < nt || many || (strcmp(tok[0], "host") != 0 &&
		    (strncmp(tok[0], "jail:", 5) != 0 ||
		    !valid_jail(tok[0] + 5))) || !account_ok(tok[1])) {
			(void)snprintf(why, len, "%s, line %zu: not scope "
			    "(host or jail:<name>), an account, +root or not, "
			    "and the console users who may become it, 64 words "
			    "at most: the file is refused", opts.terminal_users,
			    lineno);
			error = EINVAL;
			break;
		}
		if (strcmp(tok[0], scope) != 0 || strcmp(tok[1], account) != 0)
			continue;
		for (k = 2; k < nt; k++)
			if (tok[k][0] != '+' && strcmp(tok[k], user) == 0) {
				found = true;
				*root_ok = *root_ok || root;
			}
	}
	free(buf);
	if (error != 0)
		return (error);
	if (!found) {
		(void)snprintf(why, len, "%s does not let console user %s "
		    "become %s on %s", opts.terminal_users, user, account,
		    scope);
		return (EACCES);
	}
	return (0);
}

/*
 * Does the host's file still let session t be?  Its whole way from /
 * walked again each time (term_users_open()), its words read again
 * only when its device, inode, size, times, mode or owner changed.
 * false and why: it is to be hung up.
 */
static bool
term_still(struct term *t, char *why, size_t len)
{
	struct stat	sb;
	char		w[400];
	bool		root_ok;
	int		fd, error;

	if ((fd = term_users_open(&sb, &error, w, sizeof(w))) == -1) {
		(void)snprintf(why, len, "the host's terminal-users no longer "
		    "allows it: %s", w);
		return (false);
	}
	(void)close(fd);
	if (sb.st_dev ==
	    t->fst.st_dev && sb.st_ino == t->fst.st_ino && sb.st_size ==
	    t->fst.st_size && sb.st_mtim.tv_sec == t->fst.st_mtim.tv_sec &&
	    sb.st_mtim.tv_nsec == t->fst.st_mtim.tv_nsec &&
	    sb.st_ctim.tv_sec == t->fst.st_ctim.tv_sec &&
	    sb.st_ctim.tv_nsec == t->fst.st_ctim.tv_nsec &&
	    sb.st_mode == t->fst.st_mode && sb.st_uid == t->fst.st_uid)
		return (true);
	if (term_allowed(t->scope, t->account, t->who, &root_ok, &t->fst, w,
	    sizeof(w)) != 0) {
		(void)snprintf(why, len, "the host's terminal-users no longer "
		    "allows it: %s", w);
		return (false);
	}
	if (t->uid0 && !root_ok) {
		(void)snprintf(why, len, "the host's terminal-users no longer "
		    "says +root for %s, which is uid 0", t->account);
		return (false);
	}
	return (true);
}

/*
 * What login -f does not ask of a host's account (pam_acct_mgmt(3) is
 * never called), in the session's own thread before login starts:
 * there, of uid 0 only by +root, not locked, not expired, its password
 * not past its change time, a shell that logs in, nologin(5) (the
 * class's nologin, /var/run/nologin being --terminal-nologin's) unless
 * the class ignores it or the account is uid 0 (as pam_nologin(8)), the
 * class's times, hosts and ttys.  0 and *uid0, or an errno and why.
 */
static int
host_account(const char *account, bool root_ok, const char *tty,
    const char *from, bool *uid0, char *why, size_t len)
{
	struct passwd	 pw, *res;
	login_cap_t	*lc;
	const char	*nl;
	char		 buf[4096];
	time_t		 now;
	int		 error;

	if (getpwnam_r(account, &pw, buf, sizeof(buf), &res) != 0 ||
	    res == NULL) {
		(void)snprintf(why, len, "the host has no account %s", account);
		return (ENOENT);
	}
	*uid0 = pw.pw_uid == 0;
	if (pw.pw_uid == 0 && !root_ok) {
		(void)snprintf(why, len, "%s is uid 0, root by a name: only a "
		    "line of %s that says +root allows it", account,
		    opts.terminal_users);
		return (EPERM);
	}
	if (strncmp(pw.pw_passwd, LOCKED, strlen(LOCKED)) == 0) {
		(void)snprintf(why, len, "%s is locked", account);
		return (EPERM);
	}
	now = time(NULL);
	if (pw.pw_expire != 0 && now >= pw.pw_expire) {
		(void)snprintf(why, len, "%s has expired", account);
		return (EPERM);
	}
	if (pw.pw_change != 0 && now >= pw.pw_change) {
		(void)snprintf(why, len, "%s's password expired: it is to be "
		    "changed first", account);
		return (EPERM);
	}
	if (shell_refuses(pw.pw_shell)) {
		(void)snprintf(why, len, "%s's shell, %s, does not log in",
		    account, pw.pw_shell);
		return (EPERM);
	}
	if ((lc = login_getpwclass(&pw)) == NULL) {
		(void)snprintf(why, len, "%s's login class cannot be read",
		    account);
		return (EPERM);
	}
	error = 0;
	nl = login_getcapstr(lc, "nologin", _PATH_NOLOGIN, _PATH_NOLOGIN);
	/* /var/run/nologin, however named: --terminal-nologin's. */
	if (nl != NULL && strcmp(nl, _PATH_NOLOGIN) == 0)
		nl = opts.terminal_nologin;
	/* uid 0 past it, as pam_nologin(8) lets root (+root still asked). */
	if (pw.pw_uid != 0 && !login_getcapbool(lc, "ignorenologin", 0) &&
	    nl != NULL && access(nl, F_OK) == 0) {
		(void)snprintf(why, len, "logins are off: %s is there", nl);
		error = EPERM;
	} else if (!auth_timeok(lc, now)) {
		(void)snprintf(why, len, "%s's login class does not let it in "
		    "at this time", account);
		error = EPERM;
	} else if (!auth_hostok(lc, from, from)) {
		(void)snprintf(why, len, "%s's login class does not let it in "
		    "from %s", account, from);
		error = EPERM;
	} else if (!auth_ttyok(lc, tty)) {
		(void)snprintf(why, len, "%s's login class does not let it in "
		    "on %s", account, tty);
		error = EPERM;
	}
	login_close(lc);
	return (error);
}

/* The child's signals as a new program has them, its umask the
 * system's: between fork(2) and execve(2), safe calls alone. */
static void
child_reset(void)
{
	struct sigaction	sa;
	sigset_t		none;
	int			sig;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	for (sig = 1; sig < NSIG; sig++)
		(void)sigaction(sig, &sa, NULL);
	sigemptyset(&none);
	(void)sigprocmask(SIG_SETMASK, &none, NULL);
	(void)umask(022);
}

/*
 * A jail's account proved there before login -f runs in it (which would
 * prompt for an account it does not have): the jail's getent(1), by
 * jexec, its passwd line for the name: of uid 0 only by +root, not
 * locked, a shell that logs in.  The jail's own program, so the jail's
 * word; TERM_PREFLIGHT_S at most, in the session's own thread.  0 and
 * *uid0, or an errno and why.
 */
static int
jail_account(int jid, const char *jail, const char *account, bool root_ok,
    bool *uid0, char *why, size_t len)
{
	struct pollfd	 pfd;
	char		 out[1024], jidtxt[16], *f[7], *p, *line;
	char		*argv[6], *envp[2];
	size_t		 got;
	ssize_t		 n;
	int64_t		 until, rem;
	pid_t		 pid;
	int		 fds[2], null, status, i;

	(void)snprintf(jidtxt, sizeof(jidtxt), "%d", jid);
	argv[0] = (char *)(uintptr_t)opts.jexec_bin;
	argv[1] = jidtxt;
	argv[2] = (char *)(uintptr_t)opts.terminal_getent;
	argv[3] = (char *)(uintptr_t)"passwd";
	argv[4] = (char *)(uintptr_t)account;
	argv[5] = NULL;
	envp[0] = (char *)(uintptr_t)"PATH=/sbin:/bin:/usr/sbin:/usr/bin";
	envp[1] = NULL;
	if (pipe2(fds, O_CLOEXEC) == -1)
		goto sys;
	if ((null = open(_PATH_DEVNULL, O_RDWR | O_CLOEXEC)) == -1) {
		(void)close(fds[0]);
		(void)close(fds[1]);
		goto sys;
	}
	if ((pid = fork()) == -1) {
		(void)close(fds[0]);
		(void)close(fds[1]);
		(void)close(null);
		goto sys;
	}
	if (pid == 0) {
		if (dup2(null, 0) == -1 || dup2(fds[1], 1) == -1 ||
		    dup2(null, 2) == -1)
			_exit(126);
		closefrom(3);
		child_reset();
		execve(argv[0], argv, envp);
		_exit(127);
	}
	(void)close(fds[1]);
	(void)close(null);
	got = 0;
	until = mono_ms() + TERM_PREFLIGHT_S * 1000;
	pfd.fd = fds[0];
	pfd.events = POLLIN;
	while (got < sizeof(out) - 1) {
		/* What is left of the time, once, never below 0. */
		if ((rem = until - mono_ms()) <= 0)
			break;
		if (poll(&pfd, 1, (int)rem) <= 0)
			break;
		if ((n = read(fds[0], out + got, sizeof(out) - 1 - got)) <= 0)
			break;
		got += (size_t)n;
	}
	(void)close(fds[0]);
	out[got] = '\0';
	for (i = 0; i < TERM_PREFLIGHT_S * 10; i++) {
		if (waitpid(pid, &status, WNOHANG) == pid)
			break;
		(void)usleep(100000);
	}
	if (i == TERM_PREFLIGHT_S * 10) {
		(void)kill(pid, SIGKILL);
		while (waitpid(pid, &status, 0) == -1 && errno == EINTR)
			;
		(void)snprintf(why, len, "jail %s's getent did not answer",
		    jail);
		return (ETIMEDOUT);
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		(void)snprintf(why, len, "jail %s has no account %s", jail,
		    account);
		return (ENOENT);
	}
	/* name:password:uid:gid:gecos:home:shell */
	line = out;
	line[strcspn(line, "\n")] = '\0';
	for (i = 0; i < 7 && (p = strsep(&line, ":")) != NULL; i++)
		f[i] = p;
	if (i != 7 || line != NULL || strcmp(f[0], account) != 0) {
		(void)snprintf(why, len, "jail %s has no account %s", jail,
		    account);
		return (ENOENT);
	}
	*uid0 = strcmp(f[2], "0") == 0;
	if (*uid0 && !root_ok) {
		(void)snprintf(why, len, "%s is uid 0 in jail %s, root by a "
		    "name: only a line of %s that says +root allows it",
		    account, jail, opts.terminal_users);
		return (EPERM);
	}
	if (strncmp(f[1], LOCKED, strlen(LOCKED)) == 0) {
		(void)snprintf(why, len, "%s is locked in jail %s", account,
		    jail);
		return (EPERM);
	}
	if (shell_refuses(f[6])) {
		(void)snprintf(why, len, "%s's shell in jail %s, %s, does not "
		    "log in", account, jail, f[6]);
		return (EPERM);
	}
	return (0);
sys:
	(void)snprintf(why, len, "%s", strerror(errno));
	return (EIO);
}

/*
 * The accounts whose password is empty, which login(1) lets anyone in
 * as on any terminal: one fault, empty-password on "accounts", Major,
 * that says how many and no names (alarms are read, mailed and sent to
 * Telegram); the names go to the authentication log (LOG_AUTH) alone,
 * when they change.  Cleared once there are none.  The agent's own
 * reading of the passwords (as root, master.passwd's).
 */
void
terminal_findings(void)
{
	static pthread_mutex_t	 pw_lock = PTHREAD_MUTEX_INITIALIZER;
	static char		*said;	/* the names last logged */
	struct fault_live	 v = { .object = "accounts" };
	struct passwd		*pw;
	char			*names, *nn;
	size_t			 len;
	int			 n;

	names = NULL;
	len = 0;
	n = 0;
	pthread_mutex_lock(&pw_lock);
	setpwent();
	while ((pw = getpwent()) != NULL) {
		if (pw->pw_passwd == NULL || pw->pw_passwd[0] != '\0')
			continue;
		if ((nn = realloc(names, len + strlen(pw->pw_name) + 2)) ==
		    NULL)
			break;
		names = nn;
		len += (size_t)snprintf(names + len, strlen(pw->pw_name) + 2,
		    "%s%s", len > 0 ? " " : "", pw->pw_name);
		n++;
	}
	endpwent();
	if (n > 0 && (said == NULL || strcmp(said, names) != 0))
		authlog("accounts with an empty password, which login(1) lets "
		    "anyone in as: %s", names);
	free(said);
	said = names;
	pthread_mutex_unlock(&pw_lock);
	v.well = n == 0;
	(void)fault_reconcile("arcana-agent", TERM_EMPTY_PW_FAULT, NULL, &v, 1,
	    "no account has an empty password now");
	if (n == 0)
		return;
	if (!v.open)
		fault_set(TERM_EMPTY_PW_FAULT, "Major", "accounts",
		    "arcana-agent", "%d account%s log%s in with no password; "
		    "see the host's auth log", n, n == 1 ? "" : "s", n == 1 ?
		    "s" : "");
	else
		(void)fault_update(TERM_EMPTY_PW_FAULT, "accounts", "%d "
		    "account%s log%s in with no password; see the host's auth "
		    "log", n, n == 1 ? "" : "s", n == 1 ? "s" : "");
}

/* terminal_findings() now and every TERM_FINDINGS_S, in a thread of its
 * own: never on a connection's. */
static void *
findings_run(void *arg __unused)
{

	for (;;) {
		terminal_findings();
		(void)sleep(TERM_FINDINGS_S);
	}
	return (NULL);
}

void
terminal_findings_start(void)
{
	pthread_t	tid;

	if (pthread_create(&tid, NULL, findings_run, NULL) == 0)
		(void)pthread_detach(tid);
	else
		terminal_findings();
}

/*
 * The child, between fork(2) and execve(2): only what is safe in a
 * child of a process with threads.  A session of its own whose
 * controlling terminal is slave, the signals as a new program has them
 * (the agent ignores some, and an ignored signal stays so across
 * execve), the system's umask.
 */
static void __dead2
term_child(int slave, char *const argv[], char *const envp[])
{

	if (setsid() == -1 || ioctl(slave, TIOCSCTTY, 0) == -1 ||
	    dup2(slave, 0) == -1 || dup2(slave, 1) == -1 ||
	    dup2(slave, 2) == -1)
		_exit(126);
	closefrom(3);
	child_reset();
	execve(argv[0], argv, envp);
	(void)write(2, "login could not be started\r\n", 28);
	_exit(127);
}

/*
 * Session t's login(1) started on its terminal (t->slave, closed then):
 * with -h where the person comes from; in a jail the jail's own, by
 * jexec; a mapped login -f, its account after --.  0, or an errno and
 * why.
 */
static int
term_spawn(struct term *t, char *why, size_t len)
{
	char	*argv[12], *envp[3], jid[16];
	pid_t	 pid;
	int	 n;

	n = 0;
	if (t->jailed) {
		(void)snprintf(jid, sizeof(jid), "%d", t->jid);
		argv[n++] = (char *)(uintptr_t)opts.jexec_bin;
		argv[n++] = jid;
	}
	argv[n++] = (char *)(uintptr_t)opts.terminal_login;
	if (t->account[0] != '\0')
		argv[n++] = (char *)(uintptr_t)"-f";
	if (t->from[0] != '\0') {
		argv[n++] = (char *)(uintptr_t)"-h";
		argv[n++] = t->from;
	}
	if (t->account[0] != '\0') {
		argv[n++] = (char *)(uintptr_t)"--";
		argv[n++] = t->account;
	}
	argv[n] = NULL;
	envp[0] = (char *)(uintptr_t)"TERM=xterm-256color";
	envp[1] = (char *)(uintptr_t)"PATH=/sbin:/bin:/usr/sbin:/usr/bin";
	envp[2] = NULL;
	if ((pid = fork()) == -1) {
		(void)snprintf(why, len, "%s", strerror(errno));
		return (errno);
	}
	if (pid == 0)
		term_child(t->slave, argv, envp);
	close(t->slave);
	t->slave = -1;
	t->pid = pid;
	return (0);
}

/*
 * A session's login gone at once, on the connection's thread (its
 * stream not accepted, no thread for it): SIGKILL to its group, which
 * is reaped as soon as it dies, never TERM_HUP_S of waiting.
 */
static void
term_kill(struct term *t)
{
	int	status;

	if (t->master != -1)
		close(t->master);
	t->master = -1;
	if (t->slave != -1)
		close(t->slave);
	t->slave = -1;
	if (t->pid <= 0)
		return;
	(void)kill(-t->pid, SIGKILL);
	(void)kill(t->pid, SIGKILL);
	while (waitpid(t->pid, &status, 0) == -1 && errno == EINTR)
		;
}

/* A refusal: said to the console, and for a mapped login, logged to
 * LOG_AUTH with who, as whom, where and from where (each NULL where it
 * was not one to log: what the request said is never logged unchecked). */
static int
term_refuse(cbl_req *req, bool mapped, int error, const char *account,
    const char *scope, const char *from, const char *why)
{
	const char	*user;

	(void)cbl_req_set_err(req, why, NULL, 0, -1);
	if (mapped) {
		user = cbl_req_user(req);
		authlog("terminal refused: console user %s as %s on %s, from "
		    "%s: %s", user != NULL ? user : "(none)", account != NULL ?
		    account : "(not given or not a name)", scope != NULL ?
		    scope : "(not given or not a jail's name)", from != NULL ?
		    from : "(not given or not an address)", why);
	}
	return (error);
}

/*
 * arcana-stream's terminal (mapped false): jail=, rows=, cols= and
 * from=, login(1) on a terminal of the host's or of a jail's, as it
 * comes and goes.  terminal-as (mapped): account= besides, from=
 * required, login -f of that account for the request's user, as the
 * host's file allows it and its checks pass.  The host's file is
 * judged here; a mapped login's account checks (host_account(),
 * jail_account()) and its login(1) are its session's thread's
 * (term_run()), whose refusal closes the stream.
 */
static int
term_open(cbl_req *req, const struct arcana_stream_open *rq, cbl_stream *s,
    bool mapped)
{
	struct arcana_stream_opened	 rsp;
	struct winsize			 ws;
	struct work			 w;
	struct stat			 fst;
	struct term			*t;
	pthread_t			 tid;
	const char			*jail, *rows, *cols, *from, *errstr;
	const char			*user, *account;
	char				 json[512], pts[64];
	char				 scope[MAXHOSTNAMELEN + 8], why[512];
	enum peer_kind			 kind;
	int				 master, j, error;
	bool				 root_ok;

	jail = word(rq, "jail");
	rows = word(rq, "rows");
	cols = word(rq, "cols");
	from = word(rq, "from");
	account = mapped ? word(rq, "account") : NULL;
	memset(&ws, 0, sizeof(ws));
	ws.ws_row = 24;
	ws.ws_col = 80;
	errstr = NULL;
	if (rows != NULL)
		ws.ws_row = (unsigned short)strtonum(rows, 1, 1000, &errstr);
	if (errstr == NULL && cols != NULL)
		ws.ws_col = (unsigned short)strtonum(cols, 1, 1000, &errstr);
	if (jail != NULL && valid_jail(jail))
		(void)snprintf(scope, sizeof(scope), "jail:%s", jail);
	else
		(void)snprintf(scope, sizeof(scope), "host");
	if (!words_ok(rq, mapped) || errstr != NULL || (jail != NULL &&
	    !valid_jail(jail)) || (from != NULL && !from_ok(from)) || (mapped &&
	    (from == NULL || !account_ok(account)))) {
		(void)snprintf(why, sizeof(why), mapped ? "a mapped login is "
		    "opened by jail= (a running jail's name, or none for the "
		    "host), rows= and cols= (1 to 1000), from= (an address) and "
		    "account= (an account's name: a lowercase letter or _, "
		    "then lowercase letters, digits, _ and -, 32 at most), "
		    "each once" : "a terminal is opened by jail= (a running "
		    "jail's name, or none for the host), rows= and cols= (1 to "
		    "1000) and from= (an address), each once");
		return (term_refuse(req, mapped, EINVAL, account_ok(account) ?
		    account : NULL, jail == NULL || valid_jail(jail) ? scope :
		    NULL, from_ok(from) ? from : NULL, why));
	}
	user = cbl_req_user(req);
	if (mapped) {
		/* Whom for: the name NACM judged, said by the console, its
		 * socket's group or root on the unix socket alone. */
		kind = peer_kind(cbl_req_peer(req), NULL);
		if (kind != PEER_CONSOLE && kind != PEER_GROUP && kind !=
		    PEER_ROOT)
			return (term_refuse(req, true, EPERM, account, scope,
			    from, "a mapped login is the console's to ask (or "
			    "root's on the unix socket)"));
		if (user == NULL)
			return (term_refuse(req, true, EPERM, account, scope,
			    from, "a mapped login is for a console user: the "
			    "recovery session names one"));
		if (strcmp(user, NACM_CONSOLE) == 0 && kind != PEER_ROOT)
			return (term_refuse(req, true, EPERM, account, scope,
			    from, "the console's own user has no mapped "
			    "login"));
	}
	j = 0;
	if (jail != NULL) {
		work_init(&w);
		j = jail_lookup(&w, jail);
		work_free(&w);
		if (j <= 0)
			return (term_refuse(req, mapped, ENOENT, account, scope,
			    from, "no jail of that name is running"));
	}
	root_ok = false;
	memset(&fst, 0, sizeof(fst));
	/* The host's say: its own file, read here. */
	if (mapped && (error = term_allowed(scope, account, user, &root_ok,
	    &fst, why, sizeof(why))) != 0)
		return (term_refuse(req, true, error, account, scope, from,
		    why));
	pthread_mutex_lock(&term_lock);
	if (nterms >= TERM_MAX) {
		pthread_mutex_unlock(&term_lock);
		return (term_refuse(req, mapped, EBUSY, account, scope, from,
		    "eight terminals at most are open at once"));
	}
	nterms++;
	pthread_mutex_unlock(&term_lock);

	if ((t = calloc(1, sizeof(*t))) == NULL) {
		pthread_mutex_lock(&term_lock);
		nterms--;
		pthread_mutex_unlock(&term_lock);
		(void)cbl_req_set_err(req, "out of memory", NULL, 0, -1);
		return (ENOMEM);
	}
	pthread_mutex_init(&t->lock, NULL);
	t->master = t->slave = t->wake[0] = t->wake[1] = -1;
	t->refs = 1;
	t->jailed = jail != NULL;
	t->jid = j;
	t->root_ok = root_ok;
	t->fst = fst;
	t->last_in = mono();
	(void)snprintf(t->where, sizeof(t->where), jail != NULL ? "jail %s" :
	    "the host", jail);
	(void)snprintf(t->jail, sizeof(t->jail), "%s", jail != NULL ? jail :
	    "");
	(void)snprintf(t->scope, sizeof(t->scope), "%s", scope);
	(void)snprintf(t->who, sizeof(t->who), "%s", user != NULL ? user :
	    "the recovery session");
	(void)snprintf(t->from, sizeof(t->from), "%s", from != NULL ? from :
	    "");
	(void)snprintf(t->account, sizeof(t->account), "%s", account != NULL ?
	    account : "");
	error = EIO;
	if (pipe2(t->wake, O_CLOEXEC | O_NONBLOCK) == -1 ||
	    (master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC)) == -1) {
		(void)cbl_req_set_err(req, strerror(errno), NULL, 0, -1);
		goto fail;
	}
	t->master = master;
	if (grantpt(master) == -1 || unlockpt(master) == -1 ||
	    ptsname_r(master, pts, sizeof(pts)) != 0 ||
	    (t->slave = open(pts, O_RDWR | O_NOCTTY | O_CLOEXEC)) == -1 ||
	    ioctl(master, TIOCSWINSZ, &ws) == -1) {
		(void)cbl_req_set_err(req, strerror(errno), NULL, 0, -1);
		goto fail;
	}
	(void)snprintf(t->tty, sizeof(t->tty), "%s", strncmp(pts, "/dev/", 5)
	    == 0 ? pts + 5 : pts);
	/* A plain login starts now; a mapped one in its thread. */
	error = EIO;
	if (!mapped && term_spawn(t, why, sizeof(why)) != 0) {
		(void)cbl_req_set_err(req, why, NULL, 0, -1);
		goto fail;
	}
	(void)fcntl(master, F_SETFL, fcntl(master, F_GETFL) | O_NONBLOCK);
	t->s = s;
	t->refs = 2;
	if (mapped)
		(void)snprintf(json, sizeof(json), "{\"tty\":\"%s\",\"rows\":%u,"
		    "\"cols\":%u,\"account\":\"%s\",\"scope\":\"%s\"}", t->tty,
		    ws.ws_row, ws.ws_col, t->account, t->scope);
	else
		(void)snprintf(json, sizeof(json), "{\"tty\":\"%s\",\"pid\":%d,"
		    "\"rows\":%u,\"cols\":%u}", t->tty, (int)t->pid, ws.ws_row,
		    ws.ws_col);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = true;
	rsp.json = json;
	if (ys_accept(s, &rsp, &term_cbs, t) != 0) {
		t->refs = 1;
		term_kill(t);
		term_unref(t);
		return (ECONNREFUSED);
	}
	if (!mapped)
		logmsg(LOG_NOTICE, "terminal %s on %s for %s%s%s: login(1), "
		    "pid %d", t->tty, t->where, t->who, t->from[0] != '\0' ?
		    ", from " : "", t->from, (int)t->pid);
	cbl_stream_ref(s);
	if (pthread_create(&tid, NULL, term_run, t) != 0) {
		/* The stream's reference is given back by its close. */
		(void)cbl_stream_close(s, EAGAIN, "no thread for it");
		term_kill(t);
		cbl_stream_rele(s);
		term_unref(t);
		return (0);
	}
	(void)pthread_detach(tid);
	return (0);
fail:
	if (t->slave != -1)
		close(t->slave);
	t->slave = -1;
	if (t->master != -1)
		close(t->master);
	t->master = -1;
	term_unref(t);
	return (error);
}

int
terminal_open(cbl_req *req, const struct arcana_stream_open *rq,
    cbl_stream *s)
{

	return (term_open(req, rq, s, false));
}

int
terminal_as_open(cbl_req *req, const struct arcana_stream_open *rq,
    cbl_stream *s)
{

	return (term_open(req, rq, s, true));
}
