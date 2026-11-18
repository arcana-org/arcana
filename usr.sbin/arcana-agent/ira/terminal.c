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
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
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
	bool		 jailed;
	/* The lock's: */
	char		*in;		/* typed, not yet written */
	size_t		 inlen, incap;
	bool		 closed;	/* the stream ended */
	bool		 flood;		/* more typed than TERM_IN_MAX */
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
				if ((t->in = realloc(t->in, cap)) == NULL)
					err(1, "realloc");
				t->incap = cap;
			}
			memcpy(t->in + t->inlen, c->data.p, c->data.len);
			t->inlen += c->data.len;
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

/* The session hung up and login reaped, its group killed when it does
 * not go. */
static void
term_hangup(struct term *t)
{
	pid_t	fg;
	int	i, status;

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
	const char			*why;
	size_t				 pend;
	ssize_t				 n;
	time_t				 now, start, utx_at, idle_at;
	int				 code, error, ms, nfd;
	bool				 said;

	why = "the session ended";
	code = 0;
	pend = 0;
	said = t->jailed;
	start = utx_at = mono();
	login[0] = '\0';
	if ((buf = malloc(TERM_CHUNK)) == NULL) {
		why = strerror(ENOMEM);
		code = ENOMEM;
		goto out;
	}
	for (;;) {
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
		now = mono();
		idle_at = t->last_in + opts.terminal_idle_s;
		if (now >= idle_at) {
			pthread_mutex_unlock(&t->lock);
			why = "no typing for the idle time: hung up";
			code = ETIMEDOUT;
			break;
		}
		/* What was typed, as much as the terminal takes now. */
		if (t->inlen > 0) {
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
		pfd[nfd++].events = (pend == 0 ? POLLIN : 0) | (t->inlen > 0 ?
		    POLLOUT : 0);
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
		/* Who logged in, said once (the host's sessions). */
		if (!said && now >= utx_at) {
			utx_at = now + TERM_UTX_S;
			if (now - start > TERM_UTX_FOR)
				said = true;
			else if (login[0] != '\0' || term_login(t, login,
			    sizeof(login))) {
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
			if (n > 0)
				pend = (size_t)n;
		}
	}
out:
	term_hangup(t);
	if (why != NULL)
		(void)cbl_stream_close(t->s, code, why);
	logmsg(LOG_NOTICE, "terminal %s on %s for %s ended: %s; %ju bytes "
	    "typed, %ju written", t->tty, t->where, t->who, why != NULL ? why :
	    "the console ended it", (uintmax_t)t->nin, (uintmax_t)t->nout);
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

/* Each name one of jail=, rows=, cols=, from=, once. */
static bool
words_ok(const struct arcana_stream_open *rq)
{
	static const char *const keys[] = { "jail=", "rows=", "cols=",
	    "from=" };
	unsigned int	seen;
	size_t		i, k;

	seen = 0;
	for (i = 0; i < rq->name.n; i++) {
		for (k = 0; k < nitems(keys); k++)
			if (rq->name.v[i] != NULL && strncmp(rq->name.v[i],
			    keys[k], strlen(keys[k])) == 0)
				break;
		if (k == nitems(keys) || (seen & (1u << k)) != 0)
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
	struct sigaction	sa;
	sigset_t		none;
	int			sig;

	if (setsid() == -1 || ioctl(slave, TIOCSCTTY, 0) == -1 ||
	    dup2(slave, 0) == -1 || dup2(slave, 1) == -1 ||
	    dup2(slave, 2) == -1)
		_exit(126);
	closefrom(3);
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	for (sig = 1; sig < NSIG; sig++)
		(void)sigaction(sig, &sa, NULL);
	sigemptyset(&none);
	(void)sigprocmask(SIG_SETMASK, &none, NULL);
	(void)umask(022);
	execve(argv[0], argv, envp);
	(void)write(2, "login could not be started\r\n", 28);
	_exit(127);
}

/*
 * arcana-stream's terminal: jail=, rows=, cols= and from=, login(1) on
 * a terminal of the host's or of a jail's, as it comes and goes.
 */
int
terminal_open(cbl_req *req, const struct arcana_stream_open *rq,
    cbl_stream *s)
{
	struct arcana_stream_opened	 rsp;
	struct winsize			 ws;
	struct work			 w;
	struct term			*t;
	pthread_t			 tid;
	const char			*jail, *rows, *cols, *from, *errstr;
	const char			*user;
	char				 json[256], pts[64], jid[16];
	char				*argv[8], *envp[3];
	int				 master, slave, n, j;
	pid_t				 pid;

	jail = word(rq, "jail");
	rows = word(rq, "rows");
	cols = word(rq, "cols");
	from = word(rq, "from");
	memset(&ws, 0, sizeof(ws));
	ws.ws_row = 24;
	ws.ws_col = 80;
	errstr = NULL;
	if (rows != NULL)
		ws.ws_row = (unsigned short)strtonum(rows, 1, 1000, &errstr);
	if (errstr == NULL && cols != NULL)
		ws.ws_col = (unsigned short)strtonum(cols, 1, 1000, &errstr);
	if (!words_ok(rq) || errstr != NULL || (jail != NULL &&
	    !valid_jail(jail)) || (from != NULL && !from_ok(from))) {
		(void)cbl_req_set_err(req, "a terminal is opened by jail= (a "
		    "running jail's name, or none for the host), rows= and "
		    "cols= (1 to 1000) and from= (an address)", NULL, 0, -1);
		return (EINVAL);
	}
	j = 0;
	if (jail != NULL) {
		work_init(&w);
		j = jail_lookup(&w, jail);
		work_free(&w);
		if (j <= 0) {
			(void)cbl_req_set_err(req, "no jail of that name is "
			    "running", NULL, 0, -1);
			return (ENOENT);
		}
	}
	pthread_mutex_lock(&term_lock);
	if (nterms >= TERM_MAX) {
		pthread_mutex_unlock(&term_lock);
		(void)cbl_req_set_err(req, "eight terminals at most are open "
		    "at once", NULL, 0, -1);
		return (EBUSY);
	}
	nterms++;
	pthread_mutex_unlock(&term_lock);

	if ((t = calloc(1, sizeof(*t))) == NULL)
		err(1, "calloc");
	pthread_mutex_init(&t->lock, NULL);
	t->master = t->wake[0] = t->wake[1] = -1;
	t->refs = 1;
	t->jailed = jail != NULL;
	t->last_in = mono();
	(void)snprintf(t->where, sizeof(t->where), jail != NULL ? "jail %s" :
	    "the host", jail);
	user = cbl_req_user(req);
	(void)snprintf(t->who, sizeof(t->who), "%s", user != NULL ? user :
	    "the recovery session");
	(void)snprintf(t->from, sizeof(t->from), "%s", from != NULL ? from :
	    "");
	slave = -1;
	if (pipe2(t->wake, O_CLOEXEC | O_NONBLOCK) == -1 ||
	    (master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC)) == -1) {
		(void)cbl_req_set_err(req, strerror(errno), NULL, 0, -1);
		goto fail;
	}
	t->master = master;
	if (grantpt(master) == -1 || unlockpt(master) == -1 ||
	    ptsname_r(master, pts, sizeof(pts)) != 0 ||
	    (slave = open(pts, O_RDWR | O_NOCTTY | O_CLOEXEC)) == -1 ||
	    ioctl(master, TIOCSWINSZ, &ws) == -1) {
		(void)cbl_req_set_err(req, strerror(errno), NULL, 0, -1);
		goto fail;
	}
	(void)snprintf(t->tty, sizeof(t->tty), "%s", strncmp(pts, "/dev/", 5)
	    == 0 ? pts + 5 : pts);
	/* login(1), with -h where the person comes from; in a jail the
	 * jail's own, by jexec. */
	n = 0;
	if (jail != NULL) {
		(void)snprintf(jid, sizeof(jid), "%d", j);
		argv[n++] = (char *)(uintptr_t)opts.jexec_bin;
		argv[n++] = jid;
	}
	argv[n++] = (char *)(uintptr_t)opts.terminal_login;
	if (from != NULL) {
		argv[n++] = (char *)(uintptr_t)"-h";
		argv[n++] = t->from;
	}
	argv[n] = NULL;
	envp[0] = (char *)(uintptr_t)"TERM=xterm-256color";
	envp[1] = (char *)(uintptr_t)"PATH=/sbin:/bin:/usr/sbin:/usr/bin";
	envp[2] = NULL;
	if ((pid = fork()) == -1) {
		(void)cbl_req_set_err(req, strerror(errno), NULL, 0, -1);
		goto fail;
	}
	if (pid == 0)
		term_child(slave, argv, envp);
	close(slave);
	slave = -1;
	t->pid = pid;
	(void)fcntl(master, F_SETFL, fcntl(master, F_GETFL) | O_NONBLOCK);
	t->s = s;
	t->refs = 2;
	(void)snprintf(json, sizeof(json), "{\"tty\":\"%s\",\"pid\":%d,"
	    "\"rows\":%u,\"cols\":%u}", t->tty, (int)pid, ws.ws_row,
	    ws.ws_col);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = true;
	rsp.json = json;
	if (ys_accept(s, &rsp, &term_cbs, t) != 0) {
		t->refs = 1;
		term_hangup(t);
		term_unref(t);
		return (ECONNREFUSED);
	}
	logmsg(LOG_NOTICE, "terminal %s on %s for %s%s%s: login(1), pid %d",
	    t->tty, t->where, t->who, t->from[0] != '\0' ? ", from " : "",
	    t->from, (int)pid);
	cbl_stream_ref(s);
	if (pthread_create(&tid, NULL, term_run, t) != 0) {
		/* The stream's reference is given back by its close. */
		(void)cbl_stream_close(s, EAGAIN, "no thread for it");
		term_hangup(t);
		cbl_stream_rele(s);
		term_unref(t);
		return (0);
	}
	(void)pthread_detach(tid);
	return (0);
fail:
	if (slave != -1)
		close(slave);
	if (t->master != -1)
		close(t->master);
	t->master = -1;
	term_unref(t);
	return (EIO);
}
