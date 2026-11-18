/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Run a program with posix_spawn(3), never through a shell, capturing
 * stdout and stderr and recording it as an exec step.
 */

#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <libutil.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"

/*
 * What is left in the pipes once the program exited is read for this
 * long at most: what it started (a jail's exec.start, a daemon) may hold
 * them open and write on for as long as it lives.
 */
#define	EXEC_DRAIN_SEC	2
#define	LINES_MAX	(1024 * 1024)	/* a line run_exec_lines() gives */

#define	WINDOW_MAX	512		/* the last of a watched program's */

struct capture {
	char	*buf;
	size_t	 len;
	size_t	 max;
	bool	 truncated;
};

/*
 * The last WINDOW_MAX bytes a watched program wrote, both outputs as
 * they came, kept whatever the capture keeps: where its marks are
 * looked for (exec_set_busy()), a mark split between two reads too,
 * and the line it printed last.
 */
struct window {
	char	 buf[WINDOW_MAX + 1];
	size_t	 len;
};

static void	capture_read(int *, struct capture *, struct window *);

static void
window_put(struct window *win, const char *p, size_t len)
{

	if (len >= WINDOW_MAX) {
		memcpy(win->buf, p + len - WINDOW_MAX, WINDOW_MAX);
		win->len = WINDOW_MAX;
	} else {
		if (win->len + len > WINDOW_MAX) {
			memmove(win->buf, win->buf + win->len + len -
			    WINDOW_MAX, WINDOW_MAX - len);
			win->len = WINDOW_MAX - len;
		}
		memcpy(win->buf + win->len, p, len);
		win->len += len;
	}
	win->buf[win->len] = '\0';
}

static void
capture_read(int *fd, struct capture *c, struct window *win)
{
	char	buf[8192];
	ssize_t	n;

	n = read(*fd, buf, sizeof(buf));
	if (n <= 0) {
		close(*fd);
		*fd = -1;
		return;
	}
	window_put(win, buf, (size_t)n);
	if (c->len + (size_t)n > c->max) {
		n = (ssize_t)(c->max - c->len);
		c->truncated = true;
	}
	if (n > 0) {
		if ((c->buf = realloc(c->buf, c->len + (size_t)n)) == NULL)
			err(1, "realloc");
		memcpy(c->buf + c->len, buf, (size_t)n);
		c->len += (size_t)n;
	}
}

/*
 * Returns the exit status (128 + signal when killed), or -1 if the
 * program could not be started.  The output in *res lives in w's pool.
 */
int
run_exec(struct work *w, char *const argv[], struct execres *res)
{

	return (run_exec_max(w, argv, res, ARC_MAX_OUTPUT));
}

/*
 * The next program this thread runs only reads (sysrc -n, service
 * status): a dry run runs it too, so that what follows from what it
 * says is as a job's would be.  Taken by run_exec_max() at once.
 */
static _Thread_local bool	exec_reads;

int
run_read(struct work *w, char *const argv[], struct execres *res)
{

	return (run_read_max(w, argv, res, ARC_MAX_OUTPUT));
}

int
run_read_max(struct work *w, char *const argv[], struct execres *res,
    size_t max)
{

	exec_reads = true;
	return (run_exec_max(w, argv, res, max));
}

/*
 * HOME for the programs this thread runs, or none.  A build sets it to
 * its directory: compilers keep caches under it (emcc refuses to run
 * without one), and the build user has no home of its own.
 */
static _Thread_local char	*exec_home;

/*
 * What the next program run by this thread reads on its standard input,
 * through a pipe: a key, which no file and no argument list holds.  Once
 * only; /dev/null otherwise.
 */
static _Thread_local const char	*exec_in;
static _Thread_local size_t	 exec_inlen;

void
exec_set_stdin(const char *text, size_t len)
{

	exec_in = text;
	exec_inlen = len;
}

/*
 * Where a program's scratch file goes (a dtrace script, a socket's
 * directory): TMPDIR's, when it names one, else /tmp.  Never a key's or
 * a passphrase's: those go through a pipe.
 */
const char *
tmp_dir(void)
{
	const char	*t;

	t = getenv("TMPDIR");
	return (t != NULL && t[0] == '/' ? t : "/tmp");
}

/*
 * A file the next program this thread runs reads on its standard input,
 * or writes its standard output to, in place of /dev/null and the pipe
 * read: one opened beneath a jail's root, which no path given to a host
 * program would name safely.  Once only; -1 for none.  The caller keeps
 * and closes them.
 */
static _Thread_local int	exec_infd = -1, exec_outfd = -1;

void
exec_set_fds(int in, int out)
{

	exec_infd = in;
	exec_outfd = out;
}

/*
 * What the programs this thread runs print is kept out of the trace,
 * while this is set: it has keys in it, and a trace is read far away.
 */
static _Thread_local bool	exec_secret;

void
exec_set_secret(bool on)
{

	exec_secret = on;
}

/*
 * A word the command lines this thread runs are traced without, shown
 * as <hidden>: a key that is an argument (sysrc of a variable holding
 * one).  Until set again; NULL for none.
 */
static _Thread_local const char	*exec_hide;

void
exec_set_hide(const char *word)
{

	exec_hide = word != NULL && word[0] != '\0' ? word : NULL;
}

/* The command line as traced: the hidden word shown as <hidden>. */
static const char *
traced(struct work *w, const char *s)
{
	const char	*p, *out;

	if (exec_hide == NULL)
		return (s);
	out = "";
	while ((p = strstr(s, exec_hide)) != NULL) {
		out = wfmt(w, "%s%.*s<hidden>", out, (int)(p - s), s);
		s = p + strlen(exec_hide);
	}
	return (wfmt(w, "%s%s", out, s));
}

/*
 * The daemon's umask is 077 (main()): what it makes is its own unless it
 * says otherwise.  A directory made with mode has that mode, whatever
 * the umask; one already there is left as it is.  mkdir(2)'s return.
 */
int
mkdir_mode(const char *path, mode_t mode)
{

	if (mkdir(path, mode) == -1)
		return (-1);
	(void)chmod(path, mode);
	return (0);
}

/*
 * posix_spawn(3) with the umask the system's programs expect, 022: a
 * child has the daemon's 077 otherwise, and a service restarted, a jail
 * started (its rc), pkg, would make their files as the daemon makes its
 * secrets.  posix_spawn sets no umask; it returns once the child has
 * exec'd (vfork(2)'s way), so the mask is set around it, under a lock.
 * Another thread's file made meanwhile is made with its own explicit
 * mode: a secret's 0600 stays 0600 under either mask.
 */
static pthread_mutex_t	spawn_lock = PTHREAD_MUTEX_INITIALIZER;

int
agent_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *fa,
    const posix_spawnattr_t *sa, char *const argv[], char *const envp[])
{
	mode_t	old;
	int	rc;

	pthread_mutex_lock(&spawn_lock);
	old = umask(022);
	rc = posix_spawn(pid, path, fa, sa, argv, envp);
	(void)umask(old);
	pthread_mutex_unlock(&spawn_lock);
	return (rc);
}

/*
 * argv as the trace has it: the hidden word (exec_set_hide()) shown as
 * <hidden> in every argument, the value of a variable whose name says
 * it is a secret and the argument after one that announces a secret
 * (secret_word(): -k, --password); *secretp says there was one, and
 * then what the program prints (sysrc's "name: old -> new") is not
 * kept either.
 */
static char **
trace_argv(struct work *w, char *const argv[], bool *secretp)
{
	char	**v;
	size_t	  n, i, keep;

	*secretp = false;
	for (n = 0; argv[n] != NULL; n++)
		;
	v = wcalloc(w, n + 1, sizeof(*v));
	for (i = 0; i < n; i++) {
		v[i] = (char *)(uintptr_t)traced(w, argv[i]);
		if (i > 0 && secret_assign(argv[i], &keep)) {
			v[i] = wfmt(w, "%.*s%s", (int)keep, argv[i], MASK_MARK);
			*secretp = true;
		} else if (i > 1 && secret_word(argv[i - 1]) && argv[i][0] !=
		    '\0' && strncmp(argv[i], "--", 2) != 0) {
			v[i] = (char *)(uintptr_t)MASK_MARK;
			*secretp = true;
		}
	}
	return (v);
}

/*
 * The programs this thread runs while this is set (pkg): each in a
 * process group of its own, so that what it starts (pkg -j's child in
 * the jail) is stopped with it; stopped too once nothing has come from
 * it for idle seconds, and when its job is cancelled.  0: not watched.
 */
static _Thread_local int	exec_idle;

void
exec_set_watch(int idle)
{

	exec_idle = idle;
}

/*
 * A watched program that has printed one of marks (NULL-ended) has
 * begun what silence is part of: pkg installing, whose packages'
 * scripts stop and start services and may wait on them (an rc stop of
 * a daemon that does not stop).  Silent past the watch's bound from
 * then on, it is not stopped: a step of the trace, labelled what, says
 * that it waits and what it printed last, and it is stopped once
 * silent for secs, or by its job's cancel.  NULL: none.
 */
static _Thread_local const char *const	*exec_busy_marks;
static _Thread_local int		 exec_busy;
static _Thread_local const char		*exec_busy_what;

void
exec_set_busy(const char *const *marks, int secs, const char *what)
{

	exec_busy_marks = marks;
	exec_busy = secs;
	exec_busy_what = what;
}

/* "2 seconds", "10 minutes", as exec_error() says a silence. */
static const char *
secs_text(struct work *w, int secs)
{

	return (wfmt(w, "%d %s", secs >= 120 ? secs / 60 : secs, secs >= 120 ?
	    "minutes" : "seconds"));
}

/* The last line in win that has something in it, made visible; "". */
static const char *
window_last(struct work *w, const struct window *win)
{
	const char	*p, *e;

	e = win->buf + win->len;
	while (e > win->buf && isspace((unsigned char)e[-1]))
		e--;
	for (p = e; p > win->buf && p[-1] != '\n' && p[-1] != '\r'; p--)
		;
	return (traced(w, wvis(w, wstrndup(w, p, (size_t)(e - p)))));
}

/* Has the program printed one of marks? */
static bool
window_marked(const struct window *win, const char *const *marks)
{
	size_t	i;

	for (i = 0; marks != NULL && marks[i] != NULL; i++)
		if (strstr(win->buf, marks[i]) != NULL)
			return (true);
	return (false);
}

/*
 * The job this thread is at, for the marks a watched program is given
 * in its environment: ARCANA_AGENT_JOB=<agent's pid>:<job>:<kind> and
 * ARCANA_AGENT_JOB_TITLE=<title>.  An agent started after this one went
 * finds by them what it left running (exec_orphans()).  0: none, a
 * request's.
 */
#define	JOB_MARK	"ARCANA_AGENT_JOB="
#define	JOB_MARK_TITLE	"ARCANA_AGENT_JOB_TITLE="

static _Thread_local uint64_t	 exec_job;
static _Thread_local uint8_t	 exec_job_kind;
static _Thread_local const char	*exec_job_title;

void
exec_set_job(uint64_t id, uint8_t kind, const char *title)
{

	exec_job = id;
	exec_job_kind = kind;
	exec_job_title = title;
}

/* The program stopped, its process group with it when it has one. */
static void
exec_kill(pid_t pid, bool group)
{

	(void)kill(group ? -pid : pid, SIGTERM);
	sleep(2);
	(void)kill(group ? -pid : pid, SIGKILL);
}

/*
 * The next program this thread runs ends within secs, or once it has
 * been silent for as long: killed then, with its process group, and
 * said timed out.  Once only.  A read's program run in a jail by
 * jexec(8), or sysrc -j, has JAIL_READ_SEC without asking.
 */
static _Thread_local int	exec_limit;

void
exec_set_limit(int secs)
{

	exec_limit = secs;
}

void
exec_set_home(struct work *w, const char *dir)
{

	exec_home = dir != NULL ? wfmt(w, "HOME=%s", dir) : NULL;
}

/* One more NAME=value in the environment of what this thread runs
 * (SSH_AUTH_SOCK for ssh-add and ssh-keygen -U), or none with NULL. */
static _Thread_local char	*exec_extra;

void
exec_set_env(struct work *w, const char *name, const char *value)
{

	exec_extra = name != NULL ? wfmt(w, "%s=%s", name, value) : NULL;
}

/*
 * As run_exec(), keeping up to max bytes of standard output for the
 * caller; the trace step still carries at most ARC_MAX_OUTPUT of them.
 * res->truncated says the program printed more than was kept.
 */
int
run_exec_max(struct work *w, char *const argv[], struct execres *res,
    size_t max)
{
	posix_spawn_file_actions_t	 fa;
	posix_spawnattr_t		 sa;
	sigset_t			 none, dfl;
	struct pollfd			 pfd[3];
	struct capture			 out, eout;
	static char			 pathenv[] =
	    "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin";
	/* git reads no configuration but the repository's own. */
	static char			 gitglobal[] =
	    "GIT_CONFIG_GLOBAL=/dev/null";
	static char			 gitsystem[] = "GIT_CONFIG_NOSYSTEM=1";
	char				*env[8];
	const char			*cmdline;
	char				**targv;
	size_t				 i;
	time_t				 deadline, heard, drain;
	int				 ne, limit, idle, busy;
	bool				 group, secret, watched, marked, noted;
	const char *const		*marks;
	struct window			 win;

	ne = 0;
	env[ne++] = pathenv;
	env[ne++] = gitglobal;
	env[ne++] = gitsystem;
	if (exec_home != NULL)
		env[ne++] = exec_home;
	if (exec_extra != NULL)
		env[ne++] = exec_extra;
	env[ne] = NULL;
	pid_t				 pid;
	int				 op[2], ep[2], ip[2], status, rc, step,
					 n, infd, outfd;
	bool				 exited, reads;
	struct live			*live;
	size_t				 had;
	const char			*in;
	size_t				 inlen, off;
	ssize_t				 wr;

	argv = scope_argv(w, argv);
	limit = exec_limit;
	exec_limit = 0;
	/* A read of the jail's own: by jexec(8), or sysrc -j (the jail's
	 * /bin/sh, by jexec). */
	if (limit == 0 && w->nice && w->jail != NULL && (argv[0] ==
	    opts.jexec_bin || argv[0] == opts.sysrc_bin))
		limit = JAIL_READ_SEC;
	idle = exec_idle;
	watched = idle > 0;
	if (limit > 0 && (idle == 0 || idle > limit))
		idle = limit;
	/* Its busy phase, a watched program's with no deadline of its own. */
	marks = watched && limit == 0 && exec_busy > idle ? exec_busy_marks :
	    NULL;
	busy = exec_busy;
	marked = false;
	win.len = 0;
	win.buf[0] = '\0';
	in = exec_in;
	inlen = exec_inlen;
	exec_in = NULL;
	exec_inlen = 0;
	reads = exec_reads;
	exec_reads = false;
	infd = exec_infd;
	outfd = exec_outfd;
	exec_infd = exec_outfd = -1;

	memset(res, 0, sizeof(*res));
	targv = trace_argv(w, argv, &secret);
	cmdline = wvis(w, targv[0]);
	for (i = 1; targv[i] != NULL; i++)
		cmdline = wfmt(w, "%s %s", cmdline, wvis(w, targv[i]));
	cmdline = traced(w, cmdline);
	step = step_begin(w, STEP_EXEC, cmdline,
	    "posix_spawn(3), no shell");
	/* A dry run's: what would be run, said, and taken as done. */
	if (w->dry && !reads) {
		res->out = res->err = "";
		step_notrun(w, step, targv);
		step_end(w, step, true, "not run: a dry run");
		return (0);
	}

	memset(&out, 0, sizeof(out));
	memset(&eout, 0, sizeof(eout));
	out.max = max;
	eout.max = ARC_MAX_OUTPUT;
	op[0] = op[1] = ip[0] = ip[1] = -1;
	if ((outfd == -1 && pipe2(op, O_CLOEXEC) == -1) ||
	    pipe2(ep, O_CLOEXEC) == -1)
		err(1, "pipe2");
	if (in != NULL && pipe2(ip, O_CLOEXEC) == -1)
		err(1, "pipe2");
	posix_spawn_file_actions_init(&fa);
	if (in != NULL)
		posix_spawn_file_actions_adddup2(&fa, ip[0], STDIN_FILENO);
	else if (infd != -1)
		posix_spawn_file_actions_adddup2(&fa, infd, STDIN_FILENO);
	else
		posix_spawn_file_actions_addopen(&fa, STDIN_FILENO,
		    "/dev/null", O_RDONLY, 0);
	posix_spawn_file_actions_adddup2(&fa, outfd != -1 ? outfd : op[1],
	    STDOUT_FILENO);
	posix_spawn_file_actions_adddup2(&fa, ep[1], STDERR_FILENO);
	/* The daemon keeps its stop signals blocked; a program does not. */
	sigemptyset(&none);
	sigemptyset(&dfl);
	sigaddset(&dfl, SIGTERM);
	sigaddset(&dfl, SIGINT);
	posix_spawnattr_init(&sa);
	posix_spawnattr_setsigmask(&sa, &none);
	posix_spawnattr_setsigdefault(&sa, &dfl);
	/* Watched: a process group of its own, stopped whole. */
	group = idle > 0;
	if (group)
		posix_spawnattr_setpgroup(&sa, 0);
	/* Watched: marked, for the agent after this one to find. */
	if (watched) {
		env[ne++] = wfmt(w, JOB_MARK "%d:%ju:%u", (int)getpid(),
		    (uintmax_t)exec_job, (unsigned int)exec_job_kind);
		env[ne++] = wfmt(w, JOB_MARK_TITLE "%s", exec_job_title !=
		    NULL ? exec_job_title : "");
		env[ne] = NULL;
	}
	posix_spawnattr_setflags(&sa, POSIX_SPAWN_SETSIGMASK |
	    POSIX_SPAWN_SETSIGDEF | (group ? POSIX_SPAWN_SETPGROUP : 0));
	rc = agent_spawn(&pid, argv[0], &fa, &sa, argv, env);
	if (rc == 0 && w->nice)
		(void)setpriority(PRIO_PROCESS, pid, READ_NICE);
	posix_spawnattr_destroy(&sa);
	posix_spawn_file_actions_destroy(&fa);
	if (op[1] != -1)
		close(op[1]);
	close(ep[1]);
	/*
	 * What the program reads is written as it reads it, beside its
	 * output being read: a large input (a ruleset for ipfw -n) does not
	 * wait on a pipe the program cannot empty while its own output
	 * fills the other.
	 */
	off = 0;
	if (in != NULL) {
		close(ip[0]);
		if (rc != 0 || inlen == 0) {
			close(ip[1]);
			ip[1] = -1;
		} else
			(void)fcntl(ip[1], F_SETFL, fcntl(ip[1], F_GETFL) |
			    O_NONBLOCK);
	} else
		ip[1] = -1;
	if (rc != 0) {
		if (op[0] != -1)
			close(op[0]);
		close(ep[0]);
		res->status = -1;
		res->err = wfmt(w, "cannot run %s: %s", argv[0],
		    strerror(rc));
		res->errlen = strlen(res->err);
		step_exec(w, step, targv, -1, NULL, 0, res->err, res->errlen);
		step_end(w, step, false, "%s", res->err);
		return (-1);
	}

	/*
	 * A job's program, its output kept: a live copy beside the capture,
	 * for whoever follows it while it runs (live.c).
	 */
	live = NULL;
	if (w->told && step >= 0 && !exec_secret && !secret &&
	    (live = live_new()) != NULL) {
		pthread_mutex_lock(&w->lock);
		w->steps[step].live = live;
		pthread_mutex_unlock(&w->lock);
	}

	/*
	 * Read until the program has exited and its output is drained, not
	 * until the pipes close: what a jail's exec.start leaves running may
	 * keep them open for as long as it lives, and write on.  Drained for
	 * EXEC_DRAIN_SEC at most, within the deadline and the job's cancel.
	 */
	exited = false;
	noted = false;
	deadline = time(NULL) + (limit > 0 ? limit : EXEC_TIMEOUT_SEC);
	heard = drain = time(NULL);
	while (op[0] != -1 || ep[0] != -1) {
		pfd[0].fd = op[0];
		pfd[0].events = POLLIN;
		pfd[1].fd = ep[0];
		pfd[1].events = POLLIN;
		pfd[2].fd = ip[1];
		pfd[2].events = POLLOUT;
		n = poll(pfd, 3, exited ? 0 : 1000);
		if (n == -1 && errno != EINTR)
			err(1, "poll");
		if (n > 0 && ip[1] != -1 && (pfd[2].revents & (POLLOUT | POLLHUP |
		    POLLERR))) {
			wr = (pfd[2].revents & POLLOUT) ? write(ip[1], in + off,
			    inlen - off) : -1;
			if (wr > 0)
				off += (size_t)wr;
			/* All of it written, or the program is not reading. */
			if (off >= inlen || (wr == -1 && errno != EAGAIN &&
			    errno != EINTR) || (pfd[2].revents & (POLLHUP |
			    POLLERR))) {
				close(ip[1]);
				ip[1] = -1;
			}
		}
		if (n > 0) {
			/* Something from it: not silent. */
			if ((op[0] != -1 && (pfd[0].revents & POLLIN)) ||
			    (ep[0] != -1 && (pfd[1].revents & POLLIN))) {
				heard = time(NULL);
				noted = false;
			}
			if (op[0] != -1 &&
			    (pfd[0].revents & (POLLIN | POLLHUP))) {
				had = out.len;
				capture_read(&op[0], &out, &win);
				live_put(live, out.buf + had, out.len - had);
			}
			if (ep[0] != -1 &&
			    (pfd[1].revents & (POLLIN | POLLHUP))) {
				had = eout.len;
				capture_read(&ep[0], &eout, &win);
				live_put(live, eout.buf + had, eout.len - had);
			}
			if (!marked && marks != NULL)
				marked = window_marked(&win, marks);
		} else if (n == 0 && exited)
			break;
		if (exited) {
			if (time(NULL) > drain || time(NULL) > deadline ||
			    (group && w->cancel))
				break;
			continue;
		}
		if (waitpid(pid, &status, WNOHANG) == pid) {
			exited = true;
			drain = time(NULL) + EXEC_DRAIN_SEC;
			continue;
		}
		if (time(NULL) > deadline) {
			exec_kill(pid, group);
			res->timedout = true;
			break;
		}
		if (group && w->cancel) {
			exec_kill(pid, group);
			res->cancelled = true;
			break;
		}
		/*
		 * In its busy phase, silent past the watch: said once each
		 * silence, in a step of its own; stopped past busy.
		 */
		if (group && marked && time(NULL) - heard > idle) {
			if (time(NULL) - heard > busy) {
				exec_kill(pid, group);
				res->stalled = busy;
				res->waited = window_last(w, &win);
				break;
			}
			if (!noted) {
				int	ns;

				noted = true;
				ns = step_begin(w, STEP_DAEMON, exec_busy_what !=
				    NULL ? exec_busy_what : "the program waits",
				    "nothing from it for %s; last it printed: "
				    "\"%s\"; stopped once silent for %s, or by "
				    "the job's cancel", secs_text(w, idle),
				    window_last(w, &win), secs_text(w, busy));
				step_end(w, ns, true, NULL);
			}
			continue;
		}
		if (group && time(NULL) - heard > idle) {
			exec_kill(pid, group);
			if (limit > 0)
				res->timedout = true;
			else
				res->stalled = idle;
			break;
		}
	}
	if (op[0] != -1)
		close(op[0]);
	if (ep[0] != -1)
		close(ep[0]);
	if (ip[1] != -1)
		close(ip[1]);
	while (!exited && waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			err(1, "waitpid");
	rc = WIFEXITED(status) ? WEXITSTATUS(status) :
	    128 + WTERMSIG(status);
	live_end(live);

	res->status = rc;
	res->out = out.len > 0 ? wstrndup(w, out.buf, out.len) : "";
	res->outlen = out.len;
	res->err = eout.len > 0 ? wstrndup(w, eout.buf, eout.len) : "";
	res->errlen = eout.len;
	res->truncated = out.truncated;
	free(out.buf);
	free(eout.buf);
	if (exec_secret || secret)
		step_exec(w, step, targv, rc, "(not kept: it has keys in it)\n",
		    30, secret ? "" : res->err, secret ? 0 : res->errlen);
	else
		step_exec(w, step, targv, rc, res->out, MIN(res->outlen,
		    (size_t)ARC_MAX_OUTPUT), res->err, res->errlen);
	step_end(w, step, rc == 0, "exit status %d%s%s", rc,
	    out.truncated || eout.truncated ? ", output truncated" : "",
	    res->timedout ? ", killed: out of time" : res->cancelled ?
	    ", stopped: the job was cancelled" : res->stalled > 0 ?
	    ", killed: silent too long" : "");
	return (rc);
}

/* "jail exited with status 1: <last line of stderr>" */
const char *
exec_error(struct work *w, const struct execres *res, const char *prog)
{
	const char	*p;
	size_t		 len;

	len = res->err != NULL ? res->errlen : 0;
	while (len > 0 && res->err[len - 1] == '\n')
		len--;
	if (res->timedout)
		return (wfmt(w, "%s was killed: it did not finish in time", prog));
	if (res->cancelled)
		return (wfmt(w, "%s was stopped: the job was cancelled", prog));
	if (res->stalled > 0 && res->note != NULL)
		return (wfmt(w, "%s was killed: nothing came from it for %d "
		    "%s; %s", prog, res->stalled >= 120 ? res->stalled / 60 :
		    res->stalled, res->stalled >= 120 ? "minutes" : "seconds",
		    res->note));
	if (res->stalled > 0)
		return (wfmt(w, "%s was killed: nothing came from it for %d "
		    "%s (a download that stalled, or a question it waits on)",
		    prog, res->stalled >= 120 ? res->stalled / 60 : res->stalled,
		    res->stalled >= 120 ? "minutes" : "seconds"));
	if (len == 0)
		return (wfmt(w, "%s exited with status %d", prog,
		    res->status));
	for (p = res->err + len; p > res->err && p[-1] != '\n'; p--)
		;
	return (wfmt(w, "%s exited with status %d: %.*s", prog,
	    res->status, (int)(res->err + len - p), p));
}

/*
 * The whole lines of buf (*lenp bytes, one more there to end a line) to
 * fn, what is left moved to its start; one longer than LINES_MAX in
 * pieces, and at the end the rest as a line.  How many.
 */
static size_t
lines_out(char *buf, size_t *lenp, bool end, void (*fn)(const char *,
    void *), void *arg)
{
	char	*p, *nl, c;
	size_t	 left, n;

	n = 0;
	buf[*lenp] = '\0';
	for (p = buf; (left = *lenp - (size_t)(p - buf)) > 0; p = nl) {
		if ((nl = memchr(p, '\n', left)) == NULL) {
			if (left > LINES_MAX)
				nl = p + LINES_MAX;
			else if (end)
				nl = p + left;
			else
				break;
		}
		c = *nl;
		*nl = '\0';
		fn(p, arg);
		n++;
		if ((*nl = c) == '\n')
			nl++;
	}
	memmove(buf, p, left);
	*lenp = left;
	return (n);
}

/*
 * Run a program for its lines: each goes to fn as it comes and none is
 * kept, for output too large to hold.  Standard error is dropped.
 * Returns the exit status, or -1 if the program could not be started.
 */
int
run_exec_lines(struct work *w, char *const argv[],
    void (*fn)(const char *, void *), void *arg)
{
	posix_spawn_file_actions_t	 fa;
	posix_spawnattr_t		 sa;
	sigset_t			 none, dfl;
	static char			 pathenv[] =
	    "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin";
	char				*env[] = { pathenv, NULL };
	struct pollfd			 pfd;
	const char			*cmdline;
	char				*buf, **targv;
	size_t				 cap, len, i, lines;
	ssize_t				 got;
	time_t				 deadline, drain;
	pid_t				 pid;
	int				 op[2], status, rc, step, n;
	bool				 exited, timedout, secret;

	argv = scope_argv(w, argv);
	/* Its lines are not traced: only its command line is. */
	targv = trace_argv(w, argv, &secret);
	(void)secret;
	cmdline = wvis(w, targv[0]);
	for (i = 1; targv[i] != NULL; i++)
		cmdline = wfmt(w, "%s %s", cmdline, wvis(w, targv[i]));
	cmdline = traced(w, cmdline);
	step = step_begin(w, STEP_EXEC, cmdline,
	    "posix_spawn(3), no shell; read line by line");
	if (w->dry) {
		step_notrun(w, step, targv);
		step_end(w, step, true, "not run: a dry run");
		return (0);
	}
	if (pipe2(op, O_CLOEXEC) == -1)
		err(1, "pipe2");
	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null",
	    O_RDONLY, 0);
	posix_spawn_file_actions_adddup2(&fa, op[1], STDOUT_FILENO);
	posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null",
	    O_WRONLY, 0);
	sigemptyset(&none);
	sigemptyset(&dfl);
	sigaddset(&dfl, SIGTERM);
	sigaddset(&dfl, SIGINT);
	posix_spawnattr_init(&sa);
	posix_spawnattr_setsigmask(&sa, &none);
	posix_spawnattr_setsigdefault(&sa, &dfl);
	posix_spawnattr_setflags(&sa, POSIX_SPAWN_SETSIGMASK |
	    POSIX_SPAWN_SETSIGDEF);
	rc = agent_spawn(&pid, argv[0], &fa, &sa, argv, env);
	if (rc == 0 && w->nice)
		(void)setpriority(PRIO_PROCESS, pid, READ_NICE);
	posix_spawnattr_destroy(&sa);
	posix_spawn_file_actions_destroy(&fa);
	close(op[1]);
	if (rc != 0) {
		close(op[0]);
		step_end(w, step, false, "%s", strerror(rc));
		return (-1);
	}
	/*
	 * Read as run_exec_max() reads: until the program exited and its
	 * output is drained, EXEC_DRAIN_SEC at most after, within the
	 * deadline.  Each whole line to fn as it comes; one longer than
	 * LINES_MAX in pieces.
	 */
	buf = NULL;
	cap = len = 0;
	lines = 0;
	exited = timedout = false;
	deadline = time(NULL) + EXEC_TIMEOUT_SEC;
	drain = 0;
	while (op[0] != -1) {
		pfd.fd = op[0];
		pfd.events = POLLIN;
		n = poll(&pfd, 1, exited ? 0 : 1000);
		if (n == -1 && errno != EINTR)
			err(1, "poll");
		if (n > 0) {
			if (len + 8192 + 1 > cap) {
				cap = (len + 8192 + 1) * 2;
				if ((buf = realloc(buf, cap)) == NULL)
					err(1, "realloc");
			}
			if ((got = read(op[0], buf + len, 8192)) <= 0) {
				close(op[0]);
				op[0] = -1;
			} else
				len += (size_t)got;
			lines += lines_out(buf, &len, op[0] == -1, fn, arg);
		} else if (n == 0 && exited)
			break;
		if (exited) {
			if (time(NULL) > drain || time(NULL) > deadline)
				break;
			continue;
		}
		if (waitpid(pid, &status, WNOHANG) == pid) {
			exited = true;
			drain = time(NULL) + EXEC_DRAIN_SEC;
			continue;
		}
		if (time(NULL) > deadline) {
			exec_kill(pid, false);
			timedout = true;
			break;
		}
	}
	free(buf);
	if (op[0] != -1)
		close(op[0]);
	while (!exited && waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			err(1, "waitpid");
	rc = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
	step_end(w, step, rc == 0, "exit status %d, %zu lines read%s", rc,
	    lines, timedout ? ", killed: out of time" : "");
	return (rc);
}

/* Whether pid is a process that has not ended (a zombie has). */
bool
pid_alive(pid_t pid)
{
	struct kinfo_proc	*kp;
	bool			 alive;

	if (pid <= 1 || (kp = kinfo_getproc(pid)) == NULL)
		return (false);
	alive = kp->ki_stat != SZOMB;
	free(kp);
	return (alive);
}

/*
 * Is the process of a pid the program it is taken for?  A pid file
 * left by a crash or a reboot names a number that may be another's by
 * now: its name (ki_comm) or what it was started as (argv[0]) must be
 * the program's before it is believed, let alone signalled.
 */
bool
pid_is(pid_t pid, const char *prog)
{
	struct kinfo_proc	*kp;
	const char		*base;
	bool			 is;

	if (pid <= 1 || prog == NULL)
		return (false);
	if ((kp = kinfo_getproc(pid)) == NULL)
		return (false);
	/* A zombie has ended; only its reaper, slow in a container, is
	 * yet to collect it. */
	if (kp->ki_stat == SZOMB) {
		free(kp);
		return (false);
	}
	base = strrchr(prog, '/') != NULL ? strrchr(prog, '/') + 1 : prog;
	is = strcmp(kp->ki_comm, base) == 0;
	free(kp);
	if (!is) {
		/* What it was started as: its argv[0], or, a script's (whose
		 * name the kernel gives its interpreter), argv[1]. */
		int	mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ARGS, pid };
		char	av[2 * MAXPATHLEN], *p, *e;
		size_t	len = sizeof(av) - 1;
		int	k;

		if (sysctl(mib, 4, av, &len, NULL, 0) == 0 && len > 0) {
			av[len] = '\0';
			for (p = av, k = 0; !is && k < 2 && p < av + len; p = e +
			    1, k++) {
				e = p + strlen(p);
				is = strcmp(p, prog) == 0 || (strrchr(p, '/') !=
				    NULL && strcmp(strrchr(p, '/') + 1, base) == 0);
			}
		}
	}
	return (is);
}

/* The pid a file holds, when that process is prog's; 0 otherwise. */
pid_t
pidfile_of(const char *path, const char *prog)
{
	FILE	*fp;
	long	 pid = 0;

	if ((fp = fopen(path, "re")) == NULL)
		return (0);
	if (fscanf(fp, "%ld", &pid) != 1)
		pid = 0;
	fclose(fp);
	return (pid > 1 && pid_is((pid_t)pid, prog) ? (pid_t)pid : 0);
}

/*
 * A program's process stopped: SIGTERM, up to wait_ms for it to go,
 * then SIGKILL; each signal only while the pid is still that program's.
 */
void
pid_stop(pid_t pid, const char *prog, int wait_ms)
{
	int	i;

	if (!pid_is(pid, prog))
		return;
	(void)kill(pid, SIGTERM);
	for (i = 0; i < wait_ms / 20 && pid_is(pid, prog); i++)
		usleep(20000);
	if (pid_is(pid, prog))
		(void)kill(pid, SIGKILL);
}

/*
 * The marks of a job's watched program in the environment of process
 * pid, when it has them (run_exec_max()): whose agent's job it is (that
 * agent's pid, the job and its kind) and the job's title.  Our own
 * marks come first in what the program was given, so the start of its
 * environment is enough.
 */
static bool
job_mark(pid_t pid, pid_t *agentp, uint64_t *idp, uint8_t *kindp,
    char *title, size_t tlen)
{
	int		 mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ENV, pid };
	char		 buf[16384], *p;
	size_t		 len;
	uintmax_t	 id;
	unsigned int	 kind;
	int		 apid;
	bool		 found;

	len = sizeof(buf) - 1;
	if (sysctl(mib, 4, buf, &len, NULL, 0) == -1 && errno != ENOMEM)
		return (false);
	if (len == 0 || len >= sizeof(buf))
		return (false);
	buf[len] = '\0';
	found = false;
	title[0] = '\0';
	for (p = buf; p < buf + len; p += strlen(p) + 1) {
		if (strncmp(p, JOB_MARK, sizeof(JOB_MARK) - 1) == 0 &&
		    sscanf(p + sizeof(JOB_MARK) - 1, "%d:%ju:%u", &apid, &id,
		    &kind) == 3 && apid > 1) {
			*agentp = (pid_t)apid;
			*idp = (uint64_t)id;
			*kindp = (uint8_t)kind;
			found = true;
		} else if (strncmp(p, JOB_MARK_TITLE, sizeof(JOB_MARK_TITLE) -
		    1) == 0)
			strlcpy(title, p + sizeof(JOB_MARK_TITLE) - 1, tlen);
	}
	return (found);
}

/*
 * The processes this agent was started under, while it still knows
 * them (before daemon(3) leaves them): a pkg job that upgrades Arcana
 * restarts the agent from its script, and is not this agent's
 * predecessor's to stop.  exec_orphans() leaves their process groups.
 */
static pid_t	ancestors[32];
static size_t	nancestors;

void
exec_note_ancestors(void)
{
	struct kinfo_proc	*kp;
	pid_t			 pid;

	nancestors = 0;
	for (pid = getppid(); pid > 1 && nancestors < nitems(ancestors); ) {
		if ((kp = kinfo_getproc(pid)) == NULL)
			break;
		ancestors[nancestors++] = pid;
		pid = kp->ki_ppid;
		free(kp);
	}
}

/*
 * What a job's watched program (pkg) left running when the agent that
 * ran it went (an update restarts the agent under a pkg in a jail that
 * waits on a mirror for hours): no thread of this agent waits on it,
 * reads it or watches it.  Each is known by its marks (job_mark()), an
 * agent's that is not this one and no longer runs, and by being in a
 * process group of its own that is not its session's: the group that
 * agent made for it (POSIX_SPAWN_SETPGROUP), which a daemon it started
 * left by setsid(2).  Stopped, not adopted: this agent cannot wait on a
 * process that is not its child, nor read its output, nor tell its
 * silence; its job was the other agent's, whose queue is gone.  Each
 * group is sent SIGTERM, and SIGKILL when anything of it is left after
 * ORPHAN_GRACE_SEC; then told to fn.  How many groups.
 */
size_t
exec_orphans(void (*fn)(uint64_t, uint8_t, const char *, pid_t, time_t,
    const char *, void *), void *arg)
{
	struct orphan {
		pid_t		 pgid;
		pid_t		 pid;
		uint64_t	 id;
		uint8_t		 kind;
		time_t		 started;
		char		 title[160];
		bool		 left;
	}			*v;
	struct kinfo_proc	*kp;
	char			 title[160];
	pid_t			 agent, skip[nitems(ancestors)];
	uint64_t		 id;
	uint8_t			 kind;
	size_t			 n, i, k, nskip;
	int			 cnt, j, waited;
	bool			 any;

	if ((kp = kinfo_getallproc(&cnt)) == NULL)
		return (0);
	/* The groups of what this agent was started under. */
	nskip = 0;
	for (j = 0; j < cnt; j++)
		for (k = 0; k < nancestors && nskip < nitems(skip); k++)
			if (kp[j].ki_pid == ancestors[k])
				skip[nskip++] = kp[j].ki_pgid;
	if ((v = calloc((size_t)cnt + 1, sizeof(*v))) == NULL) {
		free(kp);
		return (0);
	}
	n = 0;
	for (j = 0; j < cnt; j++) {
		if (kp[j].ki_pid == getpid() || kp[j].ki_stat == SZOMB ||
		    kp[j].ki_pgid <= 1 || kp[j].ki_sid == kp[j].ki_pgid)
			continue;
		for (k = 0; k < nskip && skip[k] != kp[j].ki_pgid; k++)
			;
		if (k < nskip)
			continue;
		if (!job_mark(kp[j].ki_pid, &agent, &id, &kind, title,
		    sizeof(title)) || agent == getpid() ||
		    pid_is(agent, "arcana-agent"))
			continue;
		for (i = 0; i < n && v[i].pgid != kp[j].ki_pgid; i++)
			;
		if (i == n) {
			v[n].pgid = kp[j].ki_pgid;
			v[n].pid = kp[j].ki_pid;
			v[n].id = id;
			v[n].kind = kind;
			v[n].started = kp[j].ki_start.tv_sec;
			strlcpy(v[n].title, title, sizeof(v[n].title));
			n++;
		} else if (kp[j].ki_pid == kp[j].ki_pgid ||
		    kp[j].ki_start.tv_sec < v[i].started) {
			/* The one that leads it, or began first: the
			 * program the job ran. */
			v[i].pid = kp[j].ki_pid;
			v[i].started = kp[j].ki_start.tv_sec;
		}
	}
	free(kp);
	for (i = 0; i < n; i++) {
		logmsg(LOG_NOTICE, "job %ju of the agent before (%s): pid %d "
		    "left running, stopped", (uintmax_t)v[i].id, v[i].title,
		    (int)v[i].pid);
		(void)kill(-v[i].pgid, SIGTERM);
	}
	/* Gone within the grace, or killed. */
	for (waited = 0; n > 0 && waited < ORPHAN_GRACE_SEC * 10; waited++) {
		any = false;
		for (i = 0; i < n; i++)
			if (kill(-v[i].pgid, 0) == 0)
				any = true;
		if (!any)
			break;
		usleep(100000);
	}
	for (i = 0; i < n; i++)
		if (kill(-v[i].pgid, 0) == 0) {
			v[i].left = true;
			(void)kill(-v[i].pgid, SIGKILL);
		}
	for (i = 0; i < n; i++)
		fn(v[i].id, v[i].kind, v[i].title, v[i].pid, v[i].started,
		    v[i].left ? "SIGTERM, then SIGKILL" : "SIGTERM", arg);
	free(v);
	return (n);
}
