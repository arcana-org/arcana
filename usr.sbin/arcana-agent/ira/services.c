/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * rc.d services, through service(8) and sysrc(8) so that what the host
 * does is what an administrator at the console would do: the scripts of
 * the rc.d directories, whether rc.conf enables them (<name>_enable as
 * "sysrc -A" has it, which runs no script: "service -e" runs them all,
 * and scripts without a default for their rcvar warn each time; read
 * by libvarconf, as sysrc -A takes seconds, sysrc -A where reading does
 * not tell), whether the enabled ones run ("service x status"), and
 * their rc.conf variables read and written by sysrc(8).  Every program
 * run is a step in the trace with its output.
 *
 * A script's status, rcvar, describe and extracommands run the script
 * as root, and it runs whatever it runs: never for a viewer's request
 * (clearance()).  A viewer is answered from what the collector saw last
 * (each enabled service running or not, its status line and pid, its
 * rcvar once a read said it): a look of its own every COLLECT_S
 * seconds, and every list or read an operator's, an admin's, the
 * console's or the recovery session's request ran; the scripts there
 * and whether each is enabled are read as ever (the rc.d directories,
 * libvarconf, sysrc -A), which runs none.
 *
 * An enabled service rc says does not run is looked at once more: its
 * pidfile and program as its script sets them, and the host's processes
 * (svc_stale()).  Its program running where rc looks for it while the
 * pidfile is missing, or names a pid gone or another program's, the
 * pidfile is stale: rc's stop and restart miss the daemon, and a start
 * makes a second one.  A job (the service-action pidfile) writes it
 * again with the pid of the one process found.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <libutil.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"
#include "varconf.h"

#define	COLLECT_S	300	/* between the collector's looks */

struct script {
	const char	*name;
	const char	*path;
};

/* A service as the collector saw it last. */
struct collected {
	char		 name[65];
	char		 rcvar[65];
	char		 status[256];
	char		 pidfile[MAXPATHLEN];
	char		 stale[512];
	uint32_t	 pid;
	uint32_t	 pidfile_pid;
	bool		 has_running;
	bool		 running;
	bool		 has_pid;
	bool		 has_pidfile_pid;
};

/*
 * A service's pidfile and program, as its script sets them for
 * run_rc_command (svc_rcproc()), and where rc(8) looks for its process.
 */
struct rcproc {
	const char	*pidfile;
	const char	*procname;
	const char	*interp;	/* command_interpreter, or "" */
	int		 jid;		/* 0, or its service jail's */
};

static pthread_mutex_t	 coll_lock = PTHREAD_MUTEX_INITIALIZER;
static struct collected	*coll;
static size_t		 ncoll;
static time_t		 coll_at;

static int	cmp_script(const void *, const void *);
static bool	valid_name(const char *);
static bool	valid_var(const char *);
static void	scan_scripts(struct work *, struct script **, size_t *);
static const struct script *script_find(const struct script *, size_t,
		    const char *);
static int	svc_run(struct work *, const char *, const char *,
		    struct execres *);
static void	svc_status(struct work *, struct arc_service *);
static pid_t	svc_stale(struct work *, struct arc_service *,
		    struct rcproc *);
static void	svc_pidfile(struct work *, const struct script *,
		    struct service_action_rsp *);
static const char *svc_rcvar(struct work *, const char *, const char **);
static bool	rc_yes(const char *);
static bool	enabled_in(const struct execres *, const char *);
static int	sysrc_all(struct work *, struct execres *);
static int	enabled_all(struct work *, const struct script *, size_t,
		    bool *, const char **);
static const char *last_line(struct work *, const char *, size_t);
static void	svc_about(struct work *, const char *,
		    struct service_config_rsp *);
static void	collect_keep(const struct arc_service *, size_t, bool);

static int
cmp_script(const void *a, const void *b)
{

	return (strcmp(((const struct script *)a)->name,
	    ((const struct script *)b)->name));
}

/* Script names: letters, digits, '_', '-', '.'; not hidden. */
static bool
valid_name(const char *s)
{

	if (*s == '\0' || *s == '.' || *s == '-' || strlen(s) > 64)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("_.-", *s) == NULL)
			return (false);
	return (true);
}

/* rc.conf variable names, as sh(1) takes them. */
static bool
valid_var(const char *s)
{

	if (*s == '\0' || isdigit((unsigned char)*s) || strlen(s) > 128)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && *s != '_')
			return (false);
	return (true);
}

/* The executable scripts of the rc.d directories, sorted by name. */
static void
scan_scripts(struct work *w, struct script **outp, size_t *np)
{
	struct script	*v;
	struct dirent	*de;
	struct stat	 st;
	DIR		*d;
	char		*dirs, *it, *dir, *path;
	size_t		 n, cap;
	int		 step;

	v = NULL;
	n = cap = 0;
	if ((dirs = strdup(opts.rc_dirs)) == NULL)
		err(1, "strdup");
	for (it = dirs; (dir = strsep(&it, ":")) != NULL; ) {
		if (*dir == '\0')
			continue;
		step = step_begin(w, STEP_FILE, "read", "scripts in %s",
		    dir);
		if ((d = opendir(dir)) == NULL) {
			step_end(w, step, false, "%s: %s", dir, strerror(errno));
			continue;
		}
		while ((de = readdir(d)) != NULL) {
			if (!valid_name(de->d_name))
				continue;
			path = wfmt(w, "%s/%s", dir, de->d_name);
			if (stat(path, &st) == -1 || !S_ISREG(st.st_mode) ||
			    (st.st_mode & S_IXUSR) == 0)
				continue;
			if (n == cap) {
				cap = cap == 0 ? 64 : cap * 2;
				if ((v = reallocarray(v, cap, sizeof(*v))) ==
				    NULL)
					err(1, "reallocarray");
			}
			v[n].name = wstrdup(w, de->d_name);
			v[n].path = path;
			n++;
		}
		closedir(d);
		step_end(w, step, true, "%zu scripts", n);
	}
	free(dirs);
	if (n > 1)
		qsort(v, n, sizeof(*v), cmp_script);
	*outp = wadopt(w, v);
	*np = n;
}

static const struct script *
script_find(const struct script *v, size_t n, const char *name)
{
	size_t	i;

	for (i = 0; i < n; i++)
		if (strcmp(v[i].name, name) == 0)
			return (&v[i]);
	return (NULL);
}

/* "service <name> <verb>", or "service <verb>" with name NULL. */
static int
svc_run(struct work *w, const char *name, const char *verb,
    struct execres *res)
{
	char	*argv[4];
	int	 i;

	i = 0;
	argv[i++] = (char *)(uintptr_t)opts.service_bin;
	if (name != NULL)
		argv[i++] = (char *)(uintptr_t)name;
	argv[i++] = (char *)(uintptr_t)verb;
	argv[i] = NULL;
	/* What only asks is run in a dry run too. */
	if (strcmp(verb, "status") == 0 || strcmp(verb, "rcvar") == 0 ||
	    strcmp(verb, "enabled") == 0 || strcmp(verb, "describe") == 0 ||
	    strcmp(verb, "extracommands") == 0)
		return (run_read(w, argv, res));
	return (run_exec(w, argv, res));
}

/* The last non-empty line of a program's output, fit for a text. */
static const char *
last_line(struct work *w, const char *s, size_t len)
{
	const char	*p;

	while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r'))
		len--;
	if (len == 0)
		return (NULL);
	for (p = s + len; p > s && p[-1] != '\n'; p--)
		;
	return (wtext(w, wstrndup(w, p, (size_t)(s + len - p))));
}

/* "sysrc -A": every variable with its value, defaults included. */
static int
sysrc_all(struct work *w, struct execres *res)
{
	char	*argv[3];

	argv[0] = (char *)(uintptr_t)opts.sysrc_bin;
	argv[1] = (char *)(uintptr_t)"-A";
	argv[2] = NULL;
	return (run_read(w, argv, res));
}

/*
 * Does "sysrc -A" ("key: value" lines) say <name>_enable is yes?  The
 * rcvar of nearly every script is its name and _enable; the few that
 * differ show as disabled until looked at, where rcvar is asked.
 */
static bool
enabled_in(const struct execres *res, const char *name)
{
	const char	*p, *e;
	size_t		 len;

	len = strlen(name);
	for (p = res->out; p != NULL && *p != '\0'; p = e != NULL ? e + 1 :
	    NULL) {
		e = strchr(p, '\n');
		if (strncmp(p, name, len) == 0 && strncmp(p + len, "_enable: ",
		    9) == 0)
			return (rc_yes(p + len + 9));
	}
	return (false);
}

/* A value that says yes, as enabled_in() reads one. */
static bool
rc_yes(const char *v)
{

	return (strncasecmp(v, "yes", 3) == 0 || strncasecmp(v, "true", 4) ==
	    0 || strncasecmp(v, "on", 2) == 0 || *v == '1');
}

/*
 * on[i]: sc[i]'s <name>_enable says yes, as "sysrc -A" has it: the
 * files read by libvarconf (milliseconds), sysrc -A (seconds) only
 * where reading does not tell, the step saying why.
 */
static int
enabled_all(struct work *w, const struct script *sc, size_t n, bool *on,
    const char **errp)
{
	struct execres	  res;
	const char	**names;
	char		**vals, **paths, err[256], *d;
	size_t		  np, i, k;
	int		  step;

	names = wcalloc(w, n + 1, sizeof(*names));
	for (i = 0; i < n; i++)
		names[i] = wfmt(w, "%s_enable", sc[i].name);
	step = step_begin(w, STEP_FILE, "read", "rc.conf(5): <name>_enable "
	    "of %zu scripts", n);
	err[0] = '\0';
	if (vc_rc_values(opts.root != NULL ? opts.root : "", names, n, &vals,
	    &paths, &np, err, sizeof(err)) == 0) {
		for (i = k = 0; i < n; i++)
			if ((on[i] = vals[i] != NULL && rc_yes(vals[i])))
				k++;
		d = wfmt(w, "%zu of %zu enabled:", k, n);
		for (i = 0; i < np; i++)
			d = wfmt(w, "%s %s", d, paths[i]);
		step_end(w, step, true, "%s", d);
		vc_rc_files_free(vals, n);
		vc_rc_files_free(paths, np);
		return (0);
	}
	if (sysrc_all(w, &res) != 0) {
		step_end(w, step, false, "%s", err);
		*errp = wtext(w, exec_error(w, &res, "sysrc -A"));
		return (-1);
	}
	for (i = 0; i < n; i++)
		on[i] = enabled_in(&res, sc[i].name);
	step_end(w, step, true, "by sysrc -A: %s", err);
	return (0);
}

/* "service <name> status": running, and the pid if it says one. */
static void
svc_status(struct work *w, struct arc_service *s)
{
	struct execres	 res;
	const char	*p;

	svc_run(w, s->name, "status", &res);
	s->has_running = res.status != -1;
	s->running = res.status == 0;
	s->status = last_line(w, res.out, res.outlen);
	if (s->status == NULL)
		s->status = last_line(w, res.err, res.errlen);
	if (s->status != NULL && (p = strstr(s->status, "pid ")) != NULL &&
	    isdigit((unsigned char)p[4])) {
		s->has_pid = true;
		s->pid = (uint32_t)strtoul(p + 4, NULL, 10);
	}
	/* Not running to rc: is its program running all the same?  Not in
	 * a dry run: what it read follows a change it did not make. */
	if (s->has_running && !s->running && s->path != NULL && !w->dry)
		(void)svc_stale(w, s, NULL);
}

/*
 * The script sourced after rc.subr(8), run_rc_command stood in for:
 * what it would check, printed (the pidfile, the program as procname or
 * command, ${name}_program taken as rc.subr takes it, the interpreter,
 * the service jail).  $1 the script, $2 rc.subr.
 */
static const char rc_probe[] =
    "s=$1 r=$2; set -- status; . \"$r\"\n"
    "run_rc_command() {\n"
    "\teval _o=\\$${name}_program; _c=${_o:-$command}\n"
    "\teval _v=\\$${name}_svcj; _j=\n"
    "\tcase $_v in [Yy][Ee][Ss]|[Tt][Rr][Uu][Ee]|[Oo][Nn]|1) "
    "_j=svcj-$name ;; esac\n"
    "\tprintf '%s\\n%s\\n%s\\n%s\\n' \"$pidfile\" \"${procname:-$_c}\" "
    "\"$command_interpreter\" \"$_j\"\n"
    "}\n"
    ". \"$s\"\n";

/*
 * A service's pidfile and program, as its script sets them: its top
 * level runs, as service(8) status runs it, so never for a viewer
 * (clearance()).  False when it has no pidfile.
 */
static bool
svc_rcproc(struct work *w, const char *path, struct rcproc *rp)
{
	struct execres	 res;
	char		*argv[7], *out, *f[4];
	int		 i;

	argv[0] = (char *)(uintptr_t)"/bin/sh";
	argv[1] = (char *)(uintptr_t)"-c";
	argv[2] = (char *)(uintptr_t)rc_probe;
	argv[3] = (char *)(uintptr_t)"sh";
	argv[4] = (char *)(uintptr_t)path;
	argv[5] = (char *)(uintptr_t)opts.rc_subr;
	argv[6] = NULL;
	if (run_read(w, argv, &res) != 0 || res.outlen == 0)
		return (false);
	out = wstrndup(w, res.out, res.outlen);
	for (i = 0; i < 4; i++)
		f[i] = strsep(&out, "\n");
	if (f[3] == NULL || f[0][0] != '/' || f[1][0] == '\0')
		return (false);
	rp->pidfile = f[0];
	rp->procname = f[1];
	rp->interp = f[2];
	rp->jid = 0;
	/* rc.subr's own fallback: no such jail, the host. */
	if (f[3][0] != '\0' && (rp->jid = jail_getid(f[3])) < 0)
		rp->jid = 0;
	return (true);
}

/*
 * What rc.subr's _find_processes matches: the first word of a daemon's
 * command line is procname, its base name, or that as setproctitle(3)
 * and the kernel write it; an interpreted script's line is its
 * interpreter, as its #! line says, then procname.
 */
static bool
rc_match(struct work *w, const char *av, size_t len,
    const struct rcproc *rp)
{
	const char	*bn, *interp;
	char		*line, *p, word[MAXPATHLEN];
	size_t		 n;
	FILE		*fp;

	bn = strrchr(rp->procname, '/') != NULL ? strrchr(rp->procname, '/') +
	    1 : rp->procname;
	line = wstrndup(w, av, len);
	for (p = line; p < line + len; p++)
		if (*p == '\0')
			*p = ' ';
	if (rp->interp[0] == '\0') {
		n = strcspn(line, " \t");
		snprintf(word, sizeof(word), "%.*s", (int)n, line);
		return (strcmp(word, rp->procname) == 0 || strcmp(word, bn) ==
		    0 || (strncmp(word, bn, strlen(bn)) == 0 &&
		    strcmp(word + strlen(bn), ":") == 0) || strcmp(word,
		    wfmt(w, "(%s)", bn)) == 0 || strcmp(word, wfmt(w, "[%s]",
		    bn)) == 0);
	}
	interp = rp->interp;
	if ((fp = fopen(rp->procname, "re")) != NULL) {
		if (fgets(word, sizeof(word), fp) != NULL && word[0] == '#' &&
		    word[1] == '!') {
			word[strcspn(word, "\n")] = '\0';
			p = word + 2 + strspn(word + 2, " \t");
			/* env(1) dropped, for the name it runs. */
			n = strcspn(p, " \t");
			if (n >= 8 && strncmp(p + n - 8, "/bin/env", 8) == 0)
				p += n + strspn(p + n, " \t");
			interp = wstrdup(w, p);
		}
		fclose(fp);
	}
	p = wfmt(w, "%s %s", interp, rp->procname);
	n = strlen(p);
	return (strcmp(line, p) == 0 || (strncmp(line, p, n) == 0 &&
	    line[n] == ' '));
}

/* Process pid's command line, its words NUL-separated; NULL unread. */
static char *
proc_args(struct work *w, pid_t pid, size_t *lenp)
{
	int	 mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ARGS, (int)pid };
	char	*av;
	size_t	 len = 2 * MAXPATHLEN;

	av = wcalloc(w, 1, len + 1);
	if (sysctl(mib, 4, av, &len, NULL, 0) == -1 || len == 0)
		return (NULL);
	*lenp = len;
	return (av);
}

/* Is pid a process of rp's program, where rc looks for it? */
static bool
rc_proc_is(struct work *w, pid_t pid, const struct rcproc *rp)
{
	struct kinfo_proc	*kp;
	const char		*av;
	size_t			 len;
	bool			 is;

	if (pid <= 1 || (kp = kinfo_getproc(pid)) == NULL)
		return (false);
	is = kp->ki_stat != SZOMB && kp->ki_jid == rp->jid;
	free(kp);
	return (is && (av = proc_args(w, pid, &len)) != NULL && rc_match(w,
	    av, len, rp));
}

/*
 * Service s, which rc says does not run: does its program run all the
 * same, where rc looks for it, while its pidfile is missing or names a
 * pid that is gone or another program's?  Its pidfile is then stale,
 * said in s (pidfile, pidfile_pid, pidfile_stale; pid, the process,
 * when there is one alone).  The process found alone, or 0; rpp, the
 * script's pidfile and program.
 */
static pid_t
svc_stale(struct work *w, struct arc_service *s, struct rcproc *rpp)
{
	struct kinfo_proc	*kp, *other;
	struct rcproc		 rp;
	const char		*why, *av, *pids;
	FILE			*fp;
	size_t			 len, n, i, k;
	pid_t			 self, found, fpid;
	long			 v;
	int			 mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_PROC };
	const char		*bn;

	if (!svc_rcproc(w, s->path, &rp))
		return (0);
	if (rpp != NULL)
		*rpp = rp;
	bn = strrchr(rp.procname, '/') != NULL ? strrchr(rp.procname, '/') +
	    1 : rp.procname;
	/* The processes of its program, where rc looks for them. */
	if (sysctl(mib, 3, NULL, &len, NULL, 0) == -1)
		return (0);
	len += len / 4;
	kp = wcalloc(w, 1, len);
	if (sysctl(mib, 3, kp, &len, NULL, 0) == -1)
		return (0);
	self = getpid();
	found = 0;
	pids = "";
	for (i = k = 0; i < len / sizeof(*kp); i++) {
		if (kp[i].ki_pid == self || kp[i].ki_stat == SZOMB ||
		    kp[i].ki_jid != rp.jid || (rp.interp[0] == '\0' &&
		    strncmp(kp[i].ki_comm, bn, COMMLEN) != 0))
			continue;
		if ((av = proc_args(w, kp[i].ki_pid, &n)) == NULL ||
		    !rc_match(w, av, n, &rp))
			continue;
		found = kp[i].ki_pid;
		pids = wfmt(w, "%s%s%d", pids, k > 0 ? ", " : "",
		    (int)found);
		k++;
	}
	if (k == 0)
		return (0);
	/* What its pidfile says. */
	fpid = 0;
	if ((fp = fopen(rp.pidfile, "re")) == NULL)
		why = wfmt(w, "%s is not there", rp.pidfile);
	else {
		if (fscanf(fp, "%ld", &v) == 1 && v > 1 && v <= INT_MAX)
			fpid = (pid_t)v;
		fclose(fp);
		if (fpid == 0)
			why = wfmt(w, "%s names no pid", rp.pidfile);
		else if (rc_proc_is(w, fpid, &rp))
			/* Its own: rc's status failed for another reason. */
			return (0);
		else if ((other = kinfo_getproc(fpid)) == NULL ||
		    other->ki_stat == SZOMB) {
			free(other);
			why = wfmt(w, "%s names pid %d, which is gone",
			    rp.pidfile, (int)fpid);
		} else {
			why = other->ki_jid != 0 ? wfmt(w, "%s names pid %d, "
			    "another program's (%s, in jail %d)", rp.pidfile,
			    (int)fpid, other->ki_comm, other->ki_jid) : wfmt(w,
			    "%s names pid %d, another program's (%s)",
			    rp.pidfile, (int)fpid, other->ki_comm);
			free(other);
		}
	}
	s->pidfile = wtext(w, rp.pidfile);
	if (fpid != 0) {
		s->has_pidfile_pid = true;
		s->pidfile_pid = (uint32_t)fpid;
	}
	if (k == 1) {
		s->has_pid = true;
		s->pid = (uint32_t)found;
		s->pidfile_stale = wtext(w, wfmt(w, "%s, while %s runs as "
		    "pid %d", why, rp.procname, (int)found));
		return (found);
	}
	s->has_pid = false;
	s->pidfile_stale = wtext(w, wfmt(w, "%s, while %zu processes of %s "
	    "run (pids %s): which is the service's is not known", why, k,
	    rp.procname, pids));
	return (0);
}

/*
 * The service's stale pidfile written again with the pid of its
 * program's process, the one svc_stale() found alone, checked again
 * just before (where rc looks for it, its command line rc's match):
 * a file of the same mode next to it, renamed over it.  Refused when
 * rc says it runs, when nothing of it runs or more than one process
 * does, and when the pidfile is not a plain file.
 */
static void
svc_pidfile(struct work *w, const struct script *sc,
    struct service_action_rsp *rsp)
{
	struct arc_service	 s;
	struct rcproc		 rp;
	struct stat		 st;
	const char		*tmp;
	char			 line[32];
	pid_t			 pid;
	mode_t			 mode;
	int			 fd, step;
	ssize_t			 n;

	memset(&s, 0, sizeof(s));
	s.name = sc->name;
	s.path = sc->path;
	memset(&rp, 0, sizeof(rp));
	svc_status(w, &s);
	if (s.running) {
		rsp->error = wfmt(w, "service %s status says it runs: its "
		    "pidfile is not stale", sc->name);
		return;
	}
	pid = s.pidfile_stale != NULL ? svc_stale(w, &s, &rp) : 0;
	if (s.pidfile_stale == NULL) {
		rsp->error = wfmt(w, "%s does not run, as far as its pidfile "
		    "and its processes tell: nothing to write; start it",
		    sc->name);
		return;
	}
	if (pid == 0) {
		rsp->error = wfmt(w, "%s; write the right pid in %s yourself, "
		    "or stop those processes and start the service",
		    s.pidfile_stale, s.pidfile);
		return;
	}
	step = step_begin(w, STEP_FILE, "write", "%s: pid %d", rp.pidfile,
	    (int)pid);
	if (work_dry(w, step)) {
		rsp->ok = true;
		return;
	}
	mode = 0644;
	if (lstat(rp.pidfile, &st) == 0) {
		if (!S_ISREG(st.st_mode)) {
			step_end(w, step, false, "not a plain file");
			rsp->error = wfmt(w, "%s is not a plain file: not "
			    "written", rp.pidfile);
			return;
		}
		mode = st.st_mode & 0777;
	}
	/* The process checked again, now: still its program's. */
	if (!rc_proc_is(w, pid, &rp)) {
		step_end(w, step, false, "pid %d is gone", (int)pid);
		rsp->error = wfmt(w, "pid %d is no longer %s's: not written",
		    (int)pid, rp.procname);
		return;
	}
	tmp = wfmt(w, "%s.arcana", rp.pidfile);
	snprintf(line, sizeof(line), "%d\n", (int)pid);
	(void)unlink(tmp);
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
	    O_CLOEXEC, mode)) == -1) {
		step_end(w, step, false, "%s: %s", tmp, strerror(errno));
		rsp->error = wfmt(w, "%s: %s", tmp, strerror(errno));
		return;
	}
	n = write(fd, line, strlen(line));
	(void)fchmod(fd, mode);
	if (n != (ssize_t)strlen(line) || fsync(fd) == -1 || close(fd) == -1 ||
	    rename(tmp, rp.pidfile) == -1) {
		step_end(w, step, false, "%s", strerror(errno));
		rsp->error = wfmt(w, "%s: %s", rp.pidfile, strerror(errno));
		(void)unlink(tmp);
		return;
	}
	step_end(w, step, true, "%s's pid, %d", rp.procname, (int)pid);
	rsp->ok = true;
}

/*
 * Whether a service runs and whether it is enabled, now: what a change
 * made in safe mode is put back to.
 */
void
service_state(struct work *w, const char *name, bool *running, bool *enabled)
{
	struct arc_service	s;
	struct execres		res;

	memset(&s, 0, sizeof(s));
	s.name = name;
	svc_status(w, &s);
	*running = s.running;
	/* rc.subr's own answer, by the script's real rcvar: one quick run,
	 * not sysrc -A's every variable with the defaults (seconds). */
	*enabled = svc_run(w, name, "enabled", &res) == 0;
}

/* "service <name> rcvar": the first variable it names, or NULL. */
static const char *
svc_rcvar(struct work *w, const char *name, const char **errp)
{
	struct execres	 res;
	const char	*p, *e;

	if (svc_run(w, name, "rcvar", &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "service"));
		return (NULL);
	}
	for (p = res.out; *p != '\0'; p = e != NULL ? e + 1 : p + strlen(p)) {
		e = strchr(p, '\n');
		if (*p != '#' && isalpha((unsigned char)*p) &&
		    strchr(p, '=') != NULL && (e == NULL || strchr(p, '=') < e))
			return (wstrndup(w, p, (size_t)(strchr(p, '=') - p)));
	}
	*errp = wfmt(w, "%s has no rcvar; it cannot be enabled or disabled",
	    name);
	return (NULL);
}

/* The scripts there are, with their names and paths alone: running's. */
void
service_scripts(struct work *w, struct services_rsp *rsp)
{
	struct arc_service	*v;
	struct script		*sc;
	size_t			 n, i;

	rsp->has_ok = true;
	rsp->ok = true;
	scan_scripts(w, &sc, &n);
	v = wcalloc(w, n + 1, sizeof(*v));
	for (i = 0; i < n; i++) {
		v[i].name = wtext(w, sc[i].name);
		v[i].path = wtext(w, sc[i].path);
	}
	rsp->services.v = v;
	rsp->services.n = n;
}

const char *
service_rcvar(struct work *w, const char *name, const char **errp)
{

	return (svc_rcvar(w, name, errp));
}

bool
valid_var_name(const char *s)
{

	return (valid_var(s));
}

int
do_services(struct work *w, struct services_rsp *rsp)
{
	struct arc_service	*v;
	struct script		*sc;
	const char		*e;
	size_t			 n, i;
	bool			*on;

	rsp->has_ok = true;
	rsp->ok = true;
	scan_scripts(w, &sc, &n);
	on = wcalloc(w, n + 1, sizeof(*on));
	if (enabled_all(w, sc, n, on, &e) != 0) {
		rsp->ok = false;
		rsp->error = e;
		return (0);
	}
	v = wcalloc(w, n + 1, sizeof(*v));
	for (i = 0; i < n; i++) {
		v[i].name = wtext(w, sc[i].name);
		v[i].path = wtext(w, sc[i].path);
		v[i].has_enabled = true;
		v[i].enabled = on[i];
		if (v[i].enabled)
			svc_status(w, &v[i]);
	}
	rsp->services.v = v;
	rsp->services.n = n;
	collect_keep(v, n, true);
	return (0);
}

/* The service as it is now, for a reply. */
static struct arc_service *
svc_current(struct work *w, const struct script *sc)
{
	struct arc_service	*s;
	const char		*e;
	bool			 on;

	s = wcalloc(w, 1, sizeof(*s));
	s->name = wtext(w, sc->name);
	s->path = wtext(w, sc->path);
	if (enabled_all(w, sc, 1, &on, &e) == 0) {
		s->has_enabled = true;
		s->enabled = on;
	}
	svc_status(w, s);
	return (s);
}

int
do_service_action(struct work *w, const char *name, uint8_t action,
    struct service_action_rsp *rsp)
{
	const struct script	*sc;
	struct script		*all;
	struct execres		 res;
	const char		*verb, *rcvar, *e;
	char			*argv[3];
	size_t			 n;

	rsp->has_ok = true;
	rsp->ok = false;
	/* Whoever asks (the operation, a YANG action): service(8) gets it. */
	if (name == NULL || !valid_service(name)) {
		rsp->error = "invalid service name";
		return (0);
	}
	scan_scripts(w, &all, &n);
	if ((sc = script_find(all, n, name)) == NULL) {
		rsp->error = wfmt(w, "no rc.d script '%s' in %s", name,
		    opts.rc_dirs);
		return (0);
	}
	switch (action) {
	case ARC_SERVICE_ACTION_ENABLE:
	case ARC_SERVICE_ACTION_DISABLE:
		if ((rcvar = svc_rcvar(w, name, &e)) == NULL) {
			rsp->error = e;
			goto out;
		}
		argv[0] = (char *)(uintptr_t)opts.sysrc_bin;
		argv[1] = wfmt(w, "%s=%s", rcvar,
		    action == ARC_SERVICE_ACTION_ENABLE ? "YES" : "NO");
		argv[2] = NULL;
		if (run_exec(w, argv, &res) == 0)
			rsp->ok = true;
		else
			rsp->error = wtext(w, exec_error(w, &res, "sysrc"));
		break;
	case ARC_SERVICE_ACTION_PIDFILE:
		svc_pidfile(w, sc, rsp);
		break;
	default:
		verb = action == ARC_SERVICE_ACTION_START ? "start" :
		    action == ARC_SERVICE_ACTION_STOP ? "stop" :
		    action == ARC_SERVICE_ACTION_RESTART ? "restart" : "reload";
		/*
		 * The daemon's own service, stopped or restarted: service(8)
		 * waits for the daemon to go, and the daemon would wait for
		 * service(8), which it runs, to end.  So it is handed to a
		 * process of its own, and this is answered first.
		 */
		if (strcmp(name, OWN_SERVICE) == 0 && (action ==
		    ARC_SERVICE_ACTION_STOP || action ==
		    ARC_SERVICE_ACTION_RESTART)) {
			n = (size_t)step_begin(w, STEP_DAEMON,
			    "own service", "service %s %s: arcana-agent %s",
			    name, verb, action == ARC_SERVICE_ACTION_STOP ?
			    "stops" : "restarts");
			if (work_dry(w, (int)n)) {
				rsp->ok = true;
				break;
			}
			service_detached(name, verb);
			step_end(w, (int)n, true, "handed to a process of its "
			    "own: this daemon is stopped by it in a moment");
			rsp->ok = true;
			break;
		}
		if (svc_run(w, name, verb, &res) == 0)
			rsp->ok = true;
		else
			rsp->error = wtext(w, exec_error(w, &res, "service"));
		break;
	}
out:
	rsp->service_result = svc_current(w, sc);
	return (0);
}

/* What service name's script says of itself, and its extra commands. */
static void
svc_about(struct work *w, const char *name, struct service_config_rsp *rsp)
{
	struct execres	  res;
	const char	**cmds;
	char		 *copy, *it, *tok;
	size_t		  ncmd;

	if (svc_run(w, name, "describe", &res) == 0 && res.outlen > 0)
		rsp->description = wtext(w, wstrndup(w, res.out, res.outlen -
		    (res.out[res.outlen - 1] == '\n' ? 1 : 0)));
	cmds = NULL;
	ncmd = 0;
	if (svc_run(w, name, "extracommands", &res) == 0 && res.outlen > 0) {
		copy = wstrndup(w, res.out, res.outlen);
		for (it = copy; (tok = strsep(&it, " \t\n")) != NULL; ) {
			if (*tok == '\0')
				continue;
			if ((cmds = reallocarray(cmds, ncmd + 1,
			    sizeof(*cmds))) == NULL)
				err(1, "reallocarray");
			cmds[ncmd++] = wtext(w, tok);
		}
	}
	rsp->commands.v = wadopt(w, cmds);
	rsp->commands.n = ncmd;
}

/*
 * The variables of a service: those in rc.conf whose name starts with
 * the script's name or with its rcvar's stem, as "sysrc -a" lists them.
 * Variables in the request are set (sysrc key=value) or unset (sysrc -x
 * key) first; only such names are accepted.
 */
int
do_service_config(struct work *w, const struct service_config_req *rq,
    struct service_config_rsp *rsp)
{
	const struct script	*sc;
	struct script		*all;
	struct arc_variable	*vars;
	struct execres		 res;
	const char		*name, *rcvar, *stem, *e, *p, *nl, *sep;
	char			*argv[4];
	size_t			 n, i, nv, stemlen, namelen;
	int			 rc;

	name = rq->service;
	rsp->has_ok = true;
	rsp->ok = false;
	scan_scripts(w, &all, &n);
	sc = script_find(all, n, name);
	if (sc == NULL) {
		rsp->error = wfmt(w, "no rc.d script '%s' in %s", name,
		    opts.rc_dirs);
		return (0);
	}
	/* The rcvar tells the prefix: jail_enable -> jail_*. */
	rcvar = svc_rcvar(w, name, &e);
	stem = NULL;
	stemlen = 0;
	if (rcvar != NULL && (p = strstr(rcvar, "_enable")) != NULL &&
	    p[7] == '\0') {
		stem = rcvar;
		stemlen = (size_t)(p - rcvar) + 1;
	}
	namelen = strlen(name);

	/* All of them are looked at before the first is written. */
	for (i = 0; i < rq->variables.n; i++) {
		const struct arc_variable *var = &rq->variables.v[i];

		if (var->key == NULL || !valid_var(var->key) ||
		    !((strncmp(var->key, name, namelen) == 0 &&
		    var->key[namelen] == '_') || (stem != NULL &&
		    strncmp(var->key, stem, stemlen) == 0))) {
			rsp->error = wfmt(w, "'%s' is not a variable of %s",
			    var->key != NULL ? var->key : "", name);
			goto out;
		}
		if (!var->remove && !rc_value_ok(var->value)) {
			rsp->error = wfmt(w, "the value of %s has a quote, $, "
			    "` or \\: rc.conf would read it as more than a "
			    "value", var->key);
			goto out;
		}
	}
	for (i = 0; i < rq->variables.n; i++) {
		const struct arc_variable *var = &rq->variables.v[i];

		argv[0] = (char *)(uintptr_t)opts.sysrc_bin;
		if (var->remove) {
			argv[1] = (char *)(uintptr_t)"-x";
			argv[2] = (char *)(uintptr_t)var->key;
			argv[3] = NULL;
		} else {
			argv[1] = wfmt(w, "%s=%s", var->key,
			    var->value != NULL ? var->value : "");
			argv[2] = NULL;
		}
		if (run_exec(w, argv, &res) != 0 && !(var->remove &&
		    res.status == 1)) {
			rsp->error = wtext(w, exec_error(w, &res, "sysrc"));
			goto out;
		}
	}

	/* What rc.conf holds now. */
	argv[0] = (char *)(uintptr_t)opts.sysrc_bin;
	argv[1] = (char *)(uintptr_t)"-a";
	argv[2] = NULL;
	/* Every variable's value: no trace's, which every role reads. */
	exec_set_secret(true);
	rc = run_exec(w, argv, &res);
	exec_set_secret(false);
	if (rc != 0) {
		rsp->error = wtext(w, exec_error(w, &res, "sysrc -a"));
		goto out;
	}
	vars = NULL;
	nv = 0;
	for (p = res.out; *p != '\0'; p = nl != NULL ? nl + 1 :
	    p + strlen(p)) {
		nl = strchr(p, '\n');
		if ((sep = strstr(p, ": ")) == NULL || (nl != NULL && sep > nl))
			continue;
		if (!((strncmp(p, name, namelen) == 0 && p[namelen] == '_') ||
		    (stem != NULL && strncmp(p, stem, stemlen) == 0)))
			continue;
		if ((vars = reallocarray(vars, nv + 1, sizeof(*vars))) == NULL)
			err(1, "reallocarray");
		memset(&vars[nv], 0, sizeof(vars[nv]));
		vars[nv].key = wtext(w, wstrndup(w, p, (size_t)(sep - p)));
		vars[nv].value = wtext(w, wstrndup(w, sep + 2, nl != NULL ?
		    (size_t)(nl - sep - 2) : strlen(sep + 2)));
		nv++;
	}
	rsp->variables.v = wadopt(w, vars);
	rsp->variables.n = nv;
	svc_about(w, name, rsp);
	rsp->ok = true;
out:
	rsp->service_result = svc_current(w, sc);
	return (0);
}

/*
 * A service as it is now, without the others' status: enabled by
 * rc.subr's own answer (its rcvar, the defaults included), running or
 * not, what it says of itself and its extra commands.
 */
int
service_read(struct work *w, const char *name, struct service_config_rsp *rsp)
{
	const struct script	*sc;
	struct script		*all;
	struct arc_service	*s;
	struct execres		 res;
	const char		*e;
	size_t			 n;

	rsp->has_ok = true;
	rsp->ok = false;
	if (name == NULL || !valid_service(name)) {
		rsp->error = "invalid service name";
		return (0);
	}
	scan_scripts(w, &all, &n);
	if ((sc = script_find(all, n, name)) == NULL) {
		rsp->error = wfmt(w, "no rc.d script '%s' in %s", name,
		    opts.rc_dirs);
		return (0);
	}
	s = wcalloc(w, 1, sizeof(*s));
	s->name = wtext(w, sc->name);
	s->path = wtext(w, sc->path);
	s->rcvar = svc_rcvar(w, name, &e);
	s->has_enabled = true;
	s->enabled = svc_run(w, name, "enabled", &res) == 0;
	svc_status(w, s);
	rsp->service_result = s;
	svc_about(w, name, rsp);
	rsp->ok = true;
	collect_keep(s, 1, false);
	return (0);
}

/*
 * What a list or a read saw (v, n of them) kept for a viewer's
 * requests: each one's running, status line, pid and rcvar; with all,
 * v is every enabled service, and one not among them is forgotten.
 */
static void
collect_keep(const struct arc_service *v, size_t n, bool all)
{
	struct collected	*c, *nc;
	size_t			 i, k, m;

	pthread_mutex_lock(&coll_lock);
	if (all) {
		/* Kept: those of v, and their rcvars said before. */
		if ((nc = calloc(n + 1, sizeof(*nc))) == NULL) {
			pthread_mutex_unlock(&coll_lock);
			return;
		}
		for (i = m = 0; i < n; i++) {
			if (!v[i].has_enabled || !v[i].enabled)
				continue;
			(void)strlcpy(nc[m].name, v[i].name, sizeof(nc[m].name));
			for (k = 0; k < ncoll; k++)
				if (strcmp(coll[k].name, v[i].name) == 0)
					(void)strlcpy(nc[m].rcvar, coll[k].rcvar,
					    sizeof(nc[m].rcvar));
			m++;
		}
		free(coll);
		coll = nc;
		ncoll = m;
		coll_at = time(NULL);
	}
	for (i = 0; i < n; i++) {
		if (all && (!v[i].has_enabled || !v[i].enabled))
			continue;
		for (k = 0; k < ncoll && strcmp(coll[k].name, v[i].name) != 0;
		    k++)
			;
		if (k == ncoll) {
			if ((nc = reallocarray(coll, ncoll + 1,
			    sizeof(*coll))) == NULL)
				break;
			coll = nc;
			memset(&coll[ncoll], 0, sizeof(coll[ncoll]));
			(void)strlcpy(coll[ncoll].name, v[i].name,
			    sizeof(coll[ncoll].name));
			ncoll++;
		}
		c = &coll[k];
		c->has_running = v[i].has_running;
		c->running = v[i].running;
		c->has_pid = v[i].has_pid;
		c->pid = v[i].pid;
		(void)strlcpy(c->status, v[i].status != NULL ? v[i].status : "",
		    sizeof(c->status));
		(void)strlcpy(c->pidfile, v[i].pidfile != NULL ? v[i].pidfile :
		    "", sizeof(c->pidfile));
		(void)strlcpy(c->stale, v[i].pidfile_stale != NULL ?
		    v[i].pidfile_stale : "", sizeof(c->stale));
		c->has_pidfile_pid = v[i].has_pidfile_pid;
		c->pidfile_pid = v[i].pidfile_pid;
		if (v[i].rcvar != NULL)
			(void)strlcpy(c->rcvar, v[i].rcvar, sizeof(c->rcvar));
	}
	pthread_mutex_unlock(&coll_lock);
}

/* Service s as the collector saw it last, into s; true when it did.
 * The trace says how old it is. */
static bool
collected_of(struct work *w, struct arc_service *s)
{
	size_t	k;
	bool	seen = false;
	int	step;

	step = step_begin(w, STEP_DAEMON, "collected", "%s, as last seen: no "
	    "rc.d script run for a viewer", s->name);
	pthread_mutex_lock(&coll_lock);
	for (k = 0; k < ncoll; k++) {
		if (strcmp(coll[k].name, s->name) != 0)
			continue;
		s->has_running = coll[k].has_running;
		s->running = coll[k].running;
		s->has_pid = coll[k].has_pid;
		s->pid = coll[k].pid;
		if (coll[k].status[0] != '\0')
			s->status = wtext(w, coll[k].status);
		if (coll[k].pidfile[0] != '\0')
			s->pidfile = wtext(w, coll[k].pidfile);
		if (coll[k].stale[0] != '\0')
			s->pidfile_stale = wtext(w, coll[k].stale);
		s->has_pidfile_pid = coll[k].has_pidfile_pid;
		s->pidfile_pid = coll[k].pidfile_pid;
		if (coll[k].rcvar[0] != '\0')
			s->rcvar = wtext(w, coll[k].rcvar);
		seen = coll[k].has_running;
		break;
	}
	if (coll_at > 0)
		step_end(w, step, true, "%jd s ago", (intmax_t)(time(NULL) -
		    coll_at));
	else
		step_end(w, step, true, "not seen yet");
	pthread_mutex_unlock(&coll_lock);
	return (seen);
}

/* The list for a viewer: the scripts and whether each is enabled, as
 * ever; running from what was collected (collected_of()). */
int
do_services_collected(struct work *w, struct services_rsp *rsp)
{
	struct arc_service	*v;
	struct script		*sc;
	const char		*e;
	size_t			 n, i;
	bool			*on;

	rsp->has_ok = true;
	rsp->ok = true;
	scan_scripts(w, &sc, &n);
	on = wcalloc(w, n + 1, sizeof(*on));
	if (enabled_all(w, sc, n, on, &e) != 0) {
		rsp->ok = false;
		rsp->error = e;
		return (0);
	}
	v = wcalloc(w, n + 1, sizeof(*v));
	for (i = 0; i < n; i++) {
		v[i].name = wtext(w, sc[i].name);
		v[i].path = wtext(w, sc[i].path);
		v[i].has_enabled = true;
		v[i].enabled = on[i];
		if (v[i].enabled)
			(void)collected_of(w, &v[i]);
	}
	rsp->services.v = v;
	rsp->services.n = n;
	return (0);
}

/* A service read for a viewer: as do_services_collected() has it, no
 * description nor extra commands (the script's to say, run). */
int
service_read_collected(struct work *w, const char *name,
    struct service_config_rsp *rsp)
{
	const struct script	*sc;
	struct script		*all;
	struct arc_service	*s;
	const char		*e;
	size_t			 n;
	bool			 on;

	rsp->has_ok = true;
	rsp->ok = false;
	if (name == NULL || !valid_service(name)) {
		rsp->error = "invalid service name";
		return (0);
	}
	scan_scripts(w, &all, &n);
	if ((sc = script_find(all, n, name)) == NULL) {
		rsp->error = wfmt(w, "no rc.d script '%s' in %s", name,
		    opts.rc_dirs);
		return (0);
	}
	s = wcalloc(w, 1, sizeof(*s));
	s->name = wtext(w, sc->name);
	s->path = wtext(w, sc->path);
	if (enabled_all(w, sc, 1, &on, &e) == 0) {
		s->has_enabled = true;
		s->enabled = on;
	}
	(void)collected_of(w, s);
	rsp->service_result = s;
	rsp->ok = true;
	return (0);
}

/* The collector: every COLLECT_S, the list as an operator's read has
 * it, kept (collect_keep()). */
static void *
collector(void *arg __unused)
{
	struct services_rsp	 r;
	struct work		 w;

	for (;;) {
		(void)sleep(COLLECT_S);
		work_init(&w);
		w.nice = true;
		memset(&r, 0, sizeof(r));
		(void)do_services(&w, &r);
		work_free(&w);
	}
	return (NULL);
}

void
services_collect_start(void)
{
	pthread_t	tid;
	int		error;

	if ((error = pthread_create(&tid, NULL, collector, NULL)) != 0)
		logmsg(LOG_ERR, "services: no collector: %s", strerror(error));
	else
		(void)pthread_detach(tid);
}

