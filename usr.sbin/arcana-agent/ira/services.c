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
 * Between those looks a service started or stopped by hand is noticed
 * as it happens, by one thread on one kqueue(2) (svc_watcher()), and
 * only that service's status is run again:
 *
 * - a running one's main process (rc's status line's pid, or else its
 *   pidfile's) is watched for its exit (EVFILT_PROC, NOTE_EXIT);
 * - a stopped one is looked at by its pidfile alone (a file read, and
 *   the process it names checked as rc checks it, rc_proc_is()): when
 *   the host's processes start (gula/hostwatch.c's tick says so,
 *   services_procs_started()), each second for a few seconds after
 *   that or after an exit (a daemon writes its pidfile a moment after
 *   it forks), and every RECHECK_S seconds for a start nothing else
 *   tells of (one the agent's own children made, which hostwatch
 *   does not count);
 * - one that says no pid while it runs, or has no pidfile while it is
 *   stopped, has its status run every UNKNOWN_S seconds.
 *
 * Its pidfile and program (svc_rcproc(), which runs the script's top
 * level) are read once a COLLECT_S, and only for a service that needs
 * them.  Whatever look saw a service's state change (started, stopped,
 * another pid) says so in the event service-state, which the console's
 * stream carries to every page that shows the host.
 *
 * An enabled service rc says does not run is looked at once more: its
 * pidfile and program as its script sets them, and the host's processes
 * (svc_stale()).  Its program running where rc looks for it while the
 * pidfile is missing, or names a pid gone or another program's, the
 * pidfile is stale: rc's stop and restart miss the daemon, and a start
 * makes a second one.  A job (the service-action pidfile) writes it
 * again with the pid of the one process found.
 *
 * A running jail's services are the jail's own, worked on from the host
 * with nothing installed in it, for a work whose jail is set
 * (scope_enter_jail(), by the job or the read that names the jail):
 *
 * - its scripts, those of its /etc/rc.d and /usr/local/etc/rc.d, and
 *   whether each is enabled, are read by this program again as a helper
 *   attached to the jail (rc_scripts_helper()), where the jail's root
 *   is "/" and no link of the jail's leads out of it; reading not
 *   telling (a command in its rc.conf), by sysrc -j <jid> -A;
 * - a script runs in the jail alone, by the jail's own service(8):
 *   service -j <jid> <name> <verb> (jexec(8)), and rc.conf is written
 *   there by sysrc -j <jid>, never by Arcana's file of the host's;
 * - a jail whose root is the host's ("/": a service jail rc.subr made)
 *   has the host's scripts, and is not looked at as one of its own.
 *
 * What the collector saw is kept by the jail and the name, the jails
 * that run looked at with the host each COLLECT_S; the watcher watches
 * a running one's process as the host's (its pid is the host's too),
 * and the event service-state says the jail; a stopped one is looked at
 * by its status every UNKNOWN_S.  A jail's stale pidfile is looked for
 * in the jail: its script's pidfile and program read by the probe run
 * there by the jail's own sh and rc.subr (jexec(8)), its processes and
 * its pidfile by the helper attached to it (rc_stale_helper()), which
 * sees the jail's processes alone and its files as the jail has them;
 * the pidfile is written beneath the jail's root, never through a link.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <ctype.h>
#include <dirent.h>
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
#define	FIRST_S		10	/* the collector's first look, after start */
#define	RECHECK_S	15	/* the stopped ones' pidfiles looked at */
#define	UNKNOWN_S	60	/* status of those no pid or pidfile tells of */
#define	HOT_LOOKS	3	/* seconds of looks after a start or an exit */
#define	JAIL_RC_DIRS	"/etc/rc.d:/usr/local/etc/rc.d"	/* jails' */

struct script {
	const char	*name;
	const char	*path;
	int		 on;	/* a jail's: enabled 1, 0, -1 not read */
};

/* A service as the collector saw it last: the host's, jail "". */
struct collected {
	char		 jail[MAXHOSTNAMELEN];
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
	uint32_t	 quiet;		/* a look saw nothing new at it */
	/* Its script's pidfile and program (svc_rcproc()), the watcher's:
	 * RP_NONE when it has no pidfile, read at rp_at. */
	int		 rp_state;
	time_t		 rp_at;
	char		 rp_pidfile[MAXPATHLEN];
	char		 rp_procname[MAXPATHLEN];
	char		 rp_interp[MAXPATHLEN];
	int		 rp_jid;
};

enum { RP_UNREAD, RP_READ, RP_NONE };

/* The watcher's kevents: its two pokes, its two timers. */
enum { K_REARM = 1, K_STARTED, K_RECHECK, K_HOT };

/*
 * A service's pidfile and program, as its script sets them for
 * run_rc_command (svc_rcproc()), and where rc(8) looks for its process.
 */
struct rcproc {
	const char	*pidfile;
	const char	*procname;
	const char	*interp;	/* command_interpreter, or "" */
	const char	*svcj;		/* its service jail's name, or "" */
	int		 jid;		/* 0, or its service jail's */
};

static pthread_mutex_t	 coll_lock = PTHREAD_MUTEX_INITIALIZER;
static struct collected	*coll;
static size_t		 ncoll;
static time_t		 coll_at;
/* The watcher's kqueue(2), -1 none: poked by collect_keep() and by
 * services_procs_started(). */
static int		 svc_kq = -1;

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
static pid_t	stale_find(struct work *, const struct rcproc *,
		    struct arc_service *);
static pid_t	jail_stale(struct work *, const struct rcproc *,
		    struct arc_service *);
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
static void	collect_keep(const char *, const struct arc_service *,
		    size_t, bool);
static void	jail_scripts(struct work *, struct script **, size_t *);

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

	/* A jail's, read in the jail. */
	if (w->jail != NULL) {
		jail_scripts(w, outp, np);
		return;
	}
	v = NULL;
	n = cap = 0;
	dirs = wstrdup(w, opts.rc_dirs);
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
			v = wgrow(w, v, n, &cap, sizeof(*v));
			v[n].name = wstrdup(w, de->d_name);
			v[n].path = path;
			v[n].on = -1;
			n++;
		}
		closedir(d);
		step_end(w, step, true, "%zu scripts", n);
	}
	if (n > 1)
		qsort(v, n, sizeof(*v), cmp_script);
	*outp = v;
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

/*
 * The scripts of the jail w works in, and whether each is enabled: by
 * the helper attached to it (rc_scripts_helper()), its lines "name path
 * yes|no", or "?" for all after a first "#unread why".
 */
static void
jail_scripts(struct work *w, struct script **outp, size_t *np)
{
	struct execres	 res;
	struct script	*v;
	char		*out, *line, *f[3];
	size_t		 n, cap;
	int		 i;

	v = NULL;
	n = cap = 0;
	if (run_read(w, helper_argv(w, "rc-scripts", 0, NULL), &res) == 0 &&
	    res.out != NULL) {
		out = wstrndup(w, res.out, res.outlen);
		while ((line = strsep(&out, "\n")) != NULL) {
			if (line[0] == '#' || line[0] == '\0')
				continue;
			for (i = 0; i < 3; i++)
				f[i] = strsep(&line, " ");
			if (f[2] == NULL || !valid_name(f[0]) || f[1][0] != '/')
				continue;
			v = wgrow(w, v, n, &cap, sizeof(*v));
			v[n].name = f[0];
			v[n].path = f[1];
			v[n].on = strcmp(f[2], "yes") == 0 ? 1 : strcmp(f[2],
			    "no") == 0 ? 0 : -1;
			n++;
		}
	}
	*outp = v;
	*np = n;
}

/* No such script, where w looks for them. */
static const char *
no_script(struct work *w, const char *name)
{

	if (w->jail != NULL)
		return (wfmt(w, "the jail %s has no rc.d script '%s' (in its "
		    "%s)", w->jail, name, JAIL_RC_DIRS));
	return (wfmt(w, "no rc.d script '%s' in %s", name, opts.rc_dirs));
}

static int
cmp_named(const void *a, const void *b)
{

	return (strcmp(*(char *const *)a, *(char *const *)b));
}

/*
 * The helper's rc-scripts (scope_helper(), attached to the jail): the
 * executable scripts of the jail's rc.d directories, sorted, each with
 * whether its <name>_enable says yes in the files the jail's rc(8)
 * reads (libvarconf), read here, where the jail's root is "/" and a
 * link of the jail's leads nowhere out of it.  A line each, "name path
 * yes|no"; when reading does not tell (a command in its rc.conf), a
 * first line "#unread why" and "?" for each.
 */
int
rc_scripts_helper(int argc, char **argv)
{
	struct dirent	 *de;
	struct stat	  st;
	DIR		 *d;
	char		**v, **names, **vals, **files, err[256], *dirs, *it,
			 *dir, *e;
	size_t		  n, cap, nf, i;
	bool		  read;

	(void)argv;
	if (argc != 1)
		return (2);
	v = NULL;
	n = cap = 0;
	if ((dirs = strdup(JAIL_RC_DIRS)) == NULL)
		return (1);
	for (it = dirs; (dir = strsep(&it, ":")) != NULL; ) {
		if ((d = opendir(dir)) == NULL)
			continue;
		while ((de = readdir(d)) != NULL) {
			if (!valid_name(de->d_name) || fstatat(dirfd(d),
			    de->d_name, &st, 0) == -1 || !S_ISREG(st.st_mode) ||
			    (st.st_mode & S_IXUSR) == 0)
				continue;
			if (n == cap) {
				cap = cap * 2 + 32;
				if ((v = reallocarray(v, cap, sizeof(*v))) ==
				    NULL)
					return (1);
			}
			/* "name path": the name first, for the sort. */
			if (asprintf(&v[n], "%s %s/%s", de->d_name, dir,
			    de->d_name) == -1)
				return (1);
			n++;
		}
		closedir(d);
	}
	free(dirs);
	if (n > 1)
		qsort(v, n, sizeof(*v), cmp_named);
	if ((names = calloc(n + 1, sizeof(*names))) == NULL)
		return (1);
	for (i = 0; i < n; i++)
		if (asprintf(&names[i], "%.*s_enable", (int)strcspn(v[i], " "),
		    v[i]) == -1)
			return (1);
	err[0] = '\0';
	read = vc_rc_values("", (const char *const *)names, n, &vals, &files,
	    &nf, err, sizeof(err)) == 0;
	if (!read) {
		for (e = err; *e != '\0'; e++)
			if (*e == '\n')
				*e = ' ';
		printf("#unread %s\n", err);
	}
	for (i = 0; i < n; i++)
		printf("%s %s\n", v[i], !read ? "?" : vals[i] != NULL &&
		    rc_yes(vals[i]) ? "yes" : "no");
	if (read) {
		vc_rc_files_free(vals, n);
		vc_rc_files_free(files, nf);
	}
	return (fflush(stdout) == 0 ? 0 : 1);
}

/*
 * "service <name> <verb>", or "service <verb>" with name NULL; in the
 * jail w works in, by its own service(8): service -j <jid> (jexec(8)).
 */
static int
svc_run(struct work *w, const char *name, const char *verb,
    struct execres *res)
{
	char	*argv[6];
	int	 i;

	i = 0;
	argv[i++] = (char *)(uintptr_t)opts.service_bin;
	if (w->jail != NULL) {
		argv[i++] = (char *)(uintptr_t)"-j";
		argv[i++] = wfmt(w, "%d", w->jid);
	}
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

	/* A jail's, as its helper read them; else by sysrc -j -A. */
	if (w->jail != NULL) {
		for (i = 0; i < n && sc[i].on >= 0; i++)
			on[i] = sc[i].on == 1;
		if (i == n)
			return (0);
		step = step_begin(w, STEP_FILE, "read", "the jail %s's "
		    "rc.conf: <name>_enable of %zu scripts", w->jail, n);
		if (sysrc_all(w, &res) != 0) {
			step_end(w, step, false, "sysrc -A");
			*errp = wtext(w, exec_error(w, &res, "sysrc -A"));
			return (-1);
		}
		for (i = 0; i < n; i++)
			on[i] = enabled_in(&res, sc[i].name);
		step_end(w, step, true, "by sysrc -j -A: reading did not tell");
		return (0);
	}
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
 * (clearance()).  A jail's runs in the jail, by its own sh and rc.subr
 * (jexec(8)): its paths are the jail's.  False when it has no pidfile.
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
	argv[5] = (char *)(uintptr_t)(w->jail != NULL ? "/etc/rc.subr" :
	    opts.rc_subr);
	argv[6] = NULL;
	if (run_read(w, scope_jexec(w, argv), &res) != 0 || res.outlen == 0)
		return (false);
	out = wstrndup(w, res.out, res.outlen);
	for (i = 0; i < 4; i++)
		f[i] = strsep(&out, "\n");
	if (f[3] == NULL || f[0][0] != '/' || f[1][0] == '\0')
		return (false);
	rp->pidfile = f[0];
	rp->procname = f[1];
	rp->interp = f[2];
	rp->svcj = f[3];
	/* A jail's service jail is looked for in the jail, by the helper. */
	rp->jid = w->jail != NULL ? w->jid : 0;
	/* rc.subr's own fallback: no such jail, the host. */
	if (w->jail == NULL && f[3][0] != '\0' && (rp->jid =
	    jail_getid(f[3])) < 0)
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
 * script's pidfile and program.  A jail's is looked at in the jail.
 */
static pid_t
svc_stale(struct work *w, struct arc_service *s, struct rcproc *rpp)
{
	struct rcproc	rp;

	if (!svc_rcproc(w, s->path, &rp))
		return (0);
	if (rpp != NULL)
		*rpp = rp;
	return (w->jail != NULL ? jail_stale(w, &rp, s) : stale_find(w, &rp,
	    s));
}

/*
 * svc_stale()'s look, at rp's processes and pidfile as this process
 * sees them: the host's, or the jail's in the helper attached to it.
 */
static pid_t
stale_find(struct work *w, const struct rcproc *rpp, struct arc_service *s)
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

	rp = *rpp;
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
 * stale_find() in the jail w works in, by the helper attached to it
 * (rc_stale_helper()): the jail's processes alone, its service jail
 * looked for there, its pidfile read as the jail has it.
 */
static pid_t
jail_stale(struct work *w, const struct rcproc *rp, struct arc_service *s)
{
	struct execres	 res;
	const char	*words[4], *stale;
	char		*out, *line, *v, *end;
	unsigned long	 n, fpid, pid;

	words[0] = rp->pidfile;
	words[1] = rp->procname;
	words[2] = rp->interp[0] != '\0' ? rp->interp : "-";
	words[3] = rp->svcj[0] != '\0' ? rp->svcj : "-";
	if (run_read(w, helper_argv(w, "rc-stale", 4, words), &res) != 0 ||
	    res.out == NULL)
		return (0);
	stale = NULL;
	fpid = pid = 0;
	out = wstrndup(w, res.out, res.outlen);
	while ((line = strsep(&out, "\n")) != NULL) {
		if ((v = strchr(line, ' ')) == NULL)
			continue;
		*v++ = '\0';
		if (strcmp(line, "stale") == 0) {
			stale = v;
			continue;
		}
		errno = 0;
		n = strtoul(v, &end, 10);
		if (errno != 0 || *end != '\0' || n <= 1 || n > INT_MAX)
			continue;
		if (strcmp(line, "pidfile-pid") == 0)
			fpid = n;
		else if (strcmp(line, "pid") == 0)
			pid = n;
	}
	if (stale == NULL)
		return (0);
	s->pidfile = wtext(w, rp->pidfile);
	if (fpid != 0) {
		s->has_pidfile_pid = true;
		s->pidfile_pid = (uint32_t)fpid;
	}
	s->has_pid = pid != 0;
	s->pid = (uint32_t)pid;
	s->pidfile_stale = wtext(w, stale);
	return ((pid_t)pid);
}

/*
 * The helper's rc-stale (scope_helper(), attached to the jail jid):
 * stale_find() for a service of the jail's, its pidfile, program,
 * interpreter and service jail ("-" for none) as the probe run there
 * read them.  Its lines "pidfile-pid N", "pid N" (the one process),
 * "stale why", when stale; none otherwise.
 */
int
rc_stale_helper(int jid, int argc, char **argv)
{
	struct work		w;
	struct arc_service	s;
	struct rcproc		rp;
	pid_t			found;
	int			rc;

	if (argc != 5 || argv[1][0] != '/' || argv[2][0] == '\0')
		return (2);
	work_init(&w);
	memset(&s, 0, sizeof(s));
	rp.pidfile = argv[1];
	rp.procname = argv[2];
	rp.interp = strcmp(argv[3], "-") == 0 ? "" : argv[3];
	rp.svcj = strcmp(argv[4], "-") == 0 ? "" : argv[4];
	/* rc.subr's own fallback: no such jail, this one. */
	rp.jid = jid;
	if (rp.svcj[0] != '\0' && (rp.jid = jail_getid(rp.svcj)) < 0)
		rp.jid = jid;
	found = stale_find(&w, &rp, &s);
	if (s.pidfile_stale != NULL) {
		if (s.has_pidfile_pid)
			printf("pidfile-pid %u\n", s.pidfile_pid);
		if (found != 0)
			printf("pid %d\n", (int)found);
		printf("stale %s\n", s.pidfile_stale);
	}
	rc = fflush(stdout) == 0 ? 0 : 1;
	work_free(&w);
	return (rc);
}

/* Is pid still the one process of rp's program, where rc looks for it?
 * A jail's, asked of the helper attached to it again. */
static bool
rc_proc_still(struct work *w, pid_t pid, const struct rcproc *rp)
{
	struct arc_service	s;

	if (w->jail == NULL)
		return (rc_proc_is(w, pid, rp));
	memset(&s, 0, sizeof(s));
	return (jail_stale(w, rp, &s) == pid);
}

/*
 * The service's stale pidfile written again with the pid of its
 * program's process, the one svc_stale() found alone, checked again
 * just before (where rc looks for it, its command line rc's match):
 * a file of the same mode next to it, renamed over it; a jail's
 * beneath the jail's root, through no link.  Refused when rc says it
 * runs, when nothing of it runs or more than one process does, and
 * when the pidfile is not a plain file.
 */
static void
svc_pidfile(struct work *w, const struct script *sc,
    struct service_action_rsp *rsp)
{
	struct arc_service	 s;
	struct rcproc		 rp;
	struct stat		 st;
	const char		*base;
	char			 line[32];
	pid_t			 pid;
	mode_t			 mode;
	int			 dfd, step, there;

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
	/* Looked at here in a dry run too, where svc_status() does not
	 * look: it only reads, and is what the pidfile is written from. */
	pid = s.has_running && s.path != NULL ? svc_stale(w, &s, &rp) : 0;
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
	/* Its directory, a jail's opened beneath the jail's root. */
	if ((dfd = scope_open_dir(w, rp.pidfile, &base)) == -1) {
		step_end(w, step, false, "%s", strerror(errno));
		rsp->error = wfmt(w, "%s: %s", rp.pidfile, strerror(errno));
		return;
	}
	there = fstatat(dfd, base, &st, AT_SYMLINK_NOFOLLOW);
	close(dfd);
	if (there == 0) {
		if (!S_ISREG(st.st_mode)) {
			step_end(w, step, false, "not a plain file");
			rsp->error = wfmt(w, "%s is not a plain file: not "
			    "written", rp.pidfile);
			return;
		}
		mode = st.st_mode & 0777;
	}
	/* The process checked again, now: still its program's. */
	if (!rc_proc_still(w, pid, &rp)) {
		step_end(w, step, false, "pid %d is gone", (int)pid);
		rsp->error = wfmt(w, "pid %d is no longer %s's: not written",
		    (int)pid, rp.procname);
		return;
	}
	snprintf(line, sizeof(line), "%d\n", (int)pid);
	if (scope_replace(w, rp.pidfile, line, strlen(line), mode, NULL) ==
	    -1) {
		step_end(w, step, false, "%s", strerror(errno));
		rsp->error = wfmt(w, "%s: %s", rp.pidfile, strerror(errno));
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
	collect_keep(w->jail, v, n, true);
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
	/* What a viewer is told, and the watcher, at once. */
	if (!w->dry)
		collect_keep(w->jail, s, 1, false);
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
		rsp->error = no_script(w, name);
		return (0);
	}
	switch (action) {
	case ARC_SERVICE_ACTION_ENABLE:
	case ARC_SERVICE_ACTION_DISABLE:
		if ((rcvar = svc_rcvar(w, name, &e)) == NULL) {
			rsp->error = e;
			goto out;
		}
		/* A jail's rc.conf: sysrc -j <jid> (run_exec()'s scope). */
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
		if (w->jail == NULL && strcmp(name, OWN_SERVICE) == 0 &&
		    (action == ARC_SERVICE_ACTION_STOP || action ==
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
	size_t		  ncmd, cap;

	if (svc_run(w, name, "describe", &res) == 0 && res.outlen > 0)
		rsp->description = wtext(w, wstrndup(w, res.out, res.outlen -
		    (res.out[res.outlen - 1] == '\n' ? 1 : 0)));
	cmds = NULL;
	ncmd = cap = 0;
	if (svc_run(w, name, "extracommands", &res) == 0 && res.outlen > 0) {
		copy = wstrndup(w, res.out, res.outlen);
		for (it = copy; (tok = strsep(&it, " \t\n")) != NULL; ) {
			if (*tok == '\0')
				continue;
			cmds = wgrow(w, cmds, ncmd, &cap, sizeof(*cmds));
			cmds[ncmd++] = wtext(w, tok);
		}
	}
	rsp->commands.v = cmds;
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
	size_t			 n, i, nv, cap, stemlen, namelen;
	int			 rc;

	name = rq->service;
	rsp->has_ok = true;
	rsp->ok = false;
	scan_scripts(w, &all, &n);
	sc = script_find(all, n, name);
	if (sc == NULL) {
		rsp->error = no_script(w, name);
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
	nv = cap = 0;
	for (p = res.out; *p != '\0'; p = nl != NULL ? nl + 1 :
	    p + strlen(p)) {
		nl = strchr(p, '\n');
		if ((sep = strstr(p, ": ")) == NULL || (nl != NULL && sep > nl))
			continue;
		if (!((strncmp(p, name, namelen) == 0 && p[namelen] == '_') ||
		    (stem != NULL && strncmp(p, stem, stemlen) == 0)))
			continue;
		vars = wgrow(w, vars, nv, &cap, sizeof(*vars));
		memset(&vars[nv], 0, sizeof(vars[nv]));
		vars[nv].key = wtext(w, wstrndup(w, p, (size_t)(sep - p)));
		vars[nv].value = wtext(w, wstrndup(w, sep + 2, nl != NULL ?
		    (size_t)(nl - sep - 2) : strlen(sep + 2)));
		nv++;
	}
	rsp->variables.v = vars;
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
		rsp->error = no_script(w, name);
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
	collect_keep(w->jail, s, 1, false);
	return (0);
}

/* A service's state as a look saw it change: the event service-state,
 * a jail's ("" the host's) saying the jail. */
static void
svc_told(const char *jail, const char *name, bool running, bool has_pid,
    uint32_t pid)
{
	char	q[160], jq[2 * MAXHOSTNAMELEN];
	char	more[2 * MAXHOSTNAMELEN + 48];
	size_t	len;

	more[0] = '\0';
	if (has_pid)
		snprintf(more, sizeof(more), ",\"pid\":%u", pid);
	if (jail[0] != '\0') {
		len = strlen(more);
		snprintf(more + len, sizeof(more) - len, ",\"jail\":\"%s\"",
		    json_quote(jail, jq, sizeof(jq)));
	}
	event_add("service-state", "{\"service\":\"%s\",\"state\":\"%s\"%s}",
	    json_quote(name, q, sizeof(q)), running ? "running" : "stopped",
	    more);
}

/* The one kept of jail's ("" the host's) by that name, or ncoll;
 * coll_lock held. */
static size_t
coll_find(const char *jail, const char *name)
{
	size_t	k;

	for (k = 0; k < ncoll; k++)
		if (strcmp(coll[k].name, name) == 0 && strcmp(coll[k].jail,
		    jail) == 0)
			break;
	return (k);
}

/* The watcher told to look at what is kept again. */
static void
svc_poke(void)
{
	struct kevent	ev;

	if (svc_kq == -1)
		return;
	EV_SET(&ev, K_REARM, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
	(void)kevent(svc_kq, &ev, 1, NULL, 0, NULL);
}

/*
 * What a list or a read saw (v, n of them) of the host's or of jail's
 * services kept for a viewer's requests: each one's running, status
 * line, pid and rcvar; with all, v is every enabled service there, and
 * one of there not among them is forgotten.  One seen before whose
 * state is not what it was (started, stopped, another pid) is told
 * (svc_told()); the watcher looks again.
 */
static void
collect_keep(const char *jail, const struct arc_service *v, size_t n,
    bool all)
{
	struct collected	*c, *nc;
	size_t			 i, k, m;
	bool			*tell;

	if (jail == NULL)
		jail = "";
	if ((tell = calloc(n + 1, sizeof(*tell))) == NULL)
		return;
	pthread_mutex_lock(&coll_lock);
	if (all) {
		/* Kept: those of v, what was said of them before, and the
		 * others' as they were. */
		if ((nc = calloc(ncoll + n + 1, sizeof(*nc))) == NULL) {
			pthread_mutex_unlock(&coll_lock);
			free(tell);
			return;
		}
		for (k = m = 0; k < ncoll; k++)
			if (strcmp(coll[k].jail, jail) != 0)
				nc[m++] = coll[k];
		for (i = 0; i < n; i++) {
			if (!v[i].has_enabled || !v[i].enabled)
				continue;
			if ((k = coll_find(jail, v[i].name)) < ncoll)
				nc[m] = coll[k];
			(void)strlcpy(nc[m].jail, jail, sizeof(nc[m].jail));
			(void)strlcpy(nc[m].name, v[i].name, sizeof(nc[m].name));
			m++;
		}
		free(coll);
		coll = nc;
		ncoll = m;
		if (jail[0] == '\0')
			coll_at = time(NULL);
	}
	for (i = 0; i < n; i++) {
		if (all && (!v[i].has_enabled || !v[i].enabled))
			continue;
		if ((k = coll_find(jail, v[i].name)) == ncoll) {
			if ((nc = reallocarray(coll, ncoll + 1,
			    sizeof(*coll))) == NULL)
				break;
			coll = nc;
			memset(&coll[ncoll], 0, sizeof(coll[ncoll]));
			(void)strlcpy(coll[ncoll].jail, jail,
			    sizeof(coll[ncoll].jail));
			(void)strlcpy(coll[ncoll].name, v[i].name,
			    sizeof(coll[ncoll].name));
			ncoll++;
		}
		c = &coll[k];
		tell[i] = c->has_running && v[i].has_running && (c->running !=
		    v[i].running || (v[i].running && v[i].has_pid &&
		    (!c->has_pid || c->pid != v[i].pid)));
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
	for (i = 0; i < n; i++)
		if (tell[i])
			svc_told(jail, v[i].name, v[i].running, v[i].has_pid,
			    v[i].pid);
	free(tell);
	svc_poke();
}

/* What was kept of the jails not among those named (n of them, jails
 * that run) forgotten: a jail stopped, its services with it. */
static void
collect_jails(char *const *names, size_t n)
{
	size_t	k, m, i;

	pthread_mutex_lock(&coll_lock);
	for (k = m = 0; k < ncoll; k++) {
		for (i = 0; i < n && strcmp(coll[k].jail, names[i]) != 0; i++)
			;
		if (coll[k].jail[0] == '\0' || i < n)
			coll[m++] = coll[k];
	}
	ncoll = m;
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
		if (strcmp(coll[k].name, s->name) != 0 || strcmp(coll[k].jail,
		    w->jail != NULL ? w->jail : "") != 0)
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
		rsp->error = no_script(w, name);
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

/*
 * Each running jail's services, as the host's (do_services() in the
 * jail): a jail whose root is the host's has the host's scripts, and is
 * left out.  What was kept of a jail no longer running is forgotten.
 */
static void
collect_jails_all(void)
{
	struct services_rsp	  r;
	struct work		  w;
	const char		 *e;
	char			**names, js[16], nb[MAXHOSTNAMELEN],
				  pb[MAXPATHLEN];
	size_t			  n, cap, i;
	int			  jid;

	names = NULL;
	n = cap = 0;
	for (jid = jail_next(0); jid > 0; jid = jail_next(jid)) {
		snprintf(js, sizeof(js), "%d", jid);
		if (jail_getv(0, "jid", js, "name", nb, "path", pb, NULL) ==
		    -1 || strcmp(pb, "/") == 0)
			continue;
		if (n == cap) {
			cap = cap * 2 + 8;
			if ((names = reallocarray(names, cap,
			    sizeof(*names))) == NULL)
				return;
		}
		if ((names[n] = strdup(nb)) == NULL)
			break;
		n++;
		work_init(&w);
		w.nice = true;
		memset(&r, 0, sizeof(r));
		if (scope_enter_jail(&w, nb, &e, false) == 0)
			(void)do_services(&w, &r);
		work_free(&w);
	}
	collect_jails(names, n);
	for (i = 0; i < n; i++)
		free(names[i]);
	free(names);
}

/* The collector: FIRST_S after the start, then every COLLECT_S, the
 * list as an operator's read has it, kept (collect_keep()): the host's,
 * then each running jail's. */
static void *
collector(void *arg __unused)
{
	struct services_rsp	 r;
	struct work		 w;
	unsigned		 s = FIRST_S;

	for (;;) {
		(void)sleep(s);
		s = COLLECT_S;
		work_init(&w);
		w.nice = true;
		memset(&r, 0, sizeof(r));
		(void)do_services(&w, &r);
		work_free(&w);
		collect_jails_all();
	}
	return (NULL);
}

/* A pid watched for its exit (NOTE_EXIT), and whose; the watcher's. */
struct svc_watch {
	pid_t	 pid;
	char	 jail[MAXHOSTNAMELEN];
	char	 name[65];
};

static struct svc_watch	*watched;
static size_t		 nwatched, capwatched;

/* A service as the watcher takes it from what is kept. */
struct look {
	char		 jail[MAXHOSTNAMELEN];
	char		 name[65];
	bool		 has_running;
	bool		 running;
	bool		 has_pid;
	uint32_t	 pid;
	uint32_t	 quiet;
	int		 rp_state;
	time_t		 rp_at;
	struct rcproc	 rp;
};

/* The pid rp's pidfile names, when it is a process of rp's program
 * where rc looks for it (rc_proc_is()); 0 otherwise. */
static pid_t
rp_pid(struct work *w, const struct rcproc *rp)
{
	FILE	*fp;
	long	 v;
	pid_t	 pid = 0;

	if ((fp = fopen(rp->pidfile, "re")) == NULL)
		return (0);
	if (fscanf(fp, "%ld", &v) == 1 && v > 1 && v <= INT_MAX)
		pid = (pid_t)v;
	fclose(fp);
	return (pid != 0 && rc_proc_is(w, pid, rp) ? pid : 0);
}

/* The scripts, read once a pass and only when one is needed. */
static const struct script *
pass_script(struct work *w, struct script **sc, size_t *n, bool *read,
    const char *name)
{

	if (!*read) {
		scan_scripts(w, sc, n);
		*read = true;
	}
	return (script_find(*sc, *n, name));
}

/* l's pidfile and program read by its script, and kept with it. */
static void
pass_rp(struct work *w, const struct script *f, struct look *l)
{
	struct collected	*c;
	size_t			 k;

	/* A jail's: none read, its status looked at (the comment at the
	 * top). */
	l->rp_state = l->jail[0] == '\0' && f != NULL && svc_rcproc(w,
	    f->path, &l->rp) ? RP_READ : RP_NONE;
	l->rp_at = time(NULL);
	pthread_mutex_lock(&coll_lock);
	for (k = 0; k < ncoll; k++) {
		if (strcmp(coll[k].name, l->name) != 0 || strcmp(coll[k].jail,
		    l->jail) != 0)
			continue;
		c = &coll[k];
		c->rp_state = l->rp_state;
		c->rp_at = l->rp_at;
		if (l->rp_state == RP_READ) {
			(void)strlcpy(c->rp_pidfile, l->rp.pidfile,
			    sizeof(c->rp_pidfile));
			(void)strlcpy(c->rp_procname, l->rp.procname,
			    sizeof(c->rp_procname));
			(void)strlcpy(c->rp_interp, l->rp.interp,
			    sizeof(c->rp_interp));
			c->rp_jid = l->rp.jid;
		}
	}
	pthread_mutex_unlock(&coll_lock);
}

/* A look that saw nothing new at pid: none again for the same pid. */
static void
pass_quiet(const char *jail, const char *name, uint32_t pid)
{
	size_t	k;

	pthread_mutex_lock(&coll_lock);
	if ((k = coll_find(jail, name)) < ncoll)
		coll[k].quiet = pid;
	pthread_mutex_unlock(&coll_lock);
}

/* pid watched for its exit, as jail's name's; false when it is gone
 * already. */
static bool
watch_pid(int kq, const char *jail, const char *name, pid_t pid)
{
	struct kevent	 ev;
	struct svc_watch *nw;
	size_t		 i;

	for (i = 0; i < nwatched; i++)
		if (watched[i].pid == pid && strcmp(watched[i].name, name) ==
		    0 && strcmp(watched[i].jail, jail) == 0)
			return (true);
	EV_SET(&ev, pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, NULL);
	if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1)
		return (false);
	if (nwatched == capwatched) {
		if ((nw = reallocarray(watched, capwatched * 2 + 8,
		    sizeof(*watched))) == NULL)
			return (true);
		watched = nw;
		capwatched = capwatched * 2 + 8;
	}
	watched[nwatched].pid = pid;
	(void)strlcpy(watched[nwatched].jail, jail,
	    sizeof(watched[nwatched].jail));
	(void)strlcpy(watched[nwatched].name, name,
	    sizeof(watched[nwatched].name));
	nwatched++;
	return (true);
}

/* Was jail's name's watched process among those gone (it is no
 * longer watched then)? */
static bool
watch_gone(const char *jail, const char *name, const pid_t *gone,
    size_t ngone)
{
	size_t	i, j;
	bool	was = false;

	for (i = 0; i < nwatched; ) {
		for (j = 0; j < ngone && watched[i].pid != gone[j]; j++)
			;
		if (j < ngone && strcmp(watched[i].name, name) == 0 &&
		    strcmp(watched[i].jail, jail) == 0) {
			watched[i] = watched[--nwatched];
			was = true;
		} else
			i++;
	}
	return (was);
}

/*
 * One look over what is kept: a service whose watched process is among
 * gone, or whose pidfile (with pidfiles) names a process of its while
 * it is stopped, or (with unknown) that tells neither, has its status
 * run again and kept, which tells its change (collect_keep()); each
 * running one's process watched.
 */
static void
svc_pass(int kq, const pid_t *gone, size_t ngone, bool pidfiles,
    bool unknown)
{
	struct work		 w;
	struct look		*lv, *l;
	struct arc_service	 s;
	struct script		*sc = NULL, *jsc = NULL;
	const struct script	*f;
	struct collected	*c;
	const char		*e;
	char			 jread[MAXHOSTNAMELEN] = "";
	size_t			 nl, i, nsc = 0, njsc = 0;
	time_t			 now;
	pid_t			 pid;
	bool			 full, read = false;

	work_init(&w);
	w.nice = true;
	pthread_mutex_lock(&coll_lock);
	lv = wcalloc(&w, ncoll + 1, sizeof(*lv));
	for (i = 0; i < ncoll; i++) {
		c = &coll[i];
		l = &lv[i];
		(void)strlcpy(l->jail, c->jail, sizeof(l->jail));
		(void)strlcpy(l->name, c->name, sizeof(l->name));
		l->has_running = c->has_running;
		l->running = c->running;
		l->has_pid = c->has_pid;
		l->pid = c->pid;
		l->quiet = c->quiet;
		l->rp_state = c->rp_state;
		l->rp_at = c->rp_at;
		if (c->rp_state == RP_READ) {
			l->rp.pidfile = wstrdup(&w, c->rp_pidfile);
			l->rp.procname = wstrdup(&w, c->rp_procname);
			l->rp.interp = wstrdup(&w, c->rp_interp);
			l->rp.jid = c->rp_jid;
		}
	}
	nl = ncoll;
	pthread_mutex_unlock(&coll_lock);
	now = time(NULL);
	for (i = 0; i < nl; i++) {
		l = &lv[i];
		pid = 0;
		full = ngone > 0 && watch_gone(l->jail, l->name, gone, ngone);
		if (full || !l->has_running)
			;
		else if (!l->running) {
			if (!pidfiles && !unknown)
				continue;
			if (l->rp_state == RP_UNREAD || now - l->rp_at >=
			    COLLECT_S)
				pass_rp(&w, l->jail[0] != '\0' ? NULL :
				    pass_script(&w, &sc, &nsc, &read, l->name),
				    l);
			if (l->rp_state != RP_READ)
				full = unknown;
			else if (pidfiles && (pid = rp_pid(&w, &l->rp)) != 0)
				full = (uint32_t)pid != l->quiet;
		} else {
			pid = l->has_pid ? (pid_t)l->pid : 0;
			if (pid == 0 && (l->rp_state == RP_UNREAD || now -
			    l->rp_at >= COLLECT_S))
				pass_rp(&w, l->jail[0] != '\0' ? NULL :
				    pass_script(&w, &sc, &nsc, &read, l->name),
				    l);
			if (pid == 0 && l->rp_state == RP_READ)
				pid = rp_pid(&w, &l->rp);
			if (pid == 0)
				full = unknown;
			else if (!watch_pid(kq, l->jail, l->name, pid))
				full = (uint32_t)pid != l->quiet;
		}
		if (!full)
			continue;
		memset(&s, 0, sizeof(s));
		if (l->jail[0] != '\0') {
			/* A jail's, by its own service(8); its scripts read
			 * there once a pass a jail, for its stale pidfile.  A
			 * jail gone is the collector's to forget. */
			if (scope_enter_jail(&w, l->jail, &e, false) != 0)
				continue;
			if (strcmp(jread, l->jail) != 0) {
				scan_scripts(&w, &jsc, &njsc);
				(void)strlcpy(jread, l->jail, sizeof(jread));
			}
			s.name = wtext(&w, l->name);
			if ((f = script_find(jsc, njsc, l->name)) != NULL)
				s.path = wtext(&w, f->path);
			svc_status(&w, &s);
			w.jail = NULL;
			w.jid = 0;
			w.jroot = NULL;
		} else {
			if ((f = pass_script(&w, &sc, &nsc, &read,
			    l->name)) == NULL)
				continue;
			s.name = wtext(&w, f->name);
			s.path = wtext(&w, f->path);
			svc_status(&w, &s);
		}
		collect_keep(l->jail, &s, 1, false);
		/* Nothing new at that pid: not looked at again for it. */
		if (s.running && s.has_pid && !watch_pid(kq, l->jail, s.name,
		    (pid_t)s.pid))
			pass_quiet(l->jail, s.name, s.pid);
		else if (!s.running && pid != 0)
			pass_quiet(l->jail, s.name, (uint32_t)pid);
		else
			pass_quiet(l->jail, s.name, 0);
	}
	work_free(&w);
}

/*
 * The watcher (the comment at the top): one kqueue(2), the running
 * services' processes on it, its pokes and its timers; a look over
 * what is kept (svc_pass()) each time it wakes.
 */
static void *
svc_watcher(void *arg)
{
	struct kevent	 ev[16];
	pid_t		 gone[nitems(ev)];
	time_t		 unknown_at = 0;
	size_t		 ngone;
	int		 kq = (int)(intptr_t)arg, n, i, hot = 0;
	bool		 pidfiles, unknown, heat;

	for (;;) {
		if ((n = kevent(kq, NULL, 0, ev, nitems(ev), NULL)) == -1) {
			if (errno == EINTR)
				continue;
			logmsg(LOG_NOTICE, "services: their starts and stops "
			    "are no longer watched: kevent: %s",
			    strerror(errno));
			break;
		}
		ngone = 0;
		pidfiles = unknown = heat = false;
		for (i = 0; i < n; i++) {
			switch (ev[i].filter) {
			case EVFILT_PROC:
				if ((ev[i].fflags & NOTE_EXIT) != 0) {
					gone[ngone++] = (pid_t)ev[i].ident;
					heat = true;
				}
				break;
			case EVFILT_USER:
				if (ev[i].ident == K_STARTED) {
					pidfiles = true;
					heat = true;
				}
				break;
			case EVFILT_TIMER:
				pidfiles = true;
				if (ev[i].ident == K_HOT && hot > 0)
					hot--;
				if (ev[i].ident == K_RECHECK &&
				    time(NULL) >= unknown_at) {
					unknown = true;
					unknown_at = time(NULL) + UNKNOWN_S;
				}
				break;
			}
		}
		svc_pass(kq, gone, ngone, pidfiles, unknown);
		/* A second's looks for a few seconds: a daemon's pidfile is
		 * written a moment after it starts, and a restart's start
		 * follows its stop. */
		if (heat) {
			if (hot == 0) {
				EV_SET(&ev[0], K_HOT, EVFILT_TIMER, EV_ADD, 0,
				    1000, NULL);
				(void)kevent(kq, &ev[0], 1, NULL, 0, NULL);
			}
			hot = HOT_LOOKS;
		} else if (hot == 0) {
			EV_SET(&ev[0], K_HOT, EVFILT_TIMER, EV_DELETE, 0, 0,
			    NULL);
			(void)kevent(kq, &ev[0], 1, NULL, 0, NULL);
		}
	}
	close(kq);
	return (NULL);
}

/* The host's processes started (gula/hostwatch.c): the stopped
 * services' pidfiles looked at. */
void
services_procs_started(void)
{
	struct kevent	ev;

	if (svc_kq == -1)
		return;
	EV_SET(&ev, K_STARTED, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
	(void)kevent(svc_kq, &ev, 1, NULL, 0, NULL);
}

void
services_collect_start(void)
{
	struct kevent	ev[3];
	pthread_t	tid;
	int		kq, error;

	if ((error = pthread_create(&tid, NULL, collector, NULL)) != 0)
		logmsg(LOG_ERR, "services: no collector: %s", strerror(error));
	else
		(void)pthread_detach(tid);
	if ((kq = kqueue()) == -1) {
		logmsg(LOG_NOTICE, "services: their starts and stops are not "
		    "watched: kqueue: %s", strerror(errno));
		return;
	}
	EV_SET(&ev[0], K_REARM, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
	EV_SET(&ev[1], K_STARTED, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
	EV_SET(&ev[2], K_RECHECK, EVFILT_TIMER, EV_ADD, 0, RECHECK_S * 1000,
	    NULL);
	if (kevent(kq, ev, nitems(ev), NULL, 0, NULL) == -1 ||
	    (error = pthread_create(&tid, NULL, svc_watcher,
	    (void *)(intptr_t)kq)) != 0) {
		logmsg(LOG_NOTICE, "services: their starts and stops are not "
		    "watched");
		close(kq);
		return;
	}
	svc_kq = kq;
	(void)pthread_detach(tid);
}

