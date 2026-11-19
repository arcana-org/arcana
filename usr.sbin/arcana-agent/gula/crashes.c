/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: the cores the kernel dumped (core(5)), where kern.corefile
 * says: each with its program, pid, size and time, the largest a
 * measure of what the process held when it died.  Asked for one, its
 * backtrace, every thread's, as lldb(1) of the base system reads the
 * core with its program in batch; and the signal's code the core keeps,
 * which tells a SIGBUS of a fault the kernel could find no memory for
 * (BUS_OOMERR) from one of a bad address.  A read changes nothing: a
 * core is taken away by the crash job alone, one in kern.corefile's
 * directory (the jail's beneath its root), never one elsewhere.
 *
 * A core is a file anybody may have put there, and what reads it runs
 * what the file says, so a backtrace is only of a core the kernel wrote
 * for a crash it said (kmsg.c: "exited on signal ... (core dumped)" of
 * that program and pid, the pid where kern.corefile's pattern names
 * it), at a path the pattern gives, a regular file of one link owned
 * by the crashed process's user or root, opened here without a link
 * and passed to the debugger as its standard input (/dev/fd/0: gdb
 * reads it there; lldb takes no core it cannot size by its path, so
 * it reads a copy root made of that descriptor, in a directory of its
 * own, nobody's to read alone, gone after); the program named, one of
 * that name.  The debugger runs as nobody, with
 * no init file and no script of its own or of the symbols', within
 * limits of CPU, memory and time: nothing it says is trusted.
 *
 * A jailed process's core is where kern.corefile says beneath the
 * jail's root (the kernel resolves the pattern in the process's own
 * root), so each running jail's are listed too, with the jail's name,
 * their directory the host's path to it: each directory opened beneath
 * the jail's root, never through a link that leads out of it, and the
 * core in it without one.  Its backtrace is of the jail's own program
 * and libraries: the host's debugger told the jail's root is where the
 * program's files are (lldb's image search paths, gdb's sysroot), the
 * program found beneath the root; the core one the kernel said it
 * dumped in that jail.  The jail's root can still turn a name on that
 * way into a link after it was looked at: what the debugger reads then
 * is read as nobody, and nothing it says is trusted.
 */

#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	CORES_MAX	200
#define	BT_MAX		(512 * 1024)	/* lldb's words kept */
#define	CORE_SIZE_MAX	((off_t)2 << 30)	/* a core read, at most */
#define	DBG_CPU		120		/* a debugger's seconds of CPU */
#define	DBG_AS		((rlim_t)6 << 30)	/* and its address space */
#define	DBG_WALL	300		/* killed after so long */

/* Whose cores: the host's (jail NULL), or a running jail's, beneath its
 * root. */
struct croot {
	const char	*jail;
	int		 jid;
	const char	*path;		/* the jail's root, as the host has it */
};

static const struct croot	host_root = { NULL, 0, "/" };

/* Where cores go: kern.corefile's directory; NULL when it names none
 * (each in its process's own directory). */
static const char *
core_dir(struct work *w, char *pattern, size_t len)
{
	char	*slash;
	size_t	 n;

	n = len;
	if (sysctlbyname("kern.corefile", pattern, &n, NULL, 0) != 0)
		return (NULL);
	pattern[MIN(n, len - 1)] = '\0';
	if (pattern[0] != '/' || (slash = strrchr(pattern, '/')) == NULL)
		return (NULL);
	if (strchr(pattern, '%') != NULL && strchr(pattern, '%') < slash)
		return (NULL);
	return (wstrndup(w, pattern, slash == pattern ? 1 :
	    (size_t)(slash - pattern)));
}

/* A core's name as a directory entry: no slash, not hidden, a core. */
static bool
core_name_ok(const char *s)
{

	return (s != NULL && s[0] != '\0' && s[0] != '.' && strlen(s) < 200 &&
	    strchr(s, '/') == NULL && (strstr(s, ".core") != NULL ||
	    strcmp(s, "core") == 0));
}

/*
 * A directory of r's: the host's, or opened beneath the jail's root,
 * whatever links the jail has put on the way.  -1 with errno.
 */
static int
root_dir(const struct croot *r, const char *dir)
{
	int	root, fd, e;

	if (r->jail == NULL)
		return (open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
	if ((root = open(r->path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) == -1)
		return (-1);
	dir += strspn(dir, "/");
	fd = openat(root, dir[0] != '\0' ? dir : ".", O_RDONLY | O_DIRECTORY |
	    O_CLOEXEC | O_RESOLVE_BENEATH);
	e = errno;
	close(root);
	errno = e;
	return (fd);
}

/* A directory of r's as the host names it: beneath the jail's root. */
static const char *
root_path(struct work *w, const struct croot *r, const char *dir)
{

	if (r->jail == NULL)
		return (dir);
	return (strcmp(dir, "/") == 0 ? r->path : wfmt(w, "%s%s",
	    strcmp(r->path, "/") == 0 ? "" : r->path, dir));
}

/* Is program, as r sees it, a program there: an executable file,
 * beneath the jail's root for a jail's? */
static bool
program_ok(const struct croot *r, const char *program)
{
	struct stat	sb;
	int		root;
	bool		ok;

	if (program[0] != '/')
		return (false);
	if (r->jail == NULL)
		return (access(program, X_OK) == 0);
	if ((root = open(r->path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) == -1)
		return (false);
	ok = fstatat(root, program + 1, &sb, AT_RESOLVE_BENEATH) == 0 &&
	    S_ISREG(sb.st_mode) && (sb.st_mode & 0111) != 0;
	close(root);
	return (ok);
}

/* The program of that name (the crashed process's, as the kernel
 * names it), where programs are, as r sees them. */
static const char *
core_program(struct work *w, const struct croot *r, const char *name)
{
	static const char *const dirs[] = { "/usr/local/sbin",
	    "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin",
	    "/usr/libexec", "/usr/local/libexec" };
	const char	*p;
	size_t		 i;

	for (i = 0; i < nitems(dirs); i++) {
		p = wfmt(w, "%s/%s", dirs[i], name);
		if (program_ok(r, p))
			return (p);
	}
	return (NULL);
}

/*
 * The cores of r's dir into arr, each with where it is (the host's path
 * to it) and whose; *othersp counts the directory's other files; false,
 * with why in *errp, when the directory cannot be read.
 */
static bool
cores_list(struct work *w, const struct croot *r, const char *dir,
    ucl_object_t *arr, int *othersp, ucl_object_t *others, const char **errp)
{
	ucl_object_t	*o;
	DIR		*d;
	struct dirent	*de;
	struct stat	 st;
	char		 pid[16];
	const char	*p, *where;
	int		 n, fd, e;

	where = root_path(w, r, dir);
	if ((fd = root_dir(r, dir)) == -1 || (d = fdopendir(fd)) == NULL) {
		e = errno;
		*errp = wfmt(w, "%s: %s", where, strerror(e));
		if (fd != -1)
			close(fd);
		errno = e;
		return (false);
	}
	n = 0;
	while ((de = readdir(d)) != NULL && n < CORES_MAX) {
		if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0
		    || !S_ISREG(st.st_mode))
			continue;
		if (!core_name_ok(de->d_name)) {
			if ((*othersp)++ < 20 && others != NULL)
				ucl_array_append(others, ucl_object_fromstring(wfmt(
				    w, "%s/%s (%jd bytes)", strcmp(where, "/") == 0 ?
				    "" : where, de->d_name, (intmax_t)st.st_size)));
			continue;
		}
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(de->d_name),
		    "name", 0, true);
		ucl_object_insert_key(o, ucl_object_fromstring(where),
		    "directory", 0, true);
		if (r->jail != NULL)
			ucl_object_insert_key(o, ucl_object_fromstring(r->jail),
			    "jail", 0, true);
		ucl_object_insert_key(o, ucl_object_fromlstring(de->d_name,
		    strcspn(de->d_name, ".")), "program", 0, false);
		/* %N.%P.core: its pid, when the name has one. */
		p = strchr(de->d_name, '.');
		if (p != NULL && sscanf(p + 1, "%15[0-9]", pid) == 1)
			ucl_object_insert_key(o, ucl_object_fromint(atoi(pid)),
			    "pid", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(st.st_size),
		    "size", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(st.st_mtime),
		    "time", 0, false);
		ucl_array_append(arr, o);
		n++;
	}
	closedir(d);
	return (true);
}

/*
 * Does path match kern.corefile's pattern (core(5): %N the program's
 * name, %P its pid, %U its uid, %H the host's name, %I an index)?  A
 * pattern not absolute is where the process was: matched at the end of
 * the path, after a slash.  The name in comm (MAXCOMLEN + 2 bytes), the
 * pid in *pidp (-1 when the pattern names none).
 */
static bool
pattern_at(const char *pat, const char *s, char *comm, int *pidp)
{
	const char	*e;
	size_t		 n;

	for (; *pat != '\0'; pat++, s++) {
		if (*pat != '%' || pat[1] == '%') {
			if (*pat == '%')
				pat++;
			if (*s != *pat)
				return (false);
			continue;
		}
		switch (*++pat) {
		case 'N':
		case 'H':
			/* As long as the rest matches, shortest first. */
			for (e = s + 1; *s != '\0' && *s != '/' && e <=
			    s + strcspn(s, "/"); e++) {
				n = (size_t)(e - s);
				if (*pat == 'N' && n > MAXCOMLEN)
					break;
				if (pattern_at(pat + 1, e, comm, pidp)) {
					if (*pat == 'N')
						snprintf(comm, MAXCOMLEN + 2,
						    "%.*s", (int)n, s);
					return (true);
				}
			}
			return (false);
		case 'P':
		case 'U':
		case 'I':
			if ((n = strspn(s, "0123456789")) == 0 || n > 10)
				return (false);
			if (*pat == 'P')
				*pidp = atoi(s);
			s += n - 1;
			break;
		default:
			return (false);
		}
	}
	return (*s == '\0');
}

static bool
core_matches(const char *pattern, const char *path, char *comm, int *pidp)
{
	const char	*p;

	comm[0] = '\0';
	*pidp = -1;
	if (pattern[0] == '/')
		return (pattern_at(pattern, path, comm, pidp) && comm[0] !=
		    '\0');
	for (p = path; (p = strchr(p, '/')) != NULL; p++)
		if (pattern_at(pattern, p + 1, comm, pidp) && comm[0] != '\0')
			return (true);
	return (false);
}

/*
 * The helper's "debug-as-nobody program arg ...": the program run with
 * limits of CPU, memory and no core of its own, as nobody when the
 * agent is root, its standard input as given (a core it cannot open).
 */
int
debug_as_nobody(int argc, char **argv)
{
	struct rlimit	 rl;
	struct passwd	*pw;
	gid_t		 g;

	if (argc < 2 || argv[1][0] != '/')
		return (2);
	rl.rlim_cur = rl.rlim_max = DBG_CPU;
	if (setrlimit(RLIMIT_CPU, &rl) == -1)
		err(1, "RLIMIT_CPU");
	rl.rlim_cur = rl.rlim_max = DBG_AS;
	if (setrlimit(RLIMIT_AS, &rl) == -1)
		err(1, "RLIMIT_AS");
	rl.rlim_cur = rl.rlim_max = 0;
	if (setrlimit(RLIMIT_CORE, &rl) == -1)
		err(1, "RLIMIT_CORE");
	if (geteuid() == 0) {
		if ((pw = getpwnam("nobody")) == NULL)
			errx(1, "no user nobody");
		g = pw->pw_gid;
		if (setgroups(1, &g) == -1 || setgid(g) == -1 ||
		    setuid(pw->pw_uid) == -1)
			err(1, "nobody");
		if (setuid(0) != -1)
			errx(1, "root again after nobody");
	}
	execv(argv[1], argv + 1);
	err(127, "%s", argv[1]);
}

/*
 * The core opened: beneath its directory (beneath the jail's root for
 * a jail's), never through a link, a regular file of one link, the
 * crashed process's user's or root's, not too large; -1 and why.
 */
static int
core_open(struct work *w, const struct croot *r, const char *dir,
    const char *core, int uid, const char **errp)
{
	struct stat	 sb;
	int		 dfd, fd;

	if ((dfd = root_dir(r, dir)) == -1) {
		*errp = wfmt(w, "%s: %s", root_path(w, r, dir), strerror(errno));
		return (-1);
	}
	fd = openat(dfd, core, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	close(dfd);
	if (fd == -1) {
		*errp = wfmt(w, "%s: %s", core, strerror(errno));
		return (-1);
	}
	if (fstat(fd, &sb) == -1 || !S_ISREG(sb.st_mode) || sb.st_nlink != 1 ||
	    (sb.st_uid != (uid_t)uid && sb.st_uid != 0) || sb.st_size >
	    CORE_SIZE_MAX) {
		close(fd);
		*errp = wfmt(w, "%s is not a core the kernel wrote for uid %d "
		    "(a file of its own, of one link, 2 GiB at most): not "
		    "read", core, uid);
		return (-1);
	}
	return (fd);
}

/*
 * A copy of the core opened, for lldb: in a new directory of root's
 * beneath TMPDIR that others may pass through and not list, the file
 * nobody's, 0400.  Its path, and the directory's in *dirp; NULL and why.
 */
static const char *
core_copy(struct work *w, int cfd, const char **dirp, const char **errp)
{
	struct passwd	*pw;
	const char	*path;
	char		*dir;
	off_t		 in, out;
	ssize_t		 n;
	int		 fd;

	dir = wfmt(w, "%s/arcana-core.XXXXXXXX", tmp_dir());
	if (mkdtemp(dir) == NULL || chmod(dir, 0711) == -1) {
		*errp = wfmt(w, "%s: %s", dir, strerror(errno));
		return (NULL);
	}
	path = wfmt(w, "%s/core", dir);
	in = out = 0;
	if ((fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
	    O_CLOEXEC, 0400)) == -1 || (geteuid() == 0 && ((pw =
	    getpwnam("nobody")) == NULL || fchown(fd, pw->pw_uid, pw->pw_gid) ==
	    -1))) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		goto fail;
	}
	while ((n = copy_file_range(cfd, &in, fd, &out, SSIZE_MAX, 0)) > 0)
		;
	if (n == -1 || close(fd) == -1) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		fd = -1;
		goto fail;
	}
	*dirp = dir;
	return (path);
fail:
	if (fd != -1)
		close(fd);
	(void)unlink(path);
	(void)rmdir(dir);
	return (NULL);
}

/* The debugger as nobody, the core its standard input, within limits. */
static void
debug_run(struct work *w, char **argv, int cfd, struct execres *res)
{
	char	*hv[40];
	int	 n, i;

	n = 0;
	hv[n++] = (char *)(uintptr_t)opts.helper_bin;
	hv[n++] = (char *)(uintptr_t)"--scope-helper";
	hv[n++] = (char *)(uintptr_t)"0";
	hv[n++] = (char *)(uintptr_t)"debug-as-nobody";
	for (i = 0; argv[i] != NULL && n < (int)nitems(hv) - 1; i++)
		hv[n++] = argv[i];
	hv[n] = NULL;
	(void)lseek(cfd, 0, SEEK_SET);
	exec_set_fds(cfd, -1);
	exec_set_limit(DBG_WALL);
	(void)run_exec_max(w, hv, res, BT_MAX);
}

/*
 * lldb's backtrace of every thread of a core, and the signal's code:
 * of r's, dir as r sees it.
 */
static int
core_backtrace(struct work *w, const struct croot *r, const char *dir,
    const char *core, const char *program, ucl_object_t *top,
    const char **errp)
{
	struct execres	 res;
	const char	*lldb, *gdb, *path, *base, *copy, *cdir, *prog,
			*rootp;
	char		*argv[28], *text, pattern[MAXPATHLEN],
			 comm[MAXCOMLEN + 2];
	size_t		 len;
	int		 n, step, pid, uid, cfd;

	if (!core_name_ok(core)) {
		*errp = "a core is named as the list has it";
		return (-1);
	}
	path = wfmt(w, "%s/%s", strcmp(dir, "/") == 0 ? "" : dir, core);
	len = sizeof(pattern);
	if (sysctlbyname("kern.corefile", pattern, &len, NULL, 0) != 0) {
		*errp = wfmt(w, "kern.corefile: %s", strerror(errno));
		return (-1);
	}
	pattern[MIN(len, sizeof(pattern) - 1)] = '\0';
	if (!core_matches(pattern, path, comm, &pid)) {
		*errp = wfmt(w, "%s is not where kern.corefile (%s) puts a "
		    "core: not read", path, pattern);
		return (-1);
	}
	if (!kmsg_core_dumped(comm, pid, r->jail != NULL ? r->jid : -1,
	    &uid)) {
		*errp = pid != -1 ? wfmt(w, "the kernel was not seen to dump a "
		    "core of %s, pid %d%s%s: %s not read", comm, pid, r->jail !=
		    NULL ? ", in the jail " : "", r->jail != NULL ? r->jail : "",
		    core) : wfmt(w, "the kernel was not seen to dump a core of "
		    "%s%s%s: %s not read", comm, r->jail != NULL ? " in the jail " :
		    "", r->jail != NULL ? r->jail : "", core);
		return (-1);
	}
	/* The program the kernel named; another of its name named. */
	if (program == NULL || program[0] == '\0')
		program = core_program(w, r, comm);
	if (program != NULL) {
		base = strrchr(program, '/') != NULL ? strrchr(program, '/') +
		    1 : program;
		if (strncmp(base, comm, strlen(comm)) != 0 || (strlen(base) !=
		    strlen(comm) && strlen(comm) < MAXCOMLEN)) {
			*errp = wfmt(w, "%s is not the program of %s, which is "
			    "%s's", program, core, comm);
			return (-1);
		}
	}
	if (program == NULL || !program_ok(r, program)) {
		*errp = r->jail != NULL ? wfmt(w, "the program of %s is not found "
		    "in the jail %s: name it as the jail has it", core, r->jail) :
		    wfmt(w, "the program of %s is not found: name it", core);
		return (-1);
	}
	/* The debugger's: the host's path to the jail's. */
	rootp = r->jail != NULL && strcmp(r->path, "/") != 0 ? r->path : "";
	prog = wfmt(w, "%s%s", rootp, program);
	if ((lldb = tool(w, "lldb")) == NULL) {
		*errp = "the host has no lldb(1): its base system is built "
		    "without it";
		return (-1);
	}
	if ((cfd = core_open(w, r, dir, core, uid, errp)) == -1)
		return (-1);
	if ((copy = core_copy(w, cfd, &cdir, errp)) == NULL) {
		close(cfd);
		return (-1);
	}
	n = 0;
	argv[n++] = (char *)(uintptr_t)lldb;
	argv[n++] = (char *)(uintptr_t)"--batch";
	argv[n++] = (char *)(uintptr_t)"--no-lldbinit";
	/* No script of the symbols' own, none of the directory's. */
	argv[n++] = (char *)(uintptr_t)"-O";
	argv[n++] = (char *)(uintptr_t)"settings set target.load-script-from-"
	    "symbol-file false";
	argv[n++] = (char *)(uintptr_t)"-O";
	argv[n++] = (char *)(uintptr_t)"settings set target.load-cwd-lldbinit "
	    "false";
	/* The symbols a port keeps apart (WITH_DEBUG): beside the base
	 * system's. */
	argv[n++] = (char *)(uintptr_t)"-O";
	argv[n++] = wfmt(w, "settings set target.debug-file-search-paths "
	    "%s/usr/local/lib/debug %s/usr/lib/debug", rootp, rootp);
	/* A jail's libraries, where the core names them, beneath its root. */
	if (rootp[0] != '\0') {
		argv[n++] = (char *)(uintptr_t)"-O";
		argv[n++] = wfmt(w, "settings set target.image-search-paths / "
		    "%s/", rootp);
	}
	argv[n++] = (char *)(uintptr_t)"-c";
	argv[n++] = (char *)(uintptr_t)copy;
	argv[n++] = (char *)(uintptr_t)"-o";
	argv[n++] = (char *)(uintptr_t)"thread list";
	argv[n++] = (char *)(uintptr_t)"-o";
	argv[n++] = (char *)(uintptr_t)"thread backtrace all";
	argv[n++] = (char *)(uintptr_t)"-o";
	argv[n++] = (char *)(uintptr_t)"thread siginfo";
	argv[n++] = (char *)(uintptr_t)"--";
	argv[n++] = (char *)(uintptr_t)prog;
	argv[n] = NULL;
	step = step_begin(w, STEP_EXEC, "lldb", "%s of %s", core,
	    prog);
	debug_run(w, argv, cfd, &res);
	(void)unlink(copy);
	(void)rmdir(cdir);
	text = wfmt(w, "%.*s%.*s", (int)res.outlen, res.out != NULL ? res.out :
	    "", (int)res.errlen, res.err != NULL ? res.err : "");
	step_end(w, step, strstr(text, "error:") == NULL, NULL);
	/* gdb too, when it is installed: it reads the signal's code from a
	 * FreeBSD core (si_code 100, BUS_OOMERR, is a page fault the kernel
	 * found no memory for), which lldb does not; and what lldb could
	 * not read. */
	if ((gdb = tool(w, "gdb")) != NULL) {
		n = 0;
		argv[n++] = (char *)(uintptr_t)gdb;
		argv[n++] = (char *)(uintptr_t)"-batch";
		argv[n++] = (char *)(uintptr_t)"-nx";
		/* Before anything is read: no script of the symbols'. */
		argv[n++] = (char *)(uintptr_t)"-iex";
		argv[n++] = (char *)(uintptr_t)"set auto-load off";
		/* A jail's libraries beneath its root. */
		if (rootp[0] != '\0') {
			argv[n++] = (char *)(uintptr_t)"-iex";
			argv[n++] = wfmt(w, "set sysroot %s", rootp);
		}
		argv[n++] = (char *)(uintptr_t)"-ex";
		argv[n++] = wfmt(w, "set debug-file-directory "
		    "%s/usr/local/lib/debug:%s/usr/lib/debug", rootp, rootp);
		argv[n++] = (char *)(uintptr_t)"-ex";
		argv[n++] = (char *)(uintptr_t)"info threads";
		argv[n++] = (char *)(uintptr_t)"-ex";
		argv[n++] = (char *)(uintptr_t)"thread apply all bt";
		argv[n++] = (char *)(uintptr_t)"-ex";
		argv[n++] = (char *)(uintptr_t)"print $_siginfo";
		argv[n++] = (char *)(uintptr_t)prog;
		argv[n++] = (char *)(uintptr_t)"/dev/fd/0";
		argv[n] = NULL;
		step = step_begin(w, STEP_EXEC, "gdb", "%s of %s",
		    core, prog);
		debug_run(w, argv, cfd, &res);
		text = wfmt(w, "%s\n%.*s%.*s", text, (int)res.outlen, res.out !=
		    NULL ? res.out : "", (int)res.errlen, res.err != NULL ?
		    res.err : "");
		step_end(w, step, res.outlen > 0, NULL);
	}
	close(cfd);
	if (text[0] == '\0') {
		*errp = wtext(w, exec_error(w, &res, "lldb"));
		return (-1);
	}
	ucl_object_insert_key(top, ucl_object_fromstring(core), "core", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_fromstring(program), "program",
	    0, false);
	if (r->jail != NULL)
		ucl_object_insert_key(top, ucl_object_fromstring(r->jail), "jail",
		    0, false);
	ucl_object_insert_key(top, ucl_object_fromstring(text), "backtrace", 0,
	    false);
	if (res.truncated)
		ucl_object_insert_key(top, ucl_object_frombool(true),
		    "truncated", 0, false);
	return (0);
}


/*
 * r's cores into cores: in kern.corefile's directory dir (NULL: none of
 * its own), its others and notes where those are given; then where else
 * a core may lie, and each home directory.
 */
static void
cores_of(struct work *w, const struct croot *r, const char *dir,
    ucl_object_t *cores, ucl_object_t *onames, ucl_object_t *notes)
{
	static const char *const elsewhere[] = { "/", "/root", "/tmp",
	    "/var/tmp", "/var/db/bird", "/usr/local/etc/bird" };
	DIR		*d;
	struct dirent	*de;
	const char	*err;
	size_t		 i;
	int		 others, fd;

	if (dir != NULL) {
		err = NULL;
		others = 0;
		if (!cores_list(w, r, dir, cores, &others, onames, &err)) {
			/* A jail with no such directory has dumped nothing
			 * there. */
			if (notes != NULL && (r->jail == NULL || errno != ENOENT))
				ucl_array_append(notes, ucl_object_fromstring(
				    r->jail != NULL ? wfmt(w, "the jail %s: %s",
				    r->jail, err) : err));
		} else if (others > 0 && notes != NULL)
			ucl_array_append(notes, ucl_object_fromstring(wfmt(w,
			    "%s holds %d other file%s", root_path(w, r, dir),
			    others, others == 1 ? "" : "s")));
	}
	/* Where else a core may lie: a daemon's working directory, /,
	 * where a %N.core of an earlier setting went; and where a hand
	 * puts one aside. */
	for (i = 0; i < nitems(elsewhere); i++) {
		if (dir != NULL && strcmp(dir, elsewhere[i]) == 0)
			continue;
		err = NULL;
		others = 0;
		(void)cores_list(w, r, elsewhere[i], cores, &others, NULL, &err);
	}
	/* And each home directory. */
	if ((fd = root_dir(r, "/home")) == -1)
		return;
	if ((d = fdopendir(fd)) == NULL) {
		close(fd);
		return;
	}
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.' || de->d_type != DT_DIR)
			continue;
		err = NULL;
		others = 0;
		(void)cores_list(w, r, wfmt(w, "/home/%s", de->d_name), cores,
		    &others, NULL, &err);
	}
	closedir(d);
}

/*
 * The cores, the host's and each running jail's, or with names
 * "backtrace" core [program [jail]] one's backtrace besides (a jail's
 * core with its jail named, its program as the jail has it).
 */
void
do_crashes(struct work *w, const char *const *names, size_t n,
    struct json_rsp *rsp)
{
	ucl_object_t		*top, *cores, *notes, *onames;
	struct jinfo		*ji;
	struct croot		*roots;
	const struct croot	*r;
	char			 pattern[MAXPATHLEN], *json;
	const char		*dir, *err, *jail;
	size_t			 i, nj, nr;

	top = ucl_object_typed_new(UCL_OBJECT);
	notes = ucl_object_typed_new(UCL_ARRAY);
	dir = core_dir(w, pattern, sizeof(pattern));
	ucl_object_insert_key(top, ucl_object_fromstring(pattern),
	    "corefile", 0, false);
	cores = ucl_object_typed_new(UCL_ARRAY);
	onames = NULL;
	if (dir == NULL)
		ucl_array_append(notes, ucl_object_fromstring("kern.corefile "
		    "names no directory of its own: each core is where its "
		    "process ran"));
	else {
		ucl_object_insert_key(top, ucl_object_fromstring(dir),
		    "directory", 0, false);
		onames = ucl_object_typed_new(UCL_ARRAY);
	}
	cores_of(w, &host_root, dir, cores, onames, notes);
	if (onames != NULL)
		ucl_object_insert_key(top, onames, "others", 0, false);
	/*
	 * Each running jail's, beneath its root: kern.corefile is the
	 * host's, the path it gives the process's own.  A jail whose root
	 * is the host's has its cores where the host's are.
	 */
	ji = NULL;
	nj = nr = 0;
	err = NULL;
	if (jails_running(w, &ji, &nj, &err) != 0)
		ucl_array_append(notes, ucl_object_fromstring(wfmt(w, "the "
		    "jails' cores are not listed: %s", err != NULL ? err :
		    "the jails could not be read")));
	roots = wcalloc(w, nj + 1, sizeof(*roots));
	for (i = 0; i < nj; i++) {
		if (ji[i].dying || ji[i].name == NULL || ji[i].path == NULL ||
		    ji[i].path[0] != '/' || strcmp(ji[i].path, "/") == 0)
			continue;
		roots[nr].jail = ji[i].name;
		roots[nr].jid = ji[i].jid;
		roots[nr].path = ji[i].path;
		cores_of(w, &roots[nr], dir, cores, NULL, notes);
		nr++;
	}
	ucl_object_insert_key(top, cores, "cores", 0, false);
	ucl_object_insert_key(top, notes, "notes", 0, false);
	if (n >= 2 && strcmp(names[0], "backtrace") == 0) {
		const ucl_object_t	*c;
		ucl_object_iter_t	 it = NULL;
		const char		*where = NULL, *cj;

		/* The jail named, running. */
		jail = n >= 4 && names[3][0] != '\0' ? names[3] : NULL;
		r = &host_root;
		if (jail != NULL) {
			for (i = 0; i < nr && strcmp(roots[i].jail, jail) != 0;
			    i++)
				;
			if (i == nr) {
				ucl_object_unref(top);
				rsp->ok = false;
				rsp->error = wfmt(w, "the jail %s is not running, "
				    "or its root is the host's", jail);
				return;
			}
			r = &roots[i];
		}
		/* The core named, where the list found it, of that jail or
		 * the host. */
		while ((c = ucl_object_iterate(cores, &it, true)) != NULL) {
			cj = ucl_object_tostring(ucl_object_lookup(c, "jail"));
			if (ucl_object_tostring(ucl_object_lookup(c, "name")) !=
			    NULL && strcmp(ucl_object_tostring(ucl_object_lookup(
			    c, "name")), names[1]) == 0 && ((jail == NULL && cj ==
			    NULL) || (jail != NULL && cj != NULL && strcmp(cj,
			    jail) == 0)))
				where = ucl_object_tostring(ucl_object_lookup(c,
				    "directory"));
		}
		if (where == NULL)
			where = r->jail == NULL ? dir : dir != NULL ?
			    root_path(w, r, dir) : NULL;
		/* A jail's, as the jail sees it: beneath its root. */
		if (where != NULL && r->jail != NULL) {
			i = strlen(r->path);
			where = strncmp(where, r->path, i) == 0 && (where[i] ==
			    '\0' || where[i] == '/') ? (where[i] == '\0' ? "/" :
			    where + i) : NULL;
		}
		err = NULL;
		if (where == NULL || core_backtrace(w, r, where, names[1], n >= 3 ?
		    names[2] : NULL, top, &err) != 0) {
			ucl_object_unref(top);
			rsp->ok = false;
			rsp->error = err != NULL ? err : "no directory of cores";
			return;
		}
	}
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL) {
		rsp->ok = false;
		rsp->error = "out of memory";
		return;
	}
	rsp->json = wstrdup(w, json);
	free(json);
	rsp->ok = true;
}

/*
 * The crash job: verb delete takes away the core args names, the
 * host's, or with jail a running jail's: in kern.corefile's directory
 * alone (beneath the jail's root, opened without a link out of it), a
 * regular file of one link, its name a core's.  A core elsewhere (/,
 * /tmp, a home directory) is listed but not taken away here: a file
 * there may be anybody's.  Not undone, so never in safe mode.
 */
const char *
crash_check(const struct arc_job_spec *sp)
{

	if (sp->safe)
		return ("a core taken away is not put back: not in safe mode");
	if (sp->verb == NULL || strcmp(sp->verb, "delete") != 0)
		return ("a crash job's verb is delete");
	if (sp->names.n != 1 || !core_name_ok(sp->names.v[0]))
		return ("name one core as the crashes read lists it, its file's "
		    "name: <program>.<pid>.core, <program>.core or core");
	return (NULL);
}

char *
crash_title(const struct arc_job_spec *sp)
{
	char	*t;

	if (asprintf(&t, "core %s taken away%s%s", sp->names.n > 0 ?
	    sp->names.v[0] : "?", sp->jail != NULL && sp->jail[0] != '\0' ?
	    " in " : "", sp->jail != NULL ? sp->jail : "") == -1)
		return (NULL);
	return (t);
}

int
do_crash_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	struct croot	 r;
	struct jinfo	*ji;
	struct stat	 sb;
	char		 pattern[MAXPATHLEN];
	const char	*dir, *name, *err;
	size_t		 i, nj;
	int		 dfd, e;

	name = sp->names.v[0];
	if ((dir = core_dir(w, pattern, sizeof(pattern))) == NULL) {
		*errp = "kern.corefile names no directory of its own: a core "
		    "where its process ran is not taken away by Arcana";
		return (-1);
	}
	r = host_root;
	if (sp->jail != NULL && sp->jail[0] != '\0') {
		ji = NULL;
		nj = 0;
		err = NULL;
		if (jails_running(w, &ji, &nj, &err) != 0) {
			*errp = err != NULL ? err : "the jails could not be read";
			return (-1);
		}
		for (i = 0; i < nj; i++)
			if (!ji[i].dying && ji[i].name != NULL && strcmp(
			    ji[i].name, sp->jail) == 0 && ji[i].path != NULL &&
			    ji[i].path[0] == '/' && strcmp(ji[i].path, "/") != 0)
				break;
		if (i == nj) {
			*errp = wfmt(w, "the jail %s is not running, or its root "
			    "is the host's", sp->jail);
			return (-1);
		}
		r.jail = ji[i].name;
		r.jid = ji[i].jid;
		r.path = ji[i].path;
	}
	if ((dfd = root_dir(&r, dir)) == -1) {
		*errp = wfmt(w, "%s: %s", root_path(w, &r, dir), strerror(errno));
		return (-1);
	}
	if (fstatat(dfd, name, &sb, AT_SYMLINK_NOFOLLOW) != 0) {
		e = errno;
		close(dfd);
		*errp = wfmt(w, "%s/%s: %s", root_path(w, &r, dir), name,
		    strerror(e));
		return (-1);
	}
	if (!S_ISREG(sb.st_mode) || sb.st_nlink != 1) {
		close(dfd);
		*errp = wfmt(w, "%s/%s is not a core of its own (a regular "
		    "file of one link): not taken away", root_path(w, &r, dir),
		    name);
		return (-1);
	}
	if (unlinkat(dfd, name, 0) != 0) {
		e = errno;
		close(dfd);
		*errp = wfmt(w, "%s/%s: %s", root_path(w, &r, dir), name,
		    strerror(e));
		return (-1);
	}
	close(dfd);
	return (0);
}
