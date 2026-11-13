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
 * (BUS_OOMERR) from one of a bad address.  Nothing is changed: a core
 * is read, not moved nor taken away.
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

/* The program of that name (the crashed process's, as the kernel
 * names it), where programs are. */
static const char *
core_program(struct work *w, const char *name)
{
	static const char *const dirs[] = { "/usr/local/sbin",
	    "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin",
	    "/usr/libexec", "/usr/local/libexec" };
	const char	*p;
	size_t		 i;

	for (i = 0; i < nitems(dirs); i++) {
		p = wfmt(w, "%s/%s", dirs[i], name);
		if (access(p, X_OK) == 0)
			return (p);
	}
	return (NULL);
}

/*
 * The cores of dir into arr, each with where it is; *othersp counts
 * the directory's other files; false, with why in *errp, when the
 * directory cannot be read.
 */
static bool
cores_list(struct work *w, const char *dir, ucl_object_t *arr, int *othersp,
    ucl_object_t *others, const char **errp)
{
	ucl_object_t	*o;
	DIR		*d;
	struct dirent	*de;
	struct stat	 st;
	char		 pid[16];
	const char	*p;
	int		 n;

	if ((d = opendir(dir)) == NULL) {
		*errp = wfmt(w, "%s: %s", dir, strerror(errno));
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
				    w, "%s/%s (%jd bytes)", strcmp(dir, "/") == 0 ? "" :
				    dir, de->d_name, (intmax_t)st.st_size)));
			continue;
		}
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(de->d_name),
		    "name", 0, true);
		ucl_object_insert_key(o, ucl_object_fromstring(dir), "directory",
		    0, true);
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
 * The core opened: beneath its directory, never through a link, a
 * regular file of one link, the crashed process's user's or root's,
 * not too large; -1 and why.
 */
static int
core_open(struct work *w, const char *dir, const char *core, int uid,
    const char **errp)
{
	struct stat	 sb;
	int		 dfd, fd;

	if ((dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) == -1) {
		*errp = wfmt(w, "%s: %s", dir, strerror(errno));
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

/* lldb's backtrace of every thread of a core, and the signal's code. */
static int
core_backtrace(struct work *w, const char *dir, const char *core,
    const char *program, ucl_object_t *top, const char **errp)
{
	struct execres	 res;
	const char	*lldb, *gdb, *path, *base, *copy, *cdir;
	char		*argv[24], *text, pattern[MAXPATHLEN],
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
	if (!kmsg_core_dumped(comm, pid, &uid)) {
		*errp = pid != -1 ? wfmt(w, "the kernel was not seen to dump a "
		    "core of %s, pid %d: %s not read", comm, pid, core) :
		    wfmt(w, "the kernel was not seen to dump a core of %s: %s "
		    "not read", comm, core);
		return (-1);
	}
	/* The program the kernel named; another of its name named. */
	if (program == NULL || program[0] == '\0')
		program = core_program(w, comm);
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
	if (program == NULL || program[0] != '/' || access(program, X_OK) !=
	    0) {
		*errp = wfmt(w, "the program of %s is not found: name it", core);
		return (-1);
	}
	if ((lldb = tool(w, "lldb")) == NULL) {
		*errp = "the host has no lldb(1): its base system is built "
		    "without it";
		return (-1);
	}
	if ((cfd = core_open(w, dir, core, uid, errp)) == -1)
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
	argv[n++] = (char *)(uintptr_t)"settings set target.debug-file-search-"
	    "paths /usr/local/lib/debug /usr/lib/debug";
	argv[n++] = (char *)(uintptr_t)"-c";
	argv[n++] = (char *)(uintptr_t)copy;
	argv[n++] = (char *)(uintptr_t)"-o";
	argv[n++] = (char *)(uintptr_t)"thread list";
	argv[n++] = (char *)(uintptr_t)"-o";
	argv[n++] = (char *)(uintptr_t)"thread backtrace all";
	argv[n++] = (char *)(uintptr_t)"-o";
	argv[n++] = (char *)(uintptr_t)"thread siginfo";
	argv[n++] = (char *)(uintptr_t)"--";
	argv[n++] = (char *)(uintptr_t)program;
	argv[n] = NULL;
	step = step_begin(w, STEP_EXEC, "lldb", "%s of %s", core,
	    program);
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
		argv[n++] = (char *)(uintptr_t)"-ex";
		argv[n++] = (char *)(uintptr_t)"set debug-file-directory "
		    "/usr/local/lib/debug:/usr/lib/debug";
		argv[n++] = (char *)(uintptr_t)"-ex";
		argv[n++] = (char *)(uintptr_t)"info threads";
		argv[n++] = (char *)(uintptr_t)"-ex";
		argv[n++] = (char *)(uintptr_t)"thread apply all bt";
		argv[n++] = (char *)(uintptr_t)"-ex";
		argv[n++] = (char *)(uintptr_t)"print $_siginfo";
		argv[n++] = (char *)(uintptr_t)program;
		argv[n++] = (char *)(uintptr_t)"/dev/fd/0";
		argv[n] = NULL;
		step = step_begin(w, STEP_EXEC, "gdb", "%s of %s",
		    core, program);
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
	ucl_object_insert_key(top, ucl_object_fromstring(text), "backtrace", 0,
	    false);
	if (res.truncated)
		ucl_object_insert_key(top, ucl_object_frombool(true),
		    "truncated", 0, false);
	return (0);
}

/*
 * The cores, or with names "backtrace" core [program] one's backtrace
 * besides.
 */
void
do_crashes(struct work *w, const char *const *names, size_t n,
    struct json_rsp *rsp)
{
	static const char *const elsewhere[] = { "/", "/root", "/tmp",
	    "/var/tmp", "/var/db/bird", "/usr/local/etc/bird" };
	ucl_object_t	*top, *cores, *notes, *onames;
	char		 pattern[MAXPATHLEN], *json;
	const char	*dir, *err;
	size_t		 i;
	int		 others;

	top = ucl_object_typed_new(UCL_OBJECT);
	notes = ucl_object_typed_new(UCL_ARRAY);
	dir = core_dir(w, pattern, sizeof(pattern));
	ucl_object_insert_key(top, ucl_object_fromstring(pattern),
	    "corefile", 0, false);
	cores = ucl_object_typed_new(UCL_ARRAY);
	others = 0;
	if (dir == NULL)
		ucl_array_append(notes, ucl_object_fromstring("kern.corefile "
		    "names no directory of its own: each core is where its "
		    "process ran"));
	else {
		ucl_object_insert_key(top, ucl_object_fromstring(dir),
		    "directory", 0, false);
		onames = ucl_object_typed_new(UCL_ARRAY);
		err = NULL;
		if (!cores_list(w, dir, cores, &others, onames, &err))
			ucl_array_append(notes, ucl_object_fromstring(err));
		else if (others > 0)
			ucl_array_append(notes, ucl_object_fromstring(wfmt(w,
			    "%s holds %d other file%s", dir, others, others == 1 ?
			    "" : "s")));
		ucl_object_insert_key(top, onames, "others", 0, false);
	}
	/* Where else a core may lie: a daemon's working directory, /,
	 * where a %N.core of an earlier setting went; and where a hand
	 * puts one aside. */
	for (i = 0; i < nitems(elsewhere); i++) {
		if (dir != NULL && strcmp(dir, elsewhere[i]) == 0)
			continue;
		err = NULL;
		others = 0;
		(void)cores_list(w, elsewhere[i], cores, &others, NULL, &err);
	}
	/* And each home directory. */
	{
		DIR		*d;
		struct dirent	*de;

		if ((d = opendir("/home")) != NULL) {
			while ((de = readdir(d)) != NULL) {
				if (de->d_name[0] == '.' || de->d_type != DT_DIR)
					continue;
				err = NULL;
				others = 0;
				(void)cores_list(w, wfmt(w, "/home/%s", de->d_name),
				    cores, &others, NULL, &err);
			}
			closedir(d);
		}
	}
	ucl_object_insert_key(top, cores, "cores", 0, false);
	ucl_object_insert_key(top, notes, "notes", 0, false);
	if (n >= 2 && strcmp(names[0], "backtrace") == 0) {
		const ucl_object_t	*c;
		ucl_object_iter_t	 it = NULL;
		const char		*where = dir;

		/* The core named, where the list found it. */
		while ((c = ucl_object_iterate(cores, &it, true)) != NULL)
			if (ucl_object_tostring(ucl_object_lookup(c, "name")) !=
			    NULL && strcmp(ucl_object_tostring(ucl_object_lookup(
			    c, "name")), names[1]) == 0)
				where = ucl_object_tostring(ucl_object_lookup(c,
				    "directory"));
		err = NULL;
		if (where == NULL || core_backtrace(w, where, names[1], n >= 3 ?
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
