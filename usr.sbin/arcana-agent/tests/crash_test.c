/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * crash [backtrace core [program [jail]]]: crashes.c alone, for
 * agent_test.sh, what a backtrace is let read and how its debugger is
 * run.  The environment stands in for the host: COREFILE kern.corefile's
 * pattern, KMSG "name pid uid [jid]" the core the kernel said it dumped,
 * JAILS "name:jid:root ..." the jails running,
 * LLDB and GDB the debuggers found (none when unset), TMPDIR where a
 * copy goes.  Each program it would run is printed as "exec" and its
 * words, what its standard input begins with as "stdin" (or "stdin
 * none"), and what the file after -c begins with as "core-file", with
 * its mode; then "ok" and the reply, or "error" and why.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "agent.h"

struct opts	opts;
static int	in_fd = -1;

/* The host's kern.corefile, COREFILE's. */
int
sysctlbyname(const char *name, void *old, size_t *oldlen,
    const void *new __unused, size_t newlen __unused)
{
	const char	*v;

	if (strcmp(name, "kern.corefile") != 0 || (v = getenv("COREFILE")) ==
	    NULL) {
		errno = ENOENT;
		return (-1);
	}
	if (old != NULL)
		strlcpy(old, v, *oldlen);
	*oldlen = strlen(v) + 1;
	return (0);
}

/* KMSG "name pid uid [jid]": jid 0, the host's, when not given. */
bool
kmsg_core_dumped(const char *comm, int pid, int jid, int *uidp)
{
	const char	*k;
	char		 c[64];
	int		 p, u, j;

	j = 0;
	if ((k = getenv("KMSG")) == NULL || sscanf(k, "%63s %d %d %d", c, &p,
	    &u, &j) < 3 || strcmp(c, comm) != 0 || (pid != -1 && pid != p) ||
	    (jid != -1 && jid != j))
		return (false);
	*uidp = u;
	return (true);
}

/* The running jails, JAILS's "name:jid:root" separated by spaces. */
int
jails_running(struct work *w __unused, struct jinfo **out, size_t *nout,
    const char **errp __unused)
{
	struct jinfo	*v;
	char		*s, *one, *name, *jid;
	size_t		 n;

	*out = NULL;
	*nout = 0;
	if (getenv("JAILS") == NULL || (s = strdup(getenv("JAILS"))) == NULL)
		return (0);
	if ((v = calloc(16, sizeof(*v))) == NULL)
		abort();
	n = 0;
	while (n < 16 && (one = strsep(&s, " ")) != NULL) {
		if ((name = strsep(&one, ":")) == NULL || (jid = strsep(&one,
		    ":")) == NULL || one == NULL)
			continue;
		v[n].name = name;
		v[n].jid = atoi(jid);
		v[n].path = one;
		n++;
	}
	*out = v;
	*nout = n;
	return (0);
}

void *
wcalloc(struct work *w __unused, size_t n, size_t size)
{
	void	*p;

	if ((p = calloc(n, size)) == NULL)
		abort();
	return (p);
}

const char *
tmp_dir(void)
{

	return (getenv("TMPDIR") != NULL ? getenv("TMPDIR") : "/tmp");
}

const char *
tool(struct work *w __unused, const char *name)
{

	return (getenv(strcmp(name, "lldb") == 0 ? "LLDB" : strcmp(name,
	    "gdb") == 0 ? "GDB" : "NONE"));
}

void
exec_set_fds(int in, int out __unused)
{

	in_fd = in;
}

void
exec_set_limit(int secs)
{

	printf("limit %d\n", secs);
}

int
run_exec_max(struct work *w __unused, char *const argv[],
    struct execres *res, size_t max __unused)
{
	struct stat	 sb;
	FILE		*fp;
	char		 buf[32];
	ssize_t		 n;
	int		 i;

	printf("exec");
	for (i = 0; argv[i] != NULL; i++)
		printf(" %s", argv[i]);
	printf("\n");
	for (i = 0; argv[i] != NULL; i++)
		if (strcmp(argv[i], "-c") == 0 && argv[i + 1] != NULL &&
		    (fp = fopen(argv[i + 1], "r")) != NULL) {
			if (fgets(buf, sizeof(buf), fp) != NULL &&
			    fstat(fileno(fp), &sb) == 0)
				printf("core-file %.*s %o\n", (int)strcspn(buf,
				    "\n"), buf, sb.st_mode & 07777);
			fclose(fp);
		}
	if (in_fd == -1)
		printf("stdin none\n");
	else if ((n = pread(in_fd, buf, sizeof(buf) - 1, 0)) >= 0) {
		buf[n] = '\0';
		printf("stdin %.*s\n", (int)strcspn(buf, "\n"), buf);
	}
	in_fd = -1;
	memset(res, 0, sizeof(*res));
	res->out = "bt\n";
	res->outlen = 3;
	return (0);
}

const char *
exec_error(struct work *w __unused, const struct execres *res __unused,
    const char *prog)
{

	return (prog);
}

int
step_begin(struct work *w __unused, uint8_t kind __unused,
    const char *label __unused, const char *fmt __unused, ...)
{

	return (0);
}

void
step_end(struct work *w __unused, int step __unused, bool ok __unused,
    const char *fmt __unused, ...)
{
}

char *
wstrdup(struct work *w __unused, const char *s)
{

	return (strdup(s));
}

char *
wstrndup(struct work *w __unused, const char *s, size_t n)
{

	return (strndup(s, n));
}

char *
wfmt(struct work *w __unused, const char *fmt, ...)
{
	va_list	 ap;
	char	*s;

	va_start(ap, fmt);
	if (vasprintf(&s, fmt, ap) == -1)
		abort();
	va_end(ap);
	return (s);
}

const char *
wtext(struct work *w __unused, const char *s)
{

	return (s);
}

int
main(int argc, char **argv)
{
	struct work	w;
	struct json_rsp	rsp;

	memset(&w, 0, sizeof(w));
	memset(&rsp, 0, sizeof(rsp));
	opts.helper_bin = "/helper";
	do_crashes(&w, (const char *const *)(argv + 1), (size_t)argc - 1,
	    &rsp);
	if (rsp.ok)
		printf("ok %s\n", rsp.json);
	else
		printf("error %s\n", rsp.error);
	return (0);
}
