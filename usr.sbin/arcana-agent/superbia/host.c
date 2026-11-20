/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/utsname.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"
#include "zprog.h"

/* What this agent takes that one before it did not (hello's features). */
static const char *const features[] = {
	ZPROG_FEATURE,		/* agent-update's program compressed */
	SIGNED_UPDATE_FEATURE,	/* its signature of its statement */
};

/*
 * Whether this agent has the feature: all of them, unless --features
 * names those it has, as an agent before the others.
 */
bool
has_feature(const char *name)
{
	const char	*p;
	size_t		 n;

	if (opts.features == NULL)
		return (true);
	n = strlen(name);
	for (p = opts.features; *p != '\0'; p += strcspn(p, ",")) {
		p += strspn(p, ",");
		if (strncmp(p, name, n) == 0 && (p[n] == ',' || p[n] == '\0'))
			return (true);
	}
	return (false);
}

/*
 * A text sysctl of the kernel's, its first line: from sysctl(3), or
 * from the sysctl(8) the tests give in its place.  NULL when there is
 * none.
 */
static const char *
kern_text(struct work *w, const char *name)
{
	struct execres	 res;
	char		*argv[4], *v;
	size_t		 len;

	if (strcmp(opts.sysctl_bin, "/sbin/sysctl") == 0) {
		if (sysctlbyname(name, NULL, &len, NULL, 0) != 0 || len == 0)
			return (NULL);
		v = wcalloc(w, len + 1, 1);
		if (sysctlbyname(name, v, &len, NULL, 0) != 0)
			return (NULL);
	} else {
		argv[0] = (char *)(uintptr_t)opts.sysctl_bin;
		argv[1] = (char *)(uintptr_t)"-n";
		argv[2] = (char *)(uintptr_t)name;
		argv[3] = NULL;
		if (run_read(w, argv, &res) != 0 || res.out == NULL)
			return (NULL);
		v = wstrndup(w, res.out, res.outlen);
	}
	v[strcspn(v, "\n")] = '\0';
	return (v[0] != '\0' ? wtext(w, v) : NULL);
}

/* Facts about this host, from uname(3) and sysctl(3). */
void
host_info(struct work *w, struct host_facts *h)
{
	struct utsname	 u;
	struct timeval	 boot;
	const char	**fv;
	uint64_t	 physmem;
	size_t		 len, i;
	char		 name[MAXHOSTNAMELEN];
	int		 ncpu, securelevel, step;

	memset(h, 0, sizeof(*h));
	step = step_begin(w, STEP_LIB, "uname(3)", NULL);
	if (uname(&u) == 0) {
		h->sysname = wtext(w, wstrdup(w, u.sysname));
		h->release = wtext(w, wstrdup(w, u.release));
		h->machine = wtext(w, wstrdup(w, u.machine));
		step_end(w, step, true, "%s %s %s", u.sysname, u.release,
		    u.machine);
	} else
		step_end(w, step, false, NULL);
	if (gethostname(name, sizeof(name)) == 0)
		h->hostname = wname(w, wstrdup(w, name));
	h->has_osreldate = true;
	h->osreldate = (uint32_t)getosreldate();
	/* The running kernel: its version line names its build (the
	 * commit, "main-n291371-fb9969ca61ca", when built from git), the
	 * console's to compare with the fixes it knows of. */
	h->kernel_version = kern_text(w, "kern.version");
	if (strcmp(opts.sysctl_bin, "/sbin/sysctl") != 0) {
		const char	*od;
		char		*end;
		unsigned long	 n;

		if ((od = kern_text(w, "kern.osreldate")) != NULL &&
		    (n = strtoul(od, &end, 10)) > 0 && *end == '\0')
			h->osreldate = (uint32_t)n;
	}
	{
		long	r;

		if ((r = sysctl_int_here(w, "net.inet6.ip6.redirect")) >= 0) {
			h->has_ip6_redirect = true;
			h->ip6_redirect = r != 0;
		}
	}

	step = step_begin(w, STEP_LIB, "sysctlbyname(3)",
	    "hw.ncpu hw.physmem kern.boottime kern.securelevel");
	len = sizeof(ncpu);
	if (sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0) == 0) {
		h->has_ncpu = true;
		h->ncpu = (uint32_t)ncpu;
	}
	len = sizeof(physmem);
	if (sysctlbyname("hw.physmem", &physmem, &len, NULL, 0) == 0) {
		h->has_physmem = true;
		h->physmem = physmem;
	}
	len = sizeof(boot);
	if (sysctlbyname("kern.boottime", &boot, &len, NULL, 0) == 0) {
		h->has_boottime = true;
		h->boottime = boot.tv_sec;
	}
	len = sizeof(securelevel);
	if (sysctlbyname("kern.securelevel", &securelevel, &len, NULL,
	    0) == 0) {
		h->has_securelevel = true;
		h->securelevel = securelevel;
	}
	step_end(w, step, true, NULL);
	h->has_time = true;
	h->time = time(NULL);
	h->has_privileged = true;
	h->privileged = geteuid() == 0;
	h->has_safe_wait = true;
	h->safe_wait = (uint32_t)opts.safe_wait;
	h->terminal_users = terminal_users_usable();
	h->version = ARCANA_AGENT_VERSION;
	if (opts.build[0] != '\0')
		h->build = opts.build;
	plugins_there(w, 0, NULL, &h->plugins.v, &h->plugins.n);
	fv = wcalloc(w, nitems(features), sizeof(*fv));
	for (i = 0; i < nitems(features); i++)
		if (has_feature(features[i]))
			fv[h->features.n++] = features[i];
	h->features.v = fv;
}
