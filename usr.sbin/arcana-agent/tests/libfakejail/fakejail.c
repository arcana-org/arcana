/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The jail system calls for the tests, preloaded (LD_PRELOAD) into the
 * agent they start: jail_get(2), jail_set(2) and jail_remove(2) of the
 * jails in the file FAKEJAIL names, one jail a line,
 *
 *	name jid vnet path [osrelease] [parameter=value ...]
 *
 * as "gw 4 new /tmp/t/jroot 16.0-CURRENT allow.chflags=0
 * host.hostname=gw.example.org ip4.addr=10.0.0.4": jails nobody made,
 * there for the agent alone.  libjail(3) is the host's, and asks these,
 * so what it says of a jail (jail_getv, jail_getid, jailparam_get) is
 * the file's: a parameter the line does not give is what a jail has of
 * nothing, 0 or empty.  A jail not in it, or no file, is not running;
 * a walk by lastjid goes through the file's, by their jids.  An update
 * of one (jailparam_set with JAIL_UPDATE, as jail -m) writes what it
 * sets on its line, a boolean as 1 or 0; jail_remove takes its line
 * out.  Without FAKEJAIL, or without the file for a walk, the kernel
 * answers: the list of every jail stays the host's.  A jail made
 * (JAIL_CREATE) is the kernel's; nothing else reaches a jail of the
 * host's while FAKEJAIL is set.
 *
 * And if_nametoindex(3): the interfaces FAKEIFS names, separated by
 * spaces, are there when the host has none of the name, so that the
 * tests' documents may name a host's network card (vtnet0) on a host
 * whose cards are called otherwise.
 *
 * And sysctl(3)'s reads of the values FAKESYSCTL names, as
 * "net.add_addr_allfibs=0 kern.hostname=lab" (separated by spaces): the
 * value given, not the host's, which may be set otherwise than the
 * kernel's default the tests' plans are made for, or name the machine
 * the tests run on.  A number is an int, or a long where the caller's
 * room or the number asks it (hw.physmem); anything else a string.
 * gethostname(3) and uname(3)'s node name answer kern.hostname's.  The
 * format, description and everything else are the kernel's; a write
 * goes to the kernel.
 *
 * And time(3) stepped by the seconds in the file FAKETIME names (read
 * again a second on at most, by the monotonic clock), as a step of the
 * wall clock would: the monotonic clock is the kernel's.
 *
 * And ipfw's IP_FW3 socket option, when FAKEIPFW names a file: the raw
 * socket ipfw(8) asks with (AF_INET, SOCK_RAW, IPPROTO_RAW) is a
 * descriptor of /dev/null, and on it IP_FW_XGET answers the rules of
 * the file, one a line,
 *
 *	number set packets bytes comment ...
 *
 * as "9 30 100 8000 am 0.0 out 0 sw1/a-b": a count rule of that number
 * in that set with those counters, the rest its comment (O_NOP), the
 * file read anew at each question; IP_FW_TABLE_XSWAP writes "swap set
 * first second" and the wall clock's milliseconds at the end of
 * FAKEIPFW.log.  Any other IP_FW3 opcode is refused (EOPNOTSUPP).
 */

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/uio.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_fw.h>
#include <arpa/inet.h>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* A line's fields: name, jid, vnet, path, osrelease, then key=value. */
#define	FJ_POS		5
#define	FJ_FIELDS	64
#define	FJ_LINE		(MAXPATHLEN + 4096)

/* One jail of the file: its line, split in place. */
struct fj {
	char	 line[FJ_LINE];
	char	*f[FJ_FIELDS];
	int	 n;			/* fields, FJ_POS at least */
	int	 jid;
};

typedef int	jail_iov_fn(struct iovec *, unsigned int, int);
typedef int	jail_remove_fn(int);

static char	empty[] = "";

/* The real system call's wrapper, libc's. */
static void *
real(const char *name)
{
	void	*fn;

	if ((fn = dlsym(RTLD_NEXT, name)) == NULL)
		errno = ENOSYS;
	return (fn);
}

/* The message the kernel gives back in errmsg, when asked for one. */
static void
iov_errmsg(struct iovec *iov, unsigned int niov, const char *msg)
{
	unsigned int	i;

	for (i = 0; i + 1 < niov; i += 2)
		if (iov[i].iov_base != NULL && strcmp(iov[i].iov_base,
		    "errmsg") == 0 && iov[i + 1].iov_base != NULL &&
		    iov[i + 1].iov_len > 0)
			strlcpy(iov[i + 1].iov_base, msg, iov[i + 1].iov_len);
}

/* A line split: false for a comment or one without name and jid. */
static bool
fj_split(struct fj *j)
{
	char	*p, *s;
	int	 n;

	if (j->line[0] == '#')
		return (false);
	j->line[strcspn(j->line, "\n")] = '\0';
	n = 0;
	p = j->line;
	while (n < FJ_FIELDS && (s = strsep(&p, " \t")) != NULL)
		if (s[0] != '\0') {
			/* No release, its parameters at once. */
			if (n == FJ_POS - 1 && strchr(s, '=') != NULL)
				j->f[n++] = empty;
			if (n < FJ_FIELDS)
				j->f[n++] = s;
		}
	if (n < 2)
		return (false);
	while (n < FJ_POS)
		j->f[n++] = empty;
	j->n = n;
	j->jid = (int)strtol(j->f[1], NULL, 10);
	return (true);
}

/*
 * Every jail of the file, in js (*nj of them, at most max); false
 * without the file.
 */
static bool
fj_read(const char *file, struct fj *js, int max, int *nj)
{
	FILE	*fp;

	*nj = 0;
	if ((fp = fopen(file, "r")) == NULL)
		return (false);
	while (*nj < max && fgets(js[*nj].line, FJ_LINE, fp) != NULL)
		if (fj_split(&js[*nj]))
			(*nj)++;
	fclose(fp);
	return (true);
}

/* The file again, from js: a new one put in its place. */
static int
fj_write(const char *file, struct fj *js, int nj)
{
	FILE	*fp;
	char	 tmp[MAXPATHLEN];
	int	 i, k;

	snprintf(tmp, sizeof(tmp), "%s.fj%d", file, (int)getpid());
	if ((fp = fopen(tmp, "w")) == NULL)
		return (-1);
	for (i = 0; i < nj; i++) {
		if (js[i].n == 0)
			continue;
		for (k = 0; k < js[i].n; k++) {
			/* An empty release written as one would not be read. */
			if (k == FJ_POS - 1 && js[i].f[k][0] == '\0') {
				if (js[i].n == FJ_POS)
					break;
				continue;
			}
			fprintf(fp, "%s%s", k == 0 ? "" : " ", js[i].f[k]);
		}
		fputc('\n', fp);
	}
	if (fclose(fp) != 0 || rename(tmp, file) != 0) {
		unlink(tmp);
		return (-1);
	}
	return (0);
}

/* The value the line gives the parameter, or NULL. */
static const char *
fj_value(const struct fj *j, const char *name)
{
	static const char	*pos[FJ_POS] = { "name", "jid", "vnet",
				    "path", "osrelease" };
	size_t			 n;
	int			 i;

	for (i = 0; i < FJ_POS; i++)
		if (strcmp(name, pos[i]) == 0)
			return (i == FJ_POS - 1 && j->f[i][0] == '\0' ? NULL :
			    j->f[i]);
	n = strlen(name);
	for (i = FJ_POS; i < j->n; i++)
		if (strncmp(j->f[i], name, n) == 0 && j->f[i][n] == '=')
			return (j->f[i] + n + 1);
	return (NULL);
}

/* A value as the kernel's integer: booleans and jailsys words too. */
static bool
fj_int(const char *s, long *v)
{
	char	*end;

	if (strcmp(s, "true") == 0 || strcmp(s, "new") == 0)
		*v = 1;
	else if (strcmp(s, "false") == 0 || strcmp(s, "disable") == 0)
		*v = 0;
	else if (strcmp(s, "inherit") == 0)
		*v = 2;
	else {
		errno = 0;
		*v = strtol(s, &end, 10);
		return (s[0] != '\0' && *end == '\0' && errno == 0);
	}
	return (true);
}

/* The addresses of ip4.addr or ip6.addr, as the kernel's array. */
static int
fj_addrs(const char *s, int af, void *buf, size_t len, size_t *need)
{
	char	 copy[1024], *p, *a;
	size_t	 el = af == AF_INET ? sizeof(struct in_addr) :
		    sizeof(struct in6_addr);

	*need = 0;
	if (s == NULL)
		return (0);
	snprintf(copy, sizeof(copy), "%s", s);
	for (p = copy; (a = strsep(&p, ",")) != NULL; ) {
		if (a[0] == '\0')
			continue;
		if (buf != NULL && *need + el <= len &&
		    inet_pton(af, a, (char *)buf + *need) != 1)
			return (-1);
		*need += el;
	}
	return (0);
}

/* One parameter of the jail into the caller's buffer, as jail_get(2). */
static int
fj_get_one(const struct fj *j, struct iovec *v, const char *name)
{
	const char	*s;
	size_t		 need;
	long		 n;
	int		 af;

	s = fj_value(j, name);
	if (strcmp(name, "dying") == 0 && s == NULL)
		s = "0";
	af = strcmp(name, "ip4.addr") == 0 ? AF_INET :
	    strcmp(name, "ip6.addr") == 0 ? AF_INET6 : 0;
	if (af != 0) {
		if (fj_addrs(s, af, v->iov_base, v->iov_len, &need) == -1)
			return (EINVAL);
		if (v->iov_base != NULL && need > v->iov_len)
			return (EINVAL);
		v->iov_len = need;
		return (0);
	}
	if (v->iov_base == NULL || v->iov_len == 0)
		return (0);
	if (s == NULL) {
		/* Not on the line: what a new jail has, nothing. */
		memset(v->iov_base, 0, v->iov_len);
		return (0);
	}
	if ((v->iov_len == sizeof(int) || v->iov_len == sizeof(long)) &&
	    fj_int(s, &n)) {
		if (v->iov_len == sizeof(int))
			*(int *)v->iov_base = (int)n;
		else
			*(long *)v->iov_base = n;
		return (0);
	}
	if (strlen(s) + 1 > v->iov_len)
		return (EINVAL);
	strcpy(v->iov_base, s);
	return (0);
}

/*
 * The key of a call, as the kernel takes it: lastjid (a walk), a jid
 * not 0, else the name.  The index of its name in iov, or -1.
 */
static int
fj_key(struct iovec *iov, unsigned int niov, long *after, int *jid,
    const char **name)
{
	unsigned int	i;
	int		ki = -1, ji = -1, ni = -1;

	*after = -1;
	*jid = 0;
	*name = NULL;
	for (i = 0; i + 1 < niov; i += 2) {
		if (iov[i].iov_base == NULL)
			continue;
		if (strcmp(iov[i].iov_base, "lastjid") == 0 &&
		    iov[i + 1].iov_len == sizeof(int) &&
		    iov[i + 1].iov_base != NULL) {
			*after = *(int *)iov[i + 1].iov_base;
			ki = (int)i;
		} else if (strcmp(iov[i].iov_base, "jid") == 0 &&
		    iov[i + 1].iov_len == sizeof(int) &&
		    iov[i + 1].iov_base != NULL &&
		    *(int *)iov[i + 1].iov_base != 0)
			ji = (int)i;
		else if (strcmp(iov[i].iov_base, "name") == 0 &&
		    iov[i + 1].iov_base != NULL && iov[i + 1].iov_len > 0)
			ni = (int)i;
	}
	if (ki >= 0)
		return (ki);
	if (ji >= 0) {
		*jid = *(int *)iov[ji + 1].iov_base;
		return (ji);
	}
	if (ni >= 0) {
		*name = iov[ni + 1].iov_base;
		return (ni);
	}
	return (-1);
}

/* The file's jail the key names; -1 if none. */
static int
fj_find(struct fj *js, int nj, long after, int jid, const char *name)
{
	int	i, best = -1;

	for (i = 0; i < nj; i++) {
		if (after >= 0) {
			if (js[i].jid > after && (best < 0 ||
			    js[i].jid < js[best].jid))
				best = i;
		} else if (jid != 0 ? js[i].jid == jid :
		    strcmp(js[i].f[0], name) == 0)
			return (i);
	}
	return (best);
}

/* The jails of the file, when FAKEJAIL names one: room for them. */
static struct fj *
fj_all(int *max)
{
	*max = 64;
	return (calloc((size_t)*max, sizeof(struct fj)));
}

int
jail_get(struct iovec *iov, unsigned int niov, int flags)
{
	jail_iov_fn	*fn;
	struct fj	*js;
	const char	*file, *name;
	char		 msg[128];
	long		 after;
	unsigned int	 i;
	int		 nj, max, k, jid, ki, e;

	if ((file = getenv("FAKEJAIL")) == NULL ||
	    (ki = fj_key(iov, niov, &after, &jid, &name)) < 0 ||
	    (flags & (JAIL_USE_DESC | JAIL_AT_DESC)) != 0) {
		if ((fn = (jail_iov_fn *)real("jail_get")) == NULL)
			return (-1);
		return (fn(iov, niov, flags));
	}
	if ((js = fj_all(&max)) == NULL)
		return (-1);
	if (!fj_read(file, js, max, &nj) && after >= 0) {
		/* No file: the host's jails, for a walk. */
		free(js);
		if ((fn = (jail_iov_fn *)real("jail_get")) == NULL)
			return (-1);
		return (fn(iov, niov, flags));
	}
	if ((k = fj_find(js, nj, after, jid, name)) < 0) {
		if (after >= 0)
			snprintf(msg, sizeof(msg), "no jail after %ld", after);
		else if (jid != 0)
			snprintf(msg, sizeof(msg), "jail %d not found", jid);
		else
			snprintf(msg, sizeof(msg), "jail \"%s\" not found",
			    name);
		iov_errmsg(iov, niov, msg);
		free(js);
		errno = ENOENT;
		return (-1);
	}
	for (i = 0; i + 1 < niov; i += 2) {
		if ((int)i == ki || iov[i].iov_base == NULL ||
		    strcmp(iov[i].iov_base, "errmsg") == 0 ||
		    strcmp(iov[i].iov_base, "lastjid") == 0)
			continue;
		if ((e = fj_get_one(&js[k], &iov[i + 1], iov[i].iov_base)) !=
		    0) {
			snprintf(msg, sizeof(msg), "%s: no room for its value",
			    (char *)iov[i].iov_base);
			iov_errmsg(iov, niov, msg);
			free(js);
			errno = e;
			return (-1);
		}
	}
	jid = js[k].jid;
	free(js);
	return (jid);
}

/* The parameter set on the line: replaced, or added at its end. */
static void
fj_put(struct fj *j, const char *name, const char *value, char *store,
    size_t len)
{
	static const char	*pos[FJ_POS] = { "name", "jid", "vnet",
				    "path", "osrelease" };
	size_t			 n;
	int			 i;

	snprintf(store, len, "%s", value);
	for (i = 0; i < FJ_POS; i++)
		if (strcmp(name, pos[i]) == 0) {
			j->f[i] = store;
			return;
		}
	snprintf(store, len, "%s=%s", name, value);
	n = strlen(name);
	for (i = FJ_POS; i < j->n; i++)
		if (strncmp(j->f[i], name, n) == 0 && j->f[i][n] == '=') {
			j->f[i] = store;
			return;
		}
	if (j->n < FJ_FIELDS)
		j->f[j->n++] = store;
}

int
jail_set(struct iovec *iov, unsigned int niov, int flags)
{
	jail_iov_fn	*fn;
	struct fj	*js;
	const char	*file, *name, *pn, *dot;
	char		 store[FJ_FIELDS][256], pname[128], msg[128];
	long		 after;
	unsigned int	 i;
	int		 nj, max, k, jid, ki, ns;

	/* Not one of the file's: the kernel's, a jail made among them. */
	js = NULL;
	if ((file = getenv("FAKEJAIL")) == NULL ||
	    (ki = fj_key(iov, niov, &after, &jid, &name)) < 0 ||
	    after >= 0 || (js = fj_all(&max)) == NULL ||
	    !fj_read(file, js, max, &nj) ||
	    (k = fj_find(js, nj, -1, jid, name)) < 0) {
		if (js != NULL && file != NULL && (flags & JAIL_CREATE) == 0) {
			/* An update of a jail not there: never the host's. */
			free(js);
			snprintf(msg, sizeof(msg), "jail not found");
			iov_errmsg(iov, niov, msg);
			errno = ENOENT;
			return (-1);
		}
		free(js);
		if ((fn = (jail_iov_fn *)real("jail_set")) == NULL)
			return (-1);
		return (fn(iov, niov, flags));
	}
	if ((flags & JAIL_UPDATE) == 0 || (flags & JAIL_ATTACH) != 0) {
		free(js);
		snprintf(msg, sizeof(msg), "%s", (flags & JAIL_UPDATE) == 0 ?
		    "jail exists" : "a fake jail cannot be attached to");
		iov_errmsg(iov, niov, msg);
		errno = (flags & JAIL_UPDATE) == 0 ? EEXIST : EPERM;
		return (-1);
	}
	for (i = 0, ns = 0; i + 1 < niov && ns < FJ_FIELDS; i += 2) {
		pn = iov[i].iov_base;
		if ((int)i == ki || pn == NULL || strcmp(pn, "errmsg") == 0)
			continue;
		if (iov[i + 1].iov_base == NULL) {
			/* A boolean: set by its name, unset by its "no" one. */
			dot = strrchr(pn, '.');
			dot = dot == NULL ? pn : dot + 1;
			if (strncmp(dot, "no", 2) == 0) {
				snprintf(pname, sizeof(pname), "%.*s%s",
				    (int)(dot - pn), pn, dot + 2);
				fj_put(&js[k], pname, "0", store[ns++],
				    sizeof(store[0]));
			} else
				fj_put(&js[k], pn, "1", store[ns++],
				    sizeof(store[0]));
		} else if (iov[i + 1].iov_len == sizeof(int)) {
			snprintf(pname, sizeof(pname), "%d",
			    *(int *)iov[i + 1].iov_base);
			fj_put(&js[k], pn, pname, store[ns++],
			    sizeof(store[0]));
		} else
			fj_put(&js[k], pn, iov[i + 1].iov_base, store[ns++],
			    sizeof(store[0]));
	}
	if (fj_write(file, js, nj) == -1) {
		free(js);
		return (-1);
	}
	jid = js[k].jid;
	free(js);
	return (jid);
}

int
jail_remove(int jid)
{
	jail_remove_fn	*fn;
	struct fj	*js;
	const char	*file;
	int		 nj, max, k;

	if ((file = getenv("FAKEJAIL")) == NULL) {
		if ((fn = (jail_remove_fn *)real("jail_remove")) == NULL)
			return (-1);
		return (fn(jid));
	}
	if ((js = fj_all(&max)) == NULL)
		return (-1);
	if (jid <= 0 || !fj_read(file, js, max, &nj) ||
	    (k = fj_find(js, nj, -1, jid, NULL)) < 0) {
		/* Not the file's: never the host's either. */
		free(js);
		errno = EINVAL;
		return (-1);
	}
	js[k].n = 0;
	k = fj_write(file, js, nj);
	free(js);
	return (k);
}

/* The host's interface, or one FAKEIFS names: an index past the host's. */
unsigned int
if_nametoindex(const char *ifname)
{
	unsigned int	(*realf)(const char *);
	const char	*list, *p;
	unsigned int	 idx;
	size_t		 n;

	if ((realf = (unsigned int (*)(const char *))dlsym(RTLD_NEXT,
	    "if_nametoindex")) != NULL && (idx = realf(ifname)) != 0)
		return (idx);
	if (ifname != NULL && (list = getenv("FAKEIFS")) != NULL) {
		n = strlen(ifname);
		for (p = list, idx = 0; *(p += strspn(p, " ")) != '\0';
		    p += strcspn(p, " ")) {
			idx++;
			if (n > 0 && strncmp(p, ifname, n) == 0 && (p[n] == ' ' ||
			    p[n] == '\0'))
				return (10000 + idx);
		}
	}
	errno = ENXIO;
	return (0);
}

typedef int	sysctl_fn(const int *, u_int, void *, size_t *, const void *,
		    size_t);
typedef int	sysctlbyname_fn(const char *, void *, size_t *, const void *,
		    size_t);

/* The value FAKESYSCTL gives name, as its text; false if none. */
static bool
fake_value(const char *name, char *buf, size_t buflen)
{
	const char	*p;
	size_t		 n, len, vl;

	if (name == NULL || (p = getenv("FAKESYSCTL")) == NULL)
		return (false);
	n = strlen(name);
	for (; *(p += strspn(p, " ")) != '\0'; p += len) {
		len = strcspn(p, " ");
		if (len > n && strncmp(p, name, n) == 0 && p[n] == '=') {
			vl = len - n - 1;
			if (vl >= buflen)
				vl = buflen - 1;
			memcpy(buf, p + n + 1, vl);
			buf[vl] = '\0';
			return (true);
		}
	}
	return (false);
}

/*
 * A read answered with text v, as the kernel answers it: a number as an
 * int, or a long where the caller's room is a long's or the number does
 * not fit an int; anything else a string with its NUL.
 */
static int
fake_read(const char *v, void *oldp, size_t *oldlenp)
{
	char		*end;
	long		 l;
	int		 i;
	size_t		 need;

	l = strtol(v, &end, 10);
	if (*v == '\0' || *end != '\0') {
		need = strlen(v) + 1;
		if (oldp != NULL) {
			if (*oldlenp < need) {
				errno = ENOMEM;
				return (-1);
			}
			memcpy(oldp, v, need);
		}
		*oldlenp = need;
		return (0);
	}
	if ((oldp != NULL && *oldlenp >= sizeof(l)) || l > INT_MAX ||
	    l < INT_MIN) {
		if (oldp != NULL) {
			if (*oldlenp < sizeof(l)) {
				errno = ENOMEM;
				return (-1);
			}
			memcpy(oldp, &l, sizeof(l));
		}
		*oldlenp = sizeof(l);
		return (0);
	}
	i = (int)l;
	if (oldp != NULL) {
		if (*oldlenp < sizeof(i)) {
			errno = ENOMEM;
			return (-1);
		}
		memcpy(oldp, &i, sizeof(i));
	}
	*oldlenp = sizeof(i);
	return (0);
}

/* The name FAKESYSCTL gives a value whose numbers are mib's. */
static bool
fake_mib(const int *mib, u_int miblen, char *val, size_t vallen)
{
	const char	*list, *p, *eq;
	char		 name[128];
	int		 oid[CTL_MAXNAME];
	size_t		 n, len;

	if ((list = getenv("FAKESYSCTL")) == NULL)
		return (false);
	for (p = list; *(p += strspn(p, " ")) != '\0'; p += len) {
		len = strcspn(p, " ");
		if ((eq = memchr(p, '=', len)) == NULL || (size_t)(eq - p) >=
		    sizeof(name))
			continue;
		memcpy(name, p, (size_t)(eq - p));
		name[eq - p] = '\0';
		n = nitems(oid);
		if (sysctlnametomib(name, oid, &n) == 0 && n == miblen &&
		    memcmp(oid, mib, n * sizeof(*oid)) == 0)
			return (fake_value(name, val, vallen));
	}
	return (false);
}

int
sysctl(const int *mib, u_int miblen, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen)
{
	static sysctl_fn	*realf;
	char			 v[256];

	/* Not the kernel's own nodes (CTL_SYSCTL): sysctlnametomib(3)
	 * asks by them. */
	if (newp == NULL && oldlenp != NULL && miblen > 0 &&
	    mib[0] != CTL_SYSCTL && fake_mib(mib, miblen, v, sizeof(v)))
		return (fake_read(v, oldp, oldlenp));
	if (realf == NULL && (realf = (sysctl_fn *)dlsym(RTLD_NEXT,
	    "sysctl")) == NULL) {
		errno = ENOSYS;
		return (-1);
	}
	return (realf(mib, miblen, oldp, oldlenp, newp, newlen));
}

int
sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen)
{
	static sysctlbyname_fn	*realf;
	char			 v[256];

	if (newp == NULL && oldlenp != NULL && fake_value(name, v, sizeof(v)))
		return (fake_read(v, oldp, oldlenp));
	if (realf == NULL && (realf = (sysctlbyname_fn *)dlsym(RTLD_NEXT,
	    "sysctlbyname")) == NULL) {
		errno = ENOSYS;
		return (-1);
	}
	return (realf(name, oldp, oldlenp, newp, newlen));
}

/* The host's name, or the one FAKESYSCTL gives kern.hostname. */
int
gethostname(char *name, size_t namelen)
{
	int		(*realf)(char *, size_t);
	char		 v[256];
	size_t		 n;

	if (fake_value("kern.hostname", v, sizeof(v))) {
		n = strlen(v);
		if (n >= namelen) {
			errno = ENAMETOOLONG;
			return (-1);
		}
		memcpy(name, v, n + 1);
		return (0);
	}
	if ((realf = (int (*)(char *, size_t))dlsym(RTLD_NEXT,
	    "gethostname")) == NULL) {
		errno = ENOSYS;
		return (-1);
	}
	return (realf(name, namelen));
}

int	__xuname(int, void *);	/* libc's, behind uname(3) */

/* uname(3)'s, its node name kern.hostname's where FAKESYSCTL gives it.
 * libc's uname() is __xuname() with the struct's field length. */
int
__xuname(int namesize, void *namebuf)
{
	int		(*realf)(int, void *);
	char		 v[256];
	int		 rc;

	if ((realf = (int (*)(int, void *))dlsym(RTLD_NEXT, "__xuname")) ==
	    NULL) {
		errno = ENOSYS;
		return (-1);
	}
	if ((rc = realf(namesize, namebuf)) == 0 &&
	    fake_value("kern.hostname", v, sizeof(v)) && namesize > 0)
		/* Each field namesize bytes, the node name the second. */
		(void)strlcpy((char *)namebuf + namesize, v, (size_t)namesize);
	return (rc);
}

/* time(3), stepped by FAKETIME's file's seconds when it is set. */
time_t
time(time_t *tp)
{
	static time_t	 step, read_at = -1;
	struct timespec	 ts, mono;
	const char	*file;
	char		 buf[32];
	FILE		*fp;
	time_t		 t;

	(void)clock_gettime(CLOCK_REALTIME, &ts);
	t = ts.tv_sec;
	if ((file = getenv("FAKETIME")) != NULL) {
		(void)clock_gettime(CLOCK_MONOTONIC, &mono);
		if (read_at < 0 || mono.tv_sec != read_at) {
			read_at = mono.tv_sec;
			if ((fp = fopen(file, "re")) != NULL) {
				if (fgets(buf, sizeof(buf), fp) != NULL)
					step = (time_t)strtoll(buf, NULL, 10);
				fclose(fp);
			}
		}
		t += step;
	}
	if (tp != NULL)
		*tp = t;
	return (t);
}

/* ---- ipfw's IP_FW3, FAKEIPFW's ------------------------------------- */

#define	FW_RULES	256

typedef int	socket_fn(int, int, int);
typedef int	getsockopt_fn(int, int, int, void *, socklen_t *);
typedef int	setsockopt_fn(int, int, int, const void *, socklen_t);

static int	fw_fd = -1;	/* the raw socket stood in for */

int
socket(int domain, int type, int protocol)
{
	socket_fn	*realf;
	int		 fd;

	if (getenv("FAKEIPFW") != NULL && domain == AF_INET &&
	    (type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK)) == SOCK_RAW &&
	    protocol == IPPROTO_RAW) {
		if ((fd = open("/dev/null", O_RDWR | ((type & SOCK_CLOEXEC) !=
		    0 ? O_CLOEXEC : 0))) != -1)
			fw_fd = fd;
		return (fd);
	}
	if ((realf = (socket_fn *)real("socket")) == NULL)
		return (-1);
	return (realf(domain, type, protocol));
}

/*
 * IP_FW_XGET of the file's rules: the header, the rule list's TLV, and
 * each rule's TLV with its counters (IPFW_CFG_GET_COUNTERS) and its
 * body, a comment and a count, as the kernel lays them out.
 */
static int
fw_xget(void *buf, socklen_t *lenp)
{
	ipfw_cfg_lheader	*cfg = buf;
	ipfw_obj_ctlv		*ctlv;
	ipfw_obj_tlv		*tlv;
	struct ip_fw_bcounter	*cnt;
	struct ip_fw_rule	*r;
	ipfw_insn		*cmd;
	FILE			*fp;
	char			 line[512], *cm;
	unsigned long		 num, set;
	unsigned long long	 pk, by;
	size_t			 need, at, clen, rlen;
	uint32_t		 first, last, nr;
	int			 n;

	if (*lenp < sizeof(*cfg) + sizeof(*ctlv)) {
		errno = EINVAL;
		return (-1);
	}
	first = cfg->start_rule;
	last = cfg->end_rule != 0 ? cfg->end_rule : UINT32_MAX;
	need = at = sizeof(*cfg) + sizeof(*ctlv);
	nr = 0;
	if ((fp = fopen(getenv("FAKEIPFW"), "re")) != NULL) {
		while (nr < FW_RULES && fgets(line, sizeof(line), fp) != NULL) {
			line[strcspn(line, "\n")] = '\0';
			if (sscanf(line, "%lu %lu %llu %llu %n", &num, &set, &pk,
			    &by, &n) != 4 || num < first || num > last)
				continue;
			cm = line + n;
			/* The comment, NUL-ended, in whole words of 4. */
			clen = (strlen(cm) + 1 + 3) / 4;
			rlen = roundup2(sizeof(*r) - sizeof(ipfw_insn) +
			    (1 + clen + 1) * sizeof(ipfw_insn), 8);
			need += sizeof(*tlv) + sizeof(*cnt) + rlen;
			if (need > *lenp)
				continue;
			tlv = (ipfw_obj_tlv *)(void *)((char *)buf + at);
			memset(tlv, 0, sizeof(*tlv) + sizeof(*cnt) + rlen);
			tlv->type = IPFW_TLV_RULE_ENT;
			tlv->length = (uint32_t)(sizeof(*tlv) + sizeof(*cnt) +
			    rlen);
			cnt = (struct ip_fw_bcounter *)(void *)(tlv + 1);
			cnt->size = sizeof(*cnt);
			cnt->pcnt = pk;
			cnt->bcnt = by;
			r = (struct ip_fw_rule *)(cnt + 1);
			r->rulenum = (uint32_t)num;
			r->set = (uint8_t)set;
			r->act_ofs = (uint16_t)(1 + clen);
			r->cmd_len = (uint16_t)(1 + clen + 1);
			cmd = r->cmd;
			cmd->opcode = O_NOP;
			cmd->len = (uint8_t)(1 + clen);
			memcpy(cmd + 1, cm, strlen(cm) + 1);
			cmd += 1 + clen;
			cmd->opcode = O_COUNT;
			cmd->len = 1;
			at += tlv->length;
			nr++;
		}
		fclose(fp);
	}
	cfg->size = (uint32_t)need;
	if (need > *lenp) {
		errno = ENOMEM;
		return (-1);
	}
	ctlv = (ipfw_obj_ctlv *)(cfg + 1);
	memset(ctlv, 0, sizeof(*ctlv));
	ctlv->head.type = IPFW_TLV_RULE_LIST;
	ctlv->head.length = (uint32_t)(at - sizeof(*cfg));
	ctlv->count = nr;
	cfg->set_mask = ~0u;
	*lenp = (socklen_t)at;
	return (0);
}

int
getsockopt(int s, int level, int name, void *val, socklen_t *lenp)
{
	getsockopt_fn	*realf;
	ip_fw3_opheader	*op = val;

	if (fw_fd != -1 && s == fw_fd && level == IPPROTO_IP &&
	    name == IP_FW3) {
		if (val == NULL || lenp == NULL || *lenp < sizeof(*op)) {
			errno = EINVAL;
			return (-1);
		}
		if (op->opcode == IP_FW_XGET)
			return (fw_xget(val, lenp));
		errno = EOPNOTSUPP;
		return (-1);
	}
	if ((realf = (getsockopt_fn *)real("getsockopt")) == NULL)
		return (-1);
	return (realf(s, level, name, val, lenp));
}

int
setsockopt(int s, int level, int name, const void *val, socklen_t len)
{
	setsockopt_fn		*realf;
	const ipfw_obj_header	*oh = val;
	const ipfw_obj_ntlv	*second;
	struct timespec		 ts;
	char			 log[MAXPATHLEN];
	FILE			*fp;

	if (fw_fd != -1 && s == fw_fd && level == IPPROTO_IP &&
	    name == IP_FW3) {
		if (val == NULL || len < sizeof(oh->opheader)) {
			errno = EINVAL;
			return (-1);
		}
		if (oh->opheader.opcode != IP_FW_TABLE_XSWAP ||
		    len < sizeof(*oh) + sizeof(*second)) {
			errno = EOPNOTSUPP;
			return (-1);
		}
		second = (const ipfw_obj_ntlv *)(oh + 1);
		(void)clock_gettime(CLOCK_REALTIME, &ts);
		snprintf(log, sizeof(log), "%s.log", getenv("FAKEIPFW"));
		if ((fp = fopen(log, "ae")) != NULL) {
			fprintf(fp, "swap %u %.*s %.*s %jd\n", oh->ntlv.set,
			    (int)strnlen(oh->ntlv.name, sizeof(oh->ntlv.name)),
			    oh->ntlv.name, (int)strnlen(second->name,
			    sizeof(second->name)), second->name,
			    (intmax_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
			fclose(fp);
		}
		return (0);
	}
	if ((realf = (setsockopt_fn *)real("setsockopt")) == NULL)
		return (-1);
	return (realf(s, level, name, val, len));
}
