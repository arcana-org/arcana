/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the network of a jail that has one of its own (vnet), worked
 * on from the host.  Nothing is installed in the jail: there is no
 * agent in it.
 *
 * A request names the jail, and from then on what the request runs is
 * run for that jail:
 *
 *   ifconfig, route, netstat, sockstat, ngctl
 *		the host's own programs, with their -j: they attach to
 *		the jail themselves, and need nothing in it.
 *   sysrc	the host's, with -j and the jail's number: the jail's own
 *		rc.conf is where its network is kept for its next start.
 *		Never -R with the jail's root: sysrc(8) runs the jail's
 *		/bin/sh by chroot(8), as the host's root, when no running
 *		jail has that path, which the jail's root can see to; -j
 *		has jexec(8) alone, and fails when the jail is gone.
 *   birdc, bird, wg
 *		the jail's own programs, through jexec(8): the daemon in
 *		the jail is the jail's version, and so must be what
 *		parses its configuration and speaks to it.
 *
 * What the daemon reads in its own process, the interfaces with their
 * counters, is read for a jail by this same program run again as a
 * helper (-Q), which attaches to the jail first.
 *
 * Files in a jail are the jail's: its root user can make any name
 * there a link to anywhere.  They are opened beneath the jail's root
 * and never through a link that leads out of it.
 */

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <netinet/in.h>

#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "agent.h"

/*
 * Have w work in the jail named, when one is: it must be running and
 * have a network of its own.  jail_getv(3) says: jid 4, vnet new, path
 * /usr/jails/gateway.
 */
int
scope_enter(struct work *w, const char *jail, const char **errp)
{

	return (scope_enter_jail(w, jail, errp, true));
}

/* The same; with vnet false, a jail without a network of its own too. */
int
scope_enter_jail(struct work *w, const char *jail, const char **errp,
    bool vnet)
{
	struct jinfo	ji;

	w->jail = NULL;
	w->jid = 0;
	w->jroot = NULL;
	if (jail == NULL || jail[0] == '\0')
		return (0);
	if (jail_named(w, jail, &ji) < 0) {
		*errp = vnet ? wfmt(w, "the jail %s is not running: its "
		    "network is there only while it runs", jail) : wfmt(w,
		    "the jail %s is not running", jail);
		return (-1);
	}
	if (ji.path[0] != '/') {
		*errp = wfmt(w, "jail_getv(3) did not say where the jail %s "
		    "is", jail);
		return (-1);
	}
	if (vnet && !ji.vnet) {
		*errp = wfmt(w, "the jail %s has no network of its own (vnet): "
		    "its addresses are the host's, and are managed there",
		    jail);
		return (-1);
	}
	w->jid = ji.jid;
	w->jail = ji.name;
	w->jroot = ji.path;
	return (0);
}

/*
 * argv as it is run for the jail w works in; argv itself when w works
 * on the host, or the program is none that has to do with a network.
 */
char *const *
scope_argv(struct work *w, char *const argv[])
{
	char	**v;
	size_t	  n, i, k;

	if (w->jail == NULL)
		return (argv);
	/*
	 * run_exec() scopes what it runs itself: one scoped already by its
	 * caller is left as it is, not told the jail twice.
	 */
	if (argv[0] != NULL && argv[1] != NULL && ((strcmp(argv[1], "-j") ==
	    0 && (argv[0] == opts.ifconfig_bin || argv[0] == opts.netstat_bin ||
	    argv[0] == opts.ngctl_bin || argv[0] == opts.sysrc_bin))))
		return (argv);
	for (n = 0; argv[n] != NULL; n++)
		;
	v = wcalloc(w, n + 4, sizeof(*v));
	k = 0;
	if (argv[0] == opts.ifconfig_bin || argv[0] == opts.netstat_bin ||
	    argv[0] == opts.ngctl_bin || argv[0] == opts.sysrc_bin) {
		v[k++] = argv[0];
		v[k++] = (char *)(uintptr_t)"-j";
		v[k++] = wfmt(w, "%d", w->jid);
		i = 1;
	} else if (argv[0] == opts.birdc_bin || argv[0] == opts.bird_bin ||
	    argv[0] == opts.wg_bin ||
	    argv[0] == opts.ipfw_bin ||
	    argv[0] == opts.swanctl_bin || argv[0] == opts.sysctl_bin ||
	    argv[0] == opts.ifmcstat_bin) {
		/* The jail's own: ipfw(8), sysctl(8) and ifmcstat(8) have no
		 * way to name a jail, and what they tell is its vnet's. */
		v[k++] = (char *)(uintptr_t)opts.jexec_bin;
		v[k++] = wfmt(w, "%d", w->jid);
		i = 0;
	} else
		return (argv);
	for (; i < n; i++)
		v[k++] = argv[i];
	v[k] = NULL;
	return (v);
}

/*
 * argv run in the jail w works in, by jexec(8), whatever the program:
 * for one this daemon has no option of its own for (arp, ndp), which
 * scope_argv() does not know.  argv itself on the host.
 */
char *const *
scope_jexec(struct work *w, char *const argv[])
{
	char	**v;
	size_t	  n, i;

	if (w->jail == NULL)
		return (argv);
	for (n = 0; argv[n] != NULL; n++)
		;
	v = wcalloc(w, n + 3, sizeof(*v));
	v[0] = (char *)(uintptr_t)opts.jexec_bin;
	v[1] = wfmt(w, "%d", w->jid);
	for (i = 0; i < n; i++)
		v[2 + i] = argv[i];
	v[2 + n] = NULL;
	return (v);
}

/*
 * The helper's argv for a verb and its n words: this program again,
 * told the jail w works in, or 0 for the host.
 */
char **
helper_argv(struct work *w, const char *verb, size_t n,
    const char *const words[])
{
	char	**v;
	size_t	  i;

	v = wcalloc(w, n + 5, sizeof(*v));
	v[0] = (char *)(uintptr_t)opts.helper_bin;
	v[1] = (char *)(uintptr_t)"--scope-helper";
	v[2] = wfmt(w, "%d", w->jail != NULL ? w->jid : 0);
	v[3] = (char *)(uintptr_t)verb;
	for (i = 0; i < n; i++)
		v[4 + i] = (char *)(uintptr_t)words[i];
	v[4 + n] = NULL;
	return (v);
}

/*
 * A jail's name and whether it has a network of its own ("new"), by
 * its number; -1 when it is not there.
 */
int
jail_jid_name(int jid, char *name, size_t nlen, char *vnet, size_t vlen)
{
	char	js[16], nb[MAXHOSTNAMELEN], vb[16];

	snprintf(js, sizeof(js), "%d", jid);
	if (jail_getv(0, "jid", js, "name", nb, "vnet", vb, NULL) == -1)
		return (-1);
	strlcpy(name, nb, nlen);
	strlcpy(vnet, vb, vlen);
	return (0);
}

/* The jail after jid, by number (0 for the first); 0 when none. */
int
jail_next(int jid)
{
	char	ls[16], js[16];
	int	next;

	snprintf(ls, sizeof(ls), "%d", jid);
	js[0] = '\0';
	if ((next = jail_getv(0, "lastjid", ls, "jid", js, NULL)) == -1)
		return (0);
	return (next);
}

/*
 * A socket in a jail's own network: the helper attaches to the jail,
 * makes it there with verb (and word), and hands it over on a socket
 * that is its standard output.  -1 when it could not.
 */
static int
helper_socket(int jid, const char *verb, const char *word)
{
	static char *const		 noenv[] = { NULL };
	posix_spawn_file_actions_t	 fa;
	struct msghdr			 msg;
	struct cmsghdr			*cm;
	struct iovec			 iov;
	struct pollfd			 pfd;
	union {
		struct cmsghdr	hdr;
		char		buf[CMSG_SPACE(sizeof(int))];
	}				 cbuf;
	char				 js[16], one, *argv[6];
	pid_t				 pid;
	int				 sp[2], fd, rc, status;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp) == -1)
		return (-1);
	snprintf(js, sizeof(js), "%d", jid);
	argv[0] = (char *)(uintptr_t)opts.helper_bin;
	argv[1] = (char *)(uintptr_t)"--scope-helper";
	argv[2] = js;
	argv[3] = (char *)(uintptr_t)verb;
	argv[4] = (char *)(uintptr_t)word;
	argv[5] = NULL;
	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null",
	    O_RDONLY, 0);
	posix_spawn_file_actions_adddup2(&fa, sp[1], STDOUT_FILENO);
	rc = agent_spawn(&pid, argv[0], &fa, NULL, argv, noenv);
	posix_spawn_file_actions_destroy(&fa);
	close(sp[1]);
	if (rc != 0) {
		close(sp[0]);
		return (-1);
	}
	fd = -1;
	pfd.fd = sp[0];
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 5000) == 1) {
		memset(&msg, 0, sizeof(msg));
		iov.iov_base = &one;
		iov.iov_len = 1;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cbuf.buf;
		msg.msg_controllen = sizeof(cbuf.buf);
		if (recvmsg(sp[0], &msg, MSG_CMSG_CLOEXEC) == 1 &&
		    (cm = CMSG_FIRSTHDR(&msg)) != NULL && cm->cmsg_level ==
		    SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS &&
		    cm->cmsg_len == CMSG_LEN(sizeof(int)))
			memcpy(&fd, CMSG_DATA(cm), sizeof(int));
	}
	close(sp[0]);
	if (fd == -1)
		(void)kill(pid, SIGKILL);
	while (waitpid(pid, &status, 0) == -1 && errno == EINTR)
		;
	return (fd);
}

/* A netlink(4) socket in a jail's own network, told of what is
 * watched. */
int
helper_netlink(int jid)
{

	return (helper_socket(jid, "route-socket", NULL));
}

/* A raw ICMP or ICMPv6 socket in a jail's own network: probes sent
 * from there, as the jail's routing tables have them. */
int
helper_icmp_socket(int jid, int af)
{

	return (helper_socket(jid, "icmp-socket", af == AF_INET ? "inet" :
	    "inet6"));
}

/* The raw socket ipfw(8) asks its firewall on (IP_FW3), in a jail's own
 * network: the firewall it reaches is the jail's (gula/altmark.c). */
int
helper_ipfw_socket(int jid)
{

	return (helper_socket(jid, "ipfw-socket", NULL));
}

/* A BMP station's listener of FIB fib on port, in a jail's own network
 * (gula/bmp.c). */
int
helper_bmp_socket(int jid, int fib, int port)
{
	char	word[32];

	snprintf(word, sizeof(word), "%d:%d", fib, port);
	return (helper_socket(jid, "bmp-socket", word));
}

/* The helper's side: fd handed over on its standard output. */
static int
fd_send(int fd)
{
	struct msghdr	 msg;
	struct cmsghdr	*cm;
	struct iovec	 iov;
	union {
		struct cmsghdr	hdr;
		char		buf[CMSG_SPACE(sizeof(int))];
	}		 cbuf;
	char		 one = '1';

	memset(&msg, 0, sizeof(msg));
	memset(&cbuf, 0, sizeof(cbuf));
	iov.iov_base = &one;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf.buf;
	msg.msg_controllen = sizeof(cbuf.buf);
	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &fd, sizeof(int));
	return (sendmsg(STDOUT_FILENO, &msg, 0) == 1 ? 0 : 1);
}

/* Lines written into a stream of the daemon's, each given on. */
struct lines {
	void	(*fn)(const char *, void *);
	void	*arg;
	char	*buf;
	size_t	 len, cap;
};

static int
lines_write(void *cookie, const char *data, int n)
{
	struct lines	*l = cookie;
	char		*nl;
	size_t		 k;

	if (l->len + (size_t)n + 1 > l->cap) {
		l->cap = (l->len + (size_t)n + 1) * 2;
		if ((l->buf = realloc(l->buf, l->cap)) == NULL)
			return (-1);
	}
	memcpy(l->buf + l->len, data, (size_t)n);
	l->len += (size_t)n;
	while ((nl = memchr(l->buf, '\n', l->len)) != NULL) {
		*nl = '\0';
		l->fn(l->buf, l->arg);
		k = (size_t)(nl - l->buf) + 1;
		memmove(l->buf, nl + 1, l->len - k);
		l->len -= k;
	}
	return (n);
}

/*
 * What the helper's verb prints, a line at a time to fn: of the host's
 * own stack read here, by the daemon itself, as it is written; of a
 * jail's, or when the helper is another program (-H), by the helper.
 */
int
helper_lines(struct work *w, const char *verb, size_t n,
    const char *const words[], void (*fn)(const char *, void *), void *arg)
{
	struct lines	 l;
	FILE		*fp;
	int		 step, rc;

	if (w->jail != NULL || !opts.helper_self)
		return (run_exec_lines(w, helper_argv(w, verb, n, words), fn,
		    arg));
	step = step_begin(w, STEP_LIB, strncmp(verb, "pcb-", 4) == 0 ?
	    "sysctl(3)" : "netlink(4)", "%s %s", verb, n > 0 ? words[0] : "");
	memset(&l, 0, sizeof(l));
	l.fn = fn;
	l.arg = arg;
	if ((fp = fwopen(&l, lines_write)) == NULL) {
		step_end(w, step, false, "fwopen");
		return (-1);
	}
	/* Line by line: each is given on when it is whole. */
	(void)setvbuf(fp, NULL, _IOLBF, 0);
	if (strcmp(verb, "routes") == 0 && n == 4)
		rc = route_list(fp, atoi(words[0]), (uint32_t)strtoul(words[1],
		    NULL, 10), strcmp(words[2], "-") != 0 ? words[2] : NULL,
		    strcmp(words[3], "-") != 0 ? words[3] : NULL);
	else if (strcmp(verb, "route-get") == 0 && n == 2)
		rc = route_lookup(fp, words[0], (uint32_t)strtoul(words[1],
		    NULL, 10));
	else if (strcmp(verb, "route-addrs") == 0 && n == 0)
		rc = addr_lines(fp);
	else if (strcmp(verb, "route-neighs") == 0 && n == 2)
		rc = neigh_list(fp, atoi(words[0]), strcmp(words[1], "-") != 0 ?
		    words[1] : NULL);
	else if (strncmp(verb, "pcb-", 4) == 0 && n == 1)
		rc = pcb_list(fp, strcmp(verb, "pcb-socks") == 0, atoi(
		    words[0]));
	else
		rc = 2;
	fclose(fp);
	free(l.buf);
	step_end(w, step, rc == 0, NULL);
	return (rc == 0 ? 0 : -1);
}

/*
 * Why a program of the jail's own did not run, when the jail has no
 * such program: said so, rather than as jexec says it.  NULL otherwise.
 */
const char *
scope_missing(struct work *w, const struct execres *res, const char *prog,
    const char *package)
{

	if (w->jail == NULL || res->err == NULL || strstr(res->err,
	    "execvp") == NULL)
		return (NULL);
	/* No package: the base system's, which the jail's does not have. */
	if (package == NULL)
		return (wfmt(w, "the jail %s has no %s: it is the jail's own "
		    "base system's that is run there", w->jail, prog));
	return (wfmt(w, "the jail %s has no %s: it is the jail's own that is "
	    "run there (pkg -j %s install %s)", w->jail, prog, w->jail,
	    package));
}

/*
 * A directory of the host, or of the jail w works in: opened beneath
 * the jail's root, whatever links the jail has put on the way.
 */
int
scope_dirfd(struct work *w, const char *dir)
{
	int	root, fd;

	if (w->jail == NULL)
		return (open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
	if ((root = open(w->jroot, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) == -1)
		return (-1);
	dir += strspn(dir, "/");
	fd = openat(root, dir[0] != '\0' ? dir : ".", O_RDONLY | O_DIRECTORY |
	    O_CLOEXEC | O_RESOLVE_BENEATH);
	close(root);
	return (fd);
}

/* path as its directory, opened, and the name in it; -1 for no such. */
int
scope_open_dir(struct work *w, const char *path, const char **basep)
{
	const char	*slash;
	char		*dir;

	if ((slash = strrchr(path, '/')) != NULL && slash[1] == '\0') {
		errno = EINVAL;
		return (-1);
	}
	/* A bare name is in the scope's own directory: the host's current
	 * one (a test's), or the jail's root. */
	if (slash == NULL) {
		*basep = path;
		return (scope_dirfd(w, "."));
	}
	dir = slash == path ? wstrdup(w, "/") : wstrndup(w, path,
	    (size_t)(slash - path));
	*basep = slash + 1;
	return (scope_dirfd(w, dir));
}

/* A file of the host or of w's jail, whole; NULL, with errno, for none. */
char *
scope_slurp(struct work *w, const char *path, size_t *lenp)
{
	struct stat	 sb;
	const char	*base;
	char		*buf;
	ssize_t		 n;
	int		 dfd, fd, e;

	if ((dfd = scope_open_dir(w, path, &base)) == -1)
		return (NULL);
	/* Not blocking: a FIFO in its place is not waited on. */
	fd = openat(dfd, base, O_RDONLY | O_NONBLOCK | O_CLOEXEC | (w->jail !=
	    NULL ? O_NOFOLLOW : 0));
	e = errno;
	close(dfd);
	errno = e;
	if (fd == -1)
		return (NULL);
	if (fstat(fd, &sb) == -1 || !S_ISREG(sb.st_mode) || sb.st_size >
	    ARC_MAX_JSON) {
		close(fd);
		errno = EFBIG;
		return (NULL);
	}
	buf = wmalloc(w, (size_t)sb.st_size + 1);
	n = read(fd, buf, (size_t)sb.st_size);
	close(fd);
	if (n != sb.st_size) {
		errno = EIO;
		return (NULL);
	}
	buf[n] = '\0';
	if (lenp != NULL)
		*lenp = (size_t)n;
	return (buf);
}

/*
 * A file of the host or of w's jail opened, created with mode where it
 * is not, beneath the jail's root and never through a link: for a host
 * program to write to (tar's -f -), which is given no path there.
 * flags are open(2)'s; -1 with errno for none.
 */
int
scope_open(struct work *w, const char *path, int flags, mode_t mode)
{
	const char	*base;
	int		 dfd, fd, e;

	if ((dfd = scope_open_dir(w, path, &base)) == -1)
		return (-1);
	fd = openat(dfd, base, flags | O_NOFOLLOW | O_CLOEXEC, mode);
	e = errno;
	close(dfd);
	errno = e;
	return (fd);
}

/*
 * A file of the host or of w's jail opened to read, through the links
 * on its way as the jail sees them (/var/audit/current is one, to
 * /var/audit/<its trail>): an absolute one from the jail's root, none
 * out of it.  -1 with errno for none.
 */
int
scope_open_read(struct work *w, const char *path)
{
	const char	*base;
	char		 link[PATH_MAX], *dir;
	ssize_t		 n;
	int		 dfd, fd, e, hops;

	if (w->jail == NULL)
		return (open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC));
	for (hops = 0; hops < 8; hops++) {
		if ((dfd = scope_open_dir(w, path, &base)) == -1)
			return (-1);
		fd = openat(dfd, base, O_RDONLY | O_NONBLOCK | O_NOFOLLOW |
		    O_CLOEXEC | O_RESOLVE_BENEATH);
		if (fd != -1 || (errno != EMLINK && errno != ELOOP)) {
			e = errno;
			close(dfd);
			errno = e;
			return (fd);
		}
		n = readlinkat(dfd, base, link, sizeof(link) - 1);
		e = errno;
		close(dfd);
		if (n <= 0) {
			errno = n == 0 ? ENOENT : e;
			return (-1);
		}
		link[n] = '\0';
		/* Relative: from the link's own directory. */
		if (link[0] != '/') {
			dir = wstrndup(w, path, (size_t)(base - path));
			path = wfmt(w, "%s%s", dir, link);
		} else
			path = wstrdup(w, link);
	}
	errno = ELOOP;
	return (-1);
}

/*
 * dir and the directories above it made, as mkdir -p makes them, of the
 * host or beneath w's jail's root: a link on the way is not followed,
 * so no directory is made out of the jail.  0, or -1 with errno.
 */
int
scope_mkdirs(struct work *w, const char *dir)
{
	char	*p, *c, *next;
	int	 fd, nfd, e;

	if ((fd = scope_dirfd(w, "/")) == -1)
		return (-1);
	p = wstrdup(w, dir);
	for (c = p + strspn(p, "/"); *c != '\0'; c = next) {
		next = c + strcspn(c, "/");
		if (*next == '/')
			*next++ = '\0';
		if (mkdirat(fd, c, 0755) == 0)
			(void)fchmodat(fd, c, 0755, AT_SYMLINK_NOFOLLOW);
		else if (errno != EEXIST)
			break;
		nfd = openat(fd, c, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
		    O_CLOEXEC | O_RESOLVE_BENEATH);
		e = errno;
		close(fd);
		errno = e;
		if ((fd = nfd) == -1)
			return (-1);
		next += strspn(next, "/");
	}
	e = errno;
	close(fd);
	errno = e;
	return (*c != '\0' ? -1 : 0);
}

/*
 * text in base's place in the directory dfd: written beside it, synced,
 * moved over it and the directory synced, so that it is whole or as it
 * was, after a crash too.  A file there keeps its owner, and its mode
 * when mode is 0 (a new one is 0600 then); with keep, the file as it
 * was stays beside it under that name.  0, or -1 with errno.
 */
static int
replace_at(int dfd, const char *base, const char *text, size_t len,
    mode_t mode, const char *keep)
{
	struct stat	 sb;
	char		 tmp[NAME_MAX + 1];
	size_t		 off;
	ssize_t		 n;
	int		 fd, e;
	bool		 there;

	there = fstatat(dfd, base, &sb, AT_SYMLINK_NOFOLLOW) == 0 &&
	    S_ISREG(sb.st_mode);
	if (mode == 0)
		mode = there ? sb.st_mode & 07777 : 0600;
	snprintf(tmp, sizeof(tmp), ".%.200s.%08x", base, arc4random());
	if ((fd = openat(dfd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
	    O_CLOEXEC, 0600)) == -1)
		return (-1);
	errno = 0;
	for (off = 0; off < len; off += (size_t)n)
		if ((n = write(fd, text + off, len - off)) <= 0)
			break;
	/* Another's file stays another's: only root may give it away. */
	if (off < len || (there && fchown(fd, sb.st_uid, sb.st_gid) == -1 &&
	    errno != EPERM) || fchmod(fd, mode) == -1 || fsync(fd) == -1) {
		e = off < len && errno == 0 ? EIO : errno;
		close(fd);
		(void)unlinkat(dfd, tmp, 0);
		errno = e;
		return (-1);
	}
	close(fd);
	if (keep != NULL) {
		(void)unlinkat(dfd, keep, 0);
		if (linkat(dfd, base, dfd, keep, 0) == -1 && errno != ENOENT) {
			e = errno;
			(void)unlinkat(dfd, tmp, 0);
			errno = e;
			return (-1);
		}
	}
	if (renameat(dfd, tmp, dfd, base) == -1) {
		e = errno;
		(void)unlinkat(dfd, tmp, 0);
		errno = e;
		return (-1);
	}
	(void)fsync(dfd);
	return (0);
}

/*
 * Put text in a file's place, there or in w's jail, as replace_at()
 * does: whole or as it was, its owner kept, mode its mode (0: the one it
 * has).  With keep, the file as it was stays beside it under that name.
 */
int
scope_replace(struct work *w, const char *path, const char *text, size_t len,
    mode_t mode, const char *keep)
{
	const char	*base;
	int		 dfd, rc, e;

	if ((dfd = scope_open_dir(w, path, &base)) == -1)
		return (-1);
	rc = replace_at(dfd, base, text, len, mode, keep);
	e = errno;
	close(dfd);
	errno = e;
	return (rc);
}

/*
 * The same for a file of the host's alone, by a caller with no work
 * (rcarcana.c's undo, the commits' files put back, the SAs' state).
 */
int
file_replace(const char *path, const char *text, size_t len, mode_t mode)
{
	const char	*slash;
	char		 dir[PATH_MAX];
	int		 dfd, rc, e;

	/* A bare name is the current directory's (a test's). */
	if ((slash = strrchr(path, '/')) != NULL && slash[1] == '\0') {
		errno = EINVAL;
		return (-1);
	}
	(void)snprintf(dir, sizeof(dir), "%.*s", slash == NULL ? 1 : slash ==
	    path ? 1 : (int)(slash - path), slash == NULL ? "." : path);
	if ((dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) == -1)
		return (-1);
	rc = replace_at(dfd, slash != NULL ? slash + 1 : path, text, len, mode,
	    NULL);
	e = errno;
	close(dfd);
	errno = e;
	return (rc);
}

/* A file taken away, in the scope; 0, or -1 with errno. */
int
scope_unlink(struct work *w, const char *path)
{
	const char	*base;
	int		 dfd, rc;

	if ((dfd = scope_open_dir(w, path, &base)) == -1)
		return (-1);
	rc = unlinkat(dfd, base, 0);
	close(dfd);
	return (rc);
}

/* Move a file's name in its directory, or with to NULL take it away. */
int
scope_rename(struct work *w, const char *path, const char *from,
    const char *to)
{
	const char	*base;
	int		 dfd, rc, e;

	if ((dfd = scope_open_dir(w, path, &base)) == -1)
		return (-1);
	rc = to != NULL ? renameat(dfd, from, dfd, to) : unlinkat(dfd, from, 0);
	e = errno;
	close(dfd);
	errno = e;
	return (rc);
}

/*
 * The helper: this program run as "arcana-agent -Q jid what name arg".
 * It attaches to the jail, asks what the daemon would have asked in
 * its own process, prints the answer and ends.
 */
int
scope_helper(int argc, char **argv)
{
	char	*out;
	int	 jid;

	if (argc < 2)
		return (2);
	jid = atoi(argv[0]);
	if (jid > 0 && jail_attach(jid) == -1) {
		fprintf(stderr, "arcana-agent: jail_attach(%d): %s\n", jid,
		    strerror(errno));
		return (1);
	}
	/* The routing tables, through netlink(4). */
	if (strncmp(argv[1], "route", 5) == 0)
		return (route_helper(argc - 1, argv + 1));
	if (strncmp(argv[1], "pcb-", 4) == 0)
		return (pcb_helper(argc - 1, argv + 1));
	if (strcmp(argv[1], "carp-set") == 0)
		return (carp_helper(argc - 1, argv + 1));
	if (strcmp(argv[1], "zfs-pipe") == 0)
		return (zfs_pipe(argc - 1, argv + 1));
	/* Of the host's alone: what outlives a request, out of the
	 * daemon's process. */
	if (jid == 0 && strcmp(argv[1], "run-wait") == 0)
		return (run_wait(argc - 1, argv + 1));
	if (jid == 0 && strcmp(argv[1], "service-detach") == 0)
		return (service_detach(argc - 1, argv + 1));
	/* A debugger on a core, as nobody (crashes.c). */
	if (jid == 0 && strcmp(argv[1], "debug-as-nobody") == 0)
		return (debug_as_nobody(argc - 1, argv + 1));
	/* The jail's models served on standard input, its LNE root. */
	if (strcmp(argv[1], "lne-serve") == 0 && argc == 2)
		return (lne_serve());
	/* A raw ICMP socket of the jail's network, for the probes. */
	if (strcmp(argv[1], "icmp-socket") == 0 && argc == 3) {
		int	af, fd;

		af = strcmp(argv[2], "inet6") == 0 ? AF_INET6 : AF_INET;
		if ((fd = socket(af, SOCK_RAW, af == AF_INET ? IPPROTO_ICMP :
		    IPPROTO_ICMPV6)) == -1) {
			fprintf(stderr, "socket: %s\n", strerror(errno));
			return (1);
		}
		return (fd_send(fd));
	}
	/* A BMP station's listener, its FIB's, for gula/bmp.c. */
	if (strcmp(argv[1], "bmp-socket") == 0 && argc == 3) {
		int	fd, fib, port;

		if (sscanf(argv[2], "%d:%d", &fib, &port) != 2 || fib < 0 ||
		    port < 1 || port > 65535)
			return (2);
		if ((fd = bmp_listen(fib, port)) == -1) {
			fprintf(stderr, "bmp-socket: %s\n", strerror(errno));
			return (1);
		}
		return (fd_send(fd));
	}
	/* The jail's firewall's socket, for IP_FW3. */
	if (strcmp(argv[1], "ipfw-socket") == 0 && argc == 2) {
		int	fd;

		if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
			fprintf(stderr, "socket: %s\n", strerror(errno));
			return (1);
		}
		return (fd_send(fd));
	}
	/* A number of the network's, as the jail's own network has it. */
	if (strcmp(argv[1], "sysctl-int") == 0 && argc == 3 &&
	    strncmp(argv[2], "net.", 4) == 0) {
		int	v;
		size_t	len;

		len = sizeof(v);
		if (sysctlbyname(argv[2], &v, &len, NULL, 0) == -1) {
			fprintf(stderr, "%s: %s\n", argv[2], strerror(errno));
			return (1);
		}
		printf("%d\n", v);
		return (0);
	}
	if (argc != 4)
		return (2);
	if ((out = ifq_text(argv[1], strcmp(argv[2], "-") == 0 ? NULL :
	    argv[2], strcmp(argv[3], "-") == 0 ? NULL : argv[3])) == NULL)
		return (1);
	fputs(out, stdout);
	return (0);
}
