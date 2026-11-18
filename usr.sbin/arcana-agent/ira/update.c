/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A new arcana-agent, sent by the console.  It is written beside the
 * installed one, checked against the SHA-256 that came with it, and run
 * with -V: a program for another machine or system does not run, and
 * never takes the place of one that does.  The one installed stays as
 * <path>.old.  A program sent compressed is inflated first, to no more
 * than max-program bytes: what is checked, signed and installed is the
 * program, as it runs.
 *
 * What the console's CA key signs is the update's statement (update_
 * statement(), zprog.h): the host it is for, the version and the
 * SHA-256 it stands for, and whether it may go back; the program is
 * bound by its SHA-256 and has to report that version.  A version
 * older than the running agent's is refused unless the statement says
 * downgrade yes: a program signed once is not sent again to take a fix
 * back, nor to another host.  Root on the local socket is root
 * already: its program is taken unsigned, the version's check its
 * alone, downgrade by its own word.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "agent.h"
#include "zprog.h"

#define	VERSION_PREFIX	"arcana-agent "
#define	RESTART_STOP_WAIT 30	/* s, for the daemon to stop by its pid */

extern char	**environ;

static bool
sha256_is(const uint8_t *data, size_t len, const char *hex)
{
	unsigned char	md[EVP_MAX_MD_SIZE];
	char		got[2 * EVP_MAX_MD_SIZE + 1];
	unsigned int	i, n;

	if (EVP_Digest(data, len, md, &n, EVP_sha256(), NULL) != 1)
		return (false);
	for (i = 0; i < n; i++)
		snprintf(got + 2 * i, 3, "%02x", md[i]);
	return (strcasecmp(got, hex) == 0);
}

/* What the console signs of an update: www/arcana-console/hosts.c makes
 * the same. */
static char *
update_statement(struct work *w, const char *version, const char *sha256,
    bool downgrade)
{
	char	 host[MAXHOSTNAMELEN], *sha, *p;

	if (gethostname(host, sizeof(host)) != 0)
		host[0] = '\0';
	sha = wstrdup(w, sha256);
	for (p = sha; *p != '\0'; p++)
		if (*p >= 'A' && *p <= 'F')
			*p = (char)(*p - 'A' + 'a');
	return (wfmt(w, UPDATE_STATEMENT, host, version, sha, downgrade ?
	    "yes" : "no"));
}

/*
 * a.b.c against x.y.z, as numbers: <0, 0 or >0; a version that is no
 * such triple is the oldest.
 */
static int
version_cmp(const char *a, const char *b)
{
	unsigned long	 x[3], y[3];
	int		 i;

	if (sscanf(a, "%lu.%lu.%lu", &x[0], &x[1], &x[2]) != 3)
		return (-1);
	if (sscanf(b, "%lu.%lu.%lu", &y[0], &y[1], &y[2]) != 3)
		return (1);
	for (i = 0; i < 3; i++)
		if (x[i] != y[i])
			return (x[i] < y[i] ? -1 : 1);
	return (0);
}

/*
 * Is the statement signed by a CA this host trusts (-A)?  The console's
 * CA key signs what it sends (SHA-256; Ed25519 with its own hash), and
 * any certificate of the CA file verifies.
 */
static bool
signed_by_ca(const uint8_t *data, size_t len, const uint8_t *sig,
    size_t siglen, const char **why)
{
	FILE		*fp;
	X509		*x;
	EVP_PKEY	*pk;
	EVP_MD_CTX	*ctx;
	const char	*ca;
	bool		 ok, any;

	if ((ca = tls_files_ca()) == NULL || (fp = fopen(ca, "r")) == NULL) {
		*why = "this host trusts no CA (-A): nothing can sign a program "
		    "for it";
		return (false);
	}
	ok = any = false;
	while (!ok && (x = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
		any = true;
		if ((pk = X509_get0_pubkey(x)) != NULL && (ctx = EVP_MD_CTX_new())
		    != NULL) {
			ok = EVP_DigestVerifyInit(ctx, NULL, EVP_PKEY_id(pk) ==
			    EVP_PKEY_ED25519 ? NULL : EVP_sha256(), NULL, pk) == 1 &&
			    EVP_DigestVerify(ctx, sig, siglen, data, len) == 1;
			EVP_MD_CTX_free(ctx);
		}
		X509_free(x);
	}
	fclose(fp);
	if (!ok)
		*why = any ? "the update is not signed by a CA this host trusts "
		    "(its version and SHA-256, as a console of 0.433.0 or later "
		    "signs them)" : "the CA file holds no certificate";
	return (ok);
}

static int
agent_install(struct work *w, const uint8_t *data, size_t len,
    const struct agent_update *u, struct build_rsp *rsp)
{
	struct execres	 res;
	const char	*path, *nl, *sha256;
	char		*new, *old, *argv[3], *st;
	ssize_t		 n;
	size_t		 off;
	int		 fd, s;

	sha256 = u->sha256;

	rsp->has_ok = true;
	rsp->ok = false;
	path = opts.self_path;
	new = wfmt(w, "%s.new", path);
	old = wfmt(w, "%s.old", path);

	/* Signed by the CA, unless asked by the local socket, whose root
	 * could replace the program by hand: the statement of its version
	 * and SHA-256. */
	if (!u->local) {
		const char	*why;

		s = step_begin(w, STEP_LIB, "signature", "%zu bytes by "
		    "the CA's key, of version %s and the SHA-256", u->siglen,
		    u->version != NULL ? u->version : "(none)");
		if (u->siglen == 0) {
			step_end(w, s, false, "none");
			rsp->error = "the program is not signed: a console signs "
			    "what it sends with its CA key";
			return (0);
		}
		if (u->version == NULL) {
			step_end(w, s, false, "no version");
			rsp->error = "the update says no version: a console of "
			    "0.433.0 or later signs the version with the program";
			return (0);
		}
		/* Rebuilt from this host and what was sent: a flag flipped,
		 * or a statement for another host, is not what was signed. */
		st = update_statement(w, u->version, sha256, u->downgrade);
		if (!signed_by_ca((const uint8_t *)st, strlen(st), u->sig,
		    u->siglen, &why)) {
			step_end(w, s, false, "%s", why);
			rsp->error = why;
			return (0);
		}
		step_end(w, s, true, "verified: version %s and the SHA-256",
		    u->version);
	}
	s = step_begin(w, STEP_LIB, "SHA-256", "%zu bytes", len);
	if (!sha256_is(data, len, sha256)) {
		step_end(w, s, false, "not %s", sha256);
		rsp->error = "the program does not match its SHA-256";
		return (0);
	}
	step_end(w, s, true, "%s", sha256);

	s = step_begin(w, STEP_FILE, "write", "%s", new);
	(void)unlink(new);
	if ((fd = open(new, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
	    0555)) == -1) {
		step_end(w, s, false, "%s", strerror(errno));
		rsp->error = wfmt(w, "%s: %s", new, strerror(errno));
		return (0);
	}
	for (off = 0; off < len; off += (size_t)n)
		if ((n = write(fd, data + off, len - off)) == -1)
			break;
	if (off < len || fsync(fd) == -1) {
		step_end(w, s, false, "%s", strerror(errno));
		rsp->error = wfmt(w, "%s: %s", new, strerror(errno));
		close(fd);
		(void)unlink(new);
		return (0);
	}
	close(fd);
	step_end(w, s, true, "%zu bytes", len);

	/* It has to run here, and say what it is. */
	argv[0] = new;
	argv[1] = (char *)(uintptr_t)"-V";
	argv[2] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.outlen <= strlen(
	    VERSION_PREFIX) || strncmp(res.out, VERSION_PREFIX, strlen(
	    VERSION_PREFIX)) != 0) {
		rsp->error = "the program does not run on this host as "
		    "arcana-agent";
		(void)unlink(new);
		return (0);
	}
	nl = memchr(res.out, '\n', res.outlen);
	rsp->agent_version = wstrndup(w, res.out + strlen(VERSION_PREFIX),
	    (nl != NULL ? (size_t)(nl - res.out) : res.outlen) -
	    strlen(VERSION_PREFIX));
	/* What was signed is what runs; an older one only when asked. */
	s = step_begin(w, STEP_LIB, "version", "%s, running %s",
	    rsp->agent_version, ARCANA_AGENT_VERSION);
	if (u->version != NULL && strcmp(u->version, rsp->agent_version) !=
	    0) {
		step_end(w, s, false, "not %s", u->version);
		rsp->error = wfmt(w, "the program reports %s, not the version "
		    "%s it was sent as", wtext(w, rsp->agent_version),
		    u->version);
		(void)unlink(new);
		return (0);
	}
	if (version_cmp(rsp->agent_version, ARCANA_AGENT_VERSION) < 0 &&
	    !u->downgrade) {
		step_end(w, s, false, "older");
		rsp->error = wfmt(w, "the program is %s, older than the running "
		    "%s: an update that goes back says downgrade",
		    wtext(w, rsp->agent_version), ARCANA_AGENT_VERSION);
		rsp->has_older = true;
		(void)unlink(new);
		return (0);
	}
	step_end(w, s, true, NULL);

	s = step_begin(w, STEP_FILE, "replace", "%s", path);
	(void)unlink(old);
	if ((link(path, old) == -1 && errno != ENOENT) ||
	    rename(new, path) == -1) {
		step_end(w, s, false, "%s", strerror(errno));
		rsp->error = wfmt(w, "%s: %s", path, strerror(errno));
		(void)unlink(new);
		return (0);
	}
	step_end(w, s, true, "the one before is %s", old);
	rsp->ok = true;
	return (0);
}

/*
 * The program of len bytes at data, or, with size, compressed and to
 * inflate to size bytes.
 */
int
do_agent_update(struct work *w, const uint8_t *data, size_t len,
    size_t size, const struct agent_update *u, struct build_rsp *rsp)
{
	const char	*why;
	uint8_t		*prog;
	int		 rc, s;

	if (size == 0)
		return (agent_install(w, data, len, u, rsp));
	rsp->has_ok = true;
	rsp->ok = false;
	s = step_begin(w, STEP_LIB, "inflate(3)", "%zu bytes of "
	    "gzip into %zu", len, size);
	if ((why = zprog_inflate(data, len, size, ZPROG_MAX_PROGRAM,
	    &prog)) != NULL) {
		step_end(w, s, false, "%s", why);
		rsp->error = why;
		return (0);
	}
	step_end(w, s, true, "%zu bytes", size);
	rc = agent_install(w, prog, size, u, rsp);
	free(prog);
	return (rc);
}

static void	helper_detached(const char *, const char *, const char *);

/*
 * Restart the service, from a process of its own that outlives this
 * one: service(8) stops this daemon and starts the new program.  It
 * waits a moment first, for the reply to leave.
 */
void
service_restart(const char *name)
{

	service_detached(name, "restart");
}

/*
 * service(8) name verb, from a process of its own that outlives this
 * daemon.  For what is done to the daemon's own service: run and waited
 * for like any other, service(8) would wait for the daemon to stop
 * while the daemon waits for service(8) to end.  The process is this
 * program exec'd as the helper (service-detach, below), never a fork
 * of the daemon, which would keep its heap and keys while it waits.
 */
void
service_detached(const char *name, const char *verb)
{

	helper_detached("service-detach", name, verb);
}

/*
 * The daemon's own service restarted without its pidfile: rc(8) said
 * it did not run (service_replace(), below), from a process of its own.
 */
void
service_replaced(const char *name)
{
	char	pid[16];

	snprintf(pid, sizeof(pid), "%d", (int)getpid());
	helper_detached("service-replace", name, pid);
}

/* The helper's what, with service(8), name and arg, run and waited for:
 * it forks and is gone at once, its child init's. */
static void
helper_detached(const char *what, const char *name, const char *arg)
{
	posix_spawn_file_actions_t	 fa;
	posix_spawnattr_t		 at;
	sigset_t			 none, all;
	char				*argv[8];
	pid_t				 pid;
	int				 rc, status;

	argv[0] = (char *)(uintptr_t)opts.own_bin;
	argv[1] = (char *)(uintptr_t)"--scope-helper";
	argv[2] = (char *)(uintptr_t)"0";
	argv[3] = (char *)(uintptr_t)what;
	argv[4] = (char *)(uintptr_t)opts.service_bin;
	argv[5] = (char *)(uintptr_t)name;
	argv[6] = (char *)(uintptr_t)arg;
	argv[7] = NULL;
	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null",
	    O_RDONLY, 0);
	posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null",
	    O_WRONLY, 0);
	posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null",
	    O_WRONLY, 0);
	posix_spawnattr_init(&at);
	sigemptyset(&none);
	sigfillset(&all);
	(void)posix_spawnattr_setsigmask(&at, &none);
	(void)posix_spawnattr_setsigdefault(&at, &all);
	(void)posix_spawnattr_setflags(&at, POSIX_SPAWN_SETSIGMASK |
	    POSIX_SPAWN_SETSIGDEF);
	rc = agent_spawn(&pid, argv[0], &fa, &at, argv, environ);
	posix_spawnattr_destroy(&at);
	posix_spawn_file_actions_destroy(&fa);
	if (rc != 0) {
		logmsg(LOG_ERR, "%s %s: %s: %s", name, arg, argv[0],
		    strerror(rc));
		return;
	}
	while (waitpid(pid, &status, 0) == -1 && errno == EINTR)
		;
}

/*
 * The helper's "service-detach service name verb": the process that runs it
 * forked and gone, so that init has it, in a session of its own; a
 * moment's wait, for the daemon's reply to leave, then service(8).
 */
int
service_detach(int argc, char **argv)
{
	struct timespec	 ts = { 1, 0 };
	pid_t		 pid;
	int		 status;

	if (argc != 4)
		return (2);
	closefrom(3);
	if ((pid = fork()) != 0)
		return (pid == -1 ? 1 : 0);
	(void)setsid();
	(void)nanosleep(&ts, NULL);
	/*
	 * service(8) runs in a child, so that its failing is not lost:
	 * a service that is not enabled, or not there, refuses, and
	 * nothing else would say why the old program still runs.
	 */
	if ((pid = fork()) == 0) {
		execl(argv[1], argv[1], argv[2], argv[3], (char *)NULL);
		_exit(127);
	}
	if (pid == -1 || waitpid(pid, &status, 0) == -1 ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		execl("/usr/bin/logger", "logger", "-t", "arcana-agent", "-p",
		    "daemon.err", "service(8) failed:", argv[2], argv[3],
		    "(is it enabled in rc.conf?)", (char *)NULL);
	_exit(0);
}

/* service(8) svc name verb, run and waited for: its exit status, or -1. */
static int
service_run(const char *svc, const char *name, const char *verb)
{
	pid_t	pid;
	int	status;

	if ((pid = fork()) == 0) {
		execl(svc, svc, name, verb, (char *)NULL);
		_exit(127);
	}
	if (pid == -1 || waitpid(pid, &status, 0) == -1 || !WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

/* Is pid a process still, not one gone that waits to be reaped? */
static bool
proc_alive(pid_t pid)
{
	struct kinfo_proc	kp;
	size_t			len = sizeof(kp);
	int			mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID,
				    (int)pid };

	if (sysctl(mib, nitems(mib), &kp, &len, NULL, 0) == -1 || len == 0)
		return (false);
	return (kp.ki_stat != SZOMB);
}

static void
service_log(const char *msg, const char *name)
{

	execl("/usr/bin/logger", "logger", "-t", "arcana-agent", "-p",
	    "daemon.err", msg, name, (char *)NULL);
	_exit(1);
}

/*
 * The helper's "service-replace service name pid": the daemon's own
 * service restarted without rc(8)'s pidfile, which did not stop it
 * (restart_after()).  Forked and gone, in a session of its own: if rc
 * says the service is enabled, the daemon (pid) is stopped by its pid
 * (SIGTERM, waited for), then started by rc unless rc says it runs now
 * (a restart whose start went through after all).  Not enabled, the
 * daemon is left running: nothing would start it again.
 */
int
service_replace(int argc, char **argv)
{
	struct timespec	 ts = { 0, 100 * 1000 * 1000 };
	const char	*errstr;
	pid_t		 pid, agent;
	int		 i;

	if (argc != 4)
		return (2);
	agent = (pid_t)strtonum(argv[3], 2, INT_MAX, &errstr);
	if (errstr != NULL)
		return (2);
	closefrom(3);
	if ((pid = fork()) != 0)
		return (pid == -1 ? 1 : 0);
	(void)setsid();
	if (service_run(argv[1], argv[2], "enabled") != 0)
		service_log("restart without its pidfile: not done, the "
		    "service is not enabled in rc.conf; the program before "
		    "the update keeps running:", argv[2]);
	if (kill(agent, SIGTERM) == -1 && errno != ESRCH)
		service_log("restart without its pidfile: the agent could "
		    "not be stopped by its pid:", argv[2]);
	for (i = 0; i < RESTART_STOP_WAIT * 10 && proc_alive(agent); i++)
		(void)nanosleep(&ts, NULL);
	if (proc_alive(agent))
		service_log("restart without its pidfile: the agent did not "
		    "stop; nothing started:", argv[2]);
	if (service_run(argv[1], argv[2], "status") == 0)
		_exit(0);
	if (service_run(argv[1], argv[2], "start") != 0)
		service_log("restart without its pidfile: service(8) start "
		    "failed:", argv[2]);
	_exit(0);
}
