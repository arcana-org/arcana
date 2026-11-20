/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The proxies of the SD-WAN services at this edge (MEF 138's URLF, MBSF
 * and MD+R, the function policies of a zone): Squid, a plugin the host has
 * installed (nothing is installed by Arcana), one instance per service
 * run in the service's routing table (setfib), its configuration
 * rendered here from the console's form (sdconf.c), with the agent's
 * own paths in it: the pid file, the CA, the certificate cache, the
 * certificate maker, the file of denied domains and the files of the
 * lists the console sends beside the form, each written beside it.  In
 * mode sni the TLS names are looked at (peek) and a connection to a
 * denied one ended, the rest let through unopened (splice); in mode
 * inspect TLS is opened (bump) with
 * a CA of the instance's own, made once by openssl(1) and kept, its
 * certificate told in the sdwan read for the clients to trust.  Where
 * its security policies scan for malware, a c-icap of the service's own
 * (a plugin too, with ClamAV's module and signatures) answers the Squid
 * by ICAP on the loopback, in the same table, and is started first.
 * Like the DNS filters of sddns.c: those named are started or told to
 * reconfigure, those not named any more are stopped, and the list is
 * kept for the next start.  One the admin stopped (stopped: true) stays
 * in the list, its files kept, but neither it nor its c-icap runs, now
 * or at the next start, until it is started again.
 *
 * The Security section's may run in a jail (its "jail"): its files
 * beneath the jail's root (JAIL_DIR, written by descriptors opened
 * beneath it, never through a link out of it, scope.c), its Squid, its
 * certificate maker and its c-icap the jail's own, run there by
 * jexec(8), the clients told the jail's addresses; its CA made by the
 * host's openssl(1) and written into the jail; its signals sent from
 * inside the jail.  c-icap's loopback is the jail's (a jail without a
 * network of its own has its first address for it), and ClamAV's
 * signatures are the jail's own, as its freshclam keeps them.  A jail
 * not running at the agent's start leaves its instance kept, not
 * started, until the list is applied again.
 *
 * An SD-WAN edge that is a vnet jail has its own (the payload's
 * "jail"), each service's run in the jail the same way, in the
 * service's table there (the jail's own setfib(1)), its files in
 * EDGE_DIR beneath the jail's root, Squid's and c-icap's logs in the
 * jail's /var/log, read there for what they blocked (sdblock.c), and
 * the MD+R's hashes in the jail's own ClamAV database.  Each edge's
 * list is its own, kept apart (sdwan-proxy@<jail>.json), neither the
 * host's nor another jail's stopped by it.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	PROXY_FILE	"sdwan-proxy.json"
/* The Security section's own, apart: named sec-, kept in a file of
 * their own, neither group's list stopping the other's. */
#define	SEC_FILE	"security-proxy.json"
#define	SEC_PREFIX	"sec-"
#define	IS_SEC(name)	(strncmp((name), SEC_PREFIX, 4) == 0)
/* Where freshclam keeps ClamAV's signatures, and its pid (the port's). */
#define	CLAMAV_DB	"/var/db/clamav"
#define	FRESHCLAM_PID	"/var/run/clamav/freshclam.pid"
#define	INSTANCES_MAX	64
#define	DENY_MAX	(8 * 1024 * 1024)
#define	LISTS_MAX	64		/* list files an instance */
#define	PATH_CERTGEN	"/usr/local/libexec/squid/security_file_certgen"
/* A jail's: where its instances' files are beneath its root, the
 * Security section's and a jail edge's SD-WAN services' apart. */
#define	JAIL_DIR	"/var/db/arcana-security"
#define	EDGE_DIR	"/var/db/arcana-sdwan"
#define	DIR_OF(name)	(IS_SEC(name) ? JAIL_DIR : EDGE_DIR)

struct instance {
	char	name[40];
	char	jail[64];	/* the jail it runs in, "" the host */
	bool	jaildown;	/* its jail not running at the start */
	char	mode[12];
	int	fib;
	bool	icap;		/* scans for malware: c-icap beside it */
	bool	stopped;	/* by the admin: kept, not run */
};

static pthread_mutex_t	lock = PTHREAD_MUTEX_INITIALIZER;
static struct instance	instances[INSTANCES_MAX];
static int		ninstances;
static bool		starting;	/* the kept lists applied at the start */

static void	proxies_watch(struct work *, const ucl_object_t *,
		    const struct instance *, int, const char *);

/* Is an instance of the list applied: of its group and, SD-WAN's, of
 * its edge (the jail it runs in, "" the host's)? */
static bool
of_list(const struct instance *in, bool sec, const char *edge)
{

	return (IS_SEC(in->name) == sec && (sec || strcmp(in->jail, edge) ==
	    0));
}

static bool
name_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) > 32)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '_' && s[i] != '-')
			return (false);
	return (true);
}

/* Where an instance's files are: beside the agent's kept files, or
 * beneath its jail's root when w works there. */
static const char *
inst_path(struct work *w, const char *name, const char *ext)
{
	char	buf[MAXPATHLEN];

	if (w->jail != NULL)
		return (wfmt(w, "%s/sdwan-proxy-%s.%s", DIR_OF(name), name, ext));
	sdwan_conf_path(wfmt(w, "sdwan-proxy-%s.%s", name, ext), buf,
	    sizeof(buf));
	return (wstrdup(w, buf));
}

/* w working where an instance runs: its jail, or the host.  0, or -1
 * and why. */
static int
inst_in(struct work *w, const char *jail, const char **errp)
{
	const char	*e = NULL;

	if (scope_enter_jail(w, jail, &e, false) != 0) {
		if (errp != NULL)
			*errp = e;
		return (-1);
	}
	return (0);
}

/* The gid of a group of w's jail, from its /etc/group; -1 none. */
static gid_t
jail_gid(struct work *w, const char *group)
{
	char		*t, *line;
	size_t		 n;
	long		 g;

	if ((t = scope_slurp(w, "/etc/group", NULL)) == NULL)
		return ((gid_t)-1);
	n = strlen(group);
	while ((line = strsep(&t, "\n")) != NULL)
		if (strncmp(line, group, n) == 0 && line[n] == ':' &&
		    (line = strchr(line + n + 1, ':')) != NULL) {
			g = strtol(line + 1, NULL, 10);
			return (g > 0 ? (gid_t)g : (gid_t)-1);
		}
	return ((gid_t)-1);
}

/*
 * A file of the instance name's (file, its name beside the others),
 * written whole where w works: the host's as sdwan_conf_write() and,
 * with a group, sdwan_conf_write_group() write them; a jail's beneath
 * its root, 0600, or 0640 of the jail's own group when it has one.
 */
static int
px_write(struct work *w, const char *name, const char *file,
    const char *text, const char *group, const char **errp)
{
	const char	*path, *base;
	gid_t		 gid;
	int		 dfd;

	if (w->jail == NULL)
		return (group != NULL ? sdwan_conf_write_group(file, text, group,
		    errp) : sdwan_conf_write(file, text, errp));
	path = wfmt(w, "%s/%s", DIR_OF(name), file);
	gid = group != NULL ? jail_gid(w, group) : (gid_t)-1;
	if (scope_mkdirs(w, DIR_OF(name)) != 0 || scope_replace(w, path, text,
	    strlen(text), gid != (gid_t)-1 ? 0640 : 0600, NULL) != 0) {
		*errp = wfmt(w, "%s in the jail %s: %s", path, w->jail,
		    strerror(errno));
		return (-1);
	}
	if (gid != (gid_t)-1 && (dfd = scope_open_dir(w, path, &base)) != -1) {
		(void)fchownat(dfd, base, 0, gid, AT_SYMLINK_NOFOLLOW);
		close(dfd);
	}
	return (0);
}

/* A file's text, in the work's memory; NULL when it is not there. */
static char *
file_text(struct work *w, const char *path)
{
	FILE	*fp;
	char	*text;
	long	 n;

	if (w->jail != NULL)
		return (scope_slurp(w, path, NULL));
	if ((fp = fopen(path, "r")) == NULL)
		return (NULL);
	if (fseek(fp, 0, SEEK_END) != 0 || (n = ftell(fp)) < 0 || n > 1024 *
	    1024 || fseek(fp, 0, SEEK_SET) != 0) {
		fclose(fp);
		return (NULL);
	}
	text = wcalloc(w, 1, (size_t)n + 1);
	if (fread(text, 1, (size_t)n, fp) != (size_t)n) {
		fclose(fp);
		return (NULL);
	}
	fclose(fp);
	return (text);
}

/* The programs: squid, and the certificate maker beside it. */
static const char *
squid_bin(struct work *w)
{
	const char	*p;

	if (w->jail != NULL)
		return (PATH_SQUID_BIN);
	if ((p = tool(w, "squid")) != NULL)
		return (p);
	return (opts.squid_bin);
}

static const char *
certgen_bin(struct work *w)
{
	const char	*p;

	if (w->jail != NULL)
		return (PATH_CERTGEN);
	if (opts.tools_dir != NULL) {
		p = wfmt(w, "%s/security_file_certgen", opts.tools_dir);
		if (access(p, X_OK) == 0)
			return (p);
	}
	return (PATH_CERTGEN);
}

/* The pid in an instance's pid file, when that process is there. */
static pid_t
inst_pid(struct work *w, const char *name)
{

	return (scope_pidfile(w, inst_path(w, name, "pid"), squid_bin(w)));
}

/* c-icap's files of an instance, beside the instance's own. */
static const char *
icap_path(struct work *w, const char *name, const char *ext)
{
	char	buf[MAXPATHLEN];

	if (w->jail != NULL)
		return (wfmt(w, "%s/sdwan-icap-%s.%s", DIR_OF(name), name, ext));
	sdwan_conf_path(wfmt(w, "sdwan-icap-%s.%s", name, ext), buf,
	    sizeof(buf));
	return (wstrdup(w, buf));
}

static const char *
icap_bin(struct work *w)
{
	const char	*p;

	if (w->jail != NULL)
		return (PATH_CICAP_BIN);
	if ((p = tool(w, "c-icap")) != NULL)
		return (p);
	return (opts.cicap_bin);
}

/* The pid of an instance's c-icap, when that process is there. */
static pid_t
icap_pid(struct work *w, const char *name)
{

	return (scope_pidfile(w, icap_path(w, name, "pid"), icap_bin(w)));
}

static void
icap_stop(struct work *w, const char *name)
{
	pid_t	pid;

	if ((pid = icap_pid(w, name)) == 0)
		return;
	scope_stop(w, pid, icap_bin(w), 3000);
}

/*
 * What malware scanning needs that is not FreeBSD's own: c-icap, its
 * ClamAV module (c-icap-modules) and ClamAV's signatures; NULL when
 * all are there, else what to install.  Stand-ins (-2) are taken as
 * they are.
 */
static const char *
icap_missing(struct work *w)
{
	DIR		*d;
	struct dirent	*de;
	const char	*x, *pj;
	bool		 sigs;
	int		 dfd;

	/* A jail's are its own: pkg -j installs them there. */
	pj = w->jail != NULL ? wfmt(w, "-j %s ", w->jail) : "";
	if (!scope_access(w, icap_bin(w), true))
		return (wfmt(w, "%s has no c-icap (%s): it is a plugin, "
		    "installed by hand (pkg %sinstall c-icap c-icap-modules "
		    "clamav)", w->jail != NULL ? wfmt(w, "the jail %s", w->jail) :
		    "the host", icap_bin(w), pj));
	if (opts.tools_dir != NULL)
		return (NULL);
	if (!scope_access(w, PATH_CICAP_MODULES "/clamav_mod.so", false))
		return (wfmt(w, "c-icap has no ClamAV module (" PATH_CICAP_MODULES
		    "/clamav_mod.so%s): pkg %sinstall c-icap-modules",
		    w->jail != NULL ? wfmt(w, " in the jail %s", w->jail) : "",
		    pj));
	sigs = false;
	d = (dfd = scope_dirfd(w, PATH_CLAMAV_DB)) != -1 ? fdopendir(dfd) :
	    NULL;
	if (d == NULL && dfd != -1)
		close(dfd);
	if (d != NULL) {
		while (!sigs && (de = readdir(d)) != NULL)
			if ((x = strrchr(de->d_name, '.')) != NULL && (strcmp(x,
			    ".cvd") == 0 || strcmp(x, ".cld") == 0 || strcmp(x,
			    ".hdb") == 0 || strcmp(x, ".ndb") == 0 || strcmp(x,
			    ".hsb") == 0))
				sigs = true;
		closedir(d);
	}
	if (!sigs)
		return (wfmt(w, "ClamAV has no signatures in " PATH_CLAMAV_DB
		    "%s: pkg %sinstall clamav, then freshclam (Security, "
		    "Signatures: Start freshclam enables clamav_freshclam and "
		    "starts it)", w->jail != NULL ? wfmt(w, " of the jail %s",
		    w->jail) : "", pj));
	return (NULL);
}

/*
 * An instance's c-icap, (re)started in its table with its file, as
 * icap_conf_render() made it.  Restarted rather than told, so that what
 * changed is what runs.
 */
static int
icap_start(struct work *w, const struct instance *in, const char *text,
    const char **errp)
{
	struct execres	 res;
	char		*argv[7];
	int		 k;

	if (px_write(w, in->name, wfmt(w, "sdwan-icap-%s.conf", in->name),
	    text, NULL, errp) != 0)
		return (-1);
	if (w->jail != NULL)
		(void)scope_mkdirs(w, "/var/log/c-icap");
	else
		(void)mkdir_mode("/var/log/c-icap", 0755);
	icap_stop(w, in->name);
	(void)scope_unlink(w, icap_path(w, in->name, "ctl"));
	k = 0;
	/* A jail's in its table by its own setfib(1), table 0 by none. */
	if (w->jail == NULL || in->fib != 0) {
		argv[k++] = (char *)(uintptr_t)(w->jail != NULL ?
		    "/usr/sbin/setfib" : opts.setfib_bin);
		argv[k++] = (char *)(uintptr_t)"-F";
		argv[k++] = wfmt(w, "%d", in->fib);
	}
	argv[k++] = (char *)(uintptr_t)icap_bin(w);
	argv[k++] = (char *)(uintptr_t)"-f";
	argv[k++] = (char *)(uintptr_t)icap_path(w, in->name, "conf");
	argv[k] = NULL;
	if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "c-icap"));
		return (-1);
	}
	/* It forks: up once its pid file is. */
	for (k = 0; k < 50 && icap_pid(w, in->name) == 0; k++)
		usleep(100000);
	if (icap_pid(w, in->name) == 0) {
		*errp = w->jail != NULL ? wfmt(w, "c-icap did not start: see "
		    "/var/log/c-icap in the jail %s", w->jail) : "c-icap did not "
		    "start: see /var/log/c-icap";
		return (-1);
	}
	return (0);
}

static void
icap_down(struct work *w, const char *name)
{

	icap_stop(w, name);
	(void)scope_unlink(w, icap_path(w, name, "conf"));
	(void)scope_unlink(w, icap_path(w, name, "pid"));
	(void)scope_unlink(w, icap_path(w, name, "ctl"));
}

/* An instance stopped: its process signalled and waited for, briefly. */
static void
inst_stop(struct work *w, const char *name)
{
	pid_t	pid;

	if ((pid = inst_pid(w, name)) == 0)
		return;
	scope_stop(w, pid, squid_bin(w), 3000);
}

/*
 * The instance's CA, made once by openssl(1) and kept beside its files:
 * the certificate and the key in one file for Squid, the certificate
 * alone for the clients.  A jail's made by the host's openssl beside
 * the agent's files, then written beneath the jail's root and taken
 * away here.  False and why when it could not be.
 */
static bool
inst_ca(struct work *w, const char *name, const char **errp)
{
	struct execres	 res;
	const char	*pem, *crt, *key, *jail;
	char		*argv[14], *text, *k, *c;
	size_t		 n;
	FILE		*fp;

	pem = inst_path(w, name, "pem");
	crt = inst_path(w, name, "crt");
	if (w->jail != NULL ? scope_access(w, pem, false) && scope_access(w,
	    crt, false) : access(pem, R_OK) == 0 && access(crt, R_OK) == 0)
		return (true);
	jail = NULL;
	if (w->jail != NULL) {
		jail = wstrdup(w, w->jail);
		(void)inst_in(w, "", NULL);
		crt = inst_path(w, name, "jcrt");
		pem = NULL;
	}
	key = inst_path(w, name, jail != NULL ? "jkey" : "key");
	argv[0] = (char *)(uintptr_t)"/usr/bin/openssl";
	argv[1] = (char *)(uintptr_t)"req";
	argv[2] = (char *)(uintptr_t)"-x509";
	argv[3] = (char *)(uintptr_t)"-newkey";
	argv[4] = (char *)(uintptr_t)"ec";
	argv[5] = (char *)(uintptr_t)"-pkeyopt";
	argv[6] = (char *)(uintptr_t)"ec_paramgen_curve:P-256";
	argv[7] = (char *)(uintptr_t)"-nodes";
	argv[8] = (char *)(uintptr_t)"-days";
	argv[9] = (char *)(uintptr_t)"3650";
	argv[10] = (char *)(uintptr_t)"-subj";
	argv[11] = wfmt(w, "/CN=Arcana SD-WAN %s proxy CA", name);
	argv[12] = (char *)(uintptr_t)"-keyout";
	argv[13] = NULL;
	/* The key and the certificate to files of their own, then one. */
	{
		char	*full[18];
		int	 i;

		for (i = 0; argv[i] != NULL; i++)
			full[i] = argv[i];
		full[i++] = (char *)(uintptr_t)key;
		full[i++] = (char *)(uintptr_t)"-out";
		full[i++] = (char *)(uintptr_t)crt;
		full[i] = NULL;
		exec_set_secret(true);
		n = (size_t)run_exec(w, full, &res);
		exec_set_secret(false);
		if (n != 0) {
			*errp = wtext(w, exec_error(w, &res, "openssl"));
			return (false);
		}
	}
	if ((k = file_text(w, key)) == NULL || (c = file_text(w, crt)) == NULL) {
		(void)unlink(key);
		*errp = wfmt(w, "%s: the CA was not written", name);
		if (jail != NULL)
			(void)inst_in(w, jail, NULL);
		return (false);
	}
	text = wfmt(w, "%s%s", c, k);
	(void)unlink(key);
	/* A jail's: the certificate and the pair written there. */
	if (jail != NULL) {
		(void)unlink(crt);
		if (inst_in(w, jail, errp) != 0)
			return (false);
		if (scope_mkdirs(w, DIR_OF(name)) != 0 || scope_replace(w,
		    inst_path(w, name, "pem"), text, strlen(text), 0600, NULL) !=
		    0 || scope_replace(w, inst_path(w, name, "crt"), c, strlen(c),
		    0644, NULL) != 0) {
			*errp = wfmt(w, "%s: the CA in the jail %s: %s", name, jail,
			    strerror(errno));
			explicit_bzero(text, strlen(text));
			explicit_bzero(k, strlen(k));
			return (false);
		}
		explicit_bzero(text, strlen(text));
		explicit_bzero(k, strlen(k));
		return (true);
	}
	if ((fp = fopen(pem, "w")) == NULL) {
		*errp = wfmt(w, "%s: %s", pem, strerror(errno));
		return (false);
	}
	(void)fchmod(fileno(fp), 0600);
	fputs(text, fp);
	fclose(fp);
	explicit_bzero(text, strlen(text));
	explicit_bzero(k, strlen(k));
	return (true);
}

/* A file given to the squid user, when the host has one; else as is. */
static void
inst_chown(struct work *w, const char *path, bool recurse)
{
	struct execres	 res;
	char		*argv[5];
	int		 n;

	n = 0;
	argv[n++] = (char *)(uintptr_t)"/usr/sbin/chown";
	if (recurse)
		argv[n++] = (char *)(uintptr_t)"-R";
	argv[n++] = (char *)(uintptr_t)"squid:squid";
	argv[n++] = (char *)(uintptr_t)path;
	argv[n] = NULL;
	/* A jail's by its own chown(8), its own squid user. */
	(void)run_exec(w, scope_jexec(w, argv), &res);
}

/* The certificate cache, beside the instance's files: made once, the
 * squid user's; Squid's certificate maker needs it in both modes. */
static bool
inst_ssldb(struct work *w, const char *name, const char **errp)
{
	struct execres	 res;
	char		*argv[7];
	const char	*dir;

	dir = inst_path(w, name, "ssl_db");
	if (w->jail != NULL ? scope_access(w, dir, false) : access(dir, F_OK) ==
	    0)
		return (true);
	if (w->jail != NULL)
		(void)scope_mkdirs(w, DIR_OF(name));
	argv[0] = (char *)(uintptr_t)certgen_bin(w);
	argv[1] = (char *)(uintptr_t)"-c";
	argv[2] = (char *)(uintptr_t)"-s";
	argv[3] = (char *)(uintptr_t)dir;
	argv[4] = (char *)(uintptr_t)"-M";
	argv[5] = (char *)(uintptr_t)"4MB";
	argv[6] = NULL;
	if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "security_file_certgen"));
		return (false);
	}
	inst_chown(w, dir, true);
	return (true);
}

/*
 * Where an instance's files are, as its configuration names them: its
 * own, its c-icap's, a list's (list-<name>) beside them.
 */
static void
inst_paths(struct work *w, const char *name, struct sqpaths *p)
{

	p->pid = inst_path(w, name, "pid");
	p->ca = inst_path(w, name, "pem");
	p->ssldb = inst_path(w, name, "ssl_db");
	p->certgen = certgen_bin(w);
	p->deny = inst_path(w, name, "deny");
	p->list_pre = inst_path(w, name, "list-");
	p->list_suf = "";
	p->icap_pid = icap_path(w, name, "pid");
	p->icap_cmd = icap_path(w, name, "ctl");
	/* The logs a jail's daemons write: the jail's own. */
	p->log_dir = w->jail != NULL ? "/var/log" : NULL;
}

/* An instance's list files gone, all of them. */
static void
lists_clear(struct work *w, const char *name)
{
	DIR		*d;
	struct dirent	*de;
	const char	*path, *dir, *pre;
	size_t		 n;
	int		 dfd;

	path = inst_path(w, name, "x");
	dir = strrchr(path, '/') != NULL ? wfmt(w, "%.*s", (int)(strrchr(path,
	    '/') - path), path) : ".";
	pre = wfmt(w, "sdwan-proxy-%s.list-", name);
	n = strlen(pre);
	/* Beneath a jail's root, never by a link out of it. */
	if ((dfd = scope_dirfd(w, dir)) == -1)
		return;
	if ((d = fdopendir(dfd)) == NULL) {
		close(dfd);
		return;
	}
	while ((de = readdir(d)) != NULL)
		if (strncmp(de->d_name, pre, n) == 0)
			(void)unlinkat(dirfd(d), de->d_name, 0);
	closedir(d);
}

/* An instance's list files, those it had before gone. */
static bool
lists_write(struct work *w, const char *name, const ucl_object_t *lists,
    const char **errp)
{
	const ucl_object_t	*l;
	ucl_object_iter_t	 it;

	lists_clear(w, name);
	it = NULL;
	while ((l = ucl_object_iterate(lists, &it, true)) != NULL)
		if (px_write(w, name, wfmt(w, "sdwan-proxy-%s.list-%s", name,
		    ucl_object_key(l)), ucl_object_tostring(l), "squid",
		    errp) != 0)
			return (false);
	return (true);
}

/* An instance's lists as the console sends them: names to texts. */
static bool
lists_ok(const ucl_object_t *lists)
{
	const ucl_object_t	*l;
	ucl_object_iter_t	 it;
	size_t			 n;

	if (lists == NULL)
		return (true);
	if (ucl_object_type(lists) != UCL_OBJECT)
		return (false);
	n = 0;
	it = NULL;
	while ((l = ucl_object_iterate(lists, &it, true)) != NULL)
		if (++n > LISTS_MAX || !name_ok(ucl_object_key(l)) ||
		    ucl_object_type(l) != UCL_STRING || strlen(
		    ucl_object_tostring(l)) > DENY_MAX)
			return (false);
	return (true);
}

/* An instance started in its table, or told its file again. */
static int
inst_start(struct work *w, const struct instance *in, bool running,
    const char **errp)
{
	struct execres	 res;
	char		*argv[8];
	int		 n;

	n = 0;
	if (running) {
		argv[n++] = (char *)(uintptr_t)squid_bin(w);
		argv[n++] = (char *)(uintptr_t)"-k";
		argv[n++] = (char *)(uintptr_t)"reconfigure";
	} else {
		/* A jail's in its table by its own setfib(1), table 0 by
		 * none. */
		if (w->jail == NULL || in->fib != 0) {
			argv[n++] = (char *)(uintptr_t)(w->jail != NULL ?
			    "/usr/sbin/setfib" : opts.setfib_bin);
			argv[n++] = (char *)(uintptr_t)"-F";
			argv[n++] = wfmt(w, "%d", in->fib);
		}
		argv[n++] = (char *)(uintptr_t)squid_bin(w);
	}
	argv[n++] = (char *)(uintptr_t)"-f";
	argv[n++] = (char *)(uintptr_t)inst_path(w, in->name, "conf");
	argv[n] = NULL;
	if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "squid"));
		return (-1);
	}
	return (0);
}

/* An instance stopped and its files gone, the CA kept. */
static void
inst_down(struct work *w, const char *name)
{

	inst_stop(w, name);
	icap_down(w, name);
	(void)scope_unlink(w, inst_path(w, name, "conf"));
	(void)scope_unlink(w, inst_path(w, name, "deny"));
	lists_clear(w, name);
	(void)scope_unlink(w, inst_path(w, name, "pid"));
}

/* ClamAV's hash signature files the MD+R's hashes go to. */
static const char *const sig_ext[] = { "hdb", "hsb", "fp", "sfp" };

/* Where ClamAV reads its signatures, under --root when one is given;
 * a jail's as the jail sees it. */
static const char *
clamav_db(struct work *w)
{

	return (opts.root != NULL && w->jail == NULL ? wfmt(w, "%s%s",
	    opts.root, PATH_CLAMAV_DB) : PATH_CLAMAV_DB);
}

/*
 * The MD+R's hashes as ClamAV's signature files (clamav_sigs_render),
 * arcana-sdwan.hdb, .hsb, .fp and .sfp in its database directory, each
 * written beside and moved in, those with nothing in them gone.
 * c-icap's ClamAV module reads the whole directory as it starts, as
 * the instances' c-icap do next; the host's ClamAV is one for every
 * service of its edge.  A jail edge's are its own ClamAV's, written
 * beneath the jail's root (w in the jail), through no link out of it.
 */
static int
hashes_write(struct work *w, const ucl_object_t *h, const char **errp)
{
	const ucl_object_t	*f;
	const char		*path, *tmp;
	char			*dir, *p;
	FILE			*fp;
	size_t			 i;

	if (w->jail != NULL) {
		if (scope_mkdirs(w, PATH_CLAMAV_DB) != 0) {
			*errp = wfmt(w, PATH_CLAMAV_DB " in the jail %s: %s",
			    w->jail, strerror(errno));
			return (-1);
		}
		for (i = 0; i < nitems(sig_ext); i++) {
			path = wfmt(w, PATH_CLAMAV_DB "/arcana-sdwan.%s",
			    sig_ext[i]);
			if ((f = ucl_object_lookup(h, sig_ext[i])) == NULL) {
				(void)scope_unlink(w, path);
				continue;
			}
			if (scope_replace(w, path, ucl_object_tostring(f),
			    strlen(ucl_object_tostring(f)), 0644, NULL) != 0) {
				*errp = wfmt(w, "%s in the jail %s: %s", path,
				    w->jail, strerror(errno));
				return (-1);
			}
		}
		return (0);
	}
	/* The directory, where the host has no ClamAV yet. */
	dir = wstrdup(w, clamav_db(w));
	for (p = dir + 1; (p = strchr(p, '/')) != NULL; p++) {
		*p = '\0';
		(void)mkdir_mode(dir, 0755);
		*p = '/';
	}
	(void)mkdir_mode(dir, 0755);
	for (i = 0; i < nitems(sig_ext); i++) {
		path = wfmt(w, "%s/arcana-sdwan.%s", clamav_db(w), sig_ext[i]);
		if ((f = ucl_object_lookup(h, sig_ext[i])) == NULL) {
			(void)unlink(path);
			continue;
		}
		tmp = wfmt(w, "%s.new", path);
		if ((fp = fopen(tmp, "w")) == NULL) {
			*errp = wfmt(w, "%s: %s", tmp, strerror(errno));
			return (-1);
		}
		(void)fchmod(fileno(fp), 0644);
		fputs(ucl_object_tostring(f), fp);
		if (fclose(fp) != 0 || rename(tmp, path) != 0) {
			*errp = wfmt(w, "%s: %s", path, strerror(errno));
			(void)unlink(tmp);
			return (-1);
		}
	}
	return (0);
}

static ucl_object_t *
parse(const char *json)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	return (o);
}

/*
 * The instances applied: {"instances": [{"name", "fib", "mode", "host",
 * "spec", "lists"}, ...]}, of SD-WAN; with "group": "security", of the
 * Security section, each named sec-, those of the other group left as
 * they are.  spec is the instance's form, an SD-WAN service's or the
 * Security section's, rendered by squid_conf_render() and, where it
 * scans for malware, icap_conf_render(), every one before any is
 * changed; host names the host in their comments.  Squid must be there
 * (a plugin); each instance's CA is made once; its file is checked by
 * squid -k parse before it is made the instance's; a running one is
 * told to reconfigure, one not yet is started in its table; one stopped
 * (stopped: true) is stopped, its files kept; those not named any more
 * are stopped, their files gone.  Kept for the next start.  The
 * Security section's may each name a running jail ("jail") to run in.
 * SD-WAN's with "jail" are those of an edge that is that vnet jail, run
 * in it; the other edges' are left as they are, and each edge's list
 * is kept in a file of its own.
 */
int
do_sdwan_proxy(struct work *w, const char *json, const char **errp)
{
	ucl_object_t		*top, *hashes;
	const ucl_object_t	*in, *v;
	ucl_object_iter_t	 it, hit;
	struct instance		 ni[INSTANCES_MAX];
	struct execres		 res;
	struct sqpaths		 pp;
	char			*argv[6], *confs[INSTANCES_MAX];
	char			*denies[INSTANCES_MAX], *icaps[INSTANCES_MAX];
	char			 kpath[MAXPATHLEN];
	const char		*mode, *e, *host, *edge, *file;
	int			 n, i, k, step, nkeep;
	bool			 was, ok, sec, edgedown;

	if ((top = parse(json)) == NULL || ucl_object_type(top) != UCL_OBJECT) {
		if (top != NULL)
			ucl_object_unref(top);
		*errp = "the instances are an object: instances, each a name, "
		    "a fib, a mode, a host, its spec and its lists";
		return (-1);
	}
	sec = ucl_object_lookup(top, "group") != NULL && strcmp(
	    ucl_object_tostring_forced(ucl_object_lookup(top, "group")),
	    "security") == 0;
	/* The edge, SD-WAN's: a vnet jail's, running (at the start, one
	 * that is not keeps its instances for the next apply), or the
	 * host's.  The Security section's are the host's edge's, each
	 * naming its own jail. */
	if ((edge = sdwan_payload_jail(top, errp)) == NULL) {
		ucl_object_unref(top);
		return (-1);
	}
	edge = wstrdup(w, edge);
	if (sec && edge[0] != '\0') {
		ucl_object_unref(top);
		*errp = "the Security section's are the host's edge's: each "
		    "names the jail it runs in";
		return (-1);
	}
	edgedown = false;
	if (edge[0] != '\0') {
		e = NULL;
		if (scope_enter(w, edge, &e) != 0) {
			if (!starting) {
				ucl_object_unref(top);
				*errp = wfmt(w, "the edge %s: %s", edge, e);
				return (-1);
			}
			edgedown = true;
		}
		(void)inst_in(w, "", NULL);
	}
	/* Each one's flags false unless said (stopped). */
	memset(ni, 0, sizeof(ni));
	n = 0;
	it = NULL;
	while ((in = ucl_object_iterate(ucl_object_lookup(top, "instances"),
	    &it, true)) != NULL) {
		v = ucl_object_lookup(in, "name");
		mode = ucl_object_tostring(ucl_object_lookup(in, "mode"));
		if (n == INSTANCES_MAX || v == NULL || ucl_object_type(v) !=
		    UCL_STRING || !name_ok(ucl_object_tostring(v)) ||
		    ucl_object_lookup(in, "fib") == NULL || ucl_object_toint(
		    ucl_object_lookup(in, "fib")) < 0 || ucl_object_toint(
		    ucl_object_lookup(in, "fib")) > 65535 || ucl_object_type(
		    ucl_object_lookup(in, "spec")) != UCL_OBJECT || mode ==
		    NULL || (strcmp(mode, "sni") != 0 && strcmp(mode, "inspect")
		    != 0) || !lists_ok(ucl_object_lookup(in, "lists"))) {
			ucl_object_unref(top);
			*errp = wfmt(w, "an instance is a name of letters, digits, "
			    "_ and -, 32 at most, a fib, a mode (sni or inspect), "
			    "a host, its spec and its lists (names of the same "
			    "letters to texts, %d at most), %d of them at most",
			    LISTS_MAX, INSTANCES_MAX);
			return (-1);
		}
		for (i = 0; i < n; i++)
			if (strcmp(ni[i].name, ucl_object_tostring(v)) == 0) {
				ucl_object_unref(top);
				*errp = wfmt(w, "instance %s is named twice",
				    ni[i].name);
				return (-1);
			}
		if (IS_SEC(ucl_object_tostring(v)) != sec) {
			ucl_object_unref(top);
			*errp = wfmt(w, "instance %s: the Security section's are "
			    "named " SEC_PREFIX ", SD-WAN's not",
			    ucl_object_tostring(v));
			return (-1);
		}
		snprintf(ni[n].name, sizeof(ni[n].name), "%s",
		    ucl_object_tostring(v));
		/* The jail it runs in, the Security section's alone: an
		 * SD-WAN service's runs on its edge.  Running, but at the
		 * start, when one that is not is kept for the next apply. */
		if ((v = ucl_object_lookup(in, "jail")) != NULL &&
		    (ucl_object_type(v) != UCL_STRING || ucl_object_tostring(
		    v)[0] != '\0')) {
			if (ucl_object_type(v) != UCL_STRING ||
			    !valid_jail(ucl_object_tostring(v)) || strlen(
			    ucl_object_tostring(v)) >= sizeof(ni[n].jail) ||
			    !sec) {
				ucl_object_unref(top);
				*errp = !sec ? wfmt(w, "%s: only the Security "
				    "section's run in a jail: an SD-WAN service's "
				    "runs on its edge (a jail edge's list names "
				    "the jail)", ni[n].name) : wfmt(w, "%s: its "
				    "jail is a jail's name", ni[n].name);
				return (-1);
			}
			snprintf(ni[n].jail, sizeof(ni[n].jail), "%s",
			    ucl_object_tostring(v));
			if (inst_in(w, ni[n].jail, NULL) != 0) {
				if (!starting) {
					ucl_object_unref(top);
					*errp = wfmt(w, "%s: the jail %s is not "
					    "running: it runs in it, start the jail "
					    "first", ni[n].name, ni[n].jail);
					return (-1);
				}
				ni[n].jaildown = true;
			}
			(void)inst_in(w, "", NULL);
		}
		/* An SD-WAN service's at a jail edge: in the jail. */
		if (!sec && edge[0] != '\0') {
			snprintf(ni[n].jail, sizeof(ni[n].jail), "%s", edge);
			ni[n].jaildown = edgedown;
		}
		snprintf(ni[n].mode, sizeof(ni[n].mode), "%s", mode);
		ni[n].fib = (int)ucl_object_toint(ucl_object_lookup(in, "fib"));
		ni[n].icap = squid_conf_icap(ucl_object_lookup(in, "spec"));
		if ((v = ucl_object_lookup(in, "stopped")) != NULL) {
			if (ucl_object_type(v) != UCL_BOOLEAN) {
				ucl_object_unref(top);
				*errp = wfmt(w, "%s: stopped is true or false",
				    ni[n].name);
				return (-1);
			}
			ni[n].stopped = ucl_object_toboolean(v);
		}
		/* Its files made of its form, here: what squid refuses is
		 * said before any instance is touched. */
		host = ucl_object_type(ucl_object_lookup(in, "host")) ==
		    UCL_STRING ? ucl_object_tostring(ucl_object_lookup(in,
		    "host")) : "";
		/* Its paths as it sees them: a jail's beneath its root. */
		if (!ni[n].jaildown)
			(void)inst_in(w, ni[n].jail, NULL);
		inst_paths(w, ni[n].name, &pp);
		(void)inst_in(w, "", NULL);
		e = NULL;
		icaps[n] = NULL;
		if ((confs[n] = squid_conf_render(w, ucl_object_lookup(in,
		    "spec"), ni[n].name, host, n, ucl_object_lookup(in, "lists"),
		    &pp, &denies[n], &e)) == NULL || (ni[n].icap && (icaps[n] =
		    icap_conf_render(w, ucl_object_lookup(in, "spec"),
		    ni[n].name, host, n, &pp, &e)) == NULL)) {
			ucl_object_unref(top);
			*errp = wfmt(w, "%s: %s", ni[n].name, e);
			return (-1);
		}
		n++;
	}
	/* The lists' together within the table: refused before any is
	 * started, none started and then not kept. */
	pthread_mutex_lock(&lock);
	for (i = nkeep = 0; i < ninstances; i++)
		if (!of_list(&instances[i], sec, edge))
			nkeep++;
	pthread_mutex_unlock(&lock);
	if (nkeep + n > INSTANCES_MAX) {
		ucl_object_unref(top);
		*errp = wfmt(w, "%d instances at most, SD-WAN's of every edge and "
		    "the Security section's together: the others have %d",
		    INSTANCES_MAX, nkeep);
		return (-1);
	}
	/* Squid, and c-icap where it scans, where each runs: the host's,
	 * or the jail's own. */
	for (k = 0; k < n; k++) {
		if (ni[k].jaildown || inst_in(w, ni[k].jail, NULL) != 0)
			continue;
		e = NULL;
		if (w->jail == NULL ? access(squid_bin(w), X_OK) != 0 :
		    !scope_access(w, squid_bin(w), true))
			e = w->jail == NULL ? wfmt(w, "the host has no squid "
			    "(%s): it is a plugin, installed by hand (pkg install "
			    "squid)", squid_bin(w)) : wfmt(w, "%s: the jail %s has "
			    "no squid (%s): it is a plugin, installed by hand in "
			    "the jail (pkg -j %s install squid)", ni[k].name,
			    w->jail, squid_bin(w), w->jail);
		else if (ni[k].icap)
			e = icap_missing(w);
		(void)inst_in(w, "", NULL);
		if (e != NULL) {
			ucl_object_unref(top);
			*errp = e;
			return (-1);
		}
	}
	/* The MD+R policies' hashes as ClamAV's signatures first: the
	 * instances' c-icap read them as they start.  A jail edge's in its
	 * own ClamAV's; one not running left as it is. */
	if (!sec && !edgedown) {
		e = NULL;
		if ((hashes = clamav_sigs_render(w, ucl_object_lookup(top,
		    "instances"), &e)) == NULL) {
			ucl_object_unref(top);
			*errp = e;
			return (-1);
		}
		hit = NULL;
		k = inst_in(w, edge, &e);
		if (k == 0)
			k = ucl_object_iterate(hashes, &hit, true) != NULL ||
			    (w->jail != NULL ? scope_access(w, clamav_db(w),
			    false) : access(clamav_db(w), W_OK) == 0) ?
			    hashes_write(w, hashes, &e) : 0;
		(void)inst_in(w, "", NULL);
		ucl_object_unref(hashes);
		if (k != 0) {
			ucl_object_unref(top);
			*errp = e;
			return (-1);
		}
	}
	pthread_mutex_lock(&lock);
	for (i = 0; i < ninstances; i++) {
		/* The other group's and edges' are not this list's to
		 * stop. */
		if (!of_list(&instances[i], sec, edge))
			continue;
		/* Not named any more, or moved to another place. */
		for (k = 0; k < n; k++)
			if (strcmp(ni[k].name, instances[i].name) == 0 &&
			    strcmp(ni[k].jail, instances[i].jail) == 0)
				break;
		if (k == n) {
			step = step_begin(w, STEP_DAEMON, "arcana-agent",
			    "squid %s%s%s stopped", instances[i].name,
			    instances[i].jail[0] != '\0' ? " of the jail " : "",
			    instances[i].jail);
			if (inst_in(w, instances[i].jail, &e) != 0) {
				step_end(w, step, true, "%s: its files there are "
				    "left", e);
				continue;
			}
			inst_down(w, instances[i].name);
			(void)inst_in(w, "", NULL);
			step_end(w, step, true, NULL);
		}
	}
	ok = true;
	it = NULL;
	for (k = 0; k < n; k++) {
		in = ucl_object_iterate(ucl_object_lookup(top, "instances"), &it,
		    true);
		/* Where it runs: its jail not running at the start, kept for
		 * the next apply, not started. */
		if (ni[k].jaildown || inst_in(w, ni[k].jail, NULL) != 0) {
			ni[k].jaildown = true;
			step = step_begin(w, STEP_DAEMON, "arcana-agent",
			    "squid %s of the jail %s: the jail is not running, "
			    "kept, not started", ni[k].name, ni[k].jail);
			step_end(w, step, true, NULL);
			continue;
		}
		/* Stopped by the admin: it and its c-icap, files kept. */
		if (ni[k].stopped) {
			step = step_begin(w, STEP_DAEMON, "arcana-agent",
			    "squid %s stopped, kept", ni[k].name);
			inst_stop(w, ni[k].name);
			icap_stop(w, ni[k].name);
			step_end(w, step, true, NULL);
			continue;
		}
		was = inst_pid(w, ni[k].name) != 0;
		step = step_begin(w, STEP_DAEMON, "arcana-agent",
		    "squid %s%s%s in fib %d, %s: %s", ni[k].name, ni[k].jail[0] !=
		    '\0' ? " of the jail " : "", ni[k].jail, ni[k].fib,
		    ni[k].mode, was ? "reconfigured" : "started");
		e = NULL;
		/* The certificate cache in both modes: Squid's certificate
		 * maker serves the TLS port's own pages too. */
		if (!inst_ca(w, ni[k].name, &e) || !inst_ssldb(w, ni[k].name, &e)) {
			step_end(w, step, false, "%s", e);
			*errp = wfmt(w, "%s: %s", ni[k].name, e);
			ok = false;
			break;
		}
		inst_chown(w, inst_path(w, ni[k].name, "pem"), false);
		/* Read again by Squid as its user at a reconfigure. */
		if (px_write(w, ni[k].name, wfmt(w, "sdwan-proxy-%s.deny",
		    ni[k].name), denies[k], "squid", &e) != 0 || !lists_write(w,
		    ni[k].name, ucl_object_lookup(in, "lists"), &e) ||
		    px_write(w, ni[k].name, wfmt(w, "sdwan-proxy-%s.conf",
		    ni[k].name), confs[k], "squid", &e) != 0) {
			step_end(w, step, false, "%s", e);
			*errp = wfmt(w, "%s: %s", ni[k].name, e);
			ok = false;
			break;
		}
		/* Its scanner first: Squid sends to it and waits. */
		if (ni[k].icap) {
			if (icap_start(w, &ni[k], icaps[k], &e) != 0) {
				step_end(w, step, false, "%s", e);
				*errp = wfmt(w, "%s: %s", ni[k].name, e);
				ok = false;
				break;
			}
		} else
			icap_down(w, ni[k].name);
		/* Checked first: what squid refuses is not run. */
		argv[0] = (char *)(uintptr_t)squid_bin(w);
		argv[1] = (char *)(uintptr_t)"-k";
		argv[2] = (char *)(uintptr_t)"parse";
		argv[3] = (char *)(uintptr_t)"-f";
		argv[4] = (char *)(uintptr_t)inst_path(w, ni[k].name, "conf");
		argv[5] = NULL;
		if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
			step_end(w, step, false, "squid does not take it");
			*errp = wfmt(w, "%s: squid does not take it: %s", ni[k].name,
			    res.errlen > 0 ? res.err : res.out != NULL ? res.out :
			    "no reason given");
			ok = false;
			break;
		}
		if (inst_start(w, &ni[k], was, &e) != 0) {
			step_end(w, step, false, "%s", e);
			*errp = e;
			ok = false;
			break;
		}
		step_end(w, step, true, NULL);
	}
	(void)inst_in(w, "", NULL);
	if (ok) {
		/* The other lists' kept, then this one's. */
		nkeep = 0;
		for (i = 0; i < ninstances; i++)
			if (!of_list(&instances[i], sec, edge))
				instances[nkeep++] = instances[i];
		memcpy(instances + nkeep, ni, sizeof(*ni) * (size_t)n);
		ninstances = nkeep + n;
		/* The SD-WAN's logs read for what they blocked: each
		 * running Squid's, and its c-icap's, of its edge. */
		if (!sec && !edgedown)
			proxies_watch(w, top, ni, n, edge);
	}
	pthread_mutex_unlock(&lock);
	ucl_object_unref(top);
	if (!ok)
		return (-1);
	/* Kept, a file per edge; a jail's with no instance goes, so that a
	 * start makes none for a jail that has none now. */
	file = sec ? SEC_FILE : edge[0] != '\0' ? wfmt(w,
	    "sdwan-proxy@%s.json", edge) : PROXY_FILE;
	if (edge[0] != '\0' && n == 0) {
		if (unlink(sdwan_conf_path(file, kpath, sizeof(kpath))) == -1 &&
		    errno != ENOENT) {
			*errp = wfmt(w, "%s: %s", file, strerror(errno));
			return (-1);
		}
		return (0);
	}
	e = NULL;
	if (sdwan_conf_write(file, json, &e) != 0) {
		*errp = wfmt(w, "%s: %s", file, e);
		return (-1);
	}
	return (0);
}

/*
 * The SD-WAN instances' logs of an edge, those not stopped, read for
 * what they blocked (sdblock.c): Squid's access log, c-icap's server
 * log, where sdconf.c had them write; a jail edge's in its /var/log,
 * read beneath its root.
 */
static void
proxies_watch(struct work *w, const ucl_object_t *top,
    const struct instance *ni, int n, const char *edge)
{
	const ucl_object_t	*in, *sq[INSTANCES_MAX], *ic[INSTANCES_MAX];
	const char		*sn[INSTANCES_MAX], *sp[INSTANCES_MAX];
	const char		*in_[INSTANCES_MAX], *ip[INSTANCES_MAX];
	const char		*jroot, *dir;
	ucl_object_iter_t	 it;
	char			 buf[MAXPATHLEN];
	int			 k, ns, ni_;

	jroot = NULL;
	dir = NULL;
	if (edge[0] != '\0') {
		if (inst_in(w, edge, NULL) != 0)
			return;
		jroot = wstrdup(w, w->jroot);
		(void)inst_in(w, "", NULL);
		dir = "/var/log";
	}
	ns = ni_ = 0;
	it = NULL;
	for (k = 0; k < n; k++) {
		in = ucl_object_iterate(ucl_object_lookup(top, "instances"), &it,
		    true);
		if (ni[k].stopped)
			continue;
		sn[ns] = ni[k].name;
		sp[ns] = wstrdup(w, sdwan_squid_log(buf, sizeof(buf), dir,
		    ni[k].fib));
		sq[ns++] = ucl_object_lookup(in, "spec");
		if (!ni[k].icap)
			continue;
		in_[ni_] = ni[k].name;
		ip[ni_] = wstrdup(w, sdwan_icap_log(buf, sizeof(buf), dir,
		    ni[k].fib));
		ic[ni_++] = ucl_object_lookup(in, "spec");
	}
	sdblock_watch_jail(SDB_SQUID, edge, jroot, ns, sn, sp, sq);
	sdblock_watch_jail(SDB_ICAP, edge, jroot, ni_, in_, ip, ic);
}

/* At the start: the instances kept, the host's, each jail edge's and
 * the Security section's, started again. */
void
sdwan_proxy_start(void)
{
	struct work	 w;
	struct dirent	*de;
	DIR		*d;
	char		*json, dir[MAXPATHLEN], *slash;
	const char	*e;
	size_t		 n;

	work_init(&w);
	starting = true;
	if ((json = sdwan_kept_read(PROXY_FILE)) != NULL) {
		e = NULL;
		if (do_sdwan_proxy(&w, json, &e) != 0)
			logmsg(LOG_WARNING, "sdwan proxy: %s", e);
		free(json);
	}
	sdwan_conf_path(PROXY_FILE, dir, sizeof(dir));
	if ((slash = strrchr(dir, '/')) == NULL)
		snprintf(dir, sizeof(dir), ".");
	else
		*slash = '\0';
	if ((d = opendir(dir)) != NULL) {
		while ((de = readdir(d)) != NULL) {
			n = strlen(de->d_name);
			if (strncmp(de->d_name, "sdwan-proxy@", 12) != 0 || n <=
			    17 || strcmp(de->d_name + n - 5, ".json") != 0)
				continue;
			if ((json = sdwan_kept_read(de->d_name)) == NULL)
				continue;
			e = NULL;
			if (do_sdwan_proxy(&w, json, &e) != 0)
				logmsg(LOG_WARNING, "sdwan proxy: %s: %s",
				    de->d_name, e);
			free(json);
		}
		closedir(d);
	}
	if ((json = sdwan_kept_read(SEC_FILE)) != NULL) {
		e = NULL;
		if (do_sdwan_proxy(&w, json, &e) != 0)
			logmsg(LOG_WARNING, "security proxy: %s", e);
		free(json);
	}
	starting = false;
	work_free(&w);
}

/*
 * What the Security section asked for of a kind, kept with what was
 * applied: each instance's "spec", the form's own words, for its page
 * to show and change (not the configurations made of them), as key.
 */
void
security_specs(const char *file, ucl_object_t *top, const char *key)
{
	const ucl_object_t	*in;
	ucl_object_iter_t	 it;
	ucl_object_t		*kept, *arr;
	char			*json;

	if ((json = sdwan_kept_read(file)) == NULL)
		return;
	kept = parse(json);
	free(json);
	if (kept == NULL)
		return;
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((in = ucl_object_iterate(ucl_object_lookup(kept, "instances"),
	    &it, true)) != NULL) {
		ucl_object_t		*sp;
		const ucl_object_t	*j;

		if (ucl_object_lookup(in, "spec") == NULL)
			continue;
		/* With the jail it runs in, where it has one. */
		sp = ucl_object_copy(ucl_object_lookup(in, "spec"));
		if ((j = ucl_object_lookup(in, "jail")) != NULL &&
		    ucl_object_type(j) == UCL_STRING && ucl_object_tostring(
		    j)[0] != '\0' && ucl_object_type(sp) == UCL_OBJECT)
			ucl_object_replace_key(sp, ucl_object_copy(j), "jail", 0,
			    false);
		ucl_array_append(arr, sp);
	}
	ucl_object_unref(kept);
	ucl_object_insert_key(top, arr, key, 0, false);
}

/*
 * ClamAV's signatures as freshclam left them: each database's version,
 * signatures and when it was built, read from the head of its file
 * ("ClamAV-VDB:time:version:signatures:level:..."), and whether
 * freshclam runs; the host's, or w's jail's own, read beneath its root.
 * NULL when there is no database.
 */
static ucl_object_t *
clamav_obj(struct work *w)
{
	static const char *const dbs[] = { "main", "daily", "bytecode" };
	ucl_object_t	*o, *arr, *d;
	char		 head[513], path[PATH_MAX], *f[6], *p;
	size_t		 i, k;
	ssize_t		 n;
	int		 fd;
	FILE		*pf;
	long		 pid;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < nitems(dbs); i++) {
		snprintf(path, sizeof(path), "%s/%s.cvd", CLAMAV_DB, dbs[i]);
		if ((fd = scope_open_read(w, path)) == -1) {
			snprintf(path, sizeof(path), "%s/%s.cld", CLAMAV_DB,
			    dbs[i]);
			if ((fd = scope_open_read(w, path)) == -1)
				continue;
		}
		n = read(fd, head, sizeof(head) - 1);
		close(fd);
		if (n <= 0)
			continue;
		head[n] = '\0';
		if (strncmp(head, "ClamAV-VDB:", 11) != 0)
			continue;
		head[strcspn(head, "\n")] = '\0';
		p = head;
		for (k = 0; k < nitems(f); k++)
			f[k] = strsep(&p, ":");
		if (f[3] == NULL)
			continue;
		d = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(d, ucl_object_fromstring(dbs[i]), "name",
		    0, false);
		ucl_object_insert_key(d, ucl_object_fromstring(path), "file", 0,
		    false);
		ucl_object_insert_key(d, ucl_object_fromstring(f[1]), "built", 0,
		    false);
		ucl_object_insert_key(d, ucl_object_fromint(strtol(f[2], NULL,
		    10)), "version", 0, false);
		ucl_object_insert_key(d, ucl_object_fromint(strtol(f[3], NULL,
		    10)), "signatures", 0, false);
		ucl_array_append(arr, d);
	}
	if (ucl_array_size(arr) == 0 && !scope_access(w, CLAMAV_DB, false)) {
		ucl_object_unref(arr);
		return (NULL);
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, arr, "databases", 0, false);
	pid = 0;
	if ((pf = scope_fopen(w, FRESHCLAM_PID)) != NULL) {
		if (fscanf(pf, "%ld", &pid) != 1)
			pid = 0;
		fclose(pf);
	}
	ucl_object_insert_key(o, ucl_object_frombool(pid > 1 &&
	    pid_alive((pid_t)pid)), "freshclam", 0, false);
	/* freshclam's configuration: there, and not the port's sample
	 * still saying Example, which makes freshclam refuse to run; and
	 * the last of its log, which says why signatures do not come. */
	{
		char	 line[512], last[3][512];
		int	 nl, j;
		bool	 conf, example;

		conf = (pf = scope_fopen(w, w->jail != NULL ?
		    PATH_FRESHCLAM_CONF : opts.freshclam_conf)) != NULL;
		example = false;
		while (pf != NULL && fgets(line, sizeof(line), pf) != NULL)
			if (strncmp(line, "Example", 7) == 0 && (line[7] == '\n' ||
			    line[7] == '\r' || line[7] == '\0'))
				example = true;
		if (pf != NULL)
			fclose(pf);
		ucl_object_insert_key(o, ucl_object_frombool(conf && !example),
		    "conf", 0, false);
		clamav_mirrors_json(w, o);
		nl = 0;
		if ((pf = scope_fopen(w, "/var/log/clamav/freshclam.log")) !=
		    NULL) {
			while (fgets(line, sizeof(line), pf) != NULL) {
				if (line[0] == '\n' || strncmp(line, "---", 3) == 0)
					continue;
				snprintf(last[nl % 3], sizeof(last[0]), "%s", line);
				nl++;
			}
			fclose(pf);
		}
		if (nl > 0) {
			ucl_object_t	*lg = ucl_object_typed_new(UCL_ARRAY);

			for (j = nl > 3 ? nl - 3 : 0; j < nl; j++) {
				last[j % 3][strcspn(last[j % 3], "\r\n")] = '\0';
				ucl_array_append(lg, ucl_object_fromstring(last[j % 3]));
			}
			ucl_object_insert_key(o, lg, "log", 0, false);
		}
	}
	return (o);
}

/* The instances as they are, into the sdwan reply: each its name, fib,
 * mode, whether its process is there, and its CA's certificate. */
void
sdwan_proxy_json(struct work *w, ucl_object_t *top)
{
	ucl_object_t	*arr, *o;
	char		*ca;
	int		 i;

	const char	*jails[INSTANCES_MAX];
	int		 nj, k;

	pthread_mutex_lock(&lock);
	arr = ucl_object_typed_new(UCL_ARRAY);
	nj = 0;
	for (i = 0; i < ninstances; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(instances[i].name),
		    "name", 0, false);
		/* Where it runs: a jail's read beneath its root, and its
		 * ClamAV, where it scans, the jail's own. */
		if (instances[i].jail[0] != '\0') {
			ucl_object_insert_key(o, ucl_object_fromstring(
			    instances[i].jail), "jail", 0, false);
			for (k = 0; k < nj; k++)
				if (strcmp(jails[k], instances[i].jail) == 0)
					break;
			if (k == nj && instances[i].icap)
				jails[nj++] = wstrdup(w, instances[i].jail);
		}
		if (inst_in(w, instances[i].jail, NULL) != 0) {
			ucl_object_insert_key(o, ucl_object_fromint(
			    instances[i].fib), "fib", 0, false);
			ucl_object_insert_key(o, ucl_object_fromstring(
			    instances[i].mode), "mode", 0, false);
			ucl_object_insert_key(o, ucl_object_frombool(false),
			    "running", 0, false);
			ucl_object_insert_key(o, ucl_object_fromstring(IS_SEC(
			    instances[i].name) ? "security" : "sdwan"), "group", 0,
			    false);
			ucl_array_append(arr, o);
			continue;
		}
		ucl_object_insert_key(o, ucl_object_fromint(instances[i].fib),
		    "fib", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(instances[i].mode),
		    "mode", 0, false);
		ucl_object_insert_key(o, ucl_object_frombool(inst_pid(w,
		    instances[i].name) != 0), "running", 0, false);
		if (instances[i].icap)
			ucl_object_insert_key(o, ucl_object_frombool(icap_pid(w,
			    instances[i].name) != 0), "icap", 0, false);
		if ((ca = file_text(w, inst_path(w, instances[i].name, "crt"))) !=
		    NULL)
			ucl_object_insert_key(o, ucl_object_fromstring(ca), "ca", 0,
			    false);
		ucl_object_insert_key(o, ucl_object_fromstring(IS_SEC(
		    instances[i].name) ? "security" : "sdwan"), "group", 0,
		    false);
		ucl_array_append(arr, o);
		(void)inst_in(w, "", NULL);
	}
	pthread_mutex_unlock(&lock);
	ucl_object_insert_key(top, arr, "proxy", 0, false);
	security_specs(SEC_FILE, top, "security_proxy");
	if ((o = clamav_obj(w)) != NULL)
		ucl_object_insert_key(top, o, "clamav", 0, false);
	/* Each jail's own, where a filter there scans. */
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (k = 0; k < nj; k++) {
		if (inst_in(w, jails[k], NULL) == 0 && (o = clamav_obj(w)) !=
		    NULL) {
			ucl_object_insert_key(o, ucl_object_fromstring(jails[k]),
			    "jail", 0, false);
			ucl_array_append(arr, o);
		}
		(void)inst_in(w, "", NULL);
	}
	if (ucl_array_size(arr) > 0)
		ucl_object_insert_key(top, arr, "clamav_jails", 0, false);
	else
		ucl_object_unref(arr);
}

/*
 * One instance restarted, the job instance-restart's: Squid stopped and
 * started again from its file as it is, in its table, in its jail when
 * it runs in one; its c-icap goes on as it is.  One the admin stopped
 * is refused.  A dry run says the stop and the start's command, neither
 * done.
 */
int
squid_restart(struct work *w, const char *name, const char **errp)
{
	struct instance	 in;
	pid_t		 pid;
	int		 i, step, rc;
	bool		 found;

	pthread_mutex_lock(&lock);
	found = false;
	for (i = 0; i < ninstances; i++)
		if (strcmp(instances[i].name, name) == 0) {
			in = instances[i];
			found = true;
			break;
		}
	pthread_mutex_unlock(&lock);
	if (!found) {
		*errp = wfmt(w, "no Squid instance %s (the SD-WAN services' or "
		    "the Security section's)", name);
		return (-1);
	}
	if (in.stopped) {
		*errp = wfmt(w, "Squid %s is stopped by the admin: start it "
		    "(stopped false), not restart it", name);
		return (-1);
	}
	if (inst_in(w, in.jail, errp) != 0)
		return (-1);
	step = step_begin(w, STEP_DAEMON, "arcana-agent", "squid %s stopped%s%s",
	    name, in.jail[0] != '\0' ? " in the jail " : "", in.jail);
	if (!work_dry(w, step)) {
		pid = inst_pid(w, name);
		inst_stop(w, name);
		if (pid != 0)
			step_end(w, step, true, "pid %d", (int)pid);
		else
			step_end(w, step, true, "it was not running");
	}
	step = step_begin(w, STEP_DAEMON, "arcana-agent", "squid %s started",
	    name);
	if ((rc = inst_start(w, &in, false, errp)) != 0)
		step_end(w, step, false, "%s", *errp);
	else if (!work_dry(w, step))
		step_end(w, step, true, NULL);
	(void)inst_in(w, "", NULL);
	return (rc);
}
