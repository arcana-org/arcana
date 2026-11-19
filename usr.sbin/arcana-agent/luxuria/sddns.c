/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The resolvers of the SD-WAN services at this edge (MEF 138's DNF and
 * PDNS, the function policies of a zone, and where a DPF redirects):
 * the base system's unbound(8), local-unbound, one instance
 * per service run in the service's routing table (setfib), its
 * configuration rendered here from the console's form (sdconf.c: the
 * UNIs' provider addresses it listens on, the zones' domains and
 * answers), its pid file beside the agent's kept files.  Like the DHCP instances of sddhcp.c:
 * those named are started or started again, those not named any more
 * are stopped, and the list is kept for the next start.  An edge that
 * is a vnet jail has its own, run in it by jexec(8) (the jail's
 * local-unbound), its files beneath its root: the configuration, pid
 * file and response policy zones in its /var/run, its log in its
 * /var/log, the key and certificate of DNS over TLS in its /var/db,
 * written and read through no link out of it (scope.c).
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	DNS_FILE	"sdwan-dns.json"
#define	INSTANCES_MAX	64

struct instance {
	char	name[40];
	int	fib;
	bool	tls;		/* serves DNS over TLS */
	/* An edge that is a vnet jail: the instance runs in it, its files
	 * beneath its root, as resolved when it was applied. */
	char	jail[64];
	int	jid;
	char	jroot[256];
};

/* What w worked on before an instance's scope: put back after. */
struct was_scope {
	const char	*jail;
	int		 jid;
	const char	*jroot;
};

static void
scope_save(const struct work *w, struct was_scope *sv)
{

	sv->jail = w->jail;
	sv->jid = w->jid;
	sv->jroot = w->jroot;
}

static void
scope_back(struct work *w, const struct was_scope *sv)
{

	w->jail = sv->jail;
	w->jid = sv->jid;
	w->jroot = sv->jroot;
}

/* w works on the instance's jail, or on the host. */
static void
inst_scope(struct work *w, const struct instance *in)
{

	w->jail = in->jail[0] != '\0' ? in->jail : NULL;
	w->jid = in->jail[0] != '\0' ? in->jid : 0;
	w->jroot = in->jail[0] != '\0' ? in->jroot : NULL;
}

static pthread_mutex_t	lock = PTHREAD_MUTEX_INITIALIZER;
static struct instance	instances[INSTANCES_MAX];
static int		ninstances;

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

/* A string of the instance's, as a comment takes it: "" for none. */
static const char *
sstr(const ucl_object_t *o, const char *k)
{
	const ucl_object_t	*v;

	v = ucl_object_lookup(o, k);
	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : "");
}

/* Where an instance's files are: beside the agent's kept files; a
 * jail's as its programs see them: its log in /var/log, the key and
 * certificate of DNS over TLS in /var/db, which a start of the jail
 * does not empty, the rest in /var/run. */
static const char *
inst_path(struct work *w, const struct instance *in, const char *ext)
{
	char	buf[MAXPATHLEN];

	if (in->jail[0] != '\0')
		return (wfmt(w, "/var/%s/arcana-sdwan-dns-%s.%s", strcmp(ext,
		    "log") == 0 ? "log" : strncmp(ext, "tls.", 4) == 0 ? "db" :
		    "run", in->name, ext));
	sdwan_conf_path(wfmt(w, "sdwan-dns-%s.%s", in->name, ext), buf,
	    sizeof(buf));
	return (wstrdup(w, buf));
}

/* The pid in an instance's pid file, when that process is there; a
 * jail's as the jail's pgrep finds it. */
static pid_t
inst_pid(struct work *w, const struct instance *in)
{

	inst_scope(w, in);
	return (scope_pidfile(w, inst_path(w, in, "pid"), opts.unbound_bin));
}

/* An instance stopped: its process signalled and waited for, briefly. */
static void
inst_stop(struct work *w, const struct instance *in)
{

	inst_scope(w, in);
	scope_pid_stop(w, inst_path(w, in, "pid"), opts.unbound_bin, 1000);
}

/* A file of an instance's written: the host's beside the kept files
 * (name its name there), a jail's beneath its root, root's alone. */
static int
inst_write(struct work *w, const struct instance *in, const char *name,
    const char *path, const char *text, mode_t mode, const char **errp)
{

	if (in->jail[0] == '\0')
		return (sdwan_conf_write(name, text, errp));
	inst_scope(w, in);
	if (scope_replace(w, path, text, strlen(text), mode, NULL) != 0) {
		*errp = wfmt(w, "%s of the jail %s: %s", path, in->jail,
		    strerror(errno));
		return (-1);
	}
	return (0);
}

/* An instance started in its table, by setfib, on its file; a jail's in
 * the jail, by jexec(8). */
static int
inst_start(struct work *w, const struct instance *in, const char **errp)
{
	struct execres	 res;
	char		*argv[8];
	int		 n;

	inst_scope(w, in);
	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.setfib_bin;
	argv[n++] = (char *)(uintptr_t)"-F";
	argv[n++] = wfmt(w, "%d", in->fib);
	argv[n++] = (char *)(uintptr_t)opts.unbound_bin;
	argv[n++] = (char *)(uintptr_t)"-c";
	argv[n++] = (char *)(uintptr_t)inst_path(w, in, "conf");
	argv[n] = NULL;
	/* unbound puts itself in the background once it listens. */
	if (in->jail[0] != '\0')
		exec_set_limit(JAIL_READ_SEC);
	if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "local-unbound"));
		return (-1);
	}
	return (0);
}

/* An instance's response policy zones gone, all of them; a jail's
 * from its directory as opened beneath its root. */
static void
rpz_clear(struct work *w, const struct instance *in)
{
	DIR		*d;
	struct dirent	*de;
	const char	*path, *dir, *pre;
	size_t		 n;
	int		 dfd;

	path = inst_path(w, in, "rpz-");
	dir = strrchr(path, '/') != NULL ? wfmt(w, "%.*s", (int)(strrchr(path,
	    '/') - path), path) : ".";
	pre = strrchr(path, '/') != NULL ? strrchr(path, '/') + 1 : path;
	n = strlen(pre);
	inst_scope(w, in);
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

/*
 * The key and certificate an instance serves DNS over TLS with: made by
 * openssl(1), the certificate its own (self-signed, the UNIs' addresses
 * its names), kept beside its files and made again when the addresses
 * are others; the sdwan read tells the certificate for the clients to
 * trust.  False and why when it could not be.
 */
static bool
inst_tls(struct work *w, const struct instance *in, const ucl_object_t *spec,
    const char **errp)
{
	struct execres		 res;
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;
	const char		*key, *pem, *names, *san, *name = in->name;
	char			*argv[19], had[1024], *text;
	FILE			*fp;
	size_t			 n;
	int			 i, fd;

	key = inst_path(w, in, "tls.key");
	pem = inst_path(w, in, "tls.pem");
	names = inst_path(w, in, "tls.names");
	san = "subjectAltName=";
	it = NULL;
	while ((u = ucl_object_iterate(ucl_object_lookup(spec, "unis"), &it,
	    true)) != NULL)
		if (sstr(u, "address") != NULL)
			san = wfmt(w, "%s%sIP:%s", san, san[15] != '\0' ? "," : "",
			    sstr(u, "address"));
	if (san[15] == '\0') {
		*errp = "DNS over TLS: no address to serve it on";
		return (false);
	}
	had[0] = '\0';
	inst_scope(w, in);
	if (in->jail[0] != '\0') {
		/* The jail's files, read through no link out of it. */
		if ((text = scope_slurp(w, names, NULL)) != NULL)
			snprintf(had, sizeof(had), "%s", text);
		if (strcmp(had, san) == 0 && scope_slurp(w, key, NULL) != NULL &&
		    scope_slurp(w, pem, NULL) != NULL)
			return (true);
	} else {
		if ((fp = fopen(names, "r")) != NULL) {
			n = fread(had, 1, sizeof(had) - 1, fp);
			had[n] = '\0';
			fclose(fp);
		}
		if (strcmp(had, san) == 0 && access(key, R_OK) == 0 &&
		    access(pem, R_OK) == 0)
			return (true);
	}
	i = 0;
	argv[i++] = (char *)(uintptr_t)"/usr/bin/openssl";
	argv[i++] = (char *)(uintptr_t)"req";
	argv[i++] = (char *)(uintptr_t)"-x509";
	argv[i++] = (char *)(uintptr_t)"-newkey";
	argv[i++] = (char *)(uintptr_t)"ec";
	argv[i++] = (char *)(uintptr_t)"-pkeyopt";
	argv[i++] = (char *)(uintptr_t)"ec_paramgen_curve:P-256";
	argv[i++] = (char *)(uintptr_t)"-nodes";
	argv[i++] = (char *)(uintptr_t)"-days";
	argv[i++] = (char *)(uintptr_t)"3650";
	argv[i++] = (char *)(uintptr_t)"-subj";
	argv[i++] = wfmt(w, "/CN=Arcana SD-WAN %s resolver", name);
	argv[i++] = (char *)(uintptr_t)"-addext";
	argv[i++] = (char *)(uintptr_t)san;
	argv[i++] = (char *)(uintptr_t)"-keyout";
	argv[i++] = (char *)(uintptr_t)key;
	argv[i++] = (char *)(uintptr_t)"-out";
	argv[i++] = (char *)(uintptr_t)pem;
	argv[i] = NULL;
	/* A jail's made by the jail's own openssl, as the jail's root,
	 * where the jail has its files. */
	if (in->jail[0] != '\0') {
		if (scope_mkdirs(w, "/var/db") != 0) {
			*errp = wfmt(w, "/var/db of the jail %s: %s", in->jail,
			    strerror(errno));
			return (false);
		}
		(void)scope_unlink(w, key);
		exec_set_limit(JAIL_READ_SEC);
	} else
		(void)unlink(key);
	exec_set_secret(true);
	i = run_exec(w, scope_jexec(w, argv), &res);
	exec_set_secret(false);
	if (i != 0) {
		*errp = wtext(w, exec_error(w, &res, "openssl"));
		return (false);
	}
	if (in->jail[0] != '\0') {
		if ((fd = scope_open(w, key, O_RDONLY, 0)) != -1) {
			(void)fchmod(fd, 0600);
			close(fd);
		}
		if (scope_replace(w, names, san, strlen(san), 0600, NULL) != 0) {
			*errp = wfmt(w, "%s of the jail %s: %s", names, in->jail,
			    strerror(errno));
			return (false);
		}
		return (true);
	}
	(void)chmod(key, 0600);
	if ((fp = fopen(names, "w")) == NULL) {
		*errp = wfmt(w, "%s: %s", names, strerror(errno));
		return (false);
	}
	fputs(san, fp);
	fclose(fp);
	return (true);
}

/* The certificate an instance serves DNS over TLS with, in the work's
 * memory; NULL when it serves none. */
static char *
tls_cert(struct work *w, const struct instance *in)
{
	FILE	*fp;
	char	*text;
	size_t	 n;

	if (in->jail[0] != '\0') {
		inst_scope(w, in);
		if ((text = scope_slurp(w, inst_path(w, in, "tls.pem"), &n)) ==
		    NULL || n > 16383)
			return (NULL);
		return (strstr(text, "BEGIN CERTIFICATE") != NULL ? text : NULL);
	}
	if ((fp = fopen(inst_path(w, in, "tls.pem"), "r")) == NULL)
		return (NULL);
	text = wcalloc(w, 1, 16384);
	n = fread(text, 1, 16383, fp);
	fclose(fp);
	text[n] = '\0';
	return (strstr(text, "BEGIN CERTIFICATE") != NULL ? text : NULL);
}

/* An instance stopped and its files gone, its key for DNS over TLS
 * kept. */
static void
inst_down(struct work *w, const struct instance *in)
{

	inst_stop(w, in);
	if (in->jail[0] != '\0') {
		(void)scope_unlink(w, inst_path(w, in, "conf"));
		(void)scope_unlink(w, inst_path(w, in, "pid"));
	} else {
		(void)unlink(inst_path(w, in, "conf"));
		(void)unlink(inst_path(w, in, "pid"));
	}
	rpz_clear(w, in);
}

static int	 dns_apply(struct work *, const char *, const char **);

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
 * The instances applied: {"instances": [{"name", "fib", "host",
 * "spec"}, ...]}, the host's, or with "jail" those of an edge that is a
 * vnet jail, run in it; spec the service's form, rendered by
 * dns_conf_render() (host names the host in its comment), every one
 * before any is changed.
 * Each file, with the pid file and the run as root added (no chroot,
 * the kept files being where they are), is checked by
 * local-unbound-checkconf before it is made the instance's; a running
 * instance is stopped and started again on it; those of the same edge
 * not named any more are stopped, the other edges' left as they are.
 * Kept for the next start, a file per edge.
 */
int
do_sdwan_dns(struct work *w, const char *json, const char **errp)
{
	struct was_scope	 sv;
	int			 rc;

	scope_save(w, &sv);
	rc = dns_apply(w, json, errp);
	scope_back(w, &sv);
	return (rc);
}

static int
dns_apply(struct work *w, const char *json, const char **errp)
{
	ucl_object_t		*top;
	const ucl_object_t	*in, *v;
	ucl_object_iter_t	 it;
	struct instance		 ni[INSTANCES_MAX], keep[INSTANCES_MAX];
	struct execres		 res;
	struct dnspaths		 dp;
	ucl_object_t		*rpzs[INSTANCES_MAX];
	const ucl_object_t	*z;
	ucl_object_iter_t	 zit;
	char			*argv[3], *text, *confs[INSTANCES_MAX];
	char			 path[MAXPATHLEN];
	const char		*names[INSTANCES_MAX], *paths[INSTANCES_MAX];
	const ucl_object_t	*specs[INSTANCES_MAX];
	const char		*conf, *e, *jail, *file;
	int			 n, i, k, step, nkeep;
	bool			 was, ok;

	if ((top = parse(json)) == NULL || ucl_object_type(top) != UCL_OBJECT) {
		if (top != NULL)
			ucl_object_unref(top);
		*errp = "the instances are an object: instances, each a name, "
		    "a fib, a host and its spec";
		return (-1);
	}
	/* The jail's name, in w's memory: it is used after top goes. */
	if ((jail = sdwan_payload_jail(top, errp)) == NULL) {
		ucl_object_unref(top);
		return (-1);
	}
	jail = wstrdup(w, jail);
	if (jail[0] != '\0' && scope_enter(w, jail, errp) != 0) {
		ucl_object_unref(top);
		return (-1);
	}
	if (jail[0] != '\0' && strlen(w->jroot) >= sizeof(ni[0].jroot)) {
		ucl_object_unref(top);
		*errp = wfmt(w, "the jail %s is too deep a path", jail);
		return (-1);
	}
	n = 0;
	it = NULL;
	while ((in = ucl_object_iterate(ucl_object_lookup(top, "instances"),
	    &it, true)) != NULL) {
		v = ucl_object_lookup(in, "name");
		if (n == INSTANCES_MAX || v == NULL || ucl_object_type(v) !=
		    UCL_STRING || !name_ok(ucl_object_tostring(v)) ||
		    ucl_object_lookup(in, "fib") == NULL || ucl_object_toint(
		    ucl_object_lookup(in, "fib")) < 0 || ucl_object_toint(
		    ucl_object_lookup(in, "fib")) > 65535 || ucl_object_type(
		    ucl_object_lookup(in, "spec")) != UCL_OBJECT) {
			ucl_object_unref(top);
			*errp = wfmt(w, "an instance is a name of letters, digits, "
			    "_ and -, 32 at most, a fib, a host and its spec, %d "
			    "of them at most", INSTANCES_MAX);
			return (-1);
		}
		for (i = 0; i < n; i++)
			if (strcmp(ni[i].name, ucl_object_tostring(v)) == 0) {
				ucl_object_unref(top);
				*errp = wfmt(w, "instance %s is named twice",
				    ni[i].name);
				return (-1);
			}
		snprintf(ni[n].name, sizeof(ni[n].name), "%s",
		    ucl_object_tostring(v));
		ni[n].fib = (int)ucl_object_toint(ucl_object_lookup(in, "fib"));
		ni[n].tls = ucl_object_toboolean(ucl_object_lookup(
		    ucl_object_lookup(in, "spec"), "dot"));
		snprintf(ni[n].jail, sizeof(ni[n].jail), "%s", jail);
		ni[n].jid = jail[0] != '\0' ? w->jid : 0;
		snprintf(ni[n].jroot, sizeof(ni[n].jroot), "%s", jail[0] != '\0' ?
		    w->jroot : "");
		/* Its file names its own: the key and certificate of DNS
		 * over TLS, the response policy zones' files; a jail's as
		 * the jail sees them. */
		dp.tlskey = inst_path(w, &ni[n], "tls.key");
		dp.tlspem = inst_path(w, &ni[n], "tls.pem");
		dp.rpz_pre = inst_path(w, &ni[n], "rpz-");
		rpzs[n] = ucl_object_typed_new(UCL_OBJECT);
		e = NULL;
		if ((confs[n] = dns_conf_render(w, ucl_object_lookup(in,
		    "spec"), sstr(in, "host"), &dp, rpzs[n], &e)) == NULL) {
			for (i = 0; i <= n; i++)
				ucl_object_unref(rpzs[i]);
			ucl_object_unref(top);
			*errp = wfmt(w, "%s: %s", ni[n].name, e);
			return (-1);
		}
		n++;
	}
	pthread_mutex_lock(&lock);
	/* Those of this edge that go, first; the other edges' are kept. */
	nkeep = 0;
	for (i = 0; i < ninstances; i++) {
		if (strcmp(instances[i].jail, jail) != 0) {
			keep[nkeep++] = instances[i];
			continue;
		}
		for (k = 0; k < n; k++)
			if (strcmp(ni[k].name, instances[i].name) == 0)
				break;
		if (k == n) {
			step = step_begin(w, STEP_DAEMON, "arcana-agent",
			    "unbound %s%s%s stopped", instances[i].name, jail[0] !=
			    '\0' ? " of " : "", jail);
			inst_down(w, &instances[i]);
			step_end(w, step, true, NULL);
		}
	}
	ok = true;
	it = NULL;
	/* A jail's directories, made where they are none, beneath its
	 * root. */
	if (jail[0] != '\0' && (scope_mkdirs(w, "/var/run") != 0 ||
	    scope_mkdirs(w, "/var/log") != 0)) {
		*errp = wfmt(w, "the jail %s's /var/run and /var/log: %s", jail,
		    strerror(errno));
		ok = false;
	}
	for (k = 0; ok && k < n; k++) {
		in = ucl_object_iterate(ucl_object_lookup(top, "instances"), &it,
		    true);
		conf = confs[k];
		was = inst_pid(w, &ni[k]) != 0;
		step = step_begin(w, STEP_DAEMON, "arcana-agent",
		    "unbound %s in fib %d%s%s: %s", ni[k].name, ni[k].fib,
		    jail[0] != '\0' ? " of " : "", jail, was ? "started again" :
		    "started");
		/* Its response policy zones, files of their own; its key
		 * for DNS over TLS where it serves it. */
		e = NULL;
		rpz_clear(w, &ni[k]);
		zit = NULL;
		while ((z = ucl_object_iterate(rpzs[k], &zit, true)) != NULL)
			if (inst_write(w, &ni[k], wfmt(w, "sdwan-dns-%s.rpz-%s",
			    ni[k].name, ucl_object_key(z)), inst_path(w, &ni[k],
			    wfmt(w, "rpz-%s", ucl_object_key(z))),
			    ucl_object_tostring(z), 0600, &e) != 0)
				break;
		if (e == NULL && ni[k].tls)
			(void)inst_tls(w, &ni[k], ucl_object_lookup(in, "spec"),
			    &e);
		if (e != NULL) {
			step_end(w, step, false, "%s", e);
			*errp = wfmt(w, "%s: %s", ni[k].name, e);
			ok = false;
			break;
		}
		/* The agent's own clause after the console's: the pid file,
		 * no chroot, the user it runs as, and its log, which the
		 * agent reads for what it blocked (sdblock.c). */
		text = wfmt(w, "%s%sserver:\n\tpidfile: \"%s\"\n\tchroot: \"\"\n\t"
		    "username: \"\"\n\tlogfile: \"%s\"\n\tuse-syslog: no\n", conf,
		    conf[0] != '\0' && conf[strlen(conf) - 1] != '\n' ? "\n" : "",
		    inst_path(w, &ni[k], "pid"), inst_path(w, &ni[k], "log"));
		if (inst_write(w, &ni[k], wfmt(w, "sdwan-dns-%s.conf",
		    ni[k].name), inst_path(w, &ni[k], "conf"), text, 0600,
		    &e) != 0) {
			step_end(w, step, false, "%s", e);
			*errp = wfmt(w, "%s: %s", ni[k].name, e);
			ok = false;
			break;
		}
		/* Checked first, by the unbound that runs it: what it
		 * refuses is not run. */
		inst_scope(w, &ni[k]);
		argv[0] = wfmt(w, "%s-checkconf", opts.unbound_bin);
		argv[1] = (char *)(uintptr_t)inst_path(w, &ni[k], "conf");
		argv[2] = NULL;
		if (jail[0] != '\0')
			exec_set_limit(JAIL_READ_SEC);
		if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
			step_end(w, step, false, "unbound does not take it");
			*errp = wfmt(w, "%s: unbound does not take it: %s",
			    ni[k].name, res.errlen > 0 ? res.err : res.out !=
			    NULL ? res.out : "no reason given");
			ok = false;
			break;
		}
		if (was)
			inst_stop(w, &ni[k]);
		if (inst_start(w, &ni[k], &e) != 0) {
			step_end(w, step, false, "%s", e);
			*errp = e;
			ok = false;
			break;
		}
		step_end(w, step, true, NULL);
	}
	if (ok && nkeep + n > INSTANCES_MAX) {
		*errp = wfmt(w, "%d instances at most, all edges counted",
		    INSTANCES_MAX);
		ok = false;
	}
	if (ok) {
		memcpy(instances, keep, sizeof(*keep) * (size_t)nkeep);
		memcpy(instances + nkeep, ni, sizeof(*ni) * (size_t)n);
		ninstances = nkeep + n;
		/* Their logs read for what they blocked, this edge's; a
		 * jail's beneath its root. */
		it = NULL;
		for (k = 0; k < n; k++) {
			in = ucl_object_iterate(ucl_object_lookup(top,
			    "instances"), &it, true);
			names[k] = ni[k].name;
			paths[k] = inst_path(w, &ni[k], "log");
			specs[k] = ucl_object_lookup(in, "spec");
		}
		sdblock_watch_jail(SDB_UNBOUND, jail, jail[0] != '\0' ?
		    w->jroot : NULL, n, names, paths, specs);
	}
	pthread_mutex_unlock(&lock);
	for (k = 0; k < n; k++)
		ucl_object_unref(rpzs[k]);
	ucl_object_unref(top);
	if (!ok)
		return (-1);
	/* Kept, a file per edge; a jail's with no instance goes, so that a
	 * start makes none for a jail that has none now. */
	file = jail[0] != '\0' ? wfmt(w, "sdwan-dns@%s.json", jail) : DNS_FILE;
	if (jail[0] != '\0' && n == 0) {
		if (unlink(sdwan_conf_path(file, path, sizeof(path))) == -1 &&
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

/* At the start: the instances kept, the host's and each jail's,
 * started again. */
void
sdwan_dns_start(void)
{
	struct work	 w;
	struct dirent	*de;
	DIR		*d;
	char		*json, dir[MAXPATHLEN], *slash;
	const char	*e;
	size_t		 n;

	work_init(&w);
	if ((json = sdwan_kept_read(DNS_FILE)) != NULL) {
		e = NULL;
		if (do_sdwan_dns(&w, json, &e) != 0)
			logmsg(LOG_WARNING, "sdwan dns: %s", e);
		free(json);
	}
	sdwan_conf_path(DNS_FILE, dir, sizeof(dir));
	if ((slash = strrchr(dir, '/')) == NULL)
		snprintf(dir, sizeof(dir), ".");
	else
		*slash = '\0';
	if ((d = opendir(dir)) != NULL) {
		while ((de = readdir(d)) != NULL) {
			n = strlen(de->d_name);
			if (strncmp(de->d_name, "sdwan-dns@", 10) != 0 || n <= 15 ||
			    strcmp(de->d_name + n - 5, ".json") != 0)
				continue;
			if ((json = sdwan_kept_read(de->d_name)) == NULL)
				continue;
			e = NULL;
			if (do_sdwan_dns(&w, json, &e) != 0)
				logmsg(LOG_WARNING, "sdwan dns: %s: %s", de->d_name,
				    e);
			free(json);
		}
		closedir(d);
	}
	work_free(&w);
}

/* The instances as they are, into the sdwan reply: each its name, fib,
 * the jail it runs in, whether its process is there, and the
 * certificate of its DNS over TLS where it serves it. */
void
sdwan_dns_json(struct work *w, ucl_object_t *top)
{
	struct was_scope sv;
	struct instance	*iv;
	ucl_object_t	*arr, *o;
	char		*cert;
	int		 i, niv;

	/* Copied, and a jail's asked without the lock: its pgrep may take
	 * a while, and an apply waits on the lock. */
	iv = wcalloc(w, INSTANCES_MAX, sizeof(*iv));
	pthread_mutex_lock(&lock);
	niv = ninstances;
	memcpy(iv, instances, sizeof(*iv) * (size_t)niv);
	pthread_mutex_unlock(&lock);
	scope_save(w, &sv);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < niv; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(iv[i].name),
		    "name", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(iv[i].fib),
		    "fib", 0, false);
		if (iv[i].jail[0] != '\0')
			ucl_object_insert_key(o, ucl_object_fromstring(
			    iv[i].jail), "jail", 0, false);
		ucl_object_insert_key(o, ucl_object_frombool(inst_pid(w,
		    &iv[i]) != 0), "running", 0, false);
		if (iv[i].tls && (cert = tls_cert(w, &iv[i])) != NULL)
			ucl_object_insert_key(o, ucl_object_fromstring(cert),
			    "tls_cert", 0, false);
		ucl_array_append(arr, o);
	}
	scope_back(w, &sv);
	ucl_object_insert_key(top, arr, "dns", 0, false);
}
