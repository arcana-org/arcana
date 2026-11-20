/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The DHCP servers of the SD-WAN services at this edge (MEF 70.2 §11.4,
 * §11.5): FreeBSD's base has no DHCP server, so dnsmasq from packages,
 * one instance per service run in the service's routing table
 * (setfib), its configuration rendered here from the console's form
 * (sdconf.c), its pid and lease files beside the agent's kept files.  Like the BIRD instances
 * of sdbird.c: those named are started or started again, those not
 * named any more are stopped, and the list is kept for the next start.
 * An edge that is a vnet jail has its own, run in it by jexec(8) (the
 * jail's dnsmasq), its files beneath its root: the configuration and
 * pid file in its /var/run, the leases in its /var/db, written and read
 * through no link out of it (scope.c).
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	DHCP_FILE	"sdwan-dhcp.json"
#define	INSTANCES_MAX	64

struct instance {
	char	name[40];
	int	fib;
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
/* An apply at a time: the console's, a start's, a jail followed's. */
static pthread_mutex_t	apply_lock = PTHREAD_MUTEX_INITIALIZER;
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
 * jail's as its programs see them, the leases in its /var/db, which a
 * start of the jail does not empty. */
static const char *
inst_path(struct work *w, const struct instance *in, const char *ext)
{
	char	buf[MAXPATHLEN];

	if (in->jail[0] != '\0')
		return (wfmt(w, "/var/%s/arcana-sdwan-dhcp-%s.%s", strcmp(ext,
		    "leases") == 0 ? "db" : "run", in->name, ext));
	sdwan_conf_path(wfmt(w, "sdwan-dhcp-%s.%s", in->name, ext), buf,
	    sizeof(buf));
	return (wstrdup(w, buf));
}

/* The pid in an instance's pid file, when that process is there; a
 * jail's as the jail's pgrep finds it. */
static pid_t
inst_pid(struct work *w, const struct instance *in)
{

	inst_scope(w, in);
	return (scope_pidfile(w, inst_path(w, in, "pid"), opts.dnsmasq_bin));
}

/* An instance stopped: its process signalled and waited for, briefly. */
static void
inst_stop(struct work *w, const struct instance *in)
{

	inst_scope(w, in);
	scope_pid_stop(w, inst_path(w, in, "pid"), opts.dnsmasq_bin, 1000);
}

/* An instance started in its table, by setfib, on its file; a jail's in
 * the jail, by jexec(8). */
static int
inst_start(struct work *w, const struct instance *in, const char **errp)
{
	struct execres	 res;
	char		*argv[10];
	int		 n;

	inst_scope(w, in);
	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.setfib_bin;
	argv[n++] = (char *)(uintptr_t)"-F";
	argv[n++] = wfmt(w, "%d", in->fib);
	argv[n++] = (char *)(uintptr_t)opts.dnsmasq_bin;
	argv[n++] = (char *)(uintptr_t)"-C";
	argv[n++] = (char *)(uintptr_t)inst_path(w, in, "conf");
	argv[n++] = (char *)(uintptr_t)"-x";
	argv[n++] = (char *)(uintptr_t)inst_path(w, in, "pid");
	argv[n] = NULL;
	/* dnsmasq puts itself in the background at once. */
	if (in->jail[0] != '\0')
		exec_set_limit(JAIL_READ_SEC);
	if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "dnsmasq"));
		return (-1);
	}
	return (0);
}

/* An instance stopped, its files gone but the leases, kept for next time. */
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
}

/* An instance's file written: the host's beside the kept files, a
 * jail's beneath its root, root's alone either way. */
static int
inst_write(struct work *w, const struct instance *in, const char *text,
    const char **errp)
{
	const char	*path;

	if (in->jail[0] == '\0')
		return (sdwan_conf_write(wfmt(w, "sdwan-dhcp-%s.conf", in->name),
		    text, errp));
	inst_scope(w, in);
	path = inst_path(w, in, "conf");
	if (scope_mkdirs(w, "/var/run") != 0 || scope_mkdirs(w, "/var/db") !=
	    0 || scope_replace(w, path, text, strlen(text), 0600, NULL) != 0) {
		*errp = wfmt(w, "%s of the jail %s: %s", path, in->jail,
		    strerror(errno));
		return (-1);
	}
	return (0);
}

static int	 dhcp_apply(struct work *, const char *, const char **);

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
 * dhcp_conf_render() (host names the host in its comment), every one
 * before any is changed.  Each file, with the pid and lease files
 * added, is checked by dnsmasq --test before it is made the
 * instance's; a running instance is stopped and started again on it;
 * those of the same edge not named any more are stopped, the other
 * edges' left as they are.  Kept for the next start, a file per edge.
 */
int
do_sdwan_dhcp(struct work *w, const char *json, const char **errp)
{
	struct was_scope	 sv;
	int			 rc;

	pthread_mutex_lock(&apply_lock);
	scope_save(w, &sv);
	rc = dhcp_apply(w, json, errp);
	scope_back(w, &sv);
	pthread_mutex_unlock(&apply_lock);
	return (rc);
}

/*
 * The jail edges followed (ira/jailwatch.c): one made (or running at
 * the start) that keeps a list (sdwan-dhcp@JAIL.json), and whose
 * instances do not run in it (another jid, or none applied), is
 * wanted, once the interfaces its UNIs name are in it (none named: one
 * up besides the loopback); then its kept list is applied again, its
 * files made again beneath its root.
 */
static int
dhcp_wants(const char *jail, int jid, char (*ifs)[JAIL_IFNAMSIZ], int max)
{
	int	i;

	pthread_mutex_lock(&lock);
	for (i = 0; i < ninstances; i++)
		if (strcmp(instances[i].jail, jail) == 0 &&
		    instances[i].jid == jid)
			break;
	pthread_mutex_unlock(&lock);
	return (i < ninstances ? -1 : sdwan_kept_ifs("dhcp", jail, ifs, max));
}

static int
dhcp_follow(struct work *w, const char *jail, const char **errp)
{
	struct was_scope	 sv;
	const char		*e;
	char			*json;
	int			 rc;

	pthread_mutex_lock(&apply_lock);
	rc = 0;
	if ((json = sdwan_kept_read(wfmt(w, "sdwan-dhcp@%s.json", jail))) !=
	    NULL) {
		e = NULL;
		scope_save(w, &sv);
		rc = dhcp_apply(w, json, &e);
		scope_back(w, &sv);
		free(json);
		if (rc != 0)
			*errp = wfmt(w, "sdwan dhcp: %s", e);
	}
	pthread_mutex_unlock(&apply_lock);
	return (rc);
}

/* A jail edge removed: its instances run in none, until it is made
 * again (whatever jid it is given then). */
static void
dhcp_gone(const char *jail, int jid)
{
	int	i;

	pthread_mutex_lock(&lock);
	for (i = 0; i < ninstances; i++)
		if (instances[i].jid == jid && strcmp(instances[i].jail, jail) ==
		    0)
			instances[i].jid = 0;
	pthread_mutex_unlock(&lock);
}

static const struct jail_follower dhcp_follower = {
	"sdwan dhcp (dnsmasq)", dhcp_wants, dhcp_follow, dhcp_gone
};

static int
dhcp_apply(struct work *w, const char *json, const char **errp)
{
	ucl_object_t		*top;
	const ucl_object_t	*in, *v;
	ucl_object_iter_t	 it;
	struct instance		 ni[INSTANCES_MAX], keep[INSTANCES_MAX];
	struct execres		 res;
	char			*argv[5], *text, *confs[INSTANCES_MAX];
	char			 path[MAXPATHLEN];
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
		snprintf(ni[n].jail, sizeof(ni[n].jail), "%s", jail);
		ni[n].jid = jail[0] != '\0' ? w->jid : 0;
		snprintf(ni[n].jroot, sizeof(ni[n].jroot), "%s", jail[0] != '\0' ?
		    w->jroot : "");
		e = NULL;
		if ((confs[n] = dhcp_conf_render(w, ucl_object_lookup(in,
		    "spec"), sstr(in, "host"), &e)) == NULL) {
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
			    "dnsmasq %s%s%s stopped", instances[i].name, jail[0] !=
			    '\0' ? " of " : "", jail);
			inst_down(w, &instances[i]);
			step_end(w, step, true, NULL);
		}
	}
	ok = true;
	for (k = 0; k < n; k++) {
		conf = confs[k];
		was = inst_pid(w, &ni[k]) != 0;
		step = step_begin(w, STEP_DAEMON, "arcana-agent",
		    "dnsmasq %s in fib %d%s%s: %s", ni[k].name, ni[k].fib,
		    jail[0] != '\0' ? " of " : "", jail, was ? "started again" :
		    "started");
		/* The agent's own lines after the console's: where the pid
		 * and the leases go. */
		text = wfmt(w, "%s%spid-file=%s\ndhcp-leasefile=%s\n", conf,
		    conf[0] != '\0' && conf[strlen(conf) - 1] != '\n' ? "\n" :
		    "", inst_path(w, &ni[k], "pid"), inst_path(w, &ni[k],
		    "leases"));
		e = NULL;
		if (inst_write(w, &ni[k], text, &e) != 0) {
			step_end(w, step, false, "%s", e);
			*errp = wfmt(w, "%s: %s", ni[k].name, e);
			ok = false;
			break;
		}
		/* Checked first, by the dnsmasq that runs it: what it
		 * refuses is not run. */
		inst_scope(w, &ni[k]);
		argv[0] = (char *)(uintptr_t)opts.dnsmasq_bin;
		argv[1] = (char *)(uintptr_t)"--test";
		argv[2] = (char *)(uintptr_t)"-C";
		argv[3] = (char *)(uintptr_t)inst_path(w, &ni[k], "conf");
		argv[4] = NULL;
		if (jail[0] != '\0')
			exec_set_limit(JAIL_READ_SEC);
		if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
			step_end(w, step, false, "dnsmasq does not take it");
			*errp = wfmt(w, "%s: dnsmasq does not take it: %s",
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
	if (ok && nkeep + n <= INSTANCES_MAX) {
		memcpy(instances, keep, sizeof(*keep) * (size_t)nkeep);
		memcpy(instances + nkeep, ni, sizeof(*ni) * (size_t)n);
		ninstances = nkeep + n;
	} else if (ok) {
		*errp = wfmt(w, "%d instances at most, all edges counted",
		    INSTANCES_MAX);
		ok = false;
	}
	pthread_mutex_unlock(&lock);
	ucl_object_unref(top);
	if (!ok)
		return (-1);
	/* Kept, a file per edge; a jail's with no instance goes, so that a
	 * start makes none for a jail that has none now. */
	file = jail[0] != '\0' ? wfmt(w, "sdwan-dhcp@%s.json", jail) : DHCP_FILE;
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
sdwan_dhcp_start(void)
{
	struct work	 w;
	struct dirent	*de;
	DIR		*d;
	char		*json, dir[MAXPATHLEN], *slash;
	const char	*e;
	size_t		 n;

	/* The jails followed from now: jailwatch.c starts after. */
	jail_follow(&dhcp_follower);
	work_init(&w);
	if ((json = sdwan_kept_read(DHCP_FILE)) != NULL) {
		e = NULL;
		if (do_sdwan_dhcp(&w, json, &e) != 0)
			logmsg(LOG_WARNING, "sdwan dhcp: %s", e);
		free(json);
	}
	sdwan_conf_path(DHCP_FILE, dir, sizeof(dir));
	if ((slash = strrchr(dir, '/')) == NULL)
		snprintf(dir, sizeof(dir), ".");
	else
		*slash = '\0';
	if ((d = opendir(dir)) != NULL) {
		while ((de = readdir(d)) != NULL) {
			n = strlen(de->d_name);
			if (strncmp(de->d_name, "sdwan-dhcp@", 11) != 0 || n <= 16 ||
			    strcmp(de->d_name + n - 5, ".json") != 0)
				continue;
			if ((json = sdwan_kept_read(de->d_name)) == NULL)
				continue;
			e = NULL;
			if (do_sdwan_dhcp(&w, json, &e) != 0)
				logmsg(LOG_WARNING, "sdwan dhcp: %s: %s", de->d_name,
				    e);
			free(json);
		}
		closedir(d);
	}
	work_free(&w);
}

/*
 * The instances as they are, into the sdwan reply: each its name, fib,
 * the jail it runs in, whether its process is there, and the leases it
 * gave, as dnsmasq keeps them (expires, the client's hardware address
 * or IAID, the address, the host name).
 */
void
sdwan_dhcp_json(struct work *w, ucl_object_t *top)
{
	struct was_scope sv;
	struct instance	*iv;
	ucl_object_t	*arr, *o, *ls, *l;
	char		*text, *line, *word, *rest;
	size_t		 len;
	int		 i, k, niv;

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
		ls = ucl_object_typed_new(UCL_ARRAY);
		inst_scope(w, &iv[i]);
		if ((text = scope_slurp(w, inst_path(w, &iv[i], "leases"),
		    &len)) != NULL) {
			while ((line = strsep(&text, "\n")) != NULL) {
				/* expires id address name client-id */
				if (line[0] == '\0' || strncmp(line, "duid ", 5)
				    == 0)
					continue;
				l = ucl_object_typed_new(UCL_OBJECT);
				rest = line;
				for (k = 0; k < 4 && (word = strsep(&rest, " "))
				    != NULL; k++)
					ucl_object_insert_key(l, k == 0 ?
					    ucl_object_fromint(strtoll(word, NULL,
					    10)) : ucl_object_fromstring(word), k ==
					    0 ? "expires" : k == 1 ? "id" : k == 2 ?
					    "address" : "name", 0, false);
				ucl_array_append(ls, l);
			}
		}
		ucl_object_insert_key(o, ls, "leases", 0, false);
		ucl_array_append(arr, o);
	}
	scope_back(w, &sv);
	ucl_object_insert_key(top, arr, "dhcp", 0, false);
}
