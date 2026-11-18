/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * SD-WAN routing at the UNIs (MEF 70.2 §11.6): a BIRD instance of each
 * service on the edge, its configuration rendered here from the
 * console's form (sdconf.c), run in
 * the service's routing table with a control socket of its own, kept
 * beside the probes and the rules and started again with the agent.
 * It talks BGP or OSPF with the subscriber at the UNI, and iBGP with
 * the other edges by the tunnels, so what one UNI learns reaches them
 * all.  Its faults (bird-instance and bgp-neighbor by "bird", bfd by
 * "bfd") are held to what it watches (fault_reconcile()): the sessions
 * at its first look and whenever the instances change, the instances
 * and their neighbours whenever either changes; birdwatch.c's of the
 * host's BIRD ("host:", "jail:") are not its.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include <dirent.h>
#include <errno.h>

#include "agent.h"

#define	BIRD_FILE	"sdwan-bird.json"
#define	INSTANCES_MAX	64

struct instance {
	char	name[40];
	int	fib;
	/* An edge that is a vnet jail: the instance runs in it (jexec), its
	 * files beneath its root, as resolved when it was applied. */
	char	jail[64];
	int	jid;
	char	jroot[256];
};

/* w works on the instance's jail, or on the host. */
static void
inst_scope(struct work *w, const struct instance *in)
{

	w->jail = in->jail[0] != '\0' ? in->jail : NULL;
	w->jid = in->jail[0] != '\0' ? in->jid : 0;
	w->jroot = in->jail[0] != '\0' ? in->jroot : NULL;
}

/* A BFD session as an instance lists it: the far address, where. */
struct bfd {
	char	instance[40];
	char	address[64];
	char	iface[32];
	char	since[32];
	int	state;		/* PROBE_UP, PROBE_DOWN, else PROBE_UNKNOWN */
};

#define	BFD_MAX		512
#define	BFD_EVERY_S	1

static bool	 protocols_watch(struct work *, const struct instance *,
		    char (*)[160], int *);
static int	 inst_start(struct work *, const struct instance *,
		    const char **);

/*
 * What was up once: a BFD session or a BGP neighbour starts down, and
 * only its going down after being up is a fault.
 */
#define	SEEN_MAX	512
static char		seen_up[SEEN_MAX][160];
static int		nseen;

static bool
was_up(const char *key, bool now_up)
{
	int	i;

	for (i = 0; i < nseen; i++)
		if (strcmp(seen_up[i], key) == 0)
			return (true);
	if (now_up && nseen < SEEN_MAX)
		snprintf(seen_up[nseen++], sizeof(seen_up[0]), "%s", key);
	return (false);
}

static pthread_mutex_t	lock = PTHREAD_MUTEX_INITIALIZER;
static struct instance	instances[INSTANCES_MAX];
static int		ninstances;
static struct bfd	bfds[BFD_MAX];
static int		nbfds;

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

/* Where an instance's files are: beside the agent's kept files; a
 * jail's in its /var/run, as its programs see them. */
static const char *
inst_path(struct work *w, const struct instance *in, const char *ext)
{
	char	buf[MAXPATHLEN];

	if (in->jail[0] != '\0')
		return (wfmt(w, "/var/run/arcana-sdwan-bird-%s.%s", in->name, ext));
	sdwan_conf_path(wfmt(w, "sdwan-bird-%s.%s", in->name, ext), buf,
	    sizeof(buf));
	return (wstrdup(w, buf));
}

/*
 * birdc on an instance's socket; 0 and its output when it answered.
 * Within JAIL_READ_SEC, or killed and res->timedout: a jail edge's root
 * may put a birdc there that never ends, and the watch, the reads and
 * the steering's BFD would wait on it.
 */
static int
inst_birdc(struct work *w, const struct instance *in, const char *a,
    const char *b, struct execres *res)
{
	char	*argv[7];
	int	 n;

	inst_scope(w, in);
	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.birdc_bin;
	argv[n++] = (char *)(uintptr_t)"-s";
	argv[n++] = (char *)(uintptr_t)inst_path(w, in, "ctl");
	argv[n++] = (char *)(uintptr_t)a;
	if (b != NULL)
		argv[n++] = (char *)(uintptr_t)b;
	argv[n] = NULL;
	exec_set_limit(JAIL_READ_SEC);
	return (run_exec(w, argv, res));
}

static bool
inst_alive(struct work *w, const struct instance *in)
{
	struct execres	res;

	/* Its socket there, and answering. */
	if (in->jail[0] == '\0' && access(inst_path(w, in, "ctl"), F_OK) != 0)
		return (false);
	return (inst_birdc(w, in, "show", "status", &res) == 0 && res.out !=
	    NULL && strstr(res.out, "BIRD") != NULL && strstr(res.out,
	    "Shutdown") == NULL);
}

/* An instance started in its table, or told to read its file again. */
static int
inst_up(struct work *w, const struct instance *in, bool was,
    const char **errp)
{
	struct execres	 res;

	/* One that answers on its socket is told again, whether this agent
	 * started it or one before it did. */
	(void)was;
	if (inst_alive(w, in)) {
		/* "Reconfigured", or "Reconfiguration in progress" (or queued)
		 * while its sessions settle: taken, either way. */
		if (inst_birdc(w, in, "configure", NULL, &res) != 0 ||
		    res.out == NULL || strstr(res.out, "Reconfigur") == NULL) {
			*errp = wfmt(w, "%s: bird did not take its "
			    "configuration: %s", in->name, res.out != NULL ?
			    res.out : "no answer");
			return (-1);
		}
		return (0);
	}
	return (inst_start(w, in, errp));
}

/* An instance started in its table, with a socket and pid file of its
 * own; a jail's in the jail, by jexec(8). */
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
	argv[n++] = (char *)(uintptr_t)opts.bird_bin;
	argv[n++] = (char *)(uintptr_t)"-c";
	argv[n++] = (char *)(uintptr_t)inst_path(w, in, "conf");
	argv[n++] = (char *)(uintptr_t)"-s";
	argv[n++] = (char *)(uintptr_t)inst_path(w, in, "ctl");
	argv[n++] = (char *)(uintptr_t)"-P";
	argv[n++] = (char *)(uintptr_t)inst_path(w, in, "pid");
	argv[n] = NULL;
	/* bird puts itself in the background at once: the lock the
	 * instances are applied under is not held for longer. */
	exec_set_limit(JAIL_READ_SEC);
	if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "bird"));
		return (-1);
	}
	return (0);
}

/* An instance stopped, its files gone. */
static void
inst_down(struct work *w, const struct instance *in)
{
	struct execres	res;

	(void)inst_birdc(w, in, "down", NULL, &res);
	if (in->jail[0] != '\0') {
		(void)scope_unlink(w, inst_path(w, in, "conf"));
		(void)scope_unlink(w, inst_path(w, in, "pid"));
	} else {
		(void)unlink(inst_path(w, in, "conf"));
		(void)unlink(inst_path(w, in, "pid"));
	}
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
 * The instances applied: {"instances": [{"name", "fib", "host",
 * "spec"}, ...]}, the host's, or with "jail" those of an edge that is a
 * vnet jail, run in it; spec the instance's form, rendered by
 * bird_conf_render() (host names the host in its comment), every one
 * before any is changed.  Each file is parsed by bird before it is made
 * the instance's;
 * those of the same edge not named any more are stopped, the other
 * edges' left as they are.  Kept for the next start, a file per edge.
 */
int
do_sdwan_bird(struct work *w, const char *json, const char **errp)
{
	ucl_object_t		*top;
	const ucl_object_t	*in, *v;
	ucl_object_iter_t	 it;
	struct instance		 ni[INSTANCES_MAX], keep[INSTANCES_MAX];
	struct bmp_station	 mons[INSTANCES_MAX];
	const ucl_object_t	*rm;
	struct execres		 res;
	char			*argv[5], path[MAXPATHLEN], *confs[INSTANCES_MAX];
	const char		*conf, *e, *jail, *file, *host;
	int			 n, i, k, step, nkeep, nm;
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
	nm = 0;
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
		host = ucl_object_type(ucl_object_lookup(in, "host")) ==
		    UCL_STRING ? ucl_object_tostring(ucl_object_lookup(in,
		    "host")) : "";
		e = NULL;
		if ((confs[n] = bird_conf_render(w, ucl_object_lookup(in,
		    "spec"), host, &e)) == NULL) {
			ucl_object_unref(top);
			*errp = wfmt(w, "%s: %s", ni[n].name, e);
			return (-1);
		}
		/* Its BMP station, in the FIB it runs in: its table, the one
		 * its file names the port of. */
		if ((rm = ucl_object_lookup(ucl_object_lookup(in, "spec"),
		    "route_monitoring")) != NULL) {
			if (ucl_object_toint(ucl_object_lookup(ucl_object_lookup(
			    in, "spec"), "table")) != ni[n].fib) {
				ucl_object_unref(top);
				*errp = wfmt(w, "%s: route monitoring needs the "
				    "form's table to be the instance's fib, %d",
				    ni[n].name, ni[n].fib);
				return (-1);
			}
			memset(&mons[nm], 0, sizeof(mons[nm]));
			snprintf(mons[nm].name, sizeof(mons[nm].name), "%s",
			    ni[n].name);
			mons[nm].jid = ni[n].jid;
			mons[nm].fib = ni[n].fib;
			mons[nm].kept = ucl_object_lookup(rm, "kept") != NULL ?
			    (int)ucl_object_toint(ucl_object_lookup(rm, "kept")) :
			    64;
			nm++;
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
			    "bird %s%s%s stopped", instances[i].name, jail[0] !=
			    '\0' ? " of " : "", jail);
			inst_down(w, &instances[i]);
			fault_clear("bird-instance", instances[i].name, "the BIRD "
			    "instance %s is stopped", instances[i].name);
			step_end(w, step, true, NULL);
		}
	}
	ok = true;
	for (k = 0; k < n; k++) {
		conf = confs[k];
		was = false;
		for (i = 0; i < ninstances; i++)
			if (strcmp(ni[k].name, instances[i].name) == 0)
				was = true;
		step = step_begin(w, STEP_DAEMON, "arcana-agent", "bird "
		    "%s in fib %d%s%s: %s", ni[k].name, ni[k].fib, jail[0] != '\0' ?
		    " of " : "", jail, was ? "configured again" : "started");
		e = NULL;
		inst_scope(w, &ni[k]);
		if (jail[0] != '\0' ? scope_replace(w, inst_path(w, &ni[k],
		    "conf"), conf, strlen(conf), 0600, NULL) != 0 && (e =
		    wfmt(w, "%s: %s", inst_path(w, &ni[k], "conf"), strerror(
		    errno))) != NULL : sdwan_conf_write(wfmt(w, "sdwan-bird-%s.conf",
		    ni[k].name), conf, &e) != 0) {
			step_end(w, step, false, "%s", e);
			*errp = wfmt(w, "%s: %s", ni[k].name, e);
			ok = false;
			break;
		}
		/* Parsed first: what bird refuses is not run. */
		argv[0] = (char *)(uintptr_t)opts.bird_bin;
		argv[1] = (char *)(uintptr_t)"-p";
		argv[2] = (char *)(uintptr_t)"-c";
		argv[3] = (char *)(uintptr_t)inst_path(w, &ni[k], "conf");
		argv[4] = NULL;
		exec_set_limit(JAIL_READ_SEC);
		if (run_exec(w, argv, &res) != 0) {
			step_end(w, step, false, "bird does not take it");
			*errp = wfmt(w, "%s: bird does not take it: %s",
			    ni[k].name, res.errlen > 0 ? res.err : res.out !=
			    NULL ? res.out : "no reason given");
			ok = false;
			break;
		}
		if (inst_up(w, &ni[k], was, &e) != 0) {
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
	/* The stations of the instances that monitor their routes; BIRD
	 * connects again until one listens. */
	bmp_set(jail, mons, nm);
	/* Kept, a file per edge; a jail's with no instance goes, so that a
	 * start makes none for a jail that has none now. */
	file = jail[0] != '\0' ? wfmt(w, "sdwan-bird@%s.json", jail) : BIRD_FILE;
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

/*
 * The BFD sessions of an instance, as "show bfd sessions" lists them:
 * a heading, then a line each of address, interface, state, since,
 * interval, timeout; into out, at most max; how many, -1 when birdc
 * did not answer in time.
 */
static int
bfd_read(struct work *w, const struct instance *in, struct bfd *out,
    int max)
{
	struct execres	 res;
	char		*text, *line, *p, *f[6];
	int		 n, k;

	if (inst_birdc(w, in, "show", "bfd sessions", &res) != 0 || res.out ==
	    NULL)
		return (res.timedout ? -1 : 0);
	n = 0;
	text = wstrdup(w, res.out);
	while (n < max && (line = strsep(&text, "\n")) != NULL) {
		if (line[0] == '\0' || line[0] == ' ' || strncmp(line, "BIRD", 4)
		    == 0 || strncmp(line, "IP address", 10) == 0 || line[strlen(
		    line) - 1] == ':')
			continue;
		p = line;
		for (k = 0; k < 6; k++) {
			while (*p == ' ' || *p == '\t')
				p++;
			f[k] = p;
			while (*p != '\0' && *p != ' ' && *p != '\t')
				p++;
			if (*p != '\0')
				*p++ = '\0';
		}
		if (f[2][0] == '\0')
			continue;
		snprintf(out[n].instance, sizeof(out[n].instance), "%s", in->name);
		snprintf(out[n].address, sizeof(out[n].address), "%s", f[0]);
		snprintf(out[n].iface, sizeof(out[n].iface), "%s", f[1]);
		snprintf(out[n].since, sizeof(out[n].since), "%s", f[3]);
		out[n].state = strcasecmp(f[2], "up") == 0 ? PROBE_UP : strcasecmp(
		    f[2], "down") == 0 ? PROBE_DOWN : PROBE_UNKNOWN;
		n++;
	}
	return (n);
}

/*
 * The faults held to what is watched (fault_reconcile()), so that one
 * of an instance, a neighbour or a session gone, or one an agent before
 * raised whose cause went with the restart, does not stay open.
 * birdwatch.c's of the host's BIRD share the owner "bird" ("host:" and
 * "jail:" objects): not these.
 */
static const char *const bird_scope[] = { "!host:", "!jail:", NULL };

/* The BFD sessions listed now (now, m of them), each by its tunnel or
 * address, one up well: at the first look and whenever the instances
 * change.  Between those a session no longer listed is a fault (it went
 * with the session that asked for it), not one gone. */
static void
bfd_reconcile(const struct bfd *now, int m)
{
	struct fault_live	*v;
	char			(*obj)[64];
	const char		*id;
	int			 k;

	if ((v = calloc((size_t)m + 1, sizeof(*v))) == NULL ||
	    (obj = calloc((size_t)m + 1, sizeof(*obj))) == NULL) {
		free(v);
		return;
	}
	for (k = 0; k < m; k++) {
		id = sdwan_tunnel_by_via(now[k].address);
		(void)strlcpy(obj[k], id != NULL ? id : now[k].address,
		    sizeof(obj[k]));
		v[k].object = obj[k];
		v[k].well = now[k].state == PROBE_UP;
	}
	(void)fault_reconcile("bfd", "bfd", NULL, v, (size_t)m, "no BFD "
	    "session of an SD-WAN BIRD instance is there");
	free(v);
	free(obj);
}

/* The instances (in, n of them) and the BGP neighbours their last look
 * listed (bgp, nb of them): when either changed, or at the first. */
static void
bird_reconcile(const struct instance *in, int n, char (*bgp)[160], int nb)
{
	static char		 said[8192];
	static bool		 once;
	struct fault_live	*v;
	char			 now[sizeof(said)];
	size_t			 off;
	int			 i;

	for (i = 0, off = 0; i < n && off < sizeof(now); i++)
		off += (size_t)snprintf(now + off, sizeof(now) - off, "%s\n",
		    in[i].name);
	for (i = 0; i < nb && off < sizeof(now); i++)
		off += (size_t)snprintf(now + off, sizeof(now) - off, "%s\n",
		    bgp[i]);
	if (once && strcmp(now, said) == 0)
		return;
	if ((v = calloc((size_t)(n + nb) + 1, sizeof(*v))) == NULL)
		return;
	for (i = 0; i < n; i++) {
		v[i].type = "bird-instance";
		v[i].object = in[i].name;
	}
	for (i = 0; i < nb; i++) {
		v[n + i].type = "bgp-neighbor";
		v[n + i].object = bgp[i];
	}
	(void)fault_reconcile("bird", NULL, bird_scope, v, (size_t)(n + nb),
	    "the SD-WAN BIRD instance or its neighbour is taken away");
	free(v);
	(void)strlcpy(said, now, sizeof(said));
	once = true;
}

/* The instances' names, a line each: whether they changed. */
static bool
insts_changed(const struct instance *in, int n)
{
	static char	said[INSTANCES_MAX * 41 + 1];
	static bool	once;
	char		now[sizeof(said)];
	size_t		off;
	int		i;

	for (i = 0, off = 0; i < n; i++)
		off += (size_t)snprintf(now + off, sizeof(now) - off, "%s\n",
		    in[i].name);
	now[off] = '\0';
	if (once && strcmp(now, said) == 0)
		return (false);
	(void)strlcpy(said, now, sizeof(said));
	once = true;
	return (true);
}

/*
 * The sessions read again every second, each change an event
 * (sdwan-tunnel, by bfd, R60), and the steering told, which takes
 * BFD's word over the probe's where there is a session: made again on
 * the prober's worker, the changes counted with the probes'.
 */
static void *
bfd_watch(void *arg __unused)
{
	struct work	 w;
	struct instance	 in[INSTANCES_MAX];
	struct bfd	*now, *chg;
	char		 (*bgp)[160];
	int		 n, i, k, m, r, was, nchg, round, nb;
	bool		 changed, whole;

	if ((now = calloc(BFD_MAX, sizeof(*now))) == NULL || (chg = calloc(
	    BFD_MAX, sizeof(*chg))) == NULL || (bgp = calloc(SEEN_MAX,
	    sizeof(*bgp))) == NULL)
		return (NULL);
	round = 0;
	for (;;) {
		sleep(BFD_EVERY_S);
		pthread_mutex_lock(&lock);
		n = ninstances;
		memcpy(in, instances, sizeof(*in) * (size_t)n);
		pthread_mutex_unlock(&lock);
		/* None left: what the last of them raised cleared. */
		if (n == 0) {
			if (insts_changed(in, 0)) {
				bfd_reconcile(now, 0);
				bird_reconcile(in, 0, bgp, 0);
			}
			continue;
		}
		work_init(&w);
		w.nice = true;
		m = 0;
		for (i = 0; i < n && m < BFD_MAX; i++) {
			if ((r = bfd_read(&w, &in[i], now + m, BFD_MAX - m)) >= 0) {
				m += r;
				continue;
			}
			/* Not waited for: its sessions as last read, not
			 * taken down by a birdc that hangs, and the instance
			 * said not to answer. */
			fault_set("bird-instance", "Critical", in[i].name,
			    "bird", "the BIRD instance %s does not answer "
			    "within %d s", in[i].name, JAIL_READ_SEC);
			pthread_mutex_lock(&lock);
			for (k = 0; k < nbfds && m < BFD_MAX; k++)
				if (strcmp(bfds[k].instance, in[i].name) == 0)
					now[m++] = bfds[k];
			pthread_mutex_unlock(&lock);
		}
		changed = false;
		nchg = 0;
		/* Seen up once: from then on, down is a fault. */
		for (k = 0; k < m; k++)
			if (now[k].state == PROBE_UP)
				(void)was_up(now[k].address, true);
		pthread_mutex_lock(&lock);
		for (k = 0; k < m; k++) {
			was = PROBE_NONE;
			for (i = 0; i < nbfds; i++)
				if (strcmp(bfds[i].address, now[k].address) == 0 &&
				    strcmp(bfds[i].iface, now[k].iface) == 0) {
					was = bfds[i].state;
					break;
				}
			if (was != now[k].state && (was != PROBE_NONE || now[k].
			    state == PROBE_DOWN)) {
				chg[nchg++] = now[k];
				changed = true;
			}
		}
		/* One that was up and is listed no more went down with the
		 * session that asked for it (BGP's, on its fault). */
		for (i = 0; i < nbfds && nchg < BFD_MAX; i++) {
			if (bfds[i].state != PROBE_UP)
				continue;
			for (k = 0; k < m; k++)
				if (strcmp(bfds[i].address, now[k].address) == 0 &&
				    strcmp(bfds[i].iface, now[k].iface) == 0)
					break;
			if (k == m) {
				chg[nchg] = bfds[i];
				chg[nchg++].state = PROBE_DOWN;
				changed = true;
			}
		}
		if (m != nbfds)
			changed = true;
		memcpy(bfds, now, sizeof(*now) * (size_t)m);
		nbfds = m;
		pthread_mutex_unlock(&lock);
		/* Published: the changes counted for the prober's worker,
		 * which makes the steering again with its own (gula/
		 * probe_engine.c), a session listed or gone one; at once,
		 * not after the events, which may wait on the steering's
		 * lock while a run of it is in ipfw. */
		if (changed) {
			logmsg(LOG_DEBUG, "sdwan bird: %d BFD change%s counted "
			    "for the steering", nchg > 0 ? nchg : 1, nchg > 1 ?
			    "s" : "");
			probe_steer_due(nchg > 0 ? (unsigned)nchg : 1);
		}
		/* Told without the lock: the steering has a lock of its own,
		 * taken the other way round when it asks BFD. */
		for (k = 0; k < nchg; k++) {
			const char	*id = sdwan_tunnel_by_via(chg[k].address);

			event_add("sdwan-tunnel", "{\"id\":\"%s\",\"address\":\"%s\","
			    "\"interface\":\"%s\",\"state\":\"%s\",\"by\":\"bfd\"}",
			    id != NULL ? id : chg[k].iface, chg[k].address,
			    chg[k].iface, chg[k].state == PROBE_UP ? "up" :
			    chg[k].state == PROBE_DOWN ? "down" : "unknown");
			if (chg[k].state == PROBE_DOWN && was_up(chg[k].address,
			    false))
				fault_set("bfd", "Major", id != NULL ? id :
				    chg[k].address, "bfd", "BFD to %s on %s is down",
				    chg[k].address, chg[k].iface);
			else if (chg[k].state == PROBE_UP) {
				(void)was_up(chg[k].address, true);
				fault_clear("bfd", id != NULL ? id : chg[k].address,
				    "BFD to %s on %s is up", chg[k].address,
				    chg[k].iface);
			}
		}
		/* The sessions' faults held to them: at the first look and
		 * when the instances change. */
		if (insts_changed(in, n) || round == 0)
			bfd_reconcile(now, m);
		/* Every five seconds, the instances and their BGP neighbours;
		 * every one answering, a full view of them. */
		if (++round % 5 == 0) {
			whole = true;
			nb = 0;
			for (i = 0; i < n; i++)
				whole &= protocols_watch(&w, &in[i], bgp, &nb);
			if (whole)
				bird_reconcile(in, n, bgp, nb);
		}
		work_free(&w);
	}
	return (NULL);
}

/*
 * What a BIRD of a jail's says, for a fault, which goes as it is to mail
 * and to Telegram: one line, no control character, max bytes at most,
 * not cut inside a character.
 */
static const char *
bird_said(struct work *w, const char *s, size_t max)
{
	char	*t;
	size_t	 n;

	n = strlen(s);
	if (n > max) {
		for (n = max; n > 0 && ((unsigned char)s[n] & 0xc0) == 0x80;
		    n--)
			;
	}
	t = wstrndup(w, s, n);
	return (wname(w, t));
}

/*
 * An instance that does not answer is a fault (Critical: nothing is
 * routed by it), and each BGP neighbour of it that is not up is one
 * (Major), cleared when it is (Table 4).  Each neighbour listed added
 * to bgp (*nb of them, SEEN_MAX at most); false when the instance did
 * not answer.
 */
static bool
protocols_watch(struct work *w, const struct instance *in, char (*bgp)[160],
    int *nb)
{
	struct execres	 res;
	const char	*name = in->name, *e;
	char		*text, *line, *word, *rest, obj[160];
	int		 k;

	if (inst_birdc(w, in, "show", "protocols", &res) != 0 &&
	    res.timedout) {
		/* There, and not answering: not started a second time. */
		fault_set("bird-instance", "Critical", name, "bird", "the BIRD "
		    "instance %s does not answer within %d s", name,
		    JAIL_READ_SEC);
		return (false);
	}
	if (res.status != 0 || res.out == NULL) {
		struct instance	again = *in;

		/* Gone (BIRD 3.3.3 has died on a reconfigure): started
		 * again, on its file as it is; a jail's where the jail is
		 * now, if it runs. */
		fault_set("bird-instance", "Critical", name, "bird", "the BIRD "
		    "instance %s does not answer: started again", name);
		e = NULL;
		if (again.jail[0] != '\0') {
			if (scope_enter(w, again.jail, &e) != 0 || strlen(w->jroot)
			    >= sizeof(again.jroot)) {
				logmsg(LOG_WARNING, "sdwan bird: %s not started "
				    "again: %s", name, e != NULL ? e : "the jail's "
				    "path");
				return (false);
			}
			again.jid = w->jid;
			snprintf(again.jroot, sizeof(again.jroot), "%s", w->jroot);
			pthread_mutex_lock(&lock);
			for (k = 0; k < ninstances; k++)
				if (strcmp(instances[k].name, again.name) == 0 &&
				    strcmp(instances[k].jail, again.jail) == 0)
					instances[k] = again;
			pthread_mutex_unlock(&lock);
			/* Its station, in the jail's network as it is now. */
			bmp_rejail(again.jail, name, again.jid);
		}
		if (inst_start(w, &again, &e) != 0)
			logmsg(LOG_WARNING, "sdwan bird: %s not started again: %s",
			    name, e);
		return (false);
	}
	fault_clear("bird-instance", name, "the BIRD instance %s answers again",
	    name);
	/* Its station listening, if it could not before. */
	bmp_rejail(in->jail, name, in->jail[0] != '\0' ? in->jid : 0);
	text = wstrdup(w, res.out);
	while ((line = strsep(&text, "\n")) != NULL) {
		char	*f[4];

		if (line[0] == '\0' || line[0] == ' ' || strncmp(line, "BIRD", 4)
		    == 0 || strncmp(line, "Name ", 5) == 0)
			continue;
		rest = line;
		for (k = 0; k < 4 && (word = strsep(&rest, " ")) != NULL; k++) {
			f[k] = word;
			while (rest != NULL && *rest == ' ')
				rest++;
		}
		if (k < 4 || strcmp(f[1], "BGP") != 0)
			continue;
		f[0] = (char *)(uintptr_t)bird_said(w, f[0], 64);
		f[3] = (char *)(uintptr_t)bird_said(w, f[3], 32);
		if (rest != NULL)
			rest = (char *)(uintptr_t)bird_said(w, rest, 200);
		snprintf(obj, sizeof(obj), "%s/%s", name, f[0]);
		if (*nb < SEEN_MAX)
			(void)strlcpy(bgp[(*nb)++], obj, sizeof(bgp[0]));
		if (strcmp(f[3], "up") == 0) {
			(void)was_up(obj, true);
			fault_clear("bgp-neighbor", obj, "BGP %s of %s is up", f[0],
			    name);
		} else if (was_up(obj, false))
			fault_set("bgp-neighbor", "Major", obj, "bird", "BGP %s of %s "
			    "is %s%s%s", f[0], name, f[3], rest != NULL && rest[0]
			    != '\0' ? ": " : "", rest != NULL ? rest : "");
	}
	return (true);
}

/* What BFD says of the tunnel whose far address this is; NONE without. */
int
sdwan_bfd_state(const char *address)
{
	int	i, st;

	st = PROBE_NONE;
	pthread_mutex_lock(&lock);
	for (i = 0; address != NULL && i < nbfds; i++)
		if (strcmp(bfds[i].address, address) == 0) {
			st = bfds[i].state;
			break;
		}
	pthread_mutex_unlock(&lock);
	return (st);
}

/* At the start: the instances kept, started again; the sessions watched. */
void
sdwan_bird_start(void)
{
	struct work	 w;
	struct dirent	*de;
	DIR		*d;
	char		*json, dir[MAXPATHLEN], *slash;
	const char	*e;
	pthread_t	 tid;
	size_t		 n;
	int		 error;

	work_init(&w);
	if ((json = sdwan_kept_read(BIRD_FILE)) != NULL) {
		e = NULL;
		if (do_sdwan_bird(&w, json, &e) != 0)
			logmsg(LOG_WARNING, "sdwan bird: %s", e);
		free(json);
	}
	/* The jails', each from its own file. */
	sdwan_conf_path(BIRD_FILE, dir, sizeof(dir));
	if ((slash = strrchr(dir, '/')) == NULL)
		snprintf(dir, sizeof(dir), ".");
	else
		*slash = '\0';
	if ((d = opendir(dir)) != NULL) {
		while ((de = readdir(d)) != NULL) {
			n = strlen(de->d_name);
			if (strncmp(de->d_name, "sdwan-bird@", 11) != 0 || n <= 16 ||
			    strcmp(de->d_name + n - 5, ".json") != 0)
				continue;
			if ((json = sdwan_kept_read(de->d_name)) == NULL)
				continue;
			e = NULL;
			if (do_sdwan_bird(&w, json, &e) != 0)
				logmsg(LOG_WARNING, "sdwan bird: %s: %s", de->d_name,
				    e);
			free(json);
		}
		closedir(d);
	}
	work_free(&w);
	if ((error = pthread_create(&tid, NULL, bfd_watch, NULL)) != 0)
		logmsg(LOG_WARNING, "sdwan bird: no BFD watch: %s", strerror(
		    error));
	else
		pthread_detach(tid);
}

/*
 * The instances as they are, into the sdwan reply: each its name, fib,
 * whether it answers, and its protocols as birdc lists them (name,
 * kind, state, what it says).
 */
void
sdwan_bird_json(struct work *w, ucl_object_t *top)
{
	struct execres	 res;
	struct instance	*iv;
	struct bfd	*bv;
	ucl_object_t	*arr, *o, *ps, *p;
	char		*text, *line, *word, *rest;
	int		 i, k, niv, nbv;

	/* Copied, and birdc run without the lock: the steering asks BFD's
	 * state under it, and an instance that does not answer would hold
	 * every other edge's reads and failover until it is killed. */
	iv = wcalloc(w, INSTANCES_MAX, sizeof(*iv));
	bv = wcalloc(w, BFD_MAX, sizeof(*bv));
	pthread_mutex_lock(&lock);
	niv = ninstances;
	memcpy(iv, instances, sizeof(*iv) * (size_t)niv);
	nbv = nbfds;
	memcpy(bv, bfds, sizeof(*bv) * (size_t)nbv);
	pthread_mutex_unlock(&lock);
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
		ps = ucl_object_typed_new(UCL_ARRAY);
		if (inst_birdc(w, &iv[i], "show", "protocols",
		    &res) == 0 && res.out != NULL) {
			ucl_object_insert_key(o, ucl_object_frombool(true),
			    "running", 0, false);
			text = wstrdup(w, res.out);
			while ((line = strsep(&text, "\n")) != NULL) {
				/* Name Proto Table State Since Info */
				if (line[0] == '\0' || line[0] == ' ' ||
				    strncmp(line, "BIRD", 4) == 0 || strncmp(line,
				    "Name ", 5) == 0)
					continue;
				p = ucl_object_typed_new(UCL_OBJECT);
				rest = line;
				for (k = 0; k < 5 && (word = strsep(&rest, " "))
				    != NULL; k++) {
					while (rest != NULL && *rest == ' ')
						rest++;
					if (k == 0)
						ucl_object_insert_key(p,
						    ucl_object_fromstring(word),
						    "name", 0, false);
					else if (k == 1)
						ucl_object_insert_key(p,
						    ucl_object_fromstring(word),
						    "proto", 0, false);
					else if (k == 3)
						ucl_object_insert_key(p,
						    ucl_object_fromstring(word),
						    "state", 0, false);
				}
				if (rest != NULL && rest[0] != '\0')
					ucl_object_insert_key(p,
					    ucl_object_fromstring(rest), "info",
					    0, false);
				ucl_array_append(ps, p);
			}
		} else
			ucl_object_insert_key(o, ucl_object_frombool(false),
			    "running", 0, false);
		ucl_object_insert_key(o, ps, "protocols", 0, false);
		/* Its BFD sessions, as last read. */
		ps = ucl_object_typed_new(UCL_ARRAY);
		for (k = 0; k < nbv; k++) {
			if (strcmp(bv[k].instance, iv[i].name) != 0)
				continue;
			p = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(p, ucl_object_fromstring(
			    bv[k].address), "address", 0, false);
			ucl_object_insert_key(p, ucl_object_fromstring(
			    bv[k].iface), "interface", 0, false);
			ucl_object_insert_key(p, ucl_object_fromstring(
			    bv[k].state == PROBE_UP ? "up" : bv[k].state ==
			    PROBE_DOWN ? "down" : "unknown"), "state", 0, false);
			ucl_object_insert_key(p, ucl_object_fromstring(
			    bv[k].since), "since", 0, false);
			ucl_array_append(ps, p);
		}
		ucl_object_insert_key(o, ps, "bfd", 0, false);
		/* Its BMP station, when it monitors its routes. */
		if ((p = bmp_json(iv[i].jail, iv[i].name)) != NULL)
			ucl_object_insert_key(o, p, "bmp", 0, false);
		ucl_array_append(arr, o);
	}
	ucl_object_insert_key(top, arr, "bird", 0, false);
}
