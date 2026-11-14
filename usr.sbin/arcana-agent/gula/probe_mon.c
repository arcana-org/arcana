/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula, the admin's own monitors on any tunnel interface, by the same
 * prober: the monitor job (set, changed in place, removed) and the
 * monitors set together (do_monitors_set(), arcana-probe's edit), each
 * a target whose owner is "monitor", an edge's list in place of its own
 * (probe.c's targets_parse() and the engine's swap) and kept in its own
 * file (monitors.json, monitors@j.json).  On the host a monitor with no
 * address probes its interface's far end (a gre's or a gif's inner
 * address), through the interface's FIB when it names none.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"
#include "stamp.h"
#include "probe_int.h"

/* A monitor's name: letters, digits and _ . @ -, 63 at most. */
static bool
mon_name_ok(const char *s)
{
	size_t	n;

	return (s != NULL && (n = strlen(s)) > 0 && n < 64 && strspn(s,
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	    "_.@-") == n);
}

static const char *
arg_of(const char *word, const char *name)
{
	size_t	n;

	n = strlen(name);
	return (strncmp(word, name, n) == 0 && word[n] == '=' ? word + n + 1 :
	    NULL);
}

/* The name a monitor job is for (name=), or NULL. */
static const char *
mon_name(const struct arc_job_spec *sp)
{
	const char	*v;
	size_t		 i;

	for (i = 0; i < sp->names.n; i++)
		if ((v = arg_of(sp->names.v[i], "name")) != NULL)
			return (v);
	return (NULL);
}


/*
 * The far end of a point-to-point interface of the host (a gre's or a
 * gif's inner address): its first inet destination, else its first
 * inet6 one that is not link-local.  NULL with none.
 */
static const char *
ptp_dst(struct work *w, const char *ifname)
{
	struct ifaddrs	*ifap, *i;
	const char	*v4, *v6;
	char		 buf[INET6_ADDRSTRLEN];

	if (getifaddrs(&ifap) == -1)
		return (NULL);
	v4 = v6 = NULL;
	for (i = ifap; i != NULL; i = i->ifa_next) {
		if (strcmp(i->ifa_name, ifname) != 0 || (i->ifa_flags &
		    IFF_POINTOPOINT) == 0 || i->ifa_dstaddr == NULL)
			continue;
		if (i->ifa_dstaddr->sa_family == AF_INET && v4 == NULL &&
		    inet_ntop(AF_INET, &((struct sockaddr_in *)(void *)
		    i->ifa_dstaddr)->sin_addr, buf, sizeof(buf)) != NULL)
			v4 = wstrdup(w, buf);
		else if (i->ifa_dstaddr->sa_family == AF_INET6 && v6 == NULL &&
		    !IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6 *)(void *)
		    i->ifa_dstaddr)->sin6_addr) && inet_ntop(AF_INET6,
		    &((struct sockaddr_in6 *)(void *)i->ifa_dstaddr)->sin6_addr,
		    buf, sizeof(buf)) != NULL)
			v6 = wstrdup(w, buf);
	}
	freeifaddrs(ifap);
	return (v4 != NULL ? v4 : v6);
}

static const char *const mon_keys[] = { "name", "interface", "address",
    "fib", "interval", "size", "dscp", "eval", "history", "down", "up",
    "timeout", "delay-max", "ipdv-max", "loss-max", "damping", NULL };

const char *
monitor_check(const struct arc_job_spec *sp)
{
	const char	*v;
	char		*end;
	double		 d;
	size_t		 i, k;

	if (sp->verb == NULL || (strcmp(sp->verb, "set") != 0 && strcmp(
	    sp->verb, "remove") != 0))
		return ("a monitor job is set or remove");
	if (sp->safe)
		return ("a monitor measures, it changes nothing to undo: not in "
		    "safe mode");
	if (!mon_name_ok(mon_name(sp)))
		return ("a monitor has a name: name=, letters, digits and _ . "
		    "@ -, 63 at most");
	for (i = 0; i < sp->names.n; i++) {
		for (k = 0; mon_keys[k] != NULL; k++)
			if (arg_of(sp->names.v[i], mon_keys[k]) != NULL)
				break;
		if (mon_keys[k] == NULL || (strcmp(sp->verb, "remove") == 0 &&
		    k != 0))
			return (strcmp(sp->verb, "remove") == 0 ? "remove takes "
			    "the monitor's name= alone" : "set takes name=, "
			    "interface=, address=, fib=, interval=, size=, dscp=, "
			    "eval=, history=, down=, up=, timeout=, delay-max=, "
			    "ipdv-max=, loss-max= and damping=");
		/* The numbers' form here; their bounds where they are kept. */
		v = strchr(sp->names.v[i], '=') + 1;
		if (k == 1 && !valid_ifname(v))
			return ("interface= is an interface's name");
		if (k >= 12 && k <= 14) {
			d = strtod(v, &end);
			if (*v == '\0' || *end != '\0' || d < 0 || (k == 14 &&
			    d > 100))
				return ("a threshold is a number, loss-max a per "
				    "cent");
		} else if (k >= 3) {
			(void)strtol(v, &end, 10);
			if (*v == '\0' || *end != '\0')
				return ("fib=, interval=, size=, dscp=, eval=, "
				    "history=, down=, up=, timeout= and damping= "
				    "are whole numbers");
		}
	}
	return (NULL);
}

char *
monitor_title(const struct arc_job_spec *sp)
{
	const char	*v;
	size_t		 i;
	char		*t;

	v = NULL;
	for (i = 0; i < sp->names.n && v == NULL; i++)
		v = arg_of(sp->names.v[i], "interface");
	if (asprintf(&t, "monitor %s %s%s%s%s%s", sp->verb, mon_name(sp),
	    v != NULL ? " on " : "", v != NULL ? v : "", sp->jail != NULL &&
	    sp->jail[0] != '\0' ? " in " : "", sp->jail != NULL ? sp->jail :
	    "") == -1)
		return (NULL);
	return (t);
}

/* A whole number argument into o's key, checked by targets_parse after. */
static int
put_num(ucl_object_t *o, const char *key, const char *v, const char **errp)
{
	char	*end;
	long	 n;

	errno = 0;
	n = strtol(v, &end, 10);
	if (errno != 0 || *v == '\0' || *end != '\0') {
		*errp = "is not a whole number";
		return (-1);
	}
	ucl_object_insert_key(o, ucl_object_fromint(n), key, 0, true);
	return (0);
}

/*
 * An edge's monitors in the place of those it had: arr, the targets as
 * targets_parse takes them (taken), the owner's file written again.
 */
static int
monitors_put(struct work *w, ucl_object_t *arr, const char *jail,
    const char **errp)
{
	struct target	*new;
	ucl_object_t	*top;
	const char	*e;
	char		*json, path[MAXPATHLEN], jbuf[64];
	int		 n, step;

	if (jail[0] != '\0') {
		top = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(top, ucl_object_fromstring(jail), "jail", 0,
		    false);
		ucl_object_insert_key(top, arr, "targets", 0, false);
	} else
		top = arr;
	n = (int)ucl_array_size(ucl_object_lookup(top, "targets") != NULL ?
	    ucl_object_lookup(top, "targets") : top);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL) {
		*errp = "no memory";
		return (-1);
	}
	if ((new = calloc(TARGETS_MAX, sizeof(*new))) == NULL) {
		free(json);
		*errp = strerror(errno);
		return (-1);
	}
	if ((n = targets_parse(w, json, new, jbuf, sizeof(jbuf), OWN_MONITOR,
	    errp)) < 0) {
		free(new);
		free(json);
		return (-1);
	}
	if (!engine_swap(new, n, jail, OWN_MONITOR)) {
		*errp = wfmt(w, "%d targets at most, monitors and SD-WAN's "
		    "together", TARGETS_MAX);
		targets_drop(new, n);
		free(json);
		return (-1);
	}
	conf_path(path, sizeof(path), jail, OWN_MONITOR);
	step = step_begin(w, STEP_FILE, "write", "%s", path);
	e = NULL;
	if (n == 0 ? unlink(path) == -1 && errno != ENOENT && (e = strerror(
	    errno)) != NULL : conf_write(json, jail, OWN_MONITOR, &e) != 0) {
		step_end(w, step, false, "%s", e);
		*errp = wfmt(w, "%s: %s", path, e);
		free(json);
		return (-1);
	}
	step_end(w, step, true, "%d monitor%s", n, n == 1 ? "" : "s");
	free(json);
	return (0);
}

/*
 * A monitor set (added, or changed in place: its samples kept when it
 * probes the same address the same way) or removed, at the host or at
 * the vnet jail sp->jail; the owner's file written again.
 */
int
do_monitor_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	ucl_object_t		*arr, *o, *tc;
	const struct target	*t;
	struct snap		*s;
	const char		*name, *jail, *a, *v, *ifname, *e;
	double			 d;
	size_t			 i;
	int			 k;
	bool			 found;

	name = mon_name(sp);
	jail = sp->jail != NULL ? sp->jail : "";
	if (jail[0] != '\0' && !valid_jail(jail)) {
		*errp = "invalid jail name";
		return (-1);
	}
	arr = ucl_object_typed_new(UCL_ARRAY);
	found = false;
	s = snap_get();
	for (k = 0; s != NULL && k < s->n; k++) {
		t = &s->v[k].t;
		if (!is_monitor(t) || strcmp(t->jail, jail) != 0)
			continue;
		if (strcmp(t->id, name) == 0) {
			found = true;
			continue;
		}
		ucl_array_append(arr, target_conf(t));
	}
	snap_put(s);
	if (strcmp(sp->verb, "remove") == 0 && !found) {
		ucl_object_unref(arr);
		*errp = wfmt(w, "no monitor %s%s%s", name, jail[0] != '\0' ?
		    " in jail " : "", jail);
		return (-1);
	}
	if (strcmp(sp->verb, "set") == 0) {
		o = ucl_object_typed_new(UCL_OBJECT);
		tc = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(name), "id", 0,
		    false);
		ifname = NULL;
		e = NULL;
		for (i = 0; i < sp->names.n && e == NULL; i++) {
			a = sp->names.v[i];
			if (arg_of(a, "name") != NULL)
				continue;
			if ((v = arg_of(a, "interface")) != NULL) {
				if (!valid_ifname(v))
					e = "interface= is an interface's name";
				ifname = v;
				ucl_object_insert_key(o, ucl_object_fromstring(v),
				    "interface", 0, true);
			} else if ((v = arg_of(a, "address")) != NULL)
				ucl_object_insert_key(o, ucl_object_fromstring(v),
				    "address", 0, true);
			else if ((v = arg_of(a, "delay-max")) != NULL ||
			    (v = arg_of(a, "ipdv-max")) != NULL ||
			    (v = arg_of(a, "loss-max")) != NULL) {
				char	*end;

				d = strtod(v, &end);
				if (*v == '\0' || *end != '\0' || d < 0 ||
				    (arg_of(a, "loss-max") != NULL && d > 100))
					e = "a threshold is a number, loss-max a "
					    "per cent";
				ucl_object_insert_key(tc, ucl_object_fromdouble(
				    arg_of(a, "loss-max") != NULL ? d / 100 : d),
				    arg_of(a, "delay-max") != NULL ? "delay" :
				    arg_of(a, "ipdv-max") != NULL ? "ipdv" : "loss",
				    0, true);
			} else if ((v = arg_of(a, "damping")) != NULL) {
				if (put_num(tc, "damping", v, &e) != 0)
					e = wfmt(w, "damping %s", e);
			} else {
				const char	*key = wstrndup(w, a, strcspn(a,
				    "="));

				if (put_num(o, key, strchr(a, '=') + 1, &e) != 0)
					e = wfmt(w, "%s %s", key, e);
			}
		}
		/* On the host, a tunnel's far end and its table found. */
		if (e == NULL && ucl_object_lookup(o, "address") == NULL) {
			if (ifname != NULL && jail[0] == '\0' && (v = ptp_dst(w,
			    ifname)) != NULL)
				ucl_object_insert_key(o, ucl_object_fromstring(v),
				    "address", 0, true);
			else
				e = ifname != NULL && jail[0] == '\0' ? wfmt(w,
				    "%s has no far end to probe (not point to "
				    "point): give address=", ifname) : "address= "
				    "is needed";
		}
		if (e == NULL && ucl_object_lookup(o, "fib") == NULL && ifname !=
		    NULL && jail[0] == '\0' && if_fib(ifname) > 0)
			ucl_object_insert_key(o, ucl_object_fromint(if_fib(
			    ifname)), "fib", 0, true);
		if (e != NULL) {
			ucl_object_unref(o);
			ucl_object_unref(tc);
			ucl_object_unref(arr);
			*errp = e;
			return (-1);
		}
		if (ucl_object_lookup(tc, "delay") != NULL || ucl_object_lookup(
		    tc, "ipdv") != NULL || ucl_object_lookup(tc, "loss") != NULL)
			ucl_object_insert_key(o, tc, "tca", 0, false);
		else
			ucl_object_unref(tc);
		ucl_array_append(arr, o);
	}
	return (monitors_put(w, arr, jail, errp));
}

/*
 * An edge's monitors set together, json {"jail", "targets"} (a
 * monitor's id its name): on the host one without an address probes
 * its interface's far end, through the interface's FIB when it names
 * none.
 */
int
do_monitors_set(struct work *w, const char *json, const char **errp)
{
	struct ucl_parser	*p;
	ucl_object_t		*top, *arr, *o;
	const ucl_object_t	*v, *e;
	ucl_object_iter_t	 it;
	const char		*jail, *ifname, *dst;
	int			 rc;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	top = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	if (top == NULL || ucl_object_type(top) != UCL_OBJECT) {
		if (top != NULL)
			ucl_object_unref(top);
		*errp = "the monitors are a JSON object";
		return (-1);
	}
	jail = (v = ucl_object_lookup(top, "jail")) != NULL &&
	    ucl_object_type(v) == UCL_STRING ? ucl_object_tostring(v) : "";
	if (jail[0] != '\0' && !valid_jail(jail)) {
		ucl_object_unref(top);
		*errp = "invalid jail name";
		return (-1);
	}
	jail = wstrdup(w, jail);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(top, "targets"), &it,
	    true)) != NULL) {
		o = ucl_object_copy(e);
		ifname = (v = ucl_object_lookup(o, "interface")) != NULL &&
		    ucl_object_type(v) == UCL_STRING ? ucl_object_tostring(v) :
		    NULL;
		if (ifname != NULL && (ifname[0] == '\0' || strlen(ifname) >=
		    IFNAMSIZ || !valid_ifname(ifname))) {
			ucl_object_unref(o);
			ucl_object_unref(arr);
			ucl_object_unref(top);
			*errp = "a monitor's interface is an interface's name";
			return (-1);
		}
		if (ucl_object_lookup(o, "address") == NULL) {
			if (ifname == NULL || jail[0] != '\0' || (dst = ptp_dst(w,
			    ifname)) == NULL) {
				*errp = ifname != NULL && jail[0] == '\0' ?
				    wfmt(w, "%s has no far end to probe (not "
				    "point to point): give an address", ifname) :
				    "a monitor needs an address";
				ucl_object_unref(o);
				ucl_object_unref(arr);
				ucl_object_unref(top);
				return (-1);
			}
			ucl_object_insert_key(o, ucl_object_fromstring(dst),
			    "address", 0, true);
			if (ucl_object_lookup(o, "fib") == NULL && if_fib(ifname) >
			    0)
				ucl_object_insert_key(o, ucl_object_fromint(
				    if_fib(ifname)), "fib", 0, true);
		}
		ucl_array_append(arr, o);
	}
	ucl_object_unref(top);
	rc = monitors_put(w, arr, jail, errp);
	return (rc);
}
