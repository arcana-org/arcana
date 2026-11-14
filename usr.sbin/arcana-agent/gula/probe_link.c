/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula, the links an edge watches (Mplify 119's interface faults): its
 * UCS end points' and UNIs' interfaces, each a fault while it has no
 * link (down, or its carrier gone), told by the console beside the
 * targets ("links": [{"interface", "id", "role"}]) and kept with them
 * (probe.c's files).  Each is looked at when it is told, and then as
 * the kernel tells its changes (netlink, on the host's or a jail's
 * network: probe_link()).  The links are not the engine's: nothing is
 * probed for them, so they have their own lock, links_mtx, under which
 * faults.c is told (its lock inside); the steering reads none of them.
 * The faults of a link no longer watched are cleared (fault_reconcile(),
 * "link"), once the kept files are read and at each change of the
 * links or of the targets.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <ucl.h>

#include "agent.h"
#include "stamp.h"
#include "probe_int.h"

static pthread_mutex_t	 links_mtx = PTHREAD_MUTEX_INITIALIZER;
static struct link	 links[LINKS_MAX];
static int		 nlinks;
static bool		 watching;	/* the kept ones read */

/* A link's fault object: its id, id@jail at a jail's edge. */
static const char *
link_name(const struct link *l, char *buf, size_t len)
{

	if (l->jail[0] != '\0')
		snprintf(buf, len, "%s@%s", l->id, l->jail);
	else
		snprintf(buf, len, "%s", l->id);
	return (buf);
}

/* A link's state as now seen: a fault when it goes, cleared when back. */
static void
link_state(struct link *l, int up)
{
	char	obj[TOBJ_MAX];

	if (l->state == up)
		return;
	l->state = up;
	if (up == 0)
		fault_set("interface", "Major", link_name(l, obj, sizeof(obj)),
		    "link", "the %s %s has no link on %s", strcmp(l->role,
		    "uni") == 0 ? "UNI" : "UCS end point", l->id, l->ifname);
	else
		fault_clear("interface", link_name(l, obj, sizeof(obj)),
		    "the %s %s has its link on %s again", strcmp(l->role, "uni")
		    == 0 ? "UNI" : "UCS end point", l->id, l->ifname);
}

/* With links_mtx held, once the kept ones are read: a link's fault
 * while it has none, cleared when it has its link again or is watched
 * no more. */
static void
links_held(void)
{
	struct fault_live	*v;
	char			*nm;
	int			 i;

	if (!watching)
		return;
	v = calloc((size_t)nlinks + 1, sizeof(*v));
	nm = calloc((size_t)nlinks + 1, TOBJ_MAX);
	if (v == NULL || nm == NULL) {
		logmsg(LOG_WARNING, "probe: no memory to hold the faults to the "
		    "links");
		goto out;
	}
	for (i = 0; i < nlinks; i++) {
		link_name(&links[i], &nm[i * TOBJ_MAX], TOBJ_MAX);
		v[i].type = "interface";
		v[i].object = &nm[i * TOBJ_MAX];
		v[i].reason = "it has its link again";
		v[i].well = links[i].state == 1;
	}
	(void)fault_reconcile("link", "interface", NULL, v, (size_t)nlinks,
	    "watched no more");
out:
	free(v);
	free(nm);
}

/* The links' faults held to them, as they are now. */
void
links_reconcile(void)
{

	pthread_mutex_lock(&links_mtx);
	links_held();
	pthread_mutex_unlock(&links_mtx);
}

/* The kept ones read: the links' faults held to them from now on. */
void
links_watch(void)
{

	pthread_mutex_lock(&links_mtx);
	watching = true;
	links_held();
	pthread_mutex_unlock(&links_mtx);
}

/* The links now, into v (max of them): how many. */
int
links_copy(struct link *v, int max)
{
	int	n;

	pthread_mutex_lock(&links_mtx);
	n = nlinks < max ? nlinks : max;
	memcpy(v, links, (size_t)n * sizeof(*v));
	pthread_mutex_unlock(&links_mtx);
	return (n);
}

bool
has_links(const char *json)
{
	struct ucl_parser	*p;
	ucl_object_t		*top;
	bool			 yes;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	top = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	yes = top != NULL && ucl_object_type(top) == UCL_OBJECT &&
	    ucl_array_size(ucl_object_lookup(top, "links")) > 0;
	if (top != NULL)
		ucl_object_unref(top);
	return (yes);
}

/*
 * An edge's links from its payload, in place of those it had; each
 * looked at now (later the interface's own changes tell).  A link no
 * longer watched has its fault cleared.  -1 and why when bad.
 */
int
links_set(struct work *w, const char *json, const char *jail,
    const char **errp)
{
	struct ucl_parser	*p;
	ucl_object_t		*top;
	const ucl_object_t	*o, *v;
	ucl_object_iter_t	 it;
	struct link		 nl[LINKS_MAX], *l;
	struct work		 jw;
	const char		*s, *e;
	int			 n, k, i;
	bool			 ok;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	top = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	n = 0;
	it = NULL;
	while (top != NULL && ucl_object_type(top) == UCL_OBJECT && (o =
	    ucl_object_iterate(ucl_object_lookup(top, "links"), &it, true)) !=
	    NULL) {
		if (n == LINKS_MAX) {
			*errp = wfmt(w, "%d links at most", LINKS_MAX);
			ucl_object_unref(top);
			return (-1);
		}
		l = &nl[n];
		memset(l, 0, sizeof(*l));
		l->state = -1;
		snprintf(l->jail, sizeof(l->jail), "%s", jail);
		if ((v = ucl_object_lookup(o, "interface")) == NULL ||
		    ucl_object_type(v) != UCL_STRING || (s =
		    ucl_object_tostring(v))[0] == '\0' || strlen(s) >=
		    sizeof(l->ifname) || !valid_ifname(s) || (v =
		    ucl_object_lookup(o, "id")) == NULL || ucl_object_type(v) !=
		    UCL_STRING || ucl_object_tostring(v)[0] == '\0' ||
		    strlen(ucl_object_tostring(v)) >= sizeof(l->id)) {
			*errp = "each link has an interface and an id";
			ucl_object_unref(top);
			return (-1);
		}
		snprintf(l->ifname, sizeof(l->ifname), "%s", s);
		snprintf(l->id, sizeof(l->id), "%s", ucl_object_tostring(v));
		v = ucl_object_lookup(o, "role");
		snprintf(l->role, sizeof(l->role), "%s", v != NULL &&
		    ucl_object_type(v) == UCL_STRING && strcmp(
		    ucl_object_tostring(v), "uni") == 0 ? "uni" : "ucs");
		n++;
	}
	if (top != NULL)
		ucl_object_unref(top);
	/* Each as it is now, where the edge is. */
	work_init(&jw);
	e = NULL;
	if (jail[0] != '\0' && scope_enter(&jw, jail, &e) != 0)
		jw.jail = NULL;
	for (i = 0; i < n; i++)
		if (jail[0] == '\0' || jw.jail != NULL)
			nl[i].state = if_link(&jw, nl[i].ifname, &ok) ? ok :
			    0;
	work_free(&jw);
	pthread_mutex_lock(&links_mtx);
	/* The others' kept, the edge's new after them. */
	for (i = k = 0; k < nlinks; k++)
		if (strcmp(links[k].jail, jail) != 0)
			links[i++] = links[k];
	if (i + n > LINKS_MAX) {
		pthread_mutex_unlock(&links_mtx);
		*errp = wfmt(w, "%d links at most, all edges' together",
		    LINKS_MAX);
		return (-1);
	}
	for (k = 0; k < n; k++) {
		int	st = nl[k].state;

		links[i] = nl[k];
		links[i].state = -1;
		/* Not known (no such interface yet): down until it is. */
		link_state(&links[i], st == 1 ? 1 : 0);
		i++;
	}
	nlinks = i;
	/* Those no longer watched: their faults cleared. */
	links_held();
	pthread_mutex_unlock(&links_mtx);
	return (0);
}

/*
 * An interface's link as the kernel tells it changed (netlink, on the
 * host's or a jail's network): a watched link's fault set or cleared.
 */
void
probe_link(const char *jail, const char *ifname, bool ok)
{
	int	k;

	pthread_mutex_lock(&links_mtx);
	for (k = 0; k < nlinks; k++)
		if (strcmp(links[k].jail, jail != NULL ? jail : "") == 0 &&
		    strcmp(links[k].ifname, ifname) == 0)
			link_state(&links[k], ok ? 1 : 0);
	pthread_mutex_unlock(&links_mtx);
}
