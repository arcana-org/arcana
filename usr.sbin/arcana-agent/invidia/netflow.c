/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: a service's flows recorded (PLAN-SDN-YANG 5.6.1), NetFlow
 * version 9 (RFC 3954) by the base's netgraph(4), nothing of Arcana's
 * own on the data path.  For each service of the sdwan-rules payload's
 * flowexp, K its place there, the edge's graph has
 *
 *	ipfw:  <C>    -- iface0  arcnfK (ng_netflow)  export9 -- arcnfKx
 *	ipfw:  <C+1>  -- iface1                        (ng_ksocket, UDP,
 *						        to the collector)
 *
 * C the cookie FE_COOKIE + 2K, both hooks DLT_RAW (ipfw hands bare IP
 * packets), the timeouts set; and the set has, on rule FE_RULE (9,
 * after alternate marking's way out of the tunnels, before the
 * console's rules), for each tunnel:
 *
 *	[prob 1/N] ngtee C   ip from any to any in recv TUN
 *		what came out of the tunnel, a copy to iface0
 *	[prob 1/N] ngtee C+1 ip from any to any out xmit TUN
 *		what goes into it, a copy to iface1
 *
 * ngtee is a tee: the packet itself goes on.  But with no ng_ipfw
 * loaded ipfw drops what an ngtee rule matches, so the rules are
 * refused unless it is (the console has the edge load and keep it);
 * and ng_ipfw makes its node in the host's network alone, so a vnet
 * jail's edge, or an agent that is itself in a vnet jail, has nowhere
 * to send the copies: refused too.  The nodes are made again at each
 * load of the set, every arcnf node there shut down first (ng_netflow
 * sends what it holds as it goes), and with none, none is left; at the
 * agent's start the kept payload is loaded again, and the nodes with
 * it.
 *
 * The collector is an IPv4 address: ng_ksocket takes "inet/A:P"; an
 * IPv6 one would need its generic sockaddr form, not done yet.
 * ng_netflow sends a datagram once it is full, so a quiet service's
 * expired flows wait for more (TODO.md).
 */

#include <sys/param.h>
#include <sys/module.h>

#include <arpa/inet.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

#include "agent.h"

#define	FE_NODE		"arcnf"		/* the nodes' names, K after */

/* Letters, digits, _ . - and the characters more alone, 1 to max. */
static bool
word_ok(const char *s, size_t max, const char *more)
{
	char	set[96];
	size_t	n;

	if (s == NULL || (n = strlen(s)) == 0 || n > max)
		return (false);
	snprintf(set, sizeof(set), "%s%s", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789_.-", more);
	return (strspn(s, set) == n);
}

/* A number of key between lo and hi, def when it is not there; -1 when
 * it is no such number. */
static int
num_of(const ucl_object_t *s, const char *key, int lo, int hi, int def)
{
	const ucl_object_t	*v;
	int64_t			 n;

	if ((v = ucl_object_lookup(s, key)) == NULL)
		return (def);
	if (ucl_object_type(v) != UCL_INT || (n = ucl_object_toint(v)) < lo ||
	    n > hi)
		return (-1);
	return ((int)n);
}

void
netflow_free(struct fe_service *v, int n)
{

	for (int i = 0; v != NULL && i < n; i++)
		free(v[i].tun);
	free(v);
}

/*
 * The sdwan-rules payload's flowexp: each service's name, collector,
 * port, sampling, timeouts and tunnels (id, interface at this edge).
 * 0, or -1 and why.
 */
int
netflow_parse(const ucl_object_t *arr, struct fe_service **outp, int *np,
    const char **errp)
{
	const ucl_object_t	*s, *t, *v;
	ucl_object_iter_t	 it, tit;
	struct fe_service	*out, *f;
	struct in_addr		 a4;
	int			 n, k;

	*outp = NULL;
	*np = 0;
	if (arr == NULL)
		return (0);
	if (ucl_object_type(arr) != UCL_ARRAY || ucl_array_size(arr) >
	    FE_SERVICES) {
		*errp = "flowexp is a list of services, 16 at most";
		return (-1);
	}
	if (ucl_array_size(arr) == 0)
		return (0);
	if ((out = calloc(ucl_array_size(arr), sizeof(*out))) == NULL) {
		*errp = strerror(errno);
		return (-1);
	}
	n = 0;
	it = NULL;
	while ((s = ucl_object_iterate(arr, &it, true)) != NULL) {
		f = &out[n];
		v = ucl_object_lookup(s, "service");
		if (ucl_object_type(s) != UCL_OBJECT || v == NULL ||
		    !word_ok(ucl_object_tostring(v), sizeof(f->name) - 1, "")) {
			*errp = "flowexp: a service is named by letters, digits "
			    "and _ . -";
			goto bad;
		}
		snprintf(f->name, sizeof(f->name), "%s", ucl_object_tostring(v));
		v = ucl_object_lookup(s, "collector");
		if (v == NULL || ucl_object_tostring(v) == NULL ||
		    inet_pton(AF_INET, ucl_object_tostring(v), &a4) != 1) {
			*errp = "flowexp: a service's collector is an IPv4 "
			    "address";
			goto bad;
		}
		(void)inet_ntop(AF_INET, &a4, f->collector,
		    sizeof(f->collector));
		if ((f->port = num_of(s, "port", 1, 65535, 2055)) < 0 ||
		    (f->sampling = num_of(s, "sampling", 1, 65535, 1)) < 0 ||
		    (f->active = num_of(s, "active_timeout", 1, 65535,
		    1800)) < 0 || (f->inactive = num_of(s, "inactive_timeout",
		    1, 65535, 15)) < 0) {
			*errp = "flowexp: a service's port, sampling and "
			    "timeouts are 1 to 65535";
			goto bad;
		}
		v = ucl_object_lookup(s, "tunnels");
		if (v == NULL || ucl_object_type(v) != UCL_ARRAY ||
		    ucl_array_size(v) == 0 || ucl_array_size(v) > FE_TUNNELS) {
			*errp = "flowexp: a service has 1 to 64 tunnels";
			goto bad;
		}
		if ((f->tun = calloc(ucl_array_size(v), sizeof(*f->tun))) ==
		    NULL) {
			*errp = strerror(errno);
			goto bad;
		}
		k = 0;
		tit = NULL;
		while ((t = ucl_object_iterate(v, &tit, true)) != NULL) {
			const ucl_object_t *id = ucl_object_lookup(t, "id");
			const ucl_object_t *ifn = ucl_object_lookup(t,
			    "interface");

			/* A tunnel's id is the service's and its ends'
			 * ("sw1/a-b"), a comment of the rules alone. */
			if (id == NULL || ifn == NULL || !word_ok(
			    ucl_object_tostring(id), sizeof(f->tun[k].id) - 1,
			    "/:@") || !word_ok(ucl_object_tostring(ifn),
			    sizeof(f->tun[k].ifname) - 1, "")) {
				*errp = "flowexp: a tunnel is its id and its "
				    "interface at this edge";
				goto bad;
			}
			snprintf(f->tun[k].id, sizeof(f->tun[k].id), "%s",
			    ucl_object_tostring(id));
			snprintf(f->tun[k].ifname, sizeof(f->tun[k].ifname), "%s",
			    ucl_object_tostring(ifn));
			k++;
		}
		f->ntun = k;
		n++;
	}
	*outp = out;
	*np = n;
	return (0);
bad:
	/* Zeroed: what was not reached has no tunnels to free. */
	netflow_free(out, (int)ucl_array_size(arr));
	return (-1);
}

/*
 * May the work's network record flows?  ng_ipfw in the kernel (without
 * it an ngtee rule drops what it matches) and its node in this network:
 * ng_ipfw makes it in the host's alone, so a vnet jail, an agent's own
 * among them, has none and its ngtee goes nowhere.  NULL, or why not.
 */
const char *
netflow_ready(struct work *w)
{
	struct execres	 res;
	char		*argv[4];

	if (modfind("ng_ipfw") == -1)
		return ("flow records need ng_ipfw loaded (kldload ng_ipfw): "
		    "without it ipfw drops what an ngtee rule matches");
	argv[0] = (char *)(uintptr_t)opts.ngctl_bin;
	argv[1] = (char *)(uintptr_t)"info";
	argv[2] = (char *)(uintptr_t)"ipfw:";
	argv[3] = NULL;
	if (run_exec(w, argv, &res) != 0)
		return ("flow records need ng_ipfw's node, which is the host's "
		    "network's alone: a vnet jail has none");
	return (NULL);
}

/*
 * The ngtee rules of v into fp, ipfw's own lines in set set, rule
 * FE_RULE: a copy of each packet out of each tunnel and into it, one in
 * the service's sampling.  How many.
 */
int
netflow_rules(FILE *fp, const char *set, const struct fe_service *v, int n)
{
	char	prob[32];
	int	i, j, nr, c;

	nr = 0;
	for (i = 0; i < n; i++) {
		c = FE_COOKIE + 2 * i;
		prob[0] = '\0';
		if (v[i].sampling > 1)
			snprintf(prob, sizeof(prob), "prob %.6f ", 1.0 /
			    v[i].sampling);
		for (j = 0; j < v[i].ntun; j++) {
			fprintf(fp, "add %d set %s %sngtee %d ip from any to any "
			    "in recv %s // fe %d.%d in %.50s\n", FE_RULE, set,
			    prob, c, v[i].tun[j].ifname, i, j, v[i].name);
			fprintf(fp, "add %d set %s %sngtee %d ip from any to any "
			    "out xmit %s // fe %d.%d out %.50s\n", FE_RULE, set,
			    prob, c + 1, v[i].tun[j].ifname, i, j, v[i].name);
			nr += 2;
		}
	}
	return (nr);
}

/* The edge's ng_netflow nodes, as "ngctl list" prints them ("  Name:
 * arcnf0  Type: netflow ..."), into a script of shutdowns; each one's
 * ksocket (arcnfKx) goes with its only hook. */
static void
shutdowns(struct work *w, FILE *fp)
{
	struct execres	 res;
	char		*argv[3];
	const char	*p, *e;

	argv[0] = (char *)(uintptr_t)opts.ngctl_bin;
	argv[1] = (char *)(uintptr_t)"list";
	argv[2] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL)
		return;
	for (p = res.out; (p = strstr(p, "Name: " FE_NODE)) != NULL; p = e) {
		p += 6;
		e = p + strcspn(p, " \t\n");
		if ((size_t)(e - p) < 64 && e[-1] != 'x')
			fprintf(fp, "shutdown %.*s:\n", (int)(e - p), p);
	}
}

/*
 * The edge's graph made as v says, in the work's scope (a jail's own):
 * each arcnf node there shut down, then each service's made.  0, or -1
 * and why.
 */
int
netflow_set(struct work *w, const struct fe_service *v, int n,
    const char **errp)
{
	struct execres	 res;
	char		*script, *argv[4], nm[16];
	size_t		 len;
	FILE		*fp;
	int		 i, c;

	if ((fp = open_memstream(&script, &len)) == NULL) {
		*errp = strerror(errno);
		return (-1);
	}
	shutdowns(w, fp);
	for (i = 0; i < n; i++) {
		c = FE_COOKIE + 2 * i;
		snprintf(nm, sizeof(nm), FE_NODE "%d", i);
		fprintf(fp, "mkpeer ipfw: netflow %d iface0\n", c);
		fprintf(fp, "name ipfw:%d %s\n", c, nm);
		fprintf(fp, "connect ipfw: %s: %d iface1\n", nm, c + 1);
		fprintf(fp, "msg %s: setdlt { iface=0 dlt=12 }\n", nm);
		fprintf(fp, "msg %s: setdlt { iface=1 dlt=12 }\n", nm);
		fprintf(fp, "msg %s: settimeouts { inactive=%d active=%d }\n",
		    nm, v[i].inactive, v[i].active);
		fprintf(fp, "mkpeer %s: ksocket export9 inet/dgram/udp\n", nm);
		fprintf(fp, "name %s:export9 %sx\n", nm, nm);
		fprintf(fp, "msg %sx: connect inet/%s:%d\n", nm, v[i].collector,
		    v[i].port);
	}
	if (fclose(fp) != 0) {
		free(script);
		*errp = strerror(errno);
		return (-1);
	}
	if (len == 0) {
		free(script);
		return (0);
	}
	argv[0] = (char *)(uintptr_t)opts.ngctl_bin;
	argv[1] = (char *)(uintptr_t)"-f";
	argv[2] = (char *)(uintptr_t)"-";
	argv[3] = NULL;
	exec_set_stdin(script, len);
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "ngctl"));
		free(script);
		return (-1);
	}
	free(script);
	return (0);
}
