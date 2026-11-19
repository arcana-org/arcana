/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Luxuria: the divert rules of the Security section's Suricata that
 * prevents in a jail with a network of its own (vnet).  divert(4)
 * sockets are a vnet jail's alone (the kernel grants
 * PRIV_NETINET_DIVERT to none other), and the packets they take are
 * those its own ipfw(8) diverts: the rules are placed there, by the
 * jail's ipfw run in it (jexec(8), scope.c), as SSL inspection places
 * its own (sslproxy.c).
 *
 * One rule an interface the instance watches, "divert <port> ip from
 * any to any via <if> // secids:<name>", at rule 6 (before SSL
 * inspection's 7, the ACLs' 8 and the SD-WAN's 9 to 99) in set 25:
 * set 24 emptied and disabled, the rules added to it, swapped with set
 * 25, set 24 emptied; none left, set 25 deleted.  The jail admin's
 * rules are never touched: a rule of set 24 or 25 that is not the
 * IDS's own (its comment), or one of another set at rule 6, refuses
 * the change and nothing is loaded.  A packet given back by Suricata
 * goes on at the rule after the divert.
 */

#include <sys/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"

#define	TAG		"secids:"	/* the rules' comments */
#define	FW_RULE		6		/* the rules' number */
#define	FW_SET		25		/* their set */
#define	FW_STAGE	24		/* where they are loaded first */
#define	SET(n)		__XSTRING(n)

struct krule {
	long		 num;
	int		 set;
	bool		 ours;
};

/* The jail's ipfw -a -S list read; -1 where ipfw cannot be. */
static int
kernel_rules(struct work *w, struct krule **out, size_t *np)
{
	struct execres	 res;
	struct krule	*v;
	const char	*p, *nl, *c;
	char		*argv[5], *line;
	size_t		 n, cap;
	uintmax_t	 pkts, bytes;
	long		 num;
	int		 set, off;

	*out = NULL;
	*np = 0;
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"-a";
	argv[2] = (char *)(uintptr_t)"-S";
	argv[3] = (char *)(uintptr_t)"list";
	argv[4] = NULL;
	if (run_read_max(w, argv, &res, ARC_MAX_JSON) != 0)
		return (-1);
	n = cap = 0;
	v = NULL;
	for (p = res.out != NULL ? res.out : ""; *p != '\0';
	    p = *nl != '\0' ? nl + 1 : nl) {
		nl = p + strcspn(p, "\n");
		line = wstrndup(w, p, (size_t)(nl - p));
		if (sscanf(line, "%ld %ju %ju set %d %n", &num, &pkts, &bytes,
		    &set, &off) != 4)
			continue;
		if (n == cap) {
			struct krule	*nv;

			cap = cap == 0 ? 64 : cap * 2;
			nv = wcalloc(w, cap, sizeof(*v));
			if (n > 0)
				memcpy(nv, v, n * sizeof(*v));
			v = nv;
		}
		v[n].num = num;
		v[n].set = set;
		v[n].ours = (c = strstr(line + off, "// ")) != NULL &&
		    strstr(c, TAG) != NULL;
		n++;
	}
	*out = v;
	*np = n;
	return (0);
}

/* Whether the jail's rules leave sets 24, 25 and rule 6 to the IDS;
 * NULL, or why not.  *any: set 25 holds rules of its own. */
static const char *
kernel_free(struct work *w, const struct krule *k, size_t n, bool *any)
{
	size_t	i;

	*any = false;
	for (i = 0; i < n; i++) {
		if (k[i].set == FW_SET || k[i].set == FW_STAGE) {
			if (!k[i].ours)
				return (wfmt(w, "rule %ld is in ipfw set %d of the "
				    "jail %s, which its intrusion prevention keeps, "
				    "and is not its own: move it to another set "
				    "first", k[i].num, k[i].set, w->jail));
			if (k[i].set == FW_SET)
				*any = true;
			continue;
		}
		if (k[i].num == FW_RULE)
			return (wfmt(w, "rule %d of ipfw set %d in the jail %s is at "
			    "the number its intrusion prevention keeps (%d): "
			    "renumber it first", FW_RULE, k[i].set, w->jail,
			    FW_RULE));
	}
	return (NULL);
}

static int
ipfw(struct work *w, const char **errp, const char *const args[])
{
	struct execres	 res;
	char		*argv[24];
	int		 n;

	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[n++] = (char *)(uintptr_t)"-q";
	for (; *args != NULL && n < 23; args++)
		argv[n++] = (char *)(uintptr_t)*args;
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		if (errp != NULL)
			*errp = wtext(w, exec_error(w, &res, "ipfw"));
		return (-1);
	}
	return (0);
}

#define	IPFW(w, e, ...)	ipfw((w), (e), (const char *const []){ __VA_ARGS__, NULL })

/* Whether the change could be made: NULL, or why not.  w is in the
 * jail. */
const char *
idsfw_check(struct work *w)
{
	struct krule	*k;
	size_t		 nk;
	bool		 any;

	if (kernel_rules(w, &k, &nk) != 0)
		return (wfmt(w, "the jail %s's ipfw cannot be read (ipfw(4) not "
		    "loaded, or not on in its network?): nothing would divert "
		    "to its Suricata", w->jail));
	return (kernel_free(w, k, nk, &any));
}

/*
 * The jail's divert rules made those of the n instances given (w in
 * the jail): each its name, port and interfaces; none, set 25 taken
 * away where it holds the IDS's rules alone.  0, or -1 and why.
 */
int
idsfw_set(struct work *w, int n, const struct idsfw *v, const char **errp)
{
	struct krule	*k;
	const char	*e;
	size_t		 nk;
	int		 i, j, step, rc, nr;
	bool		 any;

	for (i = nr = 0; i < n; i++)
		nr += v[i].nifs;
	step = step_begin(w, STEP_EXEC, "ipfw divert", "%d rule%s in set "
	    SET(FW_SET) " at rule " SET(FW_RULE) " of the jail %s", nr, nr ==
	    1 ? "" : "s", w->jail);
	if (kernel_rules(w, &k, &nk) != 0) {
		if (n == 0) {
			step_end(w, step, true, "ipfw cannot be read: nothing "
			    "to take away");
			return (0);
		}
		*errp = wfmt(w, "the jail %s's ipfw cannot be read (ipfw(4) not "
		    "loaded, or not on in its network?): nothing diverts to its "
		    "Suricata", w->jail);
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	if ((e = kernel_free(w, k, nk, &any)) != NULL) {
		*errp = e;
		step_end(w, step, false, "%s", e);
		return (-1);
	}
	rc = -1;
	if (nr == 0) {
		if (any && IPFW(w, errp, "-f", "delete", "set", SET(FW_SET)) !=
		    0)
			goto out;
		rc = 0;
		goto out;
	}
	(void)IPFW(w, NULL, "-f", "delete", "set", SET(FW_STAGE));
	if (IPFW(w, errp, "set", "disable", SET(FW_STAGE)) != 0)
		goto out;
	for (i = 0; i < n; i++)
		for (j = 0; j < v[i].nifs; j++)
			if (IPFW(w, errp, "add", SET(FW_RULE), "set",
			    SET(FW_STAGE), "divert", wfmt(w, "%d", v[i].port),
			    "ip", "from", "any", "to", "any", "via",
			    v[i].ifs[j], "//", wfmt(w, TAG
			    "%s", v[i].name)) != 0) {
				(void)IPFW(w, NULL, "-f", "delete", "set",
				    SET(FW_STAGE));
				goto out;
			}
	if (IPFW(w, errp, "set", "swap", SET(FW_STAGE), SET(FW_SET)) != 0) {
		(void)IPFW(w, NULL, "-f", "delete", "set", SET(FW_STAGE));
		goto out;
	}
	(void)IPFW(w, NULL, "set", "enable", SET(FW_SET));
	(void)IPFW(w, NULL, "-f", "delete", "set", SET(FW_STAGE));
	rc = 0;
out:
	if (rc == 0)
		step_end(w, step, true, NULL);
	else
		step_end(w, step, false, "%s", *errp);
	return (rc);
}
