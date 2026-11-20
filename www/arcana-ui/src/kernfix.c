/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The kernel fixes a feature of Arcana's waits for, and whether a
 * host's running kernel has one: by its kern.osreldate and its version
 * line (arcana-host's osreldate and kernel-version, the host's list),
 * as FreeBSD's newvers.sh writes it.  A kernel built from git on main
 * says its commit count and commit ("main-n291371-fb9969ca61ca"), which
 * order it among main's commits; one built otherwise says when it was
 * built, which can only say that it is older than a fix.  Only a note:
 * nothing is refused by it.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "app.h"

/*
 * FreeBSD main fb9969ca61ca, "netinet6: Keep a pfil-chosen next hop in
 * ip6_tryforward()": committed 2026-11-18 21:36:32 UTC, while
 * __FreeBSD_version was 1600031, main's 291371st commit (first parent).
 * Before it, with net.inet6.ip6.redirect at 0, forwarded IPv6 that an
 * ipfw fwd rule matched took the route to its destination, not the
 * rule's next hop.
 */
#define	FWD6_OSRELDATE	1600031
#define	FWD6_COUNT	291371L
#define	FWD6_COMMITTED	1795037792LL	/* 2026-11-18T21:36:32Z */

/* When the version line says the kernel was built, UTC; -1 unknown.
 * *slack: its zone was a name, not an offset (up to 14 hours off). */
static int64_t
built_at(const char *v, bool *slack)
{
	static const char *const months[] = { "Jan", "Feb", "Mar", "Apr",
	    "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	struct tm	 tm;
	const char	*p;
	char		 wd[8], mon[8], zone[16];
	int		 d, hh, mm, ss, y, i, off;

	*slack = false;
	/* "FreeBSD 16.0-CURRENT #11 [branch-nN-hash]: Thu Nov 19 15:15:26
	 * +0330 2026": the date after the build number's colon. */
	if ((p = strchr(v, '#')) == NULL || (p = strstr(p, ": ")) == NULL)
		return (-1);
	if (sscanf(p + 2, "%7s %7s %d %d:%d:%d %15s %d", wd, mon, &d, &hh, &mm,
	    &ss, zone, &y) != 8)
		return (-1);
	for (i = 0; i < 12 && strcmp(mon, months[i]) != 0; i++)
		;
	if (i == 12)
		return (-1);
	memset(&tm, 0, sizeof(tm));
	tm.tm_year = y - 1900;
	tm.tm_mon = i;
	tm.tm_mday = d;
	tm.tm_hour = hh;
	tm.tm_min = mm;
	tm.tm_sec = ss;
	off = 0;
	if ((zone[0] == '+' || zone[0] == '-') && strlen(zone) == 5) {
		off = ((zone[1] - '0') * 10 + zone[2] - '0') * 3600 +
		    ((zone[3] - '0') * 10 + zone[4] - '0') * 60;
		if (zone[0] == '-')
			off = -off;
	} else if (strcmp(zone, "UTC") != 0 && strcmp(zone, "GMT") != 0)
		*slack = true;
	return ((int64_t)timegm(&tm) - off);
}

/*
 * Has the host's kernel fb9969ca61ca: KFIX_HAS, KFIX_BEFORE, or
 * KFIX_UNKNOWN when its version does not say (a kernel of 1600031
 * built from another branch, or not from git, after the commit).
 */
int
kernel_fwd6_fix(const struct server *s)
{
	const char	*v, *p;
	int64_t		 rel, t;
	long		 n;
	bool		 slack;

	rel = jint(s->list, "host.osreldate", 0);
	if (rel > FWD6_OSRELDATE)
		return (KFIX_HAS);
	if (rel > 0 && rel < FWD6_OSRELDATE)
		return (KFIX_BEFORE);
	if ((v = jstr(s->list, "host.kernel_version")) == NULL)
		return (KFIX_UNKNOWN);
	/* Built from main by git: its place among main's commits. */
	if ((p = strstr(v, " main-n")) != NULL) {
		n = strtol(p + 7, NULL, 10);
		if (n > 0)
			return (n >= FWD6_COUNT ? KFIX_HAS : KFIX_BEFORE);
	}
	/* Otherwise its build's date can only say it is older. */
	if ((t = built_at(v, &slack)) >= 0 && t + (slack ? 14 * 3600 : 0) <
	    FWD6_COMMITTED)
		return (KFIX_BEFORE);
	return (KFIX_UNKNOWN);
}

/*
 * The note where IPv6 ipfw fwd rules are (what names them) on a host
 * whose net.inet6.ip6.redirect is 0 and whose kernel predates the fix,
 * or may: true when one was written.
 */
bool
kernel_fwd6_note(struct html *h, const struct server *s, const char *what)
{
	const char	*v;
	int		 fix;

	if (s == NULL || (fix = kernel_fwd6_fix(s)) == KFIX_HAS)
		return (false);
	h_fmt(h, "<div class=\"notice %s kern-fwd6\" data-fix=\"%s\">",
	    fix == KFIX_BEFORE ? "warn" : "dim", fix == KFIX_BEFORE ? "before" :
	    "unknown");
	h_raw(h, fix == KFIX_BEFORE ? "This host's kernel predates" : "This "
	    "host's kernel may predate");
	h_raw(h, " FreeBSD main <code>fb9969ca61ca</code> (2026-11-18): with "
	    "<code>net.inet6.ip6.redirect</code> at 0, as the sysctl hardening "
	    "sets it, forwarded IPv6 takes <code>ip6_tryforward()</code>, "
	    "which there loses the next hop an <code>ipfw fwd</code> rule "
	    "chose, so ");
	h_txt(h, what);
	h_raw(h, " may send IPv6 by the routing table instead. A kernel from "
	    "that commit on has the fix; <code>net.inet6.ip6.redirect=1</code> "
	    "avoids it until then.");
	if (fix == KFIX_UNKNOWN) {
		h_raw(h, " Its version does not say whether it has it");
		if ((v = jstr(s->list, "host.kernel_version")) != NULL) {
			h_raw(h, ": <code>");
			h_txt(h, v);
			h_raw(h, "</code>");
		}
		h_raw(h, ".");
	}
	h_raw(h, "</div>");
	return (true);
}
