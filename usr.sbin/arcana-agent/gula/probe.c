/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula, the tunnels: each target an address pinged again and again
 * (ICMP echo, as Mplify 119 §11.4 has an SD-WAN edge measure its
 * tunnels), through the routing table it says, by one thread for them
 * all, the prober's engine, which polls their sockets (poll(2)), one
 * raw socket a FIB and a family for the host's echoes, and sends each
 * probe when it is due.  An echo's round trip is timed by
 * the kernel (SO_TIMESTAMP, the monotonic clock), not by when the
 * prober got to its reply.  Of each eval interval it keeps a sample:
 * the one-way delay, half the mean round trip (MEF 105 §7.2.4); the
 * delay variation, the mean difference between one round trip and the next; the loss; the
 * least and the most.  So many misses in a row and the target is down,
 * so many answers and it is up again, each an event (sdwan-tunnel).
 *
 * The targets come from the console (sdwan-probes): a JSON array, the
 * host's own, or {"jail": "j", "targets": [...]}, those of an edge that
 * is the vnet jail j, probed from its network.  Each edge's list
 * replaces its own only, and is kept in a file of its own beside
 * history.conf (sdwan-probes.json, sdwan-probes@j.json) for the next
 * start.  Each
 * says its id and address, and may say its fib, interval (ms), size
 * (bytes), count (0: without end), dscp, down and up (misses and
 * answers), timeout (ms), eval (ms), history (samples kept) and report.
 * A raw socket needs root: without it the target says so, and its
 * socket is tried again a second on, the wait doubling to a minute (a
 * jail's made by the helper, on the engine's worker).  Each target's
 * echo id is its own among the live targets of its family, from one
 * counter that starts at random.
 *
 * A target that is Arcana's far end is measured by STAMP (RFC 8762)
 * instead, through libstamp's sender (the submodule stamp/): its UDP
 * socket in the target's FIB, connected to the far end's stampd(8)
 * (which the far agent runs in the FIBs it probes in, gula/stampd.c),
 * on the same schedule, its samples the same, the round trip with the
 * reflector's time taken out; and, a stateful reflector's counter
 * telling the way out from the way back, the loss each way; and the
 * delay each way, one way when both ends' clocks say they are
 * synchronised closely enough (libstamp's rule: both Error Estimates'
 * S bit, their errors together within a tenth of half the round trip),
 * else half the round trip, flagged an estimate; the reflector's
 * Timestamp Information TLV (RFC 8972 4.3) asked for and kept; and the
 * DSCP each way, the Class of Service TLV (4.4) asking the reflector
 * to reply with the target's DSCP and telling the DSCP the probe
 * reached it with, the reply's read as it comes (IP_RECVTOS,
 * IPV6_RECVTCLASS): a DSCP rewritten or bleached on the way out or
 * back is seen, and a reflector that refuses the DSCP (RP); the
 * Location TLV (4.2), the address and port the probe reached the far
 * end from and to, which a NAT on the way rewrites (the source not the
 * socket's own, the destination not the target's); and the loss each
 * way by the Direct Measurement TLV's counters (4.5), the packets the
 * sender sent and the reflector's session received and sent, beside
 * the sequence's.  Those counters are the two processes', not ipfw's:
 * the probe is one UDP flow both ends own and count, so a count rule
 * would see the same packets (bar the kernel's drops before ipfw) at
 * the price of rules in the admin's ruleset; ipfw's counters belong to
 * the service's own traffic (alternate marking, 5.5).  How a target is
 * measured is its kind (arcana-probe's, PLAN-SDN-YANG 5.1.8): icmp, an
 * echo alone (the console's breakout beacons, hosts not Arcana's);
 * stamp, STAMP alone; auto, the default, STAMP when the target is an
 * SD-WAN target of the host's (Arcana's far end: not a monitor, the
 * admin's on any tunnel, not at a jail's edge, which has no socket of
 * its network yet), --stamp-port 0 measuring none so, and ICMP its
 * fallback: a reflector that refuses (port unreachable), or as many
 * STAMP probes unanswered in a row as make the target down, and the
 * target is pinged instead, its misses left one short of down, so
 * that the first echo decides whether the tunnel is down or its
 * reflector alone; one STAMP probe every STAMP_RETRY seconds, not
 * counted, and an answer brings STAMP back.  Kind stamp has no
 * fallback: the reflector silent, refusing or unkeyed, its probes are
 * misses and the target goes down, why kept (stamp_why), as for auto's
 * falls back.  What STAMP sees of a target is arcana-stamp's session
 * (gula/yprobe.c, from target_json()).
 *
 * A plain tunnel's target (GRE, gif, geneve without IPsec: nothing on
 * the way authenticates its packets) says its end's interface and the
 * far end's public half (stamp_interface, stamp_peer, the console's
 * ${uswe:...} of the far end's pair): its STAMP is the authenticated
 * mode (RFC 8762 4.4, HMAC-SHA-256-128), its key and SSID derived from
 * the interface's X25519 pair (invidia/sa.c, the key verb) and that
 * half by HKDF-SHA256, salted apart from the SAs' ("arcana stamp v1"):
 * the same at both ends, never on the wire nor at the console.  The
 * key is kept in memory; stampd(8)'s key file holds the reflector's
 * copy (gula/stampd.c).  A reply that does not authenticate is no reply
 * (counted, auth_failed), so a far end of another key, or a packet
 * tampered with on the way, falls back to ICMP as an unanswered
 * reflector does; until the key is derived (the pair not made yet),
 * the target is pinged and the key tried again with STAMP.  A key that
 * brings no authenticated answer is derived anew, at each STAMP try of
 * a fallen-back target and every STAMP_RETRY seconds of a kind stamp
 * one that is down: a pair made again at this end is used without an
 * apply, stampd's copy following.  The far end's half is the console's
 * to bring (its apply); until then its pair made again keeps failing.
 * A plain tunnel's target fallen back is measured unauthenticated,
 * which one on the path can force: an alarm, arcana-alarms'
 * stamp-unauthenticated, cleared when authenticated STAMP answers
 * again.
 *
 * The same prober measures tunnels outside SD-WAN too: the monitors an
 * admin puts on any tunnel interface (the monitor job), each target's
 * owner "monitor" rather than "sdwan".  An owner's list is replaced by
 * its own alone, so an SD-WAN apply never takes a monitor away, and is
 * kept in its own file (monitors.json, monitors@j.json).  A monitor's
 * state and thresholds are events (monitor, monitor-threshold), not
 * SD-WAN's faults.
 *
 * The faults the prober raises (tunnel, underlay, stamp-unauthenticated,
 * tca; the links' interface) are held to its targets and links: once
 * the kept ones are read at the start, and at each change of them,
 * what it watches is told to faults.c (fault_reconcile()), which clears
 * those of a target or link gone, or of a threshold taken away; a tca
 * or stamp-unauthenticated fault an agent before left open is taken
 * up, cleared when the figure is under the threshold again or STAMP
 * authenticated answers.  A measurement interval ends by the monotonic
 * clock, the wall clock only naming it.
 *
 * The prober's files: this one the table and its configuration (the
 * targets parsed and checked, kept in their files, swapped in, the
 * start); probe_mon.c the admin's monitors; probe_engine.c the thread
 * that owns the targets, and its worker; probe_icmp.c and probe_echo.c
 * the echoes; probe_stamp.c STAMP and its keys; probe_pm.c the states,
 * samples, thresholds and measurement intervals; probe_link.c the
 * links; probe_view.c the snapshot the readers have and what they read
 * of it; probe_int.h what they share.
 *
 * Its locks, in their order: req_mtx (probe_engine.c), the changes
 * handed to the engine, held to queue one or to tell it done, and
 * across a whole change only by an asker before the engine runs; then
 * snap_mtx (probe_view.c), the snapshot published, held for a pointer
 * and a count.  wk_mtx (probe_engine.c, the worker's jobs and answers),
 * links_mtx (probe_link.c, the links) and rtc_lock (probe_view.c, the
 * routes counted, across a dump) are each taken alone.  The engine
 * holds none while it works.  faults.c's, events.c's and stampd.c's
 * own come after any of them; invidia/sdwan.c's before snap_mtx, as
 * the steering asks a target's state holding it.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"
#include "stamp.h"
#include "probe_int.h"

#define	PROBE_FILE	"sdwan-probes.json"
#define	MONITOR_FILE	"monitors.json"
#define	SAMPLES_MAX	100000
#define	CLASSES_MAX	8	/* classes of service a target, at most */

const char *const kind_names[] = { "auto", "stamp", "icmp" };
const char *const state_names[] = { "unknown", "up", "down", "ended",
    "error" };

bool
is_monitor(const struct target *t)
{

	return (strcmp(t->owner, OWN_MONITOR) == 0);
}

/* Measured by STAMP: kind stamp; under auto, an SD-WAN target of the
 * host's (Arcana's far end, the console's tunnels); never kind icmp. */
static bool
is_arcana(const struct target *t)
{

	if (t->kind == KIND_ICMP)
		return (false);
	if (t->kind == KIND_STAMP)
		return (true);
	return (opts.stamp_port != 0 && !is_monitor(t) && t->jail[0] == '\0');
}

/* The file of an owner's targets at an edge: the host's, or jail's. */
const char *
conf_path(char *buf, size_t len, const char *jail, const char *owner)
{
	const char	*slash;
	char		 base[128];
	bool		 mon;

	mon = owner != NULL && strcmp(owner, OWN_MONITOR) == 0;
	if (jail != NULL && jail[0] != '\0')
		snprintf(base, sizeof(base), "%s@%s.json", mon ? "monitors" :
		    "sdwan-probes", jail);
	else
		snprintf(base, sizeof(base), "%s", mon ? MONITOR_FILE :
		    PROBE_FILE);
	if ((slash = strrchr(opts.history_conf, '/')) != NULL)
		snprintf(buf, len, "%.*s/%s", (int)(slash - opts.history_conf),
		    opts.history_conf, base);
	else
		snprintf(buf, len, "%s", base);
	return (buf);
}

/* Its sockets closed, its STAMP sender given up: its FIB's echo socket
 * is the FIBs' table's (probe_icmp.c), a jail's its own. */
void
target_close(struct target *t)
{

	if (t->sock != -1 && t->own)
		close(t->sock);
	t->sock = -1;
	t->own = false;
	if (t->usock != -1)
		close(t->usock);
	t->usock = -1;
	stamp_drop(t);
}

void
target_free(struct target *t)
{

	target_close(t);
	target_rows_free(t);
	explicit_bzero(&t->key, sizeof(t->key));
	explicit_bzero(&t->was, sizeof(t->was));
	t->keyed = false;
}

/* Its name in faults and the log: its id, and id@jail at a jail's
 * edge, so that both ends of a tunnel on one host are told apart. */
const char *
target_name(const struct target *t, char *buf, size_t len)
{

	if (t->jail[0] != '\0')
		snprintf(buf, len, "%s@%s", t->id, t->jail);
	else
		snprintf(buf, len, "%s", t->id);
	/* A class's session: id/class. */
	if (t->cls[0] != '\0')
		snprintf(buf + strlen(buf), len - strlen(buf), "/%s", t->cls);
	return (buf);
}

/* ---- The targets, as told ------------------------------------------ */

static int64_t
num(const ucl_object_t *o, const char *key, int64_t dflt, int64_t lo,
    int64_t hi, const char **errp)
{
	const ucl_object_t	*v;
	int64_t			 n;

	if ((v = ucl_object_lookup(o, key)) == NULL)
		return (dflt);
	if (ucl_object_type(v) != UCL_INT || (n = ucl_object_toint(v)) < lo ||
	    n > hi) {
		if (*errp == NULL)
			*errp = "bad";
		return (dflt);
	}
	return (n);
}

/*
 * The targets parsed from json into new (TARGETS_MAX at most); the
 * number, or -1 and why.
 */
int
targets_parse(struct work *w, const char *json, struct target *new,
    char *jail, size_t jlen, const char *owner, const char **errp)
{
	struct ucl_parser	*p;
	ucl_object_t		*top;
	const ucl_object_t	*o, *v;
	ucl_object_iter_t	 it;
	struct target		*t;
	struct sockaddr_in	*s4;
	struct sockaddr_in6	*s6;
	const ucl_object_t	*list;
	const char		*id, *addr, *bad;
	int			 n, k;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	top = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	/* An edge that is a vnet jail: {"jail", "targets"}. */
	jail[0] = '\0';
	list = top;
	if (top != NULL && ucl_object_type(top) == UCL_OBJECT) {
		/* {"targets", "links"}, a jail's with "jail". */
		if ((v = ucl_object_lookup(top, "jail")) != NULL && (ucl_object_type(
		    v) != UCL_STRING || !valid_jail(ucl_object_tostring(v)) ||
		    strlen(ucl_object_tostring(v)) >= jlen)) {
			ucl_object_unref(top);
			*errp = "invalid jail name";
			return (-1);
		}
		if (v != NULL)
			snprintf(jail, jlen, "%s", ucl_object_tostring(v));
		list = ucl_object_lookup(top, "targets");
	}
	if (list == NULL || ucl_object_type(list) != UCL_ARRAY) {
		if (top != NULL)
			ucl_object_unref(top);
		*errp = "the targets are a JSON array, or an object with them "
		    "as targets (and links, jail)";
		return (-1);
	}
	n = 0;
	it = NULL;
	while ((o = ucl_object_iterate(list, &it, true)) != NULL) {
		if (n == TARGETS_MAX) {
			*errp = wfmt(w, "%d targets at most", TARGETS_MAX);
			goto bad;
		}
		t = &new[n];
		memset(t, 0, sizeof(*t));
		t->sock = -1;
		t->usock = -1;
		target_rows(t);
		id = (v = ucl_object_lookup(o, "id")) != NULL && ucl_object_type(
		    v) == UCL_STRING ? ucl_object_tostring(v) : NULL;
		addr = (v = ucl_object_lookup(o, "address")) != NULL &&
		    ucl_object_type(v) == UCL_STRING ? ucl_object_tostring(v) :
		    NULL;
		if (id == NULL || id[0] == '\0' || strlen(id) >= sizeof(t->id) ||
		    addr == NULL || strlen(addr) >= sizeof(t->address)) {
			*errp = "each target has an id and an address";
			goto bad;
		}
		for (k = 0; k < n; k++)
			if (strcmp(new[k].id, id) == 0) {
				*errp = wfmt(w, "target %s is there twice", id);
				goto bad;
			}
		snprintf(t->id, sizeof(t->id), "%s", id);
		snprintf(t->address, sizeof(t->address), "%s", addr);
		/* At an edge that is a vnet jail: probed from its network. */
		snprintf(t->jail, sizeof(t->jail), "%s", jail);
		snprintf(t->owner, sizeof(t->owner), "%s", owner);
		/* Its tunnel's, as events say it: a name ("" none). */
		if ((v = ucl_object_lookup(o, "interface")) != NULL) {
			if (ucl_object_type(v) != UCL_STRING ||
			    (ucl_object_tostring(v)[0] != '\0' &&
			    !valid_ifname(ucl_object_tostring(v)))) {
				*errp = wfmt(w, "target %s: interface is an "
				    "interface's name", id);
				goto bad;
			}
			snprintf(t->ifname, sizeof(t->ifname), "%s",
			    ucl_object_tostring(v));
		}
		/* The underlay's path, not a tunnel: SD-WAN's alone. */
		if ((v = ucl_object_lookup(o, "underlay")) != NULL) {
			if (ucl_object_type(v) != UCL_BOOLEAN ||
			    strcmp(owner, OWN_MONITOR) == 0) {
				*errp = wfmt(w, "target %s: underlay is true or "
				    "false, an SD-WAN target's", id);
				goto bad;
			}
			t->underlay = ucl_object_toboolean(v);
		}
		/* How it is measured: auto, stamp or icmp. */
		t->kind = KIND_AUTO;
		if ((v = ucl_object_lookup(o, "kind")) != NULL) {
			for (k = 0; k < (int)nitems(kind_names); k++)
				if (ucl_object_type(v) == UCL_STRING && strcmp(
				    ucl_object_tostring(v), kind_names[k]) == 0)
					break;
			if (k == (int)nitems(kind_names)) {
				*errp = wfmt(w, "target %s: kind is auto, stamp or "
				    "icmp", id);
				goto bad;
			}
			t->kind = k;
		}
		if (t->kind == KIND_STAMP && jail[0] != '\0') {
			*errp = wfmt(w, "target %s: kind stamp: a jail's edge "
			    "has no STAMP yet (auto or icmp)", id);
			goto bad;
		}
		t->arcana = t->by_stamp = is_arcana(t);
		/* A plain tunnel's: its STAMP authenticated, its key derived
		 * now when its pair is there (else when STAMP is tried). */
		{
			const ucl_object_t	*si, *sp;
			const char		*pv;

			si = ucl_object_lookup(o, "stamp_interface");
			sp = ucl_object_lookup(o, "stamp_peer");
			pv = sp != NULL && ucl_object_type(sp) == UCL_STRING ?
			    ucl_object_tostring(sp) : NULL;
			if ((si != NULL || sp != NULL) && (si == NULL || sp ==
			    NULL || ucl_object_type(si) != UCL_STRING ||
			    !valid_ifname(ucl_object_tostring(si)) || strlen(
			    ucl_object_tostring(si)) >= sizeof(t->stamp_if) ||
			    pv == NULL || strlen(pv) != PUB_B64 || strspn(pv,
			    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
			    "0123456789+/=") != PUB_B64)) {
				*errp = wfmt(w, "target %s: stamp_interface is "
				    "this end's tunnel and stamp_peer the far "
				    "end's public half (%d characters of base64), "
				    "both or neither", id, PUB_B64);
				goto bad;
			}
			if (si != NULL) {
				snprintf(t->stamp_if, sizeof(t->stamp_if), "%s",
				    ucl_object_tostring(si));
				snprintf(t->stamp_peer, sizeof(t->stamp_peer),
				    "%s", pv);
				if (t->arcana)
					(void)stamp_key_get(t);
			}
		}
		s4 = (struct sockaddr_in *)&t->sa;
		s6 = (struct sockaddr_in6 *)&t->sa;
		if (inet_pton(AF_INET, addr, &s4->sin_addr) == 1) {
			t->af = AF_INET;
			s4->sin_family = AF_INET;
			s4->sin_len = sizeof(*s4);
		} else if (inet_pton(AF_INET6, addr, &s6->sin6_addr) == 1) {
			t->af = AF_INET6;
			s6->sin6_family = AF_INET6;
			s6->sin6_len = sizeof(*s6);
		} else {
			*errp = wfmt(w, "target %s: %s is not an address", id,
			    addr);
			goto bad;
		}
		bad = NULL;
		t->fib = (int)num(o, "fib", 0, 0, 65535, &bad);
		t->interval = (int)num(o, "interval", 100, 10, 60000, &bad);
		t->size = (int)num(o, "size", 64, 8, PKT_MAX, &bad);
		t->count = (int)num(o, "count", 0, 0, INT32_MAX, &bad);
		t->dscp = (int)num(o, "dscp", 0, 0, 63, &bad);
		t->down = (int)num(o, "down", 3, 1, 100, &bad);
		t->up = (int)num(o, "up", 3, 1, 100, &bad);
		t->timeout = (int)num(o, "timeout", 1000, 10, 60000, &bad);
		t->eval = (int)num(o, "eval", 1000, 100, 86400000, &bad);
		t->history = (int)num(o, "history", 3600, 0, SAMPLES_MAX, &bad);
		t->report = (int)num(o, "report", 1, 1, 1000, &bad);
		/* Its measurement intervals' three percentiles (RFC 9375's
		 * perf-mon; 0 for none). */
		{
			static const char *const pk[] = { "low_percentile",
			    "intermediate_percentile", "high_percentile" };
			static const double pd[] = { 10, 50, 90 };

			for (k = 0; k < 3; k++) {
				t->pct[k] = pd[k];
				if ((v = ucl_object_lookup(o, pk[k])) == NULL)
					continue;
				if ((ucl_object_type(v) != UCL_INT &&
				    ucl_object_type(v) != UCL_FLOAT) ||
				    ucl_object_todouble(v) < 0 ||
				    ucl_object_todouble(v) > 100) {
					*errp = wfmt(w, "target %s: %s is 0 to 100 "
					    "(0 for none)", id, pk[k]);
					goto bad;
				}
				t->pct[k] = ucl_object_todouble(v);
			}
		}
		t->pm_len = (int)num(o, "measurement_interval", PM_LEN, 1, 3600,
		    &bad);
		t->pm_prev[0] = t->pm_prev[1] = t->pm_prev[2] = -1;
		/* Thresholds: delay and ipdv in ms, loss a fraction. */
		{
			const ucl_object_t	*tc = ucl_object_lookup(o, "tca");

			t->tca[0] = tc != NULL ? ucl_object_todouble(
			    ucl_object_lookup(tc, "delay")) : 0;
			t->tca[1] = tc != NULL ? ucl_object_todouble(
			    ucl_object_lookup(tc, "ipdv")) : 0;
			t->tca[2] = tc != NULL ? ucl_object_todouble(
			    ucl_object_lookup(tc, "loss")) : 0;
			t->damping = tc != NULL ? (int)num(tc, "damping", 1, 1, 100,
			    &bad) : 1;
			if (t->tca[0] < 0 || t->tca[1] < 0 || t->tca[2] < 0 ||
			    t->tca[2] > 1)
				bad = "tca";
		}
		if (bad != NULL) {
			*errp = wfmt(w, "target %s: fib, interval (10-60000 ms), "
			    "size (8-%d), count, dscp (0-63), down and up "
			    "(1-100), timeout (10-60000 ms), eval (100 ms or "
			    "more), history (0-%d) and report (1-1000) are "
			    "numbers in those bounds; measurement_interval 1 to "
			    "3600 s", id, PKT_MAX, SAMPLES_MAX);
			goto bad;
		}
		n++;
		/* Its classes of service: a session each after it, with the
		 * class's DSCP, its own STAMP SSID or echo id, its own
		 * intervals. */
		if ((v = ucl_object_lookup(o, "classes")) != NULL) {
			const ucl_object_t	*c, *cn, *cd;
			ucl_object_iter_t	 cit = NULL;
			struct target		*x;
			const char		*nm;
			int			 pi = n - 1, ci = 0, d;

			if (ucl_object_type(v) != UCL_ARRAY || strcmp(owner,
			    OWN_SDWAN) != 0) {
				*errp = wfmt(w, "target %s: classes are an array "
				    "of {name, dscp}, a target's alone", id);
				goto bad;
			}
			while ((c = ucl_object_iterate(v, &cit, true)) != NULL) {
				cn = ucl_object_lookup(c, "name");
				cd = ucl_object_lookup(c, "dscp");
				nm = cn != NULL && ucl_object_type(cn) == UCL_STRING ?
				    ucl_object_tostring(cn) : NULL;
				d = cd != NULL && ucl_object_type(cd) == UCL_INT ?
				    (int)ucl_object_toint(cd) : -1;
				if (nm == NULL || nm[0] == '\0' || strlen(nm) >=
				    sizeof(t->cls) || strspn(nm, "ABCDEFGHIJKLMNOPQR"
				    "STUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
				    != strlen(nm) || d < 0 || d > 63) {
					*errp = wfmt(w, "target %s: a class is a name "
					    "(letters, digits, _ . -, 32 at most) and a "
					    "dscp (0-63)", id);
					goto bad;
				}
				if (d == new[pi].dscp) {
					*errp = wfmt(w, "target %s: class %s: dscp %d "
					    "is the target's own", id, nm, d);
					goto bad;
				}
				for (k = pi + 1; k < n; k++)
					if (strcmp(new[k].cls, nm) == 0 ||
					    new[k].dscp == d) {
						*errp = wfmt(w, "target %s: class %s: its "
						    "name or dscp is another class's", id,
						    nm);
						goto bad;
					}
				if (++ci > CLASSES_MAX || n == TARGETS_MAX) {
					*errp = wfmt(w, "target %s: %d classes at "
					    "most, %d targets and classes in all", id,
					    CLASSES_MAX, TARGETS_MAX);
					goto bad;
				}
				x = &new[n++];
				*x = new[pi];
				snprintf(x->cls, sizeof(x->cls), "%s", nm);
				x->cls_idx = ci;
				x->dscp = d;
				/* Its key's SSID its own: derived anew. */
				explicit_bzero(&x->key, sizeof(x->key));
				x->keyed = false;
				if (x->stamp_peer[0] != '\0' && x->arcana)
					(void)stamp_key_get(x);
			}
		}
	}
	ucl_object_unref(top);
	return (n);
bad:
	ucl_object_unref(top);
	/* The keys derived so far not left in what the caller frees. */
	explicit_bzero(new, TARGETS_MAX * sizeof(*new));
	return (-1);
}

/* New targets (n of them) given up before they were probed: their keys
 * zeroed, then freed. */
void
targets_drop(struct target *new, int n)
{

	while (n-- > 0)
		target_free(&new[n]);
	explicit_bzero(new, TARGETS_MAX * sizeof(*new));
	free(new);
}

/*
 * By the table's owner: an echo id that no target of v (n of them) of
 * family af has, from one counter that starts at random; never 0, which
 * marks a target that has none yet.
 */
static uint16_t
ident_alloc(const struct target *v, int n, int af)
{
	static uint16_t	next;
	static bool	seeded;
	uint16_t	id;
	int		i, tries;

	if (!seeded) {
		next = (uint16_t)arc4random();
		seeded = true;
	}
	for (tries = 0; tries < 65536; tries++) {
		if ((id = next++) == 0)
			continue;
		for (i = 0; i < n && (v[i].ident != id || v[i].af != af); i++)
			;
		if (i == n)
			return (id);
	}
	/* Not reached: TARGETS_MAX are far fewer than the ids. */
	return (next++);
}

/*
 * By the table's owner (tab, ntab targets), once the kept targets are
 * read: what the prober watches told to faults.c (fault_reconcile()),
 * each target's, so that the faults of one gone, or of a threshold
 * taken away, are cleared; what of them is still open taken up, a
 * threshold's alert and a fall back's alarm, to be cleared when its
 * cause is.  The links' are probe_link.c's.
 */
void
probe_reconcile(struct target *tab, int ntab)
{
	static const char *const mn[] = { "delay", "ipdv", "loss" };
	struct fault_live	*v;
	struct target		*t;
	char			*nm, name[TNAME_MAX];
	int			*who, max, n, i, m;

	max = ntab * 5 + 1;
	v = calloc((size_t)max, sizeof(*v));
	nm = calloc((size_t)max, TOBJ_MAX);
	who = calloc((size_t)max, sizeof(*who));
	if (v == NULL || nm == NULL || who == NULL) {
		logmsg(LOG_WARNING, "probe: no memory to hold the faults to the "
		    "targets");
		goto out;
	}
	n = 0;
	for (i = 0; i < ntab; i++) {
		t = &tab[i];
		/* A class's session and a monitor raise none. */
		if (t->id[0] == '\0' || t->cls[0] != '\0' || is_monitor(t))
			continue;
		target_name(t, name, sizeof(name));
		snprintf(&nm[n * TOBJ_MAX], TOBJ_MAX, "%s", name);
		v[n].type = t->underlay ? "underlay" : "tunnel";
		v[n].object = &nm[n * TOBJ_MAX];
		v[n].well = t->state == ST_UP;
		v[n].reason = "it answers again";
		who[n++] = i * 8;
		if (t->arcana && t->stamp_peer[0] != '\0') {
			snprintf(&nm[n * TOBJ_MAX], TOBJ_MAX, "%s", name);
			v[n].type = "stamp-unauthenticated";
			v[n].object = &nm[n * TOBJ_MAX];
			who[n++] = i * 8 + 1;
		}
		for (m = 0; m < 3; m++) {
			if (t->tca[m] <= 0)
				continue;
			snprintf(&nm[n * TOBJ_MAX], TOBJ_MAX, "%s/%s", name, mn[m]);
			v[n].type = "tca";
			v[n].object = &nm[n * TOBJ_MAX];
			who[n++] = i * 8 + 2 + m;
		}
	}
	(void)fault_reconcile("probe", NULL, NULL, v, (size_t)n,
	    "no longer measured");
	for (i = 0; i < n; i++) {
		t = &tab[who[i] / 8];
		if (who[i] % 8 == 1)
			t->downgraded = v[i].open;
		else if (who[i] % 8 >= 2)
			t->tca_on[who[i] % 8 - 2] = v[i].open;
	}
out:
	free(v);
	free(nm);
	free(who);
}

/*
 * By the table's owner (*tab, *ntab targets): the new targets in the
 * place of the old ones of their edge (jail, "" the host): one that is
 * the same target (address, fib, dscp, size, kind) keeps its socket,
 * state, samples and echo id; the other edges' stay as they are, after
 * them; a new one has an echo id of its own.  False, with nothing
 * changed, when all of them are more than TARGETS_MAX (new has room for
 * that many).
 */
bool
targets_swap(struct target **tab, int *ntab, struct target *new, int n,
    const char *jail, const char *owner)
{
	static uint64_t	 serial;
	struct target	*old, *t, *o;
	bool		 fresh[TARGETS_MAX];
	int		 nold, i, k, total, nnew;
	double		 now;

	old = *tab;
	nold = *ntab;
	total = n;
	for (k = 0; k < nold; k++)
		if (strcmp(old[k].jail, jail) != 0 || strcmp(old[k].owner,
		    owner) != 0)
			total++;
	if (total > TARGETS_MAX)
		return (false);
	now = now_s();
	nnew = n;
	for (i = 0; i < n; i++) {
		t = &new[i];
		fresh[i] = false;
		for (k = 0; k < nold; k++) {
			o = &old[k];
			if (o->id[0] != '\0' && strcmp(o->jail, jail) == 0 &&
			    strcmp(o->owner, owner) == 0 &&
			    strcmp(o->id, t->id) == 0 &&
			    strcmp(o->address, t->address) == 0 && o->fib ==
			    t->fib && o->dscp == t->dscp && o->size == t->size &&
			    o->kind == t->kind && strcmp(o->cls, t->cls) == 0)
				break;
		}
		if (k < nold) {
			int	iv = t->interval, cnt = t->count, dn = t->down;
			int	up = t->up, to = t->timeout, ev = t->eval;
			int	hi = t->history, rp = t->report, dm = t->damping;
			int	pl = t->pm_len;
			double	pc[3] = { t->pct[0], t->pct[1], t->pct[2] };
			char	ifn[IFNAMSIZ], sif[IFNAMSIZ], spe[PUB_B64 + 1];
			char	kerr[sizeof(t->key_err)];
			struct stamp_key nk = t->key;
			bool	kd = t->keyed;

			snprintf(ifn, sizeof(ifn), "%s", t->ifname);
			snprintf(sif, sizeof(sif), "%s", t->stamp_if);
			snprintf(spe, sizeof(spe), "%s", t->stamp_peer);
			snprintf(kerr, sizeof(kerr), "%s", t->key_err);
			double	tc[3] = { t->tca[0], t->tca[1], t->tca[2] };

			/* As it was, with what may change under it; its STAMP
			 * sender made again for another timeout or interval. */
			*t = *o;
			if (t->interval != iv || t->timeout != to)
				stamp_drop(t);
			memcpy(t->tca, tc, sizeof(tc));
			t->damping = dm;
			memset(o, 0, sizeof(*o));
			o->sock = -1;
			o->usock = -1;
			t->interval = iv;
			t->count = cnt;
			t->down = dn;
			t->up = up;
			t->timeout = to;
			t->eval = ev;
			t->report = rp;
			snprintf(t->ifname, sizeof(t->ifname), "%s", ifn);
			/* Its STAMP key as the new one says: its sender made
			 * again under another, or none. */
			if (kd != t->keyed || strcmp(sif, t->stamp_if) != 0 ||
			    strcmp(spe, t->stamp_peer) != 0 || (kd &&
			    memcmp(&nk, &t->key, sizeof(nk)) != 0))
				stamp_drop(t);
			t->key = nk;
			t->keyed = kd;
			snprintf(t->stamp_if, sizeof(t->stamp_if), "%s", sif);
			snprintf(t->stamp_peer, sizeof(t->stamp_peer), "%s", spe);
			snprintf(t->key_err, sizeof(t->key_err), "%s", kerr);
			explicit_bzero(&nk, sizeof(nk));
			/* Its key as derived where it was parsed: one the worker
			 * was asked for is no longer waited for. */
			t->key_pending = t->key_failed = t->rekeying = false;
			t->key_gen++;
			explicit_bzero(&t->was, sizeof(t->was));
			/* Other percentiles or another length: the intervals
			 * begun again. */
			if (t->pm_len != pl || memcmp(t->pct, pc, sizeof(pc)) !=
			    0) {
				pm_forget(t);
				t->pm_len = pl;
				memcpy(t->pct, pc, sizeof(pc));
			}
			if (t->history != hi) {
				samples_reset(t);
				t->history = hi;
			}
			if (t->state == ST_ENDED && cnt == 0) {
				t->next_send = now;
				state_set(t, ST_UNKNOWN);
			}
			continue;
		}
		fresh[i] = true;
		t->serial = ++serial;
		t->ident = 0;
		t->ssid = (uint16_t)arc4random();
		t->since = time(NULL);
		t->win_start = now;
		t->next_send = now;
		/* A fall back's alarm an agent before this one left open (the
		 * faults are kept across a restart) is taken up by
		 * probe_reconcile(), cleared by its first authenticated
		 * answer. */
		t->downgraded = false;
		/* A jail's socket the engine has its worker make. */
		t->state = ST_UNKNOWN;
		if (t->jail[0] == '\0' && !target_open(t)) {
			t->state = ST_ERROR;
			open_later(t, now);
		}
	}
	/* The other edges' and owners', moved over as they are; not those
	 * kept above, emptied (their id ""), which would come back as a
	 * target of no id nor address, in FIB 0, faulted for no answer. */
	for (k = 0; k < nold; k++)
		if (old[k].id[0] != '\0' && (strcmp(old[k].jail, jail) != 0 ||
		    strcmp(old[k].owner, owner) != 0)) {
			new[n++] = old[k];
			memset(&old[k], 0, sizeof(old[k]));
			old[k].sock = -1;
			old[k].usock = -1;
		}
	/* Each new one's echo id, its own among them all. */
	for (i = 0; i < nnew; i++)
		if (fresh[i]) {
			char	name[TNAME_MAX];

			new[i].ident = ident_alloc(new, n, new[i].af);
			logmsg(LOG_DEBUG, "probe: %s (%s): echo id %u",
			    target_name(&new[i], name, sizeof(name)),
			    new[i].address, new[i].ident);
		}
	*tab = new;
	*ntab = n;
	for (k = 0; k < nold; k++)
		target_free(&old[k]);
	free(old);
	return (true);
}

int
conf_write(const char *json, const char *jail, const char *owner,
    const char **errp)
{
	char	path[MAXPATHLEN], tmp[MAXPATHLEN];
	FILE	*fp;

	conf_path(path, sizeof(path), jail, owner);
	/* Its directory, where the host has none yet. */
	if (strrchr(path, '/') != NULL) {
		snprintf(tmp, sizeof(tmp), "%.*s", (int)(strrchr(path, '/') -
		    path), path);
		(void)mkdir_mode(tmp, 0755);
	}
	snprintf(tmp, sizeof(tmp), "%s.new", path);
	if ((fp = fopen(tmp, "we")) == NULL || fputs(json, fp) == EOF ||
	    fclose(fp) != 0 || rename(tmp, path) == -1) {
		*errp = strerror(errno);
		if (fp != NULL)
			fclose(fp);
		unlink(tmp);
		return (-1);
	}
	return (0);
}

/* The targets set: checked, kept, and probed from now on. */
int
do_probes_set(struct work *w, const char *json, const char **errp)
{
	struct target	*new;
	int		 n, step;
	const char	*e;
	char		 path[MAXPATHLEN], jail[64];

	if ((new = calloc(TARGETS_MAX, sizeof(*new))) == NULL) {
		*errp = strerror(errno);
		return (-1);
	}
	if ((n = targets_parse(w, json, new, jail, sizeof(jail), OWN_SDWAN,
	    errp)) < 0) {
		free(new);
		return (-1);
	}
	if (!engine_swap(new, n, jail, OWN_SDWAN)) {
		*errp = wfmt(w, "%d targets at most, all edges' together",
		    TARGETS_MAX);
		targets_drop(new, n);
		return (-1);
	}
	if (links_set(w, json, jail, errp) != 0)
		return (-1);
	step = step_begin(w, STEP_FILE, "write", "%s", conf_path(path,
	    sizeof(path), jail, OWN_SDWAN));
	e = NULL;
	/* None left: no file, so that a start makes no edge of it. */
	if (n == 0 && jail[0] != '\0' && !has_links(json) ? unlink(path) ==
	    -1 && errno != ENOENT &&
	    (e = strerror(errno)) != NULL : conf_write(json, jail, OWN_SDWAN,
	    &e) != 0) {
		step_end(w, step, false, "%s", e);
		*errp = wfmt(w, "%s: %s", path, e);
		return (-1);
	}
	step_end(w, step, true, "%d target%s", n, n == 1 ? "" : "s");
	return (0);
}

/* An edge's kept targets, an owner's, probed again. */
static void
start_file(const char *path, const char *owner)
{
	struct work	 w;
	struct target	*new;
	const char	*e;
	char		*json, jail[64];
	FILE		*fp;
	long		 len;
	int		 n;

	if ((fp = fopen(path, "re")) == NULL)
		return;
	if (fseek(fp, 0, SEEK_END) == 0 && (len = ftell(fp)) > 0 &&
	    len < 4 * 1024 * 1024 && (json = malloc((size_t)len + 1)) != NULL) {
		rewind(fp);
		json[fread(json, 1, (size_t)len, fp)] = '\0';
		work_init(&w);
		new = calloc(TARGETS_MAX, sizeof(*new));
		e = NULL;
		if (new != NULL && (n = targets_parse(&w, json, new, jail,
		    sizeof(jail), owner, &e)) >= 0) {
			if (!engine_swap(new, n, jail, owner)) {
				logmsg(LOG_WARNING, "%s: more than %d targets",
				    path, TARGETS_MAX);
				targets_drop(new, n);
			} else if (strcmp(owner, OWN_SDWAN) == 0 &&
			    links_set(&w, json, jail, &e) != 0)
				logmsg(LOG_WARNING, "%s: %s", path, e);
		} else {
			logmsg(LOG_WARNING, "%s: %s", path, e != NULL ? e :
			    "not read");
			free(new);
		}
		work_free(&w);
		free(json);
	}
	fclose(fp);
}

/*
 * At the start: the targets kept, probed; the faults held to them; the
 * engine's thread, theirs from then on.
 */
void
probe_start(void)
{
	struct dirent	*de;
	DIR		*d;
	char		 path[MAXPATHLEN], *slash;

	engine_begin();
	/* The host's, and each jail's beside it; the monitors likewise. */
	start_file(conf_path(path, sizeof(path), NULL, OWN_MONITOR),
	    OWN_MONITOR);
	start_file(conf_path(path, sizeof(path), NULL, OWN_SDWAN), OWN_SDWAN);
	if ((slash = strrchr(path, '/')) != NULL)
		*slash = '\0';
	else
		snprintf(path, sizeof(path), ".");
	if ((d = opendir(path)) != NULL) {
		char	f[MAXPATHLEN];

		while ((de = readdir(d)) != NULL)
			if (strncmp(de->d_name, "sdwan-probes@", 13) == 0) {
				snprintf(f, sizeof(f), "%s/%s", path, de->d_name);
				start_file(f, OWN_SDWAN);
			} else if (strncmp(de->d_name, "monitors@", 9) == 0) {
				snprintf(f, sizeof(f), "%s/%s", path, de->d_name);
				start_file(f, OWN_MONITOR);
			}
		closedir(d);
	}
	/* All of them read: the faults held to them from now on, those of
	 * targets and links no longer kept cleared, the others taken up. */
	engine_watch();
	links_watch();
	engine_start();
}
