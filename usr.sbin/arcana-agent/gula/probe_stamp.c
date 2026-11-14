/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula, a target measured by STAMP (RFC 8762) through libstamp's sender
 * (the submodule stamp/): its UDP socket in the target's FIB, connected
 * to the far end's stampd(8), on the target's schedule; the replies'
 * round trip, loss each way, delay each way, DSCP each way, Location and
 * Direct Measurement as probe.c's head comment tells.  ICMP is auto's
 * fallback: a reflector that refuses, or as many STAMP probes
 * unanswered in a row as make the target down, and it is pinged, one
 * STAMP try every STAMP_RETRY seconds bringing it back; kind stamp has
 * none, its probes misses.
 *
 * A plain tunnel's key (HKDF-SHA256 of its interface's X25519 pair and
 * the far end's half, salted STAMP_SALT) is derived where its target is
 * parsed, on the thread that asked, and again on the engine's worker
 * (probe_engine.c): never on the engine's thread, which reads no file
 * and computes no X25519.  Until the worker answers, a probe that needs
 * the key waits (stamp_send_one()'s -1), not counted; the answer is
 * told to the target (stamp_key_told()) as the engine takes it.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"
#include "stamp.h"
#include "probe_int.h"

#define	STAMP_WINDOW	4096	/* STAMP probes in the air, at most */
#define	STAMP_SALT	"arcana stamp v1"	/* HKDF's, the key's */

/* The STAMP sender given up, its socket kept: its counts from 0. */
void
stamp_drop(struct target *t)
{
	struct stamp_sender_stats	st;

	if (t->ss != NULL) {
		stamp_sender_stats(t->ss, &st);
		t->auth_failed += st.auth_failed;
		t->st_sent += st.sent;
		t->st_recv += st.received;
		t->st_lost += st.lost;
		t->st_unknown += st.unknown_lost;
		t->st_late += st.late;
		/* The loss each way not yet taken by a window's end. */
		t->fwd_lost += st.fwd_lost - t->tk_fwd;
		t->back_lost += st.back_lost - t->tk_back;
		if (st.dm_told) {
			t->dm_fwd_lost += st.dm_fwd_lost - t->tk_dmf;
			t->dm_back_lost += st.dm_back_lost - t->tk_dmb;
			t->dm_told = true;
		}
	}
	stamp_sender_free(t->ss);
	t->ss = NULL;
	t->tk_fwd = t->tk_back = 0;
	t->tk_dmf = t->tk_dmb = 0;
}

/*
 * A plain tunnel's STAMP key: HKDF-SHA256 of the agreement of its
 * interface's pair (ifname's) with the far end's public half (peer), 32
 * octets of key and 2 of SSID (0 taken as 1), the same at both ends; a
 * class's (cls, its place) an SSID of its own.  0, or -1 and why in err.
 * A file read and an X25519: never on the engine's thread.
 */
int
stamp_key_derive(const char *ifname, const char *peer, int cls,
    struct stamp_key *key, char *err, size_t len)
{
	unsigned char	 okm[34];
	struct work	 w;
	const char	*e = NULL;
	int		 rc;

	work_init(&w);
	rc = tunnel_key_derive(&w, ifname, peer, STAMP_SALT, okm, sizeof(okm),
	    &e);
	if (rc != 0)
		snprintf(err, len, "%s", e != NULL ? e : "not derived");
	work_free(&w);
	if (rc != 0)
		return (-1);
	memset(key, 0, sizeof(*key));
	memcpy(key->key, okm, 32);
	key->len = 32;
	key->ssid = okm[32] << 8 | okm[33];
	/* A class's session: an SSID of its own, the same at both ends
	 * (both have the service's classes in the same order). */
	key->ssid = (key->ssid + cls) & 0xffff;
	if (key->ssid == 0)
		key->ssid = 1;
	explicit_bzero(okm, sizeof(okm));
	return (0);
}

/* Why its key is not derived, said when it is not what it was. */
static void
stamp_key_said(struct target *t, const char *why)
{

	if (strcmp(t->key_err, why) == 0)
		return;
	snprintf(t->key_err, sizeof(t->key_err), "%s", why);
	logmsg(LOG_WARNING, "probe: %s (%s): no STAMP key: %s", t->id,
	    t->address, t->key_err);
}

/* Its key derived now, where it is parsed (not the engine's thread):
 * true, keyed; false and why in key_err (said once). */
bool
stamp_key_get(struct target *t)
{
	struct stamp_key	k;
	char			why[sizeof(t->key_err)];

	if (t->stamp_peer[0] == '\0' || t->keyed)
		return (t->keyed);
	if (stamp_key_derive(t->stamp_if, t->stamp_peer, t->cls_idx, &k, why,
	    sizeof(why)) != 0) {
		stamp_key_said(t, why);
		return (false);
	}
	t->key = k;
	explicit_bzero(&k, sizeof(k));
	t->keyed = true;
	t->key_err[0] = '\0';
	return (true);
}

/*
 * The worker's answer to its key asked for (ok, key; else why): keyed,
 * the reflector's copy following (stampd's, probe_stamp_keys()); not,
 * and the next STAMP probe told so.  Derived anew (rekeying): another
 * key, or none, is stampd's to know, and said.
 */
void
stamp_key_told(struct target *t, bool ok, const struct stamp_key *key,
    const char *why)
{

	t->key_pending = false;
	if (ok) {
		t->key = *key;
		t->keyed = true;
		t->key_err[0] = '\0';
	} else {
		stamp_key_said(t, why);
		t->keyed = false;
		t->key_failed = true;
	}
	engine_dirty();
	if (!t->rekeying) {
		/* The reflector's copy, stampd's. */
		if (ok)
			stampd_nudge();
		return;
	}
	t->rekeying = false;
	if (!t->keyed || memcmp(&t->was, &t->key, sizeof(t->was)) != 0) {
		if (t->keyed)
			logmsg(LOG_NOTICE, "probe: %s (%s): STAMP key derived "
			    "anew: %s's pair or the far end's half is another",
			    t->id, t->address, t->stamp_if);
		stampd_nudge();
	}
	explicit_bzero(&t->was, sizeof(t->was));
}

/*
 * A key that brought no authenticated answer given up, the sender under
 * it with it, and derived anew from the interface's pair as it is now
 * and the far end's half as the target has it: a pair made again at
 * this end works without an apply.  By the worker: the probes that need
 * it wait for its answer.
 */
void
stamp_rekey(struct target *t)
{

	if (!t->keyed)
		return;
	t->was = t->key;
	stamp_drop(t);
	explicit_bzero(&t->key, sizeof(t->key));
	t->keyed = false;
	t->rekeying = true;
	engine_key(t);
}

/* An address and port as "a port p" ("-" not said). */
const char *
addr_port(const struct sockaddr_storage *ss, char *buf, size_t len)
{
	char	a[INET6_ADDRSTRLEN];

	if (ss->ss_family == 0)
		snprintf(buf, len, "-");
	else
		snprintf(buf, len, "%s port %u", stamp_sa_ntop((const struct
		    sockaddr *)ss, a, sizeof(a)), stamp_sa_port((const struct
		    sockaddr *)ss));
	return (buf);
}

/*
 * Its UDP socket, in its FIB, connected to the far end's reflector;
 * its sender, the timeout and the interval the target's.  1; 0 and why
 * in errno; -1, its key asked of the worker and not yet told.
 */
static int
stamp_open(struct target *t)
{
	struct stamp_sender_conf	c;
	struct sockaddr_storage		to;
	int				v;

	/* --stamp-port 0: no reflector to send to (kind stamp's). */
	if (opts.stamp_port == 0) {
		errno = EDESTADDRREQ;
		return (0);
	}
	/* A plain tunnel's: its key first, derived now if not yet. */
	if (t->stamp_peer[0] != '\0' && !t->keyed) {
		if (t->key_failed) {
			t->key_failed = false;
			errno = ENOENT;
			return (0);
		}
		if (!t->key_pending)
			engine_key(t);
		return (-1);
	}
	if (t->usock == -1) {
		if ((t->usock = stamp_socket_fib(t->af, 0, STAMP_SOCK_MONOTONIC,
		    t->fib)) == -1)
			return (0);
		to = t->sa;
		if (to.ss_family == AF_INET)
			((struct sockaddr_in *)(void *)&to)->sin_port =
			    htons((uint16_t)opts.stamp_port);
		else
			((struct sockaddr_in6 *)(void *)&to)->sin6_port =
			    htons((uint16_t)opts.stamp_port);
		v = t->dscp << 2;
		if (t->af == AF_INET)
			(void)setsockopt(t->usock, IPPROTO_IP, IP_TOS, &v,
			    sizeof(v));
		else
			(void)setsockopt(t->usock, IPPROTO_IPV6, IPV6_TCLASS, &v,
			    sizeof(v));
		if (connect(t->usock, (struct sockaddr *)&to, to.ss_len) == -1) {
			close(t->usock);
			t->usock = -1;
			return (0);
		}
	}
	if (t->ss == NULL) {
		memset(&c, 0, sizeof(c));
		c.ssid = t->keyed ? (uint16_t)t->key.ssid : t->ssid;
		c.key = t->keyed ? &t->key : NULL;
		c.tsinfo = true;
		c.cos = true;
		c.dscp = (uint8_t)t->dscp;
		c.dm = true;
		c.location = true;
		c.timeout = t->timeout / 1000.0;
		c.window = (unsigned)(t->timeout / t->interval + 2);
		if (c.window > STAMP_WINDOW)
			c.window = STAMP_WINDOW;
		t->tk_fwd = t->tk_back = 0;
		if ((t->ss = stamp_sender_new(&c)) == NULL)
			return (0);
	}
	return (1);
}

/* No STAMP from the far end (why): pinged instead, STAMP tried again
 * every STAMP_RETRY seconds.  Said when it was measured by STAMP. */
static void
stamp_fallback(struct target *t, double now, const char *why)
{
	char	name[TNAME_MAX];

	/* Kind stamp: no fallback, its probes misses; why said once. */
	if (t->kind == KIND_STAMP) {
		if (strcmp(t->stamp_why, why) != 0)
			logmsg(LOG_NOTICE, "probe: %s (%s): %s: STAMP alone, "
			    "no fallback", target_name(t, name, sizeof(name)),
			    t->address, why);
		snprintf(t->stamp_why, sizeof(t->stamp_why), "%s", why);
		return;
	}
	stamp_drop(t);
	t->stamp_retry = now + STAMP_RETRY;
	if (!t->by_stamp)
		return;
	t->by_stamp = false;
	t->fallbacks++;
	/* The readers' copy at once: the alarm below says what it shows. */
	engine_dirty();
	snprintf(t->stamp_why, sizeof(t->stamp_why), "%s", why);
	logmsg(LOG_NOTICE, "probe: %s (%s): %s: pinged until STAMP answers",
	    target_name(t, name, sizeof(name)), t->address, why);
	/* A plain tunnel's: measured unauthenticated now, which one on the
	 * path can force (its STAMP dropped or spoiled, a port unreachable
	 * forged): an alarm, until authenticated STAMP answers again.  A
	 * class's session raises none, as for its state. */
	if (t->stamp_peer[0] != '\0' && t->cls[0] == '\0') {
		t->downgraded = true;
		fault_set("stamp-unauthenticated", "Warning", name, "probe",
		    "authenticated STAMP to %s in FIB %d fell back to ICMP "
		    "echo, unauthenticated: %s", t->address, t->fib, why);
	}
}

/* Authenticated STAMP answers: the alarm of its fall back cleared. */
static void
stamp_auth_back(struct target *t)
{
	char	name[TNAME_MAX];

	if (!t->downgraded)
		return;
	t->downgraded = false;
	fault_clear("stamp-unauthenticated", target_name(t, name,
	    sizeof(name)), "authenticated STAMP from %s answers again",
	    t->address);
}

/* A STAMP probe lost: a miss, unless it would make the target down,
 * which the first echo decides instead (the reflector may be all that
 * is gone). */
void
stamp_lost(struct target *t, double now)
{
	struct stamp_sender_stats	st;
	char				why[128];

	/* Kind stamp: a miss whatever, down at down in a row. */
	if (t->misses + 1 < t->down || t->kind == KIND_STAMP) {
		miss(t);
		if (t->misses < t->down)
			return;
	} else {
		t->w_sent++;
		t->pm_sent++;
		t->hits = 0;
		t->misses = t->down - 1;
	}
	if (t->ss != NULL)
		stamp_sender_stats(t->ss, &st);
	/* Replies that came and did not authenticate: said so. */
	if (t->keyed && t->ss != NULL && st.auth_failed > 0)
		snprintf(why, sizeof(why), "no authenticated STAMP reply in %d "
		    "probes, %ju failing authentication", t->down,
		    (uintmax_t)st.auth_failed);
	else
		snprintf(why, sizeof(why), "no STAMP reply in %d probes",
		    t->down);
	/* Kind stamp, no try to come: its key derived anew here, every
	 * STAMP_RETRY seconds while it is down (auto's at each try). */
	if (t->kind == KIND_STAMP && t->keyed && now >= t->rekey_at) {
		t->rekey_at = now + STAMP_RETRY;
		stamp_rekey(t);
	}
	stamp_fallback(t, now, why);
	if (t->kind != KIND_STAMP)
		t->next_send = now;
}

/*
 * A STAMP probe: one of the target's (counted), or a fallen-back
 * target's try (not).  1 one went; 0 none; -1 none yet, its key asked
 * of the worker: the probe waits for it, not counted.
 */
int
stamp_send_one(struct target *t, bool counted)
{
	unsigned char		pkt[PKT_MAX];
	struct stamp_sample	sm;
	struct timespec		t1;
	size_t			len;
	double			now;
	int			rc;

	now = now_s();
	/* Kind stamp without its key: tried again every STAMP_RETRY
	 * seconds, not every probe; the probes between misses. */
	if (t->kind == KIND_STAMP && t->stamp_peer[0] != '\0' && !t->keyed &&
	    now < t->stamp_retry) {
		if (counted) {
			t->sent++;
			miss(t);
		}
		return (0);
	}
	if ((rc = stamp_open(t)) != 1) {
		if (rc == -1)
			return (-1);
		if (counted && t->stamp_peer[0] != '\0' && !t->keyed) {
			char	why[200];

			snprintf(why, sizeof(why), "no STAMP key: %s",
			    t->key_err);
			stamp_fallback(t, now, why);
			t->stamp_retry = now + STAMP_RETRY;
		} else if (counted)
			stamp_fallback(t, now, strerror(errno));
		/* Kind stamp: a probe that could not go is a miss. */
		if (counted && t->kind == KIND_STAMP) {
			t->sent++;
			miss(t);
		}
		return (0);
	}
	/* The base, the Timestamp Information TLV, the rest padding. */
	len = stamp_sender_len(t->ss, t->size > 0 ? (size_t)t->size : 0);
	if (len > sizeof(pkt))
		len = sizeof(pkt);
	memset(pkt, 0, len);
	clock_gettime(CLOCK_REALTIME, &t1);
	now = now_s();
	if ((rc = stamp_sender_packet(t->ss, pkt, len, &t1, now, &sm)) == -1)
		return (0);
	if (rc == 1 && counted)
		stamp_lost(t, now);
	if (!t->by_stamp && counted)
		return (0);
	if (counted)
		t->sent++;
	if (send(t->usock, pkt, len, 0) == -1) {
		/* Port unreachable: no reflector there. */
		if (errno == ECONNREFUSED) {
			t->refused++;
			if (counted)
				stamp_fallback(t, now, "its STAMP port refused");
			return (0);
		}
		if (counted)
			snprintf(t->error, sizeof(t->error), "send: %s",
			    strerror(errno));
	} else if (counted)
		t->error[0] = '\0';
	return (1);
}

/* A STAMP reply's delay each way, into the interval and the last. */
static void
stamp_delay(struct target *t, const struct stamp_sample *sm)
{

	t->last_dfwd = sm->fwd * 1000;
	t->last_dback = sm->back * 1000;
	t->last_err = sm->err * 1000;
	t->last_owd = sm->owd;
	t->has_delay = true;
	if (sm->owd) {
		t->w_owd_n++;
		t->w_dfwd += t->last_dfwd;
		t->w_dback += t->last_dback;
	} else
		t->w_est_n++;
	t->has_ti = sm->has_tsinfo;
	if (sm->has_tsinfo)
		t->ti = sm->tsinfo;
}

/* A STAMP reply's DSCP each way: the probe's at the reflector, by its
 * Class of Service TLV; the reply's here, as it came (tos -1: not
 * said). */
static void
stamp_dscp(struct target *t, const struct stamp_sample *sm, int tos)
{

	t->has_cos = sm->has_cos;
	if (sm->has_cos) {
		t->dscp_fwd = sm->cos.dscp2;
		t->dscp_refused = sm->cos.rp != 0;
	}
	t->has_rtos = tos >= 0;
	if (tos >= 0)
		t->dscp_back = tos >> 2;
}

/* A STAMP reply's Location TLV: the source and destination the far end
 * saw, against the socket's own address and port and the target's. */
static void
stamp_where(struct target *t, const struct stamp_sample *sm)
{
	struct sockaddr_storage	self, far;
	socklen_t		slen = sizeof(self);

	if (!sm->has_loc)
		return;
	t->has_loc = true;
	t->loc = sm->loc;
	far = t->sa;
	if (far.ss_family == AF_INET)
		((struct sockaddr_in *)(void *)&far)->sin_port =
		    htons((uint16_t)opts.stamp_port);
	else
		((struct sockaddr_in6 *)(void *)&far)->sin6_port =
		    htons((uint16_t)opts.stamp_port);
	/* Connected: the socket's address is the one it sends from. */
	if (getsockname(t->usock, (struct sockaddr *)&self, &slen) == -1)
		t->nat = stamp_location_nat(&sm->loc, NULL,
		    (struct sockaddr *)&far);
	else
		t->nat = stamp_location_nat(&sm->loc, (struct sockaddr *)&self,
		    (struct sockaddr *)&far);
}

/* The replies to the target's STAMP probes: hits; to a fallen-back
 * target's try, STAMP again. */
void
stamp_recv_all(struct target *t)
{
	unsigned char		in[PKT_MAX + 64];
	struct stamp_rxinfo	ri;
	struct stamp_sample	sm;
	char			name[TNAME_MAX];
	ssize_t			n;
	double			at;

	for (;;) {
		if ((n = stamp_recv(t->usock, in, sizeof(in), &ri)) == -1) {
			if (errno == ECONNREFUSED) {
				t->refused++;
				if (t->by_stamp)
					stamp_fallback(t, now_s(), "its STAMP port "
					    "refused");
				continue;
			}
			return;
		}
		if (t->ss == NULL)
			continue;
		at = (double)ri.mono.tv_sec + (double)ri.mono.tv_nsec / 1e9;
		if (stamp_sender_reply(t->ss, in, (size_t)n, at, &ri.t,
		    &sm) != 1)
			continue;
		if (t->by_stamp) {
			/* Answered: no reason against STAMP now. */
			if (t->stamp_why[0] != '\0' && t->kind == KIND_STAMP)
				logmsg(LOG_NOTICE, "probe: %s (%s): STAMP answers "
				    "again", target_name(t, name, sizeof(name)),
				    t->address);
			t->stamp_why[0] = '\0';
			stamp_auth_back(t);
			hit(t, sm.rtt * 1000);
			pm_hit(t, sm.rtt * 1000, &sm);
			stamp_delay(t, &sm);
			stamp_dscp(t, &sm, ri.tos);
			stamp_where(t, &sm);
			continue;
		}
		/* Measured by STAMP again, by a sender of its own: the try's
		 * counts are none of the target's; no echo in the air. */
		t->by_stamp = true;
		t->stamp_why[0] = '\0';
		engine_dirty();
		stamp_drop(t);
		for (int i = 0; i < OUT_MAX; i++)
			t->out[i].live = false;
		logmsg(LOG_NOTICE, "probe: %s (%s): STAMP answers again",
		    target_name(t, name, sizeof(name)), t->address);
		stamp_auth_back(t);
	}
}

/*
 * An eval interval's end, of a target measured by STAMP: the loss each
 * way into its sample s, told by a stateful reflector's counter (a loss
 * is told once the reply after it is in, so the counts trail the
 * samples by up to a timeout), and by the Direct Measurement counters;
 * what the reflector and the path said, logged for -d.
 */
void
stamp_window(struct target *t, struct sample *s)
{
	struct stamp_sender_stats	st;
	char				name[TNAME_MAX], ti[48];
	char				dsf[8], dsb[8], src[64], dst[64];
	char				nat[48], dm[64];
	uint64_t			df, db;

	stamp_sender_stats(t->ss, &st);
	df = st.fwd_lost - t->tk_fwd;
	db = st.back_lost - t->tk_back;
	t->tk_fwd = st.fwd_lost;
	t->tk_back = st.back_lost;
	t->fwd_lost += df;
	t->back_lost += db;
	if (st.mode == STAMP_MODE_STATEFUL && t->w_sent > 0) {
		s->fwd = (double)df / t->w_sent;
		s->back = (double)db / t->w_sent;
	}
	/* The same by the Direct Measurement counters. */
	if (st.dm_told) {
		t->dm_fwd_lost += st.dm_fwd_lost - t->tk_dmf;
		t->dm_back_lost += st.dm_back_lost - t->tk_dmb;
		t->tk_dmf = st.dm_fwd_lost;
		t->tk_dmb = st.dm_back_lost;
		t->dm_told = true;
	}
	if (t->has_ti)
		snprintf(ti, sizeof(ti), "%s/%s,%s/%s",
		    stamp_sync_name(t->ti.sync_in),
		    stamp_tsm_name(t->ti.ts_in),
		    stamp_sync_name(t->ti.sync_out),
		    stamp_tsm_name(t->ti.ts_out));
	else
		snprintf(ti, sizeof(ti), "-");
	logmsg(LOG_DEBUG, "probe: %s: stamp (%s reflector): sent %d, "
	    "received %d; lost forward %ju, backward %ju all along; "
	    "delay forward %.3f ms, backward %.3f ms (%s); the "
	    "reflector's timestamps %s", target_name(t, name,
	    sizeof(name)), stamp_mode_name(st.mode), t->w_sent,
	    t->w_recv, (uintmax_t)t->fwd_lost, (uintmax_t)t->back_lost,
	    s->dfwd, s->dback, s->owd == 1 ? "one way" : s->owd == 0 ?
	    "estimated: half the round trip" : "no reply", ti);
	/* A plain tunnel's: authenticated, the replies that were not. */
	if (t->keyed)
		logmsg(LOG_DEBUG, "probe: %s: stamp authenticated (SSID "
		    "%d); replies failing authentication %ju all along",
		    target_name(t, name, sizeof(name)), t->key.ssid,
		    (uintmax_t)(t->auth_failed + st.auth_failed));
	/* The path as the last reply saw it: the DSCP each way. */
	if (t->has_cos)
		snprintf(dsf, sizeof(dsf), "%d", t->dscp_fwd);
	else
		snprintf(dsf, sizeof(dsf), "-");
	if (t->has_rtos)
		snprintf(dsb, sizeof(dsb), "%d", t->dscp_back);
	else
		snprintf(dsb, sizeof(dsb), "-");
	/* ... the addresses the far end saw, a NAT; the loss by
	 * counters. */
	addr_port(&t->loc.src, src, sizeof(src));
	addr_port(&t->loc.dst, dst, sizeof(dst));
	snprintf(nat, sizeof(nat), "%s", !t->has_loc ? "not told" :
	    t->nat == 0 ? "no NAT" : t->nat == STAMP_NAT_SRC ?
	    "NAT: the source rewritten" : t->nat == STAMP_NAT_DST ?
	    "NAT: the destination rewritten" :
	    "NAT: both rewritten");
	if (t->dm_told)
		snprintf(dm, sizeof(dm), "forward %ju, backward %ju",
		    (uintmax_t)t->dm_fwd_lost,
		    (uintmax_t)t->dm_back_lost);
	else
		snprintf(dm, sizeof(dm), "not told");
	logmsg(LOG_DEBUG, "probe: %s: stamp path: dscp %d sent, "
	    "forward %s, backward %s%s; seen from %s to %s (%s); lost "
	    "by counters %s all along", target_name(t, name,
	    sizeof(name)), t->dscp, dsf, dsb, t->has_cos &&
	    t->dscp_refused ? " (the reflector refused it)" : "", src,
	    dst, nat, dm);
}
