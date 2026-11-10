/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula, the tunnels: each target an address pinged again and again
 * (ICMP echo, as Mplify 119 §11.4 has an SD-WAN edge measure its
 * tunnels), from a thread of its own, through the routing table it
 * says.  Of each eval interval it keeps a sample: the one-way delay,
 * half the mean round trip (MEF 105 §7.2.4); the delay variation, the
 * mean difference between one round trip and the next; the loss; the
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
 * A raw socket needs root: without it the target says so.
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
 * the target is pinged and the key tried again with STAMP.
 *
 * The same prober measures tunnels outside SD-WAN too: the monitors an
 * admin puts on any tunnel interface (the monitor job), each target's
 * owner "monitor" rather than "sdwan".  An owner's list is replaced by
 * its own alone, so an SD-WAN apply never takes a monitor away, and is
 * kept in its own file (monitors.json, monitors@j.json).  A monitor's
 * state and thresholds are events (monitor, monitor-threshold), not
 * SD-WAN's faults.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <dirent.h>
#include <ifaddrs.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <math.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"
#include "stamp.h"

#define	PROBE_FILE	"sdwan-probes.json"
#define	MONITOR_FILE	"monitors.json"
#define	OWN_SDWAN	"sdwan"
#define	OWN_MONITOR	"monitor"
#define	TARGETS_MAX	256
#define	OUT_MAX		64	/* probes in the air, each */
#define	SAMPLES_MAX	100000
#define	PKT_MAX		10000
#define	STAMP_RETRY	10.0	/* s: STAMP tried again, fallen back */
#define	STAMP_WINDOW	4096	/* STAMP probes in the air, at most */
#define	STAMP_SALT	"arcana stamp v1"	/* HKDF's, the key's */
#define	PUB_B64		44	/* an X25519 public half, base64 */
#define	PM_RAW_MAX	4096	/* raw samples an interval keeps, a target */
#define	PM_KEPT		60	/* completed measurement intervals kept */
#define	PM_LEN		60	/* s: a measurement interval, by default */
#define	CLASSES_MAX	8	/* classes of service a target, at most */

enum { ST_UNKNOWN = PROBE_UNKNOWN, ST_UP = PROBE_UP, ST_DOWN = PROBE_DOWN,
    ST_ENDED = PROBE_ENDED, ST_ERROR = PROBE_ERROR };
/* A target's kind, arcana-probe's: the agent's choice, STAMP alone, ICMP
 * alone. */
enum { KIND_AUTO, KIND_STAMP, KIND_ICMP };
static const char *const kind_names[] = { "auto", "stamp", "icmp" };
static const char *const state_names[] = { "unknown", "up", "down", "ended",
    "error" };

struct sample {
	double	t, delay, ipdv, loss, min, max;
	int	sent, recv;
	double	fwd, back;	/* lost each way, by STAMP; -1 not told */
	/* The delay each way (ms), by STAMP: one way when owd is 1, half
	 * the round trip when 0 (an estimate); -1 each when not told. */
	double	dfwd, dback;
	int	owd;
};

/*
 * A measurement interval's (PLAN-SDN-YANG 5.2, RFC 9375's perf-mon): the
 * metrics of each answer, in microseconds, -1 for none: the round trip,
 * the delay out and back (by STAMP, measured one way), and the IPDV of
 * each (RFC 3393, as an absolute value: against the answer before).
 */
enum { PM_RTT, PM_FWD, PM_BACK, PM_JRTT, PM_JFWD, PM_JBACK, PM_NM };
static const char *const pm_names[] = { "rtt", "forward", "backward",
    "jitter_rtt", "jitter_forward", "jitter_backward" };

struct pm_raw {
	int32_t		v[PM_NM];
};

/* Of every value of the interval, not only those kept. */
struct pm_acc {
	uint64_t	sum;
	uint32_t	n, min, max;
};

struct pm_stats {
	uint32_t	n;		/* 0: none */
	uint64_t	min, max, mean, p[3];
};

struct pm {
	time_t		start, end;
	uint32_t	sent, recv, kept;
	int64_t		lost_fwd, lost_back;	/* -1 not told */
	struct pm_stats	st[PM_NM];
};

struct target {
	char			 id[128];
	/* A class of service the target is measured in too: a session of
	 * its own after the target's, its name and place (1 on) in the
	 * target's list; "" and 0, the target itself. */
	char			 cls[33];
	int			 cls_idx;
	char			 address[64];
	char			 jail[64];	/* its network's; "" the host's */
	char			 owner[8];	/* sdwan, monitor */
	char			 ifname[IFNAMSIZ];	/* a monitor's tunnel */
	/* The underlay's path between two UCS End Points, not a tunnel
	 * (RFC 9375's pm-type-network-link): its fault its own. */
	bool			 underlay;
	int			 af;
	struct sockaddr_storage	 sa;
	int			 fib, interval, size, count, dscp, down, up;
	int			 timeout, eval, history, report;
	/* Threshold crossing alerts (Mplify 119 §11.4, MEF 105 §7.4): a
	 * threshold a metric, 0 for none; damping, intervals in a row. */
	double			 tca[3];
	int			 damping, tca_over[3], tca_under[3];
	bool			 tca_on[3];
	int			 sock;
	/* STAMP to Arcana's far end, ICMP the fallback; kind, as the target
	 * says (KIND_*); why STAMP does not answer, said once. */
	int			 kind;
	bool			 arcana, by_stamp;
	char			 stamp_why[160];
	/* STAMP's counts all along: of senders given up (their stats
	 * added as each goes), refusals and falls back to ICMP. */
	uint64_t		 st_sent, st_recv, st_lost, st_unknown, st_late;
	uint64_t		 refused, fallbacks;
	int			 usock;		/* UDP, connected */
	uint16_t		 ssid;
	struct stamp_sender	*ss;
	/* A plain tunnel's STAMP key: this end's interface, whose pair it
	 * comes from, and the far end's public half; keyed once derived,
	 * why not when it could not be; replies that did not
	 * authenticate, of senders given up. */
	char			 stamp_if[IFNAMSIZ];
	char			 stamp_peer[PUB_B64 + 1];
	bool			 keyed;
	struct stamp_key	 key;
	char			 key_err[160];
	uint64_t		 auth_failed;
	uint64_t		 tk_fwd, tk_back;	/* of ss's, taken */
	uint64_t		 fwd_lost, back_lost;	/* all along */
	double			 stamp_retry;
	/* The delay each way of the last reply (ms), one way or half its
	 * round trip; the reflector's Timestamp Information. */
	double			 last_dfwd, last_dback, last_err;
	bool			 has_delay, last_owd, has_ti;
	struct stamp_tsinfo	 ti;
	/* The DSCP of the last reply each way: the probe's as it reached
	 * the reflector (its Class of Service TLV), the reply's as it
	 * came back; whether the reflector refused the target's (RP). */
	int			 dscp_fwd, dscp_back;
	bool			 has_cos, has_rtos, dscp_refused;
	/* The last reply's Location TLV: the source and destination as
	 * the reflector saw them, and what of them a NAT rewrote
	 * (STAMP_NAT_*). */
	bool			 has_loc;
	struct stamp_location	 loc;
	int			 nat;
	/* The loss each way by the Direct Measurement counters, of ss's
	 * taken and all along; whether any reply had them. */
	uint64_t		 tk_dmf, tk_dmb, dm_fwd_lost, dm_back_lost;
	bool			 dm_told;
	uint16_t		 ident, seq;
	struct {
		uint16_t	 seq;
		double		 sent;
		bool		 live;
	}			 out[OUT_MAX];
	int			 state;
	char			 error[128];
	int			 misses, hits;	/* in a row */
	uint64_t		 sent, received;
	double			 last_rtt;
	time_t			 since;
	double			 next_send, win_start;
	/* The eval interval in progress. */
	int			 w_sent, w_recv, w_ipdv_n;
	double			 w_sum, w_min, w_max, w_ipdv_sum, w_prev;
	int			 w_owd_n, w_est_n;	/* STAMP replies */
	double			 w_dfwd, w_dback;	/* one way, ms */
	bool			 w_has_prev;
	struct sample		*samples;
	int			 nsamples, head;
	/*
	 * Its measurement intervals, aligned to the wall clock: the three
	 * percentiles reported and the length (s); the running one's
	 * start, counts, every value's least, most and sum, and its raw
	 * samples (PM_RAW_MAX at most, a uniform sample beyond: pm_seen
	 * the answers so far); the last answer's metrics, which the next
	 * one's IPDV is against; the loss each way all along when it
	 * began; the last completed one's raw samples, kept for a read
	 * that asks (raw); and the last PM_KEPT completed ones' figures.
	 */
	double			 pct[3];
	int			 pm_len;
	time_t			 pm_start;
	uint32_t		 pm_sent, pm_recv, pm_seen;
	struct pm_acc		 pm_acc[PM_NM];
	int32_t			 pm_prev[3];
	uint64_t		 pm_fwd0, pm_back0;
	struct pm_raw		*pm_raw, *pm_last;
	int			 pm_nraw, pm_cap, pm_nlast, pm_lastcap;
	struct pm		*pm_done;
	int			 pm_ndone, pm_head;
};

static pthread_mutex_t	 lock = PTHREAD_MUTEX_INITIALIZER;
static struct target	*targets;
static int		 ntargets;

/*
 * The kernel hands an ICMP reply to the raw sockets of the FIB of the
 * interface it came in on: a probe sent in a tunnel's table (its
 * tunnelfib) over an uplink in another never hears its reply on its own
 * socket.  So replies are listened for on a socket a FIB, a family,
 * the host's, and told to the target by the echo's id.
 */
#define	RX_FIBS		16
static int		 rx[2][RX_FIBS];
static int		 nfibs = -1;

static void
rx_open(int af)
{
	struct icmp6_filter	f;
	size_t			len = sizeof(nfibs);
	int			k = af == AF_INET6, v;

	if (nfibs < 0 && (sysctlbyname("net.fibs", &nfibs, &len, NULL, 0) != 0 ||
	    nfibs < 1))
		nfibs = 1;
	for (int fib = 0; fib < nfibs && fib < RX_FIBS; fib++) {
		if (rx[k][fib] > 0)
			continue;
		if ((v = socket(af, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
		    af == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6)) == -1)
			continue;
		if (setsockopt(v, SOL_SOCKET, SO_SETFIB, &fib, sizeof(fib)) ==
		    -1) {
			close(v);
			continue;
		}
		if (af == AF_INET6) {
			ICMP6_FILTER_SETBLOCKALL(&f);
			ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &f);
			(void)setsockopt(v, IPPROTO_ICMPV6, ICMP6_FILTER, &f,
			    sizeof(f));
		}
		rx[k][fib] = v;
	}
}

/*
 * The links an edge watches (Mplify 119's interface faults): its UCS
 * end points' and UNIs' interfaces, each a fault while it has no link
 * (down, or its carrier gone), told by the console beside the targets
 * ("links": [{"interface", "id", "role"}]).
 */
#define	LINKS_MAX	128
struct link {
	char	jail[64];	/* the edge's; "" the host's */
	char	ifname[IFNAMSIZ];
	char	id[96];		/* the UNI's or UCS end point's */
	char	role[8];	/* uni, ucs */
	int	state;		/* -1 not known, 0 down, 1 up */
};
static struct link	 links[LINKS_MAX];
static int		 nlinks;

static int	links_set(struct work *, const char *, const char *,
		    const char **);
static bool	has_links(const char *);
static bool		 started;
static bool		 changed;	/* a state did, since the steering looked */

static double
now_s(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((double)ts.tv_sec + (double)ts.tv_nsec / 1e9);
}

static bool
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
static const char *
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

/* ---- One target --------------------------------------------------- */

/* The STAMP sender given up, its socket kept: its counts from 0. */
static void
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

static void
target_close(struct target *t)
{

	if (t->sock != -1)
		close(t->sock);
	t->sock = -1;
	if (t->usock != -1)
		close(t->usock);
	t->usock = -1;
	stamp_drop(t);
}

static void
target_free(struct target *t)
{

	target_close(t);
	free(t->samples);
	t->samples = NULL;
	free(t->pm_raw);
	free(t->pm_last);
	free(t->pm_done);
	t->pm_raw = t->pm_last = NULL;
	t->pm_done = NULL;
	explicit_bzero(&t->key, sizeof(t->key));
	t->keyed = false;
}

/*
 * A plain tunnel's STAMP key: HKDF-SHA256 of the agreement of its
 * interface's pair with the far end's public half, 32 octets of key and
 * 2 of SSID (0 taken as 1), the same at both ends.  True, keyed; false
 * and why in key_err (said once).
 */
static bool
stamp_key_get(struct work *w, struct target *t)
{
	unsigned char	 okm[34];
	const char	*e = NULL;
	char		 was[sizeof(t->key_err)];

	if (t->stamp_peer[0] == '\0' || t->keyed)
		return (t->keyed);
	snprintf(was, sizeof(was), "%s", t->key_err);
	if (tunnel_key_derive(w, t->stamp_if, t->stamp_peer, STAMP_SALT, okm,
	    sizeof(okm), &e) != 0) {
		snprintf(t->key_err, sizeof(t->key_err), "%s", e != NULL ? e :
		    "not derived");
		if (strcmp(was, t->key_err) != 0)
			logmsg(LOG_WARNING, "probe: %s (%s): no STAMP key: %s",
			    t->id, t->address, t->key_err);
		return (false);
	}
	memset(&t->key, 0, sizeof(t->key));
	memcpy(t->key.key, okm, 32);
	t->key.len = 32;
	t->key.ssid = okm[32] << 8 | okm[33];
	/* A class's session: an SSID of its own, the same at both ends
	 * (both have the service's classes in the same order). */
	t->key.ssid = (t->key.ssid + t->cls_idx) & 0xffff;
	if (t->key.ssid == 0)
		t->key.ssid = 1;
	explicit_bzero(okm, sizeof(okm));
	t->keyed = true;
	t->key_err[0] = '\0';
	return (true);
}

static uint16_t
cksum(const void *p, size_t len)
{
	const uint16_t	*w = p;
	uint32_t	 sum;

	sum = 0;
	while (len > 1) {
		sum += *w++;
		len -= 2;
	}
	if (len == 1)
		sum += *(const uint8_t *)w;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return ((uint16_t)~sum);
}

static bool
target_open(struct target *t)
{
	int	v, jid;

	/* Kind stamp: no echo, so no raw socket (nor root) needed; its UDP
	 * socket is made as it sends (stamp_open()). */
	if (t->kind == KIND_STAMP) {
		t->error[0] = '\0';
		return (true);
	}
	if (t->jail[0] != '\0') {
		/* A jail's: its socket made in its network by the helper,
		 * so that its routing tables carry the probes. */
		if ((jid = jail_getid(t->jail)) < 0) {
			snprintf(t->error, sizeof(t->error), "jail %s is not "
			    "running", t->jail);
			return (false);
		}
		if ((t->sock = helper_icmp_socket(jid, t->af)) == -1) {
			snprintf(t->error, sizeof(t->error), "no socket in jail "
			    "%s (probing needs root)", t->jail);
			return (false);
		}
		(void)fcntl(t->sock, F_SETFL, fcntl(t->sock, F_GETFL) |
		    O_NONBLOCK);
	} else if ((t->sock = socket(t->af, SOCK_RAW | SOCK_CLOEXEC |
	    SOCK_NONBLOCK, t->af == AF_INET ? IPPROTO_ICMP :
	    IPPROTO_ICMPV6)) == -1) {
		snprintf(t->error, sizeof(t->error), "socket: %s%s",
		    strerror(errno), errno == EPERM || errno == EACCES ?
		    " (probing needs root)" : "");
		return (false);
	}
	v = t->fib;
	if (setsockopt(t->sock, SOL_SOCKET, SO_SETFIB, &v, sizeof(v)) == -1) {
		snprintf(t->error, sizeof(t->error), "fib %d: %s", t->fib,
		    strerror(errno));
		target_close(t);
		return (false);
	}
	/* Its reply may come in on an interface of another table. */
	if (t->jail[0] == '\0' && t->fib != 0)
		rx_open(t->af);
	v = t->dscp << 2;
	if (t->af == AF_INET)
		(void)setsockopt(t->sock, IPPROTO_IP, IP_TOS, &v, sizeof(v));
	else {
		(void)setsockopt(t->sock, IPPROTO_IPV6, IPV6_TCLASS, &v,
		    sizeof(v));
		if (t->af == AF_INET6) {
			struct icmp6_filter	f;

			ICMP6_FILTER_SETBLOCKALL(&f);
			ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &f);
			(void)setsockopt(t->sock, IPPROTO_ICMPV6, ICMP6_FILTER,
			    &f, sizeof(f));
		}
	}
	t->error[0] = '\0';
	return (true);
}

/* Its name in faults and the log: its id, and id@jail at a jail's
 * edge, so that both ends of a tunnel on one host are told apart. */
static const char *
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

static void
state_set(struct target *t, int state)
{
	char	id[300], *p;
	size_t	i;

	if (t->state == state)
		return;
	t->state = state;
	t->since = time(NULL);
	/* A class's session: its state its own, no event, fault nor
	 * steering (the target's DSCP's state is the target's). */
	if (t->cls[0] != '\0')
		return;
	changed = true;
	if (state != ST_UP && state != ST_DOWN)
		return;
	/* Its id as JSON: a quote or a backslash in it escaped. */
	for (i = 0, p = id; t->id[i] != '\0' && p < id + sizeof(id) - 3; i++) {
		if (t->id[i] == '"' || t->id[i] == '\\')
			*p++ = '\\';
		*p++ = t->id[i];
	}
	*p = '\0';
	/* An underlay path is no tunnel: its fault alone, no event. */
	if (t->underlay) {
		logmsg(state == ST_UP ? LOG_NOTICE : LOG_WARNING, "sdwan: "
		    "underlay %s (%s) is %s", target_name(t, id, sizeof(id)),
		    t->address, state_names[state]);
		if (state == ST_DOWN)
			fault_set("underlay", "Major", id, "probe", "no answer "
			    "from %s in FIB %d after %d probes", t->address,
			    t->fib, t->misses);
		else
			fault_clear("underlay", id, "%s answers again",
			    t->address);
		return;
	}
	/* A jail's: said, its name a jail's (letters, digits, - _ .). */
	event_add(is_monitor(t) ? "monitor" : "sdwan-tunnel", "{\"id\":\"%s\","
	    "\"address\":\"%s\",\"state\":\"%s\",\"misses\":%d%s%s%s%s%s%s}",
	    id, t->address, state_names[state], t->misses, t->jail[0] != '\0' ?
	    ",\"jail\":\"" : "", t->jail, t->jail[0] != '\0' ? "\"" : "",
	    t->ifname[0] != '\0' ? ",\"interface\":\"" : "", t->ifname,
	    t->ifname[0] != '\0' ? "\"" : "");
	logmsg(state == ST_UP ? LOG_NOTICE : LOG_WARNING, "%s: %s (%s) is "
	    "%s", is_monitor(t) ? "monitor" : "sdwan", target_name(t, id,
	    sizeof(id)), t->address, state_names[state]);
	/* A monitor is the admin's own: an event, not SD-WAN's fault. */
	if (is_monitor(t))
		return;
	if (state == ST_DOWN)
		fault_set("tunnel", "Major", id, "probe", "no answer from %s "
		    "after %d probes", t->address, t->misses);
	else
		fault_clear("tunnel", id, "%s answers again", t->address);
}

/* A monitor's metric over its threshold, or under it again: an event. */
static void
monitor_tca(const struct target *t, const char *metric, double v, bool over)
{
	char	name[200];

	event_add("monitor-threshold", "{\"id\":\"%s\",\"metric\":\"%s\","
	    "\"value\":%.6g,\"threshold\":%.6g,\"over\":%s%s%s%s}",
	    target_name(t, name, sizeof(name)), metric, v,
	    t->tca[strcmp(metric, "delay") == 0 ? 0 : strcmp(metric, "ipdv") ==
	    0 ? 1 : 2], over ? "true" : "false", t->ifname[0] != '\0' ?
	    ",\"interface\":\"" : "", t->ifname, t->ifname[0] != '\0' ? "\"" :
	    "");
	logmsg(over ? LOG_WARNING : LOG_NOTICE, "monitor: %s: %s %.3g %s the "
	    "threshold", name, metric, v, over ? "over" : "under");
}

/* The sample against the thresholds: an alert set or cleared. */
static void
tca_check(struct target *t, const struct sample *s)
{
	static const char *const names[] = { "delay", "ipdv", "loss" };
	static const char *const units[] = { " ms", " ms", "" };
	double		v[3];
	char		obj[260], name[200];
	int		i;

	v[0] = s->delay;
	v[1] = s->ipdv;
	v[2] = s->loss;
	for (i = 0; i < 3; i++) {
		if (t->tca[i] <= 0)
			continue;
		snprintf(obj, sizeof(obj), "%s/%s", target_name(t, name,
		    sizeof(name)), names[i]);
		if (v[i] > t->tca[i]) {
			t->tca_under[i] = 0;
			if (!t->tca_on[i] && ++t->tca_over[i] >= t->damping) {
				t->tca_on[i] = true;
				if (is_monitor(t))
					monitor_tca(t, names[i], v[i], true);
				else
					fault_set("tca", "Minor", obj, "probe",
					    "%s %.3g%s over the threshold %.3g%s",
					    names[i], v[i], units[i], t->tca[i],
					    units[i]);
			}
		} else {
			t->tca_over[i] = 0;
			if (t->tca_on[i] && ++t->tca_under[i] >= t->damping) {
				t->tca_on[i] = false;
				if (is_monitor(t))
					monitor_tca(t, names[i], v[i], false);
				else
					fault_clear("tca", obj, "%s %.3g%s, under "
					    "the threshold %.3g%s again", names[i],
					    v[i], units[i], t->tca[i], units[i]);
			}
		}
	}
}

/* An address and port as "a port p" ("-" not said). */
static const char *
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

/* An address and its port as o's key_addr and key_port. */
static void
loc_put(ucl_object_t *o, const char *key, const struct sockaddr_storage *ss)
{
	char	a[INET6_ADDRSTRLEN], k[48];

	if (ss->ss_family == 0)
		return;
	snprintf(k, sizeof(k), "%s_addr", key);
	ucl_object_insert_key(o, ucl_object_fromstring(stamp_sa_ntop((const
	    struct sockaddr *)ss, a, sizeof(a))), k, 0, true);
	snprintf(k, sizeof(k), "%s_port", key);
	ucl_object_insert_key(o, ucl_object_fromint(stamp_sa_port((const struct
	    sockaddr *)ss)), k, 0, true);
}

/* ---- Measurement intervals (PLAN-SDN-YANG 5.2) ---------------------- */

static time_t
wall_s(void)
{

	return (time(NULL));
}

/* Milliseconds as whole microseconds, 0 to INT32_MAX. */
static int32_t
pm_us(double ms)
{
	double	v = ms * 1000 + 0.5;

	return (v < 0 ? 0 : v > INT32_MAX ? INT32_MAX : (int32_t)v);
}

/* The loss each way the target's STAMP has told, all along. */
static void
pm_lost(const struct target *t, uint64_t *fwd, uint64_t *back)
{
	struct stamp_sender_stats	st;

	*fwd = t->fwd_lost;
	*back = t->back_lost;
	if (t->ss != NULL) {
		stamp_sender_stats(t->ss, &st);
		*fwd += st.fwd_lost - t->tk_fwd;
		*back += st.back_lost - t->tk_back;
	}
}

/* A new interval from the boundary at or before now; the counts from 0. */
static void
pm_begin(struct target *t, time_t now)
{

	t->pm_start = now - now % t->pm_len;
	t->pm_sent = t->pm_recv = t->pm_seen = 0;
	t->pm_nraw = 0;
	memset(t->pm_acc, 0, sizeof(t->pm_acc));
	pm_lost(t, &t->pm_fwd0, &t->pm_back0);
}

/* The intervals forgotten: another length or other percentiles. */
static void
pm_forget(struct target *t)
{

	t->pm_ndone = t->pm_head = 0;
	t->pm_nlast = 0;
	t->pm_start = 0;
}

/* An answer's metrics: the round trip, and by STAMP (sm) the delay
 * each way when it was measured one way; each one's IPDV against the
 * answer before. */
static void
pm_hit(struct target *t, double rtt_ms, const struct stamp_sample *sm)
{
	struct pm_raw	 r, *nr;
	struct pm_acc	*a;
	uint32_t	 j;
	int		 i, cap;

	r.v[PM_RTT] = pm_us(rtt_ms);
	r.v[PM_FWD] = r.v[PM_BACK] = -1;
	if (sm != NULL && sm->owd) {
		r.v[PM_FWD] = pm_us(sm->fwd * 1000);
		r.v[PM_BACK] = pm_us(sm->back * 1000);
	}
	for (i = 0; i < 3; i++) {
		r.v[PM_JRTT + i] = -1;
		if (r.v[i] < 0)
			continue;
		if (t->pm_prev[i] >= 0)
			r.v[PM_JRTT + i] = r.v[i] > t->pm_prev[i] ? r.v[i] -
			    t->pm_prev[i] : t->pm_prev[i] - r.v[i];
		t->pm_prev[i] = r.v[i];
	}
	for (i = 0; i < PM_NM; i++) {
		if (r.v[i] < 0)
			continue;
		a = &t->pm_acc[i];
		if (a->n == 0 || (uint32_t)r.v[i] < a->min)
			a->min = (uint32_t)r.v[i];
		if (a->n == 0 || (uint32_t)r.v[i] > a->max)
			a->max = (uint32_t)r.v[i];
		a->sum += (uint32_t)r.v[i];
		a->n++;
	}
	/* Kept: all of them up to PM_RAW_MAX, then each in its place with
	 * a chance that keeps a uniform sample (reservoir sampling). */
	t->pm_seen++;
	if (t->pm_nraw < PM_RAW_MAX) {
		if (t->pm_nraw == t->pm_cap) {
			cap = t->pm_cap == 0 ? 64 : t->pm_cap * 2;
			if (cap > PM_RAW_MAX)
				cap = PM_RAW_MAX;
			if ((nr = reallocarray(t->pm_raw, (size_t)cap,
			    sizeof(*nr))) == NULL)
				return;
			t->pm_raw = nr;
			t->pm_cap = cap;
		}
		t->pm_raw[t->pm_nraw++] = r;
	} else if ((j = arc4random_uniform(t->pm_seen)) < PM_RAW_MAX)
		t->pm_raw[j] = r;
}

static int
pm_cmp(const void *a, const void *b)
{
	int32_t	x = *(const int32_t *)a, y = *(const int32_t *)b;

	return (x < y ? -1 : x > y);
}

/* A percentile of n sorted values, the nearest rank: the least that p
 * percent of them are less than or equal to. */
static uint64_t
pm_rank(const int32_t *v, int n, double p)
{
	int	k;

	k = (int)ceil(p * n / 100.0 - 1e-9);
	if (k < 1)
		k = 1;
	if (k > n)
		k = n;
	return ((uint64_t)v[k - 1]);
}

/* The figures of raw samples (n of them) and of every value (acc). */
static void
pm_figures(const struct target *t, const struct pm_raw *raw, int n,
    const struct pm_acc *acc, struct pm_stats *st)
{
	int32_t	*v;
	int	 i, k, m;

	memset(st, 0, PM_NM * sizeof(*st));
	v = n > 0 ? calloc((size_t)n, sizeof(*v)) : NULL;
	for (m = 0; m < PM_NM; m++) {
		if (acc[m].n == 0)
			continue;
		st[m].n = acc[m].n;
		st[m].min = acc[m].min;
		st[m].max = acc[m].max;
		st[m].mean = (acc[m].sum + acc[m].n / 2) / acc[m].n;
		if (v == NULL)
			continue;
		for (i = k = 0; i < n; i++)
			if (raw[i].v[m] >= 0)
				v[k++] = raw[i].v[m];
		if (k == 0)
			continue;
		qsort(v, (size_t)k, sizeof(*v), pm_cmp);
		for (i = 0; i < 3; i++)
			if (t->pct[i] > 0)
				st[m].p[i] = pm_rank(v, k, t->pct[i]);
	}
	free(v);
}

/* The running interval as it would end now, into p. */
static void
pm_now(const struct target *t, struct pm *p)
{
	struct stamp_sender_stats	st;
	uint64_t			f, b;

	p->start = t->pm_start;
	p->end = t->pm_start + t->pm_len;
	p->sent = t->pm_sent;
	p->recv = t->pm_recv;
	p->kept = (uint32_t)t->pm_nraw;
	p->lost_fwd = p->lost_back = -1;
	/* The loss each way, a stateful reflector's to tell. */
	if (t->by_stamp && t->ss != NULL) {
		stamp_sender_stats(t->ss, &st);
		if (st.mode == STAMP_MODE_STATEFUL) {
			pm_lost(t, &f, &b);
			p->lost_fwd = (int64_t)(f - t->pm_fwd0);
			p->lost_back = (int64_t)(b - t->pm_back0);
		}
	}
	pm_figures(t, t->pm_raw, t->pm_nraw, t->pm_acc, p->st);
}

/* The running interval ended: its figures kept, its raw samples the
 * last completed one's, a new one begun at the boundary of now. */
static void
pm_end(struct target *t, time_t now)
{
	struct pm_raw	*r;
	struct pm	*p;
	int		 c;

	if (t->pm_done == NULL && (t->pm_done = calloc(PM_KEPT,
	    sizeof(*t->pm_done))) == NULL) {
		pm_begin(t, now);
		return;
	}
	p = &t->pm_done[(t->pm_head + t->pm_ndone) % PM_KEPT];
	if (t->pm_ndone == PM_KEPT)
		t->pm_head = (t->pm_head + 1) % PM_KEPT;
	else
		t->pm_ndone++;
	pm_now(t, p);
	r = t->pm_last;
	c = t->pm_lastcap;
	t->pm_last = t->pm_raw;
	t->pm_lastcap = t->pm_cap;
	t->pm_nlast = t->pm_nraw;
	t->pm_raw = r;
	t->pm_cap = c;
	pm_begin(t, now);
}

/* Its intervals' clock: begun, or ended at its boundary. */
static void
pm_timers(struct target *t)
{
	time_t	now = wall_s();

	if (t->pm_start == 0)
		pm_begin(t, now);
	else if (now >= t->pm_start + t->pm_len)
		pm_end(t, now);
}

static void
pm_put_stats(ucl_object_t *o, const char *key, const struct target *t,
    const struct pm_stats *s)
{
	static const char *const pn[] = { "low", "intermediate", "high" };
	ucl_object_t	*c;

	if (s->n == 0)
		return;
	c = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(c, ucl_object_fromint(s->n), "count", 0, false);
	ucl_object_insert_key(c, ucl_object_fromint((int64_t)s->min), "min", 0,
	    false);
	ucl_object_insert_key(c, ucl_object_fromint((int64_t)s->max), "max", 0,
	    false);
	ucl_object_insert_key(c, ucl_object_fromint((int64_t)s->mean), "mean",
	    0, false);
	for (int i = 0; i < 3; i++)
		if (t->pct[i] > 0)
			ucl_object_insert_key(c, ucl_object_fromint((int64_t)
			    s->p[i]), pn[i], 0, false);
	ucl_object_insert_key(o, c, key, 0, false);
}

/* An interval as JSON; with raw (n of them), its raw samples too. */
static ucl_object_t *
pm_json(const struct target *t, const struct pm *p, bool complete,
    const struct pm_raw *raw, int n)
{
	ucl_object_t	*o, *r, *l;
	int		 i, m;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromint(p->start), "start", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(p->end), "end", 0, false);
	ucl_object_insert_key(o, ucl_object_frombool(complete), "complete", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(p->sent), "sent", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(p->recv), "received", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(p->kept), "kept", 0, false);
	if (p->lost_fwd >= 0) {
		ucl_object_insert_key(o, ucl_object_fromint(p->lost_fwd),
		    "lost_forward", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(p->lost_back),
		    "lost_backward", 0, false);
	}
	for (m = 0; m < PM_NM; m++)
		pm_put_stats(o, pm_names[m], t, &p->st[m]);
	if (raw != NULL) {
		r = ucl_object_typed_new(UCL_OBJECT);
		for (m = 0; m < PM_NM; m++) {
			l = ucl_object_typed_new(UCL_ARRAY);
			for (i = 0; i < n; i++)
				if (raw[i].v[m] >= 0)
					ucl_array_append(l, ucl_object_fromint(
					    raw[i].v[m]));
			ucl_object_insert_key(r, l, pm_names[m], 0, false);
		}
		ucl_object_insert_key(o, r, "raw", 0, false);
	}
	return (o);
}

/* Its measurement intervals as JSON: the percentiles, the length, the
 * completed ones ended after the time after (the last always, with its
 * raw samples when raw), the running one after them. */
static ucl_object_t *
pm_target_json(const struct target *t, uint64_t after, bool raw)
{
	ucl_object_t	*o, *arr;
	struct pm	 now;
	const struct pm	*p;
	int		 k;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromdouble(t->pct[0]), "low", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromdouble(t->pct[1]),
	    "intermediate", 0, false);
	ucl_object_insert_key(o, ucl_object_fromdouble(t->pct[2]), "high", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(t->pm_len), "length", 0,
	    false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (k = 0; k < t->pm_ndone; k++) {
		p = &t->pm_done[(t->pm_head + k) % PM_KEPT];
		if ((uint64_t)p->end <= after && k != t->pm_ndone - 1)
			continue;
		ucl_array_append(arr, pm_json(t, p, true, raw && k ==
		    t->pm_ndone - 1 ? t->pm_last : NULL, t->pm_nlast));
	}
	if (t->pm_start != 0) {
		pm_now(t, &now);
		ucl_array_append(arr, pm_json(t, &now, false, NULL, 0));
	}
	ucl_object_insert_key(o, arr, "intervals", 0, false);
	return (o);
}

static void
window_end(struct target *t, double now)
{
	struct sample	*s;

	if (t->history <= 0)
		goto reset;
	if (t->samples == NULL && (t->samples = calloc((size_t)t->history,
	    sizeof(*t->samples))) == NULL)
		goto reset;
	s = &t->samples[(t->head + t->nsamples) % t->history];
	if (t->nsamples == t->history)
		t->head = (t->head + 1) % t->history;
	else
		t->nsamples++;
	s->t = (double)time(NULL);
	s->sent = t->w_sent;
	s->recv = t->w_recv;
	s->delay = t->w_recv > 0 ? t->w_sum / t->w_recv / 2 : 0;
	s->ipdv = t->w_ipdv_n > 0 ? t->w_ipdv_sum / t->w_ipdv_n : 0;
	s->loss = t->w_sent > 0 ? (double)(t->w_sent - t->w_recv) / t->w_sent :
	    0;
	s->min = t->w_recv > 0 ? t->w_min / 2 : 0;
	s->max = t->w_recv > 0 ? t->w_max / 2 : 0;
	s->fwd = s->back = -1;
	/* The delay each way: one way when every STAMP reply of the
	 * interval had it so, else half the round trip, an estimate. */
	s->dfwd = s->dback = -1;
	s->owd = -1;
	if (t->w_owd_n > 0 && t->w_est_n == 0) {
		s->dfwd = t->w_dfwd / t->w_owd_n;
		s->dback = t->w_dback / t->w_owd_n;
		s->owd = 1;
	} else if (t->w_owd_n + t->w_est_n > 0) {
		s->dfwd = s->dback = s->delay;
		s->owd = 0;
	}
	/* The loss each way, told by a stateful reflector's counter: a
	 * loss is told once the reply after it is in, so the counts
	 * trail the samples by up to a timeout. */
	if (t->by_stamp && t->ss != NULL) {
		struct stamp_sender_stats	st;
		char				name[200], ti[48];
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
	if (t->w_sent > 0 && t->cls[0] == '\0')
		tca_check(t, s);
reset:
	t->w_sent = t->w_recv = t->w_ipdv_n = 0;
	t->w_sum = t->w_ipdv_sum = 0;
	t->w_owd_n = t->w_est_n = 0;
	t->w_dfwd = t->w_dback = 0;
	t->w_min = t->w_max = 0;
	t->win_start = now;
}

static void
miss(struct target *t)
{

	t->w_sent++;
	t->pm_sent++;
	t->hits = 0;
	if (++t->misses >= t->down && t->state != ST_DOWN)
		state_set(t, ST_DOWN);
}

static void
hit(struct target *t, double rtt_ms)
{

	t->w_sent++;
	t->w_recv++;
	t->pm_sent++;
	t->pm_recv++;
	t->received++;
	t->last_rtt = rtt_ms;
	t->w_sum += rtt_ms;
	if (t->w_recv == 1 || rtt_ms < t->w_min)
		t->w_min = rtt_ms;
	if (t->w_recv == 1 || rtt_ms > t->w_max)
		t->w_max = rtt_ms;
	if (t->w_has_prev) {
		t->w_ipdv_sum += rtt_ms > t->w_prev ? rtt_ms - t->w_prev :
		    t->w_prev - rtt_ms;
		t->w_ipdv_n++;
	}
	t->w_prev = rtt_ms;
	t->w_has_prev = true;
	t->misses = 0;
	if (++t->hits >= t->up && t->state != ST_UP)
		state_set(t, ST_UP);
}

/* An echo request. */
static void
icmp_send(struct target *t, double now)
{
	unsigned char	pkt[PKT_MAX];
	size_t		len;
	int		i, slot;

	/* A slot: the oldest in the air gone, if none is free. */
	slot = -1;
	for (i = 0; i < OUT_MAX; i++)
		if (!t->out[i].live) {
			slot = i;
			break;
		}
	if (slot == -1) {
		slot = 0;
		for (i = 1; i < OUT_MAX; i++)
			if (t->out[i].sent < t->out[slot].sent)
				slot = i;
		miss(t);
	}
	len = (size_t)t->size;
	if (len < 8)
		len = 8;
	memset(pkt, 0, len);
	t->seq++;
	if (t->af == AF_INET) {
		struct icmp	*ic = (struct icmp *)(void *)pkt;

		ic->icmp_type = ICMP_ECHO;
		ic->icmp_code = 0;
		ic->icmp_id = htons(t->ident);
		ic->icmp_seq = htons(t->seq);
		ic->icmp_cksum = 0;
		ic->icmp_cksum = cksum(pkt, len);
	} else {
		struct icmp6_hdr	*ic = (struct icmp6_hdr *)(void *)pkt;

		ic->icmp6_type = ICMP6_ECHO_REQUEST;
		ic->icmp6_code = 0;
		ic->icmp6_id = htons(t->ident);
		ic->icmp6_seq = htons(t->seq);
	}
	t->out[slot].seq = t->seq;
	t->out[slot].sent = now;
	t->out[slot].live = true;
	t->sent++;
	if (sendto(t->sock, pkt, len, 0, (const struct sockaddr *)&t->sa,
	    t->sa.ss_len) == -1) {
		t->out[slot].live = false;
		miss(t);
		snprintf(t->error, sizeof(t->error), "sendto: %s",
		    strerror(errno));
	} else
		t->error[0] = '\0';
}

/* ---- STAMP to Arcana's far end -------------------------------------- */

/* Its UDP socket, in its FIB, connected to the far end's reflector;
 * its sender, the timeout and the interval the target's. */
static bool
stamp_open(struct target *t)
{
	struct stamp_sender_conf	c;
	struct sockaddr_storage		to;
	struct work			w;
	int				v;
	bool				ok;

	/* --stamp-port 0: no reflector to send to (kind stamp's). */
	if (opts.stamp_port == 0) {
		errno = EDESTADDRREQ;
		return (false);
	}
	/* A plain tunnel's: its key first, derived now if not yet. */
	if (t->stamp_peer[0] != '\0' && !t->keyed) {
		work_init(&w);
		ok = stamp_key_get(&w, t);
		work_free(&w);
		if (!ok) {
			errno = ENOENT;
			return (false);
		}
		/* The reflector's copy, stampd's. */
		stampd_nudge();
	}
	if (t->usock == -1) {
		if ((t->usock = stamp_socket_fib(t->af, 0, STAMP_SOCK_MONOTONIC,
		    t->fib)) == -1)
			return (false);
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
			return (false);
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
			return (false);
	}
	return (true);
}

/* No STAMP from the far end (why): pinged instead, STAMP tried again
 * every STAMP_RETRY seconds.  Said when it was measured by STAMP. */
static void
stamp_fallback(struct target *t, double now, const char *why)
{
	char	name[200];

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
	snprintf(t->stamp_why, sizeof(t->stamp_why), "%s", why);
	logmsg(LOG_NOTICE, "probe: %s (%s): %s: pinged until STAMP answers",
	    target_name(t, name, sizeof(name)), t->address, why);
}

/* A STAMP probe lost: a miss, unless it would make the target down,
 * which the first echo decides instead (the reflector may be all that
 * is gone). */
static void
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
	stamp_fallback(t, now, why);
	if (t->kind != KIND_STAMP)
		t->next_send = now;
}

/* A STAMP probe: one of the target's (counted), or a fallen-back
 * target's try (not); false when none went. */
static bool
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
		return (false);
	}
	if (!stamp_open(t)) {
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
		return (false);
	}
	/* The base, the Timestamp Information TLV, the rest padding. */
	len = stamp_sender_len(t->ss, t->size > 0 ? (size_t)t->size : 0);
	if (len > sizeof(pkt))
		len = sizeof(pkt);
	memset(pkt, 0, len);
	clock_gettime(CLOCK_REALTIME, &t1);
	now = now_s();
	if ((rc = stamp_sender_packet(t->ss, pkt, len, &t1, now, &sm)) == -1)
		return (false);
	if (rc == 1 && counted)
		stamp_lost(t, now);
	if (!t->by_stamp && counted)
		return (false);
	if (counted)
		t->sent++;
	if (send(t->usock, pkt, len, 0) == -1) {
		/* Port unreachable: no reflector there. */
		if (errno == ECONNREFUSED) {
			t->refused++;
			if (counted)
				stamp_fallback(t, now, "its STAMP port refused");
			return (false);
		}
		if (counted)
			snprintf(t->error, sizeof(t->error), "send: %s",
			    strerror(errno));
	} else if (counted)
		t->error[0] = '\0';
	return (true);
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
static void
stamp_recv_all(struct target *t)
{
	unsigned char		in[PKT_MAX + 64];
	struct stamp_rxinfo	ri;
	struct stamp_sample	sm;
	char			name[200];
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
		stamp_drop(t);
		for (int i = 0; i < OUT_MAX; i++)
			t->out[i].live = false;
		logmsg(LOG_NOTICE, "probe: %s (%s): STAMP answers again",
		    target_name(t, name, sizeof(name)), t->address);
	}
}

/* The target's next probe: STAMP to Arcana's far end, else an echo. */
static void
target_send(struct target *t, double now)
{

	if (t->by_stamp)
		(void)stamp_send_one(t, true);
	/* Not by STAMP, or no longer: an echo. */
	if (!t->by_stamp)
		icmp_send(t, now);
	/* Fallen back: STAMP tried now and then. */
	if (t->arcana && !t->by_stamp && now >= t->stamp_retry) {
		t->stamp_retry = now + STAMP_RETRY;
		(void)stamp_send_one(t, false);
	}
	if (t->count > 0 && t->sent >= (uint64_t)t->count)
		t->next_send = -1;
	else
		t->next_send = now + t->interval / 1000.0;
}

/*
 * What a socket of family af has: each echo reply to the target t, or
 * with t NULL to the target of its id (a FIB's listener's).
 */
static void
sock_recv(int sock, int af, struct target *t, double now)
{
	unsigned char		 pkt[PKT_MAX + 64];
	struct sockaddr_storage	 from;
	struct target		*x;
	socklen_t		 flen;
	ssize_t			 n;
	uint16_t		 id, seq;
	int			 i, hl;

	for (;;) {
		flen = sizeof(from);
		n = recvfrom(sock, pkt, sizeof(pkt), 0, (struct sockaddr *)
		    &from, &flen);
		if (n <= 0)
			return;
		if (af == AF_INET) {
			const struct ip		*ip = (const struct ip *)(void *)pkt;
			const struct icmp	*ic;

			hl = ip->ip_hl << 2;
			if (n < hl + ICMP_MINLEN)
				continue;
			ic = (const struct icmp *)(const void *)(pkt + hl);
			if (ic->icmp_type != ICMP_ECHOREPLY)
				continue;
			id = ntohs(ic->icmp_id);
			seq = ntohs(ic->icmp_seq);
		} else {
			const struct icmp6_hdr	*ic = (const struct icmp6_hdr *)
			    (void *)pkt;

			if (n < (ssize_t)sizeof(*ic) || ic->icmp6_type !=
			    ICMP6_ECHO_REPLY)
				continue;
			id = ntohs(ic->icmp6_id);
			seq = ntohs(ic->icmp6_seq);
		}
		x = t;
		for (i = 0; x == NULL && i < ntargets; i++)
			if (targets[i].af == af && targets[i].sock != -1 &&
			    targets[i].ident == id && targets[i].jail[0] == '\0')
				x = &targets[i];
		if (x == NULL || id != x->ident)
			continue;
		for (i = 0; i < OUT_MAX; i++)
			if (x->out[i].live && x->out[i].seq == seq) {
				x->out[i].live = false;
				hit(x, (now - x->out[i].sent) * 1000);
				pm_hit(x, (now - x->out[i].sent) * 1000, NULL);
				break;
			}
	}
}

/* Probes in the air too long are lost; an eval interval over is kept. */
static void
target_timers(struct target *t, double now)
{
	struct stamp_sample	sm;
	int			i;

	for (i = 0; i < OUT_MAX; i++)
		if (t->out[i].live && now - t->out[i].sent > t->timeout /
		    1000.0) {
			t->out[i].live = false;
			miss(t);
		}
	/* A fallen-back target's tries lost: nothing to count. */
	while (t->ss != NULL && stamp_sender_expire(t->ss, now, &sm) == 1)
		if (t->by_stamp)
			stamp_lost(t, now);
	if (now - t->win_start >= t->eval / 1000.0)
		window_end(t, now);
	pm_timers(t);
	if (t->next_send < 0 && t->state != ST_ENDED && t->state != ST_ERROR) {
		bool	air = t->by_stamp && t->ss != NULL &&
			    stamp_sender_next(t->ss) > 0;

		for (i = 0; i < OUT_MAX; i++)
			air = air || t->out[i].live;
		if (!air)
			state_set(t, ST_ENDED);
	}
}

/* ---- The thread --------------------------------------------------- */

static void *
prober(void *arg __unused)
{
	struct pollfd	*pfd;
	struct target	*t;
	double		 now, wait, d;
	int		 i, n, ms;
	bool		 moved;

	/* Each target's echo and STAMP sockets, then the FIBs'
	 * listeners; whose each is, by its index (-1 a listener's). */
	int	*pt, *pk;

	pfd = calloc(2 * TARGETS_MAX + 2 * RX_FIBS, sizeof(*pfd));
	pt = calloc(2 * TARGETS_MAX + 2 * RX_FIBS, sizeof(*pt));
	pk = calloc(2 * TARGETS_MAX + 2 * RX_FIBS, sizeof(*pk));
	if (pfd == NULL || pt == NULL || pk == NULL) {
		logmsg(LOG_ERR, "sdwan probes: no memory");
		return (NULL);
	}
	for (int k = 0; k < 2; k++)
		for (int fib = 0; fib < RX_FIBS; fib++)
			rx[k][fib] = -1;
	for (;;) {
		pthread_mutex_lock(&lock);
		now = now_s();
		wait = 0.2;
		n = 0;
		for (i = 0; i < ntargets; i++) {
			t = &targets[i];
			if (t->state == ST_ERROR && t->sock == -1 &&
			    !target_open(t))
				continue;
			if (t->state == ST_ERROR)
				state_set(t, ST_UNKNOWN);
			if (t->next_send >= 0 && t->next_send <= now)
				target_send(t, now);
			target_timers(t, now);
			if (t->next_send >= 0 && (d = t->next_send - now) < wait)
				wait = d;
			if ((d = t->win_start + t->eval / 1000.0 - now) < wait)
				wait = d;
			if (t->pm_start != 0 && (d = (double)(t->pm_start +
			    t->pm_len - wall_s())) < wait)
				wait = d;
			pfd[n].fd = t->sock;
			pfd[n].events = POLLIN;
			pfd[n].revents = 0;
			pt[n] = i;
			pk[n++] = 0;
			if (t->usock != -1) {
				pfd[n].fd = t->usock;
				pfd[n].events = POLLIN;
				pfd[n].revents = 0;
				pt[n] = i;
				pk[n++] = 1;
			}
		}
		for (int k = 0; k < 2; k++)
			for (int fib = 0; fib < RX_FIBS; fib++)
				if (rx[k][fib] != -1) {
					pfd[n].fd = rx[k][fib];
					pfd[n].events = POLLIN;
					pfd[n].revents = 0;
					pt[n] = -1;
					pk[n++] = k;
				}
		moved = changed;
		changed = false;
		pthread_mutex_unlock(&lock);
		/* A tunnel down or up: the steering made again, outside the
		 * lock, as it asks the states back. */
		if (moved)
			sdwan_probe_changed();
		ms = wait > 0 ? (int)(wait * 1000) : 0;
		if (poll(pfd, (nfds_t)n, ms < 1 ? 1 : ms) <= 0)
			continue;
		pthread_mutex_lock(&lock);
		now = now_s();
		/* The targets may have changed meanwhile: each socket still
		 * the one it was, or passed over. */
		for (int j = 0; j < n; j++) {
			if (!(pfd[j].revents & POLLIN))
				continue;
			if (pt[j] == -1) {
				sock_recv(pfd[j].fd, pk[j] == 0 ? AF_INET : AF_INET6,
				    NULL, now);
				continue;
			}
			if (pt[j] >= ntargets)
				continue;
			t = &targets[pt[j]];
			if (pk[j] == 0 && t->sock == pfd[j].fd)
				sock_recv(t->sock, t->af, t, now);
			else if (pk[j] == 1 && t->usock == pfd[j].fd)
				stamp_recv_all(t);
		}
		pthread_mutex_unlock(&lock);
	}
	return (NULL);
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
static int
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
		if ((v = ucl_object_lookup(o, "interface")) != NULL &&
		    ucl_object_type(v) == UCL_STRING && strlen(
		    ucl_object_tostring(v)) < sizeof(t->ifname))
			snprintf(t->ifname, sizeof(t->ifname), "%s",
			    ucl_object_tostring(v));
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
					(void)stamp_key_get(w, t);
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
					(void)stamp_key_get(w, x);
			}
		}
	}
	ucl_object_unref(top);
	return (n);
bad:
	ucl_object_unref(top);
	return (-1);
}

/*
 * The new targets in the place of the old ones of their edge (jail, ""
 * the host): one that is the same target (address, fib, dscp, size, kind)
 * keeps its socket, state and samples; the other edges' stay as they
 * are, after them.  False, with nothing changed, when all of them are
 * more than TARGETS_MAX (new has room for that many).
 */
static bool
targets_swap(struct target *new, int n, const char *jail, const char *owner)
{
	struct target	*old, *t, *o;
	int		 nold, i, k, total;
	double		 now;

	pthread_mutex_lock(&lock);
	old = targets;
	nold = ntargets;
	total = n;
	for (k = 0; k < nold; k++)
		if (strcmp(old[k].jail, jail) != 0 || strcmp(old[k].owner,
		    owner) != 0)
			total++;
	if (total > TARGETS_MAX) {
		pthread_mutex_unlock(&lock);
		return (false);
	}
	now = now_s();
	for (i = 0; i < n; i++) {
		t = &new[i];
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
			/* Other percentiles or another length: the intervals
			 * begun again. */
			if (t->pm_len != pl || memcmp(t->pct, pc, sizeof(pc)) !=
			    0) {
				pm_forget(t);
				t->pm_len = pl;
				memcpy(t->pct, pc, sizeof(pc));
			}
			if (t->history != hi) {
				free(t->samples);
				t->samples = NULL;
				t->nsamples = t->head = 0;
				t->history = hi;
			}
			if (t->state == ST_ENDED && cnt == 0) {
				t->next_send = now;
				state_set(t, ST_UNKNOWN);
			}
			continue;
		}
		t->ident = (uint16_t)((getpid() + i * 7919 + (int)now) & 0xffff);
		t->ssid = (uint16_t)arc4random();
		t->since = time(NULL);
		t->win_start = now;
		t->next_send = now;
		t->state = target_open(t) ? ST_UNKNOWN : ST_ERROR;
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
	targets = new;
	ntargets = n;
	for (k = 0; k < nold; k++)
		target_free(&old[k]);
	free(old);
	pthread_mutex_unlock(&lock);
	/* Their FIBs stampd's (gula/stampd.c). */
	stampd_nudge();
	return (true);
}

static int
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
		(void)mkdir(tmp, 0755);
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
	if (!targets_swap(new, n, jail, OWN_SDWAN)) {
		*errp = wfmt(w, "%d targets at most, all edges' together",
		    TARGETS_MAX);
		for (n--; n >= 0; n--)
			target_free(&new[n]);
		free(new);
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

static bool
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
			if (!targets_swap(new, n, jail, owner)) {
				logmsg(LOG_WARNING, "%s: more than %d targets",
				    path, TARGETS_MAX);
				free(new);
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
	char	obj[200];

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

/*
 * An edge's links from its payload, in place of those it had; each
 * looked at now (later the interface's own changes tell).  A link no
 * longer watched has its fault cleared.  -1 and why when bad.
 */
static int
links_set(struct work *w, const char *json, const char *jail,
    const char **errp)
{
	struct ucl_parser	*p;
	ucl_object_t		*top;
	const ucl_object_t	*o, *v;
	ucl_object_iter_t	 it;
	struct link		 nl[LINKS_MAX], *l;
	struct work		 jw;
	char			 obj[200];
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
	pthread_mutex_lock(&lock);
	/* Those of the edge no longer watched: their faults cleared. */
	for (k = 0; k < nlinks; k++) {
		if (strcmp(links[k].jail, jail) != 0)
			continue;
		for (i = 0; i < n; i++)
			if (strcmp(nl[i].id, links[k].id) == 0 && strcmp(
			    nl[i].ifname, links[k].ifname) == 0)
				break;
		if (i == n && links[k].state == 0)
			fault_clear("interface", link_name(&links[k], obj,
			    sizeof(obj)), "%s is watched no more",
			    links[k].ifname);
	}
	/* The others' kept, the edge's new after them. */
	for (i = k = 0; k < nlinks; k++)
		if (strcmp(links[k].jail, jail) != 0)
			links[i++] = links[k];
	if (i + n > LINKS_MAX) {
		pthread_mutex_unlock(&lock);
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
	pthread_mutex_unlock(&lock);
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

	pthread_mutex_lock(&lock);
	for (k = 0; k < nlinks; k++)
		if (strcmp(links[k].jail, jail != NULL ? jail : "") == 0 &&
		    strcmp(links[k].ifname, ifname) == 0)
			link_state(&links[k], ok ? 1 : 0);
	pthread_mutex_unlock(&lock);
}

/* At the start: the targets kept, probed; the thread. */
void
probe_start(void)
{
	struct dirent	*de;
	DIR		*d;
	pthread_t	 tid;
	char		 path[MAXPATHLEN], *slash;

	started = true;
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
	if (pthread_create(&tid, NULL, prober, NULL) == 0)
		(void)pthread_detach(tid);
	else
		logmsg(LOG_ERR, "sdwan probes: no thread: %s", strerror(errno));
}

/* The STAMP keys of the host's plain tunnels' targets, each once, into
 * v (max of them): the reflector's copies, stampd's key file
 * (gula/stampd.c).  The caller zeroes them. */
int
probe_stamp_keys(struct stamp_key *v, int max)
{
	int	i, k, n;

	n = 0;
	pthread_mutex_lock(&lock);
	for (i = 0; i < ntargets && n < max; i++) {
		if (targets[i].jail[0] != '\0' || !targets[i].keyed)
			continue;
		for (k = 0; k < n && memcmp(&v[k], &targets[i].key,
		    sizeof(v[k])) != 0; k++)
			;
		if (k == n)
			v[n++] = targets[i].key;
	}
	pthread_mutex_unlock(&lock);
	return (n);
}

/* The FIBs the host's targets are probed in, each once, into v (max
 * of them): stampd answers there (gula/stampd.c). */
int
probe_fibs(int *v, int max)
{
	int	i, k, n;

	n = 0;
	pthread_mutex_lock(&lock);
	for (i = 0; i < ntargets && n < max; i++) {
		if (targets[i].jail[0] != '\0')
			continue;
		for (k = 0; k < n && v[k] != targets[i].fib; k++)
			;
		if (k == n)
			v[n++] = targets[i].fib;
	}
	pthread_mutex_unlock(&lock);
	return (n);
}

/* A target's state by its edge (jail, "" the host) and id; PROBE_NONE
 * when it is none. */
int
probe_state_of(const char *jail, const char *id)
{
	int	i, st;

	st = PROBE_NONE;
	pthread_mutex_lock(&lock);
	for (i = 0; i < ntargets; i++)
		if (!is_monitor(&targets[i]) && targets[i].cls[0] == '\0' &&
		    strcmp(targets[i].jail, jail) == 0 && strcmp(targets[i].id,
		    id) == 0) {
			st = targets[i].state;
			break;
		}
	pthread_mutex_unlock(&lock);
	return (st);
}

/* A target's last sample's delay, delay variation and loss; false when
 * it is none or has none. */
bool
probe_sample_of(const char *jail, const char *id, double *delay,
    double *ipdv, double *loss)
{
	const struct target	*t;
	const struct sample	*s;
	bool			 ok = false;
	int			 i;

	pthread_mutex_lock(&lock);
	for (i = 0; i < ntargets; i++) {
		t = &targets[i];
		if (is_monitor(t) || t->cls[0] != '\0' || strcmp(t->jail, jail) !=
		    0 || strcmp(t->id, id) != 0)
			continue;
		if (t->nsamples > 0 && t->samples != NULL) {
			s = &t->samples[(t->head + t->nsamples - 1) % t->history];
			*delay = s->delay;
			*ipdv = s->ipdv;
			*loss = s->loss;
			ok = true;
		}
		break;
	}
	pthread_mutex_unlock(&lock);
	return (ok);
}

/* A target as JSON: what it is, its state, the sample in progress and
 * those kept after the time after, its measurement intervals (with raw,
 * the last completed one's raw samples).  The lock is held. */
static ucl_object_t *
target_json(const struct target *t, double now, uint64_t after, bool raw)
{
	ucl_object_t	*o, *s, *row, *cur;
	struct sample	*sm;
	int		 k, from;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(t->id), "id", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromstring(t->address),
	    "address", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(t->af == AF_INET ?
	    "inet" : "inet6"), "family", 0, false);
	if (t->cls[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromstring(t->cls), "class",
		    0, false);
	if (t->jail[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromstring(t->jail),
		    "jail", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->fib), "fib", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromstring(state_names[
	    t->state]), "state", 0, false);
	if (t->error[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromstring(t->error),
		    "error", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->since), "since",
	    0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->interval),
	    "interval", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->size), "size", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(t->eval), "eval", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(t->dscp), "dscp", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)t->sent),
	    "sent", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)
	    t->received), "received", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->misses), "misses",
	    0, false);
	ucl_object_insert_key(o, ucl_object_fromdouble(t->last_rtt),
	    "last_rtt", 0, false);
	/* How it is measured: its kind, and now STAMP to Arcana's far end
	 * or an echo; of STAMP, arcana-stamp's session (gula/yprobe.c). */
	ucl_object_insert_key(o, ucl_object_fromstring(kind_names[t->kind]),
	    "kind", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(t->by_stamp ? "stamp" :
	    "icmp"), "method", 0, false);
	if (t->arcana) {
		struct stamp_sender_stats	st;
		uint64_t			af = t->auth_failed;
		uint64_t			fl = t->fwd_lost, bl = t->back_lost;
		uint64_t			dmf = t->dm_fwd_lost;
		uint64_t			dmb = t->dm_back_lost;
		bool				dm = t->dm_told;

		memset(&st, 0, sizeof(st));
		if (t->ss != NULL) {
			stamp_sender_stats(t->ss, &st);
			ucl_object_insert_key(o, ucl_object_fromstring(
			    stamp_mode_name(st.mode)), "reflector", 0, false);
			af += st.auth_failed;
			/* What the sender has that no window took yet. */
			fl += st.fwd_lost - t->tk_fwd;
			bl += st.back_lost - t->tk_back;
			if (st.dm_told) {
				dmf += st.dm_fwd_lost - t->tk_dmf;
				dmb += st.dm_back_lost - t->tk_dmb;
				dm = true;
			}
		}
		if (t->stamp_why[0] != '\0')
			ucl_object_insert_key(o, ucl_object_fromstring(
			    t->stamp_why), "reason", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(opts.stamp_port),
		    "reflector_port", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(t->keyed ?
		    (int64_t)t->key.ssid : (int64_t)t->ssid), "ssid", 0, false);
		/* Its counts all along, every sender's. */
		cur = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)
		    (t->st_sent + st.sent)), "sent", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)
		    (t->st_recv + st.received)), "received", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)
		    (t->st_lost + st.lost)), "lost", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)fl),
		    "lost_forward", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)bl),
		    "lost_backward", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)
		    (t->st_unknown + st.unknown_lost)), "lost_unknown", 0, false);
		if (dm) {
			ucl_object_insert_key(cur, ucl_object_fromint((int64_t)
			    dmf), "dm_lost_forward", 0, false);
			ucl_object_insert_key(cur, ucl_object_fromint((int64_t)
			    dmb), "dm_lost_backward", 0, false);
		}
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)
		    (t->st_late + st.late)), "late", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)af),
		    "auth_failed", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)
		    t->refused), "refused", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint((int64_t)
		    t->fallbacks), "fallbacks", 0, false);
		ucl_object_insert_key(o, cur, "stamp_counters", 0, false);
		/* A plain tunnel's: authenticated, its replies that were
		 * not, why there is no key yet. */
		ucl_object_insert_key(o, ucl_object_frombool(t->keyed),
		    "authenticated", 0, false);
		if (t->stamp_peer[0] != '\0') {
			ucl_object_insert_key(o, ucl_object_fromint((int64_t)af),
			    "auth_failed", 0, false);
			if (!t->keyed && t->key_err[0] != '\0')
				ucl_object_insert_key(o, ucl_object_fromstring(
				    t->key_err), "key_error", 0, false);
		}
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)fl),
		    "forward_lost", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)bl),
		    "backward_lost", 0, false);
		/* The last reply's delay each way: one way, or half its
		 * round trip ("estimated"); the reflector's clock. */
		if (t->by_stamp && t->has_delay) {
			ucl_object_insert_key(o, ucl_object_fromdouble(
			    t->last_dfwd), "forward_delay", 0, false);
			ucl_object_insert_key(o, ucl_object_fromdouble(
			    t->last_dback), "backward_delay", 0, false);
			ucl_object_insert_key(o, ucl_object_fromstring(
			    t->last_owd ? "measured" : "estimated"), "one_way",
			    0, false);
			ucl_object_insert_key(o, ucl_object_fromdouble(
			    t->last_err), "clock_error", 0, false);
		}
		/* The DSCP each way as the last reply saw it: the probe's
		 * at the reflector, the reply's here. */
		if (t->by_stamp && t->has_cos) {
			ucl_object_insert_key(o, ucl_object_fromint(
			    t->dscp_fwd), "dscp_forward", 0, false);
			ucl_object_insert_key(o, ucl_object_frombool(
			    t->dscp_refused), "dscp_refused", 0, false);
		}
		if (t->by_stamp && t->has_rtos)
			ucl_object_insert_key(o, ucl_object_fromint(
			    t->dscp_back), "dscp_backward", 0, false);
		/* The far end's view of the probe's addresses, a NAT. */
		if (t->has_loc) {
			char	ap[96];

			ucl_object_insert_key(o, ucl_object_fromstring(
			    addr_port(&t->loc.src, ap, sizeof(ap))),
			    "seen_source", 0, true);
			ucl_object_insert_key(o, ucl_object_fromstring(
			    addr_port(&t->loc.dst, ap, sizeof(ap))),
			    "seen_destination", 0, true);
			/* The same apart, arcana-stamp's location. */
			loc_put(o, "seen_source", &t->loc.src);
			loc_put(o, "seen_destination", &t->loc.dst);
			ucl_object_insert_key(o, ucl_object_fromstring(
			    t->nat == 0 ? "none" : t->nat == STAMP_NAT_SRC ?
			    "source" : t->nat == STAMP_NAT_DST ? "destination" :
			    "both"), "nat", 0, false);
		}
		/* The loss each way by the counters, all along. */
		if (dm) {
			ucl_object_insert_key(o, ucl_object_fromint((int64_t)
			    dmf), "dm_forward_lost", 0, false);
			ucl_object_insert_key(o, ucl_object_fromint((int64_t)
			    dmb), "dm_backward_lost", 0, false);
		}
		if (t->has_ti) {
			cur = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(cur, ucl_object_fromstring(
			    stamp_sync_name(t->ti.sync_in)), "sync_in", 0, true);
			ucl_object_insert_key(cur, ucl_object_fromstring(
			    stamp_tsm_name(t->ti.ts_in)), "timestamp_in", 0,
			    true);
			ucl_object_insert_key(cur, ucl_object_fromstring(
			    stamp_sync_name(t->ti.sync_out)), "sync_out", 0,
			    true);
			ucl_object_insert_key(cur, ucl_object_fromstring(
			    stamp_tsm_name(t->ti.ts_out)), "timestamp_out", 0,
			    true);
			ucl_object_insert_key(o, cur, "timestamp_info", 0,
			    false);
		}
	}
	/* The interval in progress, so far. */
	cur = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(cur, ucl_object_fromint(t->w_sent), "sent",
	    0, false);
	ucl_object_insert_key(cur, ucl_object_fromint(t->w_recv), "recv",
	    0, false);
	ucl_object_insert_key(cur, ucl_object_fromdouble(t->w_recv > 0 ?
	    t->w_sum / t->w_recv / 2 : 0), "delay", 0, false);
	ucl_object_insert_key(cur, ucl_object_fromdouble(t->w_ipdv_n >
	    0 ? t->w_ipdv_sum / t->w_ipdv_n : 0), "ipdv", 0, false);
	ucl_object_insert_key(cur, ucl_object_fromdouble(t->w_sent > 0 ?
	    (double)(t->w_sent - t->w_recv) / t->w_sent : 0), "loss", 0,
	    false);
	ucl_object_insert_key(cur, ucl_object_fromdouble(now -
	    t->win_start), "age", 0, false);
	ucl_object_insert_key(o, cur, "now", 0, false);
	/* The samples, the oldest first: t, delay, ipdv, loss, min,
	 * max, sent, received, the loss forward and backward (-1 not
	 * told: not by a stateful reflector), and the delay forward and
	 * backward with how (1 one way, 0 half the round trip, -1 not by
	 * STAMP: -1 each); the last report * eval ms are the report's. */
	s = ucl_object_typed_new(UCL_ARRAY);
	from = t->nsamples > 3600 ? t->nsamples - 3600 : 0;
	for (k = from; k < t->nsamples; k++) {
		sm = &t->samples[(t->head + k) % t->history];
		if ((uint64_t)sm->t <= after)
			continue;
		row = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(row, ucl_object_fromint((int64_t)
		    sm->t));
		ucl_array_append(row, ucl_object_fromdouble(sm->delay));
		ucl_array_append(row, ucl_object_fromdouble(sm->ipdv));
		ucl_array_append(row, ucl_object_fromdouble(sm->loss));
		ucl_array_append(row, ucl_object_fromdouble(sm->min));
		ucl_array_append(row, ucl_object_fromdouble(sm->max));
		ucl_array_append(row, ucl_object_fromint(sm->sent));
		ucl_array_append(row, ucl_object_fromint(sm->recv));
		ucl_array_append(row, ucl_object_fromdouble(sm->fwd));
		ucl_array_append(row, ucl_object_fromdouble(sm->back));
		ucl_array_append(row, ucl_object_fromdouble(sm->dfwd));
		ucl_array_append(row, ucl_object_fromdouble(sm->dback));
		ucl_array_append(row, ucl_object_fromint(sm->owd));
		ucl_array_append(s, row);
	}
	ucl_object_insert_key(o, s, "samples", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->nsamples),
	    "kept", 0, false);
	ucl_object_insert_key(o, pm_target_json(t, after, raw), "pm", 0,
	    false);
	if (t->ifname[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromstring(t->ifname),
		    "interface", 0, false);
	if (t->tca[0] > 0 || t->tca[1] > 0 || t->tca[2] > 0) {
		cur = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(cur, ucl_object_fromdouble(t->tca[0]),
		    "delay", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromdouble(t->tca[1]),
		    "ipdv", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromdouble(t->tca[2]),
		    "loss", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint(t->damping),
		    "damping", 0, false);
		ucl_object_insert_key(o, cur, "tca", 0, false);
	}
	ucl_object_insert_key(o, ucl_object_fromint(t->history), "history", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(t->down), "down", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(t->up), "up", 0, false);
	return (o);
}

static int
json_reply(struct work *w, ucl_object_t *top, struct json_rsp *rsp)
{
	unsigned char	*json;

	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	rsp->has_ok = true;
	if (json == NULL) {
		rsp->ok = false;
		rsp->error = "no memory";
		return (0);
	}
	rsp->json = wadopt(w, (char *)json);
	rsp->ok = true;
	return (0);
}

/*
 * What the probes have seen, as JSON, arcana-probe's state: the SD-WAN
 * targets (with after, only the samples and the measurement intervals
 * after that time; with raw, each one's last completed interval's raw
 * samples), when, and whether the prober runs.
 */
int
do_probes_read(struct work *w, uint64_t after, bool raw, struct json_rsp *rsp)
{
	ucl_object_t	*top, *arr;
	double		 now;
	int		 i;

	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	now = now_s();
	pthread_mutex_lock(&lock);
	for (i = 0; i < ntargets; i++) {
		/* The admin's monitors are read apart (do_monitors). */
		if (is_monitor(&targets[i]))
			continue;
		ucl_array_append(arr, target_json(&targets[i], now, after,
		    raw));
	}
	pthread_mutex_unlock(&lock);
	ucl_object_insert_key(top, arr, "targets", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint(time(NULL)), "time", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_frombool(started), "probing", 0,
	    false);
	return (json_reply(w, top, rsp));
}

/*
 * The SD-WAN edge as it is, as JSON, arcana-sdwan's state: the rules
 * and the steering, the services' instances, the record, the keys and
 * the faults.
 */
int
do_sdwan_state(struct work *w, struct json_rsp *rsp)
{
	ucl_object_t	*top;

	top = ucl_object_typed_new(UCL_OBJECT);
	sdwan_json(w, top);
	sdwan_bird_json(w, top);
	sdwan_dhcp_json(w, top);
	sdwan_dns_json(w, top);
	sdwan_proxy_json(w, top);
	sdwan_ids_json(w, top);
	record_json(top);
	sa_keys_json(w, top);
	faults_json(top);
	return (json_reply(w, top, rsp));
}

/* ---- Monitors: the admin's own, on any tunnel ----------------------- */

/* What the monitors have seen, as JSON, the host's and the jails'. */
int
do_monitors(struct work *w, uint64_t after, struct json_rsp *rsp)
{
	ucl_object_t	*top, *arr;
	double		 now;
	int		 i;

	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	now = now_s();
	pthread_mutex_lock(&lock);
	for (i = 0; i < ntargets; i++)
		if (is_monitor(&targets[i]))
			ucl_array_append(arr, target_json(&targets[i], now,
			    after, false));
	pthread_mutex_unlock(&lock);
	ucl_object_insert_key(top, arr, "monitors", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint(time(NULL)), "time", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_frombool(started), "probing", 0,
	    false);
	return (json_reply(w, top, rsp));
}

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

/* A target's settings, as targets_parse takes them back. */
static ucl_object_t *
target_conf(const struct target *t)
{
	ucl_object_t	*o, *tc;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(t->id), "id", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(t->address), "address",
	    0, false);
	if (t->ifname[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromstring(t->ifname),
		    "interface", 0, false);
	if (t->kind != KIND_AUTO)
		ucl_object_insert_key(o, ucl_object_fromstring(
		    kind_names[t->kind]), "kind", 0, false);
	if (t->underlay)
		ucl_object_insert_key(o, ucl_object_frombool(true), "underlay",
		    0, false);
	if (t->stamp_peer[0] != '\0') {
		ucl_object_insert_key(o, ucl_object_fromstring(t->stamp_if),
		    "stamp_interface", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(t->stamp_peer),
		    "stamp_peer", 0, false);
	}
	ucl_object_insert_key(o, ucl_object_fromint(t->fib), "fib", 0, false);
	if (!is_monitor(t)) {
		ucl_object_insert_key(o, ucl_object_fromint(t->count), "count",
		    0, false);
		ucl_object_insert_key(o, ucl_object_fromint(t->report),
		    "report", 0, false);
	}
	ucl_object_insert_key(o, ucl_object_fromint(t->interval), "interval",
	    0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->size), "size", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->dscp), "dscp", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->down), "down", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->up), "up", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->timeout), "timeout", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(t->eval), "eval", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->history), "history", 0,
	    false);
	if (t->pm_len != PM_LEN)
		ucl_object_insert_key(o, ucl_object_fromint(t->pm_len),
		    "measurement_interval", 0, false);
	/* Its measurement intervals' percentiles, where not the defaults. */
	{
		static const char *const pk[] = { "low_percentile",
		    "intermediate_percentile", "high_percentile" };
		static const double pd[] = { 10, 50, 90 };

		for (int k = 0; k < 3; k++)
			if (t->pct[k] != pd[k])
				ucl_object_insert_key(o, ucl_object_fromdouble(
				    t->pct[k]), pk[k], 0, false);
	}
	if (t->tca[0] > 0 || t->tca[1] > 0 || t->tca[2] > 0) {
		tc = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(tc, ucl_object_fromdouble(t->tca[0]),
		    "delay", 0, false);
		ucl_object_insert_key(tc, ucl_object_fromdouble(t->tca[1]),
		    "ipdv", 0, false);
		ucl_object_insert_key(tc, ucl_object_fromdouble(t->tca[2]),
		    "loss", 0, false);
		ucl_object_insert_key(tc, ucl_object_fromint(t->damping),
		    "damping", 0, false);
		ucl_object_insert_key(o, tc, "tca", 0, false);
	}
	return (o);
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
	if (!targets_swap(new, n, jail, OWN_MONITOR)) {
		*errp = wfmt(w, "%d targets at most, monitors and SD-WAN's "
		    "together", TARGETS_MAX);
		for (n--; n >= 0; n--)
			target_free(&new[n]);
		free(new);
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
	ucl_object_t	*arr, *o, *tc;
	const char	*name, *jail, *a, *v, *ifname, *e;
	double		 d;
	size_t		 i;
	int		 k;
	bool		 found;

	name = mon_name(sp);
	jail = sp->jail != NULL ? sp->jail : "";
	if (jail[0] != '\0' && !valid_jail(jail)) {
		*errp = "invalid jail name";
		return (-1);
	}
	arr = ucl_object_typed_new(UCL_ARRAY);
	found = false;
	pthread_mutex_lock(&lock);
	for (k = 0; k < ntargets; k++) {
		if (!is_monitor(&targets[k]) || strcmp(targets[k].jail, jail) !=
		    0)
			continue;
		if (strcmp(targets[k].id, name) == 0) {
			found = true;
			continue;
		}
		ucl_array_append(arr, target_conf(&targets[k]));
	}
	pthread_mutex_unlock(&lock);
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
				if (*v == '\0' || strlen(v) >= IFNAMSIZ)
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
 * The configuration of the probes as arcana-probe has it: each edge
 * (the host's first, "" its jail) with its SD-WAN targets, the links it
 * watches and the admin's monitors, as JSON
 * {"edges": [{"jail", "targets", "links", "monitors"}]}; malloc'd, NULL
 * for no memory.
 */
char *
probe_conf_json(void)
{
	ucl_object_t		*top, *edges, *e, *l;
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	const char		*jail, *key;
	char			*json;
	int			 k;

	top = ucl_object_typed_new(UCL_OBJECT);
	edges = ucl_object_typed_new(UCL_OBJECT);
	/* The host's, always. */
	e = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(edges, e, "", 0, true);
	pthread_mutex_lock(&lock);
	for (k = 0; k < ntargets + nlinks; k++) {
		/* A target's place left empty is none; a class's session is
		 * its target's classes. */
		if (k < ntargets && (targets[k].id[0] == '\0' ||
		    targets[k].cls[0] != '\0'))
			continue;
		jail = k < ntargets ? targets[k].jail : links[k - ntargets].jail;
		if ((o = ucl_object_lookup(edges, jail)) == NULL) {
			e = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(edges, e, jail, 0, true);
		} else
			e = (ucl_object_t *)(uintptr_t)o;
		key = k >= ntargets ? "links" : is_monitor(&targets[k]) ?
		    "monitors" : "targets";
		if ((o = ucl_object_lookup(e, key)) == NULL) {
			l = ucl_object_typed_new(UCL_ARRAY);
			ucl_object_insert_key(e, l, key, 0, true);
		} else
			l = (ucl_object_t *)(uintptr_t)o;
		if (k < ntargets) {
			ucl_object_t	*tc, *cl = NULL, *c;

			tc = target_conf(&targets[k]);
			for (int j = k + 1; j < ntargets && targets[j].cls[0] !=
			    '\0'; j++) {
				if (cl == NULL)
					cl = ucl_object_typed_new(UCL_ARRAY);
				c = ucl_object_typed_new(UCL_OBJECT);
				ucl_object_insert_key(c, ucl_object_fromstring(
				    targets[j].cls), "name", 0, false);
				ucl_object_insert_key(c, ucl_object_fromint(
				    targets[j].dscp), "dscp", 0, false);
				ucl_array_append(cl, c);
			}
			if (cl != NULL)
				ucl_object_insert_key(tc, cl, "classes", 0, false);
			ucl_array_append(l, tc);
		} else {
			o = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key((ucl_object_t *)(uintptr_t)o,
			    ucl_object_fromstring(links[k - ntargets].id), "id",
			    0, false);
			ucl_object_insert_key((ucl_object_t *)(uintptr_t)o,
			    ucl_object_fromstring(links[k - ntargets].ifname),
			    "interface", 0, false);
			ucl_object_insert_key((ucl_object_t *)(uintptr_t)o,
			    ucl_object_fromstring(links[k - ntargets].role),
			    "role", 0, false);
			ucl_array_append(l, (ucl_object_t *)(uintptr_t)o);
		}
	}
	pthread_mutex_unlock(&lock);
	l = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((o = ucl_object_iterate(edges, &it, true)) != NULL) {
		e = ucl_object_copy(o);
		ucl_object_insert_key(e, ucl_object_fromstring(ucl_object_key(o)),
		    "jail", 0, true);
		ucl_array_append(l, e);
	}
	ucl_object_unref(edges);
	ucl_object_insert_key(top, l, "edges", 0, false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	return (json);
}

/* Word w added to the comma-separated set at key k of o, once. */
static void
set_add(ucl_object_t *o, const char *k, const char *w)
{
	const ucl_object_t	*v;
	const char		*s, *p;
	char			 buf[4096];
	size_t			 n = strlen(w);

	if (w[0] == '\0')
		return;
	if ((v = ucl_object_lookup(o, k)) == NULL) {
		ucl_object_insert_key(o, ucl_object_fromstring(w), k, 0, true);
		return;
	}
	s = ucl_object_tostring(v);
	for (p = s; p != NULL; p = (p = strchr(p, ',')) != NULL ? p + 1 :
	    NULL)
		if (strncmp(p, w, n) == 0 && (p[n] == ',' || p[n] == '\0'))
			return;
	if ((size_t)snprintf(buf, sizeof(buf), "%s,%s", s, w) >= sizeof(buf))
		return;
	ucl_object_replace_key(o, ucl_object_fromstring(buf), k, 0, true);
}

/*
 * Each edge's interfaces and routing tables as the kernel counts them
 * now (PLAN-SDN-YANG 5.3.2, RFC 9375's termination point statistics
 * and entry summary): the interfaces its targets are measured over
 * (their interface) and its links watch, from their if_data; the FIBs
 * its targets go by, and FIB 0, their routes as netlink(4) dumps them.
 * A vnet jail's read in its own network by the helper, one question
 * for its interfaces and one for its FIBs.  As JSON {"edges": [{"jail",
 * "time", "interfaces": [{"name", "ibytes", ...}], "fibs": [{"fib",
 * "ipv4", "ipv6"}]}]}, the host's first; malloc'd, NULL for no memory.
 */
char *
probe_edges_json(void)
{
	static const char *const cn[] = { "ibytes", "ipackets", "imcasts",
	    "iqdrops", "ierrors", "noproto", "obytes", "opackets", "omcasts",
	    "oqdrops", "oerrors" };
	ucl_object_t		*want, *top, *arr, *e, *l, *o;
	const ucl_object_t	*w, *v;
	ucl_object_iter_t	 it;
	struct work		 jw;
	const char		*jail, *txt, *err, *line, *nl;
	char			 name[IFNAMSIZ], fb[16], *json;
	uintmax_t		 c[nitems(cn)];
	unsigned int		 f, n4, n6;
	int			 k;

	/* What each edge has: its interfaces and FIBs, as words. */
	want = ucl_object_typed_new(UCL_OBJECT);
	e = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(e, ucl_object_fromstring("0"), "fibs", 0, true);
	ucl_object_insert_key(want, e, "", 0, true);
	pthread_mutex_lock(&lock);
	for (k = 0; k < ntargets + nlinks; k++) {
		if (k < ntargets && targets[k].id[0] == '\0')
			continue;
		jail = k < ntargets ? targets[k].jail : links[k - ntargets].jail;
		if ((w = ucl_object_lookup(want, jail)) == NULL) {
			e = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(want, e, jail, 0, true);
		} else
			e = __DECONST(ucl_object_t *, w);
		if (k < ntargets) {
			set_add(e, "ifs", targets[k].ifname);
			snprintf(fb, sizeof(fb), "%d", targets[k].fib);
			set_add(e, "fibs", fb);
		} else
			set_add(e, "ifs", links[k - ntargets].ifname);
	}
	pthread_mutex_unlock(&lock);
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((w = ucl_object_iterate(want, &it, true)) != NULL) {
		jail = ucl_object_key(w);
		work_init(&jw);
		err = NULL;
		if (jail[0] != '\0' && scope_enter(&jw, jail, &err) != 0) {
			/* A jail not running: its network not there. */
			work_free(&jw);
			continue;
		}
		e = ucl_object_typed_new(UCL_OBJECT);
		if (jail[0] != '\0')
			ucl_object_insert_key(e, ucl_object_fromstring(jail),
			    "jail", 0, true);
		ucl_object_insert_key(e, ucl_object_fromint((int64_t)time(
		    NULL)), "time", 0, true);
		l = ucl_object_typed_new(UCL_ARRAY);
		if ((v = ucl_object_lookup(w, "ifs")) != NULL && (txt =
		    if_counters_text(&jw, ucl_object_tostring(v))) != NULL)
			for (line = txt; *line != '\0'; line = nl + 1) {
				if ((nl = strchr(line, '\n')) == NULL)
					break;
				if (sscanf(line, "%15s %ju %ju %ju %ju %ju %ju %ju "
				    "%ju %ju %ju %ju", name, &c[0], &c[1], &c[2],
				    &c[3], &c[4], &c[5], &c[6], &c[7], &c[8], &c[9],
				    &c[10]) != 12)
					continue;
				o = ucl_object_typed_new(UCL_OBJECT);
				ucl_object_insert_key(o, ucl_object_fromstring(
				    name), "name", 0, true);
				for (size_t i = 0; i < nitems(cn); i++)
					ucl_object_insert_key(o, ucl_object_fromint(
					    (int64_t)c[i]), cn[i], 0, true);
				ucl_array_append(l, o);
			}
		ucl_object_insert_key(e, l, "interfaces", 0, true);
		l = ucl_object_typed_new(UCL_ARRAY);
		if ((v = ucl_object_lookup(w, "fibs")) != NULL && (txt =
		    fib_routes_text(&jw, ucl_object_tostring(v))) != NULL)
			for (line = txt; *line != '\0'; line = nl + 1) {
				if ((nl = strchr(line, '\n')) == NULL)
					break;
				if (sscanf(line, "%u %u %u", &f, &n4, &n6) != 3)
					continue;
				o = ucl_object_typed_new(UCL_OBJECT);
				ucl_object_insert_key(o, ucl_object_fromint(f),
				    "fib", 0, true);
				ucl_object_insert_key(o, ucl_object_fromint(n4),
				    "ipv4", 0, true);
				ucl_object_insert_key(o, ucl_object_fromint(n6),
				    "ipv6", 0, true);
				ucl_array_append(l, o);
			}
		ucl_object_insert_key(e, l, "fibs", 0, true);
		work_free(&jw);
		ucl_array_append(arr, e);
	}
	ucl_object_unref(want);
	ucl_object_insert_key(top, arr, "edges", 0, false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	return (json);
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
