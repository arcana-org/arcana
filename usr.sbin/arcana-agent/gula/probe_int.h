/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula's prober inside: what its files (gula/probe*.c) share and
 * nothing else includes.  A target (struct target) is the engine's
 * (probe_engine.c) once it is in the table: only the engine's thread
 * reads or writes it then; the readers have its copy in the snapshot
 * the engine publishes (struct snap, probe_view.c).  What a target
 * keeps in bulk (its samples, its measurement intervals' raw samples
 * and figures) is rows (struct rows), chunks a snapshot shares rather
 * than copies: a row is never written again once a snapshot may see
 * it, a chunk shared is copied before one of its rows is changed.
 */

#ifndef PROBE_INT_H
#define	PROBE_INT_H

/* After <net/if.h>, "agent.h" and "stamp.h". */
#include <stdatomic.h>

struct pollfd;
struct ucl_object_s;

#define	OWN_SDWAN	"sdwan"
#define	OWN_MONITOR	"monitor"
#define	TARGETS_MAX	256
#define	OUT_MAX		64	/* probes in the air, each */
#define	PKT_MAX		10000
#define	STAMP_RETRY	10.0	/* s: STAMP tried again, fallen back */
#define	PUB_B64		44	/* an X25519 public half, base64 */
#define	PM_LEN		60	/* s: a measurement interval, by default */
/* A target's name (target_name(): id@jail/class) and a threshold's
 * fault object (name/metric), whole. */
#define	TNAME_MAX	(128 + 1 + 64 + 1 + 33)
#define	TOBJ_MAX	(TNAME_MAX + 8)

enum { ST_UNKNOWN = PROBE_UNKNOWN, ST_UP = PROBE_UP, ST_DOWN = PROBE_DOWN,
    ST_ENDED = PROBE_ENDED, ST_ERROR = PROBE_ERROR };
/* A target's kind, arcana-probe's: the agent's choice, STAMP alone, ICMP
 * alone. */
enum { KIND_AUTO, KIND_STAMP, KIND_ICMP };
extern const char *const kind_names[3];
extern const char *const state_names[5];

/* ---- Rows: chunks a snapshot shares (probe_pm.c) -------------------- */

struct rchunk {
	atomic_int	 ref;
	unsigned char	 v[];
};

/* The chunks of rows as they were when it was made: never changed. */
struct rowsnap {
	atomic_int	 ref;
	int		 nc;
	uint64_t	 base;		/* the first chunk's first row */
	struct rchunk	*c[];
};

/* The engine's: rows lo to hi (hi not), base the first chunk's first. */
struct rows {
	size_t		 esz;
	int		 per;
	struct rchunk	**c;
	int		 nc, cap;
	uint64_t	 base, lo, hi;
	struct rowsnap	*snap;		/* the last made, while current */
};

/* What a snapshot has of rows: those lo to hi of s. */
struct rowsview {
	struct rowsnap	*s;
	uint64_t	 lo, hi;
	size_t		 esz;
	int		 per;
};

/* Rows to read, the engine's or a snapshot's. */
struct rowsrc {
	struct rchunk	*const *c;
	uint64_t	 base, lo, hi;
	size_t		 esz;
	int		 per;
};

void		 rows_init(struct rows *, size_t, int);
void		 rows_clear(struct rows *);
void		*rows_push(struct rows *);
void		*rows_at(struct rows *, uint64_t);
void		 rows_trim(struct rows *, uint64_t);
struct rowsnap	*rows_snap(struct rows *);
void		 rowsnap_put(struct rowsnap *);
void		 rows_src(const struct rows *, struct rowsrc *);
void		 rowsview_src(const struct rowsview *, struct rowsrc *);
const void	*rowsrc_at(const struct rowsrc *, uint64_t);

/* ---- Echoes: ids and sequences (probe_echo.c) ----------------------- */

struct echo_out {
	uint16_t	 seq;
	double		 sent;
	bool		 live;
};

/* The echo ids of the host's targets, or the jails', each family's,
 * sorted. */
struct echo_id {
	uint16_t	 id;
	uint8_t		 af;
	int		 idx;		/* in the table */
};

struct echo_ids {
	int		 n;
	struct echo_id	 v[TARGETS_MAX];
};

void		 echo_ids_clear(struct echo_ids *);
void		 echo_ids_add(struct echo_ids *, int, uint16_t, int);
void		 echo_ids_sort(struct echo_ids *);
int		 echo_ids_find(const struct echo_ids *, int, uint16_t);
int		 echo_parse(int, const unsigned char *, size_t, uint16_t *,
		    uint16_t *);
int		 echo_slot(struct echo_out *, int, bool *);
int		 echo_take(struct echo_out *, int, uint16_t);

/* ---- A target ------------------------------------------------------- */

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
	/* Its echo socket: its FIB's, the host's, or its jail's, FIB's and
	 * family's (probe_icmp.c); shared, neither its own. */
	int			 sock;
	/* Which it is to the engine, for what is handed back to it: the
	 * same while it is kept. */
	uint64_t		 serial;
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
	/*
	 * Its key derived off the engine's thread (probe_engine.c's
	 * worker): asked for (pending, the answer of key_gen awaited),
	 * not derived (failed, told to the next STAMP probe); derived anew
	 * against the key it had (rekeying, was); a fallen-back target's
	 * STAMP try waiting for it (try_wait).
	 */
	bool			 key_pending, key_failed, rekeying, try_wait;
	uint32_t		 key_gen;
	struct stamp_key	 was;
	/* Kind stamp's key derived anew no sooner (stamp_rekey()); the
	 * stamp-unauthenticated alarm maybe open, cleared by the next
	 * authenticated answer. */
	double			 rekey_at;
	bool			 downgraded;
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
	struct echo_out		 out[OUT_MAX];
	int			 state;
	char			 error[128];
	/* Its echo socket not made: tried again at open_at, the wait
	 * open_wait doubling; a jail's made by the worker, waited for
	 * (opening). */
	double			 open_at, open_wait;
	bool			 opening;
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
	struct rows		 samp;		/* struct sample */
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
	time_t			 pm_start;	/* its name, the wall clock's */
	double			 pm_due;	/* when it ends, monotonic */
	uint32_t		 pm_sent, pm_recv, pm_seen;
	struct pm_acc		 pm_acc[PM_NM];
	int32_t			 pm_prev[3];
	uint64_t		 pm_fwd0, pm_back0;
	struct rows		 pm_raw, pm_last;	/* struct pm_raw */
	struct rows		 pm_done;		/* struct pm */
};

/* ---- The links an edge watches (probe_link.c) ----------------------- */

#define	LINKS_MAX	128
struct link {
	char	jail[64];	/* the edge's; "" the host's */
	char	ifname[IFNAMSIZ];
	char	id[96];		/* the UNI's or UCS end point's */
	char	role[8];	/* uni, ucs */
	int	state;		/* -1 not known, 0 down, 1 up */
};

int		 links_set(struct work *, const char *, const char *,
		    const char **);
bool		 has_links(const char *);
void		 links_watch(void);
void		 links_reconcile(void);
int		 links_copy(struct link *, int);

/* ---- The snapshot the readers have (probe_view.c) ------------------- */

/*
 * A target as the engine last published it: its copy, nothing in it
 * the engine's (no sender, no rows); its sender's counts then, and
 * what of its rows there were.
 */
struct tview {
	struct target			 t;
	struct stamp_sender_stats	 st;
	bool				 has_st;
	struct rowsview			 samp, raw, last, done;
};

struct snap {
	atomic_int	 ref;
	bool		 probing;
	int		 n;
	struct tview	 v[];
};

void		 snap_publish(struct target *, int, bool);
struct snap	*snap_get(void);
void		 snap_put(struct snap *);
struct ucl_object_s *target_conf(const struct target *);

/* ---- The table (probe.c) -------------------------------------------- */

const char	*target_name(const struct target *, char *, size_t);
const char	*conf_path(char *, size_t, const char *, const char *);
int		 conf_write(const char *, const char *, const char *,
		    const char **);
int		 targets_parse(struct work *, const char *, struct target *,
		    char *, size_t, const char *, const char **);
bool		 is_monitor(const struct target *);
bool		 targets_swap(struct target **, int *, struct target *, int,
		    const char *, const char *);
void		 targets_drop(struct target *, int);
void		 target_close(struct target *);
void		 target_free(struct target *);
void		 probe_reconcile(struct target *, int);

/* ---- The engine (probe_engine.c) ------------------------------------ */

double		 now_s(void);
void		 open_later(struct target *, double);
void		 engine_changed(void);
void		 engine_dirty(void);
bool		 engine_swap(struct target *, int, const char *, const char *);
void		 engine_begin(void);
void		 engine_watch(void);
void		 engine_start(void);
void		 engine_key(struct target *);

/* ---- Measurement (probe_pm.c) --------------------------------------- */

void		 state_set(struct target *, int);
void		 miss(struct target *);
void		 hit(struct target *, double);
void		 window_end(struct target *, double);
void		 pm_hit(struct target *, double, const struct stamp_sample *);
void		 pm_timers(struct target *, double);
void		 pm_forget(struct target *);
void		 pm_now(const struct target *, const struct stamp_sender_stats *,
		    const struct rowsrc *, struct pm *);
void		 pm_lost(const struct target *, const struct stamp_sender_stats *,
		    uint64_t *, uint64_t *);
void		 samples_reset(struct target *);
void		 target_rows(struct target *);
void		 target_rows_free(struct target *);

/* ---- STAMP (probe_stamp.c) ------------------------------------------ */

void		 stamp_drop(struct target *);
int		 stamp_key_derive(const char *, const char *, int,
		    struct stamp_key *, char *, size_t);
bool		 stamp_key_get(struct target *);
void		 stamp_key_told(struct target *, bool, const struct stamp_key *,
		    const char *);
void		 stamp_rekey(struct target *);
int		 stamp_send_one(struct target *, bool);
void		 stamp_lost(struct target *, double);
void		 stamp_recv_all(struct target *);
void		 stamp_window(struct target *, struct sample *);
const char	*addr_port(const struct sockaddr_storage *, char *, size_t);

/* ---- ICMP (probe_icmp.c) -------------------------------------------- */

enum { JS_HAVE, JS_WAIT, JS_ASK, JS_FULL };

bool		 target_open(struct target *);
int		 jsock_want(struct target *, uint32_t *);
int		 jsock_made(const char *, int, int, uint32_t, int, bool, char *,
		    size_t);
int		 jail_socket(const char *, int, char *, size_t);
void		 icmp_send(struct target *);
void		 icmp_recv_sock(int, int, struct target *, int, double);
void		 icmp_table(struct target *, int);
int		 icmp_pollfds(struct pollfd *, int *, int);

#endif /* !PROBE_INT_H */
