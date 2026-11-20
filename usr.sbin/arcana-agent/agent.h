/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _AGENT_H_
#define _AGENT_H_

#include <spawn.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/* Generated into the object directory; <> so that a stale copy next
 * to the sources is never picked up. */
#include <arcana.h>

#include "textfit.h"

#define	ARCANA_AGENT_VERSION	"0.348.0"

/* The nice(1) value of a program a read runs. */
#define	READ_NICE		10

#define	PATH_JAIL_CONF		"/etc/jail.conf"
#define	PATH_JAIL_CONF_D	"/etc/jail.conf.d"
#define	PATH_JAIL_BIN		"/usr/sbin/jail"
#define	PATH_RC_DIRS		"/etc/rc.d:/usr/local/etc/rc.d"
#define	PATH_SERVICE_BIN	"/usr/sbin/service"
#define	PATH_SYSRC_BIN		"/usr/sbin/sysrc"
#define	PATH_NETSTAT_BIN	"/usr/bin/netstat"
#define	PATH_SWAPINFO_BIN	"/usr/sbin/swapinfo"
#define	PATH_ZPOOL_BIN		"/sbin/zpool"
#define	PATH_PKG_BIN		"/usr/sbin/pkg"
#define	PATH_GIT_BIN		"/usr/local/bin/git"
#define	PATH_TRACEROUTE_BIN	"/usr/sbin/traceroute"
#define	PATH_IFCONFIG_BIN	"/sbin/ifconfig"
#define	PATH_NGCTL_BIN		"/usr/sbin/ngctl"
#define	PATH_JEXEC_BIN		"/usr/sbin/jexec"
#define	PATH_CRONTAB_BIN	"/usr/bin/crontab"
#define	PATH_KLDLOAD_BIN	"/sbin/kldload"
#define	PATH_KLDUNLOAD_BIN	"/sbin/kldunload"
#define	PATH_ZFS_BIN		"/sbin/zfs"
#define	PATH_GPART_BIN		"/sbin/gpart"
#define	PATH_CAMCONTROL_BIN	"/sbin/camcontrol"
#define	PATH_MOUNT_BIN		"/sbin/mount"
#define	PATH_UMOUNT_BIN		"/sbin/umount"
#define	PATH_FSTAB		"/etc/fstab"
#define	PATH_WG_BIN		"/usr/bin/wg"
#define	PATH_WG_DIR		"/usr/local/etc/wireguard"
#define	PATH_SWANCTL_BIN	"/usr/local/sbin/swanctl"
#define	PATH_SQUID_BIN		"/usr/local/sbin/squid"
#define	PATH_CICAP_BIN		"/usr/local/bin/c-icap"
#define	PATH_SURICATA_BIN	"/usr/local/bin/suricata"
#define	SURICATA_ETC		"/usr/local/etc/suricata"
#define	PATH_POUDRIERE_BIN	"/usr/local/bin/poudriere"
#define	PATH_IFMCSTAT_BIN	"/usr/sbin/ifmcstat"
#define	PATH_RTADVCTL_BIN	"/usr/sbin/rtadvctl"
#define	PATH_FRESHCLAM_CONF	"/usr/local/etc/freshclam.conf"
#define	PATH_SURICATA_RULES	"/var/lib/suricata/rules"
#define	PATH_POUDRIERE_ETC	"/usr/local/etc"
#define	PATH_CICAP_MODULES	"/usr/local/lib/c_icap"
#define	PATH_CLAMAV_DB		"/var/db/clamav"
#define	PATH_SWANCTL_DIR	"/usr/local/etc/swanctl"
#define	PATH_BIRDC_BIN		"/usr/local/sbin/birdc"
#define	PATH_BIRD_BIN		"/usr/local/sbin/bird"
#define	PATH_SETFIB_BIN		"/usr/sbin/setfib"
#define	PATH_NTP_CONF		"/etc/ntp.conf"
#define	PATH_RTADVD_CONF	"/etc/rtadvd.conf"
#define	PATH_DNSMASQ_BIN	"/usr/local/sbin/dnsmasq"
#define	PATH_UNBOUND_BIN	"/usr/sbin/local-unbound"
#define	PATH_RTSOL_BIN		"/sbin/rtsol"
#define	PATH_BIRD_CONF		"/usr/local/etc/bird.conf"
#define	OWN_SERVICE		"arcana_agent"	/* the rc.d name of this daemon */
#define	PATH_MAKE_BIN		"/usr/bin/make"
#define	PATH_KEYSCAN_BIN	"/usr/bin/ssh-keyscan"
#define	PATH_KEYGEN_BIN		"/usr/bin/ssh-keygen"
#define	PATH_BUILD_DIR		"/var/cache/arcana-build"
#define	PATH_BUILD_CONF		"/usr/local/etc/arcana/config.mk"

/* jail -e separator: ASCII unit separator, never in a jail.conf value. */
#define	JAIL_E_SEP		"\037"

#define	EXEC_TIMEOUT_SEC	3600	/* a pkg upgrade can take a while */
/*
 * A read of a jail's own program (birdc, wg, ipfw, anything by
 * jexec(8)), and every birdc of SD-WAN's instances: killed with its
 * process group when it has not ended in this long, or has been silent
 * as long.  The jail's root may put one there that never ends.
 */
#define	JAIL_READ_SEC		5
/*
 * pkg is stopped when nothing has come from it for this long (default
 * of --pkg-idle): off a terminal it prints a dot each tenth of a
 * download, so a large package on a slow link is quiet for minutes, but
 * not for ten.
 */
#define	PKG_IDLE_SEC		600
/*
 * Once pkg has begun installing ("[1/2] Upgrading ...", "Extracting"),
 * its silence is a package's script at work, often an rc stop that
 * waits on its daemon: not a stalled download, and killing pkg then
 * leaves that package half installed.  Said in the job's trace at the
 * fetch bound (--pkg-idle), and pkg stopped only once silent this many
 * times as long (30 minutes by default): a script's own work (a cache
 * rebuilt, a database converted) takes minutes, a stop that has not
 * returned in half an hour will not, and the lane is wanted back;
 * within the hour any program has (EXEC_TIMEOUT_SEC).
 */
#define	PKG_BUSY_TIMES		3
/* A terminal nobody typed in for this long is hung up. */
#define	TERM_IDLE_SEC		1800
#define	PATH_LOGIN_BIN		"/usr/bin/login"
/* Which console users may become which account by a mapped login. */
#define	PATH_TERMINAL_USERS	"/usr/local/etc/arcana/terminal-users"
#define	PATH_GETENT_BIN		"/usr/bin/getent"
/* Jobs of pkg in jails, each its own jail, at work at once. */
#define	PKG_LANES		4
/*
 * The repository asked whether it answers, from where pkg will run,
 * before pkg is: its meta.conf fetched, given up after this long.
 */
#define	REPO_REACH_SEC		8
/*
 * What a job's watched program (pkg) left running by an agent before
 * this one is given after SIGTERM before SIGKILL (exec_orphans()).
 */
#define	ORPHAN_GRACE_SEC	5
#define	TRACE_MAX		ARC_MAX_STEPS
#define	TRACE_DEPTH		16

struct opts {
	const char	*jail_conf;
	const char	*jail_conf_d;
	const char	*jail_bin;
	const char	*rc_dirs;	/* colon separated */
	gid_t		 sock_gid;	/* -g: the socket's group, the console's; -1 none */
	const char	*service_bin;
	const char	*sysrc_bin;
	const char	*netstat_bin;
	const char	*swapinfo_bin;
	const char	*zpool_bin;
	const char	*pkg_bin;
	const char	*self_path;	/* the program an update replaces */
	const char	*ifconfig_bin;
	const char	*ngctl_bin;
	const char	*jexec_bin;
	const char	*crontab_bin;	/* crontab(1): users' crontabs */
	const char	*kldload_bin;
	const char	*kldunload_bin;
	const char	*zfs_bin;
	const char	*gpart_bin;
	const char	*camcontrol_bin;
	const char	*mount_bin;
	const char	*umount_bin;
	const char	*fstab_path;
	const char	*sysctl_bin;
	const char	*ipfw_bin;
	const char	*ipfw_rules;
	const char	*sysctl_conf;
	const char	*smtpd_bin;	/* OpenSMTPD, a plugin: smtpd(8) */
	const char	*smtpctl_bin;	/* and smtpctl(8) */
	const char	*smtpd_conf;	/* its smtpd.conf(5) */
	const char	*smtpd_dir;	/* the agent's tables and kept form */
	const char	*speederv2_bin;	/* UDPspeeder's FEC relay, a plugin */
	const char	*speederv2_log;	/* where syslogd(8) writes its lines */
	const char	*sslproxy_bin;	/* SSLproxy, a plugin: sslproxy(1) */
	const char	*sslproxy_conf;	/* its sslproxy.conf(5) */
	const char	*sslproxy_dir;	/* its CA, form and fwd rules */
	const char	*log_dir;	/* where syslogd(8) writes */
	const char	*history_conf;	/* how the host is sampled */
	const char	*archive_dir;	/* --archive: the samples' long run */
	const char	*tools_dir;	/* where programs without an option are */
	const char	*helper_bin;	/* this program, run again with -Q */
	bool		 helper_self;	/* it is this program: the host's own is read here */
	const char	*own_bin;	/* this program as it runs: its helpers of the host's */
	const char	*wg_bin;
	const char	*wg_dir;	/* where wg-quick(8) reads from */
	const char	*swanctl_bin;
	const char	*squid_bin;	/* squid(8): the proxies, a plugin */
	const char	*cicap_bin;	/* c-icap: malware scanning, a plugin */
	const char	*suricata_bin;	/* suricata: intrusion detection, a plugin */
	const char	*poudriere_bin;	/* poudriere(8): the package builder, a plugin */
	const char	*ifmcstat_bin;	/* ifmcstat(8): IGMP's and MLD's state */
	const char	*rtadvctl_bin;	/* rtadvctl(8): rtadvd's reload and show */
	const char	*freshclam_conf; /* ClamAV's freshclam.conf, its mirrors */
	const char	*suricata_rules; /* where suricata-update writes the ruleset */
	const char	*exports_file;	/* exports(5) */
	const char	*ctl_conf;	/* ctl.conf(5) */
	const char	*hast_conf;	/* hast.conf(5) */
	const char	*poudriere_etc;	/* where poudriere.conf and poudriere.d are */
	const char	*swanctl_dir;	/* where swanctl(8) reads from */
	const char	*birdc_bin;
	const char	*bird_bin;	/* bird(8), to parse a configuration */
	const char	*setfib_bin;	/* setfib(1): a daemon in a table */
	const char	*ntp_conf;	/* ntp.conf, for the ntp job */
	const char	*rtadvd_conf;	/* rtadvd.conf, for the rtadvd job */
	const char	*dnsmasq_bin;	/* dnsmasq(8): the UNIs' DHCP */
	const char	*unbound_bin;	/* local-unbound(8): the DNS filters */
	const char	*rtsol_bin;	/* rtsol(8): an interface's SLAAC */
	const char	*pfkey_path;	/* --pfkey: a stand-in for PF_KEY */
	const char	*bird_conf;	/* its main file */
	int		 safe_wait;	/* s, for a safe change to be confirmed */
	const char	*sctp_also;	/* more addresses for SCTP listeners */
	const char	*telegram_api;	/* the Bot API's base, for notify */
	const char	*git_bin;
	const char	*traceroute_bin;	/* and the same with 6 */
	const char	*keyscan_bin;	/* ssh-keyscan(1) */
	const char	*keygen_bin;	/* ssh-keygen(1) */
	const char	*make_bin;
	const char	*build_dir;	/* where a tree is cloned and built */
	const char	*build_conf;	/* this host's config.mk for it */
	const char	*build_user;	/* --build-user: whom a build runs as */
	bool		 build_user_set; /* named: checked, root or not */
	const char	*root;		/* --root: the system's files under it */
	int		 bird_watch_s;	/* --bird-watch: BIRD's sessions, how often */
	int		 routes_cache_s;	/* --routes-cache: a FIB's count kept */
	int		 smtpd_watch_s;	/* --smtpd-watch: OpenSMTPD, how often */
	int		 sslproxy_watch_s; /* --sslproxy-watch: set 27, how often */
	const char	*rc_subr;	/* --rc-subr: rc.subr(8), a service's
					 * pidfile and program asked of it */
	const char	*dev_dir;	/* --dev: /dev, its devfs mounts */
	const char	*devd_pipe;	/* --devd-pipe: devd(8)'s socket */
	int		 stamp_port;	/* --stamp-port: far ends' STAMP; 0 none */
	int		 bmp_port;	/* --bmp-port: FIB 0's BMP station */
	const char	*stampd_keys;	/* --stampd-keys: stampd(8)'s key file */
	const char	*stamp_clock;	/* --stamp-clock, as given; NULL none */
	int		 pkg_idle_s;	/* --pkg-idle: a silent pkg, stopped after */
	const char	*terminal_login; /* --terminal-login: login(1) */
	const char	*terminal_users; /* --terminal-users: mapped logins'
					 * file; "none" no terminal-as at all */
	const char	*terminal_getent; /* --terminal-getent: a jail's
					 * getent(1), its accounts proved */
	const char	*terminal_nologin; /* --terminal-nologin: what stands
					 * for /var/run/nologin */
	bool		 test_no_terminal_as; /* --test-unregister terminal-as:
					 * the tests' older agent */
	int		 terminal_idle_s; /* --terminal-idle: a terminal not
					 * typed in, hung up after */
	int		 repo_reach_s;	/* --repo-reach: pkg's repository
					 * asked first, given up after */
	int		 pkg_lanes;	/* jobs of pkg in jails at once, at start */
	const char	*jobs_conf;	/* where lanes is kept */
	const char	*nacm_file;	/* NACM's rules (superbia/ynacm.c) */
	const char	*subs_file;	/* the configured subscriptions
					 * (invidia/ynotif.c) */
	const char	*features;	/* --features: hello's, NULL all */
	const char	*alloc_fault;	/* --alloc-fault: a test's (work.c) */
	char		 build[65];	/* SHA-256 of the running program */
	bool		 debug;
};

extern struct opts opts;

/*
 * work.c: one request.  Everything a reply points to is allocated from
 * the request's pool and released with it, and the request records what
 * it did in its own trace.
 */
/* What a step is, by the number arcana-jobs' step has its kind by. */
enum {
	STEP_DAEMON = 0,	/* the agent's own */
	STEP_LIB,		/* a library's call */
	STEP_SYSCALL,
	STEP_FILE,		/* a file read or written */
	STEP_EXEC,		/* a program run */
};

struct step {
	uint8_t		 kind;		/* STEP_* */
	const char	*label;
	const char	*detail;
	int		 parent;
	bool		 done;
	bool		 ok;
	uint64_t	 start;
	uint64_t	 dur;
	const char	**argv;	/* from its start (step_argv()) */
	size_t		 argc;
	bool		 ran;		/* its status and output attached */
	int		 status;
	const char	*out;
	size_t		 outlen;
	const char	*err;
	size_t		 errlen;
	bool		 notrun;	/* a dry run's program: not run */
	struct live	*live;		/* a job's program: its output as it
					 * comes (ira/live.c), or NULL */
};

struct work {
	void		**ptrs;		/* allocations owned by the request */
	size_t		 nptrs;
	size_t		 capptrs;
	struct step	 steps[TRACE_MAX];
	int		 nsteps;
	int		 stack[TRACE_DEPTH];
	int		 depth;
	/* The jail whose network the request is about; NULL the host's. */
	const char	*jail;
	int		 jid;
	const char	*jroot;
	/*
	 * A read's: the programs it runs are given READ_NICE, so that
	 * what the console asks for, often, does not crowd the host's
	 * own work or a job's.
	 */
	bool		 nice;
	/*
	 * A job's trace is read by other threads while the job runs: the
	 * step functions change it under this lock, and trace_copy() of
	 * this work into another reads it under it.
	 */
	pthread_mutex_t	 lock;
	/* The peer told each step as it begins and ends, or NULL. */
	cbl_conn	*tell;
	/* A job's: its steps changing are the jobs' change (yang_changed). */
	bool		 told;
	/*
	 * A job's, set by another thread when it is cancelled at work: a
	 * watched program it runs (exec_set_watch()) is stopped.
	 */
	_Atomic bool	 cancel;
	/*
	 * A dry run's (jobs_dry_run()): every step is taken as a job's
	 * would be, but what would change something is said and not
	 * done.  A program is traced and not started, unless run_read()
	 * runs it, which only reads; a file written, the kernel's state
	 * changed or a signal sent is a step saying so (work_dry()).
	 */
	bool		 dry;
	/*
	 * A read's: how far whom it is for is trusted with what it gives
	 * out (clearance()); a work made for no request a viewer's.
	 */
	int		 clear;
	/*
	 * Out of memory (work_oom()): what it allocated since came from
	 * the reserve (work.c).  It runs no program more (run_exec()),
	 * and its request or job fails at its end, "out of memory".
	 */
	bool		 oom;
	/* --alloc-fault: the allocation that fails as if memory had run
	 * out, its number (1 the first), and how many it has made. */
	size_t		 fault_at;
	size_t		 nalloc;
};

void		 work_init(struct work *);
void		 work_free(struct work *);
void		*wadopt(struct work *, void *);
void		*wmalloc(struct work *, size_t);
void		*wcalloc(struct work *, size_t, size_t);
char		*wstrdup(struct work *, const char *);
char		*wstrndup(struct work *, const char *, size_t);
char		*wfmt(struct work *, const char *, ...) __printflike(2, 3);
char		*wvis(struct work *, const char *);
const char	*wtext(struct work *, const char *);
const char	*wname(struct work *, const char *);
char		*wvfmt(struct work *, const char *, va_list) __printflike(2, 0);
void		*wgrow(struct work *, void *, size_t, size_t *, size_t);
void		 work_oom(struct work *);
bool		 work_oom_seen(void);
void		 work_oom_clear(void);
void		 work_fault(struct work *, const char *);

int		 step_begin(struct work *, uint8_t, const char *,
		    const char *, ...) __printflike(4, 5);
void		 step_end(struct work *, int, bool, const char *, ...)
		    __printflike(4, 5);
void		 step_argv(struct work *, int, char *const []);
void		 step_exec(struct work *, int, char *const [], int,
		    const char *, size_t, const char *, size_t);
void		 step_notrun(struct work *, int, char *const []);
bool		 work_dry(struct work *, int);
struct arcana_jobs_step;
void		 trace_copy(struct work *, struct work *,
		    const struct arcana_jobs_step **, size_t *);
void		 trace_tell(struct work *, cbl_req *);
uint64_t	 now_us(void);

/* ira/exec.c: run a program without a shell, capturing its output. */
struct execres {
	int		 status;	/* exit status, 128 + signal, or -1 */
	const char	*out;
	size_t		 outlen;
	const char	*err;
	size_t		 errlen;
	bool		 truncated;	/* more output than was kept */
	bool		 timedout;	/* killed: it did not finish in time */
	int		 stalled;	/* killed: silent this many seconds */
	bool		 cancelled;	/* killed: its job was cancelled */
	const char	*note;		/* after a stall: what was found of
					 * its cause, exec_error() says it */
	const char	*waited;	/* stalled in its busy phase
					 * (exec_set_busy()): what it
					 * printed last */
};

int		 run_exec(struct work *, char *const [], struct execres *);
int		 run_read(struct work *, char *const [], struct execres *);
int		 run_read_max(struct work *, char *const [],
		    struct execres *, size_t);
bool		 pid_alive(pid_t);
bool		 pid_is(pid_t, const char *);
pid_t		 pidfile_of(const char *, const char *);
void		 pid_stop(pid_t, const char *, int);
void		 exec_set_home(struct work *, const char *);
void		 exec_set_env(struct work *, const char *, const char *);
void		 exec_set_stdin(const char *, size_t);
void		 exec_set_fds(int, int);
const char	*tmp_dir(void);
void		 exec_set_secret(bool);
void		 exec_set_hide(const char *);
void		 exec_set_watch(int);
void		 exec_set_busy(const char *const *, int, const char *);
void		 exec_set_job(uint64_t, uint8_t, const char *);
void		 exec_note_ancestors(void);
void		 exec_set_limit(int);
/* What a job's watched program left running by an agent before this
 * one: stopped, each group told to fn (its job, kind, title, the pid
 * that led it, when it began, how it ended); how many. */
size_t		 exec_orphans(void (*)(uint64_t, uint8_t, const char *, pid_t,
		    time_t, const char *, void *), void *);
int		 mkdir_mode(const char *, mode_t);
const char	*storage_protected(struct work *, const char *, bool);
int		 agent_spawn(pid_t *, const char *, const posix_spawn_file_actions_t *,
		    const posix_spawnattr_t *, char *const [], char *const []);
int		 run_exec_lines(struct work *, char *const [],
		    void (*)(const char *, void *), void *);
int		 run_exec_max(struct work *, char *const [], struct execres *,
		    size_t);
const char	*exec_error(struct work *, const struct execres *,
		    const char *);

/* ira/jails.c: running jails (libjail) and their processes (libprocstat). */
struct jinfo {
	int		 jid;
	const char	*name;
	const char	*hostname;
	const char	*path;
	const char	*ip4;		/* comma separated */
	const char	*ip6;
	const char	*osrelease;
	bool		 vnet;
	bool		 dying;
	bool		 persist;
	int		 parent;
	int		 children;
	int		 securelevel;
	uint32_t	 nproc;
	uint64_t	 rss_kb;
	double		 cpu_pct;
};

int		 jails_running(struct work *, struct jinfo **, size_t *,
		    const char **);
void		 jails_procstats(struct work *, struct jinfo *, size_t);
int		 jail_named(struct work *, const char *, struct jinfo *);
int		 jail_lookup(struct work *, const char *);

/* superbia/confread.c: configured jails, as jail(8) -e resolves them;
 * a file it could not read, and why. */
struct conf_error {
	const char	*scope;
	const char	*message;
};

struct cjail {
	const char	*name;
	const char	*scope;		/* file to give jail(8) -f */
	struct arc_param	*params;
	size_t		 nparams;
};

struct cconf {
	const char	**scopes;
	size_t		 nscopes;
	struct cjail	*jails;
	size_t		 njails;
	struct conf_error *errors;
	size_t		 nerrors;
};

/* rc.d/jail's say on what starts at boot: jail_enable, jail_list. */
struct jboot {
	bool		 on;		/* jail_enable is yes */
	const char	*list;		/* jail_list, or NULL: every jail */
};
void		 jail_boot_read(struct work *, struct jboot *);
void		 jail_boot_files(struct work *, struct jboot *);
bool		 jail_boot_of(const struct jboot *, const char *);
int		 jail_boot_set(struct work *, const char *, bool,
		    const struct cconf *, const char **);
void		 conf_read(struct work *, struct cconf *);
int		 conf_scope_read(struct work *, const char *, struct cjail **,
		    size_t *, const char **);
const struct cjail *conf_jail(const struct cconf *, const char *);
const struct arc_param *cjail_param(const struct cjail *, const char *);
const char	*cjail_param1(const struct cjail *, const char *);

/*
 * superbia/host.c: what the host is and the agent that answers,
 * arcana-host's host as a read has it (yhost.c); features, what this
 * agent takes that one before it did not.
 */
struct host_facts {
	const char	*hostname;
	const char	*sysname;
	const char	*release;
	const char	*machine;
	bool		 has_osreldate;
	uint32_t	 osreldate;
	bool		 has_ncpu;
	uint32_t	 ncpu;
	bool		 has_physmem;
	uint64_t	 physmem;
	bool		 has_boottime;
	int64_t		 boottime;
	bool		 has_time;
	int64_t		 time;
	bool		 has_securelevel;
	int32_t		 securelevel;
	bool		 has_privileged;
	bool		 privileged;
	const char	*version;
	const char	*build;
	struct {
		size_t		 n;
		const char	*const *v;
	}		 plugins;
	bool		 has_safe_wait;
	uint32_t	 safe_wait;
	struct {
		size_t		 n;
		const char	*const *v;
	}		 features;
	bool		 terminal_users;	/* mapped logins' file usable */
	const char	*kernel_version;	/* kern.version's first line */
	bool		 has_ip6_redirect;
	bool		 ip6_redirect;		/* net.inet6.ip6.redirect */
};
void		 host_info(struct work *, struct host_facts *);
/* invidia/ipfw.c: a number sysctl of w's network (a jail's read in it),
 * -1 when there is none of that name. */
long		 sysctl_int_here(struct work *, const char *);
bool		 has_feature(const char *);

/* ira/jail.c: one jail record from runtime and configured state. */
void		 jail_record(struct work *, struct arc_jail *, const char *,
		    const struct jinfo *, const struct cjail *);
struct arc_jail	*jail_current(struct work *, const char *,
		    const struct cconf *);

/* ira/lifecycle.c: the jails, configured and running merged (do_list(),
 * with config_only the configured alone), and what an action left. */
struct jails_read {
	bool			 ok;
	const char		*error;
	struct arc_jail		*jails;
	size_t			 njails;
	const char *const	*scopes;
	size_t			 nscopes;
	struct conf_error	*errors;
	size_t			 nerrors;
};
struct jail_done {
	bool		 ok;
	const char	*error;
	struct arc_jail	*result;	/* the jail as it is after */
};
int		 do_list(struct work *, bool, struct jails_read *);
int		 do_action(struct work *, const char *, uint8_t,
		    struct jail_done *);
/* invidia/address.c */
/* ira/jailmake.c: jails made and taken away, their defaults, templates */
const char	*jail_conf_check(const struct arc_job_spec *);
int		 do_jail_conf(struct work *, const struct arc_job_spec *,
		    const char **);
int		 jail_allow_names(struct work *, const char ***, size_t *);
int		 jail_allow_live(struct work *, int, const char **, size_t,
		    const char ***);
const char	*jail_allow_check(const struct arc_job_spec *);
int		 do_jail_allow(struct work *, const struct arc_job_spec *,
		    const char **);
int		 jail_allow_undo_prepare(struct work *, const struct arc_job_spec *,
		    const char **, struct arc_variable **, size_t *, const char **);
int		 jail_allow_undo(struct work *, const struct arc_job_spec *,
		    const struct arc_variable *, size_t, const char **);
struct json_rsp;
void		 do_jail_files(struct work *, struct json_rsp *);

/* superbia/certs.c: the certificates OpenSSL trusts, as JSON */
struct json_rsp;
void		 do_certs(struct work *, struct json_rsp *);
const char	*cert_check(const struct arc_job_spec *);
int		 do_cert(struct work *, const struct arc_job_spec *,
		    const char **);

/*
 * acedia/zfskey.c: a dataset's key, typed: loaded, changed (new_key),
 * or a dataset made encrypted with new_key (create, its encryption).
 */
struct zfskey_req {
	const char	*zfs_dataset;
	const char	*zfs_key;
	const char	*zfs_new_key;
	const char	*zfs_create;
};
struct zfskey_rsp {
	bool		 has_ok;
	bool		 ok;
	const char	*error;
};
void		 do_zfs_key(struct work *, const struct zfskey_req *,
		    struct zfskey_rsp *);

/*
 * A read answered in JSON, as the operation of arcana.yaml it was gave
 * it: the modules make their trees of it (gula/y*.c, invidia/y*.c).
 */
struct json_rsp {
	bool		 has_ok;
	bool		 ok;
	const char	*error;
	const char	*json;
};

/*
 * A network table read as JSON (network.c), that arcana-network's
 * actions make typed (ynet.c): total, rows on the host, and truncated,
 * more wanted than sent, where the table says.
 */
struct net_rsp {
	bool		 has_ok;
	bool		 ok;
	const char	*error;
	const char	*json;
	bool		 has_total;
	uint64_t	 total;
	bool		 truncated;
};

/* The kept rules of the firewall (ipfw.c): read, checked or put in place. */
struct ipfw_rules_req {
	const char	*conf_text;	/* NULL: read */
	const char	*sha256;	/* of the text it was made from */
	bool		 dry_run;
	bool		 from_rc;
};
struct ipfw_rules_rsp {
	bool		 has_ok;
	bool		 ok;
	const char	*error;
	const char	*conf_text;
	const char	*sha256;
	const char	*rc_file;
};

/* A jail's address (address.c), added or taken away. */
struct address_req {
	const char	*jail;
	const char	*address;
	const char	*interface;
	bool		 remove;
	bool		 live;
	bool		 persist;
	bool		 dry_run;
};
struct address_rsp {
	bool		 has_ok;
	bool		 ok;
	const char	*error;
	const char	*diff;
	const struct arc_jail *result;
};

/* A part of a table in parts (netdump.c): what was asked. */
struct net_parts_req {
	uint8_t		 kind;		/* ARC_NET_KIND_* */
	uint8_t		 family;	/* ARC_NET_FAMILY_* */
	uint32_t	 fib;
	const char	*filter;
	const char	*jail;
};

/*
 * invidia/capture.c: packets taken with tcpdump off interface (NULL:
 * the sources there are), filter a pcap-filter(7) expression, so many
 * packets or seconds at most (0: 50, 10).
 */
struct capture_req {
	const char	*interface;
	const char	*filter;
	uint32_t	 packets;
	uint32_t	 seconds;
};
void		 do_capture(struct work *, const struct capture_req *,
		    struct json_rsp *);

/* superbia/ssh.c: the base system's sshd */
void		 do_ssh(struct work *, struct json_rsp *);
const char	*ssh_check(const struct arc_job_spec *);
/* luxuria/poudriere.c: the package builder, its runs left to go on. */
const char	*poudriere_check(const struct arc_job_spec *);
int		 do_poudriere_job(struct work *, const struct arc_job_spec *,
		    const char **);
char		*poudriere_title(const struct arc_job_spec *);

/* gula/crashes.c: the cores dumped, a backtrace of one, and the crash
 * job that takes one away. */
void		 do_crashes(struct work *, const char *const *, size_t,
		    struct json_rsp *);
const char	*crash_check(const struct arc_job_spec *);
char		*crash_title(const struct arc_job_spec *);
int		 do_crash_job(struct work *, const struct arc_job_spec *,
		    const char **);

/* luxuria/clamav.c: freshclam's mirrors. */
const char	*clamav_check(const struct arc_job_spec *);
char		*clamav_title(const struct arc_job_spec *);
int		 do_clamav_job(struct work *, const struct arc_job_spec *,
		    const char **);
void		 do_builder(struct work *, struct json_rsp *);
void		 do_builder_options(struct work *, const struct arc_job_spec *,
		    struct json_rsp *);
int		 do_ssh_job(struct work *, const struct arc_job_spec *,
		    const char **);
int		 ssh_undo(struct work *, const struct arc_job_spec *,
		    const char **);
/* invidia/carp.c: carp(4)'s vhids, read and set by netlink */
struct ucl_object_s;
void		 carp_read(struct ucl_object_s *, struct ucl_object_s *);
int		 carp_helper(int, char **);
const char	*carp_check(const struct arc_job_spec *);
const char	*carp_vhid_of(const struct arc_job_spec *);
int		 do_carp(struct work *, const struct arc_job_spec *,
		    const char **);
/* invidia/neigh.c: a neighbour set by hand, or taken away */
const char	*neigh_check(const struct arc_job_spec *);
int		 do_neigh(struct work *, const struct arc_job_spec *,
		    const char **);
int		 do_address(struct work *, const struct address_req *,
		    struct address_rsp *);

/*
 * ira/services.c: the rc.d scripts, by service(8) and sysrc(8), which
 * arcana-services serves (yservices.c, ysvcedit.c) and the jobs'
 * service-action and service-config change: the list, each enabled or
 * not and running or not (do_services()); one changed (an action,
 * ARC_SERVICE_ACTION_*) and as it is after; one's variables set or
 * unset through sysrc(8) and read back, with what the script says of
 * itself; one read as it is now (service_read()).  The jobs' enable,
 * disable and variables are service_job_rc()'s, not sysrc(8)'s.
 */
struct services_rsp {
	bool		 has_ok;
	bool		 ok;
	const char	*error;
	struct {
		struct arc_service	*v;
		size_t			 n;
	} services;
};
struct service_action_rsp {
	bool		 has_ok;
	bool		 ok;
	const char	*error;
	struct arc_service *service_result;
};
struct service_config_req {
	const char	*service;
	struct {
		const struct arc_variable *v;
		size_t			 n;
	} variables;
};
struct service_config_rsp {
	bool		 has_ok;
	bool		 ok;
	const char	*error;
	struct arc_service *service_result;
	struct {
		struct arc_variable	*v;
		size_t			 n;
	} variables;
	const char	*description;
	struct {
		const char	**v;
		size_t		 n;
	} commands;
};
/* ira/services.c: the host's services, or those of the running jail the
 * work is in (scope_enter_jail()), by its own service(8) and rc.conf. */
int		 do_services(struct work *, struct services_rsp *);
void		 service_scripts(struct work *, struct services_rsp *);
const char	*service_rcvar(struct work *, const char *, const char **);
bool		 valid_var_name(const char *);
int		 do_service_action(struct work *, const char *, uint8_t,
		    struct service_action_rsp *);
int		 do_service_config(struct work *,
		    const struct service_config_req *,
		    struct service_config_rsp *);
int		 service_read(struct work *, const char *,
		    struct service_config_rsp *);
void		 service_state(struct work *, const char *, bool *, bool *);
/* A viewer's: what the collector saw, no rc.d script run for it. */
int		 do_services_collected(struct work *, struct services_rsp *);
int		 service_read_collected(struct work *, const char *,
		    struct service_config_rsp *);
void		 services_collect_start(void);
/* The host's processes started (gula/hostwatch.c): a stopped service's
 * pidfile looked at for its start. */
void		 services_procs_started(void);
/*
 * ira/ysvcedit.c: a job's service-action enable or disable, or its
 * service-config, written as a commit writes it, to Arcana's rc.conf
 * file (rcarcana.c), the spec's accept the warnings accepted; for a
 * safe job the files as they were kept in *xp, put back by
 * service_job_undo(), let go by service_job_forget().
 */
struct rca;
int		 service_job_rc(struct work *, const struct arc_job_spec *,
		    struct rca **, const char **);
int		 service_job_undo(struct work *, struct rca *, const char **);
void		 service_job_forget(struct rca *);

/* invidia/network.c */
int		 do_network(struct work *, uint8_t, uint8_t, const char *,
		    uint32_t, uint32_t, struct net_rsp *);
int		 do_route_lookup(struct work *, const char *, uint32_t,
		    struct json_rsp *);
int		 do_traceroute(struct work *, const char *, struct json_rsp *);

/* invidia/interfaces.c */
int		 do_interfaces(struct work *, uint8_t, struct net_rsp *);
int		 do_if_address(struct work *, const char *, const char *, bool,
		    bool, const char **);
int		 do_if_state(struct work *, const char *, bool, const char **);
/* What an if-set changes: 0, -1 and NULL leave each as it is. */
struct if_change {
	unsigned int	 mtu;
	const char	*descr;		/* "" takes it off */
	int		 fib;
	int		 tunnelfib;
	const char	*addressing;	/* dhcp, slaac, static or was; NULL as
					 * is */
};
/* An interface's addressing by rc.conf: its two lines (NULL unset). */
struct addr_state {
	const char	*rc;		/* ifconfig_<if> */
	const char	*rc6;		/* ifconfig_<if>_ipv6 */
	bool		 dhcp;
	bool		 slaac;
};
void		 if_addr_state(struct work *, const char *,
		    struct addr_state *);
int		 if_addr_restore(struct work *, const char *,
		    const struct addr_state *, bool, const char **);
void		 if_addr_forget(struct work *, const char *);
const char	*if_addr_record_get(struct work *, const char *);
void		 if_addr_record_set(struct work *, const char *, const char *);
int		 do_if_set(struct work *, const char *,
		    const struct if_change *, bool, const char **);
int		 do_if_create(struct work *, const struct arc_job_spec *,
		    const char **, const char **);
int		 do_if_destroy(struct work *, const char *, bool, const char **);
bool		 if_clonable(struct work *, const char *, const char **);
void		 if_current(struct work *, const char *, unsigned int *, int *,
		    int *, char *, size_t);
bool		 if_is_up(struct work *, const char *, bool *);
bool		 if_link(struct work *, const char *, bool *);
bool		 if_exists(struct work *, const char *);
const char	*if_counters_text(struct work *, const char *);
const char	*fib_routes_text(struct work *, const char *);
int		 rt_count(int, int, uint32_t *);
const char	*if_json(struct work *);
struct ucl_object_s *if_object(struct work *, const char *);
int		 if_recreate(struct work *, const char *, const struct ucl_object_s *, int,
		    int, const char **);
bool		 if_owning(const struct sockaddr *, char *, size_t);
const char	*if_address_with_prefix(struct work *, const char *,
		    const char *);

/* invidia/routes.c */
/* What a route has besides where it leads. */
struct route_more {
	uint32_t	 metric;	/* 0: the system's */
	uint32_t	 weight;
	const char	*source;	/* the address sent from, or NULL */
	const char	*name;		/* rc.conf's for it, or NULL: arc_... */
	bool		 rc_only;	/* rc.conf alone, the kernel as it is */
};
int		 do_route(struct work *, const char *, const char *, bool,
		    uint32_t, const struct route_more *, bool, const char **);
int		 route_snapshot(struct work *, const char *, uint32_t,
		    const char **, struct route_more *, bool *, const char **);
int		 do_kept_routes(struct work *, struct net_rsp *);

/* invidia/rcconf.c: what of the network rc.conf keeps. */
bool		 rc_name_ok(const char *);
bool		 rc_value_ok(const char *);
const char	*rc_ifname(struct work *, const char *);
const char	*rc_get(struct work *, const char *);
int		 rc_set(struct work *, const char *, const char *, const char *,
		    const char **);
void		 rc_unset(struct work *, const char *);
int		 rc_alias(struct work *, const char *, const char *,
		    const char *, const char *, bool, const char **);
int		 rc_word(struct work *, const char *, const char *,
		    const char *, const char **);
void		 rc_forget_if(struct work *, const char *);

/* invidia/wireguard.c: WireGuard, through the base system's wg(8). */
int		 do_wireguard(struct work *, struct net_rsp *);
const char	*wg_check(struct work *, const struct arc_job_spec *);
int		 do_wg(struct work *, const struct arc_job_spec *,
		    const char **);
void		 wg_forget(struct work *, const char *);
char		*wg_conf_path(struct work *, const char *);
int		 wg_showconf(struct work *, const char *, char **, const char **);
int		 wg_syncconf(struct work *, const char *, const char *,
		    const char **);
bool		 wg_key_ok(const char *);

/* luxuria/ipsec.c: a plugin, strongSwan through swanctl(8). */
int		 do_ipsec(struct work *, struct net_rsp *);
const char	*ipsec_check(const struct arc_job_spec *);
int		 do_ipsec_job(struct work *, const struct arc_job_spec *,
		    const char **);
void		 ipsec_conn_files(struct work *, const char *, const char **,
		    const char **, const char **);
int		 ipsec_undo(struct work *, const char *, bool, const char **);
int		 ipsec_toggle(struct work *, const char *, bool, const char **);

/* luxuria/bird.c: a plugin, through birdc(8). */
int		 do_bird(struct work *, struct net_rsp *);
void		 bird_watch_start(void);
void		 smtpd_watch_start(void);
void		 smtpd_cert_renewed(struct work *);
const char	*bird_check(const char *, const char *const *, size_t);
int		 bird_proto_enabled(struct work *, const char *, bool *,
		    const char **);
int		 bird_configure_safe(struct work *, int, const char **);
int		 bird_configure_confirm(struct work *, const char **);
int		 bird_configure_undo(struct work *, const char **);
int		 do_bird_verb(struct work *, const char *, const char *const *,
		    size_t, const char **);
/*
 * Its configuration, the host's or w's jail's (arcana-bird): the files
 * it is made of; a text's SHA-256; whether bird(8) takes a text in a
 * file's place, the file left; a text put in place, was the SHA-256 of
 * the one it replaces (NULL: any), BIRD told, with timeout (s, 0 none)
 * a confirmed commit's of ctx's datastores, BIRD's own timer a little
 * longer, then kept or taken back as the commit is; a text put back,
 * the confirmed change that waits for it taken back; the change that
 * waited kept, a commit come after it.  0, or -1 and why in *errp;
 * *warnp what the change met that did not stop it.
 */
const char	**bird_conf_files(struct work *, size_t *);
const char	*bird_sha(struct work *, const char *, size_t);
int		 bird_conf_check(struct work *, const char *, const char *,
		    const char **);
int		 bird_conf_put(struct work *, const char *, const char *,
		    const char *, int, struct cbl_ctx *, const char **,
		    const char **);
int		 bird_conf_undo(struct work *, const char *, const char *,
		    const char **);
void		 bird_conf_settle(void);

/* invidia/scope.c: the network of a vnet jail, from the host. */
int		 scope_enter(struct work *, const char *, const char **);
int		 scope_enter_jail(struct work *, const char *, const char **,
		    bool);
int		 do_bird_routes(struct work *, const char *,
		    struct net_rsp *);
int		 do_bird_ospf(struct work *, const char *,
		    struct net_rsp *);
/* superbia/kernel.c: the kernel's modules and memory. */
const char	*do_kernel(struct work *, const char **);
bool		 kld_listed(struct work *, const char *);
int		 do_kmod(struct work *, const char *, const char *, bool,
		    const char **);
bool		 kmod_name_ok(const char *);

/* superbia/ntp.c: the NTP servers. */
int		 do_ntp(struct work *, const char *const *, size_t, bool, bool,
		    const char **);
bool		 ntp_server_ok(const char *);
/* gula: what runs, what was written down, how busy it has been. */
int		 do_processes(struct work *, const char *, struct json_rsp *);
const char	*proc_check(const struct arc_job_spec *);
char		*proc_title(const struct arc_job_spec *);
int		 do_proc_job(struct work *, const struct arc_job_spec *,
		    const char **);
bool		 log_name_ok(const char *);
int		 do_log(struct work *, const char *, const char *, bool,
		    uint64_t, uint32_t, struct json_rsp *);
void		 history_start(void);
int		 do_history(struct work *, uint64_t, bool, uint32_t, uint32_t,
		    int, int, const uint32_t *, const char *,
		    struct json_rsp *);
/* gula/kmsg.c: the kernel's messages, numbered as they come. */
struct kmsg_line {
	uint64_t	 n;
	time_t		 t;
	char		*text;
};
void		 kmsg_start(void);
void		 host_watch_start(void);
bool		 kmsg_lines(struct work *, uint64_t, const char *, uint32_t,
		    struct kmsg_line **, size_t *, uint64_t *);
bool		 kmsg_crash_line(const char *, time_t);
bool		 kmsg_core_dumped(const char *, int, int, int *);
void		 kmsg_crash_sweep(time_t);
void		 kmsg_crash_adopt(void);
const char	*kmsg_find(const char *, size_t, const char *, size_t, size_t,
		    bool);
void		 history_save(void);
void		 history_look(void);
/* gula/archive.c: the long run of the samples, on the disk, by class
 * (PLAN-SDN-YANG 5.6.3). */
enum { ARC_HOST, ARC_INTERFACE, ARC_DISK, ARC_JAIL, ARC_RELAY, ARC_PROBE,
    ARC_CLASSES };
#define	ARC_COLS_MAX	11		/* figures of a class's series */
#define	ARC_STEP	60		/* s a point stands for, unless set */
#define	ARC_STEP_MIN	10
#define	ARC_STEP_MAX	3600
#define	ARC_KEEP_MAX	3660		/* days */
#define	ARC_BUDGET	128		/* MiB, unless set */
#define	ARC_BUDGET_MIN	1
#define	ARC_BUDGET_MAX	1048576
/* Its settings: each class's step and retention, 0 its default. */
struct arc_conf {
	bool		 on;
	uint32_t	 budget;		/* MiB */
	uint16_t	 step[ARC_CLASSES];
	uint16_t	 keep[ARC_CLASSES];	/* days */
};
struct arc_state {
	bool		 ok;			/* its directory there */
	uint64_t	 bytes, budget;
	struct {
		uint64_t	 bytes;
		unsigned int	 files, series, step, keep;
		long		 oldest;	/* day since the epoch, -1 */
		bool		 full;
	}		 c[ARC_CLASSES];
};
/* What a read gives: each series' points, oldest first, each ncols
 * integers (the figure times its field's scale; -1 none). */
struct arc_series {
	char		*name;
	size_t		 npoints;
	int64_t		*t;
	int64_t		*v;
};
struct arc_read {
	int			 c;
	size_t			 ncols;
	const char *const	*fields;
	const uint32_t		*scale;
	uint32_t		 step;
	struct arc_series	*s;
	size_t			 ns;
};
void		 archive_start(void);
void		 archive_add(int, const char *, time_t, const double *, size_t);
void		 archive_sync(bool);
bool		 archive_conf_line(const char *);
void		 archive_conf_write(FILE *);
void		 archive_conf_get(struct arc_conf *);
const char	*archive_conf_set(const struct arc_conf *);
void		 archive_state(struct arc_state *);
const char	*archive_class_name(int);
int		 archive_class(const char *);
unsigned int	 archive_default_keep(int);
int		 archive_read(int, const char *, time_t, time_t, unsigned int,
		    struct arc_read *, const char **);
void		 archive_read_free(struct arc_read *);
/* gula/probe*.c: the tunnels measured, STAMP to Arcana's far ends, ICMP echo
 * to the others, again and again. */
enum { PROBE_NONE = -1, PROBE_UNKNOWN, PROBE_UP, PROBE_DOWN, PROBE_ENDED,
    PROBE_ERROR };
void		 probe_start(void);
int		 do_probes_set(struct work *, const char *, const char **);
int		 do_probes_read(struct work *, uint64_t, bool, struct json_rsp *);
int		 do_sdwan_state(struct work *, struct json_rsp *);
/* ... and the admin's own monitors on any tunnel, by the same prober. */
int		 do_monitors(struct work *, uint64_t, struct json_rsp *);
const char	*monitor_check(const struct arc_job_spec *);
char		*monitor_title(const struct arc_job_spec *);
int		 do_monitor_job(struct work *, const struct arc_job_spec *,
		    const char **);
int		 do_monitors_set(struct work *, const char *, const char **);
/* The targets, links and monitors of each edge, as JSON (malloc'd). */
char		*probe_conf_json(void);
/* Each edge's interfaces' counters and FIBs' routes now, as JSON. */
char		*probe_edges_json(void);
int		 probe_state_of(const char *, const char *);
bool		 probe_sample_of(const char *, const char *, double *, double *,
		    double *);
void		 probe_link(const char *, const char *, bool);
void		 probe_steer_due(unsigned);
int		 probe_fibs(int *, int);
/* gula/stampd.c: stampd(8), the STAMP reflector of the submodule stamp/,
 * set in rc.conf to answer in each FIB the host's services use. */
void		 stampd_start(void);
void		 stampd_nudge(void);
void		 stampd_state(bool *, char *, size_t, const char **, int *,
		    char *, size_t);
struct stamp_key;
/* A target's name (gula/probe_int.h's TNAME_MAX), with its NUL. */
#define	PROBE_NAME_MAX	(128 + 1 + 64 + 1 + 33)
int		 probe_stamp_keys(struct stamp_key *, char (*)[PROBE_NAME_MAX],
		    int);
/* gula/altmark.c: alternate marking (RFC 9341) of the services' tunnels,
 * its rules in the SD-WAN set's file, its blocks read by IP_FW3. */
#define	AM_NAME		64
#define	AM_SERVICES	16	/* an edge's measured */
#define	AM_TUNNELS	64	/* a service's at an edge */
#define	AM_EDGES	32
#define	AM_RULE_IN	9	/* out of a tunnel: first, before the IDS */
#define	AM_RULE_OUT	11	/* into it: last, before the way out's end */
#define	AM_TABLE	"arcam"	/* arcamK, arcamK_alt: service K's colours */
#define	AM_EVEN		"arcam_even"	/* a class to itself: the bit off */
struct am_tunnel {
	char	id[128];
	char	ifname[16];
	char	outer[48];	/* the far end's outer address, "" none */
	char	kind[8];	/* gre, gif, geneve, wg; "" not said */
	int	port;		/* wg's, geneve's: the far end's UDP port */
	bool	ipsec;		/* carried by ESP */
};
struct am_service {
	char		  name[AM_NAME];
	int		  period;	/* the block's length, s */
	int		  colour;	/* the colour table's, at the load */
	int		  ntun;
	struct am_tunnel *tun;
};
/* invidia/netflow.c: a service's flows recorded, NetFlow v9 */
#define	FE_SERVICES	16
#define	FE_TUNNELS	64
#define	FE_COOKIE	61000		/* ng_ipfw's hooks, 2 a service */
#define	FE_RULE		9		/* the ngtee rules' number in the set */
struct fe_tunnel {
	char		 id[128];
	char		 ifname[16];
};
struct fe_service {
	char		  name[64];
	char		  collector[16];	/* IPv4, dotted */
	int		  port;
	int		  sampling;	/* one packet in so many */
	int		  active;	/* timeouts, s */
	int		  inactive;
	int		  ntun;
	struct fe_tunnel *tun;
};
struct ucl_object_s;
int		 netflow_parse(const struct ucl_object_s *, struct fe_service **,
		    int *, const char **);
void		 netflow_free(struct fe_service *, int);
const char	*netflow_ready(struct work *);
int		 netflow_rules(FILE *, const char *, const struct fe_service *,
		    int);
int		 netflow_set(struct work *, const struct fe_service *, int,
		    const char **);
int		 altmark_parse(const struct ucl_object_s *, struct am_service **,
		    int *, const char **);
void		 altmark_free(struct am_service *, int);
void		 altmark_tables(FILE *, const char *, struct am_service *,
		    int);
int		 altmark_rules_in(FILE *, const char *, const struct am_service *,
		    int);
int		 altmark_rules_out(FILE *, const char *,
		    const struct am_service *, int);
bool		 altmark_marks_before(const char *);
void		 altmark_set(const char *, int, const struct am_service *, int);
struct ucl_object_s *altmark_json(const char *);

/* gula/bmp.c: an instance's BMP station (RFC 7854). */
struct bmp_station {
	char	name[40];	/* the BIRD instance */
	char	jail[64];	/* its edge, a vnet jail; "" the host */
	int	jid;
	int	fib;
	int	kept;		/* updates kept */
};
#define	BMP_KEPT_MAX	1024
int		 bmp_port(int);
int		 bmp_listen(int, int);
void		 bmp_set(const char *, const struct bmp_station *, int);
void		 bmp_jail_gone(int);
void		 bmp_rejail(const char *, const char *, int);
struct ucl_object_s *bmp_json(const char *, const char *);
/* invidia/acl.c: the kept ACLs applied again at the start. */
void		 acl_start(void);
/* invidia/sdwan.c: the rules that steer, and the steering. */
void		 sdwan_start(void);
int		 do_sdwan_rules(struct work *, const char *, const char **);
int		 do_sdwan_steer(struct work *, const char *, const char **);
void		 sdwan_probe_changed(void);
struct ucl_object_s;
void		 sdwan_json(struct work *, struct ucl_object_s *);
const char	*sdwan_conf_path(const char *, char *, size_t);
int		 sdwan_conf_write(const char *, const char *, const char **);
int		 sdwan_conf_write_group(const char *, const char *, const char *,
		    const char **);
void		 sdwan_conf_tighten(void);
const char	*sdwan_subst(struct work *, const char *, const char *const *,
		    const char *const *, size_t);
char		*sdwan_kept_read(const char *);
const char	*sdwan_payload_jail(const struct ucl_object_s *, const char **);
/* ... the steering as arcana-steer has it: why each choice, and the
 * console's pins (a candidate chosen while not down). */
enum { STEER_PREFERENCE, STEER_FIRST_UP, STEER_FAILOVER, STEER_OVERRIDE,
    STEER_NONE };
struct sdwan_pin {
	const char	*table;
	const char	*prefix;
	const char	*candidate;
};
char		*sdwan_steer_json(void);
int		 sdwan_fibs(int *, int);
char		*sdwan_pins_json(void);
int		 sdwan_pin_check(struct work *, const char *,
		    const struct sdwan_pin *, const char **);
int		 sdwan_pins_set(struct work *, const char *, size_t,
		    const struct sdwan_pin *, const char **);

/* luxuria/sdbird.c: a BIRD instance of each service, at the UNIs. */
int		 do_sdwan_bird(struct work *, const char *, const char **);
void		 sdwan_bird_start(void);
void		 sdwan_bird_json(struct work *, struct ucl_object_s *);
int		 do_sdwan_dhcp(struct work *, const char *, const char **);
void		 sdwan_dhcp_start(void);
void		 sdwan_dhcp_json(struct work *, struct ucl_object_s *);
int		 do_sdwan_dns(struct work *, const char *, const char **);
void		 sdwan_dns_start(void);
void		 sdwan_dns_json(struct work *, struct ucl_object_s *);
/* luxuria/sdproxy.c: the services' proxies, Squid. */
int		 do_sdwan_proxy(struct work *, const char *, const char **);
void		 sdwan_proxy_start(void);
void		 sdwan_proxy_json(struct work *, struct ucl_object_s *);
int		 squid_restart(struct work *, const char *, const char **);
void		 clamav_mirrors_json(struct work *, struct ucl_object_s *);
void		 security_specs(const char *, struct ucl_object_s *, const char *);
int		 do_sdwan_ids(struct work *, const char *, const char **);
/*
 * luxuria/sdconf.c: dnsmasq's, unbound's, Squid's, c-icap's and BIRD's files
 * from the console's forms.  Where an instance's files are: Squid's
 * and c-icap's own, a list's its name between list_pre and list_suf.
 */
struct sqpaths {
	const char	*pid, *ca, *ssldb, *certgen, *deny;
	const char	*list_pre, *list_suf;
	const char	*icap_pid, *icap_cmd;
	const char	*log_dir;	/* its logs' directory; NULL the host's */
};
/* The port an SD-WAN service's c-icap answers its Squid on; the
 * Security section's i-th, on the loopback. */
#define	SDWAN_ICAP_PORT(fib)	(1344 + 10 * (int)(fib))
#define	SEC_ICAP_PORT(i)	(1345 + 10 * (int)(i))
/* The last routing table whose c-icap port is a port. */
#define	SDWAN_ICAP_FIB_MAX	((65535 - 1344) / 10)
char		*dhcp_conf_render(struct work *, const struct ucl_object_s *,
		    const char *, const char **);
/* Where an unbound instance's files are, as its configuration names
 * them: its key and certificate for DNS over TLS, a response policy
 * zone's file (rpz_pre + the zone's name). */
struct dnspaths {
	const char	*tlskey, *tlspem, *rpz_pre;
};
char		*dns_conf_render(struct work *, const struct ucl_object_s *,
		    const char *, const struct dnspaths *, struct ucl_object_s *,
		    const char **);
char		*squid_conf_render(struct work *, const struct ucl_object_s *,
		    const char *, const char *, int, const struct ucl_object_s *,
		    const struct sqpaths *, char **, const char **);
bool		 squid_conf_icap(const struct ucl_object_s *);
struct ucl_object_s *clamav_sigs_render(struct work *,
		    const struct ucl_object_s *, const char **);
char		*icap_conf_render(struct work *, const struct ucl_object_s *,
		    const char *, const char *, int, const struct sqpaths *,
		    const char **);
char		*bird_conf_render(struct work *, const struct ucl_object_s *,
		    const char *, const char **);
/* What the daemons blocked, matched back to their forms (sdblock.c). */
const char	*sdwan_squid_log(char *, size_t, const char *, intmax_t);
const char	*sdwan_icap_log(char *, size_t, const char *, intmax_t);
const char	*sdwan_list_name(int);
bool		 sdwan_notifies(const struct ucl_object_s *, const char *);
int		 sdwan_dnf_list(const struct ucl_object_s *, const char *);
int		 sdwan_pdns_list(const struct ucl_object_s *, const char *,
		    const char **);
bool		 sdwan_dnf_wild(const struct ucl_object_s *, const char *,
		    const char **);
int		 sdwan_urlf_list(const struct ucl_object_s *, const char *,
		    const char *, const char **);
bool		 sdwan_mdr_sig(const struct ucl_object_s *, const char *,
		    const char **, int *);
/* luxuria/sdblock.c: the daemons' logs of what they blocked, events. */
enum { SDB_UNBOUND, SDB_SQUID, SDB_ICAP };
void		 sdblock_watch(int, int, const char *const *,
		    const char *const *, const struct ucl_object_s *const *);
void		 sdblock_watch_jail(int, const char *, const char *, int,
		    const char *const *, const char *const *,
		    const struct ucl_object_s *const *);
/* luxuria/idsconf.c: Suricata's YAML from an instance's settings. */
char		*ids_conf_render(struct work *, const struct ucl_object_s *,
		    const struct ucl_object_s *, const char *, const char *,
		    int64_t, struct ucl_object_s *, const char **);
char		*ids_conf_sdwan(struct work *, const struct ucl_object_s *,
		    const char *, const char *, struct ucl_object_s *,
		    const char **);
int		 do_notify(struct work *, const char *, const char *,
		    const char *, const char **);
void		 sdwan_ids_start(void);
/* superbia/geomjob.c: GEOM's classes at work. */
const char	*geom_check(const struct arc_job_spec *);
char		*geom_title(const struct arc_job_spec *);
int		 do_geom_job(struct work *, const struct arc_job_spec *,
		    const char **);
struct ucl_object_s *geom_classes_json(struct work *);
/* superbia/sysfiles.c: the system's own configuration files. */
void		 do_system(struct work *, const char *const *, size_t,
		    struct json_rsp *);
const char	*sysfile_check(const struct arc_job_spec *);
char		*sysfile_title(const struct arc_job_spec *);
int		 do_sysfile_job(struct work *, const struct arc_job_spec *,
		    const char **);
const char	*sysfile_path(struct work *, const char *);
int		 sysfile_tell(struct work *, const char *, const char **);
/* superbia/cron.c: cron(8)'s entries, Arcana's file and its part of a
 * user's crontab. */
void		 do_cron(struct work *, struct json_rsp *);
int		 cron_next_helper(int, char **);
const char	*cron_check(const struct arc_job_spec *);
char		*cron_title(const struct arc_job_spec *);
int		 do_cron_job(struct work *, const struct arc_job_spec *,
		    const char **);
const char	*cron_path(struct work *);
struct cron_was {			/* a user's crontab as it was */
	const char	*text;
	bool		 had;		/* the user had one */
	bool		 taken;
};
int		 cron_snap(struct work *, const struct arc_job_spec *,
		    struct cron_was *, const char **);
int		 cron_undo(struct work *, const struct arc_job_spec *,
		    const struct cron_was *, const char **);
/* superbia/netstore.c: NFS, iSCSI and HAST. */
void		 do_netstore(struct work *, const char *const *, size_t,
		    struct json_rsp *);
const char	*netstore_check(const struct arc_job_spec *);
char		*netstore_title(const struct arc_job_spec *);
int		 do_netstore_job(struct work *, const struct arc_job_spec *,
		    const char **);
/* luxuria/speeder.c: UDPspeeder's FEC relay, a plugin. */
void		 do_speeder(struct work *, struct json_rsp *);
const char	*speeder_check(const struct arc_job_spec *);
char		*speeder_title(const struct arc_job_spec *);
int		 do_speeder_job(struct work *, const struct arc_job_spec *,
		    const char **);
/* A relay as it was, for safe mode: its profile (NULL: the plain one). */
struct speeder_was {
	const char	*profile, *flags, *enable, *profiles;
	const char	*svcj, *svcj_options, *svcj_ipaddrs;
	bool		 running;
};
void		 speeder_snap(struct work *, const struct arc_job_spec *,
		    struct speeder_was *);
int		 speeder_back(struct work *, const struct speeder_was *,
		    const char **);
/* A relay's rates, for the history: by its syslog tag, bytes a second
 * taken in plain and added by the FEC, both ways, over its last report. */
struct speeder_rate {
	char		 tag[48];
	double		 plain, added;
};
size_t		 speeder_rates(struct speeder_rate *, size_t, unsigned int);

/* luxuria/sslproxy.c: SSL inspection by SSLproxy, a plugin. */
void		 do_sslproxy(struct work *, struct json_rsp *);
void		 sslproxy_watch_start(void);
bool		 sslproxy_jail_rtsock(int);
const char	*sslproxy_check(const struct arc_job_spec *);
int		 sslproxy_category_hosts(const struct ucl_object_s *,
		    const char **, size_t);
char		*sslproxy_title(const struct arc_job_spec *);
int		 do_sslproxy_job(struct work *, const struct arc_job_spec *,
		    const char **);
int		 sslproxy_csr(struct work *, bool, const char **,
		    const char **);
int		 sslproxy_install(struct work *, const char *, const char *,
		    const char **, int64_t *, const char **);

/* luxuria/smtpd.c: OpenSMTPD, a plugin: its read, and its job. */
void		 do_smtpd(struct work *, struct json_rsp *, bool);
const char	*smtpd_check(const struct arc_job_spec *);
char		*smtpd_title(const struct arc_job_spec *);
int		 do_smtpd_job(struct work *, const struct arc_job_spec *,
		    const char **);
char		*smtpd_render(struct work *, const struct ucl_object_s *,
		    const char **);
/* luxuria/surules.c: the ruleset's rules, and those the admin set. */
void		 do_suricata_rules(struct work *, const char *const *, size_t,
		    struct json_rsp *);
const char	*suricata_rule_check(const struct arc_job_spec *);
int		 suricata_rule_set(struct work *, const struct arc_job_spec *,
		    const char **);
int		 suricata_rule_args(struct work *, char **, int *,
		    const char **);
const char	*suricata_data_dir(struct work *);
bool		 suricata_sources_secret(struct work *);
bool		 suricata_name_ok(const char *);
const char	*suricata_socket(struct work *, const char *);
const char	*suricata_source_check(const struct arc_job_spec *);
char		*suricata_source_title(const struct arc_job_spec *);
int		 suricata_source_job(struct work *, const struct arc_job_spec *,
		    const char **);
const char	*suricata_check(const struct arc_job_spec *);
char		*suricata_title(const struct arc_job_spec *);
int		 do_suricata_job(struct work *, const struct arc_job_spec *,
		    const char **);
int		 suricata_restart(struct work *, const char *, const char **);
void		 sdwan_ids_json(struct work *, struct ucl_object_s *);
int		 suricata_inst_in(struct work *, const char *, const char **);
const char	*suricata_inst_file(struct work *, const char *, const char *);
const char	*suricata_rules_dir(struct work *);
const char	*suricata_ruleset_in(struct work *);
struct ucl_object_s *suricata_build_json(struct work *);
/* luxuria/idsfiles.c: captures in, pcap-log out, profiling read. */
struct ucl_object_s *suricata_captures_json(struct work *, const char *);
void		 suricata_profiling(struct work *, const char *,
		    struct json_rsp *);
int		 do_rtadvd(struct work *, const char *, const char *const *,
		    size_t, bool, bool, const char **);
int		 rtadvd_enter(struct work *, const char *, const char **);
/* invidia/pfkey.c: PF_KEYv2 in the agent's own process.  An SA as it is
 * put in or read back: the keys raw, put in only, never read back.  A
 * lifetime (RFC 2367's soft or hard; 0 none): seconds since added,
 * bytes, packets (allocations, which the kernel counts by packet and
 * does not enforce) and seconds since first used. */
struct pfkey_lt {
	uint64_t		 time, bytes, use;
	uint32_t		 packets;
};
struct pfkey_sa {
	struct sockaddr_storage	 src, dst;
	const unsigned char	*ekey, *akey;
	size_t			 ekeylen, akeylen;
	uint64_t		 bytes, added;	/* read: current lifetime */
	uint64_t		 used;		/* first used */
	uint32_t		 packets;
	uint32_t		 seq;		/* the sequence counter's low 32 */
	uint8_t			 lifetimes;	/* PFKEY_LT_*: those it has */
	struct pfkey_lt		 soft, hard;	/* both put in, if either is */
	uint32_t		 spi, reqid;
	uint32_t		 replay;	/* the window, bytes */
	uint32_t		 flags;		/* SADB_X_EXT_*, SADB_X_SAFLAGS_* */
	uint16_t		 sport, dport;	/* NAT-T's ports */
	uint8_t			 mode, state, ealg, aalg;
	bool			 natt;		/* ESP in UDP */
};
#define	PFKEY_LT_SOFT	0x1
#define	PFKEY_LT_HARD	0x2
int		 pfkey_open(struct work *, const char **);
int		 pfkey_register(struct work *, int, const char **);
struct sadb_msg;
void		 pfkey_news(void (*)(const struct sadb_msg *, size_t, void *),
		    void *);
void		 pfkey_sa_of(const struct sadb_msg *, size_t, struct pfkey_sa *);
int		 pfkey_add(struct work *, int, const struct pfkey_sa *,
		    const char **);
int		 pfkey_delete(struct work *, int, const struct sockaddr *,
		    const struct sockaddr *, uint32_t, const char **);
int		 pfkey_get(struct work *, int, const struct sockaddr *,
		    const struct sockaddr *, uint32_t, struct pfkey_sa *,
		    const char **);
int		 pfkey_dump(struct work *, int,
		    void (*)(const struct pfkey_sa *, void *), void *,
		    const char **);
/* A policy as it is put in or read back: its first request (Arcana's
 * have one), and how many there are.  Arcana's own are global, of the
 * priority PFKEY_SP_MARK: after setkey's (0) and ipsec.conf's, an
 * ipsec(4) interface's being scoped to it, told apart by it alone. */
#define	PFKEY_SP_MARK	0x7fa2c000u
struct pfkey_sp {
	struct sockaddr_storage	 src, dst;	/* the selector, ports in */
	struct sockaddr_storage	 tsrc, tdst;	/* tunnel mode's ends */
	uint32_t		 id;		/* the kernel's */
	uint32_t		 priority;	/* ifnet scope: the ifindex */
	uint16_t		 type;		/* IPSEC_POLICY_* */
	uint16_t		 reqid;
	uint8_t			 splen, dplen;
	uint8_t			 proto;		/* IPSEC_ULPROTO_ANY: any */
	uint8_t			 dir, scope;	/* IPSEC_DIR_*, _POLICYSCOPE_* */
	uint8_t			 rproto, mode, level;
	int			 nreq;
};
int		 pfkey_spdadd(struct work *, int, struct pfkey_sp *,
		    const char **);
int		 pfkey_spdupdate(struct work *, int, struct pfkey_sp *,
		    const char **);
int		 pfkey_spddelete(struct work *, int, uint32_t, const char **);
int		 pfkey_spddump(struct work *, int,
		    void (*)(const struct pfkey_sp *, void *), void *,
		    const char **);
void		 pfkey_sp_of(const struct sadb_msg *, size_t, struct pfkey_sp *);
const char	*pfkey_spd_text(struct work *);
/* invidia/sadb.c: the kernel's SAD news as RFC 9061's notifications. */
void		 sadb_watch_start(void);
/* invidia/ikeless.c: RFC 9061's IKE-less SAD and SPD lists.  The names
 * the controller gave its own SAs and policies (false: not its own);
 * the lifetimes of its SAs the kernel does not enforce, read with the
 * counters. */
void		 ikeless_start(void);
bool		 ikeless_sa_name(const struct sockaddr_storage *, uint32_t,
		    char *, size_t);
bool		 ikeless_sp_name(const struct pfkey_sp *, char *, size_t);
void		 ikeless_lifetimes(struct work *, int, const struct pfkey_sa *);
/* invidia/sa.c: the SD-WAN tunnels' key pairs (ikeless.c's key-pairs)
 * and what is derived from them. */
#define	SA_PUB_LEN	32	/* an X25519 public half */
#define	SA_PAIR_KEPT	0	/* sa_pair_set(): the pair as it was */
#define	SA_PAIR_MADE	1	/* made, none there */
#define	SA_PAIR_TURNED	2	/* made anew, the one before kept */
#define	SA_PAIR_BACK	3	/* the one before put back */
int		 sa_pair_set(const char *, bool, uint32_t, uint32_t, int *,
		    char *, size_t);
void		 sa_pair_unset(const char *, int, uint32_t, uint32_t);
void		 sa_pair_drop(const char *);
bool		 sa_pair_public(const char *, unsigned char *);
int		 sa_pair_derive(const char *, const unsigned char *, uint32_t,
		    bool, size_t, size_t, uint32_t *, unsigned char *,
		    unsigned char *, char *, size_t);
void		 sa_pair_state(const char *, uint32_t, uint32_t, uint32_t,
		    bool);
void		 sa_rotation_fault(const char *, const char *);
void		 sa_keys_json(struct work *, struct ucl_object_s *);
void		 sa_faults_start(void);
int		 tunnel_key_derive(struct work *, const char *, const char *,
		    const char *, unsigned char *, size_t, const char **);
bool		 rtadvd_prefix_ok(const char *);
int		 sdwan_bfd_state(const char *);
const char	*sdwan_tunnel_by_via(const char *);

/* gula/faults.c: the faults, kept a day; an object whole, so long at
 * most with its NUL (a mount point's, MNAMELEN). */
#define	FAULT_OBJECT_MAX	1024
void		 fault_set(const char *, const char *, const char *, const char *,
		    const char *, ...) __printflike(5, 6);
void		 fault_clear(const char *, const char *, const char *, ...)
		    __printflike(3, 4);
bool		 fault_update(const char *, const char *, const char *, ...)
		    __printflike(3, 4);
/* What an owner watches now (fault_reconcile()): an object of a type
 * (NULL, the call's), whether its cause is gone (its fault cleared,
 * with reason, NULL the call's line), and back whether a fault of it is
 * still open. */
struct fault_live {
	const char	*type;
	const char	*object;
	const char	*reason;
	bool		 well;
	bool		 open;
};
int		 fault_reconcile(const char *, const char *, const char *const *,
		    struct fault_live *, size_t, const char *);
int		 faults_open(const char *, const char *,
		    void (*)(const char *, time_t, void *), void *);
void		 faults_save(void);
void		 faults_json(struct ucl_object_s *);
void		 faults_start(void);
int		 faults_purge(bool, int, time_t, int, int);
int		 faults_compress(bool, const char *, const char *);
int		 faults_control(const char *, bool, char *, size_t);
char		*faults_control_json(void);
/* gula/record.c: what the security rules logged, a day of it. */
void		 record_start(void);
void		 record_json(struct ucl_object_s *);
/* A vnet jail's routing socket listened on too, where its ipfw logs
 * there (recheck: asked again while listened on); closed when it goes. */
int		 record_jail_sync(const char *, int, bool);
void		 record_jail_gone(int);
int		 rtsock_logged(void);		/* the helper's, in the jail */
int		 do_process(struct work *, uint32_t, struct json_rsp *);

/* superbia/sysctl.c: the kernel's values, as sysctl_read() gives them
 * (arcana-sysctl's), the host's whole or a jail's network's. */
struct sysctl_value {
	const char	*name, *value, *type, *descr;
	bool		 rw, tun;
};
typedef void	 sysctl_value_f(void *, const struct sysctl_value *);
int		 sysctl_read(struct work *, const char *, const char *,
		    size_t, sysctl_value_f *, void *, uint64_t *,
		    const char **, const char **);
int		 sysctl_read_jail(struct work *, const char *,
		    sysctl_value_f *, void *, const char **);
int		 sysctl_read_name(struct work *, const char *,
		    sysctl_value_f *, void *);
bool		 sysctl_flags(const char *, bool *, bool *);
bool		 sysctl_tunable(struct work *, const char *,
		    struct sysctl_value *, unsigned int *);
const char	*sysctl_conf_path(char *, size_t);
void		 sysctl_conf_lock(void);
void		 sysctl_conf_unlock(void);
int		 do_sysctl_set(struct work *, const char *, const char *, bool,
		    const char **);
bool		 sysctl_name_ok(const char *);
const char	*sysctl_get(struct work *, const char *, const char **);
const char	*sysctl_conf_get(struct work *, const char *);
int		 sysctl_conf_restore(struct work *, const char *, const char *,
		    const char **);
bool		 valid_jail(const char *);
/* What builds share: the build directory's keys and clones. */
extern pthread_mutex_t	 build_lock;
/* After an update's answer, the console's service restarted, then the
 * agent's. */
void		 restart_after(bool, bool);
/* main.c: the daemon's pidfile kept its own; false, why it is not. */
bool		 own_pidfile(char *, size_t);
bool		 stop_asked(void);
const char	*change_busy(struct work *);
bool		 valid_service(const char *);
bool		 valid_ifname(const char *);
bool		 sysctl_value_ok(const char *);
int		 do_l2(struct work *, bool, struct net_rsp *);
const char	*bridge_holding(struct work *, const char *);
const char	*l2_check(const struct arc_job_spec *);
int		 l2_destroy(struct work *, const char *, const char **);
char		*l2_title(const struct arc_job_spec *);
int		 do_l2_job(struct work *, const struct arc_job_spec *,
		    const char **);
int		 do_ipfw(struct work *, struct net_rsp *);
int		 do_fw_trace(struct work *, const char *, uint32_t, uint32_t,
		    struct json_rsp *);
int		 do_ipfw_rules(struct work *, const struct ipfw_rules_req *,
		    struct ipfw_rules_rsp *);
/*
 * The kept rules by arcana-firewall's commit: Arcana's boot script,
 * whether rc.conf boots by it, the migration to it (from-rc), what
 * differs from the kernel's set 0, the commit and its undo.
 */
const char	*ipfw_boot_script(struct work *);
char		*ipfw_script_text(const char *);
bool		 ipfw_on_script(struct work *);
int		 ipfw_migration(struct work *, const char **, const char **,
		    const char **);
const char	*ipfw_differs(struct work *, const char *, const char **);
int		 ipfw_kept_commit(struct work *, cbl_req *, const char *,
		    const char **, const char **);
int		 ipfw_kept_undo(struct work *, const char *, const char **);
const char	*ipfw_check(const struct arc_job_spec *);
char		*ipfw_title(const struct arc_job_spec *);
int		 do_ipfw_job(struct work *, const struct arc_job_spec *, bool *,
		    const char **);
const char	*ipfw_settle(struct work *, bool);
/*
 * The threat feeds' tables (invidia/feeds.c): a feed's prefixes made an
 * ipfw table whole, kept in a file beside the kept rules; given up;
 * marked in a read; made again in set 1 before Apply's swap and at the
 * start.
 */
struct feed_req {
	const char	*name;		/* the table */
	const char	*feed;
	const char	*entries;	/* a line each */
	bool		 dry_run;
	int		 peer_af;	/* the requester's address, left out */
	uint8_t		 peer[16];
};
struct feed_rsp {
	uint32_t	 count, added, removed, left_out;
	uint8_t		 set;
};
bool		 feed_name_ok(const char *);
int		 feed_load(struct work *, const struct feed_req *,
		    struct feed_rsp *, const char **);
int		 feed_drop(struct work *, const char *, bool *, const char **);
void		 feeds_mark(struct work *, struct ucl_object_s *);
int		 feeds_fill_set1(struct work *);
void		 feeds_start(void);
const char	*ipfw_unadd(struct work *, const struct arc_job_spec *);
int		 transport_watch(cbl_ctx *);
void		 transport_add(const char *, cbl_listener *);
void		 transport_init(cbl_ctx *, cbl_loop *, cbl_tls *);
/* superbia/admit.c: only the console asks */
enum peer_kind {
	PEER_NONE,		/* asks nothing */
	PEER_ROOT,		/* the unix socket's root or the agent's user */
	PEER_GROUP,		/* the unix socket's group (-g): the console */
	PEER_LOCAL,		/* another local account */
	PEER_CONSOLE,		/* TLS, urn:arcana:role:console */
	PEER_HOST,		/* TLS, urn:arcana:role:agent */
};
enum peer_kind	 peer_kind(const cbl_peer *, uid_t *);
bool		 peer_is_host(const cbl_peer *);
int		 admit_init(cbl_ctx *);
/*
 * superbia/admit.c: arcana-stream, the streams' family (ira/ystream.h);
 * each command's opening, its open structure checked by its handler:
 * acedia/xfer.c's snapshot sent and received, luxuria/idsfiles.c's
 * capture put and pcap-log file got.
 */
int		 stream_register(cbl_ctx *);
struct arcana_stream_open;
int		 zfs_send_open(cbl_req *, const struct arcana_stream_open *,
		    cbl_stream *);
int		 zfs_receive_open(cbl_req *, const struct arcana_stream_open *,
		    cbl_stream *);
extern const char *const zfs_recv_opts[];
int		 pcap_put_open(cbl_req *, const struct arcana_stream_open *,
		    cbl_stream *);
int		 pcap_get_open(cbl_req *, const struct arcana_stream_open *,
		    cbl_stream *);
/* ira/live.c: a job's program followed while it runs */
struct live;
struct live	*live_new(void);
void		 live_ref(struct live *);
void		 live_rele(struct live *);
void		 live_put(struct live *, const char *, size_t);
void		 live_end(struct live *);
const char	*live_tail(struct work *, struct live *, size_t *, bool *);
int		 exec_follow_open(cbl_req *, const struct arcana_stream_open *,
		    cbl_stream *);
struct live	*jobs_live(uint64_t, int, const char **);
/* ira/terminal.c: login(1) on a terminal of the host's or a jail's */
int		 terminal_open(cbl_req *, const struct arcana_stream_open *,
		    cbl_stream *);
int		 terminal_as_open(cbl_req *, const struct arcana_stream_open *,
		    cbl_stream *);
void		 terminal_findings(void);
bool		 terminal_users_usable(void);
void		 terminal_findings_start(void);
#define	TERM_EMPTY_PW_FAULT	"empty-password"
/* superbia/tlsfiles.c: the agent's own TLS files renewed */
const char	*tls_files_ca(void);
const char	*tls_files_cert(void);
bool		 tls_cert_dates(struct work *, time_t *, time_t *);
const char	*tls_files_key(void);
void		 tls_files_init(cbl_tls *, const char *, const char *,
		    const char *);
struct json_rsp;
void		 do_tls(struct work *, const char *, const char *,
		    const char *, const char *, const uint8_t *,
		    struct json_rsp *);
void		 transport_fini(void);
int		 do_transport(struct work *, bool, const char *, const char *,
		    bool, const char *, struct json_rsp *);
bool		 tls_file_is(const char *);
/* superbia/bundle.c: the host as a bundle, a bundle made the host. */
struct json_rsp;
int		 do_config_export(struct work *, bool, struct json_rsp *);
int		 do_config_apply(struct work *, const char *, bool, bool,
		    const char *, struct json_rsp *);
/* invidia/pathcheck.c: what this host does with a packet and its reply. */
int		 do_path_check(struct work *, const char *, const char *,
		    const char *, uint32_t, const char *, bool, uint32_t, bool,
		    struct json_rsp *);
bool		 kmod_loaded(const char *);
bool		 prefix_covers(const uint8_t *, const uint8_t *, int);
int		 if_fib(const char *);

/*
 * acedia/storage.c: disks, pools, datasets, mounts, as JSON of a kind
 * (ARC_STORAGE_KIND_*) that arcana-storage's read makes typed lists
 * (ystorage.c); fstab(5) read or put in place.
 */
struct storage_rsp {
	bool		 has_ok;
	bool		 ok;
	const char	*error;
	const char	*json;
	bool		 has_total;
	uint64_t	 total;		/* rows on the host, more than sent */
	bool		 truncated;
};
struct fstab_req {
	const char	*conf_text;	/* NULL: read */
	const char	*sha256;	/* of the text it was made from */
	bool		 dry_run;
};
struct fstab_rsp {
	bool		 has_ok;
	bool		 ok;
	const char	*error;
	const char	*conf_text;
	const char	*sha256;
};
int		 do_storage(struct work *, uint8_t, const char *,
		    struct storage_rsp *);
int		 do_fstab(struct work *, const struct fstab_req *,
		    struct fstab_rsp *);
char		**storage_argv(struct work *, const struct arc_job_spec *,
		    const char **);
const char	*storage_check(const struct arc_job_spec *);
char		*storage_title(const struct arc_job_spec *);
int		 do_storage_job(struct work *, const struct arc_job_spec *,
		    const char **);

/* luxuria/idsfw.c: the divert rules of a Security Suricata in a vnet
 * jail, in that jail's own ipfw; w in the jail. */
struct idsfw {
	const char	*name;
	int		 port;
	int		 nifs;
	const char	*ifs[16];
};
const char	*idsfw_check(struct work *);
int		 idsfw_set(struct work *, int, const struct idsfw *,
		    const char **);

/* luxuria/plugins.c */
void		 plugins_there(struct work *, int, const char *,
		    const char *const **, size_t *);
void		 plugins_forget(void);
int		 do_if_vnet(struct work *, const char *, const char *, bool,
		    bool, const char **);
char *const	*scope_argv(struct work *, char *const []);
char *const	*scope_jexec(struct work *, char *const []);
pid_t		 scope_pidfile(struct work *, const char *, const char *);
void		 scope_pid_stop(struct work *, const char *, const char *, int);
int		 scope_dirfd(struct work *, const char *);
int		 scope_open_dir(struct work *, const char *, const char **);
char		*scope_slurp(struct work *, const char *, size_t *);
int		 scope_replace(struct work *, const char *, const char *,
		    size_t, mode_t, const char *);
int		 file_replace(const char *, const char *, size_t, mode_t);
/* invidia/ynetconf.c: an undo that failed, logged and told */
void		 undo_report(const char *, int, const char *);
int		 scope_open(struct work *, const char *, int, mode_t);
bool		 scope_access(struct work *, const char *, bool);
FILE		*scope_fopen(struct work *, const char *);
int		 scope_kill(struct work *, pid_t, int);
void		 scope_stop(struct work *, pid_t, const char *, int);
int		 scope_open_read(struct work *, const char *);
int		 scope_mkdirs(struct work *, const char *);
int		 scope_unlink(struct work *, const char *);
int		 scope_rename(struct work *, const char *, const char *,
		    const char *);
int		 scope_helper(int, char **);
int		 repo_reach_helper(int, char **);
int		 rc_scripts_helper(int, char **);
int		 rc_stale_helper(int, int, char **);
const char	*scope_missing(struct work *, const struct execres *,
		    const char *, const char *);
char		*ifq_text(const char *, const char *, const char *);
char		**helper_argv(struct work *, const char *, size_t,
		    const char *const []);
int		 route_helper(int, char **);
int		 route_list(FILE *, int, uint32_t, const char *, const char *);
int		 route_lookup(FILE *, const char *, uint32_t);
int		 route_loopback(int);
int		 neigh_list(FILE *, int, const char *);
int		 addr_lines(FILE *);
int		 route_socket(void);
int		 helper_netlink(int);
int		 helper_icmp_socket(int, int, int);
int		 helper_sysctl_int(int, const char *, int *);
int		 helper_ipfw_socket(int);
int		 helper_bmp_socket(int, int, int);
int		 helper_pfkey_socket(int);
int		 helper_unix_socket(int, const char *);
int		 helper_rtsock_socket(int, bool *);
unsigned int	 plugins_here(void);
int		 jail_jid_name(int, char *, size_t, char *, size_t);
int		 jail_next(int);
/* ira/jailwatch.c: jail-state events, from EVFILT_JAIL */
void		 jail_watch_start(void);
/*
 * A service that runs in jails and follows them, told by jailwatch.c of
 * each jail made (and each running at its start) and each removed.  A
 * jail it wants is applied again once settled: the interfaces named
 * there inside it (none named: one up besides the loopback), when it
 * has a network of its own.  Registered before jail_watch_start().
 */
#define	JAIL_IFS_MAX	32
#define	JAIL_IFNAMSIZ	16	/* IFNAMSIZ */
struct jail_follower {
	const char	*what;		/* for the log: "security ids" */
	/* The jail made (name, jid) concerns it: the interfaces its
	 * instances there need inside, in ifs (max at most), and their
	 * number; -1 when it has nothing there to start. */
	int		(*wants)(const char *, int, char (*)[JAIL_IFNAMSIZ],
			    int);
	/* The jail settled: its kept lists applied again, a jail not
	 * running kept.  0, or -1 and why. */
	int		(*apply)(struct work *, const char *, const char **);
	/* The jail (name, jid) removed: what ran in it marked gone. */
	void		(*gone)(const char *, int);
};
void		 jail_follow(const struct jail_follower *);
int		 pcb_helper(int, char **);
int		 pcb_list(FILE *, bool, int);
int		 helper_lines(struct work *, const char *, size_t,
		    const char *const [], void (*)(const char *, void *), void *);
struct cbl_dump_state;
bool		 network_part(struct cbl_dump_state *,
		    const struct net_parts_req *, char **, uint64_t *,
		    const char **);
/* invidia/parts.c: the arcana-parts family, its network-parts stream. */
int		 parts_register(cbl_ctx *);
int		 zfs_pipe(int, char **);
int		 debug_as_nobody(int, char **);
int		 run_wait(int, char **);
int		 service_detach(int, char **);
int		 service_replace(int, char **);
const char	*tool(struct work *, const char *);
int		 do_health(struct work *, struct storage_rsp *);
struct ucl_object_s;
struct ucl_object_s *swap_list(struct work *);
void		 route_watch_start(void);
void		 event_add(const char *, const char *, ...) __printflike(2, 3);
/* A string as the inside of a JSON one, into a buffer (6 times its
 * length and one is room for all of it): what every event's maker
 * puts a string of the outside in with. */
const char	*json_quote(const char *, char *, size_t);
void		 events_told(bool);
void		 events_replay(time_t, void (*)(const char *, time_t, void *),
		    void (*)(void *), void *, time_t *, time_t *, bool *);
/* invidia/yserve.c: an event's JSON told as arcana-events' notification
 * on cblink's YANG family too; the events or the alarms changed, for
 * their on-change subscriptions. */
void		 yang_event(const char *);
/* A step of a request, told to its peer as arcana-jobs' steps: ENOENT
 * where it did not join group notify. */
int		 yang_step(cbl_conn *, const struct arcana_jobs_step *);
#define	YANG_EVENTS	0
#define	YANG_ALARMS	1
#define	YANG_JOBS	2
#define	YANG_INTERFACES	3
#define	YANG_ROUTING	4
#define	YANG_INSTANCES	5
#define	YANG_LNES	6
#define	YANG_NETWORKS	7
#define	YANG_COUNT	8
void		 yang_changed(int);
/* A steering choice changed: arcana-steer's steer-changed (fib -1, a
 * policy's; table NULL, a route's). */
void		 yang_steer_changed(const char *, const char *, const char *,
		    int, const char *, const char *, const char *, int, time_t);
/* What an event of that kind changed (of a jail's network, jailed). */
void		 yang_event_changed(const char *, bool);
struct cbl_ynode;
const struct cbl_ynode *ynode_named(const char *, const char *);
/* What a GET's filter names below a module's top-level node (yserve.c),
 * a hint for a get handler that lists fewer than there are: its child
 * alone; the key of that list's entry, into buf (NULL: none named). */
bool		 ytarget_is(cbl_req *, const char *, const char *,
		    const char *);
const char	*ytarget_key(cbl_req *, const char *, const char *,
		    const char *, const char *, char *, size_t);
/* A logical network element's root, by a helper attached to its jail
 * (invidia/lneroot.c). */
void		 yang_lne_failed(const char *, const char *, const char *);
struct ietf_i2nsf_ikeless_sadb_acquire;
struct ietf_i2nsf_ikeless_sadb_expire;
struct ietf_i2nsf_ikeless_sadb_seq_overflow;
void		 yang_sadb_acquire(const struct ietf_i2nsf_ikeless_sadb_acquire *);
void		 yang_sadb_expire(const struct ietf_i2nsf_ikeless_sadb_expire *);
void		 yang_sadb_seq_overflow(
		    const struct ietf_i2nsf_ikeless_sadb_seq_overflow *);
int		 lne_serve(void);
void		 lne_gone(int);
void		 lne_bound(const char *, const char *, bool);
/* invidia/ynotif.c: the configured subscriptions kept, told to cblink,
 * their receivers reached over HTTPS-notif; at the start. */
int		 ysubs_init(struct cbl_ctx *);

/*
 * superbia/secrets.c: what says it is a secret, and a text with each
 * secret's value as MASK_MARK: the one place a trace, a job, a bundle
 * and a read open to every role mask by.
 */
#define	MASK_MARK	"<hidden>"
bool		 secret_name(const char *, size_t);
bool		 secret_assign(const char *, size_t *);
bool		 secret_word(const char *);
char		*text_mask(const char *, bool *);
const char	*wmask(struct work *, const char *);
const char	*wurl(struct work *, const char *);
const char	*wjson_mask(struct work *, const char *);
bool		 text_secret(const char *);
char		*mask_secrets(const char *);
struct ucl_object_s;
int		 ucl_mask(struct ucl_object_s *);
/* luxuria/sdconf.c: a word for a rendered file's comment, or "-". */
const char	*conf_word(const char *);

/*
 * superbia/ynacm.c: how far a request's user is trusted with what a
 * read gives out, by its groups in the host's access rules: the
 * console's operators of the host are in group operator, its owners
 * (and the console itself, and the recovery session) in group admin;
 * anyone else a viewer.  A read open to every role gives a secret's
 * value to CLEAR_OPERATOR and above alone, masked (wmask()) or refused
 * below.
 */
#define	CLEAR_VIEWER	0
#define	CLEAR_OPERATOR	1
#define	CLEAR_ADMIN	2
#define	NACM_OPERATOR	"operator"
int		 clearance(cbl_req *);
const char	*jail_prog_refused(cbl_req *, const char *, const char *, char *,
		    size_t);

/* superbia/admit.c, ynacm.c: NACM (RFC 8341).  The console's users in
 * group admin by default: its admin, and the console itself for the
 * requests it makes for nobody. */
#define	NACM_ADMIN	"admin"
#define	NACM_CONSOLE	"console"
/* The rules cblink does not hold whole: a fault of this type on this
 * object, until they are (nacm_check(), at the start and each write). */
#define	NACM_FAULT		"nacm-rules"
#define	NACM_FAULT_OBJECT	"nacm"
void		 nacm_check(cbl_ctx *);
void		 event_add_jail(const char *, const char *, const char *, ...)
		    __printflike(3, 4);
int		 do_events(struct work *, uint64_t, struct json_rsp *);

/* invidia/netgraph.c */
int		 do_netgraph(struct work *, struct net_rsp *);
const char	*ng_check(const char *, const char *const *, size_t);
int		 do_ng(struct work *, const char *, const char *const *, size_t,
		    const char **);

/*
 * gula/stats.c: how busy the host is, arcana-host's stats: the CPU in
 * hundredths of a percent, the loads in hundredths; the pools from
 * zpool list.
 */
struct host_pool {
	const char	*name;
	bool		 has_size;
	uint64_t	 size;
	bool		 has_alloc;
	uint64_t	 alloc;
	bool		 has_free;
	uint64_t	 free;
	const char	*health;
};
struct host_stats {
	bool		 has_cpu_pct;
	int64_t		 cpu_pct;
	bool		 has_load1;
	int64_t		 load1;
	bool		 has_load5;
	int64_t		 load5;
	bool		 has_load15;
	int64_t		 load15;
	bool		 has_mem_total;
	uint64_t	 mem_total;
	bool		 has_mem_used;
	uint64_t	 mem_used;
	bool		 has_mem_inactive;
	uint64_t	 mem_inactive;
	bool		 has_mem_free;
	uint64_t	 mem_free;
	bool		 has_swap_total;
	uint64_t	 swap_total;
	bool		 has_swap_used;
	uint64_t	 swap_used;
	struct {
		size_t			 n;
		const struct host_pool	*v;
	}		 pools;
};
void		 do_stats(struct work *, struct host_stats *);

/* ira/packages.c: a package as pkg(8) says of it; a read of pkg's
 * (those installed, or what the repository has newer); an upgrade
 * asked and its outcome. */
struct package {
	const char	*name;
	const char	*installed;
	const char	*available;	/* the repository's, where newer */
	bool		 has_automatic;
	bool		 automatic;
	const char	*comment;
	bool		 has_size;
	uint64_t	 size;
	const char	*origin;
	bool		 vulnerable;	/* pkg audit's database says so */
	const char	**vulns;	/* its CVE (or VuXML) ids */
	size_t		 nvulns;
};
struct pkg_read {
	bool			 ok;
	const char		*error;
	struct package	*packages;
	size_t			 npackages;
	const char *const	*repos;		/* pkg -vv's, enabled or not */
	size_t			 nrepos;
	bool			 has_pkgbase;	/* a jail's base: pkgbase */
	bool			 pkgbase;
	const char		*audit_error;	/* why pkg audit said nothing */
	bool			 has_jail_pkg;	/* a jail's: pkg(8) there or not */
	bool			 jail_pkg;
	bool			 bootstrap_jail; /* none, and pkg(7) takes -j */
};
struct pkg_upgrade {
	const char		*jail;		/* NULL the host; "*" every one */
	struct {
		size_t		 n;		/* none: all */
		const char *const *v;
	}			 names;
	bool			 dry_run;
	bool			 ignore_osversion;
	uint8_t			 pkg_ip;	/* 4, 6, or 0 */
	const char		*pkg_repo;	/* from it alone, or NULL */
	bool			 no_repo_check;	/* pkg_reach() not asked */
};
struct pkg_upgraded {
	bool			 ok;
	const char		*error;
	bool			 has_upgraded;
	uint32_t		 upgraded;
	struct package	*packages;	/* still pending */
	size_t			 npackages;
};
int		 do_packages(struct work *, const char *, bool, bool, uint8_t,
		    bool, bool, struct pkg_read *);
int		 do_pkg_upgrade(struct work *, const struct pkg_upgrade *,
		    struct pkg_upgraded *);
int		 do_pkg_clean(struct work *, const char *, bool, const char **);
void		 pkg_audit(struct work *, const char *, struct pkg_read *);
int		 do_pkg_audit_fetch(struct work *, const char *, const char **);
int		 do_pkg_bootstrap(struct work *, const char *, uint8_t,
		    const char **);
bool		 pkg7_jail(struct work *);
int		 do_jail_base(struct work *, const struct arc_job_spec *,
		    const char **);
const char	*pkg_repo_error(struct work *, const struct execres *,
		    const char *);
const char	*pkg_repo_check(struct work *, const char *, const char *);
const char	*pkg_reach(struct work *, const char *, uint8_t, const char *);
const char	*pkg_stall_note(struct work *, const char *, uint8_t,
		    const char *);
void		 pkg_watch(bool);
void		 pkg_stalled(struct work *, struct execres *, const char *,
		    uint8_t, const char *);
const char	*pkg_error(struct work *, const struct execres *,
		    const char *);
void		 pkg_pkgbase_jails(struct work *, const char *const **,
		    size_t *);
int		 jobs_lanes(void);
const char	*jobs_set_lanes(int);
void		 jobs_conf_load(void);
/* invidia/cfgfiles.c: the files a commit writes, Arcana's own (false)
 * or the system's (arcana-agent's config-files). */
bool		 cf_system(void);
int		 do_pkg_install(struct work *, const struct arc_job_spec *,
		    const char **);

/* ira/jobs.c: queued changes, run in order whoever is or is not connected. */
void		 jobs_init(void);
void		 jobs_orphans_start(void);
int		 jobs_submit(const struct arc_job_spec *, size_t, const char *,
		    const char *, struct work *, const struct arc_job **,
		    size_t *);
void		 jobs_list(struct work *, const struct arc_job **, size_t *);
int		 jobs_submit_checked(cbl_req *, const struct arc_job_spec *,
		    size_t, struct work *, const struct arc_job **, size_t *,
		    const char **);
size_t		 jobs_waiting(void);
const struct arc_job *jobs_get(struct work *, uint64_t,
		    const struct arcana_jobs_step **, size_t *);
const struct arc_job *jobs_cancel(struct work *, uint64_t, const char **);
const struct arc_job *jobs_confirm(struct work *, uint64_t, const char **);
int		 jobs_dry_run(const struct arc_job_spec *, size_t,
		    struct work *, const char ***, size_t *, const char **);
int		 jobs_dry_checked(cbl_req *, const struct arc_job_spec *,
		    size_t, struct work *, const char ***, size_t *,
		    const char **);
int		 jobs_undo_preview(uint64_t, struct work *, const char ***,
		    size_t *, const char **);

/* invidia/address.c, superbia/confedit.c */
int		 ifaddr_change(struct work *, const char *, int, const void *,
		    int, bool, const char **);
int		 ifaddr_change_peer(struct work *, const char *, int,
		    const void *, int, const void *, bool, const char **);
const char	*list_edit(struct work *, const char *, const char *,
		    const char *, bool);
bool		 list_has(struct work *, const char *, const char *,
		    const char *);
char		*block_cut(struct work *, const char *, const char *, const char *,
		    char **);
char		*block_add(struct work *, const char *, const char *, const char *,
		    const char *);
int		 file_put(struct work *, const char *, const char *, mode_t,
		    const char **);
int		 write_backup(struct work *, const char *, const char *, size_t,
		    const char **);
bool		 verify_jail8(struct work *, const char *, const char *,
		    const char *, const char *, bool);

/* avaritia/resources.c, acedia/pools.c */
void		 resources_measure(struct work *, struct host_stats *);
void		 pools_measure(struct work *, struct host_stats *);

/*
 * ira/build.c, ira/update.c: what a build, a fetch or an update comes
 * to: ok or why not, with what a fetch tells of the server (its host
 * keys to confirm, the deploy key to give access); the program built,
 * compressed with its program_size, its SHA-256, version and commit.
 */
struct build_rsp {
	bool		 has_ok;
	bool		 ok;
	const char	*error;
	struct cbl_bytes binary;
	uint32_t	 program_size;
	const char	*sha256;
	const char	*agent_version;
	const char	*commit;
	const char	*host_keys;
	struct {
		size_t		 n;
		const char	*const *v;
	}		 fingerprints;
	const char	*deploy_key;
	bool		 has_older;	/* update: refused, a version before */
};
/* An update as sent: what its signature stands for (ira/update.c). */
struct agent_update {
	const char	*sha256;
	const char	*version;	/* NULL: none said */
	const uint8_t	*sig;
	size_t		 siglen;
	bool		 local;		/* root on the local socket: unsigned */
	bool		 downgrade;
};
int		 do_agent_build(struct work *, const char *, const char *,
		    const char *, const char *, struct build_rsp *);
int		 do_source_head(struct work *, const char *, const char *,
		    const char *, const char *, struct build_rsp *);
/*
 * source-log's: the head, the commits and the tags, each a JSON list,
 * and as a fetch tells them, the host keys to confirm and the deploy
 * key.
 */
struct source_log_rsp {
	bool		 has_ok;
	bool		 ok;
	const char	*error;
	const char	*commit;
	const char	*log;
	const char	*tags;
	const char	*host_keys;
	struct {
		size_t		 n;
		const char	*const *v;
	}		 fingerprints;
	const char	*deploy_key;
};
int		 do_source_log(struct work *, const char *, const char *,
		    const char *, const char *, uint32_t,
		    struct source_log_rsp *);

int		 do_console_update(struct work *, const char *, const char *,
		    const char *, const char *, struct build_rsp *);

/* ira/update.c */
int		 do_agent_update(struct work *, const uint8_t *, size_t,
		    size_t, const struct agent_update *, struct build_rsp *);
void		 service_restart(const char *);
void		 service_detached(const char *, const char *);
void		 service_replaced(const char *);

/* handlers.c */
bool		 change_note(const char *, ...) __printflike(1, 2);
void		 changes_stop(bool);
void		 changes_log(int);
void		 jobs_log(int);
void		 jobs_wake(void);
bool		 changes_stopping(void);
const char	*changes_current(struct work *, time_t *);

extern pthread_mutex_t	change_lock;	/* one change at a time */

/* main.c */
void		 logmsg(int, const char *, ...) __printflike(2, 3);

#endif /* !_AGENT_H_ */
