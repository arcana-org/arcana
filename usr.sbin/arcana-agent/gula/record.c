/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: the record of what the security rules logged (MEF 138).
 * A rule with "log logdst rtsock" tells each packet it sees on the
 * routing socket (RTM_IPFWLOG): the rule's
 * number, its action, the packet's addresses, the interface and the
 * rule's comment, which the console makes name the service and the
 * policy.  A thread of its own reads them: each is an entry of the
 * record, kept a day in memory and on disk beside the agent's files,
 * and an event (sdwan-security) as it comes, twenty a second at most.
 * When a rule nears its logamount, the agent resets its log so the
 * flow goes on.  The routing socket carries every routing message, and
 * FreeBSD's has no filter by type (ROUTE_MSGFILTER is OpenBSD's): the
 * others are read and passed over.  What the kernel dropped for want of
 * room (ENOBUFS) is counted, said with the record (lost) and logged
 * once a minute at most.
 *
 * A vnet jail's ipfw logs to the jail's own routing socket, which the
 * host's does not hear: a bound MBSF's reset of cleartext HTTP in a
 * vnet jail's SSLproxy (luxuria/sslproxy.c), or any rule of the jail's
 * with logdst rtsock.  Such a jail's socket is made in its network by
 * the helper (invidia/scope.c, rtsock-socket: it attaches to the jail,
 * reads the jail's rules by IP_FW3 and makes the socket only where one
 * logs there) and handed over (SCM_RIGHTS); one a jail, RJAILS_MAX at
 * most, read by a second thread (a kqueue of them, made with the first)
 * and closed when the jail is removed (jailwatch.c's follower, below),
 * since its credential would keep the jail dying, or when its rules no
 * longer log there.  A jail's entries and events are tagged with its
 * name (the record's jail; the event's, as event_add_jail() puts it),
 * its interface's index named by the helper in the jail (an index is
 * the jail's, not the host's; kept a while, RJ_IFS a jail), its rule's
 * log reset by the jail's own ipfw.  The
 * jails asked for: each vnet jail, as it settles and at the start, that
 * an Arcana feature has such rules in (rtsock_wanted()); and whenever
 * SSL inspection loads or takes away a vnet jail's rules, or its watch
 * finds them there.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip_fw.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	RECORD_FILE	"sdwan-record.json"
#define	RECORD_MAX	10000
#define	RECORD_KEEP	(24 * 3600)
#define	RECORD_LAST	500
#define	RECORD_EVENTS_S	20
#define	RECORD_SAVE_S	30
#define	RJAILS_MAX	64	/* jails' routing sockets listened on */
#define	NAMES_MAX	256	/* jails' names the record keeps */

struct rec {
	time_t		t;
	uint64_t	seq;
	uint32_t	rule;
	char		action[12];
	char		src[48];
	char		dst[48];
	char		iface[IFNAMSIZ];
	char		comment[82];
	const char	*jail;		/* a vnet jail's (interned), or NULL */
};

#define	RJ_IFS		16	/* a jail's interfaces named, by index */
#define	RJ_IF_KEEP	300	/* s, a name kept before it is asked again */

/* A vnet jail's routing socket, listened on, and the names of its
 * interfaces' indexes as the helper told them. */
struct rjail {
	int		 jid;
	int		 fd;
	uint32_t	 gen;		/* its kevent's udata */
	const char	*name;		/* interned */
	struct {
		unsigned	index;
		char		name[IFNAMSIZ];	/* "" none of it */
		time_t		at;
	}		 ifs[RJ_IFS];
	int		 nextif;	/* the one replaced next */
};

static pthread_mutex_t	lock = PTHREAD_MUTEX_INITIALIZER;
static struct rec	*ring;
static int		 first, count;
static uint64_t		 seq;
static uint64_t		 dropped;	/* events beyond the second's twenty */
static uint64_t		 overflows;	/* the socket's, the kernel's drops */
static bool		 dirty;

static pthread_mutex_t	jlock = PTHREAD_MUTEX_INITIALIZER;
static struct rjail	rjails[RJAILS_MAX];
static int		nrjails;
static int		jkq = -1;	/* the jails' sockets' kqueue */
static uint32_t		jgen;

/* A jail's name, kept once for every entry of it (under lock); NULL
 * past NAMES_MAX names. */
static const char *
intern(const char *name)
{
	static char	*names[NAMES_MAX];
	static int	 nnames;
	int		 i;

	if (name == NULL || name[0] == '\0')
		return (NULL);
	for (i = 0; i < nnames; i++)
		if (strcmp(names[i], name) == 0)
			return (names[i]);
	if (nnames == NAMES_MAX || (names[nnames] = strdup(name)) == NULL)
		return (NULL);
	return (names[nnames++]);
}

/* The entries of the day, as JSON, oldest first. */
static char *
record_text(void)
{
	ucl_object_t	*arr, *o;
	unsigned char	*json;
	time_t		 now;
	int		 i;

	now = time(NULL);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < count; i++) {
		const struct rec *r = &ring[(first + i) % RECORD_MAX];

		if (now - r->t > RECORD_KEEP)
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)r->t), "t", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)r->seq), "seq",
		    0, false);
		ucl_object_insert_key(o, ucl_object_fromint(r->rule), "rule", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(r->action), "action",
		    0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(r->src), "src", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(r->dst), "dst", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(r->iface), "iface", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(r->comment),
		    "comment", 0, false);
		if (r->jail != NULL)
			ucl_object_insert_key(o, ucl_object_fromstring(r->jail),
			    "jail", 0, false);
		ucl_array_append(arr, o);
	}
	json = ucl_object_emit(arr, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(arr);
	return ((char *)json);
}

/* Kept on disk, now and then, under the lock. */
static void
record_save(void)
{
	char		*text;
	const char	*e;

	if (!dirty || (text = record_text()) == NULL)
		return;
	e = NULL;
	if (sdwan_conf_write(RECORD_FILE, text, &e) != 0)
		logmsg(LOG_WARNING, "sdwan record: %s: %s", RECORD_FILE, e);
	else
		dirty = false;
	free(text);
}

/* One entry more, under the lock; whether it is one of the second's
 * twenty events. */
static bool
record_add(const struct rec *r)
{
	static time_t	sec;
	static int	in_sec;
	struct rec	*slot;

	if (count == RECORD_MAX) {
		first = (first + 1) % RECORD_MAX;
		count--;
	}
	slot = &ring[(first + count) % RECORD_MAX];
	*slot = *r;
	slot->seq = ++seq;
	count++;
	dirty = true;
	if (r->t != sec) {
		sec = r->t;
		in_sec = 0;
	}
	if (++in_sec > RECORD_EVENTS_S) {
		dropped++;
		return (false);
	}
	return (true);
}

/* The word for a rule's action, from its instruction. */
static const char *
action_word(uint8_t opcode)
{

	switch (opcode) {
	case O_DENY:
		return ("deny");
	case O_REJECT:
	case O_UNREACH6:
		return ("reject");
	case O_ACCEPT:
		return ("allow");
	case O_COUNT:
		return ("count");
	case O_SKIPTO:
		return ("skipto");
	case O_PIPE:
		return ("pipe");
	case O_QUEUE:
		return ("queue");
	case O_FORWARD_IP:
	case O_FORWARD_IP6:
		return ("fwd");
	case O_SETFIB:
		return ("setfib");
	case O_NAT:
		return ("nat");
	default:
		return ("rule");
	}
}

/* The rule's log reset, so it keeps telling; once a second a rule:
 * the host's, or a vnet jail's by its own ipfw (jail interned). */
static void
reset_log(uint32_t rule, const char *jail)
{
	static pthread_mutex_t	 rlock = PTHREAD_MUTEX_INITIALIZER;
	static uint32_t		 last_rule;
	static const char	*last_jail;
	static time_t		 last_t;
	struct work		 w;
	struct execres		 res;
	const char		*e;
	char			*argv[5], num[16];
	time_t			 now;

	now = time(NULL);
	pthread_mutex_lock(&rlock);
	if (rule == last_rule && jail == last_jail && now == last_t) {
		pthread_mutex_unlock(&rlock);
		return;
	}
	last_rule = rule;
	last_jail = jail;
	last_t = now;
	pthread_mutex_unlock(&rlock);
	work_init(&w);
	w.nice = true;
	e = NULL;
	if (jail != NULL && scope_enter(&w, jail, &e) != 0) {
		work_free(&w);
		return;
	}
	snprintf(num, sizeof(num), "%u", rule);
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"-q";
	argv[2] = (char *)(uintptr_t)"resetlog";
	argv[3] = num;
	argv[4] = NULL;
	(void)run_exec(&w, argv, &res);
	work_free(&w);
}

/* One message of the routing socket (the host's, or jail's: its
 * interned name, and jid): an entry when it is a log.  The addresses
 * in it are packed, so each is copied before it is read; the interface
 * is the header's index, named, where the message names none: by the
 * host, or for a jail's (an index of its own interfaces) by the helper
 * in it. */
static void	jail_ifname(int, const char *, unsigned, char *, size_t);

static void
record_message(const struct rt_msghdr *rtm, size_t len, const char *jail,
    int jid)
{
	const char			*p, *end;
	struct sockaddr			 sa;
	struct sockaddr_dl		 sdl;
	struct sockaddr_in		 sin;
	struct sockaddr_in6		 sin6;
	ipfwlog_rtsock_hdr_v2		 hdr;
	struct rec			 r;
	char				 jc[6 * 82], js[6 * 48], jd[6 * 48];
	char				 ji[6 * IFNAMSIZ], ja[6 * 12];
	size_t				 salen, n;
	int				 i;
	bool				 tell;

	if (rtm->rtm_type != RTM_IPFWLOG || rtm->rtm_msglen > len)
		return;
	memset(&r, 0, sizeof(r));
	r.t = time(NULL);
	p = (const char *)(rtm + 1);
	end = (const char *)rtm + rtm->rtm_msglen;
	for (i = 0; i < RTAX_MAX && p + sizeof(sa) <= end; i++) {
		if ((rtm->rtm_addrs & (1 << i)) == 0)
			continue;
		memcpy(&sa, p, sizeof(sa));
		salen = sa.sa_len > 0 ? sa.sa_len : sizeof(long);
		if (p + salen > end)
			break;
		if (i == RTAX_DST && sa.sa_family == AF_IPFWLOG) {
			memset(&sdl, 0, sizeof(sdl));
			memcpy(&sdl, p, MIN(salen, sizeof(sdl)));
			n = salen - offsetof(struct sockaddr_dl, sdl_data);
			if (salen > offsetof(struct sockaddr_dl, sdl_data) + sizeof(hdr)) {
				memcpy(&hdr, p + offsetof(struct sockaddr_dl, sdl_data),
				    sizeof(hdr));
				r.rule = hdr.rulenum;
				snprintf(r.action, sizeof(r.action), "%s", action_word(
				    hdr.cmd.opcode));
				if (sdl.sdl_nlen > 0 && n > sizeof(hdr))
					snprintf(r.comment, sizeof(r.comment), "%.*s", (int)
					    MIN((size_t)sdl.sdl_nlen, MIN(n - sizeof(hdr),
					    sizeof(r.comment) - 1)), p + offsetof(struct
					    sockaddr_dl, sdl_data) + sizeof(hdr));
			}
		} else if (i == RTAX_GATEWAY || i == RTAX_NETMASK) {
			char	*out = i == RTAX_GATEWAY ? r.src : r.dst;

			if (sa.sa_family == AF_INET && salen >= sizeof(sin)) {
				memcpy(&sin, p, sizeof(sin));
				inet_ntop(AF_INET, &sin.sin_addr, out, sizeof(r.src));
			} else if (sa.sa_family == AF_INET6 && salen >= sizeof(sin6)) {
				memcpy(&sin6, p, sizeof(sin6));
				inet_ntop(AF_INET6, &sin6.sin6_addr, out, sizeof(r.src));
			}
		} else if (i == RTAX_IFP && sa.sa_family == AF_LINK) {
			memset(&sdl, 0, sizeof(sdl));
			memcpy(&sdl, p, MIN(salen, sizeof(sdl)));
			snprintf(r.iface, sizeof(r.iface), "%.*s", (int)MIN((size_t)
			    sdl.sdl_nlen, sizeof(r.iface) - 1), sdl.sdl_data);
		}
		p += roundup2(salen, sizeof(long));
	}
	if (r.rule == 0)
		return;
	/* The interface, by its index in the message's header. */
	if (jail == NULL && r.iface[0] == '\0' && rtm->rtm_index > 0 &&
	    if_indextoname(rtm->rtm_index, r.iface) == NULL)
		r.iface[0] = '\0';
	if (jail != NULL && r.iface[0] == '\0' && rtm->rtm_index > 0)
		jail_ifname(jid, jail, rtm->rtm_index, r.iface,
		    sizeof(r.iface));
	r.jail = jail;
	pthread_mutex_lock(&lock);
	tell = record_add(&r);
	pthread_mutex_unlock(&lock);
	if (tell)
		event_add_jail(jail, "sdwan-security", "{\"seq\":%ju,\"rule\":%u,\"action\":\"%s"
		    "\",\"src\":\"%s\",\"dst\":\"%s\",\"iface\":\"%s\",\"comment\":\"%s\"}",
		    (uintmax_t)seq, r.rule, json_quote(r.action, ja, sizeof(ja)),
		    json_quote(r.src, js, sizeof(js)), json_quote(r.dst, jd,
		    sizeof(jd)), json_quote(r.iface, ji, sizeof(ji)),
		    json_quote(r.comment, jc, sizeof(jc)));
	if (rtm->rtm_flags & RTF_PROTO1)
		reset_log(r.rule, jail);
}

/* A drop of the kernel's counted, said once a minute (jail: whose). */
static void
overflowed(time_t *said, const char *jail)
{
	uintmax_t	n;

	pthread_mutex_lock(&lock);
	n = ++overflows;
	pthread_mutex_unlock(&lock);
	if (time(NULL) - *said >= 60) {
		*said = time(NULL);
		logmsg(LOG_WARNING, "sdwan record: the routing socket%s%s "
		    "overflowed (%ju times): logged packets lost", jail != NULL ?
		    " of the jail " : "", jail != NULL ? jail : "", n);
	}
}

/* The record kept on disk, RECORD_SAVE_S after the last time. */
static void
save_due(time_t *saved)
{

	if (time(NULL) - *saved < RECORD_SAVE_S)
		return;
	pthread_mutex_lock(&lock);
	record_save();
	pthread_mutex_unlock(&lock);
	*saved = time(NULL);
}

static void *
reader(void *arg __unused)
{
	char		 buf[4096];
	ssize_t		 n;
	time_t		 saved, said;
	int		 fd;

	if ((fd = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC)) == -1) {
		logmsg(LOG_WARNING, "sdwan record: routing socket: %s",
		    strerror(errno));
		return (NULL);
	}
	saved = time(NULL);
	said = 0;
	for (;;) {
		n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			/* Messages the kernel dropped, the socket full:
			 * counted, said once a minute. */
			if (errno == ENOBUFS) {
				overflowed(&said, NULL);
				continue;
			}
			break;
		}
		if (n >= (ssize_t)sizeof(struct rt_msghdr))
			record_message((const struct rt_msghdr *)buf, (size_t)n,
			    NULL, 0);
		save_due(&saved);
	}
	close(fd);
	return (NULL);
}

/* ---- The vnet jails' routing sockets ----------------------------- */

/* The listened-on socket of jid, its index; -1 for none (under jlock). */
static int
rjail_find(int jid)
{
	int	i;

	for (i = 0; i < nrjails; i++)
		if (rjails[i].jid == jid)
			return (i);
	return (-1);
}

/* The one at i closed and dropped (under jlock); its kevent goes with
 * the descriptor. */
static void
rjail_drop(int i)
{

	close(rjails[i].fd);
	rjails[i] = rjails[--nrjails];
}

static void
ifname_line(const char *line, void *arg)
{

	snprintf(arg, IFNAMSIZ, "%s", line);
}

/*
 * The name of interface index of the jail (jid), as the helper in it
 * says it (if-name), kept RJ_IF_KEEP seconds, a name it has not too: a
 * jail's interfaces are its own, the host's index names another.
 */
static void
jail_ifname(int jid, const char *jail, unsigned index, char *out,
    size_t len)
{
	struct work	 w;
	const char	*e, *words[1];
	char		 name[IFNAMSIZ], num[16];
	time_t		 now;
	int		 i, k;

	now = time(NULL);
	pthread_mutex_lock(&jlock);
	if ((i = rjail_find(jid)) == -1) {
		pthread_mutex_unlock(&jlock);
		return;
	}
	for (k = 0; k < RJ_IFS; k++)
		if (rjails[i].ifs[k].index == index && now -
		    rjails[i].ifs[k].at < RJ_IF_KEEP) {
			snprintf(out, len, "%s", rjails[i].ifs[k].name);
			pthread_mutex_unlock(&jlock);
			return;
		}
	pthread_mutex_unlock(&jlock);
	name[0] = '\0';
	work_init(&w);
	w.nice = true;
	e = NULL;
	snprintf(num, sizeof(num), "%u", index);
	words[0] = num;
	if (scope_enter(&w, jail, &e) == 0)
		(void)helper_lines(&w, "if-name", 1, words, ifname_line, name);
	work_free(&w);
	snprintf(out, len, "%s", name);
	pthread_mutex_lock(&jlock);
	if ((i = rjail_find(jid)) != -1) {
		for (k = 0; k < RJ_IFS && rjails[i].ifs[k].index != index; k++)
			;
		if (k == RJ_IFS) {
			k = rjails[i].nextif;
			rjails[i].nextif = (k + 1) % RJ_IFS;
		}
		rjails[i].ifs[k].index = index;
		snprintf(rjails[i].ifs[k].name, sizeof(rjails[i].ifs[k].name),
		    "%s", name);
		rjails[i].ifs[k].at = now;
	}
	pthread_mutex_unlock(&jlock);
}

/*
 * The jails' sockets read: an event's descriptor taken as the one it
 * was added for only while the same (its gen), so that one closed
 * meanwhile, its number given again, is not read for it.  Its message
 * copied out under jlock, never read while the socket may be closed.
 */
static void *
jreader(void *arg __unused)
{
	struct kevent	 ev;
	char		 buf[4096];
	const char	*name;
	ssize_t		 n;
	time_t		 saved, said;
	int		 i, e, jid;

	saved = time(NULL);
	said = 0;
	for (;;) {
		if (kevent(jkq, NULL, 0, &ev, 1, NULL) == -1) {
			if (errno == EINTR)
				continue;
			logmsg(LOG_WARNING, "sdwan record: the jails' routing "
			    "sockets: kevent: %s", strerror(errno));
			break;
		}
		if (ev.filter != EVFILT_READ)
			continue;
		pthread_mutex_lock(&jlock);
		for (i = 0; i < nrjails; i++)
			if (rjails[i].fd == (int)ev.ident && rjails[i].gen ==
			    (uint32_t)(uintptr_t)ev.udata)
				break;
		if (i == nrjails) {
			pthread_mutex_unlock(&jlock);
			continue;
		}
		name = rjails[i].name;
		jid = rjails[i].jid;
		n = read(rjails[i].fd, buf, sizeof(buf));
		e = errno;
		if (n == 0 || (n < 0 && e != EINTR && e != EAGAIN && e !=
		    ENOBUFS)) {
			logmsg(LOG_WARNING, "sdwan record: the jail %s's routing "
			    "socket: %s: no longer listened on", name != NULL ?
			    name : "?", n == 0 ? "closed" : strerror(e));
			rjail_drop(i);
		}
		pthread_mutex_unlock(&jlock);
		if (n < 0 && e == ENOBUFS)
			overflowed(&said, name);
		if (n >= (ssize_t)sizeof(struct rt_msghdr))
			record_message((const struct rt_msghdr *)buf, (size_t)n,
			    name, jid);
		save_due(&saved);
	}
	return (NULL);
}

/*
 * jail's (jid) routing socket listened on where its ipfw logs there,
 * the helper asked; nothing asked where it is already, unless recheck,
 * when one no longer wanted is closed.  0, or -1 where the helper
 * failed (said in the log).
 */
int
record_jail_sync(const char *jail, int jid, bool recheck)
{
	struct kevent	 ev;
	pthread_t	 tid;
	const char	*name;
	bool		 none, have;
	int		 fd, i, error;

	if (jail == NULL || jid <= 0 || ring == NULL)
		return (0);
	pthread_mutex_lock(&jlock);
	/* Its number given to another jail: the old one's dropped. */
	if ((i = rjail_find(jid)) != -1 && (rjails[i].name == NULL ||
	    strcmp(rjails[i].name, jail) != 0)) {
		rjail_drop(i);
		i = -1;
	}
	have = i != -1;
	pthread_mutex_unlock(&jlock);
	if (have && !recheck)
		return (0);
	if ((fd = helper_rtsock_socket(jid, &none)) == -1) {
		if (!none) {
			logmsg(LOG_WARNING, "sdwan record: no routing socket in "
			    "the jail %s (the helper failed): what its rules "
			    "log there is not recorded", jail);
			return (-1);
		}
		if (have) {
			record_jail_gone(jid);
			logmsg(LOG_INFO, "sdwan record: no rule of the jail %s "
			    "logs to its routing socket any more: not listened "
			    "on", jail);
		}
		return (0);
	}
	(void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	pthread_mutex_lock(&lock);
	name = intern(jail);
	pthread_mutex_unlock(&lock);
	pthread_mutex_lock(&jlock);
	if (rjail_find(jid) != -1) {
		/* Listened on already (asked again meanwhile). */
		pthread_mutex_unlock(&jlock);
		close(fd);
		return (0);
	}
	if (nrjails == RJAILS_MAX || name == NULL) {
		pthread_mutex_unlock(&jlock);
		close(fd);
		logmsg(LOG_WARNING, "sdwan record: %d jails' routing sockets "
		    "listened on already: the jail %s's is not", nrjails,
		    jail);
		return (-1);
	}
	if (jkq == -1) {
		if ((jkq = kqueue()) == -1 || (error = pthread_create(&tid,
		    NULL, jreader, NULL)) != 0) {
			logmsg(LOG_WARNING, "sdwan record: the jails' routing "
			    "sockets not read: %s", jkq == -1 ? strerror(errno) :
			    strerror(error));
			if (jkq != -1)
				close(jkq);
			jkq = -1;
			pthread_mutex_unlock(&jlock);
			close(fd);
			return (-1);
		}
		(void)pthread_detach(tid);
	}
	EV_SET(&ev, fd, EVFILT_READ, EV_ADD, 0, 0, (void *)(uintptr_t)++jgen);
	if (kevent(jkq, &ev, 1, NULL, 0, NULL) == -1) {
		pthread_mutex_unlock(&jlock);
		logmsg(LOG_WARNING, "sdwan record: the jail %s's routing socket: "
		    "kevent: %s", jail, strerror(errno));
		close(fd);
		return (-1);
	}
	memset(&rjails[nrjails], 0, sizeof(rjails[nrjails]));
	rjails[nrjails].jid = jid;
	rjails[nrjails].fd = fd;
	rjails[nrjails].gen = jgen;
	rjails[nrjails].name = name;
	nrjails++;
	pthread_mutex_unlock(&jlock);
	logmsg(LOG_INFO, "sdwan record: listening on the routing socket of "
	    "the jail %s", jail);
	return (0);
}

/* The jail removed (or its rules gone): its socket closed. */
void
record_jail_gone(int jid)
{
	int	i;

	pthread_mutex_lock(&jlock);
	if ((i = rjail_find(jid)) != -1)
		rjail_drop(i);
	pthread_mutex_unlock(&jlock);
}

/*
 * Whether a jail made concerns the record: a vnet jail some Arcana
 * feature has rules logging to the routing socket in (SSL inspection's
 * kept rules); none to wait for but one up besides the loopback.
 */
static int
rtsock_wanted(const char *name __unused, int jid,
    char (*ifs)[JAIL_IFNAMSIZ] __unused, int max __unused)
{

	return (sslproxy_jail_rtsock(jid) ? 0 : -1);
}

/* The jail settled: listened on where its rules log there now. */
static int
rtsock_apply(struct work *w, const char *jail, const char **errp)
{
	struct jinfo	ji;
	int		jid;

	if ((jid = jail_named(w, jail, &ji)) < 0 || !ji.vnet)
		return (0);
	if (record_jail_sync(jail, jid, true) != 0) {
		*errp = "no routing socket made in it";
		return (-1);
	}
	return (0);
}

static void
rtsock_gone(const char *name __unused, int jid)
{

	record_jail_gone(jid);
}

static const struct jail_follower rtsock_follower = {
	.what = "sdwan record",
	.wants = rtsock_wanted,
	.apply = rtsock_apply,
	.gone = rtsock_gone,
};

/*
 * The helper's, attached to the jail: whether a rule of its ipfw logs
 * to the routing socket (an O_LOG with IPFW_LOG_RTSOCK), read by IP_FW3
 * (IP_FW_XGET).  1, 0, or -1 where ipfw cannot be read (none there).
 */
int
rtsock_logged(void)
{
	ipfw_cfg_lheader	*cfg;
	ipfw_obj_ctlv		*ctlv;
	ipfw_obj_tlv		*tlv;
	struct ip_fw_bcounter	*cnt;
	struct ip_fw_rule	*r;
	const ipfw_insn		*cmd;
	socklen_t		 sz;
	size_t			 at, room, k, l;
	uint32_t		 i;
	int			 fd, tries, found;

	if ((fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW)) ==
	    -1)
		return (-1);
	sz = 65536;
	cfg = NULL;
	for (tries = 0; tries < 8; tries++) {
		free(cfg);
		if ((cfg = calloc(1, sz)) == NULL)
			break;
		cfg->opheader.opcode = IP_FW_XGET;
		cfg->opheader.version = IP_FW3_OPVER;
		cfg->flags = IPFW_CFG_GET_STATIC | IPFW_CFG_GET_COUNTERS;
		cfg->start_rule = 0;
		cfg->end_rule = IPFW_DEFAULT_RULE;
		if (getsockopt(fd, IPPROTO_IP, IP_FW3, cfg, &sz) == 0)
			break;
		if (errno != ENOMEM) {
			free(cfg);
			cfg = NULL;
			break;
		}
		sz = cfg->size > sz * 2 ? cfg->size : sz * 2;
	}
	close(fd);
	if (cfg == NULL || tries == 8) {
		free(cfg);
		return (-1);
	}
	found = 0;
	at = sizeof(*cfg);
	ctlv = (ipfw_obj_ctlv *)(void *)((char *)cfg + at);
	if (at + sizeof(*ctlv) <= sz && ctlv->head.type ==
	    IPFW_TLV_TBLNAME_LIST) {
		at += ctlv->head.length;
		ctlv = (ipfw_obj_ctlv *)(void *)((char *)cfg + at);
	}
	if (at + sizeof(*ctlv) > sz || ctlv->head.type != IPFW_TLV_RULE_LIST) {
		free(cfg);
		return (0);
	}
	at += sizeof(*ctlv);
	for (i = 0; i < ctlv->count && at + sizeof(*tlv) <= sz && !found; i++,
	    at += tlv->length) {
		tlv = (ipfw_obj_tlv *)(void *)((char *)cfg + at);
		if (tlv->length < sizeof(*tlv) + sizeof(*cnt) + sizeof(*r) ||
		    at + tlv->length > sz)
			break;
		cnt = (struct ip_fw_bcounter *)(void *)(tlv + 1);
		if (cnt->size < sizeof(*cnt) || sizeof(*tlv) + cnt->size +
		    sizeof(*r) > tlv->length)
			break;
		r = (struct ip_fw_rule *)(void *)((char *)cnt + cnt->size);
		room = (tlv->length - sizeof(*tlv) - cnt->size -
		    offsetof(struct ip_fw_rule, cmd)) / sizeof(ipfw_insn);
		for (k = 0; k < r->cmd_len && k < room; k += l) {
			cmd = &r->cmd[k];
			if ((l = F_LEN(cmd)) == 0)
				break;
			if (cmd->opcode == O_LOG &&
			    (cmd->arg1 & IPFW_LOG_RTSOCK) != 0) {
				found = 1;
				break;
			}
		}
	}
	free(cfg);
	return (found);
}

/* At the start: the day's record read back, and the reader started. */
void
record_start(void)
{
	pthread_t		 tid;
	struct ucl_parser	*p;
	ucl_object_t		*top;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	char			*text;
	struct rec		 r;

	if ((ring = calloc(RECORD_MAX, sizeof(*ring))) == NULL)
		return;
	if ((text = sdwan_kept_read(RECORD_FILE)) != NULL) {
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		top = ucl_parser_add_string(p, text, 0) ? ucl_parser_get_object(p)
		    : NULL;
		ucl_parser_free(p);
		free(text);
		it = NULL;
		while (top != NULL && (e = ucl_object_iterate(top, &it, true)) !=
		    NULL) {
			memset(&r, 0, sizeof(r));
			r.t = (time_t)ucl_object_toint(ucl_object_lookup(e, "t"));
			r.rule = (uint32_t)ucl_object_toint(ucl_object_lookup(e,
			    "rule"));
			snprintf(r.action, sizeof(r.action), "%s",
			    ucl_object_tostring_forced(ucl_object_lookup(e, "action")));
			snprintf(r.src, sizeof(r.src), "%s", ucl_object_tostring_forced(
			    ucl_object_lookup(e, "src")));
			snprintf(r.dst, sizeof(r.dst), "%s", ucl_object_tostring_forced(
			    ucl_object_lookup(e, "dst")));
			snprintf(r.iface, sizeof(r.iface), "%s",
			    ucl_object_tostring_forced(ucl_object_lookup(e, "iface")));
			snprintf(r.comment, sizeof(r.comment), "%s",
			    ucl_object_tostring_forced(ucl_object_lookup(e, "comment")));
			r.jail = intern(ucl_object_tostring(ucl_object_lookup(e,
			    "jail")));
			if (time(NULL) - r.t <= RECORD_KEEP)
				(void)record_add(&r);
		}
		if (top != NULL)
			ucl_object_unref(top);
		dirty = false;
	}
	if (pthread_create(&tid, NULL, reader, NULL) == 0)
		(void)pthread_detach(tid);
	/* The vnet jails followed from now: jailwatch.c starts after. */
	jail_follow(&rtsock_follower);
}

/* The day's count, the last sequence number and the latest entries. */
void
record_json(ucl_object_t *top)
{
	ucl_object_t	*o, *arr, *e;
	time_t		 now;
	int		 i, n, from;

	now = time(NULL);
	o = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	pthread_mutex_lock(&lock);
	n = 0;
	for (i = 0; i < count; i++)
		if (now - ring[(first + i) % RECORD_MAX].t <= RECORD_KEEP)
			n++;
	from = count > RECORD_LAST ? count - RECORD_LAST : 0;
	for (i = count - 1; i >= from; i--) {
		const struct rec *r = &ring[(first + i) % RECORD_MAX];

		if (now - r->t > RECORD_KEEP)
			continue;
		e = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(e, ucl_object_fromint((int64_t)r->t), "t", 0,
		    false);
		ucl_object_insert_key(e, ucl_object_fromint((int64_t)r->seq), "seq",
		    0, false);
		ucl_object_insert_key(e, ucl_object_fromint(r->rule), "rule", 0,
		    false);
		ucl_object_insert_key(e, ucl_object_fromstring(r->action), "action",
		    0, false);
		ucl_object_insert_key(e, ucl_object_fromstring(r->src), "src", 0,
		    false);
		ucl_object_insert_key(e, ucl_object_fromstring(r->dst), "dst", 0,
		    false);
		ucl_object_insert_key(e, ucl_object_fromstring(r->iface), "iface", 0,
		    false);
		ucl_object_insert_key(e, ucl_object_fromstring(r->comment),
		    "comment", 0, false);
		if (r->jail != NULL)
			ucl_object_insert_key(e, ucl_object_fromstring(r->jail),
			    "jail", 0, false);
		ucl_array_append(arr, e);
	}
	ucl_object_insert_key(o, ucl_object_fromint(n), "count", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)seq), "seq", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)dropped),
	    "untold", 0, false);
	if (overflows > 0)
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)overflows),
		    "lost", 0, false);
	pthread_mutex_unlock(&lock);
	ucl_object_insert_key(o, arr, "last", 0, false);
	ucl_object_insert_key(top, o, "record", 0, false);
}
