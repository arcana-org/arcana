/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A terminal to a host, or to one of its jails, for the page: a
 * WebSocket at /api/terminal, relayed both ways to the host's
 * arcana-stream terminal stream (the agent's ira/terminal.c), on which
 * the host runs login(1): the person logs in to an account of the
 * host's, by the host's own PAM.  The console gives no account and
 * knows no password; it decides who may reach the login prompt at all.
 *
 * The page's first message names the host,
 *
 *	{"server": "<id>", "jail": "<name>", "rows": 24, "cols": 80}
 *
 * (jail left out for the host's own), and is answered
 * {"opened": {...}} once the host's login runs, or {"error": "why"} and
 * the socket closed.  Then each binary message from the page is what
 * was typed, {"resize": [rows, cols]} the window's new size; each
 * binary message to it what the terminal wrote, {"login": "<name>"}
 * the account that logged in when the host says (utmpx, the host's own
 * sessions), and {"end": "why"} its end, after which the socket is
 * closed.
 *
 * Who may: a user signed in with a security key (no API token, no
 * session a password opened that the console limits: cnodes.c), whose
 * role on the host is operator or admin (users.c: the console's owners
 * are admins of every host, a tenant's users of their tenant's hosts
 * alone); a viewer never.  The page of ours alone asks, by its Origin,
 * as for /api/stream.  The socket is bound to the session that opened
 * it (auth.c's sbind), judged again every second with the role: the
 * session ended or the role gone, the terminal is hung up.
 *
 * The audit trail (audit.c) has each one: terminal-refused when the
 * console said no, terminal-opened when the host's login runs (who,
 * which host and jail, from where), terminal-closed at its end (the
 * bytes typed and written, how long, the account that logged in when
 * the host told it, why it ended).
 *
 * Mapped logins: a host's admin maps a console user, by id, to an
 * account of the host's or of one of its jails (servers.c, arcana-
 * console's terminal-login; audited, and the page says it gives that
 * account's full rights).  The user's terminal there is then the host's
 * terminal-as, login -f of that account (the agent's ira/terminal.c),
 * unless the first message says "prompt": true and the host allows the
 * password prompt (terminal-prompt, never: no prompt at all).  The host
 * decides by its own terminal-users which accounts may be had; the
 * mapping only chooses.  A mapping removed or changed, or the prompt
 * turned off under a plain one, hangs the terminal up within a second
 * (tsock_ok()).  An agent without terminal-as is said to be one ("this
 * host's agent cannot do mapped logins"), never given the prompt in its
 * place.  The trail's rows carry the account asked for and whether the
 * host confirmed it (utmpx; never in a jail); a refusal of the host's
 * is a terminal-refused with its reason.  A host's peer name, where it
 * is NULL, is its URI's host, which cblink checks the certificate for:
 * no host is taken on its CA alone.
 *
 * Each terminal is a task of its own, acting for its user, on the
 * connection the console shares with the host (hosts_shared()).  What
 * the host writes is taken from the stream's window, given back only
 * once the page's socket has less than TERM_WS_MAX queued: a page that
 * does not keep up holds its own host's terminal, whose writer then
 * waits, and nothing else.  TERM_WHO terminals of one user at once,
 * TERM_ALL of all; the host has its own limit and its own idle time.
 */

#include <sys/param.h>
#include <sys/queue.h>

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <cblink.h>
#include <cbl_schema.h>

#include "console.h"
#include "ymodel.h"
#include "ystream.h"

#define	TERM_ALL	32		/* at once, of every user */
#define	TERM_WHO	4		/* ... of one user */
#define	TERM_WINDOW	(256 * 1024)	/* what the host writes ahead */
#define	TERM_WS_MAX	(256 * 1024)	/* queued for the page, at most */
#define	TERM_IN_MAX	(64 * 1024)	/* typed, not yet sent */
#define	TERM_SEND	(16 * 1024)	/* typed, sent at once */
#define	TERM_MSG	(64 * 1024)	/* a message of the task's */
#define	TERM_TICK_MS	100
#define	TERM_FROM_MAX	64

/* A socket: who opened it, and its terminal once asked. */
struct tsock {
	LIST_ENTRY(tsock)	 list;
	struct conn		*c;
	struct sbind		 b;
	struct term		*t;	/* NULL before it asked, after it ended */
	bool			 asked;
};

/* What the host wrote, waiting for the task. */
struct tpart {
	STAILQ_ENTRY(tpart)	 next;
	size_t			 len;	/* of data */
	size_t			 took;	/* of the stream's window */
	char			 data[];
};

struct term {
	struct task		 task;	/* first */
	LIST_ENTRY(term)	 list;
	struct conn		*c;	/* the worker's: NULL once it went */
	atomic_bool		 stop;
	atomic_bool		 room;	/* the page's socket has room */
	atomic_bool		 gone;	/* the page's socket went */
	char			 sid[9];
	char			*uri, *peer, *host;
	char			 jail[256];
	char			 from[TERM_FROM_MAX + 1];
	char			 who[USER_NAME_LEN + 16];
	char			 uid[USER_ID_LEN];	/* the user's id */
	char			 account[33];	/* mapped: login -f's; "" */
	bool			 seen;		/* the host wrote: opened */
	int			 rows, cols;
	time_t			 born;
	pthread_mutex_t		 lock;
	pthread_cond_t		 wake;
	/* The lock's: */
	struct buf		*in;		/* typed, not yet sent */
	int			 nrows, ncols;	/* a size to send; 0 none */
	STAILQ_HEAD(, tpart)	 parts;
	char			 login[33];
	bool			 login_new;
	const char		*stopwhy;	/* why the console hung it up */
	bool			 opened, closed, writable;
	int			 code;
	char			 why[200];
	char			*json;		/* what the host said opening it */
	uint64_t		 nin, nout;
};

static LIST_HEAD(, tsock)	tsocks = LIST_HEAD_INITIALIZER(tsocks);
static LIST_HEAD(, term)	terms = LIST_HEAD_INITIALIZER(terms);
static int			nterms;
static struct timer		*term_timer;
static unsigned int		ticks;
static char			*msgbuf;	/* what the worker reads into */

/* {"key": text}, made by ucl: no text of a host's makes it more. */
static char *
json_of(const char *key, const char *text)
{
	ucl_object_t	*o;
	char		*s;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(text), key, 0, false);
	s = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(o);
	return (s);
}

/* To the page, from the task: a kind ('o' bytes, 'j' a text) first. */
static void
say(struct term *t, char kind, const void *p, size_t len)
{
	char	*m;

	if (len + 1 > TERM_MSG)
		return;
	m = xmalloc(len + 1);
	m[0] = kind;
	memcpy(m + 1, p, len);
	task_channel_write(&t->task, m, (uint32_t)(len + 1));
	free(m);
}

static void
say_json(struct term *t, const char *key, const char *text)
{
	char	*s;

	if ((s = json_of(key, text)) == NULL)
		return;
	say(t, 'j', s, strlen(s));
	free(s);
}

/* ---- The host's stream, from the loop that runs the connection ------ */

static void
t_open(cbl_stream *s __unused, cbl_msg *accept, int error, void *arg)
{
	struct arcana_stream_opened	 o;
	struct term			*t = arg;
	cbl_yarena			*a;

	pthread_mutex_lock(&t->lock);
	if (error == 0) {
		t->opened = true;
		if ((a = cbl_yarena_new()) != NULL) {
			if (ys_opened(accept, &o, a) == 0 && o.json != NULL)
				t->json = strdup(o.json);
			cbl_yarena_free(a);
		}
	} else {
		t->closed = true;
		t->code = error;
		/* An agent from before terminal-as (cblink's unknown
		 * command): said, never the prompt in its place. */
		if (t->account[0] != '\0' && error == EOPNOTSUPP &&
		    (accept == NULL || cbl_msg_err_str(accept) == NULL ||
		    strstr(cbl_msg_err_str(accept), "unknown command") !=
		    NULL))
			snprintf(t->why, sizeof(t->why), "this host's agent "
			    "cannot do mapped logins: update it");
		else
			snprintf(t->why, sizeof(t->why), "the host refused: %s",
			    accept != NULL && cbl_msg_err_str(accept) != NULL ?
			    cbl_msg_err_str(accept) : strerror(error));
	}
	pthread_cond_signal(&t->wake);
	pthread_mutex_unlock(&t->lock);
}

static void
t_data(cbl_stream *s, cbl_msg *data, void *arg)
{
	struct arcana_stream_chunk	 c;
	struct term			*t = arg;
	struct tpart			*p;
	cbl_yarena			*a;

	if ((a = cbl_yarena_new()) == NULL) {
		(void)cbl_stream_reset(s, ENOMEM);
		return;
	}
	if (ys_chunk(data, &c, a) != 0) {
		cbl_yarena_free(a);
		(void)cbl_stream_reset(s, EBADMSG);
		return;
	}
	/* Even a chunk of nothing took its room: given back with the
	 * rest. */
	if ((p = malloc(sizeof(*p) + c.data.len)) == NULL) {
		cbl_yarena_free(a);
		(void)cbl_stream_reset(s, ENOMEM);
		return;
	}
	p->len = c.data.len;
	p->took = cbl_msg_len(data);
	if (c.data.len > 0)
		memcpy(p->data, c.data.p, c.data.len);
	pthread_mutex_lock(&t->lock);
	if (c.login != NULL && t->login[0] == '\0') {
		snprintf(t->login, sizeof(t->login), "%s", c.login);
		t->login_new = true;
	}
	t->nout += c.data.len;
	STAILQ_INSERT_TAIL(&t->parts, p, next);
	pthread_cond_signal(&t->wake);
	pthread_mutex_unlock(&t->lock);
	cbl_yarena_free(a);
}

static void
t_close(cbl_stream *s __unused, int code, const char *text, void *arg)
{
	struct term	*t = arg;

	pthread_mutex_lock(&t->lock);
	if (!t->closed) {
		t->closed = true;
		t->code = code;
		if (t->why[0] == '\0')
			snprintf(t->why, sizeof(t->why), "%s", text != NULL &&
			    text[0] != '\0' ? text : code != 0 ? strerror(code) :
			    "the session ended");
	}
	pthread_cond_signal(&t->wake);
	pthread_mutex_unlock(&t->lock);
}

static void
t_writable(cbl_stream *s __unused, size_t credit __unused, void *arg)
{
	struct term	*t = arg;

	pthread_mutex_lock(&t->lock);
	t->writable = true;
	pthread_cond_signal(&t->wake);
	pthread_mutex_unlock(&t->lock);
}

static const struct cbl_stream_cbs t_cbs = {
	.on_open = t_open,
	.on_data = t_data,
	.on_close = t_close,
	.on_writable = t_writable,
};

/* The host's terminal stream opened, its room given back by hand. */
static int
t_stream(struct term *t, cbl_conn *conn, cbl_stream **sp)
{
	struct arcana_stream_open	 rq;
	const char			*names[5];
	char				 jail[300], rows[16], cols[16];
	char				 from[TERM_FROM_MAX + 8], account[48];
	size_t				 n;

	n = 0;
	if (t->jail[0] != '\0') {
		snprintf(jail, sizeof(jail), "jail=%s", t->jail);
		names[n++] = jail;
	}
	snprintf(rows, sizeof(rows), "rows=%d", t->rows);
	names[n++] = rows;
	snprintf(cols, sizeof(cols), "cols=%d", t->cols);
	names[n++] = cols;
	if (t->from[0] != '\0') {
		snprintf(from, sizeof(from), "from=%s", t->from);
		names[n++] = from;
	}
	if (t->account[0] != '\0') {
		snprintf(account, sizeof(account), "account=%s", t->account);
		names[n++] = account;
	}
	memset(&rq, 0, sizeof(rq));
	rq.name.v = names;
	rq.name.n = n;
	return (ys_open(conn, t->account[0] != '\0' ? YS_TERMINAL_AS :
	    YS_TERMINAL, &rq, TERM_WINDOW,
	    CBL_SF_MANUAL_CREDIT, &t_cbs, t, sp));
}

/* Where: the host by its name and id, and the jail. */
static void
t_where(const struct term *t, char *buf, size_t len)
{

	snprintf(buf, len, "host %s (%s)%s%s", t->host, t->sid,
	    t->jail[0] != '\0' ? ", jail " : "", t->jail);
}

/*
 * A mapped login opened, in the trail: once the host wrote, or told
 * the login (whichever first; its checks come after the stream's
 * accept, so the accept alone is no opening).
 */
static void
t_opened(struct term *t, const char *where)
{

	t->seen = true;
	audit_add("terminal-opened", "Allow", "terminal", "login -f of a "
	    "mapped account on a pseudo-terminal of the host's "
	    "(arcana-stream's terminal-as)", where, t->who, "from %s, as %s "
	    "(requested; %s)", t->from[0] != '\0' ? t->from : "an address not "
	    "known", t->account, t->jail[0] != '\0' ? "a jail's account is "
	    "proved by its getent, never confirmed by utmpx" : "the host "
	    "confirms it by utmpx");
}

/* In a task thread: the terminal, both ways, until either end goes. */
static int
term_run(struct task *task)
{
	struct term	*t = (struct term *)task;
	struct tpart	*p;
	struct arcana_stream_chunk c;
	struct timespec	 until;
	cbl_conn	*conn;
	cbl_stream	*st;
	const char	*msg;
	char		 where[400], *chunk, *s;
	size_t		 owed, n;
	int		 error, r, k;
	bool		 stopped;

	stopped = false;
	hosts_need(ROLE_OPERATOR);
	t_where(t, where, sizeof(where));
	if ((msg = hosts_shared(t->uri, t->peer, &conn)) != NULL) {
		say_json(t, "error", msg);
		log_msg(LOG_NOTICE, "terminal %s: %s", t->sid, msg);
		return (WEB_OK);
	}
	st = NULL;
	if ((error = t_stream(t, conn, &st)) != 0) {
		/* Only an agent without the command is said to be old. */
		snprintf(t->why, sizeof(t->why), "%s", error == EOPNOTSUPP ||
		    error == ENOENT ? t->account[0] != '\0' ? "this host's "
		    "agent cannot do mapped logins: update it" : "the host has "
		    "no terminal to give: is its agent older than this "
		    "console?" : strerror(error));
		say_json(t, "error", t->why);
		audit_add("terminal-refused", "Block", "terminal",
		    t->account[0] != '\0' ? "the host's terminal-as" : "the "
		    "host's terminal", where, t->who, "from %s%s%s: %s",
		    t->from[0] != '\0' ? t->from : "an address not known",
		    t->account[0] != '\0' ? ", as " : "", t->account, t->why);
		hosts_shared_done(conn, false);
		return (WEB_OK);
	}
	cbl_stream_ref(st);
	pthread_mutex_lock(&t->lock);
	while (!t->opened && !t->closed && !atomic_load(&t->stop)) {
		clock_gettime(CLOCK_REALTIME, &until);
		until.tv_sec += 1;
		(void)pthread_cond_timedwait(&t->wake, &t->lock, &until);
	}
	if (!t->opened) {
		pthread_mutex_unlock(&t->lock);
		say_json(t, "error", t->why[0] != '\0' ? t->why : "the page "
		    "went first");
		if (t->why[0] != '\0')
			audit_add("terminal-refused", "Block", "terminal",
			    t->account[0] != '\0' ? "the host's own "
			    "terminal-users and account checks (terminal-as)" :
			    "the host's terminal", where, t->who, "from %s%s%s: "
			    "%s", t->from[0] != '\0' ? t->from : "an address "
			    "not known", t->account[0] != '\0' ? ", as " : "",
			    t->account, t->why);
		goto done;
	}
	n = strlen(t->json != NULL ? t->json : "{}") + 16;
	s = xmalloc(n);
	snprintf(s, n, "{\"opened\":%s}", t->json != NULL ? t->json : "{}");
	pthread_mutex_unlock(&t->lock);
	say(t, 'j', s, strlen(s));
	free(s);
	/* A mapped login is opened once the host writes: its account's
	 * checks come after the stream's accept, and a refusal closes it
	 * before anything is written (terminal-refused, below). */
	if (t->account[0] == '\0')
		audit_add("terminal-opened", "Allow", "terminal", "login(1) on "
		    "a pseudo-terminal of the host's (arcana-stream's "
		    "terminal)", where, t->who, "from %s", t->from[0] != '\0' ?
		    t->from : "an address not known");
	log_msg(LOG_NOTICE, "terminal: %s opened %s", t->who, where);

	chunk = xmalloc(TERM_SEND);
	owed = 0;
	pthread_mutex_lock(&t->lock);
	for (;;) {
		/* Woken by the host, the page, room, or a tenth of a second
		 * to look at stop and the page's socket. */
		while (STAILQ_EMPTY(&t->parts) && !t->login_new && (t->in->offset
		    == 0 || !t->writable) && t->nrows == 0 && !t->closed &&
		    !atomic_load(&t->stop) && (owed == 0 ||
		    !atomic_load(&t->room))) {
			clock_gettime(CLOCK_REALTIME, &until);
			until.tv_nsec += TERM_TICK_MS * 1000000L;
			if (until.tv_nsec >= 1000000000L) {
				until.tv_sec++;
				until.tv_nsec -= 1000000000L;
			}
			(void)pthread_cond_timedwait(&t->wake, &t->lock, &until);
		}
		if (atomic_load(&t->stop) || (t->closed &&
		    STAILQ_EMPTY(&t->parts) && !t->login_new))
			break;
		/* What the host wrote, to the page. */
		while ((p = STAILQ_FIRST(&t->parts)) != NULL) {
			STAILQ_REMOVE_HEAD(&t->parts, next);
			pthread_mutex_unlock(&t->lock);
			if (p->len > 0)
				say(t, 'o', p->data, p->len);
			if (t->account[0] != '\0' && !t->seen && p->len > 0)
				t_opened(t, where);
			owed += p->took;
			free(p);
			pthread_mutex_lock(&t->lock);
		}
		if (t->login_new) {
			t->login_new = false;
			pthread_mutex_unlock(&t->lock);
			say_json(t, "login", t->login);
			/* A session that writes nothing (.hushlogin, an
			 * empty prompt) is opened by its login all the same. */
			if (t->account[0] != '\0' && !t->seen)
				t_opened(t, where);
			/* The host's word that the mapped account logged in. */
			if (t->account[0] != '\0')
				audit_add("terminal-confirmed", strcmp(t->login,
				    t->account) == 0 ? "Allow" : "Block",
				    "terminal", "the host's utmpx, as the agent "
				    "read it (arcana-stream's terminal-as)", where,
				    t->who, "%s requested, %s logged in: %s",
				    t->account, t->login, strcmp(t->login,
				    t->account) == 0 ? "confirmed" : "not "
				    "confirmed");
			pthread_mutex_lock(&t->lock);
		}
		/* What was typed, to the host, as it has room. */
		if (t->in->offset > 0 && t->writable && !t->closed) {
			n = MIN(t->in->offset, TERM_SEND);
			memcpy(chunk, t->in->data, n);
			pthread_mutex_unlock(&t->lock);
			error = ys_send(st, chunk, n);
			pthread_mutex_lock(&t->lock);
			if (error == 0) {
				memmove(t->in->data, t->in->data + n,
				    t->in->offset - n);
				t->in->offset -= n;
				t->nin += n;
			} else if (error == EAGAIN)
				t->writable = false;
			else
				t->closed = true;
		}
		if (t->nrows != 0 && !t->closed) {
			r = t->nrows;
			k = t->ncols;
			t->nrows = t->ncols = 0;
			pthread_mutex_unlock(&t->lock);
			memset(&c, 0, sizeof(c));
			c.has_rows = c.has_cols = true;
			c.rows = (uint16_t)r;
			c.cols = (uint16_t)k;
			/* Without room the next size the page sends does. */
			(void)ys_send_chunk(st, &c);
			pthread_mutex_lock(&t->lock);
		}
		/* The page took what it was sent: the host writes on. */
		if (owed > 0 && atomic_load(&t->room) && !t->closed) {
			pthread_mutex_unlock(&t->lock);
			(void)cbl_stream_consumed(st, owed);
			owed = 0;
			pthread_mutex_lock(&t->lock);
		}
	}
	free(chunk);
	pthread_mutex_unlock(&t->lock);
done:
	/* The page went, or the console ended it: the host hangs up. */
	pthread_mutex_lock(&t->lock);
	stopped = !t->closed;
	pthread_mutex_unlock(&t->lock);
	if (stopped)
		(void)cbl_stream_close(st, 0, NULL);
	/* Until it is closed its callbacks still look at t. */
	pthread_mutex_lock(&t->lock);
	while (!t->closed) {
		clock_gettime(CLOCK_REALTIME, &until);
		until.tv_sec += 5;
		if (pthread_cond_timedwait(&t->wake, &t->lock, &until) ==
		    ETIMEDOUT)
			break;
	}
	if (t->why[0] == '\0' || stopped)
		snprintf(t->why, sizeof(t->why), "%s", t->stopwhy != NULL ?
		    t->stopwhy : !atomic_load(&t->gone) ?
		    "the console ended it: the session ended or "
		    "the role is gone" : "the page closed it");
	pthread_mutex_unlock(&t->lock);
	cbl_stream_rele(st);
	hosts_shared_done(conn, true);
	if (t->opened && t->account[0] != '\0' && !t->seen &&
	    t->login[0] == '\0') {
		/* Closed before the host wrote: its checks refused it. */
		say_json(t, "end", t->why);
		audit_add("terminal-refused", "Block", "terminal", "the host's "
		    "own terminal-users and account checks (terminal-as)",
		    where, t->who, "from %s, as %s: %s", t->from[0] != '\0' ?
		    t->from : "an address not known", t->account, t->why);
		log_msg(LOG_NOTICE, "terminal: %s refused %s as %s: %s", t->who,
		    where, t->account, t->why);
	} else if (t->opened && t->account[0] != '\0') {
		say_json(t, "end", t->why);
		audit_add("terminal-closed", "Allow", "terminal", "login -f of "
		    "a mapped account on a pseudo-terminal of the host's "
		    "(arcana-stream's terminal-as)", where, t->who, "%ju bytes "
		    "typed, %ju bytes written, %jd s; %s requested, %s%s%s; %s",
		    (uintmax_t)t->nin, (uintmax_t)t->nout, (intmax_t)(time(NULL)
		    - t->born), t->account, strcmp(t->login, t->account) == 0 ?
		    "confirmed" : "not confirmed", t->login[0] != '\0' &&
		    strcmp(t->login, t->account) != 0 ? ": the host told " : "",
		    t->login[0] != '\0' && strcmp(t->login, t->account) != 0 ?
		    t->login : "", t->why);
		log_msg(LOG_NOTICE, "terminal: %s closed %s as %s: %ju bytes "
		    "typed, %ju written; %s", t->who, where, t->account,
		    (uintmax_t)t->nin, (uintmax_t)t->nout, t->why);
	} else if (t->opened) {
		say_json(t, "end", t->why);
		audit_add("terminal-closed", "Allow", "terminal", "login(1) on "
		    "a pseudo-terminal of the host's (arcana-stream's "
		    "terminal)", where, t->who, "%ju bytes typed, %ju bytes "
		    "written, %jd s; %s%s; %s", (uintmax_t)t->nin,
		    (uintmax_t)t->nout, (intmax_t)(time(NULL) - t->born),
		    t->login[0] != '\0' ? "logged in as " : "the account "
		    "that logged in not told", t->login, t->why);
		log_msg(LOG_NOTICE, "terminal: %s closed %s: %ju bytes typed, "
		    "%ju written; %s", t->who, where, (uintmax_t)t->nin,
		    (uintmax_t)t->nout, t->why);
	}
	return (WEB_OK);
}

/* ---- The page's socket, on the worker -------------------------------- */

static void
term_free(struct term *t)
{
	struct tpart	*p;
	struct tsock	*k;

	if (t->c != NULL && (k = t->c->hdlr_extra) != NULL && k->t == t)
		k->t = NULL;
	LIST_REMOVE(t, list);
	nterms--;
	task_destroy(&t->task);
	while ((p = STAILQ_FIRST(&t->parts)) != NULL) {
		STAILQ_REMOVE_HEAD(&t->parts, next);
		free(p);
	}
	buf_free(t->in);
	free(t->json);
	free(t->uri);
	free(t->peer);
	free(t->host);
	pthread_mutex_destroy(&t->lock);
	pthread_cond_destroy(&t->wake);
	free(t);
}

/* What the task wrote, to the page; its end closes the socket. */
static void
term_ready(struct task *task)
{
	struct term	*t = (struct term *)task;
	uint32_t	 len;

	while (task_channel_pending(task)) {
		len = task_channel_read(task, msgbuf, TERM_MSG);
		if (len < 1 || len > TERM_MSG || t->c == NULL)
			continue;
		ws_send(t->c, msgbuf[0] == 'o' ? WS_OP_BINARY : WS_OP_TEXT,
		    msgbuf + 1, len - 1);
	}
	if (t->c != NULL)
		atomic_store(&t->room, ws_queued(t->c) < TERM_WS_MAX);
	if (task_finished(task)) {
		if (t->c != NULL)
			ws_close(t->c);
		term_free(t);
	}
}

/* The socket's binding still good, and its user an operator of the
 * terminal's host still?  Else it is hung up. */
static bool
tsock_ok(struct conn *c)
{
	struct tsock	*k;
	struct term	*t;
	const char	*why;
	char		 acct[33];

	why = NULL;
	if ((k = c->hdlr_extra) != NULL && sbind_ok(&k->b) && (k->t == NULL ||
	    principal_may(&k->b.who, k->t->sid, ROLE_OPERATOR))) {
		/* A mapped login's mapping still the same; a prompt's host
		 * still allowing it. */
		if ((t = k->t) == NULL)
			return (true);
		if (t->account[0] != '\0' && (!servers_term_account(t->sid,
		    t->jail[0] != '\0' ? t->jail : NULL, t->uid, acct,
		    sizeof(acct)) || strcmp(acct, t->account) != 0))
			why = "the console ended it: the mapped login was "
			    "removed or changed";
		else if (t->account[0] == '\0' && servers_term_never(t->sid))
			why = "the console ended it: the host's password prompt "
			    "was turned off";
		else
			return (true);
	}
	if (k != NULL && k->t != NULL) {
		atomic_store(&k->t->stop, true);
		pthread_mutex_lock(&k->t->lock);
		if (why != NULL)
			k->t->stopwhy = why;
		pthread_cond_signal(&k->t->wake);
		pthread_mutex_unlock(&k->t->lock);
		/* The page told why first: its task's end closes the socket. */
		if (why != NULL)
			return (false);
	}
	ws_close(c);
	return (false);
}

/* So often: the pages' sockets measured for room, and every second
 * judged again. */
static void
term_tick(void *arg __unused, uint64_t now __unused)
{
	struct tsock	*k, *next;
	struct term	*t;
	bool		 had;

	ticks++;
	LIST_FOREACH(t, &terms, list) {
		if (t->c == NULL)
			continue;
		had = atomic_load(&t->room);
		atomic_store(&t->room, ws_queued(t->c) < TERM_WS_MAX);
		if (!had && atomic_load(&t->room)) {
			pthread_mutex_lock(&t->lock);
			pthread_cond_signal(&t->wake);
			pthread_mutex_unlock(&t->lock);
		}
	}
	if (ticks % (1000 / TERM_TICK_MS) != 0)
		return;
	LIST_FOREACH_SAFE(k, &tsocks, list, next)
		(void)tsock_ok(k->c);
}

static void
term_connect(struct conn *c)
{
	struct tsock	*k;

	if ((k = c->hdlr_extra) == NULL) {
		ws_close(c);
		return;
	}
	k->c = c;
	LIST_INSERT_HEAD(&tsocks, k, list);
	if (term_timer == NULL)
		term_timer = timer_add(term_tick, TERM_TICK_MS, NULL, 0);
}

/* The socket went: its terminal hung up, its task ending by itself. */
static void
term_disconnect(struct conn *c)
{
	struct tsock	*k;
	struct term	*t;

	LIST_FOREACH(t, &terms, list)
		if (t->c == c) {
			t->c = NULL;
			atomic_store(&t->gone, true);
			atomic_store(&t->stop, true);
			pthread_mutex_lock(&t->lock);
			pthread_cond_signal(&t->wake);
			pthread_mutex_unlock(&t->lock);
		}
	if ((k = c->hdlr_extra) != NULL && k->c == c)
		LIST_REMOVE(k, list);
	free(c->hdlr_extra);
	c->hdlr_extra = NULL;
}

/* No: said to the page, and the socket closed. */
static void
refuse(struct conn *c, const char *why)
{
	char	*s;

	if ((s = json_of("error", why)) != NULL) {
		ws_send(c, WS_OP_TEXT, s, strlen(s));
		free(s);
	}
	ws_close(c);
}

/* login -h's host: the page's address, of what a host name has. */
static void
from_of(const char *addr, char *buf, size_t len)
{
	size_t	n;

	for (n = 0; *addr != '\0' && n + 1 < len; addr++)
		if (isalnum((unsigned char)*addr) || strchr(".:-_", *addr) !=
		    NULL)
			buf[n++] = *addr;
	buf[n] = '\0';
	while (buf[0] == '-')
		memmove(buf, buf + 1, strlen(buf));
}

/* The page's first message: which host and jail, how large. */
static void
term_ask(struct conn *c, struct tsock *k, const char *data, size_t len)
{
	const struct server	*sv;
	struct ucl_parser	*p;
	ucl_object_t		*o;
	struct term		*t, *u;
	const char		*sid, *jail, *q;
	char			 who[USER_NAME_LEN + 16], where[400], acct[33];
	int64_t			 rows, cols;
	int			 n;
	bool			 prompt, mapped;

	k->asked = true;
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = NULL;
	if (ucl_parser_add_chunk(p, (const unsigned char *)data, len))
		o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	sid = o != NULL ? ucl_str(o, "server") : NULL;
	jail = o != NULL ? ucl_str(o, "jail") : NULL;
	rows = o != NULL ? ucl_object_toint(ucl_object_lookup(o, "rows")) : 0;
	cols = o != NULL ? ucl_object_toint(ucl_object_lookup(o, "cols")) : 0;
	prompt = o != NULL && ucl_object_toboolean(ucl_object_lookup(o,
	    "prompt"));
	if (jail != NULL && jail[0] == '\0')
		jail = NULL;
	q = jail;
	if (jail != NULL)
		for (; *q != '\0'; q++)
			if (!isalnum((unsigned char)*q) && strchr("._-", *q) ==
			    NULL)
				break;
	if (sid == NULL || rows < 1 || rows > 1000 || cols < 1 || cols > 1000 ||
	    (jail != NULL && (*q != '\0' || strlen(jail) > 255 || jail[0] ==
	    '.'))) {
		refuse(c, "a terminal is asked for by server, jail (a jail's "
		    "name, or none for the host), rows and cols (1 to 1000)");
		goto out;
	}
	if ((sv = server_find(sid)) == NULL || !principal_may(&k->b.who, sid,
	    ROLE_VIEWER)) {
		refuse(c, "no such server");
		goto out;
	}
	(void)principal_who(&k->b.who, who, sizeof(who));
	if (k->b.who.kind != P_USER || !principal_may(&k->b.who, sid,
	    ROLE_OPERATOR)) {
		snprintf(where, sizeof(where), "host %s (%s)%s%s", sv->name,
		    sv->id, jail != NULL ? ", jail " : "", jail != NULL ? jail :
		    "");
		audit_add("terminal-refused", "Block", "terminal", "the "
		    "console's roles: an operator or admin of the host alone",
		    where, who, "from %s: a viewer of the host", k->b.addr);
		refuse(c, "a terminal is for an operator or an admin of the "
		    "host: a viewer gets none");
		goto out;
	}
	/* Mapped: the account this user is logged in as there, by id, but
	 * when the prompt is asked for and allowed. */
	mapped = servers_term_account(sv->id, jail, k->b.who.uid, acct,
	    sizeof(acct)) && !(prompt && !servers_term_never(sv->id));
	if (!mapped && servers_term_never(sv->id)) {
		snprintf(where, sizeof(where), "host %s (%s)%s%s", sv->name,
		    sv->id, jail != NULL ? ", jail " : "", jail != NULL ? jail :
		    "");
		audit_add("terminal-refused", "Block", "terminal", "the host's "
		    "terminal-prompt: never", where, who, "from %s: no mapped "
		    "login there, and no password prompt", k->b.addr);
		refuse(c, "this host allows no password prompt, and no mapped "
		    "login of yours is there");
		goto out;
	}
	n = 0;
	LIST_FOREACH(u, &terms, list)
		if (strcmp(u->task.who.name, k->b.who.name) == 0)
			n++;
	if (nterms >= TERM_ALL || n >= TERM_WHO) {
		refuse(c, nterms >= TERM_ALL ? "too many terminals are open "
		    "on this console: try again later" : "four terminals of "
		    "yours are open: close one first");
		goto out;
	}
	if (msgbuf == NULL)
		msgbuf = xmalloc(TERM_MSG);
	t = xcalloc(1, sizeof(*t));
	t->c = c;
	atomic_init(&t->stop, false);
	atomic_init(&t->room, true);
	atomic_init(&t->gone, false);
	strlcpy(t->sid, sv->id, sizeof(t->sid));
	t->uri = xstrdup(sv->uri);
	t->peer = sv->peer_name != NULL ? xstrdup(sv->peer_name) : NULL;
	t->host = xstrdup(sv->name);
	if (jail != NULL)
		strlcpy(t->jail, jail, sizeof(t->jail));
	from_of(k->b.addr, t->from, sizeof(t->from));
	strlcpy(t->who, who, sizeof(t->who));
	strlcpy(t->uid, k->b.who.uid, sizeof(t->uid));
	if (mapped)
		strlcpy(t->account, acct, sizeof(t->account));
	t->rows = (int)rows;
	t->cols = (int)cols;
	t->born = time(NULL);
	t->in = buf_alloc(1024);
	t->writable = true;
	pthread_mutex_init(&t->lock, NULL);
	pthread_cond_init(&t->wake, NULL);
	STAILQ_INIT(&t->parts);
	LIST_INSERT_HEAD(&terms, t, list);
	nterms++;
	k->t = t;
	task_create(&t->task, term_run);
	task_bind_callback(&t->task, term_ready);
	task_bind_principal(&t->task, &k->b.who);
	task_run(&t->task);
out:
	if (o != NULL)
		ucl_object_unref(o);
}

static void
term_message(struct conn *c, uint8_t op, void *data, size_t len)
{
	struct tsock	*k;
	struct term	*t;
	ucl_object_t	*o;
	const ucl_object_t *sz;
	struct ucl_parser *p;
	int64_t		 r, n;

	if (!tsock_ok(c) || (k = c->hdlr_extra) == NULL)
		return;
	if (!k->asked) {
		if (op != WS_OP_TEXT || len > 4096)
			refuse(c, "the first message names the host, as JSON");
		else
			term_ask(c, k, data, len);
		return;
	}
	if ((t = k->t) == NULL)
		return;
	if (op == WS_OP_BINARY) {
		pthread_mutex_lock(&t->lock);
		if (t->in->offset + len > TERM_IN_MAX) {
			pthread_mutex_unlock(&t->lock);
			atomic_store(&t->stop, true);
			refuse(c, "more was typed than the host takes");
			return;
		}
		buf_append(t->in, data, len);
		pthread_cond_signal(&t->wake);
		pthread_mutex_unlock(&t->lock);
		return;
	}
	if (len > 256)
		return;
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = NULL;
	if (ucl_parser_add_chunk(p, data, len))
		o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	if (o == NULL)
		return;
	if ((sz = ucl_object_lookup(o, "resize")) != NULL &&
	    ucl_object_type(sz) == UCL_ARRAY && ucl_array_size(sz) == 2) {
		r = ucl_object_toint(ucl_array_find_index(sz, 0));
		n = ucl_object_toint(ucl_array_find_index(sz, 1));
		if (r >= 1 && r <= 1000 && n >= 1 && n <= 1000) {
			pthread_mutex_lock(&t->lock);
			t->nrows = (int)r;
			t->ncols = (int)n;
			pthread_cond_signal(&t->wake);
			pthread_mutex_unlock(&t->lock);
		}
	}
	ucl_object_unref(o);
}

/*
 * GET /api/terminal, to become a WebSocket.  It needs the session (a
 * security key's: cnodes.c), and a page of ours asking, by its Origin;
 * which host, and whether this user may, the first message says.
 */
int
api_terminal(struct http_request *req)
{
	const char	*v;

	if (!guard(req, true))
		return (WEB_OK);
	if (!http_request_header(req, "origin", &v) || (strcmp(v,
	    cfg.origin) != 0 && !cluster_origin(v)))
		return (reply_error(req, 403, "csrf", "not from the console's "
		    "own page"));
	free(req->owner->hdlr_extra);
	req->owner->hdlr_extra = xcalloc(1, sizeof(struct tsock));
	sbind_make(req, &((struct tsock *)req->owner->hdlr_extra)->b);
	ws_handshake(req, term_connect, term_message, term_disconnect);
	return (WEB_OK);
}
