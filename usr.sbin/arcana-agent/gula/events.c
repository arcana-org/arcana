/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: what happened on the host, as it happened.  An event is a
 * number, a time, a kind and what it is about, a JSON object; whoever
 * sees one happen adds it (the kernel's netlink messages, for one),
 * and the last of them are kept, to be asked for from a number on:
 * who asks again with the number of the last one it has misses none,
 * unless more happened in between than are kept, which the reply's
 * "first" tells.
 *
 * What one is about is made by its maker as JSON text, each string of
 * the outside in it by json_quote(), and checked here before it is
 * kept: one that is no JSON object (RFC 8259, UTF-8) is dropped and
 * said, so that it never spoils the list it would be read in.
 */

#include <sys/types.h>

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "agent.h"

#define	EVENTS_KEPT	512
#define	EVENT_MAX	4096		/* bytes of what one is about */
#define	JSON_DEPTH	32

struct event {
	uint64_t	 n;
	time_t		 t;
	const char	*kind;		/* a literal */
	char		*jail;		/* whose network, NULL the host's */
	char		*data;
};

static pthread_mutex_t	ev_lock = PTHREAD_MUTEX_INITIALIZER;
static struct event	ring[EVENTS_KEPT];
static size_t		ring_first, ring_n;
static uint64_t		ev_last;
static time_t		ev_since;	/* the first event's, or the start */
static bool		 ev_told;	/* up: the events are told */

/*
 * The agent up: the events are told to those who subscribed, as
 * arcana-events' notification; down before it goes, so that none is
 * told after.
 */
void
events_told(bool up)
{

	pthread_mutex_lock(&ev_lock);
	ev_told = up;
	pthread_mutex_unlock(&ev_lock);
}

static void	event_vadd(const char *, const char *, const char *,
		    va_list) __printflike(3, 0);

/* kind is a string that stays; the rest makes a JSON object. */
void
event_add(const char *kind, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	event_vadd(NULL, kind, fmt, ap);
	va_end(ap);
}

/* The same, of a jail's own network: jail is its name. */
void
event_add_jail(const char *jail, const char *kind, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	event_vadd(jail, kind, fmt, ap);
	va_end(ap);
}

/* A JSON string of a jail's name: letters, digits and ._- only. */
static bool
name_ok(const char *s)
{

	return (s != NULL && s[0] != '\0' && strlen(s) < 256 && s[strspn(s,
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	    "._-")] == '\0');
}

/* The length of the UTF-8 character s begins with, whole and the
 * shortest form; 0 when it is none. */
static size_t
utf8_len(const unsigned char *s)
{
	size_t	n, i;
	unsigned int	c;

	if (s[0] < 0x80)
		return (1);
	if (s[0] >= 0xc2 && s[0] <= 0xdf)
		n = 2;
	else if (s[0] >= 0xe0 && s[0] <= 0xef)
		n = 3;
	else if (s[0] >= 0xf0 && s[0] <= 0xf4)
		n = 4;
	else
		return (0);
	for (i = 1; i < n; i++)
		if ((s[i] & 0xc0) != 0x80)
			return (0);
	c = n == 3 ? (s[0] & 0x0fU) << 12 | (s[1] & 0x3fU) << 6 :
	    n == 4 ? (s[0] & 0x07U) << 18 | (s[1] & 0x3fU) << 12 : 0x80;
	/* Overlong, a surrogate, beyond U+10FFFF. */
	if ((n == 3 && (c < 0x800 || (c >= 0xd800 && c <= 0xdfff))) ||
	    (n == 4 && (c < 0x10000 || c > 0x10ffff)))
		return (0);
	return (n);
}

/*
 * s as the inside of a JSON string into buf, len bytes: '"' and '\'
 * escaped, a control character as \u00XX, a byte that is no UTF-8 '?';
 * cut short where the next would not fit, never inside one.  buf.
 */
const char *
json_quote(const char *s, char *buf, size_t len)
{
	const unsigned char	*p;
	size_t			 n, k;

	if (len == 0)
		return (buf);
	for (p = (const unsigned char *)(s != NULL ? s : ""), n = 0; *p !=
	    '\0'; p += k) {
		if (*p == '"' || *p == '\\') {
			if (n + 3 > len)
				break;
			buf[n++] = '\\';
			buf[n++] = (char)*p;
			k = 1;
		} else if (*p < 0x20) {
			if (n + 7 > len)
				break;
			if (*p == '\t' || *p == '\n' || *p == '\r') {
				buf[n++] = '\\';
				buf[n++] = *p == '\t' ? 't' : *p == '\n' ? 'n' :
				    'r';
			} else
				n += (size_t)snprintf(buf + n, len - n,
				    "\\u%04x", *p);
			k = 1;
		} else if ((k = utf8_len(p)) == 0) {
			if (n + 2 > len)
				break;
			buf[n++] = '?';
			k = 1;
		} else {
			if (n + k + 1 > len)
				break;
			memcpy(buf + n, p, k);
			n += k;
		}
	}
	buf[n] = '\0';
	return (buf);
}

/* JSON's whitespace skipped. */
static const char *
ws(const char *s)
{

	while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')
		s++;
	return (s);
}

static const char	*json_value(const char *, int);

/* A JSON string at s ('"'): past it, or NULL. */
static const char *
json_string(const char *s)
{
	size_t	k;
	int	i;

	for (s++; *s != '"'; s += k) {
		if ((unsigned char)*s < 0x20)
			return (NULL);
		k = 1;
		if (*s == '\\') {
			if (s[1] == 'u') {
				for (i = 2; i < 6; i++)
					if (strchr("0123456789abcdefABCDEF",
					    s[i]) == NULL || s[i] == '\0')
						return (NULL);
				k = 6;
			} else if (s[1] != '\0' && strchr("\"\\/bfnrt", s[1]) !=
			    NULL)
				k = 2;
			else
				return (NULL);
		} else if ((k = utf8_len((const unsigned char *)s)) == 0)
			return (NULL);
	}
	return (s + 1);
}

/* A JSON number at s: past it, or NULL. */
static const char *
json_number(const char *s)
{

	if (*s == '-')
		s++;
	if (*s == '0')
		s++;
	else if (*s >= '1' && *s <= '9')
		while (*s >= '0' && *s <= '9')
			s++;
	else
		return (NULL);
	if (*s == '.') {
		if (*++s < '0' || *s > '9')
			return (NULL);
		while (*s >= '0' && *s <= '9')
			s++;
	}
	if (*s == 'e' || *s == 'E') {
		if (*++s == '+' || *s == '-')
			s++;
		if (*s < '0' || *s > '9')
			return (NULL);
		while (*s >= '0' && *s <= '9')
			s++;
	}
	return (s);
}

/* A JSON value at s (RFC 8259), depth deep at most: past it, or NULL. */
static const char *
json_value(const char *s, int depth)
{
	char	end;

	s = ws(s);
	switch (*s) {
	case '{':
	case '[':
		if (depth == 0)
			return (NULL);
		end = *s == '{' ? '}' : ']';
		if (*(s = ws(s + 1)) == end)
			return (s + 1);
		for (;;) {
			if (end == '}') {
				if (*s != '"' || (s = json_string(s)) == NULL ||
				    *(s = ws(s)) != ':')
					return (NULL);
				s++;
			}
			if ((s = json_value(s, depth - 1)) == NULL)
				return (NULL);
			if (*(s = ws(s)) == end)
				return (s + 1);
			if (*s != ',')
				return (NULL);
			s = ws(s + 1);
		}
	case '"':
		return (json_string(s));
	case 't':
		return (strncmp(s, "true", 4) == 0 ? s + 4 : NULL);
	case 'f':
		return (strncmp(s, "false", 5) == 0 ? s + 5 : NULL);
	case 'n':
		return (strncmp(s, "null", 4) == 0 ? s + 4 : NULL);
	default:
		return (json_number(s));
	}
}

/* s is one JSON object, and nothing after it. */
static bool
json_object(const char *s)
{

	s = ws(s);
	return (*s == '{' && (s = json_value(s, JSON_DEPTH)) != NULL &&
	    *ws(s) == '\0');
}

static void
event_vadd(const char *jail, const char *kind, const char *fmt, va_list ap)
{
	struct event		*e;
	char			*data, *json, *jname;
	int			 n;

	n = vasprintf(&data, fmt, ap);
	if (n == -1)
		return;
	jname = NULL;
	/* Not JSON, or too long: dropped, and said, never kept to spoil
	 * the list. */
	if (n > EVENT_MAX || !json_object(data)) {
		logmsg(LOG_WARNING, "event %s dropped: %s: %.200s", kind, n >
		    EVENT_MAX ? "longer than an event may be" : "not a JSON "
		    "object", data);
		free(data);
		return;
	}
	if (jail != NULL && (!name_ok(jail) || (jname = strdup(jail)) ==
	    NULL)) {
		free(data);
		return;
	}
	pthread_mutex_lock(&ev_lock);
	if (ring_n < EVENTS_KEPT)
		e = &ring[(ring_first + ring_n++) % EVENTS_KEPT];
	else {
		e = &ring[ring_first];
		ring_first = (ring_first + 1) % EVENTS_KEPT;
		free(e->data);
		free(e->jail);
	}
	e->n = ++ev_last;
	e->t = time(NULL);
	if (ev_since == 0)
		ev_since = e->t;
	e->kind = kind;
	e->jail = jname;
	e->data = data;
	/* Told to the subscribers too, as arcana-events' notification,
	 * in the order they are kept. */
	json = NULL;
	if (ev_told && asprintf(&json, "{\"n\":%ju,\"t\":%jd,"
	    "\"kind\":\"%s\"%s%s%s,\"data\":%s}", (uintmax_t)e->n,
	    (intmax_t)e->t, kind, jname != NULL ? ",\"jail\":\"" : "",
	    jname != NULL ? jname : "", jname != NULL ? "\"" : "", data) !=
	    -1)
		yang_event(json);
	pthread_mutex_unlock(&ev_lock);
	free(json);
	yang_changed(YANG_EVENTS);
	yang_event_changed(kind, jail != NULL);
}

/*
 * The events kept since from, the oldest first, each as the subscribers
 * are told it (JSON) with its time, to fn; then done, both under the
 * lock that orders the events, so that what comes after is told live.
 * *since: when the events began to be kept; *oldest: the oldest still
 * kept; *aged: whether older ones were let go.
 */
void
events_replay(time_t from, void (*fn)(const char *, time_t, void *),
    void (*done)(void *), void *arg, time_t *since, time_t *oldest,
    bool *aged)
{
	struct event	*e;
	char		*json;
	size_t		 i;

	pthread_mutex_lock(&ev_lock);
	*since = ev_since != 0 ? ev_since : time(NULL);
	*oldest = ring_n > 0 ? ring[ring_first].t : 0;
	*aged = ev_last > ring_n;
	for (i = 0; fn != NULL && i < ring_n; i++) {
		e = &ring[(ring_first + i) % EVENTS_KEPT];
		if (e->t < from)
			continue;
		if (asprintf(&json, "{\"n\":%ju,\"t\":%jd,\"kind\":\"%s\"%s%s%s,"
		    "\"data\":%s}", (uintmax_t)e->n, (intmax_t)e->t, e->kind,
		    e->jail != NULL ? ",\"jail\":\"" : "", e->jail != NULL ?
		    e->jail : "", e->jail != NULL ? "\"" : "", e->data) == -1)
			continue;
		fn(json, e->t, arg);
		free(json);
	}
	if (done != NULL)
		done(arg);
	pthread_mutex_unlock(&ev_lock);
}

/*
 * {"last":n,"first":n,"events":[{"n","t","kind","jail","data":{}}]},
 * after one; jail only for a jail's.
 */
int
do_events(struct work *w, uint64_t after, struct json_rsp *rsp)
{
	const struct event	*e;
	FILE			*fp;
	char			*json;
	size_t			 len, i, n;
	int			 step;

	rsp->has_ok = true;
	rsp->ok = false;
	step = step_begin(w, STEP_DAEMON, "events",
	    "those after number %ju", (uintmax_t)after);
	json = NULL;
	if ((fp = open_memstream(&json, &len)) == NULL) {
		step_end(w, step, false, "open_memstream");
		rsp->error = "out of memory";
		return (0);
	}
	pthread_mutex_lock(&ev_lock);
	fprintf(fp, "{\"last\":%ju,\"first\":%ju,\"kept\":%d,\"events\":[",
	    (uintmax_t)ev_last, (uintmax_t)(ring_n > 0 ? ring[ring_first].n :
	    0), EVENTS_KEPT);
	for (i = n = 0; i < ring_n; i++) {
		e = &ring[(ring_first + i) % EVENTS_KEPT];
		if (e->n <= after)
			continue;
		fprintf(fp, "%s{\"n\":%ju,\"t\":%jd,\"kind\":\"%s\"%s%s%s,"
		    "\"data\":%s}", n++ > 0 ? "," : "", (uintmax_t)e->n,
		    (intmax_t)e->t, e->kind, e->jail != NULL ? ",\"jail\":\"" :
		    "", e->jail != NULL ? e->jail : "", e->jail != NULL ? "\"" :
		    "", e->data);
	}
	pthread_mutex_unlock(&ev_lock);
	fprintf(fp, "]}");
	if (fclose(fp) != 0 || json == NULL) {
		free(json);
		step_end(w, step, false, "out of memory");
		rsp->error = "out of memory";
		return (0);
	}
	step_end(w, step, true, "%zu events", n);
	rsp->json = wadopt(w, json);
	rsp->ok = true;
	return (0);
}
