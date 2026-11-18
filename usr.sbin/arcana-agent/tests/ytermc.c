/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * ytermc [-j jail] [-r rows] [-c cols] [-f from] [-t seconds]
 *     [-u user] [-a account] uri:
 * arcana-stream's terminal opened on uri (a unix socket, as a local
 * user, for the user -u says), or with -a its terminal-as, a mapped
 * login of that account, driven by the script on standard input, a
 * command a line:
 *
 *	send TEXT	what is typed, \r \n \t \\ and \xHH escaped
 *	expect TEXT	wait until the terminal wrote TEXT, after what the
 *			last expect matched
 *	resize R C	the window's new size
 *	sleep MS
 *	end		wait until the host ends the stream
 *	close		end it from here
 *
 * What the terminal wrote goes to standard output as it comes; the
 * stream's opening ("opened <json>"), the login the host told ("login
 * <name>") and its end ("ended: <code> <why>") to standard error, or
 * what refused it ("refused: <why>").  Exit 1 when an expect or an end
 * waited longer than -t (20 seconds), or the stream was refused.  For
 * agent_test.sh's terminal cases.
 */

#include <sys/param.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <cblink.h>

#include "ymodel.h"
#include "ystream.h"

static cbl_conn	*conn;
static bool	 opened, ended, broken;
static char	*out;
static size_t	 outlen, mark;

static void
on_open(cbl_stream *s, cbl_msg *accept, int error, void *arg)
{
	struct arcana_stream_opened	 o;
	cbl_yarena			*a;

	(void)s;
	(void)arg;
	if (error != 0) {
		fprintf(stderr, "refused: %s\n", accept != NULL &&
		    cbl_msg_err_str(accept) != NULL ? cbl_msg_err_str(accept) :
		    strerror(error));
		ended = true;
		return;
	}
	opened = true;
	if ((a = cbl_yarena_new()) != NULL && ys_opened(accept, &o, a) == 0)
		fprintf(stderr, "opened %s\n", o.json != NULL ? o.json : "");
	cbl_yarena_free(a);
}

static void
on_data(cbl_stream *s, cbl_msg *data, void *arg)
{
	struct arcana_stream_chunk	 c;
	cbl_yarena			*a;

	(void)arg;
	if ((a = cbl_yarena_new()) == NULL || ys_chunk(data, &c, a) != 0) {
		cbl_yarena_free(a);
		(void)cbl_stream_reset(s, EBADMSG);
		return;
	}
	if (c.login != NULL)
		fprintf(stderr, "login %s\n", c.login);
	if (c.data.len > 0) {
		if ((out = realloc(out, outlen + c.data.len + 1)) == NULL)
			err(1, "realloc");
		memcpy(out + outlen, c.data.p, c.data.len);
		outlen += c.data.len;
		out[outlen] = '\0';
		fwrite(c.data.p, 1, c.data.len, stdout);
		fflush(stdout);
	}
	cbl_yarena_free(a);
}

static void
on_close(cbl_stream *s, int code, const char *text, void *arg)
{

	(void)s;
	(void)arg;
	if (!ended)
		fprintf(stderr, "ended: %d %s\n", code, text != NULL ? text : "");
	ended = true;
}

static const struct cbl_stream_cbs cbs = {
	.on_open = on_open,
	.on_data = on_data,
	.on_close = on_close,
};

/* The connection run for ms at most. */
static void
pump(int ms)
{
	struct pollfd	pfd;
	int		ev, wait;

	if (broken)
		return;
	ev = 0;
	wait = -1;
	(void)cbl_conn_interest(conn, &ev, &wait);
	if (wait < 0 || wait > ms)
		wait = ms;
	pfd.fd = cbl_conn_fd(conn);
	pfd.events = ((ev & CBL_EV_READ) != 0 ? POLLIN : 0) |
	    ((ev & CBL_EV_WRITE) != 0 ? POLLOUT : 0);
	pfd.revents = 0;
	if (poll(&pfd, 1, wait) == -1)
		return;
	ev = ((pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0 ?
	    CBL_EV_READ : 0) | ((pfd.revents & POLLOUT) != 0 ? CBL_EV_WRITE :
	    0);
	if (cbl_conn_process(conn, ev) != 0) {
		broken = true;
		if (!ended)
			fprintf(stderr, "ended: the connection ended\n");
		ended = true;
	}
}

/* TEXT with its escapes undone, into buf; its length. */
static size_t
unescape(const char *s, char *buf, size_t len)
{
	size_t	n;
	char	hex[3];

	for (n = 0; *s != '\0' && n < len; s++) {
		if (*s != '\\' || s[1] == '\0') {
			buf[n++] = *s;
			continue;
		}
		switch (*++s) {
		case 'r':
			buf[n++] = '\r';
			break;
		case 'n':
			buf[n++] = '\n';
			break;
		case 't':
			buf[n++] = '\t';
			break;
		case 'x':
			if (isxdigit((unsigned char)s[1]) &&
			    isxdigit((unsigned char)s[2])) {
				hex[0] = s[1];
				hex[1] = s[2];
				hex[2] = '\0';
				buf[n++] = (char)strtol(hex, NULL, 16);
				s += 2;
			}
			break;
		default:
			buf[n++] = *s;
			break;
		}
	}
	return (n);
}

static time_t
now(void)
{
	struct timespec	ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec);
}

int
main(int argc, char **argv)
{
	struct arcana_stream_open	 rq;
	struct arcana_stream_chunk	 c;
	cbl_ctx				*ctx;
	cbl_stream			*s;
	const char			*names[5];
	char				 jail[300], rows[16], cols[16], from[80];
	char				 account[80];
	const char			*user;
	uint16_t			 cmd;
	char				*line, text[4096], *p;
	size_t				 cap, n;
	ssize_t				 len;
	time_t				 until;
	int				 ch, error, limit, r, k;

	limit = 20;
	user = NULL;
	cmd = YS_TERMINAL;
	memset(&rq, 0, sizeof(rq));
	n = 0;
	while ((ch = getopt(argc, argv, "a:c:f:j:r:t:u:")) != -1) {
		switch (ch) {
		case 'a':
			snprintf(account, sizeof(account), "account=%s", optarg);
			names[n++] = account;
			cmd = YS_TERMINAL_AS;
			break;
		case 'u':
			user = optarg;
			break;
		case 'c':
			snprintf(cols, sizeof(cols), "cols=%s", optarg);
			names[n++] = cols;
			break;
		case 'f':
			snprintf(from, sizeof(from), "from=%s", optarg);
			names[n++] = from;
			break;
		case 'j':
			snprintf(jail, sizeof(jail), "jail=%s", optarg);
			names[n++] = jail;
			break;
		case 'r':
			snprintf(rows, sizeof(rows), "rows=%s", optarg);
			names[n++] = rows;
			break;
		case 't':
			limit = atoi(optarg);
			break;
		default:
			errx(2, "usage: ytermc [-j jail] [-r rows] [-c cols] "
			    "[-f from] [-t seconds] [-u user] [-a account] uri");
		}
		if (n == nitems(names))
			errx(2, "each option once");
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		errx(2, "usage: ytermc [-j jail] [-r rows] [-c cols] [-f from] "
		    "[-t seconds] [-u user] [-a account] uri");
	if ((error = cbl_ctx_new(&ctx)) != 0 || (error = cbl_conn_new(ctx,
	    argv[0], 0, &conn)) != 0)
		errc(1, error, "%s", argv[0]);
	if (user != NULL)
		(void)cbl_conn_set_user(conn, user);
	if (cbl_conn_connect(conn) != 0)
		errx(1, "%s: %s", argv[0], cbl_conn_errstr(conn));
	rq.name.v = names;
	rq.name.n = n;
	if ((error = ys_open(conn, cmd, &rq, YS_WINDOW, 0, &cbs, NULL,
	    &s)) != 0) {
		fprintf(stderr, "refused: %s\n", strerror(error));
		return (1);
	}
	until = now() + limit;
	while (!opened && !ended && now() < until)
		pump(100);
	if (!opened)
		return (1);
	line = NULL;
	cap = 0;
	while ((len = getline(&line, &cap, stdin)) > 0) {
		if (line[len - 1] == '\n')
			line[--len] = '\0';
		if ((p = strchr(line, ' ')) != NULL)
			*p++ = '\0';
		else
			p = line + len;
		until = now() + limit;
		if (strcmp(line, "send") == 0) {
			n = unescape(p, text, sizeof(text));
			while ((error = ys_send(s, text, n)) == EAGAIN && !ended)
				pump(100);
			if (error != 0) {
				fprintf(stderr, "send: %s\n", strerror(error));
				return (1);
			}
		} else if (strcmp(line, "expect") == 0) {
			n = unescape(p, text, sizeof(text) - 1);
			text[n] = '\0';
			while ((out == NULL || strstr(out + mark, text) == NULL) &&
			    !ended && now() < until)
				pump(100);
			if (out == NULL || strstr(out + mark, text) == NULL) {
				fprintf(stderr, "expect timed out: %s\n", p);
				return (1);
			}
			mark = (size_t)(strstr(out + mark, text) - out) + n;
		} else if (strcmp(line, "resize") == 0) {
			if (sscanf(p, "%d %d", &r, &k) != 2)
				errx(2, "resize R C");
			memset(&c, 0, sizeof(c));
			c.has_rows = c.has_cols = true;
			c.rows = (uint16_t)r;
			c.cols = (uint16_t)k;
			while ((error = ys_send_chunk(s, &c)) == EAGAIN &&
			    !ended)
				pump(100);
		} else if (strcmp(line, "sleep") == 0) {
			until = now() + atoi(p) / 1000 + 1;
			for (k = atoi(p) / 50; k > 0 && !ended; k--)
				pump(50);
		} else if (strcmp(line, "end") == 0) {
			while (!ended && now() < until)
				pump(100);
			if (!ended) {
				fprintf(stderr, "end timed out\n");
				return (1);
			}
		} else if (strcmp(line, "close") == 0) {
			(void)cbl_stream_close(s, 0, NULL);
			for (k = 0; k < 10 && !broken; k++)
				pump(50);
			break;
		} else if (line[0] != '\0' && line[0] != '#')
			errx(2, "%s: no such command", line);
	}
	free(line);
	cbl_conn_free(conn);
	cbl_ctx_free(ctx);
	return (0);
}
