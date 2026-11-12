/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Notifications to the devices that asked for them, by Web Push: a
 * task that ends in one browser is told to the others, a phone say,
 * whether or not the console is open there.
 *
 * A browser subscribes with its push service and gives the console the
 * address to post to and its keys.  The console keeps those in
 * push.json, and its own key, which the push services know it by
 * (VAPID), in vapid.pem, both in the data directory.  A message is
 * encrypted for each subscription (libwebpush(3)) and posted to its
 * address over HTTPS, from a task thread.  A push service that says a
 * subscription is gone has it dropped.  Each subscription is its
 * user's: a user reads, changes and is sent to their own alone, as
 * arcana-console's push (cyang.c).
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <ipfeeds.h>
#include <webpush.h>

#include "console.h"
#include "restconf.h"

#define	PUSH_FILE	"push.json"
#define	VAPID_FILE	"vapid.pem"
#define	PUSH_MAX	16		/* devices */
#define	PUSH_TIMEOUT	15		/* s, for a push service to answer */

struct target {
	char	*endpoint;
	uint8_t	*p256dh;
	uint8_t	*auth;
	int	 status;		/* what the push service said; 0 none */
	char	 said[201];		/* and in words, when it refused */
};

struct send {
	struct task	 task;		/* first: the server frees the send */
	struct target		 targets[PUSH_MAX];
	size_t			 ntargets;
	char			*payload;
	bool			 owner;		/* sent by an owner: told what was said */
};

static EVP_PKEY		*vapid;
static char		*vapid_pub;	/* base64url, for the browsers */
static ucl_object_t	*subs;		/* {"subscriptions": [...]} */

static const char	*keys_bad(const char *, const char *);

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, false);
}

static ucl_object_t *
sub_list(void)
{

	return ((ucl_object_t *)(uintptr_t)ucl_object_lookup(subs,
	    "subscriptions"));
}

/* The key the push services know this console by; made once. */
int
push_init(void)
{
	unsigned char	*pub;
	char		 path[1024];
	FILE		*fp;
	size_t		 publen;
	int		 fd;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, VAPID_FILE);
	if ((fp = fopen(path, "r")) != NULL) {
		vapid = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
		fclose(fp);
	}
	if (vapid == NULL) {
		if ((vapid = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256")) ==
		    NULL)
			return (-1);
		(void)unlink(path);
		if ((fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
		    0600)) == -1 || (fp = fdopen(fd, "w")) == NULL) {
			log_msg(LOG_ERR, "%s: %s", path, strerror(errno));
			if (fd != -1)
				close(fd);
			return (-1);
		}
		PEM_write_PrivateKey(fp, vapid, NULL, NULL, 0, NULL, NULL);
		fclose(fp);
	}
	if ((publen = EVP_PKEY_get1_encoded_public_key(vapid, &pub)) != 65)
		return (-1);
	vapid_pub = webpush_b64url(pub, publen);
	OPENSSL_free(pub);
	push_reload();
	return (vapid_pub != NULL ? 0 : -1);
}

/*
 * push.json: at start, and when another node of the cluster wrote it.
 * A subscription whose keys are not what a browser gives (the file
 * changed by hand, or broken) is dropped, and said: the encryption
 * reads 65 and 16 bytes of them.
 */
void
push_reload(void)
{
	const ucl_object_t	*e;
	ucl_object_t		*kept;
	ucl_object_iter_t	 it;
	const char		*bad;

	if (subs != NULL)
		ucl_object_unref(subs);
	if ((subs = store_load(PUSH_FILE)) == NULL || sub_list() == NULL) {
		if (subs != NULL)
			ucl_object_unref(subs);
		subs = ucl_object_typed_new(UCL_OBJECT);
		put(subs, "subscriptions", ucl_object_typed_new(UCL_ARRAY));
		return;
	}
	kept = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(sub_list(), &it, true)) != NULL) {
		if ((bad = keys_bad(ucl_str(e, "p256dh"), ucl_str(e,
		    "auth"))) != NULL) {
			log_msg(LOG_WARNING, "%s: a subscription of %s dropped: "
			    "%s", PUSH_FILE, ucl_str(e, "user") != NULL ?
			    ucl_str(e, "user") : "no one", bad);
			continue;
		}
		ucl_array_append(kept, ucl_object_ref(e));
	}
	ucl_object_replace_key(subs, kept, "subscriptions", 0, false);
}

/* The host of an "https://host[:443]/path" address, and its path. */
static bool
endpoint_parse(const char *url, char *host, size_t hostlen, const char **path)
{
	const char	*p, *e;
	size_t		 n;

	if (strncmp(url, "https://", 8) != 0)
		return (false);
	/* It goes into a request line: no space, nothing that ends one. */
	for (p = url; *p != '\0'; p++)
		if ((unsigned char)*p <= 0x20 || *p == 0x7f)
			return (false);
	p = url + 8;
	e = p + strcspn(p, "/:");
	n = (size_t)(e - p);
	if (n == 0 || n >= hostlen)
		return (false);
	memcpy(host, p, n);
	host[n] = '\0';
	for (p = host; *p != '\0'; p++)
		if (!isalnum((unsigned char)*p) && *p != '.' && *p != '-')
			return (false);
	if (*e == ':') {
		if (strncmp(e, ":443/", 5) != 0)
			return (false);
		e += 4;
	}
	if (*e != '/')
		return (false);
	*path = e;
	return (true);
}

/* Is sa an address of this host's own? */
static bool
addr_ours(const struct sockaddr *sa)
{
	struct ifaddrs	*ifa, *i;
	bool		 ours;

	if (getifaddrs(&ifa) == -1)
		return (true);
	ours = false;
	for (i = ifa; i != NULL && !ours; i = i->ifa_next) {
		if (i->ifa_addr == NULL || i->ifa_addr->sa_family !=
		    sa->sa_family)
			continue;
		if (sa->sa_family == AF_INET)
			ours = memcmp(&((const struct sockaddr_in *)
			    (const void *)sa)->sin_addr,
			    &((struct sockaddr_in *)(void *)
			    i->ifa_addr)->sin_addr,
			    sizeof(struct in_addr)) == 0;
		else if (sa->sa_family == AF_INET6)
			ours = memcmp(&((const struct sockaddr_in6 *)
			    (const void *)sa)->sin6_addr,
			    &((struct sockaddr_in6 *)(void *)
			    i->ifa_addr)->sin6_addr,
			    sizeof(struct in6_addr)) == 0;
	}
	freeifaddrs(ifa);
	return (ours);
}

/*
 * A connection to host's port 443, made within the time allowed: to an
 * address it resolves to that is on the internet and not this host's,
 * the one checked the one connected to.
 */
static int
connect_to(const char *host)
{
	struct addrinfo	 hints, *res, *ai;
	struct timeval	 tv = { PUSH_TIMEOUT, 0 };
	struct pollfd	 pfd;
	socklen_t	 len;
	int		 fd, flags, error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, "443", &hints, &res) != 0)
		return (-1);
	fd = -1;
	for (ai = res; ai != NULL; ai = ai->ai_next) {
		/* A push service is on the internet: nothing only we reach,
		 * nor the console itself. */
		if (!ipf_sockaddr_public(ai->ai_addr) || addr_ours(ai->ai_addr))
			continue;
		if ((fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC,
		    ai->ai_protocol)) == -1)
			continue;
		flags = fcntl(fd, F_GETFL);
		(void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
		error = 0;
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == -1) {
			pfd.fd = fd;
			pfd.events = POLLOUT;
			len = sizeof(error);
			if (errno != EINPROGRESS || poll(&pfd, 1, PUSH_TIMEOUT *
			    1000) != 1 || getsockopt(fd, SOL_SOCKET, SO_ERROR,
			    &error, &len) == -1)
				error = -1;
		}
		if (error == 0) {
			/* From here on it waits, but never for long. */
			(void)fcntl(fd, F_SETFL, flags);
			(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv,
			    sizeof(tv));
			(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv,
			    sizeof(tv));
			break;
		}
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return (fd);
}

/*
 * POST body to an HTTPS address with the headers given; the status the
 * server answers with, or -1.  The certificate is checked against the
 * system's and the name asked for.  In a task thread: it waits, for
 * the connection, the handshake and the answer, each for a time.
 */
static int
https_post(const char *url, const char *headers, const uint8_t *body,
    size_t len, char *said, size_t saidlen)
{
	SSL_CTX		*ctx;
	SSL		*ssl;
	const char	*path;
	char		 host[256], *req, line[1024], *b;
	int		 n, status, fd, reqlen;

	status = -1;
	said[0] = '\0';
	ssl = NULL;
	fd = -1;
	if (!endpoint_parse(url, host, sizeof(host), &path) ||
	    (ctx = SSL_CTX_new(TLS_client_method())) == NULL)
		return (-1);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	if (SSL_CTX_set_default_verify_paths(ctx) != 1 ||
	    (fd = connect_to(host)) == -1 || (ssl = SSL_new(ctx)) == NULL ||
	    SSL_set_tlsext_host_name(ssl, host) != 1 ||
	    SSL_set1_host(ssl, host) != 1 || SSL_set_fd(ssl, fd) != 1 ||
	    SSL_connect(ssl) != 1)
		goto out;
	if ((reqlen = asprintf(&req, "POST %s HTTP/1.1\r\nHost: %s\r\n%s"
	    "Content-Length: %zu\r\nConnection: close\r\n\r\n", path, host,
	    headers, len)) == -1)
		goto out;
	if (SSL_write(ssl, req, reqlen) == reqlen && (len == 0 ||
	    SSL_write(ssl, body, (int)len) == (int)len) &&
	    (n = SSL_read(ssl, line, sizeof(line) - 1)) > 12) {
		line[n] = '\0';
		if (strncmp(line, "HTTP/1.", 7) == 0)
			status = atoi(line + 9);
		/* What it says besides, when it refuses: its reason. */
		if (status >= 300 && (b = strstr(line, "\r\n\r\n")) != NULL)
			snprintf(said, saidlen, "%.200s", b + 4);
	}
	free(req);
out:
	ERR_clear_error();
	if (ssl != NULL) {
		(void)SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	if (fd != -1)
		close(fd);
	SSL_CTX_free(ctx);
	return (status);
}

/* In a task thread: the message, to each device in turn. */
static int
send_run(struct task *t)
{
	struct send	*s;
	struct target	*tg;
	const char	*path;
	char		 host[256], aud[280], contact[300], *auth, *headers;
	uint8_t		*body;
	size_t		 i, len;

	s = (struct send *)t;
	for (i = 0; i < s->ntargets; i++) {
		tg = &s->targets[i];
		if (!endpoint_parse(tg->endpoint, host, sizeof(host), &path))
			continue;
		snprintf(aud, sizeof(aud), "https://%s", host);
		/*
		 * Whom the push service may write to about this sender: an
		 * https address or a mailbox, nothing else is taken.
		 */
		if (strncmp(cfg.origin, "https://", 8) == 0)
			snprintf(contact, sizeof(contact), "%s", cfg.origin);
		else
			snprintf(contact, sizeof(contact), "mailto:arcana@%s",
			    strcmp(cfg.rp_id, "localhost") == 0 ?
			    "localhost.localdomain" : cfg.rp_id);
		auth = webpush_vapid(vapid, aud, contact, time(NULL));
		if (auth == NULL || webpush_encrypt(tg->p256dh, tg->auth, NULL,
		    NULL, (const uint8_t *)s->payload, strlen(s->payload),
		    &body, &len) != 0) {
			thread_log(LOG_WARNING, "push to %s: %s", host, auth ==
			    NULL ? "no VAPID token made" :
			    "the message not encrypted");
			free(auth);
			continue;
		}
		if (asprintf(&headers, "TTL: 86400\r\nUrgency: normal\r\n"
		    "Content-Encoding: aes128gcm\r\nContent-Type: "
		    "application/octet-stream\r\nAuthorization: %s\r\n",
		    auth) != -1) {
			tg->status = https_post(tg->endpoint, headers, body,
			    len, tg->said, sizeof(tg->said));
			free(headers);
		}
		free(auth);
		free(body);
	}
	return (WEB_OK);
}

static void
send_free(struct send *s)
{
	size_t	i;

	for (i = 0; i < s->ntargets; i++) {
		free(s->targets[i].endpoint);
		free(s->targets[i].p256dh);
		free(s->targets[i].auth);
	}
	s->ntargets = 0;
	free(s->payload);
	s->payload = NULL;
}

/*
 * The request is going away, answered or given up by its browser: what
 * the send held is released, once its task has ended.
 */
void
api_push_free(struct http_request *req)
{
	struct send	*s;

	if ((s = req->hdlr_extra) != NULL && task_finished(&s->task))
		send_free(s);
}

/* Whose a subscription made by the request is: its user, "" for none. */
static const char *
owner_of(struct http_request *req)
{
	const char	*u;

	return ((u = session_user(req)) != NULL ? u : "");
}

/* Whether subscription e is user's. */
static bool
mine(const ucl_object_t *e, const char *user)
{
	const char	*u;

	return (strcmp((u = ucl_str(e, "user")) != NULL ? u : "", user) == 0);
}

/*
 * Remove the subscription with this address, user's alone when user is
 * not NULL; true if there was one.
 */
static bool
sub_remove(const char *endpoint, const char *user)
{
	const ucl_object_t	*e;
	const char		*s;
	ucl_object_t		*list, *keep;
	ucl_object_iter_t	 it;
	bool			 found;

	keep = ucl_object_typed_new(UCL_ARRAY);
	found = false;
	it = NULL;
	while ((e = ucl_object_iterate(sub_list(), &it, true)) != NULL) {
		s = ucl_str(e, "endpoint");
		if (s != NULL && strcmp(s, endpoint) == 0 && (user == NULL ||
		    mine(e, user)))
			found = true;
		else
			ucl_array_append(keep, ucl_object_ref(
			    (ucl_object_t *)(uintptr_t)e));
	}
	list = ucl_object_typed_new(UCL_OBJECT);
	put(list, "subscriptions", keep);
	ucl_object_unref(subs);
	subs = list;
	return (found);
}

/*
 * A subscription's keys checked: p256dh a P-256 public key, auth 16
 * bytes.  NULL, or what is wrong.
 */
static const char *
keys_bad(const char *p256dh, const char *auth)
{
	uint8_t	*raw;
	size_t	 len;

	if (p256dh == NULL || (raw = webpush_unb64url(p256dh, &len)) == NULL ||
	    len != WEBPUSH_KEYLEN || raw[0] != 0x04) {
		if (p256dh != NULL)
			free(raw);
		return ("p256dh is not a P-256 public key");
	}
	free(raw);
	if (auth == NULL || (raw = webpush_unb64url(auth, &len)) == NULL ||
	    len != WEBPUSH_AUTHLEN) {
		free(raw);
		return ("auth is not 16 bytes");
	}
	free(raw);
	return (NULL);
}

/*
 * The subscription of user at endpoint made, or made again (the same
 * browser replaces what it had); not kept until push_save().  0, or the
 * HTTP status and why.
 */
static int
sub_add(const char *user, const char *endpoint, const char *p256dh,
    const char *auth, const char *name, int64_t added, char *why,
    size_t len)
{
	struct sockaddr_in	 sin;
	ucl_object_t		*e;
	const char		*bad, *path;
	char			 host[256];

	if (endpoint == NULL || strlen(endpoint) > 1024 ||
	    !endpoint_parse(endpoint, host, sizeof(host), &path)) {
		snprintf(why, len, "the address of a push service is "
		    "https://host/path");
		return (400);
	}
	/* An address said as one: on the internet, or not taken (a name is
	 * resolved and held to the same when it is posted to). */
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	if (inet_pton(AF_INET, host, &sin.sin_addr) == 1 &&
	    (!ipf_sockaddr_public((struct sockaddr *)&sin) ||
	    addr_ours((struct sockaddr *)&sin))) {
		snprintf(why, len, "a push service is on the internet: %s is "
		    "not", host);
		return (400);
	}
	if ((bad = keys_bad(p256dh, auth)) != NULL) {
		snprintf(why, len, "%s", bad);
		return (400);
	}
	(void)sub_remove(endpoint, NULL);
	if (ucl_array_size(sub_list()) >= PUSH_MAX) {
		snprintf(why, len, "%d devices are subscribed already; remove "
		    "one in Settings", PUSH_MAX);
		return (409);
	}
	if (name == NULL)
		name = "a browser";
	e = ucl_object_typed_new(UCL_OBJECT);
	put(e, "endpoint", ucl_object_fromstring(endpoint));
	put(e, "p256dh", ucl_object_fromstring(p256dh));
	put(e, "auth", ucl_object_fromstring(auth));
	put(e, "name", ucl_object_fromlstring(name, strnlen(name, 80)));
	put(e, "added", ucl_object_fromint(added));
	put(e, "user", ucl_object_fromstring(user));
	ucl_array_append(sub_list(), e);
	return (0);
}

/* push.json written: 0, or 500 and why. */
static int
push_save(char *why, size_t len)
{

	if (store_save(PUSH_FILE, subs) == -1) {
		snprintf(why, len, "cannot write %s", PUSH_FILE);
		return (500);
	}
	cyang_changed("push");
	return (0);
}

/* At most max bytes of s, not ending inside a UTF-8 sequence. */
static size_t
utf8_cut(const char *s, size_t max)
{
	size_t	n;

	if ((n = strnlen(s, max)) < max || s[n] == '\0')
		return (n);
	while (n > 0 && ((unsigned char)s[n] & 0xc0) == 0x80)
		n--;
	return (n);
}

/*
 * The message, {"title", "body"} as JSON: a title of 120 bytes at most
 * and a body of 600, each cut between characters, the body shorter
 * again until the JSON, escaped, fits what one push carries.
 */
static char *
payload(const char *title, const char *text)
{
	ucl_object_t	*msg;
	char		*p;
	size_t		 tn, bn;

	tn = utf8_cut(title, 120);
	bn = utf8_cut(text, 600);
	for (;;) {
		msg = ucl_object_typed_new(UCL_OBJECT);
		put(msg, "title", ucl_object_fromlstring(title, tn));
		put(msg, "body", ucl_object_fromlstring(text, bn));
		p = (char *)ucl_object_emit(msg, UCL_EMIT_JSON_COMPACT);
		ucl_object_unref(msg);
		if (p == NULL || strlen(p) <= WEBPUSH_MAXLEN)
			return (p);
		free(p);
		if (bn > 0)
			bn = utf8_cut(text, bn / 2);
		else if (tn > 0)
			tn = utf8_cut(title, tn / 2);
		else
			return (NULL);
	}
}

/*
 * arcana-console's push/send action, {"title", "body", "except"}: tell
 * every device of the request's user but the one at the address
 * "except", which is the one that asks.
 */
int
api_push_send(struct http_request *req)
{
	ucl_object_t		*body, *o, *res, *one;
	const ucl_object_t	*e, *in;
	ucl_object_iter_t	 it;
	struct send		*s;
	struct target		*tg;
	const char		*title, *text, *except, *ep, *k, *a, *path;
	const char		*user;
	char			 host[256];
	size_t			 i, len;
	int			 sent, gone;
	bool			 changed;

	if (req->hdlr_extra != NULL) {
		s = req->hdlr_extra;
		if (task_state(&s->task) != TASK_STATE_FINISHED) {
			http_request_sleep(req);
			return (WEB_RETRY);
		}
		/* 404 and 410: the browser has left; forget it. */
		sent = gone = 0;
		changed = false;
		for (i = 0; i < s->ntargets; i++) {
			if (s->targets[i].status >= 200 &&
			    s->targets[i].status < 300)
				sent++;
			else if (s->targets[i].status == 404 ||
			    s->targets[i].status == 410) {
				gone++;
				changed |= sub_remove(s->targets[i].endpoint,
				    NULL);
			}
		}
		if (changed) {
			char	why[64];

			(void)push_save(why, sizeof(why));
		}
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "sent", ucl_object_fromint(sent));
		put(o, "gone", ucl_object_fromint(gone));
		put(o, "failed", ucl_object_fromint((int64_t)s->ntargets -
		    sent - gone));
		/* What each push service said: 201 is taken, -1 no answer. */
		res = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < s->ntargets; i++) {
			one = ucl_object_typed_new(UCL_OBJECT);
			put(one, "index", ucl_object_fromint((int64_t)i));
			if (endpoint_parse(s->targets[i].endpoint, host,
			    sizeof(host), &path))
				put(one, "service", ucl_object_fromstring(host));
			put(one, "status", ucl_object_fromint(
			    s->targets[i].status));
			if (s->owner && s->targets[i].said[0] != '\0')
				put(one, "said", ucl_object_fromstring(
				    s->targets[i].said));
			ucl_array_append(res, one);
		}
		put(o, "result", res);
		send_free(s);
		return (cyang_output(req, o));
	}
	if (!guard(req, true))
		return (WEB_OK);
	body = read_json(req);
	if (req->http_body != NULL && req->http_body->length > 0 && (body ==
	    NULL || (body->len > 0 && ucl_object_lookup(body,
	    "arcana-console:input") == NULL))) {
		ucl_object_unref(body);
		return (restconf_error_tag(req, 400, "malformed-message",
		    "an action's body is {\"arcana-console:input\": {...}}"));
	}
	in = ucl_object_lookup(body, "arcana-console:input");
	if ((title = ucl_str(in, "title")) == NULL)
		title = "Arcana";
	if ((text = ucl_str(in, "body")) == NULL)
		text = "";
	if ((except = ucl_str(in, "except")) == NULL)
		except = "";
	user = owner_of(req);
	s = xcalloc(1, sizeof(*s));
	s->owner = session_user(req) != NULL && user_console(
	    session_user(req)) == CROLE_OWNER;
	s->payload = payload(title, text);
	it = NULL;
	while ((e = ucl_object_iterate(sub_list(), &it, true)) != NULL &&
	    s->ntargets < PUSH_MAX) {
		ep = ucl_str(e, "endpoint");
		k = ucl_str(e, "p256dh");
		a = ucl_str(e, "auth");
		if (ep == NULL || k == NULL || a == NULL || strcmp(ep,
		    except) == 0 || !mine(e, user))
			continue;
		/* Of the lengths webpush_encrypt() reads, or none. */
		if (keys_bad(k, a) != NULL)
			continue;
		tg = &s->targets[s->ntargets];
		tg->endpoint = strdup(ep);
		tg->p256dh = webpush_unb64url(k, &len);
		if (tg->p256dh != NULL && len != WEBPUSH_KEYLEN) {
			free(tg->p256dh);
			tg->p256dh = NULL;
		}
		tg->auth = webpush_unb64url(a, &len);
		if (tg->auth != NULL && len != WEBPUSH_AUTHLEN) {
			free(tg->auth);
			tg->auth = NULL;
		}
		if (tg->endpoint == NULL || tg->p256dh == NULL ||
		    tg->auth == NULL) {
			free(tg->endpoint);
			free(tg->p256dh);
			free(tg->auth);
			continue;
		}
		s->ntargets++;
	}
	ucl_object_unref(body);
	if (s->ntargets == 0 || s->payload == NULL) {
		send_free(s);
		free(s);
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "sent", ucl_object_fromint(0));
		return (cyang_output(req, o));
	}
	req->hdlr_extra = s;
	task_create(&s->task, send_run);
	task_bind_request(&s->task, req);
	task_run(&s->task);
	return (WEB_RETRY);
}

/* ---- arcana-console's push (cyang.c) --------------------------------- */

/* arcana-console:push's value: the key, the request's user's devices,
 * never their keys. */
ucl_object_t *
push_yang(struct http_request *req)
{
	const ucl_object_t	*e, *v;
	ucl_object_t		*o, *a, *d;
	ucl_object_iter_t	 it;
	const char		*path, *user;
	char			 host[256];

	user = owner_of(req);
	o = ucl_object_typed_new(UCL_OBJECT);
	if (vapid_pub != NULL)
		put(o, "public-key", ucl_object_fromstring(vapid_pub));
	a = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(sub_list(), &it, true)) != NULL) {
		if (!mine(e, user) || ucl_str(e, "endpoint") == NULL)
			continue;
		d = ucl_object_typed_new(UCL_OBJECT);
		put(d, "endpoint", ucl_object_fromstring(ucl_str(e,
		    "endpoint")));
		if (ucl_str(e, "name") != NULL)
			put(d, "name", ucl_object_fromstring(ucl_str(e,
			    "name")));
		if (endpoint_parse(ucl_str(e, "endpoint"), host, sizeof(host),
		    &path))
			put(d, "service", ucl_object_fromstring(host));
		if ((v = ucl_object_lookup(e, "added")) != NULL)
			put(d, "added", yang_time((double)ucl_object_toint(v)));
		ucl_array_append(a, d);
	}
	put(o, "subscription", a);
	return (o);
}

/* user's subscription at endpoint, as kept; NULL: none. */
static const ucl_object_t *
sub_of(const char *endpoint, const char *user)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;

	while ((e = ucl_object_iterate(sub_list(), &it, true)) != NULL)
		if (ucl_str(e, "endpoint") != NULL && strcmp(ucl_str(e,
		    "endpoint"), endpoint) == 0 && mine(e, user))
			return (e);
	return (NULL);
}

/*
 * The request's user's subscriptions changed from was to now: one made
 * needs its keys; one changed keeps those it had unless given others;
 * one left out removed.  All checked before push.json is written.  0,
 * or the HTTP status and why.
 */
int
push_yang_set(struct http_request *req, const ucl_object_t *was,
    const ucl_object_t *now, char *why, size_t len)
{
	const ucl_object_t	*e, *o, *k;
	ucl_object_t		*keep;
	ucl_object_iter_t	 it;
	const char		*user, *ep, *p256dh, *auth;
	int64_t			 added;
	int			 rc;

	user = owner_of(req);
	/* What was, to go back to when a change is refused. */
	keep = ucl_object_copy(subs);
	rc = 0;
	it = NULL;
	while (rc == 0 && (o = ucl_object_iterate(ucl_object_lookup(was,
	    "subscription"), &it, true)) != NULL)
		if (cyang_entry(ucl_object_lookup(now, "subscription"),
		    "endpoint", ucl_str(o, "endpoint")) == NULL)
			(void)sub_remove(ucl_str(o, "endpoint"), user);
	it = NULL;
	while (rc == 0 && (e = ucl_object_iterate(ucl_object_lookup(now,
	    "subscription"), &it, true)) != NULL) {
		ep = ucl_str(e, "endpoint");
		o = cyang_entry(ucl_object_lookup(was, "subscription"),
		    "endpoint", ep);
		if (o != NULL && cyang_same(o, e))
			continue;
		p256dh = ucl_str(e, "p256dh");
		auth = ucl_str(e, "auth");
		added = time(NULL);
		/* Its keys and when it was made, as they were, unless
		 * given anew. */
		if (o != NULL && (k = sub_of(ep, user)) != NULL) {
			if (p256dh == NULL)
				p256dh = ucl_str(k, "p256dh");
			if (auth == NULL)
				auth = ucl_str(k, "auth");
			added = ucl_object_toint(ucl_object_lookup(k, "added"));
		}
		if (p256dh == NULL || auth == NULL) {
			snprintf(why, len, "a subscription is made with its "
			    "p256dh and auth");
			rc = 400;
			break;
		}
		/* sub_add() replaces it: the strings copied first. */
		{
			char	*kp = strdup(p256dh), *ka = strdup(auth);

			rc = kp != NULL && ka != NULL ? sub_add(user, ep, kp, ka,
			    ucl_str(e, "name"), added, why, len) : 500;
			if (kp != NULL)
				explicit_bzero(kp, strlen(kp));
			if (ka != NULL)
				explicit_bzero(ka, strlen(ka));
			free(kp);
			free(ka);
		}
	}
	if (rc == 0)
		rc = push_save(why, len);
	if (rc != 0) {
		ucl_object_unref(subs);
		subs = keep;
	} else
		ucl_object_unref(keep);
	return (rc);
}
