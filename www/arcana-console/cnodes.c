/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Who may touch which of the console's own nodes: one table, one row a
 * node or a subtree (the longest that matches a path rules it), and one
 * function every reader, writer and action asks (req_may_path(); guard()
 * and cyang.c's, the handlers' reads of what is the whole fleet's).  A
 * row says the console role to read and to write it (users.c: member,
 * operator, owner), whether it is the whole fleet's (the SD-WAN, the
 * L3NM and the virtual networks: no tenant's) or every tenant's alike
 * and so no tenant's either (the prefix lists, the threat feeds, until
 * they are a tenant's: docs/TODO.md), and what an API token does with
 * it (nothing, read it, or change it too).  A principal is judged as
 * itself: a user by their role and tenant, an API token (a bearer's, or
 * the session it opened) by its kind and by its maker's role and tenant,
 * never more than the maker may now.  The hosts' own nodes are judged
 * per host besides (users.c, hosts.c).  "make check-cnodes" has every
 * top-level node and action of share/yang/arcana-console@*.yang here.
 */

#include <stdio.h>
#include <string.h>

#include "console.h"

#define	CD	CYANG_DATA
#define	CO	"/restconf/operations/arcana-console:"

#define	M	CROLE_MEMBER
#define	O	CROLE_OPERATOR
#define	W	CROLE_OWNER

#define	TK_NO		0	/* no API token */
#define	TK_READ		1	/* a token reads it */
#define	TK_WRITE	2	/* a write token changes it too */

#define	T_ANY		0	/* every tenant's principal, its own part */
#define	T_FLEET		1	/* the whole fleet's: no tenant's */
#define	T_ALL		2	/* every tenant's alike: no tenant's */

struct cnode {
	const char	*path;	/* a prefix, each * one key */
	bool		 exact;	/* the node alone, not below it */
	enum crole	 read, write;
	int		 tenant;	/* T_* */
	int		 token;		/* TK_* */
};

static const struct cnode	cnodes[] = {
	{ CD "settings", false, W, W, T_ANY, TK_NO },
	{ CD "settings/mail-test", false, W, W, T_ANY, TK_NO },
	{ CD "settings/telegram-test", false, W, W, T_ANY, TK_NO },
	{ CD "tokens", false, W, W, T_ANY, TK_READ },
	{ CD "tokens/create", false, W, W, T_ANY, TK_READ },
	{ CD "users", false, W, W, T_ANY, TK_READ },
	{ CD "users/user=*/invite", false, W, W, T_ANY, TK_READ },
	{ CD "roles", false, W, W, T_ANY, TK_READ },
	{ CD "groups", false, W, W, T_ANY, TK_READ },
	{ CD "enrolment", false, W, W, T_ANY, TK_NO },
	{ CD "enrolment/create-token", false, W, W, T_ANY, TK_NO },
	{ CD "workflows", false, O, O, T_ANY, TK_WRITE },
	{ CD "workflows/workflow=*/run", false, O, O, T_ANY, TK_WRITE },
	{ CD "runs", false, O, O, T_ANY, TK_WRITE },
	{ CD "runs/run=*/approve", false, O, O, T_ANY, TK_WRITE },
	{ CD "runs/run=*/stop", false, O, O, T_ANY, TK_WRITE },
	{ CD "runs/clear", false, O, O, T_ANY, TK_WRITE },
	{ CD "templates", false, O, O, T_ANY, TK_WRITE },
	{ CD "labels", false, M, M, T_ANY, TK_WRITE },
	{ CD "prefix-lists", false, M, O, T_ALL, TK_WRITE },
	{ CD "threat-feeds", false, O, O, T_ALL, TK_WRITE },
	{ CD "threat-feeds/feed=*/fetch", false, O, O, T_ALL, TK_WRITE },
	{ CD "threat-feeds/feed=*/preview", false, O, O, T_ALL, TK_WRITE },
	{ CD "threat-feeds/feed=*/take", false, O, O, T_ALL, TK_WRITE },
	{ CD "transfers", false, O, O, T_ANY, TK_WRITE },
	{ CD "transfers/transfer=*/stop", false, O, O, T_ANY, TK_WRITE },
	{ CD "transfers/start", false, O, O, T_ANY, TK_WRITE },
	{ CD "push", false, M, M, T_ANY, TK_NO },
	{ CD "push/send", false, M, M, T_ANY, TK_NO },
	/* Each host its own (users.c's role on it); added by operators. */
	{ CD "hosts", false, M, M, T_ANY, TK_WRITE },
	{ CD "hosts", true, M, O, T_ANY, TK_WRITE },
	{ CD "hosts/host=*/move", false, M, M, T_ANY, TK_WRITE },
	{ CD "hosts/host=*/keep-commit", false, M, M, T_ANY, TK_WRITE },
	{ CD "hosts/host=*/undo-commit", false, M, M, T_ANY, TK_WRITE },
	{ CD "hosts/host=*/renew-tls", false, M, M, T_ANY, TK_WRITE },
	{ CD "hosts/host=*/inspection-ca", false, M, M, T_ANY, TK_WRITE },
	{ CD "hosts/host=*/listen", false, M, M, T_ANY, TK_WRITE },
	{ CD "hosts/host=*/switch-transport", false, M, M, T_ANY, TK_WRITE },
	{ CD "hosts/host=*/nacm-sync", false, M, M, T_ANY, TK_WRITE },
	{ CD "hosts/host=*/agent-build", false, M, M, T_ANY, TK_WRITE },
	{ CD "hosts/host=*/agent-update", false, M, M, T_ANY, TK_WRITE },
	{ CD "hosts/host=*/console-update", false, M, M, T_ANY, TK_WRITE },
	{ CD "hosts/host=*/export-configuration", false, M, M, T_ANY,
	    TK_WRITE },
	{ CD "hosts/host=*/apply-configuration", false, M, M, T_ANY,
	    TK_WRITE },
	{ CD "hosts/host=*/capture", false, M, M, T_ANY, TK_WRITE },
	{ CD "hosts/host=*/dataset-key", false, M, M, T_ANY, TK_WRITE },
	{ CD "hosts/host=*/subscription-token", false, M, M, T_ANY,
	    TK_WRITE },
	{ CD "sdwan", false, O, O, T_FLEET, TK_WRITE },
	{ CD "sdwan/check", false, O, O, T_FLEET, TK_WRITE },
	{ CD "sdwan/apply", false, O, O, T_FLEET, TK_WRITE },
	{ CD "sdwan/pin", false, O, O, T_FLEET, TK_WRITE },
	{ CD "sdwan/rekey", false, O, O, T_FLEET, TK_WRITE },
	{ CD "sdwan/fetch-lists", false, O, O, T_FLEET, TK_WRITE },
	{ CD "sdwan/issue-identity", false, O, O, T_FLEET, TK_WRITE },
	{ CD "sdwan/revoke-identity", false, O, O, T_FLEET, TK_WRITE },
	{ CD "sdwan/attach", false, O, O, T_FLEET, TK_WRITE },
	{ CD "update", false, W, W, T_ANY, TK_WRITE },
	{ CD "update-notes", false, W, W, T_ANY, TK_WRITE },
	{ CD "cluster", false, M, M, T_ANY, TK_WRITE },
	{ CD "ca", false, W, W, T_ANY, TK_READ },
	{ CD "ca/make", false, W, W, T_ANY, TK_READ },
	{ CD "ca/request", false, W, W, T_ANY, TK_READ },
	{ CD "ca/import", false, W, W, T_ANY, TK_READ },
	{ CD "ca/discard", false, W, W, T_ANY, TK_READ },
	{ CD "ca/rollout", false, W, W, T_ANY, TK_READ },
	{ CD "ca/finish", false, W, W, T_ANY, TK_READ },
	/* Every user's own; enabled by owners (cplug.c). */
	{ CD "plugins", false, M, M, T_ANY, TK_WRITE },
	/* Every user's own keys (auth.c). */
	{ CD "credentials", false, M, M, T_ANY, TK_NO },
	{ CO "trace-path", false, O, O, T_ANY, TK_WRITE },
	{ CO "wireguard-keypair", false, O, O, T_ANY, TK_WRITE },
	/* The L3NM and the virtual networks: the SD-WAN's services. */
	{ "/restconf/data/ietf-l3vpn-ntw:l3vpn-ntw", false, O, O, T_FLEET,
	    TK_WRITE },
	{ "/restconf/data/ietf-vn:access-point", false, O, O, T_FLEET,
	    TK_WRITE },
	{ "/restconf/data/ietf-vn:virtual-network", false, O, O, T_FLEET,
	    TK_WRITE },
	{ "/restconf/operations/ietf-vn:vn-compute", false, O, O, T_FLEET,
	    TK_WRITE },
	/* The rest of RESTCONF, the hosts' by host; the modules described
	 * for forms (ymodule.c); of /api, the socket's reads and an IDS's
	 * pcap files. */
	{ "/restconf", false, M, M, T_ANY, TK_WRITE },
	/* The event streams, each source judged by host (rcstream.c); a
	 * page's stream changed (a POST) by the session that opened it,
	 * as a change, its Origin checked. */
	{ "/restconf/streams", false, M, M, T_ANY, TK_WRITE },
	{ "/yang", false, M, M, T_ANY, TK_WRITE },
	{ "/api/stream", false, M, M, T_ANY, TK_WRITE },
	/* A terminal: a security key's session alone; the host's role is
	 * terminal.c's to judge. */
	{ "/api/terminal", false, M, M, T_ANY, TK_NO },
	{ "/api/servers/*/ids/pcap", false, M, M, T_ANY, TK_WRITE },
	{ "/api/servers/*/ids/pcap-log", false, M, M, T_ANY, TK_WRITE },
};

/* What no row names: every user's, no token's. */
static const struct cnode	cnode_rest = { "", false, M, M, T_ANY, TK_NO };

/*
 * Does pat, each * a key (no /), match path whole (exact) or as far as
 * a node's end ("", /, ? or =)?  How much of path, or 0.
 */
static size_t
cnode_match(const char *pat, const char *path, bool exact)
{
	const char	*p0 = path;
	size_t		 n;

	while (*pat != '\0') {
		if (*pat == '*') {
			if ((n = strcspn(path, "/?")) == 0)
				return (0);
			path += n;
			pat++;
			continue;
		}
		if (*pat++ != *path++)
			return (0);
	}
	if (exact ? *path != '\0' && *path != '?' : *path != '\0' && *path !=
	    '/' && *path != '?' && *path != '=')
		return (0);
	return ((size_t)(path - p0) + (exact ? 1 : 0));
}

/* The row that rules path: the longest that matches; the node alone's
 * before its subtree's. */
static const struct cnode *
cnode_of(const char *path)
{
	const struct cnode	*best;
	size_t			 i, n, bn;

	best = &cnode_rest;
	bn = 0;
	for (i = 0; i < nitems(cnodes); i++)
		if ((n = cnode_match(cnodes[i].path, path, cnodes[i].exact)) >
		    bn) {
			best = &cnodes[i];
			bn = n;
		}
	return (best);
}

/* May an API token of kind (TOKEN_READ, TOKEN_WRITE) take path? */
static bool
cnode_token(const struct cnode *c, int kind, bool mutate)
{

	if (mutate)
		return (kind == TOKEN_WRITE && c->token == TK_WRITE);
	return (c->token != TK_NO);
}

bool
token_readable(const char *path)
{

	return (cnode_token(cnode_of(path), TOKEN_READ, false));
}

bool
token_writable(const char *path)
{

	return (cnode_token(cnode_of(path), TOKEN_WRITE, true));
}

/* Is path the whole fleet's, or every tenant's alike: no tenant's? */
bool
path_fleet_wide(const char *path)
{

	return (cnode_of(path)->tenant != T_ANY);
}

/* May a user of console role r take path, its role alone? */
bool
user_path_ok(enum crole r, const char *path, bool mutate)
{
	const struct cnode	*c;

	c = cnode_of(path);
	return (r != CROLE_NONE && r >= (mutate ? c->write : c->read));
}

static const char *
crole_a(enum crole r)
{

	return (r == CROLE_OPERATOR ? "an operator" : r == CROLE_MEMBER ?
	    "a member" : r == CROLE_OWNER ? "an owner" : "a user no longer");
}

/* The console role the request acts with: its user's, or its API
 * token's maker's; none for no one. */
enum crole
req_console(struct http_request *req)
{
	struct principal	p;

	req_principal(req, &p);
	return (p.kind == P_USER ? user_console(p.name) : p.kind == P_RTOKEN ||
	    p.kind == P_WTOKEN ? token_console(p.name) : CROLE_NONE);
}

/*
 * May the request take path (a change of it, or an action, mutate):
 * 0, or the HTTP status with ietf-restconf's code into *codep and why.
 * The request's principal: its session's user, the API token that
 * opened its session, or its bearer token; the token as its kind says
 * and as its maker may now.
 */
int
req_may_path(struct http_request *req, const char *path, bool mutate,
    const char **codep, char *why, size_t len)
{
	const struct cnode	*c;
	struct principal	 p;
	const char		*t, *code;
	enum crole		 r;
	int			 k, st;

	c = cnode_of(path);
	code = "";
	st = 0;
	why[0] = '\0';
	if (!session_valid(req)) {
		/*
		 * A bearer token is not sent by a browser by itself: no CSRF
		 * checks; what its row lets it, and its maker's role.
		 */
		switch ((k = token_kind(req))) {
		case TOKEN_WRITE:
			if (!cnode_token(c, k, mutate)) {
				st = 403;
				code = "token";
				snprintf(why, len, "an API token may not %s this",
				    mutate ? "change" : "read");
			}
			break;
		case TOKEN_READ:
			if (!cnode_token(c, k, mutate)) {
				st = 401;
				code = "unauthenticated";
				snprintf(why, len, "%s", mutate ? "an API token "
				    "reads only" : "log in first");
			}
			break;
		default:
			st = 401;
			code = "unauthenticated";
			snprintf(why, len, "log in first");
			break;
		}
	}
	if (st == 0) {
		req_principal(req, &p);
		/* One of no one, neither a user's nor a token's, opens
		 * nothing: no name is no role, never every role. */
		if (p.kind == P_NONE) {
			st = 401;
			code = "unauthenticated";
			snprintf(why, len, "a session of no user: sign in "
			    "again");
		} else if (session_valid(req) && session_by_token(req) &&
		    !cnode_token(c, TOKEN_WRITE, mutate)) {
			/* Opened with a write token, or by a password the
			 * console limits: what a write token may, no more. */
			st = 403;
			code = "token";
			snprintf(why, len, "a session opened with an API token "
			    "or a password may not %s this: sign in with a "
			    "security key", mutate ? "change" : "read");
		}
	}
	if (st == 0 && (t = req_tenant(req))[0] != '\0' && c->tenant !=
	    T_ANY) {
		st = 403;
		code = "tenant";
		snprintf(why, len, "%s", c->tenant == T_FLEET ? "the SD-WAN "
		    "and its services are the whole fleet's: not a tenant's "
		    "user's" : "the prefix lists and the threat feeds are every "
		    "tenant's alike: not a tenant's user's");
	}
	if (st == 0) {
		r = req_console(req);
		if (r == CROLE_NONE || r < (mutate ? c->write : c->read)) {
			st = 403;
			code = "role";
			if (p.kind == P_USER)
				snprintf(why, len, "%s of this console may not %s "
				    "this", crole_a(r), mutate ? "change" :
				    "read");
			else
				snprintf(why, len, "the API token's maker, %s of "
				    "this console, may not %s this", crole_a(r),
				    mutate ? "change" : "read");
		}
	}
	if (codep != NULL)
		*codep = code;
	return (st);
}

/* May user take path: their role and tenant (req_may_path()'s, for a
 * user named, not a request). */
bool
user_may_path(const char *user, const char *path, bool mutate)
{
	const struct cnode	*c;

	c = cnode_of(path);
	return (user_path_ok(user_console(user), path, mutate) &&
	    (user_tenant(user)[0] == '\0' || c->tenant == T_ANY));
}
