/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The console's users, roles and what each may do (RBAC).  A role
 * names what may be done: on the console (owner: everything, the
 * settings, keys, tokens, CA, users and roles among it; operator: the
 * fleet's tools too, SD-WAN, workflows, templates, transfers; member:
 * the hosts alone) and on the hosts, by host id or "*" for all (viewer
 * reads; operator changes; admin also updates, moves and removes).  A
 * user has roles, one or more, and what they allow together; and may
 * belong to a tenant, a fleet of its own: it then sees the hosts of
 * that tenant alone (servers carry the tenant's name), and is an
 * operator of the console at most, whose own are every tenant's.  Each
 * user has a stable id (user_id()), named beside the name by what
 * stays: a user removed and another made with the name is another.
 * A user the directory keeps is the directory's: no edit makes it a
 * local one, and no local user's name signs in by the directory.
 * Three roles
 * come built in, owner, operator and viewer, and may be changed like
 * any.  Sign-in keys belong to a user; a key with none is the built-in
 * admin's, an owner, so a console with keys from before has its owner.
 * A user is invited: a one-time token with which they register their
 * first key.  A group is users given roles together: a user may do
 * what its own roles allow and what its groups' do.  users.json in the
 * data directory, {"users": [...], "roles": [...], "groups": [...],
 * "invites": [...]}, served as arcana-console's users, roles and groups
 * (cyang.c), an invitation by users/user=<name>/invite.
 *
 * A user the console keeps may also have a password of the console's
 * own, beside their keys: kept as crypt(3)'s bcrypt ("$2b$"), hashed in
 * a task (user_password_hash()), never said back, set from a session
 * that may change the sign-in, one's own with the current one or one's
 * key as proof (auth.c), or at the console's setup by password; a
 * session it opens has the
 * user's roles, or, with password_full = false in web.conf, is limited
 * as a directory user's is.  A user the directory keeps (source ldap)
 * signs in with the directory's.
 */

#include <sys/param.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#include <stdatomic.h>

#include "console.h"

#define	USERS_FILE	"users.json"
#define	USERS_MAX	256
#define	ROLES_MAX	64
#define	GROUPS_MAX	64
#define	INVITE_LIFE	(24 * 3600)
#define	INVITE_BYTES	24

static ucl_object_t	*udoc;

static const char	*pw_of(const char *);
static int		 users_save(void);
static const ucl_object_t *acl_get(void);
static void		 acl_put(const ucl_object_t *);

/*
 * What the threads judge a principal by (principal_reach()): the users,
 * roles and groups, each server's tenant and where it is reached, and
 * the tokens, as the loop last had them; made again whenever one
 * changes and every second besides (acl_publish()).  The loop judges by
 * its own.  Never changed once made: a thread reads it while it holds a
 * reference, taken and given back under the lock.
 */
static pthread_mutex_t			 acl_lock = PTHREAD_MUTEX_INITIALIZER;
static ucl_object_t			*acl;
static _Thread_local const ucl_object_t	*acl_in;	/* judged by it */

/* Base64url of bytes, without padding. */
static void
b64url_of(const uint8_t *d, size_t n, char *out, size_t len)
{
	static const char	alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789-_";
	size_t			i, o;
	uint32_t		v;
	int			bits;

	o = 0;
	v = 0;
	bits = 0;
	for (i = 0; i < n && o + 1 < len; i++) {
		v = (v << 8) | d[i];
		bits += 8;
		while (bits >= 6 && o + 1 < len) {
			bits -= 6;
			out[o++] = alphabet[(v >> bits) & 0x3f];
		}
	}
	if (bits > 0 && o + 1 < len)
		out[o++] = alphabet[(v << (6 - bits)) & 0x3f];
	out[o] = '\0';
}

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_replace_key(o, v, key, 0, true);
}

static ucl_object_t *
list_of(const char *key)
{

	return ((ucl_object_t *)(uintptr_t)ucl_object_lookup(acl_in != NULL ?
	    acl_in : udoc, key));
}

/* users.json written, and the threads told. */
static int
users_save(void)
{
	int	rc;

	rc = store_save(USERS_FILE, udoc);
	acl_publish();
	return (rc);
}

static const ucl_object_t *
by_name(const char *list, const char *name)
{
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;

	it = NULL;
	while (name != NULL && (u = ucl_object_iterate(list_of(list), &it,
	    true)) != NULL)
		if (ucl_str(u, "name") != NULL && strcmp(ucl_str(u, "name"), name)
		    == 0)
			return (u);
	return (NULL);
}

/* A user's, a role's or a tenant's name: letters, digits, _ . @ -,
 * USER_NAME_MAX. */
bool
user_name_ok(const char *s)
{
	size_t	n;

	if (s == NULL)
		return (false);
	n = strlen(s);
	return (n > 0 && n <= USER_NAME_MAX && strspn(s,
	    "abcdefghijklmnopqrstuvwxyz"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.@-") == n);
}

/* A name the hosts are told stands for no user (console.h): the console
 * itself, a read token.  No user is made of it. */
bool
user_name_reserved(const char *s)
{

	return (s != NULL && (strcmp(s, NACM_CONSOLE) == 0 || strcmp(s,
	    NACM_TOKEN_READ) == 0));
}

bool
user_exists(const char *name)
{

	return (by_name("users", name) != NULL);
}

/*
 * A user's stable id, made once with the user (when it was made, and
 * random bytes): what a session, a token's maker or a stored intent's
 * author names beside the name, so that a user removed and another made
 * with the name, of another tenant even, is not taken for them.
 */
static void
uid_new(char *buf, size_t len)
{
	uint8_t	r[12];
	char	s[20];

	arc4random_buf(r, sizeof(r));
	b64url_of(r, sizeof(r), s, sizeof(s));
	snprintf(buf, len, "%jx-%s", (intmax_t)time(NULL), s);
}

/*
 * The id of a user kept before ids, or the built-in owner made at start:
 * of its name and when it was made, so that every node of a cluster,
 * reading the same users, gives it the same; the built-in owner's of
 * its name alone, as each node makes its own at its first start.
 */
static void
uid_of(const ucl_object_t *u, char *buf, size_t len)
{
	uint8_t		 h[32];
	char		 s[64], text[USER_NAME_LEN + 32];
	unsigned int	 n;
	int64_t		 made;

	made = ucl_str(u, "name") != NULL && strcmp(ucl_str(u, "name"),
	    ADMIN_USER) == 0 ? 0 : ucl_object_toint(ucl_object_lookup(u,
	    "created"));
	snprintf(text, sizeof(text), "%s/%jd", ucl_str(u, "name") != NULL ?
	    ucl_str(u, "name") : "", (intmax_t)made);
	EVP_Digest(text, strlen(text), h, &n, EVP_sha256(), NULL);
	b64url_of(h, 12, s, sizeof(s));
	snprintf(buf, len, "%jx-%s", (intmax_t)made, s);
}

/* The user's id; "" for no such user. */
const char *
user_id(const char *name)
{
	const ucl_object_t	*u;

	if ((u = by_name("users", name)) == NULL || ucl_str(u, "id") == NULL)
		return ("");
	return (ucl_str(u, "id"));
}

/* Is the user one the directory keeps (source ldap)? */
bool
user_ldap(const char *name)
{
	const ucl_object_t	*u;

	return ((u = by_name("users", name)) != NULL && ucl_str(u, "source") !=
	    NULL && strcmp(ucl_str(u, "source"), "ldap") == 0);
}

/*
 * The principal of console user name, with their id: false, and p no
 * one's, when there is no such user or the name does not fit.
 */
bool
principal_user(struct principal *p, const char *name)
{

	memset(p, 0, sizeof(*p));
	if (!user_exists(name) || !name_copy(p->name, sizeof(p->name), name) ||
	    !name_copy(p->uid, sizeof(p->uid), user_id(name))) {
		memset(p, 0, sizeof(*p));
		return (false);
	}
	p->kind = P_USER;
	p->need = ROLE_VIEWER;
	return (true);
}

/* Is p's user, by name and id, still there? */
static bool
principal_user_alive(const struct principal *p)
{

	return (user_exists(p->name) && (p->uid[0] == '\0' || strcmp(
	    user_id(p->name), p->uid) == 0));
}

/*
 * The users' names in v, max of them, copies the caller frees: every
 * one, or the owners of the console alone; how many.
 */
size_t
users_names(char **v, size_t max, bool owners_only)
{
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;
	size_t			 n;

	n = 0;
	it = NULL;
	while (n < max && (u = ucl_object_iterate(list_of("users"), &it,
	    true)) != NULL)
		if (ucl_str(u, "name") != NULL && (!owners_only ||
		    user_console(ucl_str(u, "name")) == CROLE_OWNER))
			v[n++] = xstrdup(ucl_str(u, "name"));
	return (n);
}

/*
 * The names of the users whose role on host sid is an operator's or an
 * admin's and who are no owner of the console, in v, max of them,
 * copies the caller frees; how many.  Their NACM group on the host
 * (ytrans_nacm_sync()).
 */
size_t
users_operators(char **v, size_t max, const char *sid)
{
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;
	const char		*name;
	size_t			 n;

	n = 0;
	it = NULL;
	while (n < max && (u = ucl_object_iterate(list_of("users"), &it,
	    true)) != NULL)
		if ((name = ucl_str(u, "name")) != NULL && user_console(name) !=
		    CROLE_OWNER && user_host(name, sid) >= ROLE_OPERATOR)
			v[n++] = xstrdup(name);
	return (n);
}

static enum crole
crole_of(const char *s)
{

	if (s == NULL)
		return (CROLE_MEMBER);
	if (strcmp(s, "owner") == 0)
		return (CROLE_OWNER);
	if (strcmp(s, "operator") == 0)
		return (CROLE_OPERATOR);
	return (CROLE_MEMBER);
}

static enum role
role_of(const char *s)
{

	if (s == NULL)
		return (ROLE_NONE);
	if (strcmp(s, "admin") == 0)
		return (ROLE_ADMIN);
	if (strcmp(s, "operator") == 0)
		return (ROLE_OPERATOR);
	if (strcmp(s, "viewer") == 0)
		return (ROLE_VIEWER);
	return (ROLE_NONE);
}

const char *
role_name(enum role r)
{

	return (r == ROLE_ADMIN ? "admin" : r == ROLE_OPERATOR ? "operator" :
	    r == ROLE_VIEWER ? "viewer" : "none");
}

const char *
crole_name(enum crole r)
{

	return (r == CROLE_OWNER ? "owner" : r == CROLE_OPERATOR ? "operator" :
	    r == CROLE_MEMBER ? "member" : "none");
}

/* A role's say on a host: the host's own entry, else "*"'s. */
static enum role
role_host(const ucl_object_t *role, const char *sid)
{
	const ucl_object_t	*h;

	h = ucl_object_lookup(role, "hosts");
	if (sid != NULL && ucl_object_lookup(h, sid) != NULL)
		return (role_of(ucl_object_tostring(ucl_object_lookup(h, sid))));
	return (role_of(ucl_object_tostring(ucl_object_lookup(h, "*"))));
}

/*
 * A user's roles: its own, and its groups'; into v, max at most, each
 * once.  How many.
 */
static int
roles_of(const ucl_object_t *u, const ucl_object_t **v, int max)
{
	const ucl_object_t	*e, *g, *r;
	ucl_object_iter_t	 it, git;
	int			 n, i;

	n = 0;
	it = NULL;
	while (n < max && (e = ucl_object_iterate(ucl_object_lookup(u,
	    "roles"), &it, true)) != NULL)
		if ((r = by_name("roles", ucl_object_tostring(e))) != NULL)
			v[n++] = r;
	it = NULL;
	while ((g = ucl_object_iterate(ucl_object_lookup(u, "groups"), &it,
	    true)) != NULL) {
		if ((g = by_name("groups", ucl_object_tostring(g))) == NULL)
			continue;
		git = NULL;
		while (n < max && (e = ucl_object_iterate(ucl_object_lookup(g,
		    "roles"), &git, true)) != NULL) {
			if ((r = by_name("roles", ucl_object_tostring(e))) ==
			    NULL)
				continue;
			for (i = 0; i < n && v[i] != r; i++)
				;
			if (i == n)
				v[n++] = r;
		}
	}
	return (n);
}

/* The most a user's roles allow on the console, a tenant's or not. */
static enum crole
crole_roles(const ucl_object_t *u)
{
	const ucl_object_t	*v[ROLES_MAX];
	enum crole		 best, c;
	int			 i, n;

	best = CROLE_NONE;
	n = roles_of(u, v, ROLES_MAX);
	for (i = 0; i < n; i++) {
		c = crole_of(ucl_str(v[i], "console"));
		if (c > best)
			best = c;
	}
	return (best);
}

/*
 * A user's role on the console: the most its roles allow; none for no
 * user (an API token's reach is tokens.c's, not a role).  A tenant's
 * user is an operator at most: the console's own (its tokens, users,
 * settings, CA) are every tenant's, so no tenant's (users_init() logs
 * one whose roles say more).
 */
enum crole
user_console(const char *name)
{
	const ucl_object_t	*u;
	enum crole		 best;

	if (name == NULL || name[0] == '\0')
		return (CROLE_NONE);
	if ((u = by_name("users", name)) == NULL)
		return (CROLE_NONE);
	best = crole_roles(u);
	if (best == CROLE_OWNER && ucl_str(u, "tenant") != NULL &&
	    ucl_str(u, "tenant")[0] != '\0')
		best = CROLE_OPERATOR;
	return (best);
}

/* The user's tenant, "" for none. */
const char *
user_tenant(const char *name)
{
	const ucl_object_t	*u;

	if ((u = by_name("users", name)) == NULL || ucl_str(u, "tenant") == NULL)
		return ("");
	return (ucl_str(u, "tenant"));
}

/* Host sid's tenant into *tp ("" none): false when there is no such
 * host.  The threads' as acl_publish() last had it. */
static bool
host_tenant(const char *sid, const char **tp)
{
	const struct server	*s;
	const ucl_object_t	*v;

	if (sid == NULL)
		return (false);
	if (acl_in != NULL) {
		if ((v = ucl_object_lookup(ucl_object_lookup(acl_in,
		    "tenants"), sid)) == NULL)
			return (false);
		*tp = ucl_object_tostring(v);
		return (true);
	}
	if ((s = server_find(sid)) == NULL)
		return (false);
	*tp = s->tenant != NULL ? s->tenant : "";
	return (true);
}

/*
 * A user's role on a host: the most its roles allow there; none on a
 * host of another tenant, and none for no user: who has no name has
 * no role (a token's reach is principal_host()'s).
 */
enum role
user_host(const char *name, const char *sid)
{
	const ucl_object_t	*u, *v[ROLES_MAX];
	const char		*t, *ht;
	enum role		 best, h;
	int			 i, n;

	if (name == NULL || name[0] == '\0')
		return (ROLE_NONE);
	if ((u = by_name("users", name)) == NULL)
		return (ROLE_NONE);
	t = ucl_str(u, "tenant");
	if (t != NULL && t[0] != '\0') {
		if (!host_tenant(sid, &ht) || strcmp(ht, t) != 0)
			return (ROLE_NONE);
	}
	best = ROLE_NONE;
	n = roles_of(u, v, ROLES_MAX);
	for (i = 0; i < n; i++) {
		h = role_host(v[i], sid);
		if (h > best)
			best = h;
	}
	return (best);
}

/*
 * What the API token of id is now: TOKEN_NONE once deleted; its
 * maker's name and id into *makerp and *midp ("" none: one made before
 * tokens kept their maker, the built-in owner's).
 */
static int
token_now(const char *id, const char **makerp, const char **midp)
{
	const ucl_object_t	*e;
	const char		*k;

	*makerp = *midp = "";
	if (acl_in == NULL)
		return (token_maker_of(id, makerp, midp));
	e = ucl_object_lookup(ucl_object_lookup(acl_in, "tokens"), id);
	if ((k = ucl_str(e, "kind")) == NULL)
		return (TOKEN_NONE);
	if (ucl_str(e, "maker") != NULL)
		*makerp = ucl_str(e, "maker");
	if (ucl_str(e, "maker_id") != NULL)
		*midp = ucl_str(e, "maker_id");
	return (strcmp(k, "write") == 0 ? TOKEN_WRITE : TOKEN_READ);
}

/*
 * A principal's role on host sid: a user's own (user_host()), none once
 * the user of the name is another (its id); an API token's its reach,
 * a read token a viewer's and a write token an admin's, never more
 * than its maker may now (none once the maker is gone; one made before
 * tokens kept their maker, the built-in owner's), none once deleted;
 * the console's every host's; no one's none.
 */
enum role
principal_host(const struct principal *p, const char *sid)
{
	const char	*t, *maker, *mid;
	enum role	 r, m;
	int		 k;

	switch (p->kind) {
	case P_USER:
		if (!principal_user_alive(p))
			return (ROLE_NONE);
		return (user_host(p->name, sid));
	case P_RTOKEN:
	case P_WTOKEN:
		if (!host_tenant(sid, &t))
			return (ROLE_NONE);
		if ((k = token_now(p->name, &maker, &mid)) == TOKEN_NONE)
			return (ROLE_NONE);
		r = p->kind == P_WTOKEN && k == TOKEN_WRITE ? ROLE_ADMIN :
		    ROLE_VIEWER;
		if (maker[0] == '\0')
			maker = ADMIN_USER;
		if (!user_exists(maker) || (mid[0] != '\0' && strcmp(
		    user_id(maker), mid) != 0))
			return (ROLE_NONE);
		m = user_host(maker, sid);
		return (m < r ? m : r);
	case P_CONSOLE:
		return (ROLE_ADMIN);
	default:
		return (ROLE_NONE);
	}
}

/*
 * Who p is said to a host as, its NACM user (RFC 8341), into buf: a
 * user by their name; a read token as NACM_TOKEN_READ, a name no user
 * has and in no group, which a host holds to a viewer's reads; a write
 * token as its maker (the built-in owner for one made before tokens
 * kept a maker), so that the host's rules for that user hold it, a read
 * token's name once it reads only or is gone; "" for the console and no
 * one, said as the connection's user ("console").  From any thread.
 */
const char *
principal_nacm(const struct principal *p, char *buf, size_t len)
{
	const ucl_object_t	*snap, *was;
	const char		*maker, *mid;

	buf[0] = '\0';
	switch (p->kind) {
	case P_USER:
		snprintf(buf, len, "%s", p->name);
		break;
	case P_RTOKEN:
		snprintf(buf, len, "%s", NACM_TOKEN_READ);
		break;
	case P_WTOKEN:
		snprintf(buf, len, "%s", NACM_TOKEN_READ);
		if ((snap = acl_get()) == NULL)
			break;
		was = acl_in;
		acl_in = snap;
		if (token_now(p->name, &maker, &mid) == TOKEN_WRITE)
			snprintf(buf, len, "%s", maker[0] != '\0' ? maker :
			    ADMIN_USER);
		acl_in = was;
		acl_put(snap);
		break;
	default:
		break;
	}
	return (buf);
}

/* The tenant of an API token's maker, "" none (users.c's, tokens.c's
 * acl). */
const char *
token_tenant(const char *id)
{
	const char	*maker, *mid;

	if (token_now(id, &maker, &mid) == TOKEN_NONE)
		return ("");
	return (user_tenant(maker[0] != '\0' ? maker : ADMIN_USER));
}

/* May p have need on host sid (ROLE_VIEWER: read it)? */
bool
principal_may(const struct principal *p, const char *sid, enum role need)
{
	enum role	r;

	if (need < ROLE_VIEWER)
		need = ROLE_VIEWER;
	r = principal_host(p, sid);
	return (r != ROLE_NONE && r >= need);
}

/* Who p is, for a log line or a refusal. */
const char *
principal_who(const struct principal *p, char *buf, size_t len)
{

	switch (p->kind) {
	case P_USER:
		snprintf(buf, len, "user %s", p->name);
		break;
	case P_RTOKEN:
	case P_WTOKEN:
		snprintf(buf, len, "API token %s", p->name);
		break;
	case P_CONSOLE:
		snprintf(buf, len, "the console");
		break;
	default:
		snprintf(buf, len, "no one");
		break;
	}
	return (buf);
}

/*
 * p as a stored intent's author keeps it, {"kind", "name", "id"}: a
 * user with their id, a token by its id, the console.
 */
ucl_object_t *
principal_record(const struct principal *p)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "kind", ucl_object_fromstring(p->kind == P_USER ? "user" :
	    p->kind == P_RTOKEN || p->kind == P_WTOKEN ? "token" : p->kind ==
	    P_CONSOLE ? "console" : "none"));
	if (p->kind == P_USER || p->kind == P_RTOKEN || p->kind == P_WTOKEN)
		put(o, "name", ucl_object_fromstring(p->name));
	if (p->kind == P_USER)
		put(o, "id", ucl_object_fromstring(p->uid[0] != '\0' ? p->uid :
		    user_id(p->name)));
	if (p->kind == P_WTOKEN)
		put(o, "write", ucl_object_frombool(true));
	return (o);
}

/*
 * The author r (principal_record()'s) as a principal into p: a user by
 * name and id (one of the name with another id is not them, and has no
 * role: principal_host()), a token by its id; false, p no one's, for
 * none, or one that does not fit.
 */
bool
principal_of_record(const ucl_object_t *r, struct principal *p)
{
	const char	*k;

	memset(p, 0, sizeof(*p));
	if ((k = ucl_str(r, "kind")) == NULL || !name_copy(p->name,
	    sizeof(p->name), ucl_str(r, "name") != NULL ? ucl_str(r, "name") :
	    ""))
		return (false);
	if (strcmp(k, "user") == 0) {
		if (!name_copy(p->uid, sizeof(p->uid), ucl_str(r, "id") != NULL ?
		    ucl_str(r, "id") : "-"))
			return (false);
		p->kind = P_USER;
	} else if (strcmp(k, "token") == 0)
		p->kind = ucl_flag(r, "write") ? P_WTOKEN : P_RTOKEN;
	else if (strcmp(k, "console") == 0)
		p->kind = P_CONSOLE;
	if (p->kind == P_NONE)
		memset(p, 0, sizeof(*p));
	p->need = ROLE_VIEWER;
	return (p->kind != P_NONE);
}

/* What acl_publish() last made, a reference taken; NULL while there
 * is none yet.  acl_put() gives it back. */
static const ucl_object_t *
acl_get(void)
{
	const ucl_object_t	*snap;

	pthread_mutex_lock(&acl_lock);
	snap = acl != NULL ? ucl_object_ref(acl) : NULL;
	pthread_mutex_unlock(&acl_lock);
	return (snap);
}

static void
acl_put(const ucl_object_t *snap)
{

	pthread_mutex_lock(&acl_lock);
	ucl_object_unref((ucl_object_t *)(uintptr_t)snap);
	pthread_mutex_unlock(&acl_lock);
}

/* The server reached at uri into sid, by snap: false, none has it. */
static bool
acl_sid(const ucl_object_t *snap, const char *uri, char *sid, size_t len)
{
	const ucl_object_t	*v;

	if ((v = ucl_object_lookup(ucl_object_lookup(snap, "uris"), uri)) ==
	    NULL || ucl_object_type(v) != UCL_STRING)
		return (false);
	snprintf(sid, len, "%s", ucl_object_tostring(v));
	return (true);
}

/* From any thread: p's role on the host reached at uri, none where no
 * server is. */
enum role
principal_host_at(const struct principal *p, const char *uri)
{
	const ucl_object_t	*snap;
	enum role		 r;
	char			 sid[16];

	if (p->kind == P_CONSOLE)
		return (ROLE_ADMIN);
	if ((snap = acl_get()) == NULL)
		return (ROLE_NONE);
	acl_in = snap;
	r = acl_sid(snap, uri, sid, sizeof(sid)) ? principal_host(p, sid) :
	    ROLE_NONE;
	acl_in = NULL;
	acl_put(snap);
	return (r);
}

/*
 * From any thread: may p ask the agent at uri for what needs need, by
 * what acl_publish() last made?  Why not into why.  A URI no server has
 * is refused, but to a principal flagged P_F_NEWURI: a host being added
 * or moved, the URI its route just checked, which the user may add or
 * move (servers.c, hosts.c); the host's access rules hold them there.
 */
bool
principal_reach(const struct principal *p, const char *uri, enum role need,
    char *why, size_t len)
{
	const ucl_object_t	*snap;
	enum role		 r;
	char			 who[96], sid[16];
	bool			 ok;

	if (p->kind == P_CONSOLE)
		return (true);
	if (p->kind == P_NONE) {
		snprintf(why, len, "asked for no one: what the console asks of "
		    "a host is for a user, a token or the console itself");
		return (false);
	}
	if ((int)need < p->need)
		need = (enum role)p->need;
	if (need < ROLE_VIEWER)
		need = ROLE_VIEWER;
	if ((snap = acl_get()) == NULL) {
		snprintf(why, len, "the console is starting");
		return (false);
	}
	acl_in = snap;
	ok = true;
	if (acl_sid(snap, uri, sid, sizeof(sid))) {
		r = principal_host(p, sid);
		if (r == ROLE_NONE || r < need) {
			ok = false;
			snprintf(why, len, "%s %s host %s%s", principal_who(p,
			    who, sizeof(who)), r == ROLE_NONE ?
			    "has no role on" : r == ROLE_VIEWER ?
			    "is a viewer of" : "is an operator of", sid,
			    r == ROLE_NONE ? "" : need == ROLE_ADMIN ?
			    ": an admin of it alone may" :
			    ": it may not change it");
		}
	} else if ((p->flags & P_F_NEWURI) == 0) {
		ok = false;
		snprintf(why, len, "no host is reached at %s", uri);
	}
	acl_in = NULL;
	acl_put(snap);
	return (ok);
}

/* From any thread: may p have need on host sid, by what acl_publish()
 * last made? */
bool
principal_may_now(const struct principal *p, const char *sid, enum role need)
{
	const ucl_object_t	*snap;
	bool			 ok;

	if (p->kind == P_CONSOLE)
		return (true);
	if ((snap = acl_get()) == NULL)
		return (false);
	acl_in = snap;
	ok = principal_may(p, sid, need);
	acl_in = NULL;
	acl_put(snap);
	return (ok);
}

/*
 * How many times who may do what changed (users, roles, groups, tokens,
 * the hosts): what judged by it before judges again (auth.c's streams).
 */
static _Atomic uint64_t	acl_gen;

uint64_t
acl_generation(void)
{

	return (atomic_load(&acl_gen));
}

static void	acl_make(void);

/* On the loop: what the threads judge by, made again, after a change. */
void
acl_publish(void)
{

	acl_make();
	atomic_fetch_add(&acl_gen, 1);
}

static void
acl_make(void)
{
	ucl_object_t		*n, *t, *u;
	const struct server	*s;
	const char		*k[] = { "users", "roles", "groups" };
	int			 i;

	n = ucl_object_typed_new(UCL_OBJECT);
	for (i = 0; i < (int)nitems(k); i++)
		put(n, k[i], list_of(k[i]) != NULL ? ucl_object_copy(
		    list_of(k[i])) : ucl_object_typed_new(UCL_ARRAY));
	t = ucl_object_typed_new(UCL_OBJECT);
	u = ucl_object_typed_new(UCL_OBJECT);
	for (i = 0; (s = server_at(i)) != NULL; i++) {
		ucl_object_insert_key(t, ucl_object_fromstring(s->tenant !=
		    NULL ? s->tenant : ""), s->id, 0, true);
		ucl_object_insert_key(u, ucl_object_fromstring(s->id), s->uri,
		    0, true);
	}
	put(n, "tenants", t);
	put(n, "uris", u);
	put(n, "tokens", tokens_acl());
	pthread_mutex_lock(&acl_lock);
	/* Another node's change, read again: a change all the same. */
	if (acl == NULL || ucl_object_compare(acl, n) != 0)
		atomic_fetch_add(&acl_gen, 1);
	if (acl != NULL)
		ucl_object_unref(acl);
	acl = n;
	pthread_mutex_unlock(&acl_lock);
}

/* Every second: what another node of the cluster changed, or the
 * tokens' file, reaches the threads; a change of who may do what is
 * one of the generation's (acl_publish()). */
static void
acl_tick(void *arg __unused, uint64_t now __unused)
{

	acl_make();
}

/* At the worker's start, once the servers are read. */
void
acl_init(void)
{

	acl_publish();
	(void)timer_add(acl_tick, 1000, NULL, 0);
}

/*
 * The console role an API token acts with (cnodes.c): its maker's now
 * (the built-in owner's for one made before tokens kept a maker); none
 * once it is gone, or its maker is.
 */
enum crole
token_console(const char *id)
{
	const char	*maker, *mid;

	if (token_now(id, &maker, &mid) == TOKEN_NONE)
		return (CROLE_NONE);
	if (maker[0] == '\0')
		maker = ADMIN_USER;
	if (!user_exists(maker) || (mid[0] != '\0' && strcmp(user_id(maker),
	    mid) != 0))
		return (CROLE_NONE);
	return (user_console(maker));
}

/* The WebAuthn user handle of a user: 16 bytes of the hash of the name. */
void
user_handle(const char *name, char *buf, size_t len)
{
	uint8_t		 h[32];
	unsigned int	 n;

	EVP_Digest(name, strlen(name), h, &n, EVP_sha256(), NULL);
	b64url_of(h, 16, buf, len);
}

static void
hex_of(const uint8_t *b, size_t n, char *out)
{
	size_t	i;

	for (i = 0; i < n; i++)
		snprintf(out + 2 * i, 3, "%02x", b[i]);
}

/*
 * An invitation given out: the token's hash kept with the user and
 * when it runs out; the token itself goes to the caller once.
 */
static bool
invite_make(const char *user, char *token, size_t len)
{
	ucl_object_t	*inv;
	uint8_t		 raw[INVITE_BYTES], h[32];
	char		 hex[65], s[48];
	unsigned int	 n;

	arc4random_buf(raw, sizeof(raw));
	b64url_of(raw, sizeof(raw), s, sizeof(s));
	snprintf(token, len, "inv_%s", s);
	EVP_Digest(token, strlen(token), h, &n, EVP_sha256(), NULL);
	hex_of(h, sizeof(h), hex);
	inv = ucl_object_typed_new(UCL_OBJECT);
	put(inv, "hash", ucl_object_fromstring(hex));
	put(inv, "user", ucl_object_fromstring(user));
	put(inv, "expires", ucl_object_fromint(time(NULL) + INVITE_LIFE));
	ucl_array_append(list_of("invites"), inv);
	return (users_save() == 0);
}

/*
 * Is token an invitation of this console's, in time, of a user there
 * is: its SHA-256 into h, the user into user.  Not spent: the key it
 * lets the user register spends it (invite_spend()).
 */
bool
invite_check(const char *token, uint8_t *h, char *user, size_t len)
{
	const ucl_object_t	*inv;
	ucl_object_iter_t	 it;
	char			 hex[65];
	unsigned int		 n;
	time_t			 now;

	if (token == NULL || strncmp(token, "inv_", 4) != 0)
		return (false);
	EVP_Digest(token, strlen(token), h, &n, EVP_sha256(), NULL);
	hex_of(h, 32, hex);
	now = time(NULL);
	it = NULL;
	while ((inv = ucl_object_iterate(list_of("invites"), &it, true)) !=
	    NULL) {
		if (ucl_str(inv, "hash") == NULL || strlen(ucl_str(inv,
		    "hash")) != 64 || timingsafe_bcmp(ucl_str(inv, "hash"), hex,
		    64) != 0)
			continue;
		if (ucl_object_toint(ucl_object_lookup(inv, "expires")) < now ||
		    !user_exists(ucl_str(inv, "user")))
			break;
		snprintf(user, len, "%s", ucl_str(inv, "user"));
		return (true);
	}
	return (false);
}

/* The invitation whose SHA-256 is h, user's, spent: false when it is
 * not there any more, or ran out. */
bool
invite_spend(const uint8_t *h, const char *user)
{
	const ucl_object_t	*inv;
	ucl_object_iter_t	 it;
	char			 hex[65];

	hex_of(h, 32, hex);
	it = NULL;
	while ((inv = ucl_object_iterate(list_of("invites"), &it, true)) !=
	    NULL) {
		if (ucl_str(inv, "hash") == NULL || strlen(ucl_str(inv,
		    "hash")) != 64 || timingsafe_bcmp(ucl_str(inv, "hash"), hex,
		    64) != 0)
			continue;
		if (ucl_object_toint(ucl_object_lookup(inv, "expires")) <
		    time(NULL) || ucl_str(inv, "user") == NULL ||
		    strcmp(ucl_str(inv, "user"), user) != 0 ||
		    !user_exists(user))
			return (false);
		ucl_object_unref(ucl_array_delete(list_of("invites"),
		    (ucl_object_t *)(uintptr_t)inv));
		(void)users_save();
		return (true);
	}
	return (false);
}

/* Entries of a list taken away where match says: invitations run
 * out, or a user's, a role's name in users' lists. */
static void
invites_drop(const char *user)
{
	const ucl_object_t	*inv;
	ucl_object_iter_t	 it;
	time_t			 now;
	bool			 again;

	now = time(NULL);
	do {
		again = false;
		it = NULL;
		while ((inv = ucl_object_iterate(list_of("invites"), &it, true)) !=
		    NULL)
			if (ucl_object_toint(ucl_object_lookup(inv, "expires")) <
			    now || (user != NULL && ucl_str(inv, "user") != NULL &&
			    strcmp(ucl_str(inv, "user"), user) == 0)) {
				ucl_object_unref(ucl_array_delete(list_of("invites"),
				    (ucl_object_t *)(uintptr_t)inv));
				again = true;
				break;
			}
	} while (again);
}

static ucl_object_t *
role_new(const char *name, const char *console, const char *all)
{
	ucl_object_t	*r, *h;

	r = ucl_object_typed_new(UCL_OBJECT);
	put(r, "name", ucl_object_fromstring(name));
	put(r, "console", ucl_object_fromstring(console));
	h = ucl_object_typed_new(UCL_OBJECT);
	if (all != NULL)
		put(h, "*", ucl_object_fromstring(all));
	put(r, "hosts", h);
	put(r, "created", ucl_object_fromint(time(NULL)));
	return (r);
}

/* users.json, written by another node of the cluster: read again. */
void
users_reload(void)
{

	ucl_object_unref(udoc);
	udoc = NULL;
	users_init();
}

void
users_init(void)
{
	ucl_object_t		*u, *roles;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	bool			 changed;

	if ((udoc = store_load(USERS_FILE)) == NULL || ucl_object_type(udoc) !=
	    UCL_OBJECT) {
		if (udoc != NULL)
			ucl_object_unref(udoc);
		udoc = ucl_object_typed_new(UCL_OBJECT);
	}
	changed = false;
	if (ucl_object_lookup(udoc, "users") == NULL)
		put(udoc, "users", ucl_object_typed_new(UCL_ARRAY));
	if (ucl_object_lookup(udoc, "invites") == NULL)
		put(udoc, "invites", ucl_object_typed_new(UCL_ARRAY));
	if (ucl_object_lookup(udoc, "groups") == NULL)
		put(udoc, "groups", ucl_object_typed_new(UCL_ARRAY));
	if (ucl_object_lookup(udoc, "roles") == NULL) {
		put(udoc, "roles", ucl_object_typed_new(UCL_ARRAY));
		changed = true;
	}
	/* The roles that come built in, when none of the name is there. */
	if (by_name("roles", "owner") == NULL) {
		ucl_array_append(list_of("roles"), role_new("owner", "owner",
		    "admin"));
		changed = true;
	}
	if (by_name("roles", "operator") == NULL) {
		ucl_array_append(list_of("roles"), role_new("operator", "operator",
		    "operator"));
		changed = true;
	}
	if (by_name("roles", "viewer") == NULL) {
		ucl_array_append(list_of("roles"), role_new("viewer", "member",
		    "viewer"));
		changed = true;
	}
	/* A user written before roles: what it said becomes a role of its
	 * name, the built-in owner's the owner role. */
	it = NULL;
	while ((e = ucl_object_iterate(list_of("users"), &it, true)) != NULL) {
		if (ucl_object_lookup(e, "roles") != NULL)
			continue;
		u = (ucl_object_t *)(uintptr_t)e;
		roles = ucl_object_typed_new(UCL_ARRAY);
		if (strcmp(ucl_str(u, "name"), ADMIN_USER) == 0 || (ucl_str(u,
		    "console") == NULL && ucl_object_lookup(u, "hosts") == NULL))
			ucl_array_append(roles, ucl_object_fromstring(strcmp(
			    ucl_str(u, "name"), ADMIN_USER) == 0 ? "owner" :
			    "viewer"));
		else {
			ucl_object_t	*r = role_new(ucl_str(u, "name"), ucl_str(u,
			    "console") != NULL ? ucl_str(u, "console") : "member",
			    NULL);

			if (ucl_object_lookup(u, "hosts") != NULL)
				put(r, "hosts", ucl_object_copy(ucl_object_lookup(u,
				    "hosts")));
			if (by_name("roles", ucl_str(u, "name")) == NULL)
				ucl_array_append(list_of("roles"), r);
			else
				ucl_object_unref(r);
			ucl_array_append(roles, ucl_object_fromstring(ucl_str(u,
			    "name")));
		}
		put(u, "roles", roles);
		(void)ucl_object_delete_key(u, "console");
		(void)ucl_object_delete_key(u, "hosts");
		changed = true;
	}
	/* The built-in owner: the keys from before users belong to it. */
	if (by_name("users", ADMIN_USER) == NULL) {
		u = ucl_object_typed_new(UCL_OBJECT);
		put(u, "name", ucl_object_fromstring(ADMIN_USER));
		roles = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(roles, ucl_object_fromstring("owner"));
		put(u, "roles", roles);
		put(u, "created", ucl_object_fromint(time(NULL)));
		ucl_array_append(list_of("users"), u);
		changed = true;
	}
	/* Each user its id, one made before ids (or the built-in owner just
	 * made) given one now, the same on every node (uid_of()); a
	 * tenant's user whose roles say owner is an operator (user_console()),
	 * said once. */
	it = NULL;
	while ((e = ucl_object_iterate(list_of("users"), &it, true)) != NULL) {
		char	id[USER_ID_LEN];

		u = (ucl_object_t *)(uintptr_t)e;
		if (ucl_str(u, "id") == NULL) {
			uid_of(u, id, sizeof(id));
			put(u, "id", ucl_object_fromstring(id));
			changed = true;
		}
		if (ucl_str(u, "tenant") != NULL && ucl_str(u, "tenant")[0] !=
		    '\0' && crole_roles(u) == CROLE_OWNER)
			log_msg(LOG_WARNING, "user %s of tenant %s: its roles say "
			    "owner of the console, which a tenant's user is not; "
			    "an operator", ucl_str(u, "name"), ucl_str(u, "tenant"));
	}
	if (changed)
		(void)users_save();
}

/* Whether a role names host sid itself, not by "*". */
bool
roles_name_host(const char *sid)
{
	const ucl_object_t	*r;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((r = ucl_object_iterate(list_of("roles"), &it, true)) != NULL)
		if (ucl_object_lookup(ucl_object_lookup(r, "hosts"), sid) !=
		    NULL)
			return (true);
	return (false);
}

/* How many users have the role. */
static int
role_users(const char *role)
{
	const ucl_object_t	*u, *e;
	ucl_object_iter_t	 it, rit;
	int			 n;

	n = 0;
	it = NULL;
	while ((u = ucl_object_iterate(list_of("users"), &it, true)) != NULL) {
		rit = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(u, "roles"), &rit,
		    true)) != NULL)
			if (strcmp(ucl_object_tostring_forced(e), role) == 0) {
				n++;
				break;
			}
	}
	return (n);
}

/* How many groups give the role. */
static int
role_groups(const char *role)
{
	const ucl_object_t	*g, *e;
	ucl_object_iter_t	 it, rit;
	int			 n;

	n = 0;
	it = NULL;
	while ((g = ucl_object_iterate(list_of("groups"), &it, true)) != NULL) {
		rit = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(g, "roles"), &rit,
		    true)) != NULL)
			if (strcmp(ucl_object_tostring_forced(e), role) == 0) {
				n++;
				break;
			}
	}
	return (n);
}

static bool
in_group(const ucl_object_t *u, const char *group)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(u, "groups"), &it,
	    true)) != NULL)
		if (strcmp(ucl_object_tostring_forced(e), group) == 0)
			return (true);
	return (false);
}

/* Its members' names, as a list. */
static ucl_object_t *
group_members(const char *group)
{
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;
	ucl_object_t		*a;

	a = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((u = ucl_object_iterate(list_of("users"), &it, true)) != NULL)
		if (in_group(u, group))
			ucl_array_append(a, ucl_object_fromstring(ucl_str(u,
			    "name")));
	return (a);
}

/* How many users are owners, as their roles stand. */
static int
owners(void)
{
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	while ((u = ucl_object_iterate(list_of("users"), &it, true)) != NULL)
		if (user_console(ucl_str(u, "name")) == CROLE_OWNER)
			n++;
	return (n);
}

/* How many users of a tenant have roles that say owner: a change that
 * makes more is refused (user_check() for the user's own). */
static int
tenant_owners(void)
{
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	while ((u = ucl_object_iterate(list_of("users"), &it, true)) != NULL)
		if (ucl_str(u, "tenant") != NULL && ucl_str(u, "tenant")[0] !=
		    '\0' && crole_roles(u) == CROLE_OWNER)
			n++;
	return (n);
}

/*
 * The roles given by a directory group, and the groups: into names and
 * groups, max at most; how many.  Good while the users are not changed.
 */
int
roles_ldap_groups(const char **names, const char **groups, int max)
{
	const ucl_object_t	*r;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	while (n < max && (r = ucl_object_iterate(list_of("roles"), &it, true))
	    != NULL)
		if (ucl_str(r, "ldap_group") != NULL && ucl_str(r,
		    "ldap_group")[0] != '\0') {
			names[n] = ucl_str(r, "name");
			groups[n++] = ucl_str(r, "ldap_group");
		}
	return (n);
}

/*
 * A directory's user signed in, with the roles its groups gave: a user
 * of the console the directory keeps (source ldap) is made, or its
 * roles brought up to date, or, given none, taken away, so that the
 * sign-in is limited as before; one the owner made is left as it is.
 */
void
users_ldap_sync(const char *name, const char **roles, int nroles)
{
	const ucl_object_t	*old;
	ucl_object_t		*u, *ra;
	char			 id[USER_ID_LEN];
	int			 i;

	if (!user_name_ok(name) || user_name_reserved(name))
		return;
	old = by_name("users", name);
	if (old != NULL && (ucl_str(old, "source") == NULL || strcmp(ucl_str(
	    old, "source"), "ldap") != 0))
		return;
	/* The same user as before, its id kept. */
	if (old == NULL || ucl_str(old, "id") == NULL || !name_copy(id,
	    sizeof(id), ucl_str(old, "id")))
		uid_new(id, sizeof(id));
	if (old != NULL)
		ucl_object_unref(ucl_array_delete(list_of("users"), (ucl_object_t *)
		    (uintptr_t)old));
	if (nroles > 0) {
		u = ucl_object_typed_new(UCL_OBJECT);
		put(u, "name", ucl_object_fromstring(name));
		put(u, "id", ucl_object_fromstring(id));
		put(u, "source", ucl_object_fromstring("ldap"));
		ra = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < nroles; i++)
			ucl_array_append(ra, ucl_object_fromstring(roles[i]));
		put(u, "roles", ra);
		put(u, "created", ucl_object_fromint(time(NULL)));
		ucl_array_append(list_of("users"), u);
	}
	if (old != NULL || nroles > 0)
		(void)users_save();
}

/* ---- Passwords ---------------------------------------------------- */

#define	BCRYPT_COST	"12"		/* 2^12 rounds: a quarter second */

/* A bcrypt hash of pw, in out ("$2b$12$" and 53 more), or false. */
static bool
pw_hash(const char *pw, char *out, size_t len)
{
	static const char	alphabet[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789";
	struct crypt_data	cd;
	uint8_t			r[22];
	char			salt[40];
	const char		*h;
	size_t			i;
	bool			ok;

	arc4random_buf(r, sizeof(r));
	snprintf(salt, sizeof(salt), "$2b$%s$", BCRYPT_COST);
	for (i = 0; i < sizeof(r); i++)
		salt[7 + i] = alphabet[r[i] & 0x3f];
	salt[7 + sizeof(r)] = '\0';
	memset(&cd, 0, sizeof(cd));
	/* The hash is in cd: copied out before cd is wiped. */
	h = crypt_r(pw, salt, &cd);
	ok = h != NULL && strncmp(h, "$2b$", 4) == 0 && strlen(h) < len;
	if (ok)
		snprintf(out, len, "%s", h);
	explicit_bzero(&cd, sizeof(cd));
	return (ok);
}

/* A user's hash, or NULL: none, or one the directory keeps. */
static const char *
pw_of(const char *name)
{
	const ucl_object_t	*u;
	const char		*h;

	if ((u = by_name("users", name)) == NULL || ((h = ucl_str(u,
	    "password")) == NULL) || strncmp(h, "$2b$", 4) != 0)
		return (NULL);
	return (h);
}

bool
user_has_password(const char *name)
{

	return (name != NULL && pw_of(name) != NULL);
}

/*
 * Is pw the user's password?  One with none is compared all the same,
 * with a hash of nothing, so the time taken says not which users have
 * one.  From any thread (a sign-in's task): by what acl_publish() made.
 */
bool
user_password_ok(const char *name, const char *pw)
{
	static const char	 none[] = "$2b$" BCRYPT_COST "$"
	    "......................" "...............................";
	struct crypt_data	 cd;
	const ucl_object_t	*snap;
	const char		*want, *got, *h;
	char			 hash[128];
	bool			 ok;

	want = NULL;
	if (name != NULL && (snap = acl_get()) != NULL) {
		acl_in = snap;
		if ((h = pw_of(name)) != NULL && strlen(h) < sizeof(hash)) {
			snprintf(hash, sizeof(hash), "%s", h);
			want = hash;
		}
		acl_in = NULL;
		acl_put(snap);
	}
	if (pw == NULL || strlen(pw) > PASSWORD_MAX)
		pw = "";
	memset(&cd, 0, sizeof(cd));
	got = crypt_r(pw, want != NULL ? want : none, &cd);
	ok = want != NULL && got != NULL && strlen(got) == strlen(want) &&
	    timingsafe_bcmp(got, want, strlen(want)) == 0;
	explicit_bzero(&cd, sizeof(cd));
	explicit_bzero(hash, sizeof(hash));
	return (ok);
}

/* Does any user have one?  The sign-in page then asks for it. */
bool
users_any_password(void)
{
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((u = ucl_object_iterate(list_of("users"), &it, true)) != NULL)
		if (pw_of(ucl_str(u, "name")) != NULL)
			return (true);
	return (false);
}

/* Is pw a password that may be kept?  NULL, or what is wrong. */
const char *
user_password_check(const char *pw)
{
	size_t	i, n;

	if (pw == NULL || pw[0] == '\0')
		return ("a password, please");
	n = strlen(pw);
	if (n > PASSWORD_MAX)
		return ("a password is " __XSTRING(PASSWORD_MAX)
		    " bytes at most (bcrypt reads no more)");
	for (i = 0; i < n; i++)
		if ((unsigned char)pw[i] < 0x20 || pw[i] == 0x7f)
			return ("a password has no control characters");
	/* Characters, not bytes: a UTF-8 one counts once. */
	for (i = n = 0; pw[i] != '\0'; i++)
		if (((unsigned char)pw[i] & 0xc0) != 0x80)
			n++;
	if (n < PASSWORD_MIN)
		return ("a password is " __XSTRING(PASSWORD_MIN)
		    " characters at least");
	return (NULL);
}

/*
 * pw's bcrypt hash into out of len, "" for none (pw NULL or ""): NULL,
 * or what is wrong.  From any thread: a task's, bcrypt takes its time.
 */
const char *
user_password_hash(const char *pw, char *out, size_t len)
{
	const char	*e;

	out[0] = '\0';
	if (pw == NULL || pw[0] == '\0')
		return (NULL);
	if ((e = user_password_check(pw)) != NULL)
		return (e);
	if (!pw_hash(pw, out, len))
		return ("crypt(3) made no bcrypt hash");
	return (NULL);
}

/*
 * The user's password set to the hash user_password_hash() made, or
 * taken away when it is "".  NULL when kept, or what is wrong.
 */
const char *
user_password_set(const char *name, const char *hash)
{
	const ucl_object_t	*old;
	ucl_object_t		*u;

	if ((old = by_name("users", name)) == NULL)
		return ("no such user");
	if (ucl_str(old, "source") != NULL && strcmp(ucl_str(old, "source"),
	    "ldap") == 0)
		return ("a user the directory keeps signs in with the "
		    "directory's password");
	if (hash[0] != '\0' && strncmp(hash, "$2b$", 4) != 0)
		return ("crypt(3) made no bcrypt hash");
	u = ucl_object_copy(old);
	if (hash[0] != '\0')
		put(u, "password", ucl_object_fromstring(hash));
	else
		ucl_object_delete_key(u, "password");
	ucl_object_unref(ucl_array_delete(list_of("users"), (ucl_object_t *)
	    (uintptr_t)old));
	ucl_array_append(list_of("users"), u);
	if (users_save() != 0)
		return ("the users could not be written");
	return (NULL);
}

/*
 * An owner of the console named name, made at its setup by password
 * (auth.c) when it is not the built-in admin: NULL when there is one,
 * or what is wrong.
 */
const char *
user_owner_add(const char *name)
{
	ucl_object_t	*u, *roles;

	if (!user_name_ok(name))
		return ("a user name is 1 to 64 letters, digits and _ . @ -");
	if (by_name("users", name) == NULL && user_name_reserved(name))
		return ("that name is what a host is told the console or a "
		    "read token is: no user's name");
	if (by_name("users", name) != NULL)
		return (user_console(name) == CROLE_OWNER ? NULL : "that user "
		    "is no owner of the console");
	if (ucl_array_size(list_of("users")) >= USERS_MAX)
		return ("too many users");
	u = ucl_object_typed_new(UCL_OBJECT);
	put(u, "name", ucl_object_fromstring(name));
	{
		char	id[USER_ID_LEN];

		uid_new(id, sizeof(id));
		put(u, "id", ucl_object_fromstring(id));
	}
	roles = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(roles, ucl_object_fromstring("owner"));
	put(u, "roles", roles);
	put(u, "created", ucl_object_fromint(time(NULL)));
	ucl_array_append(list_of("users"), u);
	if (users_save() != 0) {
		ucl_object_unref(ucl_array_delete(list_of("users"), u));
		return ("the users could not be written");
	}
	return (NULL);
}

/* The owner user_owner_add() made, gone again: its password was not
 * kept.  It has no keys, sessions or invitations yet. */
void
user_owner_undo(const char *name)
{
	const ucl_object_t	*u;

	if ((u = by_name("users", name)) == NULL)
		return;
	ucl_object_unref(ucl_array_delete(list_of("users"), (ucl_object_t *)
	    (uintptr_t)u));
	(void)users_save();
}

/* Is body a role that may be kept?  NULL, or what is wrong with it. */
static const char *
role_check(const ucl_object_t *body)
{
	const ucl_object_t	*h, *v;
	ucl_object_iter_t	 it;
	const char		*s;
	size_t			 i;

	/* A directory group's DN: printable, an attribute=value in it. */
	if ((s = ucl_str(body, "ldap_group")) != NULL && s[0] != '\0') {
		if (strlen(s) > 500 || strchr(s, '=') == NULL)
			return ("ldap_group is a group's DN, cn=noc,ou=groups,"
			    "dc=example,dc=org");
		for (i = 0; s[i] != '\0'; i++)
			if ((unsigned char)s[i] < 0x20 || s[i] == 0x7f)
				return ("ldap_group has no control characters");
	}

	if ((s = ucl_str(body, "console")) != NULL && strcmp(s, "owner") != 0 &&
	    strcmp(s, "operator") != 0 && strcmp(s, "member") != 0)
		return ("console is owner, operator or member");
	if ((h = ucl_object_lookup(body, "hosts")) != NULL) {
		if (ucl_object_type(h) != UCL_OBJECT)
			return ("hosts is an object: a role by host id, or \"*\"");
		it = NULL;
		while ((v = ucl_object_iterate(h, &it, true)) != NULL) {
			if (ucl_object_type(v) != UCL_STRING || role_of(
			    ucl_object_tostring(v)) == ROLE_NONE)
				return ("a host's role is viewer, operator or admin");
			if (strcmp(ucl_object_key(v), "*") != 0 && (strlen(
			    ucl_object_key(v)) != 8 || strspn(ucl_object_key(v),
			    "0123456789abcdef") != 8))
				return ("a host is named by its id, or \"*\" for all");
		}
	}
	return (NULL);
}

/* Is body a user that may be kept?  NULL, or what is wrong with it. */
static const char *
user_check(const ucl_object_t *body)
{
	const ucl_object_t	*v, *g, *e;
	ucl_object_iter_t	 it;
	const char		*s;

	if ((s = ucl_str(body, "tenant")) != NULL && s[0] != '\0' &&
	    !user_name_ok(s))
		return ("a tenant is named by letters, digits, _ . @ and -, 64 "
		    "at most");
	if ((v = ucl_object_lookup(body, "roles")) != NULL && ucl_object_type(v)
	    != UCL_ARRAY)
		return ("roles is a list of the roles");
	it = NULL;
	while ((e = ucl_object_iterate(v, &it, true)) != NULL)
		if (ucl_object_type(e) != UCL_STRING || by_name("roles",
		    ucl_object_tostring(e)) == NULL)
			return ("a role named is one there is");
	if ((g = ucl_object_lookup(body, "groups")) != NULL && ucl_object_type(g)
	    != UCL_ARRAY)
		return ("groups is a list of the groups");
	it = NULL;
	while ((e = ucl_object_iterate(g, &it, true)) != NULL)
		if (ucl_object_type(e) != UCL_STRING || by_name("groups",
		    ucl_object_tostring(e)) == NULL)
			return ("a group named is one there is");
	if ((v == NULL || ucl_array_size(v) == 0) && (g == NULL ||
	    ucl_array_size(g) == 0))
		return ("a user has a role, or is in a group, one at least");
	/* The console's own are every tenant's: no tenant's user owns it. */
	if ((s = ucl_str(body, "tenant")) != NULL && s[0] != '\0' &&
	    crole_roles(body) == CROLE_OWNER)
		return ("a tenant's user is no owner of the console: its "
		    "tokens, users and settings are every tenant's");
	return (NULL);
}

/* Why a change is refused: its HTTP status, an error code, words. */
struct uerr {
	int		 status;
	const char	*code;
	char		 why[160];
};

static int
refuse(struct uerr *e, int status, const char *code, const char *fmt, ...)
{
	va_list	ap;

	e->status = status;
	e->code = code;
	va_start(ap, fmt);
	vsnprintf(e->why, sizeof(e->why), fmt, ap);
	va_end(ap);
	return (status);
}

/* users.json as it is kept, again: what was changed in udoc undone. */
static void
undo(void)
{

	ucl_object_unref(udoc);
	udoc = NULL;
	users_init();
}

/* users.json written: 0, or 500 and why.  arcana-console's users, roles
 * and groups (each says the others') changed. */
static int
keep(struct uerr *e, const char *what)
{

	if (users_save() != 0)
		return (refuse(e, 500, "store", "the %s could not be written",
		    what));
	cyang_changed("users");
	cyang_changed("roles");
	cyang_changed("groups");
	return (0);
}

/* A role kept, added or in place of the one of the name; body is taken.
 * 0, or the status and why. */
static int
role_keep(ucl_object_t *body, const char *who, struct uerr *err)
{
	ucl_object_t		*r;
	const ucl_object_t	*old;
	const char		*e, *name;
	char			 kept[USER_NAME_LEN];	/* the body's name */
	bool			 was_owner;
	int			 tenanted;

	name = ucl_str(body, "name");
	if (!user_name_ok(name)) {
		ucl_object_unref(body);
		return (refuse(err, 400, "invalid", "a role is named by "
		    "letters, digits, _ . @ and -, 64 at most"));
	}
	if ((e = role_check(body)) != NULL) {
		refuse(err, 400, "invalid", "%s", e);
		ucl_object_unref(body);
		return (400);
	}
	strlcpy(kept, name, sizeof(kept));
	old = by_name("roles", name);
	if (old == NULL && ucl_array_size(list_of("roles")) >= ROLES_MAX) {
		ucl_object_unref(body);
		return (refuse(err, 400, "invalid", "%d roles at most",
		    ROLES_MAX));
	}
	r = role_new(name, ucl_str(body, "console") != NULL ? ucl_str(body,
	    "console") : "member", NULL);
	if (ucl_object_lookup(body, "hosts") != NULL)
		put(r, "hosts", ucl_object_copy(ucl_object_lookup(body, "hosts")));
	if (ucl_str(body, "ldap_group") != NULL && ucl_str(body,
	    "ldap_group")[0] != '\0')
		put(r, "ldap_group", ucl_object_fromstring(ucl_str(body,
		    "ldap_group")));
	if (old != NULL && ucl_object_lookup(old, "created") != NULL)
		put(r, "created", ucl_object_fromint(ucl_object_toint(
		    ucl_object_lookup(old, "created"))));
	ucl_object_unref(body);
	/* Changed so that no owner is left: refused. */
	was_owner = old != NULL && crole_of(ucl_str(old, "console")) ==
	    CROLE_OWNER;
	tenanted = tenant_owners();
	if (old != NULL)
		ucl_object_unref(ucl_array_delete(list_of("roles"),
		    (ucl_object_t *)(uintptr_t)old));
	ucl_array_append(list_of("roles"), r);
	if (was_owner && owners() == 0) {
		undo();
		return (refuse(err, 409, "last_owner", "the console keeps an "
		    "owner: this role is what makes the last one"));
	}
	if (tenant_owners() > tenanted) {
		undo();
		return (refuse(err, 409, "tenant", "a tenant's user has this "
		    "role: no tenant's user owns the console"));
	}
	if (keep(err, "roles") != 0)
		return (500);
	log_msg(LOG_NOTICE, "role %s %s by %s", kept, old != NULL ? "changed" :
	    "added", who != NULL ? who : "?");
	return (0);
}

/* A user kept, added or in place of the one of the name; body is taken.
 * 0, or the status and why. */
static int
user_keep(ucl_object_t *body, const char *who, struct uerr *err)
{
	ucl_object_t		*u;
	const ucl_object_t	*old;
	const char		*e, *name;
	char			 kept[USER_NAME_LEN];	/* the body's name */
	char			 id[USER_ID_LEN];
	bool			 was_owner;
	int			 tenanted;

	name = ucl_str(body, "name");
	if (!user_name_ok(name)) {
		ucl_object_unref(body);
		return (refuse(err, 400, "invalid", "a user is named by "
		    "letters, digits, _ . @ and -, 64 at most"));
	}
	if ((e = user_check(body)) != NULL) {
		refuse(err, 400, "invalid", "%s", e);
		ucl_object_unref(body);
		return (400);
	}
	strlcpy(kept, name, sizeof(kept));
	old = by_name("users", name);
	if (old == NULL && user_name_reserved(name)) {
		ucl_object_unref(body);
		return (refuse(err, 400, "invalid", "%s is what a host is told "
		    "the console or a read token is: no user's name", kept));
	}
	if (old == NULL && ucl_array_size(list_of("users")) >= USERS_MAX) {
		ucl_object_unref(body);
		return (refuse(err, 400, "invalid", "%d users at most",
		    USERS_MAX));
	}
	/*
	 * A user the directory keeps is the directory's: made a local one
	 * by an edit, the directory's account of the name would sign in as
	 * it.  An owner who wants the name for a local user removes the
	 * directory's first, and makes it again.
	 */
	if (old != NULL && user_ldap(name)) {
		ucl_object_unref(body);
		return (refuse(err, 409, "directory", "user %s is the "
		    "directory's, its roles its groups': remove it first to make "
		    "a local user of the name", kept));
	}
	was_owner = old != NULL && user_console(name) == CROLE_OWNER;
	tenanted = tenant_owners();
	/* The same user: its id kept; a new one, its own. */
	if (old == NULL || ucl_str(old, "id") == NULL || !name_copy(id,
	    sizeof(id), ucl_str(old, "id")))
		uid_new(id, sizeof(id));
	u = ucl_object_typed_new(UCL_OBJECT);
	put(u, "name", ucl_object_fromstring(name));
	put(u, "id", ucl_object_fromstring(id));
	if (ucl_str(body, "tenant") != NULL && ucl_str(body, "tenant")[0] != '\0')
		put(u, "tenant", ucl_object_fromstring(ucl_str(body, "tenant")));
	put(u, "roles", ucl_object_lookup(body, "roles") != NULL ?
	    ucl_object_copy(ucl_object_lookup(body, "roles")) :
	    ucl_object_typed_new(UCL_ARRAY));
	if (ucl_object_lookup(body, "groups") != NULL &&
	    ucl_array_size(ucl_object_lookup(body, "groups")) > 0)
		put(u, "groups", ucl_object_copy(ucl_object_lookup(body,
		    "groups")));
	put(u, "created", ucl_object_fromint(old != NULL && ucl_object_lookup(
	    old, "created") != NULL ? ucl_object_toint(ucl_object_lookup(old,
	    "created")) : time(NULL)));
	/* Its password is set apart (auth.c), and kept through an edit. */
	if (old != NULL && pw_of(name) != NULL)
		put(u, "password", ucl_object_fromstring(pw_of(name)));
	ucl_object_unref(body);
	if (old != NULL)
		ucl_object_unref(ucl_array_delete(list_of("users"), (ucl_object_t *)
		    (uintptr_t)old));
	ucl_array_append(list_of("users"), u);
	/* The last owner stays one. */
	if (was_owner && owners() == 0) {
		undo();
		return (refuse(err, 409, "last_owner", "the console keeps an "
		    "owner: make another one first"));
	}
	if (tenant_owners() > tenanted) {
		undo();
		return (refuse(err, 409, "tenant", "a tenant's user is no owner "
		    "of the console"));
	}
	if (keep(err, "users") != 0)
		return (500);
	log_msg(LOG_NOTICE, "user %s %s by %s", kept, old != NULL ? "changed" :
	    "added", who != NULL ? who : "?");
	return (0);
}

/* User name gone, with its keys, invitations, sessions and console
 * plugins' stores: 0, or the status and why. */
static int
user_remove(const char *name, const char *who, struct uerr *err)
{
	const ucl_object_t	*u;

	if ((u = by_name("users", name)) == NULL)
		return (refuse(err, 404, "not_found", "no user %s", name));
	if (user_console(name) == CROLE_OWNER && owners() == 1)
		return (refuse(err, 409, "last_owner", "the console keeps an "
		    "owner: make another one first"));
	ucl_object_unref(ucl_array_delete(list_of("users"), (ucl_object_t *)
	    (uintptr_t)u));
	invites_drop(name);
	if (keep(err, "users") != 0)
		return (500);
	creds_forget_user(name);
	sessions_end_user(name);
	cplug_store_forget(name);
	log_msg(LOG_NOTICE, "user %s removed by %s", name, who != NULL ? who :
	    "?");
	return (0);
}

/* Role name gone, when no user has it and no group gives it. */
static int
role_remove(const char *name, const char *who, struct uerr *err)
{
	const ucl_object_t	*r;

	if ((r = by_name("roles", name)) == NULL)
		return (refuse(err, 404, "not_found", "no role %s", name));
	if (role_users(name) > 0)
		return (refuse(err, 409, "in_use", "%d user%s ha%s the role: "
		    "give them another first", role_users(name), role_users(name)
		    == 1 ? "" : "s", role_users(name) == 1 ? "s" : "ve"));
	if (role_groups(name) > 0)
		return (refuse(err, 409, "in_use", "%d group%s give%s the "
		    "role: take it from them first", role_groups(name),
		    role_groups(name) == 1 ? "" : "s", role_groups(name) == 1 ?
		    "s" : ""));
	ucl_object_unref(ucl_array_delete(list_of("roles"), (ucl_object_t *)
	    (uintptr_t)r));
	if (keep(err, "roles") != 0)
		return (500);
	log_msg(LOG_NOTICE, "role %s removed by %s", name, who != NULL ? who :
	    "?");
	return (0);
}

/* An invitation for user name, said once into token, with when it runs
 * out: 0, or the status and why. */
static int
user_invite(const char *name, const char *who, char *token, size_t len,
    time_t *expires, struct uerr *err)
{

	if (!user_exists(name))
		return (refuse(err, 404, "not_found", "no such user"));
	invites_drop(NULL);
	if (!invite_make(name, token, len))
		return (refuse(err, 500, "store", "the invitation could not be "
		    "written"));
	*expires = time(NULL) + INVITE_LIFE;
	cyang_changed("users");
	log_msg(LOG_NOTICE, "user %s invited by %s", name, who != NULL ? who :
	    "?");
	return (0);
}

/* Is body a group that may be kept?  NULL, or what is wrong with it. */
static const char *
group_check(const ucl_object_t *body)
{
	const ucl_object_t	*v, *e;
	ucl_object_iter_t	 it;

	if ((v = ucl_object_lookup(body, "roles")) == NULL || ucl_object_type(v)
	    != UCL_ARRAY)
		return ("roles is a list of the roles the group gives");
	it = NULL;
	while ((e = ucl_object_iterate(v, &it, true)) != NULL)
		if (ucl_object_type(e) != UCL_STRING || by_name("roles",
		    ucl_object_tostring(e)) == NULL)
			return ("a role named is one there is");
	if ((v = ucl_object_lookup(body, "members")) != NULL) {
		if (ucl_object_type(v) != UCL_ARRAY)
			return ("members is a list of the users in it");
		it = NULL;
		while ((e = ucl_object_iterate(v, &it, true)) != NULL)
			if (ucl_object_type(e) != UCL_STRING || by_name("users",
			    ucl_object_tostring(e)) == NULL)
				return ("a member named is a user there is");
	}
	if ((e = ucl_object_lookup(body, "description")) != NULL &&
	    (ucl_object_type(e) != UCL_STRING || strlen(ucl_object_tostring(e))
	    > 200))
		return ("a description is 200 characters at most");
	return (NULL);
}

/* The user in the group, or not. */
static void
membership(const char *user, const char *group, bool in)
{
	ucl_object_t		*u, *gs, *e;
	ucl_object_iter_t	 it;

	if ((u = (ucl_object_t *)(uintptr_t)by_name("users", user)) == NULL)
		return;
	if ((gs = (ucl_object_t *)(uintptr_t)ucl_object_lookup(u, "groups")) ==
	    NULL) {
		if (!in)
			return;
		gs = ucl_object_typed_new(UCL_ARRAY);
		put(u, "groups", gs);
	}
	it = NULL;
	while ((e = (ucl_object_t *)(uintptr_t)ucl_object_iterate(gs, &it,
	    true)) != NULL)
		if (strcmp(ucl_object_tostring_forced(e), group) == 0) {
			if (in)
				return;
			ucl_object_unref(ucl_array_delete(gs, e));
			break;
		}
	if (in)
		ucl_array_append(gs, ucl_object_fromstring(group));
}

/* Undone, as users.json still has it, with why: the last owner stays. */
static int
undo_owner(struct uerr *err)
{

	undo();
	return (refuse(err, 409, "last_owner", "the console keeps an owner: "
	    "make another one first"));
}

/*
 * A group kept, added or in place of the one of the name; its members,
 * when they are named, made those; body is taken.  0, or the status and
 * why.
 */
static int
group_keep(ucl_object_t *body, const char *who, struct uerr *err)
{
	ucl_object_t		*g;
	const ucl_object_t	*old, *m, *u, *e;
	ucl_object_iter_t	 it, mit;
	const char		*bad, *name;
	char			 kept[USER_NAME_LEN];	/* the body's name */
	bool			 named;
	int			 tenanted;

	tenanted = tenant_owners();
	name = ucl_str(body, "name");
	if (!user_name_ok(name)) {
		ucl_object_unref(body);
		return (refuse(err, 400, "invalid", "a group is named by "
		    "letters, digits, _ . @ and -, 64 at most"));
	}
	if ((bad = group_check(body)) != NULL) {
		refuse(err, 400, "invalid", "%s", bad);
		ucl_object_unref(body);
		return (400);
	}
	strlcpy(kept, name, sizeof(kept));
	old = by_name("groups", name);
	if (old == NULL && ucl_array_size(list_of("groups")) >= GROUPS_MAX) {
		ucl_object_unref(body);
		return (refuse(err, 400, "invalid", "%d groups at most",
		    GROUPS_MAX));
	}
	g = ucl_object_typed_new(UCL_OBJECT);
	put(g, "name", ucl_object_fromstring(name));
	put(g, "roles", ucl_object_copy(ucl_object_lookup(body, "roles")));
	if (ucl_str(body, "description") != NULL && ucl_str(body,
	    "description")[0] != '\0')
		put(g, "description", ucl_object_fromstring(ucl_str(body,
		    "description")));
	if (old != NULL)
		ucl_object_unref(ucl_array_delete(list_of("groups"),
		    (ucl_object_t *)(uintptr_t)old));
	ucl_array_append(list_of("groups"), g);
	if ((m = ucl_object_lookup(body, "members")) != NULL) {
		it = NULL;
		while ((u = ucl_object_iterate(list_of("users"), &it, true)) !=
		    NULL) {
			named = false;
			mit = NULL;
			while ((e = ucl_object_iterate(m, &mit, true)) != NULL)
				if (strcmp(ucl_object_tostring(e), ucl_str(u,
				    "name")) == 0)
					named = true;
			membership(ucl_str(u, "name"), name, named);
		}
	}
	ucl_object_unref(body);
	/* The last owner stays one, whatever a group's roles became. */
	if (owners() == 0)
		return (undo_owner(err));
	if (tenant_owners() > tenanted) {
		undo();
		return (refuse(err, 409, "tenant", "a tenant's user is in the "
		    "group: no tenant's user owns the console"));
	}
	if (keep(err, "groups") != 0)
		return (500);
	log_msg(LOG_NOTICE, "group %s %s by %s", kept, old != NULL ? "changed" :
	    "added", who != NULL ? who : "?");
	return (0);
}

/* Group name gone, its users out of it. */
static int
group_remove(const char *name, const char *who, struct uerr *err)
{
	const ucl_object_t	*g, *u;
	ucl_object_iter_t	 it;

	if ((g = by_name("groups", name)) == NULL)
		return (refuse(err, 404, "not_found", "no group %s", name));
	it = NULL;
	while ((u = ucl_object_iterate(list_of("users"), &it, true)) != NULL)
		membership(ucl_str(u, "name"), name, false);
	ucl_object_unref(ucl_array_delete(list_of("groups"), (ucl_object_t *)
	    (uintptr_t)g));
	if (owners() == 0)
		return (undo_owner(err));
	if (keep(err, "groups") != 0)
		return (500);
	log_msg(LOG_NOTICE, "group %s removed by %s", name, who != NULL ? who :
	    "?");
	return (0);
}

/* ---- arcana-console's users, roles and groups (cyang.c) -------------- */

static void
strings_into(ucl_object_t *o, const char *key, const ucl_object_t *a)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*l;

	l = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(a, &it, true)) != NULL)
		ucl_array_append(l, ucl_object_fromstring(
		    ucl_object_tostring_forced(e)));
	if (ucl_array_size(l) > 0)
		put(o, key, l);
	else
		ucl_object_unref(l);
}

/* arcana-console:users's value, as one of tenant (""  none: every
 * user) may see it: that tenant's users alone, their invitations
 * with them. */
ucl_object_t *
users_yang(const char *tenant)
{
	ucl_object_t		*o, *a, *e;
	const ucl_object_t	*u, *inv, *v;
	ucl_object_iter_t	 it, iit;
	const char		*name;
	int			 n;

	a = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((u = ucl_object_iterate(list_of("users"), &it, true)) != NULL) {
		if ((name = ucl_str(u, "name")) == NULL)
			continue;
		if (tenant != NULL && tenant[0] != '\0' && (ucl_str(u,
		    "tenant") == NULL || strcmp(ucl_str(u, "tenant"), tenant) !=
		    0))
			continue;
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "name", ucl_object_fromstring(name));
		if (ucl_str(u, "tenant") != NULL && ucl_str(u, "tenant")[0] !=
		    '\0')
			put(e, "tenant", ucl_object_fromstring(ucl_str(u,
			    "tenant")));
		strings_into(e, "role", ucl_object_lookup(u, "roles"));
		strings_into(e, "group", ucl_object_lookup(u, "groups"));
		if ((v = ucl_object_lookup(u, "created")) != NULL)
			put(e, "created", yang_time((double)ucl_object_toint(v)));
		put(e, "console-role", ucl_object_fromstring(crole_name(
		    user_console(name))));
		put(e, "keys", ucl_object_fromint(cred_count_of(name)));
		n = 0;
		iit = NULL;
		while ((inv = ucl_object_iterate(list_of("invites"), &iit,
		    true)) != NULL)
			if (ucl_str(inv, "user") != NULL && strcmp(ucl_str(inv,
			    "user"), name) == 0)
				n++;
		put(e, "invitations", ucl_object_fromint(n));
		put(e, "has-password", ucl_object_frombool(pw_of(name) !=
		    NULL));
		if (ucl_str(u, "source") != NULL && strcmp(ucl_str(u,
		    "source"), "ldap") == 0)
			put(e, "from-directory", ucl_object_frombool(true));
		ucl_array_append(a, e);
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "user", a);
	return (o);
}

/* arcana-console:roles's value. */
ucl_object_t *
roles_yang(void)
{
	ucl_object_t		*o, *a, *e, *hs, *h;
	const ucl_object_t	*r, *v;
	ucl_object_iter_t	 it, hit;
	const char		*name;

	a = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((r = ucl_object_iterate(list_of("roles"), &it, true)) != NULL) {
		if ((name = ucl_str(r, "name")) == NULL)
			continue;
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "name", ucl_object_fromstring(name));
		put(e, "console", ucl_object_fromstring(ucl_str(r, "console") !=
		    NULL ? ucl_str(r, "console") : "member"));
		hs = ucl_object_typed_new(UCL_ARRAY);
		hit = NULL;
		while ((v = ucl_object_iterate(ucl_object_lookup(r, "hosts"),
		    &hit, true)) != NULL) {
			h = ucl_object_typed_new(UCL_OBJECT);
			put(h, "id", ucl_object_fromstring(ucl_object_key(v)));
			put(h, "role", ucl_object_fromstring(
			    ucl_object_tostring_forced(v)));
			ucl_array_append(hs, h);
		}
		if (ucl_array_size(hs) > 0)
			put(e, "host", hs);
		else
			ucl_object_unref(hs);
		if (ucl_str(r, "ldap_group") != NULL && ucl_str(r,
		    "ldap_group")[0] != '\0')
			put(e, "ldap-group", ucl_object_fromstring(ucl_str(r,
			    "ldap_group")));
		if ((v = ucl_object_lookup(r, "created")) != NULL)
			put(e, "created", yang_time((double)ucl_object_toint(v)));
		put(e, "users", ucl_object_fromint(role_users(name)));
		put(e, "groups", ucl_object_fromint(role_groups(name)));
		ucl_array_append(a, e);
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "role", a);
	return (o);
}

/* arcana-console:groups's value. */
ucl_object_t *
groups_yang(void)
{
	ucl_object_t		*o, *a, *e, *m;
	const ucl_object_t	*g;
	ucl_object_iter_t	 it;
	const char		*name;

	a = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((g = ucl_object_iterate(list_of("groups"), &it, true)) != NULL) {
		if ((name = ucl_str(g, "name")) == NULL)
			continue;
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "name", ucl_object_fromstring(name));
		strings_into(e, "role", ucl_object_lookup(g, "roles"));
		if (ucl_str(g, "description") != NULL && ucl_str(g,
		    "description")[0] != '\0')
			put(e, "description", ucl_object_fromstring(ucl_str(g,
			    "description")));
		m = group_members(name);
		strings_into(e, "member", m);
		ucl_object_unref(m);
		ucl_array_append(a, e);
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "group", a);
	return (o);
}

/* list's entry named name; NULL: none. */
static const ucl_object_t *
entry_of(const ucl_object_t *list, const char *name)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;

	while ((e = ucl_object_iterate(list, &it, true)) != NULL)
		if (ucl_str(e, "name") != NULL && strcmp(ucl_str(e, "name"),
		    name) == 0)
			return (e);
	return (NULL);
}

/* Whether a and b have the same at each of keys. */
static bool
same_at(const ucl_object_t *a, const ucl_object_t *b,
    const char *const *keys)
{
	const ucl_object_t	*x, *y;

	for (; *keys != NULL; keys++) {
		x = ucl_object_lookup(a, *keys);
		y = ucl_object_lookup(b, *keys);
		if ((x == NULL) != (y == NULL) || (x != NULL &&
		    ucl_object_compare(x, y) != 0))
			return (false);
	}
	return (true);
}

/* A string list of o's key, or an empty one. */
static ucl_object_t *
strings_of(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	v = ucl_object_lookup(o, key);
	return (v != NULL ? ucl_object_copy(v) : ucl_object_typed_new(
	    UCL_ARRAY));
}

/*
 * arcana-console's users, roles and groups changed from was to now
 * (each the value of the three, as {"users": ..., "roles": ...,
 * "groups": ...}): each entry made or changed kept, each left out
 * removed, through the stores' setters.  All or nothing: what
 * was kept before a refusal undone (but a user's keys and sessions, a
 * user removed being last).  0, or the status and why.
 */
int
users_yang_set(const ucl_object_t *was, const ucl_object_t *now,
    const char *who, const char *tenant, char *why, size_t len)
{
	static const char *const ukeys[] = { "tenant", "role", "group", NULL };
	static const char *const rkeys[] = { "console", "host", "ldap-group",
	    NULL };
	static const char *const gkeys[] = { "role", "description", NULL };
	const ucl_object_t	*e, *o, *h;
	ucl_object_iter_t	 it, hit;
	ucl_object_t		*body, *hs, *saved;
	struct uerr		 err;
	int			 rc = 0;

	/* Who is who, and of which tenant, is an untenanted owner's. */
	if (tenant != NULL && tenant[0] != '\0') {
		snprintf(why, len, "the users, roles and groups are changed by "
		    "an owner of no tenant");
		return (403);
	}
	saved = ucl_object_copy(udoc);
	/* The roles, the groups, then the users made or changed. */
	it = NULL;
	while (rc == 0 && (e = ucl_object_iterate(ucl_object_lookup_path(now,
	    "roles.role"), &it, true)) != NULL) {
		o = entry_of(ucl_object_lookup_path(was, "roles.role"),
		    ucl_str(e, "name"));
		if (o != NULL && same_at(o, e, rkeys))
			continue;
		body = ucl_object_typed_new(UCL_OBJECT);
		put(body, "name", ucl_object_fromstring(ucl_str(e, "name")));
		put(body, "console", ucl_object_fromstring(ucl_str(e,
		    "console") != NULL ? ucl_str(e, "console") : "member"));
		hs = ucl_object_typed_new(UCL_OBJECT);
		hit = NULL;
		while ((h = ucl_object_iterate(ucl_object_lookup(e, "host"),
		    &hit, true)) != NULL)
			put(hs, ucl_str(h, "id"), ucl_object_fromstring(
			    ucl_str(h, "role")));
		put(body, "hosts", hs);
		if (ucl_str(e, "ldap-group") != NULL)
			put(body, "ldap_group", ucl_object_fromstring(ucl_str(e,
			    "ldap-group")));
		rc = role_keep(body, who, &err);
	}
	it = NULL;
	while (rc == 0 && (e = ucl_object_iterate(ucl_object_lookup_path(now,
	    "groups.group"), &it, true)) != NULL) {
		o = entry_of(ucl_object_lookup_path(was, "groups.group"),
		    ucl_str(e, "name"));
		if (o != NULL && same_at(o, e, gkeys))
			continue;
		body = ucl_object_typed_new(UCL_OBJECT);
		put(body, "name", ucl_object_fromstring(ucl_str(e, "name")));
		put(body, "roles", strings_of(e, "role"));
		if (ucl_str(e, "description") != NULL)
			put(body, "description", ucl_object_fromstring(ucl_str(e,
			    "description")));
		rc = group_keep(body, who, &err);
	}
	it = NULL;
	while (rc == 0 && (e = ucl_object_iterate(ucl_object_lookup_path(now,
	    "users.user"), &it, true)) != NULL) {
		o = entry_of(ucl_object_lookup_path(was, "users.user"),
		    ucl_str(e, "name"));
		if (o != NULL && same_at(o, e, ukeys))
			continue;
		body = ucl_object_typed_new(UCL_OBJECT);
		put(body, "name", ucl_object_fromstring(ucl_str(e, "name")));
		if (ucl_str(e, "tenant") != NULL)
			put(body, "tenant", ucl_object_fromstring(ucl_str(e,
			    "tenant")));
		put(body, "roles", strings_of(e, "role"));
		put(body, "groups", strings_of(e, "group"));
		rc = user_keep(body, who, &err);
	}
	/* Then those left out: the users, the groups, the roles. */
	it = NULL;
	while (rc == 0 && (o = ucl_object_iterate(ucl_object_lookup_path(was,
	    "users.user"), &it, true)) != NULL)
		if (entry_of(ucl_object_lookup_path(now, "users.user"),
		    ucl_str(o, "name")) == NULL)
			rc = user_remove(ucl_str(o, "name"), who, &err);
	it = NULL;
	while (rc == 0 && (o = ucl_object_iterate(ucl_object_lookup_path(was,
	    "groups.group"), &it, true)) != NULL)
		if (entry_of(ucl_object_lookup_path(now, "groups.group"),
		    ucl_str(o, "name")) == NULL)
			rc = group_remove(ucl_str(o, "name"), who, &err);
	it = NULL;
	while (rc == 0 && (o = ucl_object_iterate(ucl_object_lookup_path(was,
	    "roles.role"), &it, true)) != NULL)
		if (entry_of(ucl_object_lookup_path(now, "roles.role"),
		    ucl_str(o, "name")) == NULL)
			rc = role_remove(ucl_str(o, "name"), who, &err);
	if (rc != 0) {
		snprintf(why, len, "%s", err.why);
		ucl_object_unref(udoc);
		udoc = saved;
		(void)users_save();
		return (err.status);
	}
	ucl_object_unref(saved);
	return (0);
}

/* The invite action: an invitation for user name, said once.  0, or the
 * status and why. */
int
users_yang_invite(const char *name, const char *who, char *token,
    size_t tlen, time_t *expires, char *why, size_t len)
{
	struct uerr	err;

	if (user_invite(name, who, token, tlen, expires, &err) != 0) {
		snprintf(why, len, "%s", err.why);
		return (err.status);
	}
	return (0);
}
