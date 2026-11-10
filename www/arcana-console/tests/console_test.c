/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The console end to end: arcana-console(8) and an arcana-agent(8) with a
 * stand-in for jail(8), both on sockets in the work directory,
 * driven over HTTP.  The test is its own WebAuthn authenticator: it makes
 * ES256 and Ed25519 keys with libcrypto and builds authenticator data and
 * clientDataJSON byte by byte, the way a security key and a browser do.
 *
 * Configuration variables: arcana-console, arcana-agent (the programs,
 * when not the ones built beside the tests).
 */

#include <sys/param.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <net/if.h>
#include <netinet/in.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <atf-c.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ucl.h>
#include <unistd.h>

#include "harness.h"

/* The page's YANG-CBOR reader (www/arcana-ui/src/ycbor.c). */
ucl_object_t	*ycbor_json(const void *, size_t, const ucl_object_t *,
		    char *, size_t);

/* Does the kernel have SCTP: compiled in, or the module loaded. */
static bool
has_sctp(void)
{
	size_t	len;
	int	have;

	len = sizeof(have);
	if (sysctlbyname("kern.features.sctp", &have, &len, NULL, 0) == 0 &&
	    have != 0)
		return (true);
	return (modfind("sctp") != -1);
}


struct authn {
	EVP_PKEY	*key;
	int		 alg;
	uint8_t		 id[16];
};



/* base64url without padding. */
static char *
b64url(const void *data, size_t len)
{
	char	*out, *p;

	ATF_REQUIRE((out = malloc(4 * ((len + 2) / 3) + 1)) != NULL);
	EVP_EncodeBlock((unsigned char *)out, data, (int)len);
	for (p = out; *p != '\0'; p++) {
		if (*p == '+')
			*p = '-';
		else if (*p == '/')
			*p = '_';
		else if (*p == '=') {
			*p = '\0';
			break;
		}
	}
	return (out);
}

static void
authn_new(struct authn *a, int alg)
{

	a->alg = alg;
	a->key = alg == -7 ? EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256") :
	    EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
	ATF_REQUIRE(a->key != NULL);
	arc4random_buf(a->id, sizeof(a->id));
}

/* rpIdHash | flags | counter [| aaguid | idlen | id | key] */
static size_t
auth_data(uint8_t *ad, const char *rpid, uint8_t flags, uint32_t count,
    const struct authn *a)
{
	unsigned int	mdlen;
	size_t		len;

	EVP_Digest(rpid, strlen(rpid), ad, &mdlen, EVP_sha256(), NULL);
	ad[32] = flags;
	ad[33] = (uint8_t)(count >> 24);
	ad[34] = (uint8_t)(count >> 16);
	ad[35] = (uint8_t)(count >> 8);
	ad[36] = (uint8_t)count;
	len = 37;
	if (a != NULL) {
		memset(ad + len, 0, 16);
		len += 16;
		ad[len++] = 0;
		ad[len++] = sizeof(a->id);
		memcpy(ad + len, a->id, sizeof(a->id));
		len += sizeof(a->id);
		ad[len++] = 0xa0;	/* the COSE key; the server uses SPKI */
	}
	return (len);
}

static char *
client_data(const char *type, const char *challenge, const char *origin)
{
	char	cd[512];

	snprintf(cd, sizeof(cd), "{\"type\":\"%s\",\"challenge\":\"%s\","
	    "\"origin\":\"%s\",\"crossOrigin\":false}", type, challenge,
	    origin);
	return (strdup(cd));
}

/* navigator.credentials.create(), as a browser and a key would do it;
 * token the setup token, or an invitation (inv_...) of a user's. */
static void
do_register(struct authn *a, const char *token, struct resp *r)
{
	struct resp	 b;
	uint8_t		 ad[256], *spki;
	char		 body[4096], *cd, *id64, *cd64, *ad64, *pk64, *p;
	size_t		 adlen;
	int		 spkilen;

	snprintf(body, sizeof(body), "{\"%s\":\"%s\"}", token != NULL &&
	    strncmp(token, "inv_", 4) == 0 ? "invite" : "setup_token", token !=
	    NULL ? token : "");
	http("POST", "/api/auth/register/begin", body, &b);
	EXPECT(&b, 200);
	cd = client_data("webauthn.create", jstr(&b, "publicKey.challenge"),
	    harness_origin);
	adlen = auth_data(ad, RP_ID, 0x41, 0, a);
	spki = NULL;
	ATF_REQUIRE((spkilen = i2d_PUBKEY(a->key, &spki)) > 0);
	id64 = b64url(a->id, sizeof(a->id));
	cd64 = b64url(cd, strlen(cd));
	ad64 = b64url(ad, adlen);
	pk64 = b64url(spki, (size_t)spkilen);
	snprintf(body, sizeof(body), "{\"id\":\"%s\",\"clientDataJSON\":\"%s\","
	    "\"authenticatorData\":\"%s\",\"publicKey\":\"%s\","
	    "\"publicKeyAlgorithm\":%d,\"transports\":[\"usb\"],"
	    "\"name\":\"key %d\"}", id64, cd64, ad64, pk64, a->alg, a->alg);
	http("POST", "/api/auth/register/finish", body, r);
	resp_free(&b);
	p = (char *)spki;
	OPENSSL_free(p);
	free(cd);
	free(id64);
	free(cd64);
	free(ad64);
	free(pk64);
}

/*
 * navigator.credentials.get(): sign authenticatorData || SHA-256 of
 * clientDataJSON.  origin, rpid and the challenge can be wrong on purpose;
 * flip corrupts the signature.
 */
static void
do_login(struct authn *a, uint32_t count, const char *origin,
    const char *rpid, const char *challenge, bool flip, struct resp *r)
{
	struct resp	 b;
	EVP_MD_CTX	*ctx;
	uint8_t		 ad[64], msg[128], sig[256];
	char		 body[4096], *cd, *id64, *cd64, *ad64, *sig64;
	size_t		 adlen, siglen;
	unsigned int	 mdlen;

	http("POST", "/api/auth/login/begin", "{}", &b);
	EXPECT(&b, 200);
	cd = client_data("webauthn.get", challenge != NULL ? challenge :
	    jstr(&b, "publicKey.challenge"), origin);
	adlen = auth_data(ad, rpid, 0x05, count, NULL);
	memcpy(msg, ad, adlen);
	EVP_Digest(cd, strlen(cd), msg + adlen, &mdlen, EVP_sha256(), NULL);
	ATF_REQUIRE((ctx = EVP_MD_CTX_new()) != NULL);
	siglen = sizeof(sig);
	ATF_REQUIRE(EVP_DigestSignInit(ctx, NULL, a->alg == -7 ?
	    EVP_sha256() : NULL, NULL, a->key) == 1);
	ATF_REQUIRE(EVP_DigestSign(ctx, sig, &siglen, msg, adlen + 32) == 1);
	EVP_MD_CTX_free(ctx);
	if (flip)
		sig[siglen - 1] ^= 1;
	id64 = b64url(a->id, sizeof(a->id));
	cd64 = b64url(cd, strlen(cd));
	ad64 = b64url(ad, adlen);
	sig64 = b64url(sig, siglen);
	snprintf(body, sizeof(body), "{\"id\":\"%s\",\"clientDataJSON\":\"%s\","
	    "\"authenticatorData\":\"%s\",\"signature\":\"%s\"}", id64, cd64,
	    ad64, sig64);
	http("POST", "/api/auth/login/finish", body, r);
	resp_free(&b);
	free(cd);
	free(id64);
	free(cd64);
	free(ad64);
	free(sig64);
}

static char *
setup_token(void)
{
	FILE	*fp;
	char	 buf[128];

	ATF_REQUIRE((fp = fopen("data/setup-token", "r")) != NULL);
	ATF_REQUIRE(fgets(buf, sizeof(buf), fp) != NULL);
	fclose(fp);
	buf[strcspn(buf, "\n")] = '\0';
	return (strdup(buf));
}

/* Register an ES256 key with the setup token: logged in after. */
static void
enrol(struct authn *a)
{
	struct resp	 r;
	char		*tok;

	authn_new(a, -7);
	tok = setup_token();
	do_register(a, tok, &r);
	EXPECT(&r, 200);
	free(tok);
	resp_free(&r);
}

/*
 * arcana-console (PLAN-SDN-YANG 4.4.1): the console's own configuration
 * and state through RESTCONF; FLEET a host's entry in the fleet mount
 * (4.3), its id after it.
 */
#define	CC	"/restconf/data/arcana-console:"
#define	FLEET	"/restconf/data/arcana-fleet:fleet/host="

/*
 * A host added at arcana-console's hosts: members its entry's members
 * but the id ("\"name\":\"a\",\"uri\":\"tcp://...\"", tenant, peer-name,
 * safe-wait), the id made here, 8 lowercase hex digits as the console
 * makes them, a new one each time, into sid; the answer in r.
 */
static void
host_try(const char *members, char *sid, size_t len, struct resp *r)
{
	static unsigned	 next;
	char		*body;

	snprintf(sid, len, "%08x", 0x0a0c0000u + ++next);
	ATF_REQUIRE(asprintf(&body, "{\"arcana-console:host\":[{\"id\":"
	    "\"%s\",%s}]}", sid, members) != -1);
	http("POST", CC "hosts", body, r);
	free(body);
}

/* The same, made: 201. */
static void
host_new(const char *members, char *sid, size_t len)
{
	struct resp	r;

	host_try(members, sid, len, &r);
	EXPECT(&r, 201);
	resp_free(&r);
}

/*
 * r's JSON made its member key's value: a bridged node's document
 * ({"arcana-console:drift": {...}}), a list's entry ("arcana-console:
 * run.0"), an action's output ("arcana-console:output.result"); false,
 * r as it was, where there is none.
 */
static bool
resp_unwrap(struct resp *r, const char *key)
{
	const ucl_object_t	*v;
	ucl_object_t		*c;

	if (r->json == NULL || (v = ucl_object_lookup_path(r->json, key)) ==
	    NULL)
		return (false);
	c = ucl_object_copy(v);
	ucl_object_unref(r->json);
	r->json = c;
	return (true);
}

/*
 * POST of an action or rpc at path: input a whole body ("{...}"), the
 * members of its input (wrapped in "<module>:input", the module the
 * path's last prefixed node's), or NULL for none; the answer in r, its
 * JSON the output's result where it has one (a bridged verb's
 * document), else the output's members.
 */
static void
rc_act(const char *path, const char *input, struct resp *r)
{
	const char	*p, *mod, *e;
	char		*body, key[96];
	int		 n;

	body = NULL;
	mod = NULL;
	for (p = path; (p = strchr(p, '/')) != NULL; p++) {
		e = p + 1 + strcspn(p + 1, "/=:");
		if (*e == ':')
			mod = p + 1;
	}
	n = mod != NULL ? (int)strcspn(mod, ":") : 0;
	if (input != NULL && input[0] == '{')
		body = strdup(input);
	else if (input != NULL)
		ATF_REQUIRE(asprintf(&body, "{\"%.*s:input\":{%s}}", n, mod,
		    input) != -1);
	http("POST", path, body, r);
	free(body);
	snprintf(key, sizeof(key), "%.*s:output", n, mod != NULL ? mod : "");
	if (r->status == 200 && !resp_unwrap(r, "arcana-console:output.result"))
		(void)resp_unwrap(r, key);
}

/* A host named name at uri: its id, in buf. */
static void
host_add(const char *name, const char *uri, char *buf, size_t len)
{
	char	m[MAXPATHLEN + 64];

	snprintf(m, sizeof(m), "\"name\":\"%s\",\"uri\":\"%s\"", name, uri);
	host_new(m, buf, len);
}

/*
 * A user of the console, made with entry's members but the name
 * ("\"role\":[\"viewer\"]", group, tenant) and invited by the owner,
 * signed in with key k (of algorithm which), the owner's session given
 * up.
 */
static void
cc_user(struct authn *k, const char *name, const char *entry, int which)
{
	struct resp	 r;
	char		 path[96], invite[80], *body;

	snprintf(path, sizeof(path), CC "users/user=%s", name);
	ATF_REQUIRE(asprintf(&body, "{\"arcana-console:user\":[{\"name\":"
	    "\"%s\",%s}]}", name, entry) != -1);
	http("PUT", path, body, &r);
	free(body);
	ATF_CHECK_MSG(r.status == 201 || r.status == 204, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), CC "users/user=%s/invite", name);
	http("POST", path, NULL, &r);
	EXPECT(&r, 200);
	snprintf(invite, sizeof(invite), "%s", jstr(&r,
	    "arcana-console:output.token"));
	resp_free(&r);
	cookie[0] = '\0';
	authn_new(k, which);
	do_register(k, invite, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(name, jstr(&r, "user"));
	resp_free(&r);
}

#define	CONSOLE_TC(name, descr)						\
ATF_TC_WITH_CLEANUP(name);						\
ATF_TC_HEAD(name, tc)							\
{									\
	atf_tc_set_md_var(tc, "descr", descr);				\
	atf_tc_set_md_var(tc, "timeout", "60");				\
}									\
ATF_TC_CLEANUP(name, tc)						\
{									\
	stop();								\
}

/* The same with three minutes: an apply made twice over. */
#define	CONSOLE_TC_LONG(name, descr)					\
ATF_TC_WITH_CLEANUP(name);						\
ATF_TC_HEAD(name, tc)							\
{									\
	atf_tc_set_md_var(tc, "descr", descr);				\
	atf_tc_set_md_var(tc, "timeout", "180");				\
}									\
ATF_TC_CLEANUP(name, tc)						\
{									\
	stop();								\
}

CONSOLE_TC(unauthenticated, "Without a session only health and status work")
ATF_TC_BODY(unauthenticated, tc)
{
	struct resp	r;

	/* A write cut short by a stop, its temporary left: taken away at
	 * start, and what only looks like one kept. */
	ATF_REQUIRE(mkdir("data", 0700) == 0);
	put("data/sdwan-state.json", "{}");
	put("data/sdwan-state.json.AbC123", "{}");
	put("data/sdwan-state.json.backup", "{}");
	put("data/gone.json.Xy12zz", "{}");
	start(tc, 0, NULL);
	ATF_CHECK(access("data/sdwan-state.json.AbC123", F_OK) == -1);
	ATF_CHECK(access("data/sdwan-state.json.backup", F_OK) == 0);
	ATF_CHECK(access("data/gone.json.Xy12zz", F_OK) == 0);
	http("GET", "/api/health", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	resp_free(&r);
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "setup_required"));
	ATF_CHECK_STREQ(harness_origin, jstr(&r, "origin"));
	ATF_CHECK_STREQ("false", jstr(&r, "authenticated"));
	resp_free(&r);
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 401);
	ATF_CHECK_MSG(strstr(r.body, "ietf-restconf:errors") != NULL, "%s",
	    r.body);
	resp_free(&r);
	http("GET", CC "credentials", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	http("GET", FLEET "0123abcd/arcana-jails:jails", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	http("POST", "/api/auth/login/begin", "{}", &r);
	EXPECT(&r, 409);
	resp_free(&r);
	http("GET", "/", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK_EQ(0, access("data/setup-token", R_OK));
}

static void	cc_host(const char *, const char *, char *, size_t);
static void	run_wait(const char *, struct resp *);

/* Role name: the console's con, every host's hr. */
static void
r1_role(const char *name, const char *con, const char *hr)
{
	struct resp	 r;
	char		 path[96], *body;

	snprintf(path, sizeof(path), CC "roles/role=%s", name);
	ATF_REQUIRE(asprintf(&body, "{\"arcana-console:role\":[{\"name\":"
	    "\"%s\",\"console\":\"%s\",\"host\":[{\"id\":\"*\",\"role\":"
	    "\"%s\"}]}]}", name, con, hr) != -1);
	http("PUT", path, body, &r);
	free(body);
	ATF_CHECK_MSG(r.status == 201 || r.status == 204, "%d %s", r.status,
	    r.body);
	resp_free(&r);
}

/* User name's roles made role alone. */
static void
r1_roles(const char *name, const char *role)
{
	struct resp	 r;
	char		 path[96], *body;

	snprintf(path, sizeof(path), CC "users/user=%s", name);
	ATF_REQUIRE(asprintf(&body, "{\"arcana-console:user\":[{\"name\":"
	    "\"%s\",\"role\":[\"%s\"]}]}", name, role) != -1);
	http("PUT", path, body, &r);
	free(body);
	ATF_CHECK_MSG(r.status == 201 || r.status == 204, "%d %s", r.status,
	    r.body);
	resp_free(&r);
}

/* Host id's arcana-jobs:submit of the changes chg ("{...},{...}"). */
static void
r1_submit(const char *id, const char *chg, struct resp *r)
{
	char	path[128], *body;

	snprintf(path, sizeof(path), FLEET "%s/arcana-jobs:submit", id);
	ATF_REQUIRE(asprintf(&body, "{\"arcana-jobs:input\":{\"change\":[%s]}}",
	    chg) != -1);
	http("POST", path, body, r);
	free(body);
}

/* A monitor gre8 set, as the NACM cases ask it. */
#define	R1_MONITOR	"{\"monitor\":{\"verb\":\"set\",\"args\":["	\
	"\"name=gre8\",\"interface=gre8\",\"address=192.0.2.8\","	\
	"\"interval=500\",\"eval=10000\"]}}"

CONSOLE_TC(restconf, "RESTCONF's reads: discovery, the root, the fleet "
    "and a host's data by api-path, content, depth, fields and "
    "with-defaults; its errors")
/*
 * NACM (RFC 8341) on the host: the console says whose each request is.
 * An operator of the console's is in no group of the host's rules, so
 * what changes the host is refused to him there; the admin's goes.
 */
ATF_TC_WITHOUT_HEAD(nacm_user);
ATF_TC_BODY(nacm_user, tc)
{
	struct authn	 a, b;
	struct resp	 r;
	char		 id[16];

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("lab", "jgd.sock", id, sizeof(id));
	r1_role("ops", "member", "operator");
	/* bob: the console lets an operator change; the host does not. */
	cc_user(&b, "bob", "\"role\":[\"ops\"]", -8);
	r1_submit(id, R1_MONITOR, &r);
	ATF_CHECK_MSG(r.status == 403 && strstr(r.body, "access denied") !=
	    NULL, "%d %s", r.status, r.body);
	resp_free(&r);
	/* The admin. */
	cookie[0] = '\0';
	do_login(&a, 1, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	r1_submit(id, R1_MONITOR, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, "access denied") == NULL);
	resp_free(&r);
}

/*
 * The console's roles synchronized to a host's access rules, by an
 * owner, when asked and not before: bob, an owner, is anyone else to
 * the host until then; synchronized, he is of its group admin and
 * changes the host as himself; once more, nothing to do; an operator
 * again, he may not ask, and the admin's synchronizing takes him out.
 * Rules of the host's own with no group admin are left as they are.
 */
ATF_TC_WITHOUT_HEAD(nacm_sync);
ATF_TC_BODY(nacm_sync, tc)
{
	static const char rules[] = "{\"groups\":{\"group\":[{\"name\":"
	    "\"ops\",\"user-name\":[\"admin\"%s]}]},\"rule-list\":[{\"name\":"
	    "\"ops\",\"group\":[\"ops\"],\"rule\":[{\"name\":\"all\","
	    "\"module-name\":\"*\",\"access-operations\":\"*\",\"action\":"
	    "\"permit\"}]}]}";
	struct authn	 a, b;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], id[16];
	char		 sync[256], admin[160], bob[160];
	char		 cmd[3 * MAXPATHLEN];
	const char	*ctl;
	FILE		*fp;

	start(tc, 0, NULL);
	enrol(&a);
	snprintf(admin, sizeof(admin), "%s", cookie);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	cc_host("lab", "jgd.sock", id, sizeof(id));
	snprintf(sync, sizeof(sync), CC "hosts/host=%s/nacm-sync", id);
	r1_role("ops", "member", "operator");
	cc_user(&b, "bob", "\"role\":[\"owner\"]", -8);
	snprintf(bob, sizeof(bob), "%s", cookie);
	/* Not before it is asked for. */
	r1_submit(id, R1_MONITOR, &r);
	ATF_CHECK_MSG(strstr(r.body, "access denied") != NULL, "%d %s",
	    r.status, r.body);
	resp_free(&r);
	/* Synchronized: bob of the host's group admin, and let. */
	rc_act(sync, NULL, &r);
	ATF_CHECK_MSG(r.status == 200, "%d %s", r.status, r.body);
	ATF_CHECK_STREQ("changed", jstr(&r, "data.result"));
	ATF_CHECK_MSG(strstr(r.body, "\"bob\"") != NULL, "%s", r.body);
	resp_free(&r);
	r1_submit(id, R1_MONITOR, &r);
	ATF_CHECK_MSG(r.status == 200 && strstr(r.body, "access denied") ==
	    NULL, "%d %s", r.status, r.body);
	resp_free(&r);
	rc_act(sync, NULL, &r);
	ATF_CHECK_STREQ("unchanged", jstr(&r, "data.result"));
	resp_free(&r);
	/* An operator again: he may not ask; the admin's takes him out. */
	snprintf(cookie, sizeof(cookie), "%s", admin);
	r1_roles("bob", "ops");
	snprintf(cookie, sizeof(cookie), "%s", bob);
	rc_act(sync, NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	snprintf(cookie, sizeof(cookie), "%s", admin);
	rc_act(sync, NULL, &r);
	ATF_CHECK_STREQ("changed", jstr(&r, "data.result"));
	ATF_CHECK_MSG(strstr(r.body, "\"bob\"") == NULL, "%s", r.body);
	resp_free(&r);
	snprintf(cookie, sizeof(cookie), "%s", bob);
	r1_submit(id, R1_MONITOR, &r);
	ATF_CHECK_MSG(strstr(r.body, "access denied") != NULL, "%d %s",
	    r.status, r.body);
	resp_free(&r);
	/*
	 * The host's own rules decide: rules that do not let the console
	 * read them refuse it, and rules that do but have no group admin
	 * are left as they are.
	 */
	ctl = locate(tc, "../../../usr.sbin/arcanactl/arcanactl", "arcanactl",
	    "/usr/local/sbin/arcanactl");
	snprintf(cookie, sizeof(cookie), "%s", admin);
	for (int k = 0; k < 2; k++) {
		ATF_REQUIRE((fp = fopen("rules.json", "w")) != NULL);
		fprintf(fp, rules, k == 0 ? "" : ",\"console\"");
		fprintf(fp, "\n");
		fclose(fp);
		snprintf(cmd, sizeof(cmd), "%s -c unix:%s/jgd.sock edit nacm "
		    "@rules.json && %s -c unix:%s/jgd.sock commit", ctl, cwd,
		    ctl, cwd);
		ATF_REQUIRE_EQ_MSG(0, system(cmd), "%s", cmd);
		rc_act(sync, NULL, &r);
		if (k == 0)
			ATF_CHECK_MSG(jstr(&r, "data.result") == NULL &&
			    strstr(r.body, "do not let the console") != NULL,
			    "%d %s", r.status, r.body);
		else
			ATF_CHECK_STREQ("no-admin-group", jstr(&r,
			    "data.result"));
		resp_free(&r);
	}
}

/*
 * Where the console reaches a host, its own record alone: a server
 * added at a wrong address is unreachable, and told the right one it is
 * reached, the host asked nothing.  Moved, the name its certificate is
 * checked for stays the old address's host unless one is given ("" the
 * new address's own); no URI, or another server's, is refused.
 */
ATF_TC_WITHOUT_HEAD(server_readdress);
ATF_TC_BODY(server_readdress, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 128], id[16];
	char		 tid[16], path[256], jails[256];

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	cc_host("lab", "nowhere.sock", id, sizeof(id));
	snprintf(path, sizeof(path), CC "hosts/host=%s", id);
	snprintf(jails, sizeof(jails), FLEET "%s/arcana-jails:jails/jail=web",
	    id);
	http("GET", jails, NULL, &r);
	ATF_CHECK_MSG(r.status != 200, "%d %s", r.status, r.body);
	resp_free(&r);
	/* The right address: reached, nothing asked of the host before. */
	snprintf(body, sizeof(body), "{\"arcana-console:host\":[{\"id\":"
	    "\"%s\",\"uri\":\"unix:%s/jgd.sock\"}]}", id, cwd);
	http("PATCH", path, body, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", path, NULL, &r);
	ATF_CHECK_MSG(strstr(r.body, "jgd.sock") != NULL, "%s", r.body);
	ATF_CHECK(jstr(&r, "arcana-console:host.0.peer-name") == NULL);
	resp_free(&r);
	http("GET", jails, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("10.0.0.10", jstr(&r, "arcana-jails:jail.0.ip4.0"));
	resp_free(&r);
	/* Over TCP: the old host's name still checked, or the one given. */
	host_add("far", "tcp://192.0.2.7:4310", tid, sizeof(tid));
	snprintf(path, sizeof(path), CC "hosts/host=%s", tid);
	snprintf(body, sizeof(body), "{\"arcana-console:host\":[{\"id\":"
	    "\"%s\",\"uri\":\"tcp://192.0.2.8:4310\"}]}", tid);
	http("PATCH", path, body, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", path, NULL, &r);
	ATF_CHECK_STREQ("tcp://192.0.2.8:4310", jstr(&r,
	    "arcana-console:host.0.uri"));
	ATF_CHECK_STREQ("192.0.2.7", jstr(&r,
	    "arcana-console:host.0.peer-name"));
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"arcana-console:host\":[{\"id\":"
	    "\"%s\",\"uri\":\"tcp://192.0.2.9:4310\",\"peer-name\":"
	    "\"far.example\"}]}", tid);
	http("PATCH", path, body, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", path, NULL, &r);
	ATF_CHECK_STREQ("far.example", jstr(&r,
	    "arcana-console:host.0.peer-name"));
	resp_free(&r);
	/* The entry without one: the new address's own name. */
	snprintf(body, sizeof(body), "{\"arcana-console:host\":[{\"id\":"
	    "\"%s\",\"name\":\"far\",\"uri\":\"tcp://192.0.2.9:4310\"}]}", tid);
	http("PUT", path, body, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", path, NULL, &r);
	ATF_CHECK(jstr(&r, "arcana-console:host.0.peer-name") == NULL);
	resp_free(&r);
	/* No URI; another server's. */
	snprintf(body, sizeof(body), "{\"arcana-console:host\":[{\"id\":"
	    "\"%s\",\"uri\":\"192.0.2.9\"}]}", tid);
	http("PATCH", path, body, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"arcana-console:host\":[{\"id\":"
	    "\"%s\",\"uri\":\"unix:%s/jgd.sock\"}]}", tid, cwd);
	http("PATCH", path, body, &r);
	ATF_CHECK_MSG(r.status == 409 || r.status == 400, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	http("GET", CC "hosts", NULL, &r);
	ATF_CHECK_STREQ("tcp://192.0.2.9:4310", jstr(&r,
	    "arcana-console:hosts.host.1.uri"));
	resp_free(&r);
}

/*
 * What the console does for no one (a workflow at its interval) it asks
 * as NACM's user "console", never as the agent's recovery session, even
 * over the local socket as the agent's own user: with "console" out of
 * the agent's group admin, the run's change is refused.
 */
ATF_TC_WITHOUT_HEAD(nacm_console);
ATF_TC_BODY(nacm_console, tc)
{
	static const char rules[] = "{\"groups\":{\"group\":[{\"name\":"
	    "\"admin\",\"user-name\":[\"admin\"]}]},\"rule-list\":[{\"name\":"
	    "\"admin\",\"group\":[\"admin\"],\"rule\":[{\"name\":\"all\","
	    "\"module-name\":\"*\",\"access-operations\":\"*\",\"action\":"
	    "\"permit\"}]}]}";
	struct authn	 a;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 512], id[16];
	char		 wid[16], run[16], path[96], cmd[3 * MAXPATHLEN];
	const char	*ctl;
	FILE		*fp;
	int		 i;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ctl = locate(tc, "../../../usr.sbin/arcanactl/arcanactl", "arcanactl",
	    "/usr/local/sbin/arcanactl");
	/* The agent's rules, by its recovery session (this test's uid). */
	ATF_REQUIRE((fp = fopen("rules.json", "w")) != NULL);
	fprintf(fp, "%s\n", rules);
	fclose(fp);
	snprintf(cmd, sizeof(cmd), "%s -c unix:%s/jgd.sock edit nacm "
	    "@rules.json && %s -c unix:%s/jgd.sock commit", ctl, cwd, ctl, cwd);
	ATF_REQUIRE_EQ_MSG(0, system(cmd), "%s", cmd);
	cc_host("lab", "jgd.sock", id, sizeof(id));
	snprintf(wid, sizeof(wid), "0000a001");
	snprintf(body, sizeof(body), "{\"arcana-console:workflow\":[{\"id\":"
	    "\"%s\",\"name\":\"each minute\",\"host\":[\"%s\"],\"every\":60,"
	    "\"step\":[{\"id\":\"s\",\"job\":{\"kind\":\"monitor\",\"field\":["
	    "{\"name\":\"verb\",\"text\":\"set\"},{\"name\":\"args\",\"json\":"
	    "\"[\\\"name=gre8\\\",\\\"interface=gre8\\\",\\\"address=192.0.2.8"
	    "\\\",\\\"interval=500\\\",\\\"eval=10000\\\"]\"}]}}]}]}", wid, id);
	snprintf(path, sizeof(path), CC "workflows/workflow=%s", wid);
	http("PUT", path, body, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	ATF_REQUIRE((fp = fopen("data/every.json", "w")) != NULL);
	fprintf(fp, "{\"%s\": %lld}\n", wid, (long long)time(NULL) - 58);
	fclose(fp);
	restart_console();
	for (i = 0; i < 300; i++) {
		http("GET", CC "runs", NULL, &r);
		if (strstr(r.body, "\"each minute\"") != NULL &&
		    jstr(&r, "arcana-console:runs.run.0.id") != NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_REQUIRE_MSG(i < 300, "the workflow did not run");
	snprintf(run, sizeof(run), "%s", jstr(&r,
	    "arcana-console:runs.run.0.id"));
	resp_free(&r);
	run_wait(run, &r);
	ATF_CHECK_MSG(strstr(r.body, "access denied") !=
	    NULL, "%s", r.body);
	resp_free(&r);
}

/*
 * Who asked for a job: the console's user, as the host's NACM has it,
 * in the list, the job read and the event of its end; a run by hand,
 * who started it.  arcanactl as the host's recovery session names none.
 */
CONSOLE_TC(job_user, "A job records the console user who asked for it; "
    "a run who started it")
ATF_TC_BODY(job_user, tc)
{
	static const char rules[] = "{\"groups\":{\"group\":[{\"name\":"
	    "\"admin\",\"user-name\":[\"admin\",\"console\",\"alice\"]}]},"
	    "\"rule-list\":[{\"name\":\"admin\",\"group\":[\"admin\"],\"rule\":"
	    "[{\"name\":\"all\",\"module-name\":\"*\",\"access-operations\":"
	    "\"*\",\"action\":\"permit\"}]}]}";
	struct authn	 a, b;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 512], id[16];
	char		 path[256], jpath[300], wid[16], run[16];
	char		 cmd[3 * MAXPATHLEN], jid[24], key[64];
	const char	*ctl, *v;
	FILE		*fp;
	int		 i;
	bool		 seen;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ctl = locate(tc, "../../../usr.sbin/arcanactl/arcanactl", "arcanactl",
	    "/usr/local/sbin/arcanactl");
	ATF_REQUIRE((fp = fopen("rules.json", "w")) != NULL);
	fprintf(fp, "%s\n", rules);
	fclose(fp);
	snprintf(cmd, sizeof(cmd), "%s -c unix:%s/jgd.sock edit nacm "
	    "@rules.json && %s -c unix:%s/jgd.sock commit", ctl, cwd, ctl, cwd);
	ATF_REQUIRE_EQ_MSG(0, system(cmd), "%s", cmd);
	cc_host("lab", "jgd.sock", id, sizeof(id));
	snprintf(wid, sizeof(wid), "0000a002");
	snprintf(body, sizeof(body), "{\"arcana-console:workflow\":[{\"id\":"
	    "\"%s\",\"name\":\"again\",\"host\":[\"%s\"],\"step\":[{\"id\":"
	    "\"s\",\"job\":{\"kind\":\"service-action\",\"field\":[{\"name\":"
	    "\"service\",\"text\":\"sshd\"},{\"name\":\"action\",\"text\":"
	    "\"restart\"}]}}]}]}", wid, id);
	snprintf(path, sizeof(path), CC "workflows/workflow=%s", wid);
	http("PUT", path, body, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	cc_user(&b, "alice", "\"role\":[\"operator\"]", -8);

	/* alice's job: hers in the list, the read and the event. */
	r1_submit(id, "{\"service-action\":{\"service\":\"sshd\",\"action\":"
	    "\"stop\"}}", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_MSG(jstr(&r, "arcana-jobs:output.id.0") != NULL, "%s",
	    r.body);
	snprintf(jid, sizeof(jid), "%s", jstr(&r, "arcana-jobs:output.id.0"));
	resp_free(&r);
	snprintf(jpath, sizeof(jpath), FLEET "%s/arcana-jobs:jobs/job=%s/read",
	    id, jid);
	for (i = 0; i < 100; i++) {
		http("POST", jpath, NULL, &r);
		EXPECT(&r, 200);
		if (jstr(&r, "arcana-jobs:output.state") != NULL &&
		    strcmp(jstr(&r, "arcana-jobs:output.state"), "done") == 0)
			break;
		resp_free(&r);
		usleep(50000);
	}
	ATF_REQUIRE_MSG(i < 100, "the job did not finish");
	ATF_CHECK_STREQ("alice", jstr(&r, "arcana-jobs:output.user"));
	resp_free(&r);
	snprintf(path, sizeof(path), FLEET "%s/arcana-jobs:jobs/job=%s", id,
	    jid);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(jid, jstr(&r, "arcana-jobs:job.0.id"));
	ATF_CHECK_STREQ("alice", jstr(&r, "arcana-jobs:job.0.user"));
	resp_free(&r);
	snprintf(path, sizeof(path), FLEET "%s/arcana-events:events/read", id);
	seen = false;
	for (i = 0; i < 50 && !seen; i++) {
		http("POST", path, NULL, &r);
		EXPECT(&r, 200);
		for (int k = 0; k < 64 && !seen; k++) {
			snprintf(key, sizeof(key),
			    "arcana-events:output.event.%d.kind", k);
			if ((v = jstr(&r, key)) == NULL)
				break;
			snprintf(key, sizeof(key),
			    "arcana-events:output.event.%d.job.id", k);
			if (strcmp(v, "arcana-events:job") != 0 ||
			    jstr(&r, key) == NULL ||
			    strcmp(jstr(&r, key), jid) != 0)
				continue;
			snprintf(key, sizeof(key),
			    "arcana-events:output.event.%d.job.user", k);
			ATF_CHECK_STREQ("alice", jstr(&r, key));
			seen = true;
		}
		resp_free(&r);
		if (!seen)
			usleep(100000);
	}
	ATF_CHECK_MSG(seen, "no event of job %s", jid);

	/* A run by hand: who started it, and its job hers too. */
	snprintf(path, sizeof(path), CC "workflows/workflow=%s/run", wid);
	rc_act(path, NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_MSG(jstr(&r, "run") != NULL, "%s", r.body);
	snprintf(run, sizeof(run), "%s", jstr(&r, "run"));
	resp_free(&r);
	run_wait(run, &r);
	ATF_CHECK_STREQ("alice", jstr(&r, "started-by"));
	ATF_CHECK_STREQ("done", jstr(&r, "host.0.step.0.state"));
	ATF_CHECK_MSG(jstr(&r, "host.0.step.0.trace") != NULL && strstr(jstr(&r,
	    "host.0.step.0.trace"), "\"user\":\"alice\"") != NULL, "%s",
	    r.body);
	resp_free(&r);
	http("GET", CC "runs", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("alice", jstr(&r,
	    "arcana-console:runs.run.0.started-by"));
	resp_free(&r);

	/* arcanactl over the unix socket, saying no user: none. */
	snprintf(cmd, sizeof(cmd), "%s -q -c unix:%s/jgd.sock service sshd "
	    "start > /dev/null && %s --libxo json -c unix:%s/jgd.sock jobs > "
	    "ctl.json", ctl, cwd, ctl, cwd);
	ATF_REQUIRE_EQ_MSG(0, system(cmd), "%s", cmd);
	ATF_CHECK(system("grep -q '\"user\":\"alice\"' ctl.json") == 0);
	ATF_CHECK(system("grep -q '\"title\":\"service sshd start\",[^}]*"
	    "\"user\"' ctl.json") != 0);
	ATF_CHECK(system("grep -q '\"title\":\"service sshd start\"' "
	    "ctl.json") == 0);
}

/*
 * RESTCONF's changes (RFC 8040, RFC 8527): running is not written; the
 * candidate's node PUT, read back from the candidate's datastore; a
 * confirmed commit refused without persist; with it, then confirmed by
 * its persist-id; running has it.  NACM's rules, the agent's own file.
 */
ATF_TC_WITHOUT_HEAD(restconf_write);
ATF_TC_BODY(restconf_write, tc)
{
	static const char rules[] = "{\"ietf-netconf-acm:nacm\":{"
	    "\"groups\":{\"group\":[{\"name\":\"admin\",\"user-name\":"
	    "[\"admin\",\"console\"]},{\"name\":\"ops\",\"user-name\":"
	    "[\"bob\"]}]},\"rule-list\":[{\"name\":\"admin\",\"group\":"
	    "[\"admin\"],\"rule\":[{\"name\":\"all\",\"module-name\":\"*\","
	    "\"access-operations\":\"*\",\"action\":\"permit\"}]}]}}";
	struct authn	 a;
	struct resp	 r;
	char		 id[16];
	char		 data[256], cand[256], run[256], path[320];

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("lab", "jgd.sock", id, sizeof(id));
	snprintf(data, sizeof(data), "/restconf/data/arcana-fleet:fleet/"
	    "host=%s", id);
	snprintf(cand, sizeof(cand), "/restconf/ds/ietf-datastores:candidate/"
	    "arcana-fleet:fleet/host=%s", id);
	snprintf(run, sizeof(run), "/restconf/ds/ietf-datastores:running/"
	    "arcana-fleet:fleet/host=%s", id);
	/* with-origin (RFC 8527 section 3.2.2), the operational
	 * datastore's alone: nacm is running's, intended. */
	snprintf(path, sizeof(path), "/restconf/ds/ietf-datastores:"
	    "operational/arcana-fleet:fleet/host=%s/ietf-netconf-acm:nacm"
	    "?with-origin", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ_MSG("ietf-origin:intended", jstr(&r,
	    "ietf-netconf-acm:nacm.@.ietf-origin:origin"), "%s", r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-netconf-acm:nacm?with-origin",
	    run);
	http("GET", path, NULL, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* Running is changed by a commit alone. */
	snprintf(path, sizeof(path), "%s/ietf-netconf-acm:nacm", data);
	http("PUT", path, rules, &r);
	EXPECT(&r, 405);
	ATF_CHECK_MSG(strstr(r.body, "confirmed commit of the candidate") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-netconf-acm:nacm", cand);
	http("PUT", path, rules, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"ops\"") != NULL, "%s", r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-netconf-acm:nacm", run);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"ops\"") == NULL, "%s", r.body);
	resp_free(&r);
	/* Confirmed: its persist token, then confirmed by it. */
	snprintf(path, sizeof(path), "%s/ietf-netconf:commit", data);
	http("POST", path, "{\"ietf-netconf:input\":{\"confirmed\":[null],"
	    "\"confirm-timeout\":60}}", &r);
	EXPECT(&r, 400);
	ATF_CHECK(strstr(r.body, "persist") != NULL);
	resp_free(&r);
	http("POST", path, "{\"ietf-netconf:input\":{\"confirmed\":[null],"
	    "\"confirm-timeout\":60,\"persist\":\"t1\"}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("POST", path, "{\"ietf-netconf:input\":{\"persist-id\":\"t1\"}}",
	    &r);
	EXPECT(&r, 204);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-netconf-acm:nacm", run);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"ops\"") != NULL, "%s", r.body);
	resp_free(&r);
	/* What is not taken. */
	snprintf(path, sizeof(path), "%s/ietf-netconf:lock", data);
	http("POST", path, "{}", &r);
	ATF_CHECK(r.status == 404 || r.status == 405 || r.status == 400);
	resp_free(&r);
}

/*
 * An interface's router advertisements (RFC 8349's submodule with
 * arcana-ra) put in the candidate at their path below the interface,
 * committed confirmed: the first commit stops at rc-conf-files, the
 * warning accepted it goes through; running has the node, the host's
 * rtadvd.conf the record, rtadvd started.
 */
ATF_TC_WITHOUT_HEAD(restconf_ra);
ATF_TC_BODY(restconf_ra, tc)
{
	static const char node[] = "{\"ietf-ipv6-unicast-routing:"
	    "ipv6-router-advertisements\":{\"send-advertisements\":true,"
	    "\"max-rtr-adv-interval\":300,\"arcana-ra:router-preference\":"
	    "\"high\",\"arcana-ra:rdnss\":[{\"address\":\"2001:db8::53\"}],"
	    "\"prefix-list\":{\"prefix\":[{\"prefix-spec\":\"2001:db8:57::/64\","
	    "\"valid-lifetime\":3600,\"preferred-lifetime\":1800}]}}}";
	struct authn	 a;
	struct resp	 r;
	char		 id[16];
	char		 path[400], conf[MAXPATHLEN + 32];
	FILE		*fp;
	size_t		 n;
	int		 ss;

	start(tc, 0, NULL);
	enrol(&a);
	/* Arcana's rc.conf file goes where a host has the directory. */
	(void)mkdir("root/usr", 0755);
	(void)mkdir("root/usr/local", 0755);
	(void)mkdir("root/usr/local/etc", 0755);
	ATF_REQUIRE(mkdir("root/usr/local/etc/rc.conf.d", 0755) == 0);
	cc_host("lab", "jgd.sock", id, sizeof(id));
	/* A dynamic subscription as the candidate is made, gone before its
	 * commit: no change of running's, which has the configured alone. */
	snprintf(conf, sizeof(conf), "GET /restconf/streams/%s/json HTTP/1.1"
	    "\r\nHost: localhost:8443\r\nCookie: %s\r\n\r\n", id, cookie);
	ss = console_socket();
	ATF_REQUIRE(write(ss, conf, strlen(conf)) == (ssize_t)strlen(conf));
	usleep(1500000);
	snprintf(path, sizeof(path), "/restconf/ds/ietf-datastores:candidate/"
	    "arcana-fleet:fleet/host=%s/ietf-interfaces:interfaces/"
	    "interface=lo0/ietf-ip:ipv6/ietf-ipv6-unicast-routing:"
	    "ipv6-router-advertisements", id);
	http("PUT", path, node, &r);
	ATF_CHECK_MSG(r.status == 204 || r.status == 201, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"arcana-ra:router-preference\":\"high\"")
	    != NULL, "%s", r.body);
	resp_free(&r);
	close(ss);
	usleep(1500000);
	/* The commit stops at the warning: rc_conf_files does not name
	 * Arcana's file; accepted, it goes on. */
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/"
	    "host=%s/ietf-netconf:commit", id);
	http("POST", path, "{\"ietf-netconf:input\":{\"confirmed\":[null],"
	    "\"confirm-timeout\":60,\"persist\":\"ra1\"}}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"error-app-tag\":\"rc-conf-files\"") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/"
	    "host=%s/ietf-netconf:commit?arcana-accept=rc-conf-files", id);
	http("POST", path, "{\"ietf-netconf:input\":{\"confirmed\":[null],"
	    "\"confirm-timeout\":60,\"persist\":\"ra1\"}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/"
	    "host=%s/ietf-netconf:commit", id);
	http("POST", path, "{\"ietf-netconf:input\":{\"persist-id\":\"ra1\"}}",
	    &r);
	EXPECT(&r, 204);
	resp_free(&r);
	snprintf(path, sizeof(path), "/restconf/ds/ietf-datastores:running/"
	    "arcana-fleet:fleet/host=%s/ietf-interfaces:interfaces/"
	    "interface=lo0/ietf-ip:ipv6/ietf-ipv6-unicast-routing:"
	    "ipv6-router-advertisements", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"max-rtr-adv-interval\":300") != NULL &&
	    strstr(r.body, "\"send-advertisements\":true") != NULL &&
	    strstr(r.body, "\"arcana-ra:rdnss\":[{\"address\":\"2001:db8::53\"}]")
	    != NULL, "%s", r.body);
	resp_free(&r);
	/* The host's file, as rtadvd.conf(5) wants it; rtadvd run. */
	ATF_REQUIRE((fp = fopen("rtadvd.conf", "r")) != NULL);
	n = fread(conf, 1, sizeof(conf) - 1, fp);
	conf[n] = '\0';
	fclose(fp);
	ATF_CHECK_MSG(strstr(conf, "lo0:\\\n\t:maxinterval#300:raflags=\"h\":"
	    "addr=\"2001:db8:57::\":prefixlen#64:\\\n\t:vltime#3600:pltime#1800:"
	    "rdnss=\"2001:db8::53\":\n") != NULL, "%s", conf);
	ATF_CHECK(access("running.rtadvd", F_OK) == 0);
}

/* A path through a mount point (RFC 8528): a FIB's routing below its
 * network instance's vrf-root. */
ATF_TC_WITHOUT_HEAD(restconf_mount);
ATF_TC_BODY(restconf_mount, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 id[16];
	char		 path[320];
	int		 fibs = 0;
	size_t		 len = sizeof(fibs);

	if (sysctlbyname("net.fibs", &fibs, &len, NULL, 0) == -1 || fibs < 2)
		atf_tc_skip("one FIB alone here");
	start(tc, 0, NULL);
	enrol(&a);
	cc_host("lab", "jgd.sock", id, sizeof(id));
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/ietf-network-instance:network-instances/network-instance=fib1/"
	    "vrf-root/ietf-routing:routing", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"ietf-routing:routing\"") != NULL &&
	    strstr(r.body, "\"ribs\"") != NULL, "%s", r.body);
	resp_free(&r);
}

#define	NACM		"/ietf-netconf-acm:nacm"
#define	YANG_PATCH	"Content-Type: application/yang-patch+json\r\n"
#define	ERROR_TAG	"ietf-restconf:errors.error.0.error-tag"

/* The console with the lab host, the admin's session: its entry in
 * /restconf/data (data) and in the candidate (cand), each len bytes. */
static void
rc_lab(const atf_tc_t *tc, char *data, char *cand, size_t len)
{
	struct authn	 a;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 64], id[16];

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "unix:%s/jgd.sock", cwd);
	host_add("lab", body, id, sizeof(id));
	if (data != NULL)
		snprintf(data, len, FLEET "%s", id);
	snprintf(cand, len, "/restconf/ds/ietf-datastores:candidate/"
	    "arcana-fleet:fleet/host=%s", id);
}

/* method of what is below base, with headers extra (NULL: none), its
 * status and error-tag what is said. */
static void
rc_expect(const char *method, const char *base, const char *below,
    const char *extra, const char *body, int status, const char *tag)
{
	struct resp	 r;
	char		 path[512];

	snprintf(path, sizeof(path), "%s%s", base, below);
	http_with(method, path, extra != NULL ? extra : "", body, &r);
	ATF_CHECK_MSG(r.status == status, "%s %s: %d, not %d: %s", method,
	    below, r.status, status, r.body);
	if (tag != NULL)
		ATF_CHECK_STREQ(tag, jstr(&r, ERROR_TAG));
	resp_free(&r);
}

/* Whether a, b and c are in s in that order. */
static bool
in_order(const char *s, const char *a, const char *b, const char *c)
{
	const char	*pa, *pb, *pc;

	return ((pa = strstr(s, a)) != NULL && (pb = strstr(s, b)) != NULL &&
	    (pc = strstr(s, c)) != NULL && pa < pb && pb < pc);
}

/*
 * One request with a body of len bytes and headers extra (each ending in
 * CRLF), the session's: its status, its content-type in ctype, its body
 * malloc'd in *out (*outlen bytes), as they came.
 */
static int
http_bin(const char *method, const char *path, const char *extra,
    const void *body, size_t blen, char *ctype, size_t ctlen, uint8_t **out,
    size_t *outlen)
{
	char	*req, *buf, *b, *c;
	size_t	 len = 0, cap = 65536, need = 0;
	ssize_t	 n;
	int	 s, status = 0;

	ATF_REQUIRE(asprintf(&req, "%s %s HTTP/1.1\r\nHost: localhost:8443\r\n"
	    "Connection: close\r\n%s%s%s%s%s%s%s%sContent-Length: %zu\r\n\r\n",
	    method, path, send_xjg ? "X-Arcana: 1\r\n" : "",
	    origin_hdr != NULL ? "Origin: " : "",
	    origin_hdr != NULL ? origin_hdr : "",
	    origin_hdr != NULL ? "\r\n" : "",
	    cookie[0] != '\0' ? "Cookie: " : "", cookie,
	    cookie[0] != '\0' ? "\r\n" : "", extra, blen) != -1);
	s = console_socket();
	ATF_REQUIRE(write(s, req, strlen(req)) == (ssize_t)strlen(req));
	if (blen > 0)
		ATF_REQUIRE(write(s, body, blen) == (ssize_t)blen);
	free(req);
	ATF_REQUIRE((buf = malloc(cap + 1)) != NULL);
	for (;;) {
		if (len == cap)
			ATF_REQUIRE((buf = realloc(buf, (cap *= 2) + 1)) != NULL);
		if ((n = read(s, buf + len, cap - len)) <= 0)
			break;
		len += (size_t)n;
		buf[len] = '\0';
		if (need == 0 && (b = strstr(buf, "\r\n\r\n")) != NULL &&
		    (c = strcasestr(buf, "content-length:")) != NULL && c < b)
			need = (size_t)(b + 4 - buf) + strtoul(c + 15, NULL,
			    10);
		if (need != 0 && len >= need)
			break;
	}
	close(s);
	buf[len] = '\0';
	ATF_REQUIRE(sscanf(buf, "HTTP/1.1 %d", &status) == 1);
	ATF_REQUIRE((b = strstr(buf, "\r\n\r\n")) != NULL);
	ctype[0] = '\0';
	if ((c = strcasestr(buf, "\r\ncontent-type: ")) != NULL && c < b)
		snprintf(ctype, ctlen, "%.*s", (int)strcspn(c + 16, "\r"),
		    c + 16);
	*outlen = len - (size_t)(b + 4 - buf);
	ATF_REQUIRE((*out = malloc(*outlen + 1)) != NULL);
	memcpy(*out, b + 4, *outlen);
	(*out)[*outlen] = '\0';
	free(buf);
	return (status);
}

/* Every .sid file of share/yang, the agent's own: an array of them. */
static ucl_object_t *
sid_files(void)
{
	struct ucl_parser	*p;
	struct dirent		*d;
	ucl_object_t		*arr;
	DIR			*dir;
	char			 path[MAXPATHLEN];

	arr = ucl_object_typed_new(UCL_ARRAY);
	ATF_REQUIRE((dir = opendir(TESTSRC "/../../../share/yang")) != NULL);
	while ((d = readdir(dir)) != NULL) {
		if (strlen(d->d_name) < 5 || strcmp(d->d_name +
		    strlen(d->d_name) - 4, ".sid") != 0)
			continue;
		snprintf(path, sizeof(path), "%s/../../../share/yang/%s",
		    TESTSRC, d->d_name);
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
		ATF_REQUIRE_MSG(ucl_parser_add_file(p, path), "%s", path);
		ucl_array_append(arr, ucl_parser_get_object(p));
		ucl_parser_free(p);
	}
	closedir(dir);
	return (arr);
}

/*
 * application/yang-data+cbor (PLAN-SDN-YANG 4.1.10): a host's YANG-CBOR
 * passed through, as the agent has it, its keys SIDs; the page's decoder
 * (www/arcana-ui/src/ycbor.c) reads it by the agent's .sid files to what
 * the JSON says; a PUT's body of it; what the console makes of JSON
 * refused with it.
 */
CONSOLE_TC(restconf_cbor, "application/yang-data+cbor: a host's YANG-CBOR "
    "passed through and read by the page's decoder; a PUT of it")
ATF_TC_BODY(restconf_cbor, tc)
{
	static const char cbor[] = "Accept: application/yang-data+cbor\r\n";
	/* {group: [{name: "gc", user-name: ["uc"]}]}, 1259 its SID. */
	static const uint8_t group[] = { 0xa1, 0x19, 0x04, 0xeb, 0x81, 0xa2,
	    0x01, 0x62, 'g', 'c', 0x02, 0x81, 0x62, 'u', 'c' };
	struct resp	 r;
	ucl_object_t	*sids, *o;
	const ucl_object_t *a, *b;
	uint8_t		*out;
	size_t		 len;
	char		 data[256], cand[256], path[512], ctype[128], why[160];
	int		 st;

	rc_lab(tc, data, cand, sizeof(cand));
	sids = sid_files();
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces", data);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	st = http_bin("GET", path, cbor, NULL, 0, ctype, sizeof(ctype), &out,
	    &len);
	ATF_REQUIRE_MSG(st == 200, "%d %s", st, out);
	ATF_CHECK_MSG(strncmp(ctype, "application/yang-data+cbor", 26) == 0,
	    "%s", ctype);
	o = ycbor_json(out, len, sids, why, sizeof(why));
	ATF_REQUIRE_MSG(o != NULL, "%s", why);
	/* Each interface the JSON has, named the same. */
	a = ucl_object_lookup_path(r.json, "ietf-interfaces:interfaces.interface");
	b = ucl_object_lookup_path(o, "ietf-interfaces:interfaces.interface");
	ATF_REQUIRE(a != NULL && b != NULL);
	ATF_CHECK_EQ(ucl_array_size(a), ucl_array_size(b));
	for (unsigned i = 0; i < ucl_array_size(a); i++)
		ATF_CHECK_STREQ(ucl_object_tostring(ucl_object_lookup(
		    ucl_array_find_index(a, i), "name")), ucl_object_tostring(
		    ucl_object_lookup(ucl_array_find_index(b, i), "name")));
	ucl_object_unref(o);
	free(out);
	resp_free(&r);
	/* The host's entry: each top-level node the agent has. */
	st = http_bin("GET", data, cbor, NULL, 0, ctype, sizeof(ctype), &out,
	    &len);
	ATF_REQUIRE_MSG(st == 200, "%d %s", st, out);
	o = ycbor_json(out, len, sids, why, sizeof(why));
	ATF_REQUIRE_MSG(o != NULL, "%s", why);
	ATF_CHECK(ucl_object_lookup(o, "ietf-interfaces:interfaces") != NULL);
	ATF_CHECK(ucl_object_lookup(o, "ietf-yang-library:yang-library") !=
	    NULL);
	ucl_object_unref(o);
	free(out);
	/* What the console makes of JSON is not asked of YANG-CBOR. */
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces?depth=2",
	    data);
	st = http_bin("GET", path, cbor, NULL, 0, ctype, sizeof(ctype), &out,
	    &len);
	ATF_CHECK_MSG(st == 400, "%d %s", st, out);
	free(out);
	st = http_bin("GET", data, "Accept: application/yang-data+cbor; "
	    "id=name\r\n", NULL, 0, ctype, sizeof(ctype), &out, &len);
	ATF_CHECK_MSG(st == 406, "%d %s", st, out);
	free(out);
	/* JSON first in Accept: JSON. */
	st = http_bin("GET", data, "Accept: application/yang-data+json, "
	    "application/yang-data+cbor\r\n", NULL, 0, ctype, sizeof(ctype),
	    &out, &len);
	ATF_CHECK_MSG(st == 200 && strstr(ctype, "json") != NULL, "%d %s", st,
	    ctype);
	free(out);
	/* A PUT of YANG-CBOR: the group made, as JSON reads it back. */
	snprintf(path, sizeof(path), "%s" NACM "/groups/group=gc", cand);
	st = http_bin("PUT", path, "Content-Type: application/yang-data+cbor"
	    "\r\n", group, sizeof(group), ctype, sizeof(ctype), &out, &len);
	ATF_CHECK_MSG(st == 201, "%d %s", st, out);
	free(out);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("uc", jstr(&r, "ietf-netconf-acm:group.0.user-name.0"));
	resp_free(&r);
	st = http_bin("PUT", path, "Content-Type: application/yang-data+cbor"
	    "\r\n", "\xa1\x19\x04", 3, ctype, sizeof(ctype), &out, &len);
	ATF_CHECK_MSG(st == 400 && strstr((char *)out, "malformed-message") !=
	    NULL, "%d %s", st, out);
	free(out);
	ucl_object_unref(sids);
}

/*
 * RFC 8040 section 4's changes, of the candidate's NACM rules: POST
 * makes a node under its target (201, its Location), data-exists the
 * second time; PUT makes (201) or replaces (204); a plain PATCH merges,
 * and makes nothing where its target is not; DELETE takes an entry and
 * a leaf-list's value away, data-missing the second time; insert and
 * point place an entry of an ordered-by user list; a plain PATCH of the
 * datastore merges its top-level nodes.
 */
CONSOLE_TC(restconf_edit, "RESTCONF's POST, PUT, PATCH and DELETE of the "
    "candidate, their status codes, Location, insert and point")
ATF_TC_BODY(restconf_edit, tc)
{
	struct resp	 r;
	char		 cand[256], path[512], loc[512];

	rc_lab(tc, NULL, cand, sizeof(cand));
	/* POST: a group made, where Location says. */
	snprintf(path, sizeof(path), "%s" NACM "/groups", cand);
	http("POST", path, "{\"ietf-netconf-acm:group\":[{\"name\":\"g1\","
	    "\"user-name\":[\"u1\"]}]}", &r);
	EXPECT(&r, 201);
	ATF_REQUIRE_MSG(resp_header(&r, "location", loc, sizeof(loc)) != NULL,
	    "%s", r.head);
	ATF_CHECK_MSG(strstr(loc, cand) != NULL && strstr(loc, NACM
	    "/groups/group=g1") != NULL, "%s", loc);
	resp_free(&r);
	rc_expect("POST", cand, NACM "/groups", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"g1\"}]}", 409,
	    "data-exists");
	/* Of the datastore, a top-level node (section 4.4.1's jukebox). */
	rc_expect("POST", cand, "", NULL, "{\"ietf-netconf-acm:nacm\":{}}",
	    409, "data-exists");
	http("GET", strstr(loc, "/restconf/"), NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("u1", jstr(&r, "ietf-netconf-acm:group.0.user-name.0"));
	resp_free(&r);
	/* PUT: made, then replaced; the body's key must be the path's. */
	rc_expect("PUT", cand, NACM "/groups/group=g2", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"g2\"}]}", 201, NULL);
	rc_expect("PUT", cand, NACM "/groups/group=g2", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"g2\",\"user-name\":"
	    "[\"u2\"]}]}", 204, NULL);
	rc_expect("PUT", cand, NACM "/groups/group=g2", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"g3\"}]}", 400,
	    "invalid-value");
	/* Plain PATCH: merged; where nothing is, nothing made. */
	rc_expect("PATCH", cand, NACM "/groups/group=g2", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"g2\",\"user-name\":"
	    "[\"u3\"]}]}", 204, NULL);
	snprintf(path, sizeof(path), "%s" NACM "/groups/group=g2", cand);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"u2\"") != NULL && strstr(r.body,
	    "\"u3\"") != NULL, "%s", r.body);
	resp_free(&r);
	rc_expect("PATCH", cand, NACM "/groups/group=nosuch", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"nosuch\"}]}", 404,
	    "invalid-value");
	/* DELETE: a leaf-list's value, an entry; then data-missing. */
	rc_expect("DELETE", cand, NACM "/groups/group=g2/user-name=u2", NULL,
	    NULL, 204, NULL);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"u2\"") == NULL && strstr(r.body,
	    "\"u3\"") != NULL, "%s", r.body);
	resp_free(&r);
	rc_expect("DELETE", cand, NACM "/groups/group=g2", NULL, NULL, 204,
	    NULL);
	rc_expect("DELETE", cand, NACM "/groups/group=g2", NULL, NULL, 409,
	    "data-missing");
	rc_expect("GET", cand, NACM "/groups/group=g2", NULL, NULL, 404,
	    NULL);
	/* insert and point (4.8.5, 4.8.6): rule-lists are ordered by the
	 * user; PUT places one too. */
	rc_expect("POST", cand, NACM, NULL, "{\"ietf-netconf-acm:rule-list\":"
	    "[{\"name\":\"rl-b\"}]}", 201, NULL);
	rc_expect("POST", cand, NACM "?insert=first", NULL,
	    "{\"ietf-netconf-acm:rule-list\":[{\"name\":\"rl-a\"}]}", 201,
	    NULL);
	rc_expect("POST", cand, NACM "?insert=after&point=" NACM
	    "/rule-list=rl-a", NULL, "{\"ietf-netconf-acm:rule-list\":"
	    "[{\"name\":\"rl-m\"}]}", 201, NULL);
	rc_expect("PUT", cand, NACM "/rule-list=rl-z?insert=before&point=%2F"
	    "ietf-netconf-acm%3Anacm%2Frule-list%3Drl-a", NULL,
	    "{\"ietf-netconf-acm:rule-list\":[{\"name\":\"rl-z\"}]}", 201,
	    NULL);
	snprintf(path, sizeof(path), "%s" NACM, cand);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(in_order(r.body, "\"rl-z\"", "\"rl-a\"", "\"rl-m\"") &&
	    in_order(r.body, "\"rl-a\"", "\"rl-m\"", "\"rl-b\""), "%s",
	    r.body);
	resp_free(&r);
	/* A plain PATCH of the datastore: its top-level nodes merged. */
	rc_expect("PATCH", cand, "", NULL, "{\"ietf-netconf-acm:nacm\":"
	    "{\"groups\":{\"group\":[{\"name\":\"g9\"}]}}}", 204, NULL);
	rc_expect("GET", cand, NACM "/groups/group=g9", NULL, NULL, 200, NULL);
	rc_expect("GET", cand, NACM "/groups/group=g1", NULL, NULL, 200, NULL);
}

/*
 * RFC 8072's YANG Patch, its examples' kinds on the candidate's rule
 * lists: two made (A.1.2); one that is there already and another, the
 * whole refused and nothing made (A.1.1); an entry inserted after one
 * (A.1.3), one moved (A.1.4); merge, replace, delete and remove at
 * once; a datastore's edits by their whole paths (A.1.5); an edit not
 * well made, its edit-id in the status.
 */
CONSOLE_TC(restconf_yang_patch, "RFC 8072's YANG Patch of the candidate, "
    "all or nothing, its status")
ATF_TC_BODY(restconf_yang_patch, tc)
{
	struct resp	 r;
	char		 cand[256], path[512];

	rc_lab(tc, NULL, cand, sizeof(cand));
	snprintf(path, sizeof(path), "%s" NACM, cand);
	http_with("PATCH", path, YANG_PATCH, "{\"ietf-yang-patch:yang-patch\":"
	    "{\"patch-id\":\"add-lists\",\"edit\":[{\"edit-id\":\"edit1\","
	    "\"operation\":\"create\",\"target\":\"/rule-list=p1\","
	    "\"value\":{\"ietf-netconf-acm:rule-list\":[{\"name\":\"p1\"}]}},"
	    "{\"edit-id\":\"edit2\",\"operation\":\"create\",\"target\":"
	    "\"/rule-list=p3\",\"value\":{\"rule-list\":[{\"name\":\"p3\"}]}}"
	    "]}}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("add-lists", jstr(&r,
	    "ietf-yang-patch:yang-patch-status.patch-id"));
	ATF_CHECK_MSG(strstr(r.body, "\"ok\":[null]") != NULL, "%s", r.body);
	resp_free(&r);
	/* One there already: refused whole, its edit said. */
	http_with("PATCH", path, YANG_PATCH, "{\"ietf-yang-patch:yang-patch\":"
	    "{\"patch-id\":\"again\",\"edit\":[{\"edit-id\":\"edit1\","
	    "\"operation\":\"create\",\"target\":\"/rule-list=p4\","
	    "\"value\":{\"rule-list\":[{\"name\":\"p4\"}]}},"
	    "{\"edit-id\":\"edit2\",\"operation\":\"create\",\"target\":"
	    "\"/rule-list=p1\",\"value\":{\"rule-list\":[{\"name\":\"p1\"}]}}"
	    "]}}", &r);
	EXPECT(&r, 409);
	ATF_CHECK_STREQ("edit2", jstr(&r, "ietf-yang-patch:yang-patch-status."
	    "edit-status.edit.0.edit-id"));
	ATF_CHECK_STREQ("data-exists", jstr(&r, "ietf-yang-patch:"
	    "yang-patch-status.edit-status.edit.0.errors.error.0.error-tag"));
	ATF_CHECK_MSG(strstr(r.body, "rule-list[name='p1']") != NULL, "%s",
	    r.body);
	resp_free(&r);
	rc_expect("GET", cand, NACM "/rule-list=p4", NULL, NULL, 404, NULL);
	/* insert after, then move after. */
	http_with("PATCH", path, YANG_PATCH, "{\"ietf-yang-patch:yang-patch\":"
	    "{\"patch-id\":\"insert\",\"edit\":[{\"edit-id\":\"edit1\","
	    "\"operation\":\"insert\",\"target\":\"/rule-list=p2\","
	    "\"point\":\"/rule-list=p1\",\"where\":\"after\",\"value\":"
	    "{\"ietf-netconf-acm:rule-list\":[{\"name\":\"p2\"}]}}]}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", path, NULL, &r);
	ATF_CHECK_MSG(in_order(r.body, "\"p1\"", "\"p2\"", "\"p3\""), "%s",
	    r.body);
	resp_free(&r);
	http_with("PATCH", path, YANG_PATCH, "{\"ietf-yang-patch:yang-patch\":"
	    "{\"patch-id\":\"move\",\"edit\":[{\"edit-id\":\"edit1\","
	    "\"operation\":\"move\",\"target\":\"/rule-list=p1\","
	    "\"point\":\"/rule-list=p3\",\"where\":\"after\"}]}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", path, NULL, &r);
	ATF_CHECK_MSG(in_order(r.body, "\"p2\"", "\"p3\"", "\"p1\""), "%s",
	    r.body);
	resp_free(&r);
	/* merge, replace, delete, remove (of what is not there) at once. */
	http_with("PATCH", path, YANG_PATCH, "{\"ietf-yang-patch:yang-patch\":"
	    "{\"patch-id\":\"four\",\"edit\":["
	    "{\"edit-id\":\"m\",\"operation\":\"merge\",\"target\":"
	    "\"/rule-list=p2\",\"value\":{\"rule-list\":[{\"name\":\"p2\","
	    "\"group\":[\"gm\"]}]}},"
	    "{\"edit-id\":\"r\",\"operation\":\"replace\",\"target\":"
	    "\"/rule-list=p3\",\"value\":{\"rule-list\":[{\"name\":\"p3\","
	    "\"group\":[\"gr\"]}]}},"
	    "{\"edit-id\":\"d\",\"operation\":\"delete\",\"target\":"
	    "\"/rule-list=p1\"},"
	    "{\"edit-id\":\"x\",\"operation\":\"remove\",\"target\":"
	    "\"/rule-list=nosuch\"}]}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", path, NULL, &r);
	ATF_CHECK_MSG(strstr(r.body, "\"gm\"") != NULL && strstr(r.body,
	    "\"gr\"") != NULL && strstr(r.body, "\"p1\"") == NULL, "%s",
	    r.body);
	resp_free(&r);
	/* The datastore's: edits by their whole paths. */
	http_with("PATCH", cand, YANG_PATCH, "{\"ietf-yang-patch:yang-patch\":"
	    "{\"patch-id\":\"datastore\",\"edit\":[{\"edit-id\":\"edit1\","
	    "\"operation\":\"create\",\"target\":\"" NACM "/groups/group=pg\","
	    "\"value\":{\"ietf-netconf-acm:group\":[{\"name\":\"pg\"}]}}]}}",
	    &r);
	EXPECT(&r, 200);
	resp_free(&r);
	rc_expect("GET", cand, NACM "/groups/group=pg", NULL, NULL, 200, NULL);
	/* Not well made: insert without where; a move of what is not
	 * there. */
	http_with("PATCH", path, YANG_PATCH, "{\"ietf-yang-patch:yang-patch\":"
	    "{\"patch-id\":\"bad\",\"edit\":[{\"edit-id\":\"e9\","
	    "\"operation\":\"insert\",\"target\":\"/rule-list=p9\","
	    "\"value\":{\"rule-list\":[{\"name\":\"p9\"}]}}]}}", &r);
	EXPECT(&r, 400);
	ATF_CHECK_STREQ("e9", jstr(&r, "ietf-yang-patch:yang-patch-status."
	    "edit-status.edit.0.edit-id"));
	ATF_CHECK_STREQ("missing-attribute", jstr(&r, "ietf-yang-patch:"
	    "yang-patch-status.edit-status.edit.0.errors.error.0.error-tag"));
	resp_free(&r);
	http_with("PATCH", path, YANG_PATCH, "{\"ietf-yang-patch:yang-patch\":"
	    "{\"patch-id\":\"gone\",\"edit\":[{\"edit-id\":\"e8\","
	    "\"operation\":\"move\",\"target\":\"/rule-list=p9\","
	    "\"where\":\"first\"}]}}", &r);
	EXPECT(&r, 409);
	ATF_CHECK_STREQ("data-missing", jstr(&r, "ietf-yang-patch:"
	    "yang-patch-status.edit-status.edit.0.errors.error.0.error-tag"));
	resp_free(&r);
	/* The capability, and OPTIONS's Accept-Patch. */
	http("GET", "/restconf/data/ietf-restconf-monitoring:restconf-state",
	    NULL, &r);
	ATF_CHECK(strstr(r.body, "capability:yang-patch:1.0") != NULL);
	resp_free(&r);
	http("OPTIONS", path, NULL, &r);
	EXPECT(&r, 200);
	{
		char	v[256];

		ATF_CHECK_MSG(resp_header(&r, "accept-patch", v, sizeof(v)) !=
		    NULL && strstr(v, "application/yang-patch+json") != NULL,
		    "%s", r.head);
	}
	resp_free(&r);
}

/*
 * ETag and Last-Modified (RFC 8040 section 3.4.1): a GET of the
 * candidate has them, a conditional GET of the same is 304; an edit on
 * a stale tag or date is 412, on the right one goes and changes the tag;
 * If-Match: * and If-None-Match: * by what is there; running's tag
 * changes with a commit.
 */
CONSOLE_TC(restconf_etag, "RESTCONF's entity-tags and times of change, "
    "conditional reads and edits")
ATF_TC_BODY(restconf_etag, tc)
{
	static const char rules[] = "{\"ietf-netconf-acm:nacm\":{"
	    "\"groups\":{\"group\":[{\"name\":\"admin\",\"user-name\":"
	    "[\"admin\",\"console\"]}]},\"rule-list\":[{\"name\":\"admin\","
	    "\"group\":[\"admin\"],\"rule\":[{\"name\":\"all\",\"module-name\":"
	    "\"*\",\"access-operations\":\"*\",\"action\":\"permit\"}]}]}}";
	struct resp	 r;
	char		 data[256], cand[256], path[512], hdr[256];
	char		 e1[64], e2[64], lm[64], r1[64];

	rc_lab(tc, data, cand, sizeof(cand));
	snprintf(path, sizeof(path), "%s" NACM, cand);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_MSG(resp_header(&r, "etag", e1, sizeof(e1)) != NULL &&
	    resp_header(&r, "last-modified", lm, sizeof(lm)) != NULL, "%s",
	    r.head);
	resp_free(&r);
	snprintf(hdr, sizeof(hdr), "If-None-Match: %s\r\n", e1);
	rc_expect("GET", path, "", hdr, NULL, 304, NULL);
	snprintf(hdr, sizeof(hdr), "If-Modified-Since: %s\r\n", lm);
	rc_expect("GET", path, "", hdr, NULL, 304, NULL);
	rc_expect("GET", path, "", "If-Modified-Since: Sat, 01 Jan 2000 "
	    "00:00:00 GMT\r\n", NULL, 200, NULL);
	/* Stale: refused. */
	rc_expect("PUT", path, "/groups/group=e1", "If-Match: \"0-0\"\r\n",
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"e1\"}]}", 412,
	    "operation-failed");
	rc_expect("PUT", path, "/groups/group=e1", "If-Unmodified-Since: Sat, "
	    "01 Jan 2000 00:00:00 GMT\r\n", "{\"ietf-netconf-acm:group\":"
	    "[{\"name\":\"e1\"}]}", 412, "operation-failed");
	/* As it is: made, the tag a new one. */
	snprintf(hdr, sizeof(hdr), "If-Match: %s\r\n", e1);
	snprintf(path, sizeof(path), "%s" NACM "/groups/group=e1", cand);
	http_with("PUT", path, hdr, "{\"ietf-netconf-acm:group\":[{\"name\":"
	    "\"e1\"}]}", &r);
	EXPECT(&r, 201);
	ATF_REQUIRE(resp_header(&r, "etag", e2, sizeof(e2)) != NULL);
	ATF_CHECK_MSG(strcmp(e1, e2) != 0, "%s %s", e1, e2);
	resp_free(&r);
	snprintf(hdr, sizeof(hdr), "If-None-Match: %s\r\n", e1);
	rc_expect("GET", path, "", hdr, NULL, 200, NULL);
	/* * : there, or not. */
	rc_expect("PUT", cand, NACM "/groups/group=e9", "If-Match: *\r\n",
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"e9\"}]}", 412,
	    "operation-failed");
	rc_expect("PUT", cand, NACM "/groups/group=e1", "If-None-Match: *\r\n",
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"e1\"}]}", 412,
	    "operation-failed");
	rc_expect("PUT", cand, NACM "/groups/group=e1", "If-Match: *\r\n",
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"e1\"}]}", 204, NULL);
	/* Running's: a commit changes it. */
	snprintf(path, sizeof(path), "%s" NACM, data);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(resp_header(&r, "etag", r1, sizeof(r1)) != NULL);
	resp_free(&r);
	rc_expect("PUT", cand, NACM, NULL, rules, 204, NULL);
	rc_expect("POST", data, "/ietf-netconf:commit", NULL, "{}", 204, NULL);
	snprintf(hdr, sizeof(hdr), "If-None-Match: %s\r\n", r1);
	rc_expect("GET", path, "", hdr, NULL, 200, NULL);
}

/*
 * RFC 8040 section 7: each error-tag the console says, a case each, of
 * its status.  The rest it does not say: lock-denied (the agents lock
 * nothing), rollback-failed and partial-operation (a change is all or
 * nothing), resource-denied (the agent's lack of memory), too-big (a
 * body too big is the server's 413 before RESTCONF's) and
 * unknown-attribute (an annotation in a body is a member like another).
 */
CONSOLE_TC(restconf_tag_access_denied, "access-denied: 403, a viewer's "
    "change")
ATF_TC_BODY(restconf_tag_access_denied, tc)
{
	struct authn	 b;
	char		 cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	r1_role("look", "member", "viewer");
	cc_user(&b, "vic", "\"role\":[\"look\"]", -8);
	rc_expect("PUT", cand, NACM "/groups/group=v", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"v\"}]}", 403,
	    "access-denied");
}

CONSOLE_TC(restconf_tag_invalid_value, "invalid-value: 400, a body's key "
    "not the path's; 404, nothing there")
ATF_TC_BODY(restconf_tag_invalid_value, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("PUT", cand, NACM "/groups/group=a", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"b\"}]}", 400,
	    "invalid-value");
	rc_expect("GET", cand, NACM "/groups/group=nosuch", NULL, NULL, 404,
	    "invalid-value");
}

CONSOLE_TC(restconf_tag_operation_not_supported, "operation-not-supported: "
    "405, running PUT")
ATF_TC_BODY(restconf_tag_operation_not_supported, tc)
{
	char	data[256], cand[256];

	rc_lab(tc, data, cand, sizeof(cand));
	rc_expect("PUT", data, NACM "/groups/group=a", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"a\"}]}", 405,
	    "operation-not-supported");
}

CONSOLE_TC(restconf_tag_operation_failed, "operation-failed: 412, an "
    "If-Match not met")
ATF_TC_BODY(restconf_tag_operation_failed, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("PUT", cand, NACM "/groups/group=a", "If-Match: \"x\"\r\n",
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"a\"}]}", 412,
	    "operation-failed");
}

CONSOLE_TC(restconf_tag_in_use, "in-use: 409, a commit while another's "
    "confirmed commit waits")
ATF_TC_BODY(restconf_tag_in_use, tc)
{
	static const char rules[] = "{\"ietf-netconf-acm:nacm\":{"
	    "\"groups\":{\"group\":[{\"name\":\"admin\",\"user-name\":"
	    "[\"admin\",\"console\"]}]},\"rule-list\":[{\"name\":\"admin\","
	    "\"group\":[\"admin\"],\"rule\":[{\"name\":\"all\",\"module-name\":"
	    "\"*\",\"access-operations\":\"*\",\"action\":\"permit\"}]}]}}";
	char	data[256], cand[256];

	rc_lab(tc, data, cand, sizeof(cand));
	rc_expect("PUT", cand, NACM, NULL, rules, 204, NULL);
	rc_expect("POST", data, "/ietf-netconf:commit", NULL,
	    "{\"ietf-netconf:input\":{\"confirmed\":[null],"
	    "\"confirm-timeout\":60,\"persist\":\"p1\"}}", 204, NULL);
	rc_expect("POST", data, "/ietf-netconf:commit", NULL, "{}", 409,
	    "in-use");
	rc_expect("POST", data, "/ietf-netconf:cancel-commit", NULL,
	    "{\"ietf-netconf:input\":{\"persist-id\":\"p1\"}}", 204, NULL);
}

CONSOLE_TC(restconf_tag_data_exists, "data-exists: 409, a POST of what "
    "is there")
ATF_TC_BODY(restconf_tag_data_exists, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("POST", cand, NACM "/groups", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"a\"}]}", 201, NULL);
	rc_expect("POST", cand, NACM "/groups", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"a\"}]}", 409,
	    "data-exists");
}

CONSOLE_TC(restconf_tag_data_missing, "data-missing: 409, a DELETE of "
    "what is not there")
ATF_TC_BODY(restconf_tag_data_missing, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("DELETE", cand, NACM "/groups/group=nosuch", NULL, NULL,
	    409, "data-missing");
}

CONSOLE_TC(restconf_tag_missing_attribute, "missing-attribute: 400, "
    "insert=before without its point")
ATF_TC_BODY(restconf_tag_missing_attribute, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("POST", cand, NACM "?insert=before", NULL,
	    "{\"ietf-netconf-acm:rule-list\":[{\"name\":\"a\"}]}", 400,
	    "missing-attribute");
}

CONSOLE_TC(restconf_tag_bad_attribute, "bad-attribute: 400, insert in a "
    "list the system orders")
ATF_TC_BODY(restconf_tag_bad_attribute, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("POST", cand, NACM "/groups?insert=first", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"a\"}]}", 400,
	    "bad-attribute");
}

CONSOLE_TC(restconf_tag_unknown_element, "unknown-element: 400, a member "
    "that is no node")
ATF_TC_BODY(restconf_tag_unknown_element, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("PUT", cand, NACM, NULL, "{\"ietf-netconf-acm:nacm\":"
	    "{\"nosuch\":1}}", 400, "unknown-element");
}

CONSOLE_TC(restconf_tag_unknown_namespace, "unknown-namespace: 400, a "
    "module there is not")
ATF_TC_BODY(restconf_tag_unknown_namespace, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("PATCH", cand, "", NULL, "{\"example-nosuch:x\":{}}", 400,
	    "unknown-namespace");
}

CONSOLE_TC(restconf_tag_bad_element, "bad-element: 400, a value not of "
    "its leaf's type")
ATF_TC_BODY(restconf_tag_bad_element, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("PUT", cand, NACM, NULL, "{\"ietf-netconf-acm:nacm\":"
	    "{\"enable-nacm\":\"maybe\"}}", 400, "bad-element");
}

CONSOLE_TC(restconf_tag_malformed_message, "malformed-message: 400, a "
    "body that is not JSON")
ATF_TC_BODY(restconf_tag_malformed_message, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("PUT", cand, NACM, NULL, "{\"ietf-netconf-acm:nacm\": {",
	    400, "malformed-message");
}

#define	L3NM	"/restconf/data/ietf-l3vpn-ntw:l3vpn-ntw"

/*
 * RFC 9182 Appendix A.1, Figures 32 to 34, as published, but for three
 * errors of the figures against the module: Figure 32's route
 * distinguisher and target, "0:65550:1", which ietf-routing-types'
 * patterns refuse (a type 0's AS is 2 bytes), are "2:65550:1" here, the
 * type of a 4-byte AS (RFC 4364 section 4.2); Figure 34's IPv4
 * "static-addresses" is a case of a choice, no node, its members the
 * ipv4 container's own (as the figure has IPv6's); and its routing
 * protocol "ietf-vpn-common:direct", an identity RFC 9181 names
 * direct-routing.
 */
static const char l3nm_fig32[] =
    "{\"ietf-l3vpn-ntw:vpn-services\":{\"vpn-service\":[{\"vpn-id\":\"4G\","
    "\"vpn-description\":\"VPN to deploy 4G services\",\"customer-name\":"
    "\"mycustomer\",\"vpn-service-topology\":\"custom\","
    "\"vpn-instance-profiles\":{\"vpn-instance-profile\":[{\"profile-id\":"
    "\"simple-profile\",\"local-as\":65550,\"rd\":\"2:65550:1\","
    "\"address-family\":[{\"address-family\":\"ietf-vpn-common:dual-stack\","
    "\"vpn-targets\":{\"vpn-target\":[{\"id\":1,\"route-targets\":"
    "[{\"route-target\":\"2:65550:1\"}],\"route-target-type\":\"both\"}]}}]}]}}"
    "]}}";
static const char l3nm_fig33[] =
    "{\"ietf-l3vpn-ntw:vpn-nodes\":{\"vpn-node\":[{\"vpn-node-id\":\"44\","
    "\"ne-id\":\"198.51.100.1\",\"active-vpn-instance-profiles\":"
    "{\"vpn-instance-profile\":[{\"profile-id\":\"simple-profile\"}]}}]}}";
#define	L3NM_ACCESS(id, vlan, what)					\
    "{\"id\":\"" id "\",\"interface-id\":\"1/1/1\",\"description\":"	\
    "\"Interface " what " to eNODE-B\",\"vpn-network-access-type\":"	\
    "\"ietf-vpn-common:point-to-point\",\"vpn-instance-profile\":"	\
    "\"simple-profile\",\"status\":{\"admin-status\":{\"status\":"	\
    "\"ietf-vpn-common:admin-up\"}},\"connection\":{\"encapsulation\":"	\
    "{\"type\":\"ietf-vpn-common:dot1q\",\"dot1q\":{\"cvlan-id\":" vlan	\
    "}}},\"ip-connection\":{\"ipv4\":{\"local-address\":\"192.0.2.1\","	\
    "\"prefix-length\":30,\"address-allocation-type\":\"static-address\","	\
    "\"primary-address\":\"1\",\"address\":"				\
    "[{\"address-id\":\"1\",\"customer-address\":\"192.0.2.2\"}]},"	\
    "\"ipv6\":{\"local-address\":\"2001:db8::1\",\"prefix-length\":64,"	\
    "\"address-allocation-type\":\"static-address\",\"primary-address\":"	\
    "\"1\",\"address\":[{\"address-id\":\"1\",\"customer-address\":"	\
    "\"2001:db8::2\"}]}},\"routing-protocols\":{\"routing-protocol\":"	\
    "[{\"id\":\"1\",\"type\":\"ietf-vpn-common:direct-routing\"}]}}"
static const char l3nm_fig34[] =
    "{\"ietf-l3vpn-ntw:vpn-network-accesses\":{\"vpn-network-access\":["
    L3NM_ACCESS("1/1/1.1", "1", "SYNC") ","
    L3NM_ACCESS("1/1/1.2", "2", "DATA") "]}}";

/* A module of the console's own datastore, which no host has; not
 * ietf-vpn-common, which the agents implement too for RFC 9408's SAPs
 * (no data nodes of its own). */
static bool
own_name(const char *m, size_t n)
{
	static const char *const own[] = { "ietf-l3vpn-ntw", "arcana-l3nm",
	    "ietf-vn" };

	for (size_t i = 0; i < nitems(own); i++)
		if (strlen(own[i]) == n && strncmp(m, own[i], n) == 0)
			return (true);
	return (false);
}

/* A host entry's member (RFC 7951's module:node) of the console's own
 * modules, into where; NULL: none. */
static const char *
own_top(const ucl_object_t *top, char *where, size_t len)
{
	const ucl_object_t	*h, *m;
	ucl_object_iter_t	 it = NULL;
	const char		*k, *c;

	h = ucl_array_find_index(ucl_object_lookup(top, "arcana-fleet:host"),
	    0);
	while ((m = ucl_object_iterate(h, &it, true)) != NULL) {
		k = ucl_object_key(m);
		if ((c = strchr(k, ':')) != NULL && own_name(k, (size_t)(c -
		    k))) {
			snprintf(where, len, "%s", k);
			return (where);
		}
	}
	return (NULL);
}

/* A module of a yang-library's module sets, implemented or imported,
 * of the console's own, into where; NULL: none. */
static const char *
own_module(const ucl_object_t *top, char *where, size_t len)
{
	static const char *const lists[] = { "module", "import-only-module" };
	const ucl_object_t	*set, *m;
	ucl_object_iter_t	 it = NULL, mit;
	const char		*n;

	while ((set = ucl_object_iterate(ucl_object_lookup_path(top,
	    "ietf-yang-library:yang-library.module-set"), &it, true)) != NULL)
		for (size_t i = 0; i < nitems(lists); i++) {
			mit = NULL;
			while ((m = ucl_object_iterate(ucl_object_lookup(set,
			    lists[i]), &mit, true)) != NULL)
				if ((n = ucl_object_tostring(ucl_object_lookup(m,
				    "name"))) != NULL && own_name(n, strlen(n))) {
					snprintf(where, len, "%s", n);
					return (where);
				}
		}
	return (NULL);
}

CONSOLE_TC(l3nm, "the services as L3NM, the console's own datastore: RFC "
    "9182 Appendix A.1 made by its three POSTs, read back, changed, "
    "checked and kept")
ATF_TC_BODY(l3nm, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 etag[64];

	start(tc, 0, NULL);
	http("GET", L3NM, NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	enrol(&a);
	/* Nothing kept yet. */
	http("GET", L3NM "/vpn-services", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* Figure 32 as published: its route target refused, the node at
	 * fault said. */
	{
		char	pub[sizeof(l3nm_fig32)], *p;

		memcpy(pub, l3nm_fig32, sizeof(pub));
		while ((p = strstr(pub, "2:65550:1")) != NULL)
			*p = '0';
		http("POST", L3NM, pub, &r);
		EXPECT(&r, 400);
		ATF_CHECK(strstr(r.body, "route-targets/route-target\"") !=
		    NULL || strstr(r.body, "/rd\"") != NULL);
		resp_free(&r);
	}
	/* Figure 32: the service, below a container not yet there. */
	http("POST", L3NM, l3nm_fig32, &r);
	EXPECT(&r, 201);
	ATF_CHECK_MSG(resp_header(&r, "location", etag, sizeof(etag)) !=
	    NULL, "%s", r.head);
	resp_free(&r);
	http("POST", L3NM "/vpn-services/vpn-service=4G", l3nm_fig33, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("POST", L3NM "/vpn-services/vpn-service=4G/vpn-nodes/vpn-node=44",
	    l3nm_fig34, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	/* Read back, whole and a node. */
	http("GET", L3NM, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("4G", jstr(&r, "ietf-l3vpn-ntw:l3vpn-ntw.vpn-services."
	    "vpn-service.0.vpn-id"));
	ATF_CHECK_STREQ("ietf-vpn-common:custom", jstr(&r, "ietf-l3vpn-ntw:"
	    "l3vpn-ntw.vpn-services.vpn-service.0.vpn-service-topology"));
	ATF_CHECK_STREQ("2:65550:1", jstr(&r, "ietf-l3vpn-ntw:l3vpn-ntw."
	    "vpn-services.vpn-service.0.vpn-instance-profiles."
	    "vpn-instance-profile.0.rd"));
	ATF_CHECK_MSG(resp_header(&r, "etag", etag, sizeof(etag)) != NULL,
	    "%s", r.head);
	resp_free(&r);
	/* (A key with "/" in it is not named in a path the server has
	 * decoded: the accesses read and changed by their container.) */
	http("GET", L3NM "/vpn-services/vpn-service=4G/vpn-nodes/vpn-node=44/"
	    "vpn-network-accesses", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("2", jstr(&r, "ietf-l3vpn-ntw:vpn-network-accesses."
	    "vpn-network-access.1.connection.encapsulation.dot1q.cvlan-id"));
	resp_free(&r);
	/* Changed: merged; a value not of its type refused; a leafref to
	 * no profile of the node refused, nothing kept of either. */
	http("PATCH", L3NM "/vpn-services/vpn-service=4G", "{\"ietf-l3vpn-ntw:"
	    "vpn-service\":[{\"vpn-id\":\"4G\",\"vpn-name\":\"mobile\"}]}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("PATCH", L3NM "/vpn-services/vpn-service=4G/vpn-nodes/"
	    "vpn-node=44/vpn-network-accesses", "{\"ietf-l3vpn-ntw:"
	    "vpn-network-accesses\":{\"vpn-network-access\":[{\"id\":"
	    "\"1/1/1.1\",\"connection\":{\"encapsulation\":{\"dot1q\":"
	    "{\"cvlan-id\":5000}}}}]}}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("PATCH", L3NM "/vpn-services/vpn-service=4G/vpn-nodes/"
	    "vpn-node=44/vpn-network-accesses", "{\"ietf-l3vpn-ntw:"
	    "vpn-network-accesses\":{\"vpn-network-access\":[{\"id\":"
	    "\"1/1/1.1\",\"vpn-instance-profile\":\"nosuch\"}]}}", &r);
	ATF_CHECK_MSG(r.status == 400 || r.status == 409, "%d %s", r.status,
	    r.body);
	ATF_CHECK(strstr(r.body, "error-tag") != NULL);
	resp_free(&r);
	/* Kept: across a restart, in /restconf/data, the library naming
	 * its modules. */
	restart_console();
	http("GET", L3NM "/vpn-services/vpn-service=4G/vpn-name", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("mobile", jstr(&r, "ietf-l3vpn-ntw:vpn-name"));
	resp_free(&r);
	http("GET", L3NM "/vpn-services/vpn-service=4G/vpn-nodes/vpn-node=44/"
	    "vpn-network-accesses", NULL, &r);
	ATF_CHECK_STREQ("simple-profile", jstr(&r, "ietf-l3vpn-ntw:"
	    "vpn-network-accesses.vpn-network-access.0.vpn-instance-profile"));
	ATF_CHECK_STREQ("1", jstr(&r, "ietf-l3vpn-ntw:vpn-network-accesses."
	    "vpn-network-access.0.connection.encapsulation.dot1q.cvlan-id"));
	resp_free(&r);
	http("GET", "/restconf/data", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("4G", jstr(&r, "ietf-l3vpn-ntw:l3vpn-ntw.vpn-services."
	    "vpn-service.0.vpn-id"));
	ATF_CHECK(strstr(r.body, "\"name\":\"ietf-l3vpn-ntw\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"name\":\"ietf-vpn-common\"") != NULL);
	resp_free(&r);
	/* A host's are as they were: its drift, its entry and what is
	 * mounted there, none of the console's own modules. */
	{
		char	id[16], path[256], where[128];

		cc_host("lab", "jgd.sock", id, sizeof(id));
		snprintf(path, sizeof(path), CC "hosts/host=%s/drift", id);
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("true", jstr(&r, "arcana-console:drift.ok"));
		resp_free(&r);
		snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:"
		    "fleet/host=%s", id);
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		/* By key: the host's processes' arguments are free text
		 * (arcana-processes), a test's anywhere on the VM. */
		ATF_CHECK(jstr(&r, "arcana-fleet:host.0.id") != NULL);
		ATF_CHECK_MSG(own_top(r.json, where, sizeof(where)) == NULL,
		    "the host's data has %s", where);
		resp_free(&r);
		snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:"
		    "fleet/host=%s/ietf-yang-library:yang-library", id);
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK(strstr(r.body, "\"ietf-interfaces\"") != NULL);
		ATF_CHECK_MSG(own_module(r.json, where, sizeof(where)) == NULL,
		    "the host's library names %s", where);
		resp_free(&r);
		snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:"
		    "fleet/host=%s/ietf-l3vpn-ntw:l3vpn-ntw", id);
		http("GET", path, NULL, &r);
		/* No host has it: no such resource. */
		EXPECT(&r, 404);
		resp_free(&r);
	}
	/* Taken away. */
	http("DELETE", L3NM "/vpn-services/vpn-service=4G", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", L3NM "/vpn-services/vpn-service=4G", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
}

/*
 * The SD-WAN document's example (sdwan_good, @A and @B as edges a and
 * b) as L3NM and arcana-l3nm, by the mapping arcana-l3nm says: an SWVC
 * a vpn-service, its domains its VPN instance profiles (RD, RTs), each
 * edge with end points a vpn-node, each end point a vpn-network-access
 * (the UNI's interface, VLAN, first provider address and subnet length,
 * static routes and BGP L3NM's), the rest the augments.
 */
static const char l3nm_good[] =
    "{\"ietf-l3vpn-ntw:l3vpn-ntw\":{\"arcana-l3nm:sdwan\":{\"ucs\":[{\"id\""
    ":\"inet\",\"type\":\"public\",\"billing\":\"flat-rate\",\"tunnel\":{\""
    "kind\":\"gre\",\"ipsec\":true}},{\"id\":\"mpls\",\"type\":\"private\","
    "\"billing\":\"flat-rate\",\"tunnel\":{\"kind\":\"geneve\"}}],\"edge\":"
    "[{\"server\":\"a\",\"ntp\":[\"ntp.example.org\",\"10.99.0.9\"],\"ucs-e"
    "nd-point\":[{\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0"
    "\",\"breakout\":true},{\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface"
    "\":\"vtnet1\"}]},{\"server\":\"b\",\"ucs-end-point\":[{\"id\":\"b-inet"
    "\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"},{\"id\":\"b-mpls\",\"ucs"
    "\":\"mpls\",\"interface\":\"vtnet1\",\"backup\":true}]}]},\"vpn-servic"
    "es\":{\"vpn-service\":[{\"vpn-id\":\"acme\",\"vpn-instance-profiles\":"
    "{\"vpn-instance-profile\":[{\"profile-id\":\"subscriber\",\"local-as\""
    ":64600,\"rd\":\"0:64600:3\",\"arcana-l3nm:domain\":\"subscriber\",\"ar"
    "cana-l3nm:fib\":1,\"arcana-l3nm:label\":1003},{\"profile-id\":\"servic"
    "e\",\"local-as\":64600,\"rd\":\"0:64600:1\",\"address-family\":[{\"add"
    "ress-family\":\"ietf-vpn-common:dual-stack\",\"vpn-targets\":{\"vpn-ta"
    "rget\":[{\"id\":1,\"route-targets\":[{\"route-target\":\"0:64600:1\"}]"
    ",\"route-target-type\":\"both\"}]}}],\"arcana-l3nm:domain\":\"service"
    "\",\"arcana-l3nm:label\":1001,\"arcana-l3nm:prefix\":\"100.64.0.0/24\""
    "},{\"profile-id\":\"breakout\",\"local-as\":64600,\"rd\":\"0:64600:2\""
    ",\"arcana-l3nm:domain\":\"breakout\",\"arcana-l3nm:fib\":2,\"arcana-l3"
    "nm:label\":1002}]},\"vpn-nodes\":{\"vpn-node\":[{\"vpn-node-id\":\"a\""
    ",\"ne-id\":\"a\",\"active-vpn-instance-profiles\":{\"vpn-instance-prof"
    "ile\":[{\"profile-id\":\"subscriber\"}]},\"vpn-network-accesses\":{\"v"
    "pn-network-access\":[{\"id\":\"hq\",\"interface-id\":\"vtnet2\",\"vpn-"
    "network-access-type\":\"ietf-vpn-common:multipoint\",\"vpn-instance-pr"
    "ofile\":\"subscriber\",\"ip-connection\":{\"ipv4\":{\"local-address\":"
    "\"10.1.0.1\",\"prefix-length\":24,\"address-allocation-type\":\"ietf-l"
    "3vpn-ntw:provider-dhcp\",\"arcana-l3nm:mode\":\"dhcp\",\"arcana-l3nm:p"
    "rovider\":[\"10.1.0.1\"],\"arcana-l3nm:reserved\":[\"10.1.0.0/26\",\"1"
    "0.1.0.200/30\"],\"arcana-l3nm:dns\":[\"10.1.0.1\"],\"arcana-l3nm:lease"
    "\":\"1h\"}},\"routing-protocols\":{\"routing-protocol\":[{\"id\":\"sta"
    "tic\",\"type\":\"ietf-vpn-common:static-routing\",\"static\":{\"cascad"
    "ed-lan-prefixes\":{\"ipv4-lan-prefixes\":[{\"lan\":\"10.1.8.0/22\",\"n"
    "ext-hop\":\"10.1.0.2\",\"arcana-l3nm:distance\":10}]}}},{\"id\":\"bgp-"
    "1\",\"type\":\"ietf-vpn-common:bgp-routing\",\"bgp\":{\"peer-as\":6501"
    "0,\"address-family\":\"ietf-vpn-common:ipv4\",\"neighbor\":[\"10.1.0.2"
    "\"],\"bgp-timers\":{\"hold-time\":90},\"authentication\":{\"enable\":t"
    "rue,\"keying-material\":{\"key\":\"s3cret\",\"crypto-algorithm\":\"iet"
    "f-key-chain:md5\"}},\"arcana-l3nm:distance\":150,\"arcana-l3nm:communi"
    "ty\":[{\"as\":64600,\"value\":100}]}}]},\"arcana-l3nm:sdwan\":{\"uni-i"
    "d\":\"uni-hq\",\"policy-map\":[{\"zone\":\"office\",\"app\":\"all\",\""
    "ingress\":\"hubonly\",\"egress\":\"quiet\"}],\"nat\":{\"ip-version\":"
    "\"ipv4\",\"public-prefix\":\"198.51.100.0/30\"}}},{\"id\":\"road\",\"i"
    "nterface-id\":\"wg5\",\"vpn-network-access-type\":\"ietf-vpn-common:mu"
    "ltipoint\",\"vpn-instance-profile\":\"subscriber\",\"arcana-l3nm:sdwan"
    "\":{\"remote\":{\"prefix\":\"10.30.0.0/24\",\"port\":51820,\"group\":["
    "{\"name\":\"staff\",\"zone\":\"office\",\"pool\":\"10.30.0.64/26\"},{"
    "\"name\":\"guests\",\"zone\":\"office\"}],\"identity\":[{\"name\":\"al"
    "ice\",\"zone\":\"office\",\"public-key\":\"xTIBA5rboUvnH4htodjb6e697Qj"
    "LERt1NAB4mZqp8Dg=\"},{\"name\":\"carol\",\"group\":\"staff\",\"public-"
    "key\":\"HIgo9xNzJMWLKASShiTqIYNW7HVnKq0pjaZxmvZ6rKA=\"}]}}}]}},{\"vpn-"
    "node-id\":\"b\",\"ne-id\":\"b\",\"active-vpn-instance-profiles\":{\"vp"
    "n-instance-profile\":[{\"profile-id\":\"subscriber\"}]},\"vpn-network-"
    "accesses\":{\"vpn-network-access\":[{\"id\":\"branch\",\"interface-id"
    "\":\"vtnet2\",\"vpn-network-access-type\":\"ietf-vpn-common:multipoint"
    "\",\"vpn-instance-profile\":\"subscriber\",\"connection\":{\"encapsula"
    "tion\":{\"type\":\"ietf-vpn-common:dot1q\",\"dot1q\":{\"cvlan-id\":20}"
    "}},\"ip-connection\":{\"ipv6\":{\"local-address\":\"2001:db8:1::1\",\""
    "prefix-length\":64,\"address-allocation-type\":\"ietf-l3vpn-ntw:slaac"
    "\",\"arcana-l3nm:mode\":\"slaac\",\"arcana-l3nm:provider\":[\"2001:db8"
    ":1::1\"],\"arcana-l3nm:dns\":[\"2001:db8:1::1\"]}},\"arcana-l3nm:sdwan"
    "\":{\"uni-id\":\"uni-br\"}}]}}]},\"arcana-l3nm:sdwan\":{\"fib\":1,\"md"
    "5\":\"edges-secret\",\"ucs\":[\"inet\",\"mpls\"],\"reserved-prefix\":["
    "\"100.64.0.0/24\"],\"zone\":[{\"name\":\"office\",\"prefix\":[\"10.1.0"
    ".0/16\"],\"policy\":[{\"app\":\"web\",\"policy\":\"fast\"}]},{\"name\""
    ":\"rest\",\"default\":[null]}],\"virtual-topology\":[{\"name\":\"hub\""
    ",\"type\":\"rooted-multipoint\",\"root\":[\"hq\"],\"leaf\":[\"branch\""
    "]}],\"intervals\":{\"eval\":1000,\"arrival\":100,\"ir\":500},\"bfd\":{"
    "\"interval\":200,\"multiplier\":3},\"tca\":{\"delay\":\"30\",\"loss\":"
    "\"0.05\",\"damping\":2},\"rate-limiter\":[{\"name\":\"shared\",\"commi"
    "t\":\"1000000\",\"limit\":\"5000000\"}],\"security-function-policy\":["
    "{\"id\":\"g-ippf\",\"function\":\"ippf\",\"allow\":{\"tuple\":[{\"id\""
    ":1,\"dav4\":[\"192.0.2.8/29\"]}]},\"block\":{\"tuple\":[{\"id\":1,\"da"
    "v4\":[\"192.0.2.0/24\"]}]},\"no-match\":\"allow\",\"duration\":6},{\"i"
    "d\":\"g-dnf\",\"function\":\"dnf\",\"block\":{\"value\":[\"ads.example"
    "\"]},\"allow\":{\"value\":[\"ok.ads.example\"]},\"no-match\":\"allow\""
    ",\"duration\":6},{\"id\":\"g-dpf\",\"function\":\"dpf\",\"block\":{\"t"
    "uple\":[{\"id\":1,\"sav4\":[\"192.0.2.53/32\"],\"message-type\":\"resp"
    "onse\"},{\"id\":2,\"dav4\":[\"192.0.2.54/32\"],\"message-type\":\"quer"
    "y\"}]},\"no-match\":\"block\",\"redirect\":true,\"duration\":6},{\"id"
    "\":\"g-urlf\",\"function\":\"urlf\",\"block\":{\"value\":[\"bad.exampl"
    "e\"]},\"no-match\":\"allow\",\"duration\":6},{\"id\":\"g-mdr\",\"funct"
    "ion\":\"mdr\",\"detection-type\":\"signature\",\"removal\":\"block-sub"
    "set\",\"block\":{\"value\":[\"44D88612FEA8A8F36DE82E1278ABB02F:68\",\""
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\"]},"
    "\"allow\":{\"value\":[\"3395856ce81f2b7382dee72602f798b642f14140\"]},"
    "\"no-match\":\"allow\",\"duration\":24}],\"security-policy\":[{\"name"
    "\":\"guard\",\"function-policy\":[\"g-ippf\",\"g-dnf\",\"g-dpf\",\"g-u"
    "rlf\",\"g-mdr\"],\"rate-limit\":\"2000000\",\"ids\":{\"mode\":\"preven"
    "t\",\"ruleset\":true,\"rule\":[\"alert http any any -> $HOME_NET any ("
    "msg:\\\"x\\\"; sid:1000001; rev:1;)\"]}}],\"importance\":{\"level\":["
    "\"high\",\"low\"],\"default\":\"low\"},\"application-flow-group\":[\"b"
    "ulk\"],\"application-flow\":[{\"name\":\"web\",\"criteria\":{\"dport\""
    ":[80,\"https\"],\"protv4\":[\"tcp\"]}},{\"name\":\"voice\",\"group\":"
    "\"bulk\",\"criteria\":{\"appid\":[\"sip\"],\"dscp\":[46]}},{\"name\":"
    "\"all\",\"criteria\":{\"any\":true}}],\"policy\":[{\"name\":\"fast\","
    "\"direction\":\"ingress\",\"criteria\":{\"encryption\":\"required-publ"
    "ic-only\",\"performance\":{\"primary\":{\"metric\":\"delay\",\"thresho"
    "ld\":\"10\",\"ceiling\":\"12\",\"remediation\":\"9\"},\"secondary\":[{"
    "\"metric\":\"loss\",\"threshold\":\"0.05\"}]},\"rate-limiter\":\"share"
    "d\",\"business-importance\":\"high\",\"internet-breakout\":\"enabled\""
    ",\"af-security-ingress\":\"guard\"}},{\"name\":\"hubonly\",\"direction"
    "\":\"ingress\",\"criteria\":{\"virtual-topology\":\"hub\"}},{\"name\":"
    "\"quiet\",\"direction\":\"egress\",\"criteria\":{\"egress-block\":\"di"
    "scard\"}}]}}]}}}";

static const char l3nm_full[] =
    "{\"ietf-l3vpn-ntw:l3vpn-ntw\":{\"arcana-l3nm:sdwan\":{\"ucs\":[{\"id\""
    ":\"wgu\",\"type\":\"public\",\"billing\":\"usage-based\",\"tunnel\":{"
    "\"kind\":\"wg\",\"mss\":\"auto\",\"mtu\":1420}},{\"id\":\"usw\",\"type"
    "\":\"public\",\"billing\":\"other\",\"tunnel\":{\"kind\":\"uswe\",\"ms"
    "s\":1360,\"mtu\":\"auto\",\"algorithms\":\"aes-gcm-16\",\"esn\":true,"
    "\"encap\":true,\"lifetime\":3600}}],\"edge\":[{\"server\":\"c/edge1\","
    "\"own-table\":true,\"host-bird\":false,\"transit\":true,\"bgp-import\""
    ":\"sets\",\"breakout-set\":[{\"set\":\"cdn\",\"via\":\"c-wg\"}],\"ucs-"
    "end-point\":[{\"id\":\"c-wg\",\"ucs\":\"wgu\",\"interface\":\"igb0\","
    "\"address\":\"192.0.2.10\",\"gateway\":\"192.0.2.1\",\"beacon\":\"198."
    "51.100.53\",\"breakout\":true,\"bandwidth\":\"100000000\",\"preference"
    "\":200,\"nat\":true,\"relay\":[{\"to\":\"a\",\"endpoint\":\"127.0.0.1:"
    "4096\",\"port\":4097,\"plugin\":\"speederv2\",\"fec\":\"20:10\",\"mode"
    "\":0}],\"addressing\":\"dhcp\",\"vrf\":3,\"routing\":{\"bgp\":[{\"id\""
    ":1,\"family\":\"both\",\"as\":65001,\"neighbor\":[\"192.0.2.1\",\"2001"
    ":db8::1\"],\"password\":\"pw\",\"hold-time\":30,\"source\":\"192.0.2.1"
    "0\",\"multihop\":true,\"distance\":20,\"bfd\":true,\"community\":[{\"a"
    "s\":65001,\"value\":7}]}],\"ospf\":[{\"id\":1,\"family\":\"ipv4\",\"ar"
    "ea\":0,\"cost\":10,\"password\":\"k\",\"hello\":10,\"dead\":40,\"dista"
    "nce\":110,\"bfd\":false}]}}]}],\"named-list\":[{\"name\":\"branches\","
    "\"kind\":\"prefixes\",\"item\":[\"10.2.0.0/16\"]},{\"name\":\"web\",\""
    "kind\":\"services\",\"protocol\":[\"tcp\"],\"port\":[80,\"443\",\"8000"
    "-8080\"]},{\"name\":\"links\",\"kind\":\"ucs-end-points\",\"item\":[\""
    "c-wg\"],\"end-point\":[{\"id\":\"c-wg\",\"preference\":5}]}]},\"vpn-se"
    "rvices\":{\"vpn-service\":[{\"vpn-id\":\"full\",\"vpn-instance-profile"
    "s\":{\"vpn-instance-profile\":[{\"profile-id\":\"subscriber\",\"local-"
    "as\":64700,\"arcana-l3nm:fib\":9}]},\"vpn-nodes\":{\"vpn-node\":[{\"vp"
    "n-node-id\":\"c/edge1\",\"ne-id\":\"c\",\"active-vpn-instance-profiles"
    "\":{\"vpn-instance-profile\":[{\"profile-id\":\"subscriber\"}]},\"vpn-"
    "network-accesses\":{\"vpn-network-access\":[{\"id\":\"lan\",\"interfac"
    "e-id\":\"igb1\",\"vpn-instance-profile\":\"subscriber\",\"connection\""
    ":{\"encapsulation\":{\"type\":\"ietf-vpn-common:untagged-int\"}},\"ip-"
    "connection\":{\"ipv4\":{\"local-address\":\"10.2.0.1\",\"prefix-length"
    "\":24,\"address-allocation-type\":\"ietf-l3vpn-ntw:static-address\",\""
    "arcana-l3nm:mode\":\"static\",\"arcana-l3nm:provider\":[\"10.2.0.1\","
    "\"10.2.0.2\"],\"arcana-l3nm:secondary\":[{\"prefix\":\"10.2.9.0/24\","
    "\"provider\":[\"10.2.9.1\"]}]},\"ipv6\":{\"arcana-l3nm:mode\":\"ll-onl"
    "y\"}},\"routing-protocols\":{\"routing-protocol\":[{\"id\":\"static\","
    "\"type\":\"ietf-vpn-common:static-routing\",\"static\":{\"cascaded-lan"
    "-prefixes\":{\"ipv6-lan-prefixes\":[{\"lan\":\"2001:db8:9::/48\",\"nex"
    "t-hop\":\"fe80::1\",\"arcana-l3nm:distance\":5}]}}},{\"id\":\"ospf-1\""
    ",\"type\":\"ietf-vpn-common:ospf-routing\",\"ospf\":{\"address-family"
    "\":\"ietf-vpn-common:ipv4\",\"area-id\":\"0.0.0.1\",\"metric\":10,\"au"
    "thentication\":{\"enable\":true,\"keying-material\":{\"key\":\"k2\"}},"
    "\"arcana-l3nm:hello\":5,\"arcana-l3nm:dead\":20,\"arcana-l3nm:bfd\":tr"
    "ue,\"arcana-l3nm:distance\":100}}]},\"arcana-l3nm:sdwan\":{\"uni-id\":"
    "\"uni-lan\",\"host-addressed\":true,\"max-frame\":9000,\"clat\":{\"pre"
    "fix\":\"2001:db8:46::/96\"},\"policy-map\":[{\"zone\":\"Internet\",\"a"
    "pp\":\"all\",\"egress\":\"out\"}],\"nat\":{\"disabled\":[null]},\"avai"
    "lability\":\"99.9\"}}]}}]},\"arcana-l3nm:sdwan\":{\"fib\":9,\"ucs\":["
    "\"wgu\",\"usw\"],\"bgp-set\":[{\"name\":\"cdn\",\"as-path\":[13335],\""
    "community\":[{\"as\":65001,\"value\":1}]}],\"nat64\":{\"prefix\":\"64:"
    "ff9b::/96\",\"pool\":\"192.0.2.64/28\",\"edge\":\"c/edge1\"},\"ibgp\":"
    "\"tunnel\",\"control-plane\":{\"host\":\"c/edge1\",\"cluster-id\":\"10"
    ".255.0.1\",\"ctvc\":\"wgu\"},\"zone\":[{\"name\":\"lan\",\"prefix-list"
    "\":\"branches\"}],\"virtual-topology\":[{\"name\":\"mesh\",\"type\":\""
    "multipoint-to-multipoint\",\"end-point\":[\"lan\",\"lan2\"]}],\"probe"
    "\":{\"interval\":500,\"size\":128,\"count\":0,\"dscp\":46,\"down\":3,"
    "\"up\":2,\"timeout\":1000,\"history\":100,\"report\":10},\"tca\":{\"ip"
    "dv\":\"5.5\"},\"security-function-policy\":[{\"id\":\"m\",\"function\""
    ":\"mbsf\",\"allow\":{\"value\":[\"tls1.2\",\"tls1.3\"]},\"no-match\":"
    "\"block\",\"invalid-server-certificate\":\"block\",\"invalid-client-ce"
    "rtificate\":\"allow\",\"unencrypted\":\"allow\",\"trusted-cas\":\"syst"
    "em\",\"pass-through\":[\"*.bank.example\"]},{\"id\":\"p\",\"function\""
    ":\"pdns\",\"block\":{\"pdns\":[{\"id\":1,\"type\":\"A\",\"value\":\"20"
    "3.0.113.0/24\",\"encryption\":[\"any\"]},{\"id\":2,\"type\":\"NS\",\"v"
    "alue\":\"ns.bad.example\"}]},\"lists\":{\"block\":[\"feed1\"]},\"no-ma"
    "tch\":\"allow\",\"duration\":12,\"notify\":[\"block\",\"quarantine\"],"
    "\"southbound\":[\"unencrypted\",\"dot\"],\"northbound\":\"dot\",\"upst"
    "ream\":[\"192.0.2.53@853#dns.example\"]},{\"id\":\"q\",\"function\":\""
    "ippf\",\"quarantine\":{\"tuple\":[{\"id\":1,\"sav6\":[\"2001:db8::/32"
    "\"],\"nextheadv6\":[\"udp\"],\"sport\":[53],\"dport\":[\"1000-2000\"]}"
    "]},\"no-match\":\"allow\",\"duration\":1}],\"security-policy\":[{\"nam"
    "e\":\"edge\",\"function-policy\":[\"m\",\"p\"]}],\"application-flow\":"
    "[{\"name\":\"svc\",\"group\":\"None\",\"criteria\":{\"service-list\":"
    "\"web\",\"src-list\":\"branches\",\"sdav4\":[\"10.0.0.0/8\"],\"dav6\":"
    "[\"2001:db8::/32\"],\"sdav6\":[\"2001:db8:1::/48\"],\"sav6\":[\"2001:d"
    "b8:2::/48\"],\"sdport\":[22],\"sport\":[1024],\"ethertype\":[2048],\"n"
    "extheadv6\":[6],\"sav4\":[\"10.9.0.0/16\"],\"dav4\":[\"10.8.0.0/16\"]}"
    "},{\"name\":\"tun\",\"criteria\":{\"dst-list\":\"branches\",\"sdst-lis"
    "t\":\"branches\"}}],\"policy\":[{\"name\":\"p1\",\"direction\":\"ingre"
    "ss\",\"criteria\":{\"ucs-list\":\"u\",\"edge-list\":\"e\",\"ucs-end-po"
    "int-list\":\"links\",\"public-private\":\"either\",\"backup\":\"disabl"
    "ed\",\"billing-method\":\"either\",\"virtual-topology\":\"Swvc\",\"all"
    "owed-destination-zones\":{\"zone\":[\"lan\",\"Self\"]},\"bandwidth\":{"
    "\"commit\":\"1000\",\"limit\":\"2000\"},\"performance\":{\"primary\":{"
    "\"metric\":\"loss\"}}}},{\"name\":\"p2\",\"direction\":\"ingress\",\"c"
    "riteria\":{\"allowed-destination-zones\":{\"all\":[null]}}},{\"name\":"
    "\"p3\",\"direction\":\"ingress\",\"criteria\":{\"allowed-destination-z"
    "ones\":{},\"internet-breakout\":\"enabled\"}},{\"name\":\"out\",\"dire"
    "ction\":\"egress\",\"criteria\":{\"egress-block\":\"allow\",\"af-secur"
    "ity-egress\":\"edge\"}}]}}]}}}";
/* a and b the same JSON: objects with the same members, arrays in the
 * same order, values with the same text.  false, where says where. */
static bool
same_json(const ucl_object_t *a, const ucl_object_t *b, char *where,
    size_t len)
{
	const ucl_object_t	*x, *y;
	ucl_object_iter_t	 it = NULL;
	const char		*sa, *sb;
	size_t			 n, i;
	double			 da, db;
	char			 sub[256], *ea, *eb;

	if (a == NULL || b == NULL || ucl_object_type(a) != ucl_object_type(b))
		return (false);
	switch (ucl_object_type(a)) {
	case UCL_OBJECT:
		if (a->len != b->len) {
			snprintf(where, len, "%s: %u members, not %u", where,
			    a->len, b->len);
			return (false);
		}
		while ((x = ucl_object_iterate(a, &it, true)) != NULL) {
			snprintf(sub, sizeof(sub), "%s.%s", where,
			    ucl_object_key(x));
			if (!same_json(x, ucl_object_lookup(b, ucl_object_key(x)),
			    sub, sizeof(sub))) {
				snprintf(where, len, "%s", sub);
				return (false);
			}
		}
		return (true);
	case UCL_ARRAY:
		if ((n = ucl_array_size(a)) != ucl_array_size(b))
			return (false);
		for (i = 0; i < n; i++) {
			x = ucl_array_find_index(a, i);
			y = ucl_array_find_index(b, i);
			snprintf(sub, sizeof(sub), "%s.%zu", where, i);
			if (!same_json(x, y, sub, sizeof(sub))) {
				snprintf(where, len, "%s", sub);
				return (false);
			}
		}
		return (true);
	case UCL_NULL:
		return (true);
	default:
		/* A decimal64 is written with all its fraction digits. */
		sa = ucl_object_tostring_forced(a);
		sb = ucl_object_tostring_forced(b);
		if (strcmp(sa, sb) == 0)
			return (true);
		da = strtod(sa, &ea);
		db = strtod(sb, &eb);
		return (ea != sa && *ea == '\0' && eb != sb && *eb == '\0' &&
		    da == db);
	}
}

static ucl_object_t *
json_of(const char *s)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
	ATF_REQUIRE(ucl_parser_add_string(p, s, 0));
	o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	return (o);
}

CONSOLE_TC(l3nm_sdwan, "the SD-WAN document's example as L3NM and "
    "arcana-l3nm, every field the document has in a node, kept and read "
    "back the same")
ATF_TC_BODY(l3nm_sdwan, tc)
{
	struct authn		 a;
	struct resp		 r;
	ucl_object_t		*want, *full;
	const ucl_object_t	*w, *g;
	char			 where[256];

	start(tc, 0, NULL);
	enrol(&a);
	http("PUT", L3NM, l3nm_good, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", L3NM, NULL, &r);
	EXPECT(&r, 200);
	want = json_of(l3nm_good);
	snprintf(where, sizeof(where), "l3vpn-ntw");
	ATF_CHECK_MSG(same_json(want, r.json, where, sizeof(where)),
	    "not as put at %s: %s", where, r.body);
	resp_free(&r);
	/* The fields the example has not: merged, read back the same. */
	http("PATCH", L3NM, l3nm_full, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", L3NM, NULL, &r);
	EXPECT(&r, 200);
	full = json_of(l3nm_full);
	w = ucl_array_find_index(ucl_object_lookup_path(full,
	    "ietf-l3vpn-ntw:l3vpn-ntw.vpn-services.vpn-service"), 0);
	g = ucl_array_find_index(ucl_object_lookup_path(r.json,
	    "ietf-l3vpn-ntw:l3vpn-ntw.vpn-services.vpn-service"), 1);
	snprintf(where, sizeof(where), "vpn-service");
	ATF_CHECK_MSG(same_json(w, g, where, sizeof(where)),
	    "not as merged at %s: %s", where, r.body);
	w = ucl_array_find_index(ucl_object_lookup_path(full,
	    "ietf-l3vpn-ntw:l3vpn-ntw.arcana-l3nm:sdwan.edge"), 0);
	g = ucl_array_find_index(ucl_object_lookup_path(r.json,
	    "ietf-l3vpn-ntw:l3vpn-ntw.arcana-l3nm:sdwan.edge"), 2);
	snprintf(where, sizeof(where), "edge");
	ATF_CHECK_MSG(same_json(w, g, where, sizeof(where)),
	    "not as merged at %s: %s", where, r.body);
	ATF_CHECK_STREQ("speederv2", jstr(&r, "ietf-l3vpn-ntw:l3vpn-ntw."
	    "arcana-l3nm:sdwan.edge.2.ucs-end-point.0.relay.0.plugin"));
	ATF_CHECK_STREQ("8000-8080", jstr(&r, "ietf-l3vpn-ntw:l3vpn-ntw."
	    "arcana-l3nm:sdwan.named-list.1.port.2"));
	resp_free(&r);
	/* The augments are checked as L3NM is: a security policy naming
	 * no function policy, a UCS End Point of no UCS. */
	http("PATCH", L3NM "/vpn-services/vpn-service=acme",
	    "{\"ietf-l3vpn-ntw:vpn-service\":[{\"vpn-id\":\"acme\","
	    "\"arcana-l3nm:sdwan\":{\"security-policy\":[{\"name\":\"x\","
	    "\"function-policy\":[\"nosuch\"]}]}}]}", &r);
	ATF_CHECK_MSG(r.status == 400 || r.status == 409, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	http("PATCH", L3NM, "{\"ietf-l3vpn-ntw:l3vpn-ntw\":{\"arcana-l3nm:"
	    "sdwan\":{\"edge\":[{\"server\":\"a\",\"ucs-end-point\":[{\"id\":"
	    "\"a-x\",\"ucs\":\"nosuch\"}]}]}}}", &r);
	ATF_CHECK_MSG(r.status == 400 || r.status == 409, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	/* A metric's value of no type refused. */
	http("PATCH", L3NM "/vpn-services/vpn-service=acme",
	    "{\"ietf-l3vpn-ntw:vpn-service\":[{\"vpn-id\":\"acme\","
	    "\"arcana-l3nm:sdwan\":{\"tca\":{\"loss\":\"2\"}}}]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	ucl_object_unref(want);
	ucl_object_unref(full);
}

ATF_TC_BODY(restconf, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 host[128], path[256], id[16];

	start(tc, 0, NULL);
	http("GET", "/.well-known/host-meta", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, "<Link rel='restconf' href='/restconf'/>") !=
	    NULL);
	resp_free(&r);
	/* Without a session: refused, as ietf-restconf's errors say it. */
	http("GET", "/restconf", NULL, &r);
	EXPECT(&r, 401);
	ATF_CHECK_STREQ("access-denied",
	    jstr(&r, "ietf-restconf:errors.error.0.error-tag"));
	resp_free(&r);
	enrol(&a);
	cc_host("lab", "jgd.sock", id, sizeof(id));
	snprintf(host, sizeof(host), "/restconf/data/arcana-fleet:fleet/"
	    "host=%s", id);
	http("GET", "/restconf", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("2019-01-04",
	    jstr(&r, "ietf-restconf:restconf.yang-library-version"));
	resp_free(&r);
	http("GET", "/restconf/data/arcana-fleet:fleet", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("lab", jstr(&r, "arcana-fleet:fleet.host.0.name"));
	resp_free(&r);
	/* Each host's agent mounted inline (RFC 8528). */
	http("GET", "/restconf/data/ietf-yang-schema-mount:schema-mounts",
	    NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("agent", jstr(&r, "ietf-yang-schema-mount:"
	    "schema-mounts.mount-point.0.label"));
	ATF_CHECK(strstr(r.body, "\"inline\":{}") != NULL);
	resp_free(&r);
	http("GET", "/restconf/data/ietf-restconf-monitoring:restconf-state",
	    NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("urn:ietf:params:restconf:capability:depth:1.0",
	    jstr(&r, "ietf-restconf-monitoring:restconf-state.capabilities."
	    "capability.1"));
	ATF_CHECK_STREQ(id, jstr(&r, "ietf-restconf-monitoring:restconf-state."
	    "streams.stream.0.name"));
	ATF_CHECK(strstr(r.body, "/restconf/streams/") != NULL);
	ATF_CHECK(strstr(r.body, "\"name\":\"fleet\"") != NULL &&
	    strstr(r.body, "/restconf/streams/fleet/json") != NULL);
	resp_free(&r);
	/* The host's events as Server-Sent Events: a job's comes. */
	{
		struct timeval	 tv = { 10, 0 };
		char		 rq[512], buf[16384];
		size_t		 len = 0;
		ssize_t		 n;
		int		 s, i;

		s = console_socket();
		ATF_REQUIRE(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv,
		    sizeof(tv)) == 0);
		snprintf(rq, sizeof(rq), "GET /restconf/streams/%s/json "
		    "HTTP/1.1\r\nHost: localhost:8443\r\nCookie: %s\r\n\r\n",
		    id, cookie);
		ATF_REQUIRE(write(s, rq, strlen(rq)) == (ssize_t)strlen(rq));
		buf[0] = '\0';
		for (i = 0; i < 50 && strstr(buf, "NETCONF stream") == NULL;
		    i++) {
			if ((n = read(s, buf + len, sizeof(buf) - 1 - len)) <= 0)
				break;
			len += (size_t)n;
			buf[len] = '\0';
		}
		ATF_CHECK_MSG(strstr(buf, "200") != NULL && strstr(buf,
		    "text/event-stream") != NULL, "%s", buf);
		/* Subscribed once the thread has the host: then a job. */
		usleep(1500000);
		r1_submit(id, "{\"monitor\":{\"verb\":\"set\",\"args\":["
		    "\"name=gre9\",\"interface=gre9\",\"address=192.0.2.9\","
		    "\"interval=500\",\"eval=10000\"]}}", &r);
		resp_free(&r);
		for (i = 0; i < 50 && strstr(buf, "arcana-events:event") ==
		    NULL; i++) {
			if ((n = read(s, buf + len, sizeof(buf) - 1 - len)) <= 0)
				break;
			len += (size_t)n;
			buf[len] = '\0';
		}
		ATF_CHECK_MSG(strstr(buf, "\nid: 20") != NULL && strstr(buf,
		    "\ndata: {\"ietf-restconf:notification\":{\"eventTime\":")
		    != NULL && strstr(buf, "\"arcana-events:event\":") != NULL,
		    "%s", buf);
		close(s);
		/* Back with the id of one before: the agent's kept events
		 * since then first, the job's among them, then its replay
		 * said done. */
		s = console_socket();
		ATF_REQUIRE(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv,
		    sizeof(tv)) == 0);
		snprintf(rq, sizeof(rq), "GET /restconf/streams/%s/json "
		    "HTTP/1.1\r\nHost: localhost:8443\r\nCookie: %s\r\n"
		    "Last-Event-ID: 2001-01-01T00:00:00Z\r\n\r\n", id, cookie);
		ATF_REQUIRE(write(s, rq, strlen(rq)) == (ssize_t)strlen(rq));
		len = 0;
		buf[0] = '\0';
		for (i = 0; i < 50 && strstr(buf, "replay-completed") == NULL;
		    i++) {
			if ((n = read(s, buf + len, sizeof(buf) - 1 - len)) <= 0)
				break;
			len += (size_t)n;
			buf[len] = '\0';
		}
		ATF_CHECK_MSG(strstr(buf, "\"arcana-events:event\":") != NULL &&
		    strstr(buf, "replay-completed") != NULL, "%s", buf);
		close(s);
		/* The fleet's: the same, each record in its host's entry. */
		s = console_socket();
		ATF_REQUIRE(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv,
		    sizeof(tv)) == 0);
		snprintf(rq, sizeof(rq), "GET /restconf/streams/fleet/json "
		    "HTTP/1.1\r\nHost: localhost:8443\r\nCookie: %s\r\n"
		    "Last-Event-ID: 2001-01-01T00:00:00Z\r\n\r\n", cookie);
		ATF_REQUIRE(write(s, rq, strlen(rq)) == (ssize_t)strlen(rq));
		len = 0;
		buf[0] = '\0';
		for (i = 0; i < 50 && strstr(buf, "replay-completed") == NULL;
		    i++) {
			if ((n = read(s, buf + len, sizeof(buf) - 1 - len)) <= 0)
				break;
			len += (size_t)n;
			buf[len] = '\0';
		}
		snprintf(rq, sizeof(rq), "\"arcana-fleet:fleet\":{\"host\":"
		    "[{\"id\":\"%s\",\"arcana-events:event\":", id);
		ATF_CHECK_MSG(strstr(buf, "fleet's stream") != NULL &&
		    strstr(buf, rq) != NULL && strstr(buf,
		    "replay-completed") != NULL, "%s", buf);
		close(s);
	}
	/* A subscription of one's own (RFC 8650): POSTed, its id and URI
	 * answered; that URI's GET its stream, the operational datastore
	 * every half second; taken once. */
	snprintf(path, sizeof(path), "%s/ietf-subscribed-notifications:"
	    "establish-subscription", host);
	http("POST", path, "{\"ietf-subscribed-notifications:input\":{"
	    "\"ietf-yang-push:datastore\":\"ietf-datastores:operational\","
	    "\"ietf-yang-push:datastore-xpath-filter\":\"/ietf-interfaces:"
	    "interfaces/interface[name='lo0']/oper-status\","
	    "\"ietf-yang-push:periodic\":{\"period\":50}}}", &r);
	EXPECT(&r, 200);
	{
		struct timeval	 tv = { 10, 0 };
		char		 rq[512], buf[16384], sub[64];
		const char	*uri;
		size_t		 len = 0;
		ssize_t		 n;
		int		 s, i;

		uri = jstr(&r, "ietf-subscribed-notifications:output."
		    "ietf-restconf-subscribed-notifications:uri");
		ATF_REQUIRE_MSG(uri != NULL && strstr(uri, "/restconf/"
		    "subscriptions/") != NULL, "%s", r.body);
		snprintf(sub, sizeof(sub), "%s", strstr(uri, "/restconf/"));
		resp_free(&r);
		s = console_socket();
		ATF_REQUIRE(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv,
		    sizeof(tv)) == 0);
		snprintf(rq, sizeof(rq), "GET %s HTTP/1.1\r\nHost: "
		    "localhost:8443\r\nCookie: %s\r\n\r\n", sub, cookie);
		ATF_REQUIRE(write(s, rq, strlen(rq)) == (ssize_t)strlen(rq));
		buf[0] = '\0';
		for (i = 0; i < 50 && strstr(buf, "push-update") == NULL;
		    i++) {
			if ((n = read(s, buf + len, sizeof(buf) - 1 - len)) <= 0)
				break;
			len += (size_t)n;
			buf[len] = '\0';
		}
		ATF_CHECK_MSG(strstr(buf, "\"ietf-yang-push:push-update\":") !=
		    NULL && strstr(buf, "\"oper-status\":\"up\"") != NULL,
		    "%s", buf);
		close(s);
		http("GET", sub, NULL, &r);
		EXPECT(&r, 404);
		resp_free(&r);
	}
	/* Under the fleet itself: every host's, each push in its host's
	 * entry. */
	http("POST", "/restconf/data/arcana-fleet:fleet/ietf-subscribed-"
	    "notifications:establish-subscription", "{\"ietf-subscribed-"
	    "notifications:input\":{\"ietf-yang-push:datastore\":\"ietf-"
	    "datastores:operational\",\"ietf-yang-push:datastore-xpath-"
	    "filter\":\"/ietf-interfaces:interfaces/interface[name='lo0']/"
	    "oper-status\",\"ietf-yang-push:periodic\":{\"period\":50}}}", &r);
	EXPECT(&r, 200);
	{
		struct timeval	 tv = { 10, 0 };
		char		 rq[512], buf[16384], sub[64], want[128];
		const char	*uri;
		size_t		 len = 0;
		ssize_t		 n;
		int		 s, i;

		uri = jstr(&r, "ietf-subscribed-notifications:output."
		    "ietf-restconf-subscribed-notifications:uri");
		ATF_REQUIRE_MSG(uri != NULL && strstr(uri, "/restconf/"
		    "subscriptions/") != NULL, "%s", r.body);
		snprintf(sub, sizeof(sub), "%s", strstr(uri, "/restconf/"));
		resp_free(&r);
		s = console_socket();
		ATF_REQUIRE(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv,
		    sizeof(tv)) == 0);
		snprintf(rq, sizeof(rq), "GET %s HTTP/1.1\r\nHost: "
		    "localhost:8443\r\nCookie: %s\r\n\r\n", sub, cookie);
		ATF_REQUIRE(write(s, rq, strlen(rq)) == (ssize_t)strlen(rq));
		buf[0] = '\0';
		for (i = 0; i < 50 && strstr(buf, "push-update") == NULL;
		    i++) {
			if ((n = read(s, buf + len, sizeof(buf) - 1 - len)) <= 0)
				break;
			len += (size_t)n;
			buf[len] = '\0';
		}
		snprintf(want, sizeof(want), "\"arcana-fleet:fleet\":{\"host\":"
		    "[{\"id\":\"%s\",\"ietf-yang-push:push-update\":", id);
		ATF_CHECK_MSG(strstr(buf, want) != NULL && strstr(buf,
		    "\"oper-status\":\"up\"") != NULL, "%s", buf);
		close(s);
	}
	http("POST", path, "{\"ietf-subscribed-notifications:input\":{"
	    "\"stream\":\"OTHER\"}}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", "/restconf/data/arcana-fleet:fleet", "{}", &r);
	EXPECT(&r, 405);
	resp_free(&r);
	/* A leaf of the agent's, by its path. */
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces/"
	    "interface=lo0/name", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("lo0", jstr(&r, "ietf-interfaces:name"));
	resp_free(&r);
	/* An entry: depth 1 is the entry alone; content=config keeps
	 * its key and leaves out its state. */
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces/"
	    "interface=lo0?depth=1", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ_MSG("{\"ietf-interfaces:interface\":[{}]}", r.body,
	    "%s", r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces/"
	    "interface=lo0?content=config", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("lo0", jstr(&r, "ietf-interfaces:interface.0.name"));
	ATF_CHECK(jstr(&r, "ietf-interfaces:interface.0.oper-status") == NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces/"
	    "interface=lo0?content=nonconfig", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("up", jstr(&r,
	    "ietf-interfaces:interface.0.oper-status"));
	resp_free(&r);
	/* fields: the members named, the key always; with-defaults: an
	 * enabled interface's enabled is its default, true. */
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces/"
	    "interface=lo0?fields=type;statistics(in-octets)", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("lo0", jstr(&r, "ietf-interfaces:interface.0.name"));
	ATF_CHECK(jstr(&r, "ietf-interfaces:interface.0.type") != NULL);
	ATF_CHECK(jstr(&r, "ietf-interfaces:interface.0.statistics.in-octets")
	    != NULL);
	ATF_CHECK(jstr(&r, "ietf-interfaces:interface.0.statistics."
	    "out-octets") == NULL);
	ATF_CHECK(jstr(&r, "ietf-interfaces:interface.0.oper-status") == NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces/"
	    "interface=lo0?with-defaults=trim", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "ietf-interfaces:interface.0.enabled") == NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces/"
	    "interface=lo0?with-defaults=report-all-tagged", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ietf-interfaces:interface.0.enabled"));
	ATF_CHECK_STREQ("true", jstr(&r, "ietf-interfaces:interface.0."
	    "@enabled.ietf-netconf-with-defaults:default"));
	resp_free(&r);
	/* What is not there, a query not taken, a path that is none. */
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces/"
	    "interface=nosuch9", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 404);
	ATF_CHECK_STREQ("invalid-value",
	    jstr(&r, "ietf-restconf:errors.error.0.error-tag"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces?point=x",
	    host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* fields with an empty node, first or after one: refused. */
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces?fields="
	    "interface//name", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces?fields="
	    "(name)", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/interfaces", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 400);
	ATF_CHECK(strstr(r.body, "named with its module") != NULL);
	resp_free(&r);
	http("GET", "/restconf/data/arcana-fleet:fleet/host=ffffffff", NULL,
	    &r);
	EXPECT(&r, 404);
	resp_free(&r);
}

CONSOLE_TC(setup_token, "The first key needs the setup token")
ATF_TC_BODY(setup_token, tc)
{
	struct resp	r;
	struct stat	sb;

	start(tc, 0, NULL);
	ATF_REQUIRE(stat("data/setup-token", &sb) == 0);
	ATF_CHECK_EQ(0600, sb.st_mode & 0777);
	http("POST", "/api/auth/register/begin", "{}", &r);
	EXPECT(&r, 403);
	ATF_CHECK_STREQ("setup_token", jstr(&r, "error.code"));
	resp_free(&r);
	http("POST", "/api/auth/register/begin",
	    "{\"setup_token\":\"0000000000000000000000000000000000000000000000"
	    "000000000000000000\"}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
}

CONSOLE_TC(setup_password, "The console set up by a password: the setup "
    "token, an owner's name and password; then set up, no token, no "
    "second setup; the session the user's roles, settings and keys among "
    "them; no key to sign in with until one is added; signed in again by "
    "the password")
ATF_TC_BODY(setup_password, tc)
{
	struct resp	 r;
	struct stat	 sb;
	char		*tok, body[300];

	start(tc, 0, NULL);
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "setup_required"));
	ATF_CHECK_STREQ("false", jstr(&r, "keys"));
	ATF_CHECK_STREQ("true", jstr(&r, "password_full"));
	resp_free(&r);
	tok = setup_token();
	/* Not without the token; nor a short password, nor a bad name. */
	http("POST", "/api/auth/setup/password", "{\"setup_token\":\"0000\","
	    "\"user\":\"ops\",\"password\":\"correct horse battery\"}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"setup_token\":\"%s\",\"user\":"
	    "\"ops\",\"password\":\"too short\"}", tok);
	http("POST", "/api/auth/setup/password", body, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "12 characters") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"setup_token\":\"%s\",\"user\":"
	    "\"no such name!\",\"password\":\"correct horse battery\"}", tok);
	http("POST", "/api/auth/setup/password", body, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	ATF_CHECK(cookie[0] == '\0');
	/* Set up: ops an owner, signed in, the session not limited. */
	snprintf(body, sizeof(body), "{\"setup_token\":\"%s\",\"user\":"
	    "\"ops\",\"password\":\"correct horse battery\"}", tok);
	http("POST", "/api/auth/setup/password", body, &r);
	ATF_CHECK_MSG(r.status == 200, "%s", r.body);
	ATF_CHECK_STREQ("ops", jstr(&r, "user"));
	ATF_CHECK_STREQ("owner", jstr(&r, "console"));
	ATF_CHECK_STREQ("true", jstr(&r, "by_password"));
	ATF_CHECK(jstr(&r, "by_token") == NULL);
	ATF_CHECK_STREQ("false", jstr(&r, "setup_required"));
	resp_free(&r);
	ATF_CHECK(cookie[0] != '\0');
	ATF_CHECK(stat("data/setup-token", &sb) == -1 && errno == ENOENT);
	http("POST", "/api/auth/setup/password", body, &r);
	EXPECT(&r, 409);
	resp_free(&r);
	free(tok);
	/* What a key's session may: the settings, the keys, a key added. */
	http("GET", CC "settings", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", CC "credentials", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/auth/register/begin", "{}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("ops", jstr(&r, "publicKey.user.name"));
	resp_free(&r);
	/* Signed out: no key to sign in with, the password again. */
	http("POST", "/api/auth/logout", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "keys"));
	ATF_CHECK_STREQ("true", jstr(&r, "password"));
	resp_free(&r);
	cookie[0] = '\0';
	http("POST", "/api/auth/login/begin", "{}", &r);
	EXPECT(&r, 404);
	ATF_CHECK_STREQ("no_key", jstr(&r, "error.code"));
	resp_free(&r);
	http("POST", "/api/auth/login/password", "{\"user\":\"ops\","
	    "\"password\":\"correct horse battery\"}", &r);
	ATF_CHECK_MSG(r.status == 200, "%s", r.body);
	ATF_CHECK(jstr(&r, "by_token") == NULL);
	resp_free(&r);
	http("GET", CC "settings", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
}

CONSOLE_TC(register_login, "Register an ES256 key, log out, log in")
ATF_TC_BODY(register_login, tc)
{
	struct authn	a;
	struct resp	r;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_CHECK_MSG(cookie[0] != '\0', "no session cookie after enrolment");
	ATF_CHECK_MSG(access("data/setup-token", F_OK) == -1,
	    "setup token left behind");
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "authenticated"));
	ATF_CHECK_STREQ("false", jstr(&r, "setup_required"));
	resp_free(&r);
	http("GET", CC "credentials", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("key -7", jstr(&r,
	    "arcana-console:credentials.credential.0.name"));
	ATF_CHECK(strstr(r.body, "public") == NULL);
	resp_free(&r);

	/* Once a key exists, the setup token is no longer a way in: a
	 * request neither from our page nor marked X-Arcana is refused. */
	send_xjg = false;
	origin_hdr = NULL;
	http("POST", "/api/auth/register/begin", "{}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	send_xjg = true;
	origin_hdr = ORIGIN;

	http("POST", "/api/auth/logout", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK_STREQ("", cookie);
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);

	do_login(&a, 1, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "authenticated"));
	resp_free(&r);
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);

	/* The counter has to move forward. */
	cookie[0] = '\0';
	do_login(&a, 1, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 401);
	ATF_CHECK_MSG(strstr(r.body, "counter") != NULL, "%s", r.body);
	resp_free(&r);
	do_login(&a, 2, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	resp_free(&r);
}

CONSOLE_TC(login_refused, "Wrong origin, RP, challenge or signature")
ATF_TC_BODY(login_refused, tc)
{
	struct authn	a, other;
	struct resp	r, b;
	char		old[64];

	start(tc, 0, NULL);
	enrol(&a);
	cookie[0] = '\0';

	do_login(&a, 5, "https://evil.example", RP_ID, NULL, false, &r);
	EXPECT(&r, 401);
	ATF_CHECK_MSG(strstr(r.body, "origin") != NULL, "%s", r.body);
	resp_free(&r);
	do_login(&a, 6, ORIGIN, "evil.example", NULL, false, &r);
	EXPECT(&r, 401);
	ATF_CHECK_MSG(strstr(r.body, "relying party") != NULL, "%s", r.body);
	resp_free(&r);
	do_login(&a, 7, ORIGIN, RP_ID, NULL, true, &r);
	EXPECT(&r, 401);
	ATF_CHECK_MSG(strstr(r.body, "signature") != NULL, "%s", r.body);
	resp_free(&r);

	/* A challenge the console did not make, or made too long ago. */
	do_login(&a, 8, ORIGIN, RP_ID, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	    "AAA", false, &r);
	EXPECT(&r, 401);
	ATF_CHECK_MSG(strstr(r.body, "challenge") != NULL, "%s", r.body);
	resp_free(&r);

	authn_new(&other, -7);
	do_login(&other, 1, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	ATF_CHECK_STREQ("", cookie);

	/*
	 * Others asking to log in meanwhile do not take one's challenge
	 * away: nobody can keep the rest out by asking often.  And a
	 * challenge works once.
	 */
	http("POST", "/api/auth/login/begin", "{}", &b);
	strlcpy(old, jstr(&b, "publicKey.challenge"), sizeof(old));
	resp_free(&b);
	for (int i = 0; i < 100; i++) {
		http("POST", "/api/auth/login/begin", "{}", &b);
		EXPECT(&b, 200);
		resp_free(&b);
	}
	do_login(&a, 9, ORIGIN, RP_ID, old, false, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	do_login(&a, 10, ORIGIN, RP_ID, old, false, &r);
	EXPECT(&r, 401);
	ATF_CHECK_MSG(strstr(r.body, "challenge") != NULL, "%s", r.body);
	resp_free(&r);
}

/* The SHA-256 of a signing certificate, as apksigner prints it. */
#define	APP_FP	"00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:"	\
		"10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F"

CONSOLE_TC(android, "The Android app of web.conf: its assetlinks.json, and "
    "logins made in it, whose origin is its signing key's hash")
ATF_TC_BODY(android, tc)
{
	struct authn	 a;
	struct resp	 r;
	uint8_t		 h[32];
	char		 origin[128], *h64;
	int		 i;

	for (i = 0; i < 32; i++)
		h[i] = (uint8_t)i;
	h64 = b64url(h, sizeof(h));
	snprintf(origin, sizeof(origin), "android:apk-key-hash:%s", h64);
	free(h64);
	snprintf(harness_webconf, sizeof(harness_webconf), "android {\n"
	    "\tpackage = \"org.example.arcana\";\n"
	    "\tfingerprints = [ \"%s\", \"%s\" ];\n}\n", APP_FP,
	    "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
	start(tc, 0, NULL);

	/* Before any login: Android asks for it as anyone would. */
	http("GET", "/.well-known/assetlinks.json", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("android_app", jstr(&r, "0.target.namespace"));
	ATF_CHECK_STREQ("org.example.arcana", jstr(&r,
	    "0.target.package_name"));
	ATF_CHECK_STREQ(APP_FP, jstr(&r, "0.target.sha256_cert_fingerprints.0"));
	ATF_CHECK_STREQ("1F:1E:1D:1C:1B:1A:19:18:17:16:15:14:13:12:11:10:"
	    "0F:0E:0D:0C:0B:0A:09:08:07:06:05:04:03:02:01:00", jstr(&r,
	    "0.target.sha256_cert_fingerprints.1"));
	ATF_CHECK_STREQ("delegate_permission/common.get_login_creds",
	    jstr(&r, "0.relation.1"));
	resp_free(&r);

	enrol(&a);
	cookie[0] = '\0';
	do_login(&a, 1, origin, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "authenticated"));
	resp_free(&r);

	/* Another app, or the right hash under another scheme: no. */
	cookie[0] = '\0';
	do_login(&a, 2, "android:apk-key-hash:"
	    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", RP_ID, NULL, false,
	    &r);
	EXPECT(&r, 401);
	ATF_CHECK_MSG(strstr(r.body, "origin") != NULL, "%s", r.body);
	resp_free(&r);
	do_login(&a, 3, origin + strlen("android:"), RP_ID, NULL, false, &r);
	EXPECT(&r, 401);
	resp_free(&r);
}

CONSOLE_TC(android_none, "Without an Android app, no assetlinks.json and no "
    "logins from an app")
ATF_TC_BODY(android_none, tc)
{
	struct authn	 a;
	struct resp	 r;

	start(tc, 0, NULL);
	http("GET", "/.well-known/assetlinks.json", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	enrol(&a);
	cookie[0] = '\0';
	do_login(&a, 1, "android:apk-key-hash:"
	    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", RP_ID, NULL, false,
	    &r);
	EXPECT(&r, 401);
	ATF_CHECK_MSG(strstr(r.body, "origin") != NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC(second_key, "A spare Ed25519 key, added from a session")
ATF_TC_BODY(second_key, tc)
{
	struct authn	a, b;
	struct resp	r, pk;
	char		path[256];

	start(tc, 0, NULL);
	enrol(&a);
	authn_new(&b, -8);
	do_register(&b, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	cookie[0] = '\0';
	/* A passkey login names no credentials: the authenticator picks. */
	http("POST", "/api/auth/login/begin", "{\"discoverable\":true}", &pk);
	EXPECT(&pk, 200);
	ATF_CHECK(jstr(&pk, "publicKey.allowCredentials.0.id") == NULL);
	ATF_CHECK(jstr(&pk, "publicKey.rpId") != NULL);
	resp_free(&pk);
	do_login(&b, 0, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", CC "credentials", NULL, &r);
	ATF_CHECK_STREQ("key -8", jstr(&r,
	    "arcana-console:credentials.credential.1.name"));
	snprintf(path, sizeof(path), CC "credentials/credential=%s",
	    jstr(&r, "arcana-console:credentials.credential.0.id"));
	resp_free(&r);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "credentials", NULL, &r);
	ATF_CHECK(jstr(&r, "arcana-console:credentials.credential.1") == NULL);
	snprintf(path, sizeof(path), CC "credentials/credential=%s",
	    jstr(&r, "arcana-console:credentials.credential.0.id"));
	resp_free(&r);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 409);
	resp_free(&r);
}

CONSOLE_TC(users, "Users with roles: a member sees the hosts they have a "
    "role on, a viewer reads them, an admin alone updates one; a tenant is "
    "a fleet of its own; the owner keeps the console")
ATF_TC_BODY(users, tc)
{
	struct authn	a, b;
	struct resp	r;
	char		ha[12], hb[12], path[256], body[600], invite[80];

	start(tc, 0, NULL);
	enrol(&a);
	/* The keys from before users are the built-in owner's. */
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("admin", jstr(&r, "user"));
	ATF_CHECK_STREQ("owner", jstr(&r, "console"));
	resp_free(&r);
	http("GET", CC "users", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("admin", jstr(&r, "arcana-console:users.user.0.name"));
	ATF_CHECK_STREQ("owner", jstr(&r,
	    "arcana-console:users.user.0.role.0"));
	ATF_CHECK_STREQ("owner", jstr(&r,
	    "arcana-console:users.user.0.console-role"));
	ATF_CHECK_STREQ("1", jstr(&r, "arcana-console:users.user.0.keys"));
	resp_free(&r);
	/* The roles that come built in. */
	http("GET", CC "roles", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("owner", jstr(&r, "arcana-console:roles.role.0.name"));
	ATF_CHECK_STREQ("*", jstr(&r, "arcana-console:roles.role.0.host.0.id"));
	ATF_CHECK_STREQ("admin", jstr(&r,
	    "arcana-console:roles.role.0.host.0.role"));
	ATF_CHECK_STREQ("operator", jstr(&r,
	    "arcana-console:roles.role.1.name"));
	ATF_CHECK_STREQ("viewer", jstr(&r, "arcana-console:roles.role.2.name"));
	ATF_CHECK_STREQ("member", jstr(&r,
	    "arcana-console:roles.role.2.console"));
	resp_free(&r);
	host_add("a", "tcp://192.0.2.1:4310", ha, sizeof(ha));
	host_new("\"name\":\"b\",\"uri\":\"tcp://192.0.2.2:4310\",\"tenant\":"
	    "\"acme\"", hb, sizeof(hb));
	http("GET", CC "hosts", NULL, &r);
	ATF_CHECK_STREQ("acme", jstr(&r, "arcana-console:hosts.host.1.tenant"));
	resp_free(&r);
	/* A role, a-viewer: a member of the console, a viewer of a; bob
	 * with it.  What is refused: a console role that is not one, a
	 * host that is not an id, a user without a role, the last owner
	 * made less. */
	snprintf(body, sizeof(body), "{\"arcana-console:role\":[{\"name\":"
	    "\"a-viewer\",\"console\":\"member\",\"host\":[{\"id\":\"%s\","
	    "\"role\":\"viewer\"}]}]}", ha);
	http("PUT", CC "roles/role=a-viewer", body, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", CC "roles", NULL, &r);
	ATF_CHECK_STREQ("a-viewer", jstr(&r,
	    "arcana-console:roles.role.3.name"));
	ATF_CHECK_STREQ("0", jstr(&r, "arcana-console:roles.role.3.users"));
	resp_free(&r);
	http("PUT", CC "roles/role=bad", "{\"arcana-console:role\":[{\"name\":"
	    "\"bad\",\"console\":\"king\"}]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("PUT", CC "roles/role=bad", "{\"arcana-console:role\":[{\"name\":"
	    "\"bad\",\"host\":[{\"id\":\"zz\",\"role\":\"viewer\"}]}]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("PUT", CC "users/user=bob", "{\"arcana-console:user\":[{\"name\":"
	    "\"bob\",\"role\":[\"a-viewer\"]}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", CC "users", NULL, &r);
	ATF_CHECK_STREQ("bob", jstr(&r, "arcana-console:users.user.1.name"));
	ATF_CHECK_STREQ("member", jstr(&r,
	    "arcana-console:users.user.1.console-role"));
	resp_free(&r);
	http("GET", CC "roles/role=a-viewer", NULL, &r);
	ATF_CHECK_STREQ("1", jstr(&r, "arcana-console:role.0.users"));
	resp_free(&r);
	http("PUT", CC "users/user=bad", "{\"arcana-console:user\":[{\"name\":"
	    "\"bad\",\"tenant\":\"x\"}]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("PUT", CC "users/user=bad", "{\"arcana-console:user\":[{\"name\":"
	    "\"bad\",\"role\":[\"nosuch\"]}]}", &r);
	ATF_CHECK_MSG(r.status == 400 || r.status == 409, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	http("PUT", CC "users/user=admin", "{\"arcana-console:user\":[{"
	    "\"name\":\"admin\",\"role\":[\"viewer\"]}]}", &r);
	EXPECT(&r, 409);
	resp_free(&r);
	http("PUT", CC "roles/role=owner", "{\"arcana-console:role\":[{"
	    "\"name\":\"owner\",\"console\":\"member\",\"host\":[{\"id\":"
	    "\"*\",\"role\":\"admin\"}]}]}", &r);
	EXPECT(&r, 409);
	resp_free(&r);
	http("DELETE", CC "roles/role=a-viewer", NULL, &r);
	ATF_CHECK_MSG(r.status == 400 || r.status == 409, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	/* Invited: a token said once, with which bob registers a key and
	 * is signed in as bob. */
	http("POST", CC "users/user=bob/invite", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "arcana-console:output.token") != NULL);
	snprintf(invite, sizeof(invite), "%s", jstr(&r,
	    "arcana-console:output.token"));
	resp_free(&r);
	http("GET", CC "users/user=bob", NULL, &r);
	ATF_CHECK_STREQ("1", jstr(&r, "arcana-console:user.0.invitations"));
	resp_free(&r);
	cookie[0] = '\0';
	authn_new(&b, -8);
	do_register(&b, invite, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bob", jstr(&r, "user"));
	ATF_CHECK_STREQ("member", jstr(&r, "console"));
	resp_free(&r);
	/* Used once. */
	cookie[0] = '\0';
	snprintf(body, sizeof(body), "{\"invite\":\"%s\"}", invite);
	http("POST", "/api/auth/register/begin", body, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	do_login(&b, 1, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bob", jstr(&r, "user"));
	resp_free(&r);
	/* The hosts: a alone, as a viewer; b not there, and not reached. */
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(ha, jstr(&r, "arcana-console:hosts.host.0.id"));
	ATF_CHECK_STREQ("viewer", jstr(&r, "arcana-console:hosts.host.0.role"));
	ATF_CHECK(jstr(&r, "arcana-console:hosts.host.1.id") == NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), FLEET "%s/arcana-jobs:jobs", hb);
	http("GET", path, NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	r1_submit(ha, "{\"sysctl\":{\"args\":[\"kern.hostname\"]}}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* A dry run, and a job's undo previewed, are submit's and cancel's:
	 * a viewer's neither. */
	snprintf(path, sizeof(path), FLEET "%s/arcana-jobs:dry-run", ha);
	http("POST", path, "{\"arcana-jobs:input\":{\"change\":[{"
	    "\"service-action\":{\"service\":\"sshd\",\"action\":"
	    "\"restart\"}}]}}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("POST", path, "{\"arcana-jobs:input\":{\"undo\":1}}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	snprintf(path, sizeof(path), CC "hosts/host=%s", ha);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* What changes a host or the console is a change, whatever it
	 * reads: refused to a viewer. */
	snprintf(path, sizeof(path), CC "hosts/host=%s/switch-transport", ha);
	rc_act(path, "\"transport\":\"sctp\"", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	snprintf(path, sizeof(path), "/restconf/ds/ietf-datastores:candidate/"
	    "arcana-fleet:fleet/host=%s/arcana-bird:bird/configuration", ha);
	http("PATCH", path, "{\"arcana-bird:configuration\":{\"file\":[{"
	    "\"path\":\"/usr/local/etc/bird.conf\",\"text\":\"router id "
	    "10.0.0.1;\"}]}}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* The console's own, and the fleet's tools, not a member's; the
	 * prefix lists read. */
	http("GET", CC "settings", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("GET", CC "users", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("GET", CC "sdwan/document", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("GET", CC "workflows", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("GET", CC "prefix-lists", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("PUT", CC "prefix-lists/prefix-list=x", "{\"arcana-console:"
	    "prefix-list\":[{\"name\":\"x\"}]}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* Their own keys alone. */
	http("GET", CC "credentials", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bob", jstr(&r,
	    "arcana-console:credentials.credential.0.user"));
	ATF_CHECK(jstr(&r, "arcana-console:credentials.credential.1.id") ==
	    NULL);
	resp_free(&r);
	/* The owner again: bob an operator of every host of tenant acme;
	 * a is not in it, b is. */
	cookie[0] = '\0';
	do_login(&a, 1, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", CC "credentials", NULL, &r);
	ATF_CHECK(jstr(&r, "arcana-console:credentials.credential.1.user") !=
	    NULL);
	resp_free(&r);
	r1_role("acme-ops", "member", "operator");
	http("PUT", CC "users/user=bob", "{\"arcana-console:user\":[{\"name\":"
	    "\"bob\",\"tenant\":\"acme\",\"role\":[\"acme-ops\"]}]}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	/* a-viewer has no user now: it may go. */
	http("DELETE", CC "roles/role=a-viewer", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "roles", NULL, &r);
	ATF_CHECK(strstr(r.body, "a-viewer") == NULL);
	resp_free(&r);
	cookie[0] = '\0';
	do_login(&b, 2, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("acme", jstr(&r, "tenant"));
	resp_free(&r);
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(hb, jstr(&r, "arcana-console:hosts.host.0.id"));
	ATF_CHECK_STREQ("operator", jstr(&r,
	    "arcana-console:hosts.host.0.role"));
	ATF_CHECK(jstr(&r, "arcana-console:hosts.host.1.id") == NULL);
	resp_free(&r);
	/* An operator changes (the host is not reached here: not 403), an
	 * admin alone updates or removes. */
	r1_submit(hb, "{\"sysctl\":{\"args\":[\"kern.hostname\"]}}", &r);
	ATF_CHECK_MSG(r.status != 403 && r.status != 404, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), FLEET "%s/arcana-jobs:dry-run", hb);
	http("POST", path, "{\"arcana-jobs:input\":{\"undo\":1}}", &r);
	ATF_CHECK_MSG(r.status != 403 && r.status != 404, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), CC "hosts/host=%s/agent-update", hb);
	rc_act(path, "", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	snprintf(path, sizeof(path), CC "labels/label=%s,vtnet0", hb);
	snprintf(body, sizeof(body), "{\"arcana-console:label\":[{\"host\":"
	    "\"%s\",\"interface\":\"vtnet0\",\"text\":\"uplink\"}]}", hb);
	http("PUT", path, body, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	snprintf(path, sizeof(path), CC "labels/label=%s,vtnet0", ha);
	snprintf(body, sizeof(body), "{\"arcana-console:label\":[{\"host\":"
	    "\"%s\",\"interface\":\"vtnet0\",\"text\":\"uplink\"}]}", ha);
	http("PUT", path, body, &r);
	ATF_CHECK_MSG(r.status == 403 || r.status == 404, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	/* Removed by the owner: bob's keys and session go with him. */
	cookie[0] = '\0';
	do_login(&a, 2, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("DELETE", CC "users/user=admin", NULL, &r);
	EXPECT(&r, 409);
	resp_free(&r);
	/* Groups: users given roles together; a user may do what its own
	 * roles and its groups' allow. */
	http("PUT", CC "groups/group=ops", "{\"arcana-console:group\":[{"
	    "\"name\":\"ops\",\"role\":[\"operator\"]}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("PUT", CC "users/user=bob", "{\"arcana-console:user\":[{\"name\":"
	    "\"bob\",\"tenant\":\"acme\",\"role\":[\"acme-ops\"],\"group\":"
	    "[\"ops\"]}]}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "groups", NULL, &r);
	ATF_CHECK_STREQ("ops", jstr(&r, "arcana-console:groups.group.0.name"));
	ATF_CHECK_STREQ("bob", jstr(&r,
	    "arcana-console:groups.group.0.member.0"));
	resp_free(&r);
	http("GET", CC "users", NULL, &r);
	ATF_CHECK_STREQ("operator", jstr(&r,
	    "arcana-console:users.user.1.console-role"));
	ATF_CHECK_STREQ("ops", jstr(&r, "arcana-console:users.user.1.group.0"));
	resp_free(&r);
	http("PUT", CC "groups/group=bad", "{\"arcana-console:group\":[{"
	    "\"name\":\"bad\",\"role\":[\"nosuch\"]}]}", &r);
	ATF_CHECK_MSG(r.status == 400 || r.status == 409, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	http("PUT", CC "groups/group=bad", "{\"arcana-console:group\":[{"
	    "\"name\":\"bad\"}]}", &r);
	ATF_CHECK_MSG(r.status >= 400 && strstr(r.body, "too-few-elements") !=
	    NULL, "%d %s", r.status, r.body);
	resp_free(&r);
	/* A role a group gives stays while it does. */
	http("DELETE", CC "roles/role=operator", NULL, &r);
	ATF_CHECK_MSG(r.status == 409 && strstr(r.body, "group") != NULL,
	    "%d %s", r.status, r.body);
	resp_free(&r);
	/* A user of a group alone; a user of neither is not one. */
	http("PUT", CC "users/user=carl", "{\"arcana-console:user\":[{\"name\":"
	    "\"carl\",\"group\":[\"ops\"]}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", CC "users/user=carl", NULL, &r);
	ATF_CHECK_STREQ("operator", jstr(&r,
	    "arcana-console:user.0.console-role"));
	resp_free(&r);
	http("PUT", CC "users/user=dave", "{\"arcana-console:user\":[{\"name\":"
	    "\"dave\"}]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("PUT", CC "users/user=dave", "{\"arcana-console:user\":[{\"name\":"
	    "\"dave\",\"group\":[\"nosuch\"]}]}", &r);
	ATF_CHECK_MSG(r.status == 400 || r.status == 409, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	/* Not gone while a user names it; its members out of it, what they
	 * may do is their own roles' again. */
	http("DELETE", CC "groups/group=ops", NULL, &r);
	ATF_CHECK_MSG(r.status == 409 && strstr(r.body, "instance-required") !=
	    NULL, "%d %s", r.status, r.body);
	resp_free(&r);
	http("DELETE", CC "users/user=carl", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("PUT", CC "users/user=bob", "{\"arcana-console:user\":[{\"name\":"
	    "\"bob\",\"tenant\":\"acme\",\"role\":[\"acme-ops\"]}]}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("DELETE", CC "groups/group=ops", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "groups", NULL, &r);
	ATF_CHECK(jstr(&r, "arcana-console:groups.group.0.name") == NULL);
	resp_free(&r);
	http("GET", CC "users", NULL, &r);
	ATF_CHECK_STREQ("member", jstr(&r,
	    "arcana-console:users.user.1.console-role"));
	ATF_CHECK(jstr(&r, "arcana-console:users.user.1.group.0") == NULL);
	resp_free(&r);
	http("DELETE", CC "users/user=bob", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "users", NULL, &r);
	ATF_CHECK(jstr(&r, "arcana-console:users.user.1.name") == NULL);
	resp_free(&r);
	http("GET", CC "credentials", NULL, &r);
	ATF_CHECK(jstr(&r, "arcana-console:credentials.credential.1.id") ==
	    NULL);
	resp_free(&r);
	cookie[0] = '\0';
	do_login(&b, 3, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 401);
	resp_free(&r);
}

CONSOLE_TC(csrf, "Changes need our Origin, or X-Arcana from a client "
    "without one")
ATF_TC_BODY(csrf, tc)
{
	struct authn	a;
	struct resp	r;
	char		path[128], id[16];

	start(tc, 0, NULL);
	enrol(&a);
	/* Neither: refused. */
	send_xjg = false;
	origin_hdr = NULL;
	host_try("\"name\":\"x\",\"uri\":\"unix:/x.sock\"", id, sizeof(id), &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* A browser's: our page's Origin is enough (over HTTP/2 its
	 * X-Arcana is lost from the second use on); another's, or none
	 * ("null"), is refused, X-Arcana or not. */
	origin_hdr = ORIGIN;
	host_new("\"name\":\"x\",\"uri\":\"unix:/x.sock\"", id, sizeof(id));
	snprintf(path, sizeof(path), FLEET "%s/arcana-jails:jails", id);
	/* A read of a host is a GET: neither header is asked for, as a
	 * browser sends no Origin with one.  No agent answers there. */
	origin_hdr = NULL;
	http("GET", path, NULL, &r);
	ATF_CHECK_MSG(r.status != 403, "HTTP %d: %s", r.status, r.body);
	/* Nor can another site's page take the reply into its own, or
	 * frame it, and so on (web.c's sec_headers). */
	ATF_CHECK(strcasestr(r.head, "cross-origin-resource-policy: "
	    "same-origin") != NULL);
	ATF_CHECK(strcasestr(r.head, "x-content-type-options: nosniff") !=
	    NULL);
	ATF_CHECK(strcasestr(r.head, "frame-ancestors 'none'") != NULL);
	ATF_CHECK(strcasestr(r.head, "x-frame-options: DENY") != NULL);
	ATF_CHECK(strcasestr(r.head, "cross-origin-opener-policy: "
	    "same-origin") != NULL);
	ATF_CHECK(strcasestr(r.head, "referrer-policy: no-referrer") !=
	    NULL);
	ATF_CHECK(strcasestr(r.head, "camera=()") != NULL);
	resp_free(&r);
	/* The page itself, the same. */
	http("GET", "/", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strcasestr(r.head, "content-security-policy: default-src "
	    "'self'") != NULL);
	resp_free(&r);
	/*
	 * Its WebAssembly: 'wasm-unsafe-eval' for a browser that knows it,
	 * 'unsafe-eval' for one before (or one not known).
	 */
	{
		static const struct {
			const char	*ua;
			bool		 wasm;
		} uas[] = {
			{ "Mozilla/5.0 (X11; FreeBSD amd64) AppleWebKit/537.36 "
			  "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			  true },
			{ "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
			  "(KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
			  false },
			{ "Mozilla/5.0 (X11; FreeBSD amd64; rv:128.0) "
			  "Gecko/20100101 Firefox/128.0", true },
			{ "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) "
			  "Gecko/20100101 Firefox/91.0", false },
			{ "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
			  "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 "
			  "Safari/605.1.15", true },
			{ "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
			  "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 "
			  "Safari/605.1.15", false },
			{ "Mozilla/5.0 (iPhone; CPU iPhone OS 15_7 like Mac OS X) "
			  "AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0 "
			  "Mobile/15E148 Safari/604.1", false },
			{ "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
			  "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 "
			  "Mobile/15E148 Safari/604.1", true },
			{ "SomeTV/1.0", false },
		};
		char	extra[400];
		size_t	k;

		for (k = 0; k < nitems(uas); k++) {
			snprintf(extra, sizeof(extra), "User-Agent: %s\r\n",
			    uas[k].ua);
			http_with("GET", "/", extra, NULL, &r);
			EXPECT(&r, 200);
			ATF_CHECK_MSG(strcasestr(r.head, uas[k].wasm ?
			    "script-src 'self' 'wasm-unsafe-eval';" :
			    "script-src 'self' 'unsafe-eval';") != NULL,
			    "%s: %s", uas[k].ua, r.head);
			resp_free(&r);
		}
	}
	send_xjg = true;
	origin_hdr = "https://evil.example";
	host_try("\"name\":\"y\",\"uri\":\"unix:/y.sock\"", id, sizeof(id), &r);
	EXPECT(&r, 403);
	resp_free(&r);
	origin_hdr = "null";
	host_try("\"name\":\"y\",\"uri\":\"unix:/y.sock\"", id, sizeof(id), &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* A client without an Origin: X-Arcana. */
	origin_hdr = NULL;
	host_new("\"name\":\"y\",\"uri\":\"unix:/y.sock\"", id, sizeof(id));
	origin_hdr = ORIGIN;
}

/* "sha384-" and the base64 of the SHA-384 of s, as the page's
 * integrity says it. */
static void
sri_of(const char *s, char *out, size_t len)
{
	unsigned char	md[EVP_MAX_MD_SIZE], b64[96];
	unsigned int	mdlen;

	EVP_Digest(s, strlen(s), md, &mdlen, EVP_sha384(), NULL);
	EVP_EncodeBlock(b64, md, (int)mdlen);
	snprintf(out, len, "sha384-%s", b64);
}

/* What the reply says of the console plugin id, at path in it. */
static const char *
cplug_str(const struct resp *r, const char *id, const char *path)
{
	const ucl_object_t	*p, *v;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((p = ucl_object_iterate(ucl_object_lookup_path(r->json,
	    "arcana-console:plugins.plugin"), &it, true)) != NULL)
		if (strcmp(ucl_object_tostring(ucl_object_lookup(p, "id")), id)
		    == 0)
			break;
	if (p == NULL || (v = ucl_object_lookup_path(p, path)) == NULL)
		return (NULL);
	return (ucl_object_tostring_forced(v));
}

static bool
has(const char *s, const char *want)
{

	return (s != NULL && strstr(s, want) != NULL);
}

/* Console plugin id's enabled made v ("true", "false"). */
static void
r1_enable(const char *id, const char *v, struct resp *r)
{
	char	path[96], body[160];

	snprintf(path, sizeof(path), CC "plugins/plugin=%s", id);
	snprintf(body, sizeof(body), "{\"arcana-console:plugin\":[{\"id\":"
	    "\"%s\",\"enabled\":%s}]}", id, v);
	http("PATCH", path, body, r);
}

CONSOLE_TC(console_plugins, "Console plugins: scanned and hashed, served "
    "only as listed, from inside their directory, once a console owner "
    "enabled them; rescanned without a restart")
ATF_TC_BODY(console_plugins, tc)
{
	struct authn	a, b;
	struct resp	r;
	char		cwd[MAXPATHLEN], sri[128], hdr[256], owner[160];
	char		other[160], tag[64], stag[64], tok[80];
	const char	*js = "window.x = 1;\n";

#define	STORE	CC "plugins/plugin=good/store"
#define	SHARED	CC "plugins/plugin=good/shared-store"

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ATF_REQUIRE(mkdir("plugins", 0755) == 0);
	/* A good one, with files it does not list. */
	ATF_REQUIRE(mkdir("plugins/good", 0755) == 0);
	ATF_REQUIRE(mkdir("plugins/good/img", 0755) == 0);
	put("plugins/good/plugin.json", "{\"id\":\"good\",\"name\":\"Good\","
	    "\"version\":\"1.2.0\",\"arcana\":\"0.1.0\",\"description\":"
	    "\"A test\",\"author\":\"Tests\",\"entry\":[\"main.js\"],"
	    "\"styles\":[\"look.css\"],\"assets\":[\"img/*.png\"],"
	    "\"provides\":[\"theme\"]}");
	put("plugins/good/main.js", js);
	put("plugins/good/look.css", "body { color: red; }\n");
	put("plugins/good/img/a.png", "PNG a");
	put("plugins/good/img/b.png", "PNG b");
	put("plugins/good/img/.hidden.png", "hidden");
	put("plugins/good/extra.js", "window.y = 2;\n");
	/* Its id not its directory's. */
	ATF_REQUIRE(mkdir("plugins/bad", 0755) == 0);
	put("plugins/bad/plugin.json", "{\"id\":\"other\",\"name\":\"Bad\","
	    "\"version\":\"1\",\"arcana\":\"0.1.0\"}");
	/* A file that is a link out of its directory. */
	put("outside.js", "window.secret = 1;\n");
	ATF_REQUIRE(mkdir("plugins/leak", 0755) == 0);
	put("plugins/leak/plugin.json", "{\"id\":\"leak\",\"name\":\"Leak\","
	    "\"version\":\"1\",\"arcana\":\"0.1.0\",\"entry\":[\"s.js\"]}");
	ATF_REQUIRE(symlink("../../outside.js", "plugins/leak/s.js") == 0);
	/* Of a console to come. */
	ATF_REQUIRE(mkdir("plugins/newer", 0755) == 0);
	put("plugins/newer/plugin.json", "{\"id\":\"newer\",\"name\":\"Newer\","
	    "\"version\":\"1\",\"arcana\":\"99.0.0\"}");
	/* A path out of its directory; a key not of the format. */
	ATF_REQUIRE(mkdir("plugins/up", 0755) == 0);
	put("plugins/up/plugin.json", "{\"id\":\"up\",\"name\":\"Up\","
	    "\"version\":\"1\",\"arcana\":\"0.1.0\",\"entry\":"
	    "[\"../outside.js\"]}");
	ATF_REQUIRE(mkdir("plugins/odd", 0755) == 0);
	put("plugins/odd/plugin.json", "{\"id\":\"odd\",\"name\":\"Odd\","
	    "\"version\":\"1\",\"arcana\":\"0.1.0\",\"colour\":\"red\"}");
	snprintf(harness_webconf, sizeof(harness_webconf), "plugins_dir = "
	    "\"%s/plugins\";\n", cwd);
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(owner, sizeof(owner), "%s", cookie);

	/* Listed, each with why it is not served, the good one's files
	 * with their integrity. */
	http("GET", CC "plugins", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "arcana-console:plugins.directory") != NULL);
	ATF_CHECK_STREQ("bad", jstr(&r, "arcana-console:plugins.plugin.0.id"));
	ATF_CHECK(has(cplug_str(&r, "bad", "error"), "directory"));
	ATF_CHECK(cplug_str(&r, "good", "error") == NULL);
	ATF_CHECK_STREQ("Good", cplug_str(&r, "good", "name"));
	ATF_CHECK_STREQ("1.2.0", cplug_str(&r, "good", "version"));
	ATF_CHECK_STREQ("Tests", cplug_str(&r, "good", "author"));
	ATF_CHECK_STREQ("theme", cplug_str(&r, "good", "provides.0"));
	ATF_CHECK_STREQ("false", cplug_str(&r, "good", "enabled"));
	ATF_CHECK_STREQ("main.js", cplug_str(&r, "good", "file.0.path"));
	ATF_CHECK_STREQ("script", cplug_str(&r, "good", "file.0.kind"));
	sri_of(js, sri, sizeof(sri));
	ATF_CHECK_STREQ(sri, cplug_str(&r, "good", "file.0.integrity"));
	ATF_CHECK_STREQ("style", cplug_str(&r, "good", "file.1.kind"));
	ATF_CHECK_STREQ("img/a.png", cplug_str(&r, "good", "file.2.path"));
	ATF_CHECK_STREQ("asset", cplug_str(&r, "good", "file.2.kind"));
	ATF_CHECK_STREQ("img/b.png", cplug_str(&r, "good", "file.3.path"));
	ATF_CHECK(cplug_str(&r, "good", "file.4.path") == NULL);
	ATF_CHECK(has(cplug_str(&r, "leak", "error"), "outside"));
	ATF_CHECK(cplug_str(&r, "leak", "file") == NULL);
	ATF_CHECK(has(cplug_str(&r, "newer", "error"), "needs console "
	    "99.0.0"));
	ATF_CHECK(has(cplug_str(&r, "up", "error"), "not a path"));
	ATF_CHECK(has(cplug_str(&r, "odd", "error"), "colour"));
	resp_free(&r);

	/* Not served until enabled. */
	http("GET", "/plugins/good/main.js", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	r1_enable("good", "true", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "plugins", NULL, &r);
	ATF_CHECK_STREQ("true", cplug_str(&r, "good", "enabled"));
	resp_free(&r);
	ATF_CHECK(access("data/console-plugins.json", F_OK) == 0);
	/* One with something wrong is not enabled; one not there neither. */
	r1_enable("leak", "true", &r);
	EXPECT(&r, 409);
	resp_free(&r);
	r1_enable("nosuch", "true", &r);
	ATF_CHECK_MSG(r.status == 404 || r.status == 400, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	r1_enable("good", "\"yes\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/* Served: its bytes, its type, its hash its tag, the console's
	 * headers. */
	http("GET", "/plugins/good/main.js", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(js, r.body);
	ATF_CHECK(resp_header(&r, "content-type", hdr, sizeof(hdr)) != NULL &&
	    strncmp(hdr, "text/javascript", 15) == 0);
	ATF_CHECK(resp_header(&r, "cache-control", hdr, sizeof(hdr)) != NULL &&
	    strcmp(hdr, "no-cache") == 0);
	ATF_CHECK(resp_header(&r, "etag", hdr, sizeof(hdr)) != NULL &&
	    strncmp(hdr + 1, sri, strlen(sri)) == 0);
	ATF_CHECK(strcasestr(r.head, "x-content-type-options: nosniff") !=
	    NULL);
	ATF_CHECK(strcasestr(r.head, "content-security-policy: default-src "
	    "'self'") != NULL);
	resp_free(&r);
	snprintf(hdr, sizeof(hdr), "If-None-Match: \"%s\"\r\n", sri);
	http_with("GET", "/plugins/good/main.js", hdr, NULL, &r);
	EXPECT(&r, 304);
	resp_free(&r);
	http("GET", "/plugins/good/img/b.png", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(resp_header(&r, "content-type", hdr, sizeof(hdr)) != NULL &&
	    strcmp(hdr, "image/png") == 0);
	resp_free(&r);
	/* What it does not list, a hidden file, a way out: not found. */
	http("GET", "/plugins/good/extra.js", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("GET", "/plugins/good/plugin.json", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("GET", "/plugins/good/img/.hidden.png", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("GET", "/plugins/good/%2e%2e/%2e%2e/outside.js", NULL, &r);
	ATF_CHECK_MSG(r.status == 404, "HTTP %d", r.status);
	resp_free(&r);
	http("GET", "/plugins/good/img/..%2f..%2f..%2foutside.js", NULL, &r);
	ATF_CHECK_MSG(r.status == 404, "HTTP %d", r.status);
	resp_free(&r);
	http("GET", "/plugins/leak/s.js", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* Without a session, nothing. */
	cookie[0] = '\0';
	http("GET", "/plugins/good/main.js", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	http("GET", CC "plugins", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);

	/* An operator of the console, then a member: they read the list
	 * and load what is enabled, and enable or disable nothing. */
	snprintf(cookie, sizeof(cookie), "%s", owner);
	cc_user(&b, "bob", "\"role\":[\"operator\"]", -8);
	snprintf(other, sizeof(other), "%s", cookie);
	r1_enable("good", "false", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("GET", CC "plugins", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "arcana-console:plugins.directory") == NULL);
	ATF_CHECK_STREQ("true", cplug_str(&r, "good", "enabled"));
	resp_free(&r);
	http("GET", "/plugins/good/main.js", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	snprintf(cookie, sizeof(cookie), "%s", owner);
	r1_roles("bob", "viewer");
	snprintf(cookie, sizeof(cookie), "%s", other);
	r1_enable("good", "false", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("GET", "/plugins/good/look.css", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);

	/* Changed while the console runs: a plugin added, a file
	 * rewritten, a file made a link out; seen without a restart. */
	ATF_REQUIRE(mkdir("plugins/fresh", 0755) == 0);
	put("plugins/fresh/plugin.json", "{\"id\":\"fresh\",\"name\":\"Fresh\","
	    "\"version\":\"1\",\"arcana\":\"0.1.0\",\"entry\":[\"f.js\"]}");
	put("plugins/fresh/f.js", "window.f = 1;\n");
	put("plugins/good/main.js", "window.x = 2;\n");
	usleep(1200 * 1000);
	http("GET", CC "plugins", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(cplug_str(&r, "fresh", "name") != NULL);
	ATF_CHECK(cplug_str(&r, "fresh", "error") == NULL);
	ATF_CHECK_STREQ("false", cplug_str(&r, "fresh", "enabled"));
	sri_of("window.x = 2;\n", sri, sizeof(sri));
	ATF_CHECK_STREQ(sri, cplug_str(&r, "good", "file.0.integrity"));
	resp_free(&r);
	http("GET", "/plugins/good/main.js", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("window.x = 2;\n", r.body);
	resp_free(&r);
	ATF_REQUIRE(unlink("plugins/good/img/b.png") == 0);
	ATF_REQUIRE(symlink("../../../outside.js", "plugins/good/img/b.png") ==
	    0);
	http("GET", "/plugins/good/img/b.png", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	usleep(1200 * 1000);
	http("GET", CC "plugins", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(has(cplug_str(&r, "good", "error"), "outside"));
	resp_free(&r);
	http("GET", "/plugins/good/main.js", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	ATF_REQUIRE(unlink("plugins/good/img/b.png") == 0);
	put("plugins/good/img/b.png", "PNG b");
	usleep(1200 * 1000);
	http("GET", "/plugins/good/main.js", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);

	/* Its store: the owner's own, none at first, written first with no
	 * tag, then only in place of the tag read. */
	snprintf(cookie, sizeof(cookie), "%s", owner);
	http("GET", STORE, NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("PUT", STORE, "{\"arcana-console:store\":{\"level\":3}}", &r);
	EXPECT(&r, 204);
	ATF_REQUIRE(resp_header(&r, "etag", tag, sizeof(tag)) != NULL);
	resp_free(&r);
	ATF_CHECK(access("data/plugin-store/good.user.admin.json", F_OK) == 0);
	http("PUT", STORE, "{\"arcana-console:store\":{\"level\":9}}", &r);
	EXPECT(&r, 412);
	resp_free(&r);
	http_with("PUT", STORE, "If-Match: \"0\"\r\n",
	    "{\"arcana-console:store\":{\"level\":9}}", &r);
	EXPECT(&r, 412);
	resp_free(&r);
	snprintf(hdr, sizeof(hdr), "If-Match: %s\r\n", tag);
	http_with("PUT", STORE, hdr, "{\"arcana-console:store\":{\"level\":4,"
	    "\"seen\":[\"a\"]}}", &r);
	EXPECT(&r, 204);
	ATF_CHECK(resp_header(&r, "etag", stag, sizeof(stag)) != NULL &&
	    strcmp(stag, tag) != 0);
	snprintf(tag, sizeof(tag), "%s", stag);
	resp_free(&r);
	/* The old tag is stale now. */
	http_with("PUT", STORE, hdr, "{\"arcana-console:store\":{\"level\":5}}",
	    &r);
	EXPECT(&r, 412);
	resp_free(&r);
	http("GET", STORE, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("4", jstr(&r, "arcana-console:store.level"));
	ATF_CHECK_STREQ("a", jstr(&r, "arcana-console:store.seen.0"));
	ATF_CHECK(resp_header(&r, "etag", hdr, sizeof(hdr)) != NULL &&
	    strcmp(hdr, tag) == 0);
	resp_free(&r);
	/* A JSON object alone, of 16 KB at most. */
	snprintf(hdr, sizeof(hdr), "If-Match: %s\r\n", tag);
	http_with("PUT", STORE, hdr, "{\"arcana-console:store\":[1]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http_with("PUT", STORE, hdr, "level = 1;", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	{
		static const char	 pre[] = "{\"arcana-console:store\":{"
		    "\"x\":\"";
		char			*big;
		size_t			 n = sizeof(pre) - 1;

		big = malloc(17 * 1024 + 48);
		ATF_REQUIRE(big != NULL);
		memcpy(big, pre, n);
		memset(big + n, 'a', 17 * 1024);
		memcpy(big + n + 17 * 1024, "\"}}", 4);
		http_with("PUT", STORE, hdr, big, &r);
		EXPECT(&r, 413);
		resp_free(&r);
		free(big);
	}
	/* The shared one, by the owner; not for an API token. */
	http("PUT", SHARED, "{\"arcana-console:shared-store\":{\"motd\":"
	    "\"hi\"}}", &r);
	EXPECT(&r, 204);
	ATF_REQUIRE(resp_header(&r, "etag", stag, sizeof(stag)) != NULL);
	resp_free(&r);
	rc_act(CC "tokens/create", "\"name\":\"w\",\"kind\":\"write\"", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "token") != NULL);
	snprintf(tok, sizeof(tok), "%s", jstr(&r, "token"));
	resp_free(&r);
	http_bearer("GET", SHARED, tok, NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http_bearer("PUT", STORE, tok, "{\"arcana-console:store\":{\"t\":1}}",
	    &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* bob, a member now: his own, none, not the owner's; the shared
	 * one read and not written. */
	snprintf(cookie, sizeof(cookie), "%s", other);
	http("GET", STORE, NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("PUT", STORE, "{\"arcana-console:store\":{\"mine\":true}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", STORE, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "arcana-console:store.mine"));
	ATF_CHECK(jstr(&r, "arcana-console:store.level") == NULL);
	resp_free(&r);
	ATF_CHECK(access("data/plugin-store/good.user.bob.json", F_OK) == 0);
	http("GET", SHARED, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("hi", jstr(&r, "arcana-console:shared-store.motd"));
	ATF_CHECK(resp_header(&r, "etag", hdr, sizeof(hdr)) != NULL &&
	    strcmp(hdr, stag) == 0);
	resp_free(&r);
	snprintf(hdr, sizeof(hdr), "If-Match: %s\r\n", stag);
	http_with("PUT", SHARED, hdr, "{\"arcana-console:shared-store\":{"
	    "\"motd\":\"bob\"}}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* An operator writes it. */
	snprintf(cookie, sizeof(cookie), "%s", owner);
	r1_roles("bob", "operator");
	snprintf(cookie, sizeof(cookie), "%s", other);
	http_with("PUT", SHARED, hdr, "{\"arcana-console:shared-store\":{"
	    "\"motd\":\"bob\"}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", SHARED, NULL, &r);
	ATF_CHECK_STREQ("bob", jstr(&r, "arcana-console:shared-store.motd"));
	resp_free(&r);
	/* A plugin not there: not found. */
	http("GET", CC "plugins/plugin=nosuch/store", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	cookie[0] = '\0';
	http("GET", STORE, NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);

	/* Disabled by the owner: not served again, its store neither,
	 * which is kept; both in the audit trail. */
	snprintf(cookie, sizeof(cookie), "%s", owner);
	r1_enable("good", "false", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "plugins", NULL, &r);
	ATF_CHECK_STREQ("false", cplug_str(&r, "good", "enabled"));
	resp_free(&r);
	http("GET", STORE, NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	ATF_CHECK(access("data/plugin-store/good.user.admin.json", F_OK) == 0);
	snprintf(cookie, sizeof(cookie), "%s", other);
	http("GET", "/plugins/good/main.js", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* A user removed: their store with them, no one else's. */
	snprintf(cookie, sizeof(cookie), "%s", owner);
	http("DELETE", CC "users/user=bob", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	ATF_CHECK(access("data/plugin-store/good.user.bob.json", F_OK) == -1);
	ATF_CHECK(access("data/plugin-store/good.user.admin.json", F_OK) == 0);
	ATF_CHECK(access("data/plugin-store/good.shared.json", F_OK) == 0);
	snprintf(cookie, sizeof(cookie), "%s", owner);
	http("GET", CC "sdwan/audit", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(has(r.body, "plugin-enabled"));
	ATF_CHECK(has(r.body, "plugin-disabled"));
	resp_free(&r);
#undef	STORE
#undef	SHARED
}

CONSOLE_TC(jails, "Servers, jails, actions and addresses through arcana-agent")
ATF_TC_BODY(jails, tc)
{
	struct authn		 a;
	struct resp		 r;
	char			 id[16], base[96], cand[160], path[256];

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("lab", "jgd.sock", id, sizeof(id));
	snprintf(base, sizeof(base), FLEET "%s", id);
	snprintf(cand, sizeof(cand), "/restconf/ds/ietf-datastores:candidate/"
	    "arcana-fleet:fleet/host=%s", id);
	snprintf(path, sizeof(path), CC "hosts/host=%s", id);
	http("GET", path, NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "arcana-console:host.0.local"));
	resp_free(&r);
	host_try("\"name\":\"x\",\"uri\":\"http://x\"", path, sizeof(path), &r);
	EXPECT(&r, 400);
	resp_free(&r);

	snprintf(path, sizeof(path), "%s/arcana-host:host", base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("FreeBSD", jstr(&r, "arcana-host:host.sysname"));
	resp_free(&r);

	snprintf(path, sizeof(path), "%s/arcana-jails:jails", base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	/* JSON that a strict parser takes: never a key twice (",," and an
	 * array where a word goes). */
	ATF_CHECK_MSG(strstr(r.body, ",,") == NULL, "%s", r.body);
	{
		FILE	*fp;

		ATF_REQUIRE((fp = fopen("jails.json", "w")) != NULL);
		fputs(r.body, fp);
		fclose(fp);
		ATF_CHECK_MSG(system("python3 -c 'import json; json.load(open("
		    "\"jails.json\"))'") == 0, "not strict JSON: %s", r.body);
	}
	ATF_CHECK(strstr(r.body, "\"name\":\"db\"") != NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/arcana-jails:jails/jail=web", base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("stopped", jstr(&r, "arcana-jails:jail.0.state"));
	ATF_CHECK_STREQ("10.0.0.10", jstr(&r, "arcana-jails:jail.0.ip4.0"));
	ATF_CHECK_STREQ("/jails/web", jstr(&r, "arcana-jails:jail.0.path"));
	ATF_CHECK_STREQ("true", jstr(&r, "arcana-jails:jail.0.configured"));
	resp_free(&r);

	snprintf(path, sizeof(path), "%s/arcana-jails:jails/jail=web/start",
	    base);
	http("POST", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("running", jstr(&r, "arcana-jails:output.state"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/arcana-jails:jails/jail=web/reboot",
	    base);
	http("POST", path, NULL, &r);
	ATF_CHECK_MSG(r.status == 400 || r.status == 404, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/arcana-jails:jails/jail=web/stop",
	    base);
	http("POST", path, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", path, NULL, &r);
	ATF_CHECK_MSG(r.status >= 400 && strstr(r.body,
	    "jail 'web' is not running") != NULL, "%d %s", r.status, r.body);
	resp_free(&r);
	/* Started at boot: arcana-jails' boot committed, refused for what
	 * it has not accepted, the warning named; accepted, jail_list in
	 * Arcana's rc.conf file. */
	snprintf(path, sizeof(path), "%s/arcana-jails:jails/jail=web", cand);
	http("PATCH", path, "{\"arcana-jails:jail\":[{\"name\":\"web\","
	    "\"boot\":true}]}", &r);
	ATF_CHECK_MSG(r.status == 204, "%d %s", r.status, r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-netconf:commit", base);
	http("POST", path, "{\"ietf-netconf:input\":{\"confirmed\":[null],"
	    "\"confirm-timeout\":60,\"persist\":\"j1\"}}", &r);
	ATF_CHECK_MSG(r.status >= 400 && strstr(r.body,
	    "\"error-app-tag\":\"rc-conf-files\"") != NULL, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-netconf:commit?arcana-accept="
	    "rc-conf-files", base);
	http("POST", path, "{\"ietf-netconf:input\":{\"confirmed\":[null],"
	    "\"confirm-timeout\":60,\"persist\":\"j1\"}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-netconf:commit", base);
	http("POST", path, "{\"ietf-netconf:input\":{\"persist-id\":\"j1\"}}",
	    &r);
	EXPECT(&r, 204);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/arcana-jails:jails/jail=web", base);
	http("GET", path, NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "arcana-jails:jail.0.boot"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^jail_list=\"web\"$' "
	    "root/usr/local/etc/rc.conf.d/arcana") == 0);
	snprintf(path, sizeof(path), "%s/arcana-jails:jails/jail=web", cand);
	http("PATCH", path, "{\"arcana-jails:jail\":[{\"name\":\"web\","
	    "\"boot\":false}]}", &r);
	ATF_CHECK_MSG(r.status == 204, "%d %s", r.status, r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-netconf:commit?arcana-accept="
	    "rc-conf-files", base);
	http("POST", path, "{\"ietf-netconf:input\":{\"confirmed\":[null],"
	    "\"confirm-timeout\":60,\"persist\":\"j2\"}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-netconf:commit", base);
	http("POST", path, "{\"ietf-netconf:input\":{\"persist-id\":\"j2\"}}",
	    &r);
	EXPECT(&r, 204);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/arcana-jails:jails/jail=web", base);
	http("GET", path, NULL, &r);
	ATF_CHECK_STREQ("false", jstr(&r, "arcana-jails:jail.0.boot"));
	resp_free(&r);

	snprintf(path, sizeof(path), "%s/arcana-jails:jails/jail=web/"
	    "arcana-network:address", base);
	http("POST", path, "{\"arcana-network:input\":{\"address\":"
	    "\"10.0.0.11\",\"persist\":true,\"dry-run\":true}}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "arcana-network:output.diff") != NULL &&
	    strstr(jstr(&r, "arcana-network:output.diff"),
	    "+\tip4.addr = 10.0.0.10, \"10.0.0.11\";") != NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC(agent_update, "The console sends its arcana-agent to a host, "
    "which puts it in place and restarts on request; compressed to an agent "
    "that takes it so, as it is to one before")
ATF_TC_BODY(agent_update, tc)
{
	struct authn	a;
	struct resp	r;
	char		path[160], jails[160], cwd[MAXPATHLEN], body[MAXPATHLEN];
	char		old[160], jgd[MAXPATHLEN], listen[MAXPATHLEN], *argv[16];
	char		id[16];
	struct stat	sb, sbig;
	FILE		*fp;
	pid_t		pid;
	int		i;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	start(tc, 0, NULL);
	enrol(&a);
	cc_host("here", "jgd.sock", id, sizeof(id));
	snprintf(path, sizeof(path), CC "hosts/host=%s/agent-update", id);

	/* The console says which build it sends; the host runs that one
	 * here, so the page has nothing to offer. */
	http("GET", "/api/health", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "agent_build") != NULL);
	strlcpy(body, jstr(&r, "agent_build"), sizeof(body));
	ATF_CHECK_EQ(64, strlen(body));
	resp_free(&r);
	snprintf(jails, sizeof(jails), FLEET "%s/arcana-host:host", id);
	http("GET", jails, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(body, jstr(&r, "arcana-host:host.agent.build"));
	resp_free(&r);

	/* With no repository named, there is nothing to build from. */
	snprintf(jails, sizeof(jails), CC "hosts/host=%s/agent-build", id);
	rc_act(jails, "", &r);
	EXPECT(&r, 409);
	resp_free(&r);

	ATF_REQUIRE(access("installed-agent", F_OK) == -1);
	rc_act(path, "", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("false", jstr(&r, "restarting"));
	ATF_CHECK(jstr(&r, "version") != NULL);
	ATF_CHECK(access("installed-agent", X_OK) == 0);
	/* Sent compressed: the agent says it takes it so. */
	ATF_CHECK_MSG(strstr(r.body, "inflate(3)") != NULL, "%s", r.body);
	resp_free(&r);
	/*
	 * An agent before compressed updates, as one with no features in
	 * arcana-host: the program as it is, within a frame.
	 */
	snprintf(jgd, sizeof(jgd), "%s", locate(tc,
	    "../../../usr.sbin/arcana-agent/arcana-agent", "arcana-agent",
	    "/usr/local/sbin/arcana-agent"));
	snprintf(listen, sizeof(listen), "unix:%s/old.sock", cwd);
	i = 0;
	argv[i++] = jgd;
	argv[i++] = (char *)(uintptr_t)"-F";
	argv[i++] = (char *)(uintptr_t)"-l";
	argv[i++] = listen;
	argv[i++] = (char *)(uintptr_t)"-f";
	argv[i++] = (char *)(uintptr_t)"etc/jail.conf";
	argv[i++] = (char *)(uintptr_t)"-D";
	argv[i++] = (char *)(uintptr_t)"etc/jail.conf.d";
	argv[i++] = (char *)(uintptr_t)"-y";
	argv[i++] = (char *)(uintptr_t)"./fake-sysrc";
	argv[i++] = (char *)(uintptr_t)"-U";
	argv[i++] = (char *)(uintptr_t)"installed-agent3";
	argv[i++] = (char *)(uintptr_t)"--features";
	argv[i++] = (char *)(uintptr_t)"none";
	argv[i] = NULL;
	pid = spawn_server(argv, "arcana-agent2.out");
	ATF_REQUIRE((fp = fopen("arcana-agent2.pid", "w")) != NULL);
	fprintf(fp, "%d\n", (int)pid);
	fclose(fp);
	wait_for("old.sock");
	host_add("old", listen, body, sizeof(body));
	snprintf(old, sizeof(old), CC "hosts/host=%s/agent-update", body);
	rc_act(old, "", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "ok") != NULL && strcmp(jstr(&r, "ok"),
	    "true") == 0, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "inflate") == NULL, "%s", r.body);
	ATF_CHECK(stat("installed-agent3", &sb) == 0 && stat(jgd, &sbig) == 0 &&
	    sb.st_size == sbig.st_size);
	resp_free(&r);

	/*
	 * Past a frame, the agent with 7 MiB of zeros after it: carried
	 * compressed to the one that takes it so, refused for the one
	 * before.
	 */
	snprintf(body, sizeof(body), "cat '%s' > big-agent && dd if=/dev/zero "
	    "bs=1m count=7 >> big-agent 2>/dev/null && chmod 755 big-agent",
	    jgd);
	ATF_REQUIRE(system(body) == 0);
	snprintf(body, sizeof(body), "{\"arcana-console:agent-binary\":"
	    "\"%s/big-agent\"}", cwd);
	http("PUT", CC "settings/agent-binary", body, &r);
	ATF_CHECK_MSG(r.status == 201 || r.status == 204, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	rc_act(path, "", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "ok") != NULL && strcmp(jstr(&r, "ok"),
	    "true") == 0, "%s", r.body);
	ATF_CHECK(stat("installed-agent", &sb) == 0 && stat("big-agent",
	    &sbig) == 0 && sb.st_size == sbig.st_size);
	resp_free(&r);
	rc_act(old, "", &r);
	ATF_CHECK_MSG(jstr(&r, "ok") != NULL && strcmp(jstr(&r, "ok"),
	    "false") == 0, "%s", r.body);
	ATF_CHECK_MSG(jstr(&r, "error") != NULL && strstr(jstr(&r, "error"),
	    "takes no compressed update") != NULL, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(stat("installed-agent3", &sb) == 0 && sb.st_size !=
	    sbig.st_size);
	snprintf(body, sizeof(body), "{\"arcana-console:agent-binary\":"
	    "\"%s\"}", jgd);
	http("PUT", CC "settings/agent-binary", body, &r);
	ATF_CHECK_MSG(r.status == 201 || r.status == 204, "%d %s", r.status,
	    r.body);
	resp_free(&r);

	rc_act(path, "\"restart\":true", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("true", jstr(&r, "restarting"));
	ATF_CHECK(access("installed-agent.old", F_OK) == 0);
	resp_free(&r);
}

/*
 * Host id's change chg submitted and waited for until it ends or waits
 * to be confirmed: r the job's read (arcana-jobs:output.state, ok, error)
 * and true; false where submit refused it, r its answer.  The job's id
 * in jid.
 */
static bool
r1_job(const char *id, const char *chg, struct resp *r, char *jid,
    size_t len)
{
	char		 path[160];
	const char	*st;
	int		 i;

	r1_submit(id, chg, r);
	if (r->status != 200)
		return (false);
	ATF_REQUIRE_MSG(jstr(r, "arcana-jobs:output.id.0") != NULL, "%s",
	    r->body);
	snprintf(jid, len, "%s", jstr(r, "arcana-jobs:output.id.0"));
	resp_free(r);
	snprintf(path, sizeof(path), FLEET "%s/arcana-jobs:jobs/job=%s/read",
	    id, jid);
	for (i = 0; i < 300; i++) {
		http("POST", path, NULL, r);
		if (r->status == 200 && (st = jstr(r,
		    "arcana-jobs:output.state")) != NULL && (strcmp(st,
		    "done") == 0 || strcmp(st, "cancelled") == 0 ||
		    strcmp(st, "unconfirmed") == 0))
			return (true);
		resp_free(r);
		usleep(100000);
	}
	ATF_REQUIRE_MSG(0, "job %s did not end", jid);
	return (false);
}

/* Whether r1_job's r says the change refused, why. */
static bool
r1_refused(const struct resp *r, bool ran, const char *why)
{
	const char	*ok = jstr(r, "arcana-jobs:output.ok");

	return ((!ran || (ok != NULL && strcmp(ok, "false") == 0)) &&
	    r->body != NULL && strstr(r->body, why) != NULL);
}

/* Host id's read action at what (arcana-speeder:speeder/read), its input
 * members in (NULL: none). */
static void
r1_read(const char *id, const char *what, const char *in, struct resp *r)
{
	char	path[160], *body;
	int	n;

	snprintf(path, sizeof(path), FLEET "%s/%s", id, what);
	n = (int)strcspn(what, ":");
	ATF_REQUIRE(asprintf(&body, "{\"%.*s:input\":{%s}}", n, what,
	    in != NULL ? in : "") != -1);
	http("POST", path, body, r);
	free(body);
}

CONSOLE_TC(monitors, "Tunnel monitors through the console: set by a job as "
    "the page sends it, read back with their settings, a refusal said, "
    "removed")
ATF_TC_BODY(monitors, tc)
{
	struct authn	a;
	struct resp	r;
	char		path[160], id[16], jid[24];
	bool		ran;
	int		i;

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("here", "jgd.sock", id, sizeof(id));
	snprintf(path, sizeof(path), FLEET "%s/arcana-probe:probes", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"monitor\"") == NULL, "%s", r.body);
	resp_free(&r);
	r1_submit(id, "{\"monitor\":{\"verb\":\"set\",\"args\":[\"name=gre9\","
	    "\"interface=gre9\",\"address=192.0.2.9\",\"interval=500\","
	    "\"eval=10000\",\"delay-max=40\",\"loss-max=2\"]}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 100; i++) {
		http("GET", path, NULL, &r);
		if (jstr(&r, "arcana-probe:probes.monitor.0.name") != NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_CHECK_STREQ("gre9", jstr(&r, "arcana-probe:probes.monitor.0.name"));
	ATF_CHECK_STREQ("192.0.2.9", jstr(&r,
	    "arcana-probe:probes.monitor.0.address"));
	ATF_CHECK_STREQ("gre9", jstr(&r,
	    "arcana-probe:probes.monitor.0.interface"));
	ATF_CHECK_STREQ("500", jstr(&r,
	    "arcana-probe:probes.monitor.0.interval"));
	ATF_CHECK_MSG(jstr(&r, "arcana-probe:probes.monitor.0.tca.loss") !=
	    NULL && atof(jstr(&r, "arcana-probe:probes.monitor.0.tca.loss")) ==
	    0.02, "%s", r.body);
	resp_free(&r);
	/* What the host refuses comes back as the job's failure. */
	ran = r1_job(id, "{\"monitor\":{\"verb\":\"set\",\"args\":[\"name=x\","
	    "\"address=192.0.2.1\",\"loss-max=150\"]}}", &r, jid, sizeof(jid));
	ATF_CHECK_MSG(r1_refused(&r, ran, "loss-max a per cent"), "%s",
	    r.body);
	resp_free(&r);
	r1_submit(id, "{\"monitor\":{\"verb\":\"remove\",\"args\":"
	    "[\"name=gre9\"]}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 100; i++) {
		http("GET", path, NULL, &r);
		if (r.body != NULL && strstr(r.body, "\"monitor\"") == NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_CHECK_MSG(i < 100, "the monitor is not removed");
	resp_free(&r);

	/*
	 * As the Quality dialog sets them: arcana-probe's monitors, a YANG
	 * Patch of the host's candidate, then a confirmed commit confirmed;
	 * and taken away the same way.
	 */
	{
		char	cand[256], rpc[256];

		snprintf(cand, sizeof(cand), "/restconf/ds/ietf-datastores:"
		    "candidate/arcana-fleet:fleet/host=%s/arcana-probe:probes",
		    id);
		snprintf(rpc, sizeof(rpc), "/restconf/data/arcana-fleet:fleet/"
		    "host=%s/ietf-netconf:commit", id);
		http_with("PATCH", cand, "Content-Type: application/"
		    "yang-patch+json\r\n", "{\"ietf-yang-patch:yang-patch\":{"
		    "\"patch-id\":\"quality\",\"edit\":[{\"edit-id\":\"ov-gre9\","
		    "\"operation\":\"merge\",\"target\":\"/monitor=ov-gre9\","
		    "\"value\":{\"arcana-probe:monitor\":[{\"name\":\"ov-gre9\","
		    "\"interface\":\"gre9\",\"address\":\"192.0.2.9\",\"fib\":1,"
		    "\"interval\":100,\"eval\":1000}]}}]}}", &r);
		EXPECT(&r, 200);
		resp_free(&r);
		http("POST", rpc, "{\"ietf-netconf:input\":{\"confirmed\":"
		    "[null],\"confirm-timeout\":60,\"persist\":\"q1\"}}", &r);
		EXPECT(&r, 204);
		resp_free(&r);
		http("POST", rpc, "{\"ietf-netconf:input\":{\"persist-id\":"
		    "\"q1\"}}", &r);
		EXPECT(&r, 204);
		resp_free(&r);
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("ov-gre9", jstr(&r,
		    "arcana-probe:probes.monitor.0.name"));
		ATF_CHECK_STREQ("1", jstr(&r,
		    "arcana-probe:probes.monitor.0.fib"));
		ATF_CHECK_STREQ("100", jstr(&r,
		    "arcana-probe:probes.monitor.0.interval"));
		resp_free(&r);
		ATF_CHECK(system("grep -q ov-gre9 monitors.json") == 0);
		http_with("PATCH", cand, "Content-Type: application/"
		    "yang-patch+json\r\n", "{\"ietf-yang-patch:yang-patch\":{"
		    "\"patch-id\":\"quality\",\"edit\":[{\"edit-id\":\"ov-gre9\","
		    "\"operation\":\"remove\",\"target\":\"/monitor=ov-gre9\"}]}}",
		    &r);
		EXPECT(&r, 200);
		resp_free(&r);
		http("POST", rpc, "{\"ietf-netconf:input\":{}}", &r);
		EXPECT(&r, 204);
		resp_free(&r);
		http("GET", path, NULL, &r);
		ATF_CHECK_MSG(r.body != NULL && strstr(r.body, "\"monitor\"") ==
		    NULL, "%s", r.body);
		resp_free(&r);
	}
}

CONSOLE_TC(speeder, "UDPspeeder's relay read through the console, its "
    "overhead from its log; its flags written by a safe job as the page "
    "sends it, confirmed; the key in no reply")
ATF_TC_BODY(speeder, tc)
{
	struct authn	a;
	struct resp	r;
	char		path[160], id[16], jid[24];
	bool		ran;
	int		i;

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("here", "jgd.sock", id, sizeof(id));
	r1_read(id, "arcana-speeder:speeder/read", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "arcana-speeder:output.installed"));
	ATF_CHECK_MSG(jstr(&r, "arcana-speeder:output.report.client-to-server."
	    "overhead") != NULL && atof(jstr(&r, "arcana-speeder:output.report."
	    "client-to-server.overhead")) == 50.0, "%s", r.body);
	ATF_CHECK_STREQ("2", jstr(&r,
	    "arcana-speeder:output.fec-group.1.size"));
	resp_free(&r);
	/* The flags, by a safe job as the tab sends it, then confirmed. */
	ran = r1_job(id, "{\"speeder\":{\"verb\":\"conf\",\"args\":["
	    "\"role=client\",\"listen=127.0.0.1:51821\",\"remote="
	    "192.0.2.1:14350\",\"fec=20:10\",\"report=10\",\"key=t0psecret\"]},"
	    "\"safe\":true}", &r, jid, sizeof(jid));
	ATF_REQUIRE_MSG(ran, "%d %s", r.status, r.body);
	ATF_CHECK_STREQ("unconfirmed", jstr(&r, "arcana-jobs:output.state"));
	resp_free(&r);
	for (i = 0; i < 300 && system("grep -q '^arcana_relay_flags=\"-c "
	    "-l127.0.0.1:51821 -r192.0.2.1:14350 -k t0psecret -f20:10 --report "
	    "10\"$' rc.conf") != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(i < 300, "the flags are not written");
	r1_read(id, "arcana-speeder:speeder/read", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "arcana-speeder:output.key"));
	ATF_CHECK_MSG(strstr(r.body, "t0psecret") == NULL, "%s", r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), FLEET "%s/arcana-jobs:jobs/job=%s/confirm",
	    id, jid);
	http("POST", path, NULL, &r);
	ATF_CHECK_MSG(r.status == 200 || r.status == 204, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	/* Confirmed: not undone after. */
	sleep(3);
	ATF_CHECK(system("grep -q '^arcana_relay_flags=\"-c ' rc.conf") == 0);
	snprintf(path, sizeof(path), FLEET "%s/arcana-jobs:jobs", id);
	http("GET", path, NULL, &r);
	ATF_CHECK_MSG(strstr(r.body, "t0psecret") == NULL && strstr(r.body,
	    "undone") == NULL, "%.800s", r.body);
	resp_free(&r);
	/* What the host refuses comes back as the job's failure. */
	ran = r1_job(id, "{\"speeder\":{\"verb\":\"fec\",\"args\":[\"0:9\"]}}",
	    &r, jid, sizeof(jid));
	ATF_CHECK_MSG(r1_refused(&r, ran, "fec takes the ratios"), "%s",
	    r.body);
	resp_free(&r);
}

CONSOLE_TC(smtpd, "OpenSMTPD read through the console; smtpd.conf rendered on "
    "the host from the form; a table's passwords hashed there, never read back")
ATF_TC_BODY(smtpd, tc)
{
	struct authn	a;
	struct resp	r;
	char		id[16], jid[24], body[2048];
	const char	*v;
	bool		ran;
	int		i;

#define	SMTPD	"arcana-smtpd:smtpd/read"
#define	OUT	"arcana-smtpd:output."
	start(tc, 0, NULL);
	enrol(&a);
	cc_host("here", "jgd.sock", id, sizeof(id));
	/* Installed (the fake), not running: no status asked. */
	r1_read(id, SMTPD, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, OUT "installed"));
	ATF_CHECK_STREQ("false", jstr(&r, OUT "running"));
	ATF_CHECK(jstr(&r, OUT "smtpctl.status") == NULL);
	resp_free(&r);
	/* A jail's (the one that runs here): read in its root, where
	 * nothing is installed. */
	r1_read(id, SMTPD, "\"jail\":\"gw\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, OUT "installed") != NULL && strcmp(jstr(&r,
	    OUT "installed"), "false") == 0, "%.400s", r.body);
	ATF_CHECK_STREQ("gw", jstr(&r, OUT "jail"));
	resp_free(&r);
	/* The form, as the page sends it: rendered on the host, checked by
	 * smtpd -n, written; the form kept and read back. */
	snprintf(body, sizeof(body), "{\"smtpd\":{\"verb\":\"conf\","
	    "\"text\":\"{\\\"listeners\\\":[{\\\"on\\\":\\\"localhost\\\"},"
	    "{\\\"on\\\":\\\"em0\\\",\\\"port\\\":587,\\\"tls\\\":\\\"tls\\\","
	    "\\\"pki\\\":\\\"mail\\\",\\\"auth\\\":true}],\\\"domains\\\":"
	    "[\\\"example.org\\\"],\\\"delivery\\\":{\\\"kind\\\":\\\"maildir\\\","
	    "\\\"aliases\\\":true}}\"}}");
	ran = r1_job(id, body, &r, jid, sizeof(jid));
	ATF_REQUIRE_MSG(ran, "%d %s", r.status, r.body);
	ATF_CHECK_MSG((v = jstr(&r, "arcana-jobs:output.title")) != NULL &&
	    strstr(v, "smtpd conf") != NULL, "%s", r.body);
	resp_free(&r);
	for (i = 0; i < 300 && system("grep -q '^listen on em0 port 587 tls pki "
	    "mail auth <credentials>$' smtpd.conf") != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(i < 300, "smtpd.conf is not rendered");
	ATF_CHECK(system("grep -q '^smtpd -n -f ' smtpd.log") == 0);
	ATF_CHECK(system("grep -q '^match from any for domain <domains> action "
	    "\"local\"$' smtpd.conf") == 0);
	r1_read(id, SMTPD, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG((v = jstr(&r, OUT "spec")) != NULL && strstr(v,
	    "\"on\":\"em0\"") != NULL, "%.600s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "listen on localhost") != NULL, "%.600s",
	    r.body);
	resp_free(&r);
	/* What the host refuses comes back as the job's failure. */
	ran = r1_job(id, "{\"smtpd\":{\"verb\":\"conf\",\"text\":"
	    "\"{\\\"listeners\\\":[]}\"}}", &r, jid, sizeof(jid));
	ATF_CHECK_MSG(r1_refused(&r, ran, "a listener at least"), "%s",
	    r.body);
	resp_free(&r);
	/* Credentials: hashed on the host, the clear password nowhere. */
	r1_submit(id, "{\"smtpd\":{\"verb\":\"table\",\"args\":"
	    "[\"credentials\"],\"text\":\"alice hunter2\\n\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 300 && access("smtpd.d/credentials", F_OK) != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(i < 300, "the table is not written");
	ATF_CHECK(system("grep -q '^alice	$6$fake$hashOf$1$' smtpd.d/credentials")
	    == 0);
	ATF_CHECK(system("grep -q '^encrypt <hunter2$' smtpd.log") == 0);
	/* The same in the jail that runs: its table under its root, its
	 * encrypt run in it (jexec), nothing of the host's touched. */
	ATF_REQUIRE(system("mkdir -p jroot/smtpd.d && rm -f smtpd.d/aliases") ==
	    0);
	r1_submit(id, "{\"smtpd\":{\"verb\":\"table\",\"jail\":\"gw\","
	    "\"args\":[\"credentials\"],\"text\":\"bob pw2\\n\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 300 && system("grep -q '^bob	' jroot/smtpd.d/credentials "
	    "2>/dev/null") != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(i < 300, "the jail's table is not written under its root");
	ATF_CHECK(system("grep -q '^jexec 4 .*encrypt' jexec.log") == 0);
	ATF_CHECK(system("grep -q '^bob' smtpd.d/credentials") != 0);
	r1_read(id, SMTPD, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"name\":\"credentials\"") != NULL &&
	    strstr(r.body, "\"alice\"") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "hunter2") == NULL && strstr(r.body, "hashOf")
	    == NULL);
	resp_free(&r);
	/* Started (its rc.d script there, as the port installs it): its
	 * status and queue, as smtpctl says. */
	ATF_REQUIRE(mkdir("rc.d", 0755) == 0 || errno == EEXIST);
	ATF_REQUIRE(system("printf '#!/bin/sh\\n' > rc.d/smtpd && chmod +x "
	    "rc.d/smtpd") == 0);
	r1_submit(id, "{\"smtpd\":{\"verb\":\"enable\",\"args\":"
	    "[\"enable=yes\"]}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 300 && access("running.smtpd", F_OK) != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(i < 300, "smtpd was not started");
	r1_read(id, SMTPD, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, OUT "running"));
	ATF_CHECK_MSG(strstr(r.body, "{\"process\":\"mta\",\"state\":"
	    "\"running\"}") != NULL, "%s", r.body);
	ATF_CHECK_STREQ("6022923fc9341b9d", jstr(&r,
	    OUT "smtpctl.envelope.0.evpid"));
	ATF_CHECK_STREQ("(TempFail) no route", jstr(&r,
	    OUT "smtpctl.envelope.0.error"));
	resp_free(&r);
	r1_submit(id, "{\"smtpd\":{\"verb\":\"remove\",\"args\":"
	    "[\"6022923fc9341b9d\"]}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 300 && system("grep -q '^smtpctl remove 6022923fc9341b9d$'"
	    " smtpd.log") != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(i < 300, "the envelope was not removed");
	ran = r1_job(id, "{\"smtpd\":{\"verb\":\"remove\",\"args\":"
	    "[\"../x\"]}}", &r, jid, sizeof(jid));
	ATF_CHECK_MSG(r1_refused(&r, ran, ""), "%s", r.body);
	resp_free(&r);
#undef	SMTPD
#undef	OUT
}

CONSOLE_TC(update_notes, "What is new in the repository since the version "
    "running: the commit messages, new until the version's own commit, or "
    "the tags' messages where there are any")
ATF_TC_BODY(update_notes, tc)
{
	struct authn	a;
	struct resp	r;
	FILE		*fp;
	char		id[16];

#define	NOTES	CC "update-notes?component="
#define	NOTES_OF(r)	resp_unwrap((r), "arcana-console:update-notes")
	harness_other_agent = true;
	snprintf(harness_webconf, sizeof(harness_webconf), "agent_source = "
	    "\"https://example.org/arcana.git\";\nagent_ref = \"main\";\n");
	start(tc, 0, NULL);
	enrol(&a);
	/* No server yet: nothing to read the repository through. */
	http("GET", NOTES "console&from=0.2.0", NULL, &r);
	EXPECT(&r, 409);
	resp_free(&r);
	cc_host("here", "jgd.sock", id, sizeof(id));
	/* Three commits, the middle one the version running: the newest
	 * is new, the running one marked, the oldest neither. */
	ATF_REQUIRE((fp = fopen("commits", "w")) != NULL);
	fprintf(fp, "cccc\037300\037console 0.3.0: three\037the third's body\036"
	    "bbbb\037200\037agent 0.9.0, console 0.2.0: two\037\036"
	    "aaaa\037100\037console 0.1.0: one\037\036");
	fclose(fp);
	http("GET", NOTES "console&from=0.2.0", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(NOTES_OF(&r));
	ATF_REQUIRE_MSG(jstr(&r, "kind") != NULL && jstr(&r, "host") != NULL &&
	    jstr(&r, "notes.0.title") != NULL, "%d %s", r.status, r.body);
	ATF_CHECK_STREQ("commits", jstr(&r, "kind"));
	ATF_CHECK_STREQ("here", jstr(&r, "host"));
	ATF_CHECK_STREQ("console 0.3.0: three", jstr(&r, "notes.0.title"));
	ATF_CHECK_STREQ("true", jstr(&r, "notes.0.new"));
	ATF_CHECK_STREQ("the third's body", jstr(&r, "notes.0.body"));
	ATF_CHECK_STREQ("false", jstr(&r, "notes.1.new"));
	ATF_CHECK_STREQ("true", jstr(&r, "notes.1.here"));
	ATF_CHECK_STREQ("false", jstr(&r, "notes.2.new"));
	ATF_CHECK_STREQ("false", jstr(&r, "notes.2.here"));
	resp_free(&r);
	/* The agents: what is up to the console's version, from a version
	 * no commit names: everything up to it. */
	http("GET", NOTES "agent&from=0.8.0&to=0.9.0", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(NOTES_OF(&r));
	ATF_CHECK_STREQ("false", jstr(&r, "notes.0.new"));
	ATF_CHECK_STREQ("true", jstr(&r, "notes.1.new"));
	ATF_CHECK_STREQ("true", jstr(&r, "notes.2.new"));
	resp_free(&r);
	/* Tags with messages, one newer: the release notes instead, read
	 * again when asked fresh. */
	ATF_REQUIRE((fp = fopen("tags", "w")) != NULL);
	fprintf(fp, "v0.3.0\037300\037Release three\n\nWith the record.\036"
	    "v0.2.0\037200\037Release two\036");
	fclose(fp);
	http("GET", NOTES "console&from=0.2.0", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(NOTES_OF(&r));
	ATF_CHECK_STREQ("commits", jstr(&r, "kind"));
	resp_free(&r);
	http("GET", NOTES "console&from=0.2.0&fresh=1", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(NOTES_OF(&r));
	ATF_CHECK_STREQ("tags", jstr(&r, "kind"));
	ATF_CHECK_STREQ("v0.3.0", jstr(&r, "notes.0.title"));
	ATF_CHECK_STREQ("true", jstr(&r, "notes.0.new"));
	ATF_CHECK_MSG(jstr(&r, "notes.0.body") != NULL && strncmp(jstr(&r,
	    "notes.0.body"), "Release three", 13) == 0, "%s", r.body);
	ATF_CHECK_STREQ("true", jstr(&r, "notes.1.here"));
	ATF_CHECK_STREQ("false", jstr(&r, "notes.1.new"));
	resp_free(&r);
	/* The repository cannot be fetched: the host's reason, said. */
	ATF_REQUIRE((fp = fopen("fetch-fails", "w")) != NULL);
	fclose(fp);
	http("GET", NOTES "console&from=0.2.0&fresh=1", NULL, &r);
	ATF_CHECK_EQ_MSG(502, r.status, "%d %s", r.status, r.body);
	ATF_CHECK_MSG(strstr(r.body, "ietf-restconf:errors") != NULL &&
	    strstr(r.body, "host key is known") != NULL, "%d %s", r.status,
	    r.body);
	resp_free(&r);
#undef	NOTES
#undef	NOTES_OF
}

CONSOLE_TC(agent_build, "A host builds arcana-agent from the repository "
    "the console names, and the console keeps it to send")
ATF_TC_BODY(agent_build, tc)
{
	struct authn	a;
	struct resp	r;
	char		path[160], cwd[MAXPATHLEN], body[MAXPATHLEN], sha[65];
	char		id[16];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	harness_other_agent = true;
	snprintf(harness_webconf, sizeof(harness_webconf), "agent_source = "
	    "\"https://example.org/arcana.git\";\nagent_ref = \"main\";\n");
	start(tc, 0, NULL);
	/* Where the agent is built from is not told to who is not in. */
	http("GET", "/api/health", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "agent_source") == NULL);
	ATF_CHECK(jstr(&r, "agent_ref") == NULL);
	resp_free(&r);
	enrol(&a);
	cc_host("here", "jgd.sock", id, sizeof(id));
	snprintf(path, sizeof(path), CC "hosts/host=%s/agent-build", id);

	/* Before: the one installed with the console, another build. */
	http("GET", "/api/health", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("https://example.org/arcana.git", jstr(&r,
	    "agent_source"));
	ATF_CHECK_STREQ("main", jstr(&r, "agent_ref"));
	ATF_CHECK(jstr(&r, "agent_version") != NULL);
	strlcpy(sha, jstr(&r, "agent_build"), sizeof(sha));
	resp_free(&r);

	rc_act(path, "", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK(jstr(&r, "version") != NULL);
	ATF_REQUIRE(jstr(&r, "sha256") != NULL);
	ATF_CHECK(strcmp(sha, jstr(&r, "sha256")) != 0);
	strlcpy(sha, jstr(&r, "sha256"), sizeof(sha));
	/* Sent back compressed, kept inflated: its SHA-256 the program's. */
	ATF_CHECK_MSG(strstr(r.body, "deflate(3)") != NULL, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(access("data/agent/arcana-agent", X_OK) == 0);
	snprintf(body, sizeof(body), "test \"$(sha256 -q "
	    "data/agent/arcana-agent)\" = %s", sha);
	ATF_CHECK(system(body) == 0);

	/* After: what the host built is what the console sends. */
	http("GET", "/api/health", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(sha, jstr(&r, "agent_build"));
	ATF_CHECK(jstr(&r, "agent_version") != NULL);
	resp_free(&r);

	/*
	 * Unless the one installed beside the console is newer, as after
	 * the console itself was updated: that one is of its version, and
	 * the built one of the version before.
	 */
	ATF_REQUIRE(system("touch -t 203001010000 other-agent") == 0);
	http("GET", "/api/health", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strcmp(sha, jstr(&r, "agent_build")) != 0);
	resp_free(&r);
	ATF_REQUIRE(system("touch -t 200001010000 other-agent") == 0);
	http("GET", "/api/health", NULL, &r);
	ATF_CHECK_STREQ(sha, jstr(&r, "agent_build"));
	resp_free(&r);

	/*
	 * Over SSH: the host hands back the server's host keys for the
	 * user to confirm, and builds once they come back confirmed.
	 */
	ATF_REQUIRE(system("ssh-keygen -q -t ed25519 -N '' -f hostkey") == 0);
	http("PUT", CC "settings/agent-source", "{\"arcana-console:"
	    "agent-source\":\"git@git.example.org:me/arcana.git\"}", &r);
	ATF_CHECK_MSG(r.status == 201 || r.status == 204, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	rc_act(path, "", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_REQUIRE(jstr(&r, "host_keys") != NULL);
	ATF_CHECK(strncmp(jstr(&r, "host_keys"), "git.example.org ssh-ed25519 ",
	    28) == 0);
	ATF_CHECK(jstr(&r, "fingerprints.0") != NULL && strstr(jstr(&r,
	    "fingerprints.0"), "SHA256:") != NULL);
	ATF_CHECK(jstr(&r, "deploy_key") != NULL);
	snprintf(body, sizeof(body), "\"host-keys\":\"%.*s\"",
	    (int)strcspn(jstr(&r, "host_keys"), "\n"), jstr(&r, "host_keys"));
	resp_free(&r);
	rc_act(path, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	resp_free(&r);
	ATF_CHECK(access("build/known_hosts", R_OK) == 0);
	/* Without a key named, the host shows its own. */
	ATF_CHECK(system("grep -q 'ssh -i .*/build/id_ed25519 ' git.log") == 0);

	/* The key named in Settings is the one git is told to show. */
	snprintf(body, sizeof(body), "{\"arcana-console:agent-ssh-key\":"
	    "\"%s/hostkey\"}", cwd);
	http("PUT", CC "settings/agent-ssh-key", body, &r);
	ATF_CHECK_MSG(r.status == 201 || r.status == 204, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	rc_act(path, "", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	resp_free(&r);
	snprintf(body, sizeof(body), "grep -q 'ssh -i %s/hostkey ' git.log",
	    cwd);
	ATF_CHECK(system(body) == 0);

	/*
	 * The console's own update, through the agent of its host: the
	 * tree is built and installed, and the console's service asked
	 * to restart.
	 */
	snprintf(body, sizeof(body), CC "hosts/host=%s/console-update", id);
	rc_act(body, "", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("true", jstr(&r, "restarting"));
	resp_free(&r);
}

CONSOLE_TC(session_restart, "A login outlives a restart of the console; a "
    "logout does not")
ATF_TC_BODY(session_restart, tc)
{
	struct authn	a;
	struct resp	r;
	FILE		*fp;
	char		 buf[512];

	start(tc, 0, NULL);
	enrol(&a);
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* What is kept is the cookie's hash, for its user alone: a
	 * document a session. */
	ATF_CHECK(system("test \"$(ls data/sessions | wc -l)\" -eq 1") == 0);
	ATF_REQUIRE((fp = popen("cat data/sessions/*.json", "r")) != NULL);
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(fread(buf, 1, sizeof(buf) - 1, fp) > 0);
	pclose(fp);
	ATF_CHECK(strstr(buf, "\"hash\"") != NULL);
	ATF_CHECK(strstr(buf, cookie + 12) == NULL);
	ATF_CHECK(system("test \"$(stat -f %Lp data/sessions/*.json)\" = 600")
	    == 0);

	restart_console();
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);

	/* Logged out, the session is gone from the file too, and stays
	 * gone over a restart. */
	strlcpy(buf, cookie, sizeof(buf));
	http("POST", "/api/auth/logout", "{}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	strlcpy(cookie, buf, sizeof(cookie));
	ATF_CHECK(system("test -z \"$(ls data/sessions)\"") == 0);
	restart_console();
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
}

CONSOLE_TC(load, "The console keeps answering under many requests at once, "
    "some of them abandoned")
ATF_TC_BODY(load, tc)
{
	static const char *what[] = { "arcana-jails:jails", "arcana-host:host",
	    "arcana-services:services", "ietf-interfaces:interfaces",
	    "ietf-routing:routing", "arcana-kernel:kernel",
	    "arcana-jobs:jobs" };
	struct authn	a;
	struct resp	r;
	char		base[96], path[160], id[16];
	pid_t		pids[8];
	int		i, k, status, bad;

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("here", "jgd.sock", id, sizeof(id));
	snprintf(base, sizeof(base), FLEET "%s", id);

	/* Eight clients at once, each asking for everything in turn and
	 * walking away from every third request. */
	for (k = 0; k < 8; k++) {
		if ((pids[k] = fork()) == 0) {
			bad = 0;
			for (i = 0; i < 42; i++) {
				snprintf(path, sizeof(path), "%s/%s", base,
				    what[(i + k) % 7]);
				if (i % 3 == 2) {
					http_abandon(path);
					continue;
				}
				http("GET", path, NULL, &r);
				if (r.status != 200)
					bad++;
				resp_free(&r);
				http("GET", "/api/health", NULL, &r);
				if (r.status != 200)
					bad++;
				resp_free(&r);
			}
			_exit(bad > 250 ? 250 : bad);
		}
		ATF_REQUIRE(pids[k] > 0);
	}
	for (k = 0; k < 8; k++) {
		ATF_REQUIRE(waitpid(pids[k], &status, 0) == pids[k]);
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "client %d: %d requests failed", k, WIFEXITED(status) ?
		    WEXITSTATUS(status) : -1);
	}
	/* It is the same process still, and it answers. */
	http("GET", "/api/health", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK(system("! grep -Ei 'exited|signal|crash|fatal' console.out") ==
	    0);
}

/*
 * A stand-in for an agent that is never whole: on ./flaky.sock it takes
 * each connection and lets it go at once, after the request, a while
 * later, or after bytes that are no frame.
 */
static pid_t
flaky_agent(void)
{
	struct sockaddr_un	sun;
	char			buf[512];
	pid_t			pid;
	int			s, c, n;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, "flaky.sock", sizeof(sun.sun_path));
	ATF_REQUIRE((s = socket(AF_UNIX, SOCK_STREAM, 0)) != -1);
	ATF_REQUIRE(bind(s, (struct sockaddr *)&sun, sizeof(sun)) == 0);
	ATF_REQUIRE(listen(s, 64) == 0);
	ATF_REQUIRE((pid = fork()) != -1);
	if (pid != 0) {
		close(s);
		return (pid);
	}
	for (n = 0;; n++) {
		if ((c = accept(s, NULL, NULL)) == -1)
			continue;
		switch (n % 4) {
		case 1:
			(void)read(c, buf, sizeof(buf));
			break;
		case 2:
			usleep(200000);
			break;
		case 3:
			(void)write(c, "\377\377\377\377 no frame", 13);
			break;
		}
		close(c);
	}
}

CONSOLE_TC(churn, "No descriptor is closed twice while the store is "
    "written, hosts fail and pages come and go")
ATF_TC_BODY(churn, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[1024], here[16], flaky[16];
	char		wid[16], path[160], ask[300];
	pid_t		pids[8], fake;
	int		i, k, ws, status;

	start(tc, 0, NULL);
	enrol(&a);
	fake = flaky_agent();
	cc_host("here", "jgd.sock", here, sizeof(here));
	cc_host("flaky", "flaky.sock", flaky, sizeof(flaky));
	/* Runs: threads that write the store as they go. */
	snprintf(wid, sizeof(wid), "0000c001");
	snprintf(body, sizeof(body), "{\"arcana-console:workflow\":[{\"id\":"
	    "\"%s\",\"name\":\"churn\",\"host\":[\"%s\",\"%s\"],\"step\":[{"
	    "\"id\":\"a\",\"read\":\"hello\"},{\"id\":\"b\",\"read\":"
	    "\"jails\"},{\"id\":\"c\",\"read\":\"services\"}]}]}", wid, here,
	    flaky);
	snprintf(path, sizeof(path), CC "workflows/workflow=%s", wid);
	http("PUT", path, body, &r);
	EXPECT(&r, 201);
	resp_free(&r);

	for (k = 0; k < 8; k++) {
		if ((pids[k] = fork()) != 0)
			continue;
		for (i = 0; i < 30; i++) {
			switch ((i + k) % 5) {
			case 0:
				snprintf(path, sizeof(path), CC "workflows/"
				    "workflow=%s/run", wid);
				http("POST", path, NULL, &r);
				break;
			case 1:
				snprintf(path, sizeof(path), CC "labels/label="
				    "%s,e%d", here, k);
				snprintf(body, sizeof(body), "{\"arcana-"
				    "console:label\":[{\"host\":\"%s\","
				    "\"interface\":\"e%d\",\"text\":\"%d\"}]}",
				    here, k, i);
				http("PUT", path, body, &r);
				break;
			case 2:
				snprintf(path, sizeof(path), FLEET "%s/"
				    "arcana-jails:jails", here);
				http_abandon(path);
				continue;
			case 3:
				snprintf(path, sizeof(path), FLEET "%s/"
				    "arcana-jails:jails", flaky);
				http("GET", path, NULL, &r);
				break;
			default:
				/* A page following both, gone at once: the
				 * fleet's events, the socket's reads. */
				ws = console_socket();
				snprintf(ask, sizeof(ask), "GET /restconf/"
				    "streams/fleet/json HTTP/1.1\r\nHost: "
				    "localhost:8443\r\nCookie: %s\r\n\r\n",
				    cookie);
				(void)write(ws, ask, strlen(ask));
				usleep(1000 * (useconds_t)(i % 4) * 30);
				close(ws);
				ws = ws_open("/api/stream");
				snprintf(ask, sizeof(ask), "{\"id\":1,\"server\":"
				    "\"%s\",\"what\":\"restconf\",\"path\":"
				    "\"arcana-events:events\"}", here);
				ws_send(ws, ask);
				snprintf(ask, sizeof(ask), "{\"id\":2,\"server\":"
				    "\"%s\",\"what\":\"restconf\",\"path\":"
				    "\"arcana-events:events\"}", flaky);
				ws_send(ws, ask);
				snprintf(ask, sizeof(ask), "{\"id\":3,\"server\":"
				    "\"%s\",\"what\":\"sysctl\",\"filter\":"
				    "\"kern.\"}", here);
				ws_send(ws, ask);
				usleep(1000 * (useconds_t)(i % 4) * 30);
				close(ws);
				continue;
			}
			resp_free(&r);
		}
		_exit(0);
	}
	for (k = 0; k < 8; k++)
		ATF_REQUIRE(waitpid(pids[k], &status, 0) == pids[k]);
	/* The runs ended, the last of each label written. */
	for (i = 0; i < 300; i++) {
		http("GET", CC "runs", NULL, &r);
		k = strstr(r.body, "\"running\"") != NULL;
		resp_free(&r);
		if (!k)
			break;
		usleep(100000);
	}
	ATF_CHECK_MSG(i < 300, "runs still running");
	(void)kill(fake, SIGKILL);
	(void)waitpid(fake, NULL, 0);
	http("GET", "/api/health", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	if (system("grep -q 'Bad file descriptor' console.out") == 0)
		(void)system("grep -B2 -A2 'Bad file descriptor' console.out "
		    ">&2");
	ATF_CHECK(system("! grep -q 'Bad file descriptor' console.out") == 0);
	ATF_CHECK(system("! grep -Ei 'exited|signal|crash|fatal' "
	    "console.out") == 0);
}

/* Wait for run n to end; its entry of arcana-console's runs in r. */
static void
run_wait(const char *n, struct resp *r)
{
	char	path[96];
	int	i;

	snprintf(path, sizeof(path), CC "runs/run=%s", n);
	for (i = 0; i < 300; i++) {
		http("GET", path, NULL, r);
		if (r->status == 200 && resp_unwrap(r, "arcana-console:run.0") &&
		    jstr(r, "state") != NULL && strcmp(jstr(r, "state"),
		    "running") != 0)
			return;
		resp_free(r);
		usleep(100000);
	}
	ATF_REQUIRE_MSG(0, "run %s did not end", n);
}

/* A workflow's id made here, 8 hex digits, a new one each time. */
static void
r2_wid(char *wid, size_t len)
{
	static unsigned	next;

	snprintf(wid, len, "%08x", 0x0b0c0000u + ++next);
}

/*
 * A workflow added at arcana-console's workflows: members its entry's
 * members but the id, made here into wid; the answer in r.
 */
static void
r2_wf(const char *members, char *wid, size_t len, struct resp *r)
{
	char	*body;

	r2_wid(wid, len);
	ATF_REQUIRE(asprintf(&body, "{\"arcana-console:workflow\":[{\"id\":"
	    "\"%s\",%s}]}", wid, members) != -1);
	http("POST", CC "workflows", body, r);
	free(body);
}

/* The same, made: 201. */
static void
r2_wf_new(const char *members, char *wid, size_t len)
{
	struct resp	r;

	r2_wf(members, wid, len, &r);
	EXPECT(&r, 201);
	resp_free(&r);
}

/* Workflow wid run, input the members of the action's input (NULL:
 * none): the run's number into run. */
static void
r2_run(const char *wid, const char *input, char *run, size_t len)
{
	struct resp	r;
	char		path[128];

	snprintf(path, sizeof(path), CC "workflows/workflow=%s/run", wid);
	rc_act(path, input, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_MSG(jstr(&r, "run") != NULL, "%s", r.body);
	snprintf(run, len, "%s", jstr(&r, "run"));
	resp_free(&r);
}

/*
 * Each step's trace in a run's entry (r's JSON, as run_wait leaves it),
 * a JSON text, made the object it says, to be read below it.
 */
static void
r2_traces(struct resp *r)
{
	struct ucl_parser	*p;
	const ucl_object_t	*h, *s, *t;
	ucl_object_t		*o;
	ucl_object_iter_t	 hit, sit;

	hit = NULL;
	while ((h = ucl_object_iterate(ucl_object_lookup(r->json, "host"),
	    &hit, true)) != NULL) {
		sit = NULL;
		while ((s = ucl_object_iterate(ucl_object_lookup(h, "step"),
		    &sit, true)) != NULL) {
			if ((t = ucl_object_lookup(s, "trace")) == NULL ||
			    ucl_object_type(t) != UCL_STRING)
				continue;
			p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
			o = ucl_parser_add_string(p, ucl_object_tostring(t),
			    0) ? ucl_parser_get_object(p) : NULL;
			ucl_parser_free(p);
			if (o != NULL)
				ucl_object_replace_key(__DECONST(ucl_object_t *,
				    s), o, "trace", 0, true);
		}
	}
}

/* The event of the first run in a read of the runs (r) begun by
 * trigger, its JSON text; NULL, none. */
static const char *
r2_run_event(const struct resp *r, const char *trigger)
{
	char	k[96];
	int	i;

	for (i = 0; i < 64; i++) {
		snprintf(k, sizeof(k), "arcana-console:runs.run.%d.trigger", i);
		if (jstr(r, k) == NULL)
			return (NULL);
		if (strcmp(jstr(r, k), trigger) != 0)
			continue;
		snprintf(k, sizeof(k), "arcana-console:runs.run.%d.event", i);
		return (jstr(r, k));
	}
	return (NULL);
}

static void	cc_host(const char *, const char *, char *, size_t);

/* The workflows' console: host lab added, its id into sid. */
static void
wf_start(const atf_tc_t *tc, struct authn *a, char *sid, size_t len)
{

	start(tc, 0, NULL);
	enrol(a);
	cc_host("lab", "jgd.sock", sid, len);
}

CONSOLE_TC(workflows, "A workflow's steps checked against jobs.yaml, run on "
    "a host with its values, conditions and what follows a failure; its "
    "runs cleared")
ATF_TC_BODY(workflows, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[4096], sid[16], run[32], wid[16];
	char		path[128];
	int		i;

	wf_start(tc, &a, sid, sizeof(sid));

	/* What is not one, as jobs.yaml has the kinds. */
	static const char *const bad[][2] = {
		{ "{\"kind\":\"explode\"}", "one of jobs.yaml's" },
		{ "{\"kind\":\"service-action\",\"field\":[{\"name\":"
		    "\"service\",\"text\":\"sshd\"},{\"name\":\"action\","
		    "\"text\":\"start\"},{\"name\":\"bogus\",\"number\":"
		    "\"1\"}]}", "has no bogus" },
		{ "{\"kind\":\"service-action\",\"field\":[{\"name\":"
		    "\"service\",\"text\":\"sshd\"}]}", "needs action" },
		{ "{\"kind\":\"service-action\",\"field\":[{\"name\":"
		    "\"service\",\"text\":\"sshd\"},{\"name\":\"action\","
		    "\"text\":\"explode\"}]}", "one of start|stop" },
		/* A commit's warnings are a service's rc.conf change's. */
		{ "{\"kind\":\"jail-action\",\"field\":[{\"name\":\"jail\","
		    "\"text\":\"web\"},{\"name\":\"action\",\"text\":"
		    "\"start\"},{\"name\":\"accept\",\"json\":"
		    "\"[\\\"rc-conf-files\\\"]\"}]}", "has no accept" },
	};
	for (i = 0; i < (int)nitems(bad); i++) {
		snprintf(body, sizeof(body), "\"name\":\"bad\",\"host\":"
		    "[\"%s\"],\"step\":[{\"id\":\"a\",\"job\":%s}]", sid,
		    bad[i][0]);
		r2_wf(body, wid, sizeof(wid), &r);
		EXPECT(&r, 400);
		ATF_CHECK_MSG(strstr(r.body, bad[i][1]) != NULL, "%s", r.body);
		resp_free(&r);
	}
	/* What runs by itself and destroys says so. */
	snprintf(body, sizeof(body), "\"name\":\"bad\",\"host\":[\"%s\"],"
	    "\"every\":3600,\"step\":[{\"id\":\"a\",\"job\":{\"kind\":"
	    "\"if-destroy\",\"field\":[{\"name\":\"interface\",\"text\":"
	    "\"gif9\"}]}}]", sid);
	r2_wf(body, wid, sizeof(wid), &r);
	EXPECT(&r, 400);
	ATF_CHECK(strstr(r.body, "destructive") != NULL);
	resp_free(&r);
	r2_wf("\"name\":\"bad\",\"step\":[{\"id\":\"a\",\"read\":\"hello\","
	    "\"on-fail\":\"a\"}]", wid, sizeof(wid), &r);
	EXPECT(&r, 400);
	ATF_CHECK(strstr(r.body, "a step after it") != NULL);
	resp_free(&r);
	snprintf(body, sizeof(body), "\"name\":\"bad\",\"host\":[\"%s\"],"
	    "\"every\":30,\"step\":[{\"id\":\"a\",\"read\":\"hello\"}]", sid);
	r2_wf(body, wid, sizeof(wid), &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("GET", CC "workflows", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "arcana-console:workflows.workflow.0") == NULL,
	    "%s", r.body);
	resp_free(&r);

	/*
	 * A read, a job with a parameter when the read says so, one that
	 * fails and goes on further, one jumped over, a condition of a
	 * read made then, and one whose condition is not met.
	 */
	snprintf(body, sizeof(body), "\"name\":\"restart\",\"host\":[\"%s\"],"
	    "\"param\":[{\"name\":\"svc\",\"default\":\"ntpd\"}],\"step\":["
	    "{\"id\":\"r\",\"read\":\"hello\"},"
	    "{\"id\":\"a\",\"name\":\"Restart it\",\"job\":{\"kind\":"
	    "\"service-action\",\"field\":[{\"name\":\"service\",\"text\":"
	    "\"${param.svc}\"},{\"name\":\"action\",\"text\":\"restart\"}]},"
	    "\"when\":{\"step\":\"r\",\"path\":\"host.hostname\","
	    "\"op\":\"exists\"}},"
	    "{\"id\":\"b\",\"job\":{\"kind\":\"kmod\",\"field\":[{\"name\":"
	    "\"verb\",\"text\":\"load\"},{\"name\":\"args\",\"json\":"
	    "\"[\\\"../evil\\\"]\"}]},\"on-fail\":\"d\"},"
	    "{\"id\":\"c\",\"job\":{\"kind\":\"service-action\",\"field\":["
	    "{\"name\":\"service\",\"text\":\"ntpd\"},{\"name\":\"action\","
	    "\"text\":\"stop\"}]}},"
	    "{\"id\":\"d\",\"read\":\"services\",\"when\":{\"read\":\"jails\","
	    "\"path\":\"jails[name=web].state\",\"op\":\"eq\",\"value\":"
	    "\"stopped\"}},"
	    "{\"id\":\"e\",\"job\":{\"kind\":\"service-action\",\"field\":["
	    "{\"name\":\"service\",\"text\":\"${param.svc}\"},{\"name\":"
	    "\"action\",\"text\":\"stop\"}]},\"when\":{\"step\":\"r\","
	    "\"path\":\"host.hostname\",\"op\":\"eq\",\"value\":\"nope\"}}]",
	    sid);
	r2_wf_new(body, wid, sizeof(wid));
	snprintf(path, sizeof(path), CC "workflows/workflow=%s", wid);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r,
	    "arcana-console:workflow.0.step.1.destroys"));
	resp_free(&r);
	http("GET", CC "workflows", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("restart", jstr(&r,
	    "arcana-console:workflows.workflow.0.name"));
	resp_free(&r);
	r2_run(wid, "\"param\":[{\"name\":\"svc\",\"value\":\"sshd\"}]", run,
	    sizeof(run));
	run_wait(run, &r);
	r2_traces(&r);
	ATF_CHECK_STREQ("hand", jstr(&r, "trigger"));
	ATF_CHECK_STREQ("svc", jstr(&r, "param.0.name"));
	ATF_CHECK_STREQ("sshd", jstr(&r, "param.0.value"));
	ATF_CHECK_STREQ("done", jstr(&r, "host.0.step.0.state"));
	ATF_CHECK_STREQ("done", jstr(&r, "host.0.step.1.state"));
	ATF_CHECK_STREQ("service sshd restart", jstr(&r,
	    "host.0.step.1.title"));
	ATF_CHECK(jstr(&r, "host.0.step.1.trace.job.trace.0.label") != NULL);
	/* A job the console runs is in safe mode where the host can undo
	 * it; a restart it cannot, so that one was sent again without,
	 * and the step says so. */
	ATF_CHECK_STREQ("not in safe mode: the host cannot undo this one",
	    jstr(&r, "host.0.step.1.error"));
	ATF_CHECK_STREQ("failed", jstr(&r, "host.0.step.2.state"));
	ATF_CHECK_STREQ("not run", jstr(&r, "host.0.step.3.state"));
	ATF_CHECK_STREQ("done", jstr(&r, "host.0.step.4.state"));
	ATF_CHECK_STREQ("skipped", jstr(&r, "host.0.step.5.state"));
	ATF_CHECK_STREQ("failed", jstr(&r, "state"));
	resp_free(&r);
	/* Its traces are in the run's own file, not in the list. */
	snprintf(body, sizeof(body), "test -s data/runs/%s.json", run);
	ATF_CHECK(system(body) == 0);
	ATF_CHECK(system("grep -q 'sshd restart' service.log 2>/dev/null || "
	    "test -f running.sshd") == 0);
	/* The list has the runs, not their traces. */
	http("GET", CC "runs", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(run, jstr(&r, "arcana-console:runs.run.0.id"));
	ATF_CHECK(strstr(r.body, "\"trace\"") == NULL);
	ATF_CHECK(strstr(r.body, "\"state\":\"done\"") != NULL);
	resp_free(&r);

	/* The history cleared: another workflow's alone is none of
	 * these; all of it, every run that has ended, its traces too. */
	rc_act(CC "runs/clear", "\"workflow\":\"ffffffff\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("0", jstr(&r, "cleared"));
	resp_free(&r);
	rc_act(CC "runs/clear", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "cleared") != NULL && atoi(jstr(&r, "cleared"))
	    >= 1, "%s", r.body);
	resp_free(&r);
	snprintf(body, sizeof(body), "test ! -e data/runs/%s.json", run);
	ATF_CHECK(system(body) == 0);
	http("GET", CC "runs", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"state\":\"done\"") == NULL &&
	    strstr(r.body, "\"state\":\"failed\"") == NULL, "%s", r.body);
	resp_free(&r);
	/* Gone. */
	snprintf(path, sizeof(path), CC "workflows/workflow=%s", wid);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 409);
	ATF_CHECK_STREQ("data-missing", jstr(&r, ERROR_TAG));
	resp_free(&r);
}

CONSOLE_TC(workflows_arcana, "A workflow keeping Arcana up to date from its "
    "repository, a host that cannot take the agent named, and a run whose "
    "worker dies said to be interrupted")
ATF_TC_BODY(workflows_arcana, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[4096], sid[16], gone[16], run[32], wid[16];
	char		path[128];
	int		i;

	wf_start(tc, &a, sid, sizeof(sid));
	/*
	 * Arcana kept up to date from its repository: its head asked of
	 * the host, the agent built and sent to every host only when the
	 * head is newer, and the console updated through its host (by
	 * its local socket, as this one is: make install and the service
	 * restarted are stand-ins); a second run finds nothing new and
	 * builds nothing.
	 */
	http("PATCH", CC "settings", "{\"arcana-console:settings\":{"
	    "\"agent-source\":\"https://example.org/arcana.git\"}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	ATF_REQUIRE(system("echo 4444444444444444444444444444444444444444 > "
	    "head") == 0);
	snprintf(body, sizeof(body), "\"name\":\"arcana\",\"host\":[\"%s\"],"
	    "\"every\":3600,\"step\":["
	    "{\"id\":\"check\",\"arcana\":\"check\"},"
	    "{\"id\":\"build\",\"arcana\":\"build\",\"when\":{\"step\":"
	    "\"check\",\"path\":\"new\",\"op\":\"eq\",\"value\":\"true\"}},"
	    "{\"id\":\"agents\",\"arcana\":\"agents\",\"when\":{\"step\":"
	    "\"check\",\"path\":\"new_agents\",\"op\":\"eq\",\"value\":"
	    "\"true\"}},"
	    "{\"id\":\"console\",\"arcana\":\"console\",\"on-fail\":"
	    "\"continue\",\"when\":{\"step\":\"check\",\"path\":"
	    "\"new_console\",\"op\":\"eq\",\"value\":\"true\"}}]", sid);
	r2_wf_new(body, wid, sizeof(wid));
	/* None but check, build, agents and console. */
	r2_wf("\"name\":\"bad\",\"step\":[{\"id\":\"a\",\"arcana\":"
	    "\"explode\"}]", path, sizeof(path), &r);
	EXPECT(&r, 400);
	ATF_CHECK_MSG(strstr(r.body, "explode") != NULL, "%s", r.body);
	resp_free(&r);
	r2_run(wid, NULL, run, sizeof(run));
	run_wait(run, &r);
	r2_traces(&r);
	ATF_CHECK_STREQ("done", jstr(&r, "host.0.step.0.state"));
	ATF_CHECK_STREQ("4444444444444444444444444444444444444444", jstr(&r,
	    "host.0.step.0.trace.commit"));
	ATF_CHECK_STREQ("true", jstr(&r, "host.0.step.0.trace.new"));
	ATF_CHECK_STREQ("done", jstr(&r, "host.0.step.1.state"));
	ATF_CHECK_STREQ("4444444444444444444444444444444444444444", jstr(&r,
	    "host.0.step.1.trace.commit"));
	ATF_CHECK_STREQ("done", jstr(&r, "host.0.step.2.state"));
	ATF_CHECK_STREQ("lab", jstr(&r, "host.0.step.2.trace.hosts.0.host"));
	ATF_CHECK_STREQ("true", jstr(&r, "host.0.step.2.trace.hosts.0.ok"));
	ATF_CHECK_STREQ("done", jstr(&r, "host.0.step.3.state"));
	ATF_CHECK_STREQ("true", jstr(&r, "host.0.step.3.trace.restarting"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '\"built\": *\"4444' data/arcana-source.json "
	    "&& grep -q '\"agents\": *\"4444' data/arcana-source.json && "
	    "grep -q '\"updated\": *\"4444' data/arcana-source.json") == 0);
	/* Nothing newer: nothing built, nothing sent. */
	ATF_REQUIRE(system(": > git.log") == 0);
	r2_run(wid, NULL, run, sizeof(run));
	run_wait(run, &r);
	r2_traces(&r);
	ATF_CHECK_STREQ("false", jstr(&r, "host.0.step.0.trace.new_agents"));
	ATF_CHECK_STREQ("skipped", jstr(&r, "host.0.step.1.state"));
	ATF_CHECK_STREQ("skipped", jstr(&r, "host.0.step.2.state"));
	ATF_CHECK_STREQ("skipped", jstr(&r, "host.0.step.3.state"));
	resp_free(&r);
	ATF_CHECK(system("! grep -q clone git.log") == 0);
	/* A host that cannot take the agent is named, and why, in the
	 * step's error: a run's row says it. */
	host_add("gone", "unix:/nonexistent/arcana.sock", gone, sizeof(gone));
	ATF_REQUIRE(system("echo 5555555555555555555555555555555555555555 > "
	    "head") == 0);
	r2_run(wid, NULL, run, sizeof(run));
	run_wait(run, &r);
	ATF_CHECK_STREQ("failed", jstr(&r, "host.0.step.2.state"));
	ATF_CHECK_MSG(jstr(&r, "host.0.step.2.error") != NULL && strstr(jstr(
	    &r, "host.0.step.2.error"), "hosts did not take it (") != NULL &&
	    strstr(jstr(&r, "host.0.step.2.error"), "gone: the host did not "
	    "answer") != NULL && strstr(jstr(&r, "host.0.step.2.error"),
	    "gone: gone") == NULL, "%s", jstr(&r, "host.0.step.2.error"));
	resp_free(&r);
	/*
	 * A run whose worker dies under it: once one is there again, the
	 * run, its host and the step that was running are said to be
	 * interrupted, and why; the steps after it were not run.
	 */
	ATF_REQUIRE(system("touch slow") == 0);
	r2_run(wid, NULL, run, sizeof(run));
	sleep(2);
	ATF_REQUIRE(system("kill -9 $(sed -n 's/.*worker started (pid "
	    "\\([0-9]*\\)).*/\\1/p' console.out | tail -1)") == 0);
	(void)unlink("slow");
	snprintf(path, sizeof(path), CC "runs/run=%s", run);
	for (i = 0; i < 100; i++) {
		r.status = 0;
		http("GET", path, NULL, &r);
		if (r.status == 200 && resp_unwrap(&r,
		    "arcana-console:run.0") && jstr(&r, "state") != NULL &&
		    strcmp(jstr(&r, "state"), "interrupted") == 0)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_REQUIRE_MSG(i < 100, "the run was not said to be interrupted");
	ATF_CHECK_STREQ("interrupted", jstr(&r, "host.0.state"));
	ATF_CHECK_STREQ("interrupted", jstr(&r, "host.0.step.0.state"));
	ATF_CHECK(jstr(&r, "host.0.step.0.detail") != NULL && strstr(jstr(
	    &r, "host.0.step.0.detail"), "the console stopped") != NULL);
	ATF_CHECK_STREQ("not run", jstr(&r, "host.0.step.1.state"));
	resp_free(&r);
	/* What a run whose worker died is not, the console's end. */
	ATF_REQUIRE(system("sed -i '' '/exited with status/d' console.out") == 0);
}

CONSOLE_TC(workflows_every, "A workflow at an interval, counted from when "
    "it last ran, which a restart of the console does not forget")
ATF_TC_BODY(workflows_every, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[4096], sid[16], path[128], every[16];
	FILE		*fp;
	int		i;

	wf_start(tc, &a, sid, sizeof(sid));
	/*
	 * At an interval, counted from when it last ran by it, which a
	 * restart of the console does not forget: kept as having run 58 s
	 * before, a workflow of every minute runs within a tick or two of
	 * the console's start, not a minute after.
	 */
	snprintf(body, sizeof(body), "\"name\":\"each minute\",\"host\":"
	    "[\"%s\"],\"every\":60,\"step\":[{\"id\":\"s\",\"read\":"
	    "\"hello\"}]", sid);
	r2_wf_new(body, every, sizeof(every));
	ATF_REQUIRE((fp = fopen("data/every.json", "w")) != NULL);
	fprintf(fp, "{\"%s\": %lld}\n", every, (long long)time(NULL) - 58);
	fclose(fp);
	restart_console();
	for (i = 0; i < 150; i++) {
		http("GET", CC "runs", NULL, &r);
		if (r.body != NULL && strstr(r.body, "\"each minute\"") != NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_CHECK_MSG(i < 150, "the interval was counted from the restart");
	ATF_CHECK(i == 150 || strstr(r.body, "\"trigger\":\"every\"") != NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), CC "workflows/workflow=%s", every);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
}

/*
 * The host's sampling and limits (its history's) committed: a sample
 * each step seconds, keep of them, hold seconds over or under before
 * it is so; cpu, memory and swap the percentages.
 */
static void
r2_history(const char *sid, int step, int keep, int hold, int cpu, int mem,
    int swap)
{
	struct resp	r;
	char		path[256], body[512];

	snprintf(path, sizeof(path), "/restconf/ds/ietf-datastores:candidate/"
	    "arcana-fleet:fleet/host=%s/arcana-history:history", sid);
	snprintf(body, sizeof(body), "{\"arcana-history:history\":{"
	    "\"sampling\":{\"step\":%d,\"keep\":%d,\"hold\":%d},\"limits\":{"
	    "\"cpu\":%d,\"memory\":%d,\"swap\":%d}}}", step, keep, hold, cpu,
	    mem, swap);
	http("PATCH", path, body, &r);
	ATF_REQUIRE_MSG(r.status == 204 || r.status == 201, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), FLEET "%s/ietf-netconf:commit", sid);
	http("POST", path, "{}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
}

/* What SSE stream s says until want is in buf, for secs at most. */
static bool
r2_sse_until(int s, char *buf, size_t *len, size_t cap, const char *want,
    int secs)
{
	time_t	t0 = time(NULL);
	ssize_t	n;

	while (strstr(buf, want) == NULL && time(NULL) - t0 < secs &&
	    *len < cap - 1) {
		if ((n = read(s, buf + *len, cap - 1 - *len)) <= 0) {
			if (n == 0)
				break;
			continue;
		}
		*len += (size_t)n;
		buf[*len] = '\0';
	}
	return (strstr(buf, want) != NULL);
}

CONSOLE_TC(workflows_events, "Workflows begun by the host's events: a "
    "threshold crossed, a program that crashes, the host that stops "
    "answering")
ATF_TC_BODY(workflows_events, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[4096], sid[16], wid[16];
	const char	*ev;
	int		i;

	wf_start(tc, &a, sid, sizeof(sid));
	/* Begun by the host's events: a threshold crossed, then the host
	 * that stops answering. */
	snprintf(body, sizeof(body), "\"name\":\"on mem\",\"host\":[\"%s\"],"
	    "\"on\":[{\"index\":0,\"event\":\"threshold\",\"match\":[{"
	    "\"name\":\"what\",\"value\":\"mem\"},{\"name\":\"over\","
	    "\"value\":\"true\"}]}],\"step\":[{\"id\":\"s\",\"read\":"
	    "\"stats\"}]", sid);
	r2_wf_new(body, wid, sizeof(wid));
	snprintf(body, sizeof(body), "\"name\":\"on down\",\"host\":[\"%s\"],"
	    "\"on\":[{\"index\":0,\"event\":\"host-down\"}],\"step\":[{\"id\":"
	    "\"s\",\"read\":\"hello\"}]", sid);
	r2_wf_new(body, wid, sizeof(wid));
	/* A tick to learn where the events are; then the threshold. */
	sleep(7);
	r2_history(sid, 1, 10, 0, 90, 1, 90);
	/* The next tick's, which a busy host makes late. */
	for (i = 0; i < 400; i++) {
		http("GET", CC "runs", NULL, &r);
		if (r.body != NULL && strstr(r.body, "\"event threshold\"") !=
		    NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_CHECK_MSG(i < 400, "no run begun by the threshold");
	ev = r2_run_event(&r, "event threshold");
	ATF_CHECK_MSG(ev != NULL && strstr(ev, "\"what\":\"mem\"") != NULL,
	    "%s", r.body);
	resp_free(&r);
	/*
	 * A program that crashes (the kernel's line, kern.logsigexit):
	 * matched by a parameter's default, as the service-crash template
	 * does; the workflow waiting on another program is not begun.
	 */
	snprintf(body, sizeof(body), "\"name\":\"on crash\",\"host\":"
	    "[\"%s\"],\"param\":[{\"name\":\"process\",\"default\":"
	    "\"arccrash\"}],\"on\":[{\"index\":0,\"event\":\"crash\","
	    "\"match\":[{\"name\":\"process\",\"value\":\"${param.process}\"},"
	    "{\"name\":\"jid\",\"value\":\"0\"}]}],\"step\":[{\"id\":\"s\","
	    "\"read\":\"hello\"}]", sid);
	r2_wf_new(body, wid, sizeof(wid));
	snprintf(body, sizeof(body), "\"name\":\"on another crash\","
	    "\"host\":[\"%s\"],\"param\":[{\"name\":\"process\","
	    "\"default\":\"nginx\"}],\"on\":[{\"index\":0,\"event\":\"crash\","
	    "\"match\":[{\"name\":\"process\",\"value\":"
	    "\"${param.process}\"}]}],\"step\":[{\"id\":\"s\",\"read\":"
	    "\"hello\"}]", sid);
	r2_wf_new(body, wid, sizeof(wid));
	if (system("[ \"$(sysctl -n kern.logsigexit)\" = 1 ] && "
	    "[ \"$(sysctl -n security.bsd.unprivileged_read_msgbuf)\" = 1 ]")
	    == 0) {
		ATF_REQUIRE(system("cp /bin/sh arccrash && ./arccrash -c "
		    "'ulimit -c 0; kill -SEGV $$'; true") == 0);
		for (i = 0; i < 200; i++) {
			http("GET", CC "runs", NULL, &r);
			if (strstr(r.body, "\"event crash\"") != NULL)
				break;
			resp_free(&r);
			usleep(100000);
		}
		ATF_CHECK_MSG(i < 200, "no run begun by the crash");
		ev = r2_run_event(&r, "event crash");
		ATF_CHECK_MSG(ev != NULL && strstr(ev,
		    "\"process\":\"arccrash\"") != NULL, "%s", r.body);
		ATF_CHECK(strstr(r.body, "\"name\":\"on crash\"") != NULL);
		ATF_CHECK(strstr(r.body, "\"name\":\"on another crash\"") ==
		    NULL);
		resp_free(&r);
	}
	/*
	 * A page following the host's events when the agent goes, as an
	 * update restarts it: told, and the worker lives on (a timer was
	 * taken out in its own callback, and the worker died of it).
	 */
	{
		struct timeval	 tv = { 2, 0 };
		char		 rq[512], buf[16384];
		size_t		 len = 0;
		int		 s;

		s = console_socket();
		ATF_REQUIRE(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv,
		    sizeof(tv)) == 0);
		snprintf(rq, sizeof(rq), "GET /restconf/streams/%s/json "
		    "HTTP/1.1\r\nHost: localhost:8443\r\nCookie: %s\r\n\r\n",
		    sid, cookie);
		ATF_REQUIRE(write(s, rq, strlen(rq)) == (ssize_t)strlen(rq));
		buf[0] = '\0';
		ATF_CHECK_MSG(r2_sse_until(s, buf, &len, sizeof(buf),
		    "NETCONF stream", 10), "%s", buf);
		sleep(1);
		ATF_REQUIRE(system("kill $(cat arcana-agent.pid)") == 0);
		/* Events it told before it went, then why it is over. */
		ATF_CHECK_MSG(r2_sse_until(s, buf, &len, sizeof(buf),
		    "event: error", 10), "%s", buf);
		close(s);
		/* Its follow gone: the ticker runs on, with none. */
		sleep(1);
		ATF_CHECK(system("! grep -q 'exited with status' console.out") ==
		    0);
	}
	for (i = 0; i < 200; i++) {
		http("GET", CC "runs", NULL, &r);
		if (strstr(r.body, "\"event host-down\"") != NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	if (i == 200)
		(void)system("tail -20 console.out >&2");
	ATF_CHECK_MSG(i < 200, "no run begun by the host going away");
	/* Subscribed to, not asked every few seconds: a host that goes is
	 * known at once. */
	ATF_CHECK_MSG(i < 30, "host-down came after %d ms", i * 100);
	resp_free(&r);

	ATF_CHECK(system("! grep -q 'exited with status' console.out") == 0);
}

/* Wait for a step of a run's first host to reach a state; the run's
 * entry in r. */
static void
step_wait(const char *n, int k, const char *state, struct resp *r)
{
	char	path[96], key[64];
	int	i;

	snprintf(path, sizeof(path), CC "runs/run=%s", n);
	snprintf(key, sizeof(key), "host.0.step.%d.state", k);
	for (i = 0; i < 300; i++) {
		http("GET", path, NULL, r);
		if (r->status == 200 && resp_unwrap(r,
		    "arcana-console:run.0") && jstr(r, key) != NULL &&
		    strcmp(jstr(r, key), state) == 0)
			return;
		resp_free(r);
		usleep(100000);
	}
	ATF_REQUIRE_MSG(0, "run %s: step %d not %s", n, k, state);
}

CONSOLE_TC(workflow_approval, "A workflow waits at an approval step until "
    "someone approves it, the run is stopped or its time is out; serial, "
    "its hosts run one after the other and a failure leaves the rest not run")
ATF_TC_BODY(workflow_approval, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[2048], sid[16], gone[16], run[32];
	char		wid[16], path[128];

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("lab", "jgd.sock", sid, sizeof(sid));
	host_add("gone", "unix:/nonexistent/arcana.sock", gone, sizeof(gone));

	/* What an approval must say. */
	snprintf(body, sizeof(body), "\"name\":\"bad\",\"host\":[\"%s\"],"
	    "\"step\":[{\"id\":\"a\",\"approval\":{\"via\":\"all\"}}]", sid);
	r2_wf(body, wid, sizeof(wid), &r);
	EXPECT(&r, 400);
	ATF_CHECK_MSG(strstr(r.body, "text") != NULL, "%s", r.body);
	resp_free(&r);
	snprintf(body, sizeof(body), "\"name\":\"bad\",\"host\":[\"%s\"],"
	    "\"step\":[{\"id\":\"a\",\"approval\":{\"text\":\"go?\","
	    "\"timeout\":99999999}}]", sid);
	r2_wf(body, wid, sizeof(wid), &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(body, sizeof(body), "\"name\":\"bad\",\"host\":[\"%s\"],"
	    "\"step\":[{\"id\":\"a\",\"approval\":{\"text\":\"go?\"},"
	    "\"read\":\"hello\"}]", sid);
	r2_wf(body, wid, sizeof(wid), &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/*
	 * A read, an approval, a read: the run waits at the approval with
	 * its text expanded, an approval of a step that does not wait is
	 * refused, the step approved says by whom and the run goes on.
	 */
	snprintf(body, sizeof(body), "\"name\":\"gated\",\"host\":[\"%s\"],"
	    "\"step\":[{\"id\":\"r\",\"read\":\"hello\"},"
	    "{\"id\":\"ok\",\"name\":\"Go on?\",\"approval\":{\"text\":\"Go on "
	    "with ${host.name}?\"}},{\"id\":\"s\",\"read\":\"services\"}]",
	    sid);
	r2_wf_new(body, wid, sizeof(wid));
	snprintf(path, sizeof(path), CC "workflows/workflow=%s", wid);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "arcana-console:workflow.0.serial"));
	resp_free(&r);
	r2_run(wid, NULL, run, sizeof(run));
	step_wait(run, 1, "waiting", &r);
	ATF_CHECK_STREQ("running", jstr(&r, "state"));
	ATF_CHECK_STREQ("done", jstr(&r, "host.0.step.0.state"));
	ATF_CHECK_STREQ("Go on with lab?", jstr(&r, "host.0.step.1.title"));
	ATF_CHECK_STREQ("pending", jstr(&r, "host.0.step.2.state"));
	resp_free(&r);
	snprintf(path, sizeof(path), CC "runs/run=%s/approve", run);
	rc_act(path, "\"step\":\"s\"", &r);
	EXPECT(&r, 409);
	ATF_CHECK(strstr(r.body, "no step s waits") != NULL);
	resp_free(&r);
	rc_act(path, "", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	rc_act(path, "\"step\":\"ok\"", &r);
	ATF_CHECK_MSG(r.status == 200 || r.status == 204, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	run_wait(run, &r);
	r2_traces(&r);
	ATF_CHECK_STREQ("done", jstr(&r, "state"));
	ATF_CHECK_STREQ("done", jstr(&r, "host.0.step.1.state"));
	ATF_CHECK_STREQ("approved by admin", jstr(&r, "host.0.step.1.title"));
	ATF_CHECK_STREQ("admin", jstr(&r, "host.0.step.1.trace.approved_by"));
	ATF_CHECK_STREQ("ok", jstr(&r, "approved.0.step"));
	ATF_CHECK_STREQ("admin", jstr(&r, "approved.0.by"));
	ATF_CHECK_STREQ("done", jstr(&r, "host.0.step.2.state"));
	resp_free(&r);
	/* Ended, it takes no more approvals. */
	rc_act(path, "\"step\":\"ok\"", &r);
	EXPECT(&r, 409);
	resp_free(&r);

	/* Stopped while it waits: the step is cancelled, and the run. */
	r2_run(wid, NULL, run, sizeof(run));
	step_wait(run, 1, "waiting", &r);
	resp_free(&r);
	snprintf(path, sizeof(path), CC "runs/run=%s/stop", run);
	rc_act(path, NULL, &r);
	ATF_CHECK_MSG(r.status == 200 || r.status == 204, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	run_wait(run, &r);
	ATF_CHECK_STREQ("cancelled", jstr(&r, "state"));
	ATF_CHECK_STREQ("cancelled", jstr(&r, "host.0.step.1.state"));
	ATF_CHECK_STREQ("stopped while it waited", jstr(&r,
	    "host.0.step.1.error"));
	ATF_CHECK_STREQ("cancelled", jstr(&r, "host.0.step.2.state"));
	resp_free(&r);

	/* Its time out: the step fails, and what follows a failure follows
	 * (here, on at the last step). */
	snprintf(body, sizeof(body), "\"name\":\"timed\",\"host\":[\"%s\"],"
	    "\"step\":[{\"id\":\"ok\",\"approval\":{\"text\":\"go?\","
	    "\"timeout\":1},\"on-fail\":\"s\"},{\"id\":\"x\",\"read\":"
	    "\"hello\"},{\"id\":\"s\",\"read\":\"hello\"}]", sid);
	r2_wf_new(body, wid, sizeof(wid));
	r2_run(wid, NULL, run, sizeof(run));
	run_wait(run, &r);
	ATF_CHECK_STREQ("failed", jstr(&r, "state"));
	ATF_CHECK_STREQ("failed", jstr(&r, "host.0.step.0.state"));
	ATF_CHECK_STREQ("not approved within 1 s", jstr(&r,
	    "host.0.step.0.error"));
	ATF_CHECK_STREQ("not run", jstr(&r, "host.0.step.1.state"));
	ATF_CHECK_STREQ("done", jstr(&r, "host.0.step.2.state"));
	resp_free(&r);

	/*
	 * Serial: the hosts one after the other, in the workflow's order;
	 * the first fails (it is not there), so the second is not run.
	 * The same at once: both run, the second done.
	 */
	snprintf(body, sizeof(body), "\"name\":\"serial\",\"serial\":true,"
	    "\"host\":[\"%s\",\"%s\"],\"step\":[{\"id\":\"r\",\"read\":"
	    "\"hello\"}]", gone, sid);
	r2_wf_new(body, wid, sizeof(wid));
	snprintf(path, sizeof(path), CC "workflows/workflow=%s", wid);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "arcana-console:workflow.0.serial"));
	resp_free(&r);
	r2_run(wid, NULL, run, sizeof(run));
	run_wait(run, &r);
	ATF_CHECK_STREQ("failed", jstr(&r, "state"));
	ATF_CHECK_STREQ("gone", jstr(&r, "host.0.name"));
	ATF_CHECK_STREQ("failed", jstr(&r, "host.0.state"));
	ATF_CHECK_STREQ("not run", jstr(&r, "host.1.state"));
	ATF_CHECK_STREQ("not run", jstr(&r, "host.1.step.0.state"));
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"arcana-console:workflow\":[{\"id\":"
	    "\"%s\",\"name\":\"serial\",\"host\":[\"%s\",\"%s\"],\"step\":[{"
	    "\"id\":\"r\",\"read\":\"hello\"}]}]}", wid, gone, sid);
	http("PUT", path, body, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "arcana-console:workflow.0.serial"));
	resp_free(&r);
	r2_run(wid, NULL, run, sizeof(run));
	run_wait(run, &r);
	ATF_CHECK_STREQ("failed", jstr(&r, "host.0.state"));
	ATF_CHECK_STREQ("done", jstr(&r, "host.1.state"));
	resp_free(&r);
}

/*
 * A directory for the LDAP case: the slapd of a tree the configuration
 * names (slapd, slapd_lib for its libraries, slapd_etc for its schema),
 * on two ports of this test's own, with a CA and a certificate for
 * 127.0.0.1 made here; two users, one in the group.  Skipped without
 * it.  Its pid in slapd.pid, for the end of the case.
 */
static bool
slapd_start(const atf_tc_t *tc, int *portp, int *tlsportp)
{
	const char	*slapd, *lib, *etc;
	char		 cwd[MAXPATHLEN], cmd[8192];
	FILE		*fp;
	int		 port;

	if (!atf_tc_has_config_var(tc, "slapd"))
		return (false);
	slapd = atf_tc_get_config_var(tc, "slapd");
	lib = atf_tc_has_config_var(tc, "slapd_lib") ? atf_tc_get_config_var(tc,
	    "slapd_lib") : "/usr/local/lib";
	etc = atf_tc_has_config_var(tc, "slapd_etc") ? atf_tc_get_config_var(tc,
	    "slapd_etc") : "/usr/local/etc/openldap";
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	port = 20000 + (int)(getpid() % 20000);
	*portp = port;
	*tlsportp = port + 1;
	ATF_REQUIRE(system("openssl req -x509 -newkey ec -pkeyopt "
	    "ec_paramgen_curve:P-256 -nodes -keyout lca.key -out lca.pem -subj "
	    "'/CN=Arcana test LDAP CA' -days 2 >/dev/null 2>&1 && openssl req "
	    "-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout lsrv.key "
	    "-out lsrv.csr -subj '/CN=ldap.test' >/dev/null 2>&1 && printf "
	    "'subjectAltName=DNS:ldap.test,IP:127.0.0.1\\n' > lext && openssl "
	    "x509 -req -in lsrv.csr -CA lca.pem -CAkey lca.key -CAcreateserial "
	    "-out lsrv.pem -days 2 -extfile lext >/dev/null 2>&1") == 0);
	ATF_REQUIRE(mkdir("ldb", 0700) == 0);
	ATF_REQUIRE((fp = fopen("slapd.conf", "w")) != NULL);
	fprintf(fp, "include %s/schema/core.schema.sample\n"
	    "include %s/schema/cosine.schema.sample\n"
	    "include %s/schema/inetorgperson.schema.sample\n"
	    "include %s/schema/nis.schema.sample\n"
	    "pidfile %s/slapd.pid\nargsfile %s/slapd.args\n"
	    "modulepath %s/../libexec/openldap\nmoduleload back_mdb\n"
	    "TLSCACertificateFile %s/lca.pem\nTLSCertificateFile %s/lsrv.pem\n"
	    "TLSCertificateKeyFile %s/lsrv.key\n"
	    "database mdb\nmaxsize 67108864\nsuffix \"dc=lab,dc=test\"\n"
	    "rootdn \"cn=admin,dc=lab,dc=test\"\nrootpw labadmin\n"
	    "directory %s/ldb\nindex objectClass eq\n"
	    "access to attrs=userPassword by self write by anonymous auth by * "
	    "none\naccess to * by dn.exact=\"cn=reader,dc=lab,dc=test\" read by "
	    "users read by anonymous read\n", etc, etc, etc, etc, cwd, cwd, lib,
	    cwd, cwd, cwd, cwd);
	fclose(fp);
	ATF_REQUIRE((fp = fopen("base.ldif", "w")) != NULL);
	fputs("dn: dc=lab,dc=test\nobjectClass: dcObject\nobjectClass: "
	    "organization\ndc: lab\no: Lab\n\n"
	    "dn: cn=reader,dc=lab,dc=test\nobjectClass: organizationalRole\n"
	    "objectClass: simpleSecurityObject\ncn: reader\nuserPassword: "
	    "readerpw\n\n"
	    "dn: ou=people,dc=lab,dc=test\nobjectClass: organizationalUnit\n"
	    "ou: people\n\n"
	    "dn: uid=alice,ou=people,dc=lab,dc=test\nobjectClass: "
	    "inetOrgPerson\nuid: alice\ncn: Alice Lab\nsn: Lab\nuserPassword: "
	    "alicepw\n\n"
	    "dn: uid=bob,ou=people,dc=lab,dc=test\nobjectClass: inetOrgPerson\n"
	    "uid: bob\ncn: Bob Lab\nsn: Lab\nuserPassword: bobpw\n\n"
	    "dn: ou=groups,dc=lab,dc=test\nobjectClass: organizationalUnit\n"
	    "ou: groups\n\n"
	    "dn: cn=arcana,ou=groups,dc=lab,dc=test\nobjectClass: groupOfNames\n"
	    "cn: arcana\nmember: uid=alice,ou=people,dc=lab,dc=test\n\n"
	    "dn: cn=noc,ou=groups,dc=lab,dc=test\nobjectClass: groupOfNames\n"
	    "cn: noc\nmember: uid=alice,ou=people,dc=lab,dc=test\n", fp);
	fclose(fp);
	snprintf(cmd, sizeof(cmd), "LD_LIBRARY_PATH=%s %s/../sbin/slapadd -f "
	    "slapd.conf -l base.ldif >slapadd.out 2>&1 && LD_LIBRARY_PATH=%s %s "
	    "-f slapd.conf -h 'ldap://127.0.0.1:%d/ ldaps://127.0.0.1:%d/' "
	    ">slapd.out 2>&1", lib, lib, lib, slapd, port, port + 1);
	ATF_REQUIRE_MSG(system(cmd) == 0, "slapd did not start: %s", cmd);
	usleep(500000);
	return (true);
}

static void
slapd_stop(void)
{

	(void)system("[ -f slapd.pid ] && kill $(cat slapd.pid) 2>/dev/null; "
	    "true");
}

/* arcana-console's settings patched with members (YANG's names and
 * values); the answer in r. */
static void
r2_settings(const char *members, struct resp *r)
{
	char	*body;

	ATF_REQUIRE(asprintf(&body, "{\"arcana-console:settings\":{%s}}",
	    members) != -1);
	http("PATCH", CC "settings", body, r);
	free(body);
}

CONSOLE_TC(password, "A password of the console's own: set from a key's "
    "session, said as set but never its hash, kept through an edit; a "
    "sign-in with it limited as a token's under password_full = false; a "
    "wrong one, an unknown user, a short one refused; another's the "
    "owner's alone to set; taken away, the sessions it opened end; too "
    "many failures throttled")
ATF_TC_BODY(password, tc)
{
	struct authn	a, b;
	struct resp	r;
	char		keycookie[160], pwcookie[160], invite[80];
	int		i, k;

	/* The limits of a password's session, which web.conf asks for. */
	snprintf(harness_webconf, sizeof(harness_webconf), "password_full = "
	    "false;\n");
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(keycookie, sizeof(keycookie), "%s", cookie);
	/* None yet: the page offers none, and none signs in. */
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("false", jstr(&r, "password"));
	resp_free(&r);
	cookie[0] = '\0';
	http("POST", "/api/auth/login/password", "{\"user\":\"admin\","
	    "\"password\":\"correct horse battery\"}", &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* Not without a session. */
	http("POST", "/api/auth/password", "{\"password\":\"correct horse "
	    "battery\"}", &r);
	EXPECT(&r, 401);
	resp_free(&r);
	snprintf(cookie, sizeof(cookie), "%s", keycookie);
	/* Too short, a control character; then the session's own. */
	http("POST", "/api/auth/password", "{\"password\":\"short one\"}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "12 characters") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	http("POST", "/api/auth/password", "{\"password\":\"correct\\thorse "
	    "battery\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", "/api/auth/password", "{\"password\":\"correct horse "
	    "battery\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("admin", jstr(&r, "user"));
	ATF_CHECK_STREQ("true", jstr(&r, "password"));
	resp_free(&r);
	/* Said as set; its hash never, nor kept anywhere but users.json. */
	http("GET", CC "users/user=admin", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "arcana-console:user.0.has-password"));
	ATF_CHECK_MSG(strstr(r.body, "$2b$") == NULL, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q '\"password\": *\"\\$2b\\$12\\$' "
	    "data/users.json") == 0);
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "password"));
	resp_free(&r);
	/* Bob, a viewer: the owner sets his, and an edit keeps it. */
	http("PUT", CC "users/user=bob", "{\"arcana-console:user\":[{"
	    "\"name\":\"bob\",\"role\":[\"viewer\"]}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("POST", "/api/auth/password", "{\"user\":\"bob\",\"password\":"
	    "\"bob's own long password\"}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("PUT", CC "users/user=bob", "{\"arcana-console:user\":[{"
	    "\"name\":\"bob\",\"role\":[\"viewer\",\"operator\"]}]}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "users/user=bob", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "arcana-console:user.0.has-password"));
	resp_free(&r);
	http("POST", "/api/auth/password", "{\"user\":\"nosuch\",\"password\":"
	    "\"a long enough one\"}", &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* Signed in by it: a wrong one and an unknown user alike refused,
	 * then bob, limited as a token's session is. */
	cookie[0] = '\0';
	http("POST", "/api/auth/login/password", "{\"user\":\"bob\","
	    "\"password\":\"not his password\"}", &r);
	ATF_CHECK_MSG(r.status == 401 && strstr(r.body, "not right") != NULL,
	    "%s", r.body);
	resp_free(&r);
	http("POST", "/api/auth/login/password", "{\"user\":\"nobody\","
	    "\"password\":\"bob's own long password\"}", &r);
	ATF_CHECK_MSG(r.status == 401 && strstr(r.body, "not right") != NULL,
	    "%s", r.body);
	resp_free(&r);
	ATF_CHECK(cookie[0] == '\0');
	http("POST", "/api/auth/login/password", "{\"user\":\"bob\","
	    "\"password\":\"bob's own long password\"}", &r);
	ATF_CHECK_MSG(r.status == 200, "%s", r.body);
	ATF_CHECK_STREQ("bob", jstr(&r, "user"));
	ATF_CHECK_STREQ("true", jstr(&r, "by_password"));
	ATF_CHECK_STREQ("true", jstr(&r, "by_token"));
	resp_free(&r);
	ATF_CHECK(cookie[0] != '\0');
	snprintf(pwcookie, sizeof(pwcookie), "%s", cookie);
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "by_password"));
	resp_free(&r);
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* Nor its own password, nor the keys, users or settings. */
	http("POST", "/api/auth/password", "{\"password\":\"a new long "
	    "password\"}", &r);
	ATF_CHECK_MSG(r.status == 403, "%s", r.body);
	resp_free(&r);
	http("GET", CC "credentials", NULL, &r);
	ATF_CHECK_MSG(r.status == 403, "%s", r.body);
	resp_free(&r);
	http("PUT", CC "users/user=bob", "{\"arcana-console:user\":[{"
	    "\"name\":\"bob\",\"role\":[\"owner\"]}]}", &r);
	ATF_CHECK_MSG(r.status == 403, "%s", r.body);
	resp_free(&r);
	/* Bob with a key of his own sets his, not the owner's. */
	snprintf(cookie, sizeof(cookie), "%s", keycookie);
	http("POST", CC "users/user=bob/invite", NULL, &r);
	EXPECT(&r, 200);
	snprintf(invite, sizeof(invite), "%s", jstr(&r,
	    "arcana-console:output.token"));
	resp_free(&r);
	cookie[0] = '\0';
	authn_new(&b, -8);
	do_register(&b, invite, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/auth/password", "{\"user\":\"admin\",\"password\":"
	    "\"taken over now\"}", &r);
	ATF_CHECK_MSG(r.status == 403, "%s", r.body);
	resp_free(&r);
	/* Taken away by the owner: the session it opened ends. */
	snprintf(cookie, sizeof(cookie), "%s", keycookie);
	http("POST", "/api/auth/password", "{\"user\":\"bob\",\"password\":"
	    "\"\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "password"));
	resp_free(&r);
	snprintf(cookie, sizeof(cookie), "%s", pwcookie);
	for (i = 0; i < 50; i++) {
		http("GET", CC "hosts", NULL, &r);
		if (r.status == 401)
			break;
		resp_free(&r);
		usleep(100000);
	}
	EXPECT(&r, 401);
	resp_free(&r);
	/* Throttled: five failures in a minute (counted again should one
	 * begin on the way), then a wait, even for the right password. */
	cookie[0] = '\0';
	for (i = 0; i < 12; i++) {
		http("POST", "/api/auth/login/password", "{\"user\":\"admin\","
		    "\"password\":\"not the password\"}", &r);
		k = r.status;
		resp_free(&r);
		if (k == 429)
			break;
	}
	http("POST", "/api/auth/login/password", "{\"user\":\"admin\","
	    "\"password\":\"correct horse battery\"}", &r);
	ATF_CHECK_MSG(r.status == 429, "%d %s", r.status, r.body);
	resp_free(&r);
}

CONSOLE_TC(ldap, "Sign-in by LDAP over TLS: the user looked up and bound "
    "as, a group's members alone, a role by a directory group, a session "
    "limited as a token's without one; a wrong "
    "password, an unknown user, an empty password and an outsider refused; "
    "too many failures throttled; StartTLS on ldap://, ldaps:// too")
ATF_TC_BODY(ldap, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[MAXPATHLEN], body[2048], keycookie[160];
	int		port, tlsport, i;

	start(tc, 0, NULL);
	if (!slapd_start(tc, &port, &tlsport))
		atf_tc_skip("no slapd: give slapd, slapd_lib and slapd_etc");
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	/* Not set up: said so, and the status offers no directory. */
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("false", jstr(&r, "ldap"));
	resp_free(&r);
	http("POST", "/api/auth/login/password", "{\"user\":\"alice\",\"password\":"
	    "\"alicepw\"}", &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* A URL that is not one, refused; then the directory, by StartTLS,
	 * its CA from the file here, the reader and the group. */
	r2_settings("\"ldap-url\":\"http://x\"", &r);
	ATF_CHECK_MSG(r.status == 400, "%s", r.body);
	resp_free(&r);
	snprintf(body, sizeof(body), "\"ldap-url\":\"ldap://127.0.0.1:%d\","
	    "\"ldap-ca\":\"%s/lca.pem\",\"ldap-base\":\"ou=people,dc=lab,"
	    "dc=test\",\"ldap-user-attr\":\"uid\",\"ldap-group\":\"cn=arcana,"
	    "ou=groups,dc=lab,dc=test\",\"ldap-bind-dn\":\"cn=reader,dc=lab,"
	    "dc=test\",\"ldap-bind-password\":\"readerpw\"", port, cwd);
	r2_settings(body, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "ldap"));
	resp_free(&r);
	/* A role given by a directory group: noc, alice's. */
	http("PUT", CC "roles/role=noc", "{\"arcana-console:role\":[{\"name\":"
	    "\"noc\",\"console\":\"member\",\"host\":[{\"id\":\"*\",\"role\":"
	    "\"viewer\"}],\"ldap-group\":\"cn=noc,ou=groups,dc=lab,"
	    "dc=test\"}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", CC "roles/role=noc", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("cn=noc,ou=groups,dc=lab,dc=test", jstr(&r,
	    "arcana-console:role.0.ldap-group"));
	resp_free(&r);
	http("PUT", CC "roles/role=bad", "{\"arcana-console:role\":[{\"name\":"
	    "\"bad\",\"ldap-group\":\"no dn here\"}]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* The key's session kept aside: the sign-ins open their own. */
	snprintf(keycookie, sizeof(keycookie), "%s", cookie);
	cookie[0] = '\0';
	http("POST", "/api/auth/login/password", "{\"user\":\"alice\",\"password\":"
	    "\"\"}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "anonymous") != NULL,
	    "%s", r.body);
	resp_free(&r);
	http("POST", "/api/auth/login/password", "{\"user\":\"alice\",\"password\":"
	    "\"wrong\"}", &r);
	ATF_CHECK_MSG(r.status == 401 && strstr(r.body, "wrong password") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	http("POST", "/api/auth/login/password", "{\"user\":\"nobody\",\"password\":"
	    "\"x\"}", &r);
	ATF_CHECK_MSG(r.status == 401 && strstr(r.body, "no such user") != NULL,
	    "%s", r.body);
	resp_free(&r);
	/* Bob is a user, but not of the group. */
	http("POST", "/api/auth/login/password", "{\"user\":\"bob\",\"password\":"
	    "\"bobpw\"}", &r);
	ATF_CHECK_MSG(r.status == 401 && strstr(r.body, "not a member") != NULL,
	    "%s", r.body);
	resp_free(&r);
	ATF_CHECK(cookie[0] == '\0');
	/* Alice: in, said to be by LDAP, and the user alice the console
	 * made for her, with the role of her group noc: a member of the
	 * console, a viewer of the hosts. */
	http("POST", "/api/auth/login/password", "{\"user\":\"alice\",\"password\":"
	    "\"alicepw\"}", &r);
	ATF_CHECK_MSG(r.status == 200, "%s", r.body);
	ATF_CHECK_STREQ("true", jstr(&r, "authenticated"));
	ATF_CHECK_STREQ("true", jstr(&r, "by_ldap"));
	ATF_CHECK_STREQ("alice", jstr(&r, "user"));
	ATF_CHECK_STREQ("member", jstr(&r, "console"));
	resp_free(&r);
	ATF_CHECK(cookie[0] != '\0');
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "authenticated"));
	ATF_CHECK_STREQ("true", jstr(&r, "by_ldap"));
	resp_free(&r);
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", CC "settings", NULL, &r);
	ATF_CHECK_MSG(r.status == 403, "%s", r.body);
	resp_free(&r);
	http("GET", CC "credentials", NULL, &r);
	ATF_CHECK_MSG(r.status == 403, "%s", r.body);
	resp_free(&r);
	http("POST", "/api/auth/logout", "{}", &r);
	resp_free(&r);
	cookie[0] = '\0';
	/* Throttled: after the failures above and two more, a minute's
	 * wait, even for the right password. */
	for (i = 0; i < 3; i++) {
		http("POST", "/api/auth/login/password", "{\"user\":\"alice\","
		    "\"password\":\"wrong\"}", &r);
		resp_free(&r);
	}
	http("POST", "/api/auth/login/password", "{\"user\":\"alice\",\"password\":"
	    "\"alicepw\"}", &r);
	ATF_CHECK_MSG(r.status == 429, "%d %s", r.status, r.body);
	resp_free(&r);
	/* ldaps://, no group, anonymous lookup: bob is in. The throttle
	 * is the worker's minute: the console restarted for it. */
	snprintf(cookie, sizeof(cookie), "%s", keycookie);
	snprintf(body, sizeof(body), "\"ldap-url\":\"ldaps://127.0.0.1:%d\","
	    "\"ldap-group\":\"\",\"ldap-bind-dn\":\"\",\"ldap-bind-password\":"
	    "\"\"", tlsport);
	r2_settings(body, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	restart_console();
	cookie[0] = '\0';
	http("POST", "/api/auth/login/password", "{\"user\":\"bob\",\"password\":"
	    "\"bobpw\"}", &r);
	ATF_CHECK_MSG(r.status == 200, "%d %s", r.status, r.body);
	/* No group of his gives a role: no user is made for him, and the
	 * session is limited as before. */
	ATF_CHECK(jstr(&r, "user") == NULL);
	resp_free(&r);
	/* Alice's user is the directory's, its role her group's (the
	 * page's chip); bob has none. */
	snprintf(cookie, sizeof(cookie), "%s", keycookie);
	http("GET", CC "users/user=alice", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r,
	    "arcana-console:user.0.from-directory"));
	ATF_CHECK_STREQ("noc", jstr(&r, "arcana-console:user.0.role.0"));
	ATF_CHECK(jstr(&r, "arcana-console:user.0.role.1") == NULL);
	resp_free(&r);
	http("GET", CC "users", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"bob\"") == NULL, "%s", r.body);
	resp_free(&r);
	cookie[0] = '\0';
	/* A directory whose certificate is not trusted: refused. */
	snprintf(cookie, sizeof(cookie), "%s", keycookie);
	r2_settings("\"ldap-ca\":\"\"", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	cookie[0] = '\0';
	http("POST", "/api/auth/login/password", "{\"user\":\"bob\",\"password\":"
	    "\"bobpw\"}", &r);
	ATF_CHECK_MSG(r.status == 401 && strstr(r.body, "TLS") != NULL, "%d %s",
	    r.status, r.body);
	resp_free(&r);
	slapd_stop();
}

CONSOLE_TC(labels, "Labels on interfaces: the console's own tags, kept by "
    "server and interface; set, changed, taken away; a bad one refused; "
    "read by a token, not written by a read one")
ATF_TC_BODY(labels, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[400], sid[16], path[160], text[200];

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("a", "jgd.sock", sid, sizeof(sid));
	http("GET", CC "labels", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "arcana-console:labels.label.0") == NULL, "%s",
	    r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), CC "labels/label=%s,vtnet0", sid);
	snprintf(text, sizeof(text), "%s/text", path);
	snprintf(body, sizeof(body), "{\"arcana-console:label\":[{\"host\":"
	    "\"%s\",\"interface\":\"vtnet0\",\"text\":\"uplink A, to the "
	    "IXP\"}]}", sid);
	http("PUT", path, body, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("uplink A, to the IXP", jstr(&r,
	    "arcana-console:label.0.text"));
	resp_free(&r);
	http("PUT", text, "{\"arcana-console:text\":\"a\\tb\"}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "no control") != NULL,
	    "%s", r.body);
	resp_free(&r);
	http("PUT", CC "labels/label=zz,x", "{\"arcana-console:label\":[{"
	    "\"host\":\"zz\",\"interface\":\"x\",\"text\":\"x\"}]}", &r);
	ATF_CHECK_MSG(r.status == 400 || r.status == 404, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	http("PUT", text, "{\"arcana-console:text\":\"uplink B\"}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", text, NULL, &r);
	ATF_CHECK_STREQ("uplink B", jstr(&r, "arcana-console:text"));
	resp_free(&r);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "labels", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "arcana-console:labels.label.0") == NULL, "%s",
	    r.body);
	resp_free(&r);
}

#define	PFX	CC "prefix-lists/prefix-list=branches"

CONSOLE_TC(pfxlists, "The console's prefix lists: kept by name, each a "
    "description and prefixes checked as such; changed, taken away; a bad "
    "prefix or name refused")
ATF_TC_BODY(pfxlists, tc)
{
	struct authn	a;
	struct resp	r;

	start(tc, 0, NULL);
	enrol(&a);
	http("GET", CC "prefix-lists", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "arcana-console:prefix-lists.prefix-list.0") ==
	    NULL, "%s", r.body);
	resp_free(&r);
	http("PUT", PFX, "{\"arcana-console:prefix-list\":[{\"name\":"
	    "\"branches\",\"description\":\"the branches' networks\","
	    "\"prefix\":[\"10.1.8.0/22\",\"2001:db8:9::/48\"]}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", PFX, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("the branches' networks", jstr(&r,
	    "arcana-console:prefix-list.0.description"));
	ATF_CHECK_STREQ("2001:db8:9::/48", jstr(&r,
	    "arcana-console:prefix-list.0.prefix.1"));
	resp_free(&r);
	http("PUT", PFX, "{\"arcana-console:prefix-list\":[{\"name\":"
	    "\"branches\",\"prefix\":[\"10.1.8.1/22\"]}]}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "no host bits") != NULL,
	    "%s", r.body);
	resp_free(&r);
	http("PUT", CC "prefix-lists/prefix-list=bad%20name", "{\"arcana-"
	    "console:prefix-list\":[{\"name\":\"bad name\",\"prefix\":[]}]}",
	    &r);
	ATF_CHECK_MSG(r.status == 400 || r.status == 404, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	http("PUT", PFX, "{\"arcana-console:prefix-list\":[{\"name\":"
	    "\"branches\",\"prefix\":[\"10.1.8.0/22\"]}]}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", PFX, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("10.1.8.0/22", jstr(&r,
	    "arcana-console:prefix-list.0.prefix.0"));
	ATF_CHECK(jstr(&r, "arcana-console:prefix-list.0.prefix.1") == NULL);
	ATF_CHECK(jstr(&r, "arcana-console:prefix-list.0.description") ==
	    NULL);
	resp_free(&r);
	http("DELETE", PFX, NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "prefix-lists", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "arcana-console:prefix-lists.prefix-list.0") ==
	    NULL, "%s", r.body);
	resp_free(&r);
}
#undef	PFX

CONSOLE_TC(templates, "Configuration templates: a host's setup kept by "
    "name, its values {{placeholders}}, checked; applied to a host with its "
    "own values, checked first, then written; one without a value refused")
ATF_TC_BODY(templates, tc)
{
	struct authn	a;
	struct resp	r;
	char		base[128], sid[16];

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("here", "jgd.sock", sid, sizeof(sid));
	snprintf(base, sizeof(base), CC "hosts/host=%s/apply-configuration",
	    sid);

	http("GET", CC "templates", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "arcana-console:templates.template.0") == NULL,
	    "%s", r.body);
	resp_free(&r);
	/* Not kept: a secret (a template has no way to say one), a path
	 * that climbs, a bad name. */
	http("PUT", CC "templates/template=edge", "{\"arcana-console:"
	    "template\":[{\"name\":\"edge\",\"file\":[{\"path\":"
	    "\"/usr/local/etc/wireguard/wg0.conf\",\"mode\":\"0600\",\"owner\":"
	    "\"root\",\"group\":\"wheel\",\"secret\":true}]}]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("PUT", CC "templates/template=edge", "{\"arcana-console:"
	    "template\":[{\"name\":\"edge\",\"file\":[{\"path\":\"/etc/../"
	    "root/x\",\"mode\":\"0644\",\"owner\":\"root\",\"group\":\"wheel\","
	    "\"text\":\"\"}]}]}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "without ..") != NULL,
	    "%s", r.body);
	resp_free(&r);
	http("PUT", CC "templates/template=bad%20name", "{\"arcana-console:"
	    "template\":[{\"name\":\"bad name\"}]}", &r);
	ATF_CHECK_MSG(r.status == 400 || r.status == 404, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	/* Kept: rc.conf with the host's name and address its values, the
	 * address with a default. */
	http("PUT", CC "templates/template=edge", "{\"arcana-console:"
	    "template\":[{\"name\":\"edge\",\"description\":\"an edge\","
	    "\"file\":[{\"path\":\"/etc/rc.conf\",\"mode\":\"0644\",\"owner\":"
	    "\"root\",\"group\":\"wheel\",\"text\":\"hostname=\\\"{{hostname}}"
	    "\\\"\\nifconfig_lo1=\\\"inet {{address}}/32\\\"\\n# a ${shell} "
	    "word, as it is\\n\"}],\"package\":[{\"name\":\"bird3\"}],"
	    "\"variable\":[{\"name\":\"address\",\"description\":\"its "
	    "loopback\",\"default\":\"192.0.2.10\"}]}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", CC "templates", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("edge", jstr(&r,
	    "arcana-console:templates.template.0.name"));
	ATF_CHECK_STREQ("an edge", jstr(&r,
	    "arcana-console:templates.template.0.description"));
	ATF_CHECK_STREQ("/etc/rc.conf", jstr(&r,
	    "arcana-console:templates.template.0.file.0.path"));
	ATF_CHECK(jstr(&r, "arcana-console:templates.template.0.file.1") ==
	    NULL);
	ATF_CHECK_STREQ("hostname", jstr(&r,
	    "arcana-console:templates.template.0.placeholder.0"));
	ATF_CHECK_STREQ("address", jstr(&r,
	    "arcana-console:templates.template.0.placeholder.1"));
	resp_free(&r);
	/* Applied without a hostname: refused, nothing asked of the host. */
	rc_act(base, "\"template\":\"edge\",\"dry-run\":true", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "{{hostname}} has no "
	    "value") != NULL, "%s", r.body);
	resp_free(&r);
	rc_act(base, "\"template\":\"nosuch\",\"dry-run\":true", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "no template nosuch")
	    != NULL, "%s", r.body);
	resp_free(&r);
	/* Checked: what rc.conf would become, the default address in it,
	 * the shell's own ${} left alone, the package told. */
	rc_act(base, "\"template\":\"edge\",\"values\":{\"hostname\":"
	    "\"edge7\"},\"dry-run\":true", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_MSG(strstr(r.body, "\"path\":\"/etc/rc.conf\",\"state\":"
	    "\"changed\"") != NULL && strstr(r.body, "+hostname=\\\"edge7\\\"")
	    != NULL && strstr(r.body, "+ifconfig_lo1=\\\"inet 192.0.2.10/32"
	    "\\\"") != NULL && strstr(r.body, "${shell}") != NULL, "%.600s",
	    r.body);
	ATF_CHECK(strstr(r.body, "bird3") != NULL);
	resp_free(&r);
	ATF_CHECK(system("! grep -q edge7 root/etc/rc.conf") == 0);
	/* Applied: written, the file before kept. */
	rc_act(base, "\"template\":\"edge\",\"values\":{\"hostname\":"
	    "\"edge7\",\"address\":\"192.0.2.77\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "data.applied"));
	resp_free(&r);
	ATF_CHECK(system("grep -q 'hostname=\"edge7\"' root/etc/rc.conf && "
	    "grep -q 'inet 192.0.2.77/32' root/etc/rc.conf") == 0);
	/* Forgotten. */
	http("DELETE", CC "templates/template=edge", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "templates/template=edge", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
}

CONSOLE_TC(config_bundle, "A host as a bundle, its secrets only when "
    "asked; another host's bundle applied here by the console, checked "
    "first, the files before kept")
ATF_TC_BODY(config_bundle, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[MAXPATHLEN], base[128], apply[160], sid[16];
	char		*bundle, *at;

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("here", "jgd.sock", sid, sizeof(sid));
	snprintf(base, sizeof(base), CC "hosts/host=%s", sid);
	snprintf(apply, sizeof(apply), "%s/apply-configuration", base);

	/* Read: the bundle, the test's tree its files (--root). */
	snprintf(body, sizeof(body), "%s/configuration", base);
	http("GET", body, NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(resp_unwrap(&r, "arcana-console:configuration"));
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("host", jstr(&r, "data.arcana"));
	ATF_CHECK(strstr(r.body, "\"path\":\"/etc/hosts\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"trace\":[") != NULL);
	resp_free(&r);
	snprintf(body, sizeof(body), "%s/export-configuration", base);
	rc_act(body, "\"secrets\":true", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	/* The bundle as it is sent back, to be given again changed. */
	bundle = (char *)ucl_object_emit(ucl_object_lookup(r.json, "data"),
	    UCL_EMIT_JSON_COMPACT);
	ATF_REQUIRE(bundle != NULL);
	resp_free(&r);
	ATF_REQUIRE((at = strstr(bundle, "127.0.0.1 localhost\\n")) != NULL);

	/* Another host's, read by the console itself: here it is this
	 * one, and nothing would change. */
	snprintf(body, sizeof(body), "\"from\":\"%s\",\"dry-run\":true", sid);
	rc_act(apply, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK(strstr(r.body, "\"state\":\"changed\"") == NULL);
	ATF_CHECK(strstr(r.body, "\"state\":\"same\"") != NULL);
	resp_free(&r);
	rc_act(apply, "\"from\":\"ffffffff\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	rc_act(apply, "\"dry-run\":true", &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/* A bundle given: checked, then applied; the file before kept. */
	{
		char	*mod, *req;
		size_t	 n = strlen(bundle) + 64;

		mod = malloc(n);
		snprintf(mod, n, "%.*s127.0.0.1 localhost\\n192.0.2.7 db\\n%s",
		    (int)(at - bundle), bundle, at + strlen(
		    "127.0.0.1 localhost\\n"));
		ATF_REQUIRE(asprintf(&req, "\"bundle\":%s,\"dry-run\":true",
		    mod) != -1);
		rc_act(apply, req, &r);
		EXPECT(&r, 200);
		ATF_CHECK_MSG(strstr(r.body, "\"path\":\"/etc/hosts\",\"state\":"
		    "\"changed\"") != NULL, "%.400s", r.body);
		ATF_CHECK(strstr(r.body, "+192.0.2.7 db") != NULL);
		resp_free(&r);
		ATF_CHECK(system("! grep -q 192.0.2.7 root/etc/hosts") == 0);
		free(req);
		ATF_REQUIRE(asprintf(&req, "\"bundle\":%s", mod) != -1);
		rc_act(apply, req, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("true", jstr(&r, "data.applied"));
		resp_free(&r);
		ATF_CHECK(system("grep -q 192.0.2.7 root/etc/hosts && ! grep "
		    "-q 192.0.2.7 root/var/backups/arcana/config-*/etc/hosts")
		    == 0);
		free(req);
		free(mod);
	}
	free(bundle);
}

/*
 * The troubleshooter's console: host here added (its id into sid), its
 * jails' network r1 to r3 as ts_net makes it, r2's routes and firewall
 * as given.
 */
static void
ts_start(const atf_tc_t *tc, struct authn *a, char *sid, size_t len,
    const char *r2routes, const char *r2fw)
{
	char	cwd[MAXPATHLEN];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	start(tc, 0, NULL);
	enrol(a);
	cc_host("here", "jgd.sock", sid, len);
	ts_net(cwd, r2routes, r2fw);
}

/* The path finder, its input's members in body; its result in r. */
#define	TP	"/restconf/operations/arcana-console:trace-path"
#define	ASK(proto, port)						\
	snprintf(body, sizeof(body), "\"src\":\"10.1.0.2\",\"dst\":"	\
	    "\"10.3.0.2\",\"proto\":\"" proto "\",\"port\":" #port ","	\
	    "\"places\":[{\"server\":\"%s\",\"jail\":\"r1\"},{"		\
	    "\"server\":\"%s\",\"jail\":\"r2\"},{\"server\":\"%s\","	\
	    "\"jail\":\"r3\"}]", sid, sid, sid);			\
	rc_act(TP, body, &r);						\
	EXPECT(&r, 200)

CONSOLE_TC(troubleshoot, "A packet followed across the hosts' jails: the "
    "way it goes, where it is stopped and why, the reply's way, and an "
    "asymmetric return a stateful firewall drops")
ATF_TC_BODY(troubleshoot, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[MAXPATHLEN], body[1024], sid[16], path[160];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ts_start(tc, &a, sid, sizeof(sid), "10.1.0.0/24 10.12.0.1 em0\n",
	    "65535 allow ip from any to any\n");

	/* Through: in on r1 from the client's network, on to r2 by r1's
	 * default route, onto the server's network; back the same way. */
	ASK("tcp", 22);
	ATF_CHECK_STREQ("here, jail r1", jstr(&r, "hops.0.place"));
	ATF_CHECK_STREQ("em0", jstr(&r, "hops.0.ingress"));
	ATF_CHECK_STREQ("10.12.0.2", jstr(&r, "hops.0.next_hop"));
	ATF_CHECK_STREQ("here, jail r2", jstr(&r, "hops.1.place"));
	ATF_CHECK_STREQ("em0", jstr(&r, "hops.1.ingress"));
	ATF_CHECK_STREQ("em1", jstr(&r, "hops.1.egress"));
	ATF_CHECK_STREQ("delivered", jstr(&r, "end.how"));
	ATF_CHECK(jstr(&r, "hops.2.place") == NULL);
	ATF_CHECK_STREQ("here, jail r2", jstr(&r, "return.0.place"));
	ATF_CHECK_STREQ("here, jail r1", jstr(&r, "return.1.place"));
	ATF_CHECK_STREQ("delivered", jstr(&r, "return_end.how"));
	ATF_CHECK_MSG(strstr(r.body, "\"severity\":\"bad\"") == NULL &&
	    strstr(r.body, "Asymmetric") == NULL, "%.600s", r.body);
	resp_free(&r);

	/* r2's firewall: stopped there, by its rule. */
	ts_net(cwd, "10.1.0.0/24 10.12.0.1 em0\n",
	    "01000 deny tcp from any to 10.3.0.0/24 22 in\n"
	    "65535 allow ip from any to any\n");
	ASK("tcp", 22);
	ATF_CHECK_STREQ("blocked", jstr(&r, "end.how"));
	ATF_CHECK_STREQ("here, jail r2", jstr(&r, "end.place"));
	ATF_CHECK_STREQ("bad", jstr(&r, "findings.0.severity"));
	ATF_CHECK_STREQ("here, jail r2", jstr(&r, "findings.0.place"));
	/* The finding names the place to the page. */
	ATF_CHECK_STREQ(sid, jstr(&r, "findings.0.server"));
	ATF_CHECK_STREQ("r2", jstr(&r, "findings.0.jail"));
	resp_free(&r);

	/* From the Internet: no place has 203.0.113.9 nor its network; r2
	 * is the edge, its default route leaving the places asked, so the
	 * packet comes in there, on em2, and is delivered. */
	ts_net(cwd, "10.1.0.0/24 10.12.0.1 em0\n0.0.0.0/0 10.23.0.9 em2\n",
	    "65535 allow ip from any to any\n");
	snprintf(body, sizeof(body), "\"src\":\"203.0.113.9\",\"dst\":"
	    "\"10.3.0.2\",\"proto\":\"tcp\",\"port\":443,\"places\":[{"
	    "\"server\":\"%s\",\"jail\":\"r1\"},{\"server\":\"%s\",\"jail"
	    "\":\"r2\"},{\"server\":\"%s\",\"jail\":\"r3\"}]", sid, sid,
	    sid);
	rc_act(TP, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("here, jail r2", jstr(&r, "hops.0.place"));
	ATF_CHECK_STREQ("em2", jstr(&r, "hops.0.ingress"));
	ATF_CHECK_STREQ("delivered", jstr(&r, "end.how"));
	ATF_CHECK_MSG(strstr(r.body, "comes from beyond the hosts asked") !=
	    NULL, "%.500s", r.body);
	resp_free(&r);
	ts_net(cwd, "10.1.0.0/24 10.12.0.1 em0\n",
	    "01000 deny tcp from any to 10.3.0.0/24 22 in\n"
	    "65535 allow ip from any to any\n");

	/* One host asked alone, for its firewall tab: the walk, rule by
	 * rule, as the kernel would make it. */
	snprintf(path, sizeof(path), FLEET "%s/arcana-troubleshoot:"
	    "troubleshoot/path-check", sid);
	rc_act(path, "\"source\":\"10.1.0.2\",\"destination\":\"10.3.0.2\","
	    "\"protocol\":\"tcp\",\"port\":22,\"jail\":\"r2\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("deny", jstr(&r, "firewall.in.verdict"));
	ATF_CHECK_STREQ("1000", jstr(&r, "firewall.in.step.0.rule"));
	ATF_CHECK_STREQ("decides", jstr(&r, "firewall.in.step.0.how"));
	ATF_CHECK_STREQ("em0", jstr(&r, "ingress.interface"));
	resp_free(&r);
	rc_act(path, "\"source\":\"10.1.0.2\",\"destination\":\"nowhere\"",
	    &r);
	EXPECT(&r, 400);
	resp_free(&r);
	ASK("tcp", 22);
	ATF_CHECK_MSG(strstr(jstr(&r, "findings.0.what"), "The firewall drops "
	    "it coming in on em0: rule 1000") != NULL, "%s", jstr(&r,
	    "findings.0.what"));
	ATF_CHECK(jstr(&r, "return.0.place") == NULL);
	resp_free(&r);

	/* r2 sends the reply back by r3, which saw no request: its
	 * stateful firewall drops the reply.  An ICMP echo it lets by. */
	ts_net(cwd, "10.1.0.0/24 10.23.0.3 em2\n",
	    "65535 allow ip from any to any\n");
	ASK("tcp", 22);
	ATF_CHECK_STREQ("delivered", jstr(&r, "end.how"));
	ATF_CHECK_STREQ("here, jail r2", jstr(&r, "return.0.place"));
	ATF_CHECK_STREQ("here, jail r3", jstr(&r, "return.1.place"));
	ATF_CHECK_STREQ("blocked", jstr(&r, "return_end.how"));
	ATF_CHECK_STREQ("here, jail r3", jstr(&r, "return_end.place"));
	ATF_CHECK_MSG(strstr(r.body, "The reply: The firewall drops it coming "
	    "in on em1: rule 65535") != NULL, "%.1500s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "Asymmetric across the places: the request "
	    "goes here, jail r1 → here, jail r2, the reply comes back "
	    "here, jail r3 → here, jail r2") != NULL, "%.2000s", r.body);
	resp_free(&r);
	ASK("icmp", 0);
	ATF_CHECK_STREQ("delivered", jstr(&r, "return_end.how"));
	ATF_CHECK(strstr(r.body, "\"severity\":\"bad\"") == NULL);
	ATF_CHECK(strstr(r.body, "Asymmetric across the places") != NULL);
	resp_free(&r);

	/* Who is on no place's network comes in where the route back to
	 * it leaves the places asked: r1 alone asked, by its default route,
	 * on em1. */
	snprintf(body, sizeof(body), "\"src\":\"198.51.100.1\",\"dst\":"
	    "\"10.3.0.2\",\"places\":[{\"server\":\"%s\",\"jail\":\"r1\"}]",
	    sid);
	rc_act(TP, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("em1", jstr(&r, "hops.0.ingress"));
	resp_free(&r);
	/* And with no route back to it out of them at all: not known. */
	snprintf(body, sizeof(body), "\"src\":\"198.51.100.1\",\"dst\":"
	    "\"10.3.0.2\",\"places\":[{\"server\":\"%s\",\"jail\":\"r3\"}]",
	    sid);
	rc_act(TP, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("unknown", jstr(&r, "end.how"));
	resp_free(&r);
	/* SCTP, with its port: asked as TCP and UDP are. */
	snprintf(body, sizeof(body), "\"src\":\"198.51.100.1\",\"dst\":"
	    "\"10.3.0.2\",\"proto\":\"sctp\",\"port\":4310,\"places\":"
	    "[{\"server\":\"%s\",\"jail\":\"r1\"}]", sid);
	rc_act(TP, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("sctp", jstr(&r, "proto"));
	ATF_CHECK_STREQ("em1", jstr(&r, "hops.0.ingress"));
	resp_free(&r);
	rc_act(TP, "\"src\":\"10.1.0.2\",\"dst\":\"10.1.0.3\",\"proto\":"
	    "\"gre\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	rc_act(TP, "\"src\":\"10.1.0.2\",\"dst\":\"2001:db8::1\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);
}

CONSOLE_TC(troubleshoot_hang, "A packet followed across the hosts' jails "
    "while one jail's agent call hangs: waited for no longer than its "
    "deadline, the way still followed by the others")
ATF_TC_BODY(troubleshoot_hang, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[1024], sid[16];
	time_t		t0;

	ts_start(tc, &a, sid, sizeof(sid), "10.1.0.0/24 10.12.0.1 em0\n",
	    "01000 deny tcp from any to 10.3.0.0/24 22 in\n"
	    "65535 allow ip from any to any\n");
	/* r3's agent call hangs: the survey waits for it no longer than
	 * its deadline, and the way is still followed by r1 and r2. */
	ATF_REQUIRE(system("touch hang-13") == 0);
	t0 = time(NULL);
	ASK("tcp", 22);
	ATF_CHECK_MSG(time(NULL) - t0 < 40, "%lld s", (long long)(time(NULL) -
	    t0));
	ATF_CHECK_STREQ("here, jail r2", jstr(&r, "end.place"));
	ATF_CHECK_MSG(strstr(r.body, "no answer in 20 seconds") != NULL,
	    "%.400s", r.body);
	resp_free(&r);
	ATF_REQUIRE(unlink("hang-13") == 0);
}
#undef	ASK
#undef	TP

CONSOLE_TC(transfers, "A snapshot sent from one host to another, the "
    "console carrying it at the pace the receiver takes it")
ATF_TC_BODY(transfers, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[1200], sa[16], sb[16], id[32];
	int		i;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	/* Two names for the one agent here: two hosts to the console. */
	cc_host("a", "jgd.sock", sa, sizeof(sa));
	snprintf(body, sizeof(body), "unix:%s/./jgd.sock", cwd);
	host_add("b", body, sb, sizeof(sb));
	/* More than the window: the relay waits on the receiver. */
	ATF_REQUIRE(system("dd if=/dev/random of=zsend.data bs=1m count=10 "
	    "2>/dev/null") == 0);
	snprintf(body, sizeof(body), "\"from\":\"%s\",\"snapshot\":"
	    "\"tank/data@b\",\"to\":\"%s\",\"dataset\":\"tank/copy\"", sa, sb);
	rc_act(CC "transfers/start", body, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_MSG(jstr(&r, "id") != NULL, "%s", r.body);
	snprintf(id, sizeof(id), "%s", jstr(&r, "id"));
	resp_free(&r);
	for (i = 0; i < 300; i++) {
		http("GET", CC "transfers", NULL, &r);
		if (jstr(&r, "arcana-console:transfers.transfer.0.state") !=
		    NULL && strcmp(jstr(&r, "arcana-console:transfers."
		    "transfer.0.state"), "running") != 0)
			break;
		resp_free(&r);
		usleep(100000);
	}
	if (i == 300)
		(void)system("cat data/transfers.json; tail -5 storage.log; "
		    "ls -l zrecv.data; tail -20 console.out; tail -20 "
		    "arcana-agent.out");
	ATF_REQUIRE(i < 300);
	ATF_CHECK_STREQ("done", jstr(&r,
	    "arcana-console:transfers.transfer.0.state"));
	ATF_CHECK_STREQ("10485760", jstr(&r,
	    "arcana-console:transfers.transfer.0.bytes"));
	ATF_CHECK_STREQ(id, jstr(&r, "arcana-console:transfers.transfer.0.id"));
	resp_free(&r);
	ATF_CHECK(system("cmp -s zsend.data zrecv.data") == 0);
	ATF_CHECK(system("grep -q '^zfs send tank/data@b$' storage.log && "
	    "grep -q '^zfs receive -u tank/copy$' storage.log") == 0);
	ATF_CHECK(system("test \"$(stat -f %Lp data/transfers.json)\" = 600")
	    == 0);

	/* Only what changed since a snapshot both have; a receive that
	 * refuses: said as zfs says it. */
	snprintf(body, sizeof(body), "\"from\":\"%s\",\"snapshot\":"
	    "\"tank/data@b\",\"since\":\"tank/data@a\",\"to\":\"%s\","
	    "\"dataset\":\"tank/fail\"", sa, sb);
	rc_act(CC "transfers/start", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 300; i++) {
		http("GET", CC "transfers", NULL, &r);
		if (jstr(&r, "arcana-console:transfers.transfer.1.state") !=
		    NULL && strcmp(jstr(&r, "arcana-console:transfers."
		    "transfer.1.state"), "running") != 0)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_REQUIRE(i < 300);
	ATF_CHECK_STREQ("failed", jstr(&r,
	    "arcana-console:transfers.transfer.1.state"));
	ATF_CHECK_MSG(jstr(&r, "arcana-console:transfers.transfer.1.error") !=
	    NULL && strstr(jstr(&r, "arcana-console:transfers.transfer.1."
	    "error"), "destination 'tank/fail' exists") != NULL, "%s", jstr(&r,
	    "arcana-console:transfers.transfer.1.error"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^zfs send -i tank/data@a tank/data@b$' "
	    "storage.log") == 0);

	/* What is not one is refused before anything begins. */
	snprintf(body, sizeof(body), "\"from\":\"%s\",\"snapshot\":"
	    "\"tank/data@b\",\"to\":\"%s\",\"dataset\":\"tank/x\"", sa, sa);
	rc_act(CC "transfers/start", body, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(body, sizeof(body), "\"from\":\"%s\",\"snapshot\":"
	    "\"tank/data@b\",\"to\":\"%s\",\"dataset\":\"tank\"", sa, sb);
	rc_act(CC "transfers/start", body, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(body, sizeof(body), "\"from\":\"%s\",\"snapshot\":"
	    "\"tank/data\",\"to\":\"%s\",\"dataset\":\"tank/x\"", sa, sb);
	rc_act(CC "transfers/start", body, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* Ended: nothing to stop. */
	snprintf(body, sizeof(body), CC "transfers/transfer=%s/stop", id);
	rc_act(body, NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
}

/* An SD-WAN check's input, a document that is none: refused or not, not
 * for who asks. */
#define	R2_CHECK	"{\"arcana-console:input\":{\"document\":{}}}"

CONSOLE_TC(tokens, "A read-only API token, made in a session, reads what is "
    "said of the hosts and changes nothing; deleted, it opens nothing")
ATF_TC_BODY(tokens, tc)
{
	struct authn	a;
	struct resp	r;
	char		token[80], id[20], path[256], sid[16];
	char		server[256];

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("lab", "jgd.sock", sid, sizeof(sid));
	snprintf(server, sizeof(server), FLEET "%s/arcana-host:host", sid);

	/* Made in a session, its value said once; kept as its hash only. */
	rc_act(CC "tokens/create", "\"name\":\"overlay planner\"", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "token") != NULL);
	ATF_CHECK(strncmp(jstr(&r, "token"), "arcr_", 5) == 0);
	ATF_CHECK_EQ(69, strlen(jstr(&r, "token")));
	snprintf(token, sizeof(token), "%s", jstr(&r, "token"));
	snprintf(id, sizeof(id), "%s", jstr(&r, "id"));
	resp_free(&r);
	snprintf(path, sizeof(path), "grep -q '%s' data/tokens.json", token + 5);
	ATF_CHECK(system(path) != 0);
	ATF_CHECK(system("test \"$(stat -f %Lp data/tokens.json)\" = 600") ==
	    0);
	http("GET", CC "tokens", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("overlay planner", jstr(&r,
	    "arcana-console:tokens.token.0.name"));
	ATF_CHECK(strstr(r.body, token + 5) == NULL);
	resp_free(&r);

	/* It reads what is said of the hosts... */
	http_bearer("GET", CC "hosts", token, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("lab", jstr(&r, "arcana-console:hosts.host.0.name"));
	resp_free(&r);
	http_bearer("GET", server, token, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* ... and changes nothing, nor reads the console's own. */
	http_bearer("POST", CC "hosts", token, "{\"arcana-console:host\":[{"
	    "\"id\":\"0b0c00ff\",\"name\":\"x\",\"uri\":"
	    "\"unix:/nonexistent\"}]}", &r);
	EXPECT(&r, 401);
	ATF_CHECK(strstr(r.body, "reads only") != NULL);
	resp_free(&r);
	http_bearer("POST", CC "tokens/create", token, "{\"arcana-console:"
	    "input\":{\"name\":\"another\"}}", &r);
	EXPECT(&r, 401);
	resp_free(&r);
	http_bearer("GET", CC "settings", token, NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	http_bearer("GET", CC "push", token, NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	/* Every other read is its: the workflows and their runs too. */
	http_bearer("GET", CC "workflows", token, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http_bearer("GET", CC "runs", token, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http_bearer("GET", CC "sdwan/plan", token, NULL, &r);
	ATF_CHECK_MSG(r.status != 401 && r.status != 403, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	http_bearer("POST", CC "sdwan/check", token, R2_CHECK, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	http_bearer("GET", CC "hosts", "arcr_0000000000000000000000000000"
	    "000000000000000000000000000000000000", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	/* Its use noted. */
	http("GET", CC "tokens", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "arcana-console:tokens.token.0.last-used") != NULL);
	resp_free(&r);

	/*
	 * A write token changes things too, with no session's headers:
	 * but never the tokens, the console's settings, push or the CA.
	 */
	rc_act(CC "tokens/create", "\"name\":\"claude\",\"kind\":\"write\"",
	    &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "token") != NULL &&
	    strncmp(jstr(&r, "token"), "arcw_", 5) == 0);
	{
		char wtok[80];

		snprintf(wtok, sizeof(wtok), "%s", jstr(&r, "token"));
		resp_free(&r);
		http("GET", CC "tokens", NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("read", jstr(&r,
		    "arcana-console:tokens.token.0.kind"));
		ATF_CHECK_STREQ("write", jstr(&r,
		    "arcana-console:tokens.token.1.kind"));
		resp_free(&r);
		http_bearer("GET", CC "hosts", wtok, NULL, &r);
		EXPECT(&r, 200);
		resp_free(&r);
		http_bearer("POST", CC "sdwan/check", wtok, R2_CHECK, &r);
		ATF_CHECK_MSG(r.status != 401 && r.status != 403, "%d %s",
		    r.status, r.body);
		resp_free(&r);
		http_bearer("POST", CC "tokens/create", wtok, "{\"arcana-"
		    "console:input\":{\"name\":\"more\"}}", &r);
		EXPECT(&r, 403);
		ATF_CHECK(strstr(r.body, "may not change") != NULL);
		resp_free(&r);
		/* Nor who is who: a token does not make itself an owner. */
		http_bearer("PUT", CC "users/user=intruder", wtok, "{\"arcana-"
		    "console:user\":[{\"name\":\"intruder\",\"role\":"
		    "[\"owner\"]}]}", &r);
		EXPECT(&r, 403);
		resp_free(&r);
		http_bearer("POST", CC "groups", wtok, "{\"arcana-console:"
		    "group\":[{\"name\":\"g\"}]}", &r);
		EXPECT(&r, 403);
		resp_free(&r);
		http_bearer("GET", CC "settings", wtok, NULL, &r);
		EXPECT(&r, 403);
		resp_free(&r);
		http_bearer("PATCH", CC "settings", wtok, "{\"arcana-console:"
		    "settings\":{}}", &r);
		EXPECT(&r, 403);
		resp_free(&r);
		http_bearer("GET", CC "push", wtok, NULL, &r);
		EXPECT(&r, 403);
		resp_free(&r);
		http_bearer("POST", CC "ca/make", wtok, NULL, &r);
		EXPECT(&r, 403);
		resp_free(&r);
		/*
		 * Signed in on the web with it: a session that may do what
		 * the token may, no more; a read token does not sign in;
		 * deleted, the token ends the session it opened.
		 */
		{
			char	saved[sizeof(cookie)], tbody[128];

			strlcpy(saved, cookie, sizeof(saved));
			cookie[0] = '\0';
			http("POST", "/api/auth/login/token", "{\"token\":\""
			    "arcw_0000000000000000000000000000000000000000000000"
			    "000000000000000000\"}", &r);
			EXPECT(&r, 401);
			resp_free(&r);
			snprintf(tbody, sizeof(tbody), "{\"token\":\"%s\"}", token);
			http("POST", "/api/auth/login/token", tbody, &r);
			EXPECT(&r, 401);
			resp_free(&r);
			snprintf(tbody, sizeof(tbody), "{\"token\":\"%s\"}", wtok);
			http("POST", "/api/auth/login/token", tbody, &r);
			EXPECT(&r, 200);
			ATF_CHECK(strstr(r.body, "\"by_token\":true") != NULL);
			resp_free(&r);
			ATF_REQUIRE(cookie[0] != '\0');
			http("GET", "/api/auth/status", NULL, &r);
			ATF_CHECK(strstr(r.body, "\"authenticated\":true") !=
			    NULL && strstr(r.body, "\"by_token\":true") != NULL);
			resp_free(&r);
			http("GET", CC "hosts", NULL, &r);
			EXPECT(&r, 200);
			resp_free(&r);
			http("POST", CC "sdwan/check", R2_CHECK, &r);
			ATF_CHECK_MSG(r.status != 401 && r.status != 403,
			    "%d %s", r.status, r.body);
			resp_free(&r);
			http("POST", CC "tokens/create", "{\"arcana-console:"
			    "input\":{\"name\":\"more\"}}", &r);
			EXPECT(&r, 403);
			ATF_CHECK(strstr(r.body, "security key") != NULL);
			resp_free(&r);
			http("GET", CC "settings", NULL, &r);
			EXPECT(&r, 403);
			resp_free(&r);
			/* The token deleted, by a key's session. */
			{
				char	tsess[sizeof(cookie)], tid[24];

				strlcpy(tsess, cookie, sizeof(tsess));
				strlcpy(cookie, saved, sizeof(cookie));
				http("GET", CC "tokens", NULL, &r);
				EXPECT(&r, 200);
				ATF_REQUIRE(jstr(&r, "arcana-console:tokens."
				    "token.1.id") != NULL);
				snprintf(tid, sizeof(tid), "%s", jstr(&r,
				    "arcana-console:tokens.token.1.id"));
				resp_free(&r);
				snprintf(tbody, sizeof(tbody), CC
				    "tokens/token=%s", tid);
				http("DELETE", tbody, NULL, &r);
				EXPECT(&r, 204);
				resp_free(&r);
				strlcpy(cookie, tsess, sizeof(cookie));
				http("GET", CC "hosts", NULL, &r);
				EXPECT(&r, 401);
				resp_free(&r);
			}
			strlcpy(cookie, saved, sizeof(cookie));
		}
	}
	rc_act(CC "tokens/create", "\"name\":\"x\",\"kind\":\"root\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/* Deleted: it opens nothing at once. */
	snprintf(path, sizeof(path), CC "tokens/token=%s", id);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http_bearer("GET", CC "hosts", token, NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
}
#undef	R2_CHECK

/* A device's subscription to push: its endpoint, keys and name. */
#define	R2_SUB(e, k, a, n)						\
	"{\"arcana-console:subscription\":[{\"endpoint\":\"" e "\","	\
	"\"p256dh\":\"" k "\",\"auth\":\"" a "\"" n "}]}"
#define	R2_KEY	"BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx"		\
		"aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
#define	R2_AUTH	"BTBZMqHH6r4Tts7J_aSIgg"
#define	R2_SEND(in)	"{\"arcana-console:input\":{" in "}}"

CONSOLE_TC(push, "Devices subscribe to be told of tasks, and a message goes "
    "to all but the one that sends it")
ATF_TC_BODY(push, tc)
{
	struct authn	a;
	struct resp	r;

	start(tc, 0, NULL);
	http("GET", CC "push", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	enrol(&a);

	/* The console's key, for browsers to subscribe with; kept. */
	http("GET", CC "push", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "arcana-console:push.public-key") != NULL);
	ATF_CHECK_EQ(87, strlen(jstr(&r, "arcana-console:push.public-key")));
	ATF_CHECK(jstr(&r, "arcana-console:push.subscription.0") == NULL);
	resp_free(&r);
	ATF_CHECK(system("test \"$(stat -f %Lp data/vapid.pem)\" = 600") == 0);

	/* What is not a push service's address, or not keys, is refused. */
	http("POST", CC "push", R2_SUB("http://plain.example/x", R2_KEY,
	    R2_AUTH, ""), &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", CC "push", R2_SUB("https://localhost/a", "AAAA", R2_AUTH,
	    ""), &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/* Two devices; one of them twice is still one. */
	http("POST", CC "push", R2_SUB("https://localhost/a", R2_KEY, R2_AUTH,
	    ",\"name\":\"Chrome on Android\""), &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("PATCH", CC "push", "{\"arcana-console:push\":{\"subscription\":"
	    "[{\"endpoint\":\"https://localhost/a\",\"p256dh\":\"" R2_KEY "\","
	    "\"auth\":\"" R2_AUTH "\",\"name\":\"Chrome on Android\"}]}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "push", NULL, &r);
	ATF_CHECK(jstr(&r, "arcana-console:push.subscription.0") != NULL);
	ATF_CHECK(jstr(&r, "arcana-console:push.subscription.1") == NULL);
	resp_free(&r);
	http("POST", CC "push", R2_SUB("https://localhost/b", R2_KEY, R2_AUTH,
	    ",\"name\":\"Firefox on FreeBSD\""), &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", CC "push", NULL, &r);
	ATF_CHECK_STREQ("Chrome on Android", jstr(&r,
	    "arcana-console:push.subscription.0.name"));
	ATF_CHECK_STREQ("localhost", jstr(&r,
	    "arcana-console:push.subscription.0.service"));
	ATF_CHECK_STREQ("Firefox on FreeBSD", jstr(&r,
	    "arcana-console:push.subscription.1.name"));
	ATF_CHECK(jstr(&r, "arcana-console:push.subscription.2") == NULL);
	resp_free(&r);

	/*
	 * A message goes to the one that did not send it.  Nothing
	 * listens there, so it fails, and says so without failing the
	 * request; with no other device there is nothing to send.
	 */
	http("POST", CC "push/send", R2_SEND("\"title\":\"Arcana: done\","
	    "\"body\":\"start web on lab: done\",\"except\":"
	    "\"https://localhost/a\""), &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("0", jstr(&r, "arcana-console:output.sent"));
	ATF_CHECK_STREQ("1", jstr(&r, "arcana-console:output.failed"));
	resp_free(&r);

	/* b taken away: what is kept is a alone, its keys as they were. */
	http("PUT", CC "push", "{\"arcana-console:push\":{\"subscription\":"
	    "[{\"endpoint\":\"https://localhost/a\",\"name\":\"Chrome on "
	    "Android\"}]}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "push", NULL, &r);
	ATF_CHECK(jstr(&r, "arcana-console:push.subscription.0") != NULL);
	ATF_CHECK(jstr(&r, "arcana-console:push.subscription.1") == NULL);
	resp_free(&r);
	http("POST", CC "push/send", R2_SEND("\"title\":\"t\",\"body\":\"b\","
	    "\"except\":\"https://localhost/a\""), &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("0", jstr(&r, "arcana-console:output.sent"));
	resp_free(&r);

	/*
	 * What is not a text where one is meant fails nothing: an except
	 * that is no device's excepts none, the one there tried.  An
	 * address that would add to the request sent to it is refused.
	 */
	http("POST", CC "push/send", R2_SEND("\"title\":1,\"body\":2,"
	    "\"except\":3"), &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("1", jstr(&r, "arcana-console:output.failed"));
	resp_free(&r);
	http("POST", CC "push", R2_SUB("https://localhost/x HTTP/1.1\\r\\n"
	    "Host: other", R2_KEY, R2_AUTH, ""), &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/* The devices outlive a restart. */
	restart_console();
	http("GET", CC "push", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("Chrome on Android", jstr(&r,
	    "arcana-console:push.subscription.0.name"));
	resp_free(&r);
	ATF_CHECK(system("grep -q 'BTBZMqHH6r4Tts7J_aSIgg' data/push.json") ==
	    0);
}
#undef	R2_SUB
#undef	R2_KEY
#undef	R2_AUTH
#undef	R2_SEND

CONSOLE_TC(local_agent, "The agent beside the console is added by itself, "
    "once, when its socket answers")
ATF_TC_BODY(local_agent, tc)
{
	struct authn	a;
	struct resp	r;
	char		path[MAXPATHLEN], host[MAXHOSTNAMELEN];

	ATF_REQUIRE(gethostname(host, sizeof(host)) == 0);
	host[strcspn(host, ".")] = '\0';
	harness_local_agent = true;
	start(tc, 0, NULL);
	enrol(&a);

	/* It runs, and the console may reach it: there it is, by the
	 * host's name, and it answers. */
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("added", jstr(&r, "arcana-console:hosts.local"));
	ATF_CHECK_STREQ(host, jstr(&r, "arcana-console:hosts.host.0.name"));
	ATF_CHECK_STREQ("true", jstr(&r, "arcana-console:hosts.host.0.local"));
	ATF_CHECK(jstr(&r, "arcana-console:hosts.host.0.uri") != NULL &&
	    strstr(jstr(&r, "arcana-console:hosts.host.0.uri"), "/jgd.sock") !=
	    NULL);
	ATF_CHECK(jstr(&r, "arcana-console:hosts.host.1.id") == NULL);
	ATF_REQUIRE(jstr(&r, "arcana-console:hosts.host.0.id") != NULL);
	snprintf(path, sizeof(path), FLEET "%s/arcana-jails:jails", jstr(&r,
	    "arcana-console:hosts.host.0.id"));
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* Asked again, it is not added twice. */
	http("GET", CC "hosts", NULL, &r);
	ATF_CHECK(jstr(&r, "arcana-console:hosts.host.1.id") == NULL);
	snprintf(path, sizeof(path), CC "hosts/host=%s", jstr(&r,
	    "arcana-console:hosts.host.0.id"));
	resp_free(&r);

	/* Taken off the list, it stays off: over a restart too. */
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "arcana-console:hosts.host.0.id") == NULL);
	ATF_CHECK_STREQ("removed", jstr(&r, "arcana-console:hosts.local"));
	resp_free(&r);
	restart_console();
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "arcana-console:hosts.host.0.id") == NULL);
	ATF_CHECK_STREQ("removed", jstr(&r, "arcana-console:hosts.local"));
	resp_free(&r);
}

CONSOLE_TC(local_same, "The agent beside the console is not added again "
    "when it is on the list under another spelling of its socket")
ATF_TC_BODY(local_same, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[MAXPATHLEN], buf[MAXPATHLEN + 128];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ATF_REQUIRE(mkdir("data", 0700) == 0);
	snprintf(buf, sizeof(buf), "{\"servers\":[{\"id\":\"933e5390\",\"name\":"
	    "\"here\",\"uri\":\"unix://%s/jgd.sock\"}]}\n", cwd);
	put("data/servers.json", buf);
	harness_local_agent = true;
	start(tc, 0, NULL);
	enrol(&a);
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("added", jstr(&r, "arcana-console:hosts.local"));
	ATF_CHECK_STREQ("here", jstr(&r, "arcana-console:hosts.host.0.name"));
	ATF_CHECK(jstr(&r, "arcana-console:hosts.host.1.id") == NULL);
	resp_free(&r);
}

CONSOLE_TC(local_absent, "Without an agent beside the console, it says "
    "what it waits for")
ATF_TC_BODY(local_absent, tc)
{
	struct authn	a;
	struct resp	r;

	snprintf(harness_webconf, sizeof(harness_webconf), "local_agent = "
	    "\"unix:/nonexistent/arcana-agent.sock\";\n");
	harness_webconf_only_local = true;
	start(tc, 0, NULL);
	enrol(&a);
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("absent", jstr(&r, "arcana-console:hosts.local"));
	ATF_CHECK_STREQ("unix:/nonexistent/arcana-agent.sock", jstr(&r,
	    "arcana-console:hosts.local-agent"));
	ATF_CHECK(jstr(&r, "arcana-console:hosts.host.0.id") == NULL);
	resp_free(&r);
}

CONSOLE_TC(settings, "Settings are changed from the console, kept in the "
    "data directory, and override web.conf")
ATF_TC_BODY(settings, tc)
{
	struct authn	a;
	struct resp	r;

	start(tc, 0, NULL);
	http("GET", CC "settings", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	enrol(&a);

	http("GET", CC "settings", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("Arcana", jstr(&r, "arcana-console:settings.rp-name"));
	ATF_CHECK_STREQ("rp-name", jstr(&r,
	    "arcana-console:settings.source.0.name"));
	ATF_CHECK_STREQ("false", jstr(&r,
	    "arcana-console:settings.source.0.overridden"));
	resp_free(&r);
	http("GET", "/api/health", NULL, &r);
	ATF_CHECK(jstr(&r, "agent_source") == NULL);
	resp_free(&r);

	/* The program sent to hosts is never one of the console's own
	 * files: its keys are in the data directory. */
	{
		char cwd[MAXPATHLEN], body[MAXPATHLEN + 64];

		ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
		snprintf(body, sizeof(body), "\"agent-binary\":"
		    "\"%s/data/ca.key\"", cwd);
		r2_settings(body, &r);
		EXPECT(&r, 400);
		resp_free(&r);
		snprintf(body, sizeof(body), "\"agent-binary\":"
		    "\"%s/data/../data/agent/arcana-agent\"", cwd);
		r2_settings(body, &r);
		EXPECT(&r, 400);
		resp_free(&r);
	}

	/* What is not a value for a setting, or not a setting to change
	 * here, changes nothing. */
	r2_settings("\"agent-source\":\"--upload-pack=x\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	r2_settings("\"rp-id\":\"evil.example\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("PUT", CC "settings/fixed/relying-party", "{\"arcana-console:"
	    "relying-party\":\"evil.example\"}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);
	r2_settings("\"rp-name\":\"Lab\",\"update-url\":"
	    "\"http://plain.example/\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	ATF_CHECK(access("data/settings.json", F_OK) == -1);
	/* HSTS's days: 0 (none sent) to 730. */
	r2_settings("\"hsts-days\":731", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	r2_settings("\"hsts-days\":0", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	r2_settings("\"hsts-days\":730", &r);
	EXPECT(&r, 204);
	resp_free(&r);

	r2_settings("\"rp-name\":\"Lab\",\"agent-source\":"
	    "\"https://example.org/arcana.git\",\"agent-ref\":\"main\","
	    "\"update-check\":false", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "settings", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("Lab", jstr(&r, "arcana-console:settings.rp-name"));
	ATF_CHECK_STREQ("Arcana", jstr(&r,
	    "arcana-console:settings.source.0.web-conf"));
	ATF_CHECK_STREQ("true", jstr(&r,
	    "arcana-console:settings.source.0.overridden"));
	ATF_CHECK_STREQ("false", jstr(&r,
	    "arcana-console:settings.update-check"));
	resp_free(&r);
	ATF_CHECK(access("data/settings.json", R_OK) == 0);
	http("GET", "/api/health", NULL, &r);
	ATF_CHECK_STREQ("https://example.org/arcana.git", jstr(&r,
	    "agent_source"));
	ATF_CHECK_STREQ("main", jstr(&r, "agent_ref"));
	resp_free(&r);

	/* How long a sign-in lasts: in its bounds, and in force. */
	r2_settings("\"session-idle\":3", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	r2_settings("\"session-max\":0", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	r2_settings("\"session-idle\":45,\"session-max\":48", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "settings", NULL, &r);
	ATF_CHECK_STREQ("45", jstr(&r, "arcana-console:settings.session-idle"));
	ATF_CHECK_STREQ("48", jstr(&r, "arcana-console:settings.session-max"));
	resp_free(&r);
	http("GET", "/api/health", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* Back at web.conf's value, or left out: the override goes. */
	r2_settings("\"rp-name\":\"Arcana\",\"agent-ref\":\"\"", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("DELETE", CC "settings/agent-source", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "settings", NULL, &r);
	ATF_CHECK_STREQ("false", jstr(&r,
	    "arcana-console:settings.source.0.overridden"));
	resp_free(&r);
	http("GET", "/api/health", NULL, &r);
	ATF_CHECK(jstr(&r, "agent_source") == NULL);
	resp_free(&r);
}

/*
 * Telegram's Bot API, a sink of the test's: each request's first line
 * and body written to tg.out, answered as sent.  Its port is returned;
 * it runs in a child.
 */
static int
tg_sink(pid_t *pidp)
{
	struct sockaddr_in	 sin;
	socklen_t		 sl;
	char			 line[1024], *body;
	FILE			*io, *out;
	long			 len;
	int			 ls, fd;

	ATF_REQUIRE((ls = socket(AF_INET, SOCK_STREAM, 0)) != -1);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ATF_REQUIRE(bind(ls, (struct sockaddr *)&sin, sizeof(sin)) == 0);
	ATF_REQUIRE(listen(ls, 8) == 0);
	sl = sizeof(sin);
	ATF_REQUIRE(getsockname(ls, (struct sockaddr *)&sin, &sl) == 0);
	if ((*pidp = fork()) != 0) {
		close(ls);
		return (ntohs(sin.sin_port));
	}
	for (;;) {
		if ((fd = accept(ls, NULL, NULL)) == -1)
			_exit(1);
		io = fdopen(fd, "r+");
		out = fopen("tg.out", "a");
		len = 0;
		if (fgets(line, sizeof(line), io) != NULL)
			fprintf(out, "REQ %s", line);
		while (fgets(line, sizeof(line), io) != NULL && strcmp(line,
		    "\r\n") != 0)
			if (strncasecmp(line, "Content-Length:", 15) == 0)
				len = strtol(line + 15, NULL, 10);
		if (len > 0 && len < 65536 && (body = calloc(1, (size_t)len +
		    1)) != NULL) {
			if (fread(body, 1, (size_t)len, io) == (size_t)len)
				fprintf(out, "%s\n", body);
			free(body);
		}
		fclose(out);
		fputs("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
		    "Content-Length: 11\r\nConnection: close\r\n\r\n"
		    "{\"ok\":true}", io);
		fclose(io);
	}
}

/*
 * Telegram's console: the sink its Bot API (its pid into sink), events
 * read each second; host here added (its id into sid), the bot's token
 * and chats set, told by here of the jobs that failed.
 */
static void
tg_start(const atf_tc_t *tc, struct authn *a, char *sid, size_t len,
    pid_t *sink)
{
	struct resp	r;
	int		port;

	port = tg_sink(sink);
	snprintf(harness_telegram_api, sizeof(harness_telegram_api),
	    "http://127.0.0.1:%d", port);
	snprintf(harness_webconf, sizeof(harness_webconf), "mail_tick = 1;\n");
	start(tc, 0, NULL);
	enrol(a);
	cc_host("here", "jgd.sock", sid, len);
	r2_settings("\"telegram-token\":\"123:abc_DEF\",\"telegram-chats\":"
	    "\"-100 42\",\"telegram-via\":\"here\",\"telegram-jobs\":"
	    "\"failed\"", &r);
	EXPECT(&r, 204);
	resp_free(&r);
}

/* The sink stopped; the token never in the agent's output. */
static void
tg_end(pid_t sink)
{

	ATF_CHECK(system("! grep -q abc_DEF arcana-agent.out") == 0);
	(void)kill(sink, SIGTERM);
	(void)waitpid(sink, NULL, 0);
}

/* Host sid's jobs submitted: change the members of the input's change
 * list; the answer must be 200. */
static void
r2_submit(const char *sid, const char *change)
{
	struct resp	 r;
	char		 path[160], *body;

	snprintf(path, sizeof(path), FLEET "%s/arcana-jobs:submit", sid);
	ATF_REQUIRE(asprintf(&body, "{\"arcana-jobs:input\":{\"change\":[%s]}}",
	    change) != -1);
	http("POST", path, body, &r);
	free(body);
	EXPECT(&r, 200);
	resp_free(&r);
}

CONSOLE_TC(telegram, "Alerts to Telegram chats, by a bot, sent by an "
    "agent; its token never read back")
ATF_TC_BODY(telegram, tc)
{
	struct authn	a;
	struct resp	r;
	char		path[256], sid[16];
	pid_t		sink;

	tg_start(tc, &a, sid, sizeof(sid), &sink);
	/* Not a token, not a chat: refused. */
	r2_settings("\"telegram-token\":\"x y\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	r2_settings("\"telegram-chats\":\"-100 x;y\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("GET", CC "settings", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, "abc_DEF") == NULL);
	ATF_CHECK_STREQ("true", jstr(&r,
	    "arcana-console:settings.telegram-token-set"));
	resp_free(&r);
	/* The test: to each chat, by the host's agent. */
	rc_act(CC "settings/telegram-test", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("-100 42", jstr(&r, "to"));
	resp_free(&r);
	ATF_CHECK(system("grep -c '^REQ POST /bot123:abc_DEF/sendMessage' "
	    "tg.out | grep -qx 2 && grep -q '\"chat_id\":-100,' tg.out && "
	    "grep -q '\"chat_id\":42,' tg.out && grep -q '\"text\":\"🛰️ Arcana: "
	    "a test.' tg.out") == 0);
	/* How many jobs of pkg in jails run at once: set, said by the
	 * jobs list, and refused outside 1 to 32. */
	snprintf(path, sizeof(path), "/restconf/ds/ietf-datastores:candidate/"
	    "arcana-fleet:fleet/host=%s/arcana-jobs:jobs/lanes", sid);
	http("PUT", path, "{\"arcana-jobs:lanes\":3}", &r);
	ATF_CHECK_MSG(r.status == 204 || r.status == 201, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	http("PUT", path, "{\"arcana-jobs:lanes\":0}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(path, sizeof(path), FLEET "%s/ietf-netconf:commit", sid);
	http("POST", path, "{}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	snprintf(path, sizeof(path), FLEET "%s/arcana-jobs:jobs", sid);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("3", jstr(&r, "arcana-jobs:jobs.lanes"));
	resp_free(&r);
	tg_end(sink);
}

CONSOLE_TC(telegram_job, "A job that failed told to Telegram chats, by a "
    "bot, sent by an agent")
ATF_TC_BODY(telegram_job, tc)
{
	struct authn	a;
	char		sid[16];
	pid_t		sink;
	int		i;

	tg_start(tc, &a, sid, sizeof(sid), &sink);
	/* A job that failed, told within a tick or two. */
	sleep(2);
	r2_submit(sid, "{\"cert\":{\"verb\":\"trust\",\"path\":\"nosuch.0\"}}");
	for (i = 0; i < 150 && system("grep -q 'failed.ncertificate trust "
	    "nosuch.0' tg.out") != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(system("grep -q '❌ here · job [0-9]* failed.ncertificate "
	    "trust nosuch.0.n⚠️ [^\"]*.n🕒 [0-9:]*\"' tg.out") == 0,
	    "no message of the job");
	tg_end(sink);
}

CONSOLE_TC(telegram_workflow, "A workflow's message to Telegram chats, "
    "its text made for the host; mail not set up, said")
ATF_TC_BODY(telegram_workflow, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[MAXPATHLEN], sid[16], run[32], wid[16];
	pid_t		sink;

	tg_start(tc, &a, sid, sizeof(sid), &sink);
	/* A workflow's notify step: its text made for the host. */
	r2_wf("\"name\":\"bad\",\"step\":[{\"id\":\"t\",\"notify\":{\"via\":"
	    "\"pigeon\",\"text\":\"x\"}}]", wid, sizeof(wid), &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(body, sizeof(body), "\"name\":\"tell\",\"host\":[\"%s\"],"
	    "\"step\":[{\"id\":\"t\",\"notify\":{\"via\":\"telegram\","
	    "\"text\":\"${host.name} said hi\"}},{\"id\":\"m\",\"notify\":{"
	    "\"via\":\"mail\",\"text\":\"x\"}}]", sid);
	r2_wf_new(body, wid, sizeof(wid));
	r2_run(wid, NULL, run, sizeof(run));
	run_wait(run, &r);
	r2_traces(&r);
	ATF_CHECK_STREQ("done", jstr(&r, "host.0.step.0.state"));
	ATF_CHECK_STREQ("here said hi", jstr(&r, "host.0.step.0.trace.text"));
	/* Mail is not set up: the step says so. */
	ATF_CHECK_STREQ("failed", jstr(&r, "host.0.step.1.state"));
	ATF_CHECK_MSG(jstr(&r, "host.0.step.1.error") != NULL && strstr(
	    jstr(&r, "host.0.step.1.error"), "mail is not set up") != NULL,
	    "%s", r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q 'workflow tell on here.n.nhere said hi' "
	    "tg.out") == 0);
	tg_end(sink);
}

static void	pki(const char *, const char *, const char *);

CONSOLE_TC(mail, "Faults, jobs and runs mailed by sendmail(8), as the "
    "settings say")
ATF_TC_BODY(mail, tc)
{
	struct authn	a;
	struct resp	r;
	char		sid[16];
	int		i;

	/* The hosts' events read each second, not each fifteen. */
	snprintf(harness_webconf, sizeof(harness_webconf), "mail_tick = 1;\n");
	start(tc, 0, NULL);
	enrol(&a);
	cc_host("here", "jgd.sock", sid, sizeof(sid));
	/* No one to mail to: said so. */
	rc_act(CC "settings/mail-test", NULL, &r);
	EXPECT(&r, 502);
	ATF_CHECK_STREQ("no address to mail to", jstr(&r,
	    "ietf-restconf:errors.error.0.error-message"));
	resp_free(&r);
	/* Addresses only, nothing a header could be made of. */
	r2_settings("\"mail-to\":\"ops\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	r2_settings("\"mail-to\":\"ops@example.org\\nBcc: x@example.org\"",
	    &r);
	EXPECT(&r, 400);
	resp_free(&r);
	r2_settings("\"mail-jobs\":\"some\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	r2_settings("\"mail-to\":\"ops@example.org, noc@example.org\","
	    "\"mail-jobs\":\"failed\"", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	rc_act(CC "settings/mail-test", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("ops@example.org, noc@example.org", jstr(&r, "to"));
	resp_free(&r);
	ATF_CHECK(system("grep -qx 'ARGS -t -i' mail.out && grep -qx 'To: "
	    "ops@example.org, noc@example.org' mail.out && grep -qx 'Subject: "
	    "Arcana: a test' mail.out && grep -q '^From: Arcana <arcana@' "
	    "mail.out && grep -qx 'Auto-Submitted: auto-generated' mail.out")
	    == 0);
	/* The host's events read from here on: a job failed is mailed,
	 * one done is not. */
	sleep(3);
	r2_submit(sid, "{\"cert\":{\"verb\":\"rehash\"}},{\"cert\":{\"verb\":"
	    "\"trust\",\"path\":\"nosuch.0\"}}");
	for (i = 0; i < 150 && system("grep -q 'failed: certificate trust "
	    "nosuch.0' mail.out") != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(system("grep -q '^Subject: Arcana: [0-9:]* here: job "
	    "[0-9]* failed: certificate trust nosuch.0' mail.out") == 0,
	    "no mail of the job");
	ATF_CHECK(system("grep -q 'certificate rehash' mail.out") != 0);
	/* None: nothing more. */
	r2_settings("\"mail-to\":\"\"", &r);
	EXPECT(&r, 204);
	resp_free(&r);
}

/* The stand-in agent's host named name, at sock in the work directory:
 * its id into sid. */
static void
r3_host(const char *name, const char *sock, char *sid, size_t len)
{
	char	cwd[MAXPATHLEN], uri[MAXPATHLEN + 64];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(uri, sizeof(uri), "unix:%s/%s", cwd, sock);
	host_add(name, uri, sid, len);
}

/* Settings' members (RFC 7951's) merged: the status said, checked. */
static void
r3_settings(const char *members, int status)
{
	struct resp	 r;
	char		*body;

	ATF_REQUIRE(asprintf(&body, "{\"arcana-console:settings\":{%s}}",
	    members) != -1);
	http("PATCH", CC "settings", body, &r);
	free(body);
	ATF_CHECK_MSG(r.status == status, "%s: %d, not %d: %s", members,
	    r.status, status, r.body);
	resp_free(&r);
}

/* A leaf of Settings' left out: web.conf's again. */
static void
r3_unset(const char *leaf)
{
	struct resp	r;
	char		path[128];

	snprintf(path, sizeof(path), CC "settings/%s", leaf);
	http("DELETE", path, NULL, &r);
	ATF_CHECK_MSG(r.status == 204 || r.status == 404, "%s: %d %s", leaf,
	    r.status, r.body);
	resp_free(&r);
}

/* Host id's registry entry merged with members (RFC 7951's, but the
 * id): its answer in r. */
static void
r3_host_set(const char *id, const char *members, struct resp *r)
{
	char	path[128], *body;

	snprintf(path, sizeof(path), CC "hosts/host=%s", id);
	ATF_REQUIRE(asprintf(&body, "{\"arcana-console:host\":[{\"id\":\"%s\""
	    "%s%s}]}", id, members[0] != '\0' ? "," : "", members) != -1);
	http("PATCH", path, body, r);
	free(body);
}

/*
 * Host id's candidate merged with body at below (below the host's entry,
 * "/arcana-history:history"), then committed: the edit's status if it
 * was refused, else the commit's; the answer refused, or the commit's,
 * in r.
 */
static int
r3_commit(const char *id, const char *below, const char *body,
    struct resp *r)
{
	char	path[512];

	struct resp	d;

	snprintf(path, sizeof(path), "/restconf/ds/ietf-datastores:candidate/"
	    "arcana-fleet:fleet/host=%s%s", id, below);
	http("PATCH", path, body, r);
	if (r->status < 300) {
		resp_free(r);
		snprintf(path, sizeof(path), FLEET "%s/ietf-netconf:commit",
		    id);
		http("POST", path, "{}", r);
	}
	/* What was refused not left for the next commit. */
	if (r->status >= 300) {
		snprintf(path, sizeof(path), FLEET "%s/ietf-netconf:"
		    "discard-changes", id);
		http("POST", path, NULL, &d);
		resp_free(&d);
	}
	return (r->status);
}

/* Host id's arcana-history, how it samples merged with members and
 * committed: the status, as r3_commit's. */
static int
r3_history(const char *id, const char *members)
{
	struct resp	 r;
	char		*body;
	int		 st;

	ATF_REQUIRE(asprintf(&body, "{\"arcana-history:history\":{%s}}",
	    members) != -1);
	st = r3_commit(id, "/arcana-history:history", body, &r);
	free(body);
	if (st != 204)
		printf("history %s: %d %s\n", members, st, r.body);
	resp_free(&r);
	return (st);
}

/* Host id's arcana-history read, the container in r's JSON. */
static void
r3_history_get(const char *id, struct resp *r)
{
	char	path[160];

	snprintf(path, sizeof(path), FLEET "%s/arcana-history:history", id);
	http("GET", path, NULL, r);
	EXPECT(r, 200);
	ATF_REQUIRE_MSG(resp_unwrap(r, "arcana-history:history"), "%s",
	    r->body);
}

/* Host id's below (below its entry, "/arcana-jails:jails") read: its
 * answer in r, its JSON the node's value where it is 200. */
static void
r3_read(const char *id, const char *below, struct resp *r)
{
	char	path[512], key[128];

	snprintf(path, sizeof(path), FLEET "%s%s", id, below);
	http("GET", path, NULL, r);
	/* The node's name, its last's, the module's prefix kept. */
	snprintf(key, sizeof(key), "%s", strrchr(below, '/') + 1);
	key[strcspn(key, "=?")] = '\0';
	if (strchr(key, ':') == NULL) {
		const char	*m, *e;

		/* Below a module's node: the module's own prefix. */
		for (m = below; (e = strchr(m + 1, '/')) != NULL &&
		    strchr(e, ':') != NULL; m = e)
			;
		snprintf(path, sizeof(path), "%.*s:%s", (int)strcspn(m + 1,
		    ":"), m + 1, strrchr(below, '/') + 1);
		snprintf(key, sizeof(key), "%s", path);
		key[strcspn(key, "=?")] = '\0';
	}
	if (r->status == 200)
		(void)resp_unwrap(r, key);
}

/* The jail called name of arcana-jails' jails in r: its member path. */
static const char *
r3_jail(const struct resp *r, const char *name, const char *path)
{
	const ucl_object_t	*j, *o;
	ucl_object_iter_t	 it = NULL;
	const char		*s;

	while ((j = ucl_object_iterate(ucl_object_lookup(r->json, "jail"),
	    &it, true)) != NULL)
		if ((s = ucl_object_tostring(ucl_object_lookup(j, "name"))) !=
		    NULL && strcmp(s, name) == 0) {
			if ((o = ucl_object_lookup_path(j, path)) == NULL)
				return (NULL);
			return (ucl_object_tostring_forced(o));
		}
	return (NULL);
}

/* Host id's jails read, 200, its web jail's address checked. */
static void
r3_web(const char *id)
{
	struct resp	r;

	r3_read(id, "/arcana-jails:jails", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("10.0.0.10", r3_jail(&r, "web", "ip4.0"));
	resp_free(&r);
}

/* How host id's agent is reached (arcana-console's transport), its
 * document in r. */
static void
r3_transport(const char *id, struct resp *r)
{
	char	path[128];

	snprintf(path, sizeof(path), CC "hosts/host=%s/transport", id);
	http("GET", path, NULL, r);
	EXPECT(r, 200);
	ATF_CHECK_MSG(resp_unwrap(r, "arcana-console:transport"), "%s",
	    r->body);
}

/* Host id's verb (arcana-console's action of a host's: "agent-update"),
 * input its members or NULL: its answer in r, its JSON the document. */
static void
r3_verb(const char *id, const char *verb, const char *input,
    struct resp *r)
{
	char	path[160];

	snprintf(path, sizeof(path), CC "hosts/host=%s/%s", id, verb);
	rc_act(path, input, r);
}

/* Host id's registry entry (arcana-console's hosts), its URI in buf. */
static const char *
r3_uri(const char *id, char *buf, size_t len)
{
	struct resp	r;
	char		path[128];

	snprintf(path, sizeof(path), CC "hosts/host=%s/uri", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	snprintf(buf, len, "%s", jstr(&r, "arcana-console:uri") != NULL ?
	    jstr(&r, "arcana-console:uri") : "");
	resp_free(&r);
	return (buf);
}

/* id's memory limit set to lim, at once (hold 0), sampled each second. */
static void
mem_limit(const char *id, int lim)
{
	struct resp	r;
	char		body[160];

	snprintf(body, sizeof(body), "\"sampling\":{\"step\":1,\"keep\":20,"
	    "\"hold\":0},\"limits\":{\"cpu\":0,\"memory\":%d,\"swap\":0}", lim);
	ATF_CHECK_EQ(204, r3_history(id, body));
	r3_history_get(id, &r);
	ATF_CHECK_STREQ("0", jstr(&r, "sampling.hold"));
	resp_free(&r);
}

/* How many lines of the mails' bodies match the basic regular
 * expression re: a mail of one line has it as its subject too. */
static int
mailed(const char *re)
{
	char	cmd[512];
	FILE	*fp;
	int	n = -1;

	snprintf(cmd, sizeof(cmd), "grep -v '^Subject: ' mail.out | "
	    "grep -c -- '%s'", re);
	if ((fp = popen(cmd, "r")) != NULL) {
		if (fscanf(fp, "%d", &n) != 1)
			n = 0;
		pclose(fp);
	}
	return (n);
}

/*
 * The cool-down's console: events read each second, a minute of the
 * cool-down a second, the agent's BIRD watched each second.  Host here
 * added (its id into id), its faults and limits mailed, a cool-down of
 * ten; its events read from here on.
 */
static void
nc_start(const atf_tc_t *tc, struct authn *a, char *id, size_t len)
{
	harness_bird_watch = true;
	snprintf(harness_webconf, sizeof(harness_webconf), "mail_tick = 1;\n"
	    "cooldown_unit = 1;\n");
	start(tc, 0, NULL);
	enrol(a);
	r3_host("here", "jgd.sock", id, len);
	r3_settings("\"mail-to\":\"ops@example.org\",\"mail-faults\":\"Major\","
	    "\"mail-limits\":true,\"notify-cooldown\":10", 204);
	/* The host's events read from here on. */
	sleep(3);
}

CONSOLE_TC(notify_cooldown_held, "Of one thing on one host, the first "
    "change mailed at once, those within the cool-down held and said in "
    "one line at its end")
ATF_TC_BODY(notify_cooldown_held, tc)
{
	struct authn	a;
	char		id[16];
	int		i;

	nc_start(tc, &a, id, sizeof(id));
	/* Over, under, over, under within the cool-down: the first
	 * mailed, the rest held; at its end, one line. */
	for (i = 0; i < 4; i++) {
		mem_limit(id, i % 2 == 0 ? 1 : 100);
		sleep(2);
	}
	ATF_CHECK_EQ(1, mailed("here: mem over its limit"));
	ATF_CHECK_EQ(0, mailed("here: mem back under its limit"));
	for (i = 0; i < 150 && mailed("mem on here: over/under") < 1; i++)
		usleep(100000);
	ATF_CHECK_MSG(mailed("mem on here: over/under 4 times in [0-9]* s, "
	    "now under 95%$") == 1, "no line of what was held");
}

CONSOLE_TC(notify_cooldown_again, "Over and under again within the "
    "cool-down, ending as it was last told: no line at its end")
ATF_TC_BODY(notify_cooldown_again, tc)
{
	struct authn	a;
	char		id[16];
	int		i;

	nc_start(tc, &a, id, sizeof(id));
	/* The first mailed at once; then under and over again. */
	mem_limit(id, 1);
	for (i = 0; i < 100 && mailed("here: mem over its limit") < 1; i++)
		usleep(100000);
	ATF_CHECK_EQ(1, mailed("here: mem over its limit"));
	mem_limit(id, 100);
	sleep(2);
	mem_limit(id, 1);
	sleep(10);
	ATF_CHECK_EQ(0, mailed("mem on here: over/under"));
	ATF_CHECK_EQ(0, mailed("here: mem back under its limit"));
}

CONSOLE_TC(notify_cooldown_mute, "A host's utilization muted: not mailed; "
    "its sessions still are")
ATF_TC_BODY(notify_cooldown_mute, tc)
{
	struct authn	a;
	struct resp	r;
	char		id[16];
	int		i;

	nc_start(tc, &a, id, sizeof(id));
	r3_host_set(id, "\"notify-mute\":[\"cpu\"]", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	r3_host_set(id, "\"notify-mute\":[\"utilization\"]", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "hosts", NULL, &r);
	ATF_CHECK_STREQ("utilization", jstr(&r,
	    "arcana-console:hosts.host.0.notify-mute.0"));
	ATF_CHECK_MSG(strstr(r.body, "\"notify-mute\":[\"utilization\"]") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	mem_limit(id, 100);
	sleep(2);
	mem_limit(id, 1);
	sleep(3);
	ATF_CHECK_EQ(0, mailed("here: mem over its limit"));
	ATF_CHECK_EQ(0, mailed("here: mem back under its limit"));
	ATF_REQUIRE(system("touch ospf.down") == 0);
	for (i = 0; i < 100 && mailed("fault, Major: ospf-neighbor") < 1; i++)
		usleep(100000);
	ATF_CHECK_EQ(1, mailed("here: fault, Major: ospf-neighbor"));
}

CONSOLE_TC(notify_cooldown_sessions, "A host's sessions muted: the "
    "neighbour back not mailed; its admins' to set, a viewer refused")
ATF_TC_BODY(notify_cooldown_sessions, tc)
{
	struct authn	a, b;
	struct resp	r;
	char		id[16];
	int		i;

	nc_start(tc, &a, id, sizeof(id));
	r3_settings("\"notify-cooldown\":1441", 400);
	http("GET", CC "settings/notify-cooldown", NULL, &r);
	ATF_CHECK_MSG(r.status == 200 && strstr(r.body, "10") != NULL, "%d %s",
	    r.status, r.body);
	resp_free(&r);
	/* A neighbour down, mailed; its sessions muted then: the
	 * neighbour back is not mailed. */
	ATF_REQUIRE(system("touch ospf.down") == 0);
	for (i = 0; i < 100 && mailed("fault, Major: ospf-neighbor") < 1; i++)
		usleep(100000);
	ATF_REQUIRE_EQ(1, mailed("here: fault, Major: ospf-neighbor"));
	r3_host_set(id, "\"notify-mute\":[\"utilization\",\"sessions\"]", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	ATF_REQUIRE(unlink("ospf.down") == 0);
	sleep(4);
	ATF_CHECK_EQ(0, mailed("here: cleared: ospf-neighbor"));

	/* A viewer of the host may not change them. */
	cc_user(&b, "vic", "\"role\":[\"viewer\"]", -8);
	r3_host_set(id, "\"notify-mute\":[\"all\"]", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("PATCH", "/restconf/data/arcana-console:hosts", "{\"arcana-console:"
	    "hosts\":{\"host\":[{\"id\":\"00000000\"}]}}", &r);
	ATF_CHECK(r.status >= 400);
	resp_free(&r);
}

CONSOLE_TC(sampling_switch, "A host's sampling switched off through the "
    "console: said by its history, kept by the registry for the alerts; "
    "on again")
ATF_TC_BODY(sampling_switch, tc)
{
	struct authn	a;
	struct resp	r;
	char		id[16];

	start(tc, 0, NULL);
	enrol(&a);
	r3_host("here", "jgd.sock", id, sizeof(id));
	r3_history_get(id, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "sampling.enabled"));
	ATF_CHECK_STREQ("60", jstr(&r, "sampling.hold"));
	resp_free(&r);
	ATF_CHECK(r3_history(id, "\"sampling\":{\"step\":5,\"keep\":720,"
	    "\"hold\":3601}") == 400);
	ATF_CHECK_EQ(204, r3_history(id, "\"sampling\":{\"step\":5,\"keep\":"
	    "720,\"enabled\":false}"));
	r3_history_get(id, &r);
	ATF_CHECK_STREQ("false", jstr(&r, "sampling.enabled"));
	ATF_CHECK_STREQ("60", jstr(&r, "sampling.hold"));
	resp_free(&r);
	/* The registry's sampled, as the host's history read said it. */
	http("GET", CC "hosts", NULL, &r);
	ATF_CHECK_STREQ("false", jstr(&r,
	    "arcana-console:hosts.host.0.sampled"));
	resp_free(&r);
	ATF_CHECK_EQ(204, r3_history(id, "\"sampling\":{\"step\":5,\"keep\":"
	    "720,\"enabled\":true}"));
	r3_history_get(id, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "sampling.enabled"));
	resp_free(&r);
	http("GET", CC "hosts", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r,
	    "arcana-console:hosts.host.0.sampled"));
	resp_free(&r);
}

/* Host id's action or rpc at below, input its members or NULL: the
 * answer in r, its JSON the output's members. */
static void
r3_act(const char *id, const char *below, const char *input, struct resp *r)
{
	char	path[512];

	snprintf(path, sizeof(path), FLEET "%s%s", id, below);
	rc_act(path, input, r);
}

/* Host id's jobs submitted, changes the change list's entries: the
 * answer in r, its JSON the output's (id, the jobs'). */
static void
r3_submit(const char *id, const char *changes, struct resp *r)
{
	char	*in;

	ATF_REQUIRE(asprintf(&in, "\"change\":[%s]", changes) != -1);
	r3_act(id, "/arcana-jobs:submit", in, r);
	free(in);
}

/* Host id's job n read: r's JSON its output. */
static void
r3_job(const char *id, const char *n, struct resp *r)
{
	char	below[96];

	snprintf(below, sizeof(below), "/arcana-jobs:jobs/job=%s/read", n);
	r3_act(id, below, NULL, r);
	EXPECT(r, 200);
}

/* Host id's job n's title, in buf. */
static const char *
r3_title(const char *id, const char *n, char *buf, size_t len)
{
	struct resp	r;

	r3_job(id, n, &r);
	snprintf(buf, len, "%s", jstr(&r, "title") != NULL ? jstr(&r,
	    "title") : "");
	resp_free(&r);
	return (buf);
}

/* Host id's job n done, confirmed where it waits for that: r's JSON its
 * read's output. */
static void
r3_job_wait(const char *id, const char *n, struct resp *r)
{
	char	below[96];
	int	i;

	for (i = 0; i < 200; i++) {
		r3_job(id, n, r);
		if (jstr(r, "state") != NULL && strcmp(jstr(r, "state"),
		    "done") == 0)
			return;
		if (jstr(r, "state") != NULL && strcmp(jstr(r, "state"),
		    "unconfirmed") == 0) {
			struct resp	c;

			snprintf(below, sizeof(below), "/arcana-jobs:jobs/"
			    "job=%s/confirm", n);
			r3_act(id, below, NULL, &c);
			resp_free(&c);
		}
		resp_free(r);
		usleep(50000);
	}
	ATF_REQUIRE_MSG(false, "job %s did not finish", n);
}

/* Host id's safe if-address job of addr, confirmed: the timer it says. */
static int
r3_safe_timer(const char *id, const char *addr)
{
	struct resp	 r;
	char		 ch[160], n[16];
	const char	*t;
	int		 timer = -1;

	snprintf(ch, sizeof(ch), "{\"if-address\":{\"interface\":\"lo0\","
	    "\"address\":\"%s\"},\"safe\":true}", addr);
	r3_submit(id, ch, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_MSG(jstr(&r, "id.0") != NULL, "%s", r.body);
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.0"));
	resp_free(&r);
	r3_job_wait(id, n, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	if ((t = strstr(r.body, "the timer was ")) != NULL)
		timer = atoi(t + strlen("the timer was "));
	ATF_CHECK_MSG(timer > 0, "%s", r.body);
	resp_free(&r);
	return (timer);
}

CONSOLE_TC(services, "Services listed, acted on and configured through "
    "arcana-services: a GET, its actions, its configuration committed with "
    "the warnings accepted")
ATF_TC_BODY(services, tc)
{
	struct authn	a;
	struct resp	r;
	char		id[16], path[512], body[MAXPATHLEN], n[16], t[160];
	char		cand[256];
	int		i;

	start(tc, 0, NULL);
	enrol(&a);
	r3_host("here", "jgd.sock", id, sizeof(id));
	snprintf(cand, sizeof(cand), "/restconf/ds/ietf-datastores:candidate/"
	    "arcana-fleet:fleet/host=%s", id);

	r3_read(id, "/arcana-services:services", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("ntpd", jstr(&r, "service.0.name"));
	ATF_CHECK_STREQ("false", jstr(&r, "service.0.enabled"));
	ATF_CHECK_STREQ("sshd", jstr(&r, "service.1.name"));
	ATF_CHECK_STREQ("true", jstr(&r, "service.1.enabled"));
	ATF_CHECK_STREQ("false", jstr(&r, "service.1.running"));
	resp_free(&r);

	r3_act(id, "/arcana-services:services/service=sshd/start", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "running") != NULL && strcmp(jstr(&r,
	    "running"), "true") == 0, "%s", r.body);
	ATF_CHECK_STREQ("7", jstr(&r, "pid"));
	resp_free(&r);
	r3_act(id, "/arcana-services:services/service=sshd/dance", NULL, &r);
	ATF_CHECK_MSG(r.status == 404 || r.status == 400, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	/* Enabled: a commit, refused for what it has not accepted, the
	 * warning named; with it accepted, Arcana's rc.conf file has it. */
	snprintf(path, sizeof(path), "%s/arcana-services:services/"
	    "service=ntpd", cand);
	http("PATCH", path, "{\"arcana-services:service\":[{\"name\":\"ntpd\","
	    "\"enabled\":true}]}", &r);
	ATF_CHECK_MSG(r.status == 204, "%d %s", r.status, r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), FLEET "%s/ietf-netconf:commit", id);
	http("POST", path, "{}", &r);
	ATF_CHECK_MSG(r.status >= 400 && strstr(r.body,
	    "\"error-app-tag\":\"rc-conf-files\"") != NULL, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	r3_read(id, "/arcana-services:services/service=ntpd", &r);
	ATF_CHECK_STREQ("false", jstr(&r, "0.enabled"));
	resp_free(&r);
	snprintf(path, sizeof(path), FLEET "%s/ietf-netconf:commit?"
	    "arcana-accept=rc-conf-files", id);
	http("POST", path, "{}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	r3_read(id, "/arcana-services:services/service=ntpd", &r);
	ATF_CHECK_STREQ("true", jstr(&r, "0.enabled"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^ntpd_enable=\"YES\"$' "
	    "root/usr/local/etc/rc.conf.d/arcana") == 0);

	r3_read(id, "/arcana-services:services/service=sshd", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "{\"name\":\"sshd_flags\",\"value\":"
	    "\"-4\"}") != NULL, "%s", r.body);
	resp_free(&r);
	r3_act(id, "/arcana-services:services/service=sshd/read", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("The sshd daemon.", jstr(&r, "description"));
	ATF_CHECK_STREQ("reload", jstr(&r, "command.0"));
	ATF_CHECK_STREQ("true", jstr(&r, "enabled"));
	resp_free(&r);
	/* Yours sets it: a warning, then a value to merge; Arcana's file
	 * has it once both are accepted, yours as it is. */
	snprintf(path, sizeof(path), "%s/arcana-services:services/"
	    "service=sshd", cand);
	http("PATCH", path, "{\"arcana-services:service\":[{\"name\":\"sshd\","
	    "\"variable\":[{\"name\":\"sshd_flags\",\"value\":\"-6\"}]}]}", &r);
	ATF_CHECK_MSG(r.status == 204, "%d %s", r.status, r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), FLEET "%s/ietf-netconf:commit", id);
	http("POST", path, "{}", &r);
	ATF_CHECK_MSG(r.status >= 400 && strstr(r.body,
	    "\"error-app-tag\":\"rc-conf-conflict\"") != NULL, "%d %s",
	    r.status, r.body);
	resp_free(&r);
	r3_read(id, "/arcana-services:services/service=sshd", &r);
	ATF_CHECK_MSG(strstr(r.body, "{\"name\":\"sshd_flags\",\"value\":"
	    "\"-4\"}") != NULL, "%s", r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), FLEET "%s/ietf-netconf:commit?"
	    "arcana-accept=rc-conf-conflict", id);
	http("POST", path, "{}", &r);
	ATF_CHECK_MSG(r.status >= 400 && strstr(r.body,
	    "\"error-app-tag\":\"rc-conf-merge\"") != NULL, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), FLEET "%s/ietf-netconf:commit?"
	    "arcana-accept=rc-conf-conflict,rc-conf-merge", id);
	http("POST", path, "{}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	r3_read(id, "/arcana-services:services/service=sshd", &r);
	ATF_CHECK_MSG(strstr(r.body, "{\"name\":\"sshd_flags\",\"value\":"
	    "\"-6\"}") != NULL, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^sshd_flags=\"-6\"$' "
	    "root/usr/local/etc/rc.conf.d/arcana && grep -q "
	    "'^sshd_flags=\"-4\"$' root/etc/rc.conf") == 0);
	/* Another service's variable is not sshd's. */
	ATF_CHECK(r3_commit(id, "/arcana-services:services/service=sshd",
	    "{\"arcana-services:service\":[{\"name\":\"sshd\",\"variable\":[{"
	    "\"name\":\"ntpd_flags\",\"value\":\"x\"}]}]}", &r) >= 400);
	ATF_CHECK_MSG(strstr(r.body, "not a variable") != NULL, "%s", r.body);
	resp_free(&r);

	/* Usage figures: real sysctls, a zpool(8) that may not be there. */
	r3_read(id, "/arcana-host:host/stats", &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "cpu") != NULL);
	ATF_CHECK_MSG(jstr(&r, "memory-total") != NULL && atoll(jstr(&r,
	    "memory-total")) > 0, "%s", r.body);
	resp_free(&r);

	/* A dry run: the steps the job would take, said by the agent,
	 * service(8)'s start not run; a job's undo with none waiting, or
	 * a body that is neither, refused. */
	(void)unlink("running.ntpd");
	r3_act(id, "/arcana-jobs:dry-run", "\"change\":[{\"service-action\":{"
	    "\"service\":\"ntpd\",\"action\":\"start\"}}]", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("daemon", jstr(&r, "step.0.kind"));
	ATF_CHECK_STREQ("arcana-agent", jstr(&r, "step.0.label"));
	ATF_CHECK_STREQ("-1", jstr(&r, "step.0.parent"));
	ATF_CHECK_MSG(strstr(r.body, "\"detail\":\"not run: a dry run\"") !=
	    NULL && strstr(r.body, "fake-service ntpd start\"") != NULL, "%s",
	    r.body);
	resp_free(&r);
	ATF_CHECK(access("running.ntpd", F_OK) == -1);
	r3_act(id, "/arcana-jobs:dry-run", "\"undo\":424242", &r);
	ATF_CHECK_MSG(r.status >= 400 && strstr(r.body, "no such job") != NULL,
	    "%d %s", r.status, r.body);
	resp_free(&r);
	r3_act(id, "/arcana-jobs:dry-run", "\"undo\":\"x\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/* Jobs: a batch is queued, runs in order, and can be read back. */
	r3_submit(id, "{\"service-action\":{\"service\":\"sshd\",\"action\":"
	    "\"stop\"}},{\"jail-action\":{\"jail\":\"web\",\"action\":"
	    "\"start\"}}", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_MSG(jstr(&r, "id.1") != NULL, "%s", r.body);
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.0"));
	ATF_CHECK_STREQ("service sshd stop", r3_title(id, n, t, sizeof(t)));
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.1"));
	resp_free(&r);
	ATF_CHECK_STREQ("start web", r3_title(id, n, t, sizeof(t)));
	r3_job_wait(id, n, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_MSG(strstr(r.body, "start web") != NULL, "%s", r.body);
	resp_free(&r);
	r3_read(id, "/arcana-jobs:jobs", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("done", jstr(&r, "job.0.state"));
	ATF_CHECK_STREQ("done", jstr(&r, "job.1.state"));
	resp_free(&r);
	/* Done: no cancelling it. */
	snprintf(path, sizeof(path), "/arcana-jobs:jobs/job=%s/cancel", n);
	r3_act(id, path, NULL, &r);
	ATF_CHECK_MSG(r.status >= 400 || (jstr(&r, "state") != NULL &&
	    strcmp(jstr(&r, "state"), "done") == 0), "%d %s", r.status,
	    r.body);
	resp_free(&r);
	r3_submit(id, "{\"dance\":{}}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	r3_submit(id, "{\"jail-action\":{\"jail\":\"../x\",\"action\":"
	    "\"start\"}}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);

	/* Packages: pending upgrades, a dry run, an upgrade of one. */
	r3_act(id, "/arcana-packages:packages/refresh", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("aria2", jstr(&r, "package.0.name"));
	ATF_CHECK_STREQ("1.37.0_2", jstr(&r, "package.0.available"));
	ATF_CHECK_STREQ("pimd", jstr(&r, "package.1.name"));
	resp_free(&r);
	/* db, never started, does not run. */
	r3_act(id, "/arcana-jails:jails/jail=db/arcana-packages:packages/read",
	    NULL, &r);
	ATF_CHECK_MSG(r.status >= 400 && strstr(r.body, "not running") !=
	    NULL, "%d %s", r.status, r.body);
	resp_free(&r);
	r3_act(id, "/arcana-packages:packages/upgrade", "\"name\":[\"pimd\"],"
	    "\"dry-run\":true", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("pimd", jstr(&r, "package.1.name"));
	resp_free(&r);
	/* From one of pkg's repositories (pkg upgrade -r); one it has not,
	 * refused by the agent. */
	r3_act(id, "/arcana-packages:packages/upgrade", "\"name\":[\"pimd\"],"
	    "\"dry-run\":true,\"repository\":\"builder\"", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^upgrade -r builder -n pimd$' pkg.log") ==
	    0);
	r3_act(id, "/arcana-packages:packages/upgrade", "\"dry-run\":true,"
	    "\"repository\":\"nosuch\"", &r);
	ATF_CHECK_MSG(r.status >= 400 && strstr(r.body,
	    "pkg has no repository nosuch") != NULL, "%d %s", r.status, r.body);
	resp_free(&r);
	r3_act(id, "/arcana-packages:packages/upgrade", "\"name\":[\"pimd\"]",
	    &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("1", jstr(&r, "upgraded"));
	ATF_CHECK(jstr(&r, "package.1.name") == NULL);
	ATF_CHECK_STREQ("aria2", jstr(&r, "package.0.name"));
	resp_free(&r);
	r3_act(id, "/arcana-jails:jails/jail=..%2Fx/arcana-packages:packages/"
	    "upgrade", NULL, &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);

	/* The network tables: the kernel's routes, inside ours. */
	r3_act(id, "/arcana-network:network/routes", "\"family\":\"inet\"",
	    &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "rt-family.0.rt-entry.0.destination") != NULL &&
	    strcmp(jstr(&r, "rt-family.0.rt-entry.0.destination"),
	    "default") == 0, "%s", r.body);
	resp_free(&r);

	/* The routes searched on the host: the text goes through, and
	 * what is not a text to search for is refused. */
	r3_act(id, "/arcana-network:network/routes", "\"family\":\"inet\","
	    "\"filter\":\"10.0.0.\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "total") != NULL);
	resp_free(&r);

	/* The interfaces, read by the agent itself, and by the standard
	 * models; and a change to one, which is a job that runs
	 * ifconfig(8). */
	r3_act(id, "/arcana-network:network/interfaces", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "interfaces.0.name") != NULL);
	ATF_CHECK(jstr(&r, "interfaces.0.up") != NULL);
	snprintf(t, sizeof(t), "\"name\":\"%s\"", jstr(&r,
	    "interfaces.0.name"));
	resp_free(&r);
	r3_read(id, "/ietf-interfaces:interfaces", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, t) != NULL, "%s: %s", t, r.body);
	resp_free(&r);
	/* The agent's YANG data, the nodes named, as RFC 7951's JSON. */
	r3_read(id, "/arcana-sysctl:sysctl?fields=value(name)", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "value.0.name") != NULL, "%.600s", r.body);
	resp_free(&r);
	r3_read(id, "/nowhere:nowhere", &r);
	ATF_CHECK_MSG(r.status == 404 || r.status == 400, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	/* The drift: the operational configuration against running, each
	 * row a node with its api-path; what the host has beyond running
	 * says where it came from (the agent's rc.conf is a fake's:
	 * every address of the host is beyond it). */
	snprintf(path, sizeof(path), CC "hosts/host=%s/drift", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(resp_unwrap(&r, "arcana-console:drift"));
	ATF_CHECK_MSG(jstr(&r, "drift.0.path") != NULL &&
	    jstr(&r, "drift.0.path")[0] == '/' &&
	    jstr(&r, "drift.0.kind") != NULL, "%.600s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"extra\"") != NULL &&
	    strstr(r.body, "\"origin\":\"") != NULL, "%.600s", r.body);
	resp_free(&r);
	r3_submit(id, "{\"if-address\":{\"interface\":\"lo0\",\"address\":"
	    "\"10.9.0.5/24\"}},{\"if-state\":{\"interface\":\"lo0\",\"up\":"
	    "true}}", &r);
	EXPECT(&r, 200);
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.0"));
	ATF_CHECK_STREQ("lo0: add 10.9.0.5/24", r3_title(id, n, t, sizeof(t)));
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.1"));
	ATF_CHECK_STREQ("lo0: up", r3_title(id, n, t, sizeof(t)));
	resp_free(&r);
	for (i = 0; i < 100 && access("ifconfig.log", F_OK) == -1; i++)
		usleep(50000);
	usleep(300000);
	ATF_CHECK(system("grep -q '^lo0 inet 10.9.0.5/24 alias$' ifconfig.log "
	    "&& grep -q '^lo0 up$' ifconfig.log") == 0);
	r3_submit(id, "{\"if-state\":{\"interface\":\"lo0\"}}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);

	/*
	 * The host's rollback timer: kept with the host, refused out of
	 * its range, and sent with each safe change.
	 */
	r3_host_set(id, "\"safe-wait\":5", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	r3_host_set(id, "\"safe-wait\":15", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	snprintf(path, sizeof(path), CC "hosts/host=%s", id);
	http("GET", path, NULL, &r);
	ATF_CHECK_STREQ("15", jstr(&r, "arcana-console:host.0.safe-wait"));
	resp_free(&r);
	/* Which repository each pkg action takes from, per jail: kept
	 * with the host, as given; the shape is checked. */
	r3_host_set(id, "\"pkg-repos\":[{\"jail\":\".\",\"upgrade\":\"mine\"},"
	    "{\"jail\":\"web\",\"install\":\"\",\"base\":\"FreeBSD-base\"}]",
	    &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", path, NULL, &r);
	ATF_CHECK_MSG(strstr(r.body, "\"base\":\"FreeBSD-base\"") != NULL,
	    "%s", r.body);
	ATF_CHECK_STREQ("15", jstr(&r, "arcana-console:host.0.safe-wait"));
	resp_free(&r);
	r3_host_set(id, "\"pkg-repos\":[{\"jail\":\"web\",\"remove\":\"x\"}]",
	    &r);
	EXPECT(&r, 400);
	resp_free(&r);
	r3_host_set(id, "\"pkg-repos\":{}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("GET", CC "hosts", NULL, &r);
	ATF_CHECK_MSG(strstr(r.body, "\"base\":\"FreeBSD-base\"") != NULL,
	    "%s", r.body);
	resp_free(&r);

	/*
	 * A safe change waits to hear from the console again; confirmed,
	 * the change stays.
	 */
	ATF_CHECK_EQ(15, r3_safe_timer(id, "10.9.0.6/24"));
	snprintf(path, sizeof(path), CC "hosts/host=%s/safe-wait", id);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	snprintf(path, sizeof(path), CC "hosts/host=%s", id);
	http("GET", path, NULL, &r);
	ATF_CHECK(jstr(&r, "arcana-console:host.0.safe-wait") == NULL);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^lo0 inet 10.9.0.6/24 alias$' ifconfig.log "
	    "&& ! grep -q '10.9.0.6 -alias' ifconfig.log") == 0);
	/* None of its own: Settings' for every host goes with the change. */
	r3_settings("\"safe-wait\":5", 400);
	r3_settings("\"safe-wait\":25", 204);
	ATF_CHECK_EQ(25, r3_safe_timer(id, "10.9.0.7/24"));
	r3_unset("safe-wait");

	/* A static route, added and deleted with route(8). */
	r3_submit(id, "{\"route\":{\"destination\":\"10.77.0.0/16\","
	    "\"gateway\":\"10.0.0.1\"}},{\"route\":{\"destination\":"
	    "\"10.77.0.0/16\",\"remove\":true}}", &r);
	EXPECT(&r, 200);
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.0"));
	ATF_CHECK_STREQ("route add 10.77.0.0/16 via 10.0.0.1", r3_title(id, n,
	    t, sizeof(t)));
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.1"));
	ATF_CHECK_STREQ("route delete 10.77.0.0/16", r3_title(id, n, t,
	    sizeof(t)));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q route-del route.log 2>/dev/null") !=
	    0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^0 route-add 10.77.0.0/16 10.0.0.1 - 0 0 0 "
	    "-$' route.log && grep -q '^0 route-del 10.77.0.0/16 - - 0 0$' "
	    "route.log")
	    == 0);
	r3_submit(id, "{\"route\":{\"destination\":\"10.77.0.0/16\"}}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);

	/*
	 * A tunnel made, an MTU set, a route in a routing table of its
	 * own, a netgraph hook: each a job with what it needs.
	 */
	r3_submit(id, "{\"if-create\":{\"interface\":\"gif3\",\"tunnel-local\":"
	    "\"192.0.2.1\",\"tunnel-remote\":\"192.0.2.2\",\"address\":"
	    "\"10.255.0.1/30\",\"destination\":\"10.255.0.2\",\"mtu\":1400,"
	    "\"description\":\"to lab\"}},{\"if-set\":{\"interface\":\"lo0\","
	    "\"mtu\":9000}},{\"route\":{\"destination\":\"10.88.0.0/16\","
	    "\"gateway\":\"10.0.0.1\",\"fib\":2}},{\"netgraph\":{\"verb\":"
	    "\"mkpeer\",\"args\":[\"em0:\",\"bridge\",\"lower\",\"link0\"]}},"
	    "{\"if-destroy\":{\"interface\":\"gif3\"}}", &r);
	EXPECT(&r, 200);
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.0"));
	ATF_CHECK_STREQ("create gif3 to 192.0.2.2 with 10.255.0.1/30",
	    r3_title(id, n, t, sizeof(t)));
	resp_free(&r);
	r3_job(id, n, &r);
	ATF_CHECK_STREQ("if-create", jstr(&r, "kind"));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q 'gif3 destroy' ifconfig.log "
	    "2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^gif3 tunnel 192.0.2.1 192.0.2.2$' "
	    "ifconfig.log && grep -q '^gif3 inet 10.255.0.1/30 10.255.0.2$' "
	    "ifconfig.log && grep -q '^gif3 description to lab$' ifconfig.log "
	    "&& grep -q '^lo0 mtu 9000$' ifconfig.log && grep -q "
	    "'^0 route-add 10.88.0.0/16 10.0.0.1 - 2 0 0 -$' route.log && "
	    "grep -q '^mkpeer em0: bridge lower link0$' ngctl.log") == 0);
	/* What ngctl is not to be given the agent refuses to queue. */
	r3_submit(id, "{\"netgraph\":{\"verb\":\"msg\",\"args\":[\"em0:\","
	    "\"x\"]}}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q msg ngctl.log") != 0);

	/* The route to an address, and the netgraph nodes. */
	r3_act(id, "/arcana-network:network/lookup", "\"address\":"
	    "\"10.77.5.5\",\"fib\":1", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("10.0.0.1", jstr(&r, "best.gateway"));
	ATF_CHECK_STREQ("em0", jstr(&r, "best.interface"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^--scope-helper 0 route-get 10.77.5.5 1$' helper.log")
	    == 0);
	/* Not an address. */
	r3_act(id, "/arcana-network:network/lookup", "\"address\":"
	    "\"10.0.0.1;id\"", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);
	r3_act(id, "/arcana-netgraph:netgraph/read", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("em0", jstr(&r, "node.0.name"));
	ATF_CHECK_STREQ("bridge0", jstr(&r, "node.0.hook.0.peer"));
	resp_free(&r);

	/*
	 * A jail with a network of its own: read and changed through its
	 * host, by naming the jail.
	 */
	r3_act(id, "/arcana-network:network/interfaces", "\"jail\":\"gw\"",
	    &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("epair1b", jstr(&r, "interfaces.0.name"));
	ATF_CHECK_STREQ("10.99.0.2", jstr(&r,
	    "interfaces.0.addresses.0.address"));
	resp_free(&r);
	r3_act(id, "/arcana-network:network/lookup", "\"address\":"
	    "\"192.0.2.9\",\"jail\":\"gw\"", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^--scope-helper 4 route-get 192.0.2.9 0$' helper.log")
	    == 0);
	r3_act(id, "/arcana-network:network/interfaces", "\"jail\":\"a;b\"",
	    &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);
	/* A jail without one has none to show. */
	r3_act(id, "/arcana-network:network/interfaces", "\"jail\":\"web\"",
	    &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);
	r3_submit(id, "{\"if-address\":{\"jail\":\"gw\",\"interface\":"
	    "\"epair1b\",\"address\":\"10.99.0.5/24\",\"persist\":true}}", &r);
	EXPECT(&r, 200);
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.0"));
	ATF_CHECK_STREQ("gw: epair1b: add 10.99.0.5/24", r3_title(id, n, t,
	    sizeof(t)));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q 'alias0' jroot/etc/rc.conf "
	    "2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^-j 4 epair1b inet 10.99.0.5/24 alias$' "
	    "ifconfig.log && grep -q '^ifconfig_epair1b_alias0=\"inet "
	    "10.99.0.5/24\"$' jroot/etc/rc.conf && ! grep -q 10.99.0.5 "
	    "rc.conf") == 0);

	/*
	 * WireGuard: the host makes the key, and the console is told the
	 * public one; a peer is given to it.  BIRD: its protocols, and
	 * one of them restarted.
	 */
	r3_submit(id, "{\"wireguard\":{\"interface\":\"wg0\",\"verb\":\"init\","
	    "\"listen-port\":51820}},{\"wireguard\":{\"interface\":\"wg0\","
	    "\"verb\":\"peer\",\"peer\":"
	    "\"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\",\"endpoint\":"
	    "\"192.0.2.9:51820\",\"allowed-ips\":\"10.9.9.2/32\",\"keepalive\":"
	    "25}},{\"bird\":{\"verb\":\"restart\",\"args\":[\"bgp_core\"]}},"
	    "{\"bird\":{\"verb\":\"configure\"}}", &r);
	EXPECT(&r, 200);
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.0"));
	ATF_CHECK_STREQ("wg0: wireguard init", r3_title(id, n, t, sizeof(t)));
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.2"));
	ATF_CHECK_STREQ("bird restart bgp_core", r3_title(id, n, t,
	    sizeof(t)));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q '^configure$' birdc.log "
	    "2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^set wg0 listen-port 51820$' wg.log && "
	    "grep -q '^set wg0 peer xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg= "
	    "endpoint 192.0.2.9:51820 allowed-ips 10.9.9.2/32 "
	    "persistent-keepalive 25$' wg.log && grep -q '^restart bgp_core$' "
	    "birdc.log") == 0);
	r3_submit(id, "{\"wireguard\":{\"interface\":\"wg0\",\"verb\":\"peer\","
	    "\"peer\":\"short\"}}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);
	r3_act(id, "/arcana-wireguard:wireguard/read", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "interface.0.private-key"));
	ATF_CHECK_STREQ("HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=",
	    jstr(&r, "interface.0.public-key"));
	ATF_CHECK_STREQ("192.0.2.9:51820", jstr(&r,
	    "interface.0.peer.0.endpoint"));
	/* The key the host made is nowhere in what the console says. */
	ATF_CHECK(system("test -s wg.key") == 0);
	{
		char key[64];
		FILE *fp;

		ATF_REQUIRE((fp = fopen("wg.key", "r")) != NULL);
		ATF_REQUIRE(fgets(key, sizeof(key), fp) != NULL);
		fclose(fp);
		key[strcspn(key, "\n")] = '\0';
		ATF_CHECK(strstr(r.body, key) == NULL);
	}
	resp_free(&r);

	/*
	 * IPsec: the host makes its key and tells its public half; a
	 * connection is written for it, IKEv2, and read back.
	 */
	r3_submit(id, "{\"ipsec\":{\"verb\":\"init\"}}", &r);
	EXPECT(&r, 200);
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.0"));
	ATF_CHECK_STREQ("ipsec init", r3_title(id, n, t, sizeof(t)));
	resp_free(&r);
	for (i = 0; i < 100 && system("test -s swanctl/pubkey/arcana.pub") !=
	    0; i++)
		usleep(50000);
	r3_act(id, "/arcana-network:network/ipsec", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "public-key") != NULL);
	ATF_CHECK(strlen(jstr(&r, "public-key")) > 80);
	ATF_CHECK(strstr(r.body, "PRIVATE") == NULL);
	snprintf(body, sizeof(body), "{\"ipsec\":{\"verb\":\"conn\",\"conn\":"
	    "\"to-lab2\",\"tunnel-local\":\"192.0.2.1\",\"tunnel-remote\":"
	    "\"192.0.2.2\",\"ipsec-mode\":\"transport\",\"pubkey\":\"%s\","
	    "\"local-ts\":\"192.0.2.1[gre]\",\"remote-ts\":\"192.0.2.2[gre]\","
	    "\"start-action\":\"start\"}}", jstr(&r, "public-key"));
	resp_free(&r);
	r3_submit(id, body, &r);
	EXPECT(&r, 200);
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.0"));
	ATF_CHECK_STREQ("ipsec conn to-lab2 (transport)", r3_title(id, n, t,
	    sizeof(t)));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q 'version = 2' "
	    "swanctl/conf.d/arcana-to-lab2.conf 2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q 'mode = transport' "
	    "swanctl/conf.d/arcana-to-lab2.conf") == 0);
	r3_act(id, "/arcana-network:network/ipsec", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("to-lab2", jstr(&r, "connections.0.name"));
	ATF_CHECK_STREQ("true", jstr(&r, "connections.0.arcana"));
	ATF_CHECK_STREQ("INSTALLED", jstr(&r, "sas.0.children.0.state"));
	resp_free(&r);
	/* A connection is named, but for init and start. */
	r3_submit(id, "{\"ipsec\":{\"verb\":\"up\"}}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);
	r3_act(id, "/arcana-bird:bird/read", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("Router ID is 192.0.2.1", jstr(&r, "status.1"));
	ATF_CHECK_STREQ("bgp_core", jstr(&r, "protocol.1.name"));
	ATF_CHECK_MSG(strstr(r.body, "\"Established\"") != NULL && strstr(
	    r.body, "\"192.0.2.1\"") != NULL && strstr(r.body, "65001") !=
	    NULL && strstr(r.body, "\"bgp_in\"") != NULL && strstr(r.body,
	    "845233") != NULL && strstr(r.body, "\"10.0.0.2\"") != NULL &&
	    strstr(r.body, "\"r4\"") != NULL, "%s", r.body);
	resp_free(&r);

	/*
	 * BIRD's configuration: read with its checksum, put back changed
	 * once bird(8) has parsed it; what it refuses does not stay.
	 */
	r3_read(id, "/arcana-bird:bird/configuration", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_MSG(jstr(&r, "file.0.text") != NULL, "%s", r.body);
	ATF_CHECK(strstr(jstr(&r, "file.0.text"), "filter bgp_in") != NULL);
	ATF_CHECK(strstr(jstr(&r, "file.0.path"), "/bird/bird.conf") != NULL);
	snprintf(t, sizeof(t), "%s", jstr(&r, "file.0.path"));
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"arcana-bird:configuration\":{\"file\":"
	    "[{\"path\":\"%s\",\"text\":\"router id 192.0.2.9;\\nprotocol "
	    "device {\\n}\\n\"}]}}", t);
	ATF_CHECK_EQ(204, r3_commit(id, "/arcana-bird:bird/configuration",
	    body, &r));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^router id 192.0.2.9;$' bird/bird.conf && "
	    "grep -q 'filter bgp_in' bird/bird.conf.arcana-old && "
	    "grep -q '^configure$' birdc.log") == 0);
	snprintf(body, sizeof(body), "{\"arcana-bird:configuration\":{\"file\":"
	    "[{\"path\":\"%s\",\"text\":\"BROKEN\\n\"}]}}", t);
	ATF_CHECK(r3_commit(id, "/arcana-bird:bird/configuration", body, &r) >=
	    400);
	ATF_CHECK_MSG(strstr(r.body, "syntax error") != NULL, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q BROKEN bird/bird.conf") != 0);
	/* Checked, not kept: bird(8) parses it. */
	snprintf(body, sizeof(body), "\"path\":\"%s\",\"text\":\"BROKEN\\n\"",
	    t);
	r3_act(id, "/arcana-bird:bird/check", body, &r);
	ATF_CHECK_MSG(strstr(r.body, "syntax error") != NULL, "%d %s",
	    r.status, r.body);
	resp_free(&r);
	r3_act(id, "/arcana-bird:bird/check", "\"path\":\"/etc/../etc/passwd\","
	    "\"text\":\"x\"", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);

	/*
	 * Committed confirmed, BIRD is told to take the change back by
	 * itself; the confirmation makes it stay.
	 */
	snprintf(body, sizeof(body), "{\"arcana-bird:configuration\":{\"file\":"
	    "[{\"path\":\"%s\",\"text\":\"router id 192.0.2.10;\\nprotocol "
	    "device {\\n}\\n\"}]}}", t);
	snprintf(path, sizeof(path), "%s/arcana-bird:bird/configuration", cand);
	http("PATCH", path, body, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	snprintf(path, sizeof(path), FLEET "%s/ietf-netconf:commit", id);
	http("POST", path, "{\"ietf-netconf:input\":{\"confirmed\":[null],"
	    "\"confirm-timeout\":60,\"persist\":\"bird1\"}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	/* A confirmed commit of a minute, BIRD's timer a little longer. */
	ATF_CHECK(system("grep -q '^configure timeout 65$' birdc.log") == 0);
	http("POST", path, "{\"ietf-netconf:input\":{\"persist-id\":"
	    "\"bird1\"}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	/* The commit confirmed, BIRD is told so in a moment. */
	ATF_CHECK(system("for i in $(seq 1 40); do grep -q '^configure "
	    "confirm$' birdc.log && break; sleep 0.1; done; grep -q "
	    "'^configure confirm$' birdc.log && grep -q "
	    "'^router id 192.0.2.10;$' bird/bird.conf") == 0);
	http("POST", path, "{\"ietf-netconf:input\":{\"persist-id\":"
	    "\"bird1\"}}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);

	/*
	 * The kernel: what is linked into it, read from the kernel, and
	 * what its memory went to; a module loaded by a job.
	 */
	r3_read(id, "/arcana-kernel:kernel", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("kernel", jstr(&r, "file.0.name"));
	ATF_CHECK(jstr(&r, "file.0.size") != NULL);
	ATF_CHECK(jstr(&r, "file.0.module.0") != NULL);
	ATF_CHECK(jstr(&r, "memory.malloc.0.name") != NULL);
	ATF_CHECK(jstr(&r, "memory.zone.0.size") != NULL);
	resp_free(&r);
	r3_submit(id, "{\"kmod\":{\"verb\":\"load\",\"args\":[\"sctp\"],"
	    "\"persist\":true}}", &r);
	EXPECT(&r, 200);
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.0"));
	ATF_CHECK_STREQ("kldload sctp (kept)", r3_title(id, n, t, sizeof(t)));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q 'kld_list' rc.conf "
	    "2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^kldload -n sctp$' kld.log && grep -q "
	    "'^kld_list=\"sctp\"$' rc.conf") == 0);
	/* A name is a name, and a verb one of the two. */
	r3_submit(id, "{\"kmod\":{\"verb\":\"load\",\"args\":"
	    "[\"/tmp/evil.ko\"]}}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);
	r3_submit(id, "{\"kmod\":{\"verb\":\"load\"}}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);

	/*
	 * The kernel's state: from a name on, with what is kept for the
	 * next boot; one set by a job, and kept.
	 */
	r3_act(id, "/arcana-sysctl:sysctl/read", "\"prefix\":\"kern.ostype\"",
	    &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("kern.ostype", jstr(&r, "value.0.name"));
	ATF_CHECK_STREQ("FreeBSD", jstr(&r, "value.0.value"));
	ATF_CHECK_STREQ("false", jstr(&r, "value.0.writable"));
	resp_free(&r);
	r3_read(id, "/arcana-sysctl:sysctl?fields=kept", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("kern.ipc.somaxconn", jstr(&r, "kept.0.name"));
	ATF_CHECK_STREQ("1024", jstr(&r, "kept.0.value"));
	resp_free(&r);
	r3_act(id, "/arcana-sysctl:sysctl/read", "\"prefix\":\"kern,x\"", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);
	r3_submit(id, "{\"sysctl\":{\"args\":[\"kern.ipc.somaxconn\","
	    "\"4096\"],\"persist\":true}}", &r);
	EXPECT(&r, 200);
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.0"));
	ATF_CHECK_STREQ("sysctl kern.ipc.somaxconn=4096 (kept)", r3_title(id,
	    n, t, sizeof(t)));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q '^kern.ipc.somaxconn=4096$' "
	    "sysctl.conf 2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^sysctl kern.ipc.somaxconn=4096$' kld.log "
	    "&& grep -q '^kern.ipc.somaxconn=4096$' sysctl.conf && grep -q "
	    "'^# kept$' sysctl.conf && ! grep -q 1024 sysctl.conf") == 0);
	r3_submit(id, "{\"sysctl\":{\"args\":[\"kern.hostname\"]}}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);

	/*
	 * What runs, a log and the history: read as the host says them;
	 * a process sent a signal by a job.
	 */
	r3_read(id, "/arcana-processes:processes", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "process.0.pid") != NULL && jstr(&r,
	    "process.0.state.wcpu") != NULL && jstr(&r,
	    "process.0.state.memory-usage") != NULL, "%.600s", r.body);
	ATF_CHECK(jstr(&r, "ncpu") != NULL);
	resp_free(&r);
	r3_act(id, "/arcana-log:logs/read", "\"name\":\"messages\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("messages", jstr(&r, "name"));
	ATF_CHECK_STREQ("auth.log", jstr(&r, "file.0.name"));
	ATF_CHECK_STREQ("kernel", jstr(&r, "line.0.tag"));
	ATF_CHECK_STREQ("sshd", jstr(&r, "line.1.tag"));
	ATF_CHECK_STREQ("812", jstr(&r, "line.1.pid"));
	ATF_CHECK_STREQ("cron", jstr(&r, "line.2.tag"));
	resp_free(&r);
	r3_act(id, "/arcana-log:logs/read", "\"name\":\"auth.log\",\"filter\":"
	    "\"bad su\",\"lines\":5", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("su", jstr(&r, "line.0.tag"));
	i = jstr(&r, "position") != NULL ? atoi(jstr(&r, "position")) : 0;
	ATF_CHECK(i > 0);
	resp_free(&r);
	snprintf(body, sizeof(body), "\"name\":\"auth.log\",\"position\":%d",
	    i);
	r3_act(id, "/arcana-log:logs/read", body, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "line.0.text") == NULL);
	resp_free(&r);
	r3_act(id, "/arcana-log:logs/read", "\"name\":\"messages\","
	    "\"jail\":\"gw\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "line.0.text") != NULL && strcmp(jstr(&r,
	    "line.0.text"), "the jail's own line") == 0);
	resp_free(&r);
	snprintf(path, sizeof(path), "/arcana-processes:processes/process=%d/"
	    "read", (int)getpid());
	r3_act(id, path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "thread.0.tid") != NULL, "%.600s", r.body);
	resp_free(&r);
	r3_act(id, "/arcana-log:logs/read", "\"name\":\"../rc.conf\"", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);
	sleep(2);
	r3_act(id, "/arcana-history:history/read", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("5", jstr(&r, "sampling.step"));
	ATF_CHECK(jstr(&r, "sample.0.cpu") != NULL);
	ATF_CHECK_STREQ("720", jstr(&r, "sampling.keep"));
	ATF_CHECK(jstr(&r, "bytes") != NULL);
	resp_free(&r);
	/* How it is sampled is set, and said back; not anyhow. */
	ATF_CHECK_EQ(204, r3_history(id, "\"sampling\":{\"step\":3,\"keep\":"
	    "100},\"limits\":{\"cpu\":95,\"memory\":80,\"swap\":10}"));
	r3_history_get(id, &r);
	ATF_CHECK_STREQ("3", jstr(&r, "sampling.step"));
	ATF_CHECK_STREQ("100", jstr(&r, "sampling.keep"));
	ATF_CHECK_STREQ("80", jstr(&r, "limits.memory"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^step=3$' history.conf && grep -q "
	    "'^keep=100$' history.conf") == 0);
	/* A file system's limit too, when said; without it, as it was. */
	ATF_CHECK_EQ(204, r3_history(id, "\"limits\":{\"storage\":85}"));
	ATF_CHECK_EQ(204, r3_history(id, "\"sampling\":{\"step\":3,\"keep\":"
	    "100},\"limits\":{\"cpu\":95,\"memory\":80,\"swap\":10}"));
	r3_history_get(id, &r);
	ATF_CHECK_STREQ("85", jstr(&r, "limits.storage"));
	resp_free(&r);
	ATF_CHECK_EQ(400, r3_history(id, "\"limits\":{\"storage\":101}"));
	ATF_CHECK_EQ(400, r3_history(id, "\"sampling\":{\"step\":0}"));
	ATF_CHECK_EQ(204, r3_history(id, "\"sampling\":{\"step\":5,\"keep\":"
	    "720}"));
	r3_act(id, "/arcana-history:history/read", "\"after\":"
	    "\"2999-01-01T00:00:00Z\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "sample.0.time") == NULL, "%.600s", r.body);
	resp_free(&r);
	/* What happened there: numbered, to be asked for from a number. */
	r3_act(id, "/arcana-events:events/read", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "last") != NULL);
	ATF_CHECK_STREQ("512", jstr(&r, "kept"));
	resp_free(&r);
	r3_act(id, "/arcana-events:events/read", "\"after\":99999999", &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "event.0.n") == NULL);
	resp_free(&r);
	/* Packets followed through the firewall by the kernel. */
	r3_act(id, "/arcana-firewall:firewall/trace", "\"address\":"
	    "\"10.0.0.2\",\"seconds\":2,\"packets\":5", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("pass", jstr(&r, "packet.0.verdict"));
	ATF_CHECK_STREQ("100", jstr(&r, "packet.0.rule"));
	ATF_CHECK_STREQ("in", jstr(&r, "packet.0.direction"));
	ATF_CHECK_STREQ("5", jstr(&r, "limit"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^tick-2s$' trace.d") == 0);
	r3_act(id, "/arcana-firewall:firewall/trace", "\"address\":"
	    "\"10.0.0.2;x\"", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);
	ATF_REQUIRE(system("sleep 300 & echo $! > sleep.pid") == 0);
	{
		char	what[256], pid[16];
		FILE	*fp;

		ATF_REQUIRE((fp = fopen("sleep.pid", "r")) != NULL);
		ATF_REQUIRE(fgets(pid, sizeof(pid), fp) != NULL);
		fclose(fp);
		pid[strcspn(pid, "\n")] = '\0';
		snprintf(what, sizeof(what), "{\"process\":{\"verb\":"
		    "\"signal\",\"args\":[\"%s\",\"TERM\"]}}", pid);
		r3_submit(id, what, &r);
		EXPECT(&r, 200);
		snprintf(n, sizeof(n), "%s", jstr(&r, "id.0"));
		snprintf(what, sizeof(what), "kill -TERM %s", pid);
		ATF_CHECK_STREQ(what, r3_title(id, n, t, sizeof(t)));
		resp_free(&r);
		/* Alive: there, and not a zombie (one no reaper waits for,
		 * as in a container, stays one). */
		snprintf(what, sizeof(what), "kill -0 %s 2>/dev/null && ! ps "
		    "-o state= -p %s | grep -q Z", pid, pid);
		for (i = 0; i < 100 && system(what) == 0; i++)
			usleep(50000);
		ATF_CHECK(system(what) != 0);
		r3_submit(id, "{\"process\":{\"verb\":\"signal\",\"args\":"
		    "[\"1\",\"TERM\"]}}", &r);
		ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
		resp_free(&r);
	}

	/*
	 * The firewall: its rules with their sets and counters, and the
	 * kept ones; a rule kept by a job; the kept rules read and
	 * checked.
	 */
	r3_read(id, "/arcana-firewall:firewall", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "state.loaded"));
	ATF_CHECK_STREQ("5", jstr(&r, "state.rule.0.number"));
	ATF_CHECK_STREQ("skipto 500 ip from any to any out", jstr(&r,
	    "state.rule.0.text"));
	ATF_CHECK_STREQ("900", jstr(&r, "state.rule.0.octets"));
	ATF_CHECK_STREQ("T46", jstr(&r, "state.table.0.name"));
	ATF_CHECK_STREQ("1002", jstr(&r, "kept.rule.3.number"));
	resp_free(&r);
	r3_submit(id, "{\"ipfw\":{\"verb\":\"add\",\"args\":[\"1003\","
	    "\"allow\",\"tcp\",\"from\",\"any\",\"to\",\"me6\",\"443\",\"in\"],"
	    "\"persist\":true,\"live\":true}},{\"ipfw\":{\"verb\":\"apply\"}}",
	    &r);
	EXPECT(&r, 200);
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.0"));
	ATF_CHECK_STREQ("ipfw add 1003 allow tcp from any to me6 443 in "
	    "(now, and kept)", r3_title(id, n, t, sizeof(t)));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q 'set swap 0 1' ipfw.log "
	    "2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^ipfw -q add 1003 allow tcp from any to "
	    "me6 443 in$' ipfw.log && grep -q '^add 01003 allow tcp from any "
	    "to me6 443 in$' ipfw.rules && grep -q '^add 01003 set 1 allow' "
	    "loaded.rules && grep -q '^ipfw -q set disable 1$' ipfw.log") ==
	    0);
	r3_submit(id, "{\"ipfw\":{\"verb\":\"add\",\"args\":[\"10\",\"allow\","
	    "\"ip;reboot\"],\"live\":true}}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);
	r3_read(id, "/arcana-firewall:firewall/kept", &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "text") != NULL && strstr(jstr(&r, "text"),
	    "add 01003 allow") != NULL);
	resp_free(&r);
	r3_act(id, "/arcana-firewall:firewall/check", "\"text\":\"add 00010 "
	    "allow ip from any to any\\nbogus\\n\"", &r);
	ATF_CHECK_MSG(strstr(r.body, "bogus") != NULL, "%d %s", r.status,
	    r.body);
	resp_free(&r);

	/*
	 * Bridges and geneve tunnels: what they are; a port made an
	 * access port by a job.
	 */
	r3_act(id, "/arcana-network:network/bridges", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bridge0", jstr(&r, "bridges.0.name"));
	ATF_CHECK_STREQ("true", jstr(&r, "bridges.0.vlanfilter"));
	ATF_CHECK_STREQ("root", jstr(&r, "bridges.0.members.0.role"));
	ATF_CHECK_STREQ("forwarding", jstr(&r, "bridges.0.members.0.state"));
	ATF_CHECK_STREQ("trunk", jstr(&r, "bridges.0.members.1.mode"));
	ATF_CHECK_STREQ("192.0.2.7", jstr(&r,
	    "bridges.0.members.1.addresses.0"));
	ATF_CHECK_STREQ("discarding", jstr(&r, "bridges.0.members.2.state"));
	resp_free(&r);
	r3_act(id, "/arcana-network:network/geneve", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("l2", jstr(&r, "geneves.0.mode"));
	ATF_CHECK_STREQ("100", jstr(&r, "geneves.0.id"));
	ATF_CHECK_STREQ("l3", jstr(&r, "geneves.1.mode"));
	ATF_CHECK_STREQ("inherit", jstr(&r, "geneves.1.ttl"));
	resp_free(&r);
	r3_submit(id, "{\"bridge\":{\"interface\":\"bridge0\",\"verb\":"
	    "\"access\",\"args\":[\"epair5a\",\"20\"]}},{\"geneve\":{"
	    "\"interface\":\"geneve7\",\"verb\":\"create\",\"args\":[\"mode\","
	    "\"l3\",\"id\",\"7\",\"local\",\"192.0.2.1\",\"remote\","
	    "\"192.0.2.2\"]}}", &r);
	EXPECT(&r, 200);
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.0"));
	ATF_CHECK_STREQ("bridge0 access epair5a 20", r3_title(id, n, t,
	    sizeof(t)));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q 'geneve7 create' ifconfig.log "
	    "2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^bridge0 ifuntagged epair5a 20 iftagged "
	    "epair5a none$' ifconfig.log && grep -q '^geneve7 create "
	    "genevemode l3 geneveid 7 genevelocal 192.0.2.1 geneveremote "
	    "192.0.2.2 up$' ifconfig.log") == 0);

	/*
	 * How the agent is reached: its listeners and who is connected.
	 * The console keeps its connection open: what it asks next goes
	 * over the same one, and the agent has seen no new connection.
	 */
	r3_transport(id, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("unix", jstr(&r, "data.listeners.0.transport"));
	ATF_CHECK_STREQ("true", jstr(&r, "data.listeners.0.up"));
	ATF_CHECK_STREQ("unix", jstr(&r, "data.sessions.0.transport"));
	ATF_CHECK(jstr(&r, "uri") != NULL && strncmp(jstr(&r, "uri"), "unix:",
	    5) == 0);
	{
		long	seen, after;

		seen = atol(jstr(&r, "data.seen"));
		resp_free(&r);
		for (i = 0; i < 6; i++) {
			r3_read(id, "/arcana-services:services", &r);
			EXPECT(&r, 200);
			resp_free(&r);
		}
		r3_transport(id, &r);
		after = atol(jstr(&r, "data.seen"));
		ATF_CHECK_MSG(after == seen, "the agent saw %ld connections, "
		    "then %ld after six more requests", seen, after);
		resp_free(&r);
	}
	/* A local socket has no other way to be reached. */
	r3_verb(id, "switch-transport", "\"transport\":\"sctp\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/*
	 * Storage: the pools with their devices, datasets, snapshots of
	 * one, the disks from the kernel, what is mounted; a snapshot
	 * taken by a job; fstab read and put back.
	 */
	r3_act(id, "/arcana-storage:storage/read", "\"kind\":\"pools\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("tank", jstr(&r, "pool.0.name"));
	ATF_CHECK_STREQ("DEGRADED", jstr(&r, "pool.0.health"));
	ATF_CHECK_STREQ("mirror-0", jstr(&r, "pool.0.vdev.1.name"));
	ATF_CHECK_STREQ("OFFLINE", jstr(&r, "pool.0.vdev.3.state"));
	resp_free(&r);
	r3_act(id, "/arcana-storage:storage/read", "\"kind\":\"importable\"",
	    &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("spare", jstr(&r, "importable.0.name"));
	ATF_CHECK_STREQ("1234567890", jstr(&r, "importable.0.id"));
	resp_free(&r);
	r3_act(id, "/arcana-storage:storage/read", "\"kind\":\"datasets\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("tank/data", jstr(&r, "dataset.1.name"));
	ATF_CHECK_STREQ("8000000", jstr(&r, "dataset.1.quota"));
	resp_free(&r);
	/* A jail's: what its own zfs sees, by jexec; one that does not
	 * run (db) has none; and of a jail, datasets and snapshots only. */
	r3_act(id, "/arcana-storage:storage/read", "\"kind\":\"datasets\","
	    "\"jail\":\"gw\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("tank/data", jstr(&r, "dataset.1.name"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^jexec 4 .*zfs list -j -p -t filesystem,"
	    "volume' jexec.log") == 0);
	r3_act(id, "/arcana-storage:storage/read", "\"kind\":\"datasets\","
	    "\"jail\":\"db\"", &r);
	ATF_CHECK_MSG(r.status >= 400 && strstr(r.body, "not running") !=
	    NULL, "%d %s", r.status, r.body);
	resp_free(&r);
	r3_act(id, "/arcana-storage:storage/read", "\"kind\":\"pools\","
	    "\"jail\":\"gw\"", &r);
	ATF_CHECK_MSG(r.status >= 400 && strstr(r.body,
	    "of a jail, its datasets and snapshots only") != NULL, "%d %s",
	    r.status, r.body);
	resp_free(&r);
	r3_act(id, "/arcana-storage:storage/read", "\"kind\":\"snapshots\","
	    "\"filter\":\"tank/data\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("tank/data@b", jstr(&r, "snapshot.0.name"));
	resp_free(&r);
	ATF_CHECK(system("grep -q -- '-S creation -r tank/data$' storage.log")
	    == 0);
	r3_act(id, "/arcana-storage:storage/read", "\"kind\":\"snapshots\","
	    "\"filter\":\"-r\"", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);
	r3_act(id, "/arcana-storage:storage/read", "\"kind\":\"disks\"", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	r3_act(id, "/arcana-storage:storage/read", "\"kind\":\"mounts\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("/", jstr(&r, "mount.0.on"));
	ATF_CHECK_STREQ("/mnt/data", jstr(&r, "fstab.entry.1.file"));
	ATF_CHECK_STREQ("false", jstr(&r, "fstab.entry.1.mounted"));
	resp_free(&r);
	r3_submit(id, "{\"zfs\":{\"verb\":\"snapshot\",\"args\":"
	    "[\"tank/data@now\"],\"recursive\":true}},{\"gpart\":{\"verb\":"
	    "\"add\",\"args\":[\"ada9\",\"freebsd-zfs\",\"10G\",\"tank0\"]}}",
	    &r);
	EXPECT(&r, 200);
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.0"));
	ATF_CHECK_STREQ("zfs snapshot -r tank/data@now", r3_title(id, n, t,
	    sizeof(t)));
	snprintf(n, sizeof(n), "%s", jstr(&r, "id.1"));
	ATF_CHECK_STREQ("gpart add -t freebsd-zfs -a 1m -s 10G -l tank0 ada9",
	    r3_title(id, n, t, sizeof(t)));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q '^gpart add' storage.log "
	    "2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^zfs snapshot -r tank/data@now$' "
	    "storage.log") == 0);
	/* A word that is an option, or a pool to destroy, is no job. */
	r3_submit(id, "{\"zfs\":{\"verb\":\"destroy\",\"args\":[\"tank\"]}}",
	    &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);
	r3_submit(id, "{\"gpart\":{\"verb\":\"destroy\",\"args\":[\"-F\","
	    "\"ada9\"]}}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q 'destroy' storage.log") != 0);
	r3_act(id, "/arcana-storage:storage/read", "\"kind\":\"mounts\"", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_MSG(jstr(&r, "fstab.sha256") != NULL, "%s", r.body);
	ATF_CHECK(strstr(jstr(&r, "fstab.text"), "/mnt/data") != NULL);
	snprintf(body, sizeof(body), "\"text\":\"/dev/ada0p2\\t/\\tufs\\trw"
	    "\\t1\\t1\\n/dev/ada0p4 /mnt/more ufs rw 2 2\\n\",\"sha256\":"
	    "\"%s\"", jstr(&r, "fstab.sha256"));
	resp_free(&r);
	r3_act(id, "/arcana-storage:storage/fstab/replace", body, &r);
	ATF_CHECK_MSG(r.status == 200 || r.status == 204, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q '/mnt/more' fstab && grep -q '/mnt/data' "
	    "fstab.arcana-old") == 0);
	r3_act(id, "/arcana-storage:storage/fstab/replace", body, &r);
	ATF_CHECK_MSG(r.status >= 400 && strstr(r.body,
	    "changed it meanwhile") != NULL, "%d %s", r.status, r.body);
	resp_free(&r);

	/* The host says which plugins it has: the programs are there. */
	r3_read(id, "/arcana-host:host", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "plugin.0") != NULL && strstr(jstr(&r,
	    "plugin.0"), "bird") != NULL, "%s", r.body);
	ATF_CHECK_MSG(jstr(&r, "plugin.1") != NULL && strstr(jstr(&r,
	    "plugin.1"), "strongswan") != NULL, "%s", r.body);
	/* WireGuard is no plugin: wg(8) is the base system's. */
	ATF_CHECK(strstr(r.body, "wireguard\"") == NULL);
	resp_free(&r);

	/* BIRD's routes, asked for in birdc's words with , between. */
	r3_act(id, "/arcana-bird:bird/routes", "\"filter\":\"10.1.2.3,all\"",
	    &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"10.1.0.0/16\"") != NULL && strstr(
	    r.body, "\"bgp_core\"") != NULL && strstr(r.body,
	    "\"192.0.2.1\"") != NULL && strstr(r.body,
	    "BGP.as_path: 65001 65010") != NULL && strstr(r.body,
	    "\"bgp_edge\"") != NULL, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^-r show route for 10.1.2.3 all$' birdc.log")
	    == 0);
	/* A neighbour's whole table is counted, not sent. */
	r3_act(id, "/arcana-bird:bird/routes", "\"filter\":\"protocol,"
	    "bgp_core\"", &r);
	ATF_CHECK_MSG(strstr(r.body, "845233") != NULL, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	r3_act(id, "/arcana-bird:bird/routes", "\"filter\":\"where,x\"", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);
}

CONSOLE_TC(unreachable, "A server that does not answer is reported")
ATF_TC_BODY(unreachable, tc)
{
	struct authn	a;
	struct resp	r;
	char		id[16], path[128];

	start(tc, 0, NULL);
	enrol(&a);
	host_add("gone", "unix:/nonexistent/jgd.sock", id, sizeof(id));
	snprintf(path, sizeof(path), FLEET "%s/arcana-jails:jails", id);
	http("GET", path, NULL, &r);
	ATF_CHECK_MSG(r.status == 502 || r.status == 503, "%d %s", r.status,
	    r.body);
	ATF_CHECK_MSG(jstr(&r, ERROR_TAG) != NULL && strstr(r.body,
	    "jgd.sock") != NULL, "%s", r.body);
	resp_free(&r);
	http("GET", FLEET "00000000/arcana-jails:jails", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	snprintf(path, sizeof(path), CC "hosts/host=%s", id);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "hosts", NULL, &r);
	ATF_CHECK_MSG(jstr(&r, "arcana-console:hosts.host.0") == NULL, "%s",
	    r.body);
	resp_free(&r);
}

/* openssl(1): a CA, or a certificate it signs with the given SAN. */
static void
pki(const char *name, const char *ca, const char *san)
{
	char	 key[64], pem[64], csr[64], ext[64], subj[80], *argv[24];
	char	 cakey[64], capem[64];
	FILE	*fp;
	int	 i;

	snprintf(key, sizeof(key), "pki/%s.key", name);
	snprintf(pem, sizeof(pem), "pki/%s.pem", name);
	snprintf(csr, sizeof(csr), "pki/%s.csr", name);
	snprintf(ext, sizeof(ext), "pki/%s.ext", name);
	snprintf(subj, sizeof(subj), "/CN=%s", name);
	i = 0;
	argv[i++] = (char *)(uintptr_t)"/usr/bin/openssl";
	argv[i++] = (char *)(uintptr_t)"req";
	if (ca == NULL) {
		argv[i++] = (char *)(uintptr_t)"-x509";
		argv[i++] = (char *)(uintptr_t)"-days";
		argv[i++] = (char *)(uintptr_t)"2";
		argv[i++] = (char *)(uintptr_t)"-addext";
		argv[i++] =
		    (char *)(uintptr_t)"basicConstraints=critical,CA:TRUE";
	}
	argv[i++] = (char *)(uintptr_t)"-newkey";
	argv[i++] = (char *)(uintptr_t)"ec";
	argv[i++] = (char *)(uintptr_t)"-pkeyopt";
	argv[i++] = (char *)(uintptr_t)"ec_paramgen_curve:P-256";
	argv[i++] = (char *)(uintptr_t)"-nodes";
	argv[i++] = (char *)(uintptr_t)"-subj";
	argv[i++] = subj;
	argv[i++] = (char *)(uintptr_t)"-keyout";
	argv[i++] = key;
	argv[i++] = (char *)(uintptr_t)"-out";
	argv[i++] = ca == NULL ? pem : csr;
	argv[i] = NULL;
	ATF_REQUIRE_MSG(run_prog(argv), "openssl req %s failed", name);
	if (ca == NULL)
		return;
	ATF_REQUIRE((fp = fopen(ext, "w")) != NULL);
	fprintf(fp, "subjectAltName=%s\n", san);
	fclose(fp);
	snprintf(cakey, sizeof(cakey), "pki/%s.key", ca);
	snprintf(capem, sizeof(capem), "pki/%s.pem", ca);
	i = 0;
	argv[i++] = (char *)(uintptr_t)"/usr/bin/openssl";
	argv[i++] = (char *)(uintptr_t)"x509";
	argv[i++] = (char *)(uintptr_t)"-req";
	argv[i++] = (char *)(uintptr_t)"-in";
	argv[i++] = csr;
	argv[i++] = (char *)(uintptr_t)"-CA";
	argv[i++] = capem;
	argv[i++] = (char *)(uintptr_t)"-CAkey";
	argv[i++] = cakey;
	argv[i++] = (char *)(uintptr_t)"-CAcreateserial";
	argv[i++] = (char *)(uintptr_t)"-days";
	argv[i++] = (char *)(uintptr_t)"2";
	argv[i++] = (char *)(uintptr_t)"-extfile";
	argv[i++] = ext;
	argv[i++] = (char *)(uintptr_t)"-out";
	argv[i++] = pem;
	argv[i] = NULL;
	ATF_REQUIRE_MSG(run_prog(argv), "openssl x509 %s failed", name);
}

/*
 * The console over TLS with a CA of the test's, and a second
 * arcana-agent on TCP with mutual TLS, its port into *portp; host remote
 * added, its id into sid.
 */
static void
mtls_start(const atf_tc_t *tc, struct authn *a, int *portp, char *sid,
    size_t len)
{
	struct resp	 r;
	char		 cwd[MAXPATHLEN], uri[64];
	char		 jgd[MAXPATHLEN], listen[64], *argv[20];
	FILE		*fp;
	pid_t		 pid;
	int		 port, i;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ATF_REQUIRE(mkdir("pki", 0700) == 0);
	pki("ca", NULL, NULL);
	pki("server", "ca", "IP:127.0.0.1,DNS:localhost");
	pki("console", "ca", "DNS:console");
	snprintf(harness_webconf, sizeof(harness_webconf), "tls {\n"
	    "\tca = \"%s/pki/ca.pem\";\n\tcert = \"%s/pki/console.pem\";\n"
	    "\tkey = \"%s/pki/console.key\";\n\tca_key = \"%s/pki/ca.key\";\n"
	    "}\n", cwd, cwd, cwd, cwd);
	start(tc, 0, NULL);

	/* A second arcana-agent, on TCP. */
	port = 20000 + (int)(getpid() % 20000);
	snprintf(listen, sizeof(listen), "tcp://127.0.0.1:%d", port);
	snprintf(jgd, sizeof(jgd), "%s", locate(tc,
	    "../../../usr.sbin/arcana-agent/arcana-agent", "arcana-agent",
	    "/usr/local/sbin/arcana-agent"));
	i = 0;
	argv[i++] = jgd;
	argv[i++] = (char *)(uintptr_t)"-F";
	argv[i++] = (char *)(uintptr_t)"-l";
	argv[i++] = listen;
	argv[i++] = (char *)(uintptr_t)"-A";
	argv[i++] = (char *)(uintptr_t)"pki/ca.pem";
	argv[i++] = (char *)(uintptr_t)"-C";
	argv[i++] = (char *)(uintptr_t)"pki/server.pem";
	argv[i++] = (char *)(uintptr_t)"-K";
	argv[i++] = (char *)(uintptr_t)"pki/server.key";
	argv[i++] = (char *)(uintptr_t)"-f";
	argv[i++] = (char *)(uintptr_t)"etc/jail.conf";
	argv[i++] = (char *)(uintptr_t)"-D";
	argv[i++] = (char *)(uintptr_t)"etc/jail.conf.d";
	/* rc.conf: the test's own, never the host's. */
	argv[i++] = (char *)(uintptr_t)"-y";
	argv[i++] = (char *)(uintptr_t)"./fake-sysrc";
	/* The program an update replaces: not the one under test. */
	argv[i++] = (char *)(uintptr_t)"-U";
	argv[i++] = (char *)(uintptr_t)"installed-agent2";
	argv[i] = NULL;
	pid = spawn_server(argv, "arcana-agent2.out");
	ATF_REQUIRE((fp = fopen("arcana-agent2.pid", "w")) != NULL);
	fprintf(fp, "%d\n", (int)pid);
	fclose(fp);
	usleep(300000);

	enrol(a);
	snprintf(uri, sizeof(uri), "tcp://127.0.0.1:%d", port);
	host_add("remote", uri, sid, len);
	http("GET", CC "hosts", NULL, &r);
	ATF_CHECK_STREQ("false", jstr(&r,
	    "arcana-console:hosts.host.0.local"));
	resp_free(&r);
	*portp = port;
}

CONSOLE_TC(mtls, "A host over TCP with mutual TLS")
ATF_TC_BODY(mtls, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 m[256], sid[16], wrong[16];
	int		 port;

	mtls_start(tc, &a, &port, sid, sizeof(sid));
	r3_web(sid);
	/* By mutual TLS: the agent says who the console's certificate is. */
	r3_transport(sid, &r);
	ATF_CHECK_MSG(jstr(&r, "data.sessions.0.subject") != NULL && strstr(
	    jstr(&r, "data.sessions.0.subject"), "console") != NULL, "%s",
	    r.body);
	resp_free(&r);
	/* Over TLS the program sent is signed by the console's CA key, and
	 * the host checks it against the CA it trusts before anything
	 * else: here the console's own CA, so it is taken. */
	ATF_REQUIRE(access("installed-agent2", F_OK) == -1);
	r3_verb(sid, "agent-update", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "ok") != NULL && strcmp(jstr(&r, "ok"),
	    "true") == 0, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "verified") != NULL, "%s", r.body);
	/* Compressed, and the signature the program's, inflated. */
	ATF_CHECK_MSG(strstr(r.body, "inflate(3)") != NULL, "%s", r.body);
	ATF_CHECK(access("installed-agent2", X_OK) == 0);
	resp_free(&r);

	/* The certificate has to name the host the console expects. */
	snprintf(m, sizeof(m), "\"name\":\"wrong\",\"uri\":"
	    "\"tcp://localhost:%d\",\"peer-name\":\"elsewhere.example\"",
	    port);
	host_new(m, wrong, sizeof(wrong));
	r3_read(wrong, "/arcana-jails:jails", &r);
	ATF_CHECK_MSG(r.status == 502 || r.status == 503, "%d %s", r.status,
	    r.body);
	resp_free(&r);
}

CONSOLE_TC(mtls_sctp, "A host over mutual TLS switched to its SCTP "
    "listener, where the kernel has SCTP, and back")
ATF_TC_BODY(mtls_sctp, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 path[128], sid[16], uri[64];
	int		 port;
	long		 seen_pre;

	mtls_start(tc, &a, &port, sid, sizeof(sid));
	/*
	 * Beside its TCP listener the agent has an SCTP one, at the same
	 * address and port, where the kernel has SCTP.  The console is
	 * switched to it only when the agent answers there, and back.
	 */
	r3_transport(sid, &r);
	ATF_CHECK_STREQ("tcp", jstr(&r, "data.listeners.0.transport"));
	ATF_CHECK_STREQ("sctp", jstr(&r, "data.listeners.1.transport"));
	ATF_CHECK_STREQ("tcp", jstr(&r, "data.sessions.0.transport"));
	seen_pre = atol(jstr(&r, "data.seen"));
	ATF_CHECK(jstr(&r, "data.sessions.0.subject") != NULL && strstr(jstr(
	    &r, "data.sessions.0.subject"), "console") != NULL);
	resp_free(&r);
	if (has_sctp()) {
		r3_verb(sid, "switch-transport", "\"transport\":\"sctp\"", &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("true", jstr(&r, "ok"));
		resp_free(&r);
		ATF_CHECK(strncmp(r3_uri(sid, uri, sizeof(uri)), "sctp://",
		    7) == 0);
		/*
		 * A burst of first requests makes one association: the
		 * first makes it, the others wait for it and share it.
		 * The agent counts what connected.
		 */
		{
			pid_t	kids[6];
			long	seen1;
			int	k, st, bad;

			/* A read the subscriptions hold none of. */
			snprintf(path, sizeof(path), FLEET "%s/arcana-services:"
			    "services", sid);
			for (k = 0; k < 6; k++)
				if ((kids[k] = fork()) == 0) {
					struct resp	kr;

					http("GET", path, NULL, &kr);
					_exit(kr.status == 200 ? 0 : 1);
				}
			bad = 0;
			for (k = 0; k < 6; k++)
				if (waitpid(kids[k], &st, 0) == -1 ||
				    !WIFEXITED(st) || WEXITSTATUS(st) != 0)
					bad++;
			ATF_CHECK_EQ(0, bad);
			/*
			 * What comes in parts, as a stream over that same
			 * association: the kernel's state, all of it, and no
			 * connection more for it.
			 */
			{
				char	 ask[160], *m;
				int	 ws, parts, done;

				ws = ws_open("/api/stream");
				snprintf(ask, sizeof(ask), "{\"id\":3,\"server\":"
				    "\"%s\",\"what\":\"sysctl\",\"filter\":"
				    "\"kern.\"}", sid);
				ws_send(ws, ask);
				parts = done = 0;
				while (!done && (m = ws_recv(ws)) != NULL) {
					if (strstr(m, "\"rows\":[") != NULL)
						parts++;
					if (strstr(m, "\"done\":true") != NULL)
						done = 1;
					ATF_CHECK_MSG(strstr(m, "\"error\"") ==
					    NULL, "%.200s", m);
					if (strstr(m, "\"error\"") != NULL)
						done = 1;
					free(m);
				}
				close(ws);
				ATF_CHECK_MSG(done && parts > 0, "%d parts, "
				    "done %d", parts, done);
			}
			r3_transport(sid, &r);
			seen1 = atol(jstr(&r, "data.seen"));
			resp_free(&r);
			/* The switch's own, and the burst's one. */
			ATF_CHECK_MSG(seen1 - seen_pre <= 2, "the switch and a "
			    "burst of six first requests made %ld connections",
			    seen1 - seen_pre);
		}
		/* Over mutual DTLS: the agent says who the console is on
		 * its SCTP session; kept open, the next read goes over the
		 * same, no connection more. */
		{
			long	seen1, seen2;

			r3_transport(sid, &r);
			ATF_CHECK_MSG(jstr(&r, "data.sessions.0.subject") !=
			    NULL && strstr(jstr(&r, "data.sessions.0.subject"),
			    "console") != NULL, "%s", r.body);
			seen1 = atol(jstr(&r, "data.seen"));
			resp_free(&r);
			r3_read(sid, "/arcana-services:services", &r);
			EXPECT(&r, 200);
			resp_free(&r);
			r3_transport(sid, &r);
			seen2 = atol(jstr(&r, "data.seen"));
			resp_free(&r);
			ATF_CHECK_EQ_MSG(seen1, seen2, "a read made %ld "
			    "connections", seen2 - seen1);
		}
		r3_web(sid);
		/* The association's paths, as the agent's kernel sees
		 * them: to the console's address, active, the primary. */
		r3_transport(sid, &r);
		ATF_CHECK_MSG(strstr(r.body, "\"paths\":[{\"address\":"
		    "\"127.0.0.1\",\"state\":\"active\"") != NULL && strstr(
		    r.body, "\"primary\":true") != NULL && strstr(r.body,
		    "\"local\":[\"127.0.0.1\"]") != NULL, "%s", r.body);
		resp_free(&r);
		/*
		 * Requests at once go over that one association, each
		 * waiting for its own answer: the agent sees one SCTP
		 * session, however many there were.
		 */
		{
			pid_t	kids[6];
			int	k, st, bad;

			snprintf(path, sizeof(path), CC "hosts/host=%s/"
			    "transport", sid);
			for (k = 0; k < 6; k++)
				if ((kids[k] = fork()) == 0) {
					struct resp	kr;

					http("GET", path, NULL, &kr);
					_exit(kr.status == 200 ? 0 : 1);
				}
			bad = 0;
			for (k = 0; k < 6; k++)
				if (waitpid(kids[k], &st, 0) == -1 ||
				    !WIFEXITED(st) || WEXITSTATUS(st) != 0)
					bad++;
			ATF_CHECK_EQ(0, bad);
		}
		r3_transport(sid, &r);
		{
			const char	*t;
			char		 key[64];
			int		 k, nsctp;

			nsctp = 0;
			for (k = 0; k < 32; k++) {
				snprintf(key, sizeof(key),
				    "data.sessions.%d.transport", k);
				if ((t = jstr(&r, key)) == NULL)
					break;
				if (strcmp(t, "sctp") == 0)
					nsctp++;
			}
			/* The requests' alone: a read through the fleet
			 * mount holds no subscription of the jails. */
			ATF_CHECK_EQ_MSG(1, nsctp, "%d SCTP sessions", nsctp);
		}
		resp_free(&r);
		r3_transport(sid, &r);
		ATF_CHECK_STREQ("true", jstr(&r, "data.listeners.1.up"));
		ATF_CHECK_STREQ("sctp", jstr(&r, "data.sessions.0.transport"));
		ATF_CHECK(strncmp(jstr(&r, "uri"), "sctp://", 7) == 0);
		resp_free(&r);
		r3_verb(sid, "switch-transport", "\"transport\":\"tcp\"", &r);
		EXPECT(&r, 200);
		resp_free(&r);
		ATF_CHECK(strncmp(r3_uri(sid, uri, sizeof(uri)), "tcp://", 6) ==
		    0);
	} else {
		/* No SCTP here: said by the agent, and nothing is changed. */
		r3_transport(sid, &r);
		ATF_CHECK_STREQ("false", jstr(&r, "data.listeners.1.up"));
		ATF_CHECK_STREQ("false", jstr(&r, "data.sctp"));
		resp_free(&r);
		r3_verb(sid, "listen", "\"retry\":true", &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("false", jstr(&r, "ok"));
		ATF_CHECK(strstr(jstr(&r, "error"), "sctp module") != NULL);
		resp_free(&r);
		r3_verb(sid, "switch-transport", "\"transport\":\"sctp\"", &r);
		EXPECT(&r, 502);
		resp_free(&r);
		ATF_CHECK(strncmp(r3_uri(sid, uri, sizeof(uri)), "tcp://", 6) ==
		    0);
	}
	r3_web(sid);
	r3_verb(sid, "switch-transport", "\"transport\":\"udp\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);
}

CONSOLE_TC(mtls_move, "A host over mutual TLS: SCTP's other addresses "
    "kept, and the agent moved to another address and back")
ATF_TC_BODY(mtls_move, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 sid[16], uri[64];
	int		 port;

	mtls_start(tc, &a, &port, sid, sizeof(sid));
	/*
	 * SCTP over several paths: the agent's other addresses, checked,
	 * bound where they can be (192.0.2.99 is no address of this host:
	 * said with the listener), kept in rc.conf, and let go.
	 */
	r3_verb(sid, "listen", "\"sctp-also\":\"no-such\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "no-such is not an address") != NULL,
	    "%s", r.body);
	resp_free(&r);
	r3_verb(sid, "listen", "\"sctp-also\":\"192.0.2.99\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("192.0.2.99", jstr(&r, "data.sctp_also"));
	if (has_sctp())
		ATF_CHECK_MSG(strstr(r.body, "\"also_error\":\"192.0.2.99: ")
		    != NULL, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^arcana_agent_sctp_also=\"192.0.2.99\"$' "
	    "rc.conf") == 0);
	r3_verb(sid, "listen", "\"sctp-also\":\"\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, "also_error") == NULL);
	resp_free(&r);
	ATF_CHECK(system("! grep -q 'arcana_agent_sctp_also' rc.conf") == 0);

	/*
	 * Moved to another address: listened on there too, tried, and
	 * only then the old listener closed and the new kept in rc.conf;
	 * where the agent cannot listen, nothing changes.
	 */
	r3_verb(sid, "move", "\"uri\":\"udp://127.0.0.1:1\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	r3_verb(sid, "move", "\"uri\":\"tcp://192.0.2.77:4430\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strcmp(jstr(&r, "ok"), "false") == 0 && strstr(jstr(&r,
	    "error"), "did not listen on tcp://192.0.2.77:4430") != NULL,
	    "%s", r.body);
	resp_free(&r);
	ATF_REQUIRE(system("echo 'arcana_agent_listen=\"tcp://127.0.0.1:1 "
	    "keep\"' >> rc.conf") == 0);
	{
		char	moved[64], b2[160], was[64];

		snprintf(was, sizeof(was), "tcp://127.0.0.1:%d", port);
		snprintf(moved, sizeof(moved), "tcp://127.0.0.1:%d", port + 1);
		snprintf(b2, sizeof(b2), "\"uri\":\"%s\"", moved);
		r3_verb(sid, "move", b2, &r);
		EXPECT(&r, 200);
		ATF_CHECK_MSG(strcmp(jstr(&r, "ok"), "true") == 0 && strcmp(jstr(
		    &r, "uri"), moved) == 0 && jstr(&r, "note") == NULL, "%s",
		    r.body);
		resp_free(&r);
		ATF_CHECK_STREQ(moved, r3_uri(sid, uri, sizeof(uri)));
		r3_transport(sid, &r);
		ATF_CHECK_MSG(strstr(r.body, moved) != NULL && strstr(r.body,
		    was) == NULL, "%s", r.body);
		resp_free(&r);
		/* Not in arcana_agent_listen: added to it. */
		snprintf(b2, sizeof(b2), "grep -q '^arcana_agent_listen=\"tcp://"
		    "127.0.0.1:1 keep %s\"$' rc.conf", moved);
		ATF_CHECK_MSG(system(b2) == 0, "%s", b2);
		/* And back, its word put in place of the other. */
		snprintf(b2, sizeof(b2), "\"uri\":\"%s\"", was);
		r3_verb(sid, "move", b2, &r);
		EXPECT(&r, 200);
		ATF_CHECK_MSG(strcmp(jstr(&r, "ok"), "true") == 0, "%s", r.body);
		resp_free(&r);
		snprintf(b2, sizeof(b2), "grep -q '^arcana_agent_listen=\"tcp://"
		    "127.0.0.1:1 keep %s\"$' rc.conf", was);
		ATF_CHECK_MSG(system(b2) == 0, "%s", b2);
		/*
		 * Moved to SCTP at the same address: the SCTP listener the
		 * agent opened beside the TCP one is the one moved to, and is
		 * not closed with it; the host is reached there afterwards.
		 */
		if (has_sctp()) {
			char	sctp[64];

			snprintf(sctp, sizeof(sctp), "sctp://127.0.0.1:%d", port);
			snprintf(b2, sizeof(b2), "\"uri\":\"%s\"", sctp);
			r3_verb(sid, "move", b2, &r);
			EXPECT(&r, 200);
			ATF_CHECK_MSG(strcmp(jstr(&r, "ok"), "true") == 0 && strcmp(
			    jstr(&r, "uri"), sctp) == 0, "%s", r.body);
			resp_free(&r);
			r3_transport(sid, &r);
			ATF_CHECK_MSG(strstr(r.body, "\"uri\":\"sctp://127.0.0.1:")
			    != NULL && strstr(r.body, was) == NULL && strstr(r.body,
			    "\"up\":true,\"addresses\"") != NULL, "%s", r.body);
			resp_free(&r);
			snprintf(b2, sizeof(b2), "grep -q '^arcana_agent_listen=\""
			    "tcp://127.0.0.1:1 keep %s\"$' rc.conf", sctp);
			ATF_CHECK_MSG(system(b2) == 0, "%s", b2);
		}
	}
	r3_read(sid, "/arcana-jails:jails", &r);
	EXPECT(&r, 200);
	resp_free(&r);
}

/* A file's text, malloc(3)ed. */
static char *
slurp_file(const char *path)
{
	FILE	*fp;
	char	*buf;
	size_t	 n;

	ATF_REQUIRE((fp = fopen(path, "r")) != NULL);
	ATF_REQUIRE((buf = calloc(1, 65537)) != NULL);
	n = fread(buf, 1, 65536, fp);
	fclose(fp);
	buf[n] = '\0';
	return (buf);
}

/* s as a JSON string, its quotes and newlines escaped. */
static char *
json_quote_test(const char *s)
{
	char	*out, *o;

	ATF_REQUIRE((out = malloc(strlen(s) * 2 + 3)) != NULL);
	o = out;
	*o++ = '"';
	for (; *s != '\0'; s++) {
		if (*s == '\n') {
			*o++ = '\\';
			*o++ = 'n';
		} else if (*s == '"' || *s == '\\') {
			*o++ = '\\';
			*o++ = *s;
		} else
			*o++ = *s;
	}
	*o++ = '"';
	*o = '\0';
	return (out);
}

/* The CA's state once the thread is done with it. */
static void
ca_wait(struct resp *r)
{
	int	i;

	for (i = 0; i < 200; i++) {
		http("GET", CC "ca/state", NULL, r);
		(void)resp_unwrap(r, "arcana-console:state");
		if (r->status == 200 && jstr(r, "state.running") != NULL &&
		    strcmp(jstr(r, "state.running"), "false") == 0)
			return;
		resp_free(r);
		usleep(100000);
	}
	atf_tc_fail("the CA's change did not end");
}

/* The CA's step (arcana-console's ca/<verb>), input its members or
 * NULL: its answer in r, its JSON the CA's document. */
static void
ca_step(const char *verb, const char *input, struct resp *r)
{
	char	path[96];

	snprintf(path, sizeof(path), CC "ca/%s", verb);
	rc_act(path, input, r);
}

/*
 * The next CA staged by verb with input (ca_step's), rolled out and
 * finished, host id reached at each step.
 */
static void
ca_change(const char *id, const char *verb, const char *input)
{
	struct resp	r;

	ca_step(verb, input, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("staged", jstr(&r, "state.phase"));
	ATF_CHECK(jstr(&r, "next.chain.0.subject") != NULL);
	resp_free(&r);
	ca_step("rollout", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ca_wait(&r);
	if (jstr(&r, "state.phase") == NULL || strcmp(jstr(&r, "state.phase"),
	    "switched") != 0)
		(void)system("tail -30 console.out >&2");
	ATF_CHECK_MSG(jstr(&r, "state.phase") != NULL && strcmp(jstr(&r,
	    "state.phase"), "switched") == 0, "%s", r.body);
	resp_free(&r);
	r3_web(id);
	ca_step("finish", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ca_wait(&r);
	ATF_CHECK_MSG(jstr(&r, "state.phase") != NULL && strcmp(jstr(&r,
	    "state.phase"), "finished") == 0, "%s", r.body);
	ATF_CHECK_MSG(jstr(&r, "next") == NULL, "%s", r.body);
	resp_free(&r);
	r3_web(id);
}

/*
 * An agent of a release before, its program named by the environment's
 * ARCANA_OLD_AGENT or the config variable old_agent; NULL without.
 */
static const char *
old_agent(const atf_tc_t *tc)
{
	const char	*p;

	if ((p = getenv("ARCANA_OLD_AGENT")) != NULL && p[0] != '\0')
		return (p);
	if (atf_tc_has_config_var(tc, "old_agent"))
		return (atf_tc_get_config_var(tc, "old_agent"));
	return (NULL);
}

/*
 * prog listening on listen, and on tcp (not NULL) with mutual TLS, the
 * pki's server certificate; the program an update replaces, installed.
 */
static pid_t
agent_spawn(const char *prog, const char *listen, const char *tcp,
    const char *installed)
{
	char	*argv[28];
	FILE	*fp;
	pid_t	 pid;
	int	 i;

	i = 0;
	argv[i++] = (char *)(uintptr_t)prog;
	argv[i++] = (char *)(uintptr_t)"-F";
	argv[i++] = (char *)(uintptr_t)"-l";
	argv[i++] = (char *)(uintptr_t)listen;
	if (tcp != NULL) {
		argv[i++] = (char *)(uintptr_t)"-l";
		argv[i++] = (char *)(uintptr_t)tcp;
		argv[i++] = (char *)(uintptr_t)"-A";
		argv[i++] = (char *)(uintptr_t)"pki/ca.pem";
		argv[i++] = (char *)(uintptr_t)"-C";
		argv[i++] = (char *)(uintptr_t)"pki/server.pem";
		argv[i++] = (char *)(uintptr_t)"-K";
		argv[i++] = (char *)(uintptr_t)"pki/server.key";
	}
	argv[i++] = (char *)(uintptr_t)"-f";
	argv[i++] = (char *)(uintptr_t)"etc/jail.conf";
	argv[i++] = (char *)(uintptr_t)"-D";
	argv[i++] = (char *)(uintptr_t)"etc/jail.conf.d";
	argv[i++] = (char *)(uintptr_t)"-y";
	argv[i++] = (char *)(uintptr_t)"./fake-sysrc";
	argv[i++] = (char *)(uintptr_t)"-U";
	argv[i++] = (char *)(uintptr_t)installed;
	/* How it samples kept here, not where the program would. */
	argv[i++] = (char *)(uintptr_t)"-1";
	argv[i++] = (char *)(uintptr_t)"history.conf";
	argv[i] = NULL;
	pid = spawn_server(argv, "arcana-agent2.out");
	ATF_REQUIRE((fp = fopen("arcana-agent2.pid", "w")) != NULL);
	fprintf(fp, "%d\n", (int)pid);
	fclose(fp);
	return (pid);
}

/* id's agent-update, its answer in r, checked: as it is, or compressed. */
static void
bridge_update(const char *id, bool gz, struct resp *r)
{

	r3_verb(id, "agent-update", NULL, r);
	EXPECT(r, 200);
	ATF_CHECK_MSG(jstr(r, "ok") != NULL && strcmp(jstr(r, "ok"), "true") ==
	    0, "%s", r->body);
	if (gz)
		ATF_CHECK_MSG(strstr(r->body, "inflate(3)") != NULL, "%s",
		    r->body);
	else
		ATF_CHECK_MSG(strstr(r->body, "inflate") == NULL, "%s",
		    r->body);
}

/* id's host as hello said it (arcana-host's host), in r. */
static void
bridge_hello(const char *id, struct resp *r)
{

	r3_read(id, "/arcana-host:host", r);
	EXPECT(r, 200);
}

CONSOLE_TC(agent_update_bridge, "An agent of the release before the "
    "interim protocol went, a real build of it (ARCANA_OLD_AGENT), is read "
    "and updated through YANG alone, over a unix socket and over TCP with "
    "mutual TLS, sent its program as it is; the agent it becomes takes the "
    "next one compressed")
ATF_TC_BODY(agent_update_bridge, tc)
{
	struct authn	a;
	struct resp	r;
	struct stat	sb, snew;
	char		cwd[MAXPATHLEN], jgd[MAXPATHLEN], unix[MAXPATHLEN];
	char		tcp[64], id[16], became[MAXPATHLEN];
	const char	*old;
	pid_t		pid;
	int		port, i;

	if ((old = old_agent(tc)) == NULL)
		atf_tc_skip("no agent of a release before: set ARCANA_OLD_AGENT "
		    "or old_agent");
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ATF_REQUIRE(mkdir("pki", 0700) == 0);
	pki("ca", NULL, NULL);
	pki("server", "ca", "IP:127.0.0.1,DNS:localhost");
	pki("console", "ca", "DNS:console");
	snprintf(harness_webconf, sizeof(harness_webconf), "tls {\n"
	    "\tca = \"%s/pki/ca.pem\";\n\tcert = \"%s/pki/console.pem\";\n"
	    "\tkey = \"%s/pki/console.key\";\n\tca_key = \"%s/pki/ca.key\";\n"
	    "}\n", cwd, cwd, cwd, cwd);
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(jgd, sizeof(jgd), "%s", locate(tc,
	    "../../../usr.sbin/arcana-agent/arcana-agent", "arcana-agent",
	    "/usr/local/sbin/arcana-agent"));
	ATF_REQUIRE(stat(jgd, &snew) == 0);

	port = 20000 + (int)(getpid() % 20000);
	snprintf(unix, sizeof(unix), "unix:%s/old.sock", cwd);
	snprintf(tcp, sizeof(tcp), "tcp://127.0.0.1:%d", port);
	pid = agent_spawn(old, unix, tcp, "installed-old");
	wait_for("old.sock");

	/* Its hello: its version, and no features. */
	host_add("old-unix", unix, id, sizeof(id));
	bridge_hello(id, &r);
	ATF_CHECK_MSG(jstr(&r, "agent.version") != NULL, "%s", r.body);
	ATF_CHECK_MSG(jstr(&r, "agent.feature.0") == NULL, "%s", r.body);
	printf("old agent %s, its features none\n", jstr(&r,
	    "agent.version"));
	/* No boot tunables: the page says the agent needs updating. */
	ATF_CHECK_MSG(jstr(&r, "reboot-required") == NULL, "%s", r.body);
	resp_free(&r);
	r3_read(id, "/arcana-sysctl:sysctl?fields=kept", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"kept\":[") != NULL, "%s", r.body);
	resp_free(&r);
	r3_read(id, "/arcana-sysctl:boot", &r);
	ATF_CHECK_MSG(r.status == 404, "%d %s", r.status, r.body);
	resp_free(&r);
	/* A URL filter stopped: refused before the edit, by the host's
	 * own schema. */
	ATF_CHECK_EQ(400, r3_commit(id, "/arcana-sdwan:sdwan",
	    "{\"arcana-sdwan:sdwan\":{\"proxy-instance\":[{\"name\":"
	    "\"sec-web\",\"stopped\":true}]}}", &r));
	resp_free(&r);

	/* Over the unix socket: as it is, taken unsigned. */
	bridge_update(id, false, &r);
	printf("unix: %s\n", r.body);
	resp_free(&r);
	ATF_CHECK(stat("installed-old", &sb) == 0 && sb.st_size ==
	    snew.st_size);
	ATF_REQUIRE(unlink("installed-old") == 0);

	/* Over TCP with mutual TLS: as it is, signed by the CA key. */
	host_add("old-tcp", tcp, id, sizeof(id));
	bridge_update(id, false, &r);
	printf("tcp: %s\n", r.body);
	resp_free(&r);
	ATF_CHECK(stat("installed-old", &sb) == 0 && sb.st_size ==
	    snew.st_size);

	/* What it became runs, and takes the next one compressed. */
	(void)kill(pid, SIGTERM);
	for (i = 0; i < 100 && kill(pid, 0) == 0; i++)
		usleep(50000);
	ATF_REQUIRE(system("cp installed-old became && chmod 755 became") ==
	    0);
	snprintf(became, sizeof(became), "%s/became", cwd);
	snprintf(unix, sizeof(unix), "unix:%s/new.sock", cwd);
	(void)agent_spawn(became, unix, NULL, "installed-new");
	wait_for("new.sock");
	host_add("became", unix, id, sizeof(id));
	bridge_hello(id, &r);
	ATF_CHECK_MSG(strstr(r.body, "gzip-update") != NULL, "%s", r.body);
	resp_free(&r);
	bridge_update(id, true, &r);
	resp_free(&r);
	ATF_CHECK(stat("installed-new", &sb) == 0 && sb.st_size ==
	    snew.st_size);
}

/* path's GET, again while the host is not reached: its answer in r. */
static void
rc_get(const char *path, struct resp *r)
{

	for (int i = 0; i < 50; i++) {
		http("GET", path, NULL, r);
		if (r->status != 502 && r->status != 503)
			return;
		resp_free(r);
		usleep(100000);
	}
	http("GET", path, NULL, r);
}

/*
 * The fleet mount by each host's own schema (PLAN-SDN-YANG 4.3.1,
 * 4.3.2): an agent of the release the console is and one of a release
 * before (ARCANA_OLD_AGENT), each read by its own YANG library and .sid
 * files: what both have read from both, a module only the newer has
 * refused of the older as its modules', each one's library its own.
 * The older updated under the console (the newer program at its
 * address), its schema is read again and the module is there.
 */
CONSOLE_TC(restconf_revisions, "The fleet mount by each host's own schema: "
    "two agents of different releases, the older updated under the "
    "console and read again")
ATF_TC_BODY(restconf_revisions, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], jgd[MAXPATHLEN], uri[MAXPATHLEN + 8];
	char		 idn[16], ido[16], path[512];
	const char	*old;
	pid_t		 pid;
	int		 i;

	if ((old = old_agent(tc)) == NULL)
		atf_tc_skip("no agent of a release before: set ARCANA_OLD_AGENT "
		    "or old_agent");
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(jgd, sizeof(jgd), "%s", locate(tc,
	    "../../../usr.sbin/arcana-agent/arcana-agent", "arcana-agent",
	    "/usr/local/sbin/arcana-agent"));
	snprintf(uri, sizeof(uri), "unix:%s/jgd.sock", cwd);
	host_add("new", uri, idn, sizeof(idn));
	snprintf(uri, sizeof(uri), "unix:%s/old.sock", cwd);
	pid = agent_spawn(old, uri, NULL, "installed-old");
	wait_for("old.sock");
	host_add("old", uri, ido, sizeof(ido));

	/* What both have, read from both by their own SIDs. */
	for (i = 0; i < 2; i++) {
		snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/"
		    "host=%s/ietf-interfaces:interfaces", i == 0 ? idn : ido);
		rc_get(path, &r);
		ATF_CHECK_MSG(r.status == 200 && strstr(r.body,
		    "\"name\":\"lo0\"") != NULL, "%s: %d %s", i == 0 ? "new" :
		    "old", r.status, r.body);
		resp_free(&r);
	}
	/* Each one's library its own: arcana-steer the newer's alone. */
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/ietf-yang-library:yang-library", idn);
	rc_get(path, &r);
	ATF_CHECK_MSG(strstr(r.body, "\"arcana-steer\"") != NULL, "%d %s",
	    r.status, r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/ietf-yang-library:yang-library", ido);
	rc_get(path, &r);
	ATF_CHECK_MSG(r.status == 200 && strstr(r.body, "\"arcana-steer\"") ==
	    NULL, "%d %s", r.status, r.body);
	resp_free(&r);
	/* A module only the newer has: the older's modules have it not. */
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/arcana-steer:steering", ido);
	rc_get(path, &r);
	ATF_CHECK_MSG(r.status == 404 && strstr(r.body, "the host's modules "
	    "have no arcana-steer:steering") != NULL, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/arcana-steer:steering", idn);
	rc_get(path, &r);
	ATF_CHECK_MSG(strstr(r.body, "have no") == NULL, "%d %s", r.status,
	    r.body);
	resp_free(&r);

	/* The older updated under the console: the newer at its address. */
	(void)kill(pid, SIGTERM);
	for (i = 0; i < 100 && kill(pid, 0) == 0; i++)
		usleep(50000);
	(void)unlink("old.sock");
	(void)agent_spawn(jgd, uri, NULL, "installed-new");
	wait_for("old.sock");
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/arcana-steer:steering", ido);
	for (i = 0;; i++) {
		rc_get(path, &r);
		if (strstr(r.body, "have no") == NULL || i == 50)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_CHECK_MSG(strstr(r.body, "have no") == NULL, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/ietf-yang-library:yang-library", ido);
	rc_get(path, &r);
	ATF_CHECK_MSG(strstr(r.body, "\"arcana-steer\"") != NULL, "%d %s",
	    r.status, r.body);
	resp_free(&r);
}

/*
 * A tunable for the next boot (arcana-sysctl's boot) put in the
 * candidate and committed confirmed: one the kernel does not know stops
 * at unknown-tunable, accepted with it; the host's loader.conf.d file
 * has both, the kernel's value as it was; the operational state and the
 * hello say a reboot is needed; taken out, it is not.
 */
CONSOLE_TC(restconf_boot, "Loader tunables for the next boot through "
    "RESTCONF, warnings accepted; the operational state and the hello say "
    "a reboot is needed")
ATF_TC_BODY(restconf_boot, tc)
{
	struct resp	 r;
	char		 data[256], cand[256], path[512], body[512], *text;
	const char	*id;
	int		 run;
	size_t		 len = sizeof(run);
	uint8_t		 b;

	len = sizeof(b);
	ATF_REQUIRE(sysctlbyname("kern.racct.enable", &b, &len, NULL, 0) == 0);
	run = b;
	rc_lab(tc, data, cand, sizeof(cand));
	id = strrchr(data, '=') + 1;
	ATF_REQUIRE(mkdir("root/boot", 0755) == 0 || errno == EEXIST);
	snprintf(path, sizeof(path), "%s/arcana-sysctl:boot", cand);
	snprintf(body, sizeof(body), "{\"arcana-sysctl:boot\":{\"tunable\":["
	    "{\"name\":\"kern.racct.enable\",\"value\":\"%d\"},{\"name\":"
	    "\"arcana.nosuch.knob\",\"value\":\"7\"}]}}", 1 - run);
	http("PUT", path, body, &r);
	ATF_CHECK_MSG(r.status == 204 || r.status == 201, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	/* Stops at the name the kernel does not know; accepted, goes on. */
	snprintf(path, sizeof(path), "%s/ietf-netconf:commit", data);
	http("POST", path, "{\"ietf-netconf:input\":{\"confirmed\":[null],"
	    "\"confirm-timeout\":60,\"persist\":\"boot1\"}}", &r);
	ATF_CHECK_MSG(r.status >= 400 && strstr(r.body,
	    "\"error-app-tag\":\"unknown-tunable\"") != NULL, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	ATF_CHECK(access("root/boot/loader.conf.d/arcana.conf", F_OK) == -1);
	snprintf(path, sizeof(path), "%s/ietf-netconf:commit?arcana-accept="
	    "unknown-tunable,loader-conf-conflict", data);
	http("POST", path, "{\"ietf-netconf:input\":{\"confirmed\":[null],"
	    "\"confirm-timeout\":60,\"persist\":\"boot1\"}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-netconf:commit", data);
	http("POST", path, "{\"ietf-netconf:input\":{\"persist-id\":"
	    "\"boot1\"}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	text = slurp_file("root/boot/loader.conf.d/arcana.conf");
	snprintf(body, sizeof(body), "kern.racct.enable=\"%d\"\n"
	    "arcana.nosuch.knob=\"7\"\n", 1 - run);
	ATF_CHECK_STREQ(body, text);
	free(text);
	len = sizeof(b);
	ATF_REQUIRE(sysctlbyname("kern.racct.enable", &b, &len, NULL, 0) == 0);
	ATF_CHECK_EQ(run, b);
	/* Pending: the kernel's value now beside it. */
	snprintf(path, sizeof(path), "%s/arcana-sysctl:boot", data);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	snprintf(body, sizeof(body), "\"name\":\"kern.racct.enable\","
	    "\"pending\":true,\"running\":\"%d\",\"value\":\"%d\"", run,
	    1 - run);
	ATF_CHECK_MSG(strstr(r.body, body) != NULL, "%s", r.body);
	resp_free(&r);
	r3_read(id, "/arcana-sysctl:boot", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("kern.racct.enable", jstr(&r, "tunable.0.name"));
	ATF_CHECK_STREQ("true", jstr(&r, "tunable.0.pending"));
	ATF_CHECK_STREQ("arcana.nosuch.knob", jstr(&r, "tunable.1.name"));
	ATF_CHECK(jstr(&r, "tunable.1.pending") == NULL ||
	    strcmp(jstr(&r, "tunable.1.pending"), "false") == 0);
	resp_free(&r);
	r3_read(id, "/arcana-host:host", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "reboot-required"));
	resp_free(&r);
	/* Taken out: the file empty of them, no reboot needed. */
	snprintf(path, sizeof(path), "%s/arcana-sysctl:boot", cand);
	http("PUT", path, "{\"arcana-sysctl:boot\":{\"tunable\":[]}}", &r);
	ATF_CHECK_MSG(r.status == 204 || r.status == 201, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-netconf:commit", data);
	http("POST", path, "{}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	text = slurp_file("root/boot/loader.conf.d/arcana.conf");
	ATF_CHECK_STREQ("", text);
	free(text);
	r3_read(id, "/arcana-host:host", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "reboot-required"));
	resp_free(&r);
}

/*
 * A host's actions and rpcs through the fleet mount (PLAN-SDN-YANG
 * 4.3.4): each POSTed on its data path below the host's entry, its
 * input and output by the host's schema, what each does the host's own;
 * the role on the host each needs, a token's reach, a browser's POST
 * checked; YANG-CBOR either way.
 */
#define	SYSCTL_READ	"/arcana-sysctl:sysctl/read"
#define	JAIL_START	"/arcana-jails:jails/jail=web/start"

/* Line n of file (0 the first), in buf. */
static bool
log_line(const char *file, int n, char *buf, size_t len)
{
	FILE	*fp;
	bool	 ok = false;

	if ((fp = fopen(file, "r")) == NULL)
		return (false);
	for (int i = 0; i <= n; i++)
		if (!(ok = fgets(buf, (int)len, fp) != NULL))
			break;
	fclose(fp);
	return (ok);
}

CONSOLE_TC(restconf_actions, "A host's actions and rpcs POSTed through "
    "the fleet mount: input and output by the host's schema, the role each "
    "needs, tokens, CSRF, YANG-CBOR")
ATF_TC_BODY(restconf_actions, tc)
{
	/* {read: {prefix: "kern.ostype"}}, 63612 its SID. */
	static const uint8_t cin[] = { 0xa1, 0x19, 0xf8, 0x7c, 0xa1, 0x05,
	    0x6b, 'k', 'e', 'r', 'n', '.', 'o', 's', 't', 'y', 'p', 'e' };
	static const char rd[] = "{\"arcana-sysctl:input\":{\"prefix\":"
	    "\"kern.ostype\"}}";
	struct authn	 b;
	struct resp	 r;
	char		 data[256], cand[256], path[512], tok[96];
	char		 ctype[128], l1[256], l2[256], ostype[64];
	uint8_t		*out;
	size_t		 len;
	int		 st, i;

	rc_lab(tc, data, cand, sizeof(cand));
	/* jail(8)'s stand-in, what it was given kept. */
	put("fake-jail", "#!/bin/sh\nfor a; do [ \"$a\" = -e ] && "
	    "exec /usr/sbin/jail \"$@\"; done\necho \"fake-jail: $*\" | "
	    "tee -a jail.log\n");
	ATF_REQUIRE(chmod("fake-jail", 0755) == 0);

	/* A jail started: jail(8) told to make it. */
	snprintf(path, sizeof(path), "%s" JAIL_START, data);
	http("POST", path, "{}", &r);
	ATF_CHECK_MSG(r.status == 200 || r.status == 204, "%d %s", r.status,
	    r.body);
	if (r.status == 200)
		ATF_CHECK_MSG(strstr(r.body, "\"arcana-jails:output\"") != NULL,
		    "%s", r.body);
	resp_free(&r);
	ATF_REQUIRE(log_line("jail.log", 0, l1, sizeof(l1)));
	ATF_CHECK_MSG(strstr(l1, "-c web") != NULL, "%s", l1);
	/* None at all is no input too: the same again. */
	http("POST", path, NULL, &r);
	ATF_CHECK_MSG(r.status == 200 || r.status == 204, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	ATF_REQUIRE(log_line("jail.log", 1, l2, sizeof(l2)));
	ATF_CHECK_STREQ(l1, l2);

	/* A read action: what the kernel says. */
	len = sizeof(ostype);
	ATF_REQUIRE(sysctlbyname("kern.ostype", ostype, &len, NULL, 0) == 0);
	snprintf(path, sizeof(path), "%s" SYSCTL_READ, data);
	http("POST", path, rd, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("kern.ostype", jstr(&r,
	    "arcana-sysctl:output.value.0.name"));
	ATF_CHECK_STREQ(ostype, jstr(&r, "arcana-sysctl:output.value.0.value"));
	resp_free(&r);

	/* arcana-jobs' submit: two monitors set, one job each. */
	snprintf(path, sizeof(path), "%s/arcana-jobs:submit", data);
	for (i = 8; i <= 9; i++) {
		char	in[256];

		snprintf(in, sizeof(in), "{\"arcana-jobs:input\":{\"change\":[{"
		    "\"monitor\":{\"verb\":\"set\",\"args\":[\"name=gre%d\","
		    "\"interface=gre%d\",\"address=192.0.2.%d\",\"interval="
		    "500\"]}}]}}", i, i, i);
		http("POST", path, in, &r);
		EXPECT(&r, 200);
		ATF_CHECK_MSG(jstr(&r, "arcana-jobs:output.id.0") != NULL,
		    "%s", r.body);
		resp_free(&r);
	}
	snprintf(l1, sizeof(l1), "%s/arcana-probe:probes/read", data);
	for (i = 0; i < 100; i++) {
		http("POST", l1, "{\"arcana-probe:input\":{\"monitors\":true}}",
		    &r);
		if ((r.body != NULL && strstr(r.body, "gre8") != NULL &&
		    strstr(r.body, "gre9") != NULL) || i == 99)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_REQUIRE_MSG(i < 99, "the monitors are not both set: %s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"address\":\"192.0.2.8\"") != NULL &&
	    strstr(r.body, "\"address\":\"192.0.2.9\"") != NULL, "%s", r.body);
	resp_free(&r);
	/* What the host's schema refuses: its input. */
	http("POST", path, "{\"arcana-jobs:input\":{}}", &r);
	ATF_CHECK_MSG(r.status == 400, "%d %s", r.status, r.body);
	resp_free(&r);

	/* Bad input, by the host's schema; a body not an input. */
	snprintf(path, sizeof(path), "%s" SYSCTL_READ, data);
	rc_expect("POST", data, SYSCTL_READ, NULL, "{\"arcana-sysctl:input\":"
	    "{\"nosuch\":1}}", 400, "unknown-element");
	rc_expect("POST", data, SYSCTL_READ, NULL, "{\"arcana-sysctl:input\":"
	    "{\"count\":\"many\"}}", 400, "invalid-value");
	rc_expect("POST", data, SYSCTL_READ, NULL, "{\"input\":{}}", 400,
	    "malformed-message");
	rc_expect("POST", data, SYSCTL_READ "?depth=1", NULL, rd, 400,
	    "invalid-value");
	/* Read, not POSTed; none such; not the mount's. */
	rc_expect("GET", data, SYSCTL_READ, NULL, NULL, 405, NULL);
	rc_expect("POST", data, "/arcana-jails:jails/jail=web/nosuch", NULL,
	    "{}", 404, NULL);
	rc_expect("POST", data, "/ietf-netconf:get-config", NULL, "{}", 405,
	    NULL);
	rc_expect("POST", cand, JAIL_START, NULL, "{}", 405, NULL);

	/* YANG-CBOR in and out, and either alone. */
	st = http_bin("POST", path, "Content-Type: application/yang-data+cbor"
	    "\r\nAccept: application/yang-data+cbor\r\n", cin, sizeof(cin),
	    ctype, sizeof(ctype), &out, &len);
	ATF_CHECK_MSG(st == 200, "%d %s", st, out);
	ATF_CHECK_MSG(strncmp(ctype, "application/yang-data+cbor", 26) == 0,
	    "%s", ctype);
	ATF_CHECK(len > 4 && memcmp(out, cin, 4) == 0);
	ATF_CHECK(memmem(out, len, ostype, strlen(ostype)) != NULL);
	free(out);
	st = http_bin("POST", path, "Content-Type: application/yang-data+cbor"
	    "\r\n", cin, sizeof(cin), ctype, sizeof(ctype), &out, &len);
	ATF_CHECK_MSG(st == 200 && strstr((char *)out,
	    "\"arcana-sysctl:output\"") != NULL && strstr((char *)out,
	    ostype) != NULL, "%d %s", st, out);
	free(out);
	st = http_bin("POST", path, "Accept: application/yang-data+cbor\r\n",
	    rd, strlen(rd), ctype, sizeof(ctype), &out, &len);
	ATF_CHECK_MSG(st == 200 && len > 4 && memcmp(out, cin, 4) == 0, "%d",
	    st);
	free(out);
	st = http_bin("POST", path, "Content-Type: application/yang-data+cbor"
	    "\r\n", "\xa1\x19\x04\x00\xf6", 5, ctype, sizeof(ctype), &out,
	    &len);
	ATF_CHECK_MSG(st == 400 && strstr((char *)out, "malformed-message") !=
	    NULL, "%d %s", st, out);
	free(out);

	/* A read token: a read action, nothing that changes. */
	http("POST", CC "tokens/create", "{\"arcana-console:input\":{"
	    "\"name\":\"reader\"}}", &r);
	EXPECT(&r, 200);
	snprintf(tok, sizeof(tok), "%s", jstr(&r,
	    "arcana-console:output.token"));
	resp_free(&r);
	http_bearer("POST", path, tok, rd, &r);
	ATF_CHECK_MSG(r.status == 200, "%d %s", r.status, r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s" JAIL_START, data);
	http_bearer("POST", path, tok, "{}", &r);
	ATF_CHECK_MSG(r.status == 401, "%d %s", r.status, r.body);
	resp_free(&r);

	/* A browser's POST, a read's too: its Origin or X-Arcana. */
	send_xjg = false;
	origin_hdr = NULL;
	rc_expect("POST", data, SYSCTL_READ, NULL, rd, 403, NULL);
	rc_expect("POST", data, JAIL_START, NULL, "{}", 403, NULL);
	send_xjg = true;
	origin_hdr = harness_origin;

	/* A viewer: what reads, not what changes. */
	cc_user(&b, "vic", "\"role\":[\"viewer\"]", -8);
	rc_expect("POST", data, SYSCTL_READ, NULL, rd, 200, NULL);
	rc_expect("POST", data, JAIL_START, NULL, "{}", 403, NULL);
	rc_expect("POST", data, "/arcana-jobs:submit", NULL, "{}", 403, NULL);
	/* arcana-system's read, of its files: an operator's. */
	rc_expect("POST", data, "/arcana-system:system/read", NULL, "{}", 403,
	    NULL);
}

/* The socket's answer to request id: its steps counted, the rest. */
static char *
ws_answer(int ws, int id, int *steps)
{
	char	want[32], step[40], *m;

	snprintf(want, sizeof(want), "{\"id\":%d,\"", id);
	snprintf(step, sizeof(step), "{\"id\":%d,\"step\":", id);
	*steps = 0;
	while ((m = ws_recv(ws)) != NULL) {
		if (strncmp(m, step, strlen(step)) == 0)
			(*steps)++;
		else if (strncmp(m, want, strlen(want)) == 0)
			return (m);
		free(m);
	}
	return (NULL);
}

/*
 * A safe job submitted through the fleet mount and confirmed there
 * (PLAN-SDN-YANG 4.8.1): arcana-jobs' confirm over a connection the
 * console dials for it, the job kept.
 */
CONSOLE_TC(restconf_job_confirm, "A safe job through the fleet mount, "
    "confirmed by arcana-jobs' confirm")
ATF_TC_BODY(restconf_job_confirm, tc)
{
	struct resp	 r;
	char		 data[256], cand[256], path[512];
	int		 i;

	rc_lab(tc, data, cand, sizeof(cand));
	snprintf(path, sizeof(path), "%s/arcana-jobs:submit", data);
	http("POST", path, "{\"arcana-jobs:input\":{\"change\":[{\"route\":"
	    "{\"destination\":\"10.9.0.0/16\",\"gateway\":\"10.0.0.1\"},"
	    "\"safe\":true,\"safe-wait\":30}]}}", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_MSG(strstr(r.body, "\"id\":[\"1\"]") != NULL, "%s",
	    r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/arcana-jobs:jobs/job=1/read", data);
	for (i = 0; i < 100; i++) {
		http("POST", path, "{}", &r);
		if (strstr(r.body, "\"state\":\"unconfirmed\"") != NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_REQUIRE_MSG(i < 100, "never unconfirmed");
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/arcana-jobs:jobs/job=1/confirm",
	    data);
	http("POST", path, "{}", &r);
	ATF_CHECK_MSG(r.status == 200 || r.status == 204, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/arcana-jobs:jobs/job=1/read", data);
	for (i = 0; i < 100; i++) {
		http("POST", path, "{}", &r);
		if (strstr(r.body, "\"state\":\"done\"") != NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_CHECK_MSG(i < 100 && strstr(r.body, "\"ok\":true") != NULL,
	    "not kept: %s", r.body);
	resp_free(&r);
}

/*
 * A page's read through the fleet mount over the console's socket
 * (PLAN-SDN-YANG 4.8.1): a GET and an action that reads answered as
 * RESTCONF answers, the host's steps told as it takes them; a change
 * refused, as a path no module has.
 */
CONSOLE_TC(stream_restconf, "Reads through the fleet mount over the "
    "console's socket, with their steps; a change refused")
ATF_TC_BODY(stream_restconf, tc)
{
	char		 data[256], cand[256], ask[400], *m;
	const char	*id;
	int		 ws, steps;

	rc_lab(tc, data, cand, sizeof(cand));
	id = strrchr(data, '=') + 1;
	ws = ws_open("/api/stream");
	snprintf(ask, sizeof(ask), "{\"id\":1,\"server\":\"%s\",\"what\":"
	    "\"restconf\",\"path\":\"arcana-services:services\"}", id);
	ws_send(ws, ask);
	m = ws_answer(ws, 1, &steps);
	ATF_REQUIRE(m != NULL);
	ATF_CHECK_MSG(strstr(m, "\"status\":200") != NULL && strstr(m,
	    "\"arcana-services:services\"") != NULL && strstr(m,
	    "\"name\":\"sshd\"") != NULL, "%s", m);
	/* service(8) asked of each: steps of the host's. */
	ATF_CHECK_MSG(steps > 0, "no steps: %s", m);
	free(m);
	snprintf(ask, sizeof(ask), "{\"id\":2,\"server\":\"%s\",\"what\":"
	    "\"restconf\",\"path\":\"arcana-sysctl:sysctl/read\",\"body\":"
	    "{\"arcana-sysctl:input\":{\"prefix\":\"kern.ostype\"}}}", id);
	ws_send(ws, ask);
	m = ws_answer(ws, 2, &steps);
	ATF_REQUIRE(m != NULL);
	ATF_CHECK_MSG(strstr(m, "\"status\":200") != NULL && strstr(m,
	    "\"arcana-sysctl:output\"") != NULL && strstr(m,
	    "\"kern.ostype\"") != NULL, "%s", m);
	free(m);
	/* A change: not over the socket. */
	snprintf(ask, sizeof(ask), "{\"id\":3,\"server\":\"%s\",\"what\":"
	    "\"restconf\",\"path\":\"arcana-jails:jails/jail=web/start\","
	    "\"body\":{}}", id);
	ws_send(ws, ask);
	m = ws_answer(ws, 3, &steps);
	ATF_REQUIRE(m != NULL);
	ATF_CHECK_MSG(strstr(m, "\"status\":403") != NULL && strstr(m,
	    "only a read") != NULL, "%s", m);
	free(m);
	snprintf(ask, sizeof(ask), "{\"id\":4,\"server\":\"%s\",\"what\":"
	    "\"restconf\",\"path\":\"arcana-nothing:nothing\"}", id);
	ws_send(ws, ask);
	m = ws_answer(ws, 4, &steps);
	ATF_REQUIRE(m != NULL);
	ATF_CHECK_MSG(strstr(m, "\"status\":404") != NULL ||
	    strstr(m, "\"status\":400") != NULL, "%s", m);
	free(m);
	close(ws);
}

/* A safe if-address job submitted through the fleet mount, its
 * safe-wait (0: none) said; the timer its trace says, -1 refused. */
static int
rc_safe_job(const char *data, const char *addr, int wait)
{
	struct resp	 r;
	char		 path[512], body[512], sw[32];
	const char	*t;
	int		 i, timer = -1;

	snprintf(sw, sizeof(sw), ",\"safe-wait\":%d", wait);
	snprintf(body, sizeof(body), "{\"arcana-jobs:input\":{\"change\":[{"
	    "\"if-address\":{\"interface\":\"lo0\",\"address\":\"%s\"},"
	    "\"safe\":true%s}]}}", addr, wait > 0 ? sw : "");
	snprintf(path, sizeof(path), "%s/arcana-jobs:submit", data);
	http("POST", path, body, &r);
	if (r.status != 200) {
		ATF_CHECK_MSG(r.status == 400 && jstr(&r, ERROR_TAG) != NULL &&
		    strcmp(jstr(&r, ERROR_TAG), "invalid-value") == 0, "%d %s",
		    r.status, r.body);
		resp_free(&r);
		return (-1);
	}
	ATF_REQUIRE_MSG(jstr(&r, "arcana-jobs:output.id.0") != NULL, "%s",
	    r.body);
	snprintf(path, sizeof(path), "%s/arcana-jobs:jobs/job=%s/read", data,
	    jstr(&r, "arcana-jobs:output.id.0"));
	snprintf(body, sizeof(body), "%s/arcana-jobs:jobs/job=%s/confirm",
	    data, jstr(&r, "arcana-jobs:output.id.0"));
	resp_free(&r);
	/* Unconfirmed, confirmed by arcana-jobs' confirm. */
	for (i = 0; i < 200; i++) {
		http("POST", path, "{}", &r);
		EXPECT(&r, 200);
		if (strstr(r.body, "\"state\":\"done\"") != NULL)
			break;
		if (strstr(r.body, "\"state\":\"unconfirmed\"") != NULL) {
			struct resp	c;

			http("POST", body, "{}", &c);
			ATF_CHECK_MSG(c.status == 200 || c.status == 204,
			    "%d %s", c.status, c.body);
			resp_free(&c);
		}
		resp_free(&r);
		usleep(50000);
	}
	ATF_REQUIRE_MSG(i < 200, "the safe job did not finish");
	if ((t = strstr(r.body, "the timer was ")) != NULL)
		timer = atoi(t + strlen("the timer was "));
	ATF_CHECK_MSG(timer > 0, "%s", r.body);
	resp_free(&r);
	return (timer);
}

CONSOLE_TC(restconf_jobs_safe_wait, "arcana-jobs:submit through the fleet "
    "mount: a safe change with no safe-wait takes the host's timer, else "
    "Settings'; its own wins, out of the bounds Settings has 400")
ATF_TC_BODY(restconf_jobs_safe_wait, tc)
{
	struct resp	 r;
	char		 data[256], cand[256], path[128], id[16];

	rc_lab(tc, data, cand, sizeof(cand));
	snprintf(id, sizeof(id), "%s", strrchr(data, '=') + 1);
	r3_host_set(id, "\"safe-wait\":15", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	ATF_CHECK_EQ(15, rc_safe_job(data, "10.9.1.1/24", 0));
	ATF_CHECK_EQ(40, rc_safe_job(data, "10.9.1.2/24", 40));
	/* None of the host's: Settings'. */
	snprintf(path, sizeof(path), CC "hosts/host=%s/safe-wait", id);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	r3_settings("\"safe-wait\":25", 204);
	ATF_CHECK_EQ(25, rc_safe_job(data, "10.9.1.3/24", 0));
	/* The bounds, 10 to 3600 s. */
	ATF_CHECK_EQ(-1, rc_safe_job(data, "10.9.1.4/24", 3601));
	ATF_CHECK_EQ(-1, rc_safe_job(data, "10.9.1.4/24", 5));
}

/*
 * An agent of a release before (ARCANA_OLD_AGENT) lacks actions the
 * console's tables have: a clean 404, its module there all the same.
 */
CONSOLE_TC(restconf_actions_old, "An action or an rpc an older agent "
    "lacks: 404, by its own schema")
ATF_TC_BODY(restconf_actions_old, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], uri[MAXPATHLEN + 8], idn[16], ido[16];
	char		 path[512];
	const char	*old;
	int		 i;

	if ((old = old_agent(tc)) == NULL)
		atf_tc_skip("no agent of a release before: set ARCANA_OLD_AGENT "
		    "or old_agent");
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(uri, sizeof(uri), "unix:%s/jgd.sock", cwd);
	host_add("new", uri, idn, sizeof(idn));
	snprintf(uri, sizeof(uri), "unix:%s/old.sock", cwd);
	(void)agent_spawn(old, uri, NULL, "installed-old");
	wait_for("old.sock");
	host_add("old", uri, ido, sizeof(ido));
	/* Its library has the modules, not the actions. */
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/ietf-yang-library:yang-library", ido);
	rc_get(path, &r);
	ATF_CHECK_MSG(r.status == 200 && strstr(r.body, "\"arcana-jobs\"") !=
	    NULL && strstr(r.body, "\"arcana-firewall\"") != NULL, "%d %s",
	    r.status, r.body);
	resp_free(&r);
	for (i = 0; i < 2; i++) {
		snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/"
		    "host=%s/arcana-jobs:dry-run", i == 0 ? ido : idn);
		http("POST", path, "{\"arcana-jobs:input\":{\"change\":[{"
		    "\"monitor\":{\"verb\":\"remove\",\"args\":[\"name=x\"]}}]}}",
		    &r);
		if (i == 0)
			ATF_CHECK_MSG(r.status == 404 && strstr(r.body,
			    "no rpc arcana-jobs:dry-run") != NULL, "%d %s",
			    r.status, r.body);
		else
			ATF_CHECK_MSG(strstr(r.body, "have no") == NULL,
			    "%d %s", r.status, r.body);
		resp_free(&r);
		snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/"
		    "host=%s/arcana-firewall:firewall/from-rc", i == 0 ? ido :
		    idn);
		http("POST", path, "{}", &r);
		if (i == 0)
			ATF_CHECK_MSG(r.status == 404 && strstr(r.body,
			    "no action arcana-firewall:from-rc") != NULL,
			    "%d %s", r.status, r.body);
		else
			ATF_CHECK_MSG(strstr(r.body, "have no") == NULL,
			    "%d %s", r.status, r.body);
		resp_free(&r);
	}
}

/*
 * An agent of a release before (ARCANA_OLD_AGENT): its sampling neither
 * held nor switched off, refused by its own schema; the rest of its
 * history set as before.
 */
CONSOLE_TC(sampling_old, "An older agent's sampling switch and hold "
    "refused, by its own schema")
ATF_TC_BODY(sampling_old, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], uri[MAXPATHLEN + 8], ido[16];
	const char	*old;

	if ((old = old_agent(tc)) == NULL)
		atf_tc_skip("no agent of a release before: set ARCANA_OLD_AGENT "
		    "or old_agent");
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(uri, sizeof(uri), "unix:%s/old.sock", cwd);
	(void)agent_spawn(old, uri, NULL, "installed-old");
	wait_for("old.sock");
	host_add("old", uri, ido, sizeof(ido));
	r3_history_get(ido, &r);
	ATF_CHECK_MSG(jstr(&r, "sampling.step") != NULL && jstr(&r,
	    "sampling.enabled") == NULL, "%s", r.body);
	resp_free(&r);
	ATF_CHECK_EQ(400, r3_history(ido, "\"sampling\":{\"step\":5,\"keep\":"
	    "720,\"enabled\":false}"));
	ATF_CHECK_EQ(400, r3_history(ido, "\"sampling\":{\"step\":5,\"keep\":"
	    "720,\"hold\":0}"));
	ATF_CHECK_EQ(204, r3_history(ido, "\"sampling\":{\"step\":5,\"keep\":"
	    "700}"));
	r3_history_get(ido, &r);
	ATF_CHECK_MSG(jstr(&r, "sampling.keep") != NULL && strcmp(jstr(&r,
	    "sampling.keep"), "700") == 0, "%s", r.body);
	resp_free(&r);
}

#define	SAPNET	"/restconf/data/ietf-network:networks"

/* The body of r parsed; NULL: not JSON. */
static ucl_object_t *
body_of(const struct resp *r)
{
	struct ucl_parser	*p;
	ucl_object_t		*o = NULL;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
	if (r->body != NULL && ucl_parser_add_string(p, r->body, 0))
		o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	return (o);
}

/* The entry of list l whose member k is v; NULL: none. */
static const ucl_object_t *
keyed(const ucl_object_t *l, const char *k, const char *v)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	const char		*s;

	while ((e = ucl_object_iterate(l, &it, true)) != NULL)
		if ((s = ucl_object_tostring(ucl_object_lookup(e, k))) !=
		    NULL && strcmp(s, v) == 0)
			return (e);
	return (NULL);
}

/* Node id of network nw of networks top. */
static const ucl_object_t *
sn_node(const ucl_object_t *top, const char *nw, const char *id)
{

	return (keyed(ucl_object_lookup(keyed(ucl_object_lookup_path(top,
	    "ietf-network:networks.network"), "network-id", nw), "node"),
	    "node-id", id));
}

/* SAP id of node nd. */
static const ucl_object_t *
sn_sap(const ucl_object_t *nd, const char *id)
{

	return (keyed(ucl_object_lookup(ucl_array_find_index(
	    ucl_object_lookup(nd, "ietf-sap-ntw:service"), 0), "sap"),
	    "sap-id", id));
}

/* A SAP of node nd whose status is st, free or not as said (-1: either):
 * its id in buf; NULL: none. */
static const char *
sn_find(const ucl_object_t *nd, const char *st, int free_, char *buf,
    size_t len)
{
	const ucl_object_t	*s;
	ucl_object_iter_t	 it = NULL;

	while ((s = ucl_object_iterate(ucl_object_lookup(ucl_array_find_index(
	    ucl_object_lookup(nd, "ietf-sap-ntw:service"), 0), "sap"), &it,
	    true)) != NULL) {
		if (strcmp(ucl_object_tostring_forced(ucl_object_lookup_path(s,
		    "sap-status.status")), st) != 0)
			continue;
		if (free_ != -1 && ucl_object_toboolean(ucl_object_lookup(s,
		    "arcana-l3nm:free")) != (free_ == 1))
			continue;
		snprintf(buf, len, "%s", ucl_object_tostring(
		    ucl_object_lookup(s, "sap-id")));
		return (buf);
	}
	return (NULL);
}

/*
 * The fleet's SAP network (PLAN-SDN-YANG 4.6.2, RFC 9408): two agents'
 * nodes merged, a node each, over the physical network; a SAP an L3NM
 * access names shows its service and is no longer free, the same SAP of
 * the other host free; a service at a SAP that is down an anomaly; an
 * agent of a release before 4.6.1 (ARCANA_OLD_AGENT) left out.
 */
CONSOLE_TC(sapnet, "The fleet's SAP network: two hosts' nodes merged, a SAP "
    "an L3NM access names showing its service, an anomaly, an agent "
    "without SAPs left out")
ATF_TC_BODY(sapnet, tc)
{
	struct authn		 a;
	struct resp		 r;
	ucl_object_t		*top;
	const ucl_object_t	*n1, *n2, *s;
	char			 cwd[MAXPATHLEN], jgd[MAXPATHLEN];
	char			 uri[MAXPATHLEN + 8], id1[16], id2[16], ido[16];
	char			 up[64], down[64], body[1024];
	const char		*old;
	bool			 has_down;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(jgd, sizeof(jgd), "%s", locate(tc,
	    "../../../usr.sbin/arcana-agent/arcana-agent", "arcana-agent",
	    "/usr/local/sbin/arcana-agent"));
	snprintf(uri, sizeof(uri), "unix:%s/jgd.sock", cwd);
	host_add("one", uri, id1, sizeof(id1));
	snprintf(uri, sizeof(uri), "unix:%s/two.sock", cwd);
	(void)agent_spawn(jgd, uri, NULL, "installed-two");
	wait_for("two.sock");
	host_add("two", uri, id2, sizeof(id2));
	ido[0] = '\0';
	if ((old = old_agent(tc)) != NULL) {
		snprintf(uri, sizeof(uri), "unix:%s/old.sock", cwd);
		ATF_REQUIRE(rename("arcana-agent2.pid", "arcana-agent3.pid") ==
		    0);
		(void)agent_spawn(old, uri, NULL, "installed-old");
		wait_for("old.sock");
		host_add("old", uri, ido, sizeof(ido));
	}

	/* Both nodes, each over its physical node; the older's none. */
	http("GET", SAPNET, NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE((top = body_of(&r)) != NULL);
	n1 = sn_node(top, "arcana-sap", id1);
	n2 = sn_node(top, "arcana-sap", id2);
	ATF_REQUIRE_MSG(n1 != NULL && n2 != NULL, "%s", r.body);
	ATF_CHECK(sn_node(top, "arcana-physical", id1) != NULL);
	ATF_CHECK(sn_node(top, "arcana-physical", id2) != NULL);
	ATF_CHECK_STREQ("arcana-physical", ucl_object_tostring(
	    ucl_object_lookup_path(keyed(ucl_object_lookup_path(top,
	    "ietf-network:networks.network"), "network-id", "arcana-sap"),
	    "supporting-network.0.network-ref")));
	ATF_CHECK_STREQ(id1, ucl_object_tostring(ucl_object_lookup_path(n1,
	    "supporting-node.0.node-ref")));
	if (ido[0] != '\0')
		ATF_CHECK_MSG(sn_node(top, "arcana-sap", ido) == NULL &&
		    sn_node(top, "arcana-physical", ido) == NULL, "%s",
		    r.body);
	/* An up UNI free on both; no access names any yet. */
	ATF_REQUIRE_MSG(sn_find(n1, "ietf-vpn-common:op-up", 1, up,
	    sizeof(up)) != NULL, "no free SAP up: %s", r.body);
	ATF_CHECK(sn_sap(n2, up) != NULL);
	ATF_CHECK_STREQ("ietf-vpn-common:admin-down", ucl_object_tostring(
	    ucl_object_lookup_path(sn_sap(n1, up),
	    "service-status.admin-status.status")));
	has_down = sn_find(n1, "ietf-vpn-common:op-down", -1, down,
	    sizeof(down)) != NULL;
	ucl_object_unref(top);
	resp_free(&r);

	/* A service at it on host one, and at a SAP that is down. */
	snprintf(body, sizeof(body), "{\"ietf-l3vpn-ntw:vpn-services\":"
	    "{\"vpn-service\":[{\"vpn-id\":\"s1\",\"vpn-nodes\":{\"vpn-node\":"
	    "[{\"vpn-node-id\":\"%s\",\"ne-id\":\"%s\",\"vpn-network-accesses\":"
	    "{\"vpn-network-access\":[{\"id\":\"a1\",\"interface-id\":\"%s\"}"
	    "%s%s%s]}}]}}]}}", id1, id1, up, has_down ? ",{\"id\":\"a2\","
	    "\"interface-id\":\"" : "", has_down ? down : "", has_down ? "\"}" :
	    "");
	http("POST", L3NM, body, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", SAPNET, NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE((top = body_of(&r)) != NULL);
	s = sn_sap(sn_node(top, "arcana-sap", id1), up);
	ATF_REQUIRE_MSG(s != NULL, "%s", r.body);
	ATF_CHECK_STREQ("s1", ucl_object_tostring(ucl_object_lookup_path(s,
	    "arcana-l3nm:attachment.0.vpn-id")));
	ATF_CHECK_STREQ("a1", ucl_object_tostring(ucl_object_lookup_path(s,
	    "arcana-l3nm:attachment.0.access-id")));
	ATF_CHECK(!ucl_object_toboolean(ucl_object_lookup_path(s,
	    "arcana-l3nm:attachment.0.made")));
	ATF_CHECK_STREQ("ietf-vpn-common:admin-up", ucl_object_tostring(
	    ucl_object_lookup_path(s, "service-status.admin-status.status")));
	ATF_CHECK_STREQ("ietf-vpn-common:op-down", ucl_object_tostring(
	    ucl_object_lookup_path(s, "service-status.oper-status.status")));
	ATF_CHECK(!ucl_object_toboolean(ucl_object_lookup(s,
	    "arcana-l3nm:free")));
	ATF_CHECK(ucl_object_lookup(s, "arcana-l3nm:anomaly") == NULL);
	/* The same interface of the other host: free still. */
	s = sn_sap(sn_node(top, "arcana-sap", id2), up);
	ATF_CHECK(s != NULL && ucl_object_toboolean(ucl_object_lookup(s,
	    "arcana-l3nm:free")) && ucl_object_lookup(s,
	    "arcana-l3nm:attachment") == NULL);
	if (has_down) {
		s = sn_sap(sn_node(top, "arcana-sap", id1), down);
		ATF_CHECK_STREQ("arcana-l3nm:sap-down-service-up",
		    ucl_object_tostring(ucl_object_lookup_path(s,
		    "arcana-l3nm:anomaly.0")));
		ATF_CHECK(!ucl_object_toboolean(ucl_object_lookup(s,
		    "arcana-l3nm:free")));
	}
	ucl_object_unref(top);
	resp_free(&r);

	/* Administratively down: no anomaly, nothing made. */
	http("PATCH", L3NM "/vpn-services/vpn-service=s1", "{\"ietf-l3vpn-ntw:"
	    "vpn-service\":[{\"vpn-id\":\"s1\",\"status\":{\"admin-status\":"
	    "{\"status\":\"ietf-vpn-common:admin-down\"}}}]}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", SAPNET "/network=arcana-sap", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE((top = body_of(&r)) != NULL);
	s = sn_sap(keyed(ucl_object_lookup(ucl_array_find_index(
	    ucl_object_lookup(top, "ietf-network:network"), 0), "node"),
	    "node-id", id1), has_down ? down : up);
	ATF_CHECK_MSG(s != NULL && ucl_object_lookup(s,
	    "arcana-l3nm:anomaly") == NULL, "%s", r.body);
	ATF_CHECK_STREQ("ietf-vpn-common:admin-down", ucl_object_tostring(
	    ucl_object_lookup_path(s, "service-status.admin-status.status")));
	ucl_object_unref(top);
	resp_free(&r);
	http("GET", SAPNET "/network=nowhere", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("POST", SAPNET, "{}", &r);
	EXPECT(&r, 405);
	resp_free(&r);
}

/*
 * RFC 9408 Appendix D's flow (PLAN-SDN-YANG 4.6.3): a service placed on
 * a free SAP, the access's id its sap-id and its interface-id the SAP's
 * attachment-interface, the node made with the host its ne-id; the SAP
 * then the service's and no longer free; the same SAP again refused, as
 * a SAP or a service that is not there.
 */
CONSOLE_TC(sapnet_attach, "A service placed on a free SAP: the access "
    "made of it, the SAP the service's, the same again refused")
ATF_TC_BODY(sapnet_attach, tc)
{
	struct authn		 a;
	struct resp		 r;
	ucl_object_t		*top;
	const ucl_object_t	*s;
	char			 cwd[MAXPATHLEN], uri[MAXPATHLEN + 8], id1[16];
	char			 body[512], sap[64], path[256];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(uri, sizeof(uri), "unix:%s/jgd.sock", cwd);
	host_add("one", uri, id1, sizeof(id1));
	http("POST", L3NM, "{\"ietf-l3vpn-ntw:vpn-services\":{\"vpn-service\":"
	    "[{\"vpn-id\":\"s1\"}]}}", &r);
	EXPECT(&r, 201);
	resp_free(&r);

	/* No such service, no such SAP. */
	snprintf(body, sizeof(body), "\"vpn-id\":\"nope\",\"vpn-node-id\":"
	    "\"%s\"", id1);
	rc_act(CC "sdwan/attach", body, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	snprintf(body, sizeof(body), "\"vpn-id\":\"s1\",\"vpn-node-id\":"
	    "\"%s\",\"sap-id\":\"nosuch0\"", id1);
	rc_act(CC "sdwan/attach", body, &r);
	EXPECT(&r, 404);
	resp_free(&r);

	/* The first free SAP taken, the access made of it. */
	snprintf(body, sizeof(body), "\"vpn-id\":\"s1\",\"vpn-node-id\":"
	    "\"%s\",\"access\":{\"description\":\"placed\"}", id1);
	rc_act(CC "sdwan/attach", body, &r);
	ATF_CHECK_MSG(r.status == 200 || r.status == 201, "%d %s", r.status,
	    r.body);
	ATF_REQUIRE_MSG(jstr(&r, "sap-id") != NULL, "%s", r.body);
	snprintf(sap, sizeof(sap), "%s", jstr(&r, "sap-id"));
	ATF_CHECK_STREQ(sap, jstr(&r, "access-id"));
	ATF_CHECK_STREQ(id1, jstr(&r, "host"));
	resp_free(&r);
	snprintf(path, sizeof(path), L3NM "/vpn-services/vpn-service=s1/"
	    "vpn-nodes/vpn-node=%s", id1);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(id1, jstr(&r, "ietf-l3vpn-ntw:vpn-node.0.ne-id"));
	ATF_CHECK_STREQ(sap, jstr(&r, "ietf-l3vpn-ntw:vpn-node.0."
	    "vpn-network-accesses.vpn-network-access.0.id"));
	ATF_CHECK(jstr(&r, "ietf-l3vpn-ntw:vpn-node.0.vpn-network-accesses."
	    "vpn-network-access.0.interface-id") != NULL);
	ATF_CHECK_STREQ("placed", jstr(&r, "ietf-l3vpn-ntw:vpn-node.0."
	    "vpn-network-accesses.vpn-network-access.0.description"));
	resp_free(&r);

	/* The SAP the service's now, no longer free. */
	http("GET", SAPNET, NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE((top = body_of(&r)) != NULL);
	s = sn_sap(sn_node(top, "arcana-sap", id1), sap);
	ATF_REQUIRE_MSG(s != NULL, "%s", r.body);
	ATF_CHECK_STREQ("s1", ucl_object_tostring(ucl_object_lookup_path(s,
	    "arcana-l3nm:attachment.0.vpn-id")));
	ATF_CHECK(!ucl_object_toboolean(ucl_object_lookup(s,
	    "arcana-l3nm:free")));
	ucl_object_unref(top);
	resp_free(&r);

	/* The same SAP again: not free. */
	snprintf(body, sizeof(body), "\"vpn-id\":\"s1\",\"vpn-node-id\":"
	    "\"%s\",\"sap-id\":\"%s\"", id1, sap);
	rc_act(CC "sdwan/attach", body, &r);
	EXPECT(&r, 409);
	ATF_CHECK_MSG(strstr(r.body, "not free") != NULL, "%s", r.body);
	resp_free(&r);
	rc_act(CC "sdwan/attach", "\"vpn-id\":\"s1\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);
}

CONSOLE_TC(enrol, "The console's own CA, a host's certificate renewed, the CA changed for another and for an intermediate across the hosts, and a host joining with "
    "arcana-enrol(8)")
ATF_TC_BODY(enrol, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 url[64], body[512], tok[80], listen[64], path[128];
	char		 tool[MAXPATHLEN], jgd[MAXPATHLEN], *argv[20], id[16];
	char		 gone[16];
	FILE		*fp;
	pid_t		 pid;
	int		 port, jport, i;

	port = 20000 + (int)(getpid() % 20000);
	snprintf(tool, sizeof(tool), "%s", locate(tc,
	    "../../../usr.sbin/arcana-enrol/arcana-enrol", "enrol",
	    "/usr/local/sbin/arcana-enrol"));
	ATF_REQUIRE_MSG(access(tool, X_OK) == 0, "no arcana-enrol at %s",
	    tool);
	start(tc, port, NULL);

	/* No tls block in web.conf: the console made a CA of its own. */
	ATF_CHECK(access("data/ca.pem", F_OK) == 0);
	ATF_CHECK(access("data/ca.key", F_OK) == 0);
	ATF_CHECK(access("data/console.pem", F_OK) == 0);
	ATF_CHECK(access("data/console.key", F_OK) == 0);

	/* Enrolment is for the logged-in user; the joining host needs
	 * only its token. */
	rc_act(CC "enrolment/create-token", "\"name\":\"lab\",\"host\":"
	    "\"127.0.0.1\"", &r);
	EXPECT(&r, 401);
	resp_free(&r);
	enrol(&a);
	rc_act(CC "enrolment/create-token", "\"name\":\"lab\",\"host\":"
	    "\"not a host\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	rc_act(CC "enrolment/create-token", "\"name\":\"lab\",\"host\":"
	    "\"127.0.0.1\"", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_MSG(jstr(&r, "token") != NULL, "%s", r.body);
	snprintf(tok, sizeof(tok), "%s", jstr(&r, "token"));
	ATF_CHECK_MSG(strstr(jstr(&r, "command"), "arcana-enrol -s http://"
	    "localhost:") != NULL, "%s", jstr(&r, "command"));
	resp_free(&r);
	/* Another port than the usual is in the command for the host. */
	rc_act(CC "enrolment/create-token", "\"name\":\"lab\",\"host\":"
	    "\"127.0.0.1\",\"port\":4311", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(jstr(&r, "command"), "arcana-enrol -s -p 4311 "
	    "http://") != NULL, "%s", jstr(&r, "command"));
	resp_free(&r);
	http("POST", "/api/enrol", "{\"token\":\"nope\",\"csr\":\"\"}", &r);
	EXPECT(&r, 403);
	resp_free(&r);

	/* The host joins, by the address the console listens on: localhost
	 * may be ::1 first, and where that is dropped rather than refused,
	 * fetch(3) waits out its connect before it tries 127.0.0.1. */
	snprintf(url, sizeof(url), "http://127.0.0.1%s", strrchr(
	    harness_origin, ':'));
	i = 0;
	argv[i++] = tool;
	argv[i++] = (char *)(uintptr_t)"-d";
	argv[i++] = (char *)(uintptr_t)"host";
	argv[i++] = url;
	argv[i++] = tok;
	argv[i] = NULL;
	ATF_REQUIRE_MSG(run_prog(argv), "arcana-enrol failed");
	ATF_CHECK(access("host/host.key", F_OK) == 0);
	ATF_CHECK(access("host/host.pem", F_OK) == 0);
	ATF_CHECK(access("host/ca.pem", F_OK) == 0);
	i = 0;
	argv[i++] = (char *)(uintptr_t)"/usr/bin/openssl";
	argv[i++] = (char *)(uintptr_t)"verify";
	argv[i++] = (char *)(uintptr_t)"-CAfile";
	argv[i++] = (char *)(uintptr_t)"data/ca.pem";
	argv[i++] = (char *)(uintptr_t)"host/host.pem";
	argv[i] = NULL;
	ATF_CHECK_MSG(run_prog(argv), "the certificate does not verify");
	/* The token is used up. */
	i = 0;
	argv[i++] = tool;
	argv[i++] = (char *)(uintptr_t)"-d";
	argv[i++] = (char *)(uintptr_t)"again";
	argv[i++] = url;
	argv[i++] = tok;
	argv[i] = NULL;
	ATF_CHECK(!run_prog(argv));

	/* It is a server now, and a arcana-agent with the certificate
	 * answers the console over mutual TLS. */
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("lab", jstr(&r, "arcana-console:hosts.host.0.name"));
	ATF_CHECK_STREQ("tcp://127.0.0.1:4310", jstr(&r,
	    "arcana-console:hosts.host.0.uri"));
	snprintf(path, sizeof(path), CC "hosts/host=%s", jstr(&r,
	    "arcana-console:hosts.host.0.id"));
	resp_free(&r);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	jport = port + 1;
	snprintf(listen, sizeof(listen), "tcp://127.0.0.1:%d", jport);
	snprintf(jgd, sizeof(jgd), "%s", locate(tc,
	    "../../../usr.sbin/arcana-agent/arcana-agent", "arcana-agent",
	    "/usr/local/sbin/arcana-agent"));
	i = 0;
	argv[i++] = jgd;
	argv[i++] = (char *)(uintptr_t)"-F";
	argv[i++] = (char *)(uintptr_t)"-l";
	argv[i++] = listen;
	argv[i++] = (char *)(uintptr_t)"-A";
	argv[i++] = (char *)(uintptr_t)"host/ca.pem";
	argv[i++] = (char *)(uintptr_t)"-C";
	argv[i++] = (char *)(uintptr_t)"host/host.pem";
	argv[i++] = (char *)(uintptr_t)"-K";
	argv[i++] = (char *)(uintptr_t)"host/host.key";
	argv[i++] = (char *)(uintptr_t)"-f";
	argv[i++] = (char *)(uintptr_t)"etc/jail.conf";
	argv[i++] = (char *)(uintptr_t)"-D";
	argv[i++] = (char *)(uintptr_t)"etc/jail.conf.d";
	argv[i++] = (char *)(uintptr_t)"-j";
	argv[i++] = (char *)(uintptr_t)"./fake-jail";
	argv[i] = NULL;
	pid = spawn_server(argv, "arcana-agent2.out");
	ATF_REQUIRE((fp = fopen("arcana-agent2.pid", "w")) != NULL);
	fprintf(fp, "%d\n", (int)pid);
	fclose(fp);
	usleep(300000);
	snprintf(body, sizeof(body), "tcp://127.0.0.1:%d", jport);
	host_add("lab", body, id, sizeof(id));
	r3_web(id);
	/* By mutual TLS: the agent says who the console's certificate is. */
	r3_transport(id, &r);
	ATF_CHECK_MSG(jstr(&r, "data.sessions.0.subject") != NULL, "%s",
	    r.body);
	resp_free(&r);

	/* A host's certificate may reach hosts, but asks nothing of them
	 * as the console does: refused by the agent. */
	ATF_CHECK(system("openssl x509 -in host/host.pem -noout -ext "
	    "extendedKeyUsage,subjectAltName | grep -q 'TLS Web Client "
	    "Authentication' && openssl x509 -in host/host.pem -noout -ext "
	    "subjectAltName | grep -q 'URI:urn:arcana:role:agent' && openssl "
	    "x509 -in data/console.pem -noout -ext subjectAltName | grep -q "
	    "'URI:urn:arcana:role:console'") == 0);
	snprintf(body, sizeof(body), "%s -c tcp://127.0.0.1:%d -A data/ca.pem "
	    "-C host/host.pem -K host/host.key hello 2>&1 | grep -q "
	    "'not let in'", locate(tc, "../../../usr.sbin/arcanactl/"
	    "arcanactl", "arcanactl", "/usr/local/sbin/arcanactl"), jport);
	ATF_CHECK(system(body) == 0);
	/* Its certificate renewed from here: a key made there, signed
	 * here, taken there, and the host reached with it. */
	{
		char	tpath[96], first[128];

		snprintf(tpath, sizeof(tpath), CC "hosts/host=%s/tls", id);
		http("GET", tpath, NULL, &r);
		EXPECT(&r, 200);
		ATF_REQUIRE(resp_unwrap(&r, "arcana-console:tls"));
		ATF_CHECK_STREQ("CN=arcana CA", jstr(&r, "data.cert.issuer"));
		snprintf(first, sizeof(first), "%s", jstr(&r,
		    "data.cert.sha256") != NULL ? jstr(&r, "data.cert.sha256") :
		    "");
		resp_free(&r);
		r3_verb(id, "renew-tls", NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_MSG(jstr(&r, "ok") != NULL && strcmp(jstr(&r, "ok"),
		    "true") == 0, "%s", r.body);
		ATF_CHECK(jstr(&r, "data.cert.sha256") != NULL && strcmp(jstr(&r,
		    "data.cert.sha256"), first) != 0);
		ATF_CHECK_STREQ("CN=127.0.0.1", jstr(&r, "data.cert.subject"));
		resp_free(&r);
		ATF_CHECK(access("host/host.pem.before", F_OK) == 0);
		ATF_CHECK(access("host/host.key.next", F_OK) != 0);
		i = 0;
		argv[i++] = (char *)(uintptr_t)"/usr/bin/openssl";
		argv[i++] = (char *)(uintptr_t)"verify";
		argv[i++] = (char *)(uintptr_t)"-CAfile";
		argv[i++] = (char *)(uintptr_t)"data/ca.pem";
		argv[i++] = (char *)(uintptr_t)"host/host.pem";
		argv[i] = NULL;
		ATF_CHECK_MSG(run_prog(argv), "the renewed one does not verify");
		r3_web(id);
	}

	/*
	 * The CA changed for another: made here, rolled out (the host
	 * trusts both and is given a certificate from the new one, the
	 * console takes the new one's), finished (the old one trusted no
	 * more); then the console as an intermediate CA under a root of
	 * its own, from a request made here.
	 */
	/* A host that does not answer: the console does not switch, for
	 * that host would be lost to it; once it is gone, it does. */
	host_add("gone", "tcp://127.0.0.1:1", gone, sizeof(gone));
	ca_step("make", "\"cn\":\"arcana CA 2\"", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ca_step("rollout", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ca_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "state.phase"), "rolling") == 0 &&
	    strstr(jstr(&r, "state.error"), "1 host not renewed") != NULL,
	    "%s", r.body);
	resp_free(&r);
	ca_step("finish", NULL, &r);
	EXPECT(&r, 409);
	resp_free(&r);
	snprintf(path, sizeof(path), CC "hosts/host=%s", gone);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	ca_step("rollout", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ca_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "state.phase"), "switched") == 0, "%s",
	    r.body);
	resp_free(&r);
	ca_step("finish", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ca_wait(&r);
	ATF_CHECK_STREQ("finished", jstr(&r, "state.phase"));
	resp_free(&r);
	ATF_CHECK(system("openssl x509 -in host/ca.pem -noout -subject | grep "
	    "-q 'CN *= *arcana CA 2' && [ $(grep -c 'BEGIN CERT' host/ca.pem) "
	    "= 1 ]") == 0);
	/* The console's certificate from before is trusted no more. */
	snprintf(body, sizeof(body), "%s -c tcp://127.0.0.1:%d -A data/ca.pem "
	    "-C data/console.pem.before -K data/console.key.before hello "
	    ">/dev/null 2>&1", locate(tc, "../../../usr.sbin/arcanactl/"
	    "arcanactl", "arcanactl", "/usr/local/sbin/arcanactl"), jport);
	ATF_CHECK(system(body) != 0);
	snprintf(body, sizeof(body), "%s -c tcp://127.0.0.1:%d -A data/ca.pem "
	    "-C data/console.pem -K data/console.key hello >/dev/null 2>&1",
	    locate(tc, "../../../usr.sbin/arcanactl/arcanactl", "arcanactl",
	    "/usr/local/sbin/arcanactl"), jport);
	ATF_CHECK(system(body) == 0);
	/* An intermediate: the request made here, signed by a root. */
	ca_step("request", "\"cn\":\"arcana sub\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "request") != NULL && strstr(jstr(&r, "request"),
	    "CERTIFICATE REQUEST") != NULL);
	resp_free(&r);
	ATF_REQUIRE(system("openssl req -x509 -newkey ec -pkeyopt "
	    "ec_paramgen_curve:P-256 -nodes -keyout root.key -out root.pem "
	    "-days 2 -subj /CN=lab-root -addext basicConstraints=critical,"
	    "CA:TRUE -addext keyUsage=critical,keyCertSign >/dev/null 2>&1 && "
	    "printf 'basicConstraints=critical,CA:TRUE,pathlen:0\\nkeyUsage="
	    "critical,keyCertSign,cRLSign\\n' > sub.ext && openssl x509 -req "
	    "-in data/ca-next/request.csr -CA root.pem -CAkey root.key "
	    "-CAcreateserial -days 2 -extfile sub.ext -out sub.pem >/dev/null "
	    "2>&1 && cat sub.pem root.pem > subchain.pem") == 0);
	/* Without its root it is refused. */
	{
		char	*sub, *chain, *q, *bodyb;

		sub = slurp_file("sub.pem");
		chain = slurp_file("subchain.pem");
		q = json_quote_test(sub);
		ATF_REQUIRE(asprintf(&bodyb, "\"cert\":%s", q) != -1);
		ca_step("import", bodyb, &r);
		EXPECT(&r, 409);
		ATF_CHECK(strstr(r.body, "does not reach a root") != NULL);
		resp_free(&r);
		free(q);
		free(bodyb);
		q = json_quote_test(chain);
		ATF_REQUIRE(asprintf(&bodyb, "\"cert\":%s", q) != -1);
		ca_change(id, "import", bodyb);
		free(q);
		free(bodyb);
		free(sub);
		free(chain);
	}
	ATF_CHECK(system("openssl x509 -in host/ca.pem -noout -subject | grep "
	    "-q 'CN *= *lab-root' && openssl verify -CAfile root.pem "
	    "-untrusted host/host.pem host/host.pem >/dev/null 2>&1") == 0);
	r3_web(id);
}

/* A service as MEF 70.2 says one, with two edges: @A and @B are them. */
static const char sdwan_good[] =
    "{\"version\":0,"
    "\"ucs\":[{\"id\":\"inet\",\"type\":\"public\",\"billing\":\"flat-rate\","
    "\"tunnel\":{\"kind\":\"gre\",\"ipsec\":true}},{\"id\":\"mpls\","
    "\"type\":\"private\",\"billing\":\"flat-rate\",\"tunnel\":{\"kind\":"
    "\"geneve\"}}],"
    "\"edges\":[{\"server\":\"@A\",\"ntp\":[\"ntp.example.org\",\"10.99.0.9\"],"
    "\"ucs_end_points\":[{\"id\":\"a-inet\","
    "\"ucs\":\"inet\",\"interface\":\"vtnet0\",\"breakout\":true},{\"id\":"
    "\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"}]},{\"server\":"
    "\"@B\",\"ucs_end_points\":[{\"id\":\"b-inet\",\"ucs\":\"inet\","
    "\"interface\":\"vtnet0\"},{\"id\":\"b-mpls\",\"ucs\":\"mpls\","
    "\"interface\":\"vtnet1\",\"backup\":true}]}],"
    "\"swvcs\":[{\"id\":\"acme\",\"fib\":1,\"as\":64600,\"md5\":\"edges-secret\","
    "\"ucs\":[\"inet\",\"mpls\"],"
    "\"reserved_prefixes\":[\"100.64.0.0/24\"],"
    "\"domains\":{\"service\":{\"prefix\":\"100.64.0.0/24\",\"rd\":\"64600:1\","
    "\"rt\":[\"64600:1\"],\"label\":1001},\"breakout\":{\"fib\":2,\"rd\":"
    "\"64600:2\",\"label\":1002},\"subscriber\":{\"rd\":\"64600:3\",\"label\":"
    "1003}},"
    "\"zones\":[{\"name\":\"office\",\"prefixes\":[\"10.1.0.0/16\"],"
    "\"policies\":[{\"app\":\"web\",\"policy\":\"fast\"}]},{\"name\":"
    "\"rest\",\"prefixes\":\"Default\"}],"
    "\"topologies\":[{\"name\":\"hub\",\"type\":\"rooted-multipoint\","
    "\"roots\":[\"hq\"],\"leaves\":[\"branch\"]}],"
    "\"intervals\":{\"eval\":1000,\"arrival\":100,\"ir\":500},"
    "\"bfd\":{\"interval\":200,\"multiplier\":3},"
    "\"tca\":{\"delay\":30,\"loss\":0.05,\"damping\":2},"
    "\"rate_limiters\":[{\"name\":\"shared\",\"commit\":1000000,\"limit\":"
    "5000000}],"
    "\"security_function_policies\":[{\"id\":\"g-ippf\",\"function\":"
    "\"ippf\",\"allow\":[{\"dav4\":[\"192.0.2.8/29\"]}],\"block\":[{\"dav4\":"
    "[\"192.0.2.0/24\"]}],\"no-match\":\"allow\",\"duration\":6},"
    "{\"id\":\"g-dnf\",\"function\":\"dnf\",\"block\":[\"ads.example\"],"
    "\"allow\":[\"ok.ads.example\"],\"no-match\":\"allow\",\"duration\":6},"
    "{\"id\":\"g-dpf\",\"function\":\"dpf\",\"block\":[{\"sav4\":"
    "[\"192.0.2.53/32\"],\"message-type\":\"response\"},{\"dav4\":"
    "[\"192.0.2.54/32\"],\"message-type\":\"query\"}],\"no-match\":\"block\","
    "\"redirect\":true,\"duration\":6},"
    "{\"id\":\"g-urlf\",\"function\":\"urlf\",\"block\":[\"bad.example\"],"
    "\"no-match\":\"allow\",\"duration\":6},"
    "{\"id\":\"g-mdr\",\"function\":\"mdr\",\"detection-type\":"
    "\"signature\",\"removal\":\"block-subset\",\"block\":["
    "\"44D88612FEA8A8F36DE82E1278ABB02F:68\",\"275a021bbfb6489e54d4718"
    "99f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\"],\"allow\":["
    "\"3395856ce81f2b7382dee72602f798b642f14140\"],\"no-match\":\"allow\","
    "\"duration\":24}],"
    "\"security_policies\":[{\"name\":\"guard\",\"function-policies\":["
    "\"g-ippf\",\"g-dnf\",\"g-dpf\",\"g-urlf\",\"g-mdr\"],\"rate-limit\":"
    "2000000,\"ids\":{\"mode\":\"prevent\",\"ruleset\":true,"
    "\"rules\":[\"alert http any any -> $HOME_NET any (msg:\\\"x\\\"; "
    "sid:1000001; rev:1;)\"]}}],"
    "\"importance\":{\"levels\":[\"high\",\"low\"],\"default\":\"low\"},"
    "\"groups\":[\"bulk\"],"
    "\"flows\":[{\"name\":\"web\",\"criteria\":{\"dport\":[80,\"https\"],"
    "\"protv4\":[\"tcp\"]}},{\"name\":\"voice\",\"criteria\":{\"appid\":"
    "[\"sip\"],\"dscp\":[46]},\"group\":\"bulk\"},{\"name\":\"all\","
    "\"criteria\":{\"any\":true}}],"
    "\"policies\":[{\"name\":\"fast\",\"direction\":\"ingress\",\"criteria\":"
    "{\"encryption\":\"required-public-only\",\"performance\":{\"primary\":"
    "{\"metric\":\"delay\",\"threshold\":10,\"ceiling\":12,\"remediation\":"
    "9},\"secondary\":[{\"metric\":\"loss\",\"threshold\":0.05}]},"
    "\"bandwidth\":\"shared\",\"business-importance\":\"high\","
    "\"internet-breakout\":\"enabled\",\"af-security-ingress\":\"guard\"}},"
    "{\"name\":"
    "\"hubonly\",\"direction\":\"ingress\",\"criteria\":{"
    "\"virtual-topology\":\"hub\"}},{\"name\":\"quiet\",\"direction\":"
    "\"egress\",\"criteria\":{\"egress-block\":\"discard\"}}],"
    "\"end_points\":[{\"id\":\"hq\",\"edge\":\"@A\",\"uni\":{\"id\":"
    "\"uni-hq\",\"interface\":\"vtnet2\",\"ipv4\":{\"mode\":\"dhcp\","
    "\"prefix\":\"10.1.0.0/24\",\"provider\":[\"10.1.0.1\"],\"reserved\":"
    "[\"10.1.0.0/26\",\"10.1.0.200/30\"],\"dns\":[\"10.1.0.1\"],\"lease\":"
    "\"1h\"},\"routes\":"
    "[{\"prefix\":\"10.1.8.0/22\",\"next_hop\":\"10.1.0.2\",\"distance\":"
    "10}],\"bgp\":{\"family\":\"ipv4\",\"as\":65010,\"neighbors\":"
    "[\"10.1.0.2\"],\"password\":\"s3cret\",\"hold_time\":90,\"distance\":"
    "150,\"communities\":[[64600,100]]}},\"policy_map\":[{\"zone\":\"office\",\"app\":\"all\",\"ingress\":"
    "\"hubonly\",\"egress\":\"quiet\"}],\"nat\":{\"ip_version\":\"ipv4\","
    "\"public_prefix\":\"198.51.100.0/30\"}},{\"id\":\"branch\",\"edge\":"
    "\"@B\",\"uni\":{\"id\":\"uni-br\",\"interface\":\"vtnet2\",\"vlan\":20,"
    "\"ipv6\":{\"mode\":\"slaac\",\"prefix\":\"2001:db8:1::/64\","
    "\"provider\":[\"2001:db8:1::1\"],\"dns\":[\"2001:db8:1::1\"]}}},"
    "{\"id\":\"road\",\"edge\":\"@A\",\"remote\":{\"interface\":\"wg5\","
    "\"prefix\":\"10.30.0.0/24\",\"port\":51820,\"groups\":[{\"name\":"
    "\"staff\",\"zone\":\"office\",\"pool\":\"10.30.0.64/26\"},{\"name\":"
    "\"guests\",\"zone\":\"office\"}],\"identities\":[{\"name\":"
    "\"alice\",\"zone\":\"office\",\"public_key\":"
    "\"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\"},{\"name\":\"carol\","
    "\"group\":\"staff\",\"public_key\":"
    "\"HIgo9xNzJMWLKASShiTqIYNW7HVnKq0pjaZxmvZ6rKA=\"}]}}]}]}";

/* s with its first from made to, into out; false when from is not there. */
/* An interface of this host with an IPv4 address that is not the
 * loopback's, and the address: the first up, by ifconfig(8). */
static bool
host_iface(char *ifn, size_t ilen, char *addr, size_t alen)
{
	FILE	*fp;
	char	 line[200], *p, *q;

	ifn[0] = addr[0] = '\0';
	if ((fp = popen("ifconfig -l -u", "r")) == NULL)
		return (false);
	if (fgets(line, sizeof(line), fp) == NULL)
		line[0] = '\0';
	pclose(fp);
	for (p = line; (q = strsep(&p, " \n")) != NULL; ) {
		char	cmd[200];

		if (q[0] == '\0' || strncmp(q, "lo", 2) == 0 || strncmp(q, "cni",
		    3) == 0 || strncmp(q, "pflog", 5) == 0)
			continue;
		snprintf(cmd, sizeof(cmd), "ifconfig %s inet 2>/dev/null | awk "
		    "'/inet /{print $2; exit}'", q);
		if ((fp = popen(cmd, "r")) == NULL)
			continue;
		if (fgets(addr, (int)alen, fp) != NULL && addr[0] != '\0' &&
		    addr[0] != '\n') {
			addr[strcspn(addr, "\n")] = '\0';
			pclose(fp);
			snprintf(ifn, ilen, "%s", q);
			return (true);
		}
		pclose(fp);
		addr[0] = '\0';
	}
	return (false);
}

static bool
swap_in(const char *s, const char *from, const char *to, char *out,
    size_t len)
{
	const char	*p;

	if ((p = strstr(s, from)) == NULL)
		return (false);
	snprintf(out, len, "%.*s%s%s", (int)(p - s), s, to, p + strlen(from));
	return (true);
}

/* sdwan_good with its edges @A and @B named. */
static void
sdwan_good_at(const char *a, const char *b, char *doc, size_t len)
{
	char	t[8192];

	snprintf(doc, len, "%s", sdwan_good);
	while (swap_in(doc, "@A", a, t, sizeof(t)))
		snprintf(doc, len, "%s", t);
	while (swap_in(doc, "@B", b, t, sizeof(t)))
		snprintf(doc, len, "%s", t);
}

/*
 * The document a view of the L3NM kept (PLAN-SDN-YANG 4.5.3): the L3NM
 * form of the example exported as the example; a console's document of
 * before imported at its start, its version kept, the file kept aside.
 * (Every document kept by the tests comes back the same: http().)
 */
/*
 * The VN view (PLAN-SDN-YANG 4.7, RFC 9731): made of the L3NM kept at
 * each read, a VN each service, an AP each attachment, a member each
 * pair of a service's accesses on two nodes; read alone.
 */
#define	VN_VN	"/restconf/data/ietf-vn:virtual-network"
#define	VN_AP	"/restconf/data/ietf-vn:access-point"

CONSOLE_TC(l3nm_vn, "the VN view of the L3NM: l3nm_good's service of two "
    "sites one VN with its members; an L3NM change in it; edits refused")
ATF_TC_BODY(l3nm_vn, tc)
{
	static const char *const methods[] = { "PUT", "POST", "PATCH",
	    "DELETE" };
	struct authn	 a;
	struct resp	 r;
	char		 etag[64], etag2[64];

	start(tc, 0, NULL);
	enrol(&a);
	/* No service, no VN. */
	http("GET", VN_VN, NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("PUT", L3NM, l3nm_good, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	/* Sites a (hq on vtnet2, road on wg5) and b (branch on vtnet2):
	 * one VN, a member from each of a's accesses to b's. */
	http("GET", VN_VN, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("acme", jstr(&r, "ietf-vn:virtual-network.vn.0.id"));
	ATF_CHECK(jstr(&r, "ietf-vn:virtual-network.vn.1") == NULL);
	ATF_CHECK_STREQ("a:hq~b:branch", jstr(&r, "ietf-vn:virtual-network."
	    "vn.0.vn-member.0.id"));
	ATF_CHECK_STREQ("a:vtnet2", jstr(&r, "ietf-vn:virtual-network.vn.0."
	    "vn-member.0.src.ap"));
	ATF_CHECK_STREQ("acme:hq", jstr(&r, "ietf-vn:virtual-network.vn.0."
	    "vn-member.0.src.vn-ap-id"));
	ATF_CHECK_STREQ("b:vtnet2", jstr(&r, "ietf-vn:virtual-network.vn.0."
	    "vn-member.0.dest.ap"));
	ATF_CHECK_STREQ("acme:branch", jstr(&r, "ietf-vn:virtual-network."
	    "vn.0.vn-member.0.dest.vn-ap-id"));
	ATF_CHECK_STREQ("a:road~b:branch", jstr(&r, "ietf-vn:virtual-network."
	    "vn.0.vn-member.1.id"));
	ATF_CHECK(jstr(&r, "ietf-vn:virtual-network.vn.0.vn-member.2") ==
	    NULL);
	ATF_CHECK_MSG(resp_header(&r, "etag", etag, sizeof(etag)) != NULL,
	    "%s", r.head);
	resp_free(&r);
	http("GET", VN_AP, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("a:vtnet2", jstr(&r, "ietf-vn:access-point.ap.0.id"));
	ATF_CHECK_STREQ("acme:hq", jstr(&r, "ietf-vn:access-point.ap.0."
	    "vn-ap.0.id"));
	ATF_CHECK_STREQ("acme", jstr(&r, "ietf-vn:access-point.ap.0.vn-ap.0."
	    "vn"));
	ATF_CHECK_STREQ("a:wg5", jstr(&r, "ietf-vn:access-point.ap.1.id"));
	ATF_CHECK_STREQ("b:vtnet2", jstr(&r, "ietf-vn:access-point.ap.2.id"));
	ATF_CHECK(jstr(&r, "ietf-vn:access-point.ap.3") == NULL);
	resp_free(&r);
	/* A member by its key; the root and the library have the view. */
	http("GET", VN_VN "/vn=acme/vn-member=a%3Ahq~b%3Abranch/dest", NULL,
	    &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("b:vtnet2", jstr(&r, "ietf-vn:dest.ap"));
	resp_free(&r);
	http("GET", "/restconf/data", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("acme", jstr(&r, "ietf-vn:virtual-network.vn.0.id"));
	ATF_CHECK(strstr(r.body, "\"name\":\"ietf-vn\"") != NULL);
	resp_free(&r);
	/* Edits refused, the L3NM as it was. */
	for (size_t i = 0; i < nitems(methods); i++) {
		http(methods[i], VN_VN "/vn=acme", strcmp(methods[i],
		    "DELETE") == 0 ? NULL : "{\"ietf-vn:vn\":[{\"id\":"
		    "\"acme\",\"admin-status\":\"down\"}]}", &r);
		EXPECT(&r, 405);
		ATF_CHECK_STREQ("operation-not-supported", jstr(&r,
		    "ietf-restconf:errors.error.0.error-tag"));
		resp_free(&r);
	}
	http("GET", L3NM "/vpn-services/vpn-service=acme/vpn-id", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* An access added at b: a member from each of a's to it. */
	http("PATCH", L3NM "/vpn-services/vpn-service=acme/vpn-nodes/"
	    "vpn-node=b/vpn-network-accesses", "{\"ietf-l3vpn-ntw:"
	    "vpn-network-accesses\":{\"vpn-network-access\":[{\"id\":\"lab\","
	    "\"interface-id\":\"vtnet3\",\"vpn-network-access-type\":"
	    "\"ietf-vpn-common:multipoint\",\"vpn-instance-profile\":"
	    "\"subscriber\"}]}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", VN_VN, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("a:hq~b:lab", jstr(&r, "ietf-vn:virtual-network.vn.0."
	    "vn-member.1.id"));
	ATF_CHECK_STREQ("a:road~b:lab", jstr(&r, "ietf-vn:virtual-network."
	    "vn.0.vn-member.3.id"));
	ATF_CHECK_MSG(resp_header(&r, "etag", etag2, sizeof(etag2)) != NULL &&
	    strcmp(etag, etag2) != 0, "%s", r.head);
	resp_free(&r);
	/* Its accesses spokes, the service down: no member, the VN down. */
	http("PATCH", L3NM "/vpn-services/vpn-service=acme", "{\"ietf-l3vpn-"
	    "ntw:vpn-service\":[{\"vpn-id\":\"acme\",\"status\":{\""
	    "admin-status\":{\"status\":\"ietf-vpn-common:admin-down\"}},"
	    "\"vpn-instance-profiles\":{\"vpn-instance-profile\":[{"
	    "\"profile-id\":\"subscriber\",\"role\":"
	    "\"ietf-vpn-common:spoke-role\"}]}}]}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", VN_VN "/vn=acme", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("down", jstr(&r, "ietf-vn:vn.0.admin-status"));
	ATF_CHECK(jstr(&r, "ietf-vn:vn.0.vn-member") == NULL);
	resp_free(&r);
	/* The service taken away, its VN and APs with it. */
	http("DELETE", L3NM "/vpn-services/vpn-service=acme", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", VN_AP, NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
}

/*
 * A VN's path-metric-bounds (PLAN-SDN-YANG 4.7.2): its service's TCA,
 * delay and delay variation in microseconds, loss in millionths; the
 * thresholds back from them the TCA's as kept.
 */
#define	VN_BOUND(i, what) "ietf-vn:virtual-network.vn.0.arcana-sdwan-"	\
	"underlay:path-metric-bounds.path-metric-bound." #i "." what

CONSOLE_TC(l3nm_vn_tca, "a VN's path-metric-bounds its service's TCA "
    "thresholds, round-trip")
ATF_TC_BODY(l3nm_vn_tca, tc)
{
	static const struct {
		const char	*tca;		/* as the L3NM keeps it */
		const char	*metric;
		const char	*bound;
		double		 scale;
	} want[] = {
		{ "12.345", "ietf-te-types:path-metric-delay-average", "12345",
		    1e3 },
		{ "2.5", "arcana-sdwan-underlay:path-metric-delay-variation",
		    "2500", 1e3 },
		{ "0.000125", "arcana-sdwan-underlay:path-metric-loss", "125",
		    1e6 },
	};
	struct authn	 a;
	struct resp	 r;
	char		 path[160];

	start(tc, 0, NULL);
	enrol(&a);
	http("PUT", L3NM, l3nm_good, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	/* l3nm_good's: delay 30 ms, loss 0.05. */
	http("GET", VN_VN, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("ietf-te-types:path-metric-delay-average", jstr(&r,
	    VN_BOUND(0, "metric-type")));
	ATF_CHECK_STREQ("30000", jstr(&r, VN_BOUND(0, "upper-bound")));
	ATF_CHECK_STREQ("arcana-sdwan-underlay:path-metric-loss", jstr(&r,
	    VN_BOUND(1, "metric-type")));
	ATF_CHECK_STREQ("50000", jstr(&r, VN_BOUND(1, "upper-bound")));
	ATF_CHECK(jstr(&r, VN_BOUND(2, "metric-type")) == NULL);
	resp_free(&r);
	/* Changed in the L3NM: each in the VN, and each bound back in the
	 * TCA's units the value kept. */
	http("PATCH", L3NM "/vpn-services/vpn-service=acme", "{\"ietf-l3vpn-"
	    "ntw:vpn-service\":[{\"vpn-id\":\"acme\",\"arcana-l3nm:sdwan\":{"
	    "\"tca\":{\"delay\":\"12.345\",\"ipdv\":\"2.5\",\"loss\":"
	    "\"0.000125\"}}}]}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", VN_VN "/vn=acme/arcana-sdwan-underlay:path-metric-bounds",
	    NULL, &r);
	EXPECT(&r, 200);
	for (size_t i = 0; i < nitems(want); i++) {
		snprintf(path, sizeof(path), "arcana-sdwan-underlay:"
		    "path-metric-bounds.path-metric-bound.%zu.metric-type", i);
		ATF_CHECK_STREQ(want[i].metric, jstr(&r, path));
		snprintf(path, sizeof(path), "arcana-sdwan-underlay:"
		    "path-metric-bounds.path-metric-bound.%zu.upper-bound", i);
		ATF_CHECK_STREQ(want[i].bound, jstr(&r, path));
		ATF_CHECK_MSG(jstr(&r, path) != NULL && fabs(strtod(jstr(&r,
		    path), NULL) / want[i].scale - strtod(want[i].tca, NULL)) <
		    1e-9, "%s back is not %s", want[i].bound, want[i].tca);
	}
	resp_free(&r);
	http("GET", L3NM "/vpn-services/vpn-service=acme/arcana-l3nm:sdwan/tca",
	    NULL, &r);
	EXPECT(&r, 200);
	for (size_t i = 0; i < nitems(want); i++) {
		snprintf(path, sizeof(path), "arcana-l3nm:tca.%s", i == 0 ?
		    "delay" : i == 1 ? "ipdv" : "loss");
		ATF_CHECK_MSG(jstr(&r, path) != NULL && strtod(jstr(&r, path),
		    NULL) == strtod(want[i].tca, NULL), "%s: %s", path, r.body);
	}
	resp_free(&r);
	/* No TCA, no bounds. */
	http("DELETE", L3NM "/vpn-services/vpn-service=acme/arcana-l3nm:sdwan/"
	    "tca", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", VN_VN, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, VN_BOUND(0, "metric-type")) == NULL);
	resp_free(&r);
}

/*
 * arcana-console's sdwan/<what> read (document, plan, san?q=...): the
 * answer in r, its JSON the document read where it is 200.
 */
static void
r3_sdwan(const char *what, struct resp *r)
{
	char	path[256], key[96];

	snprintf(path, sizeof(path), CC "sdwan/%s", what);
	http("GET", path, NULL, r);
	snprintf(key, sizeof(key), "arcana-console:%.*s", (int)strcspn(what,
	    "?"), what);
	if (r->status == 200)
		ATF_CHECK_MSG(resp_unwrap(r, key), "%s", r->body);
}

/* The SD-WAN document, 200: r's JSON. */
static void
r3_doc(struct resp *r)
{

	r3_sdwan("document", r);
	EXPECT(r, 200);
}

/*
 * doc kept as the SD-WAN document (arcana-console's sdwan/document): the
 * answer in r; kept, it reads back the same, through the L3NM it is
 * kept as.
 */
static void
r3_doc_put(const char *doc, struct resp *r)
{
	struct resp	 k;
	char		*body, where[512];

	ATF_REQUIRE(asprintf(&body, "{\"arcana-console:document\":%s}", doc) !=
	    -1);
	http("PUT", CC "sdwan/document", body, r);
	free(body);
	if (r->status != 204)
		return;
	r3_doc(&k);
	ATF_CHECK_MSG(sdwan_round_trip(doc, k.json, where, sizeof(where)),
	    "the document as L3NM, back: %s", where);
	resp_free(&k);
}

/* doc kept, 204. */
static void
r3_keep(const char *doc)
{
	struct resp	r;

	r3_doc_put(doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);
}

/* doc checked (arcana-console's sdwan/check): the answer in r. */
static void
r3_check(const char *doc, struct resp *r)
{
	char	*in;

	ATF_REQUIRE(asprintf(&in, "{\"arcana-console:input\":{\"document\":"
	    "%s}}", doc) != -1);
	rc_act(CC "sdwan/check", in, r);
	free(in);
}

/* The two hosts of the SD-WAN cases, a and b, on the one agent. */
static void
r3_ab(char *sa, char *sb, size_t len)
{

	r3_host("a", "jgd.sock", sa, len);
	r3_host("b", "./jgd.sock", sb, len);
}

CONSOLE_TC(l3nm_mef, "the SD-WAN document a view of the L3NM: l3nm_good "
    "exported is sdwan_good; sdwan.json imported once at start")
ATF_TC_BODY(l3nm_mef, tc)
{
	struct authn	 a;
	struct resp	 r;
	FILE		*fp;
	char		 doc[8192], where[512];

	start(tc, 0, NULL);
	enrol(&a);
	http("PUT", L3NM, l3nm_good, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	r3_doc(&r);
	sdwan_good_at("a", "b", doc, sizeof(doc));
	ATF_CHECK_MSG(sdwan_round_trip(doc, r.json, where, sizeof(where)),
	    "l3nm_good is not sdwan_good: %s: %s", where, r.body);
	ATF_CHECK_STREQ("acme", jstr(&r, "swvcs.0.id"));
	ATF_CHECK_STREQ("64600:1", jstr(&r, "swvcs.0.domains.service.rd"));
	resp_free(&r);
	/* A change of the L3NM is a version of the document too. */
	r3_doc(&r);
	ATF_CHECK_STREQ("1", jstr(&r, "version"));
	resp_free(&r);
	http("DELETE", L3NM, NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	r3_doc(&r);
	ATF_CHECK_STREQ("2", jstr(&r, "version"));
	/* None: the document's lists empty, as the page has them. */
	ATF_CHECK_MSG(ucl_object_type(ucl_object_lookup(r.json, "swvcs")) ==
	    UCL_ARRAY && ucl_array_size(ucl_object_lookup(r.json, "swvcs")) ==
	    0 && ucl_array_size(ucl_object_lookup(r.json, "edges")) == 0 &&
	    ucl_object_type(ucl_object_lookup(r.json, "ucs")) == UCL_ARRAY,
	    "%s", r.body);
	resp_free(&r);

	/* A console of before: its sdwan.json, version 7. */
	console_stop();
	sdwan_good_at("a", "b", doc, sizeof(doc));
	ATF_REQUIRE(strncmp(doc, "{\"version\":0,", 13) == 0);
	ATF_REQUIRE((fp = fopen("data/sdwan.json", "w")) != NULL);
	fprintf(fp, "{\"version\":7,%s", doc + 13);
	fclose(fp);
	console_start();
	r3_doc(&r);
	ATF_CHECK(access("data/sdwan.json", F_OK) == -1);
	ATF_CHECK(access("data/sdwan-mef.json", F_OK) == 0);
	ATF_CHECK_STREQ("7", jstr(&r, "version"));
	ATF_CHECK_MSG(sdwan_round_trip(doc, r.json, where, sizeof(where)),
	    "sdwan.json not imported the same: %s: %s", where, r.body);
	resp_free(&r);
	http("GET", L3NM "/vpn-services/vpn-service=acme/vpn-nodes/"
	    "vpn-node=a/vpn-network-accesses/vpn-network-access=hq/"
	    "interface-id", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("vtnet2", jstr(&r, "ietf-l3vpn-ntw:interface-id"));
	resp_free(&r);
	/* Once: started again, nothing more of it. */
	restart_console();
	r3_doc(&r);
	ATF_CHECK_STREQ("7", jstr(&r, "version"));
	resp_free(&r);
}

CONSOLE_TC(sdwan, "SD-WAN services are checked as MEF 70.2 says, and kept")
ATF_TC_BODY(sdwan, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16];
	char		doc[8192], t1[8192], bad[8192];
	size_t		i;

	start(tc, 0, NULL);
	enrol(&a);
	r3_ab(sa, sb, sizeof(sa));
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);

	/* Nothing yet: version 0. */
	r3_doc(&r);
	ATF_CHECK_STREQ("0", jstr(&r, "version"));
	resp_free(&r);
	r3_check(doc, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	resp_free(&r);

	/* Each change that breaks a requirement, and what it is told. */
	static const char *const breaks[][3] = {
		{ "\"type\":\"public\"", "\"type\":\"cloud\"", "R170" },
		{ "\"fib\":1", "\"fib\":0", "FIB 0" },
		{ "\"10.1.0.0/16\"", "\"10.1.0.0/16\",\"10.1.4.0/24\"",
		    "(R20)" },
		{ "\"prefixes\":\"Default\"", "\"prefixes\":\"Default\"},"
		    "{\"name\":\"more\",\"prefixes\":\"Default\"", "(R21)" },
		{ "\"name\":\"rest\"", "\"name\":\"Internet\"", "(§9.5)" },
		{ "\"ceiling\":12", "\"ceiling\":8", "(R72)" },
		{ "\"remediation\":9", "\"remediation\":12", "(R75)" },
		{ "{\"any\":true}", "{\"any\":true,\"dscp\":[1]}", "(R99)" },
		{ "\"limit\":5000000", "\"limit\":10", "(R7)" },
		{ "\"ingress\":\"hubonly\"", "\"ingress\":\"quiet\"", "(R106)" },
		{ "\"zone\":\"office\"", "\"zone\":\"Internet\"", "(R107)" },
		{ "\"provider\":[\"10.1.0.1\"]", "\"provider\":[\"10.2.0.1\"]",
		    "(R131)" },
		{ "\"leaves\":[\"branch\"]", "\"leaves\":[\"hq\"]", "(R31)" },
		{ "\"neighbors\":[\"10.1.0.2\"]", "\"neighbors\":[\"10.9.0.2\"]",
		    "(§11.6.2)" },
		{ "\"hold_time\":90", "\"hold_time\":90,\"as_override\":true",
		    "as_override" },
		{ "\"as\":65010", "\"as\":0", "subscriber's AS" },
		/* The security function policies (MEF 138) and the security
		 * policies made of them. */
		{ "\"dav4\":[\"192.0.2.0/24\"]", "\"dav4\":[\"192.0.2.0/33\"]",
		    "dav4" },
		{ "\"block\":[\"ads.example\"]", "\"block\":[\"ads..example\"]",
		    "not a domain name" },
		{ "\"rate-limit\":2000000", "\"rate-limit\":10", "1000 or more" },
		{ "\"rate-limit\":2000000", "\"rate-limit\":2000000,\"nope\":true",
		    "is not of a security policy" },
		{ "\"function\":\"ippf\"", "\"function\":\"fw\"",
		    "one of MEF 138's" },
		{ "\"function\":\"ippf\"", "\"function\":\"dlp\"",
		    "no engine for data loss" },
		{ "\"no-match\":\"block\",\"redirect\"",
		    "\"no-match\":\"drop\",\"redirect\"", "allow or block" },
		{ "\"duration\":24}", "\"duration\":0}", "duration is hours" },
		{ "\"allow\":[\"ok.ads.example\"]", "\"allow\":[\"ads.example\"]",
		    "one list at most (R14)" },
		{ "\"removal\":\"block-subset\"", "\"removal\":\"remove\"",
		    "removal block-subset" },
		{ "\"g-mdr\"],", "\"g-mdr\",\"g-ippf\"],", "one of a function" },
		{ "\"g-mdr\"],", "\"g-none\"],", "no function policy g-none" },
		{ "\"allow\":[\"ok.ads.example\"],", "\"allow\":[\"ok.ads.example\"],"
		    "\"lists\":{\"block\":[\"nowhere\"]},", "no list nowhere" },
		{ "\"block\":[\"bad.example\"]", "\"block\":[\"bad.example/x\"]",
		    "seen over HTTPS where the zone's mbsf" },
		{ "\"block\":[\"bad.example\"]", "\"block\":[\"bad example\"]",
		    "is not a host" },
		{ "\"egress-block\":\"discard\"", "\"egress-block\":\"discard\","
		    "\"af-security-egress\":\"guard\"", "serves a zone's clients" },
		{ "\"redirect\":true", "\"redirect\":true,\"pass-through\":[\"x.example\"]",
		    "are mbsf's" },
		/* DPF: a message type ipfw tells by the port. */
		{ "\"message-type\":\"query\"", "\"message-type\":\"update\"",
		    "inside the message" },
		/* MD+R: hashes, one list at an edge. */
		{ "\"3395856ce81f2b7382dee72602f798b642f14140\"",
		    "\"3395856ce81f2b7382dee72602f798b642f1414\"", "is not a hash" },
		{ "\"3395856ce81f2b7382dee72602f798b642f14140\"",
		    "\"3395856ce81f2b7382dee72602f798b642f14140:0\"", "is not a hash" },
		{ "{\"id\":\"g-mdr\"", "{\"id\":\"g-mdr2\",\"function\":\"mdr\","
		    "\"detection-type\":\"signature\",\"removal\":\"block-subset\","
		    "\"quarantine\":[\"3395856CE81F2B7382DEE72602F798B642F14140:5\"],"
		    "\"no-match\":\"allow\",\"duration\":24},{\"id\":\"g-mdr\"",
		    "whose ClamAV is one for them all" },
		/* DNF: a * for a whole label, a Block's or a Quarantine's. */
		{ "\"allow\":[\"ok.ads.example\"]", "\"allow\":[\"ok.*.example\"]",
		    "a * inside a name is a Block's" },
		{ "\"block\":[\"ads.example\"]", "\"block\":[\"a*s.example\"]",
		    "a * for a whole label" },
		{ "\"block\":[\"ads.example\"]", "\"block\":[\"*.*\"]",
		    "a * for a whole label" },
		/* PDNS: what unbound takes of R104, D21 and D22. */
		{ "{\"id\":\"g-mdr\"", "{\"id\":\"g-p\",\"function\":\"pdns\","
		    "\"block\":[{\"type\":\"MX\",\"value\":\"mx.example\"}],"
		    "\"no-match\":\"allow\",\"duration\":6},{\"id\":\"g-mdr\"",
		    "MX is not taken" },
		{ "{\"id\":\"g-mdr\"", "{\"id\":\"g-p\",\"function\":\"pdns\","
		    "\"block\":[{\"type\":\"NS\",\"value\":\"not a name\"}],"
		    "\"no-match\":\"allow\",\"duration\":6},{\"id\":\"g-mdr\"",
		    "an NS entry's value" },
		{ "{\"id\":\"g-mdr\"", "{\"id\":\"g-p\",\"function\":\"pdns\","
		    "\"no-match\":\"allow\",\"duration\":6,\"southbound\":["
		    "\"unencrypted\",\"doh\"]},{\"id\":\"g-mdr\"",
		    "without DNS over HTTPS" },
		{ "{\"id\":\"g-mdr\"", "{\"id\":\"g-p\",\"function\":\"pdns\","
		    "\"block\":[{\"type\":\"A\",\"value\":\"192.0.2.1\","
		    "\"encryption\":\"unencrypted\"}],\"no-match\":\"allow\","
		    "\"duration\":6,\"southbound\":[\"unencrypted\",\"dot\"]},"
		    "{\"id\":\"g-mdr\"", "however they ask" },
		{ "{\"id\":\"g-mdr\"", "{\"id\":\"g-p\",\"function\":\"pdns\","
		    "\"no-match\":\"allow\",\"duration\":6,\"southbound\":[\"dot\"]},"
		    "{\"id\":\"g-mdr\"", "southbound has unencrypted" },
		{ "{\"id\":\"g-mdr\"", "{\"id\":\"g-p\",\"function\":\"pdns\","
		    "\"no-match\":\"allow\",\"duration\":6,\"northbound\":\"dot\","
		    "\"upstream\":[\"192.0.2.53\"]},{\"id\":\"g-mdr\"",
		    "the name its certificate has" },
		{ "{\"id\":\"g-mdr\"", "{\"id\":\"g-p\",\"function\":\"pdns\","
		    "\"no-match\":\"allow\",\"duration\":6,\"northbound\":\"dot\","
		    "\"upstream\":[\"192.0.2.53#dns.example\"]},{\"id\":\"g-q\","
		    "\"function\":\"pdns\",\"no-match\":\"allow\",\"duration\":6},"
		    "{\"id\":\"g-mdr\"", "the service has one resolver" },
		/* Intrusion detection: detect, rules with a sid. */
		{ "\"mode\":\"prevent\"", "\"mode\":\"block\"",
		    "a mode, detect or prevent" },
		{ "sid:1000001; rev:1;)", "rev:1;)", "is not a Suricata rule" },
		{ "\"alert http any", "\"shout http any", "is not a Suricata rule" },
		{ "\"ruleset\":true", "\"ruleset\":\"yes\"", "ids.ruleset is true" },
		{ "\"md5\":\"edges-secret\",", "\"md5\":\"edges-secret\","
		    "\"control_plane\":{\"host\":\"nobody\"},", "control_plane.host" },
		{ "\"md5\":\"edges-secret\",", "\"md5\":\"edges-secret\","
		    "\"control_plane\":{\"host\":\"@A\",\"cluster_id\":\"x\"},",
		    "cluster_id" },
		{ "\"md5\":\"edges-secret\",", "\"md5\":\"edges-secret\","
		    "\"control_plane\":{\"host\":\"@A\",\"ctvc\":\"dsl\"},",
		    "control_plane.ctvc" },
		{ "\"multiplier\":3", "\"multiplier\":1", "(R159)" },
		{ "\"10.99.0.9\"]", "\"not a host!\"]", "ntp:" },
		{ "\"damping\":2", "\"damping\":0", "(CR2)" },
		{ "\"vlan\":20", "\"vlan\":5000", "(§11.2)" },
		{ "\"virtual-topology\":\"hub\"", "\"virtual-topology\":\"nope\"",
		    "(R47)" },
		{ "\"metric\":\"loss\"", "\"metric\":\"delay\"", "(R68)" },
		{ "\"kind\":\"geneve\"", "\"kind\":\"wg\",\"ipsec\":true",
		    "wg encrypts" },
		{ "\"interface\":\"vtnet1\"}", "\"interface\":\"vtnet1\","
		    "\"breakout\":true}", "(§12.3)" },
		{ "\"business-importance\":\"high\"",
		    "\"business-importance\":\"mid\"", "importance levels" },
		{ "\"next_hop\":\"10.1.0.2\"", "\"next_hop\":\"10.9.0.2\"",
		    "(§11.6.1)" },
		{ "\"dport\":[80,\"https\"]", "\"dport\":[80,\"nosuchport\"]",
		    "nosuchport is not one" },
		{ "\"groups\":[\"bulk\"]", "\"groups\":[\"bulk\",\"web\"]",
		    "(R92)" },
		{ "\"egress-block\":\"discard\"", "\"encryption\":\"optional\"",
		    "egress policy" },
		{ "\"ipv6\":{", "\"ipv6\":{\"mode\":\"none\"},\"x\":{", "(R128)" },
		/* A remote end point: its port, an identity's zone
		 * and key, and not a UNI besides. */
		{ "\"port\":51820", "\"port\":70000", "port is 1 to 65535" },
		{ "\"zone\":\"office\",\"public_key\"", "\"zone\":\"nowhere\","
		    "\"public_key\"", "its zone is one of the zones" },
		{ "\"public_key\":\"xTIB", "\"public_key\":\"short", "a WireGuard "
		    "one" },
		{ "\"remote\":{", "\"uni\":{\"id\":\"x\"},\"remote\":{", "not "
		    "both" },
		/* Its groups: a zone of the service, a pool inside the prefix
		 * and not the edge's own address, reaching groups of its own,
		 * and an identity's group one of them. */
		{ "\"name\":\"guests\",\"zone\":\"office\"", "\"name\":\"guests\","
		    "\"zone\":\"nowhere\"", "group guests: its zone" },
		{ "\"pool\":\"10.30.0.64/26\"", "\"pool\":\"10.31.0.64/26\"",
		    "inside the remote's" },
		{ "\"pool\":\"10.30.0.64/26\"", "\"pool\":\"10.30.0.0/25\"",
		    "the edge's own address" },
		{ "\"name\":\"guests\",\"zone\":\"office\"", "\"name\":\"guests\","
		    "\"zone\":\"office\",\"pool\":\"10.30.0.96/27\"", "pools "
		    "overlap" },
		{ "\"name\":\"guests\",\"zone\":\"office\"", "\"name\":\"guests\","
		    "\"zone\":\"office\",\"reach\":[\"nobody\"]", "it reaches groups "
		    "of this remote" },
		{ "\"name\":\"guests\",\"zone\":\"office\"", "\"name\":\"guests\","
		    "\"zone\":\"office\",\"reach\":[\"guests\"]", "reach each other "
		    "already" },
		{ "\"group\":\"staff\"", "\"group\":\"board\"", "its group is one "
		    "of the remote's" },
		/* The UCS end points' addressing and routing (Mplify 119). */
		{ "\"interface\":\"vtnet1\",\"backup\":true", "\"interface\":"
		    "\"vtnet1\",\"backup\":true,\"addressing\":\"ppp\"",
		    "(Mplify 119 §12.2.3.2)" },
		{ "\"interface\":\"vtnet1\",\"backup\":true", "\"interface\":"
		    "\"vtnet1\",\"backup\":true,\"vrf\":0", "(§12.2.3.4)" },
		{ "\"interface\":\"vtnet1\",\"backup\":true", "\"interface\":"
		    "\"vtnet1\",\"backup\":true,\"routing\":{\"bgp\":{\"family\":"
		    "\"ipv4\",\"neighbors\":[\"10.99.0.9\"]}}", "AS number" },
		/* The routing domains (Mplify 119). */
		{ "\"breakout\":{\"fib\":2", "\"breakout\":{\"fib\":1", "(R20)" },
		{ "\"label\":1001", "\"label\":7", "(R19)" },
		{ "\"label\":1002", "\"label\":1001", "(R19)" },
		{ "\"rd\":\"64600:1\"", "\"rd\":\"x:1\"", "(R16)" },
		/* Another service with a UNI on the same interface and VLAN
		 * of the same edge. */
		{ "\"swvcs\":[", "\"swvcs\":[{\"id\":\"other\",\"fib\":2,\"ucs\":"
		    "[\"inet\"],\"zones\":[{\"name\":\"z\",\"prefixes\":\"Default\"}],"
		    "\"flows\":[{\"name\":\"all\",\"criteria\":{\"any\":true}}],"
		    "\"policies\":[{\"name\":\"p\",\"direction\":\"ingress\"}],"
		    "\"end_points\":[{\"id\":\"o1\",\"edge\":\"@A\",\"uni\":{\"id\":"
		    "\"uni-o1\",\"interface\":\"vtnet2\",\"ipv4\":{\"mode\":\"static\","
		    "\"prefix\":\"10.5.0.0/24\",\"provider\":[\"10.5.0.1\"]}}}]},",
		    "(R3)" },
	};
	for (i = 0; i < nitems(breaks); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, breaks[i][0], breaks[i][1], bad,
		    sizeof(bad)), "%s is not in the document", breaks[i][0]);
		while (swap_in(bad, "@A", sa, t1, sizeof(t1)))
			snprintf(bad, sizeof(bad), "%s", t1);
		r3_check(bad, &r);
		ATF_CHECK_MSG(r.status == 400 && strstr(r.body, breaks[i][2]) !=
		    NULL, "%s: HTTP %d, %s", breaks[i][1], r.status, r.body);
		resp_free(&r);
	}

	/* Kept, as version 1; one from version 0 again is too old. */
	r3_keep(doc);
	r3_doc_put(doc, &r);
	EXPECT(&r, 409);
	resp_free(&r);
	r3_doc(&r);
	ATF_CHECK_STREQ("1", jstr(&r, "version"));
	ATF_CHECK_STREQ("acme", jstr(&r, "swvcs.0.id"));
	ATF_CHECK_STREQ("10", jstr(&r,
	    "swvcs.0.policies.0.criteria.performance.primary.threshold"));
	resp_free(&r);
	/* Without a session, nothing. */
	cookie[0] = '\0';
	http("GET", CC "sdwan/document", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
}

/*
 * MEF 138's Security Admin Notifications (§6.3): a document kept with a
 * function policy's values changed issues a SAN of that policy (R31),
 * with the values that changed alone, a Block's names neutralised
 * (R34), who did it and from where; kept (R32), as CSV too, and mailed
 * to the SAN recipients (R36).  No SEN without events.
 */
CONSOLE_TC(sdwan_notices, "SD-WAN security admin notifications: a function "
    "policy changed is told")
ATF_TC_BODY(sdwan_notices, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16];
	char		doc[12288], t1[12288];
	int		i;

	/* The hosts' events read each second: the notices go out a tick. */
	snprintf(harness_webconf, sizeof(harness_webconf), "mail_tick = 1;\n");
	start(tc, 0, NULL);
	enrol(&a);
	r3_ab(sa, sb, sizeof(sa));
	r3_settings("\"mail-san\":\"soc@example.org\",\"mail-sen\":"
	    "\"soc@example.org\"", 204);
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* The first document: every function policy added, a SAN each. */
	r3_keep(doc);
	r3_sdwan("san", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(ucl_object_toint(ucl_object_lookup(r.json, "count")) == 5
	    && strcmp(jstr(&r, "notices.0.service"), "acme") == 0 && strlen(
	    jstr(&r, "notices.0.id")) == 36 && strcmp(jstr(&r, "notices.0.who"),
	    "key -7") == 0 && strstr(jstr(&r, "notices.0.when"), "T") != NULL &&
	    jstr(&r, "notices.0.when")[strlen(jstr(&r, "notices.0.when")) - 1] ==
	    'Z', "%s", r.body);
	resp_free(&r);
	/* The DNF's Block changed and its No-match: one SAN, of it, the
	 * entries added and taken away neutralised, the No-match's values. */
	ATF_REQUIRE(swap_in(doc, "\"version\":0", "\"version\":1", t1,
	    sizeof(t1)));
	snprintf(doc, sizeof(doc), "%s", t1);
	ATF_REQUIRE(swap_in(doc, "\"block\":[\"ads.example\"],\"allow\":"
	    "[\"ok.ads.example\"],\"no-match\":\"allow\"", "\"block\":"
	    "[\"bad.example\",\"*.worse.example\"],\"allow\":[\"ok.ads.example\"]"
	    ",\"no-match\":\"block\"", t1, sizeof(t1)));
	snprintf(doc, sizeof(doc), "%s", t1);
	r3_keep(doc);
	r3_sdwan("san?q=g-dnf", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(ucl_object_toint(ucl_object_lookup(r.json, "count")) == 6
	    && strcmp(jstr(&r, "notices.0.policy"), "g-dnf") == 0 && strcmp(
	    jstr(&r, "notices.1.policy"), "g-dnf") == 0 && jstr(&r,
	    "notices.2.policy") == NULL && strstr(jstr(&r, "notices.0.details"),
	    "block: added \"bad[.]example\", \"*[.]worse[.]example\", taken away "
	    "\"ads[.]example\"") != NULL && strstr(jstr(&r, "notices.0.details"),
	    "no-match: \"allow\" was now \"block\"") != NULL && strstr(jstr(&r,
	    "notices.0.details"), "ok") == NULL, "%s", r.body);
	resp_free(&r);
	/* The same again: nothing changed, no SAN. */
	ATF_REQUIRE(swap_in(doc, "\"version\":1", "\"version\":2", t1,
	    sizeof(t1)));
	snprintf(doc, sizeof(doc), "%s", t1);
	r3_keep(doc);
	r3_sdwan("san", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(ucl_object_toint(ucl_object_lookup(r.json, "count")) == 6,
	    "%s", r.body);
	resp_free(&r);
	http_with("GET", CC "sdwan/san", "Accept: text/csv\r\n", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strncmp(r.body, "id,when,issuer,source,who,service,policy,"
	    "details\n", 48) == 0 && strstr(r.body, ",\"key -7\",\"acme\","
	    "\"g-dnf\",\"block: added \"\"bad[.]example\"\"") != NULL, "%s",
	    r.body);
	resp_free(&r);
	/* None without a session; nothing of SENs yet. */
	r3_sdwan("sen", &r);
	EXPECT(&r, 200);
	ATF_CHECK(ucl_object_toint(ucl_object_lookup(r.json, "count")) == 0);
	resp_free(&r);
	/* Mailed to the SAN recipients, the names neutralised, within the
	 * tick; the alerts' address has none to go to. */
	for (i = 0; i < 100 && system("grep -q 'Security Admin Notification' "
	    "mail.out") != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(system("grep -qx 'To: soc@example.org' mail.out && grep "
	    "-q '^Subject: Arcana: [0-9]* Security Admin Notifications' mail.out "
	    "&& grep -q 'Security Function Policy: g-dnf of service acme' "
	    "mail.out && grep -q 'bad\\[\\.\\]example' mail.out && grep -q "
	    "'Changed by key -7' mail.out") == 0, "no mail of the SANs");
	cookie[0] = '\0';
	r3_sdwan("san", &r);
	EXPECT(&r, 401);
	resp_free(&r);
}

/*
 * An apply's input (arcana-console's sdwan/apply) accepting every
 * warning the plan lists now (each a host's device edit's:
 * rc-conf-files, the tests' hosts naming no Arcana rc.conf file), as the
 * page's Deploy does; fresh or not.  A buffer of its own, until the
 * next call.
 */
static const char *
accepting(bool fresh)
{
	static char	*json;
	struct resp	 r;
	ucl_object_t	*o, *top;

	free(json);
	http("GET", CC "sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(resp_unwrap(&r, "arcana-console:plan"));
	o = ucl_object_typed_new(UCL_OBJECT);
	if (fresh)
		ucl_object_insert_key(o, ucl_object_frombool(true), "fresh", 0,
		    false);
	ucl_object_insert_key(o, ucl_object_copy(ucl_object_lookup(r.json,
	    "accept")), "accept", 0, false);
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, o, "arcana-console:input", 0, false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	resp_free(&r);
	return (json);
}

/* The apply's end: done or failed; its state (arcana-console's
 * sdwan/apply-state, unwrapped), into r. */
static void
sdwan_wait(struct resp *r)
{
	int	i;

	/* Up to two and a half minutes: several applies run at once. */
	for (i = 0; i < 750; i++) {
		http("GET", CC "sdwan/apply-state", NULL, r);
		(void)resp_unwrap(r, "arcana-console:apply-state");
		if (r->status == 200 && jstr(r, "applying") != NULL &&
		    strcmp(jstr(r, "applying"), "false") == 0 && jstr(r,
		    "apply.state") != NULL && strcmp(jstr(r, "apply.state"),
		    "running") != 0)
			return;
		resp_free(r);
		usleep(200000);
	}
	/* What the console and the lab's agents (sdwan_lab) said. */
	show("console.out");
	show("ea/agent.out");
	show("eb/agent.out");
	http("GET", CC "sdwan/apply-state", NULL, r);
	ATF_REQUIRE_MSG(false, "the apply did not end: %s", r->body);
}

/* How many of the plan's changes are of that kind. */
static int
changes_of(const struct resp *r, const char *change)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	while ((c = ucl_object_iterate(ucl_object_lookup(r->json, "changes"),
	    &it, true)) != NULL)
		if (strcmp(ucl_object_tostring_forced(ucl_object_lookup(c,
		    "change")), change) == 0)
			n++;
	return (n);
}

/* The plan's change of a key at the first edge that has it, and the
 * form of its first instance, as JSON; NULL for none. */
static const char *
plan_spec(struct resp *r, const char *key)
{
	static char		*last;
	const ucl_object_t	*o;
	char			 path[96];
	int			 i;

	for (i = 0; i < 200; i++) {
		snprintf(path, sizeof(path), "changes.%d.key", i);
		if (jstr(r, path) == NULL)
			return (NULL);
		if (strcmp(jstr(r, path), key) != 0)
			continue;
		snprintf(path, sizeof(path), "changes.%d.make.0.instances.0.spec",
		    i);
		if ((o = ucl_object_lookup_path(r->json, path)) == NULL)
			return (NULL);
		free(last);
		last = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
		return (last);
	}
	return (NULL);
}

/*
 * The security function policies (MEF 138) the edges serve a zone with:
 * an MBSF (TLS opened, old versions refused, a host never opened, plain
 * HTTP blocked), a URLF with paths and No-match block, a PDNS by the
 * answers' addresses, the Default zone with the same: the forms the
 * agent renders, Squid's and unbound's (agent_test's sdwan_forms has
 * their text, taken by the real local-unbound-checkconf).
 */
CONSOLE_TC(sdwan_sfp, "SD-WAN security function policies: Squid and unbound "
    "by zone")
ATF_TC_BODY(sdwan_sfp, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16];
	char		doc[12288], t1[12288];
	const char	*c;
	size_t		i;

	start(tc, 0, NULL);
	enrol(&a);
	r3_ab(sa, sb, sizeof(sa));
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	static const char *const edits[][2] = {
		{ "{\"id\":\"g-urlf\",\"function\":\"urlf\",\"block\":["
		    "\"bad.example\"],\"no-match\":\"allow\"",
		    "{\"id\":\"g-mbsf\",\"function\":\"mbsf\",\"block\":[\"tls1.0\","
		    "\"tls1.1\"],\"allow\":[\"tls1.2\",\"tls1.3\"],\"no-match\":"
		    "\"block\",\"invalid-server-certificate\":\"block\","
		    "\"unencrypted\":\"block\",\"pass-through\":[\"bank.example\"]},"
		    "{\"id\":\"g-pdns\",\"function\":\"pdns\",\"block\":[{\"type\":"
		    "\"A\",\"value\":\"192.0.2.66\"},{\"type\":\"CNAME\",\"value\":"
		    "\"*.tracker.example\"},{\"type\":\"NS\",\"value\":"
		    "\"ns.evil.example\",\"encryption\":\"any\"},{\"type\":\"NS\","
		    "\"value\":\"198.51.100.53\"},{\"type\":\"NS\",\"value\":"
		    "\"2001:db8::53/128\"}],\"allow\":[{\"type\":\"AAAA\","
		    "\"value\":\"any\"},{\"type\":\"CNAME\",\"value\":"
		    "\"ok.tracker.example\",\"encryption\":[\"unencrypted\","
		    "\"dot\"]}],\"no-match\":\"allow\",\"duration\":6,"
		    "\"southbound\":[\"unencrypted\",\"dot\"],\"northbound\":\"dot\","
		    "\"upstream\":[\"192.0.2.53#dns.example\","
		    "\"2001:db8::53@8853#dns.example\"]},"
		    "{\"id\":\"g-urlf\",\"function\":\"urlf\",\"block\":["
		    "\"bad.example\",\"*.worse.example/ads/*\"],\"allow\":["
		    "\"bad.example/ok\"],\"no-match\":\"block\"" },
		{ "\"g-urlf\",\"g-mdr\"]", "\"g-urlf\",\"g-mdr\",\"g-mbsf\","
		    "\"g-pdns\"]" },
		{ "\"block\":[\"ads.example\"]", "\"block\":[\"ads.example\","
		    "\"cdn.*.example\"],\"quarantine\":[\"*.track.*\"]" },
		{ "{\"name\":\"rest\",\"prefixes\":\"Default\"}",
		    "{\"name\":\"rest\",\"prefixes\":\"Default\",\"policies\":[{"
		    "\"app\":\"web\",\"policy\":\"fast\"}]}" },
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\",\"gateway\":\"192.0.2.254\"" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\"" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
		{ "\"id\":\"uni-hq\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-hq\",\"interface\":\"lo0\"" },
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\"" },
		{ "\"kind\":\"geneve\"", "\"kind\":\"gif\"" },
	};
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s is not in the document", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	r3_keep(doc);
	r3_sdwan("plan", &r);
	EXPECT(&r, 200);
	/* Squid at a: TLS opened (inspect); the office zone by its prefixes
	 * here (its remote end point's identities' too) first, Default after
	 * it; each with its URLF, MBSF and MD+R as the service has them;
	 * where it is reached, the resolver and c-icap here. */
	ATF_REQUIRE_MSG((c = plan_spec(&r, "proxy")) != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"mode\":\"inspect\",\"host\":\"a\"") !=
	    NULL && strstr(c, "\"flavor\":\"sdwan\",\"service\":\"acme\","
	    "\"fib\":1,\"listen\":[{\"end_point\":\"hq\",\"address\":"
	    "\"10.1.0.1\"},{\"end_point\":\"road\",\"address\":\"10.30.0.1\"}],"
	    "\"resolver\":true,\"icap\":true,") != NULL, "%s", c);
	/* The DNF's names with a * inside (R71) are the zone's Squid's. */
	ATF_CHECK_MSG(strstr(c, "{\"name\":\"z0\",\"dnf\":[\"cdn.*.example\","
	    "\"*.track.*\"],\"prefixes\":") != NULL, "%s", c);
	ATF_CHECK_MSG(strstr(c, "\"zones\":[{\"name\":\"z0\",\"dnf\":[\"cdn.*."
	    "example\",\"*.track.*\"],\"prefixes\":"
	    "[\"10.1.0.0/16\",\"10.30.0.2/32\",\"10.30.0.64/32\"],") != NULL &&
	    strstr(c, "{\"name\":\"z1\",\"dnf\":[\"cdn.*.example\",\"*.track.*\"],"
	    "\"default\":true,\"urlf\"") != NULL &&
	    strstr(c, "\"name\":\"z0\"") < strstr(c, "\"name\":\"z1\""), "%s",
	    c);
	ATF_CHECK_MSG(strstr(c, "\"urlf\":{\"no-match\":\"block\",\"block\":["
	    "\"bad.example\",\"*.worse.example/ads/*\"],\"allow\":["
	    "\"bad.example/ok\"]},\"mbsf\":{\"no-match\":\"block\",\"block\":["
	    "\"tls1.0\",\"tls1.1\"],\"allow\":[\"tls1.2\",\"tls1.3\"],"
	    "\"pass-through\":[\"bank.example\"],\"invalid-server-certificate\":"
	    "\"block\",\"unencrypted\":\"block\"},\"mdr\":{\"no-match\":\"allow\","
	    "\"block\":[\"44D88612FEA8A8F36DE82E1278ABB02F:68\",\"275a021bbfb6489e"
	    "54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\"],\"allow\":["
	    "\"3395856ce81f2b7382dee72602f798b642f14140\"],\"id\":\"g-mdr\"}}") !=
	    NULL, "%s",
	    c);
	/* unbound at a: the zones' views, the Default zone's by all its
	 * prefixes; the DNF's names and the PDNS's answers. */
	ATF_REQUIRE_MSG((c = plan_spec(&r, "dns")) != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(c, "\"unis\":[{\"id\":\"uni-hq\",\"address\":"
	    "\"10.1.0.1\",\"prefix\":\"10.1.0.0/24\"}]") != NULL && strstr(c,
	    "{\"name\":\"z1\",\"prefixes\":[\"0.0.0.0/0\",\"::/0\"],") != NULL &&
	    strstr(c, "\"pdns\":{\"no-match\":\"allow\",\"block\":[{\"type\":"
	    "\"A\",\"value\":\"192.0.2.66\"},{\"type\":\"CNAME\",\"value\":"
	    "\"*.tracker.example\"},{\"type\":\"NS\",\"value\":\"ns.evil.example\""
	    ",\"encryption\":\"any\"},{\"type\":\"NS\",\"value\":\"198.51.100.53\"}"
	    ",{\"type\":\"NS\",\"value\":\"2001:db8::53/128\"}],\"allow\":[{"
	    "\"type\":\"AAAA\",\"value\":\"any\"},{\"type\":\"CNAME\",\"value\":"
	    "\"ok.tracker.example\",\"encryption\":[\"unencrypted\",\"dot\"]}]}")
	    != NULL && strstr(c, "\"dnf\":{\"no-match\":"
	    "\"allow\",\"block\":[\"ads.example\",\"cdn.*.example\"],"
	    "\"quarantine\":[\"*.track.*\"],\"allow\":[\"ok.ads.example\"]}") !=
	    NULL, "%s", c);
	/* How the PDNS has DNS carried (D21, D22), the resolver's: DNS over
	 * TLS to the clients too, its questions over TLS to the servers
	 * named. */
	ATF_CHECK_MSG(strstr(c, "\"fib\":1,\"dot\":true,\"upstream\":["
	    "\"192.0.2.53#dns.example\",\"2001:db8::53@8853#dns.example\"],"
	    "\"upstream_tls\":true,") != NULL, "%s", c);
	resp_free(&r);
}

/*
 * A USWE tunnel (Mplify 119 §10): the public underlay's tunnels made
 * ipsec(4) interfaces keyed by the agents: a pair each, the SAs derived
 * from the far end's public half, which the apply reads from that end.
 *
 * Its console: hosts a and b on the one agent, their ids into sa and sb;
 * sdwan_good with a uswe tunnel over the Internet into doc, its UNIs on
 * lo0, not kept yet.
 */
static void
uswe_start(const atf_tc_t *tc, struct authn *a, char *sa, char *sb,
    size_t len, char *doc, size_t dlen)
{
	char		t1[8192];
	size_t		i;

	start(tc, 0, NULL);
	enrol(a);
	r3_ab(sa, sb, len);
	snprintf(doc, dlen, "%s", sdwan_good);
	static const char *const edits[][2] = {
		{ "\"tunnel\":{\"kind\":\"gre\",\"ipsec\":true}",
		    "\"tunnel\":{\"kind\":\"uswe\",\"algorithms\":\"aes-gcm-16\"}" },
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\",\"gateway\":\"192.0.2.254\"" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\"" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
		{ "\"id\":\"uni-hq\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-hq\",\"interface\":\"lo0\"" },
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\"" },
		{ "\"kind\":\"geneve\"", "\"kind\":\"gif\"" },
	};
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)));
		snprintf(doc, dlen, "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, dlen, "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, dlen, "%s", t1);
}

/* The uswe document kept and applied, done. */
static void
uswe_apply(const char *doc)
{
	struct resp	r;

	r3_keep(doc);
	http("POST", CC "sdwan/apply", accepting(false), &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "done") == 0, "%s",
	    r.body);
	resp_free(&r);
}

CONSOLE_TC(sdwan_uswe, "SD-WAN with a uswe tunnel: keys made, SAs derived")
ATF_TC_BODY(sdwan_uswe, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16], doc[8192], t1[8192], t2[400];

	need_fibs(2);
	uswe_start(tc, &a, sa, sb, sizeof(sa), doc, sizeof(doc));
	/* IPsec IKEv2 under a uswe tunnel is refused. */
	ATF_REQUIRE(swap_in(doc, "\"kind\":\"uswe\",", "\"kind\":\"uswe\","
	    "\"ipsec\":true,", t1, sizeof(t1)));
	r3_doc_put(t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "encrypts by itself")
	    != NULL, "%s", r.body);
	resp_free(&r);
	r3_keep(doc);
	/* The plan: ipsec100 and ipsec101 with their reqid, a key pair each
	 * before, the SAs derived after from the far end's public half,
	 * GCM without a separate authentication, ESN and UDP by default. */
	r3_sdwan("plan", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"if-create\",\"interface\":"
	    "\"ipsec100\",\"fib\":1,\"description\":\"sdwan\",\"persist\":true,"
	    "\"tunnel_local\":\"192.0.2.1\",\"tunnel_remote\":\"192.0.2.2\","
	    "\"reqid\":100") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"key\":\"uswekey:ipsec100\",\"phase\":2") !=
	    NULL);
	ATF_CHECK(strstr(r.body, "\"kind\":\"ipsec-sa\",\"verb\":\"key\","
	    "\"interface\":\"ipsec101\"") != NULL);
	snprintf(t2, sizeof(t2), "\"kind\":\"ipsec-sa\",\"verb\":\"derive\","
	    "\"interface\":\"ipsec100\",\"reqid\":100,\"tunnel_local\":"
	    "\"192.0.2.1\",\"tunnel_remote\":\"192.0.2.2\",\"args\":[\"peer\","
	    "\"${uswe:%s:ipsec101}\",\"enc\",\"aes-gcm-16\",\"encap\",\"esn\","
	    "\"epoch\",\"0\",\"lifetime\",\"86400\"]", sb);
	ATF_CHECK_MSG(strstr(r.body, t2) != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"verb\":\"clear\",\"interface\":\"ipsec100\"")
	    != NULL);
	ATF_CHECK(strstr(r.body, "\"kind\":\"ipsec\",\"verb\":\"conn\"") == NULL);
	resp_free(&r);
	/* Applied: the pairs made (one agent stands for both ends, so two
	 * files), the far halves read from the sdwan read, the two SAs each
	 * way set by setkey, mirrored. */
	http("POST", CC "sdwan/apply", accepting(false), &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "done") == 0, "%s",
	    r.body);
	resp_free(&r);
	ATF_CHECK(system("test -f sdwan-key-ipsec100.pem -a -f "
	    "sdwan-key-ipsec101.pem") == 0);
	ATF_CHECK(system("grep -q '^ipsec100 create reqid 100' ifconfig.log && "
	    "grep -q '^ipsec101 create reqid 101' ifconfig.log") == 0);
	ATF_CHECK(system("grep -c '^add 192.0.2.1 192.0.2.2 esp 0x[0-9a-f]* -m "
	    "tunnel -u 10[01] -r 128 -esn -natt 192.0.2.1\\[4500\\] 192.0.2.2"
	    "\\[4500\\] -E aes-gcm-16 0x[0-9a-f]*' setkey.conf | grep -q '^2$'")
	    == 0);
	ATF_CHECK(system("grep '^add 192.0.2.1 192.0.2.2 ' setkey.conf | sed "
	    "'s/-u 10[01]/-u N/' | sort -u | wc -l | grep -q '^ *1$'") == 0);
	/* Its SPIs are the same both ways: what a derive on each end set. */
	ATF_CHECK(system("grep '^add 192.0.2.2 192.0.2.1 ' setkey.conf | sed "
	    "'s/-u 10[01]/-u N/' | sort -u | wc -l | grep -q '^ *1$'") == 0);
}

CONSOLE_TC(sdwan_uswe_rekey, "SD-WAN with a uswe tunnel: its keys turned "
    "by hand")
ATF_TC_BODY(sdwan_uswe_rekey, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16], doc[8192];
	int		i;

	need_fibs(2);
	uswe_start(tc, &a, sa, sb, sizeof(sa), doc, sizeof(doc));
	uswe_apply(doc);
	/* The keys turned by hand (Mplify 119 R110, R112): a next pair on
	 * each end, the new SAs from them put in inbound on both, then
	 * outbound, then the old taken out and the next pair made the pair;
	 * the apply refused meanwhile; the rotation's state kept. */
	ATF_CHECK(system("cp sdwan-key-ipsec100.pem k100.was && cp "
	    "sdwan-key-ipsec101.pem k101.was") == 0);
	rc_act(CC "sdwan/rekey", "\"tunnel\":\"acme/none\"", &r);
	EXPECT(&r, 404);
	resp_free(&r);
	rc_act(CC "sdwan/rekey", "\"tunnel\":\"acme/a-inet-b-inet\"", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", CC "sdwan/apply", accepting(false), &r);
	ATF_CHECK_MSG(r.status == 409 && strstr(r.body, "key rotation") != NULL,
	    "%d %s", r.status, r.body);
	resp_free(&r);
	for (i = 0; i < 300; i++) {
		r3_sdwan("rekeys", &r);
		if (r.status == 200 && jstr(&r, "rekeys.acme/a-inet-b-inet.state")
		    != NULL && strcmp(jstr(&r, "rekeys.acme/a-inet-b-inet.state"),
		    "running") != 0)
			break;
		resp_free(&r);
		usleep(200000);
	}
	ATF_CHECK_MSG(jstr(&r, "rekeys.acme/a-inet-b-inet.state") != NULL &&
	    strcmp(jstr(&r, "rekeys.acme/a-inet-b-inet.state"), "done") == 0,
	    "%s", r.body);
	ATF_CHECK(jstr(&r, "rekeying") != NULL && strcmp(jstr(&r, "rekeying"),
	    "false") == 0);
	resp_free(&r);
	/* Eight SAs added in all (four, then the new four: the two inbound
	 * ones, then the two outbound, each with the old outbound taken
	 * out after it), then the two old inbound taken out: in that
	 * order; the new SPIs not the old; the next pairs made the pairs. */
	ATF_CHECK(system("grep -c '^add ' setkey.conf | grep -q '^8$'") == 0);
	ATF_CHECK(system("grep -c '^delete ' setkey.conf | grep -q '^4$'") == 0);
	ATF_CHECK(system("grep '^add \\|^delete ' setkey.conf | sed -n '5,12p' | "
	    "cut -c1-3 | tr -d '\\n' | grep -q '^addaddadddeladddeldeldel$'") ==
	    0);
	ATF_CHECK(system("grep '^add \\|^delete ' setkey.conf | sed -n '5,6p' | "
	    "grep -c '^add 192.0.2.2 192.0.2.1 .* -u 100 \\|^add 192.0.2.1 "
	    "192.0.2.2 .* -u 101 ' | grep -q '^2$'") == 0);
	ATF_CHECK(system("grep '^add \\|^delete ' setkey.conf | sed -n '8p;10p' | "
	    "grep -c '^delete 192.0.2.1 192.0.2.2 \\|^delete 192.0.2.2 192.0.2.1 "
	    "' | grep -q '^2$'") == 0);
	ATF_CHECK(system("grep '^add ' setkey.conf | sed 's/-u 10[01]//' | awk "
	    "'{print $5}' | sort -u | wc -l | grep -q '^ *4$'") == 0);
	ATF_CHECK(system("test ! -e sdwan-key-ipsec100-next.pem && ! cmp -s "
	    "k100.was sdwan-key-ipsec100.pem && ! cmp -s k101.was "
	    "sdwan-key-ipsec101.pem") == 0);
}

/* Two edges on one agent: the host, and its vnet jail gw (@A/gw). */
static const char sdwan_jail_doc[] =
    "{\"version\":0,"
    "\"ucs\":[{\"id\":\"inet\",\"type\":\"public\",\"billing\":\"flat-rate\","
    "\"tunnel\":{\"kind\":\"gre\"}}],"
    "\"edges\":[{\"server\":\"@A\",\"ucs_end_points\":[{\"id\":\"a-inet\","
    "\"ucs\":\"inet\",\"interface\":\"vtnet0\",\"address\":\"192.0.2.1\"}]},"
    "{\"server\":\"@J\",\"ucs_end_points\":[{\"id\":\"g-inet\",\"ucs\":"
    "\"inet\",\"interface\":\"vtnet0\",\"address\":\"192.0.2.2\"}]}],"
    "\"swvcs\":[{\"id\":\"acme\",\"fib\":1,\"ucs\":[\"inet\"],"
    "\"reserved_prefixes\":[\"100.64.0.0/24\"],"
    "\"bfd\":{\"interval\":200,\"multiplier\":3},"
    "\"zones\":[{\"name\":\"rest\",\"prefixes\":\"Default\"}],"
    "\"intervals\":{\"eval\":1000,\"arrival\":100,\"ir\":500},"
    "\"flows\":[{\"name\":\"all\",\"criteria\":{\"any\":true}}],"
    "\"policies\":[{\"name\":\"open\",\"direction\":\"ingress\","
    "\"criteria\":{}}],"
    "\"end_points\":[{\"id\":\"hq\",\"edge\":\"@A\",\"uni\":{\"id\":"
    "\"uni-hq\",\"interface\":\"lo0\",\"ipv4\":{\"mode\":\"static\","
    "\"prefix\":\"10.1.0.0/24\",\"provider\":[\"10.1.0.1\"]}},\"policy_map\":[{\"zone\":\"rest\","
    "\"app\":\"all\",\"ingress\":\"open\"}]},{\"id\":\"branch\",\"edge\":"
    "\"@J\",\"uni\":{\"id\":\"uni-br\",\"interface\":\"epair1b\",\"ipv4\":{"
    "\"mode\":\"static\",\"prefix\":\"10.2.0.0/24\",\"provider\":["
    "\"10.2.0.1\"]}},"
    "\"policy_map\":[{\"zone\":\"rest\",\"app\":\"all\",\"ingress\":"
    "\"open\"}]}]}]}";

CONSOLE_TC(sdwan_jail, "SD-WAN at an edge that is a vnet jail: checked, "
    "planned and applied there, its probes and steering its own")
ATF_TC_BODY(sdwan_jail, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sj[40];
	char		doc[4096], t1[4096];

	need_fibs(2);
	start(tc, 0, NULL);
	enrol(&a);
	r3_host("a", "jgd.sock", sa, sizeof(sa));
	snprintf(sj, sizeof(sj), "%s/gw", sa);
	snprintf(doc, sizeof(doc), "%s", sdwan_jail_doc);
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* Not a jail's name, or no server: refused. */
	{
		char	bad[4096], bad2[4096];

		snprintf(bad, sizeof(bad), "%s", doc);
		while (swap_in(bad, "@J", "nosuch/gw", bad2, sizeof(bad2)))
			snprintf(bad, sizeof(bad), "%s", bad2);
		r3_doc_put(bad, &r);
		ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "no such server "
		    "(an edge is a server, or server/jail") != NULL, "%s", r.body);
		resp_free(&r);
		snprintf(bad, sizeof(bad), "%s", doc);
		snprintf(t1, sizeof(t1), "%s/a b", sa);
		while (swap_in(bad, "@J", t1, bad2, sizeof(bad2)))
			snprintf(bad, sizeof(bad), "%s", bad2);
		r3_doc_put(bad, &r);
		ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "no such server")
		    != NULL, "%s", r.body);
		resp_free(&r);
	}
	while (swap_in(doc, "@J", sj, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	r3_keep(doc);
	/* The plan: a tunnel between the host and its jail, each end its
	 * own edge, the jail's named a/gw. */
	r3_sdwan("plan", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_EQ_MSG(1, (int)ucl_array_size(ucl_object_lookup(r.json,
	    "tunnels")), "%s", r.body);
	ATF_CHECK_STREQ(sa, jstr(&r, "tunnels.0.ends.0.edge"));
	ATF_CHECK_STREQ(sj, jstr(&r, "tunnels.0.ends.1.edge"));
	/* Each edge watches its links: its UCS end points' and UNIs'. */
	ATF_CHECK_MSG(strstr(r.body, "\"links\":[{\"interface\":\"vtnet0\","
	    "\"id\":\"a-inet\",\"role\":\"ucs\"},{\"interface\":\"lo0\","
	    "\"id\":\"uni-hq\",\"role\":\"uni\"}]") != NULL && strstr(r.body,
	    "\"links\":[{\"interface\":\"vtnet0\",\"id\":\"g-inet\",\"role\":"
	    "\"ucs\"},{\"interface\":\"epair1b\",\"id\":\"uni-br\",\"role\":"
	    "\"uni\"}]") != NULL, "%s", r.body);
	/* The jail's BIRD, with BFD: an instance named by the jail too,
	 * run in it by the host's agent. */
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"sdwan-bird\",\"instances\":[{"
	    "\"name\":\"sw1-gw\",\"fib\":1,") != NULL, "%s", r.body);
	resp_free(&r);
	/* The jail runs no BIRD here (jls lists none in a test): the
	 * service without BFD from here on. */
	ATF_REQUIRE(swap_in(doc, "\"bfd\":{\"interval\":200,\"multiplier\":3},", "",
	    t1, sizeof(t1)));
	snprintf(doc, sizeof(doc), "%s", t1);
	/* Applied: the jail's jobs run in it, its probes, rules and
	 * steering are the jail's on the agent, the host's its own. */
	/* What the jail's edge needs is looked for in the jail, as it
	 * sees its files: strongSwan, for the public UCS's IPsec, is not
	 * there, though the host has it. */
	http("POST", CC "sdwan/apply", "{\"arcana-console:input\":{}}",
	    &r);
	EXPECT(&r, 409);
	ATF_CHECK_MSG(strstr(r.body, "a/gw: pkg install strongswan") != NULL &&
	    strstr(r.body, "a: pkg install") == NULL, "%s", r.body);
	resp_free(&r);
	ATF_REQUIRE(swap_in(doc, "\"tunnel\":{\"kind\":\"gre\"}",
	    "\"tunnel\":{\"kind\":\"gre\",\"ipsec\":false}", t1, sizeof(t1)));
	ATF_REQUIRE(swap_in(t1, "\"version\":0", "\"version\":1", doc,
	    sizeof(doc)));
	r3_keep(doc);
	/* The host's tunnel a device edit, written to Arcana's rc.conf
	 * file, which the host's rc.conf names not: the plan lists the
	 * warning, the jail's jobs none; not accepted, the step refused and
	 * the apply rolled back. */
	r3_sdwan("plan", &r);
	EXPECT(&r, 200);
	snprintf(t1, sizeof(t1), "\"accept\":[{\"server\":\"%s\",\"name\":\"a\","
	    "\"key\":\"tvc:acme/a-inet-g-inet\",\"title\":\"gre100, gre to "
	    "192.0.2.2 over a-inet\",\"warning\":\"rc-conf-files\",\"says\":", sa);
	ATF_CHECK_MSG(strstr(r.body, t1) != NULL && strstr(r.body, "/gw\","
	    "\"name\":\"a/gw\",\"key\"") == NULL, "%s", r.body);
	resp_free(&r);
	http("POST", CC "sdwan/apply", "{\"arcana-console:input\":{}}",
	    &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "rolled back") == 0 &&
	    strstr(r.body, "accept rc-conf-files to add it to /etc/rc.conf, once "
	    "(rc-conf-files); not accepted: the plan lists it, the apply accepts "
	    "it for this step") != NULL, "%s", r.body);
	resp_free(&r);
	(void)unlink("jexec.log");
	(void)unlink("ifconfig.log");
	http("POST", CC "sdwan/apply", accepting(false), &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "done") == 0, "%s",
	    r.body);
	resp_free(&r);
	/* Its tunnel made in it (ifconfig -j), the host's on the host. */
	ATF_CHECK_MSG(system("grep -q '^-j 4 gre101 create' ifconfig.log && "
	    "grep -q '^gre100 create' ifconfig.log && ! grep -q '^-j 4 gre100' "
	    "ifconfig.log") == 0, "the jail's tunnel was not made in it");
	ATF_CHECK_MSG(system("grep -q '^jexec 4 .*ipfw -q /var/run/arcana-sdwan-"
	    "rules.load' jexec.log") == 0, "the jail's rules were not loaded "
	    "by its ipfw");
	ATF_CHECK_MSG(system("test -f sdwan-probes@gw.json && test -f "
	    "sdwan-rules@gw.json && test -f sdwan-probes.json") == 0,
	    "the jail's probes and rules are not its own");
	r3_read(sa, "/arcana-sdwan:sdwan", &r);
	EXPECT(&r, 200);
	{
		const ucl_object_t	*e;
		ucl_object_iter_t	 it = NULL;
		bool			 rules = false;

		while ((e = ucl_object_iterate(ucl_object_lookup_path(r.json,
		    "state.edge"), &it, true)) != NULL)
			if (strcmp(ucl_object_tostring_forced(ucl_object_lookup(
			    e, "jail")), "gw") == 0)
				rules = ucl_object_lookup_path(e,
				    "rules.set") != NULL;
		ATF_CHECK_MSG(rules, "%s", r.body);
	}
	resp_free(&r);
	/* Its probes the jail's, in the service's table. */
	r3_read(sa, "/arcana-probe:probes", &r);
	EXPECT(&r, 200);
	{
		const ucl_object_t	*e;
		ucl_object_iter_t	 it = NULL;
		bool			 fib = false;

		while ((e = ucl_object_iterate(ucl_object_lookup_path(r.json,
		    "state.target"), &it, true)) != NULL)
			if (ucl_object_lookup(e, "jail") != NULL &&
			    strcmp(ucl_object_tostring_forced(ucl_object_lookup(
			    e, "jail")), "gw") == 0)
				fib = ucl_object_toint(ucl_object_lookup(e,
				    "fib")) == 1;
		ATF_CHECK_MSG(fib, "%s", r.body);
	}
	resp_free(&r);
	/* What only the host's own edge has yet (its NTP, say) is refused
	 * at the jail's, said so. */
	ATF_REQUIRE(swap_in(doc, "\"ucs_end_points\":[{\"id\":\"g-inet\"",
	    "\"ntp\":[\"10.0.0.1\"],\"ucs_end_points\":[{\"id\":\"g-inet\"",
	    t1, sizeof(t1)));
	ATF_REQUIRE(swap_in(t1, "\"version\":1", "\"version\":2", doc,
	    sizeof(doc)));
	r3_keep(doc);
	http("POST", CC "sdwan/apply", "{\"arcana-console:input\":{}}",
	    &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "failed") == 0 &&
	    strstr(r.body, "an edge that is a vnet jail has no ntp yet") != NULL,
	    "%s", r.body);
	resp_free(&r);
}

/*
 * The root lab (sdwan_lab): two vnet jails, each an agent's host, an
 * epair between them for the Internet and another whose ends are their
 * UNIs.  What a service makes there, snapshot by lab.sh: each jail's
 * addresses, FIBs and tunnels, and its routes to the lab's prefixes in
 * every table.  Its jails' names are its own: agent_root_test's cases
 * run beside it, and its agents' commits see their jails' networks.
 */
#define	LAB_A	"arcw_sla"
#define	LAB_B	"arcw_slb"

static const char lab_sh[] =
    "#!/bin/sh\n"
    "# up: the jails and epairs; snap: what is made; down: all gone.\n"
    "# An epair: the cloner's next, else a unit of its own (in a vnet\n"
    "# jail given an epair's b end, the cloner's next fails at its unit).\n"
    "ep() { ifconfig epair create 2>/dev/null && return; for k in $(seq 100 "
    "199); do ifconfig epair$k create 2>/dev/null && return; done; return "
    "1; }\n"
    "case $1 in\n"
    "up)\n"
    "\t# Each jail's addresses routed in its own table alone, the\n"
    "\t# kernel's default, whatever loader.conf gives a new vnet.\n"
    "\tfor j in " LAB_A " " LAB_B "; do jail -c name=$j vnet persist "
    "path=/ host.hostname=$j >/dev/null || exit 1; jexec $j sysctl "
    "net.add_addr_allfibs=0 >/dev/null; jexec $j ifconfig lo0 "
    "inet 127.0.0.1/8 up; done\n"
    "\tu=$(ep) && n=$(ep) || exit 1\n"
    "\techo \"${u%a} ${n%a}\" > lab.epairs\n"
    "\tifconfig ${u} vnet " LAB_A " && ifconfig ${u%a}b vnet " LAB_B " && "
    "ifconfig ${n} vnet " LAB_A " && ifconfig ${n%a}b vnet " LAB_B " || "
    "exit 1\n"
    "\tjexec " LAB_A " ifconfig ${u} inet 10.203.0.1/24 up && jexec " LAB_B
    " ifconfig ${u%a}b inet 10.203.0.2/24 up && jexec " LAB_A " ifconfig "
    "${n} up && jexec " LAB_B " ifconfig ${n%a}b up\n"
    "\techo \"${u} ${u%a}b ${n} ${n%a}b\" ;;\n"
    "snap)\n"
    "\tfor j in " LAB_A " " LAB_B "; do echo \"== $j\"\n"
    "\t\tjexec $j ifconfig -a | awk '/^[a-z]/ { i = $1 } /^\\t(inet |fib:|"
    "tunnelfib:|tunnel )/ && !/fe80:/ { print i, $1, $2, $3, $4 }'\n"
    "\t\tf=0; while [ $f -lt $(jexec $j sysctl -n net.fibs) ]; do jexec $j "
    "netstat -rn4 -F $f | awk -v f=$f '$1 ~ /^(10\\.|100\\.64\\.)/ { print "
    "f, $1, $2, $4 }'; f=$((f + 1)); done\n"
    "\tdone ;;\n"
    "down)\n"
    "\tfor j in " LAB_A " " LAB_B "; do jls -j $j >/dev/null 2>&1 || "
    "continue\n"
    "\t\tfor i in $(jexec $j ifconfig -l); do case $i in gre*|gif*|vlan*) "
    "jexec $j ifconfig $i destroy ;; esac; done; done\n"
    "\t[ -f lab.epairs ] && for e in $(cat lab.epairs); do for j in "
    LAB_A " " LAB_B "; do ifconfig -j $j ${e}a destroy 2>/dev/null; "
    "ifconfig -j $j ${e}b destroy 2>/dev/null; done; ifconfig ${e}a "
    "destroy 2>/dev/null; done\n"
    "\tfor j in " LAB_A " " LAB_B "; do jls -j $j >/dev/null 2>&1 && "
    "jail -r $j >/dev/null; done; true ;;\n"
    "esac\n";

/* The lab's service: hq on a, branch on b (its UNI on unib), a gre
 * tunnel between them; hq's UNI routes 10.1.8.0/22 by 10.1.0.2. */
static void
lab_doc(char *buf, size_t len, const char *version, const char *sa,
    const char *sb, char ifs[4][IFNAMSIZ], const char *unib)
{

	snprintf(buf, len, "{\"version\":%s,"
	    "\"ucs\":[{\"id\":\"inet\",\"type\":\"public\",\"billing\":"
	    "\"flat-rate\",\"tunnel\":{\"kind\":\"gre\",\"ipsec\":false}}],"
	    "\"edges\":[{\"server\":\"%s\",\"ucs_end_points\":[{\"id\":"
	    "\"a-inet\",\"ucs\":\"inet\",\"interface\":\"%s\",\"address\":"
	    "\"10.203.0.1\"}]},{\"server\":\"%s\",\"ucs_end_points\":[{\"id\":"
	    "\"b-inet\",\"ucs\":\"inet\",\"interface\":\"%s\",\"address\":"
	    "\"10.203.0.2\"}]}],"
	    "\"swvcs\":[{\"id\":\"acme\",\"fib\":1,\"ucs\":[\"inet\"],"
	    "\"reserved_prefixes\":[\"100.64.0.0/24\"],"
	    "\"zones\":[{\"name\":\"rest\",\"prefixes\":\"Default\"}],"
	    "\"intervals\":{\"eval\":1000,\"arrival\":100,\"ir\":500},"
	    "\"flows\":[{\"name\":\"all\",\"criteria\":{\"any\":true}}],"
	    "\"policies\":[{\"name\":\"open\",\"direction\":\"ingress\","
	    "\"criteria\":{}}],"
	    "\"end_points\":[{\"id\":\"hq\",\"edge\":\"%s\",\"uni\":{\"id\":"
	    "\"uni-hq\",\"interface\":\"%s\",\"ipv4\":{\"mode\":\"static\","
	    "\"prefix\":\"10.1.0.0/24\",\"provider\":[\"10.1.0.1\"]},"
	    "\"routes\":[{\"prefix\":\"10.1.8.0/22\",\"next_hop\":"
	    "\"10.1.0.2\"}]},"
	    "\"policy_map\":[{\"zone\":\"rest\",\"app\":\"all\",\"ingress\":"
	    "\"open\"}]},{\"id\":\"branch\",\"edge\":\"%s\",\"uni\":{\"id\":"
	    "\"uni-br\",\"interface\":\"%s\",\"ipv4\":{\"mode\":\"static\","
	    "\"prefix\":\"10.2.0.0/24\",\"provider\":[\"10.2.0.1\"]}},"
	    "\"policy_map\":[{\"zone\":\"rest\",\"app\":\"all\",\"ingress\":"
	    "\"open\"}]}]}]}", version, sa, ifs[0], sb, ifs[1], sa, ifs[2],
	    sb, unib);
}

/* The document's version now, for the next PUT. */
static void
lab_version(char *buf, size_t len)
{
	struct resp	r;

	r3_doc(&r);
	snprintf(buf, len, "%s", jstr(&r, "version") != NULL ? jstr(&r,
	    "version") : "0");
	resp_free(&r);
}

/* What lab.sh's snap says, malloc'd. */
static char *
lab_snap(void)
{
	FILE	*fp;
	char	*s;
	size_t	 n;

	ATF_REQUIRE(system("./lab.sh snap > snap.out 2>&1") == 0);
	ATF_REQUIRE((fp = fopen("snap.out", "r")) != NULL);
	s = calloc(1, 65536);
	n = fread(s, 1, 65535, fp);
	s[n] = '\0';
	fclose(fp);
	return (s);
}

/* A sysctl of a lab jail, its value. */
static long
lab_sysctl(const char *jail, const char *oid)
{
	char	 cmd[200], line[64];
	FILE	*fp;
	long	 v = -1;

	snprintf(cmd, sizeof(cmd), "jexec %s sysctl -n %s", jail, oid);
	if ((fp = popen(cmd, "r")) == NULL)
		return (-1);
	if (fgets(line, sizeof(line), fp) != NULL)
		v = strtol(line, NULL, 10);
	pclose(fp);
	return (v);
}

/* An apply accepting every warning the plan lists; its end into r. */
static void
lab_apply(struct resp *r, bool fresh)
{

	http("POST", CC "sdwan/apply", accepting(fresh), r);
	EXPECT(r, 200);
	resp_free(r);
	sdwan_wait(r);
}

ATF_TC_WITH_CLEANUP(sdwan_lab);
ATF_TC_HEAD(sdwan_lab, tc)
{
	atf_tc_set_md_var(tc, "descr", "The console's SD-WAN apply on a lab "
	    "for real, as root: two vnet jails, each an agent's host; a "
	    "failing apply rolled back leaves their addresses, FIBs and "
	    "routes as they were, a good one makes them, the service taken "
	    "away takes them away again");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "300");
}
ATF_TC_CLEANUP(sdwan_lab, tc)
{

	stop();
	/* Interfaces out of the jails before they go: a vnet torn down
	 * with them panics a debug kernel. */
	if (access("lab.sh", X_OK) == 0)
		(void)system("./lab.sh down");
}
ATF_TC_BODY(sdwan_lab, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[MAXPATHLEN], sa[16], sb[16];
	char		doc[4096], ver[16], line[128], ifs[4][IFNAMSIZ];
	char		*before, *after;
	FILE		*fp;

	if (system("jls -j " LAB_A " >/dev/null 2>&1 || jls -j " LAB_B
	    " >/dev/null 2>&1") == 0)
		atf_tc_skip("a jail of the lab's names is there already");
	if (system("ifconfig -C | grep -qw gre && ifconfig -C | grep -qw "
	    "epair") != 0)
		atf_tc_skip("no gre(4) or epair(4)");
	put("lab.sh", lab_sh);
	ATF_REQUIRE(chmod("lab.sh", 0755) == 0);
	ATF_REQUIRE((fp = popen("./lab.sh up", "r")) != NULL);
	ATF_REQUIRE(fgets(line, sizeof(line), fp) != NULL);
	ATF_REQUIRE(pclose(fp) == 0);
	ATF_REQUIRE(sscanf(line, "%15s %15s %15s %15s", ifs[0], ifs[1],
	    ifs[2], ifs[3]) == 4);
	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	agent_jailed(LAB_A, "ea");
	agent_jailed(LAB_B, "eb");
	r3_host("a", "ea/agent.sock", sa, sizeof(sa));
	r3_host("b", "eb/agent.sock", sb, sizeof(sb));
	before = lab_snap();
	ATF_REQUIRE_EQ(1, lab_sysctl(LAB_A, "net.fibs"));

	/*
	 * The tunnels, UNIs and routes are device edits of the hosts, each
	 * written to Arcana's rc.conf file, which the hosts' rc.conf does
	 * not name yet: the plan lists rc-conf-files to accept for each,
	 * and an apply that does not accept it is refused at the first and
	 * rolled back.
	 */
	lab_doc(doc, sizeof(doc), "0", sa, sb, ifs, ifs[3]);
	r3_keep(doc);
	r3_sdwan("plan", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"tvc:acme/a-inet-b-inet\",\""
	    "title\":\"gre100, gre to 10.203.0.2 over a-inet\",\"warning\":"
	    "\"rc-conf-files\"") != NULL && strstr(r.body, "\"key\":\"uni:hq\"")
	    != NULL && strstr(r.body, "\"key\":\"route:acme:10.1.8.0/22\"") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	http("POST", CC "sdwan/apply", "{\"arcana-console:input\":{\"fresh\":"
	    "true}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "rolled back") == 0 &&
	    strstr(r.body, "(rc-conf-files); not accepted: the plan lists it")
	    != NULL, "%s", r.body);
	resp_free(&r);
	after = lab_snap();
	ATF_CHECK_STREQ(before, after);
	free(after);

	/*
	 * b's UNI on an interface b has not: its step fails after the
	 * tunnel's and a's UNI's were made, and the apply rolled back
	 * leaves the jails as they were, but net.fibs, which only goes up.
	 */
	lab_version(ver, sizeof(ver));
	lab_doc(doc, sizeof(doc), ver, sa, sb, ifs, "lab9");
	r3_keep(doc);
	lab_apply(&r, true);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "rolled back") == 0 &&
	    strstr(r.body, "\"state\":\"undone\"") != NULL, "%s", r.body);
	resp_free(&r);
	after = lab_snap();
	ATF_CHECK_STREQ(before, after);
	free(after);

	/* The good one: made for real, kept in Arcana's rc.conf file. */
	lab_version(ver, sizeof(ver));
	lab_doc(doc, sizeof(doc), ver, sa, sb, ifs, ifs[3]);
	r3_keep(doc);
	lab_apply(&r, true);
	ATF_REQUIRE_MSG(strcmp(jstr(&r, "apply.state"), "done") == 0, "%s",
	    r.body);
	resp_free(&r);
	ATF_CHECK_MSG(system("grep -q '^cloned_interfaces=\"[^\"]*gre100' "
	    "ea/root/usr/local/etc/rc.conf.d/arcana && grep -q "
	    "'10.1.8.0/22 10.1.0.2' ea/root/usr/local/etc/rc.conf.d/arcana && "
	    "grep -q 'inet 10.1.0.1/24' ea/root/usr/local/etc/rc.conf.d/"
	    "arcana") == 0, "not kept in Arcana's rc.conf file");
	after = lab_snap();
	/* Each end of the tunnel in the service's table, its inner /31
	 * and its outer ends the underlay's; the UNI's address in it too,
	 * and hq's static route; b's routes to hq by the tunnel. */
	snprintf(line, sizeof(line), "%s: inet 10.1.0.1 netmask 0xffffff00\n"
	    "%s: fib: 1", ifs[2], ifs[2]);
	ATF_CHECK_MSG(strstr(after, "gre100: tunnel inet 10.203.0.1 -->\n"
	    "gre100: inet 100.64.0.0 --> 100.64.0.1\ngre100: fib: 1") != NULL &&
	    strstr(after, "gre101: inet 100.64.0.1 --> 100.64.0.0\n"
	    "gre101: fib: 1") != NULL && strstr(after, line) != NULL, "%s",
	    after);
	ATF_CHECK_MSG(strstr(after, "1 10.1.0.0/24 link#") != NULL &&
	    strstr(after, "1 10.1.8.0/22 10.1.0.2 ") != NULL && strstr(after,
	    "1 10.1.8.0/22 100.64.0.0 gre101") != NULL && strstr(after,
	    "1 10.2.0.0/24 link#") != NULL, "%s", after);
	free(after);
	ATF_CHECK_EQ(2, lab_sysctl(LAB_A, "net.fibs"));
	ATF_CHECK_EQ(2, lab_sysctl(LAB_B, "net.fibs"));
	ATF_CHECK_EQ(1, lab_sysctl(LAB_A, "net.inet.ip.forwarding"));
	ATF_CHECK_EQ(1, lab_sysctl(LAB_B, "net.inet6.ip6.forwarding"));
	/* The tunnel carries: b's inner end answers a's ping, in the
	 * service's table. */
	ATF_CHECK_MSG(system("jexec " LAB_A " setfib 1 ping -c 1 -t 5 "
	    "100.64.0.1 >/dev/null") == 0, "no answer through the tunnel");

	/* The service taken away: what it made goes, the rest stays. */
	lab_version(ver, sizeof(ver));
	snprintf(doc, sizeof(doc), "{\"version\":%s,\"ucs\":[],\"edges\":[],"
	    "\"swvcs\":[]}", ver);
	r3_keep(doc);
	http("POST", CC "sdwan/apply", "{\"arcana-console:input\":{}}",
	    &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "done") == 0, "%s",
	    r.body);
	resp_free(&r);
	after = lab_snap();
	ATF_CHECK_STREQ(before, after);
	free(after);
	free(before);
	ATF_CHECK_MSG(system("grep -q 'gre100\\|10.1.8.0' ea/root/usr/local/etc/"
	    "rc.conf.d/arcana") != 0, "still in Arcana's rc.conf file");
}

/*
 * PLAN-SDN-YANG 4.10.1 (sdwan_l3nm_lab): sdwan_lab's lab in jails of its
 * own, its service written as L3NM through RESTCONF:
 * hq's access in the L3NM, branch's placed on a free SAP; applied, read
 * back as VN and SAP, exported as the MEF document and imported again,
 * the L3NM unchanged, then taken away.
 */
#define	L3LAB_A		"arcw_l3a"
#define	L3LAB_B		"arcw_l3b"
#define	L3LAB_SA	"00000a3a"
#define	L3LAB_SB	"00000a3b"
#define	L3SD		"/restconf/data/arcana-console:sdwan/"

/* The UCS and the edges, a's then b's Internet interface. */
#define	L3LAB_TOP							\
    "{\"ietf-l3vpn-ntw:l3vpn-ntw\":{\"arcana-l3nm:sdwan\":{\"ucs\":[{\"id\""\
    ":\"inet\",\"type\":\"public\",\"billing\":\"flat-rate\",\"tunnel\":{"\
    "\"kind\":\"gre\",\"ipsec\":false}}],\"edge\":[{\"server\":\""	\
    L3LAB_SA "\",\"ucs-end-point\":[{\"id\":\"a-inet\",\"ucs\":\"inet\","\
    "\"interface\":\"%s\",\"address\":\"10.203.0.1\"}]},{\"server\":\""	\
    L3LAB_SB "\",\"ucs-end-point\":[{\"id\":\"b-inet\",\"ucs\":\"inet\","\
    "\"interface\":\"%s\",\"address\":\"10.203.0.2\"}]}]}}}"

/* The service: hq at a's UNI (static, 10.1.8.0/22 by 10.1.0.2), b's
 * node with no access yet. */
#define	L3LAB_SVC							\
    "{\"ietf-l3vpn-ntw:l3vpn-ntw\":{\"vpn-services\":{\"vpn-service\":[{"	\
    "\"vpn-id\":\"acme\",\"vpn-instance-profiles\":{\"vpn-instance-"	\
    "profile\":[{\"profile-id\":\"subscriber\",\"arcana-l3nm:domain\":"	\
    "\"subscriber\",\"arcana-l3nm:fib\":1}]},\"vpn-nodes\":{\"vpn-node\":"\
    "[{\"vpn-node-id\":\"" L3LAB_SA "\",\"ne-id\":\"" L3LAB_SA "\","	\
    "\"active-vpn-instance-profiles\":{\"vpn-instance-profile\":[{"	\
    "\"profile-id\":\"subscriber\"}]},\"vpn-network-accesses\":{\"vpn-"	\
    "network-access\":[{\"id\":\"hq\",\"interface-id\":\"%s\",\"vpn-"	\
    "network-access-type\":\"ietf-vpn-common:multipoint\",\"vpn-instance-"\
    "profile\":\"subscriber\",\"ip-connection\":{\"ipv4\":{\"local-address"\
    "\":\"10.1.0.1\",\"prefix-length\":24,\"address-allocation-type\":"	\
    "\"ietf-l3vpn-ntw:static-address\",\"arcana-l3nm:mode\":\"static\","	\
    "\"arcana-l3nm:provider\":[\"10.1.0.1\"]}},\"routing-protocols\":{"	\
    "\"routing-protocol\":[{\"id\":\"static\",\"type\":\"ietf-vpn-common:"\
    "static-routing\",\"static\":{\"cascaded-lan-prefixes\":{\"ipv4-lan-"	\
    "prefixes\":[{\"lan\":\"10.1.8.0/22\",\"next-hop\":\"10.1.0.2\"}]}}}]"\
    "},\"arcana-l3nm:sdwan\":{\"uni-id\":\"uni-hq\",\"policy-map\":[{"	\
    "\"zone\":\"rest\",\"app\":\"all\",\"ingress\":\"open\"}]}}]}},{"	\
    "\"vpn-node-id\":\"" L3LAB_SB "\",\"ne-id\":\"" L3LAB_SB "\","	\
    "\"active-vpn-instance-profiles\":{\"vpn-instance-profile\":[{"	\
    "\"profile-id\":\"subscriber\"}]}}]},\"arcana-l3nm:sdwan\":{\"fib\":1,"\
    "\"ucs\":[\"inet\"],\"reserved-prefix\":[\"100.64.0.0/24\"],\"zone\":"\
    "[{\"name\":\"rest\",\"default\":[null]}],\"intervals\":{\"eval\":1000,"\
    "\"arrival\":100,\"ir\":500},\"application-flow\":[{\"name\":\"all\","\
    "\"criteria\":{\"any\":true}}],\"policy\":[{\"name\":\"open\","	\
    "\"direction\":\"ingress\",\"criteria\":{}}]}}]}}}"

/* branch's access, at the SAP named (static, 10.2.0.0/24). */
#define	L3LAB_ATTACH							\
    "{\"arcana-console:input\":{\"vpn-id\":\"acme\",\"vpn-node-id\":\""	\
    L3LAB_SB "\",\"sap-id\":\"%s\",\"access\":{\"vpn-network-access-type"\
    "\":\"ietf-vpn-common:multipoint\",\"vpn-instance-profile\":"	\
    "\"subscriber\",\"ip-connection\":{\"ipv4\":{\"local-address\":"	\
    "\"10.2.0.1\",\"prefix-length\":24,\"address-allocation-type\":"	\
    "\"ietf-l3vpn-ntw:static-address\",\"arcana-l3nm:mode\":\"static\","	\
    "\"arcana-l3nm:provider\":[\"10.2.0.1\"]}},\"arcana-l3nm:sdwan\":{"	\
    "\"uni-id\":\"uni-br\",\"policy-map\":[{\"zone\":\"rest\",\"app\":"	\
    "\"all\",\"ingress\":\"open\"}]}}}}"

/* The apply's end, read at sdwan/apply-state, into r. */
static void
l3lab_wait(struct resp *r)
{
	const char	*ing, *st;
	int		 i;

	for (i = 0; i < 750; i++) {
		http("GET", L3SD "apply-state", NULL, r);
		ing = jstr(r, "arcana-console:apply-state.applying");
		st = jstr(r, "arcana-console:apply-state.apply.state");
		if (r->status == 200 && ing != NULL && strcmp(ing, "false") ==
		    0 && st != NULL && strcmp(st, "running") != 0)
			return;
		resp_free(r);
		usleep(200000);
	}
	show("console.out");
	show("la/agent.out");
	show("lb/agent.out");
	ATF_REQUIRE_MSG(false, "the apply did not end");
}

/* The plan read at sdwan/plan, applied with every warning it lists
 * accepted; the apply's end into r. */
static void
l3lab_apply(struct resp *r, bool fresh)
{
	struct resp		 p;
	const ucl_object_t	*acc;
	ucl_object_t		*in, *o;
	char			*json;

	http("GET", L3SD "plan", NULL, &p);
	EXPECT(&p, 200);
	o = ucl_object_typed_new(UCL_OBJECT);
	if (fresh)
		ucl_object_insert_key(o, ucl_object_frombool(true), "fresh", 0,
		    false);
	acc = ucl_object_lookup_path(p.json, "arcana-console:plan.accept");
	ucl_object_insert_key(o, acc != NULL ? ucl_object_copy(acc) :
	    ucl_object_typed_new(UCL_ARRAY), "accept", 0, false);
	in = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(in, o, "arcana-console:input", 0, false);
	json = (char *)ucl_object_emit(in, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(in);
	resp_free(&p);
	http("POST", L3SD "apply", json, r);
	free(json);
	EXPECT(r, 200);
	ATF_CHECK_MSG(jstr(r, "arcana-console:output.result.steps") != NULL,
	    "%s", r->body);
	resp_free(r);
	l3lab_wait(r);
}

/* How many of the plan's changes make, remake or unmake something. */
static int
l3lab_changes(void)
{
	struct resp		 r;
	const ucl_object_t	*c;
	ucl_object_iter_t	 it = NULL;
	const char		*k;
	int			 n = 0;

	http("GET", L3SD "plan", NULL, &r);
	EXPECT(&r, 200);
	while ((c = ucl_object_iterate(ucl_object_lookup_path(r.json,
	    "arcana-console:plan.changes"), &it, true)) != NULL)
		if ((k = ucl_object_tostring(ucl_object_lookup(c, "change"))) !=
		    NULL && strcmp(k, "keep") != 0)
			n++;
	if (n > 0)
		printf("plan: %s\n", r.body);
	resp_free(&r);
	return (n);
}

/* The L3NM kept, read through RESTCONF; its entity-tag into etag. */
static ucl_object_t *
l3lab_kept(char *etag, size_t len)
{
	struct resp	 r;
	ucl_object_t	*o;

	http("GET", L3NM, NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(resp_header(&r, "etag", etag, len) != NULL);
	o = ucl_object_ref(r.json);
	resp_free(&r);
	return (o);
}

/* SAP id of host h in the SAP network now; free, attached to acme and
 * made, or neither, as said. */
static void
l3lab_sap(const char *h, const char *id, bool used, bool made)
{
	struct resp		 r;
	ucl_object_t		*top;
	const ucl_object_t	*s;
	const char		*v;

	http("GET", SAPNET, NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE((top = body_of(&r)) != NULL);
	s = sn_sap(sn_node(top, "arcana-sap", h), id);
	ATF_REQUIRE_MSG(s != NULL, "no SAP %s at %s: %s", id, h, r.body);
	ATF_CHECK_STREQ("ietf-vpn-common:op-up", ucl_object_tostring(
	    ucl_object_lookup_path(s, "sap-status.status")));
	ATF_CHECK_MSG(ucl_object_toboolean(ucl_object_lookup(s,
	    "arcana-l3nm:free")) == !used, "%s at %s: free wrong: %s", id, h,
	    r.body);
	v = ucl_object_tostring(ucl_object_lookup_path(s,
	    "arcana-l3nm:attachment.0.vpn-id"));
	ATF_CHECK_MSG(used ? v != NULL && strcmp(v, "acme") == 0 : v == NULL,
	    "%s at %s: attachment wrong: %s", id, h, r.body);
	if (used) {
		ATF_CHECK_MSG(ucl_object_toboolean(ucl_object_lookup_path(s,
		    "arcana-l3nm:attachment.0.made")) == made, "%s at %s: "
		    "made wrong: %s", id, h, r.body);
		ATF_CHECK_STREQ(made ? "ietf-vpn-common:op-up" :
		    "ietf-vpn-common:op-down", ucl_object_tostring(
		    ucl_object_lookup_path(s, "service-status.oper-status."
		    "status")));
	}
	ucl_object_unref(top);
	resp_free(&r);
}

ATF_TC_WITH_CLEANUP(sdwan_l3nm_lab);
ATF_TC_HEAD(sdwan_l3nm_lab, tc)
{
	atf_tc_set_md_var(tc, "descr", "PLAN-SDN-YANG 4.10.1 on a lab, as "
	    "root: a service written as L3NM through RESTCONF, an access "
	    "placed on a free SAP, applied on two vnet jails' agents, read "
	    "back as VN and SAP, exported as the MEF document and imported "
	    "again unchanged, then taken away");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "300");
}
ATF_TC_CLEANUP(sdwan_l3nm_lab, tc)
{

	stop();
	/* Interfaces out of the jails before they go (sdwan_lab's). */
	if (access("lab.sh", X_OK) == 0)
		(void)system("./lab.sh down");
}
ATF_TC_BODY(sdwan_l3nm_lab, tc)
{
	struct authn		 a;
	struct resp		 r;
	ucl_object_t		*y0, *y1, *d0, *d1, *o;
	const ucl_object_t	*v;
	char			 cwd[MAXPATHLEN], body[MAXPATHLEN + 128];
	char			 script[sizeof(lab_sh) + 64];
	char			 t[sizeof(lab_sh) + 64], doc[8192], line[128];
	char			 etag[64], hdr[96], path[256], where[256];
	char			 ifs[4][IFNAMSIZ];
	char			*before, *after, *json;
	FILE			*fp;
	int			 i;

	if (system("jls -j " L3LAB_A " >/dev/null 2>&1 || jls -j " L3LAB_B
	    " >/dev/null 2>&1") == 0)
		atf_tc_skip("a jail of the lab's names is there already");
	if (system("ifconfig -C | grep -qw gre && ifconfig -C | grep -qw "
	    "epair") != 0)
		atf_tc_skip("no gre(4) or epair(4)");
	/* sdwan_lab's lab.sh, its jails named for this case. */
	snprintf(script, sizeof(script), "%s", lab_sh);
	while (swap_in(script, LAB_A, L3LAB_A, t, sizeof(t)))
		snprintf(script, sizeof(script), "%s", t);
	while (swap_in(script, LAB_B, L3LAB_B, t, sizeof(t)))
		snprintf(script, sizeof(script), "%s", t);
	put("lab.sh", script);
	ATF_REQUIRE(chmod("lab.sh", 0755) == 0);
	ATF_REQUIRE((fp = popen("./lab.sh up", "r")) != NULL);
	ATF_REQUIRE(fgets(line, sizeof(line), fp) != NULL);
	ATF_REQUIRE(pclose(fp) == 0);
	ATF_REQUIRE(sscanf(line, "%15s %15s %15s %15s", ifs[0], ifs[1],
	    ifs[2], ifs[3]) == 4);
	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	agent_jailed(L3LAB_A, "la");
	agent_jailed(L3LAB_B, "lb");
	snprintf(body, sizeof(body), "{\"arcana-console:host\":[{\"id\":\""
	    L3LAB_SA "\",\"name\":\"a\",\"uri\":\"unix:%s/la/agent.sock\"}]}",
	    cwd);
	http("POST", "/restconf/data/arcana-console:hosts", body, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"arcana-console:host\":[{\"id\":\""
	    L3LAB_SB "\",\"name\":\"b\",\"uri\":\"unix:%s/lb/agent.sock\"}]}",
	    cwd);
	http("POST", "/restconf/data/arcana-console:hosts", body, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	before = lab_snap();

	/*
	 * 1. Written as L3NM: the UCS and the edges where none was, then
	 * the service by the entity-tag read; a stale one refused.
	 */
	snprintf(doc, sizeof(doc), L3LAB_TOP, ifs[0], ifs[1]);
	http_with("PUT", L3NM, "If-None-Match: *\r\n", doc, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http_with("PUT", L3NM, "If-None-Match: *\r\n", doc, &r);
	EXPECT(&r, 412);
	resp_free(&r);
	y0 = l3lab_kept(etag, sizeof(etag));
	ucl_object_unref(y0);
	snprintf(doc, sizeof(doc), L3LAB_SVC, ifs[2]);
	http_with("PATCH", L3NM, "If-Match: \"0-0\"\r\n", doc, &r);
	EXPECT(&r, 412);
	resp_free(&r);
	snprintf(hdr, sizeof(hdr), "If-Match: %s\r\n", etag);
	http_with("PATCH", L3NM, hdr, doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);

	/*
	 * 2. branch placed by the SAP flow: b's UNI a free SAP, up; hq's
	 * the service's already, not made yet.
	 */
	l3lab_sap(L3LAB_SB, ifs[3], false, false);
	l3lab_sap(L3LAB_SA, ifs[2], true, false);
	snprintf(body, sizeof(body), L3LAB_ATTACH, ifs[3]);
	http("POST", L3SD "attach", body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(ifs[3], jstr(&r, "arcana-console:output.result."
	    "sap-id"));
	ATF_CHECK_STREQ(ifs[3], jstr(&r, "arcana-console:output.result."
	    "access-id"));
	resp_free(&r);
	l3lab_sap(L3LAB_SB, ifs[3], true, false);
	snprintf(body, sizeof(body), L3LAB_ATTACH, ifs[3]);
	http("POST", L3SD "attach", body, &r);
	EXPECT(&r, 409);
	resp_free(&r);

	/*
	 * 3. Planned and applied through RESTCONF, the warnings accepted:
	 * the tunnel, both UNIs and hq's route made in the jails, kept in
	 * Arcana's rc.conf file; a ping across, UNI to UNI.
	 */
	http("GET", L3SD "plan", NULL, &r);
	EXPECT(&r, 200);
	snprintf(t, sizeof(t), "\"key\":\"uni:%s\"", ifs[3]);
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"tvc:acme/a-inet-b-inet\"") !=
	    NULL && strstr(r.body, "\"key\":\"uni:hq\"") != NULL &&
	    strstr(r.body, t) != NULL && strstr(r.body, "\"key\":\"route:acme:"
	    "10.1.8.0/22\"") != NULL && strstr(r.body, "\"warning\":"
	    "\"rc-conf-files\"") != NULL, "%s", r.body);
	resp_free(&r);
	l3lab_apply(&r, true);
	ATF_REQUIRE_MSG(strcmp(jstr(&r, "arcana-console:apply-state.apply."
	    "state"), "done") == 0, "%s", r.body);
	resp_free(&r);
	ATF_CHECK_MSG(system("grep -q '^cloned_interfaces=\"[^\"]*gre100' "
	    "la/root/usr/local/etc/rc.conf.d/arcana && grep -q "
	    "'10.1.8.0/22 10.1.0.2' la/root/usr/local/etc/rc.conf.d/arcana && "
	    "grep -q 'inet 10.2.0.1/24' lb/root/usr/local/etc/rc.conf.d/"
	    "arcana") == 0, "not kept in Arcana's rc.conf file");
	after = lab_snap();
	snprintf(t, sizeof(t), "%s: inet 10.1.0.1 netmask 0xffffff00\n"
	    "%s: fib: 1", ifs[2], ifs[2]);
	snprintf(line, sizeof(line), "%s: inet 10.2.0.1 netmask 0xffffff00\n"
	    "%s: fib: 1", ifs[3], ifs[3]);
	ATF_CHECK_MSG(strstr(after, "gre100: tunnel inet 10.203.0.1 -->\n"
	    "gre100: inet 100.64.0.0 --> 100.64.0.1\ngre100: fib: 1") != NULL &&
	    strstr(after, "gre101: inet 100.64.0.1 --> 100.64.0.0\n"
	    "gre101: fib: 1") != NULL && strstr(after, t) != NULL &&
	    strstr(after, line) != NULL, "%s", after);
	ATF_CHECK_MSG(strstr(after, "1 10.1.0.0/24 link#") != NULL &&
	    strstr(after, "1 10.1.8.0/22 10.1.0.2 ") != NULL && strstr(after,
	    "1 10.1.8.0/22 100.64.0.0 gre101") != NULL && strstr(after,
	    "1 10.2.0.0/24 100.64.0.1 gre100") != NULL && strstr(after,
	    "1 10.2.0.0/24 link#") != NULL, "%s", after);
	free(after);
	ATF_CHECK_EQ(2, lab_sysctl(L3LAB_A, "net.fibs"));
	ATF_CHECK_EQ(2, lab_sysctl(L3LAB_B, "net.fibs"));
	ATF_CHECK_MSG(system("jexec " L3LAB_A " setfib 1 ping -c 1 -t 5 "
	    "100.64.0.1 >/dev/null") == 0, "no answer through the tunnel");
	ATF_CHECK_MSG(system("jexec " L3LAB_A " setfib 1 ping -c 1 -t 5 -S "
	    "10.1.0.1 10.2.0.1 >/dev/null") == 0, "hq's UNI not answered by "
	    "branch's");

	/*
	 * 4. Read back as VN: one, its member hq to branch, the tunnel its
	 * underlay, up by the probes at its ends; as SAP: both UNIs the
	 * service's, made, not free.
	 */
	http("GET", VN_VN, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("acme", jstr(&r, "ietf-vn:virtual-network.vn.0.id"));
	ATF_CHECK(jstr(&r, "ietf-vn:virtual-network.vn.1") == NULL);
	snprintf(t, sizeof(t), L3LAB_SA ":hq~" L3LAB_SB ":%s", ifs[3]);
	ATF_CHECK_STREQ(t, jstr(&r, "ietf-vn:virtual-network.vn.0.vn-member."
	    "0.id"));
	ATF_CHECK(jstr(&r, "ietf-vn:virtual-network.vn.0.vn-member.1") ==
	    NULL);
	snprintf(t, sizeof(t), L3LAB_SA ":%s", ifs[2]);
	ATF_CHECK_STREQ(t, jstr(&r, "ietf-vn:virtual-network.vn.0.vn-member."
	    "0.src.ap"));
	snprintf(t, sizeof(t), L3LAB_SB ":%s", ifs[3]);
	ATF_CHECK_STREQ(t, jstr(&r, "ietf-vn:virtual-network.vn.0.vn-member."
	    "0.dest.ap"));
	snprintf(t, sizeof(t), "acme:%s", ifs[3]);
	ATF_CHECK_STREQ(t, jstr(&r, "ietf-vn:virtual-network.vn.0.vn-member."
	    "0.dest.vn-ap-id"));
	resp_free(&r);
#define	L3LAB_TUN	"ietf-vn:vn-member.0.underlay.arcana-sdwan-underlay:" \
	"sdwan.tunnel.0."
	snprintf(path, sizeof(path), VN_VN "/vn=acme/vn-member=" L3LAB_SA
	    "%%3Ahq~" L3LAB_SB "%%3A%s", ifs[3]);
	for (i = 0; i < 300; i++) {
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		if (jstr(&r, L3LAB_TUN "state") != NULL && strcmp(jstr(&r,
		    L3LAB_TUN "state"), "up") == 0)
			break;
		resp_free(&r);
		usleep(200000);
	}
	ATF_REQUIRE_MSG(i < 300, "the tunnel not up in the VN view: %s",
	    r.body);
	ATF_CHECK_STREQ("acme/a-inet-b-inet", jstr(&r, L3LAB_TUN "id"));
	ATF_CHECK_STREQ("gre", jstr(&r, L3LAB_TUN "encapsulation"));
	ATF_CHECK_STREQ("1", jstr(&r, L3LAB_TUN "fib"));
	ATF_CHECK_STREQ(L3LAB_SA, jstr(&r, L3LAB_TUN "src.edge"));
	ATF_CHECK_STREQ("10.203.0.1", jstr(&r, L3LAB_TUN "src.outer-address"));
	ATF_CHECK_STREQ(L3LAB_SB, jstr(&r, L3LAB_TUN "dest.edge"));
	ATF_CHECK_STREQ("10.203.0.2", jstr(&r, L3LAB_TUN
	    "dest.outer-address"));
	ATF_CHECK_STREQ("true", jstr(&r, L3LAB_TUN "selected"));
	ATF_CHECK_STREQ("up", jstr(&r, "ietf-vn:vn-member.0.oper-status"));
	ATF_CHECK(jstr(&r, "ietf-vn:vn-member.0.underlay."
	    "arcana-sdwan-underlay:sdwan.tunnel.1") == NULL);
	resp_free(&r);
#undef	L3LAB_TUN
	l3lab_sap(L3LAB_SA, ifs[2], true, true);
	l3lab_sap(L3LAB_SB, ifs[3], true, true);

	/*
	 * 5. Exported as the MEF document and imported again: the L3NM
	 * kept as it was, node for node, the document the same but its
	 * version; a second plan makes nothing.
	 */
	y0 = l3lab_kept(etag, sizeof(etag));
	http("GET", L3SD "document", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("acme", jstr(&r, "arcana-console:document.swvcs.0."
	    "id"));
	ATF_CHECK_STREQ("hq", jstr(&r, "arcana-console:document.swvcs.0."
	    "end_points.0.id"));
	ATF_CHECK_STREQ(ifs[3], jstr(&r, "arcana-console:document.swvcs.0."
	    "end_points.1.id"));
	ATF_CHECK_STREQ("10.2.0.0/24", jstr(&r, "arcana-console:document."
	    "swvcs.0.end_points.1.uni.ipv4.prefix"));
	ATF_CHECK_STREQ("a-inet", jstr(&r, "arcana-console:document.edges.0."
	    "ucs_end_points.0.id"));
	d0 = ucl_object_ref(r.json);
	json = (char *)ucl_object_emit(r.json, UCL_EMIT_JSON_COMPACT);
	resp_free(&r);
	http("PUT", L3SD "document", json, &r);
	free(json);
	EXPECT(&r, 204);
	resp_free(&r);
	y1 = l3lab_kept(etag, sizeof(etag));
	snprintf(where, sizeof(where), "l3vpn-ntw");
	ATF_CHECK_MSG(same_json(y0, y1, where, sizeof(where)), "the L3NM "
	    "not as it was at %s: %s", where, ucl_object_emit(y1,
	    UCL_EMIT_JSON_COMPACT));
	http("GET", L3SD "document", NULL, &r);
	EXPECT(&r, 200);
	d1 = ucl_object_ref(r.json);
	resp_free(&r);
	ATF_CHECK_EQ(ucl_object_toint(ucl_object_lookup_path(d0,
	    "arcana-console:document.version")) + 1, ucl_object_toint(
	    ucl_object_lookup_path(d1, "arcana-console:document.version")));
	for (i = 0; i < 2; i++) {
		o = __DECONST(ucl_object_t *, ucl_object_lookup(i == 0 ? d0 :
		    d1, "arcana-console:document"));
		(void)ucl_object_delete_key(o, "version");
		(void)ucl_object_delete_key(o, "changed");
	}
	snprintf(where, sizeof(where), "document");
	ATF_CHECK_MSG(same_json(d0, d1, where, sizeof(where)), "the document "
	    "not as it was at %s", where);
	ucl_object_unref(d0);
	ucl_object_unref(d1);
	ucl_object_unref(y0);
	ucl_object_unref(y1);
	ATF_CHECK_EQ(0, l3lab_changes());

	/*
	 * 6. Taken away by the entity-tag: what it made goes, the jails as
	 * they were, the SAP free again.
	 */
	snprintf(hdr, sizeof(hdr), "If-Match: %s\r\n", etag);
	http_with("DELETE", L3NM, hdr, NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	l3lab_apply(&r, false);
	v = ucl_object_lookup_path(r.json, "arcana-console:apply-state.apply."
	    "state");
	ATF_CHECK_MSG(v != NULL && strcmp(ucl_object_tostring(v), "done") ==
	    0, "%s", r.body);
	resp_free(&r);
	after = lab_snap();
	ATF_CHECK_STREQ(before, after);
	free(after);
	free(before);
	ATF_CHECK_MSG(system("grep -q 'gre100\\|10.1.8.0' la/root/usr/local/"
	    "etc/rc.conf.d/arcana") != 0, "still in Arcana's rc.conf file");
	l3lab_sap(L3LAB_SB, ifs[3], false, false);
}

CONSOLE_TC(sdwan_mesh, "Several transports on a pair of edges: two Internet "
    "Accesses join only when their tunnels are of one kind, IPsec alike, so "
    "K transports give K tunnels; a UCS End Point's preference orders the "
    "steering where a policy names none")
ATF_TC_BODY(sdwan_mesh, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16];
	char		doc[12288], t1[12288];
	size_t		i;
	static const char *const edits[][2] = {
		/* A second Internet Access, WireGuard, beside the gre one. */
		{ "\"tunnel\":{\"kind\":\"gre\",\"ipsec\":true}}",
		    "\"tunnel\":{\"kind\":\"gre\",\"ipsec\":true}},{\"id\":\"wgnet\","
		    "\"type\":\"public\",\"billing\":\"flat-rate\",\"tunnel\":{"
		    "\"kind\":\"wg\"}}" },
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-wg\",\"ucs\":\"wgnet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\",\"breakout\":true,\"preference\":1},"
		    "{\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\",\"preference\":10" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		/* b's wg end goes through a relay of its own toward a, in a
		 * table of its own; a's is behind NAT. */
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-wg\",\"ucs\":\"wgnet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\",\"preference\":1,\"vrf\":2,\"relay\":"
		    "[{\"to\":\"@A\",\"endpoint\":\"127.0.0.1:51821\",\"port\":14350}]},"
		    "{\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\",\"preference\":10" },
		{ "\"address\":\"192.0.2.1\",\"breakout\":true,\"preference\":1}",
		    "\"address\":\"192.0.2.1\",\"breakout\":true,\"preference\":1,"
		    "\"nat\":true}" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
		{ "\"ucs\":[\"inet\",\"mpls\"]", "\"ucs\":[\"inet\",\"wgnet\","
		    "\"mpls\"]" },
		{ "\"id\":\"uni-hq\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-hq\",\"interface\":\"lo0\"" },
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\"" },
	};

	start(tc, 0, NULL);
	enrol(&a);
	r3_ab(sa, sb, sizeof(sa));
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* A preference out of range is refused. */
	ATF_REQUIRE(swap_in(doc, "\"preference\":10", "\"preference\":70000", t1,
	    sizeof(t1)));
	r3_check(t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "its preference is 0 "
	    "to 65535") != NULL, "%s", r.body);
	resp_free(&r);
	r3_keep(doc);
	/* Three tunnels, one a transport: gre over inet, wg over wgnet,
	 * geneve over mpls; none across inet and wgnet. */
	r3_sdwan("plan", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"id\":\"acme/a-inet-b-inet\"") != NULL &&
	    strstr(r.body, "\"id\":\"acme/a-wg-b-wg\"") != NULL &&
	    strstr(r.body, "\"id\":\"acme/a-mpls-b-mpls\"") != NULL &&
	    strstr(r.body, "a-inet-b-wg") == NULL && strstr(r.body,
	    "a-wg-b-inet") == NULL && jstr(&r, "tunnels.3.id") == NULL, "%s",
	    r.body);
	/* The steering's order where no policy names end points: the gre
	 * tunnel, its end preferred 10, before the wg one, preferred 1. */
	ATF_CHECK_MSG(strstr(r.body, "\"preference\":10") != NULL, "%s",
	    r.body);
	/*
	 * b's wg peer toward a points at b's relay, its interface made
	 * without a tunnelfib (the relay is on the host, in the first
	 * table) and the relay's own flow sent by b's underlay table;
	 * a's peer toward b has b's address and port; a's wg end is
	 * behind NAT, so nobody is given an endpoint for it but through
	 * a relay.
	 */
	ATF_CHECK_MSG(strstr(r.body, "\"endpoint\":\"127.0.0.1:51821\"") != NULL
	    && strstr(r.body, "\"endpoint\":\"192.0.2.2:51101\"") != NULL &&
	    strstr(r.body, "setfib 2 udp from me to 192.0.2.1 dst-port 14350 "
	    "out") != NULL, "%s", r.body);
	resp_free(&r);
	/*
	 * Two tunnels to the same edge: a far prefix's route goes over
	 * both at once, one multipath route (ECMP) the kernel shares the
	 * flows over, not kept in rc.conf; and BIRD merges the paths iBGP
	 * brings.
	 */
	r3_sdwan("plan", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG((strstr(r.body, "\"gateway\":\"100.64.0.0,100.64.0.2\"")
	    != NULL || strstr(r.body, "\"gateway\":\"100.64.0.2,100.64.0.0\"")
	    != NULL || strstr(r.body, "\"gateway\":\"100.64.0.1,100.64.0.3\"")
	    != NULL || strstr(r.body, "\"gateway\":\"100.64.0.3,100.64.0.1\"")
	    != NULL) && strstr(r.body, "\"to\":\"b\",\"local\":\"100.64.0.0\"")
	    != NULL && strstr(r.body, "\"to\":\"b\",\"local\":\"100.64.0.2\"")
	    != NULL, "%s", r.body);
	resp_free(&r);
	/* A relay toward no edge, or on an underlay that is not WireGuard,
	 * is refused. */
	ATF_REQUIRE(swap_in(doc, "\"to\":\"", "\"to\":\"x", t1, sizeof(t1)));
	r3_check(t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "to is one of the "
	    "edges") != NULL, "%s", r.body);
	resp_free(&r);
	/*
	 * A relay the apply makes, speederv2's: b's client listening where
	 * its wg peer points and sending to a's underlay at the relay's
	 * port; a's server there, handing it to a's wg port; each a
	 * profile of arcana_relay, started, taken away with the tunnel;
	 * the plugin is what the edges need.
	 */
	ATF_REQUIRE(swap_in(doc, "\"port\":14350}", "\"port\":14350,"
	    "\"plugin\":\"speederv2\",\"fec\":\"10:5\",\"mode\":0}", t1,
	    sizeof(t1)));
	ATF_REQUIRE(swap_in(t1, "\"version\":0", "\"version\":1", doc,
	    sizeof(doc)));
	r3_keep(doc);
	r3_sdwan("plan", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"relay:c_") != NULL &&
	    strstr(r.body, "\"key\":\"relay:s_") != NULL && strstr(r.body,
	    "\"role=client\",\"listen=127.0.0.1:51821\",\"remote=192.0.2.1:"
	    "14350\",\"fec=10:5\",\"mode=0\",\"report=10\",\"fifo=/var/run/"
	    "arcana_relay/c_") != NULL && strstr(r.body, "\"role=server\",\""
	    "listen=192.0.2.1:14350\",\"remote=127.0.0.1:51") != NULL &&
	    strstr(r.body, ".fifo\",\"svcj=yes\",\"svcj_ipaddrs=192.0.2.2,"
	    "127.0.0.1\"]") != NULL && strstr(r.body, ".fifo\",\"svcj=yes\","
	    "\"svcj_ipaddrs=192.0.2.1,127.0.0.1\"]") != NULL &&
	    strstr(r.body, "\"kind\":\"speeder\",\"verb\":\"remove\"") != NULL &&
	    strstr(r.body, "UDPspeeder, for the FEC relays") != NULL, "%s",
	    r.body);
	resp_free(&r);
	/* Another plugin, or ratios for a relay of the admin's own, are
	 * refused. */
	ATF_REQUIRE(swap_in(doc, "\"plugin\":\"speederv2\"", "\"plugin\":"
	    "\"udp2raw\"", t1, sizeof(t1)));
	r3_check(t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "plugin is speederv2")
	    != NULL, "%s", r.body);
	resp_free(&r);
	ATF_REQUIRE(swap_in(doc, "\"plugin\":\"speederv2\",", "", t1,
	    sizeof(t1)));
	r3_check(t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "fec is its plugin's")
	    != NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC(sdwan_host, "A host-as-subscriber edge (own_table): the service's "
    "overlay in the host's own table, its uplinks in tables of their own, "
    "its UNI left where it is; a host running its own BIRD takes no "
    "service's")
ATF_TC_BODY(sdwan_host, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16];
	char		doc[12288], t1[12288];
	size_t		i;
	static const char *const edits[][2] = {
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\"" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		/* b is the host-as-subscriber: its uplink in table 2. */
		{ "{\"server\":\"@B\",\"ucs_end_points\":[{\"id\":\"b-inet\","
		    "\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "{\"server\":\"@B\",\"own_table\":true,\"ucs_end_points\":[{"
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\",\"vrf\":2" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
		{ "\"id\":\"uni-hq\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-hq\",\"interface\":\"lo0\"" },
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\",\"host_addressed\":true" },
	};

	start(tc, 0, NULL);
	enrol(&a);
	r3_ab(sa, sb, sizeof(sa));
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* A host that runs its own BIRD cannot carry the service's (bfd). */
	ATF_REQUIRE(swap_in(doc, "\"own_table\":true", "\"own_table\":true,"
	    "\"host_bird\":true", t1, sizeof(t1)));
	r3_check(t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "runs its own BIRD") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	r3_keep(doc);
	/*
	 * On b: its tunnel end, its routes and its BIRD in the host's own
	 * table (0, no kernel table statement), its UNI not moved nor
	 * addressed (host_addressed), the uplinks' connected routes kept
	 * in the host's table too (allfibs); on a, as ever, table 1.
	 */
	r3_sdwan("plan", &r);
	EXPECT(&r, 200);
	/* a's tunnel and UNI device edits (4.5.5), bound to FIB 1's
	 * instance; b's tunnel a job still, its outer packets in a FIB of
	 * their own (tunnelfib, which a commit makes not yet). */
	ATF_CHECK_MSG(strstr(r.body, "{\"name\":\"gre100\",\"type\":"
	    "\"iana-if-type:tunnel\",\"description\":\"sdwan\",\"arcana-"
	    "interfaces:tunnel\":{\"local\":\"192.0.2.1\",\"remote\":"
	    "\"192.0.2.2\"},\"ietf-network-instance:bind-ni-name\":\"${ni:1}\"")
	    != NULL && strstr(r.body, "\"interface\":\"gre101\",\"fib\":0,") !=
	    NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "{\"name\":\"lo0\",\"ietf-network-"
	    "instance:bind-ni-name\":\"${ni:1}\",") != NULL && strstr(r.body,
	    "\"key\":\"uni:branch\",\"phase\":") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"allfibs\":true") != NULL && strstr(
	    r.body, "\"allfibs\":false") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"name\":\"sw1\",\"fib\":0,") != NULL &&
	    strstr(r.body, "\"name\":\"sw1\",\"fib\":1,") != NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC(sdwan_loop, "iBGP between the edges' loopbacks: a lo(4) per edge, "
    "a static to each far loopback over every tunnel with BFD on each path, "
    "one multihop session per edge, reflection on the edges carrying "
    "transit, the UNIs' prefixes as the edge's own statics, no far-prefix "
    "kernel statics")
ATF_TC_BODY(sdwan_loop, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16];
	char		doc[12288], t1[12288];
	const char	*p;
	size_t		i;
	int		n;
	static const char *const edits[][2] = {
		{ "\"bfd\":{\"interval\":200,\"multiplier\":3},",
		    "\"bfd\":{\"interval\":200,\"multiplier\":3},\"ibgp\":"
		    "\"loopback\"," },
		/* b carries no transit: it reflects nothing, breaks out for
		 * nobody. */
		{ "{\"server\":\"@B\",\"ucs_end_points\"",
		    "{\"server\":\"@B\",\"transit\":false,\"ucs_end_points\"" },
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\"" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\"" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
		{ "\"id\":\"uni-hq\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-hq\",\"interface\":\"lo0\"" },
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\"" },
	};

	start(tc, 0, NULL);
	enrol(&a);
	r3_ab(sa, sb, sizeof(sa));
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* Without BFD the loopbacks' routes go unwatched: refused. */
	ATF_REQUIRE(swap_in(doc, "\"bfd\":{\"interval\":200,\"multiplier\":3},",
	    "\"bfd\":null,", t1, sizeof(t1)));
	r3_check(t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "ibgp loopback needs "
	    "bfd") != NULL, "%s", r.body);
	resp_free(&r);
	r3_keep(doc);
	/*
	 * The plan: a loopback per edge after the tunnels' pairs (.0/31,
	 * .2/31), so a's is 100.64.0.4 and b's 100.64.0.6; a's BIRD has
	 * a static to b's loopback by the gre tunnel (b's inner .1), the
	 * backup geneve one (.3) in a lower static, a multihop session
	 * from loopback to loopback with rr client (a carries transit,
	 * b does not), the hq UNI's subnet and static route and the
	 * remote end point's prefix as its own statics kept out of the
	 * kernel; no kernel static for the far prefixes on b.
	 */
	r3_sdwan("plan", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"loop:acme\"") != NULL &&
	    strstr(r.body, "\"ip\":\"100.64.0.4\",\"prefix-length\":32") !=
	    NULL && strstr(r.body, "\"ip\":\"100.64.0.6\",\"prefix-length\":32")
	    != NULL, "%s", r.body);
	/* BIRD's forms (agent_test's sdwan_forms has their text). */
	ATF_CHECK_MSG(strstr(r.body, "\"loopback\":true,") != NULL && strstr(
	    r.body, "\"loop\":{\"local4\":\"100.64.0.4\",\"transit\":true,"
	    "\"edges\":[{\"name\":\"b\",\"ipv4\":\"100.64.0.6\",\"paths4\":"
	    "[\"100.64.0.1\"],\"backup4\":[\"100.64.0.3\"]}]") != NULL, "%s",
	    r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"loop\":{\"local4\":\"100.64.0.6\","
	    "\"edges\":[{\"name\":\"a\",\"ipv4\":\"100.64.0.4\",") != NULL,
	    "%s", r.body);
	for (n = 0, p = r.body; (p = strstr(p, "\"transit\":true")) != NULL; p++)
		n++;
	ATF_CHECK_MSG(n == 1, "transit %d times", n);
	ATF_CHECK_MSG(strstr(r.body, "\"multihop\":true,\"sessions\":true}") !=
	    NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"origins\":[{\"id\":\"hq\",\"interface\":"
	    "\"lo0\",\"ipv4\":[{\"prefix\":\"10.1.0.0/24\"},{\"prefix\":"
	    "\"10.1.8.0/22\",\"next_hop\":\"10.1.0.2\"}]},{\"id\":\"road\","
	    "\"interface\":\"wg5\",\"ipv4\":[{\"prefix\":\"10.30.0.0/24\"}]}]")
	    != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"route:acme:10.1.0.0/24\"") == NULL &&
	    strstr(r.body, "\"key\":\"route:acme:10.30.0.0/24\"") == NULL, "%s",
	    r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"direct\":[\"lo0\",\"gre100\","
	    "\"geneve102\",\"lo1") != NULL, "%s", r.body);
	resp_free(&r);
}

/* Hosts a and b on the stand-in agent, b by another spelling of its
 * socket: their ids into sa and sb. */
static void
r4_hosts(char *sa, char *sb, size_t len)
{
	char	cwd[MAXPATHLEN], uri[MAXPATHLEN + 64];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(uri, sizeof(uri), "unix:%s/jgd.sock", cwd);
	host_add("a", uri, sa, len);
	snprintf(uri, sizeof(uri), "unix:%s/./jgd.sock", cwd);
	host_add("b", uri, sb, len);
}

/* doc kept as arcana-console's sdwan/document; the answer in r. */
static void
r4_keep(const char *doc, struct resp *r)
{
	char	*body;

	ATF_REQUIRE(asprintf(&body, "{\"arcana-console:document\":%s}", doc) !=
	    -1);
	http("PUT", CC "sdwan/document", body, r);
	free(body);
}

/* GET of arcana-console's sdwan/<node> (a query after it as it goes);
 * on 200 r's JSON the node's document. */
static void
r4_read(const char *node, struct resp *r)
{
	char	path[256], key[96];

	snprintf(path, sizeof(path), CC "sdwan/%s", node);
	http("GET", path, NULL, r);
	snprintf(key, sizeof(key), "arcana-console:%.*s",
	    (int)strcspn(node, "?"), node);
	if (r->status == 200)
		(void)resp_unwrap(r, key);
}

/* doc checked by arcana-console's sdwan/check; on 200 r's JSON the
 * result. */
static void
r4_check(const char *doc, struct resp *r)
{
	char	*body;

	ATF_REQUIRE(asprintf(&body, "{\"arcana-console:input\":{\"document\":"
	    "%s}}", doc) != -1);
	rc_act(CC "sdwan/check", body, r);
	free(body);
}

/*
 * vn-compute (PLAN-SDN-YANG 4.7.3, RFC 9731 4.3.1): each member asked
 * for checked against the VN view, the plan's tunnels and what the
 * edges measure; the infeasible ones down with error-info.
 */
#define	VNC	"/restconf/operations/ietf-vn:vn-compute"
#define	VNC_M(id, s, d, pc) "{\"id\":\"" id "\",\"src\":{\"ap\":\"%s" s	\
	"\"},\"dest\":{\"ap\":\"%s" d "\"}" pc "}"
#define	VNC_PC(m, v) ",\"path-constraints\":{\"path-metric-bounds\":{"	\
	"\"path-metric-bound\":[{\"metric-type\":\"" m "\",\"upper-bound\":" \
	"\"" v "\"}]}}"

CONSOLE_TC(l3nm_vn_compute, "vn-compute: a member the plan's tunnels "
    "carry up, an unmeasured bound unknown, the infeasible down with "
    "error-info")
ATF_TC_BODY(l3nm_vn_compute, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[2048], sa[16], sb[16], p[64], ver[16];
	char		doc[12288], t1[12288];
	size_t		i;
	static const char *const edits[][2] = {
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\"" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\"" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
	};
	static const struct {
		const char	*status;
		const char	*reason;	/* NULL: no error-info */
	} want[] = {
		{ "up", NULL },
		{ "unknown", NULL },
		{ "down", "ietf-vn:vn-computation-error-no-resource" },
		{ "down", "ietf-vn:vn-computation-ap-unknown" },
		{ "down", "ietf-vn:vn-computation-error-path-not-found" },
	};

	start(tc, 0, NULL);
	enrol(&a);
	r4_hosts(sa, sb, sizeof(sa));
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	r4_keep(doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	r4_read("document", &r);
	EXPECT(&r, 200);
	snprintf(ver, sizeof(ver), "%s", jstr(&r, "version"));
	resp_free(&r);
	http("GET", "/restconf/operations", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, "\"ietf-vn:vn-compute\"") != NULL);
	resp_free(&r);
	http("POST", VNC, "{\"vn-member-list\":[]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* A member list that is an object: refused, its keys not taken
	 * for entries (as many as an array's size, none, would have room). */
	http("POST", VNC, "{\"ietf-vn:input\":{\"vn-member-list\":{"
	    "\"a\":{\"id\":1},\"b\":{\"id\":2},\"c\":{\"id\":3},\"d\":"
	    "{\"id\":4}}}}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "is a list") != NULL,
	    "%d %s", r.status, r.body);
	resp_free(&r);
	/* hq to branch: up; bounded by delay, which nothing has measured:
	 * unknown; by a TE metric no edge measures; from no AP; between
	 * two accesses of one node. */
	snprintf(body, sizeof(body), "{\"ietf-vn:input\":{\"vn-member-list\":["
	    VNC_M("1", ":vtnet2", ":vtnet2", "") ","
	    VNC_M("2", ":vtnet2", ":vtnet2", VNC_PC("ietf-te-types:"
	    "path-metric-delay-average", "30000")) ","
	    VNC_M("3", ":vtnet2", ":vtnet2", VNC_PC("ietf-te-types:"
	    "path-metric-te", "10")) ","
	    VNC_M("4", ":nope", ":vtnet2", "") ","
	    VNC_M("5", ":vtnet2", ":wg5", "") "]}}",
	    sa, sb, sa, sb, sa, sb, sa, sb, sa, sa);
	http("POST", VNC, body, &r);
	EXPECT(&r, 200);
	for (i = 0; i < nitems(want); i++) {
		snprintf(p, sizeof(p), "ietf-vn:output.vn-member-list.%zu.id",
		    i);
		ATF_CHECK_MSG(jstr(&r, p) != NULL && (size_t)atoi(jstr(&r, p))
		    == i + 1, "%s", r.body);
		snprintf(p, sizeof(p), "ietf-vn:output.vn-member-list.%zu."
		    "compute-status", i);
		ATF_CHECK_STREQ_MSG(want[i].status, jstr(&r, p), "%zu: %s",
		    i + 1, r.body);
		snprintf(p, sizeof(p), "ietf-vn:output.vn-member-list.%zu."
		    "error-info.error-reason", i);
		if (want[i].reason == NULL)
			ATF_CHECK(jstr(&r, p) == NULL);
		else
			ATF_CHECK_STREQ_MSG(want[i].reason, jstr(&r, p),
			    "%zu: %s", i + 1, r.body);
		snprintf(p, sizeof(p), "ietf-vn:output.vn-member-list.%zu."
		    "error-info.error-description", i);
		ATF_CHECK(want[i].reason == NULL || jstr(&r, p) != NULL);
	}
	ATF_CHECK_STREQ("acme:hq", jstr(&r, "ietf-vn:output.vn-member-list.0."
	    "src.vn-ap-id"));
	resp_free(&r);
	/* Nothing made: the L3NM as it was. */
	r4_read("document", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(ver, jstr(&r, "version"));
	resp_free(&r);
}

/* Member i of r's vn-compute output: its status, reason (NULL: no
 * error-info), and whether it says why. */
static void
vnc_want(struct resp *r, size_t i, const char *status, const char *reason,
    bool said)
{
	char	p[96];

	snprintf(p, sizeof(p), "ietf-vn:output.vn-member-list.%zu."
	    "compute-status", i);
	ATF_CHECK_STREQ_MSG(status, jstr(r, p), "%zu: %s", i, r->body);
	snprintf(p, sizeof(p), "ietf-vn:output.vn-member-list.%zu."
	    "error-info.error-reason", i);
	if (reason == NULL)
		ATF_CHECK_MSG(jstr(r, p) == NULL, "%zu: %s", i, r->body);
	else
		ATF_CHECK_STREQ_MSG(reason, jstr(r, p), "%zu: %s", i, r->body);
	snprintf(p, sizeof(p), "ietf-vn:output.vn-member-list.%zu."
	    "error-info.error-description", i);
	ATF_CHECK_MSG((jstr(r, p) != NULL) == said, "%zu: %s", i, r->body);
}

CONSOLE_TC(l3nm_vn_compute_asks, "vn-compute weighs the rest: te-bandwidth "
    "against the uplinks, cos against the service's importance levels, "
    "disjointness by UCS End Point and UCS, an optimization Arcana does "
    "not compute unknown and said")
ATF_TC_BODY(l3nm_vn_compute_asks, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[4096], sa[16], sb[16];
	char		doc[12288], t1[12288];
	size_t		i;
	static const char *const edits[][2] = {
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\",\"bandwidth\":4000000" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\",\"bandwidth\":3000000" },
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\",\"bandwidth\":4000000" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\",\"bandwidth\":3000000" },
	};
#define	VNC_BW(v)	",\"path-constraints\":{\"te-bandwidth\":{"	\
	"\"generic\":\"" v "\"}}"
#define	VNC_OPT(m)	",\"optimizations\":{"				\
	"\"optimization-metric\":[{\"metric-type\":\"ietf-te-types:" m	\
	"\",\"weight\":1}]}"

	start(tc, 0, NULL);
	enrol(&a);
	r4_hosts(sa, sb, sizeof(sa));
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	r4_keep(doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);

	/*
	 * Each edge's uplinks 7 Mbit/s, 1 Mbit/s committed: 1 Mbit/s
	 * (125000 bytes/s) up; 8 Mbit/s (a float32's) more than any UCS
	 * End Point carries, down; class-types 1 and 5 of two levels;
	 * its own paths link- and SRLG-disjoint over inet and mpls; an
	 * optimization by TE metric unknown, said; by delay, up.
	 */
	snprintf(body, sizeof(body), "{\"ietf-vn:input\":{\"vn-member-list\":["
	    VNC_M("1", ":vtnet2", ":vtnet2", VNC_BW("125000")) ","
	    VNC_M("2", ":vtnet2", ":vtnet2", VNC_BW("0x1.e848p+19")) ","
	    VNC_M("3", ":vtnet2", ":vtnet2", ",\"cos\":1") ","
	    VNC_M("4", ":vtnet2", ":vtnet2", ",\"cos\":5") ","
	    VNC_M("5", ":vtnet2", ":vtnet2", ",\"path-constraints\":{"
	    "\"disjointness\":\"link srlg\"}") ","
	    VNC_M("6", ":vtnet2", ":vtnet2", VNC_OPT("path-metric-te")) ","
	    VNC_M("7", ":vtnet2", ":vtnet2",
	    VNC_OPT("path-metric-delay-average")) "]}}",
	    sa, sb, sa, sb, sa, sb, sa, sb, sa, sb, sa, sb, sa, sb);
	http("POST", VNC, body, &r);
	EXPECT(&r, 200);
	vnc_want(&r, 0, "up", NULL, false);
	vnc_want(&r, 1, "down", "ietf-vn:vn-computation-error-no-resource",
	    true);
	ATF_CHECK_MSG(strstr(r.body, "carries 4000000 bit/s") != NULL, "%s",
	    r.body);
	vnc_want(&r, 2, "up", NULL, false);
	vnc_want(&r, 3, "down", "ietf-vn:vn-computation-error-no-resource",
	    true);
	vnc_want(&r, 4, "up", NULL, false);
	vnc_want(&r, 5, "unknown", NULL, true);
	vnc_want(&r, 6, "up", NULL, false);
	resp_free(&r);
	/* Bad: a bandwidth not one, a class out of range, a bit unknown. */
	snprintf(body, sizeof(body), "{\"ietf-vn:input\":{\"vn-member-list\":["
	    VNC_M("1", ":vtnet2", ":vtnet2", VNC_BW("lots")) "]}}", sa, sb);
	http("POST", VNC, body, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"ietf-vn:input\":{\"cos\":8,"
	    "\"vn-member-list\":[" VNC_M("1", ":vtnet2", ":vtnet2", "") "]}}",
	    sa, sb);
	http("POST", VNC, body, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"ietf-vn:input\":{"
	    "\"vn-level-diversity\":\"path\",\"vn-member-list\":["
	    VNC_M("1", ":vtnet2", ":vtnet2", "") "]}}", sa, sb);
	http("POST", VNC, body, &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/* Two members kept SRLG-apart: one over inet, one over mpls. */
#define	VNC_TWO	"{\"ietf-vn:input\":{\"vn-level-diversity\":\"srlg\","	\
	"\"vn-member-list\":[" VNC_M("a", ":vtnet2", ":vtnet2", "") ","	\
	VNC_M("b", ":vtnet2", ":vtnet2", "") "]}}"
	snprintf(body, sizeof(body), VNC_TWO, sa, sb, sa, sb);
	http("POST", VNC, body, &r);
	EXPECT(&r, 200);
	vnc_want(&r, 0, "up", NULL, false);
	vnc_want(&r, 1, "up", NULL, false);
	resp_free(&r);
	/* The service over inet alone: both share it, down. */
	ATF_REQUIRE(swap_in(doc, "\"ucs\":[\"inet\",\"mpls\"]",
	    "\"ucs\":[\"inet\"]", t1, sizeof(t1)));
	ATF_REQUIRE(swap_in(t1, "\"version\":0", "\"version\":1", doc,
	    sizeof(doc)));
	r4_keep(doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	snprintf(body, sizeof(body), VNC_TWO, sa, sb, sa, sb);
	http("POST", VNC, body, &r);
	EXPECT(&r, 200);
	vnc_want(&r, 0, "down", "ietf-vn:vn-computation-error-no-resource",
	    true);
	vnc_want(&r, 1, "down", "ietf-vn:vn-computation-error-no-resource",
	    true);
	ATF_CHECK_MSG(strstr(r.body, "both over UCS inet") != NULL, "%s",
	    r.body);
	resp_free(&r);
#undef	VNC_BW
#undef	VNC_OPT
#undef	VNC_TWO
}

CONSOLE_TC(l3nm_plan, "The planner reads the L3NM (PLAN-SDN-YANG 4.5.4): "
    "a node's active profile over the service's (its AS, router id and "
    "an RD it asks to be allocated), a service naming no table given "
    "one from the ledger, the same plan after plan")
ATF_TC_BODY(l3nm_plan, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[1024], sa[16], sb[16], want[200];
	char		doc[12288], t1[12288], fib[16], *first;
	size_t		i;
	static const char *const edits[][2] = {
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\"" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\"" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
	};

	start(tc, 0, NULL);
	enrol(&a);
	r4_hosts(sa, sb, sizeof(sa));
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	r4_keep(doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	/* The service's table on each node, its tables named by it. */
	r4_read("ledger", &r);
	EXPECT(&r, 200);
	snprintf(want, sizeof(want), "\"acme/%s\":1", sa);
	ATF_CHECK_MSG(strstr(r.body, want) != NULL && strstr(r.body,
	    "\"tables\":{\"acme\":\"sw1\"}") != NULL, "%s", r.body);
	resp_free(&r);
	/* Node a's active profile: its own AS and router id, an RD
	 * allocated; node b keeps the service's. */
	snprintf(t1, sizeof(t1), L3NM "/vpn-services/vpn-service=acme/"
	    "vpn-nodes/vpn-node=%s", sa);
	snprintf(body, sizeof(body), "{\"ietf-l3vpn-ntw:vpn-node\":[{"
	    "\"vpn-node-id\":\"%s\",\"active-vpn-instance-profiles\":{"
	    "\"vpn-instance-profile\":[{\"profile-id\":\"subscriber\","
	    "\"local-as\":65010,\"router-id\":[{\"address-family\":"
	    "\"ietf-vpn-common:ipv4\",\"router-id\":\"10.255.0.1\"}],"
	    "\"rd-auto\":{\"auto\":[null]}}]}}]}", sa);
	http("PATCH", t1, body, &r);
	ATF_REQUIRE_MSG(r.status == 204, "%d %s", r.status, r.body);
	resp_free(&r);
	r4_read("plan", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"as\":65010,\"router_id\":\"10.255.0.1\"")
	    != NULL && strstr(r.body, "\"as\":64600,\"router_id\":") != NULL,
	    "%s", r.body);
	first = strdup(r.body);
	resp_free(&r);
	r4_read("ledger", &r);
	EXPECT(&r, 200);
	snprintf(want, sizeof(want), "\"rds\":{\"acme/%s\":\"0:65010:1\"}", sa);
	ATF_CHECK_MSG(strstr(r.body, want) != NULL, "%s", r.body);
	resp_free(&r);
	/* The same again: nothing moves between plans. */
	r4_read("plan", &r);
	ATF_CHECK_STREQ(first, r.body);
	resp_free(&r);
	free(first);
	/* A service naming no table: the lowest no other has. */
	http("DELETE", L3NM "/vpn-services/vpn-service=acme/"
	    "arcana-l3nm:sdwan/fib", NULL, &r);
	resp_free(&r);
	http("DELETE", L3NM "/vpn-services/vpn-service=acme/"
	    "vpn-instance-profiles/vpn-instance-profile=subscriber/"
	    "arcana-l3nm:fib", NULL, &r);
	resp_free(&r);
	r4_read("ledger", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_MSG(jstr(&r, "fibs.acme") != NULL, "%s", r.body);
	snprintf(fib, sizeof(fib), "%s", jstr(&r, "fibs.acme"));
	snprintf(want, sizeof(want), "\"tables\":{\"acme\":\"sw%s\"}", fib);
	ATF_CHECK_MSG(strcmp(fib, "1") == 0 && strstr(r.body, want) != NULL,
	    "%s", r.body);
	resp_free(&r);
	r4_read("plan", &r);
	EXPECT(&r, 200);
	snprintf(want, sizeof(want), "\"swvc\":\"acme\",\"fib\":%s,", fib);
	ATF_CHECK_MSG(strstr(r.body, want) != NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC(sdwan_infeasible, "The infeasible refused (PLAN-SDN-YANG 4.5.6): "
    "an edge whose policies commit more bandwidth than its uplinks carry "
    "is not planned, the reason and the commit that would fit said; one "
    "with room is")
ATF_TC_BODY(sdwan_infeasible, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16];
	char		doc[12288], t1[12288];
	size_t		i;
	static const char *const edits[][2] = {
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\",\"bandwidth\":400000" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\",\"bandwidth\":300000" },
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\"" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
	};

	start(tc, 0, NULL);
	enrol(&a);
	r4_hosts(sa, sb, sizeof(sa));
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	r4_keep(doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	/* a carries 700 kbit/s, its policies commit 1 Mbit/s (shared):
	 * refused, with the commit that fits; nothing to apply. */
	r4_read("plan", &r);
	EXPECT(&r, 409);
	ATF_CHECK_MSG(strstr(r.body, "infeasible: edge a's policies commit "
	    "1000000 bit/s, more than its uplinks carry, 700000 bit/s: it "
	    "fits with the commit of rate limiter shared of service acme at "
	    "700000 bit/s or less") != NULL, "%s", r.body);
	resp_free(&r);
	http("POST", CC "sdwan/apply", "{\"arcana-console:input\":{}}", &r);
	ATF_CHECK_MSG(r.status == 409 && strstr(r.body, "infeasible") != NULL,
	    "%d %s", r.status, r.body);
	resp_free(&r);
	/* An uplink with room: planned. */
	ATF_REQUIRE(swap_in(doc, "\"bandwidth\":400000", "\"bandwidth\":"
	    "10000000", t1, sizeof(t1)));
	ATF_REQUIRE(swap_in(t1, "\"version\":0", "\"version\":1", doc,
	    sizeof(doc)));
	r4_keep(doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	r4_read("plan", &r);
	EXPECT(&r, 200);
	resp_free(&r);
}

CONSOLE_TC(sdwan_breakout, "Breakout failover: an edge with several breakout "
    "uplinks has a route to each one's gateway, the default by the most "
    "preferred, a probe to each one's beacon, and the agent told to put "
    "the first that answers in the default's place")
ATF_TC_BODY(sdwan_breakout, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16];
	char		doc[12288], t1[12288];
	size_t		i;
	static const char *const edits[][2] = {
		/* A second Internet Access, WireGuard, breaking out too, less
		 * preferred, with a beacon of its own. */
		{ "\"tunnel\":{\"kind\":\"gre\",\"ipsec\":true}}",
		    "\"tunnel\":{\"kind\":\"gre\",\"ipsec\":true}},{\"id\":\"wgnet\","
		    "\"type\":\"public\",\"billing\":\"flat-rate\",\"tunnel\":{"
		    "\"kind\":\"wg\"}}" },
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"breakout\":true",
		    "\"id\":\"a-wg\",\"ucs\":\"wgnet\",\"interface\":\"vtnet3\","
		    "\"address\":\"203.0.113.1\",\"gateway\":\"203.0.113.254\","
		    "\"beacon\":\"198.51.100.1\",\"breakout\":true,\"preference\":5},"
		    "{\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\",\"gateway\":\"192.0.2.254\","
		    "\"breakout\":true,\"preference\":10" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\"" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
		{ "\"ucs\":[\"inet\",\"mpls\"]", "\"ucs\":[\"inet\",\"wgnet\","
		    "\"mpls\"]" },
		{ "\"id\":\"uni-hq\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-hq\",\"interface\":\"lo0\"" },
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\"" },
	};

	start(tc, 0, NULL);
	enrol(&a);
	r4_hosts(sa, sb, sizeof(sa));
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* A beacon that is no address is refused. */
	ATF_REQUIRE(swap_in(doc, "\"beacon\":\"198.51.100.1\"",
	    "\"beacon\":\"nowhere\"", t1, sizeof(t1)));
	r4_check(t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "its beacon is an "
	    "address") != NULL, "%s", r.body);
	resp_free(&r);
	r4_keep(doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	/*
	 * In the breakout table (2): each gateway by its interface, the
	 * default by the preferred (inet, 10, over wg, 5), the wg one's
	 * beacon by its gateway; a probe to each beacon; the steering's
	 * route with both candidates in that order.
	 */
	r4_read("plan", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"route:acme:2:192.0.2.254/32\"") !=
	    NULL && strstr(r.body, "\"key\":\"route:acme:2:203.0.113.254/32\"") !=
	    NULL && strstr(r.body, "\"key\":\"route:acme:2:198.51.100.1/32\"") != NULL,
	    "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"destination-prefix\":\"0.0.0.0/0\","
	    "\"next-hop\":{\"next-hop-address\":\"192.0.2.254\"}") != NULL &&
	    strstr(r.body, "\"destination-prefix\":\"0.0.0.0/0\",\"next-hop\":{"
	    "\"next-hop-address\":\"203.0.113.254\"}") == NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"id\":\"bo:a-inet\",\"address\":"
	    "\"192.0.2.254\",\"fib\":2") != NULL && strstr(r.body, "\"id\":"
	    "\"bo:a-wg\",\"address\":\"198.51.100.1\",\"fib\":2") != NULL, "%s",
	    r.body);
	/* A beacon is no Arcana host: pinged alone (arcana-probe's kind). */
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"icmp\"}") != NULL, "%s",
	    r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"routes\":[{\"fib\":2,\"destination\":"
	    "\"0.0.0.0/0\",\"candidates\":[{\"id\":\"bo:a-inet\",\"via\":"
	    "\"192.0.2.254\"},{\"id\":\"bo:a-wg\",\"via\":\"203.0.113.254\"}]}]")
	    != NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC(sdwan_nat64, "NAT64 at one edge (nat64lsn, its pool among the "
    "known prefixes, the way in before the zones, the way back after the "
    "NAT) and CLAT at a UNI (nat64clat), ipfw_nat64 kept; checked")
ATF_TC_BODY(sdwan_nat64, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16];
	char		doc[12288], t1[12288];
	size_t		i;
	static const char *const edits[][2] = {
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\",\"gateway\":\"192.0.2.254\"" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\"" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
		{ "\"reserved_prefixes\":[\"100.64.0.0/24\"],",
		    "\"reserved_prefixes\":[\"100.64.0.0/24\"],\"nat64\":{\"prefix\":"
		    "\"64:ff9b::/96\",\"pool\":\"192.0.2.64/26\",\"edge\":\"@A\"}," },
		{ "\"id\":\"uni-hq\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-hq\",\"interface\":\"lo0\",\"clat\":{\"prefix\":"
		    "\"2001:db8:c::/96\"}" },
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\"" },
	};

	start(tc, 0, NULL);
	enrol(&a);
	r4_hosts(sa, sb, sizeof(sa));
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* A prefix that is no /96, an edge that is none, a CLAT without
	 * the service's NAT64: refused. */
	ATF_REQUIRE(swap_in(doc, "\"prefix\":\"64:ff9b::/96\"", "\"prefix\":"
	    "\"64:ff9b::/64\"", t1, sizeof(t1)));
	r4_check(t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "nat64 is an object") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	ATF_REQUIRE(swap_in(doc, "\"edge\":\"", "\"edge\":\"nosuch", t1,
	    sizeof(t1)));
	r4_check(t1, &r);
	ATF_CHECK_MSG(r.status == 400 && (strstr(r.body, "nat64: edge is one of "
	    "the edges") != NULL || strstr(r.body, "no such") != NULL), "%s",
	    r.body);
	resp_free(&r);
	ATF_REQUIRE(swap_in(doc, "\"nat64\":{\"prefix\":\"64:ff9b::/96\",\"pool\":"
	    "\"192.0.2.64/26\",\"edge\":\"", "\"nat64x\":{\"prefix\":\"64:ff9b::/96\","
	    "\"pool\":\"192.0.2.64/26\",\"edge\":\"", t1, sizeof(t1)));
	r4_check(t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "clat needs the "
	    "service's nat64") != NULL, "%s", r.body);
	resp_free(&r);
	r4_keep(doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	/*
	 * On a: the nat64lsn instance, the pool in the known table, the
	 * IPv6 way in before the zones (rule 100), the pool's way back
	 * after the NAT (11), the CLAT of hq with the NAT64 prefix as
	 * its PLAT, and ipfw_nat64 kept.
	 */
	r4_read("plan", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"nat64lsn sw1_64 create prefix4 "
	    "192.0.2.64/26 prefix6 64:ff9b::/96 allow_private\"") != NULL,
	    "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "[\"192.0.2.64/26\",\"0\"]") != NULL, "%s",
	    r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"10 nat64lsn sw1_64 ip6 from "
	    "table(sw1_known) to 64:ff9b::/96 in\"") != NULL && strstr(r.body,
	    "\"11 nat64lsn sw1_64 ip4 from any to 192.0.2.64/26 in recv "
	    "vtnet0\"") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"nat64clat sw1_chq create clat_prefix "
	    "2001:db8:c::/96 plat_prefix 64:ff9b::/96\"") != NULL && strstr(
	    r.body, "\"10 nat64clat sw1_chq ip4 from any to not table(sw1_known) "
	    "in recv lo0\"") != NULL && strstr(r.body, "\"10 nat64clat sw1_chq "
	    "ip6 from any to 2001:db8:c::/96 in\"") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"nat64\"") != NULL && strstr(
	    r.body, "\"args\":[\"ipfw_nat64\"]") != NULL, "%s", r.body);
	/* The CLAT prefix is hq's, routed to a from b like its subnet. */
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"route:acme:2001:db8:c::/96\"") !=
	    NULL || strstr(r.body, "carries 2001:db8:c::/96") != NULL, "%s",
	    r.body);
	resp_free(&r);
}

CONSOLE_TC(sdwan_sets, "Destination sets by BGP attribute: a service's sets "
    "(AS path, communities), an edge's breakout for each by one of its "
    "uplinks, written as BIRD's filter to the kernel with that gateway, the "
    "gateway routed by its interface in the service's table; bgp_import "
    "sets keeps every other BGP route out of the kernel; checked")
ATF_TC_BODY(sdwan_sets, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16];
	char		doc[12288], t1[12288];
	size_t		i;
	static const char *const edits[][2] = {
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\",\"gateway\":\"192.0.2.254\"" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\"" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
		/* The country's routes, by their AS path or a community, go
		 * out by a-inet on a; nothing else of BGP's reaches its
		 * kernel. */
		{ "{\"server\":\"@A\",\"ntp\"",
		    "{\"server\":\"@A\",\"breakout_sets\":[{\"set\":\"country\","
		    "\"via\":\"a-inet\"}],\"bgp_import\":\"sets\",\"ntp\"" },
		{ "\"reserved_prefixes\":[\"100.64.0.0/24\"],",
		    "\"reserved_prefixes\":[\"100.64.0.0/24\"],\"bgp_sets\":[{"
		    "\"name\":\"country\",\"as_path\":[64600,64601],\"communities\":"
		    "[[64600,100]]}]," },
		{ "\"id\":\"uni-hq\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-hq\",\"interface\":\"lo0\"" },
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\"" },
	};

	start(tc, 0, NULL);
	enrol(&a);
	r4_hosts(sa, sb, sizeof(sa));
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* A set that is none, an uplink that is no breakout of the edge:
	 * refused. */
	ATF_REQUIRE(swap_in(doc, "\"set\":\"country\"", "\"set\":\"nowhere\"", t1,
	    sizeof(t1)));
	r4_check(t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "nowhere is no bgp_sets "
	    "name") != NULL, "%s", r.body);
	resp_free(&r);
	ATF_REQUIRE(swap_in(doc, "\"via\":\"a-inet\"", "\"via\":\"a-mpls\"", t1,
	    sizeof(t1)));
	r4_check(t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "no breakout UCS end "
	    "point of this edge") != NULL, "%s", r.body);
	resp_free(&r);
	r4_keep(doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	/* a's BIRD: the filters, the gateway rewritten, the rest of BGP
	 * kept out; the gateway's route in the service's table; b's
	 * BIRD as ever. */
	r4_read("plan", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"sets\":{\"only\":true,\"sets\":[{"
	    "\"name\":\"country\",\"via\":\"a-inet\",\"gateway\":"
	    "\"192.0.2.254\",\"as_path\":[64600,64601],\"communities\":[[64600,"
	    "100]]}]}") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"host\":\"b\",\"spec\":{\"service\":"
	    "\"acme\",\"fib\":1,\"table\":1,\"as\":64600,\"router_id\":"
	    "\"100.64.0.1\",\"direct\":[\"vlan104\",\"gre101\",\"geneve103\"],"
	    "\"bfd\"") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"path\":\"ietf-network-instance:network-"
	    "instances/network-instance=${ni:1}/vrf-root/ietf-routing:routing\","
	    "\"body\":{\"ietf-routing:routing\":{\"control-plane-protocols\":{"
	    "\"control-plane-protocol\":[{\"type\":\"ietf-routing:static\","
	    "\"name\":\"rc.conf\",\"static-routes\":{\"ietf-ipv4-unicast-"
	    "routing:ipv4\":{\"route\":[{\"destination-prefix\":"
	    "\"192.0.2.254/32\",\"next-hop\":{\"outgoing-interface\":"
	    "\"vtnet0\"}}]}}}]}}}") != NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC(sdwan_neigh, "Routing neighbours at a UNI: several BGP entries, "
    "one of the service's own AS from a source address, multihop, with BFD "
    "(iBGP, next hop self); OSPF an area per family with BFD; BFD on the "
    "UNI's interface too, and multihop; checked")
ATF_TC_BODY(sdwan_neigh, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16];
	char		doc[12288], t1[12288];
	size_t		i;
	static const char *const edits[][2] = {
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\"" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\"" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
		{ "\"id\":\"uni-hq\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-hq\",\"interface\":\"lo0\"" },
		/* hq: the subscriber's eBGP neighbour watched by BFD, and an
		 * iBGP one of the service's AS from the provider address,
		 * multihop. */
		{ "\"bgp\":{\"family\":\"ipv4\",\"as\":65010,\"neighbors\":"
		    "[\"10.1.0.2\"],\"password\":\"s3cret\",\"hold_time\":90,"
		    "\"distance\":150,\"communities\":[[64600,100]]}",
		    "\"bgp\":[{\"family\":\"ipv4\",\"as\":65010,\"neighbors\":"
		    "[\"10.1.0.2\"],\"password\":\"s3cret\",\"hold_time\":90,"
		    "\"distance\":150,\"communities\":[[64600,100]],\"bfd\":true},"
		    "{\"family\":\"ipv4\",\"as\":64600,\"neighbors\":[\"10.1.0.3\"],"
		    "\"source\":\"10.1.0.1\",\"multihop\":true,\"bfd\":true}]" },
		/* branch: OSPFv3 in the backbone with BFD, OSPFv2 in area 1. */
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\"" },
		{ "\"dns\":[\"2001:db8:1::1\"]}}}",
		    "\"dns\":[\"2001:db8:1::1\"]},\"ospf\":[{\"family\":\"ipv6\","
		    "\"area\":0,\"cost\":50,\"bfd\":true},{\"family\":\"ipv4\","
		    "\"area\":1}]}}" },
	};

	start(tc, 0, NULL);
	enrol(&a);
	r4_hosts(sa, sb, sizeof(sa));
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* A source that is no address is refused. */
	ATF_REQUIRE(swap_in(doc, "\"source\":\"10.1.0.1\"", "\"source\":"
	    "\"nowhere\"", t1, sizeof(t1)));
	r4_check(t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "bgp: source is an "
	    "address") != NULL, "%s", r.body);
	resp_free(&r);
	r4_keep(doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	r4_read("plan", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"unis\":[{\"id\":\"uni-hq\",\"end_point\":"
	    "\"hq\",\"interface\":\"lo0\",\"bgp\":[{\"family\":\"ipv4\",\"as\":"
	    "65010,\"neighbors\":[\"10.1.0.2\"],") != NULL && strstr(r.body,
	    "{\"family\":\"ipv4\",\"as\":64600,\"neighbors\":[\"10.1.0.3\"],"
	    "\"source\":\"10.1.0.1\",\"multihop\":true,\"bfd\":true}") != NULL,
	    "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"bfd\":{\"interfaces\":[\"gre100\","
	    "\"geneve102\",\"lo0\"],\"interval\":200,\"multiplier\":3,"
	    "\"multihop\":true,") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "{\"id\":\"uni-br\",\"end_point\":"
	    "\"branch\",\"interface\":\"vlan104\",\"ospf\":[{\"family\":"
	    "\"ipv6\",\"area\":0,\"cost\":50,\"bfd\":true},{\"family\":"
	    "\"ipv4\",\"area\":1}]}") != NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC(sdwan_lists, "SD-WAN's named lists: prefixes, services, UCS, "
    "edges and UCS End Points kept once, each named where a value would "
    "be, checked; a prefix list an ipfw table, a service list the AFS's "
    "protocols and ports, a zone's its prefixes, a policy's the ways it "
    "takes in order of preference")
ATF_TC_BODY(sdwan_lists, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16];
	char		doc[12288], t1[12288], bad[12288];
	size_t		i;
	static const char *const edits[][2] = {
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\",\"gateway\":\"192.0.2.254\"" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\"" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
		{ "\"id\":\"uni-hq\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-hq\",\"interface\":\"lo0\"" },
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\"" },
		{ "\"kind\":\"geneve\"", "\"kind\":\"gif\"" },
		/* TCP's MSS clamped on the Internet's tunnels: auto. */
		{ "\"tunnel\":{\"kind\":\"gre\",\"ipsec\":true}", "\"tunnel\":{"
		    "\"kind\":\"gre\",\"ipsec\":true,\"mss\":\"auto\"}" },
		/* The lists, and where each is named. */
		{ "\"swvcs\":[", "\"lists\":[{\"name\":\"branches\",\"kind\":"
		    "\"prefixes\",\"items\":[\"10.1.8.0/22\",\"2001:db8:9::/48\"]},"
		    "{\"name\":\"webports\",\"kind\":\"services\",\"protocols\":"
		    "[\"tcp\"],\"ports\":[8443,\"https\"]},{\"name\":\"dc\","
		    "\"kind\":\"prefixes\",\"items\":[\"10.7.0.0/16\"]},{\"name\":"
		    "\"prefer-mpls\",\"kind\":\"ucs-end-points\",\"items\":[{\"id\":"
		    "\"b-inet\",\"preference\":200},\"a-inet\",\"a-mpls\","
		    "\"b-mpls\"]},{\"name\":\"wan\",\"kind\":\"ucs\",\"items\":"
		    "[\"inet\",\"mpls\"]},{\"name\":\"sites\",\"kind\":\"edges\","
		    "\"items\":[\"@A\",\"@B\"]}],\"swvcs\":[" },
		{ "\"flows\":[", "\"flows\":[{\"name\":\"branchweb\",\"criteria\":"
		    "{\"src-list\":\"branches\",\"service-list\":\"webports\"}}," },
		{ "\"prefixes\":[\"10.1.0.0/16\"]", "\"prefixes\":[\"10.1.0.0/16\"],"
		    "\"prefix-list\":\"dc\"" },
		{ "\"af-security-ingress\":\"guard\"", "\"af-security-ingress\":"
		    "\"guard\",\"ucs-list\":\"wan\",\"edge-list\":\"sites\","
		    "\"ucs-end-point-list\":\"prefer-mpls\"" },
		{ "{\"app\":\"web\",\"policy\":\"fast\"}", "{\"app\":\"web\","
		    "\"policy\":\"fast\"},{\"app\":\"branchweb\",\"policy\":"
		    "\"fast\"}" },
	};
	/* Each wrong reference, and what it is told. */
	static const char *const breaks[][3] = {
		{ "\"src-list\":\"branches\"", "\"src-list\":\"nolist\"",
		    "there is no list nolist of prefixes" },
		{ "\"src-list\":\"branches\"", "\"src-list\":\"webports\"",
		    "there is no list webports of prefixes" },
		{ "\"src-list\":\"branches\"", "\"src-list\":\"branches\","
		    "\"sav4\":[\"10.1.0.0/16\"]", "the sav4 and sav6 of a list" },
		{ "\"service-list\":\"webports\"", "\"service-list\":\"webports\","
		    "\"dport\":[80]", "not with protv4, nextheadv6, dport" },
		{ "\"10.7.0.0/16\"", "\"10.7.0.1/16\"", "is not a prefix" },
		{ "\"b-mpls\"]}", "\"x-mpls\"]}", "there is no UCS End Point "
		    "x-mpls" },
		{ "\"preference\":200", "\"preference\":70000", "a preference is "
		    "0 to 65535" },
		{ "\"kind\":\"ucs\"", "\"kind\":\"vrfs\"", "a list is of "
		    "prefixes" },
		{ "\"ucs-list\":\"wan\"", "\"ucs-list\":\"sites\"", "there is no "
		    "list sites of ucs" },
		{ "\"prefixes\":\"Default\"", "\"prefixes\":\"Default\","
		    "\"prefix-list\":\"dc\"", "a Default zone has no prefix list" },
		{ "\"name\":\"dc\"", "\"name\":\"d c\"", "letters, digits" },
	};

	start(tc, 0, NULL);
	enrol(&a);
	r4_hosts(sa, sb, sizeof(sa));
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	for (i = 0; i < nitems(breaks); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, breaks[i][0], breaks[i][1], bad,
		    sizeof(bad)), "%s is not in the document", breaks[i][0]);
		r4_check(bad, &r);
		ATF_CHECK_MSG(r.status == 400 && strstr(r.body, breaks[i][2]) !=
		    NULL, "%s: HTTP %d, %s", breaks[i][1], r.status, r.body);
		resp_free(&r);
	}
	/* Kept as written: the lists named, not what they stand for. */
	r4_keep(doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	r4_read("document", &r);
	ATF_CHECK(strstr(r.body, "\"prefix-list\":\"dc\"") != NULL &&
	    strstr(r.body, "\"service-list\":\"webports\"") != NULL);
	resp_free(&r);
	/* The plan: branches an ipfw table of both families; webports the
	 * flow's protocol and ports; dc among office's prefixes; fast's
	 * ways from b-inet with its preference. */
	r4_read("plan", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"name\":\"arcl_branches\",\"valtype\":"
	    "\"legacy\",\"entries\":[[\"10.1.8.0/22\",\"0\"],"
	    "[\"2001:db8:9::/48\",\"0\"]]") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "from table(arcl_branches)") != NULL &&
	    strstr(r.body, "tcp from table(arcl_branches) to") != NULL &&
	    strstr(r.body, "dst-port 8443,https") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "[\"10.7.0.0/16\",") != NULL, "%s",
	    r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"preference\":200") != NULL, "%s",
	    r.body);
	/* The MSS clamped on gre100 and gre101 (gre 24 and IPsec 64 under
	 * 1500: 1412, less 40 or 60), ipfw_pmod loaded and kept first. */
	ATF_CHECK_MSG(strstr(r.body, "tcp-setmss 1372 tcp from any to any via "
	    "gre100 tcpflags syn ip4") != NULL && strstr(r.body, "tcp-setmss "
	    "1352 tcp from any to any via gre100 tcpflags syn ip6") != NULL &&
	    strstr(r.body, "\"kind\":\"kmod\",\"verb\":\"load\",\"args\":["
	    "\"ipfw_pmod\"]") != NULL && strstr(r.body, "\"verb\":\"keep\","
	    "\"args\":[\"ipfw_pmod\"]") != NULL, "%s", r.body);
	resp_free(&r);
	/* Not auto nor bytes: refused. */
	ATF_REQUIRE(swap_in(doc, "\"mss\":\"auto\"", "\"mss\":\"big\"", bad,
	    sizeof(bad)));
	r4_check(bad, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "mss is auto") != NULL,
	    "%s", r.body);
	resp_free(&r);
	/* The tunnels' MTU likewise: auto, 1500 less the overhead, on the
	 * interface made; or bytes, 1280 to 9000; else refused. */
	ATF_REQUIRE(swap_in(doc, "\"mss\":\"auto\"", "\"mtu\":\"auto\",\"mss\":"
	    "\"auto\"", bad, sizeof(bad)));
	r4_check(bad, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_REQUIRE(swap_in(doc, "\"mss\":\"auto\"", "\"mtu\":100,\"mss\":"
	    "\"auto\"", bad, sizeof(bad)));
	r4_check(bad, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "mtu is auto") != NULL,
	    "%s", r.body);
	resp_free(&r);
}

/*
 * SD-WAN's console for the apply: the hosts' events read each second (the
 * SENs come by them), hosts a and b on the one agent (their ids into sa
 * and sb), SENs mailed to soc; the lists the security policy names, one
 * pasted, one a feed over HTTP, one dead, fetched; sdwan_good with its
 * underlays addressed and its UNIs on lo0 kept, into doc.  b-mpls's
 * interface into lifn if it is the host's (empty if not), its address
 * into laddr.
 */
static void
sdwan_apply_start(const atf_tc_t *tc, struct authn *a, char *sa, char *sb,
    size_t len, char *doc, size_t dlen, char *lifn, size_t ilen,
    char *laddr, size_t alen)
{
	struct resp	r;
	char		body[400], t1[8192], t2[300];
	size_t		i;
	int		port;

	lifn[0] = '\0';
	/* The feeds' stand-in, its 127.0.0.1 let through below. */
	port = feeds_server(tc);
	/* The hosts' events read each second: the SENs come by them. */
	snprintf(harness_webconf, sizeof(harness_webconf), "mail_tick = 1;\n");
	start(tc, 0, NULL);
	enrol(a);
	http("PATCH", CC "settings", "{\"arcana-console:settings\":{"
	    "\"mail-sen\":\"soc@example.org\",\"feeds-allow-private\":"
	    "\"127.0.0.1/32\"}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	r4_hosts(sa, sb, len);
	/* The lists the security policy names: one pasted, one a feed
	 * served over HTTP (tests/feeds/sdwan-list.txt), one dead (a 404);
	 * each kept with a version, a failed feed with its error. */
	snprintf(body, sizeof(body), "{\"arcana-console:lists\":{\"interval\":"
	    "2,\"feeds\":[{\"name\":\"blocked\",\"text\":\"198.51.100.0/24\\n"
	    "bad.example\\n\"},{\"name\":\"feedlist\",\"url\":\"http://"
	    "127.0.0.1:%d/sdwan-list.txt\"},{\"name\":\"dead\",\"url\":"
	    "\"http://127.0.0.1:%d/none.txt\"}]}}", port, port);
	http("PUT", CC "sdwan/lists", body, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("POST", CC "sdwan/fetch-lists", "{\"arcana-console:input\":{}}",
	    &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* The good one, its underlays with addresses, its UNIs on lo0. */
	snprintf(doc, dlen, "%s", sdwan_good);
	static const char *const edits[][2] = {
		{ "\"block\":[{\"dav4\":[\"192.0.2.0/24\"]}],",
		    "\"block\":[{\"dav4\":[\"192.0.2.0/24\"]}],\"lists\":{\"block\":"
		    "[\"blocked\",\"feedlist\"]}," },
		{ "\"allow\":[\"ok.ads.example\"],", "\"allow\":[\"ok.ads.example\"],"
		    "\"lists\":{\"block\":[\"feedlist\",\"blocked\"]}," },
		{ "\"md5\":\"edges-secret\",", "\"md5\":\"edges-secret\","
		    "\"control_plane\":{\"host\":\"@A\",\"cluster_id\":\"192.0.2.1\","
		    "\"ctvc\":\"inet\"}," },
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\",\"gateway\":\"192.0.2.254\","
		    "\"vrf\":3,\"routing\":{\"bgp\":{\"family\":\"ipv4\",\"as\":"
		    "65000,\"neighbors\":[\"192.0.2.254\"],\"password\":\"up\"}}" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\"" },
		{ "\"id\":\"uni-hq\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-hq\",\"interface\":\"lo0\"" },
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\"" },
		/* gif: geneve's address needs an interface the kernel has. */
		{ "\"kind\":\"geneve\"", "\"kind\":\"gif\"" },
	};
	/* b-mpls addressed by DHCP (Mplify 119 §12.2.3.2): its address is
	 * not in the document but learned from the host, so it is an
	 * interface of this host with an IPv4 address, whichever that is;
	 * a host without one keeps the address in the document. */
	if (host_iface(lifn, ilen, laddr, alen))
		snprintf(t2, sizeof(t2), "\"id\":\"b-mpls\",\"ucs\":\"mpls\","
		    "\"interface\":\"%s\",\"addressing\":\"dhcp\"", lifn);
	else {
		snprintf(laddr, alen, "10.99.0.2");
		snprintf(t2, sizeof(t2), "\"id\":\"b-mpls\",\"ucs\":\"mpls\","
		    "\"interface\":\"vtnet1\",\"address\":\"10.99.0.2\"");
	}
	ATF_REQUIRE(swap_in(doc, "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":"
	    "\"vtnet1\"", t2, t1, sizeof(t1)));
	snprintf(doc, dlen, "%s", t1);
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)));
		snprintf(doc, dlen, "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, dlen, "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, dlen, "%s", t1);
	r4_keep(doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);
}

/* The plan applied, every warning accepted: done. */
static void
sdwan_apply_done(void)
{
	struct resp	r;

	http("POST", CC "sdwan/apply", accepting(false), &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_REQUIRE_MSG(strcmp(jstr(&r, "apply.state"), "done") == 0, "%s",
	    r.body);
	resp_free(&r);
}

CONSOLE_TC_LONG(sdwan_apply_fresh, "SD-WAN applied, then made all again "
    "(fresh): the tunnels kept in rc.conf made again, the agents alive")
ATF_TC_BODY(sdwan_apply_fresh, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16];
	char		doc[8192], lifn[32], laddr[64];

	need_fibs(2);
	sdwan_apply_start(tc, &a, sa, sb, sizeof(sa), doc, sizeof(doc), lifn,
	    sizeof(lifn), laddr, sizeof(laddr));
	sdwan_apply_done();
	/* ifconfig_gif102 holds its tunnel's ends and more: replaced, the
	 * rest kept (the agent once read the words it had dropped). */
	http("POST", CC "sdwan/apply", accepting(true), &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "done") == 0, "%s",
	    r.body);
	resp_free(&r);
	ATF_CHECK(system("! grep -Ei 'signal|core' arcana-agent.out") == 0);
}

CONSOLE_TC(sdwan_apply_plan, "SD-WAN planned for the edges: the lists "
    "fetched and kept, the plan's tunnels, rules, instances and edits; a "
    "policy that requires encryption, IPv6 without inner addresses, a "
    "geneve tunnel")
ATF_TC_BODY(sdwan_apply_plan, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16];
	char		doc[8192], t1[8192], t2[300], lifn[32], laddr[64];

	sdwan_apply_start(tc, &a, sa, sb, sizeof(sa), doc, sizeof(doc), lifn,
	    sizeof(lifn), laddr, sizeof(laddr));
	r4_read("lists", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "lists.blocked.version") != NULL && strcmp(jstr(
	    &r, "lists.blocked.version"), "1") == 0 && strcmp(jstr(&r,
	    "lists.blocked.count"), "2") == 0 && strcmp(jstr(&r,
	    "lists.feedlist.version"), "1") == 0 && strcmp(jstr(&r,
	    "lists.feedlist.count"), "2") == 0 && jstr(&r, "lists.dead.error")
	    != NULL && strcmp(jstr(&r, "lists.dead.count"), "0") == 0, "%s",
	    r.body);
	ATF_CHECK_STREQ("2", jstr(&r, "interval"));
	resp_free(&r);
	/* Fetched again unchanged: the version stays. */
	http("POST", CC "sdwan/fetch-lists", "{\"arcana-console:input\":{"
	    "\"name\":\"feedlist\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	r4_read("lists", &r);
	ATF_CHECK_STREQ("1", jstr(&r, "lists.feedlist.version"));
	resp_free(&r);
	http("PUT", CC "sdwan/lists", "{\"arcana-console:lists\":{\"feeds\":[{"
	    "\"name\":\"x\",\"text\":\"not a prefix!\"}]}}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "not a prefix nor a "
	    "domain") != NULL, "%s", r.body);
	resp_free(&r);

	/*
	 * The plan: two tunnels, over the Internet (gre under IPsec) and
	 * over the MPLS (geneve), each a unit of its own and a /31 of the
	 * reserved prefix; nothing made yet.
	 */
	r4_read("plan", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_EQ_MSG(3, (int)ucl_array_size(ucl_object_lookup(r.json,
	    "tunnels")), "%s", r.body);
	/* The third is the control plane's own, over inet, after the data
	 * tunnels: gre again, marked control, addresses after theirs. */
	ATF_CHECK_STREQ("acme/a-inet-b-inet/ctvc", jstr(&r, "tunnels.2.id"));
	ATF_CHECK_STREQ("true", jstr(&r, "tunnels.2.control"));
	ATF_CHECK_STREQ("gre104", jstr(&r, "tunnels.2.ends.0.ifname"));
	ATF_CHECK_STREQ("100.64.0.4", jstr(&r, "tunnels.2.ends.0.inner4"));
	ATF_CHECK_STREQ("100.64.0.5", jstr(&r, "tunnels.2.ends.1.inner4"));
	ATF_CHECK_STREQ("gre", jstr(&r, "tunnels.0.kind"));
	ATF_CHECK_STREQ("true", jstr(&r, "tunnels.0.ipsec"));
	ATF_CHECK_STREQ("gre100", jstr(&r, "tunnels.0.ends.0.ifname"));
	ATF_CHECK_STREQ("gre101", jstr(&r, "tunnels.0.ends.1.ifname"));
	ATF_CHECK_STREQ("100.64.0.0", jstr(&r, "tunnels.0.ends.0.inner4"));
	ATF_CHECK_STREQ("100.64.0.1", jstr(&r, "tunnels.0.ends.1.inner4"));
	ATF_CHECK_STREQ("gif", jstr(&r, "tunnels.1.kind"));
	ATF_CHECK_STREQ("false", jstr(&r, "tunnels.1.ipsec"));
	ATF_CHECK_STREQ("true", jstr(&r, "tunnels.1.backup"));
	ATF_CHECK_STREQ("100.64.0.2", jstr(&r, "tunnels.1.ends.0.inner4"));
	ATF_CHECK_EQ(0, changes_of(&r, "keep"));
	ATF_CHECK(changes_of(&r, "make") > 10);
	ATF_CHECK(strstr(r.body, "\"key\":\"uni:branch\"") != NULL);
	/* Each edge measures its tunnels: the far inner address, through
	 * the service's table, as the service's probe settings say. */
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"sdwan-probes\",\"targets\":[{"
	    "\"id\":\"acme/a-inet-b-inet\",\"address\":\"100.64.0.1\",\"fib\":1,"
	    "\"eval\":1000,\"tca\":{\"delay\":30,\"loss\":0.050000,\"damping\":2}}")
	    != NULL, "%s", r.body);
	/*
	 * The gif, plain (no IPsec): its STAMP authenticated by default
	 * (PLAN-SDN-YANG 5.1.7), the key derived by each end from its
	 * pair, made first, and the far end's public half, which the apply
	 * reads from that end; the gre under IPsec's not (above).
	 */
	snprintf(t2, sizeof(t2), "\"stamp_interface\":\"gif102\","
	    "\"stamp_peer\":\"${stamp:%s:gif103}\"", sb);
	ATF_CHECK_MSG(strstr(r.body, t2) != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"stampkey:gif102\",\"phase\":2,"
	    "\"title\":\"gif102: its key pair, X25519, kept by the agent: its "
	    "authenticated STAMP's key\",\"make\":[{\"kind\":\"ipsec-sa\","
	    "\"verb\":\"key\",\"interface\":\"gif102\"}]") != NULL, "%s",
	    r.body);
	/* The rules: the UNI's packets to their zone's block, each flow
	 * with its policy's table, the rest dropped; and the steering. */
	ATF_CHECK_MSG(strstr(r.body, "\"10 skipto tablearg ip from table("
	    "sw1_zone) to any in recv lo0\"") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"10 deny ip from any to any ipoptions "
	    "lsrr,ssrr,rr in recv lo0\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"11 skipto 99 ip from any to any\"") != NULL);
	/* The office zone (block 12): web, tcp to 80 and https, by policy
	 * fast (the first policy, 0) in IPv4 and IPv6 tables; voice, sip,
	 * dropped (no policy); all, by hubonly (policy 1). */
	ATF_CHECK_MSG(strstr(r.body, "\"12 fwd tablearg tcp from any to table("
	    "sw1_z0p0_4) dst-port 80,https\"") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"12 fwd tablearg tcp from any to table("
	    "sw1_z0p0_6) dst-port 80,https\"") != NULL);
	/* Then what the flow may do beyond the tunnels: the hosts of the
	 * edge's own UNI (queued, as fast has bandwidth), the Internet by
	 * breakout (fast enables it; not known is the Internet), and
	 * nothing else; a flow with no bandwidth is let through. */
	/* Two end points on the edge, the UNI and the remote: each rule
	 * of the block names the interface it is for. */
	ATF_CHECK_MSG(strstr(r.body, "\"12 queue 3001 tcp from any to "
	    "10.1.0.0/24,10.1.8.0/22 dst-port 80,https in recv lo0\"") != NULL,
	    "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"12 queue 3001 tcp from any to not table("
	    "sw1_known) dst-port 80,https\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"12 deny tcp from any to any dst-port "
	    "80,https\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"12 allow ip4 from any to 10.1.0.0/24,"
	    "10.1.8.0/22 in recv lo0\"") != NULL);
	/* (The end points by edge, as the L3NM keeps them: road, at a,
	 * before branch.) */
	ATF_CHECK(strstr(r.body, "[\"10.1.8.0/22\",\"0\"],[\"10.30.0.0/24\","
	    "\"0\"],[\"2001:db8:1::/64\",\"0\"]") != NULL);
	/* Its bandwidth: the shared limiter a pipe of its limit, the flow
	 * a queue in it, weighted by its commit and importance (high),
	 * on the way out by the tunnels. */
	ATF_CHECK(strstr(r.body, "\"pipe 3000 config bw 5000000bit/s\"") !=
	    NULL);
	ATF_CHECK(strstr(r.body, "\"queue 3001 config pipe 3000 weight 100\"")
	    != NULL);
	ATF_CHECK_MSG(strstr(r.body, "\"11 queue 3001 tcp from any to any "
	    "dst-port 80,https src-ip table(sw1_zp0) out { xmit gre100 or xmit "
	    "gif102 }\"") != NULL, "%s", r.body);
	/* Egress: quiet discards all of the office zone leaving by hq's
	 * UNI. */
	ATF_CHECK(strstr(r.body, "\"11 deny ip from any to any src-ip table("
	    "sw1_zp0) out xmit lo0\"") != NULL);
	/*
	 * The security policy guard, named by fast, its function policies
	 * (MEF 138).  IPPF before the forward: its entries most specific
	 * first, the Allow tagging, the Block dropping the untagged and
	 * logged; its lists' prefixes in a table of its own, the list the
	 * value.  Its rate limit a pipe of its own on the way out by the
	 * tunnels.
	 */
	ATF_CHECK_MSG(strstr(r.body, "\"12 count tag 1 tcp from any to any "
	    "dst-port 80,https dst-ip 192.0.2.8/29\"") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"12 deny log logdst rtsock logamount 1000 tcp "
	    "from any to any dst-port 80,https dst-ip 192.0.2.0/24 not tagged 1 "
	    "// security acme g-ippf block\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"12 count tag 1 tcp from any to any dst-port "
	    "80,https dst-ip 192.0.2.8/29\",\"12 deny") != NULL);
	ATF_CHECK_MSG(strstr(r.body, "\"name\":\"sw1_f0v4\",\"valtype\":\"legacy\","
	    "\"entries\":[[\"198.51.100.0/24\",\"1\"],[\"203.0.113.0/24\",\"1\"]]")
	    != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"12 deny log logdst rtsock logamount 1000 tcp "
	    "from any to any dst-port 80,https dst-ip table(sw1_f0v4,1) not "
	    "tagged 1 // security acme g-ippf block\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"12 deny log logdst rtsock logamount 1000 tcp "
	    "from any to any dst-port 80,https src-ip table(sw1_f0v4,1) not "
	    "tagged 1 // security acme g-ippf block\"") != NULL);
	ATF_CHECK(strstr(r.body, "sw1_f0v6") == NULL);
	ATF_CHECK(strstr(r.body, "\"pipe 3002 config bw 2000000bit/s\"") != NULL);
	ATF_CHECK_MSG(strstr(r.body, "\"11 pipe 3002 tcp from any to any "
	    "dst-port 80,https src-ip table(sw1_zp0) out { xmit gre100 or xmit "
	    "gif102 }\"") != NULL, "%s", r.body);
	/* DPF, No-match block with redirect: the flow's DNS not to the
	 * edge sent to the service's resolver on hq's address; DNS over
	 * TLS answered at once, port unreachable (R100). */
	ATF_CHECK_MSG(strstr(r.body, "\"12 fwd 10.1.0.1,53 tcp from any to any "
	    "dst-port 80,https ipversion 4 proto udp dst-port 53 not dst-ip me "
	    "not tagged 3 in recv lo0\"") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"12 unreach port log logdst rtsock logamount 1000 "
	    "tcp from any to any dst-port 80,https proto tcp dst-port 853 not "
	    "dst-ip me not tagged 3 // security acme g-dpf no-match\"") != NULL);
	/* Its entries by message type (Table 6): a response from a server
	 * by its source port, a query to one by its destination port; the
	 * No-match blocks both ways. */
	ATF_CHECK_MSG(strstr(r.body, "\"12 unreach port log logdst rtsock "
	    "logamount 1000 tcp from any to any dst-port 80,https src-ip "
	    "192.0.2.53/32 proto udp src-port 53 not src-ip me not tagged 3 in recv "
	    "lo0 // security acme g-dpf block\"") != NULL && strstr(r.body,
	    "\"12 unreach port log logdst rtsock logamount 1000 tcp from any to "
	    "any dst-port 80,https dst-ip 192.0.2.54/32 proto udp dst-port 53 not "
	    "dst-ip me not tagged 3 in recv lo0 // security acme g-dpf block\"")
	    != NULL && strstr(r.body, "src-ip 192.0.2.53/32 proto udp dst-port 53")
	    == NULL && strstr(r.body, "\"12 unreach port log logdst rtsock "
	    "logamount 1000 tcp from any to any dst-port 80,https proto udp "
	    "src-port 53 not src-ip me not tagged 3 in recv lo0 // security acme "
	    "g-dpf no-match\"") != NULL, "%s", r.body);
	/* The DNF of the office zone: an unbound instance of the service at
	 * a, on hq's provider address, a view of the zone's own by its
	 * prefixes, the Block's names nxdomain, the Allow's transparent, the
	 * lists' domains too. */
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"dns\",\"phase\":10,\"title\":"
	    "\"DNS filtering and protective DNS (MEF 138): unbound, 1 instance "
	    "in the services' tables, a view a zone\"") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"sdwan-dns\",\"instances\":[{"
	    "\"name\":\"sw1\",\"fib\":1,\"host\":\"a\",\"spec\":{\"service\":"
	    "\"acme\",\"fib\":1,\"unis\":[{\"id\":\"uni-hq\",\"address\":"
	    "\"10.1.0.1\",\"prefix\":\"10.1.0.0/24\"}],\"zones\":[{\"name\":"
	    "\"z0\",\"prefixes\":[\"10.1.0.0/16\",") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"dnf\":{\"no-match\":\"allow\",\"block\":"
	    "[\"ads.example\"],\"allow\":[\"ok.ads.example\"],\"listed\":{"
	    "\"block\":[\"bad-feed.example\",\"bad.example\"]}}") != NULL, "%s",
	    r.body);
	ATF_CHECK(strstr(r.body, "\"10 fwd 10.1.0.1,53") == NULL);
	/* HTTP and TLS of the office zone to its proxy, by its table. */
	ATF_CHECK_MSG(strstr(r.body, "\"10 fwd 10.1.0.1,3128 tcp from table("
	    "sw1_zp0) to any dst-port 80 in recv lo0\"") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"10 fwd 10.1.0.1,3129 tcp from table("
	    "sw1_zp0) to any dst-port 443 in recv lo0\"") != NULL);
	/* Breakout at a, by a-inet: the NAT of hq's public prefix, out by
	 * vtnet0 and back in to the service's table; the default route
	 * by the gateway, reached by the interface.  At b, by a tunnel to
	 * a. */
	ATF_CHECK(strstr(r.body, "\"nat 3001 config ip 198.51.100.1\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"11 nat 3001 ip4 from table(sw1_known) to "
	    "not table(sw1_known) out xmit vtnet0\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"11 setfib 2 ip from any to 198.51.100.1 in "
	    "recv vtnet0\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"11 nat 3001 ip4 from any to 198.51.100.1 in "
	    "recv vtnet0\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"11 setfib 2 ip from any to table(sw1_known) "
	    "in recv vtnet0\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"key\":\"route:acme:2:192.0.2.254/32\"") !=
	    NULL);
	ATF_CHECK_MSG(strstr(r.body, "\"title\":\"0.0.0.0/0 via 192.0.2.254, "
	    "fib 2 (the Internet, by local breakout)\"") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"title\":\"0.0.0.0/0 via 100.64.0.0, fib "
	    "2 (the Internet, by breakout at a)\"") != NULL, "%s", r.body);
	/* The breakout domain (Mplify 119 R20-R26): the UNIs' routes in
	 * its table, the flows that break out sent to it, the way back in
	 * by it; the service's own table without a default route. */
	ATF_CHECK_MSG(strstr(r.body, "/24 via lo0, fib 2 (the UNI's hosts, in the "
	    "breakout domain (R25))\"") != NULL || strstr(r.body, "/24 via vtnet2, "
	    "fib 2 (the UNI's hosts, in the breakout domain (R25))\"") != NULL,
	    "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"10.1.8.0/22 via 10.1.0.2, fib 2 (behind the "
	    "UNI, in the breakout domain (R26))\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"12 setfib 2 tcp from any to not table("
	    "sw1_known) dst-port 80,https\"") != NULL);
	ATF_CHECK(strstr(r.body, "setfib 2 ip from any to table(sw1_known) in "
	    "recv vtnet0") != NULL);
	ATF_CHECK(strstr(r.body, "\"100.64.0.0/32 via gre101, fib 2 (the tunnel's "
	    "far end, in the breakout domain)\"") != NULL);
	ATF_CHECK(strstr(r.body, "0.0.0.0/0 via 192.0.2.254, fib 1 (") == NULL);
	/* The UCS end points (Mplify 119 §12.2.3): b-mpls addressed by
	 * DHCP, its address learned from the host (the helper says
	 * epair1b has 10.99.0.2), so the geneve tunnel still has its far
	 * end; a-inet in its own table, the gre tunnel's outer packets by
	 * it, BGP with the underlay by a BIRD instance of its own. */
	if (lifn[0] != '\0') {
		snprintf(t2, sizeof(t2), "\"kind\":\"if-set\",\"interface\":\"%s\","
		    "\"persist\":true,\"addressing\":\"dhcp\"", lifn);
		ATF_CHECK_MSG(strstr(r.body, "\"key\":\"ucs:b-mpls\"") != NULL &&
		    strstr(r.body, t2) != NULL, "%s", r.body);
		/* Undone, addressed as before, not static. */
		snprintf(t2, sizeof(t2), "\"kind\":\"if-set\",\"interface\":"
		    "\"%s\",\"persist\":true,\"addressing\":\"was\"", lifn);
		ATF_CHECK_MSG(strstr(r.body, t2) != NULL, "%s", r.body);
	}
	/* The tunnel a device edit: its ends arcana-interfaces'. */
	snprintf(t2, sizeof(t2), "\"arcana-interfaces:tunnel\":{\"local\":"
	    "\"10.99.0.1\",\"remote\":\"%s\"}", laddr);
	ATF_CHECK_MSG(strstr(r.body, t2) != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"if-set\",\"interface\":\"vtnet0\","
	    "\"persist\":true,\"fib\":3") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"tunnel_remote\":\"192.0.2.2\",\"tunnelfib\":3")
	    != NULL);
	ATF_CHECK_MSG(strstr(r.body, "{\"name\":\"ucs3\",\"fib\":3,\"host\":"
	    "\"a\",\"spec\":{\"flavor\":\"ucs\",\"end_point\":\"a-inet\","
	    "\"table\":3,\"router_id\":\"192.0.2.1\",\"interface\":\"vtnet0\","
	    "\"as\":64512,\"bgp\":{\"family\":\"ipv4\",\"as\":65000,"
	    "\"neighbors\":[\"192.0.2.254\"]") != NULL, "%s", r.body);
	/* Routing: a BIRD instance of the service on each edge, in its
	 * table, iBGP between them by each tunnel, and at hq's UNI BGP
	 * with the subscriber as the entry says. */
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"sdwan-bird\",\"instances\":[{"
	    "\"name\":\"sw1\",\"fib\":1,\"host\":\"a\",\"spec\":{\"service\":"
	    "\"acme\",\"fib\":1,\"table\":1,\"as\":64600,\"router_id\":"
	    "\"100.64.0.0\",\"direct\":[\"lo0\",\"gre100\",\"gif102\","
	    "\"gre104\"],") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"reject\":[\"100.64.0.0/24\","
	    "\"100.64.0.0/24\"]") != NULL, "%s", r.body);
	/* The hosts' addresses: hq's IPv4 by DHCP, dnsmasq (a plugin,
	 * installed before and never by the apply) in the service's table,
	 * its ranges the subnet less the reserved prefixes and the
	 * provider's address, the router and DNS told; branch's IPv6 by
	 * SLAAC, rtadvd on the VLAN with RDNSS; the kernel forwarding on
	 * both edges.  What the edges need is listed, each there or not. */
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"pkg-install\"") == NULL,
	    "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"plugin\":\"dnsmasq\",\"package\":"
	    "\"dnsmasq\"") != NULL && strstr(r.body, "\"plugin\":\"squid\"")
	    != NULL, "%s", r.body);
	/* The UNI is lo0 here (swapped in for the apply). */
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"sdwan-dhcp\",\"instances\":[{"
	    "\"name\":\"sw1\",\"fib\":1,\"host\":\"a\",\"spec\":{\"service\":"
	    "\"acme\",\"fib\":1,\"unis\":[{\"id\":\"uni-hq\",\"interface\":"
	    "\"lo0\",\"ipv4\":{\"mode\":\"dhcp\",\"prefix\":\"10.1.0.0/24\","
	    "\"provider\":[\"10.1.0.1\"],\"reserved\":[\"10.1.0.0/26\","
	    "\"10.1.0.200/30\"],\"lease\":\"1h\",\"dns\":[\"10.1.0.1\"]}}]}}") !=
	    NULL, "%s", r.body);
	/* SLAAC's advertisements with the VLAN that carries them, in its
	 * device edit (RFC 8349's, arcana-ra's DNS servers). */
	ATF_CHECK_MSG(strstr(r.body, "\"type\":\"iana-if-type:l2vlan\",\"ietf-"
	    "if-extensions:parent-interface\":\"lo0\",\"ietf-if-extensions:"
	    "encapsulation\":{\"ietf-if-vlan-encapsulation:dot1q-vlan\":{\""
	    "outer-tag\":{\"tag-type\":\"ieee802-dot1q-types:c-vlan\",\"vlan-id\""
	    ":20}}}") != NULL && strstr(r.body, "\"ietf-ipv6-unicast-routing:"
	    "ipv6-router-advertisements\":{\"send-advertisements\":true,\"prefix-"
	    "list\":{\"prefix\":[{\"prefix-spec\":\"2001:db8:1::/64\"}]},\"arcana-"
	    "ra:rdnss\":[{\"address\":\"2001:db8:1::1\"}]}") != NULL &&
	    strstr(r.body, "\"kind\":\"rtadvd\"") == NULL, "%s", r.body);
	/* Forwarding and the FIBs by arcana-sysctl, device edits of the
	 * hosts' candidates (4.5.5), no longer sysctl jobs. */
	ATF_CHECK_MSG(strstr(r.body, "{\"kind\":\"edit\",\"method\":\"PATCH\","
	    "\"path\":\"arcana-sysctl:sysctl\",\"body\":{\"arcana-sysctl:sysctl\""
	    ":{\"kept\":[{\"name\":\"net.inet.ip.forwarding\",\"value\":\"1\"},"
	    "{\"name\":\"net.inet6.ip6.forwarding\",\"value\":\"1\"}]}}}") !=
	    NULL && strstr(r.body, "{\"name\":\"net.fibs\",\"value\":\"4\"}") !=
	    NULL && strstr(r.body, "\"kind\":\"sysctl\"") == NULL, "%s",
	    r.body);
	/* The iBGP by the control tunnel alone: the host a reflector, b its
	 * client and nothing else; no session by the data tunnels. */
	ATF_CHECK_MSG(strstr(r.body, "\"peers\":[{\"tunnel\":"
	    "\"acme/a-inet-b-inet/ctvc\",\"to\":\"b\",\"local\":\"100.64.0.4\","
	    "\"neighbor\":\"100.64.0.5\",\"role\":\"client\",\"cluster_id\":"
	    "\"192.0.2.1\"}]") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"peers\":[{\"tunnel\":"
	    "\"acme/a-inet-b-inet/ctvc\",\"to\":\"a\",\"local\":\"100.64.0.5\","
	    "\"neighbor\":\"100.64.0.4\",\"role\":\"control\"}]") != NULL, "%s",
	    r.body);
	ATF_CHECK(strstr(r.body, "\"tunnel\":\"acme/a-inet-b-inet\",") == NULL);
	/* BFD on the edge's tunnel interfaces, the iBGP sessions by it. */
	ATF_CHECK_MSG(strstr(r.body, "\"bfd\":{\"interfaces\":[\"gre100\","
	    "\"gif102\",\"gre104\"],\"interval\":200,\"multiplier\":3,"
	    "\"sessions\":true},") != NULL && strstr(r.body, "\"md5\":"
	    "\"edges-secret\"") != NULL, "%s", r.body);
	/* NTP at a, with the FIBs, by the ntp job; taken away by it too. */
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"ntp\",\"phase\":1,\"title\":\"NTP: "
	    "ntpd by 2 servers, for the time faults and keys go by\",\"make\":[{"
	    "\"kind\":\"ntp\",\"args\":[\"ntp.example.org\",\"10.99.0.9\"],"
	    "\"persist\":true}]") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"unis\":[{\"id\":\"uni-hq\",\"end_point\":"
	    "\"hq\",\"interface\":\"lo0\",\"bgp\":{\"family\":\"ipv4\",\"as\":"
	    "65010,\"neighbors\":[\"10.1.0.2\"],\"password\":\"s3cret\","
	    "\"hold_time\":90,\"distance\":150,\"communities\":[[64600,100]]}}]")
	    != NULL, "%s", r.body);
	/* b has no routing at its UNI, but the service's instance all the
	 * same: what hq learns reaches it. */
	ATF_CHECK(strstr(r.body, "\"host\":\"b\",\"spec\":{\"service\":"
	    "\"acme\",\"fib\":1,\"table\":1,") != NULL);
	ATF_CHECK_MSG(strstr(r.body, "\"12 deny ip from any to any { src-port "
	    "5060,5061 or dst-port 5060,5061 } dscp 46\"") != NULL, "%s",
	    r.body);
	ATF_CHECK(strstr(r.body, "\"12 fwd tablearg ip4 from any to table("
	    "sw1_z0p1_4) in recv lo0\"") != NULL);
	/* The remote's identities get the zone's own policies, having no
	 * map of their own: the block's rules for wg5. */
	ATF_CHECK(strstr(r.body, "\"12 fwd tablearg tcp from any to table("
	    "sw1_z0p0_4) dst-port 80,https in recv wg5\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"11 deny ip from any to any in recv wg5\"")
	    != NULL);
	ATF_CHECK(strstr(r.body, "\"12 deny ip from any to any\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"99 count ip from any to any\"") != NULL);
	ATF_CHECK(strstr(r.body, "[\"10.1.0.0/16\",\"12\"]") != NULL);
	ATF_CHECK(strstr(r.body, "[\"0.0.0.0/0\",\"13\"]") != NULL);
	/* hq's branch is a leaf of the hub topology: hubonly reaches it,
	 * over the private tunnel first, the public one after. */
	ATF_CHECK_MSG(strstr(r.body, "\"table\":\"sw1_z1p1_6\",\"prefix\":"
	    "\"2001:db8:1::/64\"") == NULL, "%s", r.body);
	/* A remote end point: wg5 in the service's table with the
	 * prefix's first host, listening; the identity a peer allowed its
	 * address, the second host, which the zone table sends to its
	 * zone's block, and its packets in by wg5 as a UNI's. */
	ATF_CHECK_MSG(strstr(r.body, "{\"kind\":\"if-create\",\"interface\":"
	    "\"wg5\",\"fib\":1,\"description\":\"sdwan\",\"address\":"
	    "\"10.30.0.1/24\",\"persist\":true}") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "{\"kind\":\"wireguard\",\"verb\":\"init\","
	    "\"interface\":\"wg5\",\"listen_port\":51820,\"persist\":true}") !=
	    NULL);
	ATF_CHECK(strstr(r.body, "{\"kind\":\"wireguard\",\"verb\":\"peer\","
	    "\"interface\":\"wg5\",\"peer\":"
	    "\"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\",\"allowed_ips\":"
	    "\"10.30.0.2/32\",\"persist\":true}") != NULL);
	ATF_CHECK_MSG(strstr(r.body, "[\"10.30.0.2/32\",\"12\"]") != NULL, "%s",
	    r.body);
	ATF_CHECK(strstr(r.body, "\"10 skipto tablearg ip from table(sw1_zone) "
	    "to any in recv wg5\"") != NULL);
	/* Its groups: carol of staff takes the first address of the
	 * group's pool and her group's zone; a table each of the members;
	 * staff and guests, neither reaching the other, kept apart both
	 * ways before the zone table. */
	ATF_CHECK_MSG(strstr(r.body, "\"peer\":"
	    "\"HIgo9xNzJMWLKASShiTqIYNW7HVnKq0pjaZxmvZ6rKA=\",\"allowed_ips\":"
	    "\"10.30.0.64/32\"") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "[\"10.30.0.64/32\",\"12\"]") != NULL);
	ATF_CHECK_MSG(strstr(r.body, "\"name\":\"sw1_g0\",\"valtype\":\"legacy\","
	    "\"entries\":[[\"10.30.0.64/32\",\"0\"]]") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"name\":\"sw1_g1\",\"valtype\":\"legacy\","
	    "\"entries\":[]") != NULL);
	ATF_CHECK(strstr(r.body, "\"10 deny ip from table(sw1_g0) to "
	    "table(sw1_g1) in recv wg5\",\"10 deny ip from table(sw1_g1) to "
	    "table(sw1_g0) in recv wg5\",\"10 skipto tablearg ip from "
	    "table(sw1_zone) to any in recv wg5\"") != NULL);
	/*
	 * URLF (MEF 138): HTTP and TLS of the office zone forwarded to Squid
	 * on the edge's own addresses, the remote end point's too, where
	 * the zone's identities come from; its instance in the plan with
	 * the zone by its prefixes, the TLS name of the Block's host ended,
	 * the rest let through unopened (no MBSF), the zone's malware
	 * scanned.
	 */
	ATF_CHECK(strstr(r.body, "\"10 fwd 10.30.0.1,3129 tcp from table("
	    "sw1_zp0) to any dst-port 443 in recv wg5\"") != NULL);
	ATF_CHECK_MSG(strstr(r.body, "{\"kind\":\"sdwan-proxy\",\"instances\":[{"
	    "\"name\":\"sw1\",\"fib\":1,\"mode\":\"sni\",\"host\":\"a\","
	    "\"spec\":{\"flavor\":\"sdwan\",\"service\":\"acme\",\"fib\":1,"
	    "\"listen\":[{\"end_point\":\"hq\",\"address\":\"10.1.0.1\"},{"
	    "\"end_point\":\"road\",\"address\":\"10.30.0.1\"}],\"resolver\":"
	    "true,") != NULL && strstr(r.body, "\"zones\":[{\"name\":\"z0\","
	    "\"prefixes\":[\"10.1.0.0/16\",\"10.30.0.2/32\",\"10.30.0.64/32\"],"
	    "\"urlf\":{\"no-match\":\"allow\",\"block\":[\"bad.example\"]},"
	    "\"mdr\":{\"no-match\":\"allow\",\"block\":[\"44D88612FEA8A8F36DE82E1278"
	    "ABB02F:68\",\"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aa"
	    "bf651fd0f\"],\"allow\":[\"3395856ce81f2b7382dee72602f798b642f14140\"],"
	    "\"id\":\"g-mdr\"}}]},\"lists\":{}") != NULL, "%s", r.body);
	/* MD+R (MEF 138): what comes back goes to c-icap by ICAP, beside
	 * Squid on the edge's own address (the agent renders its file of
	 * the same form); c-icap scans with ClamAV, a need. */
	ATF_CHECK_MSG(strstr(r.body, "\"resolver\":true,\"icap\":true,") != NULL
	    && strstr(r.body, "\"plugin\":\"c-icap\",\"package\":\"c-icap "
	    "c-icap-modules clamav\"") != NULL, "%s", r.body);
	/* Intrusion detection (Arcana's own): Suricata on the service's UNIs at
	 * each edge, its home the UNIs' subnets, the policy's rules and the
	 * ruleset suricata-update keeps; Suricata a need.  It prevents: the
	 * UNI's traffic both ways diverted to it as it comes in, on the
	 * service's port, one rule before the way in, and given back to
	 * the service's table there. */
	ATF_CHECK_MSG(strstr(r.body, "\"divert\":8001") != NULL && strstr(
	    r.body, "\"9 divert 8001 ip4 from any to any in recv ") != NULL &&
	    strstr(r.body, "\"9 divert 8001 ip4 from any to 10.1.0.0/24 in not "
	    "recv ") != NULL && strstr(r.body, " not dst-ip me\",") != NULL &&
	    strstr(r.body, "\"10 setfib 1 ip4 from any to 10.1.0.0/24 in "
	    "diverted-loopback not dst-ip me\"") != NULL && strstr(r.body,
	    "\"oneside\":true") != NULL, "%s", r.body);
	/* The instance's settings, which the agent renders into Suricata's
	 * YAML: the UNIs' prefixes its home, the ruleset, one side. */
	ATF_CHECK_MSG(strstr(r.body, "{\"kind\":\"sdwan-ids\",\"instances\":[{"
	    "\"name\":\"sw1\",\"host\":\"") != NULL && strstr(r.body,
	    "\"spec\":{\"flavor\":\"sdwan\",\"service\":\"acme\",\"home\":"
	    "[\"10.1.0.0/24\"") != NULL && strstr(r.body,
	    "\"ruleset\":true,\"oneside\":true}") != NULL &&
	    strstr(r.body, "\"rules\":\"alert http any any -> $HOME_NET any "
	    "(msg:\\\"x\\\"; sid:1000001; rev:1;)\\n\"") != NULL && strstr(
	    r.body, "\"plugin\":\"suricata\",\"package\":\"suricata\"") != NULL,
	    "%s", r.body);
	resp_free(&r);
	/* The record: the edges' logged packets read now; none yet. */
	r4_read("record?swvc=acme&policy=g-ippf", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"record\":[]") != NULL, "%s", r.body);
	resp_free(&r);
	http_with("GET", CC "sdwan/record", "Accept: text/csv\r\n", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strncmp(r.body, "time,edge,rule,action,source,destination,"
	    "interface,comment\n", 60) == 0, "%s", r.body);
	resp_free(&r);

	/* A policy that requires encryption always: the private tunnel
	 * is under IPsec too; a UCS that says no IPsec cannot be. */
	ATF_REQUIRE(swap_in(doc, "\"encryption\":\"required-public-only\"",
	    "\"encryption\":\"required-always\"", t1, sizeof(t1)));
	snprintf(doc, sizeof(doc), "%s", t1);
	ATF_REQUIRE(swap_in(doc, "\"version\":0", "\"version\":1", t1,
	    sizeof(t1)));
	snprintf(doc, sizeof(doc), "%s", t1);
	r4_keep(doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	r4_read("plan", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "tunnels.1.ipsec"));
	ATF_CHECK_STREQ("gif", jstr(&r, "tunnels.1.kind"));
	resp_free(&r);
	ATF_REQUIRE(swap_in(doc, "\"kind\":\"gif\"",
	    "\"kind\":\"gif\",\"ipsec\":false", t1, sizeof(t1)));
	ATF_REQUIRE(swap_in(t1, "\"version\":1", "\"version\":2", doc,
	    sizeof(doc)));
	r4_keep(doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	r4_read("plan", &r);
	ATF_CHECK_MSG(r.status == 409 && strstr(r.body, "(R39)") != NULL, "%s",
	    r.body);
	resp_free(&r);
	ATF_REQUIRE(swap_in(doc, "\"kind\":\"gif\",\"ipsec\":false",
	    "\"kind\":\"gif\"", t1, sizeof(t1)));
	ATF_REQUIRE(swap_in(t1, "\"encryption\":\"required-always\"",
	    "\"encryption\":\"required-public-only\"", doc, sizeof(doc)));
	ATF_REQUIRE(swap_in(doc, "\"version\":2", "\"version\":3", t1,
	    sizeof(t1)));
	r4_keep(t1, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	/* An IPv6 UNI with no IPv6 inner addresses: the plan says so. */
	r4_read("plan", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"notes\":[\"swvc acme: no tunnel from a "
	    "to b carries 2001:db8:1::/64") != NULL, "%s", r.body);
	resp_free(&r);
	/* A geneve tunnel: one VNI at both ends, its table after it. */
	ATF_REQUIRE(swap_in(doc, "\"kind\":\"gif\"", "\"kind\":\"geneve\"",
	    t1, sizeof(t1)));
	snprintf(doc, sizeof(doc), "%s", t1);
	ATF_REQUIRE(swap_in(doc, "\"version\":2", "\"version\":4", t1,
	    sizeof(t1)));
	r4_keep(t1, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	r4_read("plan", &r);
	EXPECT(&r, 200);
	snprintf(t2, sizeof(t2), "\"args\":[\"mode\",\"l3\",\"id\",\"102\","
	    "\"local\",\"10.99.0.1\",\"remote\",\"%s\"]", laddr);
	ATF_CHECK_MSG(strstr(r.body, t2) != NULL, "%s", r.body);
	snprintf(t2, sizeof(t2), "\"args\":[\"mode\",\"l3\",\"id\",\"102\","
	    "\"local\",\"%s\",\"remote\",\"10.99.0.1\"]", laddr);
	ATF_CHECK_MSG(strstr(r.body, t2) != NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC_LONG(sdwan_apply, "SD-WAN made on the edges: refused without what "
    "a service needs, applied, its SENs, kept")
ATF_TC_BODY(sdwan_apply, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[400], sa[16], sb[16];
	char		doc[8192], t2[300], lifn[32], laddr[64];
	size_t		i, len;
	int		fibs = 0;

	need_fibs(2);
	sdwan_apply_start(tc, &a, sa, sb, sizeof(sa), doc, sizeof(doc), lifn,
	    sizeof(lifn), laddr, sizeof(laddr));
	/* Applied: each made, in the order, IPsec with the far key. */
	/* An edge without what a service needs there: nothing is
	 * installed by the apply, which refuses and says what to install
	 * where.  Squid back, it goes on. */
	ATF_REQUIRE(rename("tools/squid", "tools/squid.off") == 0);
	http("POST", CC "sdwan/apply", "{\"arcana-console:input\":{}}", &r);
	EXPECT(&r, 409);
	ATF_CHECK_MSG(strstr(r.body, "pkg install squid") != NULL &&
	    strstr(r.body, "nothing is installed by the apply") != NULL, "%s",
	    r.body);
	resp_free(&r);
	ATF_REQUIRE(rename("tools/squid.off", "tools/squid") == 0);
	/* A warning accepted is one the plan lists for that step and host,
	 * or the apply is refused, nothing made. */
	http("POST", CC "sdwan/apply", "{\"arcana-console:input\":{\"accept\":"
	    "[{\"server\":\"nosuch\",\"key\":\"uni:hq\",\"warning\":"
	    "\"rc-conf-files\"}]}}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "accept: rc-conf-files "
	    "of uni:hq on nosuch is not a warning the plan lists") != NULL, "%s",
	    r.body);
	resp_free(&r);
	http("POST", CC "sdwan/apply", "{\"arcana-console:input\":{\"accept\":"
	    "\"rc-conf-files\"}}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "accept is an array")
	    != NULL, "%s", r.body);
	resp_free(&r);
	http("POST", CC "sdwan/apply", accepting(false), &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "done") == 0, "%s",
	    r.body);
	/* Into the history: this one, done, with what it made. */
	ATF_CHECK_MSG(jstr(&r, "history.0.state") != NULL && strcmp(jstr(&r,
	    "history.0.state"), "done") == 0 && jstr(&r, "history.0.made") !=
	    NULL && atoi(jstr(&r, "history.0.made")) > 10 && jstr(&r,
	    "history.1.state") == NULL, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^gre100 create' ifconfig.log") == 0);
	/* The edits committed: sysctl.conf has them, sysctl(8) set them;
	 * net.fibs only where the kernel has fewer (it only goes up). */
	ATF_CHECK(system("grep -qx 'net.inet6.ip6.forwarding=1' sysctl.conf && "
	    "grep -q '^sysctl net.inet.ip.forwarding=1' kld.log") == 0);
	len = sizeof(fibs);
	if (sysctlbyname("net.fibs", &fibs, &len, NULL, 0) == 0 && fibs < 4)
		ATF_CHECK(system("grep -qx 'net.fibs=4' sysctl.conf") == 0);
	/* Suricata's alert (the stand-in writes one as it starts) is an
	 * event, and the event a Security Event Notification (MEF 138
	 * R24, Table 3): Arcana's own function, the service, the source,
	 * the action, its ID; mailed to the SEN recipients. */
	for (i = 0; i < 300; i++) {
		r4_read("sen", &r);
		if (r.status == 200 && ucl_object_toint(ucl_object_lookup(r.json,
		    "count")) > 0)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_CHECK_MSG(r.status == 200 && jstr(&r, "notices.0.id") != NULL &&
	    strlen(jstr(&r, "notices.0.id")) == 36 && strncmp(jstr(&r,
	    "notices.0.function"), "Intrusion detection", 19) == 0 && strcmp(
	    jstr(&r, "notices.0.policy"), "ids") == 0 && strcmp(jstr(&r,
	    "notices.0.service"), "acme") == 0 && strcmp(jstr(&r,
	    "notices.0.source"), "10.0.0.9") == 0 && strcmp(jstr(&r,
	    "notices.0.type"), "OTHER") == 0 && strncmp(jstr(&r,
	    "notices.0.action"), "Alerted", 7) == 0 && strcmp(jstr(&r,
	    "notices.0.uni"), strcmp(jstr(&r, "notices.0.edge"), "a") == 0 ?
	    "uni-hq" : "uni-br") == 0 && strstr(jstr(&r, "notices.0.details"),
	    "LOCAL telnet (severity 2): 10.0.0.9:4444 to 10.0.0.1:23 TCP on "
	    "lo0 at ") != NULL, "%s", r.body);
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q 'Security Event Notification' "
	    "mail.out") != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(system("grep -q 'Security Function: Intrusion detection' "
	    "mail.out && grep -q '^Subject: Arcana: .*Security Event "
	    "Notification' mail.out && grep -qx 'To: soc@example.org' mail.out")
	    == 0, "no mail of the SEN");
	ATF_CHECK(system("grep -q '^gre100 fib 1' ifconfig.log") == 0);
	ATF_CHECK(system("grep -q '^gre100 tunnel 192.0.2.1 192.0.2.2' "
	    "ifconfig.log") == 0);
	ATF_CHECK(system("grep -q '^gre101 tunnel 192.0.2.2 192.0.2.1' "
	    "ifconfig.log") == 0);
	ATF_CHECK(system("grep -q '^gre100 inet 100.64.0.0/31 100.64.0.1' "
	    "ifconfig.log") == 0);
	snprintf(t2, sizeof(t2), "grep -q '^gif102 tunnel 10.99.0.1 %s' "
	    "ifconfig.log", laddr);
	ATF_CHECK_MSG(system(t2) == 0, "%s", t2);
	ATF_CHECK(system("grep -q '^lo0 fib 1' ifconfig.log") == 0);
	ATF_CHECK(system("grep -q 'vlan106 create vlan 20 vlandev lo0' "
	    "ifconfig.log") == 0);
	/* The proxy, by the stand-ins: parsed, started in the table. */
	ATF_CHECK(system("grep -q '^squid -k parse -f .*sdwan-proxy-sw1.conf' "
	    "squid.log && grep -q '^setfib -F 1 .*tools/squid -f .*sdwan-proxy-"
	    "sw1.conf' setfib.log") == 0);
	/* Its scanner, c-icap, started in the table before it. */
	ATF_CHECK(system("grep -q '^setfib -F 1 .*tools/c-icap -f .*sdwan-icap-"
	    "sw1.conf' setfib.log") == 0);
	/* The remote end point's wg, by the stand-in: listening, the
	 * identity its peer. */
	ATF_CHECK(system("grep -q '^set wg5 listen-port 51820' wg.log && grep "
	    "-q '^set wg5 peer xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg= "
	    "allowed-ips 10.30.0.2/32' wg.log") == 0);
	/* One IPsec connection for the pair of outer addresses and kind. */
	ATF_CHECK(system("ls swanctl/conf.d/arcana-sdw*.conf | wc -l | grep -q "
	    "'^ *2$'") == 0);
	ATF_CHECK(system("grep -q 'mode = transport' "
	    "swanctl/conf.d/arcana-sdw*.conf") == 0);
	ATF_CHECK(system("grep -q 'dynamic\\[gre\\]' "
	    "swanctl/conf.d/arcana-sdw*.conf") == 0);
	/* The agent probes them from now on (without root, it says so),
	 * and holds the rules in set 30 and their tables. */
	snprintf(body, sizeof(body), FLEET "%s/arcana-probe:probes/state", sa);
	rc_get(body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"id\":\"acme/a-inet-b-inet\"") != NULL &&
	    strstr(r.body, "\"id\":\"acme/a-mpls-b-mpls\"") != NULL, "%s",
	    r.body);
	ATF_CHECK_MSG(jstr(&r, "arcana-probe:state.target.0.state") != NULL,
	    "%s", r.body);
	/* Their measurement intervals (PLAN-SDN-YANG 5.2): the percentiles
	 * they report, the defaults (no interval runs while a target cannot
	 * be probed: here, without root, none can). */
	ATF_CHECK_MSG(jstr(&r, "arcana-probe:state.target.0.pm."
	    "low-percentile") != NULL && strtod(jstr(&r, "arcana-probe:state."
	    "target.0.pm.low-percentile"), NULL) == 10 && jstr(&r,
	    "arcana-probe:state.target.0.pm.intermediate-percentile") != NULL &&
	    strtod(jstr(&r, "arcana-probe:state.target.0.pm."
	    "intermediate-percentile"), NULL) == 50 && jstr(&r, "arcana-probe:"
	    "state.target.0.pm.high-percentile") != NULL && strtod(jstr(&r,
	    "arcana-probe:state.target.0.pm.high-percentile"), NULL) == 90,
	    "%s", r.body);
	resp_free(&r);
	/* What STAMP sees of them (arcana-stamp, PLAN-SDN-YANG 5.1.8): a
	 * session each tunnel's far end, kind auto, the sender's port. */
	snprintf(body, sizeof(body), FLEET "%s/arcana-stamp:stamp", sa);
	rc_get(body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"target\":\"acme/a-inet-b-inet\"") !=
	    NULL && strstr(r.body, "\"kind\":\"auto\"") != NULL && jstr(&r,
	    "arcana-stamp:stamp.sender.port") != NULL && jstr(&r,
	    "arcana-stamp:stamp.session.0.reflector-udp-port") != NULL, "%s",
	    r.body);
	resp_free(&r);
	snprintf(body, sizeof(body), FLEET "%s/arcana-sdwan:sdwan/state", sa);
	rc_get(body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "arcana-sdwan:state.rules.set") != NULL &&
	    strcmp(jstr(&r, "arcana-sdwan:state.rules.set"), "30") == 0, "%s",
	    r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^setfib -F 1 ./fake-local-unbound -c .*sdwan-dns-"
	    "sw1.conf' setfib.log && grep -q '^checkconf .*sdwan-dns-sw1.conf' "
	    "unbound.log") == 0);
	ATF_CHECK(system("grep -q '^setfib -F 1 ./fake-dnsmasq -C .*sdwan-dhcp-sw1"
	    ".conf -x ' setfib.log") == 0);
	/* rtadvd's record by the commit, kept in Arcana's rc.conf file. */
	ATF_CHECK_MSG(system("grep -q 'addr=\"2001:db8:1::\"' rtadvd.conf && "
	    "grep -q 'prefixlen#64' rtadvd.conf && grep -q 'rdnss=\"2001:db8:1::"
	    "1\"' rtadvd.conf && grep -q '^vlan[0-9]*:' rtadvd.conf && grep -q "
	    "'^rtadvd_enable=\"YES\"' root/usr/local/etc/rc.conf.d/arcana") == 0,
	    "no record of the VLAN's in rtadvd.conf, or rtadvd not enabled");
	ATF_CHECK(system("grep -q '^setfib -F 1 .*fake-bird -c .*sdwan-bird-sw1"
	    ".conf -s ' setfib.log") == 0);
	ATF_CHECK(system("grep -q '^server ntp.example.org iburst$' ntp.conf && "
	    "grep -q '^server 10.99.0.9 iburst$' ntp.conf && grep -q "
	    "'^ntpd_enable=\"YES\"' rc.conf") == 0);
	ATF_CHECK(system("grep -q 'add 12 set 30 fwd tablearg tcp from any to "
	    "table(sw1_z0p0_4) dst-port 80,https' ipfw.log") == 0);
	ATF_CHECK(system("grep -q 'ipfw -q set enable 30' ipfw.log") == 0);
	/* Again: nothing to do. */
	r4_read("plan", &r);
	EXPECT(&r, 200);
	ATF_CHECK_EQ(0, changes_of(&r, "make") + changes_of(&r, "remake") +
	    changes_of(&r, "unmake"));
	resp_free(&r);
}

CONSOLE_TC_LONG(sdwan_apply_identities, "SD-WAN's remote identities: issued, "
    "listed, in a group, revoked; the audit trail")
ATF_TC_BODY(sdwan_apply_identities, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16];
	char		doc[8192], lifn[32], laddr[64];

	need_fibs(2);
	sdwan_apply_start(tc, &a, sa, sb, sizeof(sa), doc, sizeof(doc), lifn,
	    sizeof(lifn), laddr, sizeof(laddr));
	sdwan_apply_done();
	/* Identities: one issued for a name, its key pair made
	 * here, the configuration answered once with its address, the
	 * second host after alice's, and the edges applied; listed with
	 * both; revoked, gone and the peer removed; alice past the
	 * remote's re-authorisation has no peer. */
	rc_act(CC "sdwan/issue-identity", "\"swvc\":\"acme\",\"end-point\":"
	    "\"road\",\"name\":\"bob\",\"zone\":\"office\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bob", jstr(&r, "name"));
	ATF_CHECK_MSG(jstr(&r, "config") != NULL && strstr(jstr(&r, "config"),
	    "[Interface]\nPrivateKey = ") != NULL && strstr(jstr(&r, "config"),
	    "\nAddress = 10.30.0.3/24\n") != NULL && strstr(jstr(&r, "config"),
	    "\n[Peer]\nPublicKey = ") != NULL && strstr(jstr(&r, "config"),
	    "\nEndpoint = 192.0.2.1:51820\n") != NULL && strstr(jstr(&r,
	    "config"), "AllowedIPs = 10.1.0.0/24, 10.1.8.0/22, 10.30.0.0/24, "
	    "2001:db8:1::/64\n") != NULL, "%s", r.body);
	ATF_CHECK_STREQ("true", jstr(&r, "applied"));
	ATF_CHECK(strlen(jstr(&r, "public_key")) == 44);
	resp_free(&r);
	sdwan_wait(&r);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^set wg5 peer .* allowed-ips 10.30.0.3/32' "
	    "wg.log") == 0);
	r4_read("identities", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("alice", jstr(&r, "identities.0.name"));
	ATF_CHECK_STREQ("10.30.0.2", jstr(&r, "identities.0.address"));
	ATF_CHECK_STREQ("true", jstr(&r, "identities.0.live"));
	ATF_CHECK_STREQ("carol", jstr(&r, "identities.1.name"));
	ATF_CHECK_STREQ("staff", jstr(&r, "identities.1.group"));
	ATF_CHECK_STREQ("office", jstr(&r, "identities.1.zone"));
	ATF_CHECK_STREQ("10.30.0.64", jstr(&r, "identities.1.address"));
	ATF_CHECK_STREQ("bob", jstr(&r, "identities.2.name"));
	ATF_CHECK_STREQ("10.30.0.3", jstr(&r, "identities.2.address"));
	ATF_CHECK_STREQ("false", jstr(&r, "identities.2.user"));
	/* Its session, as the edge's wg tells its peer (S3.4): the stand-in
	 * keeps the last peer set on an interface. */
	ATF_CHECK_MSG(jstr(&r, "identities.2.session.endpoint") != NULL &&
	    strcmp(jstr(&r, "identities.2.session.endpoint"), "192.0.2.9:51820")
	    == 0 && jstr(&r, "identities.2.session.rx") != NULL, "%s", r.body);
	resp_free(&r);
	/* One issued into a group: the group's zone, an address outside
	 * every pool; a group the remote has not, refused. */
	rc_act(CC "sdwan/issue-identity", "\"swvc\":\"acme\",\"end-point\":"
	    "\"road\",\"name\":\"dave\",\"group\":\"guests\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "config") != NULL && strstr(jstr(&r, "config"),
	    "\nAddress = 10.30.0.4/24\n") != NULL, "%s", r.body);
	resp_free(&r);
	sdwan_wait(&r);
	resp_free(&r);
	r4_read("identities", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("dave", jstr(&r, "identities.3.name"));
	ATF_CHECK_STREQ("guests", jstr(&r, "identities.3.group"));
	ATF_CHECK_STREQ("office", jstr(&r, "identities.3.zone"));
	resp_free(&r);
	rc_act(CC "sdwan/revoke-identity", "\"swvc\":\"acme\",\"end-point\":"
	    "\"road\",\"name\":\"dave\"", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	resp_free(&r);
	rc_act(CC "sdwan/issue-identity", "\"swvc\":\"acme\",\"end-point\":"
	    "\"road\",\"name\":\"erin\",\"group\":\"board\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* A console user: a sign-in key of the name, or none. */
	rc_act(CC "sdwan/issue-identity", "\"swvc\":\"acme\",\"end-point\":"
	    "\"road\",\"name\":\"nobody\",\"zone\":\"office\",\"user\":true",
	    &r);
	EXPECT(&r, 404);
	resp_free(&r);
	rc_act(CC "sdwan/revoke-identity", "\"swvc\":\"acme\",\"end-point\":"
	    "\"road\",\"name\":\"bob\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bob", jstr(&r, "revoked"));
	resp_free(&r);
	sdwan_wait(&r);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^set wg5 peer .* remove' wg.log") == 0);
	r4_read("identities", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("carol", jstr(&r, "identities.1.name"));
	ATF_CHECK(jstr(&r, "identities.2.name") == NULL);
	resp_free(&r);
	rc_act(CC "sdwan/revoke-identity", "\"swvc\":\"acme\",\"end-point\":"
	    "\"road\",\"name\":\"bob\"", &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* The audit trail (MEF 118.1 §13.1): the issue an Allow, the revoke a
	 * Block, the document kept and the apply by the System
	 * Administrator, each with who did it, newest first; the chain
	 * whole.  A line altered on disk, the read says where it broke. */
	r4_read("audit", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(ucl_object_toboolean(ucl_object_lookup(r.json, "intact"))
	    && strcmp(jstr(&r, "events.0.event"), "identity-revoked") == 0 &&
	    strcmp(jstr(&r, "events.0.action"), "Block") == 0 &&
	    strcmp(jstr(&r, "events.0.who"), "key -7") == 0 && strcmp(jstr(&r,
	    "events.0.policy"), "office") == 0 && strstr(jstr(&r,
	    "events.0.where"), "end point road of acme") != NULL && strstr(
	    r.body, "\"event\":\"identity-issued\",\"action\":\"Allow\"") !=
	    NULL && strstr(r.body, "\"event\":\"policies-changed\",\"action\":"
	    "\"Administer\"") != NULL && strstr(r.body, "\"event\":\""
	    "policies-applied\"") != NULL && strstr(r.body, "\"prev\"") == NULL,
	    "%s", r.body);
	resp_free(&r);
	http_with("GET", CC "sdwan/audit", "Accept: text/csv\r\n", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strncmp(r.body, "seq,when,event,action,policy,how,where,"
	    "who,why\n", 45) == 0 && strstr(r.body, ",\"identity-revoked\","
	    "\"Block\",\"office\",") != NULL, "%s", r.body);
	resp_free(&r);
	ATF_REQUIRE(system("sed -i '' '2s/\"Allow\"/\"Block\"/; "
	    "2s/\"Administer\"/\"Allow\"/' data/sdwan-audit.jsonl") == 0);
	r4_read("audit", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(!ucl_object_toboolean(ucl_object_lookup(r.json,
	    "intact")) && ucl_object_toint(ucl_object_lookup(r.json,
	    "broken_at")) == 2, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(system("stat -f %Lp data/sdwan-audit.key | grep -qx 600 && "
	    "stat -f %Lp data/sdwan-audit.jsonl | grep -qx 600") == 0);
}

/* An edge's first policy entry, as arcana-steer's state has it. */
#define	ST	"arcana-steer:state.policy.0."

CONSOLE_TC_LONG(sdwan_apply_steer, "SD-WAN's steering: sent by the manager, "
    "said by the edge, pinned and cleared; the VN view's underlay, an "
    "operator's too")
ATF_TC_BODY(sdwan_apply_steer, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[400], sa[16], sb[16];
	char		doc[8192], lifn[32], laddr[64];
	size_t		i;

	need_fibs(2);
	sdwan_apply_start(tc, &a, sa, sb, sizeof(sa), doc, sizeof(doc), lifn,
	    sizeof(lifn), laddr, sizeof(laddr));
	sdwan_apply_done();
	/* The manager: on its first tick it sends each edge its steering,
	 * and says what it sent; branch's web flows reach hq's prefixes by
	 * the encrypted public tunnel (the private one is a backup). */
	for (i = 0; i < 60; i++) {
		r4_read("steering", &r);
		EXPECT(&r, 200);
		snprintf(body, sizeof(body), "sent.%s.entries.0.prefix", sb);
		if (jstr(&r, body) != NULL)
			break;
		resp_free(&r);
		usleep(300000);
	}
	ATF_REQUIRE_MSG(i < 60, "the manager sent nothing");
	ATF_CHECK_STREQ("10.1.0.0/24", jstr(&r, body));
	snprintf(body, sizeof(body), "sent.%s.entries.0.candidates.0.id", sb);
	ATF_CHECK_STREQ("acme/a-inet-b-inet", jstr(&r, body));
	snprintf(body, sizeof(body), "sent.%s.entries.0.policy", sb);
	ATF_CHECK_STREQ("fast", jstr(&r, body));
	resp_free(&r);
	/*
	 * arcana-steer: the edge says why each choice is what it is, in
	 * its read and as the manager last read it; the console's pin is
	 * in the edge's read at once, one of no candidate refused, and
	 * cleared, the policy's order is again.
	 */
	{
		char	tbl[64], pfx[64], c1[96], pin[400];

		snprintf(body, sizeof(body), FLEET "%s/arcana-steer:steering/"
		    "state", sb);
		rc_get(body, &r);
		EXPECT(&r, 200);
		ATF_REQUIRE_MSG(jstr(&r, ST "table") != NULL, "%s", r.body);
		snprintf(tbl, sizeof(tbl), "%s", jstr(&r, ST "table"));
		snprintf(pfx, sizeof(pfx), "%s", jstr(&r, ST "prefix"));
		ATF_REQUIRE_MSG(jstr(&r, ST "candidate.0.id") != NULL, "%s",
		    r.body);
		snprintf(c1, sizeof(c1), "%s", jstr(&r, ST "candidate.0.id"));
		ATF_CHECK_STREQ("preference", jstr(&r, ST "reason"));
		ATF_CHECK(jstr(&r, ST "since") != NULL);
		resp_free(&r);
		for (i = 0; i < 60; i++) {
			r4_read("steering", &r);
			EXPECT(&r, 200);
			snprintf(pin, sizeof(pin), "live.%s.steer.0.reason",
			    sb);
			if (jstr(&r, pin) != NULL)
				break;
			resp_free(&r);
			usleep(300000);
		}
		ATF_REQUIRE_MSG(i < 60, "the manager read no steering");
		ATF_CHECK_STREQ("preference", jstr(&r, pin));
		resp_free(&r);
		snprintf(pin, sizeof(pin), "\"edge\":\"%s\",\"table\":\"%s\","
		    "\"prefix\":\"%s\",\"candidate\":\"%s\"", sb, tbl, pfx, c1);
		rc_act(CC "sdwan/pin", pin, &r);
		EXPECT(&r, 200);
		resp_free(&r);
		rc_get(body, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("override", jstr(&r, ST "reason"));
		ATF_CHECK_STREQ(c1, jstr(&r, ST "pinned"));
		ATF_CHECK_STREQ(c1, jstr(&r, ST "chosen"));
		resp_free(&r);
		snprintf(pin, sizeof(pin), "\"edge\":\"%s\",\"table\":\"%s\","
		    "\"prefix\":\"%s\",\"candidate\":\"acme/nowhere\"", sb, tbl,
		    pfx);
		rc_act(CC "sdwan/pin", pin, &r);
		ATF_CHECK_MSG(r.status == 409 && strstr(r.body,
		    "acme/nowhere is no candidate") != NULL, "%s", r.body);
		resp_free(&r);
		snprintf(pin, sizeof(pin), "\"edge\":\"%s\",\"table\":\"%s\","
		    "\"prefix\":\"%s\"", sb, tbl, pfx);
		rc_act(CC "sdwan/pin", pin, &r);
		EXPECT(&r, 200);
		resp_free(&r);
		rc_get(body, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("preference", jstr(&r, ST "reason"));
		ATF_CHECK(jstr(&r, ST "pinned") == NULL);
		ATF_CHECK_STREQ(c1, jstr(&r, ST "chosen"));
		resp_free(&r);
		ATF_CHECK(system("grep -q 'steering-pinned' data/audit.log") ==
		    0 || system("grep -rq 'steering-pinned' data") == 0);
	}
	/*
	 * The VN view's underlay (PLAN-SDN-YANG 4.7.2): hq to branch by the
	 * plan's two tunnels, each with its ends; the steering read through
	 * the fleet mount, the one in use selected, the member's
	 * oper-status what the probes say.
	 */
	{
		char	tp[200], u[128];
		int	k, inet = -1;

		snprintf(tp, sizeof(tp), "/restconf/data/ietf-vn:virtual-network/"
		    "vn=acme/vn-member=%s%%3Ahq~%s%%3Abranch", sa, sb);
		http("GET", tp, NULL, &r);
		EXPECT(&r, 200);
		for (k = 0; k < 2; k++) {
			snprintf(u, sizeof(u), "ietf-vn:vn-member.0.underlay."
			    "arcana-sdwan-underlay:sdwan.tunnel.%d.", k);
			snprintf(tp, sizeof(tp), "%sid", u);
			if (jstr(&r, tp) != NULL && strcmp(jstr(&r, tp),
			    "acme/a-inet-b-inet") == 0)
				inet = k;
		}
		ATF_REQUIRE_MSG(inet >= 0, "%s", r.body);
		snprintf(u, sizeof(u), "ietf-vn:vn-member.0.underlay."
		    "arcana-sdwan-underlay:sdwan.tunnel.%d.", inet);
		snprintf(tp, sizeof(tp), "%sencapsulation", u);
		ATF_CHECK_STREQ("gre", jstr(&r, tp));
		snprintf(tp, sizeof(tp), "%sipsec", u);
		ATF_CHECK_STREQ("true", jstr(&r, tp));
		snprintf(tp, sizeof(tp), "%ssrc.edge", u);
		ATF_CHECK_STREQ(sa, jstr(&r, tp));
		snprintf(tp, sizeof(tp), "%ssrc.outer-address", u);
		ATF_CHECK_STREQ("192.0.2.1", jstr(&r, tp));
		snprintf(tp, sizeof(tp), "%sdest.edge", u);
		ATF_CHECK_STREQ(sb, jstr(&r, tp));
		snprintf(tp, sizeof(tp), "%sdest.inner-ipv4", u);
		ATF_CHECK(jstr(&r, tp) != NULL);
		snprintf(tp, sizeof(tp), "%sselected", u);
		ATF_CHECK_STREQ("true", jstr(&r, tp));
		snprintf(tp, sizeof(tp), "%sstate", u);
		ATF_CHECK_MSG(jstr(&r, tp) != NULL, "%s", r.body);
		ATF_CHECK_MSG(jstr(&r, "ietf-vn:vn-member.0.oper-status") !=
		    NULL, "%s", r.body);
		ATF_CHECK(jstr(&r, "ietf-vn:vn-member.0.if-selected") == NULL);
		resp_free(&r);
	}
	/*
	 * An operator of no host: the plan's tunnels shown, no edge's
	 * steering read for him, so no tunnel's state nor selection and
	 * no oper-status.
	 */
	{
		struct authn	o;
		char		tp[200], u[128], inv[128], keep[sizeof(cookie)];
		int		k;

		http("PUT", CC "roles/role=a-op", "{\"arcana-console:role\":[{"
		    "\"name\":\"a-op\",\"console\":\"operator\"}]}", &r);
		EXPECT(&r, 201);
		resp_free(&r);
		http("PUT", CC "users/user=dave", "{\"arcana-console:user\":[{"
		    "\"name\":\"dave\",\"role\":[\"a-op\"]}]}", &r);
		EXPECT(&r, 201);
		resp_free(&r);
		http("POST", CC "users/user=dave/invite", NULL, &r);
		EXPECT(&r, 200);
		snprintf(inv, sizeof(inv), "%s", jstr(&r,
		    "arcana-console:output.token"));
		resp_free(&r);
		memcpy(keep, cookie, sizeof(keep));
		cookie[0] = '\0';
		authn_new(&o, -7);
		do_register(&o, inv, &r);
		EXPECT(&r, 200);
		resp_free(&r);
		snprintf(tp, sizeof(tp), "/restconf/data/ietf-vn:virtual-network/"
		    "vn=acme/vn-member=%s%%3Ahq~%s%%3Abranch", sa, sb);
		http("GET", tp, NULL, &r);
		EXPECT(&r, 200);
		for (k = 0; k < 2; k++) {
			snprintf(u, sizeof(u), "ietf-vn:vn-member.0.underlay."
			    "arcana-sdwan-underlay:sdwan.tunnel.%d.", k);
			snprintf(tp, sizeof(tp), "%sid", u);
			ATF_CHECK_MSG(jstr(&r, tp) != NULL, "%s", r.body);
			snprintf(tp, sizeof(tp), "%sselected", u);
			ATF_CHECK_MSG(jstr(&r, tp) == NULL, "%s", r.body);
			snprintf(tp, sizeof(tp), "%sstate", u);
			ATF_CHECK_MSG(jstr(&r, tp) == NULL, "%s", r.body);
		}
		ATF_CHECK_MSG(jstr(&r, "ietf-vn:vn-member.0.oper-status") ==
		    NULL, "%s", r.body);
		resp_free(&r);
		memcpy(cookie, keep, sizeof(cookie));
	}
}

#undef	ST

/*
 * The services' performance view (PLAN-SDN-YANG 5.3.1, RFC 9375):
 * networks arcana:underlay and arcana:vpn:<vpn-id> beside the SAP
 * network, in the shape of RFC 9375 Appendix A.2 and A.3, made of the
 * plan's tunnels and what the agent measured.
 */

/* Entry key=id of list member l of o; NULL: none. */
static const ucl_object_t *
pm_entry(const ucl_object_t *o, const char *l, const char *key,
    const char *id)
{
	const ucl_object_t	*e, *k;
	ucl_object_iter_t	 it = NULL;

	while ((e = ucl_object_iterate(ucl_object_lookup(o, l), &it, true)) !=
	    NULL)
		if ((k = ucl_object_lookup(e, key)) != NULL &&
		    strcmp(ucl_object_tostring_forced(k), id) == 0)
			return (e);
	return (NULL);
}

static const char *
pm_str(const ucl_object_t *o, const char *path)
{
	const ucl_object_t	*v;

	if (o == NULL || (v = ucl_object_lookup_path(o, path)) == NULL)
		return (NULL);
	return (ucl_object_tostring_forced(v));
}

/* Whether RFC 9375's statistics s (delay or jitter, what) are interval
 * figures f's (min, max, the three percentiles, microseconds). */
static bool
pm_same(const ucl_object_t *s, const char *what, const ucl_object_t *f,
    char *why, size_t len)
{
	static const char *const lv[] = { "low", "intermediate", "high" };
	char	k[64], fk[64];

	if (s == NULL || f == NULL) {
		snprintf(why, len, "%s: none", what);
		return (false);
	}
	if (pm_str(s, "unit-value") == NULL || strcmp(pm_str(s, "unit-value"),
	    "ietf-lime-time-types:microseconds") != 0) {
		snprintf(why, len, "%s: unit %s", what, pm_str(s, "unit-value"));
		return (false);
	}
	snprintf(k, sizeof(k), "min-%s-value", what);
	if (pm_str(s, k) == NULL || pm_str(f, "min") == NULL ||
	    strcmp(pm_str(s, k), pm_str(f, "min")) != 0) {
		snprintf(why, len, "%s %s != %s", k, pm_str(s, k), pm_str(f,
		    "min"));
		return (false);
	}
	snprintf(k, sizeof(k), "max-%s-value", what);
	if (pm_str(s, k) == NULL || strcmp(pm_str(s, k), pm_str(f, "max")) !=
	    0) {
		snprintf(why, len, "%s %s", k, pm_str(s, k));
		return (false);
	}
	for (size_t i = 0; i < nitems(lv); i++) {
		snprintf(k, sizeof(k), "%s-%s-percentile", lv[i], what);
		snprintf(fk, sizeof(fk), "%s-percentile", lv[i]);
		if (pm_str(s, k) == NULL || pm_str(f, fk) == NULL ||
		    strcmp(pm_str(s, k), pm_str(f, fk)) != 0) {
			snprintf(why, len, "%s %s != %s", k, pm_str(s, k),
			    pm_str(f, fk));
			return (false);
		}
	}
	return (true);
}

CONSOLE_TC(sdwan_vpn_pm, "The services' performance view (RFC 9375): the "
    "underlay and a network a service in ietf-network:networks, two links "
    "a tunnel, each one's pm of the agent's last completed measurement "
    "interval (the percentiles and length the service sets, a class's "
    "own), in the shape of RFC 9375's examples, valid by yanglint")
ATF_TC_BODY(sdwan_vpn_pm, tc)
{
	struct authn		 a;
	struct resp		 r, st;
	const ucl_object_t	*nw, *un, *n, *l, *pa, *t, *iv, *c, *cs;
	const char		*sd, *start;
	char			 sa[16], sb[16], doc[8192], t1[8192], lifn[32];
	char			 laddr[64], path[512], cand[256], data[256];
	char			 port[16], why[200], lid[256], *json;
	char			 ea[64], eb[64];
	char			*argv[12];
	FILE			*fp;
	int			 i, p;

	/* Under MAKEOBJDIRPREFIX, or in the submodule's own obj/. */
	sd = locate(tc, "../../../stamp/usr.sbin/stampd/stampd", "stampd",
	    "/usr/local/sbin/stampd");
	if (access(sd, X_OK) != 0)
		sd = locate(tc, "../../../../stamp/obj/usr.sbin/stampd/stampd",
		    "stampd", "/usr/local/sbin/stampd");
	if (sd == NULL || access(sd, X_OK) != 0)
		atf_tc_skip("no stampd (the submodule stamp/)");
	/* A stampd of the test's on the loopback, the agent's far end. */
	p = 20000 + (int)arc4random_uniform(40000);
	snprintf(port, sizeof(port), "%d", p);
	argv[0] = __DECONST(char *, sd);
	argv[1] = __DECONST(char *, "-d");
	argv[2] = __DECONST(char *, "-r");
	argv[3] = __DECONST(char *, "0");
	argv[4] = __DECONST(char *, "-R");
	argv[5] = __DECONST(char *, "0");
	argv[6] = __DECONST(char *, "-p");
	argv[7] = port;
	argv[8] = NULL;
	(void)spawn(argv, "stampd.out");
	for (i = 0; i < 100 && system("grep -q started stampd.out") != 0; i++)
		usleep(50000);
	ATF_REQUIRE_MSG(i < 100, "stampd did not start");
	harness_stamp_port = p;

	/* The service: its probes' percentiles, a measurement interval of
	 * 2 s, and a class of service. */
	sdwan_apply_start(tc, &a, sa, sb, sizeof(sa), doc, sizeof(doc), lifn,
	    sizeof(lifn), laddr, sizeof(laddr));
	ATF_REQUIRE(swap_in(doc, "\"bfd\":{\"interval\":200,\"multiplier\":3},",
	    "\"bfd\":{\"interval\":200,\"multiplier\":3},\"probe\":{"
	    "\"low_percentile\":25,\"measurement_interval\":2,\"classes\":[{"
	    "\"name\":\"voice\",\"dscp\":46}]},", t1, sizeof(t1)));
	ATF_REQUIRE(swap_in(t1, "\"version\":0,", "\"version\":1,", doc,
	    sizeof(doc)));
	r4_keep(doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);

	/* Nothing measured yet: the networks, their links without pm. */
	http("GET", "/restconf/data/ietf-network:networks", NULL, &r);
	EXPECT(&r, 200);
	nw = ucl_object_lookup(r.json, "ietf-network:networks");
	ATF_REQUIRE_MSG(pm_entry(nw, "network", "network-id",
	    "arcana-physical") != NULL && pm_entry(nw, "network", "network-id",
	    "arcana-sap") != NULL && pm_entry(nw, "network", "network-id",
	    "arcana:underlay") != NULL && (n = pm_entry(nw, "network",
	    "network-id", "arcana:vpn:acme")) != NULL, "%s", r.body);
	snprintf(lid, sizeof(lid), "arcana:tunnel:acme/a-inet-b-inet,a-inet,"
	    "b-inet");
	snprintf(ea, sizeof(ea), "arcana:edge:%s", sa);
	snprintf(eb, sizeof(eb), "arcana:edge:%s", sb);
	l = pm_entry(n, "ietf-network-topology:link", "link-id", lid);
	ATF_REQUIRE_MSG(l != NULL, "%s", r.body);
	ATF_CHECK_MSG(pm_str(l, "ietf-network-vpn-pm:perf-mon.pm") == NULL,
	    "%s", r.body);
	resp_free(&r);

	/*
	 * Each tunnel's target at the agent as the apply would make it, by
	 * STAMP to the test's stampd, with the service's settings.
	 */
	snprintf(data, sizeof(data), FLEET "%s", sa);
	snprintf(cand, sizeof(cand), "/restconf/ds/ietf-datastores:candidate/"
	    "arcana-fleet:fleet/host=%s", sa);
	snprintf(path, sizeof(path), "%s/arcana-probe:probes", cand);
	http("PUT", path, "{\"arcana-probe:probes\":{\"target\":["
	    "{\"id\":\"acme/a-inet-b-inet\",\"address\":\"127.0.0.1\","
	    "\"kind\":\"stamp\",\"interval\":20,\"timeout\":300,"
	    "\"low-percentile\":\"25\",\"measurement-interval\":2,"
	    "\"class\":[{\"name\":\"voice\",\"dscp\":46}]},"
	    "{\"id\":\"acme/a-mpls-b-mpls\",\"address\":\"127.0.0.1\","
	    "\"kind\":\"stamp\",\"interval\":20,\"timeout\":300,"
	    "\"low-percentile\":\"25\",\"measurement-interval\":2}]}}", &r);
	ATF_REQUIRE_MSG(r.status == 201 || r.status == 204, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	rc_expect("POST", data, "/ietf-netconf:commit", NULL, "{}", 204, NULL);

	/* Until an interval of 2 s has ended and is in the view. */
	snprintf(path, sizeof(path), "/restconf/data/ietf-network:networks/"
	    "network=arcana:vpn:acme");
	for (i = 0; i < 100; i++) {
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		n = ucl_array_find_index(ucl_object_lookup(r.json,
		    "ietf-network:network"), 0);
		l = pm_entry(n, "ietf-network-topology:link", "link-id", lid);
		if (pm_str(l, "ietf-network-vpn-pm:perf-mon.pm") != NULL &&
		    (c = ucl_array_find_index(ucl_object_lookup_path(l,
		    "ietf-network-vpn-pm:perf-mon.pm.0.pm-attributes."
		    "one-way-pm-statistics-per-class"), 0)) != NULL)
			break;
		resp_free(&r);
		usleep(200000);
	}
	ATF_REQUIRE_MSG(i < 100, "no interval in the view: %s", r.body);

	/* RFC 9375 Appendix A.2's shape: the service, its nodes PEs. */
	ATF_CHECK_STREQ("arcana:vpn:acme", pm_str(n, "network-id"));
	ATF_CHECK_STREQ("acme", pm_str(n, "network-types."
	    "ietf-network-vpn-pm:service.vpn-id"));
	ATF_CHECK_STREQ("ietf-vpn-common:l3vpn", pm_str(n, "network-types."
	    "ietf-network-vpn-pm:service.service-type"));
	ATF_CHECK(pm_str(n, "network-types.ietf-network-vpn-pm:service."
	    "vpn-service-topology") != NULL);
	ATF_CHECK_STREQ("arcana:underlay", pm_str(n,
	    "supporting-network.0.network-ref"));
	for (i = 0; i < 2; i++) {
		t = pm_entry(n, "node", "node-id", i == 0 ? ea : eb);
		ATF_CHECK_MSG(t != NULL && strcmp(pm_str(t,
		    "ietf-network-vpn-pm:node-type"), "ietf-network-vpn-pm:pe") ==
		    0 && pm_str(t, "ietf-network-vpn-pm:role") != NULL &&
		    strcmp(pm_str(t, "supporting-node.0.network-ref"),
		    "arcana:underlay") == 0 && pm_str(t,
		    "ietf-network-topology:termination-point.1.tp-id") != NULL,
		    "%s", r.body);
	}
	/* Two links a tunnel (inet's, mpls', the control plane's), one
	 * each way, each over the underlay's. */
	ATF_CHECK_EQ(6, (int)ucl_array_size(ucl_object_lookup(n,
	    "ietf-network-topology:link")));
	ATF_CHECK_STREQ(ea, pm_str(l, "source.source-node"));
	ATF_CHECK_STREQ(eb, pm_str(l, "destination.dest-node"));
	ATF_CHECK_MSG(pm_str(l, "source.source-tp") != NULL && strncmp(pm_str(
	    l, "source.source-tp"), "arcana:if:gre", 13) == 0, "%s", r.body);
	ATF_CHECK_STREQ("arcana:underlay:a-inet,b-inet", pm_str(l,
	    "supporting-link.0.link-ref"));
	t = pm_entry(n, "ietf-network-topology:link", "link-id",
	    "arcana:tunnel:acme/a-inet-b-inet,b-inet,a-inet");
	ATF_CHECK_MSG(t != NULL && strcmp(pm_str(t, "source.source-node"), eb) ==
	    0 && strcmp(pm_str(t, "destination.dest-node"), ea) == 0, "%s",
	    r.body);
	t = pm_entry(n, "ietf-network-topology:link", "link-id",
	    "arcana:tunnel:acme/a-mpls-b-mpls,a-mpls,b-mpls");
	ATF_CHECK_STREQ("ietf-vpn-common:ip-in-ip", pm_str(t,
	    "ietf-network-vpn-pm:perf-mon.vpn-pm-type.vpn-tunnel."
	    "vpn-tunnel-type"));
	/* A.3's: the percentiles the service set, Arcana's high 90. */
	ATF_CHECK_STREQ("25.000", pm_str(l, "ietf-network-vpn-pm:perf-mon."
	    "low-percentile"));
	ATF_CHECK_STREQ("50.000", pm_str(l, "ietf-network-vpn-pm:perf-mon."
	    "intermediate-percentile"));
	ATF_CHECK_STREQ("90.000", pm_str(l, "ietf-network-vpn-pm:perf-mon."
	    "high-percentile"));
	ATF_CHECK_STREQ("2", pm_str(l, "ietf-network-vpn-pm:perf-mon."
	    "measurement-interval"));
	ATF_CHECK_STREQ("ietf-network-vpn-pm:pm-type-vpn-tunnel", pm_str(l,
	    "ietf-network-vpn-pm:perf-mon.pm.0.pm-type"));
	ATF_CHECK_STREQ("ietf-vpn-common:gre", pm_str(l,
	    "ietf-network-vpn-pm:perf-mon.vpn-pm-type.vpn-tunnel."
	    "vpn-tunnel-type"));
	pa = ucl_object_lookup_path(l, "ietf-network-vpn-pm:perf-mon.pm.0."
	    "pm-attributes");
	ATF_CHECK_STREQ("ietf-network-vpn-pm:pm-source-stamp", pm_str(pa,
	    "pm-source"));
	ATF_REQUIRE((start = pm_str(pa, "start-time")) != NULL);
	ATF_CHECK(pm_str(pa, "end-time") != NULL);
	ATF_CHECK_STREQ("voice", pm_str(c, "class-id"));
	ATF_CHECK_STREQ("46", pm_str(c, "arcana-network-vpn-pm:dscp"));

	/*
	 * The values mapped: the agent's interval of that start, the
	 * one-way figures its forward direction's (where the reflector's
	 * clock allowed one way), the round trip the augment's.
	 */
	snprintf(path, sizeof(path), FLEET "%s/arcana-probe:probes/state", sa);
	rc_get(path, &st);
	EXPECT(&st, 200);
	t = pm_entry(ucl_object_lookup_path(st.json, "arcana-probe:state"),
	    "target", "id", "acme/a-inet-b-inet");
	iv = pm_entry(ucl_object_lookup_path(t, "pm"), "interval", "start",
	    start);
	ATF_REQUIRE_MSG(iv != NULL, "no interval %s: %s", start, st.body);
	ATF_CHECK_STREQ("true", pm_str(iv, "complete"));
	ATF_CHECK_MSG(pm_same(ucl_object_lookup_path(pa, "arcana-network-vpn-pm:"
	    "round-trip-pm-statistics.delay-statistics"), "delay",
	    ucl_object_lookup(iv, "round-trip"), why, sizeof(why)), "round "
	    "trip: %s", why);
	ATF_CHECK_STREQ(pm_str(iv, "loss.count"), pm_str(pa,
	    "arcana-network-vpn-pm:round-trip-pm-statistics.loss-statistics."
	    "packet-loss-count"));
	if (pm_str(iv, "forward.count") != NULL && atoi(pm_str(iv,
	    "forward.count")) > 0) {
		ATF_CHECK_STREQ("source", pm_str(pa,
		    "arcana-network-vpn-pm:one-way-measured-at"));
		ATF_CHECK_MSG(pm_same(ucl_object_lookup_path(pa,
		    "one-way-pm-statistics.delay-statistics"), "delay",
		    ucl_object_lookup(iv, "forward"), why, sizeof(why)),
		    "one way: %s", why);
		ATF_CHECK_MSG(pm_same(ucl_object_lookup_path(pa,
		    "one-way-pm-statistics.jitter-statistics"), "jitter",
		    ucl_object_lookup_path(iv, "jitter.forward"), why,
		    sizeof(why)), "one way's jitter: %s", why);
		ATF_CHECK_STREQ(pm_str(iv, "loss.forward-count"), pm_str(pa,
		    "one-way-pm-statistics.loss-statistics.packet-loss-count"));
	} else
		ATF_CHECK_MSG(pm_str(pa, "one-way-pm-statistics") == NULL,
		    "one way where the agent has none: %s", r.body);
	/* The class's own session. */
	cs = NULL;
	{
		const ucl_object_t	*e;
		ucl_object_iter_t	 it = NULL;

		while ((e = ucl_object_iterate(ucl_object_lookup_path(st.json,
		    "arcana-probe:state.target"), &it, true)) != NULL)
			if (pm_str(e, "class") != NULL && strcmp(pm_str(e,
			    "class"), "voice") == 0 && strcmp(pm_str(e, "id"),
			    "acme/a-inet-b-inet") == 0)
				cs = e;
	}
	iv = pm_entry(ucl_object_lookup(cs, "pm"), "interval", "start", start);
	if (iv != NULL)
		ATF_CHECK_MSG(pm_same(ucl_object_lookup_path(c,
		    "arcana-network-vpn-pm:round-trip-pm-statistics."
		    "delay-statistics"), "delay", ucl_object_lookup(iv,
		    "round-trip"), why, sizeof(why)), "voice's round trip: %s",
		    why);
	resp_free(&st);

	/* The underlay: no service, the edges, a link each way between two
	 * UCS End Points. */
	http("GET", "/restconf/data/ietf-network:networks/"
	    "network=arcana:underlay", NULL, &st);
	EXPECT(&st, 200);
	un = ucl_array_find_index(ucl_object_lookup(st.json,
	    "ietf-network:network"), 0);
	ATF_CHECK(pm_str(un, "network-types.ietf-network-vpn-pm:service") ==
	    NULL);
	t = pm_entry(un, "node", "node-id", ea);
	ATF_CHECK_MSG(t != NULL && pm_entry(t,
	    "ietf-network-topology:termination-point", "tp-id",
	    "arcana:ucs-ep:a-inet") != NULL && pm_entry(t,
	    "ietf-network-topology:termination-point", "tp-id",
	    "arcana:ucs-ep:a-mpls") != NULL, "%s", st.body);
	ATF_CHECK_MSG(pm_entry(un, "ietf-network-topology:link", "link-id",
	    "arcana:underlay:a-inet,b-inet") != NULL && pm_entry(un,
	    "ietf-network-topology:link", "link-id",
	    "arcana:underlay:b-mpls,a-mpls") != NULL, "%s", st.body);

	/* Valid by libyang too: both networks, the modules as published. */
	if (access("/usr/local/bin/yanglint", X_OK) == 0) {
		ucl_object_t	*top, *nws, *list;

		list = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(list, ucl_object_copy(un));
		ucl_array_append(list, ucl_object_copy(n));
		nws = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(nws, list, "network", 0, false);
		top = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(top, nws, "ietf-network:networks", 0,
		    false);
		json = (char *)ucl_object_emit(top, UCL_EMIT_JSON);
		ucl_object_unref(top);
		ATF_REQUIRE((fp = fopen("vpnpm.json", "w")) != NULL);
		fputs(json, fp);
		fclose(fp);
		free(json);
		snprintf(path, sizeof(path), "cd %s/../../../share/yang && "
		    "/usr/local/bin/yanglint -i -t get -f json "
		    "-F ietf-vpn-common:'*' ietf-network-vpn-pm@2023-03-20.yang "
		    "arcana-network-vpn-pm@2026-11-10.yang \"$OLDPWD/vpnpm.json\" "
		    "> \"$OLDPWD/yanglint.out\" 2>&1", TESTSRC);
		if (system(path) != 0)
			show("yanglint.out");
		ATF_CHECK_MSG(system(path) == 0, "yanglint refused the view");
	}
	resp_free(&st);
	resp_free(&r);
}

CONSOLE_TC_LONG(sdwan_apply_change, "SD-WAN changed on the edges: the MPLS no "
    "longer the service's, its tunnel taken away")
ATF_TC_BODY(sdwan_apply_change, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16];
	char		doc[8192], t1[8192], lifn[32], laddr[64];

	need_fibs(2);
	sdwan_apply_start(tc, &a, sa, sb, sizeof(sa), doc, sizeof(doc), lifn,
	    sizeof(lifn), laddr, sizeof(laddr));
	sdwan_apply_done();
	/* The MPLS no longer the service's: its tunnel taken away. */
	ATF_REQUIRE(swap_in(doc, "\"ucs\":[\"inet\",\"mpls\"]",
	    "\"ucs\":[\"inet\"]", t1, sizeof(t1)));
	snprintf(doc, sizeof(doc), "%s", t1);
	ATF_REQUIRE(swap_in(doc, "\"version\":0", "\"version\":1", t1,
	    sizeof(t1)));
	r4_keep(t1, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	r4_read("plan", &r);
	EXPECT(&r, 200);
	/* Its two ends, and the pairs of its authenticated STAMP (a plain
	 * gif's, PLAN-SDN-YANG 5.1.7). */
	ATF_CHECK_EQ_MSG(4, changes_of(&r, "unmake"), "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"stampkey:") != NULL, "%s",
	    r.body);
	ATF_CHECK_EQ(2, (int)ucl_array_size(ucl_object_lookup(r.json,
	    "tunnels")));
	resp_free(&r);
	http("POST", CC "sdwan/apply", accepting(false), &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "done") == 0, "%s",
	    r.body);
	/* The tunnels taken away by their device edits (the stand-in's
	 * made none the kernel has, so nothing there to destroy). */
	ATF_CHECK_MSG(strstr(r.body, "\"method\":\"DELETE\",\"path\":\"ietf-"
	    "interfaces:interfaces/interface=gif102\"") != NULL && strstr(r.body,
	    "\"method\":\"DELETE\",\"path\":\"ietf-interfaces:interfaces/"
	    "interface=gif103\"") != NULL, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(system("! grep -q '\"units\":\\[102' data/sdwan-state.json") ==
	    0);
}

/*
 * A Security form (the page's) as arcana-sdwan's sec- instance, made as
 * the page makes it (sdread.c's proxy_one(), ids_one()), unchecked:
 * the forms' checks are the page's; host the host's name.
 */
static ucl_object_t *
r4_sec_one(const ucl_object_t *in, bool ids, const char *host)
{
	const ucl_object_t	*e, *v;
	ucl_object_iter_t	 it;
	ucl_object_t		*o, *ifs, *lua, *l;
	const char		*s, *colon;
	char			*spec, a[24];

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_copy(ucl_object_lookup(in,
	    "name")), "name", 0, false);
	if (!ids) {
		v = ucl_object_lookup(in, "fib");
		ucl_object_insert_key(o, ucl_object_fromint(v != NULL ?
		    ucl_object_toint(v) : 0), "fib", 0, false);
		v = ucl_object_lookup(in, "mode");
		ucl_object_insert_key(o, ucl_object_fromstring(v != NULL ?
		    ucl_object_tostring(v) : "sni"), "mode", 0, false);
	} else {
		ifs = ucl_object_typed_new(UCL_ARRAY);
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(in,
		    "interfaces"), &it, true)) != NULL)
			ucl_array_append(ifs, ucl_object_copy(e));
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(in, "pairs"),
		    &it, true)) != NULL) {
			s = ucl_object_tostring(e);
			if ((colon = strchr(s, ':')) == NULL)
				continue;
			snprintf(a, sizeof(a), "%.*s", (int)(colon - s), s);
			ucl_array_append(ifs, ucl_object_fromstring(a));
			ucl_array_append(ifs, ucl_object_fromstring(colon + 1));
		}
		if (ucl_array_size(ifs) > 0)
			ucl_object_insert_key(o, ifs, "interface", 0, false);
		else
			ucl_object_unref(ifs);
		if ((v = ucl_object_lookup(in, "rules")) != NULL)
			ucl_object_insert_key(o, ucl_object_copy(v), "rules", 0,
			    false);
		if ((v = ucl_object_lookup(in, "divert")) != NULL &&
		    ucl_object_toint(v) > 0)
			ucl_object_insert_key(o, ucl_object_copy(v), "divert", 0,
			    false);
		if ((v = ucl_object_lookup(in, "capture")) != NULL &&
		    strcmp(ucl_object_tostring(v), "netmap") == 0)
			ucl_object_insert_key(o, ucl_object_copy(v), "capture",
			    0, false);
		if (ucl_object_toboolean(ucl_object_lookup(in, "offload_off")))
			ucl_object_insert_key(o, ucl_object_frombool(false),
			    "offload", 0, false);
		if ((v = ucl_object_lookup(in, "lua")) != NULL) {
			lua = ucl_object_typed_new(UCL_ARRAY);
			it = NULL;
			while ((e = ucl_object_iterate(v, &it, true)) != NULL) {
				l = ucl_object_typed_new(UCL_OBJECT);
				ucl_object_insert_key(l, ucl_object_fromstring(
				    ucl_object_key(e)), "name", 0, false);
				ucl_object_insert_key(l, ucl_object_copy(e),
				    "text", 0, false);
				ucl_array_append(lua, l);
			}
			ucl_object_insert_key(o, lua, "lua", 0, false);
		}
		if ((v = ucl_object_lookup(in, "plugins")) != NULL)
			ucl_object_insert_key(o, ucl_object_copy(v), "plugin", 0,
			    false);
		if ((v = ucl_object_lookup(in, "thresholds")) != NULL)
			ucl_object_insert_key(o, ucl_object_copy(v),
			    "thresholds", 0, false);
	}
	ucl_object_insert_key(o, ucl_object_fromstring(host), "host", 0,
	    false);
	if (ucl_object_toboolean(ucl_object_lookup(in, "stopped")))
		ucl_object_insert_key(o, ucl_object_frombool(true), "stopped", 0,
		    false);
	spec = (char *)ucl_object_emit(in, UCL_EMIT_JSON_COMPACT);
	ucl_object_insert_key(o, ucl_object_fromstring(spec), "spec", 0,
	    false);
	free(spec);
	return (o);
}

/*
 * The Security section's forms saved at host sid (named host) as the
 * page saves them (sdread.c's security_ysave()): form {"what": "proxy"
 * or "ids", "instances": [...]}, its instances put among running's
 * arcana-sdwan beside SD-WAN's, the whole into the candidate and
 * committed; the same as running has, the part set again by apply.
 * The last answer in r: 204 or 200 saved, else the host's refusal.
 */
static void
r4_sec(const char *sid, const char *host, const char *form,
    struct resp *r)
{
	struct ucl_parser	*p;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	ucl_object_t		*f, *sd, *was, *arr, *top;
	char			 path[300], in[96], *json;
	const char		*key;
	bool			 ids;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
	ATF_REQUIRE(ucl_parser_add_string(p, form, 0));
	f = ucl_parser_get_object(p);
	ucl_parser_free(p);
	ids = strcmp(ucl_object_tostring(ucl_object_lookup(f, "what")),
	    "ids") == 0;
	key = ids ? "ids-instance" : "proxy-instance";
	snprintf(path, sizeof(path), "/restconf/ds/ietf-datastores:running/"
	    "arcana-fleet:fleet/host=%s/arcana-sdwan:sdwan", sid);
	rc_get(path, r);
	ATF_REQUIRE_MSG(r->status == 200 || r->status == 404, "%d %s",
	    r->status, r->body);
	v = r->status == 200 ? ucl_object_lookup(r->json,
	    "arcana-sdwan:sdwan") : NULL;
	sd = v != NULL ? ucl_object_copy(v) : ucl_object_typed_new(UCL_OBJECT);
	resp_free(r);
	was = ucl_object_copy(sd);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(ucl_object_lookup(was, key), &it,
	    true)) != NULL)
		if (strncmp(ucl_object_tostring_forced(ucl_object_lookup(v,
		    "name")), "sec-", 4) != 0)
			ucl_array_append(arr, ucl_object_copy(v));
	it = NULL;
	while ((v = ucl_object_iterate(ucl_object_lookup(f, "instances"), &it,
	    true)) != NULL)
		ucl_array_append(arr, r4_sec_one(v, ids, host));
	ucl_object_unref(f);
	ucl_object_delete_key(sd, key);
	if (ucl_array_size(arr) > 0)
		ucl_object_insert_key(sd, arr, key, 0, false);
	else
		ucl_object_unref(arr);
	if (ucl_object_compare(was, sd) == 0) {
		ucl_object_unref(was);
		ucl_object_unref(sd);
		snprintf(path, sizeof(path), FLEET "%s/arcana-sdwan:sdwan/apply",
		    sid);
		snprintf(in, sizeof(in), "\"part\":\"%s\",\"security\":true",
		    ids ? "ids" : "proxy");
		rc_act(path, in, r);
		return;
	}
	ucl_object_unref(was);
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, sd, "arcana-sdwan:sdwan", 0, false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	snprintf(path, sizeof(path), "/restconf/ds/ietf-datastores:candidate/"
	    "arcana-fleet:fleet/host=%s/arcana-sdwan:sdwan", sid);
	http("PUT", path, json, r);
	free(json);
	if (r->status != 201 && r->status != 204)
		return;
	resp_free(r);
	snprintf(path, sizeof(path), FLEET "%s/ietf-netconf:commit", sid);
	http("POST", path, "{\"ietf-netconf:input\":{}}", r);
	if (r->status != 204 && r->status != 200) {
		snprintf(path, sizeof(path), FLEET "%s/ietf-netconf:"
		    "discard-changes", sid);
		{
			struct resp	d;

			http("POST", path, "{\"ietf-netconf:input\":{}}", &d);
			resp_free(&d);
		}
	}
}

/* r4_sec()'s answer: saved. */
#define	R4_SAVED(r)	ATF_CHECK_MSG((r)->status == 204 ||		\
	(r)->status == 200, "%d %s", (r)->status, (r)->body)

CONSOLE_TC_LONG(sdwan_apply_security, "The Security page's own proxy and IDS "
    "beside SD-WAN's: checked, rendered, its captures and files, stopped")
ATF_TC_BODY(sdwan_apply_security, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16];
	char		doc[8192], t1[8192], t2[300], lifn[32], laddr[64];

	need_fibs(2);
	sdwan_apply_start(tc, &a, sa, sb, sizeof(sa), doc, sizeof(doc), lifn,
	    sizeof(lifn), laddr, sizeof(laddr));
	sdwan_apply_done();
	/* The Security page's own, saved as the page saves them (a form
	 * not right is the page's to refuse, sdread.c): one made into
	 * Squid's and c-icap's files beside SD-WAN's; Suricata's the same;
	 * [] stops them. */
	r4_sec(sa, "a", "{\"what\":\"proxy\",\"instances\":[{\"name\":"
	    "\"sec-web\",\"listen\":[\"10.1.0.1\",\"2001:db8::1\"],\"allow\":"
	    "[\"10.1.0.0/24\"],\"deny\":[\".bad.example\",\"worse.example\"],"
	    "\"malware\":true}]}", &r);
	R4_SAVED(&r);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^http_port 10.1.0.1:3128 ssl-bump tls-cert=' "
	    "sdwan-proxy-sec-web.conf && grep -q '^http_port \\[2001:db8::1\\]:"
	    "3128 ' sdwan-proxy-sec-web.conf && grep -q '^acl localnet src "
	    "10.1.0.0/24$' sdwan-proxy-sec-web.conf && grep -q 'icap://"
	    "127.0.0.1:1345/avscan' sdwan-proxy-sec-web.conf && grep -q "
	    "'^ssl_bump splice all$' sdwan-proxy-sec-web.conf") == 0);
	ATF_CHECK(system("grep -qx '.bad.example' sdwan-proxy-sec-web.deny && "
	    "grep -qx '.worse.example' sdwan-proxy-sec-web.deny") == 0);
	ATF_CHECK(system("grep -q '^Port 127.0.0.1:1345$' "
	    "sdwan-icap-sec-web.conf") == 0);
	snprintf(t1, sizeof(t1), FLEET "%s/arcana-sdwan:sdwan/state", sa);
	rc_get(t1, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"name\":\"sec-web\"") != NULL &&
	    strstr(r.body, "\"name\":\"sw1\"") != NULL && strstr(r.body,
	    "acl localnet") == NULL, "%s", r.body);
	resp_free(&r);
	/* Stopped: its c-icap with it, its files kept, stopped in running
	 * as the fleet mount has it; started again. */
	{
		const char	*stop = "{\"what\":\"proxy\",\"instances\":[{"
		    "\"name\":\"sec-web\",\"listen\":[\"10.1.0.1\",\"2001:db8::1\"],"
		    "\"allow\":[\"10.1.0.0/24\"],\"deny\":[\".bad.example\","
		    "\"worse.example\"],\"malware\":true%s}]}";
		char		 sbody[512], spath[256];
		FILE		*pf;
		long		 ipid;
		int		 k;

		ipid = 0;
		if ((pf = fopen("sdwan-icap-sec-web.pid", "r")) != NULL) {
			if (fscanf(pf, "%ld", &ipid) != 1)
				ipid = 0;
			fclose(pf);
		}
		ATF_CHECK(ipid > 0 && kill((pid_t)ipid, 0) == 0);
		snprintf(sbody, sizeof(sbody), stop, ",\"stopped\":true");
		r4_sec(sa, "a", sbody, &r);
		R4_SAVED(&r);
		resp_free(&r);
		for (k = 0; k < 50 && ipid > 0 && kill((pid_t)ipid, 0) == 0;
		    k++)
			usleep(100000);
		ATF_CHECK_MSG(ipid > 0 && kill((pid_t)ipid, 0) != 0,
		    "its c-icap still runs");
		ATF_CHECK(access("sdwan-proxy-sec-web.conf", F_OK) == 0 &&
		    access("sdwan-icap-sec-web.conf", F_OK) == 0 &&
		    access("sdwan-proxy-sec-web.deny", F_OK) == 0);
		ATF_CHECK(system("grep -q '\"stopped\":true' "
		    "security-proxy.json") == 0);
		snprintf(spath, sizeof(spath), "/restconf/data/arcana-fleet:fleet/"
		    "host=%s/arcana-sdwan:sdwan/proxy-instance=sec-web/stopped",
		    sa);
		rc_get(spath, &r);
		ATF_CHECK_MSG(r.status == 200 && strstr(r.body, "true") !=
		    NULL, "%d %s", r.status, r.body);
		resp_free(&r);
		snprintf(sbody, sizeof(sbody), stop, "");
		r4_sec(sa, "a", sbody, &r);
		R4_SAVED(&r);
		resp_free(&r);
		ipid = 0;
		if ((pf = fopen("sdwan-icap-sec-web.pid", "r")) != NULL) {
			if (fscanf(pf, "%ld", &ipid) != 1)
				ipid = 0;
			fclose(pf);
		}
		ATF_CHECK_MSG(ipid > 0 && kill((pid_t)ipid, 0) == 0,
		    "its c-icap was not started again");
		ATF_CHECK(system("grep -q '\"stopped\"' security-proxy.json") !=
		    0);
	}
	/* Rules of its own or the ruleset, its thresholds' lines: the
	 * page's to check (sdread.c's ids_one()). */
	r4_sec(sa, "a", "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"rules\":\"alert tcp any any "
	    "-> any 23 (sid:1000009;)\"}]}", &r);
	R4_SAVED(&r);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^  - interface: lo0$' sdwan-ids-sec-lan.yaml "
	    "&& grep -q 'HOME_NET: \"\\[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'"
	    " sdwan-ids-sec-lan.yaml && grep -q 'sid:1000009' "
	    "sdwan-ids-sec-lan.rules") == 0);
	/* Every address its home: any, alone, and so outside too. */
	r4_sec(sa, "a", "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\",\"10.0.0.0/8\"],"
	    "\"rules\":\"alert tcp any any -> any 23 (sid:1000009;)\"}]}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	ATF_CHECK_MSG(strstr(r.body, "any stands alone") != NULL, "%s", r.body);
	resp_free(&r);
	r4_sec(sa, "a", "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"nonsense\"],"
	    "\"rules\":\"alert tcp any any -> any 23 (sid:1000009;)\"}]}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	ATF_CHECK_MSG(strstr(r.body, "nonsense is not one") != NULL && strstr(
	    r.body, "or any") != NULL, "%s", r.body);
	resp_free(&r);
	r4_sec(sa, "a", "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\"],"
	    "\"rules\":\"alert tcp any any -> any 23 (sid:1000009;)\"}]}", &r);
	R4_SAVED(&r);
	resp_free(&r);
	ATF_CHECK(system("grep -q 'HOME_NET: \"any\"$' sdwan-ids-sec-lan.yaml && "
	    "grep -q 'EXTERNAL_NET: \"any\"$' sdwan-ids-sec-lan.yaml") == 0);
	/* Its thresholds: threshold.config's lines, written to a file of
	 * its own, which its configuration names. */
	r4_sec(sa, "a", "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\"],"
	    "\"thresholds\":\"# quiet\\nsuppress gen_id 1, sig_id 1000009, "
	    "track by_src, ip 10.0.0.9\\n\",\"rules\":\"alert tcp any any -> "
	    "any 23 (sid:1000009;)\"}]}", &r);
	R4_SAVED(&r);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^threshold-file: .*sdwan-ids-sec-lan."
	    "threshold$' sdwan-ids-sec-lan.yaml && grep -qx 'suppress gen_id "
	    "1, sig_id 1000009, track by_src, ip 10.0.0.9' "
	    "sdwan-ids-sec-lan.threshold") == 0);
	/* A capture up from the page, in two parts: on the host, beside its
	 * replay; a part that does not follow, refused. */
	snprintf(t1, sizeof(t1), "/api/servers/%s/ids/pcap?instance=sec-lan&"
	    "file=up.pcap", sa);
	http("POST", t1, "PCAP", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"ok\":true") != NULL && strstr(r.body,
	    "/sdwan-ids-sec-lan.replay.d/captures/up.pcap\"") != NULL &&
	    strstr(r.body, "\"size\":4") != NULL, "%s", r.body);
	resp_free(&r);
	snprintf(t1, sizeof(t1), "/api/servers/%s/ids/pcap?instance=sec-lan&"
	    "file=up.pcap&offset=9&last=1", sa);
	http("POST", t1, "DATA", &r);
	EXPECT(&r, 502);
	ATF_CHECK_MSG(strstr(r.body, "the part before ended at 4, not 9") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	snprintf(t1, sizeof(t1), "/api/servers/%s/ids/pcap?instance=sec-lan&"
	    "file=up.pcap&offset=4&last=1", sa);
	http("POST", t1, "DATA", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK(system("[ \"$(cat sdwan-ids-sec-lan.replay.d/captures/"
	    "up.pcap)\" = PCAPDATA ] && [ ! -e sdwan-ids-sec-lan.replay.d/"
	    "captures/up.pcap.part ]") == 0);
	snprintf(t1, sizeof(t1), "/api/servers/%s/ids/pcap?instance=sec-lan&"
	    "file=../up.pcap", sa);
	http("POST", t1, "PCAP", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* A file of its pcap-log down, as an alert's row links it; one it
	 * has not, said. */
	ATF_CHECK(system("mkdir -p sdwan-ids-sec-lan.d && printf PCAPLOG > "
	    "sdwan-ids-sec-lan.d/log.pcap.1792400000") == 0);
	snprintf(t1, sizeof(t1), "/api/servers/%s/ids/pcap-log?instance="
	    "sec-lan&file=log.pcap.1792400000", sa);
	http("GET", t1, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "PCAPLOG") != NULL, "%s", r.body);
	resp_free(&r);
	snprintf(t1, sizeof(t1), "/api/servers/%s/ids/pcap-log?instance="
	    "sec-lan&file=log.pcap.1", sa);
	http("GET", t1, NULL, &r);
	EXPECT(&r, 404);
	ATF_CHECK_MSG(strstr(r.body, "has no such file") != NULL, "%s", r.body);
	resp_free(&r);
	snprintf(t1, sizeof(t1), "/api/servers/%s/ids/pcap-log?instance="
	    "sec-lan&file=eve.json", sa);
	http("GET", t1, NULL, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* What its profiling wrote, read through the console. */
	snprintf(t1, sizeof(t1), FLEET "%s/arcana-suricata:suricata/"
	    "read-profiling", sa);
	rc_act(t1, "\"instance\":\"sec-lan\"", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"build\":{") != NULL, "%s", r.body);
	resp_free(&r);
	/* Its settings: each into Suricata's YAML, checked first; where the
	 * host has Suricata itself, what it makes of the whole. */
	r4_sec(sa, "a", "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\"],"
	    "\"runmode\":\"fast\",\"rules\":\"alert tcp any any -> any 23 "
	    "(sid:1000009;)\"}]}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	ATF_CHECK_MSG(strstr(r.body, "runmode is autofp, workers or single") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	r4_sec(sa, "a", "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\"],"
	    "\"flow_memcap\":\"lots\",\"rules\":\"alert tcp any any -> any "
	    "23 (sid:1000009;)\"}]}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	resp_free(&r);
	r4_sec(sa, "a", "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\"],"
	    "\"eve\":[\"http\",\"dns\",\"tls\",\"flow\"],\"payload\":true,"
	    "\"stats_interval\":30,\"runmode\":\"workers\",\"mpm\":\"ac-ks\","
	    "\"profile\":\"high\",\"management_cpus\":\"0\",\"worker_cpus\":"
	    "\"0-1\",\"max_pending\":2048,\"flow_memcap\":\"128mb\","
	    "\"stream_memcap\":\"64mb\",\"reassembly_memcap\":\"256mb\","
	    "\"defrag_memcap\":\"32mb\",\"host_memcap\":\"32mb\","
	    "\"http_memcap\":\"64mb\",\"stream_inline\":\"auto\","
	    "\"reassembly_depth\":\"1mb\",\"http_request_body\":\"200kb\","
	    "\"http_response_body\":\"2mb\",\"midstream\":true,"
	    "\"exception_policy\":\"drop-flow\",\"yaml\":\"vlan:\\n  "
	    "use-for-tracking: false\\n\",\"rules\":\"alert tcp any any -> "
	    "any 23 (sid:1000009;)\"}]}", &r);
	R4_SAVED(&r);
	resp_free(&r);
	ATF_CHECK(system("f=sdwan-ids-sec-lan.yaml; grep -q '^        - alert:$' "
	    "$f && grep -q '^            payload-printable: yes$' $f && "
	    "grep -q '^        - tls$' $f && grep -q '^  interval: 30$' $f && "
	    "grep -q '^runmode: workers$' $f && grep -q '^mpm-algo: ac-ks$' $f "
	    "&& grep -q '^  profile: high$' $f && grep -q '^      cpu: \\[ 0-1 "
	    "\\]$' $f && grep -q '^max-pending-packets: 2048$' $f && grep -q "
	    "'^    depth: 1mb$' $f && grep -q '^          response-body-limit: "
	    "2mb$' $f && grep -q '^exception-policy: drop-flow$' $f && grep -q "
	    "'^  use-for-tracking: false$' $f") == 0);
	if (access("/usr/local/bin/suricata", X_OK) == 0)
		ATF_CHECK_MSG(system("/usr/local/bin/suricata -T -c "
		    "sdwan-ids-sec-lan.yaml > suricata-T.out 2>&1") == 0,
		    "Suricata refuses the settings: see suricata-T.out");
	/* By netmap(4): a pair at L2, copy-mode ips both ways, a worker's
	 * to the end; pairs are netmap's; not with divert.  A preset's
	 * values where a field says none. */
	r4_sec(sa, "a", "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"pairs\":[\"em0:em1\"],"
	    "\"rules\":\"alert tcp any any -> any 23 (sid:1000009;)\"}]}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	ATF_CHECK_MSG(strstr(r.body, "pairs of interfaces are netmap's") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	r4_sec(sa, "a", "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"capture\":\"netmap\",\"divert\":8600,"
	    "\"pairs\":[\"em0:em1\"],\"rules\":\"alert tcp any any -> any "
	    "23 (sid:1000009;)\"}]}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	ATF_CHECK_MSG(strstr(r.body, "not both") != NULL, "%s", r.body);
	resp_free(&r);
	r4_sec(sa, "a", "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"capture\":\"netmap\",\"pairs\":[\"lo0:lo0^\"],"
	    "\"home\":[\"any\"],\"preset\":\"large\",\"flow_memcap\":"
	    "\"64mb\",\"offload_off\":true,\"rules\":\"alert tcp any any -> "
	    "any 23 (sid:1000009;)\"}]}", &r);
	R4_SAVED(&r);
	resp_free(&r);
	ATF_CHECK(system("f=sdwan-ids-sec-lan.yaml; grep -q '^netmap:$' $f && "
	    "grep -A3 -x '  - interface: lo0' $f | grep -qx '    copy-iface: "
	    "lo0^' && grep -A3 -x '  - interface: lo0^' $f | grep -qx '    "
	    "copy-iface: lo0' && grep -q '^runmode: workers$' $f && ! grep -q "
	    "'^pcap:' $f && grep -A1 -x 'flow:' $f | grep -qx '  memcap: 64mb' "
	    "&& grep -A3 -x 'stream:' $f | grep -qx '    memcap: 2gb' && "
	    "grep -q '^  profile: high$' $f") == 0);
	ATF_CHECK(system("grep -q '\"capture\":\"netmap\"' security-ids.json "
	    "&& grep -q '\"interfaces\":\\[\"lo0\",\"lo0^\"\\]' "
	    "security-ids.json && grep -q '\"offload\":false' security-ids.json")
	    == 0);
	if (access("/usr/local/bin/suricata", X_OK) == 0)
		ATF_CHECK_MSG(system("/usr/local/bin/suricata -T -c "
		    "sdwan-ids-sec-lan.yaml > suricata-T.out 2>&1") == 0,
		    "Suricata refuses netmap's: see suricata-T.out");
	/* Lua: its scripts to the agent, allowed for rules, one an
	 * output; the packets of its alerts kept; its plugins.  Suricata
	 * itself checks the first two where the host has it. */
	r4_sec(sa, "a", "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\"],"
	    "\"lua_outputs\":[\"nosuch.lua\"],\"rules\":\"alert tcp any any "
	    "-> any 23 (sid:1000009;)\"}]}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	ATF_CHECK_MSG(strstr(r.body, "a Lua output is one of its scripts") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	r4_sec(sa, "a", "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\"],"
	    "\"lua\":{\"pkts.lua\":\"function init (args)\\n  local needs = "
	    "{}\\n  needs[\\\"type\\\"] = \\\"packet\\\"\\n  return needs\\n"
	    "end\\nfunction setup (args)\\nend\\nfunction log (args)\\nend\\n"
	    "function deinit (args)\\nend\\n\"},\"lua_outputs\":[\"pkts.lua\"],"
	    "\"pcap_log\":true,\"pcap_log_limit\":\"10mb\",\"pcap_log_files\":"
	    "3,\"rules\":\"alert tcp any any -> any 23 (sid:1000009;)\"}]}",
	    &r);
	R4_SAVED(&r);
	resp_free(&r);
	ATF_CHECK(system("f=sdwan-ids-sec-lan.yaml; grep -q '^  - lua:$' $f && "
	    "grep -q '^      scripts-dir: .*sdwan-ids-sec-lan.lua$' $f && "
	    "grep -q '^        - pkts.lua$' $f && grep -q '^    allow-rules: "
	    "yes$' $f && grep -q '^  - pcap-log:$' $f && grep -q '^      "
	    "max-files: 3$' $f && grep -q '^      conditional: alerts$' $f && "
	    "grep -q 'needs' sdwan-ids-sec-lan.lua/pkts.lua") == 0);
	if (access("/usr/local/bin/suricata", X_OK) == 0)
		ATF_CHECK_MSG(system("/usr/local/bin/suricata -T -c "
		    "sdwan-ids-sec-lan.yaml > suricata-T.out 2>&1") == 0,
		    "Suricata refuses Lua or pcap-log: see suricata-T.out");
	r4_sec(sa, "a", "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"plugins\":[\"/tmp/x.so\"],"
	    "\"rules\":\"alert tcp any any -> any 23 (sid:1000009;)\"}]}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	ATF_CHECK_MSG(strstr(r.body, "a .so under /usr/local/lib") != NULL,
	    "%s", r.body);
	resp_free(&r);
	/* Stopped by the admin: kept in the list, told to the agent. */
	r4_sec(sa, "a", "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\"],"
	    "\"stopped\":true,\"rules\":\"alert tcp any any -> any 23 "
	    "(sid:1000009;)\"}]}", &r);
	R4_SAVED(&r);
	resp_free(&r);
	ATF_CHECK(system("grep -q '\"name\":\"sec-lan\",\"host\":\"a\","
	    "\"interfaces\":\\[\"lo0\"\\],\"stopped\":true' security-ids.json")
	    == 0);
	/* A job's words, its args, carried to the host for ClamAV and
	 * Suricata alike. */
	snprintf(t2, sizeof(t2), FLEET "%s/arcana-jobs:submit", sa);
	rc_act(t2, "\"change\":[{\"clamav\":{\"verb\":\"mirrors\","
	    "\"args\":[\"mirror=db.example.net\"]}},{\"suricata\":{\"verb\":"
	    "\"rule\",\"args\":[\"off=2000001\"]}}]", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	snprintf(t2, sizeof(t2), FLEET "%s/arcana-jobs:jobs", sa);
	rc_get(t2, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "freshclam mirrors db.example.net") !=
	    NULL && strstr(r.body, "suricata rules set: off=2000001") != NULL,
	    "%s", r.body);
	resp_free(&r);
	r4_sec(sa, "a", "{\"what\":\"ids\",\"instances\":[]}", &r);
	R4_SAVED(&r);
	resp_free(&r);
	r4_sec(sa, "a", "{\"what\":\"proxy\",\"instances\":[]}", &r);
	R4_SAVED(&r);
	resp_free(&r);
	ATF_CHECK(access("sdwan-proxy-sec-web.conf", F_OK) != 0);
	ATF_CHECK(access("sdwan-proxy-sw1.conf", F_OK) == 0);
}

CONSOLE_TC_LONG(sdwan_apply_rollback, "SD-WAN's apply rolled back when a step "
    "fails after others were made")
ATF_TC_BODY(sdwan_apply_rollback, tc)
{
	struct authn	a;
	struct resp	r;
	char		sa[16], sb[16];
	char		doc[8192], t1[8192], lifn[32], laddr[64];

	need_fibs(2);
	sdwan_apply_start(tc, &a, sa, sb, sizeof(sa), doc, sizeof(doc), lifn,
	    sizeof(lifn), laddr, sizeof(laddr));
	sdwan_apply_done();
	/* Kept with the MPLS tunnel a geneve one, as sdwan_apply_plan's
	 * last, as sdwan_apply's rollback had it. */
	ATF_REQUIRE(swap_in(doc, "\"kind\":\"gif\"", "\"kind\":\"geneve\"", t1,
	    sizeof(t1)));
	ATF_REQUIRE(swap_in(t1, "\"version\":0", "\"version\":1", doc,
	    sizeof(doc)));
	snprintf(t1, sizeof(t1), "%s", doc);
	r4_keep(t1, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	/*
	 * A step that fails after others were made rolls the apply back:
	 * what it made before is taken away again, the last first, and
	 * the apply says which step failed.  A route the host refuses
	 * (10.66.0.0/16, the stand-in's, as a UNI's static route the far
	 * edge gets a route to) comes after the tunnels; made all again,
	 * the tunnels are destroyed once at the start and once more by
	 * the rollback.
	 */
	r4_read("document", &r);
	EXPECT(&r, 200);
	{
		char	*kept;

		kept = (char *)ucl_object_emit(r.json, UCL_EMIT_JSON_COMPACT);
		ATF_REQUIRE(kept != NULL && swap_in(kept, "\"prefix\":"
		    "\"10.1.8.0/22\",\"next_hop\"", "\"prefix\":"
		    "\"10.66.0.0/16\",\"next_hop\"", t1, sizeof(t1)));
		free(kept);
	}
	resp_free(&r);
	r4_keep(t1, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	ATF_REQUIRE(system(": > ifconfig.log") == 0);
	http("POST", CC "sdwan/apply", accepting(true), &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "rolled back") == 0 &&
	    jstr(&r, "apply.failed_step") != NULL && strstr(r.body,
	    "\"state\":\"undone\"") != NULL && strstr(r.body, "taken away "
	    "again: a step after it failed") != NULL, "%s", r.body);
	ATF_CHECK_MSG(system("test \"$(grep -c '^gre100 destroy' ifconfig.log)\" "
	    "-ge 2 && grep -q '^gre100 create' ifconfig.log") == 0,
	    "the tunnel was not made and taken away again");
	resp_free(&r);
}

static const char *const cl_nodes[] = { "na", "nb", "nc" };

/* A case of the cluster's: its consoles stopped, each in its directory. */
#define	CLUSTER_TC(name, descr)						\
ATF_TC_WITH_CLEANUP(name);						\
ATF_TC_HEAD(name, tc)							\
{									\
	atf_tc_set_md_var(tc, "descr", descr);				\
	atf_tc_set_md_var(tc, "timeout", "120");				\
}									\
ATF_TC_CLEANUP(name, tc)						\
{									\
	char	cwd[MAXPATHLEN];					\
	int	i;							\
									\
	if (getcwd(cwd, sizeof(cwd)) == NULL)				\
		return;							\
	for (i = 0; i < 3; i++)						\
		if (chdir(cl_nodes[i]) == 0) {				\
			stop();						\
			(void)chdir(cwd);				\
		}							\
}

/* GET path of node i until its answer says want: 15 s at most. */
static bool
cl_until(const char *cwd, int i, const char *path, const char *want)
{
	struct resp	r;
	int		k;
	bool		ok;

	ATF_REQUIRE(chdir(cl_nodes[i]) == 0);
	ok = false;
	for (k = 0; k < 150 && !ok; k++) {
		http("GET", path, NULL, &r);
		ok = r.status == 200 && r.body != NULL && strstr(r.body,
		    want) != NULL;
		resp_free(&r);
		if (!ok)
			usleep(100000);
	}
	ATF_REQUIRE(chdir(cwd) == 0);
	return (ok);
}

/*
 * The three consoles started, each in its directory under cwd; the
 * seed's first key, once it leads; the others follow it.  Signed in on
 * one, signed in on every one.
 */
static void
cl_start(const atf_tc_t *tc, const char *cwd, struct authn *a)
{
	char	nodes[1024];
	int	i, n;

#ifndef ARCANA_CLUSTER
	atf_tc_skip("arcana-console built without clustering "
	    "(WITHOUT_CLUSTER)");
#endif
	n = snprintf(nodes, sizeof(nodes), "nodes {");
	for (i = 0; i < 3; i++)
		n += snprintf(nodes + n, sizeof(nodes) - (size_t)n, " %s { uri "
		    "= \"unix:%s/%s/cl.sock\"; }", cl_nodes[i], cwd,
		    cl_nodes[i]);
	snprintf(nodes + n, sizeof(nodes) - (size_t)n, " }");
	for (i = 0; i < 3; i++) {
		ATF_REQUIRE(mkdir(cl_nodes[i], 0755) == 0);
		ATF_REQUIRE(chdir(cl_nodes[i]) == 0);
		snprintf(harness_webconf, sizeof(harness_webconf), "cluster { "
		    "self = \"%s\"; listen = \"unix:%s/%s/cl.sock\"; %s }\n",
		    cl_nodes[i], cwd, cl_nodes[i], nodes);
		start(tc, 0, NULL);
		ATF_REQUIRE(chdir(cwd) == 0);
	}
	harness_webconf[0] = '\0';
	ATF_REQUIRE(chdir(cl_nodes[0]) == 0);
	enrol(a);
	ATF_REQUIRE(chdir(cwd) == 0);
	ATF_CHECK(cl_until(cwd, 0, CC "cluster", "\"role\":\"leader\""));
	ATF_CHECK(cl_until(cwd, 1, CC "cluster", "\"leader\":\"na\""));
	ATF_CHECK(cl_until(cwd, 2, CC "cluster", "\"leader\":\"na\""));
	ATF_CHECK(cl_until(cwd, 2, CC "hosts", "\"arcana-console:hosts\""));
}

/*
 * Three consoles of a cluster, each in its own directory, joined by unix
 * sockets: the seed leads, a change made on any is every one's, a
 * sign-in too.
 */
CLUSTER_TC(cluster, "Three consoles of a cluster: the seed leads, a change "
    "on any is every one's, a sign-in too; a store written on two at once "
    "loses nothing")
ATF_TC_BODY(cluster, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[MAXPATHLEN], key[64], far[16];
	char		path[128], body[256];
	pid_t		pid;
	int		i, k, st;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	cl_start(tc, cwd, &a);
	/* A host added on a follower: written by the leader, every one's. */
	ATF_REQUIRE(chdir(cl_nodes[1]) == 0);
	host_new("\"name\":\"far\",\"uri\":\"tcp://192.0.2.9:4310\"", far,
	    sizeof(far));
	ATF_REQUIRE(chdir(cwd) == 0);
	for (i = 0; i < 3; i++)
		ATF_CHECK_MSG(cl_until(cwd, i, CC "hosts", "\"far\""),
		    "%s", cl_nodes[i]);
	/* A store read, changed and written again on two nodes at the same
	 * time, ten times over: each reads what the other wrote before it
	 * (the cluster's lock, and the writes committed before it waited
	 * for), so no label is written over. */
	for (k = 0; k < 10; k++) {
		if ((pid = fork()) == 0) {
			ATF_REQUIRE(chdir(cl_nodes[2]) == 0);
			snprintf(path, sizeof(path), CC "labels/label=%s,em%d",
			    far, 10 + k);
			snprintf(body, sizeof(body), "{\"arcana-console:"
			    "label\":[{\"host\":\"%s\",\"interface\":\"em%d\","
			    "\"text\":\"by nc\"}]}", far, 10 + k);
			http("PUT", path, body, &r);
			_exit(r.status == 201 ? 0 : 1);
		}
		ATF_REQUIRE(pid > 0);
		ATF_REQUIRE(chdir(cl_nodes[1]) == 0);
		snprintf(path, sizeof(path), CC "labels/label=%s,em%d", far, k);
		snprintf(body, sizeof(body), "{\"arcana-console:label\":[{"
		    "\"host\":\"%s\",\"interface\":\"em%d\",\"text\":"
		    "\"by nb\"}]}", far, k);
		http("PUT", path, body, &r);
		EXPECT(&r, 201);
		resp_free(&r);
		ATF_REQUIRE(chdir(cwd) == 0);
		ATF_REQUIRE(waitpid(pid, &st, 0) == pid);
		ATF_CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
	}
	ATF_CHECK(cl_until(cwd, 0, CC "labels", "\"interface\":\"em19\""));
	ATF_REQUIRE(chdir(cl_nodes[0]) == 0);
	http("GET", CC "labels", NULL, &r);
	for (k = 0; k < 20; k++) {
		snprintf(key, sizeof(key), "\"interface\":\"em%d\"", k);
		ATF_CHECK_MSG(strstr(r.body, key) != NULL, "em%d's label "
		    "written over: %.400s", k, r.body);
	}
	resp_free(&r);
	ATF_REQUIRE(chdir(cwd) == 0);
}

/*
 * The same three consoles: one stopped catches up when it starts
 * again; signed out on one, signed out on every one.
 */
CLUSTER_TC(cluster_catchup, "Three consoles of a cluster: one stopped "
    "catches up, a sign-out is every one's")
ATF_TC_BODY(cluster_catchup, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[MAXPATHLEN], body[128], later[16];
	int		n, k;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	cl_start(tc, cwd, &a);
	/* One stopped misses a change two make; started, it has it. */
	ATF_REQUIRE(chdir(cl_nodes[2]) == 0);
	console_stop();
	ATF_REQUIRE(chdir(cwd) == 0);
	ATF_REQUIRE(chdir(cl_nodes[0]) == 0);
	host_new("\"name\":\"later\",\"uri\":\"tcp://192.0.2.10:4310\"",
	    later, sizeof(later));
	ATF_REQUIRE(chdir(cwd) == 0);
	ATF_REQUIRE(chdir(cl_nodes[2]) == 0);
	console_start();
	ATF_REQUIRE(chdir(cwd) == 0);
	ATF_CHECK(cl_until(cwd, 2, CC "hosts", "\"later\""));
	/* Signed out on one, signed out on every one: the session's own
	 * document taken away. */
	strlcpy(body, cookie, sizeof(body));
	ATF_REQUIRE(chdir(cl_nodes[1]) == 0);
	http("POST", "/api/auth/logout", "{}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_REQUIRE(chdir(cwd) == 0);
	strlcpy(cookie, body, sizeof(cookie));
	ATF_REQUIRE(chdir(cl_nodes[2]) == 0);
	for (k = 0; k < 300; k++) {
		http("GET", CC "hosts", NULL, &r);
		n = r.status;
		resp_free(&r);
		if (n == 401)
			break;
		usleep(100000);
	}
	ATF_CHECK_EQ(401, n);
	ATF_REQUIRE(chdir(cwd) == 0);
}

/* tls_ec's host, its id made by the test. */
#define	R4_TLS_ID	"0a0e0001"

/*
 * HTTPS with an EC certificate (P-256), which the console serves as it
 * does an RSA one, on TLS 1.3: HTTP/2 to a client that offers it (by
 * ALPN), HTTP/1.1 to one that does not.
 */
ATF_TC_WITH_CLEANUP(tls_ec);
ATF_TC_HEAD(tls_ec, tc)
{
	atf_tc_set_md_var(tc, "descr", "the console serves HTTPS with an EC "
	    "certificate, over HTTP/2 and HTTP/1.1");
	atf_tc_set_md_var(tc, "require.progs", "curl openssl");
}
ATF_TC_BODY(tls_ec, tc)
{
	char	cwd[MAXPATHLEN], cmd[MAXPATHLEN * 2];
	int	port, i;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ATF_REQUIRE(system("openssl req -x509 -newkey ec -pkeyopt "
	    "ec_paramgen_curve:P-256 -nodes -keyout ec.key -out ec.pem -days 1 "
	    "-subj /CN=localhost 2>/dev/null") == 0);
	snprintf(harness_server, sizeof(harness_server), "\tcertfile = "
	    "\"%s/ec.pem\";\n\tcertkey = \"%s/ec.key\";\n", cwd, cwd);
	port = 20000 + (int)(getpid() % 20000);
	start(tc, port, NULL);
	for (i = 0; i < 50; i++) {
		snprintf(cmd, sizeof(cmd), "curl -sk https://127.0.0.1:%d/api/"
		    "health | grep -q '\"ok\":true'", port);
		if (system(cmd) == 0)
			break;
		usleep(100000);
	}
	ATF_CHECK_MSG(i < 50, "no answer over HTTPS");
	snprintf(cmd, sizeof(cmd), "echo | openssl s_client -connect "
	    "127.0.0.1:%d 2>/dev/null | grep -q 'Peer signature type: "
	    "ecdsa_secp256r1_sha256'", port);
	ATF_CHECK_MSG(system(cmd) == 0, "not signed with the EC key");
	snprintf(cmd, sizeof(cmd), "curl -sk --http2 -o /dev/null -w "
	    "'%%{http_version} %%{http_code}' https://127.0.0.1:%d/api/health "
	    "| grep -qx '2 200'", port);
	ATF_CHECK_MSG(system(cmd) == 0, "no HTTP/2");
	/* A request with a body, and a reply without one (over the
	 * largest body), each to the end of its stream. */
	snprintf(cmd, sizeof(cmd), "curl -sk --http2 -m 5 -o /dev/null -w "
	    "'%%{http_version} %%{http_code}' -H 'content-type: application/"
	    "json' -d '{}' https://127.0.0.1:%d/api/auth/status | grep -qx "
	    "'2 [0-9][0-9][0-9]'", port);
	ATF_CHECK_MSG(system(cmd) == 0, "no answer to a body over HTTP/2");
	snprintf(cmd, sizeof(cmd), "curl -sk --http1.1 -o /dev/null -w "
	    "'%%{http_version} %%{http_code}' https://127.0.0.1:%d/api/health "
	    "| grep -qx '1.1 200'", port);
	ATF_CHECK_MSG(system(cmd) == 0, "no HTTP/1.1");
	/* Over HTTPS, browsers are kept to it for the settings' days
	 * (a year unless set). */
	snprintf(cmd, sizeof(cmd), "curl -skI https://127.0.0.1:%d/api/health "
	    "| grep -qi '^strict-transport-security: max-age=31536000'", port);
	ATF_CHECK_MSG(system(cmd) == 0, "no Strict-Transport-Security");
	/*
	 * A reply larger than an HTTP/2 frame (16 KB): a host's sysctl
	 * read through the fleet mount, with a session opened by an API
	 * token, its host added with the console's Origin.  Written whole,
	 * it ended the connection (curl: exit 16).
	 */
	snprintf(cmd, sizeof(cmd), "T=arcw_$(printf 'b%%.0s' $(seq 1 64)); "
	    "printf '{\"tokens\":[{\"hash\":\"%%s\",\"name\":\"t\","
	    "\"created\":1,\"last\":0,\"write\":true}]}' $(printf %%s $T "
	    "| sha256 -q) > data/tokens.json && "
	    "curl -sk --http2 -c jar -H 'content-type: application/json' -d "
	    "\"{\\\"token\\\":\\\"$T\\\"}\" https://127.0.0.1:%d/api/auth/"
	    "login/token -o /dev/null && "
	    "curl -sk --http2 -b jar -H 'origin: %s' -H 'content-type: "
	    "application/json' -d '{\"arcana-console:host\":[{\"id\":"
	    "\"" R4_TLS_ID "\",\"name\":\"here\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}]}' -o servers.out -w '%%{http_code}' "
	    "https://127.0.0.1:%d" CC "hosts | grep -qx 201 && "
	    "curl -sk --http2 -b jar -o sysctl.out -w '%%{http_version} "
	    "%%{http_code}' -H 'origin: %s' -H 'content-type: application/"
	    "json' -d '{\"arcana-sysctl:input\":{}}' https://127.0.0.1:%d"
	    FLEET R4_TLS_ID SYSCTL_READ " | grep -qx '2 200' && "
	    "[ $(wc -c < sysctl.out) -gt 65536 ]", port, harness_origin, cwd,
	    port, harness_origin, port);
	if (system(cmd) != 0) {
		(void)system("echo servers:; head -c 300 servers.out; echo; "
		    "echo sysctl:; head -c 300 sysctl.out; echo; wc -c sysctl.out; "
		    "tail -5 console.out; tail -5 arcana-agent.out");
		atf_tc_fail("a large reply did not come whole over HTTP/2");
	}
	/*
	 * Forty large replies on one connection, to a client with
	 * HTTP/2's own window (64 KB, nghttp's; curl's is far larger)
	 * that keeps to the 24 streams the console allows: the host's
	 * sysctl tree read by GET, larger than the window.  Written past
	 * the window, the client ended the connection with
	 * FLOW_CONTROL_ERROR; a stream ended while output waited stayed
	 * open to libwebsockets after the client had its end, and the
	 * client's next one, past the limit, ended the connection.
	 */
	snprintf(cmd, sizeof(cmd), "command -v nghttp >/dev/null || exit 0; "
	    "C=$(awk '/arc_session/ { print $7 }' jar) && "
	    "curl -sk --http2 -b jar -o tree.out https://127.0.0.1:%d" FLEET
	    R4_TLS_ID "/arcana-sysctl:sysctl && [ $(wc -c < tree.out) -gt "
	    "65536 ] && nghttp -nv -M 24 -m 40 -H \"cookie: arc_session=$C\" "
	    "https://127.0.0.1:%d" FLEET R4_TLS_ID "/arcana-sysctl:sysctl "
	    "> nghttp.out 2>&1; "
	    "[ $(grep -c ':status: 200' nghttp.out) -eq 40 ] && "
	    "! grep -q 'recv GOAWAY\\|FLOW_CONTROL' nghttp.out", port, port);
	if (system(cmd) != 0) {
		(void)system("wc -c tree.out; grep -i 'goaway\\|status\\|"
		    "processed' -A1 nghttp.out | head -20");
		atf_tc_fail("not every large reply on one HTTP/2 connection came");
	}
	/*
	 * The key is the key manager's, the worker's child: killed, the
	 * worker goes with it and the supervisor starts both again.
	 */
	ATF_REQUIRE(system("W=$(sed -n 's/.*worker started (pid "
	    "\\([0-9]*\\)).*/\\1/p' console.out | tail -1) && "
	    "ps -o command= -p $(pgrep -P $W) | grep -q 'arcana-console: "
	    "keymgr' && pkill -TERM -P $W -f 'arcana-console: keymgr'") == 0);
	for (i = 0; i < 50; i++) {
		snprintf(cmd, sizeof(cmd), "curl -sk https://127.0.0.1:%d/api/"
		    "health | grep -q '\"ok\":true'", port);
		/* The next handshake finds it gone; one after, both are
		 * back. */
		if (system(cmd) == 0 && system("grep -q 'keymgr: gone' "
		    "console.out") == 0)
			break;
		usleep(200000);
	}
	ATF_CHECK_MSG(i < 50, "no HTTPS after the key manager was killed");
	ATF_CHECK(system("[ $(grep -c 'worker started' console.out) -ge 2 ]")
	    == 0);
	/* Plain HTTP on that port is not served. */
	snprintf(cmd, sizeof(cmd), "! curl -s http://127.0.0.1:%d/api/health "
	    "| grep -q ok", port);
	ATF_CHECK(system(cmd) == 0);
}
ATF_TC_CLEANUP(tls_ec, tc)
{

	(void)tc;
	stop();
}

/* The host's records kept by the console, those after n: how many have
 * what, within secs. */
static int
notif_count(const char *id, const char *what, int want, int secs)
{
	struct resp	 r;
	char		 path[128];
	int		 n = 0, i;

	snprintf(path, sizeof(path), CC "hosts/host=%s/notifications", id);
	for (i = 0; i < secs * 10; i++) {
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		n = 0;
		for (const char *p = r.body; (p = strstr(p, what)) != NULL;
		    p += strlen(what))
			n++;
		resp_free(&r);
		if (n >= want)
			break;
		usleep(100000);
	}
	return (n);
}

/* The token in the document subscription-token gives; a record. */
#define	NOTIF_TOKEN_PATH \
	"candidate.ietf-subscribed-notifications:subscriptions." \
	"ietf-subscribed-notif-receivers:receiver-instances." \
	"receiver-instance.0.ietf-https-notif-transport:https-receiver." \
	"arcana-notif:token"
#define	NOTIF_RECORD \
	"{\"ietf-restconf:notification\":{\"eventTime\":" \
	"\"2026-10-28T10:00:00Z\",\"arcana-events:event\":{\"id\":1}}}"

/* GET of arcana-console's hosts/host=<id>/<node>, a bridged node; on
 * 200 r's JSON its document. */
static void
r4_host_read(const char *id, const char *node, struct resp *r)
{
	char	path[256], key[96];

	snprintf(path, sizeof(path), CC "hosts/host=%s/%s", id, node);
	http("GET", path, NULL, r);
	snprintf(key, sizeof(key), "arcana-console:%.*s",
	    (int)strcspn(node, "?"), node);
	if (r->status == 200)
		(void)resp_unwrap(r, key);
}

/* A job of the host's through arcana-jobs' submit, change the list's
 * entries; the answer in r. */
static void
r4_submit(const char *id, const char *change, struct resp *r)
{
	char	path[256], *in;

	snprintf(path, sizeof(path), FLEET "%s/arcana-jobs:submit", id);
	ATF_REQUIRE(asprintf(&in, "\"change\":[%s]", change) != -1);
	rc_act(path, in, r);
	free(in);
}

/* The host's subscription token made anew: r's JSON the document. */
static void
r4_sub_token(const char *id, struct resp *r)
{
	char	path[256];

	snprintf(path, sizeof(path), CC "hosts/host=%s/subscription-token", id);
	rc_act(path, "", r);
}

/*
 * The console as a host's receiver (RFC 8639 section 2.5 over
 * HTTPS-notif): the host's candidate given what /subscription says and
 * committed, the agent connects to the TLS listener with its
 * certificate, the records come and are kept; the console restarted,
 * they are still there, the agent connects again and what it missed
 * meanwhile is replayed after them.
 */
CONSOLE_TC(notif_receiver, "A host's configured subscription to the "
    "console over HTTPS-notif: records kept, resumed over a restart")
ATF_TC_BODY(notif_receiver, tc)
{
	struct authn	 a;
	struct resp	 r;
	ucl_object_t	*cand;
	unsigned char	*json;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 64], id[16];
	char		 path[256], path2[256], token[80];
	int		 n, after;

	harness_tls_port = 20000 + (int)(getpid() % 20000);
	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	/* The host, known by the name its certificate has. */
	snprintf(body, sizeof(body), "\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "jgd.sock\",\"peer-name\":\"localhost\"", cwd);
	host_new(body, id, sizeof(id));
	/* Not the agent: no certificate, refused. */
	snprintf(path, sizeof(path), "/api/notif/%s/capabilities", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	/* Nothing yet. */
	r4_host_read(id, "notifications", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("0", jstr(&r, "last"));
	resp_free(&r);
	/* What to put: the console's endpoints for the host. */
	r4_host_read(id, "subscription", &r);
	EXPECT(&r, 200);
	snprintf(body, sizeof(body), "https://127.0.0.1:%d/api/notif/%s/"
	    "capabilities", harness_tls_port, id);
	ATF_CHECK_STREQ(body, jstr(&r, "candidate.ietf-subscribed-notifications:"
	    "subscriptions.ietf-subscribed-notif-receivers:receiver-instances."
	    "receiver-instance.0.ietf-https-notif-transport:https-receiver."
	    "capabilities-endpoint.uri"));
	ATF_CHECK_STREQ("certificate", jstr(&r, "notif_auth"));
	ATF_CHECK_STREQ("false", jstr(&r, "token"));
	cand = ucl_object_ref(ucl_object_lookup(r.json, "candidate"));
	snprintf(path, sizeof(path), "%s", jstr(&r, "put"));
	snprintf(body, sizeof(body), "%s", jstr(&r, "commit"));
	resp_free(&r);
	/* A token made for the host is shown once, in the document; the
	 * receiver, by the certificate alone (notif_auth's default),
	 * refuses a record with the token and no certificate. */
	r4_sub_token(id, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, NOTIF_TOKEN_PATH) != NULL);
	snprintf(token, sizeof(token), "%s", jstr(&r, NOTIF_TOKEN_PATH));
	ATF_CHECK_EQ(64, strlen(token));
	resp_free(&r);
	snprintf(path2, sizeof(path2), "/api/notif/%s/relay-notification", id);
	http_bearer("POST", path2, token, NOTIF_RECORD, &r);
	EXPECT(&r, 401);
	ATF_CHECK_STREQ("certificate", jstr(&r, "error.code"));
	resp_free(&r);
	json = ucl_object_emit(cand, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(cand);
	http("PUT", path, (const char *)json, &r);
	/* Made in the candidate, which had none (RFC 8040 section 4.5). */
	EXPECT(&r, 201);
	resp_free(&r);
	free(json);
	http("POST", body, "{\"ietf-netconf:input\":{}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	/* The agent connected: told subscription-started, kept. */
	ATF_REQUIRE_EQ(1, notif_count(id, "subscription-started", 1, 15));
	ATF_REQUIRE_EQ(1, notif_count(id, "replay-completed", 1, 5));
	/* An event of the host's: a record. */
	r4_submit(id, "{\"sysctl\":{\"args\":[\"kern.hostname\",\"lab\"]}}",
	    &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_REQUIRE(notif_count(id, "\"arcana-events:event\"", 1, 15) >= 1);
	r4_host_read(id, "notifications", &r);
	EXPECT(&r, 200);
	after = atoi(jstr(&r, "last"));
	ATF_CHECK(after >= 3);
	ATF_CHECK(strstr(r.body, "\"eventTime\":\"") != NULL);
	resp_free(&r);
	/* The subscription seen on the host, its receiver active. */
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/ietf-subscribed-notifications:subscriptions", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"state\":\"active\"") != NULL, "%s",
	    r.body);
	resp_free(&r);
	/* The console restarted: the records kept are there; the agent,
	 * whose POST failed meanwhile, connects again and replays what it
	 * missed after them. */
	restart_console();
	r4_submit(id, "{\"sysctl\":{\"args\":[\"kern.hostname\",\"lab2\"]}}",
	    &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_REQUIRE_EQ(2, notif_count(id, "subscription-started", 2, 30));
	snprintf(path, sizeof(path), "notifications?after=%d", after);
	n = 0;
	for (int i = 0; i < 100 && n == 0; i++) {
		r4_host_read(id, path, &r);
		EXPECT(&r, 200);
		if (strstr(r.body, "replay-previous-event-time") != NULL &&
		    strstr(r.body, "lab2") != NULL)
			n = atoi(jstr(&r, "last"));
		resp_free(&r);
		if (n == 0)
			usleep(100000);
	}
	ATF_CHECK_MSG(n > after, "no replay after the restart");
	/* All of them, from the first: nothing lost over the restart. */
	r4_host_read(id, "notifications", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("1", jstr(&r, "records.0.n"));
	ATF_CHECK(strstr(r.body, "\"kern.hostname=lab\"") != NULL ||
	    strstr(r.body, "lab") != NULL);
	resp_free(&r);
}

/*
 * The host's token beside its certificate (notif_auth = token): made
 * and shown once in the subscription document, kept hashed; on the
 * plain listener (TLS ended before it) it names the host, none or
 * another is refused; the agent, handed it in its candidate, sends it;
 * made anew, the one before is refused; with either, a bearer decides
 * where there is one, the certificate else.
 */
CONSOLE_TC(notif_token, "A host's token for the console's receiver, "
    "beside its certificate (notif_auth): records taken on a plain "
    "listener, the agent sends it, a new one retires the old")
ATF_TC_BODY(notif_token, tc)
{
	struct authn	 a;
	struct resp	 r;
	ucl_object_t	*cand;
	unsigned char	*json;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 64], id[16];
	char		 put[256], commit[256], relay[256], caps[256];
	char		 path[256], token[80], token2[80];

	harness_tls_port = 20000 + (int)(getpid() % 20000);
	snprintf(harness_webconf, sizeof(harness_webconf),
	    "notif_auth = \"token\";\n");
	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "jgd.sock\",\"peer-name\":\"localhost\"", cwd);
	host_new(body, id, sizeof(id));
	snprintf(path, sizeof(path), CC "hosts/host=%s", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r,
	    "arcana-console:host.0.notification-token-set"));
	resp_free(&r);
	snprintf(relay, sizeof(relay), "/api/notif/%s/relay-notification", id);
	snprintf(caps, sizeof(caps), "/api/notif/%s/capabilities", id);
	/* Made and shown once, in the document; the listing says the host
	 * has one, the GET of the document shows none. */
	r4_sub_token(id, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("token", jstr(&r, "notif_auth"));
	ATF_REQUIRE(jstr(&r, NOTIF_TOKEN_PATH) != NULL);
	snprintf(token, sizeof(token), "%s", jstr(&r, NOTIF_TOKEN_PATH));
	ATF_CHECK_EQ(64, strlen(token));
	cand = ucl_object_ref(ucl_object_lookup(r.json, "candidate"));
	snprintf(put, sizeof(put), "%s", jstr(&r, "put"));
	snprintf(commit, sizeof(commit), "%s", jstr(&r, "commit"));
	resp_free(&r);
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r,
	    "arcana-console:hosts.host.0.notification-token-set"));
	resp_free(&r);
	r4_host_read(id, "subscription", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "token"));
	ATF_CHECK(strstr(r.body, "arcana-notif:token") == NULL);
	ATF_CHECK(strstr(r.body, token) == NULL);
	resp_free(&r);
	/* On the plain listener: the token names the host; none, or
	 * another, is refused. */
	http_bearer("GET", caps, token, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, "encoding:json") != NULL);
	resp_free(&r);
	http_bearer("POST", relay, token, NOTIF_RECORD, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("POST", relay, NOTIF_RECORD, &r);
	EXPECT(&r, 401);
	ATF_CHECK_STREQ("token", jstr(&r, "error.code"));
	resp_free(&r);
	snprintf(token2, sizeof(token2), "%064d", 0);
	http_bearer("POST", relay, token2, NOTIF_RECORD, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	r4_host_read(id, "notifications", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("1", jstr(&r, "last"));
	resp_free(&r);
	/* The agent, handed the token in its candidate, sends it with
	 * each request: its records come over the TLS listener, the token
	 * judged. */
	json = ucl_object_emit(cand, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(cand);
	http("PUT", put, (const char *)json, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	free(json);
	http("POST", commit, "{\"ietf-netconf:input\":{}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	ATF_REQUIRE_EQ(1, notif_count(id, "subscription-started", 1, 15));
	ATF_REQUIRE_EQ(1, notif_count(id, "replay-completed", 1, 5));
	/* The token is not read back from the host but by a rule that
	 * permits it: the admin's does. */
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/ietf-subscribed-notifications:subscriptions", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"state\":\"active\"") != NULL, "%s",
	    r.body);
	resp_free(&r);
	/* A new token: the one before is refused. */
	r4_sub_token(id, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, NOTIF_TOKEN_PATH) != NULL);
	snprintf(token2, sizeof(token2), "%s", jstr(&r, NOTIF_TOKEN_PATH));
	resp_free(&r);
	ATF_CHECK(strcmp(token, token2) != 0);
	http_bearer("POST", relay, token, NOTIF_RECORD, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	http_bearer("POST", relay, token2, NOTIF_RECORD, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	/* either: a bearer decides where there is one; without one, the
	 * certificate, which the plain listener has none of. */
	ATF_REQUIRE_EQ(0, system("sed -i '' 's/notif_auth = \"token\"/"
	    "notif_auth = \"either\"/' web.conf"));
	restart_console();
	http_bearer("POST", relay, token2, NOTIF_RECORD, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http_bearer("POST", relay, token, NOTIF_RECORD, &r);
	EXPECT(&r, 401);
	ATF_CHECK_STREQ("token", jstr(&r, "error.code"));
	resp_free(&r);
	http("POST", relay, NOTIF_RECORD, &r);
	EXPECT(&r, 401);
	ATF_CHECK_STREQ("certificate", jstr(&r, "error.code"));
	resp_free(&r);
}

#define	HELD	"held: the host's subscription pushed it"

/*
 * A read of the console's own (hosts_read()), as a workflow's read step
 * asks it, the only reads the subscriptions answer: steps the reads,
 * by commas ("stats,jails"), of host id, a workflow of them made once;
 * its run's entry in r, each step's trace made the read's answer.
 */
static void
r4_wf_read(const char *id, const char *steps, struct resp *r)
{
	static struct {
		char	steps[64];
		char	wid[16];
	}		 made[8];
	static size_t	 nmade;
	char		 body[1024], run[24];
	const char	*p;
	size_t		 i, n;
	int		 k;

	for (i = 0; i < nmade; i++)
		if (strcmp(made[i].steps, steps) == 0)
			break;
	if (i == nmade) {
		ATF_REQUIRE(nmade < nitems(made));
		n = (size_t)snprintf(body, sizeof(body), "\"name\":\"read %s\","
		    "\"host\":[\"%s\"],\"step\":[", steps, id);
		for (p = steps, k = 0; *p != '\0'; k++) {
			n += (size_t)snprintf(body + n, sizeof(body) - n,
			    "%s{\"id\":\"s%d\",\"read\":\"%.*s\"}", k > 0 ? "," :
			    "", k, (int)strcspn(p, ","), p);
			p += strcspn(p, ",");
			if (*p == ',')
				p++;
		}
		snprintf(body + n, sizeof(body) - n, "]");
		snprintf(made[nmade].steps, sizeof(made[nmade].steps), "%s",
		    steps);
		r2_wf_new(body, made[nmade].wid, sizeof(made[nmade].wid));
		nmade++;
	}
	r2_run(made[i].wid, NULL, run, sizeof(run));
	run_wait(run, r);
	r2_traces(r);
}

/* Whether step k's answer, of r4_wf_read()'s run in r, says s. */
static bool
r4_step_has(const struct resp *r, int k, const char *s)
{
	char	 key[64], *t;
	bool	 has;

	snprintf(key, sizeof(key), "host.0.step.%d.trace", k);
	if ((t = (char *)ucl_object_emit(ucl_object_lookup_path(r->json, key),
	    UCL_EMIT_JSON_COMPACT)) == NULL)
		return (false);
	has = strstr(t, s) != NULL;
	free(t);
	return (has);
}

/* r's JSON and text made step k's answer, of r4_wf_read()'s run. */
static void
r4_step(struct resp *r, int k)
{
	char	key[64];

	snprintf(key, sizeof(key), "host.0.step.%d.trace", k);
	ATF_REQUIRE_MSG(resp_unwrap(r, key), "%s", r->body);
	free(r->body);
	r->body = (char *)ucl_object_emit(r->json, UCL_EMIT_JSON_COMPACT);
}

/* A host on the test's agent, its id in id. */
static void
watch_host(char *id, size_t len)
{
	char	cwd[MAXPATHLEN], uri[MAXPATHLEN + 64];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(uri, sizeof(uri), "unix:%s/jgd.sock", cwd);
	host_add("lab", uri, id, len);
}

/*
 * The console's subscription of topic at host id, as its watch says
 * it: its state and pushes, within secs of it being open with a push
 * since pushed (time(3)); asked for by read meanwhile, the console's
 * own read of it (r4_wf_read()'s steps).
 */
static bool
watch_open(const char *id, const char *topic, const char *read,
    time_t pushed, int secs)
{
	const ucl_object_t	*t;
	ucl_object_iter_t	 it;
	struct resp		 r;
	bool			 open;

	for (int i = 0; i < secs * 10; i++) {
		if (read != NULL) {
			r4_wf_read(id, read, &r);
			resp_free(&r);
		}
		r4_host_read(id, "watch", &r);
		EXPECT(&r, 200);
		open = false;
		it = NULL;
		while ((t = ucl_object_iterate(ucl_object_lookup(r.json,
		    "topics"), &it, true)) != NULL)
			if (strcmp(ucl_object_tostring(ucl_object_lookup(t,
			    "topic")), topic) == 0 && strcmp(ucl_object_tostring(
			    ucl_object_lookup(t, "state")), "open") == 0 &&
			    (pushed == 0 || ucl_object_toint(ucl_object_lookup(
			    t, "pushed")) >= pushed) && (strcmp(topic,
			    "events") == 0 || ucl_object_lookup(t, "pushed") !=
			    NULL))
				open = true;
		resp_free(&r);
		if (open)
			return (true);
		usleep(100000);
	}
	return (false);
}

/* The watch's count of what was asked of the agents, or answered
 * held. */
static long
watch_count(const char *id, const char *which)
{
	struct resp	 r;
	char		 path[128];
	long		 n;

	r4_host_read(id, "watch", &r);
	EXPECT(&r, 200);
	snprintf(path, sizeof(path), "requests.%s", which);
	n = jstr(&r, path) != NULL ? atol(jstr(&r, path)) : -1;
	resp_free(&r);
	return (n);
}

/*
 * PLAN-SDN-YANG 3.4.1: one connection per agent for its subscriptions,
 * made again when the agent comes back.  The console's first read of
 * the jails (a workflow's step) goes to the host and has them
 * subscribed; once pushed, its reads are answered from what is held.
 * The agent restarted, the connection is made again a while on, the
 * subscription with it, and the reads are answered from it again.
 */
CONSOLE_TC(watch_reconnect, "The subscriptions' connection to an agent: "
    "the reads answered from it, an agent restarted, it comes back")
ATF_TC_BODY(watch_reconnect, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 id[16], name[64];
	unsigned char	*host, *held;
	time_t		 t;
	int		 i;

	start(tc, 0, NULL);
	enrol(&a);
	watch_host(id, sizeof(id));
	r4_wf_read(id, "jails", &r);
	r4_step(&r, 0);
	ATF_CHECK(strstr(r.body, HELD) == NULL);
	ATF_REQUIRE(jstr(&r, "jails.0.name") != NULL);
	snprintf(name, sizeof(name), "%s", jstr(&r, "jails.0.name"));
	host = ucl_object_emit(ucl_object_lookup(r.json, "jails"),
	    UCL_EMIT_JSON_COMPACT);
	resp_free(&r);
	ATF_REQUIRE_MSG(watch_open(id, "jails", "jails", 0, 15),
	    "the jails not subscribed");
	r4_wf_read(id, "jails", &r);
	r4_step(&r, 0);
	ATF_CHECK_MSG(strstr(r.body, HELD) != NULL, "%s", r.body);
	/* As the host gives it: the host by hello, the jails, each as
	 * the host's own answer has it. */
	ATF_CHECK_STREQ(name, jstr(&r, "jails.0.name"));
	ATF_CHECK(jstr(&r, "host.version") != NULL);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	held = ucl_object_emit(ucl_object_lookup(r.json, "jails"),
	    UCL_EMIT_JSON_COMPACT);
	ATF_CHECK_MSG(host != NULL && held != NULL && strcmp((char *)host,
	    (char *)held) == 0, "the host's:\n%s\nheld:\n%s", host, held);
	free(host);
	free(held);
	resp_free(&r);
	r4_host_read(id, "watch", &r);
	ATF_CHECK_STREQ("true", jstr(&r, "connected"));
	ATF_CHECK_STREQ("0", jstr(&r, "reconnects"));
	resp_free(&r);

	t = time(NULL);
	agent_restart();
	/* Gone: the reads go to the host again; back, they are held. */
	ATF_REQUIRE_MSG(watch_open(id, "jails", "jails", t, 30),
	    "the subscription did not come back");
	r4_host_read(id, "watch", &r);
	ATF_CHECK_STREQ("true", jstr(&r, "connected"));
	ATF_CHECK(jstr(&r, "reconnects") != NULL && atoi(jstr(&r,
	    "reconnects")) >= 1);
	resp_free(&r);
	for (i = 0; i < 50; i++) {
		r4_wf_read(id, "jails", &r);
		r4_step(&r, 0);
		if (strstr(r.body, HELD) != NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_REQUIRE_MSG(i < 50, "not held after the agent came back");
	ATF_CHECK_STREQ(name, jstr(&r, "jails.0.name"));
	resp_free(&r);
}

/* What the fleet's stream s says until want is in buf, for secs at most. */
static bool
sse_until(int s, char *buf, size_t *len, size_t cap, const char *want,
    int secs)
{
	time_t	t0 = time(NULL);
	ssize_t	n;

	while (strstr(buf, want) == NULL && time(NULL) - t0 < secs &&
	    *len < cap - 1) {
		if ((n = read(s, buf + *len, cap - 1 - *len)) <= 0) {
			if (n == 0)
				break;
			continue;
		}
		*len += (size_t)n;
		buf[*len] = '\0';
	}
	return (strstr(buf, want) != NULL);
}

/* How many arcana-events records buf has from p on. */
static int
events_count(const char *p)
{
	int	n = 0;

	while ((p = strstr(p, "\"arcana-events:event\":")) != NULL) {
		p++;
		n++;
	}
	return (n);
}

/*
 * The numbers of the arcana-events records in buf from p on, to end
 * (NULL: to its end), each one more than the one before; how many.
 * Every data line once.
 */
static int
events_continuous(const char *p, const char *end, const char *what)
{
	const char	*k = "\"arcana-events:event\":", *num, *nl;
	unsigned long	 v, prev = 0;
	int		 n = 0;

	while ((p = strstr(p, k)) != NULL && (end == NULL || p < end)) {
		p += strlen(k);
		nl = strchr(p, '\n');
		if ((num = strstr(p, "\"number\":\"")) == NULL || (nl != NULL &&
		    num > nl))
			continue;
		v = strtoul(num + 10, NULL, 10);
		ATF_CHECK_MSG(n == 0 || v == prev + 1, "%s: %lu after %lu",
		    what, v, prev);
		prev = v;
		n++;
	}
	return (n);
}

/*
 * The fleet's stream outlives a host's agent restarting: its stream
 * ended is said, the host subscribed again by the console, from its
 * last record on, said heard again; what came after on the same reply,
 * numbered on without a gap or a record twice.  A host removed is not
 * asked again: said so, the reply ends.
 */
/*
 * The fleet's stream read on socket s into buf (cap long, len had), of
 * a console with one host (its id into id), until a job's event of the
 * host's on it.
 */
static int
fs_open(const atf_tc_t *tc, struct authn *a, char *id, size_t idlen,
    char *buf, size_t *lenp, size_t cap)
{
	struct resp	 r;
	struct timeval	 tv = { 2, 0 };
	char		 rq[512];
	int		 s;

	start(tc, 0, NULL);
	enrol(a);
	watch_host(id, idlen);
	s = console_socket();
	ATF_REQUIRE(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv,
	    sizeof(tv)) == 0);
	snprintf(rq, sizeof(rq), "GET /restconf/streams/fleet/json "
	    "HTTP/1.1\r\nHost: localhost:8443\r\nCookie: %s\r\n\r\n", cookie);
	ATF_REQUIRE(write(s, rq, strlen(rq)) == (ssize_t)strlen(rq));
	ATF_REQUIRE_MSG(sse_until(s, buf, lenp, cap, "fleet's stream", 10),
	    "%s", buf);
	/* Subscribed once the thread has the host: then a job. */
	usleep(1500000);
	r4_submit(id, "{\"monitor\":{\"verb\":\"set\",\"args\":["
	    "\"name=gre9\",\"interface=gre9\",\"address=192.0.2.9\","
	    "\"interval=500\",\"eval=10000\"]}}", &r);
	resp_free(&r);
	ATF_REQUIRE_MSG(sse_until(s, buf, lenp, cap, "arcana-events:event",
	    15), "%s", buf);
	return (s);
}

CONSOLE_TC(fleet_stream_rejoin, "The fleet's event stream subscribes "
    "again to a host whose agent restarted")
ATF_TC_BODY(fleet_stream_rejoin, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 id[16], want[128];
	char		*buf, *info, *line, *nl;
	size_t		 len = 0, cap = 1 << 20;
	ssize_t		 n;
	int		 s, before, after;

	ATF_REQUIRE((buf = calloc(1, cap)) != NULL);
	s = fs_open(tc, &a, id, sizeof(id), buf, &len, cap);

	/* The agent restarted: said lost, then heard again. */
	agent_restart();
	snprintf(want, sizeof(want), "host %s: ", id);
	ATF_CHECK_MSG(sse_until(s, buf, &len, cap, "event: error", 15) &&
	    strstr(strstr(buf, "event: error"), want) != NULL, "%s", buf);
	snprintf(want, sizeof(want), "event: info\ndata: {\"host\":\"%s\"", id);
	ATF_REQUIRE_MSG(sse_until(s, buf, &len, cap, want, 30), "%s", buf);
	/* A job's event after it, on the same reply. */
	after = events_count(strstr(buf, want));
	r4_submit(id, "{\"monitor\":{\"verb\":\"set\",\"args\":["
	    "\"name=gre8\",\"interface=gre8\",\"address=192.0.2.8\","
	    "\"interval=500\",\"eval=10000\"]}}", &r);
	resp_free(&r);
	for (n = 0; n < 15 && events_count(strstr(buf, want)) <= after; n++)
		(void)sse_until(s, buf, &len, cap, "\a", 1);
	ATF_CHECK_MSG(events_count(strstr(buf, want)) > after, "%s", buf);
	info = strstr(buf, want);
	before = events_continuous(buf, info, "before the restart");
	after = events_continuous(info, NULL, "after the restart");
	ATF_CHECK_MSG(before > 0 && after > 0, "%d before, %d after:\n%s",
	    before, after, buf);
	/* No record twice. */
	for (line = buf; (line = strstr(line, "\ndata: {\"ietf-restconf:"
	    "notification\"")) != NULL; line = nl) {
		line++;
		if ((nl = strchr(line, '\n')) == NULL)
			break;
		*nl = '\0';
		ATF_CHECK_MSG(strstr(nl + 1, line) == NULL, "twice: %s", line);
		*nl = '\n';
	}
	close(s);
	free(buf);
}

CONSOLE_TC(fleet_stream_removed, "The fleet's event stream lets go of a "
    "host removed")
ATF_TC_BODY(fleet_stream_removed, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 id[16], path[128], want[128];
	char		*buf;
	size_t		 len = 0, cap = 1 << 20;
	ssize_t		 n;
	int		 s;

	ATF_REQUIRE((buf = calloc(1, cap)) != NULL);
	s = fs_open(tc, &a, id, sizeof(id), buf, &len, cap);
	/* Removed: its stream ended, it is not asked again; the reply
	 * ends, it was the only one. */
	snprintf(path, sizeof(path), CC "hosts/host=%s", id);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	agent_restart();
	snprintf(want, sizeof(want), "host %s: removed", id);
	ATF_CHECK_MSG(sse_until(s, buf, &len, cap, want, 15), "%s", buf);
	ATF_CHECK_MSG(sse_until(s, buf, &len, cap, "every host was removed",
	    10), "%s", buf);
	n = strstr(buf, want) != NULL ? (ssize_t)(strstr(buf, want) - buf) :
	    0;
	ATF_CHECK_MSG(strstr(buf + n, "event: info") == NULL, "%s", buf);
	close(s);
	free(buf);
}

/*
 * PLAN-SDN-YANG 3.4.2: the console's own reads (a workflow's read
 * steps, hosts_read()) answered from the subscriptions, in the shapes
 * the host's answers have: the stats (periodic) and the jails
 * (periodic); nothing asked of the agent meanwhile but the jails'
 * host by hello.  A job a workflow waits on (hosts_job()) has the
 * jobs subscribed (on-change).  The SD-WAN state is no longer held:
 * the console's own reads of it ask for all its samples (no after=),
 * which only the host has.
 */
CONSOLE_TC(watch_held, "The stats and jails the console reads answered "
    "from subscriptions, nothing asked of the agent; a job waited on "
    "has the jobs subscribed")
ATF_TC_BODY(watch_held, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 id[16], wid[16], run[24], body[512];
	long		 asked, held;
	int		 i;

	start(tc, 0, NULL);
	enrol(&a);
	watch_host(id, sizeof(id));
	/* The host's own answers, before. */
	r4_wf_read(id, "stats", &r);
	ATF_CHECK(!r4_step_has(&r, 0, HELD));
	r4_step(&r, 0);
	ATF_CHECK_MSG(jstr(&r, "stats.mem_total") != NULL, "%s", r.body);
	resp_free(&r);
	ATF_REQUIRE(watch_open(id, "stats", "stats", 0, 15));
	ATF_REQUIRE(watch_open(id, "jails", "jails", 0, 15));
	asked = watch_count(id, "asked");
	held = watch_count(id, "held");
	for (i = 0; i < 20; i++) {
		r4_wf_read(id, "stats,jails", &r);
		ATF_CHECK(r4_step_has(&r, 0, HELD));
		ATF_CHECK(r4_step_has(&r, 1, HELD));
		ATF_CHECK(jstr(&r, "host.0.step.0.trace.stats.mem_total") !=
		    NULL);
		ATF_CHECK(jstr(&r, "host.0.step.0.trace.stats.cpu_pct") != NULL);
		ATF_CHECK(jstr(&r, "host.0.step.1.trace.jails.0.name") != NULL);
		ATF_CHECK(ucl_object_lookup_path(r.json,
		    "host.0.step.1.trace.scopes") != NULL);
		resp_free(&r);
	}
	/* The jails' host by its hello alone, each time: what tools it
	 * has can change unannounced. */
	ATF_CHECK_MSG(watch_count(id, "asked") == asked + 20, "the agent was "
	    "asked %ld times", watch_count(id, "asked") - asked);
	ATF_CHECK(watch_count(id, "held") >= held + 40);

	/* A job a workflow waits on: the jobs subscribed for it. */
	snprintf(body, sizeof(body), "\"name\":\"a job\",\"host\":[\"%s\"],"
	    "\"step\":[{\"id\":\"j\",\"job\":{\"kind\":\"sysctl\",\"field\":["
	    "{\"name\":\"args\",\"json\":"
	    "\"[\\\"kern.hostname\\\",\\\"lab\\\"]\"}]}}]", id);
	r2_wf_new(body, wid, sizeof(wid));
	r2_run(wid, NULL, run, sizeof(run));
	run_wait(run, &r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "state"), "done") == 0, "%s", r.body);
	resp_free(&r);
	ATF_CHECK_MSG(watch_open(id, "jobs", NULL, 0, 15),
	    "the jobs not subscribed");
}

/*
 * PLAN-SDN-YANG 3.4.3: the host's events told to each page that follows
 * them on the host's NETCONF stream (RESTCONF's SSE), within a second of
 * the agent telling it: sysctl.conf changed by somebody else, the agent
 * told by the kernel (EVFILT_VNODE).
 */
CONSOLE_TC(watch_events, "A host's events told on its stream to each "
    "page that follows them within a second")
ATF_TC_BODY(watch_events, tc)
{
	struct authn	 a;
	struct resp	 r;
	struct timespec	 t0, t1;
	struct pollfd	 pfd[2];
	struct timeval	 tv = { 2, 0 };
	char		 id[16], rq[512], path[160], in[64], *buf[2];
	size_t		 len[2], mark[2], cap = 1 << 18;
	ssize_t		 k;
	double		 secs;
	long		 last;
	bool		 got[2], told;
	int		 s[2], n, j;

	start(tc, 0, NULL);
	enrol(&a);
	watch_host(id, sizeof(id));
	for (j = 0; j < 2; j++) {
		ATF_REQUIRE((buf[j] = calloc(1, cap)) != NULL);
		len[j] = 0;
		got[j] = false;
		s[j] = console_socket();
		ATF_REQUIRE(setsockopt(s[j], SOL_SOCKET, SO_RCVTIMEO, &tv,
		    sizeof(tv)) == 0);
		snprintf(rq, sizeof(rq), "GET /restconf/streams/%s/json "
		    "HTTP/1.1\r\nHost: localhost:8443\r\nCookie: %s\r\n\r\n",
		    id, cookie);
		ATF_REQUIRE(write(s[j], rq, strlen(rq)) == (ssize_t)strlen(rq));
		ATF_REQUIRE_MSG(sse_until(s[j], buf[j], &len[j], cap,
		    "NETCONF stream", 10), "%s", buf[j]);
	}
	/* Subscribed once each thread has the host. */
	usleep(1500000);
	mark[0] = len[0];
	mark[1] = len[1];
	/* The last the agent has, read from it. */
	snprintf(path, sizeof(path), FLEET "%s/arcana-events:events/read", id);
	rc_act(path, "", &r);
	EXPECT(&r, 200);
	last = jstr(&r, "last") != NULL ? atol(jstr(&r, "last")) : 0;
	resp_free(&r);
	/*
	 * The agent says what it saw once a second: when it has the event
	 * is when its read has it, asked meanwhile; each page has it
	 * within a second of that.
	 */
	ATF_REQUIRE(system("echo 'kern.maxfiles=4321' >> sysctl.conf") == 0);
	told = false;
	secs = 0;
	memset(&t0, 0, sizeof(t0));
	snprintf(in, sizeof(in), "\"after\":%ld", last);
	for (n = 0; n < 2000 && !(got[0] && got[1]); n++) {
		if (!told) {
			rc_act(path, in, &r);
			if (r.status == 200 && strstr(r.body, "sysctl.conf") !=
			    NULL) {
				clock_gettime(CLOCK_MONOTONIC, &t0);
				told = true;
			}
			resp_free(&r);
		}
		for (j = 0; j < 2; j++) {
			pfd[j].fd = s[j];
			pfd[j].events = POLLIN;
			pfd[j].revents = 0;
		}
		if (poll(pfd, 2, 20) < 1)
			continue;
		for (j = 0; j < 2; j++) {
			if ((pfd[j].revents & POLLIN) == 0 || len[j] >= cap - 1)
				continue;
			k = read(s[j], buf[j] + len[j], cap - 1 - len[j]);
			if (k <= 0)
				continue;
			len[j] += (size_t)k;
			buf[j][len[j]] = '\0';
			if (got[j] || strstr(buf[j] + mark[j], "sysctl.conf") ==
			    NULL)
				continue;
			clock_gettime(CLOCK_MONOTONIC, &t1);
			if (!told) {
				t0 = t1;
				told = true;
			}
			secs = (double)(t1.tv_sec - t0.tv_sec) +
			    (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
			got[j] = true;
		}
	}
	ATF_REQUIRE_MSG(got[0] && got[1], "the event not told to both:\n%s\n"
	    "%s", buf[0] + mark[0], buf[1] + mark[1]);
	printf("the event in the page %.3f s after the agent had it\n", secs);
	ATF_CHECK_MSG(secs < 1.0, "the event came %.3f s after", secs);
	for (j = 0; j < 2; j++) {
		close(s[j]);
		free(buf[j]);
	}
}

/*
 * What is held is held for one user, read as that user: the host's
 * access rules (NACM) let the admin read arcana-host and deny it bob;
 * once the admin's reads (his workflow's steps, the console's own
 * reads acting for who runs it) are held, bob's (the same workflow run
 * by him) are never answered with them, his own subscription read as
 * him.
 */
CONSOLE_TC(watch_nacm, "What the subscriptions hold is one user's, read "
    "as that user: another whose rules deny it never sees it")
ATF_TC_BODY(watch_nacm, tc)
{
	static const char rules[] = "{\"groups\":{\"group\":[{\"name\":"
	    "\"admin\",\"user-name\":[\"admin\",\"console\"]},{\"name\":"
	    "\"ops\",\"user-name\":[\"bob\"]}]},\"rule-list\":[{\"name\":"
	    "\"admin\",\"group\":[\"admin\"],\"rule\":[{\"name\":\"all\","
	    "\"module-name\":\"*\",\"access-operations\":\"*\",\"action\":"
	    "\"permit\"}]},{\"name\":\"ops\",\"group\":[\"ops\"],\"rule\":["
	    "{\"name\":\"no-probe\",\"module-name\":\"arcana-probe\","
	    "\"access-operations\":\"*\",\"action\":\"deny\"},{\"name\":"
	    "\"no-host\",\"module-name\":\"arcana-host\",\"access-operations\":"
	    "\"*\",\"action\":\"deny\"}]}]}";
	struct authn	 a, b;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], cmd[3 * MAXPATHLEN], id[16];
	char		 invite[80], *t;
	const char	*ctl;
	FILE		*fp;
	int		 i;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ctl = locate(tc, "../../../usr.sbin/arcanactl/arcanactl", "arcanactl",
	    "/usr/local/sbin/arcanactl");
	ATF_REQUIRE((fp = fopen("rules.json", "w")) != NULL);
	fprintf(fp, "%s\n", rules);
	fclose(fp);
	snprintf(cmd, sizeof(cmd), "%s -c unix:%s/jgd.sock edit nacm "
	    "@rules.json && %s -c unix:%s/jgd.sock commit", ctl, cwd, ctl, cwd);
	ATF_REQUIRE_EQ_MSG(0, system(cmd), "%s", cmd);
	watch_host(id, sizeof(id));
	/* bob runs the console's workflows: an operator of it. */
	http("PUT", CC "roles/role=ops", "{\"arcana-console:role\":[{\"name\":"
	    "\"ops\",\"console\":\"operator\",\"host\":[{\"id\":\"*\","
	    "\"role\":\"operator\"}]}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("PUT", CC "users/user=bob", "{\"arcana-console:user\":[{\"name\":"
	    "\"bob\",\"role\":[\"ops\"]}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("POST", CC "users/user=bob/invite", NULL, &r);
	EXPECT(&r, 200);
	snprintf(invite, sizeof(invite), "%s", jstr(&r,
	    "arcana-console:output.token"));
	resp_free(&r);

	/* The admin's, held. */
	ATF_REQUIRE(watch_open(id, "stats", "stats", 0, 15));
	r4_wf_read(id, "stats", &r);
	ATF_CHECK(r4_step_has(&r, 0, HELD));
	ATF_CHECK(jstr(&r, "host.0.step.0.trace.stats.mem_total") != NULL);
	resp_free(&r);

	/* bob, while the admin's stay held: never the admin's (his own
	 * held, the stats his rules deny him left out). */
	cookie[0] = '\0';
	authn_new(&b, -8);
	do_register(&b, invite, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bob", jstr(&r, "user"));
	resp_free(&r);
	for (i = 0; i < 10; i++) {
		r4_wf_read(id, "stats", &r);
		t = (char *)ucl_object_emit(ucl_object_lookup_path(r.json,
		    "host.0.step.0"), UCL_EMIT_JSON_COMPACT);
		ATF_CHECK_MSG(jstr(&r, "host.0.step.0.trace.stats.mem_total") ==
		    NULL, "bob was given the stats: %.600s", t);
		free(t);
		resp_free(&r);
	}
	/* His own subscriptions, as him. */
	r4_host_read(id, "watch", &r);
	ATF_CHECK_MSG(strstr(r.body, "\"user\":\"bob\"") != NULL, "%s", r.body);
	resp_free(&r);
}

#define	CF	CC "threat-feeds/feed="

/*
 * Of a feed's entry in r, the value at key: a dotted path, or
 * "<list>=<host>/<leaf>" for the leaf of the entry of list (delivered,
 * last-preview.host) that is host's.
 */
static const char *
feed_str(const struct resp *r, const char *key)
{
	const char	*eq, *sl, *h;
	char		 k[160];
	int		 i;

	if ((eq = strchr(key, '=')) == NULL)
		return (jstr(r, key));
	ATF_REQUIRE((sl = strchr(eq, '/')) != NULL);
	for (i = 0; i < 64; i++) {
		snprintf(k, sizeof(k), "%.*s.%d.host", (int)(eq - key), key, i);
		if ((h = jstr(r, k)) == NULL)
			return (NULL);
		if (strlen(h) != (size_t)(sl - eq - 1) || strncmp(h, eq + 1,
		    (size_t)(sl - eq - 1)) != 0)
			continue;
		snprintf(k, sizeof(k), "%.*s.%d.%s", (int)(eq - key), key, i,
		    sl + 1);
		return (jstr(r, k));
	}
	return (NULL);
}

/*
 * GET of feed id until what is told: a key that is there (feed_str()'s),
 * its value want where want is not NULL; r's JSON the feed's entry.
 */
static void
feed_wait(const char *id, const char *key, const char *want,
    struct resp *r)
{
	char	path[96];
	int	i;

	snprintf(path, sizeof(path), CF "%s", id);
	for (i = 0; i < 300; i++) {
		http("GET", path, NULL, r);
		if (r->status == 200 && resp_unwrap(r,
		    "arcana-console:feed.0") && feed_str(r, key) != NULL &&
		    (want == NULL ||
		    strcmp(feed_str(r, key), want) == 0))
			return;
		resp_free(r);
		usleep(100000);
	}
	http("GET", path, NULL, r);
	atf_tc_fail("feed %s: no %s%s%s: %s", id, key, want != NULL ? " = " :
	    "", want != NULL ? want : "", r->body);
}

/* GET of feed id once; r's JSON its entry. */
static void
feed_get(const char *id, struct resp *r)
{
	char	path[96];

	snprintf(path, sizeof(path), CF "%s", id);
	http("GET", path, NULL, r);
	EXPECT(r, 200);
	ATF_CHECK(resp_unwrap(r, "arcana-console:feed.0"));
}

/* PUT of feed id, members its entry's but the id; the answer in r. */
static void
feed_put(const char *id, const char *members, struct resp *r)
{
	char	path[96], *body;

	snprintf(path, sizeof(path), CF "%s", id);
	ATF_REQUIRE(asprintf(&body, "{\"arcana-console:feed\":[{\"id\":"
	    "\"%s\"%s%s}]}", id, members[0] != '\0' ? "," : "", members) !=
	    -1);
	http("PUT", path, body, r);
	free(body);
}

/* The same, kept: 201 or 204. */
static void
feed_keep(const char *id, const char *members)
{
	struct resp	r;

	feed_put(id, members, &r);
	ATF_CHECK_MSG(r.status == 201 || r.status == 204, "feed %s: %d %s",
	    id, r.status, r.body);
	resp_free(&r);
}

/* POST of feed id's action verb (fetch, preview); its status. */
static int
feed_ask(const char *id, const char *verb)
{
	struct resp	r;
	char		path[96];
	int		st;

	snprintf(path, sizeof(path), CF "%s/%s", id, verb);
	http("POST", path, NULL, &r);
	st = r.status;
	resp_free(&r);
	return (st);
}

/* The feed's dropped entries below base in r: is entry there with a
 * reason or detail that has why? */
static bool
cc_dropped(const struct resp *r, const char *base, const char *entry,
    const char *why)
{
	char	k[160];
	int	i;

	for (i = 0; i < 50; i++) {
		snprintf(k, sizeof(k), "%s.dropped.%d.entry", base, i);
		if (jstr(r, k) == NULL)
			return (false);
		if (strcmp(jstr(r, k), entry) != 0)
			continue;
		snprintf(k, sizeof(k), "%s.dropped.%d.reason", base, i);
		if (strstr(jstr(r, k), why) != NULL)
			return (true);
		snprintf(k, sizeof(k), "%s.dropped.%d.detail", base, i);
		return (jstr(r, k) != NULL && strstr(jstr(r, k), why) != NULL);
	}
	return (false);
}

/* What the feed in r last fetched dropped. */
static bool
feed_dropped(const struct resp *r, const char *entry, const char *why)
{

	return (cc_dropped(r, "last-fetch", entry, why));
}

/* A host the stand-in agent answers for, named name: its id into sid. */
static void
cc_host(const char *name, const char *sock, char *sid, size_t len)
{
	char	cwd[MAXPATHLEN], uri[MAXPATHLEN + 64];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(uri, sizeof(uri), "unix:%s/%s", cwd, sock);
	host_add(name, uri, sid, len);
}

/* Role name: console's role, hosts its host entries ({"id":...}), ""
 * for none. */
static void
cc_role(const char *name, const char *console, const char *hosts)
{
	struct resp	 r;
	char		 path[96], *body;

	snprintf(path, sizeof(path), CC "roles/role=%s", name);
	ATF_REQUIRE(asprintf(&body, "{\"arcana-console:role\":[{\"name\":"
	    "\"%s\",\"console\":\"%s\"%s%s%s}]}", name, console,
	    hosts[0] != '\0' ? ",\"host\":[" : "", hosts,
	    hosts[0] != '\0' ? "]" : "") != -1);
	http("PUT", path, body, &r);
	free(body);
	ATF_CHECK_MSG(r.status == 201 || r.status == 204, "role %s: %d %s",
	    name, r.status, r.body);
	resp_free(&r);
}

/* User name of role role made and invited: the invitation into inv. */
static void
cc_invite(const char *name, const char *role, char *inv, size_t len)
{
	struct resp	 r;
	char		 path[96], *body;

	snprintf(path, sizeof(path), CC "users/user=%s", name);
	ATF_REQUIRE(asprintf(&body, "{\"arcana-console:user\":[{\"name\":"
	    "\"%s\",\"role\":[\"%s\"]}]}", name, role) != -1);
	http("PUT", path, body, &r);
	free(body);
	ATF_CHECK_MSG(r.status == 201 || r.status == 204, "user %s: %d %s",
	    name, r.status, r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), CC "users/user=%s/invite", name);
	http("POST", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "arcana-console:output.token") != NULL);
	snprintf(inv, len, "%s", jstr(&r, "arcana-console:output.token"));
	resp_free(&r);
}

/*
 * The feeds' console: the stand-in source (its port returned), host a
 * (id into sa), far at 192.0.2.77, near at 100.64.0.5 (id into sn) and
 * gone, which no agent answers for (id into sg); alice last signed in
 * from 203.0.113.9.
 */
static int
feeds_start(const atf_tc_t *tc, struct authn *a, char *sa, char *sn,
    char *sg, size_t len)
{
	char	sf[16];
	int	port;

	port = feeds_server(tc);
	start(tc, 0, NULL);
	enrol(a);
	cc_host("a", "jgd.sock", sa, len);
	/* A host the console reaches at 192.0.2.77, and a user who last
	 * signed in from 203.0.113.9: no feed is to cut either off. */
	host_add("far", "tcp://192.0.2.77:4310", sf, sizeof(sf));
	/* And one at 100.64.0.5, which the operator below may read. */
	host_add("near", "tcp://100.64.0.5:4310", sn, len);
	/* And one no agent answers for, which the operator may not read. */
	cc_host("gone", "none.sock", sg, len);
	put("data/signins.json", "{\"alice\":{\"addr\":\"203.0.113.9\","
	    "\"at\":1}}");
	return (port);
}

/* The stand-in's 127.0.0.1 let through by the settings. */
static void
feeds_allow(void)
{
	struct resp	r;

	http("PATCH", CC "settings", "{\"arcana-console:settings\":{"
	    "\"feeds-allow-private\":\"127.0.0.1/32\"}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
}

/* Spamhaus DROP on host sa, until delivered there; the feed in r. */
static void
feeds_spamhaus(int port, const char *sa, struct resp *r)
{
	char	body[1024], k[96];

	snprintf(body, sizeof(body), "\"preset\":\"spamhaus-drop-v4\","
	    "\"url\":\"http://127.0.0.1:%d/drop_v4.json\",\"enabled\":true,"
	    "\"host\":[\"%s\"]", port, sa);
	feed_keep("spamhaus-drop-v4", body);
	snprintf(k, sizeof(k), "delivered=%s/at", sa);
	feed_wait("spamhaus-drop-v4", k, NULL, r);
	ATF_CHECK_STREQ("feed_spamhaus_drop_v4", jstr(r, "table"));
	ATF_CHECK_STREQ("12", jstr(r, "interval"));
}

/* A feed of the stand-in's kept with members, until key is there (want,
 * if not NULL); the feed in r. */
static void
feeds_put(const char *id, const char *members, const char *key,
    const char *want, struct resp *r)
{

	feed_keep(id, members);
	feed_wait(id, key, want, r);
}

/* FireHOL level 1 on host sa, until fetched; the feed in r. */
static void
feeds_firehol(int port, const char *sa, struct resp *r)
{
	char	body[1024];

	snprintf(body, sizeof(body), "\"preset\":\"firehol-level1\",\"url\":"
	    "\"http://127.0.0.1:%d/firehol_level1.netset\",\"enabled\":true,"
	    "\"host\":[\"%s\"]", port, sa);
	feeds_put("firehol-level1", body, "fetched-at", NULL, r);
}

/* A list of one's own on host sa, of every kind of entry, until
 * fetched; the feed in r. */
static void
feeds_local(int port, const char *sa, struct resp *r)
{
	char	body[1024];

	snprintf(body, sizeof(body), "\"name\":\"Local\",\"url\":\"http://"
	    "127.0.0.1:%d/local.txt\",\"format\":\"plain\",\"interval\":1,"
	    "\"enabled\":true,\"host\":[\"%s\"]", port, sa);
	feeds_put("local", body, "fetched-at", NULL, r);
	ATF_CHECK_STREQ("feed_local", jstr(r, "table"));
}

/* A feed of chosen addresses, until fetched; the feed in r. */
static void
feeds_oracle(int port, struct resp *r)
{
	char	body[1024];

	snprintf(body, sizeof(body), "\"url\":\"http://127.0.0.1:%d/"
	    "oracle.txt\",\"enabled\":true", port);
	feeds_put("oracle", body, "fetched-at", NULL, r);
}

/* A feed on host sg, which fails there, until its error is told; then
 * its preview's.  The feed in r. */
static void
feeds_seen(int port, const char *sg, struct resp *r)
{
	char	body[1024], k[96];

	snprintf(body, sizeof(body), "\"url\":\"http://127.0.0.1:%d/"
	    "drop_v4.json\",\"format\":\"spamhaus-json\",\"enabled\":true,"
	    "\"host\":[\"%s\"]", port, sg);
	snprintf(k, sizeof(k), "delivered=%s/error", sg);
	feeds_put("seen", body, k, NULL, r);
	snprintf(k, sizeof(k), "delivered=%s/name", sg);
	ATF_CHECK_STREQ("gone", feed_str(r, k));
	resp_free(r);
	ATF_CHECK_EQ(204, feed_ask("seen", "preview"));
	snprintf(k, sizeof(k), "last-preview.host=%s/error", sg);
	feed_wait("seen", k, NULL, r);
}

CONSOLE_TC(feeds, "Threat feeds: what resolves to private space refused "
    "unless let through; the presets; Spamhaus DROP fetched by the console "
    "with If-Modified-Since, delivered as an ipfw table swapped in; "
    "FireHOL's bogons kept but for the console's address")
ATF_TC_BODY(feeds, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[1024], sa[16], sn[16], sg[16], k[96];
	int		port, i;

	port = feeds_start(tc, &a, sa, sn, sg, sizeof(sa));
	/* A feed comes from the internet: what resolves to loopback,
	 * private space or a cloud's metadata is refused, unless Settings
	 * let its prefix through; the stand-in's 127.0.0.1 so. */
	{
		static const char *const priv[] = { "127.0.0.1", "10.0.0.1",
		    "169.254.169.254", "[::1]" };

		for (i = 0; i < 4; i++) {
			snprintf(body, sizeof(body), "\"url\":\"http://%s:%d/"
			    "drop_v4.json\"", priv[i], port);
			feed_put("x", body, &r);
			ATF_CHECK_MSG(r.status == 400 && strstr(r.body,
			    "is a private or reserved address") != NULL, "%s: %s",
			    priv[i], r.body);
			resp_free(&r);
		}
	}
	feeds_allow();

	/* The presets, off, each with its source and its terms. */
	http("GET", CC "threat-feeds", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("spamhaus-drop-v4", jstr(&r,
	    "arcana-console:threat-feeds.preset.0.id"));
	ATF_CHECK_STREQ("https://www.spamhaus.org/drop/terms/", jstr(&r,
	    "arcana-console:threat-feeds.preset.0.terms-url"));
	ATF_CHECK_STREQ("true", jstr(&r,
	    "arcana-console:threat-feeds.preset.2.bogons"));
	ATF_CHECK(jstr(&r, "arcana-console:threat-feeds.feed.0.id") == NULL);
	resp_free(&r);
	/* What is no feed: refused. */
	feed_put("x", "\"url\":\"ftp://example.org/x\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	feed_put("x", "\"url\":\"https://example.org/x\",\"interval\":0", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	feed_put("x", "\"url\":\"https://example.org/x\",\"table\":"
	    "\"bad table\"", &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/* Spamhaus DROP, its JSON lines: fetched, kept, sent to host a as
	 * a table filled by a scratch one and swapped in. */
	feeds_spamhaus(port, sa, &r);
	ATF_CHECK_STREQ("4", jstr(&r, "count"));
	ATF_CHECK_STREQ("1.10.16.0/20", jstr(&r, "sample.0"));
	snprintf(k, sizeof(k), "delivered=%s/count", sa);
	ATF_CHECK_STREQ("4", feed_str(&r, k));
	ATF_CHECK_STREQ("4", jstr(&r, "event.0.count"));
	resp_free(&r);
	ATF_CHECK(system("grep -q 'table feed_spamhaus_drop_v4 swap "
	    "feed_spamhaus_drop_v4_load' ipfw.log") == 0);
	ATF_CHECK(system("grep -q 'table feed_spamhaus_drop_v4_load add "
	    "1.10.16.0/20 0 1.19.0.0/16 0' ipfw.log") == 0);
	ATF_CHECK(system("grep -q '^# arcana feed spamhaus-drop-v4$' "
	    "feeds/feed_spamhaus_drop_v4") == 0);
	/* Fetched again: If-Modified-Since, a 304, nothing sent again. */
	ATF_REQUIRE(system(": > ipfw.log") == 0);
	ATF_CHECK_EQ(204, feed_ask("spamhaus-drop-v4", "fetch"));
	for (i = 0; i < 300 && system("grep -q 'drop_v4.json 304' "
	    "feedsrv.log") != 0; i++)
		usleep(100000);
	ATF_CHECK(system("grep -q 'drop_v4.json 304' feedsrv.log") == 0);
	usleep(500000);
	ATF_CHECK(system("grep -q 'swap' ipfw.log") != 0);

	/* FireHOL level 1 lists the bogons on purpose: kept, but for what
	 * covers the console's own 127.0.0.1. */
	feeds_firehol(port, sa, &r);
	ATF_CHECK_MSG(feed_dropped(&r, "127.0.0.0/8", "covers 127.0.0.1, the "
	    "console's"), "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"198.18.0.0/15\"") != NULL, "%s",
	    r.body);
	ATF_CHECK_STREQ("13", jstr(&r, "count"));
	resp_free(&r);
}

CONSOLE_TC(feeds_local, "Threat feeds: a list of one's own, a host's and a "
    "sign-in's addresses dropped, private space kept only where listed on "
    "purpose; a preview; a feed disabled or removed gives up its table "
    "alone")
ATF_TC_BODY(feeds_local, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[1024], sa[16], sn[16], sg[16], k[96];
	int		port, i;

	port = feeds_start(tc, &a, sa, sn, sg, sizeof(sa));
	feeds_allow();
	feeds_spamhaus(port, sa, &r);
	resp_free(&r);
	feeds_firehol(port, sa, &r);
	resp_free(&r);

	/* A list of one's own, of every kind of entry: what is no prefix,
	 * the whole space, a host's and a sign-in's address, private space
	 * it does not list on purpose; one within another left out. */
	feeds_local(port, sa, &r);
	ATF_CHECK_STREQ("2", jstr(&r, "count"));
	ATF_CHECK_STREQ("1", jstr(&r, "covered"));
	ATF_CHECK_STREQ("5", jstr(&r, "dropped-count"));
	ATF_CHECK_MSG(feed_dropped(&r, "192.0.2.0/24", "covers a protected "
	    "address"), "%s", r.body);
	ATF_CHECK_MSG(feed_dropped(&r, "192.0.2.0/24", "covers 192.0.2.77, "
	    "host far's"), "%s", r.body);
	ATF_CHECK_MSG(feed_dropped(&r, "203.0.113.0/24", "alice's last "
	    "sign-in"), "%s", r.body);
	ATF_CHECK_MSG(feed_dropped(&r, "198.51.100.0/24", "private or "
	    "reserved"), "%s", r.body);
	ATF_CHECK_MSG(feed_dropped(&r, "0.0.0.0/0", "the whole address space"),
	    "%s", r.body);
	ATF_CHECK_MSG(feed_dropped(&r, "line 2", "not an address"), "%s",
	    r.body);
	ATF_CHECK_MSG(strstr(r.body, "nonsense") == NULL, "%s", r.body);
	ATF_CHECK_STREQ("8.8.8.0/24", jstr(&r, "sample.0"));
	ATF_CHECK_STREQ("2001:4860::/32", jstr(&r, "sample.1"));
	resp_free(&r);
	/* The preview: each host's dry run; nothing changes. */
	ATF_REQUIRE(system(": > ipfw.log") == 0);
	ATF_CHECK_EQ(204, feed_ask("local", "preview"));
	snprintf(k, sizeof(k), "last-preview.host=%s/count", sa);
	feed_wait("local", k, "2", &r);
	snprintf(k, sizeof(k), "last-preview.host=%s/added", sa);
	ATF_CHECK_STREQ("0", feed_str(&r, k));
	resp_free(&r);
	ATF_CHECK(system("grep -q 'swap' ipfw.log") != 0);

	/* Disabled: its own table given up, the others' left. */
	snprintf(body, sizeof(body), "\"name\":\"Local\",\"url\":\"http://"
	    "127.0.0.1:%d/local.txt\",\"enabled\":false,\"host\":[\"%s\"]",
	    port, sa);
	feed_keep("local", body);
	for (i = 0; i < 300 && access("feeds/feed_local", F_OK) == 0; i++)
		usleep(100000);
	ATF_CHECK(access("feeds/feed_local", F_OK) != 0);
	ATF_CHECK(access("feeds/feed_spamhaus_drop_v4", F_OK) == 0);
	ATF_CHECK(access("feeds/feed_firehol_level1", F_OK) == 0);
	/* Removed: the same. */
	http("DELETE", CF "firehol-level1", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	for (i = 0; i < 300 && access("feeds/feed_firehol_level1", F_OK) ==
	    0; i++)
		usleep(100000);
	ATF_CHECK(access("feeds/feed_firehol_level1", F_OK) != 0);
	ATF_CHECK(access("feeds/feed_spamhaus_drop_v4", F_OK) == 0);
}

CONSOLE_TC(feeds_alarm, "Threat feeds: a source gone, an alarm after three "
    "failures in a row, the hosts' table as it was; back, cleared")
ATF_TC_BODY(feeds_alarm, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[1024], sa[16], sn[16], sg[16], k[96];
	int		port, i;

	port = feeds_start(tc, &a, sa, sn, sg, sizeof(sa));
	feeds_allow();
	feeds_spamhaus(port, sa, &r);
	resp_free(&r);
	/* A source gone: an alarm after three failures in a row, the
	 * hosts' table as it was; back, the alarm cleared. */
	snprintf(body, sizeof(body), "\"preset\":\"spamhaus-drop-v4\","
	    "\"url\":\"http://127.0.0.1:%d/missing\",\"enabled\":true,"
	    "\"host\":[\"%s\"]", port, sa);
	feed_keep("spamhaus-drop-v4", body);
	feed_wait("spamhaus-drop-v4", "failures", "1", &r);
	resp_free(&r);
	for (i = 2; i <= 3; i++) {
		(void)feed_ask("spamhaus-drop-v4", "fetch");
		snprintf(k, sizeof(k), "%d", i);
		feed_wait("spamhaus-drop-v4", "failures", k, &r);
		resp_free(&r);
	}
	feed_wait("spamhaus-drop-v4", "alarm.since", NULL, &r);
	ATF_CHECK_STREQ("4", jstr(&r, "count"));
	resp_free(&r);
	ATF_CHECK(access("feeds/feed_spamhaus_drop_v4", F_OK) == 0);
	snprintf(body, sizeof(body), "\"preset\":\"spamhaus-drop-v4\","
	    "\"url\":\"http://127.0.0.1:%d/drop_v4.json\",\"enabled\":true,"
	    "\"host\":[\"%s\"]", port, sa);
	feed_keep("spamhaus-drop-v4", body);
	feed_wait("spamhaus-drop-v4", "failures", "0", &r);
	ATF_CHECK(jstr(&r, "alarm.since") == NULL);
	resp_free(&r);
}

CONSOLE_TC(feeds_redirect, "Threat feeds: a redirect followed, not to a "
    "cloud's metadata; a feed of chosen addresses, each dropped and why; "
    "a feed on a host that fails there, its error told")
ATF_TC_BODY(feeds_redirect, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[1024], sa[16], sn[16], sg[16];
	int		port;

	port = feeds_start(tc, &a, sa, sn, sg, sizeof(sa));
	feeds_allow();
	/* Redirected: followed on the stand-in; to a cloud's metadata,
	 * refused though the stand-in itself is let through. */
	snprintf(body, sizeof(body), "\"url\":\"http://127.0.0.1:%d/"
	    "redirect\",\"format\":\"spamhaus-json\",\"enabled\":true", port);
	feeds_put("hop", body, "count", "4", &r);
	resp_free(&r);
	snprintf(body, sizeof(body), "\"url\":\"http://127.0.0.1:%d/"
	    "redirect-private\",\"enabled\":true", port);
	feeds_put("meta", body, "failures", "1", &r);
	ATF_CHECK_MSG(strstr(r.body, "169.254.169.254 is a private or "
	    "reserved address") != NULL, "%s", r.body);
	resp_free(&r);

	/* A feed of chosen addresses: a sign-in's, an unreadable host's, a
	 * readable host's.  The owner sees each entry dropped, and why. */
	feeds_oracle(port, &r);
	ATF_CHECK_MSG(feed_dropped(&r, "203.0.113.9/32", "alice's last "
	    "sign-in") && feed_dropped(&r, "192.0.2.77/32", "host far's") &&
	    feed_dropped(&r, "100.64.0.5/32", "host near's"), "%s", r.body);
	ATF_CHECK(jstr(&r, "last-fetch.protected-hidden") == NULL);
	ATF_CHECK_STREQ("1", jstr(&r, "count"));
	resp_free(&r);

	/* A feed on host gone, which fails there: the owner sees it, by
	 * its name and error, in what was sent and in a preview. */
	feeds_seen(port, sg, &r);
	resp_free(&r);
}

CONSOLE_TC(sdwan_list_urls, "SD-WAN's lists fetched as threat feeds are: "
    "a URL resolving to private space refused unless Settings let it "
    "through, a redirect to a cloud's metadata too; http(s) alone, a "
    "file: URL refused when kept and not read when fetched")
ATF_TC_BODY(sdwan_list_urls, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[512];
	int		port, i;

	port = feeds_server(tc);
	start(tc, 0, NULL);
	enrol(&a);
	/* Loopback, private space, a cloud's metadata: refused when kept,
	 * nothing fetched from them. */
	{
		static const char *const priv[] = { "127.0.0.1", "10.0.0.1",
		    "169.254.169.254", "[::1]" };

		for (i = 0; i < 4; i++) {
			snprintf(body, sizeof(body), "{\"arcana-console:lists\":"
			    "{\"feeds\":[{\"name\":\"in\",\"url\":\"http://%s:%d/"
			    "oracle.txt\"}]}}", priv[i], port);
			http("PUT", CC "sdwan/lists", body, &r);
			ATF_CHECK_MSG(r.status == 400 && strstr(r.body,
			    "is a private or reserved address") != NULL, "%s: %d "
			    "%s", priv[i], r.status, r.body);
			resp_free(&r);
		}
	}
	ATF_CHECK(system("grep -q oracle.txt feedsrv.log") != 0);
	/* A file on the console's host, or any scheme but http(s): refused
	 * when kept, by the list's name. */
	{
		static const char *const other[] = { "file:///etc/passwd",
		    "ftp://192.0.2.1/list.txt" };

		for (i = 0; i < 2; i++) {
			snprintf(body, sizeof(body), "{\"arcana-console:lists\":"
			    "{\"feeds\":[{\"name\":\"local\",\"url\":\"%s\"}]}}",
			    other[i]);
			http("PUT", CC "sdwan/lists", body, &r);
			ATF_CHECK_MSG(r.status == 400 && strstr(r.body,
			    "list local: only http(s) URLs are accepted") != NULL,
			    "%s: %d %s", other[i], r.status, r.body);
			resp_free(&r);
		}
		r4_read("lists", &r);
		ATF_CHECK_MSG(jstr(&r, "lists.local.count") == NULL, "%s",
		    r.body);
		resp_free(&r);
	}

	/* The stand-in's 127.0.0.1 let through: its list fetched; one
	 * redirected to a cloud's metadata not, its error kept. */
	feeds_allow();
	snprintf(body, sizeof(body), "{\"arcana-console:lists\":{\"feeds\":["
	    "{\"name\":\"in\",\"url\":\"http://127.0.0.1:%d/oracle.txt\"},"
	    "{\"name\":\"meta\",\"url\":\"http://127.0.0.1:%d/"
	    "redirect-private\"}]}}", port, port);
	http("PUT", CC "sdwan/lists", body, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("POST", CC "sdwan/fetch-lists", "{\"arcana-console:input\":{}}",
	    &r);
	EXPECT(&r, 200);
	resp_free(&r);
	r4_read("lists", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "lists.in.count") != NULL && strcmp(jstr(&r,
	    "lists.in.count"), "4") == 0 && jstr(&r, "lists.in.error") == NULL,
	    "%s", r.body);
	ATF_CHECK_MSG(jstr(&r, "lists.meta.error") != NULL && strstr(jstr(&r,
	    "lists.meta.error"), "169.254.169.254 is a private or reserved "
	    "address") != NULL && strcmp(jstr(&r, "lists.meta.count"), "0") ==
	    0, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q 'GET /oracle.txt 200' feedsrv.log") == 0);

	/* A file: URL kept from before (written into the store by hand):
	 * not read when fetched, the list's error, its last entries kept. */
	ATF_REQUIRE(system("sed -i '' 's|http://127.0.0.1:[0-9]*/oracle.txt|"
	    "file:///etc/passwd|' data/sdwan-lists.json && grep -q "
	    "'file:///etc/passwd' data/sdwan-lists.json") == 0);
	http("POST", CC "sdwan/fetch-lists", "{\"arcana-console:input\":{"
	    "\"name\":\"in\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	r4_read("lists", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "lists.in.error") != NULL && strstr(jstr(&r,
	    "lists.in.error"), "only http(s) URLs are accepted") != NULL &&
	    strcmp(jstr(&r, "lists.in.count"), "4") == 0 && strstr(r.body,
	    "root:") == NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC(feeds_operator, "Threat feeds an operator of some hosts may "
    "not take away nor change, nor read beyond them; members may not")
ATF_TC_BODY(feeds_operator, tc)
{
	struct authn	a, b, c;
	struct resp	r;
	char		body[1024], sa[16], sn[16], sg[16], invite[80];
	char		invite2[80];
	int		port;

	port = feeds_start(tc, &a, sa, sn, sg, sizeof(sa));
	feeds_allow();
	feeds_spamhaus(port, sa, &r);
	resp_free(&r);
	feeds_local(port, sa, &r);
	resp_free(&r);
	feeds_oracle(port, &r);
	resp_free(&r);
	feeds_seen(port, sg, &r);
	resp_free(&r);

	/* An operator who only views hosts a and near may not take away
	 * the feed that is on a, nor change it: refused, its table left.
	 * A member reads none and changes none. */
	snprintf(body, sizeof(body), "{\"id\":\"%s\",\"role\":\"viewer\"},"
	    "{\"id\":\"%s\",\"role\":\"viewer\"}", sa, sn);
	cc_role("a-viewer-op", "operator", body);
	cc_invite("carol", "a-viewer-op", invite2, sizeof(invite2));
	cc_invite("bob", "viewer", invite, sizeof(invite));
	cookie[0] = '\0';
	authn_new(&c, -7);
	do_register(&c, invite2, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("operator", jstr(&r, "console"));
	resp_free(&r);
	http("DELETE", CF "spamhaus-drop-v4", NULL, &r);
	ATF_CHECK_MSG(r.status == 403 && strstr(r.body, "host a is not one") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	snprintf(body, sizeof(body), "\"preset\":\"spamhaus-drop-v4\","
	    "\"url\":\"http://127.0.0.1:%d/drop_v4.json\",\"enabled\":false",
	    port);
	feed_put("spamhaus-drop-v4", body, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	snprintf(body, sizeof(body), "\"url\":\"http://127.0.0.1:%d/"
	    "drop_v4.json\",\"enabled\":true,\"host\":[\"%s\"]", port, sa);
	feed_put("carols", body, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	usleep(3000000);
	ATF_CHECK(access("feeds/feed_spamhaus_drop_v4", F_OK) == 0);
	feed_get("spamhaus-drop-v4", &r);
	ATF_CHECK_STREQ("true", jstr(&r, "enabled"));
	resp_free(&r);
	/* What a feed dropped read by one who is no owner: what covers
	 * a host's address it may not read, or a sign-in's, only counted. */
	feed_get("local", &r);
	ATF_CHECK_MSG(!feed_dropped(&r, "192.0.2.0/24", "covers") &&
	    !feed_dropped(&r, "203.0.113.0/24", "covers"), "%s", r.body);
	ATF_CHECK_STREQ("2", jstr(&r, "last-fetch.protected-hidden"));
	ATF_CHECK_MSG(strstr(r.body, "192.0.2.77") == NULL && strstr(r.body,
	    "203.0.113.9") == NULL && strstr(r.body, "alice") == NULL &&
	    strstr(r.body, "far") == NULL && strstr(r.body, "127.0.0.1,") ==
	    NULL, "%s", r.body);
	resp_free(&r);
	/* A feed from a URL of one's own is an owner's: an operator uses
	 * a preset, enables or disables such a feed, and previews none. */
	snprintf(body, sizeof(body), "\"url\":\"http://127.0.0.1:%d/"
	    "drop_v4.json\",\"enabled\":true", port);
	feed_put("carol2", body, &r);
	ATF_CHECK_MSG(r.status == 403 && strstr(r.body, "console owner") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	feed_put("dshield", "\"preset\":\"dshield\",\"enabled\":false", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	feed_get("dshield", &r);
	ATF_CHECK_STREQ("https://feeds.dshield.org/block.txt", jstr(&r,
	    "url"));
	resp_free(&r);
	ATF_CHECK_EQ(403, feed_ask("oracle", "preview"));
	snprintf(body, sizeof(body), "\"url\":\"http://127.0.0.1:%d/"
	    "oracle.txt\",\"enabled\":false", port);
	feed_put("oracle", body, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	feed_get("oracle", &r);
	ATF_CHECK_STREQ("false", jstr(&r, "enabled"));
	resp_free(&r);
	snprintf(body, sizeof(body), "\"url\":\"http://127.0.0.1:%d/"
	    "local.txt\",\"enabled\":true", port);
	feed_put("oracle", body, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* Host gone is not the operator's to read: neither its id nor its
	 * name nor its error anywhere, only counted. */
	http("GET", CC "threat-feeds", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, sg) == NULL && strstr(r.body, "gone") ==
	    NULL && strstr(r.body, "none.sock") == NULL, "%s", r.body);
	resp_free(&r);
	feed_get("seen", &r);
	ATF_CHECK_MSG(strstr(r.body, sg) == NULL && strstr(r.body, "gone") ==
	    NULL && strstr(r.body, "none.sock") == NULL, "%s", r.body);
	ATF_CHECK_STREQ("1", jstr(&r, "hosts-hidden"));
	ATF_CHECK_STREQ("1", jstr(&r, "delivered-hidden"));
	ATF_CHECK_STREQ("1", jstr(&r, "last-preview.hosts-hidden"));
	resp_free(&r);
	/* Not even listed by entry, which a feed of chosen addresses
	 * would tell: counted; the host it may read, listed. */
	feed_get("oracle", &r);
	ATF_CHECK_MSG(strstr(r.body, "203.0.113.9") == NULL && strstr(r.body,
	    "192.0.2.77") == NULL && strstr(r.body, "alice") == NULL,
	    "%s", r.body);
	ATF_CHECK_STREQ("2", jstr(&r, "last-fetch.protected-hidden"));
	ATF_CHECK_MSG(feed_dropped(&r, "100.64.0.5/32", "host near's"), "%s",
	    r.body);
	resp_free(&r);
	cookie[0] = '\0';
	authn_new(&b, -8);
	do_register(&b, invite, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("member", jstr(&r, "console"));
	resp_free(&r);
	http("GET", CC "threat-feeds", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	feed_put("x", "\"url\":\"https://example.org/x\"", &r);
	EXPECT(&r, 403);
	resp_free(&r);
}

/*
 * arcana-console (PLAN-SDN-YANG 4.4.1): the console's own configuration
 * and state through RESTCONF.
 */

/* A member of the console, a viewer of every host: bob, signed in with
 * key b. */
static void
cc_member(struct authn *b)
{
	struct resp	 r;
	char		 invite[80];

	cc_invite("bob", "viewer", invite, sizeof(invite));
	cookie[0] = '\0';
	authn_new(b, -8);
	do_register(b, invite, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bob", jstr(&r, "user"));
	resp_free(&r);
}

CONSOLE_TC(cyang_settings, "arcana-console's settings: GET and PUT, each "
    "one's source, a secret never read, entity-tags, a member refused")
ATF_TC_BODY(cyang_settings, tc)
{
	struct authn	a, b;
	struct resp	r;
	char		e1[64], e2[64], hdr[128];

	start(tc, 0, NULL);
	http("GET", CC "settings", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	enrol(&a);
	/* The library names it. */
	http("GET", "/restconf/data/ietf-yang-library:yang-library", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, "\"arcana-console\"") != NULL);
	resp_free(&r);
	/* Read: web.conf's, none set here. */
	http("GET", CC "settings", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("Arcana", jstr(&r, "arcana-console:settings.rp-name"));
	ATF_CHECK_STREQ("30", jstr(&r, "arcana-console:settings.session-idle"));
	ATF_CHECK_STREQ("false", jstr(&r,
	    "arcana-console:settings.telegram-token-set"));
	/* Each one's label and help, the page's form's. */
	ATF_CHECK_STREQ("rp-name", jstr(&r,
	    "arcana-console:settings.source.0.name"));
	ATF_CHECK_STREQ("false", jstr(&r,
	    "arcana-console:settings.source.0.overridden"));
	ATF_CHECK_STREQ("Name shown by security keys", jstr(&r,
	    "arcana-console:settings.source.0.label"));
	ATF_CHECK(jstr(&r, "arcana-console:settings.source.0.help") != NULL);
	ATF_REQUIRE(resp_header(&r, "etag", e1, sizeof(e1)) != NULL);
	resp_free(&r);
	http("GET", CC "settings/rp-name", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("Arcana", jstr(&r, "arcana-console:rp-name"));
	resp_free(&r);
	/* Changed, set here over web.conf's; a bad value refused, nothing
	 * kept. */
	http("PUT", CC "settings/rp-name", "{\"arcana-console:rp-name\":"
	    "\"Lab\"}", &r);
	EXPECT(&r, 204);
	ATF_REQUIRE(resp_header(&r, "etag", e2, sizeof(e2)) != NULL);
	ATF_CHECK(strcmp(e1, e2) != 0);
	resp_free(&r);
	http("GET", CC "settings", NULL, &r);
	ATF_CHECK_STREQ("Lab", jstr(&r, "arcana-console:settings.rp-name"));
	ATF_CHECK_STREQ("true", jstr(&r,
	    "arcana-console:settings.source.0.overridden"));
	resp_free(&r);
	http("PATCH", CC "settings", "{\"arcana-console:settings\":{"
	    "\"update-url\":\"http://plain.example/\",\"rp-name\":\"X\"}}", &r);
	EXPECT(&r, 400);
	ATF_CHECK(strstr(r.body, "error-tag") != NULL);
	resp_free(&r);
	http("PATCH", CC "settings", "{\"arcana-console:settings\":{"
	    "\"session-idle\":2}}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("GET", CC "settings/rp-name", NULL, &r);
	ATF_CHECK_STREQ("Lab", jstr(&r, "arcana-console:rp-name"));
	resp_free(&r);
	/* Another change, its entity-tag a new one: the old refused. */
	http("PATCH", CC "settings", "{\"arcana-console:settings\":{"
	    "\"session-idle\":45}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "settings/session-idle", NULL, &r);
	ATF_CHECK_STREQ("45", jstr(&r, "arcana-console:session-idle"));
	resp_free(&r);
	snprintf(hdr, sizeof(hdr), "If-Match: %s\r\n", e2);
	http_with("PUT", CC "settings/rp-name", hdr,
	    "{\"arcana-console:rp-name\":\"Y\"}", &r);
	EXPECT(&r, 412);
	resp_free(&r);
	/* Left out: web.conf's again. */
	http("DELETE", CC "settings/rp-name", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "settings", NULL, &r);
	ATF_CHECK_STREQ("Arcana", jstr(&r, "arcana-console:settings.rp-name"));
	ATF_CHECK_STREQ("false", jstr(&r,
	    "arcana-console:settings.source.0.overridden"));
	resp_free(&r);
	/* A secret: set, never read; its being set said. */
	http("PATCH", CC "settings", "{\"arcana-console:settings\":{"
	    "\"telegram-token\":\"123456:ABCdefGhIJKlmnoPQRstuVWxyz0123456"
	    "78\"}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "settings", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r,
	    "arcana-console:settings.telegram-token-set"));
	ATF_CHECK(strstr(r.body, "ABCdefGhIJ") == NULL);
	resp_free(&r);
	http("GET", "/restconf/data", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, "ABCdefGhIJ") == NULL);
	ATF_CHECK_STREQ("true", jstr(&r,
	    "arcana-console:settings.telegram-token-set"));
	resp_free(&r);
	/* A PUT of what was read keeps the secret. */
	http("GET", CC "settings?content=config", NULL, &r);
	EXPECT(&r, 200);
	{
		char	*doc = strdup(r.body);

		resp_free(&r);
		http("PUT", CC "settings", doc, &r);
		EXPECT(&r, 204);
		resp_free(&r);
		free(doc);
	}
	http("GET", CC "settings/telegram-token-set", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "arcana-console:telegram-token-set"));
	resp_free(&r);
	/* A member: neither reads nor changes them. */
	cc_member(&b);
	http("GET", CC "settings", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("PUT", CC "settings/rp-name", "{\"arcana-console:rp-name\":"
	    "\"Mine\"}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("GET", "/restconf/data", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "arcana-console:settings") == NULL);
	ATF_CHECK(jstr(&r, "arcana-console:users") == NULL);
	resp_free(&r);
	http("PATCH", CC "settings", "{\"arcana-console:settings\":{"
	    "\"rp-name\":\"Mine\"}}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
}

CONSOLE_TC(cyang_tokens, "arcana-console's tokens: made by an action, "
    "the value said once and in no GET, removed by DELETE, a token's own "
    "reach held")
ATF_TC_BODY(cyang_tokens, tc)
{
	struct authn	a;
	struct resp	r;
	char		token[80], wtoken[80], id[20], path[128];

	start(tc, 0, NULL);
	enrol(&a);
	http("POST", CC "tokens/create", "{\"arcana-console:input\":{"
	    "\"name\":\"planner\"}}", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "arcana-console:output.token") != NULL);
	ATF_CHECK(strncmp(jstr(&r, "arcana-console:output.token"), "arcr_",
	    5) == 0);
	snprintf(token, sizeof(token), "%s", jstr(&r,
	    "arcana-console:output.token"));
	snprintf(id, sizeof(id), "%s", jstr(&r, "arcana-console:output.id"));
	resp_free(&r);
	http("POST", CC "tokens/create", "{\"arcana-console:input\":{"
	    "\"name\":\"writer\",\"kind\":\"write\"}}", &r);
	EXPECT(&r, 200);
	snprintf(wtoken, sizeof(wtoken), "%s", jstr(&r,
	    "arcana-console:output.token"));
	resp_free(&r);
	http("POST", CC "tokens/create", "{\"arcana-console:input\":{}}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* Read: the list, the value nowhere. */
	http("GET", CC "tokens", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(id, jstr(&r, "arcana-console:tokens.token.0.id"));
	ATF_CHECK_STREQ("planner", jstr(&r,
	    "arcana-console:tokens.token.0.name"));
	ATF_CHECK_STREQ("read", jstr(&r, "arcana-console:tokens.token.0.kind"));
	ATF_CHECK(jstr(&r, "arcana-console:tokens.token.0.created") != NULL);
	ATF_CHECK(strstr(r.body, token + 5) == NULL);
	ATF_CHECK(strstr(r.body, wtoken + 5) == NULL);
	resp_free(&r);
	http("GET", "/restconf/data", NULL, &r);
	ATF_CHECK(strstr(r.body, token + 5) == NULL);
	ATF_CHECK(strstr(r.body, wtoken + 5) == NULL);
	resp_free(&r);
	/* Made or renamed by an edit: refused. */
	http("PUT", CC "tokens/token=0123456789abcdef", "{\"arcana-console:"
	    "token\":[{\"id\":\"0123456789abcdef\",\"name\":\"x\"}]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(path, sizeof(path), CC "tokens/token=%s/name", id);
	http("PUT", path, "{\"arcana-console:name\":\"renamed\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* A read token reads them, not the settings; a write token
	 * neither makes nor removes one. */
	http_bearer("GET", CC "tokens", token, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http_bearer("GET", CC "settings", token, NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	http_bearer("GET", CC "enrolment", wtoken, NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http_bearer("POST", CC "tokens/create", wtoken, "{\"arcana-console:"
	    "input\":{\"name\":\"more\"}}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	snprintf(path, sizeof(path), CC "tokens/token=%s", id);
	http_bearer("DELETE", path, wtoken, NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http_bearer("GET", "/restconf/data", wtoken, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "arcana-console:settings") == NULL);
	ATF_CHECK(jstr(&r, "arcana-console:enrolment") == NULL);
	ATF_CHECK(jstr(&r, "arcana-console:tokens") != NULL);
	resp_free(&r);
	/* Deleted: it opens nothing. */
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "tokens", NULL, &r);
	ATF_CHECK(strstr(r.body, id) == NULL);
	resp_free(&r);
	http_bearer("GET", CC "hosts", token, NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
}

CONSOLE_TC(cyang_users, "arcana-console's users, roles and groups: made "
    "and changed, a role named that is none refused, the last "
    "owner kept, an invitation by its action")
ATF_TC_BODY(cyang_users, tc)
{
	struct authn	a;
	struct resp	r;

	start(tc, 0, NULL);
	enrol(&a);
	http("GET", CC "users", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("admin", jstr(&r, "arcana-console:users.user.0.name"));
	ATF_CHECK_STREQ("owner", jstr(&r,
	    "arcana-console:users.user.0.role.0"));
	ATF_CHECK_STREQ("owner", jstr(&r,
	    "arcana-console:users.user.0.console-role"));
	ATF_CHECK_STREQ("1", jstr(&r, "arcana-console:users.user.0.keys"));
	resp_free(&r);
	http("GET", CC "roles/role=owner", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("*", jstr(&r, "arcana-console:role.0.host.0.id"));
	ATF_CHECK_STREQ("admin", jstr(&r, "arcana-console:role.0.host.0.role"));
	resp_free(&r);
	/* A role, a group giving it, a user in the group. */
	http("POST", CC "roles", "{\"arcana-console:role\":[{\"name\":\"noc\","
	    "\"console\":\"operator\",\"host\":[{\"id\":\"*\",\"role\":"
	    "\"viewer\"}]}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("PUT", CC "groups/group=night", "{\"arcana-console:group\":[{"
	    "\"name\":\"night\",\"role\":[\"noc\"],\"description\":"
	    "\"on call\"}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("PUT", CC "users/user=carol", "{\"arcana-console:user\":[{"
	    "\"name\":\"carol\",\"group\":[\"night\"]}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", CC "users", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("carol", jstr(&r, "arcana-console:users.user.1.name"));
	ATF_CHECK_STREQ("night", jstr(&r,
	    "arcana-console:users.user.1.group.0"));
	ATF_CHECK_STREQ("operator", jstr(&r,
	    "arcana-console:users.user.1.console-role"));
	resp_free(&r);
	http("GET", CC "roles", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("noc", jstr(&r, "arcana-console:roles.role.3.name"));
	ATF_CHECK_STREQ("*", jstr(&r, "arcana-console:roles.role.3.host.0.id"));
	ATF_CHECK_STREQ("viewer", jstr(&r,
	    "arcana-console:roles.role.3.host.0.role"));
	resp_free(&r);
	http("GET", CC "groups/group=night", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("carol", jstr(&r, "arcana-console:group.0.member.0"));
	resp_free(&r);
	/* A user of a tenant, a member. */
	http("PUT", CC "users/user=dave", "{\"arcana-console:user\":[{\"name\":"
	    "\"dave\",\"role\":[\"viewer\"],\"tenant\":\"acme\"}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", CC "users/user=dave", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("acme", jstr(&r, "arcana-console:user.0.tenant"));
	ATF_CHECK_STREQ("member", jstr(&r,
	    "arcana-console:user.0.console-role"));
	resp_free(&r);
	/* Refused: a role that is none (its leafref), a user with no role
	 * nor group, the last owner made less, a role in use. */
	http("PUT", CC "users/user=eve", "{\"arcana-console:user\":[{\"name\":"
	    "\"eve\",\"role\":[\"nosuch\"]}]}", &r);
	ATF_CHECK_MSG(r.status == 400 || r.status == 409, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	http("PUT", CC "users/user=eve", "{\"arcana-console:user\":[{\"name\":"
	    "\"eve\"}]}", &r);
	EXPECT(&r, 400);
	ATF_CHECK(strstr(r.body, "one at least") != NULL);
	resp_free(&r);
	http("PUT", CC "users/user=admin", "{\"arcana-console:user\":[{"
	    "\"name\":\"admin\",\"role\":[\"viewer\"]}]}", &r);
	EXPECT(&r, 409);
	ATF_CHECK(strstr(r.body, "keeps an owner") != NULL);
	resp_free(&r);
	http("GET", CC "users/user=admin", NULL, &r);
	ATF_CHECK_STREQ("owner", jstr(&r, "arcana-console:user.0.role.0"));
	resp_free(&r);
	http("DELETE", CC "roles/role=noc", NULL, &r);
	ATF_CHECK_MSG(r.status == 400 || r.status == 409, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	/* An invitation, said once. */
	http("POST", CC "users/user=dave/invite", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strncmp(jstr(&r, "arcana-console:output.token"), "inv_", 4) ==
	    0);
	ATF_CHECK(jstr(&r, "arcana-console:output.expires") != NULL);
	resp_free(&r);
	http("GET", CC "users/user=dave/invitations", NULL, &r);
	ATF_CHECK_STREQ("1", jstr(&r, "arcana-console:invitations"));
	resp_free(&r);
	http("POST", CC "users/user=nobody/invite", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* Removed: the user, then the group, then the role. */
	http("DELETE", CC "users/user=carol", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("DELETE", CC "groups/group=night", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("DELETE", CC "roles/role=noc", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "users", NULL, &r);
	ATF_CHECK(strstr(r.body, "carol") == NULL);
	ATF_CHECK(strstr(r.body, "night") == NULL);
	resp_free(&r);
	http("GET", CC "roles", NULL, &r);
	ATF_CHECK(strstr(r.body, "\"noc\"") == NULL);
	resp_free(&r);
	http("GET", CC "groups", NULL, &r);
	ATF_CHECK(strstr(r.body, "night") == NULL);
	resp_free(&r);
}

CONSOLE_TC(cyang_enrolment, "arcana-console's enrolment: a token by its "
    "action where enrolment is on, refused where off, the token in no GET")
ATF_TC_BODY(cyang_enrolment, tc)
{
	struct authn	a;
	struct resp	r;
	char		tok[80];
	bool		on;

	start(tc, 0, NULL);
	enrol(&a);
	http("GET", CC "enrolment", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "arcana-console:enrolment.enabled") != NULL);
	on = strcmp(jstr(&r, "arcana-console:enrolment.enabled"), "true") == 0;
	resp_free(&r);
	http("POST", CC "enrolment/create-token", "{\"arcana-console:input\":"
	    "{\"name\":\"h2\",\"host\":\"h2.example\",\"port\":4311}}", &r);
	EXPECT(&r, on ? 200 : 409);
	if (on) {
		snprintf(tok, sizeof(tok), "%s", jstr(&r,
		    "arcana-console:output.token"));
		ATF_CHECK_EQ(64, strlen(tok));
		ATF_CHECK(strstr(jstr(&r, "arcana-console:output.command"),
		    "-p 4311") != NULL);
		resp_free(&r);
		http("GET", "/restconf/data", NULL, &r);
		ATF_CHECK(strstr(r.body, tok) == NULL);
	}
	resp_free(&r);
	http("POST", CC "enrolment/create-token", "{\"arcana-console:input\":"
	    "{\"name\":\"h3\",\"host\":\"-bad\"}}", &r);
	ATF_CHECK_MSG(r.status == 400 || r.status == 409, "%d", r.status);
	resp_free(&r);
	http("PUT", CC "enrolment", "{\"arcana-console:enrolment\":{}}", &r);
	EXPECT(&r, 405);
	resp_free(&r);
}

CONSOLE_TC(cyang_workflows, "arcana-console's workflows and runs: made "
    "and changed through the console's check, read back, run, the runs "
    "cleared")
ATF_TC_BODY(cyang_workflows, tc)
{
	struct authn	a;
	struct resp	r;
	char		body[2048], id[16], path[256];
	int		i;

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("lab", "jgd.sock", id, sizeof(id));
	/* Made: read back as it was made. */
	snprintf(body, sizeof(body), "{\"arcana-console:workflow\":[{\"id\":"
	    "\"0000beef\",\"name\":\"probe\",\"host\":[\"%s\"],\"param\":[{"
	    "\"name\":\"what\",\"default\":\"hostname\"}],\"step\":[{\"id\":"
	    "\"r\",\"read\":\"hello\"},{\"id\":\"s\",\"job\":{\"kind\":"
	    "\"sysctl\",\"field\":[{\"name\":\"args\",\"json\":"
	    "\"[\\\"kern.${param.what}\\\"]\"}]},\"when\":{\"step\":\"r\","
	    "\"path\":\"hostname\",\"op\":\"exists\"},\"on-fail\":"
	    "\"continue\"}]}]}", id);
	http("PUT", CC "workflows/workflow=0000beef", body, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", CC "workflows/workflow=0000beef", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("probe", jstr(&r, "arcana-console:workflow.0.name"));
	ATF_CHECK_STREQ("hello", jstr(&r, "arcana-console:workflow.0.step.0."
	    "read"));
	ATF_CHECK_STREQ("sysctl", jstr(&r, "arcana-console:workflow.0.step.1."
	    "job.kind"));
	ATF_CHECK_STREQ("args", jstr(&r, "arcana-console:workflow.0.step.1."
	    "job.field.0.name"));
	ATF_CHECK_MSG(jstr(&r, "arcana-console:workflow.0.step.1.job.field.0."
	    "json") != NULL && strstr(jstr(&r, "arcana-console:workflow.0."
	    "step.1.job.field.0.json"), "\"kern.${param.what}\"") != NULL,
	    "%s", r.body);
	ATF_CHECK_STREQ("exists", jstr(&r, "arcana-console:workflow.0.step.1."
	    "when.op"));
	ATF_CHECK_STREQ("continue", jstr(&r, "arcana-console:workflow.0.step.1."
	    "on-fail"));
	ATF_CHECK_STREQ("false", jstr(&r, "arcana-console:workflow.0.step.1."
	    "destroys"));
	ATF_CHECK(jstr(&r, "arcana-console:workflow.0.changed") != NULL);
	resp_free(&r);
	/* What the console's check refuses refused, nothing kept. */
	http("PATCH", CC "workflows/workflow=0000beef", "{\"arcana-console:"
	    "workflow\":[{\"id\":\"0000beef\",\"step\":[{\"id\":\"s\",\"job\":"
	    "{\"kind\":\"nosuch\"}}]}]}", &r);
	EXPECT(&r, 400);
	ATF_CHECK(strstr(r.body, "jobs.yaml") != NULL);
	resp_free(&r);
	http("GET", CC "workflows/workflow=0000beef", NULL, &r);
	ATF_CHECK_STREQ("sysctl", jstr(&r, "arcana-console:workflow.0.step.1."
	    "job.kind"));
	resp_free(&r);
	/* Renamed by a merge. */
	http("PATCH", CC "workflows/workflow=0000beef", "{\"arcana-console:"
	    "workflow\":[{\"id\":\"0000beef\",\"name\":\"probe2\"}]}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "workflows/workflow=0000beef", NULL, &r);
	ATF_CHECK_STREQ("probe2", jstr(&r, "arcana-console:workflow.0.name"));
	ATF_CHECK_MSG(jstr(&r, "arcana-console:workflow.0.step.1.job.field.0."
	    "json") != NULL && strstr(jstr(&r, "arcana-console:workflow.0."
	    "step.1.job.field.0.json"), "\"kern.${param.what}\"") != NULL,
	    "%s", r.body);
	resp_free(&r);
	/* Run by its action; read in the runs, with its traces when it is
	 * named. */
	http("POST", CC "workflows/workflow=0000beef/run", "{\"arcana-console:"
	    "input\":{\"param\":[{\"name\":\"what\",\"value\":\"ostype\"}]}}",
	    &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "arcana-console:output.run") != NULL);
	snprintf(path, sizeof(path), CC "runs/run=%s", jstr(&r,
	    "arcana-console:output.run"));
	resp_free(&r);
	for (i = 0; i < 100; i++) {
		http("GET", path, NULL, &r);
		if (r.status == 200 && jstr(&r, "arcana-console:run.0.state") !=
		    NULL && strcmp(jstr(&r, "arcana-console:run.0.state"),
		    "running") != 0)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_REQUIRE_MSG(i < 100, "the run did not end");
	ATF_CHECK_STREQ("probe2", jstr(&r, "arcana-console:run.0.name"));
	ATF_CHECK_STREQ("hand", jstr(&r, "arcana-console:run.0.trigger"));
	ATF_CHECK_STREQ("ostype", jstr(&r, "arcana-console:run.0.param.0.value"));
	ATF_CHECK_STREQ(id, jstr(&r, "arcana-console:run.0.host.0.id"));
	ATF_CHECK(jstr(&r, "arcana-console:run.0.host.0.step.0.trace") != NULL);
	resp_free(&r);
	http("POST", CC "runs/run=1/stop", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("POST", CC "runs/clear", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("1", jstr(&r, "arcana-console:output.cleared"));
	resp_free(&r);
	http("GET", CC "runs", NULL, &r);
	ATF_CHECK(jstr(&r, "arcana-console:runs.run.0") == NULL);
	resp_free(&r);
	/* Two events of one kind: both read, both kept through a change,
	 * their matches' types too. */
	snprintf(body, sizeof(body), "{\"arcana-console:workflow\":[{\"id\":"
	    "\"0000cafe\",\"name\":\"jails\",\"host\":[\"%s\"],\"step\":[{"
	    "\"id\":\"r\",\"read\":\"jails\"}],\"on\":[{\"index\":0,\"event\":"
	    "\"jail-state\",\"match\":[{\"name\":\"name\",\"value\":\"web\"}]},"
	    "{\"index\":1,\"event\":\"jail-state\",\"match\":[{\"name\":"
	    "\"name\",\"value\":\"db\"},{\"name\":\"jid\",\"number\":7}]},"
	    "{\"index\":2,\"event\":\"host-down\"}]}]}", id);
	http("PUT", CC "workflows/workflow=0000cafe", body, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", CC "workflows/workflow=0000cafe", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("jail-state", jstr(&r, "arcana-console:workflow.0.on.0."
	    "event"));
	ATF_CHECK_STREQ("web", jstr(&r, "arcana-console:workflow.0.on.0.match.0."
	    "value"));
	ATF_CHECK_STREQ("1", jstr(&r, "arcana-console:workflow.0.on.1.index"));
	ATF_CHECK_STREQ("jail-state", jstr(&r, "arcana-console:workflow.0.on.1."
	    "event"));
	ATF_CHECK_STREQ("host-down", jstr(&r, "arcana-console:workflow.0.on.2."
	    "event"));
	resp_free(&r);
	http("PATCH", CC "workflows/workflow=0000cafe", "{\"arcana-console:"
	    "workflow\":[{\"id\":\"0000cafe\",\"name\":\"jails2\"}]}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "workflows/workflow=0000cafe", NULL, &r);
	ATF_CHECK_STREQ("jails2", jstr(&r, "arcana-console:workflow.0.name"));
	ATF_CHECK_STREQ("jail-state", jstr(&r, "arcana-console:workflow.0.on.0."
	    "event"));
	ATF_CHECK_STREQ("web", jstr(&r, "arcana-console:workflow.0.on.0.match.0."
	    "value"));
	ATF_CHECK_STREQ("jail-state", jstr(&r, "arcana-console:workflow.0.on.1."
	    "event"));
	ATF_CHECK_MSG(strstr(r.body, "\"value\":\"db\"") != NULL &&
	    strstr(r.body, "\"number\":\"7\"") != NULL, "%s", r.body);
	ATF_CHECK_STREQ("host-down", jstr(&r, "arcana-console:workflow.0.on.2."
	    "event"));
	ATF_CHECK(jstr(&r, "arcana-console:workflow.0.on.3") == NULL);
	resp_free(&r);
	ATF_CHECK(system("grep -q '\"db\"' data/workflows.json && "
	    "grep -q '\"jid\": *7' data/workflows.json && "
	    "test $(grep -o 'jail-state' data/workflows.json | wc -l) -eq 2") ==
	    0);
	http("DELETE", CC "workflows/workflow=0000cafe", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	/* Deleted. */
	http("DELETE", CC "workflows/workflow=0000beef", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "workflows", NULL, &r);
	ATF_CHECK(jstr(&r, "arcana-console:workflows.workflow.0") == NULL);
	resp_free(&r);
}

CONSOLE_TC(cyang_templates, "arcana-console's templates: kept and changed "
    "through the console's check, read back, forgotten; operators', not "
    "members'")
ATF_TC_BODY(cyang_templates, tc)
{
	struct authn	a, b;
	struct resp	r;
	char		e1[64], hdr[96];

	start(tc, 0, NULL);
	enrol(&a);
	http("PUT", CC "templates/template=edge", "{\"arcana-console:template\":"
	    "[{\"name\":\"edge\",\"description\":\"an edge\",\"file\":[{"
	    "\"path\":\"/etc/rc.conf\",\"mode\":\"0644\",\"owner\":\"root\","
	    "\"group\":\"wheel\",\"text\":\"hostname=\\\"{{hostname}}\\\"\\n"
	    "ifconfig_lo1=\\\"inet {{address}}/32\\\"\\n\"}],\"package\":[{"
	    "\"name\":\"bird3\",\"origin\":\"net/bird3\"}],\"facts\":"
	    "\"{\\\"arch\\\":\\\"amd64\\\"}\",\"variable\":[{\"name\":"
	    "\"address\",\"description\":\"its loopback\",\"default\":"
	    "\"192.0.2.10\"}]}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	/* Read back whole, its placeholders found. */
	http("GET", CC "templates/template=edge", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("an edge", jstr(&r,
	    "arcana-console:template.0.description"));
	ATF_CHECK_STREQ("/etc/rc.conf", jstr(&r,
	    "arcana-console:template.0.file.0.path"));
	ATF_CHECK_STREQ("net/bird3", jstr(&r,
	    "arcana-console:template.0.package.0.origin"));
	ATF_CHECK_STREQ("address", jstr(&r,
	    "arcana-console:template.0.variable.0.name"));
	ATF_CHECK_STREQ("192.0.2.10", jstr(&r,
	    "arcana-console:template.0.variable.0.default"));
	ATF_CHECK_STREQ("hostname", jstr(&r,
	    "arcana-console:template.0.placeholder.0"));
	ATF_CHECK_STREQ("address", jstr(&r,
	    "arcana-console:template.0.placeholder.1"));
	ATF_CHECK(jstr(&r, "arcana-console:template.0.updated") != NULL);
	ATF_CHECK_STREQ("{\"arch\":\"amd64\"}", jstr(&r,
	    "arcana-console:template.0.facts"));
	ATF_REQUIRE(resp_header(&r, "etag", e1, sizeof(e1)) != NULL);
	resp_free(&r);
	/* Another kept: read back, the old entity-tag refused. */
	http("PUT", CC "templates/template=core", "{\"arcana-console:template\":"
	    "[{\"name\":\"core\",\"file\":[{\"path\":\"/etc/motd\",\"mode\":"
	    "\"0644\",\"owner\":\"root\",\"group\":\"wheel\",\"text\":"
	    "\"core\\n\"}]}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	/* A key with "/" is not named in a path (libwebsockets decodes
	 * it): the entry whole. */
	http("GET", CC "templates/template=core", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("/etc/motd", jstr(&r,
	    "arcana-console:template.0.file.0.path"));
	ATF_CHECK_STREQ("core\n", jstr(&r,
	    "arcana-console:template.0.file.0.text"));
	resp_free(&r);
	snprintf(hdr, sizeof(hdr), "If-Match: %s\r\n", e1);
	http_with("PATCH", CC "templates", hdr, "{\"arcana-console:templates\":"
	    "{\"template\":[{\"name\":\"edge\",\"description\":\"x\"}]}}", &r);
	EXPECT(&r, 412);
	resp_free(&r);
	/* A PATCH: merged, the rest kept. */
	http("PATCH", CC "templates/template=edge", "{\"arcana-console:"
	    "template\":[{\"name\":\"edge\",\"description\":\"the edge\"}]}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "templates/template=edge", NULL, &r);
	ATF_CHECK_STREQ("the edge", jstr(&r,
	    "arcana-console:template.0.description"));
	ATF_CHECK_STREQ("bird3", jstr(&r,
	    "arcana-console:template.0.package.0.name"));
	ATF_CHECK(jstr(&r, "arcana-console:template.0.package.1") == NULL);
	resp_free(&r);
	/* The console's check: a path that climbs, facts no object;
	 * nothing kept. */
	http("PUT", CC "templates/template=bad", "{\"arcana-console:template\":"
	    "[{\"name\":\"bad\",\"file\":[{\"path\":\"/etc/../root/x\","
	    "\"mode\":\"0644\",\"owner\":\"root\",\"group\":\"wheel\","
	    "\"text\":\"\"}]}]}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "without ..") != NULL,
	    "%s", r.body);
	resp_free(&r);
	http("PATCH", CC "templates/template=edge", "{\"arcana-console:"
	    "template\":[{\"name\":\"edge\",\"facts\":\"[1]\"}]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("GET", CC "templates/template=bad", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("GET", CC "templates/template=edge/facts", NULL, &r);
	ATF_CHECK_STREQ("{\"arch\":\"amd64\"}", jstr(&r,
	    "arcana-console:facts"));
	resp_free(&r);
	/* Forgotten. */
	http("DELETE", CC "templates/template=core", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "templates/template=core", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* A member: neither reads nor changes them. */
	cc_member(&b);
	http("GET", CC "templates", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("DELETE", CC "templates/template=edge", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("GET", "/restconf/data", NULL, &r);
	ATF_CHECK(jstr(&r, "arcana-console:templates") == NULL);
	ATF_CHECK(jstr(&r, "arcana-console:prefix-lists") != NULL);
	resp_free(&r);
}

CONSOLE_TC(cyang_labels, "arcana-console's labels: set, changed and taken "
    "away, a bad one refused, a host's set by whom may change it")
ATF_TC_BODY(cyang_labels, tc)
{
	struct authn	a, b;
	struct resp	r;
	char		sid[16], path[160], body[300];

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("a", "jgd.sock", sid, sizeof(sid));
	snprintf(path, sizeof(path), CC "labels/label=%s,vtnet0", sid);
	snprintf(body, sizeof(body), "{\"arcana-console:label\":[{\"host\":"
	    "\"%s\",\"interface\":\"vtnet0\",\"text\":\"uplink A\"}]}", sid);
	http("PUT", path, body, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("uplink A", jstr(&r, "arcana-console:label.0.text"));
	resp_free(&r);
	/* Another, by a POST of the list: read in the list. */
	snprintf(body, sizeof(body), "{\"arcana-console:label\":[{\"host\":"
	    "\"%s\",\"interface\":\"vtnet1\",\"text\":\"uplink B\"}]}", sid);
	http("POST", CC "labels", body, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", CC "labels", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(sid, jstr(&r, "arcana-console:labels.label.0.host"));
	ATF_CHECK_STREQ("vtnet0", jstr(&r,
	    "arcana-console:labels.label.0.interface"));
	ATF_CHECK_STREQ(sid, jstr(&r, "arcana-console:labels.label.1.host"));
	ATF_CHECK_STREQ("vtnet1", jstr(&r,
	    "arcana-console:labels.label.1.interface"));
	ATF_CHECK_STREQ("uplink B", jstr(&r,
	    "arcana-console:labels.label.1.text"));
	resp_free(&r);
	/* A control character refused. */
	snprintf(body, sizeof(body), "%s/text", path);
	http("PUT", body, "{\"arcana-console:text\":\"a\\tb\"}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "no control") != NULL,
	    "%s", r.body);
	resp_free(&r);
	http("PUT", body, "{\"arcana-console:text\":\"uplink C\"}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", path, NULL, &r);
	ATF_CHECK_STREQ("uplink C", jstr(&r, "arcana-console:label.0.text"));
	resp_free(&r);
	/* A viewer of the host reads them, changes none. */
	cc_member(&b);
	http("GET", CC "labels", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("uplink C", jstr(&r,
	    "arcana-console:labels.label.0.text"));
	resp_free(&r);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	cookie[0] = '\0';
	do_login(&a, 1, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("GET", CC "labels", NULL, &r);
	ATF_CHECK_STREQ("vtnet1", jstr(&r,
	    "arcana-console:labels.label.0.interface"));
	ATF_CHECK(jstr(&r, "arcana-console:labels.label.1") == NULL);
	resp_free(&r);
}

CONSOLE_TC(cyang_pfxlists, "arcana-console's prefix lists: kept and taken "
    "away, a prefix with host bits refused; members read them")
ATF_TC_BODY(cyang_pfxlists, tc)
{
	struct authn	a, b;
	struct resp	r;

	start(tc, 0, NULL);
	enrol(&a);
	http("POST", CC "prefix-lists", "{\"arcana-console:prefix-list\":[{"
	    "\"name\":\"branches\",\"description\":\"the branches\",\"prefix\":"
	    "[\"10.1.8.0/22\",\"2001:db8:9::/48\"]}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", CC "prefix-lists/prefix-list=branches", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("the branches", jstr(&r,
	    "arcana-console:prefix-list.0.description"));
	ATF_CHECK_STREQ("2001:db8:9::/48", jstr(&r,
	    "arcana-console:prefix-list.0.prefix.1"));
	resp_free(&r);
	/* One with no prefix yet. */
	http("PUT", CC "prefix-lists/prefix-list=hq", "{\"arcana-console:"
	    "prefix-list\":[{\"name\":\"hq\"}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", CC "prefix-lists/prefix-list=hq", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("hq", jstr(&r, "arcana-console:prefix-list.0.name"));
	resp_free(&r);
	http("PATCH", CC "prefix-lists/prefix-list=branches", "{\"arcana-"
	    "console:prefix-list\":[{\"name\":\"branches\",\"prefix\":["
	    "\"10.1.8.1/22\"]}]}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "no host bits") != NULL,
	    "%s", r.body);
	resp_free(&r);
	http("PUT", CC "prefix-lists/prefix-list=branches", "{\"arcana-"
	    "console:prefix-list\":[{\"name\":\"branches\",\"description\":"
	    "\"the branches\",\"prefix\":[\"192.0.2.0/24\"]}]}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "prefix-lists/prefix-list=branches", NULL, &r);
	ATF_CHECK_STREQ("192.0.2.0/24", jstr(&r,
	    "arcana-console:prefix-list.0.prefix.0"));
	ATF_CHECK(jstr(&r, "arcana-console:prefix-list.0.prefix.1") == NULL);
	ATF_CHECK_STREQ("the branches", jstr(&r,
	    "arcana-console:prefix-list.0.description"));
	resp_free(&r);
	/* A member reads them and changes none. */
	cc_member(&b);
	http("GET", CC "prefix-lists", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("branches", jstr(&r,
	    "arcana-console:prefix-lists.prefix-list.0.name"));
	resp_free(&r);
	http("DELETE", CC "prefix-lists/prefix-list=hq", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	cookie[0] = '\0';
	do_login(&a, 1, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("DELETE", CC "prefix-lists/prefix-list=hq", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "prefix-lists", NULL, &r);
	ATF_CHECK(strstr(r.body, "\"hq\"") == NULL);
	ATF_CHECK_STREQ("branches", jstr(&r,
	    "arcana-console:prefix-lists.prefix-list.0.name"));
	resp_free(&r);
}

CONSOLE_TC(cyang_transfers, "arcana-console's transfers: read, "
    "begun and stopped by their actions, both hosts the user's to change")
ATF_TC_BODY(cyang_transfers, tc)
{
	struct authn	a, b;
	struct resp	r;
	char		sa[16], body[400];

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("a", "jgd.sock", sa, sizeof(sa));
	/* One the console's restart did not cut: running. */
	put("data/transfers.json", "{\"transfers\":[{\"id\":77,\"from\":"
	    "\"0000aaaa\",\"snapshot\":\"tank/a@1\",\"recursive\":false,"
	    "\"to\":\"0000bbbb\",\"dataset\":\"tank/b\",\"state\":\"running\","
	    "\"bytes\":4096,\"started\":1700000000},{\"id\":78,\"from\":"
	    "\"0000aaaa\",\"snapshot\":\"tank/a@2\",\"to\":\"0000bbbb\","
	    "\"dataset\":\"tank/b\",\"state\":\"failed\",\"error\":\"gone\","
	    "\"bytes\":0,\"started\":1700000000,\"ended\":1700000060}]}");
	http("GET", CC "transfers", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("77", jstr(&r,
	    "arcana-console:transfers.transfer.0.id"));
	ATF_CHECK_STREQ("running", jstr(&r,
	    "arcana-console:transfers.transfer.0.state"));
	ATF_CHECK_STREQ("4096", jstr(&r,
	    "arcana-console:transfers.transfer.0.bytes"));
	ATF_CHECK_STREQ("2023-11-14T22:13:20Z", jstr(&r,
	    "arcana-console:transfers.transfer.0.started"));
	ATF_CHECK_STREQ("gone", jstr(&r,
	    "arcana-console:transfers.transfer.1.error"));
	resp_free(&r);
	/* Not changed but by its actions. */
	http("PUT", CC "transfers", "{\"arcana-console:transfers\":{}}", &r);
	EXPECT(&r, 405);
	resp_free(&r);
	/* Begun: a host that is none, one host twice, a bad snapshot. */
	snprintf(body, sizeof(body), "{\"arcana-console:input\":{\"from\":"
	    "\"%s\",\"snapshot\":\"tank/a@1\",\"to\":\"0000cccc\",\"dataset\":"
	    "\"tank/b\"}}", sa);
	http("POST", CC "transfers/start", body, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"arcana-console:input\":{\"from\":"
	    "\"%s\",\"snapshot\":\"tank/a@1\",\"to\":\"%s\",\"dataset\":"
	    "\"tank/b\"}}", sa, sa);
	http("POST", CC "transfers/start", body, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "two hosts") != NULL,
	    "%s", r.body);
	resp_free(&r);
	/* Stopped: marked so; one that runs not, refused. */
	http("POST", CC "transfers/transfer=78/stop", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("POST", CC "transfers/transfer=77/stop", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "transfers/transfer=77/cancel", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "arcana-console:cancel"));
	resp_free(&r);
	/* A member: none of it. */
	cc_member(&b);
	http("GET", CC "transfers", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"arcana-console:input\":{\"from\":"
	    "\"%s\",\"snapshot\":\"tank/a@1\",\"to\":\"%s\",\"dataset\":"
	    "\"tank/b\"}}", sa, sa);
	http("POST", CC "transfers/start", body, &r);
	EXPECT(&r, 403);
	resp_free(&r);
}

CONSOLE_TC(authz_scope, "labels and transfers of hosts one may not read "
    "not shown nor stopped; which agent a host is a console owner's alone "
    "to change, a move keeping its certificate's name an admin's")
ATF_TC_BODY(authz_scope, tc)
{
	struct authn	a, d;
	struct resp	r;
	char		sa[16], sb[16], sc[16], body[600], path[160];
	char		keep[sizeof(cookie)];

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("a", "jgd.sock", sa, sizeof(sa));
	host_add("b", "tcp://192.0.2.50:4310", sb, sizeof(sb));
	host_add("c", "tcp://192.0.2.70:4310", sc, sizeof(sc));
	snprintf(body, sizeof(body), "{\"arcana-console:labels\":{\"label\":["
	    "{\"host\":\"%s\",\"interface\":\"em0\",\"text\":\"uplink a\"},"
	    "{\"host\":\"%s\",\"interface\":\"em0\",\"text\":\"uplink b\"}]}}",
	    sa, sb);
	http("PUT", CC "labels", body, &r);
	ATF_CHECK_MSG(r.status == 204 || r.status == 201, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"transfers\":[{\"id\":90,\"from\":"
	    "\"%s\",\"snapshot\":\"tank/a@1\",\"recursive\":false,\"to\":"
	    "\"%s\",\"dataset\":\"tank/b\",\"state\":\"running\",\"bytes\":1,"
	    "\"started\":1700000000}]}", sa, sb);
	put("data/transfers.json", body);

	/* dave: an operator, admin of a and c, nothing of b. */
	snprintf(body, sizeof(body), "{\"id\":\"%s\",\"role\":\"admin\"},"
	    "{\"id\":\"%s\",\"role\":\"admin\"}", sa, sc);
	cc_role("ac", "operator", body);
	memcpy(keep, cookie, sizeof(keep));
	cc_user(&d, "dave", "\"role\":[\"ac\"]", -7);

	/* Labels: a's alone. */
	http("GET", CC "labels", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, "uplink a") != NULL);
	ATF_CHECK_MSG(strstr(r.body, "uplink b") == NULL && strstr(r.body,
	    sb) == NULL, "%s", r.body);
	resp_free(&r);
	/* A PUT of what he sees leaves b's label alone. */
	snprintf(body, sizeof(body), "{\"arcana-console:labels\":{\"label\":["
	    "{\"host\":\"%s\",\"interface\":\"em0\",\"text\":\"uplink a\"}]}}",
	    sa);
	http("PUT", CC "labels", body, &r);
	ATF_CHECK_MSG(r.status < 300, "%d %s", r.status, r.body);
	resp_free(&r);

	/* Transfers: one to b neither shown nor stopped. */
	http("GET", CC "transfers", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "arcana-console:transfers.transfer.0.id") ==
	    NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"90\"") == NULL && strstr(r.body,
	    ":90") == NULL, "%s", r.body);
	resp_free(&r);
	http("POST", CC "transfers/transfer=90/stop", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);

	/* Which agent c is: not his to change, nor its certificate's name
	 * made the new URI's host; a move keeping it is. */
	snprintf(path, sizeof(path), CC "hosts/host=%s", sc);
	snprintf(body, sizeof(body), "{\"arcana-console:host\":[{\"id\":\"%s\","
	    "\"uri\":\"tcp://192.0.2.71:4310\",\"peer-name\":"
	    "\"other.example\"}]}", sc);
	http("PATCH", path, body, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"arcana-console:host\":[{\"id\":\"%s\","
	    "\"uri\":\"tcp://192.0.2.72:4310\",\"peer-name\":\"192.0.2.72\"}]}",
	    sc);
	http("PATCH", path, body, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"arcana-console:host\":[{\"id\":\"%s\","
	    "\"uri\":\"tcp://192.0.2.71:4310\"}]}", sc);
	http("PATCH", path, body, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", path, NULL, &r);
	ATF_CHECK_STREQ("192.0.2.70", jstr(&r,
	    "arcana-console:host.0.peer-name"));
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"arcana-console:host\":[{\"id\":\"%s\","
	    "\"name\":\"c\",\"uri\":\"tcp://192.0.2.71:4310\",\"peer-name\":"
	    "\"other.example\"}]}", sc);
	http("PATCH", path, body, &r);
	EXPECT(&r, 403);
	resp_free(&r);

	/* The owner: b's label kept; he may say which agent c is. */
	memcpy(cookie, keep, sizeof(cookie));
	http("GET", CC "labels", NULL, &r);
	ATF_CHECK_MSG(strstr(r.body, "uplink b") != NULL, "%s", r.body);
	resp_free(&r);
	http("GET", CC "transfers", NULL, &r);
	ATF_CHECK_STREQ("90", jstr(&r,
	    "arcana-console:transfers.transfer.0.id"));
	resp_free(&r);
	http("PATCH", path, body, &r);
	EXPECT(&r, 204);
	resp_free(&r);
}

CONSOLE_TC(cyang_push, "arcana-console's push: each user's own "
    "subscriptions, their keys never read and kept when left out, a "
    "message sent to the user's own devices alone")
ATF_TC_BODY(cyang_push, tc)
{
	/* A P-256 point and 16 bytes, as a browser gives them. */
	static const char key[] = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx"
	    "aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
	static const char auth[] = "BTBZMqHH6r4Tts7J_aSIgg";
	struct authn	a, b;
	struct resp	r;
	char		body[1024], token[80], *doc;

	start(tc, 0, NULL);
	enrol(&a);
	http("GET", CC "push", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_EQ(87, strlen(jstr(&r, "arcana-console:push.public-key")));
	resp_free(&r);
	/* Made: two devices, one without its keys refused. */
	snprintf(body, sizeof(body), "{\"arcana-console:subscription\":[{"
	    "\"endpoint\":\"https://localhost/a\",\"name\":\"Phone\","
	    "\"p256dh\":\"%s\",\"auth\":\"%s\"}]}", key, auth);
	http("POST", CC "push", body, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"arcana-console:subscription\":[{"
	    "\"endpoint\":\"https://localhost/b\",\"name\":\"Laptop\","
	    "\"p256dh\":\"%s\",\"auth\":\"%s\"}]}", key, auth);
	http("POST", CC "push", body, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("POST", CC "push", "{\"arcana-console:subscription\":[{"
	    "\"endpoint\":\"https://localhost/c\"}]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"arcana-console:subscription\":[{"
	    "\"endpoint\":\"https://localhost/d\",\"p256dh\":\"AAAA\","
	    "\"auth\":\"%s\"}]}", auth);
	http("POST", CC "push", body, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "P-256") != NULL,
	    "%s", r.body);
	resp_free(&r);
	/* Read: the two, the keys nowhere. */
	http("GET", CC "push", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("Phone", jstr(&r,
	    "arcana-console:push.subscription.0.name"));
	ATF_CHECK_STREQ("Laptop", jstr(&r,
	    "arcana-console:push.subscription.1.name"));
	ATF_CHECK(jstr(&r, "arcana-console:push.subscription.2") == NULL);
	ATF_CHECK_STREQ("https://localhost/a", jstr(&r,
	    "arcana-console:push.subscription.0.endpoint"));
	ATF_CHECK_STREQ("localhost", jstr(&r,
	    "arcana-console:push.subscription.0.service"));
	ATF_CHECK(jstr(&r, "arcana-console:push.subscription.0.added") !=
	    NULL);
	ATF_CHECK(strstr(r.body, key) == NULL && strstr(r.body, auth) == NULL);
	resp_free(&r);
	http("GET", "/restconf/data", NULL, &r);
	ATF_CHECK(strstr(r.body, key) == NULL && strstr(r.body, auth) == NULL);
	resp_free(&r);
	/* A PUT of what was read: the keys kept, a name changed. */
	http("GET", CC "push?content=config", NULL, &r);
	EXPECT(&r, 200);
	doc = strdup(r.body);
	resp_free(&r);
	http("PUT", CC "push", doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	free(doc);
	http("PATCH", CC "push", "{\"arcana-console:push\":{\"subscription\":"
	    "[{\"endpoint\":\"https://localhost/b\",\"name\":\"Desk\"}]}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	ATF_CHECK(system("grep -q 'BTBZMqHH6r4Tts7J_aSIgg' data/push.json") ==
	    0);
	/* Sent to b, the other: nothing listens there, so it fails, and
	 * says so; its keys there to be used. */
	http("POST", CC "push/send", "{\"arcana-console:input\":{\"title\":"
	    "\"t\",\"body\":\"b\",\"except\":\"https://localhost/a\"}}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("0", jstr(&r, "arcana-console:output.sent"));
	ATF_CHECK_STREQ("1", jstr(&r, "arcana-console:output.failed"));
	ATF_CHECK_STREQ("localhost", jstr(&r,
	    "arcana-console:output.result.0.service"));
	resp_free(&r);
	/* Another user: sees none of these, makes and removes their own,
	 * neither reads nor removes the owner's, nor sends to them. */
	cc_member(&b);
	http("GET", CC "push", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, "localhost/a") == NULL);
	ATF_CHECK(jstr(&r, "arcana-console:push.subscription.0") == NULL);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"arcana-console:subscription\":[{"
	    "\"endpoint\":\"https://localhost/e\",\"name\":\"Bob's\","
	    "\"p256dh\":\"%s\",\"auth\":\"%s\"}]}", key, auth);
	http("POST", CC "push", body, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("PATCH", CC "push", "{\"arcana-console:push\":{\"subscription\":"
	    "[{\"endpoint\":\"https://localhost/a\",\"name\":\"mine\"}]}}",
	    &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "p256dh and auth") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	/* Their own alone: the owner's left out of what they see. */
	http("GET", CC "push", NULL, &r);
	ATF_CHECK_STREQ("https://localhost/e", jstr(&r,
	    "arcana-console:push.subscription.0.endpoint"));
	ATF_CHECK(jstr(&r, "arcana-console:push.subscription.1") == NULL);
	resp_free(&r);
	http("POST", CC "push/send", "{\"arcana-console:input\":{}}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("1", jstr(&r, "arcana-console:output.failed"));
	resp_free(&r);
	http("PUT", CC "push", "{\"arcana-console:push\":{}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "push", NULL, &r);
	ATF_CHECK(jstr(&r, "arcana-console:push.subscription.0") == NULL);
	resp_free(&r);
	ATF_CHECK(system("grep -q 'localhost/a' data/push.json && "
	    "grep -q 'localhost/b' data/push.json && "
	    "! grep -q 'localhost/e' data/push.json") == 0);
	/* A token reads none of it. */
	cookie[0] = '\0';
	do_login(&a, 1, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", CC "tokens/create", "{\"arcana-console:input\":{"
	    "\"name\":\"w\",\"kind\":\"write\"}}", &r);
	EXPECT(&r, 200);
	snprintf(token, sizeof(token), "%s", jstr(&r,
	    "arcana-console:output.token"));
	resp_free(&r);
	http_bearer("GET", CC "push", token, NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http_bearer("GET", "/restconf/data", token, NULL, &r);
	ATF_CHECK(jstr(&r, "arcana-console:push") == NULL);
	resp_free(&r);
}

CONSOLE_TC(cyang_settings_actions, "arcana-console's settings: the mail "
    "test as an action, its answer and its refusals")
ATF_TC_BODY(cyang_settings_actions, tc)
{
	struct authn	a, b;
	struct resp	r;

	start(tc, 0, NULL);
	enrol(&a);
	http("POST", CC "settings/mail-test", NULL, &r);
	EXPECT(&r, 502);
	ATF_CHECK(strstr(r.body, "no address to mail to") != NULL);
	ATF_CHECK(strstr(r.body, "ietf-restconf:errors") != NULL);
	resp_free(&r);
	http("PATCH", CC "settings", "{\"arcana-console:settings\":{"
	    "\"mail-to\":\"ops@example.org\"}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("POST", CC "settings/mail-test", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("ops@example.org", jstr(&r,
	    "arcana-console:output.to"));
	resp_free(&r);
	ATF_CHECK(system("grep -qx 'To: ops@example.org' mail.out") == 0);
	cc_member(&b);
	http("POST", CC "settings/mail-test", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
}

#define	CFL	"arcana-console:feed.0.last-fetch"

CONSOLE_TC_LONG(cyang_feeds, "arcana-console's threat feeds: kept, "
    "fetched and previewed, every protection held: an "
    "address of the internet alone, a URL of one's own an owner's, a "
    "change needing the feed's hosts the user's, hosts and protected "
    "addresses the reader may not read only counted")
ATF_TC_BODY(cyang_feeds, tc)
{
	struct authn	a, b, c;
	struct resp	r;
	char		body[1024], sa[16], sn[16], sg[16], k[128], *doc;
	int		port, i;

	port = feeds_server(tc);
	start(tc, 0, NULL);
	enrol(&a);
	cc_host("a", "jgd.sock", sa, sizeof(sa));
	cc_host("gone", "none.sock", sg, sizeof(sg));
	host_add("far", "tcp://192.0.2.77:4310", k, sizeof(k));
	host_add("near", "tcp://100.64.0.5:4310", sn, sizeof(sn));
	put("data/signins.json", "{\"alice\":{\"addr\":\"203.0.113.9\","
	    "\"at\":1}}");

	/* An address of the internet alone: loopback, private space, a
	 * cloud's metadata refused. */
	{
		static const char *const priv[] = { "127.0.0.1", "10.0.0.1",
		    "169.254.169.254", "[::1]" };

		for (i = 0; i < 4; i++) {
			snprintf(body, sizeof(body), "{\"arcana-console:feed\":[{"
			    "\"id\":\"x\",\"url\":\"http://%s:%d/drop_v4.json\"}]}",
			    priv[i], port);
			http("PUT", CF "x", body, &r);
			ATF_CHECK_MSG(r.status == 400 && strstr(r.body,
			    "is a private or reserved address") != NULL, "%s: %s",
			    priv[i], r.body);
			resp_free(&r);
		}
	}
	http("GET", CC "threat-feeds", NULL, &r);
	ATF_CHECK(jstr(&r, "arcana-console:threat-feeds.feed.0.id") == NULL);
	resp_free(&r);
	/* Nor by a URL changed in place. */
	http("POST", CC "threat-feeds", "{\"arcana-console:feed\":[{\"id\":"
	    "\"spamhaus-drop-v4\",\"preset\":\"spamhaus-drop-v4\"}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"arcana-console:url\":\"http://"
	    "169.254.169.254:%d/x\"}", port);
	http("PUT", CF "spamhaus-drop-v4/url", body, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "private or reserved")
	    != NULL, "%s", r.body);
	resp_free(&r);
	feed_get("spamhaus-drop-v4", &r);
	ATF_CHECK_STREQ("https://www.spamhaus.org/drop/drop_v4.json", jstr(&r,
	    "url"));
	ATF_CHECK_STREQ("feed_spamhaus_drop_v4", jstr(&r, "table"));
	ATF_CHECK_STREQ("12", jstr(&r, "interval"));
	resp_free(&r);
	feeds_allow();

	/* The presets. */
	http("GET", CC "threat-feeds/preset=dshield", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("dshield", jstr(&r, "arcana-console:preset.0.format"));
	ATF_CHECK(jstr(&r, "arcana-console:preset.0.terms-url") != NULL);
	resp_free(&r);

	/* A list of one's own, on host a: fetched, kept, read back. */
	snprintf(body, sizeof(body), "{\"arcana-console:feed\":[{\"id\":"
	    "\"local\",\"name\":\"Local\",\"url\":\"http://127.0.0.1:%d/"
	    "local.txt\",\"format\":\"plain\",\"interval\":1,\"enabled\":true,"
	    "\"host\":[\"%s\"]}]}", port, sa);
	http("PUT", CF "local", body, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	feed_wait("local", "fetched-at", NULL, &r);
	ATF_CHECK_STREQ("feed_local", jstr(&r, "table"));
	resp_free(&r);
	http("GET", CF "local", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("2", jstr(&r, "arcana-console:feed.0.count"));
	ATF_CHECK_STREQ("1", jstr(&r, "arcana-console:feed.0.covered"));
	ATF_CHECK_STREQ("5", jstr(&r, "arcana-console:feed.0.dropped-count"));
	ATF_CHECK_STREQ("8.8.8.0/24", jstr(&r, "arcana-console:feed.0.sample.0"));
	ATF_CHECK_STREQ(sa, jstr(&r, "arcana-console:feed.0.host.0"));
	ATF_CHECK_MSG(cc_dropped(&r, CFL, "192.0.2.0/24", "host far's") &&
	    cc_dropped(&r, CFL, "203.0.113.0/24", "alice's last sign-in"),
	    "%s", r.body);
	ATF_CHECK(jstr(&r, CFL ".protected-hidden") == NULL);
	resp_free(&r);
	snprintf(k, sizeof(k), CF "local/delivered=%s", sa);
	for (i = 0; i < 300; i++) {
		http("GET", k, NULL, &r);
		if (jstr(&r, "arcana-console:delivered.0.at") != NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	if (i == 300)
		http("GET", k, NULL, &r);
	ATF_CHECK_MSG(jstr(&r, "arcana-console:delivered.0.count") != NULL &&
	    strcmp(jstr(&r, "arcana-console:delivered.0.count"), "2") == 0 &&
	    jstr(&r, "arcana-console:delivered.0.table") != NULL,
	    "%d %s", r.status, r.body);
	resp_free(&r);
	/* Fetched and previewed by their actions. */
	ATF_REQUIRE(system(": > ipfw.log") == 0);
	http("POST", CF "local/preview", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	snprintf(k, sizeof(k), "last-preview.host=%s/count", sa);
	feed_wait("local", k, "2", &r);
	resp_free(&r);
	ATF_CHECK(system("grep -q 'swap' ipfw.log") != 0);
	http("GET", CF "local/last-preview", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(sa, jstr(&r, "arcana-console:last-preview.host.0.host"));
	ATF_CHECK_STREQ("2", jstr(&r, "arcana-console:last-preview.count"));
	resp_free(&r);
	http("POST", CF "local/fetch", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("POST", CF "nosuch/fetch", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* Changed by a PATCH: merged, the rest kept. */
	http("PATCH", CF "local", "{\"arcana-console:feed\":[{\"id\":\"local\","
	    "\"interval\":2}]}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	feed_get("local", &r);
	ATF_CHECK_STREQ("2", jstr(&r, "interval"));
	ATF_CHECK_STREQ("true", jstr(&r, "enabled"));
	resp_free(&r);
	/* A list of chosen addresses on no host, and one on host gone. */
	snprintf(body, sizeof(body), "{\"arcana-console:feed\":[{\"id\":"
	    "\"oracle\",\"url\":\"http://127.0.0.1:%d/oracle.txt\","
	    "\"enabled\":true}]}", port);
	http("PUT", CF "oracle", body, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"arcana-console:feed\":[{\"id\":"
	    "\"seen\",\"url\":\"http://127.0.0.1:%d/drop_v4.json\",\"format\":"
	    "\"spamhaus-json\",\"enabled\":true,\"host\":[\"%s\"]}]}", port, sg);
	http("PUT", CF "seen", body, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	feed_wait("oracle", "fetched-at", NULL, &r);
	resp_free(&r);
	snprintf(k, sizeof(k), "delivered=%s/error", sg);
	feed_wait("seen", k, NULL, &r);
	resp_free(&r);
	http("GET", CF "seen", NULL, &r);
	ATF_CHECK_STREQ(sg, jstr(&r, "arcana-console:feed.0.host.0"));
	ATF_CHECK_STREQ("gone", jstr(&r,
	    "arcana-console:feed.0.delivered.0.name"));
	resp_free(&r);

	/* An operator who views hosts a and near. */
	snprintf(body, sizeof(body), "{\"id\":\"%s\",\"role\":\"viewer\"},"
	    "{\"id\":\"%s\",\"role\":\"viewer\"}", sa, sn);
	cc_role("a-viewer-op", "operator", body);
	cc_user(&c, "carol", "\"role\":[\"a-viewer-op\"]", -7);
	/* What it may not read of a host only counted: host gone's id,
	 * name and error nowhere; the protected addresses not its hosts'
	 * nowhere. */
	http("GET", CC "threat-feeds", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, sg) == NULL && strstr(r.body,
	    "\"gone\"") == NULL && strstr(r.body, "none.sock") == NULL &&
	    strstr(r.body, "192.0.2.77") == NULL && strstr(r.body,
	    "203.0.113.9") == NULL && strstr(r.body, "alice") == NULL &&
	    strstr(r.body, "host far") == NULL, "%s", r.body);
	resp_free(&r);
	http("GET", CF "seen", NULL, &r);
	ATF_CHECK_STREQ("1", jstr(&r, "arcana-console:feed.0.hosts-hidden"));
	ATF_CHECK_STREQ("1", jstr(&r, "arcana-console:feed.0.delivered-hidden"));
	ATF_CHECK(jstr(&r, "arcana-console:feed.0.host.0") == NULL);
	resp_free(&r);
	http("GET", CF "oracle", NULL, &r);
	ATF_CHECK_STREQ("2", jstr(&r,
	    "arcana-console:feed.0.last-fetch.protected-hidden"));
	ATF_CHECK_MSG(cc_dropped(&r, CFL, "100.64.0.5/32", "host near's"),
	    "%s", r.body);
	resp_free(&r);
	http("GET", "/restconf/data", NULL, &r);
	ATF_CHECK(strstr(r.body, sg) == NULL && strstr(r.body, "192.0.2.77") ==
	    NULL);
	resp_free(&r);
	/* What it read put back whole changes nothing: no host it may not
	 * read is taken off a feed. */
	http("GET", CC "threat-feeds?content=config", NULL, &r);
	EXPECT(&r, 200);
	doc = strdup(r.body);
	resp_free(&r);
	http("PUT", CC "threat-feeds", doc, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	free(doc);
	cookie[0] = '\0';
	do_login(&a, 1, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	feed_get("seen", &r);
	ATF_CHECK_STREQ(sg, jstr(&r, "host.0"));
	resp_free(&r);
	cookie[0] = '\0';
	do_login(&c, 1, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* A change of a feed on a host it may not change: refused, the
	 * feed as it was. */
	http("PATCH", CF "local", "{\"arcana-console:feed\":[{\"id\":\"local\","
	    "\"enabled\":false}]}", &r);
	ATF_CHECK_MSG(r.status == 403 && strstr(r.body, "host a is not one") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	http("DELETE", CF "local", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("POST", CF "local/fetch", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	feed_get("local", &r);
	ATF_CHECK_STREQ("true", jstr(&r, "enabled"));
	resp_free(&r);
	/* Nor a host it may not change added. */
	snprintf(body, sizeof(body), "{\"arcana-console:feed\":[{\"id\":"
	    "\"oracle\",\"host\":[\"%s\"]}]}", sa);
	http("PATCH", CF "oracle", body, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "not one you may "
	    "change") != NULL, "%s", r.body);
	resp_free(&r);
	/* A URL of one's own: an owner's to make, change and preview; the
	 * operator disables it, and uses a preset. */
	snprintf(body, sizeof(body), "{\"arcana-console:feed\":[{\"id\":"
	    "\"carols\",\"url\":\"http://127.0.0.1:%d/drop_v4.json\"}]}", port);
	http("PUT", CF "carols", body, &r);
	ATF_CHECK_MSG(r.status == 403 && strstr(r.body, "console owner") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	/* The console's settings the owner's alone, by /restconf/data;
	 * and never served by /restconf/ds, whose datastores are each
	 * host's: no way past the owner's check there either. */
	http("GET", "/restconf/data/arcana-console:settings", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("GET", "/restconf/ds/ietf-datastores:running/arcana-console:"
	    "settings", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("PUT", "/restconf/ds/ietf-datastores:running/arcana-console:"
	    "settings", "{\"arcana-console:settings\":{}}", &r);
	ATF_CHECK_MSG(r.status == 404 || r.status == 403, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"arcana-console:url\":\"http://"
	    "127.0.0.1:%d/local.txt\"}", port);
	http("PUT", CF "oracle/url", body, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("POST", CF "oracle/preview", NULL, &r);
	ATF_CHECK_MSG(r.status == 403 && strstr(r.body, "previewed by a "
	    "console owner") != NULL, "%s", r.body);
	resp_free(&r);
	http("PATCH", CF "oracle", "{\"arcana-console:feed\":[{\"id\":"
	    "\"oracle\",\"enabled\":false}]}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	feed_get("oracle", &r);
	ATF_CHECK_STREQ("false", jstr(&r, "enabled"));
	resp_free(&r);
	http("POST", CC "threat-feeds", "{\"arcana-console:feed\":[{\"id\":"
	    "\"dshield\",\"preset\":\"dshield\"}]}", &r);
	EXPECT(&r, 201);
	resp_free(&r);
	/* A member: none of it. */
	cookie[0] = '\0';
	do_login(&a, 2, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	cc_user(&b, "dave", "\"role\":[\"viewer\"]", -8);
	http("GET", CC "threat-feeds", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("POST", CF "dshield/fetch", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
}

/*
 * A request of arcana-console's: its status want, an error RFC 8040's
 * where it is one, and has (if not NULL) in its body.
 */
static void
cc_want(const char *method, const char *path, const char *body, int want,
    const char *has)
{
	struct resp	r;

	http(method, path, body, &r);
	ATF_CHECK_MSG(r.status == want, "%s %s: %d, not %d: %.400s", method,
	    path, r.status, want, r.body);
	if (r.status >= 400)
		ATF_CHECK_MSG(strstr(r.body, "ietf-restconf:errors") != NULL,
		    "%s", r.body);
	if (has != NULL)
		ATF_CHECK_MSG(strstr(r.body, has) != NULL, "%s %s: no %s: "
		    "%.400s", method, path, has, r.body);
	resp_free(&r);
}

CONSOLE_TC(cyang_hosts, "arcana-console's hosts: the registry, added, "
    "renamed, changed and removed, each user the hosts they have a role "
    "on, a member refused")
ATF_TC_BODY(cyang_hosts, tc)
{
	struct authn	a, b;
	struct resp	r;
	char		sa[16], path[160], body[512];

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("a", "jgd.sock", sa, sizeof(sa));
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(sa, jstr(&r, "arcana-console:hosts.host.0.id"));
	ATF_CHECK_STREQ("a", jstr(&r, "arcana-console:hosts.host.0.name"));
	ATF_CHECK_STREQ("true", jstr(&r, "arcana-console:hosts.host.0.local"));
	ATF_CHECK_STREQ("admin", jstr(&r, "arcana-console:hosts.host.0.role"));
	ATF_CHECK_STREQ("false", jstr(&r,
	    "arcana-console:hosts.host.0.notification-token-set"));
	resp_free(&r);
	/* Renamed, its tenant, timer and repositories. */
	snprintf(path, sizeof(path), CC "hosts/host=%s", sa);
	snprintf(body, sizeof(body), "{\"arcana-console:host\":[{\"id\":"
	    "\"%s\",\"name\":\"b\",\"tenant\":\"t1\",\"safe-wait\":30,"
	    "\"pkg-repos\":[{\"jail\":\".\",\"upgrade\":\"FreeBSD\"}]}]}", sa);
	http("PATCH", path, body, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("b", jstr(&r, "arcana-console:host.0.name"));
	ATF_CHECK_STREQ("t1", jstr(&r, "arcana-console:host.0.tenant"));
	ATF_CHECK_STREQ("30", jstr(&r, "arcana-console:host.0.safe-wait"));
	ATF_CHECK_STREQ(".", jstr(&r, "arcana-console:host.0.pkg-repos.0.jail"));
	ATF_CHECK_STREQ("FreeBSD", jstr(&r,
	    "arcana-console:host.0.pkg-repos.0.upgrade"));
	resp_free(&r);
	/* Refused: a timer out of range. */
	snprintf(body, sizeof(body), "{\"arcana-console:host\":[{\"id\":"
	    "\"%s\",\"safe-wait\":5}]}", sa);
	http("PATCH", path, body, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* Added: its URI another's refused, a bad one refused. */
	http("POST", CC "hosts", "{\"arcana-console:host\":[{\"id\":"
	    "\"0000abcd\",\"name\":\"c\",\"uri\":\"tcp://192.0.2.1:4310\"}]}",
	    &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("POST", CC "hosts", "{\"arcana-console:host\":[{\"id\":"
	    "\"0000abce\",\"name\":\"d\",\"uri\":\"tcp://192.0.2.1:4310\"}]}",
	    &r);
	EXPECT(&r, 409);
	resp_free(&r);
	http("POST", CC "hosts", "{\"arcana-console:host\":[{\"id\":"
	    "\"0000abce\",\"name\":\"d\",\"uri\":\"ftp://x\"}]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* An id not 8 lowercase hex digits refused: ids name files. */
	http("POST", CC "hosts", "{\"arcana-console:host\":[{\"id\":"
	    "\"../../x\",\"name\":\"e\",\"uri\":\"tcp://192.0.2.9:4310\"}]}",
	    &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", CC "hosts", "{\"arcana-console:host\":[{\"id\":"
	    "\"0000ABCF\",\"name\":\"e\",\"uri\":\"tcp://192.0.2.9:4310\"}]}",
	    &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/*
	 * An id a role still names is refused: a host made with it would
	 * be given whoever holds the role.  A member is refused alike
	 * whether the id is a host's or not: no id told.
	 */
	{
		struct authn	m;
		char		inv[128], keep[sizeof(cookie)], hp[160];

		cc_role("stale", "operator", "{\"id\":\"deadbeef\",\"role\":"
		    "\"admin\"}");
		http("POST", CC "hosts", "{\"arcana-console:host\":[{\"id\":"
		    "\"deadbeef\",\"name\":\"s\",\"uri\":\"tcp://192.0.2.10:"
		    "4310\"}]}", &r);
		ATF_CHECK_MSG(r.status == 409 && strstr(r.body, "a role names")
		    != NULL, "%d %s", r.status, r.body);
		resp_free(&r);
		cc_role("plain", "member", "");
		cc_invite("mia", "plain", inv, sizeof(inv));
		memcpy(keep, cookie, sizeof(keep));
		cookie[0] = '\0';
		authn_new(&m, -7);
		do_register(&m, inv, &r);
		EXPECT(&r, 200);
		resp_free(&r);
		snprintf(body, sizeof(body), "{\"arcana-console:host\":[{\"id\":"
		    "\"%s\",\"name\":\"z\",\"uri\":\"tcp://192.0.2.11:4310\"}]}",
		    sa);
		snprintf(hp, sizeof(hp), CC "hosts/host=%s", sa);
		http("PUT", hp, body, &r);
		EXPECT(&r, 403);
		resp_free(&r);
		http("PUT", CC "hosts/host=0badf00d", "{\"arcana-console:host\":"
		    "[{\"id\":\"0badf00d\",\"name\":\"z\",\"uri\":\"tcp://"
		    "192.0.2.12:4310\"}]}", &r);
		EXPECT(&r, 403);
		resp_free(&r);
		memcpy(cookie, keep, sizeof(cookie));
	}
	http("GET", CC "hosts", NULL, &r);
	ATF_CHECK_STREQ("c", jstr(&r, "arcana-console:hosts.host.1.name"));
	ATF_CHECK(jstr(&r, "arcana-console:hosts.host.2.name") == NULL);
	resp_free(&r);
	/* Moved by the console alone: the certificate checked is the
	 * name it was enrolled as. */
	http("PATCH", CC "hosts/host=0000abcd", "{\"arcana-console:host\":[{"
	    "\"id\":\"0000abcd\",\"uri\":\"tcp://192.0.2.2:4310\"}]}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "hosts/host=0000abcd", NULL, &r);
	ATF_CHECK_STREQ("192.0.2.1", jstr(&r,
	    "arcana-console:host.0.peer-name"));
	resp_free(&r);
	/* Removed. */
	http("DELETE", CC "hosts/host=0000abcd", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "hosts", NULL, &r);
	ATF_CHECK(jstr(&r, "arcana-console:hosts.host.1.name") == NULL);
	resp_free(&r);
	/* A member, a viewer of every host: reads them, changes none. */
	cc_member(&b);
	http("GET", CC "hosts", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("viewer", jstr(&r,
	    "arcana-console:hosts.host.0.role"));
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"arcana-console:host\":[{\"id\":"
	    "\"%s\",\"tenant\":\"t2\"}]}", sa);
	http("PATCH", path, body, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("POST", CC "hosts", "{\"arcana-console:host\":[{\"id\":"
	    "\"0000abcf\",\"name\":\"e\",\"uri\":\"tcp://192.0.2.3:4310\"}]}",
	    &r);
	EXPECT(&r, 403);
	resp_free(&r);
}

CONSOLE_TC(cyang_host_verbs, "arcana-console's hosts: what the console "
    "answers of a host, and its verbs, at their RESTCONF paths, their "
    "refusals held")
ATF_TC_BODY(cyang_host_verbs, tc)
{
	struct authn	a, b;
	struct resp	r;
	char		sa[16], cc[160];

#define	HV(m, node, body, want, has) do {				\
	snprintf(cc, sizeof(cc), CC "hosts/host=%s/%s", sa, node);	\
	cc_want(m, cc, body, want, has);				\
} while (0)
	start(tc, 0, NULL);
	enrol(&a);
	cc_host("a", "jgd.sock", sa, sizeof(sa));
	snprintf(cc, sizeof(cc), CC "hosts/host=%s/drift", sa);
	http("GET", cc, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "arcana-console:drift.ok"));
	resp_free(&r);
	HV("GET", "watch", NULL, 200, "\"arcana-console:watch\":{"
	    "\"connected\":");
	HV("GET", "notifications", NULL, 200, "\"records\":[]");
	/* No https origin the hosts reach the console by. */
	HV("GET", "subscription", NULL, 409, "https origin");
	HV("GET", "tls", NULL, 200, "no TLS files");
	HV("GET", "transport", NULL, 200, "\"arcana-console:transport\"");
	HV("GET", "configuration", NULL, 200, "\"arcana\":\"host\"");
	/* A host on its local socket is not moved, nor switched. */
	HV("POST", "move", "{\"arcana-console:input\":{\"uri\":"
	    "\"tcp://192.0.2.1:4310\"}}", 400, "local socket is not moved");
	HV("POST", "switch-transport", "{\"arcana-console:input\":{"
	    "\"transport\":\"sctp\"}}", 400, NULL);
	/* A bare body is no input. */
	HV("POST", "move", "{\"uri\":\"tcp://192.0.2.1:4310\"}", 400, NULL);
	HV("POST", "subscription-token", NULL, 409, "https origin");
	HV("POST", "export-configuration", "{\"arcana-console:input\":{"
	    "\"secrets\":false}}", 200, "\"arcana-console:output\":{\"result\"");
	HV("POST", "apply-configuration", "{\"arcana-console:input\":{"
	    "\"dry-run\":true}}", 400, "bundle");
	HV("POST", "capture", "{\"arcana-console:input\":{}}", 200,
	    "\"arcana-console:output\":{\"result\"");
	HV("POST", "nacm-sync", NULL, 200, "\"result\":\"unchanged\"");
	/* No such host. */
	http("GET", CC "hosts/host=0000ffff/drift", NULL, &r);
	EXPECT(&r, 404);
	ATF_CHECK(strstr(r.body, "ietf-restconf:errors") != NULL);
	resp_free(&r);
	/* A member, a viewer: reads, and administers nothing. */
	cc_member(&b);
	HV("GET", "drift", NULL, 200, "\"arcana-console:drift\"");
	HV("POST", "agent-update", "{\"arcana-console:input\":{}}", 403,
	    "access-denied");
	HV("POST", "nacm-sync", NULL, 403, "access-denied");
	HV("POST", "renew-tls", NULL, 403, "access-denied");
	HV("POST", "subscription-token", NULL, 403, "access-denied");
#undef	HV
}

CONSOLE_TC(cyang_dataset_key, "arcana-console's dataset-key: a dataset's "
    "key loaded and changed, in no log; a bad input, a bare body and a "
    "viewer refused")
ATF_TC_BODY(cyang_dataset_key, tc)
{
	struct authn	a, b;
	struct resp	r;
	char		sa[16], cc[160], body[512];

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("a", "jgd.sock", sa, sizeof(sa));
	snprintf(cc, sizeof(cc), CC "hosts/host=%s/dataset-key", sa);
	/* Loaded: the dataset's name with its /, in the input. */
	http("POST", cc, "{\"arcana-console:input\":{\"dataset\":"
	    "\"tank/vault\",\"key\":\"correct horse battery\"}}", &r);
	ATF_CHECK_MSG(r.status == 200 && strstr(r.body,
	    "\"arcana-console:output\":{\"result\"") != NULL, "%d %s",
	    r.status, r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -qx 'key=correct horse battery' storage.log && "
	    "grep -qx 'zfs load-key tank/vault' storage.log") == 0);
	/* Changed: the new key, its leaf's name - for _. */
	http("POST", cc, "{\"arcana-console:input\":{\"dataset\":"
	    "\"tank/vault\",\"key\":\"correct horse battery\","
	    "\"new-key\":\"tr0ub4dor and more\"}}", &r);
	ATF_CHECK_MSG(r.status == 200, "%d %s", r.status, r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^zfs change-key' storage.log") == 0);
	/* The keys are in no log of the console's, nor in its data. */
	ATF_CHECK(system("grep -rqs 'correct horse battery' console.out "
	    "data") != 0);
	ATF_CHECK(system("grep -rqs 'tr0ub4dor and more' console.out data")
	    != 0);
	/* Neither key: refused. */
	http("POST", cc, "{\"arcana-console:input\":{\"dataset\":"
	    "\"tank/vault\"}}", &r);
	EXPECT(&r, 400);
	ATF_CHECK(strstr(r.body, "ietf-restconf:errors") != NULL);
	resp_free(&r);
	/* No dataset; one too long for its leaf. */
	http("POST", cc, "{\"arcana-console:input\":{\"key\":\"x\"}}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	memset(body, 0, sizeof(body));
	snprintf(body, sizeof(body), "{\"arcana-console:input\":{\"dataset\":"
	    "\"tank/%0300d\",\"key\":\"x\"}}", 0);
	http("POST", cc, body, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* A bare body is no input. */
	http("POST", cc, "{\"dataset\":\"tank/vault\",\"key\":\"x\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* A viewer types no key. */
	cc_member(&b);
	http("POST", cc, "{\"arcana-console:input\":{\"dataset\":"
	    "\"tank/vault\",\"key\":\"x\"}}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
}

/*
 * GET of a bridged node of arcana-console's at path: 200, r's JSON its
 * document (the value of "arcana-console:<node>").
 */
static void
cc_doc(const char *path, const char *node, struct resp *r)
{
	char	key[96];

	http("GET", path, NULL, r);
	EXPECT(r, 200);
	snprintf(key, sizeof(key), "arcana-console:%s", node);
	ATF_CHECK_MSG(resp_unwrap(r, key), "%s: no %s: %.300s", path, key,
	    r->body);
}

/* {"arcana-console:input": {"document": doc}} */
static char *
cc_doc_input(const char *doc)
{
	char	*s;

	ATF_REQUIRE(asprintf(&s, "{\"arcana-console:input\":{\"document\":%s}}",
	    doc) != -1);
	return (s);
}

CONSOLE_TC_LONG(cyang_sdwan, "arcana-console's sdwan: the document, plan, "
    "ledger, apply, steering, rekeys, lists, identities and records at "
    "their RESTCONF paths, the plan's refusals held, a member refused")
ATF_TC_BODY(cyang_sdwan, tc)
{
	struct authn	 a, b;
	struct resp	 r;
	char		 sa[16], sb[16], doc[8192], t1[8192], body[8448];
	char		*in;

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("a", "jgd.sock", sa, sizeof(sa));
	cc_host("b", "./jgd.sock", sb, sizeof(sb));
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	cc_doc(CC "sdwan/document", "document", &r);
	ATF_CHECK_STREQ("0", jstr(&r, "version"));
	ATF_CHECK(jstr(&r, "swvcs.0") == NULL);
	resp_free(&r);
	/* Nothing to plan yet: an empty plan, an empty ledger. */
	cc_doc(CC "sdwan/plan", "plan", &r);
	ATF_CHECK(jstr(&r, "changes") != NULL && jstr(&r, "changes.0") ==
	    NULL);
	resp_free(&r);
	cc_doc(CC "sdwan/ledger", "ledger", &r);
	ATF_CHECK(jstr(&r, "fibs") != NULL);
	resp_free(&r);
	/* Checked, a broken one refused. */
	in = cc_doc_input(doc);
	http("POST", CC "sdwan/check", in, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "arcana-console:output.result.ok"));
	resp_free(&r);
	free(in);
	ATF_REQUIRE(swap_in(doc, "\"fib\":1", "\"fib\":0", t1, sizeof(t1)));
	in = cc_doc_input(t1);
	cc_want("POST", CC "sdwan/check", in, 400, "FIB 0 is the underlay's");
	free(in);
	/* Kept, as version 1; again from version 0, too old. */
	snprintf(body, sizeof(body), "{\"arcana-console:document\":%s}", doc);
	http("PUT", CC "sdwan/document", body, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	cc_doc(CC "sdwan/document", "document", &r);
	ATF_CHECK_STREQ("1", jstr(&r, "version"));
	resp_free(&r);
	http("PUT", CC "sdwan/document", body, &r);
	EXPECT(&r, 409);
	ATF_CHECK(strstr(r.body, "ietf-restconf:errors") != NULL);
	resp_free(&r);
	cc_doc(CC "sdwan/document", "document", &r);
	ATF_CHECK_STREQ("acme", jstr(&r, "swvcs.0.id"));
	ATF_CHECK_STREQ(sa, jstr(&r, "edges.0.server"));
	ATF_CHECK_STREQ(sb, jstr(&r, "edges.1.server"));
	resp_free(&r);
	/* Its end points have no address yet: no plan, no ledger. */
	cc_want("GET", CC "sdwan/plan", NULL, 409, "has no address");
	cc_want("GET", CC "sdwan/ledger", NULL, 409, "has no address");
	cc_doc(CC "sdwan/apply-state", "apply-state", &r);
	ATF_CHECK_STREQ("false", jstr(&r, "applying"));
	resp_free(&r);
	cc_doc(CC "sdwan/steering", "steering", &r);
	ATF_CHECK(jstr(&r, "sent") != NULL && jstr(&r, "live") != NULL);
	resp_free(&r);
	cc_doc(CC "sdwan/rekeys", "rekeys", &r);
	ATF_CHECK_STREQ("false", jstr(&r, "rekeying"));
	resp_free(&r);
	cc_doc(CC "sdwan/identities", "identities", &r);
	ATF_CHECK_STREQ("alice", jstr(&r, "identities.0.name"));
	ATF_CHECK_STREQ("carol", jstr(&r, "identities.1.name"));
	ATF_CHECK_STREQ(sa, jstr(&r, "identities.0.edge"));
	resp_free(&r);
	cc_doc(CC "sdwan/audit", "audit", &r);
	ATF_CHECK_STREQ("true", jstr(&r, "intact"));
	ATF_CHECK_STREQ("1", jstr(&r, "count"));
	ATF_CHECK_STREQ("policies-changed", jstr(&r, "events.0.event"));
	resp_free(&r);
	cc_doc(CC "sdwan/sen", "sen", &r);
	ATF_CHECK_STREQ("0", jstr(&r, "count"));
	resp_free(&r);
	cc_doc(CC "sdwan/san", "san", &r);
	ATF_CHECK_STREQ("5", jstr(&r, "count"));
	resp_free(&r);
	cc_doc(CC "sdwan/audit?q=policies", "audit", &r);
	ATF_CHECK_STREQ("1", jstr(&r, "count"));
	resp_free(&r);
	/* A record as CSV, by Accept. */
	http_with("GET", CC "sdwan/audit", "Accept: text/csv\r\n", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.head, "text/csv") != NULL);
	resp_free(&r);
	/* An apply of a plan that cannot be made; what is none refused. */
	cc_want("POST", CC "sdwan/apply", "{\"arcana-console:input\":{}}", 409,
	    "has no address");
	cc_want("POST", CC "sdwan/rekey", "{\"arcana-console:input\":{"
	    "\"tunnel\":\"acme/none\"}}", 404, NULL);
	cc_want("POST", CC "sdwan/pin", "{\"arcana-console:input\":{\"edge\":"
	    "\"none\",\"table\":\"t\",\"prefix\":\"10.0.0.0/8\"}}", 404,
	    "no such edge");
	http("POST", CC "sdwan/revoke-identity", "{\"arcana-console:input\":{"
	    "\"swvc\":\"x\",\"end-point\":\"y\",\"name\":\"z\"}}", &r);
	EXPECT(&r, 404);
	resp_free(&r);
	cc_want("POST", CC "sdwan/issue-identity", "{\"arcana-console:input\":{"
	    "\"swvc\":\"x\",\"end-point\":\"y\",\"name\":\"\"}}", 400,
	    "printable ASCII");
	cc_want("POST", CC "sdwan/attach", "{\"arcana-console:input\":{"
	    "\"vpn-id\":\"none\",\"vpn-node-id\":\"x\"}}", 404,
	    "no such service");
	/* The lists: kept, a bad interval refused. */
	http("PUT", CC "sdwan/lists", "{\"arcana-console:lists\":{\"interval\":"
	    "2,\"feeds\":[{\"name\":\"l1\",\"text\":\"10.0.0.0/8\"}]}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	cc_doc(CC "sdwan/lists", "lists", &r);
	ATF_CHECK_STREQ("2", jstr(&r, "interval"));
	ATF_CHECK_STREQ("l1", jstr(&r, "feeds.0.name"));
	ATF_CHECK_STREQ("10.0.0.0/8", jstr(&r, "feeds.0.entries.0"));
	resp_free(&r);
	cc_want("PUT", CC "sdwan/lists", "{\"arcana-console:lists\":{"
	    "\"interval\":0}}", 400, "interval is hours");
	http("POST", CC "sdwan/fetch-lists", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r,
	    "arcana-console:output.result.fetched"));
	resp_free(&r);
	/* A member: none of it. */
	cc_member(&b);
	http("GET", CC "sdwan/plan", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("POST", CC "sdwan/apply", "{\"arcana-console:input\":{}}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("GET", CC "sdwan/audit", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
}

CONSOLE_TC(cyang_console, "arcana-console's update, notes, cluster, CA, "
    "security keys, path finder and WireGuard key pair at their RESTCONF "
    "paths, an owner's an owner's, a key never the last, a token reading "
    "no key")
ATF_TC_BODY(cyang_console, tc)
{
	struct authn	 a, b;
	struct resp	 r;
	char		 sa[16], id[600], path[700], token[80], body[512];

	start(tc, 0, NULL);
	enrol(&a);
	cc_host("a", "jgd.sock", sa, sizeof(sa));
#ifdef ARCANA_CLUSTER
	cc_doc(CC "cluster", "cluster", &r);
	ATF_CHECK_STREQ("false", jstr(&r, "on"));
	resp_free(&r);
	http("GET", "/api/health", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "cluster"));
	resp_free(&r);
#else
	/* Built WITHOUT_CLUSTER: the cluster is not there, and says so. */
	cc_want("GET", CC "cluster", NULL, 501, "built without clustering");
	http("GET", "/api/health", NULL, &r);
	ATF_CHECK_STREQ("false", jstr(&r, "cluster"));
	resp_free(&r);
#endif
	cc_doc(CC "update", "update", &r);
	ATF_CHECK(jstr(&r, "current") != NULL);
	resp_free(&r);
	cc_want("GET", CC "update-notes?component=agent", NULL, 409,
	    "names no repository");
	/* The CA: its state, at the container and below it. */
	http("GET", CC "ca", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "arcana-console:ca.state.own"));
	ATF_CHECK_STREQ("CN=arcana CA", jstr(&r,
	    "arcana-console:ca.state.trusted.0.subject"));
	resp_free(&r);
	http("GET", CC "ca/state", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "arcana-console:state.own"));
	resp_free(&r);
	http("POST", CC "ca/discard", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "arcana-console:output.result.own"));
	resp_free(&r);
	cc_want("POST", CC "ca/finish", "{\"arcana-console:input\":{}}", 409,
	    "nothing rolled out");
	/* The path finder: what is no pair of addresses refused, else
	 * asked. */
	cc_want("POST", "/restconf/operations/arcana-console:trace-path",
	    "{\"arcana-console:input\":{\"src\":\"10.0.0.1\",\"dst\":\"::1\"}}",
	    400, "both IPv4 or both IPv6");
	snprintf(body, sizeof(body), "{\"arcana-console:input\":{\"src\":"
	    "\"10.1.0.2\",\"dst\":\"10.3.0.2\",\"proto\":\"tcp\",\"port\":22,"
	    "\"places\":[{\"server\":\"%s\"}]}}", sa);
	http("POST", "/restconf/operations/arcana-console:trace-path", body,
	    &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, "{\"arcana-console:output\":{\"result\":") ==
	    r.body);
	resp_free(&r);
	http("GET", "/restconf/operations", NULL, &r);
	ATF_CHECK(strstr(r.body, "arcana-console:wireguard-keypair") != NULL);
	resp_free(&r);
	/* A key pair, said once. */
	http("POST", "/restconf/operations/arcana-console:wireguard-keypair",
	    NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "arcana-console:output.result.private_key") !=
	    NULL && strlen(jstr(&r,
	    "arcana-console:output.result.private_key")) == 44);
	resp_free(&r);
	/* The keys: the owner's one, renamed, never the last removed. */
	http("GET", CC "credentials", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "arcana-console:credentials.credential.0.id") !=
	    NULL);
	snprintf(id, sizeof(id), "%s", jstr(&r,
	    "arcana-console:credentials.credential.0.id"));
	ATF_CHECK(jstr(&r, "arcana-console:credentials.credential.0.user") !=
	    NULL);
	ATF_CHECK(jstr(&r, "arcana-console:credentials.credential.1") == NULL);
	ATF_CHECK(strstr(r.body, "public") == NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), CC "credentials/credential=%s", id);
	snprintf(body, sizeof(body), "{\"arcana-console:credential\":[{\"id\":"
	    "\"%s\",\"name\":\"Desk key\"}]}", id);
	http("PATCH", path, body, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "credentials", NULL, &r);
	ATF_CHECK_STREQ("Desk key", jstr(&r,
	    "arcana-console:credentials.credential.0.name"));
	resp_free(&r);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 409);
	resp_free(&r);
	/* A token reads no key, and changes no CA. */
	http("POST", CC "tokens/create", "{\"arcana-console:input\":{"
	    "\"name\":\"w\",\"kind\":\"write\"}}", &r);
	EXPECT(&r, 200);
	snprintf(token, sizeof(token), "%s", jstr(&r,
	    "arcana-console:output.token"));
	resp_free(&r);
	http_bearer("GET", CC "credentials", token, NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http_bearer("POST", CC "ca/discard", token, NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* A member: their own key alone; none of an owner's. */
	cc_member(&b);
	http("GET", CC "credentials", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bob", jstr(&r,
	    "arcana-console:credentials.credential.0.user"));
	ATF_CHECK(jstr(&r, "arcana-console:credentials.credential.1.id") ==
	    NULL);
	resp_free(&r);
	/* Another's key is not there for a member. */
	http("DELETE", path, NULL, &r);
	ATF_CHECK_MSG(r.status == 409 && strstr(r.body, "data-missing") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	http("GET", CC "ca", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("GET", CC "update", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("POST", "/restconf/operations/arcana-console:wireguard-keypair",
	    NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
#ifdef ARCANA_CLUSTER
	/* The cluster's state is any user's to read. */
	cc_doc(CC "cluster", "cluster", &r);
	ATF_CHECK_STREQ("false", jstr(&r, "on"));
	resp_free(&r);
#endif
}

CONSOLE_TC(cyang_plugins, "arcana-console's plugins: listed, enabled by "
    "an owner alone, each user's store their own, the shared one written "
    "by operators and owners, If-Match held")
ATF_TC_BODY(cyang_plugins, tc)
{
	struct authn	a, b;
	struct resp	r;
	char		cwd[MAXPATHLEN], tag[64], hdr[128];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ATF_REQUIRE(mkdir("plugins", 0755) == 0);
	ATF_REQUIRE(mkdir("plugins/good", 0755) == 0);
	put("plugins/good/plugin.json", "{\"id\":\"good\",\"name\":\"Good\","
	    "\"version\":\"1.2.0\",\"arcana\":\"0.1.0\",\"entry\":"
	    "[\"main.js\"],\"provides\":[\"theme\"]}");
	put("plugins/good/main.js", "window.x = 1;\n");
	snprintf(harness_webconf, sizeof(harness_webconf), "plugins_dir = "
	    "\"%s/plugins\";\n", cwd);
	start(tc, 0, NULL);
	enrol(&a);
	http("GET", CC "plugins", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "arcana-console:plugins.directory") != NULL);
	ATF_CHECK_STREQ("good", jstr(&r, "arcana-console:plugins.plugin.0.id"));
	ATF_CHECK_STREQ("false", jstr(&r,
	    "arcana-console:plugins.plugin.0.enabled"));
	ATF_CHECK_STREQ("main.js", jstr(&r,
	    "arcana-console:plugins.plugin.0.file.0.path"));
	ATF_CHECK_STREQ("theme", jstr(&r,
	    "arcana-console:plugins.plugin.0.provides.0"));
	resp_free(&r);
	/* Its store not found until enabled. */
	cc_want("GET", CC "plugins/plugin=good/store", NULL, 404,
	    "no plugin good enabled");
	http("PATCH", CC "plugins/plugin=good", "{\"arcana-console:plugin\":"
	    "[{\"id\":\"good\",\"enabled\":true}]}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", CC "plugins", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r,
	    "arcana-console:plugins.plugin.0.enabled"));
	resp_free(&r);
	http("POST", CC "plugins", "{\"arcana-console:plugin\":[{\"id\":"
	    "\"nosuch\",\"enabled\":true}]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* The owner's store: none yet, kept, then only by its tag. */
	http("GET", CC "plugins/plugin=good/store", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("PUT", CC "plugins/plugin=good/store",
	    "{\"arcana-console:store\":{\"level\":3}}", &r);
	EXPECT(&r, 204);
	ATF_REQUIRE(resp_header(&r, "etag", tag, sizeof(tag)) != NULL);
	resp_free(&r);
	http("GET", CC "plugins/plugin=good/store", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("3", jstr(&r, "arcana-console:store.level"));
	resp_free(&r);
	http("PUT", CC "plugins/plugin=good/store",
	    "{\"arcana-console:store\":{\"level\":9}}", &r);
	EXPECT(&r, 412);
	resp_free(&r);
	snprintf(hdr, sizeof(hdr), "If-Match: %s\r\n", tag);
	http_with("PUT", CC "plugins/plugin=good/store", hdr,
	    "{\"arcana-console:store\":{\"level\":4}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("PUT", CC "plugins/plugin=good/store", "{\"level\":5}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("PUT", CC "plugins/plugin=good/shared-store",
	    "{\"arcana-console:shared-store\":{\"theme\":\"dark\"}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	/* A member: reads the list and the shared store, a store of its
	 * own, enables nothing, writes no shared store. */
	cc_member(&b);
	http("GET", CC "plugins", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "arcana-console:plugins.directory") == NULL);
	resp_free(&r);
	http("PATCH", CC "plugins/plugin=good", "{\"arcana-console:plugin\":"
	    "[{\"id\":\"good\",\"enabled\":false}]}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("GET", CC "plugins/plugin=good/store", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("GET", CC "plugins/plugin=good/shared-store", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("dark", jstr(&r, "arcana-console:shared-store.theme"));
	resp_free(&r);
	http("PUT", CC "plugins/plugin=good/shared-store",
	    "{\"arcana-console:shared-store\":{\"theme\":\"light\"}}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
}

/* The node of a module's description at path, below nodes, choices and
 * cases passed through. */
static const ucl_object_t *
ym_node(const ucl_object_t *nodes, const char *path)
{
	const ucl_object_t	*n, *f, *v;
	ucl_object_iter_t	 it = NULL;

	while ((n = ucl_object_iterate(nodes, &it, true)) != NULL) {
		if ((v = ucl_object_lookup(n, "path")) != NULL &&
		    strcmp(ucl_object_tostring(v), path) == 0)
			return (n);
		if ((v = ucl_object_lookup(n, "children")) != NULL &&
		    (f = ym_node(v, path)) != NULL)
			return (f);
		if ((v = ucl_object_lookup(n, "cases")) != NULL &&
		    (f = ym_node(v, path)) != NULL)
			return (f);
	}
	return (NULL);
}

static const char *
ym_str(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	v = o != NULL ? ucl_object_lookup_path(o, key) : NULL;
	return (v != NULL ? ucl_object_tostring_forced(v) : NULL);
}

CONSOLE_TC(yang_module, "A module described for forms (4.8.3): the jail "
    "list with its key, a leaf's type, an enumeration's values, the "
    "descriptions; another revision 404, without a session 401, 304 by "
    "its entity-tag")
ATF_TC_BODY(yang_module, tc)
{
	struct authn		 a;
	struct resp		 r;
	const ucl_object_t	*jail, *n, *e;
	char			 etag[128], hdr[192];
	bool			 found;
	ucl_object_iter_t	 it;

	start(tc, 0, NULL);
	http("GET", "/yang/arcana-jails@2026-10-14.json", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	enrol(&a);
	http("GET", "/yang/arcana-jails@2026-10-14.json", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(r.json != NULL);
	ATF_CHECK_STREQ("arcana-jails", ym_str(r.json, "name"));
	ATF_CHECK_STREQ("urn:arcana:yang:arcana-jails", ym_str(r.json,
	    "namespace"));
	ATF_CHECK(ym_str(r.json, "description") != NULL &&
	    strstr(ym_str(r.json, "description"), "jail.conf(5)") != NULL);
	jail = ym_node(ucl_object_lookup(r.json, "nodes"),
	    "/arcana-jails:jails/jail");
	ATF_REQUIRE_MSG(jail != NULL, "no jail list: %.300s", r.body);
	ATF_CHECK_STREQ("list", ym_str(jail, "kind"));
	ATF_CHECK_STREQ("true", ym_str(jail, "config"));
	ATF_CHECK_STREQ("name", ym_str(jail, "keys.0"));
	/* Its key first among its children. */
	ATF_CHECK_STREQ("name", ym_str(jail, "children.0.name"));
	n = ym_node(ucl_object_lookup(jail, "children"),
	    "/arcana-jails:jails/jail/boot");
	ATF_CHECK_STREQ("boolean", ym_str(n, "type.base"));
	ATF_CHECK(ym_str(n, "description") != NULL);
	n = ym_node(ucl_object_lookup(jail, "children"),
	    "/arcana-jails:jails/jail/param/value");
	ATF_CHECK_STREQ("leaf-list", ym_str(n, "kind"));
	ATF_CHECK_STREQ("string", ym_str(n, "type.base"));
	/* State as config false; an enumeration's values, its typedef. */
	n = ym_node(ucl_object_lookup(jail, "children"),
	    "/arcana-jails:jails/jail/state");
	ATF_CHECK_STREQ("false", ym_str(n, "config"));
	ATF_CHECK_STREQ("enumeration", ym_str(n, "type.base"));
	ATF_CHECK_STREQ("jail-state", ym_str(n, "typedef"));
	found = false;
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup_path(n, "type.enum"),
	    &it, true)) != NULL)
		if (strcmp(ym_str(e, "name"), "stopped") == 0 &&
		    strcmp(ym_str(e, "value"), "1") == 0 &&
		    ym_str(e, "description") != NULL)
			found = true;
	ATF_CHECK_MSG(found, "no enum stopped = 1");
	/* An action and its input; its output left out. */
	n = ym_node(ucl_object_lookup(jail, "children"),
	    "/arcana-jails:jails/jail/start");
	ATF_CHECK_STREQ("action", ym_str(n, "kind"));
	ATF_CHECK(ym_node(ucl_object_lookup(jail, "children"),
	    "/arcana-jails:jails/jail/start/output") == NULL);
	/* A leafref's path and target. */
	n = ym_node(ucl_object_lookup(jail, "children"),
	    "/arcana-jails:jails/jail/lne");
	ATF_CHECK(ym_str(n, "type.leafref.path") != NULL);
	ATF_CHECK_STREQ("/ietf-logical-network-element:logical-network-"
	    "elements/logical-network-element/name", ym_str(n,
	    "type.leafref.target"));
	ATF_REQUIRE(resp_header(&r, "etag", etag, sizeof(etag)) != NULL);
	resp_free(&r);
	/* Asked again with its tag: not modified. */
	snprintf(hdr, sizeof(hdr), "If-None-Match: %s\r\n", etag);
	http_with("GET", "/yang/arcana-jails@2026-10-14.json", hdr, NULL, &r);
	EXPECT(&r, 304);
	resp_free(&r);
	/* Another module. */
	http("GET", "/yang/arcana-network@2026-10-29.json", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("arcana-network", ym_str(r.json, "name"));
	resp_free(&r);
	/* Another revision than the console's, a module it has not. */
	http("GET", "/yang/arcana-jails@2020-01-01.json", NULL, &r);
	EXPECT(&r, 404);
	ATF_CHECK(strstr(r.body, "2026-10-14") != NULL);
	resp_free(&r);
	http("GET", "/yang/no-such-module@2020-01-01.json", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
}

ATF_TP_ADD_TCS(tp)
{
	/* The longest first: kyua starts them in this order. */
	ATF_TP_ADD_TC(tp, sdwan_apply_rollback);
	ATF_TP_ADD_TC(tp, sdwan_apply_fresh);
	ATF_TP_ADD_TC(tp, troubleshoot_hang);
	ATF_TP_ADD_TC(tp, sdwan_apply_identities);
	ATF_TP_ADD_TC(tp, notify_cooldown_again);
	ATF_TP_ADD_TC(tp, sdwan_apply_security);
	ATF_TP_ADD_TC(tp, sdwan_uswe_rekey);
	ATF_TP_ADD_TC(tp, sdwan_apply_steer);
	ATF_TP_ADD_TC(tp, notify_cooldown_held);
	ATF_TP_ADD_TC(tp, feeds_operator);
	ATF_TP_ADD_TC(tp, mtls_sctp);
	ATF_TP_ADD_TC(tp, sdwan_apply_change);
	ATF_TP_ADD_TC(tp, sdwan_apply);
	ATF_TP_ADD_TC(tp, feeds_local);
	ATF_TP_ADD_TC(tp, sdwan_uswe);
	ATF_TP_ADD_TC(tp, feeds_alarm);
	ATF_TP_ADD_TC(tp, feeds_redirect);
	ATF_TP_ADD_TC(tp, sdwan_list_urls);
	ATF_TP_ADD_TC(tp, notify_cooldown_mute);
	ATF_TP_ADD_TC(tp, workflows_every);
	ATF_TP_ADD_TC(tp, fleet_stream_rejoin);
	ATF_TP_ADD_TC(tp, workflows_events);
	ATF_TP_ADD_TC(tp, notify_cooldown_sessions);
	ATF_TP_ADD_TC(tp, cluster);
	ATF_TP_ADD_TC(tp, mtls);
	ATF_TP_ADD_TC(tp, mtls_move);
	ATF_TP_ADD_TC(tp, fleet_stream_removed);
	ATF_TP_ADD_TC(tp, workflows_arcana);
	ATF_TP_ADD_TC(tp, feeds);
	ATF_TP_ADD_TC(tp, telegram_job);
	ATF_TP_ADD_TC(tp, workflows);
	ATF_TP_ADD_TC(tp, troubleshoot);
	ATF_TP_ADD_TC(tp, sdwan_apply_plan);
	ATF_TP_ADD_TC(tp, sdwan_vpn_pm);
	ATF_TP_ADD_TC(tp, telegram);
	ATF_TP_ADD_TC(tp, telegram_workflow);
	ATF_TP_ADD_TC(tp, cluster_catchup);

	ATF_TP_ADD_TC(tp, watch_nacm);
	ATF_TP_ADD_TC(tp, notif_receiver);
	ATF_TP_ADD_TC(tp, notif_token);
	ATF_TP_ADD_TC(tp, watch_reconnect);
	ATF_TP_ADD_TC(tp, watch_held);
	ATF_TP_ADD_TC(tp, watch_events);

	ATF_TP_ADD_TC(tp, unauthenticated);
	ATF_TP_ADD_TC(tp, setup_token);
	ATF_TP_ADD_TC(tp, setup_password);
	ATF_TP_ADD_TC(tp, register_login);
	ATF_TP_ADD_TC(tp, login_refused);
	ATF_TP_ADD_TC(tp, android);
	ATF_TP_ADD_TC(tp, android_none);
	ATF_TP_ADD_TC(tp, second_key);
	ATF_TP_ADD_TC(tp, users);
	ATF_TP_ADD_TC(tp, csrf);
	ATF_TP_ADD_TC(tp, console_plugins);
	ATF_TP_ADD_TC(tp, jails);
	ATF_TP_ADD_TC(tp, restconf);
	ATF_TP_ADD_TC(tp, restconf_write);
	ATF_TP_ADD_TC(tp, restconf_ra);
	ATF_TP_ADD_TC(tp, restconf_boot);
	ATF_TP_ADD_TC(tp, restconf_mount);
	ATF_TP_ADD_TC(tp, restconf_cbor);
	ATF_TP_ADD_TC(tp, restconf_edit);
	ATF_TP_ADD_TC(tp, restconf_yang_patch);
	ATF_TP_ADD_TC(tp, restconf_etag);
	ATF_TP_ADD_TC(tp, restconf_tag_access_denied);
	ATF_TP_ADD_TC(tp, restconf_tag_invalid_value);
	ATF_TP_ADD_TC(tp, restconf_tag_operation_not_supported);
	ATF_TP_ADD_TC(tp, restconf_tag_operation_failed);
	ATF_TP_ADD_TC(tp, restconf_tag_in_use);
	ATF_TP_ADD_TC(tp, restconf_tag_data_exists);
	ATF_TP_ADD_TC(tp, restconf_tag_data_missing);
	ATF_TP_ADD_TC(tp, restconf_tag_missing_attribute);
	ATF_TP_ADD_TC(tp, restconf_tag_bad_attribute);
	ATF_TP_ADD_TC(tp, restconf_tag_unknown_element);
	ATF_TP_ADD_TC(tp, restconf_tag_unknown_namespace);
	ATF_TP_ADD_TC(tp, restconf_tag_bad_element);
	ATF_TP_ADD_TC(tp, restconf_tag_malformed_message);
	ATF_TP_ADD_TC(tp, l3nm);
	ATF_TP_ADD_TC(tp, l3nm_sdwan);
	ATF_TP_ADD_TC(tp, l3nm_mef);
	ATF_TP_ADD_TC(tp, l3nm_vn);
	ATF_TP_ADD_TC(tp, l3nm_vn_tca);
	ATF_TP_ADD_TC(tp, l3nm_vn_compute);
	ATF_TP_ADD_TC(tp, l3nm_vn_compute_asks);
	ATF_TP_ADD_TC(tp, cyang_settings);
	ATF_TP_ADD_TC(tp, cyang_tokens);
	ATF_TP_ADD_TC(tp, cyang_users);
	ATF_TP_ADD_TC(tp, cyang_enrolment);
	ATF_TP_ADD_TC(tp, cyang_workflows);
	ATF_TP_ADD_TC(tp, cyang_templates);
	ATF_TP_ADD_TC(tp, cyang_labels);
	ATF_TP_ADD_TC(tp, cyang_pfxlists);
	ATF_TP_ADD_TC(tp, cyang_transfers);
	ATF_TP_ADD_TC(tp, authz_scope);
	ATF_TP_ADD_TC(tp, cyang_push);
	ATF_TP_ADD_TC(tp, cyang_settings_actions);
	ATF_TP_ADD_TC(tp, cyang_feeds);
	ATF_TP_ADD_TC(tp, nacm_user);
	ATF_TP_ADD_TC(tp, nacm_sync);
	ATF_TP_ADD_TC(tp, server_readdress);
	ATF_TP_ADD_TC(tp, nacm_console);
	ATF_TP_ADD_TC(tp, job_user);
	ATF_TP_ADD_TC(tp, services);
	ATF_TP_ADD_TC(tp, agent_update);
	ATF_TP_ADD_TC(tp, agent_build);
	ATF_TP_ADD_TC(tp, update_notes);
	ATF_TP_ADD_TC(tp, smtpd);
	ATF_TP_ADD_TC(tp, speeder);
	ATF_TP_ADD_TC(tp, monitors);
	ATF_TP_ADD_TC(tp, settings);
	ATF_TP_ADD_TC(tp, mail);
	ATF_TP_ADD_TC(tp, sampling_switch);
	ATF_TP_ADD_TC(tp, sampling_old);
	ATF_TP_ADD_TC(tp, local_agent);
	ATF_TP_ADD_TC(tp, local_same);
	ATF_TP_ADD_TC(tp, local_absent);
	ATF_TP_ADD_TC(tp, push);
	ATF_TP_ADD_TC(tp, tokens);
	ATF_TP_ADD_TC(tp, transfers);
	ATF_TP_ADD_TC(tp, config_bundle);
	ATF_TP_ADD_TC(tp, templates);
	ATF_TP_ADD_TC(tp, pfxlists);
	ATF_TP_ADD_TC(tp, labels);
	ATF_TP_ADD_TC(tp, password);
	ATF_TP_ADD_TC(tp, ldap);
	ATF_TP_ADD_TC(tp, workflow_approval);
	ATF_TP_ADD_TC(tp, sdwan);
	ATF_TP_ADD_TC(tp, sdwan_mesh);
	ATF_TP_ADD_TC(tp, sdwan_host);
	ATF_TP_ADD_TC(tp, sdwan_loop);
	ATF_TP_ADD_TC(tp, l3nm_plan);
	ATF_TP_ADD_TC(tp, sdwan_infeasible);
	ATF_TP_ADD_TC(tp, sdwan_breakout);
	ATF_TP_ADD_TC(tp, sdwan_nat64);
	ATF_TP_ADD_TC(tp, sdwan_sets);
	ATF_TP_ADD_TC(tp, sdwan_neigh);
	ATF_TP_ADD_TC(tp, sdwan_lists);
	ATF_TP_ADD_TC(tp, sdwan_notices);
	ATF_TP_ADD_TC(tp, sdwan_sfp);
	ATF_TP_ADD_TC(tp, sdwan_jail);
	ATF_TP_ADD_TC(tp, sdwan_lab);
	ATF_TP_ADD_TC(tp, sdwan_l3nm_lab);
	ATF_TP_ADD_TC(tp, load);
	ATF_TP_ADD_TC(tp, churn);
	ATF_TP_ADD_TC(tp, session_restart);
	ATF_TP_ADD_TC(tp, unreachable);
	ATF_TP_ADD_TC(tp, agent_update_bridge);
	ATF_TP_ADD_TC(tp, restconf_revisions);
	ATF_TP_ADD_TC(tp, restconf_actions);
	ATF_TP_ADD_TC(tp, restconf_actions_old);
	ATF_TP_ADD_TC(tp, stream_restconf);
	ATF_TP_ADD_TC(tp, restconf_job_confirm);
	ATF_TP_ADD_TC(tp, restconf_jobs_safe_wait);
	ATF_TP_ADD_TC(tp, sapnet);
	ATF_TP_ADD_TC(tp, sapnet_attach);
	ATF_TP_ADD_TC(tp, enrol);
	ATF_TP_ADD_TC(tp, tls_ec);
	ATF_TP_ADD_TC(tp, cyang_hosts);
	ATF_TP_ADD_TC(tp, cyang_host_verbs);
	ATF_TP_ADD_TC(tp, cyang_dataset_key);
	ATF_TP_ADD_TC(tp, cyang_sdwan);
	ATF_TP_ADD_TC(tp, cyang_console);
	ATF_TP_ADD_TC(tp, cyang_plugins);
	ATF_TP_ADD_TC(tp, yang_module);
	return (atf_no_error());
}
