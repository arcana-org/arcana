/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * WebAuthn for one user, and sessions.
 *
 * Browsers hand over the credential's public key as SubjectPublicKeyInfo
 * (getPublicKey()) and the authenticator data as bytes
 * (getAuthenticatorData()), so nothing here decodes CBOR: libcrypto
 * parses the key and checks signatures.  With attestation "none" there is
 * no attestation statement to verify; the one-time setup token is what
 * makes the first registration trustworthy.  The console may also be set
 * up by a password (api_setup_password): the setup token, an owner's
 * name and their password, for a browser no key reaches.  It is set up
 * once a key is registered or a user has a password (setup_done()).
 *
 * The server runs the console in one worker, so the sessions live in
 * that process, and each in a document of its own, so that a restart
 * keeps them; a challenge lives nowhere, what it is for said in it
 * under the console's MAC.
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/stat.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "console.h"

#define	CREDENTIALS	"credentials.json"
#define	SETUP_TOKEN	"setup-token"

/* Authenticator data flags. */
#define	AD_UP		0x01	/* user present */
#define	AD_UV		0x04	/* user verified */
#define	AD_AT		0x40	/* attested credential data included */

#define	COSE_ES256	-7
#define	COSE_EDDSA	-8
#define	COSE_RS256	-257

/* A challenge used: SHA-256 of its value, until it would end. */
struct used {
	uint8_t		hash[32];
	time_t		expires;
};

struct session {
	uint8_t		hash[32];	/* SHA-256 of the cookie value */
	time_t		created;
	time_t		last;
	bool		used;
	char		who[65];	/* the key it was opened with, its name */
	char		cred[65];	/* SHA-256 of that key's id, hex; ""
					 * opened by none */
	char		tok[17];	/* the API token it was, its id; "" a key */
	bool		ldap;		/* opened by a directory's user */
	bool		pw;		/* ... by the console's own password */
	char		user[USER_NAME_LEN];	/* the console user (users.c);
						 * "" none */
	char		uid[USER_ID_LEN];	/* its id; "": one opened before
						 * ids */
	time_t		written;	/* last as its document has it */
};

static ucl_object_t	*creds;		/* the credentials document */
static char		 setup_token[65];
static char		 last_user[USER_NAME_LEN];	/* of the session just started: its
					 * cookie is not on the request yet */

/*
 * Challenges are not kept, a login's nor a registration's.  Anyone may
 * ask for a login's, and one kept for each asker would let whoever
 * asks most push the others' out; a registration's kept once for all
 * would let one ceremony end another's.  A challenge says when it ends
 * and what it is for (a registration: whose key, how, by which
 * invitation), with a MAC of the console's over all of it; it is noted
 * once used, to be used once, and only once its ceremony succeeded,
 * so that none but one who may can fill the notes.
 */
#define	USED_CHALS	1024
#define	CHAL_MAX	192		/* a challenge's text, with its NUL */
static uint8_t		 chal_key[32];
static bool		 chal_keyed;
static struct used	 used_chals[USED_CHALS];

/* What a registration's challenge carries. */
#define	REG_SESSION	1	/* a signed-in user's key, or the owner's for
				 * another */
#define	REG_SETUP	2	/* the first key, by the setup token */
#define	REG_INVITE	3	/* an invited user's, by the invitation */
struct regchal {
	uint8_t		mode;
	uint8_t		inv[32];	/* REG_INVITE: its SHA-256 */
	char		user[65];	/* whose key */
};
#define	REG_CARRY	(1 + 32 + 64)
/*
 * The sessions, as many as are open, SESSIONS_MAX at most: a user (or
 * a token) has SESSIONS_USER of them, their own oldest ending when
 * they open another, so that no one signing in again and again ends
 * anyone else's; the least recently used of all only when the users
 * together fill the table.
 */
static struct session	**sessions;
static int		 nsessions;
static uint64_t		 session_gen;	/* one more at each session's end */
static time_t		 sessions_saved;	/* when the file was last written */

static char	*b64url(const void *, size_t);
static bool	 origin_ours(const char *);
static uint8_t	*unb64url(const char *, size_t *);
static void	 sha256(const void *, size_t, uint8_t *);
static const char *check_client_data(const uint8_t *, size_t, const char *,
		    char *, size_t);
static const char *check_auth_data(const uint8_t *, size_t, uint8_t *,
		    uint32_t *);
static bool	 verify_sig(int, const uint8_t *, size_t, const uint8_t *,
		    size_t, const uint8_t *, size_t);
static bool	 key_matches(int, const uint8_t *, size_t);
static ucl_object_t *cred_list(void);
static const ucl_object_t *cred_find(const char *);
static struct session *session_start(struct http_request *, const char *,
		    const char *, const char *, const char *);
static void	 sessions_save(void);
static void	 sessions_load(void);
static void	 session_put(struct session *);
static void	 session_end(struct session *);
static bool	 cred_alive(const char *);
static void	 setup_token_init(void);
static bool	 setup_done(void);
static bool	 setup_token_ok(const char *);
static void	 put(ucl_object_t *, const char *, ucl_object_t *);
static int	 status_reply(struct http_request *, bool);

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

/* base64url without padding; the caller frees with free(). */
static char *
b64url(const void *data, size_t len)
{
	char	*out;

	if (!b64url_encode(data, len, &out, B64_RAW))
		return (NULL);
	return (out);
}

/* base64url, padded or not. */
static uint8_t *
unb64url(const char *s, size_t *lenp)
{
	uint8_t	*out;

	if (s == NULL || *s == '\0' || !b64url_decode(s, &out, lenp, B64_RAW))
		return (NULL);
	return (out);
}

static void
sha256(const void *data, size_t len, uint8_t *md)
{
	unsigned int	mdlen;

	EVP_Digest(data, len, md, &mdlen, EVP_sha256(), NULL);
}

/*
 * A challenge: 12 random bytes, when it ends, what it carries (wlen
 * bytes of what), and the console's MAC over them, base64url into out.
 */
static void
chal_make(const uint8_t *what, size_t wlen, char *out, size_t len)
{
	uint8_t		 raw[16 + REG_CARRY + 16], mac[32];
	unsigned int	 n;
	char		*s;

	if (!chal_keyed) {
		arc4random_buf(chal_key, sizeof(chal_key));
		chal_keyed = true;
	}
	arc4random_buf(raw, 12);
	be32enc(raw + 12, (uint32_t)(time(NULL) + CHALLENGE_TTL));
	if (wlen > 0)
		memcpy(raw + 16, what, wlen);
	HMAC(EVP_sha256(), chal_key, sizeof(chal_key), raw, 16 + wlen, mac,
	    &n);
	memcpy(raw + 16 + wlen, mac, 16);
	s = b64url(raw, 16 + wlen + 16);
	strlcpy(out, s, len);
	free(s);
}

/*
 * Is value a challenge of ours, in time, carrying wlen bytes (into
 * what), and not used yet?  When it ends into *expp.
 */
static bool
chal_check(const char *value, uint8_t *what, size_t wlen, time_t *expp)
{
	uint8_t		*raw, mac[32], h[32];
	size_t		 len;
	unsigned int	 n;
	time_t		 now;
	int		 i;
	bool		 ok;

	if (!chal_keyed || strlen(value) >= CHAL_MAX ||
	    (raw = unb64url(value, &len)) == NULL)
		return (false);
	ok = len == 16 + wlen + 16;
	if (ok) {
		HMAC(EVP_sha256(), chal_key, sizeof(chal_key), raw, 16 + wlen,
		    mac, &n);
		ok = CRYPTO_memcmp(mac, raw + 16 + wlen, 16) == 0;
	}
	now = time(NULL);
	*expp = ok ? (time_t)be32dec(raw + 12) : 0;
	if (ok && wlen > 0)
		memcpy(what, raw + 16, wlen);
	free(raw);
	if (!ok || now > *expp)
		return (false);
	sha256(value, strlen(value), h);
	for (i = 0; i < USED_CHALS; i++)
		if (used_chals[i].expires >= now && memcmp(used_chals[i].hash,
		    h, sizeof(h)) == 0)
			return (false);
	return (true);
}

/* value noted used, until it would have ended: false when it was. */
static bool
chal_use(const char *value, time_t expires)
{
	struct used	*slot;
	uint8_t		 h[32];
	time_t		 now;
	int		 i;

	now = time(NULL);
	sha256(value, strlen(value), h);
	slot = &used_chals[0];
	for (i = 0; i < USED_CHALS; i++) {
		if (used_chals[i].expires >= now && memcmp(used_chals[i].hash,
		    h, sizeof(h)) == 0)
			return (false);
		if (used_chals[i].expires < slot->expires)
			slot = &used_chals[i];
	}
	memcpy(slot->hash, h, sizeof(h));
	slot->expires = expires;
	return (true);
}

/* A registration's challenge for rc, into out. */
static void
reg_challenge(const struct regchal *rc, char *out, size_t len)
{
	uint8_t	what[REG_CARRY];

	memset(what, 0, sizeof(what));
	what[0] = rc->mode;
	memcpy(what + 1, rc->inv, sizeof(rc->inv));
	memcpy(what + 33, rc->user, strnlen(rc->user, 64));
	chal_make(what, sizeof(what), out, len);
}

/* Is value a registration's challenge of ours: what it carries into
 * rc, when it ends into *expp. */
static bool
reg_challenge_read(const char *value, struct regchal *rc, time_t *expp)
{
	uint8_t	what[REG_CARRY];

	if (!chal_check(value, what, sizeof(what), expp))
		return (false);
	memset(rc, 0, sizeof(*rc));
	rc->mode = what[0];
	memcpy(rc->inv, what + 1, sizeof(rc->inv));
	memcpy(rc->user, what + 33, 64);
	rc->user[64] = '\0';
	return (rc->mode >= REG_SESSION && rc->mode <= REG_INVITE &&
	    rc->user[0] != '\0');
}

/*
 * The console's origin, or the Android app's named in web.conf: a
 * credential made or used in the app comes with the origin
 * android:apk-key-hash:<base64url of its signing certificate's SHA-256>.
 */
static bool
origin_ours(const char *origin)
{
	static const char	 pfx[] = "android:apk-key-hash:";
	char			*h;
	bool			 ok;
	int			 i;

	if (strcmp(origin, cfg.origin) == 0 || cluster_origin(origin))
		return (true);
	if (strncmp(origin, pfx, sizeof(pfx) - 1) != 0)
		return (false);
	ok = false;
	for (i = 0; !ok && i < cfg.nandroid_keys; i++) {
		h = b64url(cfg.android_keys[i], sizeof(cfg.android_keys[i]));
		ok = h != NULL && strcmp(origin + sizeof(pfx) - 1, h) == 0;
		free(h);
	}
	return (ok);
}

/*
 * clientDataJSON must be of the expected type, for the challenge we
 * issued, from our origin.  Returns NULL or what is wrong.
 */
static const char *
check_client_data(const uint8_t *cd, size_t len, const char *type,
    char *chal, size_t chlen)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	const char		*s, *err;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = NULL;
	if (ucl_parser_add_chunk(p, cd, len))
		o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	if (o == NULL)
		return ("clientDataJSON is not JSON");
	err = NULL;
	if ((s = ucl_str(o, "type")) == NULL || strcmp(s, type) != 0)
		err = "wrong clientData type";
	else if ((s = ucl_str(o, "challenge")) == NULL || strlcpy(chal, s,
	    chlen) >= chlen)
		err = "unknown or expired challenge";
	else if ((s = ucl_str(o, "origin")) == NULL || !origin_ours(s))
		err = "wrong origin";
	else if (ucl_flag(o, "crossOrigin"))
		err = "cross-origin request";
	ucl_object_unref(o);
	return (err);
}

/*
 * Authenticator data: the RP ID hash must be ours and the user present.
 * Returns NULL or what is wrong; *flags and *count are filled in.
 */
static const char *
check_auth_data(const uint8_t *ad, size_t len, uint8_t *flags,
    uint32_t *count)
{
	uint8_t	rpid[32];

	if (len < 37)
		return ("authenticator data too short");
	sha256(cfg.rp_id, strlen(cfg.rp_id), rpid);
	if (memcmp(ad, rpid, sizeof(rpid)) != 0)
		return ("authenticator data for another relying party");
	*flags = ad[32];
	*count = (uint32_t)ad[33] << 24 | (uint32_t)ad[34] << 16 |
	    (uint32_t)ad[35] << 8 | ad[36];
	if ((*flags & AD_UP) == 0)
		return ("user not present");
	return (NULL);
}

/* Is the SubjectPublicKeyInfo a key of the COSE algorithm's type? */
static bool
key_matches(int alg, const uint8_t *spki, size_t len)
{
	const uint8_t	*p;
	EVP_PKEY	*pk;
	char		 group[64];
	size_t		 glen;
	bool		 ok;

	p = spki;
	if ((pk = d2i_PUBKEY(NULL, &p, (long)len)) == NULL)
		return (false);
	switch (alg) {
	case COSE_ES256:
		ok = EVP_PKEY_get_base_id(pk) == EVP_PKEY_EC &&
		    EVP_PKEY_get_group_name(pk, group, sizeof(group),
		    &glen) == 1 && strcmp(group, "prime256v1") == 0;
		break;
	case COSE_EDDSA:
		ok = EVP_PKEY_get_base_id(pk) == EVP_PKEY_ED25519;
		break;
	case COSE_RS256:
		ok = EVP_PKEY_get_base_id(pk) == EVP_PKEY_RSA &&
		    EVP_PKEY_get_bits(pk) >= 2048;
		break;
	default:
		ok = false;
		break;
	}
	EVP_PKEY_free(pk);
	return (ok);
}

static bool
verify_sig(int alg, const uint8_t *spki, size_t spkilen, const uint8_t *msg,
    size_t msglen, const uint8_t *sig, size_t siglen)
{
	const uint8_t	*p;
	EVP_PKEY	*pk;
	EVP_MD_CTX	*ctx;
	bool		 ok;

	if (!key_matches(alg, spki, spkilen))
		return (false);
	p = spki;
	if ((pk = d2i_PUBKEY(NULL, &p, (long)spkilen)) == NULL)
		return (false);
	ctx = EVP_MD_CTX_new();
	ok = ctx != NULL && EVP_DigestVerifyInit(ctx, NULL,
	    alg == COSE_EDDSA ? NULL : EVP_sha256(), NULL, pk) == 1 &&
	    EVP_DigestVerify(ctx, sig, siglen, msg, msglen) == 1;
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pk);
	return (ok);
}

/* credentials.json kept; arcana-console's credentials changed. */
static int
creds_save(void)
{
	int	rc;

	rc = store_save(CREDENTIALS, creds);
	cyang_changed("credentials");
	return (rc);
}

static ucl_object_t *
cred_list(void)
{
	const ucl_object_t	*a;

	a = ucl_object_lookup(creds, "credentials");
	return ((ucl_object_t *)(uintptr_t)a);
}

static const ucl_object_t *
cred_find(const char *id)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it;
	const char		*s;

	it = NULL;
	while ((c = ucl_object_iterate(cred_list(), &it, true)) != NULL)
		if ((s = ucl_str(c, "id")) != NULL && strcmp(s, id) == 0)
			return (c);
	return (NULL);
}

/*
 * Set up: a key registered, or a user with a password of the console's;
 * in a cluster, also once the log has a setup that spent its token,
 * before this node has read what it wrote.
 */
static bool
setup_done(void)
{
#ifdef ARCANA_CLUSTER
	uint8_t	h[32];
	char	node[64];

	if (cluster_on() && cluster_setup_state(h, node, sizeof(node)) ==
	    CLUSTER_SETUP_DONE)
		return (true);
#endif
	return (ucl_array_size(cred_list()) > 0 || users_any_password());
}

/*
 * Is token the setup token?  None once the console is set up.  A
 * cluster's is the one whose SHA-256 its log has, on every node.
 */
static bool
setup_token_ok(const char *token)
{
#ifdef ARCANA_CLUSTER
	uint8_t	h[32], mine[32];
	char	node[64];

	if (cluster_on()) {
		if (token == NULL || strlen(token) != 64 || cluster_setup_state(h,
		    node, sizeof(node)) != CLUSTER_SETUP_TOKEN)
			return (false);
		sha256(token, 64, mine);
		return (timingsafe_bcmp(h, mine, sizeof(h)) == 0);
	}
#endif
	return (token != NULL && setup_token[0] != '\0' && strlen(token) ==
	    strlen(setup_token) && timingsafe_bcmp(token, setup_token,
	    strlen(setup_token)) == 0);
}

/* Where the setup token is, for one who asks for it: this console's
 * setup-token, or in a cluster the leader's that made it. */
static void
setup_token_where(char *buf, size_t len)
{
#ifdef ARCANA_CLUSTER
	uint8_t	h[32];
	char	node[64];

	if (cluster_on() && cluster_setup_state(h, node, sizeof(node)) ==
	    CLUSTER_SETUP_TOKEN) {
		snprintf(buf, len, "%s/%s on node %s of the cluster",
		    cfg.datadir, SETUP_TOKEN, node);
		return;
	}
#endif
	snprintf(buf, len, "%s/%s", cfg.datadir, SETUP_TOKEN);
}

/*
 * No setup token to check one against: a cluster's node, the console not
 * set up, before its leader made one (none is made here instead); why.
 */
static bool
setup_token_none(char *why, size_t len)
{
#ifdef ARCANA_CLUSTER
	uint8_t	h[32];
	char	node[64];

	if (cluster_on() && cluster_setup_state(h, node, sizeof(node)) ==
	    CLUSTER_SETUP_NONE) {
		if (node[0] == '\0')
			snprintf(why, len, "this node of the cluster has no "
			    "leader, and the setup token is the leader's to "
			    "make: there is none until one is elected");
		else
			snprintf(why, len, "the leader of the cluster, %s, has "
			    "not made the setup token yet: ask again in a "
			    "moment", node);
		return (true);
	}
#endif
	(void)why;
	(void)len;
	return (false);
}

/* setup_token written to path, whole or not at all: whoever reads it never
 * finds it empty.  Where only the console's user can read it. */
static int
setup_token_write(const char *path)
{
	char	tmp[MAXPATHLEN];
	int	fd;

	snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path);
	if ((fd = mkstemp(tmp)) == -1) {
		log_msg(LOG_ERR, "%s: %s", path, strerror(errno));
		return (-1);
	}
	if (fchmod(fd, 0600) == -1 || dprintf(fd, "%s\n", setup_token) < 0) {
		log_msg(LOG_ERR, "%s: %s", path, strerror(errno));
		(void)close(fd);
		(void)unlink(tmp);
		return (-1);
	}
	if (close(fd) == -1 || rename(tmp, path) == -1) {
		log_msg(LOG_ERR, "%s: %s", path, strerror(errno));
		(void)unlink(tmp);
		return (-1);
	}
	return (0);
}

/* setup_token as path has it, when it is one: else "". */
static void
setup_token_read(const char *path)
{
	FILE	*fp;

	setup_token[0] = '\0';
	if ((fp = fopen(path, "r")) == NULL)
		return;
	if (fgets(setup_token, sizeof(setup_token), fp) == NULL)
		setup_token[0] = '\0';
	fclose(fp);
	setup_token[strcspn(setup_token, "\n")] = '\0';
	if (strlen(setup_token) != 64)
		explicit_bzero(setup_token, sizeof(setup_token));
}

#ifdef ARCANA_CLUSTER
/*
 * A cluster's setup token is its leader's: made by the node that leads,
 * on its lease and once it knows the writes before its term
 * (cluster_leads()), its SHA-256 through the log (cluster_setup_make()),
 * its text in that node's setup-token alone.  Another node never makes
 * one; one whose text the log no longer has (the leader changed, or the
 * console was set up) takes its file away.  On the worker's tick.
 */
static void
setup_token_cluster(void)
{
	uint8_t	 raw[32], h[32], mine[32];
	char	 path[MAXPATHLEN], node[64], why[256];
	int	 st, i;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, SETUP_TOKEN);
	st = cluster_setup_state(h, node, sizeof(node));
	if (st == CLUSTER_SETUP_TOKEN && setup_token[0] != '\0') {
		sha256(setup_token, strlen(setup_token), mine);
		if (strcmp(node, cluster_self()) == 0 && timingsafe_bcmp(h, mine,
		    sizeof(h)) == 0)
			return;
	}
	if (setup_token[0] != '\0' || access(path, F_OK) == 0) {
		explicit_bzero(setup_token, sizeof(setup_token));
		(void)unlink(path);
	}
	if (st == CLUSTER_SETUP_DONE || setup_done() || !cluster_leads())
		return;
	arc4random_buf(raw, sizeof(raw));
	for (i = 0; i < 32; i++)
		snprintf(setup_token + i * 2, 3, "%02x", raw[i]);
	explicit_bzero(raw, sizeof(raw));
	sha256(setup_token, 64, h);
	if (cluster_setup_make(h, why, sizeof(why)) == -1 ||
	    setup_token_write(path) == -1) {
		explicit_bzero(setup_token, sizeof(setup_token));
		return;
	}
	log_msg(LOG_NOTICE, "not set up yet (no security key, no password): "
	    "the setup token of the cluster is in %s", path);
}

/* The worker's tick of a cluster's node. */
void
auth_cluster_tick(void)
{

	setup_token_cluster();
}

/*
 * The cluster's console set up by the setup token of hash: doc, as o is to
 * be, written on every node by the write of the log that spends the
 * token, if it is the first.  0 it was; else 409 another came first (or
 * the token is not the log's), 503 it is not known here which, 500; why.
 */
static int
setup_spend(const uint8_t *hash, const char *doc, const ucl_object_t *o,
    char *why, size_t len)
{
	unsigned char	*json;
	int		 rc;

	if ((json = ucl_object_emit(o, UCL_EMIT_JSON)) == NULL) {
		snprintf(why, len, "out of memory");
		return (500);
	}
	rc = cluster_setup_spend(hash, doc, json, strlen((char *)json), why,
	    len);
	free(json);
	return (rc == 1 ? 0 : rc == 0 ? 409 : 503);
}
#endif

/*
 * Until the console is set up, the first key, or the first password,
 * needs a setup token, written where only the console's user can read
 * it.
 */
static void
setup_token_init(void)
{
	uint8_t	 raw[32];
	char	 path[MAXPATHLEN];
	int	 i;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, SETUP_TOKEN);
#ifdef ARCANA_CLUSTER
	/* A cluster's is the leader's: what this node made before it
	 * stopped is read, and kept only while the log has it. */
	if (cluster_on()) {
		if (setup_token[0] == '\0')
			setup_token_read(path);
		setup_token_cluster();
		return;
	}
#endif
	if (setup_done()) {
		setup_token[0] = '\0';
		(void)unlink(path);
		return;
	}
	setup_token_read(path);
	if (setup_token[0] != '\0')
		return;
	arc4random_buf(raw, sizeof(raw));
	for (i = 0; i < 32; i++)
		snprintf(setup_token + i * 2, 3, "%02x", raw[i]);
	if (setup_token_write(path) == -1)
		return;
	log_msg(LOG_NOTICE, "not set up yet (no security key, no password): "
	    "the setup token is in %s", path);
}

/* A store of the cluster's written by another node: read again. */
void
auth_reload(const char *name)
{

	if (name == NULL || strcmp(name, CREDENTIALS) == 0) {
		ucl_object_t	*was;
		static const char *const kept[] = { "user_id", "decoy_key" };
		size_t		 i;

		was = creds;
		if ((creds = store_load(CREDENTIALS)) == NULL)
			creds = ucl_object_typed_new(UCL_OBJECT);
		/*
		 * None written yet (a cluster's console not set up, its
		 * documents taken from the seed): what auth_init() made of
		 * it stays, for the first key made here.
		 */
		for (i = 0; i < nitems(kept); i++)
			if (ucl_object_lookup(creds, kept[i]) == NULL &&
			    ucl_object_lookup(was, kept[i]) != NULL)
				put(creds, kept[i], ucl_object_copy(
				    ucl_object_lookup(was, kept[i])));
		if (cred_list() == NULL)
			put(creds, "credentials", ucl_object_typed_new(
			    UCL_ARRAY));
		ucl_object_unref(was);
	}
	if (name == NULL || strncmp(name, SESSIONS_DIR "/",
	    sizeof(SESSIONS_DIR)) == 0)
		sessions_load();
}

void
auth_init(void)
{
	uint8_t	 uid[16];
	char	*s;

	if ((creds = store_load(CREDENTIALS)) == NULL)
		creds = ucl_object_typed_new(UCL_OBJECT);
	if (ucl_object_lookup(creds, "user_id") == NULL) {
		arc4random_buf(uid, sizeof(uid));
		s = b64url(uid, sizeof(uid));
		put(creds, "user_id", ucl_object_fromstring(s));
		free(s);
	}
	/* What the sign-in's decoys are made with: kept, so that a name
	 * gets the same ones after a restart, on every node. */
	if (ucl_object_lookup(creds, "decoy_key") == NULL) {
		uint8_t	dk[32];

		arc4random_buf(dk, sizeof(dk));
		s = b64url(dk, sizeof(dk));
		put(creds, "decoy_key", ucl_object_fromstring(s));
		free(s);
		explicit_bzero(dk, sizeof(dk));
		if (cred_list() != NULL && ucl_array_size(cred_list()) > 0)
			(void)creds_save();
	}
	if (cred_list() == NULL)
		put(creds, "credentials", ucl_object_typed_new(UCL_ARRAY));
	sessions_load();
	setup_token_init();
}

/*
 * Each session a document of its own, sessions/<hash>.json, the hash of
 * its cookie with its times: what is on disk does not log anyone in.
 * One document a session, so that two sign-ins at once on two nodes of
 * a cluster write different documents, and an end is the end of its
 * own alone.
 */
static void
session_doc(const struct session *s, char *buf, size_t len)
{
	char	hex[65];
	int	k;

	for (k = 0; k < 32; k++)
		snprintf(hex + 2 * k, 3, "%02x", s->hash[k]);
	snprintf(buf, len, "%s/%s.json", SESSIONS_DIR, hex);
}

static void
session_put(struct session *s)
{
	ucl_object_t	*e;
	char		 name[128], hex[65];
	int		 k;

	for (k = 0; k < 32; k++)
		snprintf(hex + 2 * k, 3, "%02x", s->hash[k]);
	e = ucl_object_typed_new(UCL_OBJECT);
	put(e, "hash", ucl_object_fromstring(hex));
	put(e, "created", ucl_object_fromint(s->created));
	put(e, "last", ucl_object_fromint(s->last));
	put(e, "who", ucl_object_fromstring(s->who));
	if (s->cred[0] != '\0')
		put(e, "cred", ucl_object_fromstring(s->cred));
	if (s->tok[0] != '\0')
		put(e, "token", ucl_object_fromstring(s->tok));
	if (s->ldap)
		put(e, "ldap", ucl_object_frombool(true));
	if (s->pw)
		put(e, "password", ucl_object_frombool(true));
	if (s->user[0] != '\0')
		put(e, "user", ucl_object_fromstring(s->user));
	if (s->uid[0] != '\0')
		put(e, "uid", ucl_object_fromstring(s->uid));
	session_doc(s, name, sizeof(name));
	(void)store_save(name, e);
	ucl_object_unref(e);
	s->written = s->last;
}

/* A session ended: its document taken away, it out of the table and
 * freed. */
static void
session_end(struct session *s)
{
	char	name[128];
	int	i;

	/* Its streams judged again, and closed (sbind_ok()). */
	session_gen++;
	if (s->used) {
		session_doc(s, name, sizeof(name));
		(void)store_remove(name);
	}
	for (i = 0; i < nsessions; i++)
		if (sessions[i] == s) {
			sessions[i] = sessions[--nsessions];
			break;
		}
	explicit_bzero(s, sizeof(*s));
	free(s);
}

/* Every session, ended in memory alone (its document kept). */
static void
sessions_drop(void)
{

	session_gen++;
	while (nsessions > 0) {
		explicit_bzero(sessions[nsessions - 1], sizeof(struct session));
		free(sessions[--nsessions]);
	}
}

/* A new slot, its session's owner's oldest ended when they have
 * SESSIONS_USER, the least recently used when the table is full. */
static struct session *
session_slot(const char *user, const char *tok)
{
	struct session	*s, *mine, *lru;
	int		 i, n;

	mine = lru = NULL;
	n = 0;
	for (i = 0; i < nsessions; i++) {
		s = sessions[i];
		if (lru == NULL || s->last < lru->last)
			lru = s;
		if ((user[0] != '\0' && strcmp(s->user, user) == 0) ||
		    (user[0] == '\0' && tok[0] != '\0' && s->user[0] == '\0' &&
		    strcmp(s->tok, tok) == 0)) {
			n++;
			if (mine == NULL || s->last < mine->last)
				mine = s;
		}
	}
	if (n >= SESSIONS_USER)
		session_end(mine);
	else if (nsessions >= SESSIONS_MAX)
		session_end(lru);
	if (sessions == NULL)
		sessions = xcalloc(SESSIONS_MAX, sizeof(*sessions));
	s = xcalloc(1, sizeof(*s));
	sessions[nsessions++] = s;
	return (s);
}

/* The times of use not written yet, now and then. */
static void
sessions_save(void)
{
	int	i;

	for (i = 0; i < nsessions; i++)
		if (sessions[i]->used && sessions[i]->last !=
		    sessions[i]->written)
			session_put(sessions[i]);
	sessions_saved = time(NULL);
}

/* Those of the documents that have not run out; those that have, gone. */
static void
sessions_load(void)
{
	ucl_object_t		*e;
	DIR			*d;
	struct dirent		*de;
	const char		*hex;
	struct session		*s;
	char			 path[MAXPATHLEN], name[300];
	unsigned int		 b;
	time_t			 now;
	size_t			 len;
	int			 n, k;

	sessions_drop();
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, SESSIONS_DIR);
	if ((d = opendir(path)) == NULL)
		return;
	now = time(NULL);
	n = 0;
	s = NULL;
	while (n < SESSIONS_MAX && (de = readdir(d)) != NULL) {
		len = strlen(de->d_name);
		if (de->d_type != DT_REG || len != 69 || strcmp(de->d_name +
		    64, ".json") != 0)
			continue;
		snprintf(name, sizeof(name), "%s/%s", SESSIONS_DIR, de->d_name);
		if ((e = store_load(name)) == NULL)
			continue;
		if (s == NULL)
			s = xcalloc(1, sizeof(*s));
		else
			memset(s, 0, sizeof(*s));
		hex = ucl_object_lookup(e, "hash") != NULL ?
		    ucl_object_tostring_forced(ucl_object_lookup(e, "hash")) :
		    "";
		for (k = 0; k < 32 && strlen(hex) == 64; k++) {
			if (sscanf(hex + 2 * k, "%2x", &b) != 1)
				break;
			s->hash[k] = (uint8_t)b;
		}
		s->created = ucl_object_toint(ucl_object_lookup(e, "created"));
		s->last = s->written = ucl_object_toint(ucl_object_lookup(e,
		    "last"));
		snprintf(s->who, sizeof(s->who), "%s", ucl_object_lookup(e, "who")
		    != NULL ? ucl_object_tostring_forced(ucl_object_lookup(e,
		    "who")) : "");
		snprintf(s->tok, sizeof(s->tok), "%s", ucl_object_lookup(e,
		    "token") != NULL ? ucl_object_tostring_forced(
		    ucl_object_lookup(e, "token")) : "");
		snprintf(s->cred, sizeof(s->cred), "%s", ucl_str(e, "cred") !=
		    NULL ? ucl_str(e, "cred") : "");
		s->ldap = ucl_object_toboolean(ucl_object_lookup(e, "ldap"));
		s->pw = ucl_object_toboolean(ucl_object_lookup(e, "password"));
		/* A name or an id that does not fit is no one's. */
		if (!name_copy(s->user, sizeof(s->user), ucl_str(e, "user") !=
		    NULL ? ucl_str(e, "user") : "") || !name_copy(s->uid,
		    sizeof(s->uid), ucl_str(e, "uid") != NULL ? ucl_str(e,
		    "uid") : ""))
			s->user[0] = s->tok[0] = '\0';
		ucl_object_unref(e);
		/* One of no one (neither a user's nor a token's) opens
		 * nothing. */
		if (k < 32 || s->created > now || now - s->last >
		    cfg.session_idle || now - s->created > cfg.session_max ||
		    (s->user[0] == '\0' && s->tok[0] == '\0')) {
			(void)store_remove(name);
			continue;
		}
		s->used = true;
		if (sessions == NULL)
			sessions = xcalloc(SESSIONS_MAX, sizeof(*sessions));
		sessions[nsessions++] = s;
		s = NULL;
		n++;
	}
	free(s);
	closedir(d);
}

/* The request's session, valid or not; NULL: none. */
static struct session *
session_of(struct http_request *req)
{
	uint8_t		 h[32];
	char		*cookie;
	int		 i;

	if (!http_request_cookie(req, SESSION_COOKIE, &cookie) ||
	    strlen(cookie) != 64)
		return (NULL);
	sha256(cookie, strlen(cookie), h);
	for (i = 0; i < nsessions; i++)
		if (sessions[i]->used && memcmp(sessions[i]->hash, h,
		    sizeof(h)) == 0)
			return (sessions[i]);
	return (NULL);
}

/*
 * Whether the request's session was opened with an API token: it may
 * then do what the token may, no more (guard()).
 */
bool
session_by_token(struct http_request *req)
{
	struct session	*s;

	/* One opened by the directory's password is limited as a token is:
	 * what changes the console's own sign-in, tokens, users, CA and
	 * settings takes a key; one by the console's own password too,
	 * when web.conf says password_full = false. */
	return ((s = session_of(req)) != NULL && (s->tok[0] != '\0' ||
	    s->ldap || (s->pw && !cfg.password_full)));
}

/*
 * Whether the request's session was opened by a security key: no API
 * token, no password (the console's or the directory's).  What opens a
 * terminal asks it, and what changes mapped logins.
 */
bool
session_by_key(struct http_request *req)
{
	struct session	*s;

	return ((s = session_of(req)) != NULL && s->tok[0] == '\0' &&
	    !s->ldap && !s->pw);
}

/* How the session was opened: by a key, a directory or a password. */
enum by { BY_KEY, BY_LDAP, BY_PASSWORD };

static enum by
session_by(struct http_request *req)
{
	struct session	*s;

	if ((s = session_of(req)) == NULL)
		return (BY_KEY);
	return (s->ldap ? BY_LDAP : s->pw ? BY_PASSWORD : BY_KEY);
}

/*
 * Is s still good: in time, and its token, its key and its user (by
 * name and id: one removed and made again is another) still there, on
 * every node?
 */
static bool
session_alive(const struct session *s, time_t now)
{

	return (now - s->last <= cfg.session_idle && now - s->created <=
	    cfg.session_max && (s->tok[0] == '\0' || token_alive(s->tok)) &&
	    (s->cred[0] == '\0' || cred_alive(s->cred)) && (s->user[0] ==
	    '\0' || (user_exists(s->user) && (s->uid[0] == '\0' ||
	    strcmp(user_id(s->user), s->uid) == 0))));
}

bool
session_valid(struct http_request *req)
{
	struct session	*s;
	time_t		 now;

	now = time(NULL);
	if ((s = session_of(req)) != NULL) {
		/* Its token deleted, its key removed, or its user, the
		 * session it opened ends with it, on every node. */
		if (!session_alive(s, now)) {
			session_end(s);
			return (false);
		}
		s->last = now;
		/* The time of use, written now and then, not at every
		 * request. */
		if (now - sessions_saved >= SESSION_SAVE)
			sessions_save();
		return (true);
	}
	return (false);
}

/*
 * Who a request comes from, for the audit trail (MEF 118.1's who of a
 * Policy Action) and the log: the session's user and their id, and the
 * key that opened it by its id (the first bytes of its hash), its name
 * beside them alone, which any user names as they like; "API token
 * <id> (<name>)" for a write token's; NULL else.
 */
const char *
session_who(struct http_request *req)
{
	static char	 who[256];
	struct session	*s;

	if ((s = session_of(req)) == NULL)
		return (token_who(req));
	if (s->user[0] == '\0' && s->tok[0] != '\0')
		snprintf(who, sizeof(who), "%s", s->who);
	else if (s->cred[0] != '\0')
		snprintf(who, sizeof(who), "user %s %s, key %.16s \"%s\"",
		    s->user, s->uid[0] != '\0' ? s->uid : "-", s->cred,
		    s->who[0] != '\0' ? s->who : "a security key");
	else
		snprintf(who, sizeof(who), "user %s %s, %s", s->user,
		    s->uid[0] != '\0' ? s->uid : "-", s->ldap ? "the directory's "
		    "password" : "a password");
	return (who);
}

/*
 * Whose a thing the request makes is, to be taken by the same alone:
 * the session's user, their id, the key's hash and the token's id, or
 * a bearer token's id; into buf, "" for none.
 */
const char *
session_owner(struct http_request *req, char *buf, size_t len)
{
	struct session		*s;
	struct principal	 p;

	buf[0] = '\0';
	if ((s = session_of(req)) != NULL)
		snprintf(buf, len, "s:%s/%s/%s/%s", s->user, s->uid, s->cred,
		    s->tok);
	else if (token_principal(req, &p))
		snprintf(buf, len, "t:%s", p.name);
	return (buf);
}

/* Who a request comes from, in words (session_who()), into buf. */
const char *
req_who(struct http_request *req, char *buf, size_t len)
{
	const char	*w;

	snprintf(buf, len, "%s", (w = session_who(req)) != NULL ? w : "?");
	return (buf);
}

/*
 * The console user a request's session is of (users.c): NULL for one
 * that carries none, an API token's.
 */
const char *
session_user(struct http_request *req)
{
	struct session	*s;

	if ((s = session_of(req)) == NULL || s->user[0] == '\0')
		return (NULL);
	return (s->user);
}

/*
 * Whom a request acts for: its session's user; the API token that
 * opened its session, or its bearer token; no one else.  Its need the
 * least, a viewer's: what it changes says more where it does.
 */
void
req_principal(struct http_request *req, struct principal *p)
{
	struct session	*s;

	memset(p, 0, sizeof(*p));
	if ((s = session_of(req)) != NULL) {
		/* One opened before ids: its user's id now. */
		if (s->user[0] != '\0' && name_copy(p->name, sizeof(p->name),
		    s->user) && name_copy(p->uid, sizeof(p->uid), s->uid[0] !=
		    '\0' ? s->uid : user_id(s->user)))
			p->kind = P_USER;
		else if (s->user[0] == '\0' && s->tok[0] != '\0' && name_copy(
		    p->name, sizeof(p->name), s->tok))
			p->kind = P_WTOKEN;
		else
			memset(p, 0, sizeof(*p));
	} else
		(void)token_principal(req, p);
	p->need = ROLE_VIEWER;
}

/* The tenant of the request's user, or of its token's maker; "" for
 * none. */
const char *
req_tenant(struct http_request *req)
{
	struct principal	 p;
	const char		*u;

	if ((u = session_user(req)) != NULL)
		return (user_tenant(u));
	req_principal(req, &p);
	return (p.kind == P_RTOKEN || p.kind == P_WTOKEN ? token_tenant(p.name)
	    : "");
}

/* ---- Streams bound to their session ---------------------------------- */

uint64_t
sbind_gen(void)
{

	return (session_gen + acl_generation());
}

/* req's session, or its bearer token, into b, with whom it acts for. */
void
sbind_make(struct http_request *req, struct sbind *b)
{
	struct session	*s;

	memset(b, 0, sizeof(*b));
	req_principal(req, &b->who);
	(void)web_peer(req, b->addr, sizeof(b->addr));
	b->born = time(NULL);
	if ((s = session_of(req)) != NULL)
		memcpy(b->hash, s->hash, sizeof(b->hash));
	else if (b->who.kind == P_RTOKEN || b->who.kind == P_WTOKEN)
		(void)name_copy(b->tok, sizeof(b->tok), b->who.name);
	b->gen = sbind_gen();
	b->until = b->born;	/* judged at its first use */
}

/*
 * On the loop: is what b is bound to still good?  Judged again only
 * when who may do what, or a session, changed since, or its session's
 * end is due: a walk of the sessions then, never at every record.
 * Once dead, dead.
 */
bool
sbind_ok(struct sbind *b)
{
	static const uint8_t	 zero[32];
	struct session		*s;
	time_t			 now;
	int			 i;

	if (b->dead)
		return (false);
	now = time(NULL);
	if (b->gen == sbind_gen() && now < b->until)
		return (true);
	b->gen = sbind_gen();
	if (memcmp(b->hash, zero, sizeof(zero)) == 0) {
		/* A bearer token's: while it is there, a minute at a time. */
		if (b->tok[0] == '\0' || token_kind_of(b->tok) == TOKEN_NONE) {
			b->dead = true;
			return (false);
		}
		b->until = now + 60;
		return (true);
	}
	s = NULL;
	for (i = 0; i < nsessions && s == NULL; i++)
		if (sessions[i]->used && memcmp(sessions[i]->hash, b->hash,
		    sizeof(b->hash)) == 0)
			s = sessions[i];
	if (s == NULL || !session_alive(s, now)) {
		if (s != NULL)
			session_end(s);
		b->dead = true;
		return (false);
	}
	b->until = MIN(s->last + cfg.session_idle, s->created +
	    cfg.session_max) + 1;
	return (true);
}

/* web.h's. */
void
web_principal(struct http_request *req, struct principal *p)
{

	req_principal(req, p);
}

/* web.h's: who a request is, in words (session_who()), and from
 * where (web_peer()). */
void
web_describe(struct http_request *req, char *who, size_t wlen, char *from,
    size_t flen)
{

	snprintf(who, wlen, "%s", session_who(req));
	(void)web_peer(req, from, flen);
}

/* The request's role on host sid (principal_host()). */
enum role
req_host_role(struct http_request *req, const char *sid)
{
	struct principal	p;

	req_principal(req, &p);
	return (principal_host(&p, sid));
}

/*
 * May the request's user do this on the host: a viewer reads, an
 * operator changes, an admin also what admin says (updating, moving,
 * removing it).  Without a reply; host_allowed() sends one.
 */
bool
host_role_ok(struct http_request *req, const char *sid, bool mutate,
    bool admin)
{
	struct principal	p;

	req_principal(req, &p);
	return (principal_may(&p, sid, admin ? ROLE_ADMIN : mutate ?
	    ROLE_OPERATOR : ROLE_VIEWER));
}

bool
host_allowed(struct http_request *req, const char *sid, bool mutate,
    bool admin)
{
	enum role	r;

	if (host_role_ok(req, sid, mutate, admin))
		return (true);
	r = req_host_role(req, sid);
	if (r == ROLE_NONE)
		reply_error(req, 404, "not_found", "no such server");
	else
		reply_error(req, 403, "role", "a %s of this host may not %s "
		    "it", role_name(r), admin ? "administer" : "change");
	return (false);
}

/* The sessions of a user, ended: when the user is removed. */
void
sessions_end_user(const char *user)
{
	int	i;

	for (i = nsessions - 1; i >= 0; i--)
		if (i < nsessions && strcmp(sessions[i]->user, user) == 0)
			session_end(sessions[i]);
}

/* The user's sessions opened by their password: its change ends them. */
void
sessions_end_password(const char *user)
{
	int	i;

	for (i = nsessions - 1; i >= 0; i--)
		if (i < nsessions && sessions[i]->pw && strcmp(
		    sessions[i]->user, user) == 0)
			session_end(sessions[i]);
}

/* The user a key belongs to: the built-in owner's when it says none. */
static const char *
cred_user(const ucl_object_t *c)
{

	return (ucl_str(c, "user") != NULL ? ucl_str(c, "user") : ADMIN_USER);
}

int
cred_count_of(const char *user)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	while ((c = ucl_object_iterate(cred_list(), &it, true)) != NULL)
		if (strcmp(cred_user(c), user) == 0)
			n++;
	return (n);
}

/* A user's keys, gone with the user. */
void
creds_forget_user(const char *user)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it;
	bool			 again;

	do {
		again = false;
		it = NULL;
		while ((c = ucl_object_iterate(cred_list(), &it, true)) != NULL)
			if (strcmp(cred_user(c), user) == 0) {
				ucl_object_unref(ucl_array_delete(cred_list(),
				    (ucl_object_t *)(uintptr_t)c));
				again = true;
				break;
			}
	} while (again);
	(void)creds_save();
}

/* A key's id into hex, its SHA-256: what a session opened by it
 * keeps. */
static void
cred_hash(const char *id, char *hex)
{
	uint8_t	h[32];
	int	k;

	sha256(id, strlen(id), h);
	for (k = 0; k < 32; k++)
		snprintf(hex + 2 * k, 3, "%02x", h[k]);
}

/* Is the key whose id hashes to hex still there? */
static bool
cred_alive(const char *hex)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it = NULL;
	char			 h[65];

	while ((c = ucl_object_iterate(cred_list(), &it, true)) != NULL) {
		if (ucl_str(c, "id") == NULL)
			continue;
		cred_hash(ucl_str(c, "id"), h);
		if (strcmp(h, hex) == 0)
			return (true);
	}
	return (false);
}

/* The sessions opened by the key of id, ended: it was removed. */
static void
sessions_end_cred(const char *id)
{
	char	hex[65];
	int	i;

	cred_hash(id, hex);
	for (i = nsessions - 1; i >= 0; i--)
		if (i < nsessions && strcmp(sessions[i]->cred, hex) == 0)
			session_end(sessions[i]);
}

/* A new session in a cookie only the console can read, opened by the
 * key named who of id cred, or by the API token of id tok, for the
 * console user (NULL or "": none); its slot, for the caller to mark. */
static struct session *
session_start(struct http_request *req, const char *who, const char *cred,
    const char *tok, const char *user)
{
	struct session	*s;
	uint8_t		 raw[32];
	char		 token[65], cookie[256];
	int		 i;

	arc4random_buf(raw, sizeof(raw));
	for (i = 0; i < 32; i++)
		snprintf(token + i * 2, 3, "%02x", raw[i]);
	s = session_slot(user != NULL ? user : "", tok != NULL ? tok : "");
	sha256(token, 64, s->hash);
	s->created = s->last = time(NULL);
	s->used = true;
	snprintf(s->who, sizeof(s->who), "%s", who != NULL ? who : "");
	if (cred != NULL)
		cred_hash(cred, s->cred);
	snprintf(s->tok, sizeof(s->tok), "%s", tok != NULL ? tok : "");
	s->ldap = s->pw = false;
	/* A name that does not fit opens a session of no one, which
	 * guard() refuses; never another user's, cut. */
	if (!name_copy(s->user, sizeof(s->user), user != NULL ? user : "") ||
	    !name_copy(s->uid, sizeof(s->uid), s->user[0] != '\0' ?
	    user_id(s->user) : ""))
		s->user[0] = s->uid[0] = '\0';
	snprintf(last_user, sizeof(last_user), "%s", s->user);
	/* Where from: no threat feed is to cut it off. */
	feeds_signin(req, s->user);
	snprintf(cookie, sizeof(cookie), "%s=%s; Path=/; HttpOnly; "
	    "SameSite=Strict; Max-Age=%d%s", SESSION_COOKIE, token,
	    cfg.session_max, cfg.cookie_secure ? "; Secure" : "");
	http_response_header(req, "set-cookie", cookie);
	explicit_bzero(token, sizeof(token));
	session_put(s);
	return (s);
}

static int
status_reply_as(struct http_request *req, bool authenticated, bool by_token,
    enum by by)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "authenticated", ucl_object_frombool(authenticated));
	/* Opened with an API token, or by a directory's user: the page
	 * does not offer what it may not do. */
	if (authenticated && by_token)
		put(o, "by_token", ucl_object_frombool(true));
	if (authenticated && by == BY_LDAP)
		put(o, "by_ldap", ucl_object_frombool(true));
	if (authenticated && by == BY_PASSWORD)
		put(o, "by_password", ucl_object_frombool(true));
	/* Who, and what they may (users.c): the page offers no more. */
	if (authenticated) {
		const char	*u = session_user(req);
		char		 just[USER_NAME_LEN];

		/* Just signed in: the session's cookie is on its way. */
		if (u == NULL && session_of(req) == NULL && last_user[0] != '\0') {
			snprintf(just, sizeof(just), "%s", last_user);
			u = just;
		}
		last_user[0] = '\0';
		if (u != NULL) {
			put(o, "user", ucl_object_fromstring(u));
			put(o, "console", ucl_object_fromstring(crole_name(
			    user_console(u))));
			if (user_tenant(u)[0] != '\0')
				put(o, "tenant", ucl_object_fromstring(
				    user_tenant(u)));
		} else
			put(o, "console", ucl_object_fromstring("operator"));
	}
	/* The page offers a user and password when a directory is set,
	 * or a user has a password of the console's own. */
	put(o, "ldap", ucl_object_frombool(ldap_enabled()));
	put(o, "password", ucl_object_frombool(users_any_password()));
	put(o, "password_full", ucl_object_frombool(cfg.password_full));
	put(o, "setup_required", ucl_object_frombool(!setup_done()));
#ifdef ARCANA_CLUSTER
	/* A cluster's setup token: the node whose data directory has it,
	 * the same on every node; or why there is none yet. */
	if (cluster_on() && !setup_done()) {
		uint8_t	h[32];
		char	node[64], why[256];

		if (cluster_setup_state(h, node, sizeof(node)) ==
		    CLUSTER_SETUP_TOKEN)
			put(o, "setup_node", ucl_object_fromstring(node));
		else if (setup_token_none(why, sizeof(why)))
			put(o, "setup_waiting", ucl_object_fromstring(why));
	}
#endif
	/* Whether there is a key to sign in with: a console set up by a
	 * password alone has none yet. */
	put(o, "keys", ucl_object_frombool(ucl_array_size(cred_list()) > 0));
	put(o, "rp_id", ucl_object_fromstring(cfg.rp_id));
	/* The browser checks both against its address before any key is
	 * asked: the page says so when they do not match. */
	put(o, "origin", ucl_object_fromstring(cfg.origin));
	return (reply_json(req, 200, o));
}

static int
status_reply(struct http_request *req, bool authenticated)
{

	return (status_reply_as(req, authenticated, authenticated &&
	    session_by_token(req), authenticated ? session_by(req) : BY_KEY));
}

int
api_auth_status(struct http_request *req)
{

	return (status_reply(req, session_valid(req)));
}

/*
 * Options for navigator.credentials.create().  The first registration
 * needs the setup token; later ones, to add a spare key, a session.
 */
int
api_register_begin(struct http_request *req)
{
	const ucl_object_t	*c;
	ucl_object_t		*body, *o, *pk, *rp, *user, *params, *p, *excl;
	ucl_object_t		*sel, *e;
	ucl_object_iter_t	 it;
	struct regchal		 rc;
	const char		*token;
	static const int	 algs[] = { COSE_EDDSA, COSE_ES256,
				    COSE_RS256 };
	char			 chal[CHAL_MAX];
	size_t			 i;

	body = read_json(req);
	/*
	 * Whose key: an invited user's, by their invitation (users.c),
	 * spent only when the key is registered; the first key the
	 * built-in owner's, by the setup token; else the signed-in user's
	 * own, or, for the owner, the one named.  Said in the challenge,
	 * kept nowhere else: each ceremony is its own.
	 */
	memset(&rc, 0, sizeof(rc));
	if (body != NULL && ucl_str(body, "invite") != NULL) {
		if (!invite_check(ucl_str(body, "invite"), rc.inv, rc.user,
		    sizeof(rc.user))) {
			ucl_object_unref(body);
			return (reply_error(req, 403, "invite", "not an "
			    "invitation of this console's, or one that ran out"));
		}
		rc.mode = REG_INVITE;
	} else if (!setup_done()) {
		char	where[MAXPATHLEN + 128];

		token = body != NULL ? ucl_str(body, "setup_token") : NULL;
		if (setup_token_none(where, sizeof(where))) {
			ucl_object_unref(body);
			return (reply_error(req, 503, "setup_token", "%s",
			    where));
		}
		if (!setup_token_ok(token)) {
			ucl_object_unref(body);
			setup_token_where(where, sizeof(where));
			return (reply_error(req, 403, "setup_token",
			    "the first key needs the setup token from %s",
			    where));
		}
		rc.mode = REG_SETUP;
		snprintf(rc.user, sizeof(rc.user), "%s", ADMIN_USER);
#ifdef ARCANA_CLUSTER
		/* Which token, for the cluster's log to spend it: its
		 * SHA-256, under the challenge's MAC. */
		if (cluster_on())
			sha256(token, strlen(token), rc.inv);
#endif
	} else {
		const char	*u, *forname;

		if (!guard(req, true)) {
			ucl_object_unref(body);
			return (WEB_OK);
		}
		u = session_user(req);
		forname = body != NULL ? ucl_str(body, "user") : NULL;
		if (forname != NULL && forname[0] != '\0' && (u == NULL ||
		    strcmp(forname, u) != 0)) {
			if (user_console(u) != CROLE_OWNER || !user_exists(
			    forname)) {
				ucl_object_unref(body);
				return (reply_error(req, 403, "role", "a key for "
				    "another user is registered by the owner, for "
				    "a user there is"));
			}
			snprintf(rc.user, sizeof(rc.user), "%s", forname);
		} else if (u != NULL)
			snprintf(rc.user, sizeof(rc.user), "%s", u);
		else {
			ucl_object_unref(body);
			return (reply_error(req, 403, "role", "a key is a "
			    "user's"));
		}
		rc.mode = REG_SESSION;
	}
	ucl_object_unref(body);

	reg_challenge(&rc, chal, sizeof(chal));
	pk = ucl_object_typed_new(UCL_OBJECT);
	put(pk, "challenge", ucl_object_fromstring(chal));
	rp = ucl_object_typed_new(UCL_OBJECT);
	put(rp, "id", ucl_object_fromstring(cfg.rp_id));
	put(rp, "name", ucl_object_fromstring(cfg.rp_name));
	put(pk, "rp", rp);
	user = ucl_object_typed_new(UCL_OBJECT);
	if (strcmp(rc.user, ADMIN_USER) == 0)
		put(user, "id", ucl_object_fromstring(ucl_str(creds, "user_id")));
	else {
		char	handle[40];

		user_handle(rc.user, handle, sizeof(handle));
		put(user, "id", ucl_object_fromstring(handle));
	}
	put(user, "name", ucl_object_fromstring(rc.user));
	put(user, "displayName", ucl_object_fromstring(rc.user));
	put(pk, "user", user);
	params = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < nitems(algs); i++) {
		p = ucl_object_typed_new(UCL_OBJECT);
		put(p, "type", ucl_object_fromstring("public-key"));
		put(p, "alg", ucl_object_fromint(algs[i]));
		ucl_array_append(params, p);
	}
	put(pk, "pubKeyCredParams", params);
	excl = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((c = ucl_object_iterate(cred_list(), &it, true)) != NULL) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "type", ucl_object_fromstring("public-key"));
		put(e, "id", ucl_object_fromstring(ucl_str(c, "id")));
		ucl_array_append(excl, e);
	}
	put(pk, "excludeCredentials", excl);
	/* A discoverable credential where the authenticator offers one: a
	 * phone's passkey logs in without the credential list. */
	sel = ucl_object_typed_new(UCL_OBJECT);
	put(sel, "residentKey", ucl_object_fromstring("preferred"));
	put(sel, "userVerification", ucl_object_fromstring("preferred"));
	put(pk, "authenticatorSelection", sel);
	put(pk, "attestation", ucl_object_fromstring("none"));
	put(pk, "timeout", ucl_object_fromint(CHALLENGE_TTL * 1000));
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "publicKey", pk);
	return (reply_json(req, 200, o));
}

/*
 * {id, clientDataJSON, authenticatorData, publicKey, publicKeyAlgorithm,
 *  transports, name}, all binary fields base64url.
 */
int
api_register_finish(struct http_request *req)
{
	ucl_object_t		*body, *c, *tr;
	const ucl_object_t	*v, *t;
	ucl_object_iter_t	 it;
	struct regchal		 rc;
	uint8_t			*cd, *ad, *spki, *credid, flags;
	const char		*id, *err, *name, *u;
	char			 chal[CHAL_MAX];
	size_t			 cdlen, adlen, spkilen, idlen, l;
	uint32_t		 count;
	time_t			 exp;
	int64_t			 alg;
	int			 status;

	cd = ad = spki = credid = NULL;
	status = 400;
	err = NULL;
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "bad_request",
		    "expected a JSON object"));
	id = ucl_str(body, "id");
	v = ucl_object_lookup(body, "publicKeyAlgorithm");
	alg = v != NULL ? ucl_object_toint(v) : 0;
	if (id == NULL || (credid = unb64url(id, &idlen)) == NULL ||
	    (cd = unb64url(ucl_str(body, "clientDataJSON"), &cdlen)) ==
	    NULL ||
	    (ad = unb64url(ucl_str(body, "authenticatorData"), &adlen)) ==
	    NULL ||
	    (spki = unb64url(ucl_str(body, "publicKey"), &spkilen)) == NULL) {
		err = "missing or malformed fields";
		goto out;
	}
	if ((err = check_client_data(cd, cdlen, "webauthn.create", chal,
	    sizeof(chal))) != NULL)
		goto out;
	if (!reg_challenge_read(chal, &rc, &exp)) {
		err = "unknown or expired challenge";
		goto out;
	}
	/*
	 * How its challenge says it may be made: an invited user's first
	 * key by the invitation alone, the first key by the setup token
	 * while the console is not set up, any other by a session of the
	 * user's own or the owner's.
	 */
	if (rc.mode == REG_SETUP && setup_done()) {
		status = 403;
		err = "this console is set up already: sign in";
		goto out;
	}
	if (rc.mode == REG_SESSION) {
		/* Refused, the reply sent. */
		if (!guard(req, true)) {
			status = 0;
			goto out;
		}
		u = session_user(req);
		if (u == NULL || (strcmp(u, rc.user) != 0 && (user_console(u) !=
		    CROLE_OWNER || !user_exists(rc.user)))) {
			status = 403;
			err = "a key for another user is registered by the "
			    "owner";
			goto out;
		}
	}
	if ((err = check_auth_data(ad, adlen, &flags, &count)) != NULL)
		goto out;
	/* Attested credential data: aaguid(16) idlen(2) id. */
	if ((flags & AD_AT) == 0 || adlen < 55) {
		err = "no attested credential data";
		goto out;
	}
	l = (size_t)ad[53] << 8 | ad[54];
	if (l != idlen || adlen < 55 + l || memcmp(ad + 55, credid, l) != 0) {
		err = "credential id does not match the authenticator data";
		goto out;
	}
	if (!key_matches((int)alg, spki, spkilen)) {
		err = "unsupported key or algorithm";
		goto out;
	}
	if (cred_find(id) != NULL) {
		err = "credential already registered";
		goto out;
	}
	name = ucl_str(body, "name");
	if (name != NULL && strlen(name) > 64) {
		err = "the key's name is at most 64 characters";
		goto out;
	}
	/* Used once; an invitation spent only now, by the ceremony it
	 * began. */
	if (!chal_use(chal, exp)) {
		err = "unknown or expired challenge";
		goto out;
	}
	if (rc.mode == REG_INVITE && !invite_spend(rc.inv, rc.user)) {
		status = 403;
		err = "the invitation was used, or ran out";
		goto out;
	}

	c = ucl_object_typed_new(UCL_OBJECT);
	put(c, "id", ucl_object_fromstring(id));
	put(c, "public_key", ucl_object_fromstring(ucl_str(body,
	    "publicKey")));
	put(c, "alg", ucl_object_fromint(alg));
	put(c, "sign_count", ucl_object_fromint(count));
	put(c, "name", ucl_object_fromstring(name != NULL && *name != '\0' ?
	    name : "Security key"));
	put(c, "created", ucl_object_fromint(time(NULL)));
	put(c, "user_verified", ucl_object_frombool((flags & AD_UV) != 0));
	tr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	if ((v = ucl_object_lookup(body, "transports")) != NULL)
		while ((t = ucl_object_iterate(v, &it, true)) != NULL &&
		    ucl_array_size(tr) < 8)
			if (ucl_object_type(t) == UCL_STRING)
				ucl_array_append(tr, ucl_object_copy(t));
	put(c, "transports", tr);
	if (strcmp(rc.user, ADMIN_USER) != 0)
		put(c, "user", ucl_object_fromstring(rc.user));
	ucl_array_append(cred_list(), c);
#ifdef ARCANA_CLUSTER
	/* A cluster's first key is the write that spends the setup token,
	 * the first of them committed: another node's first owner may have
	 * come before it. */
	if (rc.mode == REG_SETUP && cluster_on()) {
		char	why[256];

		if ((status = setup_spend(rc.inv, CREDENTIALS, creds, why,
		    sizeof(why))) != 0) {
			ucl_object_unref(ucl_array_delete(cred_list(), c));
			if (status == 409)
				status = 403;
			log_msg(LOG_NOTICE, "first key refused: %s", why);
			err = strstr(why, "set up already") != NULL ? "this "
			    "console is set up already: sign in" : strstr(why,
			    "setup token") != NULL ? "not the setup token: "
			    "the leader of the cluster made another" : "the "
			    "cluster did not say whether it was kept: reload "
			    "the page";
			goto out;
		}
		cyang_changed("credentials");
	} else
#endif
	if (creds_save() == -1) {
		/* A key that would be gone after a restart is not one. */
		ucl_object_unref(ucl_array_delete(cred_list(), c));
		status = 500;
		err = "cannot save the credential";
		goto out;
	}
	log_msg(LOG_NOTICE, "registered security key \"%s\" of %s",
	    ucl_str(c, "name"), cred_user(c));
	setup_token_init();
	session_start(req, ucl_str(c, "name"), ucl_str(c, "id"), NULL,
	    cred_user(c));
	status = 200;
out:
	free(cd);
	free(ad);
	free(spki);
	free(credid);
	ucl_object_unref(body);
	if (status == 0)
		return (WEB_OK);
	if (status != 200)
		return (reply_error(req, status, "registration", "%s", err));
	return (status_reply(req, true));
}

/*
 * Ids that stand for keys of a user name the console has no key of, as
 * many as hashing the name says (one or two), each as long as the first
 * key's is: made by HMAC of the name with a secret the console keeps
 * (credentials.json's decoy_key), so that each name always gets the
 * same and a reply tells not whether the user is there.  Into allow.
 */
static void
decoys(const char *name, ucl_object_t *allow)
{
	const ucl_object_t	*c;
	ucl_object_t		*e;
	uint8_t			*key, *first, mac[64], id[64];
	char			*s, text[USER_NAME_LEN + 8];
	size_t			 klen, idlen, n, i;
	unsigned int		 mlen;

	if ((key = unb64url(ucl_str(creds, "decoy_key"), &klen)) == NULL)
		return;
	idlen = 32;
	c = ucl_array_head(cred_list());
	if (c != NULL && (first = unb64url(ucl_str(c, "id"), &n)) != NULL) {
		if (n >= 16 && n <= sizeof(id))
			idlen = n;
		free(first);
	}
	snprintf(text, sizeof(text), "n/%s", name);
	HMAC(EVP_sha256(), key, (int)klen, (const uint8_t *)text,
	    strlen(text), mac, &mlen);
	n = 1 + (mac[0] & 1);
	for (i = 0; i < n; i++) {
		/* Each id of its own: the name, its index, as long as
		 * wanted, two MACs. */
		snprintf(text, sizeof(text), "%zu/%s", i, name);
		HMAC(EVP_sha256(), key, (int)klen, (const uint8_t *)text,
		    strlen(text), mac, &mlen);
		HMAC(EVP_sha256(), key, (int)klen, mac, 32, mac + 32, &mlen);
		memcpy(id, mac, idlen);
		if ((s = b64url(id, idlen)) == NULL)
			continue;
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "type", ucl_object_fromstring("public-key"));
		put(e, "id", ucl_object_fromstring(s));
		ucl_array_append(allow, e);
		free(s);
	}
	explicit_bzero(key, klen);
	free(key);
}

/*
 * Options for navigator.credentials.get(): no credential list, so that
 * no one learns who has which key, the authenticator offering the
 * passkeys it holds for this RP (registration asks for one: residentKey
 * preferred); the id it answers with is looked up as usual.  {"user"}
 * names whose keys, for a key that is not discoverable: that user's,
 * or, for a name with none, decoys() as many; the sign-in throttle's
 * (ldap.c), a try of the address's.
 */
int
api_login_begin(struct http_request *req)
{
	const ucl_object_t	*c, *t;
	ucl_object_t		*o, *pk, *allow, *e, *body;
	ucl_object_iter_t	 it;
	char			 chal[CHAL_MAX], name[USER_NAME_LEN], addr[64];
	bool			 named;

	if (ucl_array_size(cred_list()) == 0)
		return (setup_done() ? reply_error(req, 404, "no_key", "no "
		    "security key registered yet: sign in with a password") :
		    reply_error(req, 409, "setup_required", "no security key "
		    "registered yet"));
	body = read_json(req);
	named = body != NULL && ucl_str(body, "user") != NULL && ucl_str(body,
	    "user")[0] != '\0';
	if (named && !name_copy(name, sizeof(name), ucl_str(body, "user"))) {
		ucl_object_unref(body);
		return (reply_error(req, 400, "login", "a user name is "
		    __XSTRING(USER_NAME_MAX) " characters at most"));
	}
	ucl_object_unref(body);
	if (named) {
		(void)web_peer(req, addr, sizeof(addr));
		if (signin_throttled(addr, name))
			return (reply_error(req, 429, "login", "too many failed "
			    "sign-ins: try again in a minute"));
		/* A try of the address's: names asked one after another
		 * wait, the user's own sign-ins by name are not held. */
		signin_failed(addr, NULL);
	}
	chal_make(NULL, 0, chal, sizeof(chal));
	pk = ucl_object_typed_new(UCL_OBJECT);
	put(pk, "challenge", ucl_object_fromstring(chal));
	put(pk, "rpId", ucl_object_fromstring(cfg.rp_id));
	allow = ucl_object_typed_new(UCL_ARRAY);
	if (named && cred_count_of(name) == 0)
		decoys(name, allow);
	it = NULL;
	while (named && cred_count_of(name) > 0 &&
	    (c = ucl_object_iterate(cred_list(), &it, true)) != NULL) {
		if (strcmp(cred_user(c), name) != 0)
			continue;
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "type", ucl_object_fromstring("public-key"));
		put(e, "id", ucl_object_fromstring(ucl_str(c, "id")));
		if ((t = ucl_object_lookup(c, "transports")) != NULL &&
		    ucl_array_size(t) > 0)
			put(e, "transports", ucl_object_copy(t));
		ucl_array_append(allow, e);
	}
	put(pk, "allowCredentials", allow);
	put(pk, "userVerification", ucl_object_fromstring("preferred"));
	put(pk, "timeout", ucl_object_fromint(CHALLENGE_TTL * 1000));
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "publicKey", pk);
	return (reply_json(req, 200, o));
}

/* {id, clientDataJSON, authenticatorData, signature}, base64url. */
int
api_login_finish(struct http_request *req)
{
	const ucl_object_t	*c;
	ucl_object_t		*body;
	uint8_t			*cd, *ad, *sig, *spki, *msg, flags;
	uint8_t			 cdhash[32];
	const char		*id, *err;
	char			 chal[CHAL_MAX];
	size_t			 cdlen, adlen, siglen, spkilen;
	uint32_t		 count, stored;
	time_t			 exp;

	cd = ad = sig = spki = msg = NULL;
	err = NULL;
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "bad_request",
		    "expected a JSON object"));
	if ((id = ucl_str(body, "id")) == NULL ||
	    (c = cred_find(id)) == NULL) {
		err = "unknown credential";
		goto out;
	}
	if ((cd = unb64url(ucl_str(body, "clientDataJSON"), &cdlen)) ==
	    NULL ||
	    (ad = unb64url(ucl_str(body, "authenticatorData"), &adlen)) ==
	    NULL ||
	    (sig = unb64url(ucl_str(body, "signature"), &siglen)) == NULL ||
	    (spki = unb64url(ucl_str(c, "public_key"), &spkilen)) == NULL) {
		err = "missing or malformed fields";
		goto out;
	}
	if ((err = check_client_data(cd, cdlen, "webauthn.get", chal,
	    sizeof(chal))) != NULL ||
	    (err = check_auth_data(ad, adlen, &flags, &count)) != NULL)
		goto out;
	if (!chal_check(chal, NULL, 0, &exp)) {
		err = "unknown or expired challenge";
		goto out;
	}
	/* The signature covers authenticatorData || SHA-256(clientData). */
	sha256(cd, cdlen, cdhash);
	if ((msg = malloc(adlen + sizeof(cdhash))) == NULL) {
		err = "out of memory";
		goto out;
	}
	memcpy(msg, ad, adlen);
	memcpy(msg + adlen, cdhash, sizeof(cdhash));
	if (!verify_sig((int)ucl_object_toint(ucl_object_lookup(c, "alg")),
	    spki, spkilen, msg, adlen + sizeof(cdhash), sig, siglen)) {
		err = "bad signature";
		goto out;
	}
	/* A counter that does not move forward means a cloned key. */
	stored = (uint32_t)ucl_object_toint(ucl_object_lookup(c,
	    "sign_count"));
	if ((count != 0 || stored != 0) && count <= stored) {
		err = "signature counter went backwards";
		log_msg(LOG_WARNING, "security key \"%s\": counter %u after "
		    "%u: possibly cloned", ucl_str(c, "name"), count, stored);
		goto out;
	}
	/* Used once, noted only now: a signature of the key's it took. */
	if (!chal_use(chal, exp)) {
		err = "unknown or expired challenge";
		goto out;
	}
	ucl_object_replace_key((ucl_object_t *)(uintptr_t)c,
	    ucl_object_fromint(count), "sign_count", 0, true);
	ucl_object_replace_key((ucl_object_t *)(uintptr_t)c,
	    ucl_object_fromint(time(NULL)), "last_used", 0, true);
	(void)creds_save();
	session_start(req, ucl_str(c, "name"), ucl_str(c, "id"), NULL,
	    cred_user(c));
	log_msg(LOG_NOTICE, "login with \"%s\" of %s", ucl_str(c, "name"),
	    cred_user(c));
out:
	free(cd);
	free(ad);
	free(sig);
	free(spki);
	free(msg);
	ucl_object_unref(body);
	if (err != NULL) {
		log_msg(LOG_NOTICE, "login refused: %s", err);
		return (reply_error(req, 401, "login", "%s", err));
	}
	return (status_reply(req, true));
}

/*
 * POST /api/auth/login/token {"token": "arcw_..."}: signed in with a
 * write token, for one with no security key at hand.  The session may
 * do what the token may and no more: not the console's settings,
 * sign-in, push, enrolment, tokens or CA; it ends when the token is
 * deleted.  A read token does not sign in.
 */
int
api_login_token(struct http_request *req)
{
	ucl_object_t	*body;
	const char	*v, *name;
	char		 id[17], who[96];

	if (req->method != HTTP_METHOD_POST)
		return (reply_error(req, 405, "method", "POST"));
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "bad_request", "expected a JSON "
		    "object"));
	v = ucl_str(body, "token");
	name = v != NULL ? token_login(v, id, sizeof(id)) : NULL;
	if (name == NULL) {
		ucl_object_unref(body);
		log_msg(LOG_NOTICE, "login with a token refused");
		return (reply_error(req, 401, "login", "not a write token of "
		    "this console's: a read token does not sign in, and a "
		    "deleted one opens nothing"));
	}
	snprintf(who, sizeof(who), "API token %s", name);
	session_start(req, who, NULL, id, NULL);
	log_msg(LOG_NOTICE, "login with %s", who);
	ucl_object_unref(body);
	/* Its cookie is only on its way: said so here. */
	return (status_reply_as(req, true, true, BY_KEY));
}

/*
 * A sign-in by a password, in a task: bcrypt and the directory take
 * their time, the loop none of it.  What it reads of the console is
 * given it (the directory groups of the roles), or read by what
 * acl_publish() made (the user's hash, user_password_ok()).
 */
struct pwlogin {
	struct task	 task;		/* first */
	/* The directory groups of the roles: roles_ldap_groups()'s. */
	char		 user[USER_NAME_LEN];
	char		*password;	/* wiped and freed once tried */
	char		 addr[64];
	bool		 own;		/* the console's own password */
	char		 rn[ROLES_LDAP_MAX][72];
	char		 rg[ROLES_LDAP_MAX][512];
	int		 nr;
	bool		 ok, failed;
	char		 who[96];
	char		 err[300];
	const char	*roles[ROLES_LDAP_MAX];	/* of rn */
	int		 nroles;
};

static int
pwlogin_run(struct task *t)
{
	struct pwlogin	*pl = (struct pwlogin *)t;
	const char	*rn[ROLES_LDAP_MAX], *rg[ROLES_LDAP_MAX];
	int		 i;

	if (pl->own || !ldap_enabled()) {
		/* Compared even for a user with none, the time the same. */
		pl->ok = user_password_ok(pl->user, pl->password);
		if (pl->ok)
			snprintf(pl->who, sizeof(pl->who), "%s (password)",
			    pl->user);
		else {
			pl->failed = true;
			snprintf(pl->err, sizeof(pl->err), "the user name or "
			    "the password is not right");
		}
	} else {
		for (i = 0; i < pl->nr; i++) {
			rn[i] = pl->rn[i];
			rg[i] = pl->rg[i];
		}
		pl->ok = ldap_login(pl->user, pl->password, rn, rg, pl->nr,
		    pl->who, sizeof(pl->who), pl->err, sizeof(pl->err),
		    pl->roles, &pl->nroles, ROLES_LDAP_MAX, &pl->failed);
	}
	explicit_bzero(pl->password, strlen(pl->password));
	free(pl->password);
	pl->password = NULL;
	if (pl->failed)
		signin_failed(pl->addr, pl->user);
	return (WEB_OK);
}

void
api_login_password_free(struct http_request *req)
{
	struct pwlogin	*pl = req->hdlr_extra;

	/* Asked while the task runs too: only once it is done. */
	if (pl == NULL || !task_finished(&pl->task))
		return;
	task_destroy(&pl->task);
	free(pl);
	req->hdlr_extra = NULL;
}

/* The sign-in tried: a session, or why not. */
static int
pwlogin_done(struct http_request *req, struct pwlogin *pl)
{
	struct session	*s;
	bool		 own;

	own = pl->own;
	if (pl->ok && !own && user_exists(pl->user) && !user_ldap(pl->user)) {
		/* The name is a local user's (the built-in owner, keys
		 * alone, among them): the directory's account of that
		 * name is not them. */
		pl->ok = false;
		snprintf(pl->err, sizeof(pl->err), "%s is a user of the "
		    "console's own, not the directory's: it signs in with its "
		    "key or its own password", pl->user);
	} else if (pl->ok && !own) {
		/* The directory's groups give the user's roles (users.c):
		 * the user kept, or made, as the groups say.  One the
		 * console then has no record of has no role on it:
		 * refused, not let in as no one. */
		users_ldap_sync(pl->user, pl->roles, pl->nroles);
		if (!user_exists(pl->user) || !user_ldap(pl->user)) {
			pl->ok = false;
			snprintf(pl->err, sizeof(pl->err), "the directory "
			    "gives %s no role on this console: an owner maps a "
			    "directory group to a role (Settings, AAA, Roles)",
			    pl->user);
		}
	}
	if (!pl->ok) {
		log_msg(LOG_NOTICE, "login by password refused: %s", pl->err);
		return (reply_error(req, strstr(pl->err, "too many") != NULL ?
		    429 : strstr(pl->err, "not set") != NULL || strstr(pl->err,
		    "characters") != NULL ? 400 : 401, "login", "%s",
		    pl->err));
	}
	s = session_start(req, pl->who, NULL, "", pl->user);
	if (own)
		s->pw = true;
	else
		s->ldap = true;
	session_put(s);
	log_msg(LOG_NOTICE, "login by %s", pl->who);
	return (status_reply_as(req, true, !own || !cfg.password_full, own ?
	    BY_PASSWORD : BY_LDAP));
}

/*
 * POST {"user", "password"}: a sign-in by a password, limited as a
 * token's is.  A user with a password of the console's own (users.c)
 * is checked against it, and against nothing else; any other, by the
 * directory Settings name, when there is one, and let in only as a
 * user the console then has (its groups give it a role).  The password
 * is kept nowhere: it is hashed, or goes to the directory, and is
 * wiped.  Failures count towards a limit a minute of the address they
 * come from and of the name tried, both ways alike (ldap.c).
 */
int
api_login_password(struct http_request *req)
{
	struct pwlogin	*pl;
	ucl_object_t	*body;
	const char	*user, *password, *rn[ROLES_LDAP_MAX];
	const char	*rg[ROLES_LDAP_MAX];
	int		 i;

	if ((pl = req->hdlr_extra) != NULL) {
		if (task_state(&pl->task) != TASK_STATE_FINISHED) {
			http_request_sleep(req);
			return (WEB_RETRY);
		}
		return (pwlogin_done(req, pl));
	}
	if (req->method != HTTP_METHOD_POST)
		return (reply_error(req, 405, "method", "POST"));
	config_refresh();
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "bad_request", "expected a JSON "
		    "object"));
	user = ucl_str(body, "user");
	password = ucl_str(body, "password");
	pl = xcalloc(1, sizeof(*pl));
	pl->own = user != NULL && user_has_password(user);
	if (!pl->own && !ldap_enabled() && !users_any_password()) {
		if (password != NULL)
			explicit_bzero((char *)(uintptr_t)password,
			    strlen(password));
		ucl_object_unref(body);
		free(pl);
		return (reply_error(req, 404, "password", "no sign-in by "
		    "password on this console: no user has one, and no "
		    "directory is set up"));
	}
	if (!name_copy(pl->user, sizeof(pl->user), user != NULL ? user : "")) {
		if (password != NULL)
			explicit_bzero((char *)(uintptr_t)password,
			    strlen(password));
		ucl_object_unref(body);
		free(pl);
		return (reply_error(req, 400, "login", "a user name is "
		    __XSTRING(USER_NAME_MAX) " characters at most"));
	}
	(void)web_peer(req, pl->addr, sizeof(pl->addr));
	if (signin_throttled(pl->addr, pl->user)) {
		if (password != NULL)
			explicit_bzero((char *)(uintptr_t)password,
			    strlen(password));
		ucl_object_unref(body);
		free(pl);
		log_msg(LOG_NOTICE, "login by password refused: too many "
		    "failed sign-ins");
		return (reply_error(req, 429, "login", "too many failed "
		    "sign-ins: try again in a minute"));
	}
	pl->password = xstrdup(password != NULL ? password : "");
	if (password != NULL)
		explicit_bzero((char *)(uintptr_t)password, strlen(password));
	ucl_object_unref(body);
	pl->nr = roles_ldap_groups(rn, rg, ROLES_LDAP_MAX);
	for (i = 0; i < pl->nr; i++) {
		snprintf(pl->rn[i], sizeof(pl->rn[i]), "%s", rn[i]);
		snprintf(pl->rg[i], sizeof(pl->rg[i]), "%s", rg[i]);
	}
	req->hdlr_extra = pl;
	task_create(&pl->task, pwlogin_run);
	task_bind_request(&pl->task, req);
	task_run(&pl->task);
	return (WEB_RETRY);
}

/*
 * A password hashed in a task, and a current one checked there: bcrypt
 * takes a quarter second, the loop none of it.  What the loop decided
 * before (the setup token, whose password, the proof by a key) is in
 * it; what is kept once it is done the loop's again.
 */
struct pwset {
	struct task	 task;		/* first */
	char		 user[USER_NAME_LEN];
	char		 addr[64];
	char		*password;	/* wiped and freed once hashed */
	char		*current;	/* NULL: not asked for */
	bool		 setup;		/* api_setup_password's */
	bool		 made;		/* setup: the user made for it */
#ifdef ARCANA_CLUSTER
	uint8_t		 token[32];	/* setup: SHA-256 of its token */
#endif
	char		 hash[128];
	const char	*err;
};

static int
pwset_run(struct task *t)
{
	struct pwset	*ps = (struct pwset *)t;

	ps->err = NULL;
	if (ps->current != NULL && !user_password_ok(ps->user, ps->current)) {
		ps->err = "the current password is not right";
		signin_failed(ps->addr, ps->user);
	}
	if (ps->err == NULL)
		ps->err = user_password_hash(ps->password, ps->hash,
		    sizeof(ps->hash));
	if (ps->current != NULL) {
		explicit_bzero(ps->current, strlen(ps->current));
		free(ps->current);
		ps->current = NULL;
	}
	explicit_bzero(ps->password, strlen(ps->password));
	free(ps->password);
	ps->password = NULL;
	return (WEB_OK);
}

/* The request's task, a sign-in's or a password's, freed once done. */
void
api_pwset_free(struct http_request *req)
{
	struct pwset	*ps = req->hdlr_extra;

	if (ps == NULL || !task_finished(&ps->task))
		return;
	task_destroy(&ps->task);
	explicit_bzero(ps->hash, sizeof(ps->hash));
	free(ps);
	req->hdlr_extra = NULL;
}

static struct pwset *
pwset_new(struct http_request *req, const char *user, const char *password,
    const char *current)
{
	struct pwset	*ps;

	ps = xcalloc(1, sizeof(*ps));
	(void)name_copy(ps->user, sizeof(ps->user), user);
	(void)web_peer(req, ps->addr, sizeof(ps->addr));
	ps->password = xstrdup(password != NULL ? password : "");
	ps->current = current != NULL ? xstrdup(current) : NULL;
	return (ps);
}

static int
pwset_start(struct http_request *req, struct pwset *ps)
{

	req->hdlr_extra = ps;
	task_create(&ps->task, pwset_run);
	task_bind_request(&ps->task, req);
	task_run(&ps->task);
	return (WEB_RETRY);
}

/* Still hashing: true, the request put to sleep. */
static bool
pwset_waiting(struct http_request *req, struct pwset *ps)
{

	if (task_state(&ps->task) != TASK_STATE_FINISHED) {
		http_request_sleep(req);
		return (true);
	}
	return (false);
}

static int
setup_password_done(struct http_request *req, struct pwset *ps)
{
	struct session	*s;
	const char	*e;
	char		 who[96];

	e = ps->err;
	/* Another set it up meanwhile: the first one's. */
	if (e == NULL && setup_done())
		e = "this console is set up already: sign in";
#ifdef ARCANA_CLUSTER
	/* A cluster's first owner is the write that spends the setup token,
	 * the first of them committed, users.json as it is to be in it. */
	if (e == NULL && cluster_on()) {
		ucl_object_t	*doc;
		char		 why[256];
		int		 st;

		if ((doc = user_owner_doc(ps->user, ps->hash, &e)) != NULL) {
			st = setup_spend(ps->token, "users.json", doc, why,
			    sizeof(why));
			ucl_object_unref(doc);
			if (st != 0) {
				explicit_bzero(ps->hash, sizeof(ps->hash));
				log_msg(LOG_NOTICE, "setup by password refused: "
				    "%s", why);
				return (reply_error(req, st, "setup", "%s",
				    st == 409 && strstr(why, "setup token") !=
				    NULL ? "not the setup token: the leader of the "
				    "cluster made another" : st == 409 ? "this "
				    "console is set up already: sign in" : why));
			}
			/* Written here by that write: read now, for the
			 * session opened with it. */
			users_reload();
		}
	} else
#endif
	if (e == NULL) {
		ps->made = !user_exists(ps->user);
		if ((e = user_owner_add(ps->user)) == NULL)
			e = user_password_set(ps->user, ps->hash);
	}
	explicit_bzero(ps->hash, sizeof(ps->hash));
	if (e != NULL) {
		/* A user made for a password that was not kept goes. */
		if (ps->made)
			user_owner_undo(ps->user);
		log_msg(LOG_NOTICE, "setup by password refused: %s", e);
		return (reply_error(req, strstr(e, "set up already") != NULL ?
		    409 : strstr(e, "written") != NULL || strstr(e, "crypt") !=
		    NULL ? 500 : 400, "setup", "%s", e));
	}
	setup_token_init();
	snprintf(who, sizeof(who), "%s (password)", ps->user);
	s = session_start(req, who, NULL, "", ps->user);
	s->pw = true;
	session_put(s);
	log_msg(LOG_NOTICE, "console set up by password: owner %s", ps->user);
	return (status_reply_as(req, true, !cfg.password_full, BY_PASSWORD));
}

/*
 * POST {"setup_token", "user", "password"}: the console set up by a
 * password instead of a key, for a browser no key reaches (a remote
 * desktop's).  The setup token, as for the first key; the user the
 * built-in admin unless named, a new one made an owner; the password
 * kept as any user's (users.c), hashed in a task.  The console is then
 * set up: the token is gone, and the session opened is the password's.
 */
int
api_setup_password(struct http_request *req)
{
	struct pwset	*ps;
	ucl_object_t	*body;
	const char	*token, *user, *password, *e;
	char		 name[USER_NAME_LEN], addr[64];
	char		 where[MAXPATHLEN + 128];

	if ((ps = req->hdlr_extra) != NULL)
		return (pwset_waiting(req, ps) ? WEB_RETRY :
		    setup_password_done(req, ps));
	name[0] = '\0';
	if (req->method != HTTP_METHOD_POST)
		return (reply_error(req, 405, "method", "POST"));
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "bad_request", "{\"setup_token\", "
		    "\"user\", \"password\"}"));
	if (setup_done()) {
		ucl_object_unref(body);
		return (reply_error(req, 409, "setup_done", "this console is "
		    "set up already: sign in"));
	}
	token = ucl_str(body, "setup_token");
	user = ucl_str(body, "user") != NULL && ucl_str(body, "user")[0] !=
	    '\0' ? ucl_str(body, "user") : ADMIN_USER;
	password = ucl_str(body, "password");
	e = NULL;
	(void)web_peer(req, addr, sizeof(addr));
	/* Its own count, the sign-ins' not touched by it, nor it by
	 * theirs. */
	if (setup_throttled(addr))
		e = "too many failed attempts: try again in a minute";
	else if (setup_token_none(where, sizeof(where))) {
		if (password != NULL)
			explicit_bzero((char *)(uintptr_t)password,
			    strlen(password));
		ucl_object_unref(body);
		return (reply_error(req, 503, "setup", "%s", where));
	} else if (!setup_token_ok(token)) {
		setup_failed(addr);
		e = "not the setup token";
	} else if ((e = user_password_check(password)) == NULL &&
	    !name_copy(name, sizeof(name), user))
		e = "a user name is 1 to 64 letters, digits and _ . @ -";
	if (e != NULL) {
		if (password != NULL)
			explicit_bzero((char *)(uintptr_t)password,
			    strlen(password));
		ucl_object_unref(body);
		log_msg(LOG_NOTICE, "setup by password refused: %s", e);
		if (cluster_on())
			setup_token_where(where, sizeof(where));
		else
			strlcpy(where, "the console's data directory, "
			    "setup-token", sizeof(where));
		return (reply_error(req, strstr(e, "too many") != NULL ? 429 :
		    strstr(e, "setup token") != NULL ? 403 : 400, "setup",
		    "%s%s%s", e, strstr(e, "setup token") != NULL ? ": it is in "
		    : "", strstr(e, "setup token") != NULL ? where : ""));
	}
	ps = pwset_new(req, name, password, NULL);
	ps->setup = true;
#ifdef ARCANA_CLUSTER
	sha256(token, strlen(token), ps->token);
#endif
	explicit_bzero((char *)(uintptr_t)password, strlen(password));
	ucl_object_unref(body);
	return (pwset_start(req, ps));
}

/*
 * What a password change's challenge carries (api_auth_password_begin):
 * PW_CHAL and whose password, so that it proves that user's key alone,
 * for that alone (a sign-in's carries nothing, a registration's more).
 */
#define	PW_CHAL		4
#define	PW_CARRY	(1 + 64)

/*
 * POST {}: options for navigator.credentials.get() that prove the
 * session's user changes their own password: a challenge for that, the
 * user's keys.
 */
int
api_auth_password_begin(struct http_request *req)
{
	const ucl_object_t	*c, *t;
	ucl_object_t		*o, *pk, *allow, *e;
	ucl_object_iter_t	 it;
	const char		*me;
	uint8_t			 what[PW_CARRY];
	char			 chal[CHAL_MAX];

	if (req->method != HTTP_METHOD_POST)
		return (reply_error(req, 405, "method", "POST"));
	if (!guard(req, true))
		return (WEB_OK);
	if ((me = session_user(req)) == NULL || cred_count_of(me) == 0)
		return (reply_error(req, 404, "no_key", "no key of yours to "
		    "confirm with: give your current password"));
	memset(what, 0, sizeof(what));
	what[0] = PW_CHAL;
	memcpy(what + 1, me, strnlen(me, 64));
	chal_make(what, sizeof(what), chal, sizeof(chal));
	pk = ucl_object_typed_new(UCL_OBJECT);
	put(pk, "challenge", ucl_object_fromstring(chal));
	put(pk, "rpId", ucl_object_fromstring(cfg.rp_id));
	allow = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((c = ucl_object_iterate(cred_list(), &it, true)) != NULL) {
		if (strcmp(cred_user(c), me) != 0)
			continue;
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "type", ucl_object_fromstring("public-key"));
		put(e, "id", ucl_object_fromstring(ucl_str(c, "id")));
		if ((t = ucl_object_lookup(c, "transports")) != NULL &&
		    ucl_array_size(t) > 0)
			put(e, "transports", ucl_object_copy(t));
		ucl_array_append(allow, e);
	}
	put(pk, "allowCredentials", allow);
	put(pk, "userVerification", ucl_object_fromstring("preferred"));
	put(pk, "timeout", ucl_object_fromint(CHALLENGE_TTL * 1000));
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "publicKey", pk);
	return (reply_json(req, 200, o));
}

/*
 * Is a, {id, clientDataJSON, authenticatorData, signature}, an assertion
 * of one of user's keys over a challenge api_auth_password_begin() made
 * for user, not used before?  NULL, the challenge then used and the
 * key's counter kept, or what is wrong.
 */
static const char *
pw_assertion(const ucl_object_t *a, const char *user)
{
	const ucl_object_t	*c;
	uint8_t			*cd, *ad, *sig, *spki, *msg, flags;
	uint8_t			 cdhash[32], what[PW_CARRY];
	const char		*id, *err;
	char			 chal[CHAL_MAX], whose[65];
	size_t			 cdlen, adlen, siglen, spkilen;
	uint32_t		 count, stored;
	time_t			 exp;

	cd = ad = sig = spki = msg = NULL;
	err = NULL;
	if ((id = ucl_str(a, "id")) == NULL || (c = cred_find(id)) == NULL ||
	    strcmp(cred_user(c), user) != 0)
		return ("not a key of yours");
	if ((cd = unb64url(ucl_str(a, "clientDataJSON"), &cdlen)) == NULL ||
	    (ad = unb64url(ucl_str(a, "authenticatorData"), &adlen)) ==
	    NULL ||
	    (sig = unb64url(ucl_str(a, "signature"), &siglen)) == NULL ||
	    (spki = unb64url(ucl_str(c, "public_key"), &spkilen)) == NULL) {
		err = "missing or malformed fields";
		goto out;
	}
	if ((err = check_client_data(cd, cdlen, "webauthn.get", chal,
	    sizeof(chal))) != NULL ||
	    (err = check_auth_data(ad, adlen, &flags, &count)) != NULL)
		goto out;
	memset(whose, 0, sizeof(whose));
	if (!chal_check(chal, what, sizeof(what), &exp) || what[0] !=
	    PW_CHAL || (memcpy(whose, what + 1, 64), strcmp(whose, user)) !=
	    0) {
		err = "unknown or expired challenge";
		goto out;
	}
	sha256(cd, cdlen, cdhash);
	msg = xcalloc(1, adlen + sizeof(cdhash));
	memcpy(msg, ad, adlen);
	memcpy(msg + adlen, cdhash, sizeof(cdhash));
	if (!verify_sig((int)ucl_object_toint(ucl_object_lookup(c, "alg")),
	    spki, spkilen, msg, adlen + sizeof(cdhash), sig, siglen)) {
		err = "bad signature";
		goto out;
	}
	stored = (uint32_t)ucl_object_toint(ucl_object_lookup(c,
	    "sign_count"));
	if ((count != 0 || stored != 0) && count <= stored) {
		err = "signature counter went backwards";
		goto out;
	}
	if (!chal_use(chal, exp)) {
		err = "unknown or expired challenge";
		goto out;
	}
	ucl_object_replace_key((ucl_object_t *)(uintptr_t)c,
	    ucl_object_fromint(count), "sign_count", 0, true);
	(void)creds_save();
out:
	free(cd);
	free(ad);
	free(sig);
	free(spki);
	free(msg);
	return (err);
}

static int
auth_password_done(struct http_request *req, struct pwset *ps)
{
	ucl_object_t	*o;
	const char	*e;
	bool		 set;

	set = ps->hash[0] != '\0';
	if ((e = ps->err) == NULL)
		e = user_password_set(ps->user, ps->hash);
	explicit_bzero(ps->hash, sizeof(ps->hash));
	if (e != NULL)
		return (reply_error(req, strcmp(e, "no such user") == 0 ? 404 :
		    strstr(e, "current password") != NULL ? 403 : strstr(e,
		    "written") != NULL || strstr(e, "crypt") != NULL ? 500 :
		    400, strstr(e, "current password") != NULL ? "proof" :
		    "invalid", "%s", e));
	sessions_end_password(ps->user);
	log_msg(LOG_NOTICE, "password of %s %s by %s", ps->user, set ? "set" :
	    "taken away", session_who(req) != NULL ? session_who(req) : "?");
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "ok", ucl_object_frombool(true));
	put(o, "user", ucl_object_fromstring(ps->user));
	put(o, "password", ucl_object_frombool(set));
	return (reply_json(req, 200, o));
}

/*
 * POST {"user", "password", "current" | "assertion"}: a password of the
 * console's own set for the user, or taken away when it is "" or null.
 * The user is the session's own when not named, and then proved again:
 * by the current password ("current"), or, for a user with none or
 * signed in by a key, by a key of theirs over a challenge of
 * api_auth_password_begin()'s ("assertion"); a session left open is not
 * enough.  Another's is the owner's to set, as before.  Not from a
 * session opened by a token or a directory's password: guard() refuses
 * those (/api/auth is not theirs), and one opened by the console's own
 * password when password_full = false.  Hashed (and the current one
 * checked) in a task.  The user's sessions opened by the password
 * before end.
 */
int
api_auth_password(struct http_request *req)
{
	struct pwset		*ps;
	ucl_object_t		*body;
	const ucl_object_t	*a;
	const char		*me, *user, *password, *current, *e;
	char			 name[USER_NAME_LEN], addr[64];

	if ((ps = req->hdlr_extra) != NULL)
		return (pwset_waiting(req, ps) ? WEB_RETRY :
		    auth_password_done(req, ps));
	if (req->method != HTTP_METHOD_POST)
		return (reply_error(req, 405, "method", "POST"));
	if (!guard(req, true))
		return (WEB_OK);
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "bad_request", "{\"user\", "
		    "\"password\", \"current\"}"));
	me = session_user(req);
	user = ucl_str(body, "user") != NULL && ucl_str(body, "user")[0] !=
	    '\0' ? ucl_str(body, "user") : me;
	password = ucl_str(body, "password");
	current = ucl_str(body, "current");
	e = NULL;
	if (user == NULL || !user_name_ok(user))
		e = "whose password: \"user\"";
	else if ((me == NULL || strcmp(me, user) != 0) && user_console(me) !=
	    CROLE_OWNER)
		e = "another user's password is the owner's to set";
	else if (me != NULL && strcmp(me, user) == 0 && current == NULL) {
		/* One's own: the key proves it, said now. */
		if ((a = ucl_object_lookup(body, "assertion")) == NULL ||
		    ucl_object_type(a) != UCL_OBJECT)
			e = "your current password (\"current\"), or your key's "
			    "assertion (\"assertion\"), please";
		else if ((e = pw_assertion(a, me)) != NULL)
			log_msg(LOG_NOTICE, "password change of %s refused: %s",
			    me, e);
	} else if (me != NULL && strcmp(me, user) == 0) {
		(void)web_peer(req, addr, sizeof(addr));
		if (!user_has_password(me))
			e = "you have no password yet: confirm with your key";
		else if (signin_throttled(addr, me))
			e = "too many failed sign-ins: try again in a minute";
	}
	if (e != NULL) {
		if (password != NULL)
			explicit_bzero((char *)(uintptr_t)password,
			    strlen(password));
		if (current != NULL)
			explicit_bzero((char *)(uintptr_t)current,
			    strlen(current));
		ucl_object_unref(body);
		return (reply_error(req, strstr(e, "owner's") != NULL ? 403 :
		    strstr(e, "too many") != NULL ? 429 : strstr(e, "user\"") !=
		    NULL ? 400 : 403, strstr(e, "owner's") != NULL ? "role" :
		    strstr(e, "user\"") != NULL ? "invalid" : "proof", "%s", e));
	}
	snprintf(name, sizeof(name), "%s", user);
	/* The current password checked only for one's own, given. */
	ps = pwset_new(req, name, password, me != NULL && strcmp(me, name) ==
	    0 ? current : NULL);
	if (password != NULL)
		explicit_bzero((char *)(uintptr_t)password, strlen(password));
	if (current != NULL)
		explicit_bzero((char *)(uintptr_t)current, strlen(current));
	ucl_object_unref(body);
	return (pwset_start(req, ps));
}

int
api_logout(struct http_request *req)
{
	uint8_t	 h[32];
	char	*cookie, clear[128];
	int	 i;

	if (http_request_cookie(req, SESSION_COOKIE, &cookie)) {
		sha256(cookie, strlen(cookie), h);
		for (i = nsessions - 1; i >= 0; i--)
			if (i < nsessions && memcmp(sessions[i]->hash, h,
			    sizeof(h)) == 0)
				session_end(sessions[i]);
	}
	snprintf(clear, sizeof(clear), "%s=; Path=/; HttpOnly; "
	    "SameSite=Strict; Max-Age=0", SESSION_COOKIE);
	http_response_header(req, "set-cookie", clear);
	return (status_reply(req, false));
}

/* Is there a sign-in key of this name: a console user? */
bool
cred_named(const char *name)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it;

	it = NULL;
	while (name != NULL && (c = ucl_object_iterate(cred_list(), &it, true))
	    != NULL)
		if (ucl_str(c, "name") != NULL && strcmp(ucl_str(c, "name"), name)
		    == 0)
			return (true);
	return (false);
}

/*
 * arcana-console's credentials (cyang.c): the request's user's keys (an
 * owner's: every user's), their public keys not among them.
 */
ucl_object_t *
credentials_yang(struct http_request *req)
{
	const ucl_object_t	*c, *v;
	ucl_object_t		*top, *a, *e;
	ucl_object_iter_t	 it = NULL;
	const char		*u;

	u = session_user(req);
	a = ucl_object_typed_new(UCL_ARRAY);
	while ((c = ucl_object_iterate(cred_list(), &it, true)) != NULL) {
		if (u != NULL && user_console(u) != CROLE_OWNER && strcmp(
		    cred_user(c), u) != 0)
			continue;
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "id", ucl_object_fromstring(ucl_str(c, "id")));
		if (ucl_str(c, "name") != NULL && ucl_str(c, "name")[0] != '\0')
			put(e, "name", ucl_object_fromstring(ucl_str(c,
			    "name")));
		put(e, "user", ucl_object_fromstring(cred_user(c)));
		if ((v = ucl_object_lookup(c, "alg")) != NULL)
			put(e, "alg", ucl_object_copy(v));
		if ((v = ucl_object_lookup(c, "created")) != NULL)
			put(e, "created", yang_time((double)ucl_object_toint(v)));
		if ((v = ucl_object_lookup(c, "last_used")) != NULL)
			put(e, "last-used", yang_time((double)ucl_object_toint(
			    v)));
		if ((v = ucl_object_lookup(c, "sign_count")) != NULL)
			put(e, "sign-count", ucl_object_copy(v));
		if ((v = ucl_object_lookup(c, "transports")) != NULL &&
		    ucl_object_type(v) == UCL_ARRAY && ucl_array_size(v) > 0)
			put(e, "transports", ucl_object_copy(v));
		ucl_array_append(a, e);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	put(top, "credential", a);
	return (top);
}

/*
 * The keys' change from was to now: each renamed or removed by its
 * user, or by an owner, never the last; none made here (the WebAuthn
 * ceremony registers one).  0, or the HTTP status and why.
 */
int
credentials_yang_set(struct http_request *req, const ucl_object_t *was,
    const ucl_object_t *now, char *why, size_t len)
{
	const ucl_object_t	*wl, *nl, *e, *o, *c;
	ucl_object_iter_t	 it;
	const char		*u, *n;
	size_t			 gone;

	wl = ucl_object_lookup(was, "credential");
	nl = ucl_object_lookup(now, "credential");
	u = session_user(req);
	gone = 0;
	it = NULL;
	while ((e = ucl_object_iterate(nl, &it, true)) != NULL)
		if (cyang_entry(wl, "id", ucl_str(e, "id")) == NULL) {
			snprintf(why, len, "a key is registered by signing in "
			    "with it (/api/auth/register)");
			return (400);
		}
	it = NULL;
	while ((o = ucl_object_iterate(wl, &it, true)) != NULL) {
		if ((c = cred_find(ucl_str(o, "id"))) == NULL)
			continue;
		e = cyang_entry(nl, "id", ucl_str(o, "id"));
		if (e != NULL && cyang_same(o, e))
			continue;
		if (u != NULL && user_console(u) != CROLE_OWNER && strcmp(
		    cred_user(c), u) != 0) {
			snprintf(why, len, "another user's key is changed by "
			    "the owner");
			return (403);
		}
		if (e == NULL)
			gone++;
		else if ((n = ucl_str(e, "name")) != NULL && (strlen(n) > 64 ||
		    strpbrk(n, "\r\n") != NULL)) {
			snprintf(why, len, "a key's name is one line of 64 at "
			    "most");
			return (400);
		}
	}
	if (gone > 0 && gone >= ucl_array_size(cred_list())) {
		snprintf(why, len, "register another key before removing the "
		    "last one");
		return (409);
	}
	it = NULL;
	while ((o = ucl_object_iterate(wl, &it, true)) != NULL) {
		if ((c = cred_find(ucl_str(o, "id"))) == NULL)
			continue;
		if ((e = cyang_entry(nl, "id", ucl_str(o, "id"))) == NULL) {
			log_msg(LOG_NOTICE, "key \"%s\" of %s removed",
			    ucl_str(c, "name") != NULL ? ucl_str(c, "name") :
			    "", cred_user(c));
			/* What it opened ends with it. */
			if (ucl_str(c, "id") != NULL)
				sessions_end_cred(ucl_str(c, "id"));
			ucl_object_unref(ucl_array_delete(cred_list(),
			    (ucl_object_t *)(uintptr_t)c));
		} else if (!cyang_same(o, e))
			ucl_object_replace_key((ucl_object_t *)(uintptr_t)c,
			    ucl_object_fromstring(ucl_str(e, "name") != NULL ?
			    ucl_str(e, "name") : ""), "name", 0, true);
	}
	if (creds_save() == -1) {
		snprintf(why, len, "cannot save");
		return (500);
	}
	return (0);
}
